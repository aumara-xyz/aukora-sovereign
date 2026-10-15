#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The walls, checked by source scan and by dependency (checks/run.py rules 6 and 11). A module of its own, so any
lens can probe it: `from walls import file_findings, dep_findings`.

Rust is stripped string-aware first (comments dropped, string and char contents blanked) and `a :: b` is normalised to
`a::b`, so neither a string nor a comment can hide code or trip a rule. Every other file is scanned as it is.
"""
import re

ALLOW = {"net": {"frontdoor", "relay", "broker", "kira", "supervisor", "launcher"},
         "proc": {"launcher", "supervisor"},
         "unsafe": {"launcher", "canon", "pentora", "wasmcell"}}
# External crates that are themselves network or system access.
NET_CRATES = {"reqwest", "tokio", "hyper", "hyper-util", "hyper-rustls", "h2", "quinn", "quinn-proto", "quinn-udp", "socket2",
              "mio", "axum", "tungstenite", "tokio-tungstenite", "async-tungstenite", "rustls", "tokio-rustls", "tower",
              "tower-http", "ureq"}
SYS_CRATES = {"libc", "nix", "rustix", "landlock", "seccompiler", "memfd", "caps", "procfs"}
NO_SYS = {"guest", "canon"}
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"

NET = (r"std::net|std::os::unix::(net|\{|\*)|\bUnix(Stream|Listener|Datagram)\b|TcpStream|TcpListener|UdpSocket|"
       r"tokio::(net|\{)|hyper::|hyper_util|tungstenite|rustls::|reqwest|socket2|quinn|\bh2::|axum::|mio::|"
       r"nix::sys::socket|rustix::net|libc::(socket|connect|bind|listen|accept\w*|send\w*|recv\w*|syscall)")
PROC = (r"std::process::(Command|Child|Stdio)|std::process::\{[^}]*\b(Command|Child|Stdio)\b|\bCommand::new|"
        r"libc::(exec\w*|fork|vfork|posix_spawn\w*|system|popen|clone\w*|syscall)|nix::unistd::(exec\w*|fork)|rustix::runtime")
UNSAFE = r"(?<![\w#])unsafe\b"
SMUGGLE = r"\binclude!\s*\(|#!?\[\s*path\s*="
PICTURE = r"HealthSnapshot|organ_map|OrganMap|pentora::"
PICTURE_STRICT = PICTURE + r"|HealthEvidence|CheckRef"
TEST_ATTR = (r"#!?\[\s*(test|bench|rstest|quickcheck)\s*[\](]|#!?\[\s*[\w:]*::test\b|#!?\[\s*cfg\s*\(\s*test\s*\)|"
             r"#!?\[\s*cfg\s*\(\s*(all|any)\s*\([^\]]*\btest\b|\bproptest!\s*[{(]")
TEST_PATH = (r"(^|/)(test|tests|__tests__|benches)/|(^|/)tests\.rs$|(^|/)test\.(m?js|cjs|ts|tsx|jsx|py|sh|rs)$|"
             r"[._-](test|spec)\.[a-z0-9]+$|(^|/)test_[^/]*\.py$")
JS_BAD = (r"(?<![\w$.])eval\s*\(|(?<![\w$.])Function\s*\(|\bnew\s+Function\b|\bset(Timeout|Interval)\s*\(\s*[\"'`]|"
          r"\.(inner|outer)HTML\b|\[\s*[\"'`](inner|outer)HTML[\"'`]\s*\]|\binsertAdjacentHTML\b|\bcreateContextualFragment\b|"
          r"\bsrcdoc\b|\bdocument\s*\.\s*write(ln)?\s*\(|\bimport\s*\(\s*[\"'`]data:|constructor\s*\.\s*constructor|"
          r"\b(window|globalThis|self)\s*\[")
HTML_BAD = (r"<script(?![^>]*\bsrc\s*=)(?![^>]*\btype\s*=\s*[\"']application/json[\"'])[^>]*>|<script[^>]*\bsrc\s*=[^>]*>\s*[^<\s]|"
            r"\son[a-z]+\s*=|(href|src|action|formaction|xlink:href)\s*=\s*[\"']?\s*javascript:")
SCANNED = r"\.(rs|ts|tsx|js|jsx|mjs|cjs|html|htm|svg)$"
RAW_STRING = re.compile(r'b?r(#*)"')
CHAR = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|.)|[^\\'])'")


def strip_rs(t):
    """Drop // and nested /* */ comments; blank the contents of strings, raw strings and chars; keep lifetimes."""
    out, i, n = [], 0, len(t)
    while i < n:
        c, two = t[i], t[i:i + 2]
        boundary = i == 0 or not (t[i - 1].isalnum() or t[i - 1] == "_")
        if two == "//":
            j = t.find("\n", i)
            i = n if j < 0 else j
        elif two == "/*":
            depth, i = 1, i + 2
            while i < n and depth:
                if t[i:i + 2] == "/*":
                    depth, i = depth + 1, i + 2
                elif t[i:i + 2] == "*/":
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            out.append(" ")
        elif boundary and RAW_STRING.match(t, i):
            m = RAW_STRING.match(t, i)
            end = '"' + m.group(1)
            j = t.find(end, m.end())
            i = n if j < 0 else j + len(end)
            out.append('""')
        elif c == '"' or (c == "b" and t[i + 1:i + 2] == '"' and boundary):
            j = i + (2 if c == "b" else 1)
            while j < n and t[j] != '"':
                j += 2 if t[j] == "\\" else 1
            i = j + 1
            out.append('""')
        elif c == "'" and CHAR.match(t, i):
            i = CHAR.match(t, i).end()
            out.append("''")
        else:
            out.append(c)
            i += 1
    return re.sub(r"\s*::\s*", "::", "".join(out))


def unit_of(path):
    return path.split("/")[1] if path.startswith("crates/") else path.split("/")[0]


def file_findings(path, text):
    """Every wall a file breaks, as (rule, path) pairs."""
    low, unit, found = path.lower(), unit_of(path), []
    if re.search(TEST_PATH, low) and not low.startswith("tests/e2e/"):
        found.append(("no-test-suites", path))
    if not re.search(SCANNED, low):
        return found
    if low.endswith(".rs"):
        code = strip_rs(text)
        for rule, pattern, allowed in (("no-test-suites", TEST_ATTR, set()), ("wall-smuggle", SMUGGLE, set()),
                                       ("wall-network", NET, ALLOW["net"]), ("wall-exec", PROC, ALLOW["proc"]),
                                       ("wall-unsafe", UNSAFE, ALLOW["unsafe"])):
            if unit not in allowed and re.search(pattern, code):
                found.append((rule, path))
        picture = {"gate": PICTURE, "frontdoor": PICTURE_STRICT, "launcher": PICTURE_STRICT}.get(unit)
        if picture and re.search(picture, code):
            found.append(("wall-picture", path))
    elif re.search(JS_BAD, text) or (re.search(r"\.(html|htm|svg)$", low) and re.search(HTML_BAD, text, re.I)):
        found.append(("wall-browser", path))
    return found


def dep_findings(unit, dep):
    """Walls a crate's external dependency breaks (dep is one entry of cargo metadata's `dependencies`)."""
    name, found = dep["name"], []
    if dep.get("source") != CRATES_IO:
        found.append(("deps-source", f"{unit} uses {name} from {dep.get('source')}, not crates.io"))
    if name in NET_CRATES and unit not in ALLOW["net"]:
        found.append(("wall-network", f"{unit} depends on {name}"))
    if name in SYS_CRATES and unit in NO_SYS:
        found.append(("wall-sys", f"{unit} depends on {name}"))
    return found
