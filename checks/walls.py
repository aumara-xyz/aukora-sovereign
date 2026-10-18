#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The walls, checked by source scan and by dependency (checks/run.py rules 6 and 11). A module of its own, so any
lens can probe it: `from walls import file_findings, dep_findings`.

Rust is stripped string-aware first (comments dropped, string and char contents blanked) and `a :: b` is normalised to
`a::b`, so neither a string nor a comment can hide code or trip a rule. Every other file is scanned as it is.
"""
import re

# Product defaults retained in Kira's command help and the inherited Live app are not review-folder references.
HOME_DEFAULTS = {
    "crates/kira/src/shared/service/cli.rs": ("~" + "/aukora-memory/kira",),
    "crates/kira/src/shared/service/mod.rs": ("~" + "/aukora-memory/kira", "~" + "/aukora-memory/archive/epoch1-2026-10-17/notes.jsonl"),
    "engine/plugins/aukora-face/apps/src/index.ts": ("~" + "/aukora-live/room.log",),
}


def foreign_path(path, text):
    """Local home/review paths, including docs and YAML; installed product defaults remain explicit exceptions."""
    for default in HOME_DEFAULTS.get(path, ()):
        text = text.replace(default, "")
    home = re.search(r"(?<![A-Za-z0-9._-])/(?:Users|home)/|~/(?!\.(?:cargo|ssh|local|dsh|aukora-spawn)\b|Downloads\b)", text)
    code = not path.endswith((".md", ".yaml", ".yml"))
    return home is not None or (code and re.search(r"aukora-(?:prime|genesis|contact|buzz|sovereign-archive)/", text) is not None)


ALLOW = {"net": {"frontdoor", "relay", "broker", "kira", "supervisor", "launcher"},
         "proc": {"launcher", "supervisor"},
         "unsafe": {"launcher", "supervisor", "canon", "pentora"}}
# External crates that are themselves network or system access.
NET_CRATES = {"reqwest", "tokio", "hyper", "hyper-util", "hyper-rustls", "h2", "quinn", "quinn-proto", "quinn-udp", "socket2",
              "mio", "axum", "tungstenite", "tokio-tungstenite", "async-tungstenite", "rustls", "tokio-rustls", "tower",
              "tower-http", "ureq", "instant-acme"}
SYS_CRATES = {"libc", "nix", "rustix", "landlock", "seccompiler", "memfd", "caps", "procfs"}
NO_SYS = {"guest", "canon"}
# Crates that run programs or build tools at run time: only for the units allowed to spawn processes.
PROC_CRATES = {"rustc_version", "cc", "cmake", "pkg-config", "jobserver", "signal-hook-registry", "duct", "subprocess"}
# Browser bindings: only the owner WASM, and web-sys only with exactly these features (a feature such as Request or
# WebSocket would give the code a way out that no source scan names).
BROWSER_CRATES = {"web-sys", "js-sys", "wasm-bindgen", "wasm-bindgen-futures"}
BROWSER_ALLOW = {"aumlok"}
WEB_SYS_FEATURES = {"Window", "Location", "Navigator", "CredentialsContainer", "CredentialRequestOptions",
                    "PublicKeyCredentialRequestOptions", "PublicKeyCredentialDescriptor", "PublicKeyCredentialType",
                    "UserVerificationRequirement", "PublicKeyCredential", "Credential", "AuthenticatorResponse",
                    "AuthenticatorAssertionResponse", "AuthenticationExtensionsClientInputs",
                    "AuthenticationExtensionsClientOutputs"}
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"

NET = (r"\b(ToSocketAddrs|to_socket_addrs|lookup_host)\b|std::net::(?!(IpAddr|Ipv[46]Addr|SocketAddr(V[46])?|AddrParseError)\b)|std::os::unix::(net|\*)|\bUnix(Stream|Listener|Datagram)\b|TcpStream|TcpListener|UdpSocket|"
       r"tokio::(net|\{)|hyper::|hyper_util|tungstenite|rustls::|reqwest|socket2|quinn|\bh2::|axum::|mio::|"
       r"nix::sys::socket|rustix::net|libc::(socket|connect|bind|listen|accept\w*|send\w*|recv\w*|syscall)")
PROC = (r"std::process(?!::(exit|id|abort|ExitCode)\b)|::\$\w+|std::process::(Command|Child|Stdio)|std::process::\{[^}]*\b(Command|Child|Stdio)\b|\bCommand::new|"
        r"libc::(exec\w*|fork|vfork|posix_spawn\w*|system|popen|clone\w*|syscall)|nix::unistd::(exec\w*|fork)|rustix::runtime")
UNSAFE = r"(?<![\w#])unsafe\b|#!?\[\s*(no_mangle|export_name|link_section)\b"
# Lint levels that would switch the compiler walls off from inside the source.
LINT_OFF = r"\b(allow|expect|warn)\s*\([^)]*clippy::(disallowed|all|restriction)|\ballow\s*\(\s*warnings\b"
SMUGGLE = r"\binclude\s*!|#!?\[[^\]]*\bpath\s*="
PICTURE = r"HealthSnapshot|organ_map|OrganMap|pentora::"
PICTURE_STRICT = PICTURE + r"|HealthEvidence|CheckRef"
TEST_ATTR = (r"#!?\[\s*(test|bench|rstest|quickcheck)\s*[\](]|#!?\[\s*[\w:]*::test\b|#!?\[\s*cfg\s*\(\s*test\s*\)|"
             r"#!?\[\s*cfg\s*\(\s*(all|any)\s*\([^\]]*\btest\b|\bproptest!\s*[{(]|#!?\[\s*cfg_attr\s*\([^\]]*,\s*(test|bench)\s*[,)]")
TEST_PATH = (r"(^|/)(test|tests|__tests__|benches)/|(^|/)tests\.rs$|(^|/)test\.(m?js|cjs|ts|tsx|jsx|py|sh|rs)$|"
             r"[._-](test|spec)\.[a-z0-9]+$|(^|/)test_[^/]*\.py$")
JS_BAD = (r"(?<![\w$.])eval\s*\(|(?<![\w$.])Function\s*\(|\bnew\s+Function\b|\bset(Timeout|Interval)\s*\(\s*[\"'`]|"
          r"\.(inner|outer)HTML\b|\[\s*[\"'`](inner|outer)HTML[\"'`]\s*\]|\binsertAdjacentHTML\b|\bcreateContextualFragment\b|"
          r"\bsrcdoc\b|\bdocument\s*\.\s*write(ln)?\s*\(|\bimport\s*\(\s*[\"'`]data:|constructor\s*\.\s*constructor|"
          r"\b(window|globalThis|self)\s*\[|"
          r"\bdangerouslySetInnerHTML\b|\b(set|parse)HTMLUnsafe\b|\bDOMParser\b|\bsetAttribute\s*\(\s*[\"'`]on")
HTML_BAD = (r"<script(?![^>]*\bsrc\s*=)(?![^>]*\btype\s*=\s*[\"']application/json[\"'])[^>]*>|<script[^>]*\bsrc\s*=[^>]*>\s*[^<\s]|"
            r"\son[a-z]+\s*=|(href|src|action|formaction|xlink:href)\s*=\s*[\"']?\s*javascript:")
# The owner WASM (aumlok) holds the phrase and the root secret. Rust that reaches the browser may not evaluate a string,
# build a function, take the global object, glob-import the bindings or name a network-capable web-sys type; a web-sys
# feature that would unlock one is refused by dep_findings (WEB_SYS_FEATURES). `extern { .. }` imports are wall-abi.
BROWSER_RS = (r"\bjs_sys::(eval|global)\b|\b(js_sys|web_sys)::\*|\bFunction::new_(no_args|with_args)\b|"
              r"\bweb_sys::(Request|Response|Headers|WebSocket|XmlHttpRequest|EventSource|Worker|SharedWorker|ServiceWorker|"
              r"RtcPeerConnection|BroadcastChannel|MessageChannel|FormData|Blob)\w*|\b(fetch_with_\w+|send_beacon\w*)\b")
ABI = r"\bextern\s*(\"\"\s*)?\{|\bglobal_asm\b|\basm\s*!|#!?\[\s*(link|link_name)\b|\bextern\s+crate\b|\buse\s+(::)?(std|core|alloc)\s+as\b"
SCANNED = r"\.(rs|ts|tsx|js|jsx|mjs|cjs|html|htm|svg)$"
# Preview-only shims (the simulated passkey, the simulated second device, the stand-in node, the /__diag event log, the camera
# canvas) live outside the product tree. Any trace of one in product source, or in the product build, is a leak.
PREVIEW_MARKERS = (r"__preview|/__diag\b|\bpreview-(stub|pairing|diag)\b|Simulate (passkey|second device)|PREVIEW ONLY|"
                   r"\b__previewCam\b|\b__previewLoop\b|\b__previewSimulate\b")
PRODUCT_PATH = r"^(app|ui|portal|crates)/"
RAW_STRING = re.compile(r'[bc]?r(#*)"')
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
        elif c == '"' or (c in "bc" and t[i + 1:i + 2] == '"' and boundary):
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
    code = re.sub(r"\s*::\s*", "::", re.sub(r"\br#(?=[A-Za-z_])", "", "".join(out)))
    return code + "\n" + "\n".join(p for m in re.finditer(r"\buse\s+([^;]*);", code) for p in expand("", m.group(1)))


def expand(prefix, tree):
    parts, depth, cur = [], 0, ""
    for ch in tree:
        depth += (ch == "{") - (ch == "}")
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    out = []
    for p in (x.strip() for x in parts):
        m = re.match(r"(.*?)::\{(.*)\}$", p, re.S)
        if p.startswith("{"):
            out += expand(prefix, p[1:-1])
        elif m:
            out += expand(prefix + m.group(1) + "::", m.group(2))
        elif p:
            out.append(prefix + p.split(" as ")[0].strip())
    return out


def unit_of(path):
    return path.split("/")[1] if path.startswith("crates/") else path.split("/")[0]


def file_findings(path, text):
    """Every wall a file breaks, as (rule, path) pairs."""
    low, unit, found = path.lower(), unit_of(path), []
    # Test folders and files are allowed (Peter, 2026-10-17); TEST_PATH stays defined for other tools.
    if not re.search(SCANNED, low):
        return found
    if re.search(PRODUCT_PATH, low) and re.search(PREVIEW_MARKERS, text):
        found.append(("wall-preview", path))
    if low.endswith(".rs"):
        code = strip_rs(text)
        # Peter, 2026-10-17: unit tests (#[cfg(test)] modules) are allowed; nothing gates a merge on them.
        for rule, pattern, allowed in (("wall-smuggle", SMUGGLE, set()),
                                       ("wall-network", NET, ALLOW["net"]), ("wall-exec", PROC, ALLOW["proc"]),
                                       ("wall-unsafe", UNSAFE, ALLOW["unsafe"]), ("wall-lint", LINT_OFF, set()), ("wall-abi", ABI, {"launcher"}),
                                       ("wall-browser", BROWSER_RS, set())):
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
    if name in PROC_CRATES and unit not in ALLOW["proc"]:
        found.append(("wall-exec", f"{unit} depends on {name}"))
    if name in SYS_CRATES and unit in NO_SYS:
        found.append(("wall-sys", f"{unit} depends on {name}"))
    if name in BROWSER_CRATES and unit not in BROWSER_ALLOW:
        found.append(("wall-browser", f"{unit} depends on {name}"))
    if name == "web-sys" and set(dep.get("features", [])) != WEB_SYS_FEATURES:
        found.append(("wall-browser", f"{unit}'s web-sys features differ from the pinned set in checks/walls.py"))
    return found


# The compiler walls (checks/run.py rule 12): which crate roots forbid unsafe code, and each crate's clippy.toml.
UNSAFE_ROOT = {"launcher": None, "supervisor": None, "canon": "deny", "pentora": "deny"}  # every other unit: forbid
WASM_ALLOW = {"crates/canon/src/wasm.rs", "crates/pentora/src/wasm.rs"}
_NET_TYPES = ["std::net::TcpStream", "std::net::TcpListener", "std::net::UdpSocket", "std::os::unix::net::UnixStream",
              "std::os::unix::net::UnixListener", "std::os::unix::net::UnixDatagram"]
_NET_METHODS = ["std::net::TcpStream::connect", "std::net::TcpListener::bind", "std::net::UdpSocket::bind",
                "std::net::ToSocketAddrs::to_socket_addrs", "std::os::unix::net::UnixStream::connect",
                "std::os::unix::net::UnixListener::bind", "std::os::unix::net::UnixDatagram::bind"]
_PROC_TYPES = ["std::process::Command", "std::process::Child"]
_PROC_METHODS = ["std::process::Command::new"]
_FS_METHODS = ["std::fs::read", "std::fs::read_to_string", "std::fs::write", "std::fs::File::open", "std::fs::File::create",
               "std::fs::OpenOptions::open", "std::fs::remove_file", "std::fs::create_dir_all", "std::fs::read_dir"]


def clippy_toml(unit):
    """The exact clippy.toml each crate must carry; clippy resolves these paths, so no alias or group can hide them."""
    types, methods = [], []
    if unit not in ALLOW["net"]:
        types += [(t, "only frontdoor, relay, broker, kira, supervisor and launcher touch the network") for t in _NET_TYPES]
        methods += [(m, "only frontdoor, relay, broker, kira, supervisor and launcher touch the network") for m in _NET_METHODS]
    if unit not in ALLOW["proc"]:
        types += [(t, "only launcher and supervisor spawn processes") for t in _PROC_TYPES]
        methods += [(m, "only launcher and supervisor spawn processes") for m in _PROC_METHODS]
    if unit == "guest":
        methods += [(m, "Auma never touches the filesystem; her data comes through FD 3") for m in _FS_METHODS]
    fmt = lambda xs: "".join(f'  {{ path = "{p}", reason = "{r}" }},\n' for p, r in xs)
    return ("# Generated by checks/walls.py; checks/run.py fails if it differs. Clippy enforces it on resolved paths.\n"
            f"disallowed-types = [\n{fmt(types)}]\ndisallowed-methods = [\n{fmt(methods)}]\n")


# The engine's own walls (checks/run.py rule "engine-io"): TypeScript and JavaScript under engine/ may not reach the
# network, run a program, read the environment or evaluate a string, except in the exact files checks/baseline.json
# `engine_io_allowed` lists, each with its reason. The engine holds no keys; its only ways out are the door and the broker.
# Unlike every rule above, this one also reads files checks/pins.json pins: a pinned hash says the bytes did not change,
# not that the bytes are allowed to do this.
ENGINE_SCANNED = r"^engine/.*\.(ts|tsx|js|mjs)$"
_ENGINE_MODULES = (r"(?:node:)?(?:net|http|https|http2|dgram|tls|dns|child_process|worker_threads|cluster)|"
                   r"undici|ws|node-fetch|axios|got")
ENGINE_BAD = {
    "network": (r"(?<![\w$.\"'`/-])(?<!typeof )fetch\b(?![\w$\"'`-]|\s*\??\s*:)|\.\s*fetch\s*\(|\b(XMLHttpRequest|WebSocket|EventSource)\b|\bsendBeacon\b"),
    "network-module": (r"(?m)^(?!\s*(?:import|export)\s+type\b)[^\n]*?(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s+)[\"'](?:" + _ENGINE_MODULES + r")(?:/[\w./-]*)?[\"']"),
    "process": (r"(?<![\w$.])(?:exec|execFile|execFileSync|execSync|spawn|spawnSync|fork)\s*\(|\.\s*(?:execFile|execFileSync|execSync|spawn|spawnSync)\s*\("),
    "env": (r"\bprocess\s*(?:\.\s*env\b|\[\s*[\"']env[\"']\s*\])|\bimport\.meta\.env\b|\bDeno\.env\b|"
            r"\{[^}]*\benv\b[^}]*\}\s*=\s*process\b|import\s*\{[^}]*\benv\b[^}]*\}\s*from\s*[\"'](?:node:)?process[\"']"),
    "eval": r"(?<![\w$.])(?:eval|Function)\s*\(|\bnew\s+Function\b",
}


def strip_js_comments(text):
    """Drop // and /* */ comments from JavaScript or TypeScript, string-aware (quotes and template literals are kept
    whole, so a `//` inside a URL string is not a comment). A regex literal containing a quote can confuse it; it errs
    toward keeping more text, which can only add findings."""
    out, i, n = [], 0, len(text)
    while i < n:
        c, two = text[i], text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif two == "/*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif c in "\"'`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
                if c != "`" and j < n and text[j] == "\n":
                    break
            out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def engine_findings(path, text):
    """The kinds of reach (network, network-module, process, env, eval) a file under engine/ has; test files are exempt
    as everywhere else (Peter, 2026-10-17)."""
    if not re.search(ENGINE_SCANNED, path) or re.search(TEST_PATH, path.lower()):
        return []
    code = strip_js_comments(text)
    return [kind for kind, pattern in ENGINE_BAD.items() if re.search(pattern, code)]

