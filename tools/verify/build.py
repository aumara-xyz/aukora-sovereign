#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate the standalone verifier without importing or executing its implementation."""
import ast
import builtins
import io
from pathlib import Path
import symtable
import sys
import tokenize

MODULES = ("common", "gate", "owner", "ledger", "api", "cli")
STDLIB = frozenset("argparse base64 binascii hashlib json os re stat sys".split())
HEADER = '''#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Standalone offline verifier; regenerate with python3 -B tools/verify/build.py."""
# Generated from tools/verify; implementation statements retain their parsed form.
'''
ENTRY = 'if __name__ == "__main__":\n    sys.exit(main(sys.argv[1:]))\n'


def require(condition, reason):
    if not condition:
        raise ValueError("verifier:" + reason)


def compact(source):
    """Remove empty and comment lines, preserving every line inside string tokens."""
    strings = set()
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.STRING:
            strings.update(range(token.start[0], token.end[0] + 1))
    return "\n".join(line for number, line in enumerate(source.splitlines(), 1)
                     if number in strings or line.strip() and not line.lstrip().startswith("#")) + "\n"


def definitions(node):
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return (node.name,)
    require(isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name), "build-source")
    return (node.targets[0].id,)


def check_scope(source, name, bindings):
    forbidden = {"__name__", "__doc__", "__file__", "__package__", "__spec__", "__loader__", "__builtins__",
                 "globals", "locals", "vars", "eval", "exec", "compile", "__import__"}
    allowed = set(bindings) | set(dir(builtins))
    pending = [symtable.symtable(source, name + ".py", "exec")]
    while pending:
        scope = pending.pop()
        for symbol in scope.get_symbols():
            if symbol.is_global() and symbol.is_referenced():
                require(symbol.get_name() in allowed - forbidden, "build-scope")
        pending.extend(scope.get_children())


def generate(directory):
    bindings, modules, imports, statements, segments = {}, {}, {"sys"}, [], []
    for name in MODULES:
        source = (directory / (name + ".py")).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=name + ".py")
        require(not any(isinstance(node, ast.Global) for node in ast.walk(tree)), "build-scope")
        local = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    require(alias.asname is None and alias.name in STDLIB, "build-import")
                    binding = ("stdlib", alias.name)
                    require(alias.name not in bindings or bindings[alias.name] == binding, "build-binding")
                    bindings[alias.name] = local[alias.name] = binding
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                require(node.level == 1 and node.module in modules, "build-import")
                for alias in node.names:
                    require(alias.asname is None and alias.name in modules[node.module], "build-import")
                    binding = modules[node.module][alias.name]
                    require(bindings.get(alias.name) == binding, "build-binding")
                    local[alias.name] = binding
            else:
                for identifier in definitions(node):
                    require(identifier not in bindings and identifier not in STDLIB
                            and identifier not in vars(builtins) and not identifier.startswith("__"), "build-binding")
                    bindings[identifier] = local[identifier] = (name, identifier)
                statements.append(node)
                segments.append(ast.get_source_segment(source, node))
        check_scope(source, name, local)
        modules[name] = local

    package = ast.parse((directory / "__init__.py").read_text(encoding="utf-8"))
    exports, package_names = None, set()
    for node in package.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.ImportFrom):
            require(node.level == 1 and node.module in modules, "build-export")
            for alias in node.names:
                require(alias.asname is None and alias.name in modules[node.module]
                        and bindings.get(alias.name) == modules[node.module][alias.name], "build-export")
                package_names.add(alias.name)
        else:
            require(isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "__all__"
                    and exports is None, "build-export")
            exports = ast.literal_eval(node.value)
    require(isinstance(exports, tuple) and all(isinstance(name, str) and name in package_names for name in exports)
            and len(exports) == len(set(exports)), "build-export")

    imported = "import " + ", ".join(sorted(imports)) + "\n"
    exported = "__all__ = " + repr(exports) + "\n"
    body = compact("\n".join(segments))
    result = HEADER + imported + body + exported + ENTRY
    expected = ast.parse(HEADER + imported).body + statements + ast.parse(exported + ENTRY).body
    require(ast.dump(ast.parse(result)) == ast.dump(ast.Module(body=expected, type_ignores=[])), "build-source")
    require(len(result.splitlines()) <= 1000, "build-size")
    compile(result, "verify.py", "exec")
    return result.encode("utf-8")


def main(arguments):
    try:
        require(arguments in ([], ["--check"]), "build-usage")
        directory = Path(__file__).resolve().parent
        output = directory.parent / "verify.py"
        source = generate(directory)
        if arguments:
            require(output.read_bytes() == source, "standalone-stale")
            print("Standalone source matches package; syntax and statement equivalence checked.")
        else:
            output.write_bytes(source)
            print("Generated tools/verify.py (" + str(len(source.splitlines())) + " lines).")
        return 0
    except (OSError, ValueError, SyntaxError, tokenize.TokenError) as error:
        print(str(error) if str(error).startswith("verifier:") else "verifier:build-source", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
