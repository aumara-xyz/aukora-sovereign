# Nebius CLI reference

The instance create, get-by-name, delete and list help and platform JSON came
from Peter's read-only live references for CLI v0.12.223. Platform resource
IDs were removed from that supplied JSON. Instance get and platform list
help came from the installed v0.12.223 CLI using `--no-check-update --help`;
these commands made no cloud requests. Help files have ANSI escapes and
trailing whitespace removed.

`test.sh` reads option names, types, required flags and enum values from these
help files. Its VM mock uses the recorded platform JSON, plus separate hostile
presets for the CPU, memory and GPU protection tests. Requests with unknown
flags, missing required flags, invalid values or incomplete network interfaces
must fail. The supported create/delete mock path waits synchronously; the
asynchronous path returns an operation without completing the resource change.

These references pin the tested CLI interface. Refresh them and rerun the
mutation suite when changing the supported CLI version. They do not prove
live allocation, networking, cloud-init or deletion.
