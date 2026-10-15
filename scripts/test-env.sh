#!/bin/sh
# Resolve the tools required by every parity check.
if [ "${AUKORA_NODE+x}" != x ]; then
  if [ -x /Users/peterviviani/.local/node-v24.11.1/bin/node ]; then
    AUKORA_NODE=/Users/peterviviani/.local/node-v24.11.1/bin/node
  else
    AUKORA_NODE=$(command -v node) || {
      echo 'AUKORA_NODE: Node is missing; set AUKORA_NODE or put node on PATH' >&2
      exit 1
    }
  fi
fi
AUKORA_PRIME=${AUKORA_PRIME-/Users/peterviviani/aukora-prime}
export AUKORA_NODE AUKORA_PRIME
echo "AUKORA_NODE=$AUKORA_NODE"
echo "AUKORA_PRIME=$AUKORA_PRIME"
if ! "$AUKORA_NODE" --version > /dev/null 2>&1; then
  echo "AUKORA_NODE: cannot run '$AUKORA_NODE'; set AUKORA_NODE to Node or put node on PATH" >&2
  exit 1
fi
if [ -z "$AUKORA_PRIME" ] || [ ! -d "$AUKORA_PRIME" ]; then
  echo "AUKORA_PRIME: checkout '$AUKORA_PRIME' is missing; set AUKORA_PRIME to the Prime checkout" >&2
  exit 1
fi
