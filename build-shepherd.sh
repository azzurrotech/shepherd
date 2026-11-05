#!/bin/bash
# build-shepherd.sh - Build and run the SHEPHERD (identity-less IAM/firewall) service
#
# Usage:
#   ./build-shepherd.sh           # build and start on default port
#   ./build-shepherd.sh 8083    # start on port 8083
#   ./build-shepherd.sh http://localhost:8083  # use existing running service
#
# Automatically detects an open local port if none specified,
# otherwise accepts a URL as argument.

set -e

# Defaults
PORT=""
SECRET=""

# Parse arguments: first positional arg is port, or use --port/--secret flags
if [ $# -ge 1 ]; then
  FIRST="$1"
  if echo "$FIRST" | grep -qE '^[0-9]+$'; then
    PORT="$FIRST"
  elif echo "$FIRST" | grep -q '^http://\|^https://'; then
    PORT_PART=$(echo "$FIRST" | sed -E 's|://[^:]+:?([0-9]*)/.*|\1|')
    if [ -n "$PORT_PART" ] && [ "$PORT_PART" != ":" ]; then
      PORT=":$PORT_PART"
    fi
  fi
fi

# Handle --port and --secret flags
while [ $# -gt 0 ]; do
  case "$1" in
    --port|-p)
      PORT="$2"
      shift 2
      ;;
    --secret|-s)
      SECRET="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

# Find an open port if not provided
if [ -z "$PORT" ]; then
  for trial_port in 8083 8084 8085 9090 3001; do
    if ! curl -s "http://localhost${trial_port}" > /dev/null 2>&1; then
      PORT=":$trial_port"
      echo ">>> Using available port $trial_port"
      break
    fi
  done
  if [ -z "$PORT" ]; then
    echo ">>> No default port available, relying on Go defaults/env"
    PORT=""
  fi
fi

# Build the Go binary
echo ">>> Building SHEPHERD binary..."
go build -o shepherd .

echo ">>> Starting SHEPHERD..."
if [ -n "$PORT" ]; then
  echo ">>> Using port $PORT"
  if [ -z "$SECRET" ]; then
    export SHEPHERD_SECRET="${SECRET:-change-me}"
  fi
  export SHEPHERD_PORT="${PORT#:}"
  ./shepherd -port "${PORT#:}" -secret "${SECRET:-}"
else
  ./shepherd -port "8084" -secret "${SECRET:-}"
fi