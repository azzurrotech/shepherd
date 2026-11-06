#!/bin/bash
# run.sh for shepherd - Standalone shepherd service
#
# Detects if shepherd is already running locally and prompts:
#   use local / start new local / use remote
# Default: use any running local instance

set -e

SHEPHERD_PORT="${SHEPHERD_PORT:-8083}"

# Check if shepherd is already running locally
is_local_running() {
    curl -s "http://127.0.0.1:$SHEPHERD_PORT/.well-known/shepherd" > /dev/null 2>&1
    return $?
}

# Check if shepherd remote is reachable
is_remote_running() {
    curl -s "http://${SHEPHERD_REMOTE:-127.0.0.1:$SHEPHERD_PORT}/.well-known/shepherd" > /dev/null 2>&1
    return $?
}

echo "=== shepherd Service ==="
echo "Configuration:"
echo "  Local address: 127.0.0.1:$SHEPHERD_PORT"

SELECTED=""

if is_local_running; then
    echo "✓ Local shepherd is already running on 127.0.0.1:$SHEPHERD_PORT"
    read -p "Use local instance? [Y/n/remote]: " choice
    case "$choice" in
        n|N)
            SELECTED="remote"
            ;;
        *)
            SELECTED="local"
            ;;
    esac
fi

if [ "$SELECTED" = "" ]; then
    if is_remote_running; then
        echo "✓ Remote shepherd is reachable at ${SHEPHERD_REMOTE:-127.0.0.1:$SHEPHERD_PORT}"
        read -p "Use remote instance? [y/N/local]: " choice
        case "$choice" in
            y|Y)
                SELECTED="remote"
                ;;
            l|L)
                SELECTED="local"
                ;;
            *)
                SELECTED="local"
                ;;
        esac
    else
        echo "✗ No local or remote shepherd running. Starting new local instance..."
        SELECTED="local"
    fi
fi

case "$SELECTED" in
    local)
        echo ">>> Starting new local shepherd instance..."
        if [ -x "$(command -v shepherd)" ]; then
            shepherd -port "$SHEPHERD_PORT" -secret "secret-change-me" &
            echo "    PID: $!"
            echo "✓ shepherd started locally on 127.0.0.1:$SHEPHERD_PORT"
        else
            echo "✗ shepherd binary not found. Please build first: go build ./..."
        fi
        ;;
    remote)
        echo ">>> Using remote shepherd at ${SHEPHERD_REMOTE:-127.0.0.1:$SHEPHERD_PORT}"
        if [ -z "$SHEPHERD_REMOTE" ]; then
            export SHEPHERD_REMOTE="${SHEPHERD_REMOTE:-127.0.0.1:$SHEPHERD_PORT}"
            echo "✓ Remote set: $SHEPHERD_REMOTE"
        fi
        ;;
    *)
        echo ">>> Starting new local shepherd instance..."
        if [ -x "$(command -v shepherd)" ]; then
            shepherd -port "$SHEPHERD_PORT" -secret "secret-change-me" &
            echo "    PID: $!"
            echo "✓ shepherd started locally on 127.0.0.1:$SHEPHERD_PORT"
        else
            echo "✗ shepherd binary not found. Please build first: go build ./..."
        fi
        ;;
esac

echo ""
echo "shepherd service ready on port $SHEPHERD_PORT"
echo "API endpoints:"
echo "  Health:          http://127.0.0.1:$SHEPHERD_PORT/.well-known/shepherd"
echo "  Keys (issue):    http://127.0.0.1:$SHEPHERD_PORT/api/keys"
echo "  Revoke:        http://127.0.0.1:$SHEPHERD_PORT/api/revoke"
echo "  Rate limit:      http://127.0.0.1:$SHEPHERD_PORT/api/ratelimit/status"
echo "  Firewall:        http://127.0.0.1:$SHEPHERD_PORT/api/firewall/rules"
