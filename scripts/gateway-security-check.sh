#!/bin/bash
# Gateway Security Self-Check
# Run at boot or periodically to prevent configuration regression
# Exit 0 = secure, Exit 1 = insecure
#
# Environment Variables:
#   GATEWAY_CONFIG    Path to config file (default: ~/.openclaw/openclaw.json)
#   GATEWAY_PORT      Port to check (default: 18789)

set -e

# Configuration
CONFIG_FILE="${GATEWAY_CONFIG:-$HOME/.openclaw/openclaw.json}"
GATEWAY_PORT="${GATEWAY_PORT:-18789}"
ERRORS=0

echo "=== Gateway Security Check ==="
echo "Config: $CONFIG_FILE"
echo "Port: $GATEWAY_PORT"
echo ""

# Helper: increment error count without failing on set -e
inc_error() {
    ERRORS=$((ERRORS + 1))
}

# 1. Check config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[FAIL] Config file not found: $CONFIG_FILE"
    inc_error
else
    # 2. Check bind address in config
    BIND=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('gateway',{}).get('bind',''))" 2>/dev/null || echo "UNKNOWN")
    if [[ "$BIND" == "loopback" ]]; then
        echo "[PASS] Config bind = loopback"
    else
        echo "[FAIL] Config bind = $BIND (should be 'loopback')"
        inc_error
    fi

    # 3. Check allowInsecureAuth
    INSECURE_AUTH=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('gateway',{}).get('controlUi',{}).get('allowInsecureAuth', False))" 2>/dev/null || echo "UNKNOWN")
    if [[ "$INSECURE_AUTH" == "False" ]]; then
        echo "[PASS] allowInsecureAuth = false"
    else
        echo "[FAIL] allowInsecureAuth = $INSECURE_AUTH (should be false)"
        inc_error
    fi

    # 4. Check dangerouslyDisableDeviceAuth
    DISABLE_DEVICE_AUTH=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('gateway',{}).get('controlUi',{}).get('dangerouslyDisableDeviceAuth', False))" 2>/dev/null || echo "UNKNOWN")
    if [[ "$DISABLE_DEVICE_AUTH" == "False" ]]; then
        echo "[PASS] dangerouslyDisableDeviceAuth = false"
    else
        echo "[FAIL] dangerouslyDisableDeviceAuth = $DISABLE_DEVICE_AUTH (should be false)"
        inc_error
    fi
fi

# 5. Check actual listener (if gateway is running)
echo ""
echo "--- Listener Check ---"
if lsof -nP -iTCP:$GATEWAY_PORT -sTCP:LISTEN &>/dev/null; then
    LISTENERS=$(lsof -nP -iTCP:$GATEWAY_PORT -sTCP:LISTEN 2>/dev/null | grep -v "^COMMAND")

    # Check for dangerous binds: *:port, 0.0.0.0:port, :::port (IPv6 wildcard)
    if echo "$LISTENERS" | awk '{print $9}' | grep -qE "^\*:|^0\.0\.0\.0:|^:::"; then
        echo "[FAIL] Gateway exposed on wildcard address!"
        echo "$LISTENERS" | while read line; do
            ADDR=$(echo "$line" | awk '{print $9}')
            echo "       EXPOSED: $ADDR"
        done
        inc_error
    else
        echo "[PASS] Gateway bound to localhost only:"
        echo "$LISTENERS" | while read line; do
            ADDR=$(echo "$line" | awk '{print $9}')
            echo "       OK: LISTEN $ADDR"
        done
    fi
else
    echo "[INFO] Gateway not running (listener check skipped)"
fi

# 6. Check Docker port publishing (common regression)
echo ""
echo "--- Docker Check ---"
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    # Check if any container publishes port to 0.0.0.0
    DOCKER_EXPOSED=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E "0\.0\.0\.0:$GATEWAY_PORT->|:::$GATEWAY_PORT->" || true)
    if [[ -n "$DOCKER_EXPOSED" ]]; then
        echo "[FAIL] Docker container exposing port $GATEWAY_PORT to all interfaces!"
        echo "       $DOCKER_EXPOSED"
        inc_error
    else
        DOCKER_ANY=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep ":$GATEWAY_PORT->" || true)
        if [[ -n "$DOCKER_ANY" ]]; then
            echo "[PASS] Docker container uses port $GATEWAY_PORT (localhost-bound):"
            echo "       $DOCKER_ANY"
        else
            echo "[PASS] No Docker containers using port $GATEWAY_PORT"
        fi
    fi
else
    echo "[INFO] Docker not running (check skipped)"
fi

# Summary
echo ""
echo "==============================="
if [[ $ERRORS -gt 0 ]]; then
    echo "SECURITY CHECK FAILED ($ERRORS issue(s))"
    echo "==============================="
    exit 1
else
    echo "SECURITY CHECK PASSED"
    echo "==============================="
    exit 0
fi
