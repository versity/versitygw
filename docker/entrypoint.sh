#!/bin/sh
set -e

# Default binary location
BIN="${VGW_BINARY:-/usr/local/bin/versitygw}"

# Check if binary exists
if [ ! -x "$BIN" ]; then
    echo "ERROR: versitygw binary not found at $BIN" >&2
    exit 1
fi

# Default command is s3multi
COMMAND="${1:-s3multi}"

# Build arguments array
ARGS=""

# Multi-backend specific environment variables
if [ "$COMMAND" = "s3multi" ]; then
    # Config file (required for s3multi)
    if [ -n "${VGW_CONFIG_FILE}" ]; then
        ARGS="$ARGS --config ${VGW_CONFIG_FILE}"
    elif [ -f "/etc/versitygw/config.json" ]; then
        ARGS="$ARGS --config /etc/versitygw/config.json"
    else
        echo "ERROR: No config file found. Set VGW_CONFIG_FILE or mount to /etc/versitygw/config.json" >&2
        exit 1
    fi

    # Gateway credentials (optional - will generate random if not provided)
    if [ -n "${VGW_ACCESS_KEY}" ]; then
        ARGS="$ARGS --access ${VGW_ACCESS_KEY}"
    fi
    
    if [ -n "${VGW_SECRET_KEY}" ]; then
        ARGS="$ARGS --secret ${VGW_SECRET_KEY}"
    fi

    # Port
    if [ -n "${VGW_PORT}" ]; then
        ARGS="$ARGS --port ${VGW_PORT}"
    fi

    # Host/Address
    if [ -n "${VGW_HOST}" ]; then
        ARGS="$ARGS --host ${VGW_HOST}"
    fi

    # Region
    if [ -n "${VGW_REGION}" ]; then
        ARGS="$ARGS --region ${VGW_REGION}"
    fi

    # Certificate files for HTTPS
    if [ -n "${VGW_CERT}" ]; then
        ARGS="$ARGS --cert ${VGW_CERT}"
    fi

    if [ -n "${VGW_KEY}" ]; then
        ARGS="$ARGS --key ${VGW_KEY}"
    fi

    # Debug mode
    if [ "${VGW_DEBUG}" = "true" ]; then
        ARGS="$ARGS --debug"
    fi
fi

# Additional custom arguments
if [ -n "${VGW_EXTRA_ARGS}" ]; then
    ARGS="$ARGS ${VGW_EXTRA_ARGS}"
fi

echo "Starting VersityGW Multi-Backend..."
echo "Command: $BIN $COMMAND $ARGS"
echo ""

# Execute with proper argument expansion
# shellcheck disable=SC2086
exec $BIN $COMMAND $ARGS
