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

# Build arguments array - use proper quoting to prevent injection
ARGS=""

# Multi-backend specific environment variables
if [ "$COMMAND" = "s3multi" ]; then
    # Config file (required for s3multi)
    if [ -n "${VGW_CONFIG_FILE}" ]; then
        ARGS="$ARGS --config \"${VGW_CONFIG_FILE}\""
    elif [ -f "/etc/versitygw/config.json" ]; then
        ARGS="$ARGS --config \"/etc/versitygw/config.json\""
    else
        echo "ERROR: No config file found. Set VGW_CONFIG_FILE or mount to /etc/versitygw/config.json" >&2
        exit 1
    fi

    # Gateway credentials are read from environment variables by the binary
    # DO NOT pass them via command line to avoid exposure in process list
    # The versitygw binary will read ROOT_ACCESS_KEY and ROOT_SECRET_KEY from environment
    if [ -n "${VGW_ACCESS_KEY}" ]; then
        export ROOT_ACCESS_KEY="${VGW_ACCESS_KEY}"
    fi
    
    # Do NOT pass secret via command line; it will be exposed in process list.
    # The secret should be provided via environment variable VGW_SECRET_KEY or mounted file.
    # Ensure the binary reads the secret from the environment or file.

    # Port
    if [ -n "${VGW_PORT}" ]; then
        ARGS="$ARGS --port \"${VGW_PORT}\""
    fi

    # Host/Address
    if [ -n "${VGW_HOST}" ]; then
        ARGS="$ARGS --host \"${VGW_HOST}\""
    fi

    # Region
    if [ -n "${VGW_REGION}" ]; then
        ARGS="$ARGS --region \"${VGW_REGION}\""
    fi

    # Certificate files for HTTPS
    if [ -n "${VGW_CERT}" ]; then
        ARGS="$ARGS --cert \"${VGW_CERT}\""
    fi

    if [ -n "${VGW_KEY}" ]; then
        ARGS="$ARGS --key \"${VGW_KEY}\""
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
# Redact any --access or --secret arguments from log output for security
REDACTED_ARGS=$(echo "$ARGS" | sed -E 's/--access[[:space:]]+[^ ]+/--access ****/g' | sed -E 's/--secret[[:space:]]+[^ ]+/--secret ****/g')
echo "Command: $BIN $COMMAND $REDACTED_ARGS"
echo ""

# Execute with proper argument expansion
# shellcheck disable=SC2086
exec $BIN $COMMAND $ARGS
