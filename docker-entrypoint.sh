#!/bin/sh
set -e

BIN="${VGW_BINARY:-/usr/local/bin/versitygw}"

if [ ! -x "$BIN" ]; then
    echo "Entrypoint error: versitygw binary not found at $BIN" >&2
    exit 1
fi

# If arguments were provided, run them directly for backward compatibility.
if [ "$#" -gt 0 ]; then
    exec "$BIN" "$@"
fi

backend="${VGW_BACKEND:-}"
if [ -z "$backend" ]; then
    cat >&2 <<'EOF'
No command arguments were provided and VGW_BACKEND is unset.
Set VGW_BACKEND to one of: posix, scoutfs, s3, azure, plugin
or pass explicit arguments to the container to run the versitygw command directly.
EOF
    exit 1
fi

case "$backend" in
    posix|scoutfs|s3|azure|plugin)
        ;;
    *)
        echo "VGW_BACKEND invalid backend (was '$backend')." >&2
        exit 1
        ;;
esac

set -- "$backend"

if [ -n "${VGW_BACKEND_ARG:-}" ]; then
    set -- "$@" "$VGW_BACKEND_ARG"
fi

if [ -n "${VGW_BACKEND_ARGS:-}" ]; then
    # shellcheck disable=SC2086
    set -- "$@" ${VGW_BACKEND_ARGS}
fi

if [ -n "${VGW_ARGS:-}" ]; then
    # shellcheck disable=SC2086
    set -- "$@" ${VGW_ARGS}
fi

exec "$BIN" "$@"
