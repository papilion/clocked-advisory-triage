#!/usr/bin/env bash
# Start the Streamlit app on port 8501 if it is not already running.
#
# Called from both postCreateCommand and postStartCommand in
# devcontainer.json: postStartCommand does not reliably fire in every
# Codespaces environment, so startup must also work from postCreate.
# Idempotent: safe to run any number of times; exits 0 without
# launching a duplicate when something already listens on 8501.

PORT=8501
LOG=/tmp/streamlit.log

port_listening() {
    python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(2)
try:
    s.connect(('127.0.0.1', ${PORT}))
except OSError:
    sys.exit(1)
else:
    sys.exit(0)
finally:
    s.close()
"
}

if port_listening; then
    echo "start_app: port ${PORT} already listening, nothing to do."
    exit 0
fi

# Run from the workspace root (this script lives in .devcontainer/).
cd "$(dirname "$0")/.." || exit 0

echo "start_app: launching streamlit on port ${PORT} (log: ${LOG})"
nohup streamlit run app.py \
    --server.port "${PORT}" \
    --server.address 0.0.0.0 \
    --server.enableCORS false \
    --server.enableXsrfProtection false \
    > "${LOG}" 2>&1 &

# Poll up to ~30s for the port to accept connections.
for _ in $(seq 1 30); do
    if port_listening; then
        echo "start_app: app is up on port ${PORT}."
        exit 0
    fi
    sleep 1
done

echo "start_app: port ${PORT} did not come up within 30s; last log lines:"
tail -n 20 "${LOG}" 2>/dev/null || true
exit 0
