#!/usr/bin/env bash
# PVE ONLY. Temporary one-shot authenticated upload of one known SHA256 APK.
# Listens only on the Tailscale IP, with automatic 20-minute shutdown.
# No SSH password policy or firewall changes; no effects on CT103 or releases.
set -Eeuo pipefail
umask 077

STAGE=/root/multiservis-android110-transfer
BIND=100.121.109.73
PORT=38471
EXPECTED=002700716b62db2fb007e34393846fab724eac5f92735612bce95111457505c6

[[ ${EUID} -eq 0 ]] || { echo "BLOCKED: run as root in PVE console."; exit 1; }
command -v python3 >/dev/null || { echo "BLOCKED: python3 missing"; exit 1; }
command -v systemd-run >/dev/null || { echo "BLOCKED: systemd-run missing"; exit 1; }
ip -o -4 addr show | grep -Fq " $BIND/" || { echo "BLOCKED: Tailscale address $BIND not found on PVE"; exit 1; }
install -d -m 0700 "$STAGE"
for old in "$STAGE/app-release-unsigned.apk" "$STAGE/app-release-unsigned.apk.sha256"; do
    [[ ! -e "$old" ]] || { echo "BLOCKED: file already exists: $old. Do not overwrite."; exit 1; }
done
# Previous upload attempts may have left an active single-use receiver.
# Restart only OUR transient units, making any previous shared/incorrect
# token invalid, and then start a new 20-minute receiver.
while IFS= read -r unit; do
    [[ "$unit" =~ ^multiservis-android110-upload-[0-9]+[.]service$ ]] || continue
    systemctl stop "$unit" >/dev/null || true
done < <(
    systemctl list-units --all --plain --no-legend 'multiservis-android110-upload-*.service' 2>/dev/null |
       awk '{print $1}'
)
TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
printf '%s' "$TOKEN" > "$STAGE/.upload-token"
chmod 0600 "$STAGE/.upload-token"
cat > "$STAGE/.upload-receiver.py" <<'PY'
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

STAGE=Path("/root/multiservis-android110-transfer")
TARGET=STAGE/"app-release-unsigned.apk"
SIDECAR=STAGE/"app-release-unsigned.apk.sha256"
EXPECTED="002700716b62db2fb007e34393846fab724eac5f92735612bce95111457505c6"
BIND="100.121.109.73"
PORT=38471
MIN_SIZE=1000000
MAX_SIZE=150000000
TOKEN=(STAGE/".upload-token").read_text(encoding="ascii")

class Receiver(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Avoid writing authenticated URLs or private headers to journals.
        pass

    def reply(self, code, message):
        data=(message+"\n").encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type","text/plain; charset=utf-8")
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError):
            pass

    def do_POST(self):
        address=ipaddress.ip_address(self.client_address[0])
        if (self.path!="/android110" or
                address not in ipaddress.ip_network("100.64.0.0/10")):
            return self.reply(404,"Not found")
        supplied=self.headers.get("X-Upload-Token","")
        if not hmac.compare_digest(supplied,TOKEN):
            return self.reply(403,"Invalid one-time token")
        if TARGET.exists() or SIDECAR.exists():
            return self.reply(409,"APK is already present; will not overwrite")
        if self.headers.get("Transfer-Encoding"):
            return self.reply(411,"Use Content-Length")
        try:
            amount=int(self.headers.get("Content-Length","0"))
        except ValueError:
            return self.reply(411,"Bad Content-Length")
        if not MIN_SIZE <= amount <= MAX_SIZE:
            return self.reply(413,"APK file size out of range")
        fd,tmp=tempfile.mkstemp(prefix=".android110-upload-",dir=STAGE)
        digest=hashlib.sha256()
        received=0
        try:
            with os.fdopen(fd,"wb") as file:
                while received < amount:
                    chunk=self.rfile.read(min(1024*1024,amount-received))
                    if not chunk:
                        return self.reply(400,"Incomplete upload")
                    file.write(chunk)
                    digest.update(chunk)
                    received+=len(chunk)
                file.flush()
                os.fsync(file.fileno())
            if not hmac.compare_digest(digest.hexdigest(), EXPECTED):
                return self.reply(422,"APK checksum mismatch - nothing staged")
            os.chmod(tmp,0o600)
            os.replace(tmp,TARGET)
            SIDECAR.write_text(EXPECTED+"  app-release-unsigned.apk\n",encoding="ascii")
            os.chmod(SIDECAR,0o600)
            self.reply(201,"PASS: staged verified APK + SHA256. Run signing on PVE.")
            threading.Thread(target=self.server.shutdown,daemon=True).start()
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

if __name__=="__main__":
    HTTPServer.allow_reuse_address=True
    server=HTTPServer((BIND,PORT),Receiver)
    print(f"Android 1.10 one-shot receiver listening on {BIND}:{PORT}",flush=True)
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        server.server_close()
        (STAGE/".upload-token").unlink(missing_ok=True)
PY
chmod 0600 "$STAGE/.upload-receiver.py"
python3 -m py_compile "$STAGE/.upload-receiver.py"
UNIT="multiservis-android110-upload-$(date +%s)"
systemd-run --quiet --collect --unit="$UNIT" \
  --property=RuntimeMaxSec=1800 \
  /usr/bin/python3 -u "$STAGE/.upload-receiver.py"
sleep 1
systemctl is-active --quiet "$UNIT.service" ||
  { echo "BLOCKED: receiver failed to start. Inspect journalctl -u $UNIT"; exit 1; }
echo
echo "READY: ONE-TIME APK upload on PVE/Tailscale (20 minutes)."
echo "Windows target: http://$BIND:$PORT/android110"
echo "Temporary TOKEN (paste ONLY into Windows PowerShell prompt): $TOKEN"
echo "No GitHub secret/keystore involved; PVE accepts only preapproved APK SHA256."
