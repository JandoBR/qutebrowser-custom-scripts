import socket
import json
import subprocess
import os
import secrets
import shlex
import sys
import ctypes
import time # Added for sleep/timeout

# Configuration
SOCKET_PATH = "/tmp/bw.sock"
TOKEN_PATH = "/tmp/bw_token"
PASS_PROMPT = 'rofi -dmenu -p "Master Password" -password -lines 0'

def lock_memory():
    try:
        libc = ctypes.CDLL('libc.so.6')
        libc.mlockall(3)
    except Exception as e:
        print(f"Memory lock failed: {e}")

def get_vault():
    while True:
        try:
            # 1. Ask for password
            proc = subprocess.run(shlex.split(PASS_PROMPT), text=True, capture_output=True)

            # If user hits Escape or cancels Rofi
            if proc.returncode != 0:
                sys.exit(0)

            master_pass = proc.stdout.strip()

            # 2. Attempt Unlock
            unlock_proc = subprocess.run(
                ['bw', 'unlock', '--raw', '--passwordenv', 'BW_MASTERPASS'],
                env={**os.environ, 'BW_MASTERPASS': master_pass},
                text=True,
                capture_output=True
            )

            if unlock_proc.returncode != 0:
                subprocess.run(['notify-send', 'Bitwarden', 'Invalid master password. Please try again.'])
                continue

            session_key = unlock_proc.stdout.strip()

            # 3. Pull Data
            print("Syncing vault into RAM...")
            data = subprocess.check_output(['bw', 'list', 'items', '--session', session_key], text=True)
            return json.loads(data)

        except Exception as e:
            subprocess.run(['notify-send', 'Bitwarden Daemon Error', str(e)])
            sys.exit(1)

def rotate_token():
    new_token = secrets.token_hex(16)
    with open(TOKEN_PATH, 'w') as f:
        f.write(new_token)
    os.chmod(TOKEN_PATH, 0o600)
    return new_token

def start_daemon():
    try:
        # Looking for the qutebrowser process owned by the current user
        parent_pid = int(subprocess.check_output(["pgrep", "-u", os.environ.get("USER"), "^qutebrowser$"]).strip().split('\n')[0])
    except:
        # Fallback to current ppid if pgrep fails
        # TODO this fallback fails to kill the process
        parent_pid = os.getppid()

    lock_memory()
    vault = get_vault()
    auth_token = rotate_token()

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o600)
    server.listen(5)

    server.settimeout(2.0)

    print(f"Daemon ready. Monitoring PID: {parent_pid}")

    try:
        while True:
            try:
                os.kill(parent_pid, 0)
            except OSError:
                # Browser is gone
                break

            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue

            try:
                raw_data = conn.recv(4096).decode().strip()
                if not raw_data or ":" not in raw_data:
                    continue

                received_token, domain = raw_data.split(':', 1)

                if not secrets.compare_digest(received_token, auth_token):
                    conn.sendall(b"[]")
                    continue

                matches = []
                clean_domain = domain.lower().replace("https://", "").replace("http://", "").split('/')[0]

                for item in vault:
                    uris = (item.get('login') or {}).get('uris') or []
                    for u in uris:
                        val = (u.get('uri') or "").lower()
                        if val and (val in clean_domain or clean_domain in val):
                            matches.append(item)
                            break

                conn.sendall(json.dumps(matches).encode())
                auth_token = rotate_token()

            except Exception as e:
                print(f"Error: {e}")
            finally:
                conn.close()
    finally:
        # Cleanup files when browser closes or daemon exits
        if os.path.exists(SOCKET_PATH): os.remove(SOCKET_PATH)
        if os.path.exists(TOKEN_PATH): os.remove(TOKEN_PATH)

if __name__ == "__main__":
    start_daemon()
