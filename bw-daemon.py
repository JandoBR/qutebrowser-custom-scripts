import socket
import json
import subprocess
import os
import secrets
import shlex
import sys
import ctypes
import time
import threading
import logging

# Configuration
SOCKET_PATH = "/tmp/bw.sock"
TOKEN_PATH = "/tmp/bw_token"
LOG_FILE = "/tmp/bw-daemon.log"

# Point this to your ACTUAL Bitwarden CLI config directory
DAEMON_CONFIG_DIR = os.path.expanduser("~/.config/Bitwarden CLI")

PASS_PROMPT = 'rofi -dmenu -password -theme ~/.config/rofi/minimal.rasi -p "Bitwarden 🔐 "'
SYNC_INTERVAL = 600

# Ensure the config directory exists
os.makedirs(DAEMON_CONFIG_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Global state
vault_lock = threading.Lock()
vault_data = []
bw_session_key = ""

def lock_memory():
    try:
        libc = ctypes.CDLL('libc.so.6')
        libc.mlockall(3)
    except Exception as e:
        logging.error(f"Memory lock failed: {e}")

def get_initial_vault():
    global bw_session_key
    while True:
        try:
            proc = subprocess.run(shlex.split(PASS_PROMPT), text=True, capture_output=True)
            if proc.returncode != 0:
                sys.exit(0)

            master_pass = proc.stdout.strip()

            # Note: We use the daemon-specific config dir here too
            my_env = os.environ.copy()
            my_env['BITWARDENCLI_APPDATA_DIR'] = DAEMON_CONFIG_DIR

            unlock_proc = subprocess.run(
                ['bw', 'unlock', '--raw', '--passwordenv', 'BW_MASTERPASS'],
                env={**my_env, 'BW_MASTERPASS': master_pass},
                text=True,
                capture_output=True
            )

            if unlock_proc.returncode != 0:
                subprocess.run(['notify-send', 'Bitwarden', 'Invalid master password. Please try again.'])
                logging.warning("Failed unlock attempt.")
                continue

            bw_session_key = unlock_proc.stdout.strip()
            logging.info("Vault unlocked. Fetching initial data...")

            data = subprocess.check_output(
                ['bw', 'list', 'items', '--session', bw_session_key],
                env=my_env,
                text=True
            )
            return json.loads(data)

        except Exception as e:
            logging.exception("Critical error in get_initial_vault")
            sys.exit(1)

def sync_worker():
    global vault_data, bw_session_key
    # Initial grace period
    time.sleep(10)

    while True:
        try:
            logging.info("Starting background sync...")
            my_env = os.environ.copy()
            my_env['BITWARDENCLI_APPDATA_DIR'] = DAEMON_CONFIG_DIR

            # 1. Sync
            sync_res = subprocess.run(
                ['bw', 'sync', '--session', bw_session_key],
                env=my_env, capture_output=True, text=True
            )

            if sync_res.returncode != 0:
                logging.error(f"Sync failed: {sync_res.stderr.strip()}")
            else:
                # 2. Pull updated items only if sync succeeded
                raw_new_data = subprocess.check_output(
                    ['bw', 'list', 'items', '--session', bw_session_key],
                    env=my_env, text=True
                )
                with vault_lock:
                    vault_data = json.loads(raw_new_data)

                logging.info(f"Sync successful. Items in memory: {len(vault_data)}")
                subprocess.run(['notify-send', 'Bitwarden', 'Vault synced successfully'])

        except Exception as e:
            logging.exception("An unexpected error occurred during sync_worker loop")

        logging.info(f"Sync thread sleeping for {SYNC_INTERVAL}s")
        time.sleep(SYNC_INTERVAL)

def rotate_token():
    new_token = secrets.token_hex(16)
    with open(TOKEN_PATH, 'w') as f:
        f.write(new_token)
    os.chmod(TOKEN_PATH, 0o600)
    return new_token

def start_daemon():
    global vault_data

    qute_pid_env = os.environ.get("QUTE_PID")
    if qute_pid_env:
        parent_pid = int(qute_pid_env)
    else:
        try:
            parent_pid = int(subprocess.check_output(["pgrep", "-u", os.environ.get("USER"), "^qutebrowser$"]).strip().split('\n')[0])
        except:
            parent_pid = os.getppid()

    lock_memory()
    vault_data = get_initial_vault()

    threading.Thread(target=sync_worker, daemon=True).start()

    auth_token = rotate_token()

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o600)
    server.listen(5)
    server.settimeout(2.0)

    logging.info(f"Daemon ready. Monitoring PID: {parent_pid}")

    try:
        while True:
            try:
                os.kill(parent_pid, 0)
            except OSError:
                logging.info("Parent browser process ended. Exiting...")
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

                with vault_lock:
                    for item in vault_data:
                        uris = (item.get('login') or {}).get('uris') or []
                        for u in uris:
                            val = (u.get('uri') or "").lower()
                            if val and (val in clean_domain or clean_domain in val):
                                matches.append(item)
                                break

                conn.sendall(json.dumps(matches).encode())
                auth_token = rotate_token()

            except Exception as e:
                logging.error(f"Socket Error: {e}")
            finally:
                conn.close()
    finally:
        if os.path.exists(SOCKET_PATH): os.remove(SOCKET_PATH)
        if os.path.exists(TOKEN_PATH): os.remove(TOKEN_PATH)

if __name__ == "__main__":
    start_daemon()
