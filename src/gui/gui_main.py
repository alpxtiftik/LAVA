import os
import sys
# pyrefly: ignore [missing-import]
import webview
import subprocess
import signal
import json
import base64
import threading
import datetime
import re
import pty
import fcntl
import termios
import struct

scan_process = None
scan_buffer = bytearray()
scan_buffer_lock = threading.Lock()
master_fd_global = None

# The application root is the LAVA folder (src/gui -> parent src -> parent LAVA)
DIRECTORY = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.dirname(os.path.dirname(DIRECTORY))

class Api:
    def __init__(self):
        self.current_log_file = None

    def open_folder_dialog(self):
        try:
            window = webview.windows[0]
            result = window.create_file_dialog(webview.FOLDER_DIALOG, allow_multiple=False)
            if result and len(result) > 0:
                return result[0]
        except Exception as e:
            print(f"Dialog error: {e}")
        return ""

    def open_file_dialog(self):
        try:
            window = webview.windows[0]
            result = window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False)
            if result and len(result) > 0:
                return result[0]
        except Exception as e:
            print(f"Dialog error: {e}")
        return ""

    _CONFIG_KEYS = ("AI_PROVIDER", "GEMINI_API_KEY", "CUSTOM_GREP_ENABLED",
                    "SCAN_PROFILE", "S99_SCAN", "MCP_BATCH_SIZE")
    _CONFIG_DEFAULTS = {
        "AI_PROVIDER": "local", "GEMINI_API_KEY": "",
        "CUSTOM_GREP_ENABLED": "0", "SCAN_PROFILE": "iot-testing",
        "S99_SCAN": "narrow", "MCP_BATCH_SIZE": "40",
    }

    def _config_path(self):
        return os.path.join(APP_DIR, "config", "ai_config.env")

    def get_ai_config(self):
        config = dict(self._CONFIG_DEFAULTS)
        path = self._config_path()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    if key in self._CONFIG_KEYS:
                        config[key] = val.strip().strip('"\'')
        return config

    def save_ai_config(self, new_config):
        path = self._config_path()
        lines = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()

        # Only touch keys the UI actually sent
        to_set = {k: str(new_config[k]) for k in self._CONFIG_KEYS if k in new_config}
        found = {k: False for k in to_set}
        for i, line in enumerate(lines):
            stripped = line.strip()
            for k, v in to_set.items():
                if stripped.startswith(k + "="):
                    lines[i] = f'{k}="{v}"\n'
                    found[k] = True

        if lines and not lines[-1].endswith('\n'):
            lines[-1] = lines[-1] + '\n'
        for k, v in to_set.items():
            if not found[k]:
                lines.append(f'{k}="{v}"\n')

        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        return {"status": "success"}

    def list_scan_profiles(self):
        """Names of the JSON profiles in config/scan_profiles/ (and local/)."""
        base = os.path.join(APP_DIR, "config", "scan_profiles")
        names = []
        for root in (base, os.path.join(base, "local")):
            if not os.path.isdir(root):
                continue
            for fn in sorted(os.listdir(root)):
                if fn.endswith(".json"):
                    names.append(fn[:-5])
        return names or ["iot-testing"]

    def start_scan(self, input_path, mode="log"):
        global scan_process
        input_path = input_path.strip()
        if not input_path:
            return {"status": "error", "message": "Input path required"}

        if scan_process and scan_process.poll() is None:
            return {"status": "error", "message": "Scan already running"}

        try:
            log_dir = None
            if mode == "firmware":
                sh_path = os.path.join(APP_DIR, "scripts", "run_emba_lava.sh")
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                # Mirror run_emba_lava.sh: EMBA rejects anything outside
                # [a-zA-Z0-9./_~-] in its -l path, so the leaf name is sanitized;
                # if the parent dir itself is not EMBA-safe, relocate to ~/.cache/lava.
                parent = os.path.dirname(input_path)
                leaf = "lava_scan_" + re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(input_path)) + "_" + timestamp
                if re.search(r"[^A-Za-z0-9./_~-]", parent):
                    log_dir = os.path.join(os.path.expanduser("~/.cache/lava"), leaf)
                else:
                    log_dir = os.path.join(parent, leaf)
                cmd = ["bash", sh_path, "-FirmwarePath", input_path, "-LogDir", log_dir]
            else:
                sh_path = os.path.join(APP_DIR, "scripts", "run_lava.sh")
                cmd = ["bash", sh_path, "-LogDir", input_path]

            global scan_buffer, master_fd_global
            with scan_buffer_lock:
                scan_buffer.clear()

            master_fd, slave_fd = pty.openpty()
            master_fd_global = master_fd
            winsize = struct.pack("HHHH", 30, 120, 0, 0)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

            env = os.environ.copy()
            env["TERM"] = "xterm-256color"
            env["LAVA_GUI_MODE"] = "1"

            scan_process = subprocess.Popen(
                cmd,
                preexec_fn=os.setsid,
                cwd=APP_DIR,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env
            )
            os.close(slave_fd)

            actual_log_dir = log_dir if mode == "firmware" else input_path

            # Do not create the log directory beforehand if we are running EMBA (firmware mode)
            # because EMBA checks if the log directory is empty and prompts for deletion.
            if mode == "firmware":
                self.current_log_file = None
            else:
                lava_out_dir = os.path.join(actual_log_dir, "lava_out")
                os.makedirs(lava_out_dir, exist_ok=True)
                self.current_log_file = os.path.join(lava_out_dir, "lava_scan.log")
                open(self.current_log_file, 'w').close()

            def _reader():
                while True:
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    with scan_buffer_lock:
                        scan_buffer.extend(chunk)

                    if self.current_log_file:
                        try:
                            with open(self.current_log_file, "ab") as f:
                                f.write(chunk)
                        except Exception:
                            pass

            threading.Thread(target=_reader, daemon=True).start()

            msg = f"Started LAVA pipeline for {input_path}"
            if mode == "firmware":
                msg = f"Started EMBA + LAVA pipeline for firmware {input_path}"
            return {"status": "success", "message": msg, "log_dir": log_dir if mode == "firmware" else input_path}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def stop_scan(self):
        global scan_process
        if scan_process and scan_process.poll() is None:
            try:
                os.killpg(os.getpgid(scan_process.pid), signal.SIGTERM)
            except Exception:
                scan_process.terminate()
            scan_process = None
            return {"status": "success"}
        return {"status": "error", "message": "No scan running"}

    def get_status(self):
        global scan_process
        if scan_process is not None:
            poll = scan_process.poll()
            return {"running": poll is None, "exit_code": poll}
        return {"running": False}

    def resize_pty(self, rows, cols):
        global master_fd_global
        if master_fd_global is not None:
            try:
                winsize = struct.pack("HHHH", int(rows), int(cols), 0, 0)
                fcntl.ioctl(master_fd_global, termios.TIOCSWINSZ, winsize)
                return {"status": "success"}
            except Exception as e:
                return {"status": "error", "message": str(e)}
        return {"status": "ignored"}

    def get_scan_logs(self, last_offset=0):
        global scan_buffer
        with scan_buffer_lock:
            data = bytes(scan_buffer[last_offset:])
            new_offset = len(scan_buffer)
        if data:
            return {"data": base64.b64encode(data).decode("ascii"), "offset": new_offset}
        return {"data": "", "offset": last_offset}

    def save_terminal_log(self):
        try:
            window = webview.windows[0]
            result = window.create_file_dialog(webview.SAVE_DIALOG, save_filename='lava_terminal_log.txt')
            if result and len(result) > 0:
                save_path = result[0]
                global scan_buffer
                with scan_buffer_lock:
                    data = bytes(scan_buffer)

                # Strip ANSI codes for clean text file
                data_str = data.decode('utf-8', 'replace')
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                clean_data = ansi_escape.sub('', data_str)

                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(clean_data)
                return {"status": "success", "path": save_path}
        except Exception as e:
            return {"status": "error", "message": str(e)}
        return {"status": "cancelled"}

    def _get_latest_out_dir(self, log_dir):
        base_out = os.path.join(log_dir, "lava_out")
        if not os.path.exists(base_out):
            return base_out
        try:
            dirs = [d for d in os.listdir(base_out) if os.path.isdir(os.path.join(base_out, d)) and d.startswith("20")]
            if not dirs:
                return base_out
            dirs.sort(reverse=True)
            return os.path.join(base_out, dirs[0])
        except Exception:
            return base_out

    def get_verdicts(self, log_dir):
        if not log_dir:
            return []
        out_dir = self._get_latest_out_dir(log_dir)
        verdicts_path = os.path.join(out_dir, "verdicts.json")
        if os.path.exists(verdicts_path):
            try:
                with open(verdicts_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                return {"error": str(e)}
        return []

    def get_total_findings(self, log_dir):
        if not log_dir:
            return {"total": 0}
        out_dir = self._get_latest_out_dir(log_dir)
        enriched_path = os.path.join(out_dir, "enriched_findings.json")
        if os.path.exists(enriched_path):
            try:
                with open(enriched_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return {"total": len(data)}
            except Exception:
                pass
        return {"total": 0}

    def export_html(self, log_dir):
        if not log_dir:
            return {"status": "error", "message": "logDir required"}

        out_dir = self._get_latest_out_dir(log_dir)
        verdicts_file = os.path.join(out_dir, "verdicts.json")
        report_file = os.path.join(out_dir, "lava_report.html")

        if not os.path.exists(verdicts_file):
            return {"status": "error", "message": "No verdicts.json found. Please run a scan first."}

        try:
            generator_script = os.path.join(APP_DIR, "src", "reporting", "html_report.py")
            cmd = ["python3", generator_script, "--verdicts", verdicts_file, "--out", report_file]
            subprocess.check_call(cmd)

            filepath = os.path.abspath(report_file)
            subprocess.call(["xdg-open", filepath])

            return {"status": "success", "path": report_file}
        except Exception as e:
            return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    html_file = os.path.join(DIRECTORY, "ui", "index.html")
    print("[*] Starting the LAVA desktop UI...")

    # Create a native desktop window with PyWebView
    api = Api()
    window = webview.create_window(
        title='LAVA - Local AI Vulnerability Auditor',
        url=html_file,
        width=1280,
        height=800,
        resizable=True,
        js_api=api
    )

    def on_closing():
        try:
            api.stop_scan()
        except Exception:
            pass
        # Do not return False, because returning False cancels the close event in pywebview

    window.events.closing += on_closing

    webview.start()

    print("\n[!] Application closed.")
    if 'scan_process' in globals() and scan_process and scan_process.poll() is None:
        try:
            os.killpg(os.getpgid(scan_process.pid), signal.SIGTERM)
            scan_process.terminate()
        except Exception:
            pass
    sys.exit(0)
