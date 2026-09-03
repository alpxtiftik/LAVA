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

_LAVA_CACHE = os.path.expanduser("~/.cache/lava")
# The scripts print this line once they know where the run's output goes.
_OUTPUT_DIR_MARKER = re.compile(rb"LAVA_OUTPUT_DIR=(\S+)")


class Api:
    def __init__(self):
        self.current_log_file = None
        self.last_output_dir = None  # captured from the scan's stdout marker

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
                    "SCAN_PROFILE", "S99_SCAN", "MCP_BATCH_SIZE", "CVE_SCAN_ENABLED")
    _CONFIG_DEFAULTS = {
        "AI_PROVIDER": "local", "GEMINI_API_KEY": "",
        "CUSTOM_GREP_ENABLED": "0", "SCAN_PROFILE": "iot-testing",
        "S99_SCAN": "raw", "MCP_BATCH_SIZE": "40", "CVE_SCAN_ENABLED": "0",
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

    def start_scan(self, input_path, mode="log", modules=None):
        global scan_process
        input_path = input_path.strip()
        if not input_path:
            return {"status": "error", "message": "Input path required"}

        if scan_process and scan_process.poll() is None:
            return {"status": "error", "message": "Scan already running"}

        # modules: list/str of "credentials" and/or "cve"; None -> script default
        mod_arg = []
        if modules:
            if isinstance(modules, str):
                modules = [modules]
            picked = [m for m in ("credentials", "cve") if m in modules]
            if not picked:
                return {"status": "error", "message": "Select at least one module (Credentials / CVE)."}
            mod_arg = ["-Modules", ",".join(picked)]

        try:
            self.last_output_dir = None
            if mode == "firmware":
                # run_emba_lava.sh picks the output locations itself
                # (emba_<name>_<ts>/ and lava_scan_<name>_<ts>/ next to the
                # firmware, or under ~/.cache/lava if the path isn't EMBA-safe).
                sh_path = os.path.join(APP_DIR, "scripts", "run_emba_lava.sh")
                cmd = ["bash", sh_path, "-FirmwarePath", input_path, *mod_arg]
            else:
                sh_path = os.path.join(APP_DIR, "scripts", "run_lava.sh")
                cmd = ["bash", sh_path, "-LogDir", input_path, *mod_arg]

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

            # Persist the raw terminal output to a stable location (the real
            # output dir is only known once the script prints its marker).
            os.makedirs(_LAVA_CACHE, exist_ok=True)
            self.current_log_file = os.path.join(_LAVA_CACHE, "last_scan.log")
            try:
                open(self.current_log_file, "w").close()
            except Exception:
                self.current_log_file = None

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

                    m = _OUTPUT_DIR_MARKER.search(chunk)
                    if m:
                        try:
                            self.last_output_dir = m.group(1).decode("utf-8", "replace")
                        except Exception:
                            pass

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
            # `log_dir` is a HINT the UI passes back to get_verdicts(); the real
            # output dir is resolved later (marker / newest sibling dir).
            return {"status": "success", "message": msg, "log_dir": input_path}
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

    def _is_emba_logdir(self, d):
        return os.path.isdir(d) and (
            os.path.isdir(os.path.join(d, "csv_logs"))
            or os.path.isfile(os.path.join(d, "emba.log"))
            or os.path.isdir(os.path.join(d, "s99_grepit"))
            or os.path.isdir(os.path.join(d, "s106_deep_key_search")))

    def _resolve_emba_logdir(self, hint):
        """The selected path, or an EMBA log dir one level inside it."""
        hint = os.path.expanduser(hint)
        if self._is_emba_logdir(hint):
            return hint
        for cand in ([os.path.join(hint, "emba_logs")] +
                     [os.path.join(hint, d) for d in sorted(os.listdir(hint))] if os.path.isdir(hint) else []):
            if self._is_emba_logdir(cand):
                return cand
        return hint

    def _get_latest_out_dir(self, hint):
        """Resolve where a run wrote its output. Priority:
        1. the marker line the running/last script printed
        2. newest 'lava_scan_*' (firmware hint) / 'lava_out_*' (log-dir hint)
           dir next to the target, or under ~/.cache/lava
        3. legacy layout: <log_dir>/lava_out/<timestamp>/
        """
        if self.last_output_dir and os.path.isdir(self.last_output_dir):
            return self.last_output_dir

        # A scan is running but has not printed its LAVA_OUTPUT_DIR marker yet
        # (still in EMBA). Do NOT fall back to a PREVIOUS run's directory - that
        # would show stale findings for the whole EMBA phase.
        if scan_process is not None and scan_process.poll() is None:
            return os.path.join(_LAVA_CACHE, "__scan_pending__")

        hint = os.path.expanduser(hint or "")
        cands = []
        if os.path.isfile(hint):                       # firmware path
            bases, prefixes = [os.path.dirname(hint), _LAVA_CACHE], ("lava_scan_",)
        else:                                          # EMBA log dir (or its parent)
            emba = self._resolve_emba_logdir(hint)
            bases = [os.path.dirname(emba), _LAVA_CACHE]
            prefixes = ("lava_out_", "lava_scan_")
        for b in bases:
            try:
                for d in os.listdir(b):
                    p = os.path.join(b, d)
                    if os.path.isdir(p) and d.startswith(prefixes):
                        cands.append(p)
            except OSError:
                pass
        def _legacy_descent(d):
            # old layout put the run under <d>/lava_out/<timestamp>/
            lo = os.path.join(d, "lava_out")
            try:
                ts = sorted((x for x in os.listdir(lo)
                             if x.startswith("20") and os.path.isdir(os.path.join(lo, x))), reverse=True)
                if ts:
                    return os.path.join(lo, ts[0])
            except OSError:
                pass
            return None

        if cands:
            best = max(cands, key=os.path.getmtime)
            if not any(os.path.exists(os.path.join(best, f)) for f in
                       ("verdicts.json", "enriched_findings.json", "cve_findings.json")):
                return _legacy_descent(best) or best
            return best

        return _legacy_descent(hint) or os.path.join(hint, "lava_out")

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

    def get_cve_findings(self, log_dir):
        """CVE module output (cve_findings.json). [] when the CVE module did not
        run or produced nothing."""
        if not log_dir:
            return []
        out_dir = self._get_latest_out_dir(log_dir)
        cve_path = os.path.join(out_dir, "cve_findings.json")
        if os.path.exists(cve_path):
            try:
                with open(cve_path, "r", encoding="utf-8") as f:
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
        cve_file = os.path.join(out_dir, "cve_findings.json")
        report_file = os.path.join(out_dir, "lava_report.html")

        generator_script = os.path.join(APP_DIR, "src", "reporting", "html_report.py")
        cmd = ["python3", generator_script, "--out", report_file]
        if os.path.exists(verdicts_file):
            cmd += ["--verdicts", verdicts_file]
        if os.path.exists(cve_file):
            cmd += ["--cve-findings", cve_file]
        if "--verdicts" not in cmd and "--cve-findings" not in cmd:
            return {"status": "error", "message": "No results found. Please run a scan first."}

        try:
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
