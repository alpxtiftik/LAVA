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

if sys.platform != "win32":
    import pty
    import fcntl
    import termios
    import struct

scan_process = None
scan_buffer = bytearray()
scan_buffer_lock = threading.Lock()
master_fd_global = None

# PyInstaller .exe olarak paketlendiğinde geçici klasörü (_MEIPASS) kullan, aksi halde mevcut dizini kullan
if getattr(sys, 'frozen', False):
    DIRECTORY = sys._MEIPASS
    # Uygulama dizini, exe'nin bulunduğu yerdir
    APP_DIR = os.path.dirname(sys.executable)
else:
    DIRECTORY = os.path.dirname(os.path.abspath(__file__))
    # Uygulama kök dizini LAVA klasörüdür (src/gui -> üstü src -> üstü LAVA)
    APP_DIR = os.path.dirname(os.path.dirname(DIRECTORY))

class Api:
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

    def get_platform(self):
        return sys.platform

    def get_ai_config(self):
        config_path = os.path.join(APP_DIR, "config", "ai_config.env")
        config = {"AI_PROVIDER": "local", "GEMINI_API_KEY": ""}
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("AI_PROVIDER="):
                        config["AI_PROVIDER"] = line.split("=", 1)[1].strip('"\' ')
                    elif line.startswith("GEMINI_API_KEY="):
                        config["GEMINI_API_KEY"] = line.split("=", 1)[1].strip('"\' ')
        return config

    def save_ai_config(self, new_config):
        config_path = os.path.join(APP_DIR, "config", "ai_config.env")
        lines = []
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        
        provider = new_config.get("AI_PROVIDER", "local")
        gemini_key = new_config.get("GEMINI_API_KEY", "")
        
        provider_found = False
        gemini_found = False
        
        for i, line in enumerate(lines):
            if line.strip().startswith("AI_PROVIDER="):
                lines[i] = f'AI_PROVIDER="{provider}"\n'
                provider_found = True
            elif line.strip().startswith("GEMINI_API_KEY="):
                lines[i] = f'GEMINI_API_KEY="{gemini_key}"\n'
                gemini_found = True
                
        # Son satırda newline yoksa ekle
        if lines and not lines[-1].endswith('\n'):
            lines[-1] = lines[-1] + '\n'
            
        if not provider_found:
            lines.append(f'AI_PROVIDER="{provider}"\n')
        if not gemini_found:
            lines.append(f'GEMINI_API_KEY="{gemini_key}"\n')
            
        with open(config_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        return {"status": "success"}

    def start_scan(self, input_path, mode="log"):
        global scan_process
        input_path = input_path.strip()
        if not input_path:
            return {"status": "error", "message": "Input path required"}
        
        if scan_process and scan_process.poll() is None:
            return {"status": "error", "message": "Scan already running"}
        
        try:
            log_dir = None
            if sys.platform == "win32":
                CREATE_NO_WINDOW = 0x08000000
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                
                if mode == "firmware":
                    return {"status": "error", "message": "Windows uzerinde otomatik EMBA calistirma (WSL kisitlamalari nedeniyle) desteklenmemektedir. Lutfen EMBA'yi native Linux uzerinde calistirip log dizinini secin."}
                else:
                    ps1_path = os.path.join(APP_DIR, "scripts", "run_lava.ps1")
                    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps1_path, "-LogDir", input_path]
                    
                log_out = open(os.path.join(APP_DIR, "lava_scan.log"), "w", encoding="utf-8")
                scan_process = subprocess.Popen(
                    cmd, 
                    creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                    cwd=APP_DIR,
                    stdout=log_out,
                    stderr=subprocess.STDOUT
                )
            else:
                if mode == "firmware":
                    sh_path = os.path.join(APP_DIR, "scripts", "run_emba_lava.sh")
                    base_log_dir = os.path.join(os.path.dirname(input_path), "emba_logs_" + os.path.basename(input_path))
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    log_dir = f"{base_log_dir}_{timestamp}"
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
            if sys.platform == "win32":
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(scan_process.pid)], creationflags=subprocess.CREATE_NO_WINDOW)
                # Cleanup WSL ghost processes to be safe
                subprocess.call(['wsl', '-u', 'root', '--', 'bash', '-c', 'pkill -f emba; pkill -f run_emba; docker ps -q | xargs -r docker stop'], creationflags=subprocess.CREATE_NO_WINDOW)
            else:
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
        if sys.platform != "win32" and master_fd_global is not None:
            try:
                winsize = struct.pack("HHHH", int(rows), int(cols), 0, 0)
                fcntl.ioctl(master_fd_global, termios.TIOCSWINSZ, winsize)
                return {"status": "success"}
            except Exception as e:
                return {"status": "error", "message": str(e)}
        return {"status": "ignored"}

    def get_scan_logs(self, last_offset=0):
        # Linux (pty buffer)
        if sys.platform != "win32":
            global scan_buffer
            with scan_buffer_lock:
                data = bytes(scan_buffer[last_offset:])
                new_offset = len(scan_buffer)
            if data:
                return {"data": base64.b64encode(data).decode("ascii"), "offset": new_offset}
            return {"data": "", "offset": last_offset}
            
        # Windows (file buffer fallback)
        log_file = os.path.join(APP_DIR, "lava_scan.log")
        if os.path.exists(log_file):
            try:
                with open(log_file, "rb") as f:
                    f.seek(last_offset)
                    data = f.read()
                    new_offset = f.tell()
                    if data:
                        return {"data": base64.b64encode(data).decode("ascii"), "offset": new_offset}
            except Exception:
                pass
        return {"data": "", "offset": last_offset}

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
            python_exec = "py" if sys.platform == "win32" else "python3"
            cmd = [python_exec, generator_script, "--verdicts", verdicts_file, "--out", report_file]
            
            # Subprocess without console window on Windows
            if sys.platform == "win32":
                subprocess.check_call(cmd, creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                subprocess.check_call(cmd)
                
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(report_file))
                
            return {"status": "success", "path": report_file}
        except Exception as e:
            return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    html_file = os.path.join(DIRECTORY, "ui", "index.html")
    print(f"[*] LAVA Masaüstü Arayüzü başlatılıyor...")
    
    # PyWebView ile yerel masaüstü penceresi oluştur
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
    
    print("\n[!] Uygulama sonlandırıldı.")
    if 'scan_process' in globals() and scan_process and scan_process.poll() is None:
        try:
            if sys.platform == "win32":
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(scan_process.pid)], creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                os.killpg(os.getpgid(scan_process.pid), signal.SIGTERM)
            scan_process.terminate()
        except:
            pass
    sys.exit(0)
