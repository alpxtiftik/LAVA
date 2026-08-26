import os
import sys
# pyrefly: ignore [missing-import]
import webview
import subprocess
import signal
import json

scan_process = None

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

    def start_scan(self, input_path, mode="log"):
        global scan_process
        input_path = input_path.strip()
        if not input_path:
            return {"status": "error", "message": "Input path required"}
        
        if scan_process and scan_process.poll() is None:
            return {"status": "error", "message": "Scan already running"}
        
        try:
            if sys.platform == "win32":
                CREATE_NO_WINDOW = 0x08000000
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                
                if mode == "firmware":
                    ps1_path = os.path.join(APP_DIR, "scripts", "run_emba_lava.ps1")
                    log_dir = os.path.join(os.path.dirname(input_path), "emba_logs_" + os.path.basename(input_path))
                    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps1_path, "-FirmwarePath", input_path, "-LogDir", log_dir]
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
                    log_dir = os.path.join(os.path.dirname(input_path), "emba_logs_" + os.path.basename(input_path))
                    cmd = ["bash", sh_path, "-FirmwarePath", input_path, "-LogDir", log_dir]
                else:
                    sh_path = os.path.join(APP_DIR, "scripts", "run_lava.sh")
                    cmd = ["bash", sh_path, "-LogDir", input_path]
                    
                log_out = open(os.path.join(APP_DIR, "lava_scan.log"), "w", encoding="utf-8")
                scan_process = subprocess.Popen(
                    cmd, 
                    preexec_fn=os.setsid,
                    cwd=APP_DIR,
                    stdout=log_out,
                    stderr=subprocess.STDOUT
                )
            
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

    def get_scan_logs(self):
        log_file = os.path.join(APP_DIR, "lava_scan.log")
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    # Return the last 100 lines for the embedded terminal
                    return "".join(lines[-100:])
            except Exception:
                pass
        return ""

    def get_verdicts(self, log_dir):
        if not log_dir:
            return []
        verdicts_path = os.path.join(log_dir, "lava_out", "verdicts.json")
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
        enriched_path = os.path.join(log_dir, "lava_out", "enriched_findings.json")
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
            
        out_dir = os.path.join(log_dir, "lava_out")
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
    
    window.events.closing += api.stop_scan
    
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
