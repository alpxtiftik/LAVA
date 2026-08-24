import os
import sys
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
    # Uygulama kök dizini LAVA klasörüdür
    APP_DIR = os.path.dirname(DIRECTORY)

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

    def start_scan(self, log_dir):
        global scan_process
        log_dir = log_dir.strip()
        if not log_dir:
            return {"status": "error", "message": "logDir required"}
        
        if scan_process and scan_process.poll() is None:
            return {"status": "error", "message": "Scan already running"}
        
        try:
            if sys.platform == "win32":
                CREATE_NO_WINDOW = 0x08000000
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                ps1_path = os.path.join(APP_DIR, "cli", "run_lava.ps1")
                cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps1_path, "-LogDir", log_dir]
                scan_process = subprocess.Popen(
                    cmd, 
                    creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                    cwd=APP_DIR
                )
            else:
                sh_path = os.path.join(APP_DIR, "cli", "run_lava.sh")
                cmd = ["bash", sh_path, "-LogDir", log_dir]
                scan_process = subprocess.Popen(
                    cmd, 
                    preexec_fn=os.setsid,
                    cwd=APP_DIR
                )
            return {"status": "success", "message": "Started"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def stop_scan(self):
        global scan_process
        if scan_process and scan_process.poll() is None:
            try:
                if sys.platform == "win32":
                    os.kill(scan_process.pid, signal.CTRL_BREAK_EVENT)
                else:
                    os.killpg(os.getpgid(scan_process.pid), signal.SIGTERM)
                scan_process.terminate()
            except Exception:
                pass
            scan_process = None
            return {"status": "success", "message": "Stopped"}
        return {"status": "success", "message": "Not running"}

    def get_status(self):
        global scan_process
        is_running = scan_process is not None and scan_process.poll() is None
        return {"running": is_running}

    def get_verdicts(self):
        verdicts_path = os.path.join(APP_DIR, "verdicts.json")
        if os.path.exists(verdicts_path):
            try:
                with open(verdicts_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                return {"error": str(e)}
        return []

if __name__ == "__main__":
    verdicts_path = os.path.join(APP_DIR, "verdicts.json")
    if not os.path.exists(verdicts_path):
        print("[!] UYARI: verdicts.json mevcut dizinde bulunamadı. Uygulama veri gösteremeyebilir.", file=sys.stderr)
        
    html_file = os.path.join(DIRECTORY, "ui", "index.html")
    print(f"[*] LAVA Masaüstü Arayüzü başlatılıyor...")
    
    # PyWebView ile yerel masaüstü penceresi oluştur
    api = Api()
    webview.create_window(
        title='LAVA - Local AI Vulnerability Auditor',
        url=html_file,
        width=1280,
        height=800,
        resizable=True,
        js_api=api
    )
    
    webview.start()
    
    print("\n[!] Uygulama sonlandırıldı.")
    if scan_process and scan_process.poll() is None:
        try:
            if sys.platform == "win32":
                os.kill(scan_process.pid, signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(os.getpgid(scan_process.pid), signal.SIGTERM)
            scan_process.terminate()
        except:
            pass
    sys.exit(0)
