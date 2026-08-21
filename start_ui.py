import http.server
import socketserver
import threading
import os
import sys
import webview
import subprocess
import signal
import json

PORT = 8000
scan_process = None

# PyInstaller .exe olarak paketlendiğinde geçici klasörü (_MEIPASS) kullan, aksi halde mevcut dizini kullan
if getattr(sys, 'frozen', False):
    DIRECTORY = sys._MEIPASS
else:
    DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Api:
    def open_folder_dialog(self):
        try:
            # We must run this in the webview's context. The first window is our main window.
            window = webview.windows[0]
            result = window.create_file_dialog(webview.FOLDER_DIALOG, allow_multiple=False)
            if result and len(result) > 0:
                # webview returns a tuple of paths, we need the first one
                return result[0]
        except Exception as e:
            print(f"Dialog error: {e}")
        return ""

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    # Konsolu temiz tutmak için logları kapat
    def log_message(self, format, *args):
        pass

    def translate_path(self, path):
        # verdicts.json'ın _MEIPASS (geçici exe klasörü) içinden değil, 
        # exe'nin çalıştırıldığı klasörden okunmasını sağla
        if path.endswith("/verdicts.json"):
            return os.path.join(os.getcwd(), "verdicts.json")
        return super().translate_path(path)
        
    def do_GET(self):
        global scan_process
        if self.path == "/api/status":
            is_running = scan_process is not None and scan_process.poll() is None
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"running": is_running}).encode('utf-8'))
            return
        return super().do_GET()

    def do_POST(self):
        global scan_process
        if self.path == "/api/start":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(post_data)
                log_dir = data.get("logDir", "").strip()
                if not log_dir:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"logDir required")
                    return
                
                if scan_process and scan_process.poll() is None:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Scan already running")
                    return
                
                if sys.platform == "win32":
                    CREATE_NEW_PROCESS_GROUP = 0x00000200
                    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", "run_lava.ps1", "-LogDir", log_dir]
                    scan_process = subprocess.Popen(
                        cmd, 
                        creationflags=CREATE_NEW_PROCESS_GROUP,
                        cwd=os.getcwd()
                    )
                else:
                    cmd = ["bash", "run_lava.sh", "-LogDir", log_dir]
                    scan_process = subprocess.Popen(
                        cmd, 
                        preexec_fn=os.setsid,
                        cwd=os.getcwd()
                    )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Started")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
            return
            
        if self.path == "/api/stop":
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
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Stopped")
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Not running")
            return
            
        self.send_response(404)
        self.end_headers()

def start_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"[+] LAVA UI Yerel Sunucusu başlatıldı (Port: {PORT})")
        httpd.serve_forever()

if __name__ == "__main__":
    if not os.path.exists("verdicts.json"):
        print("[!] UYARI: verdicts.json mevcut dizinde bulunamadı. Uygulama veri gösteremeyebilir.", file=sys.stderr)
        
    # Sunucuyu arka planda (daemon thread) başlat
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    
    url = f"http://localhost:{PORT}/ui/"
    print(f"[*] LAVA Masaüstü Arayüzü başlatılıyor...")
    
    # PyWebView ile yerel masaüstü penceresi oluştur
    api = Api()
    webview.create_window(
        title='LAVA - Local AI Vulnerability Auditor',
        url=url,
        width=1280,
        height=800,
        resizable=True,
        js_api=api
    )
    
    # Ana thread'i bloklayarak pencereyi açık tut
    webview.start()
    
    print("\n[!] Uygulama sonlandırıldı.")
    # Kapatıldığında çalışan tarama varsa onu da öldür
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
