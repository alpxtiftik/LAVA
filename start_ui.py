import http.server
import socketserver
import threading
import os
import sys
import webview

PORT = 8000

# PyInstaller .exe olarak paketlendiğinde geçici klasörü (_MEIPASS) kullan, aksi halde mevcut dizini kullan
if getattr(sys, 'frozen', False):
    DIRECTORY = sys._MEIPASS
else:
    DIRECTORY = os.path.dirname(os.path.abspath(__file__))

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
    webview.create_window(
        title='LAVA - Local AI Vulnerability Assessor',
        url=url,
        width=1280,
        height=800,
        resizable=True
    )
    
    # Ana thread'i bloklayarak pencereyi açık tut (pencere kapanınca start() döner)
    webview.start()
    
    print("\n[!] Uygulama sonlandırıldı.")
    sys.exit(0)
