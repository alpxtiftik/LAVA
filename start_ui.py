import http.server
import socketserver
import webbrowser
import threading
import os
import sys

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    # Disable logging to keep terminal clean
    def log_message(self, format, *args):
        pass

def start_server():
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"[+] LAVA UI Sunucusu başlatıldı!")
        print(f"[+] Lütfen tarayıcınızda şu adresi açın: http://localhost:{PORT}/ui/")
        print(f"[+] (Sunucuyu durdurmak için CTRL+C yapabilirsiniz)")
        httpd.serve_forever()

if __name__ == "__main__":
    if not os.path.exists("verdicts.json"):
        print("[!] UYARI: verdicts.json bulunamadı. Lütfen önce run_lava.ps1 ile sistemi çalıştırın.", file=sys.stderr)
        
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    
    url = f"http://localhost:{PORT}/ui/"
    print(f"[*] Tarayıcı otomatik açılıyor: {url}")
    webbrowser.open(url)
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[!] Sunucu durduruldu.")
        sys.exit(0)
