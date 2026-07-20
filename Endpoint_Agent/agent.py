import time
import requests
import psutil
import socket
import platform
import uuid
import getpass

# ==========================================
# SET-CDP Endpoint Agent
# ==========================================

SERVER_URL = "http://127.0.0.1:5000/api/agent/heartbeat"
API_KEY = "SET-CDP-AGENT-KEY"

def get_mac_address():
    mac = uuid.getnode()
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))

AGENT_ID = get_mac_address()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ---- الإضافة الجديدة: جلب العمليات ----
def get_top_processes():
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'exe']):
        try:
            info = proc.info
            procs.append({
                "pid": info['pid'],
                "name": info['name'] or "-",
                "username": info['username'] or "-",
                "cpu_percent": round(info['cpu_percent'] or 0, 1),
                "memory_percent": round(info['memory_percent'] or 0, 1),
                "exe": info['exe'] or "-"
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    # ترتيب حسب استهلاك الرام وإرجاع أعلى 20 عملية فقط لتخفيف الضغط
    return sorted(procs, key=lambda p: p['memory_percent'], reverse=True)[:20]

# ---- الإضافة الجديدة: جلب الاتصالات ----
def get_active_connections():
    conns = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status in ["ESTABLISHED", "LISTEN"]:
            try:
                process_name = "-"
                if conn.pid:
                    try:
                        process_name = psutil.Process(conn.pid).name()
                    except Exception:
                        pass
                        
                conns.append({
                    "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
                    "remote_ip": conn.raddr.ip if conn.raddr else None,
                    "remote_port": conn.raddr.port if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid or "-",
                    "process_name": process_name
                })
            except Exception:
                pass
    return conns

def send_heartbeat():
    print("========================================")
    print("🛡️  SET-CDP Endpoint Agent Started...")
    print(f"🔗 Agent ID : {AGENT_ID}")
    print(f"📡 Server   : {SERVER_URL}")
    print("========================================\n")
    
    while True:
        try:
            payload = {
                "api_key": API_KEY,
                "agent_id": AGENT_ID,
                "hostname": socket.gethostname(),
                "username": getpass.getuser(),
                "os_name": f"{platform.system()} {platform.release()}",
                "local_ip": get_local_ip(),
                "cpu_percent": psutil.cpu_percent(interval=1),
                "ram_percent": psutil.virtual_memory().percent,
                "processes": get_top_processes(),        # <--- إرسال العمليات
                "connections": get_active_connections()  # <--- إرسال الاتصالات
            }
            
            response = requests.post(SERVER_URL, json=payload, timeout=5)
            
            if response.status_code == 200:
                print(f"[{time.strftime('%H:%M:%S')}] ✅ Data Sent! (Procs: {len(payload['processes'])}, Conns: {len(payload['connections'])})")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] ⚠️ Server returned: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"[{time.strftime('%H:%M:%S')}] ❌ Connection failed.")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] ❌ Error: {e}")
        
        time.sleep(10)

if __name__ == "__main__":
    send_heartbeat()