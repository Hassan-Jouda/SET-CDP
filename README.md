# 🛡️ SET-CDP

**Security Education, Testing & Cyber Defense Platform**

SET-CDP is a comprehensive cybersecurity education and training platform designed to combine security awareness, defensive security assessment, threat simulation, browser-based protection tools, endpoint monitoring, and cyber defense practices within a unified environment.

The platform provides students, researchers, educators, and organizations with practical tools to understand modern cyber threats, evaluate security posture, and improve cybersecurity awareness through interactive learning and controlled simulations.

---

## 🎯 Project Vision

To bridge the gap between cybersecurity theory and practical experience by providing a safe, educational, and interactive environment that enables users to understand cyber threats from both offensive and defensive perspectives.

SET-CDP is designed to support practical cybersecurity learning by combining:

* Defensive security assessment tools
* Red Teaming educational simulations
* Security awareness training & interactive Chatbot
* Mini-SOC & Endpoint Monitoring (Mini-EDR)
* Browser extension-based protection
* User activity tracking & reporting
* Cyber threat knowledge base
* Quiz-based student assessment with automated certificates

---

## 🚀 Core Components

### 🔵 Blue Teaming (Defensive Scanners)

Defensive security tools designed to assess, analyze, and improve security posture:

* **Website Security Scanner:** Evaluates HTTPS and Security Headers.
* **SSL/TLS Certificate Inspector:** Checks validity, issuer, and expiration.
* **URL Safety Checker:** Advanced detection of phishing indicators and malicious links.
* **Header Security Analyzer:** Deep inspection of CSP, HSTS, and X-Frame-Options.
* **Password Strength Analyzer:** Local, privacy-first password evaluation.
* **Secure Password Generator:** Generates strong, random passwords.
* **Email Phishing Detector:** Analyzes email text for social engineering triggers.
* **File Hash & Metadata Analyzer:** Local SHA-256 generation.
* **URL Expander:** Uncovers short links and redirect chains.

### 📡 Mini-SOC & Endpoint Monitoring

A built-in lightweight Security Operations Center designed to teach centralized monitoring and incident response:

* **Endpoint Agent:** A Python-based agent deployed on authorized client machines to send heartbeat and telemetrics.
* **Mini-EDR Live Monitor:** Tracks live processes, network connections, CPU/RAM usage, and evaluates risk scores in real-time.
* **Device Center:** Centralized dashboard to view all connected devices and their security posture.

### 🔴 Red Teaming (Educational Simulations)

Controlled awareness and threat-emulation modules designed for cybersecurity education:

* Training Clone Generator
* Security Awareness Landing Pages
* QR Code Awareness Simulation (Quishing)
* Fake Session Expired Pop-up Simulation
* USB Security Awareness Simulation
* Social Engineering Awareness Templates (Facebook, Instagram, LinkedIn, etc.)
* User Interaction Tracking & Result Logging

### 🟢 Security Awareness & Education

Interactive learning modules that help users understand cyber threats:

* **SET-CDP Awareness Chatbot:** A built-in, local rule-based interactive assistant providing instant guidance, explaining security concepts, and offering protection tips.
* **Interactive Security Quiz System:** Dynamic question builder, automated scoring, and instant PDF certificate generation.
* **Cyber Threat Library:** Comprehensive knowledge base covering Phishing, Malware, XSS, MITM, Ransomware, and more.

### 🧩 Browser Extension Store

A built-in store providing standalone browser extensions designed to enhance user protection directly inside the browser (Manifest V3):

* **🛡️ SET-CDP WebShield Ultimate:** Proactive URL, QR, and privacy scanning.
* **🍪 SET-CDP CookieShield Pro:** Privacy-focused cookie management and security auditing.
* **🚫 SET-CDP AdShield Pro:** Reduces ads, trackers, and malicious pop-up exposure.
* **✅ Advanced To-Do List:** A secure, local productivity workflow tool.

---

## 👥 User Management & Profiles

SET-CDP includes a Role-Based Access Control (RBAC) model:

* **Administrator:** Full dashboard access, manages users, quizzes, simulations, and platform analytics.
* **Standard User:** Accesses security tools, awareness simulations, quizzes, personal reports, and tracking.
* **User Profiles:** Official certificate names, profile images, personal quiz results, activity history, and training statistics.

---

## 🏗️ Technology Stack

**Backend**

* Python 3
* Flask Framework
* SQLite & Werkzeug

**Frontend**

* HTML5, CSS3, JavaScript
* Bootstrap 5
* Jinja2 Templating
* Chart.js & Font Awesome

**Core Python Libraries**

* `requests`, `BeautifulSoup4`, `qrcode`, `Pillow`, `PyPDF2`, `hashlib`, `psutil`, `socket`

**Browser Extension Technologies**

* Manifest V3, Local Storage, Declarative Net Request, Cookies API

**Development Tools**

* Visual Studio Code, Git/GitHub, DB Browser for SQLite

---

## 📂 Project Structure

```text
SET-CDP/
│
├── app.py                  # Main Flask application routing and logic
├── agent.py                # Mini-EDR Endpoint Agent script
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
│
├── static/                 # CSS, JS, and extension files
│   ├── style.css
│   ├── script.js
│   └── extensions/         # Downloadable ZIP files for browser extensions
│
├── templates/              # Jinja2 HTML templates
│   ├── index.html          # Main Dashboard & Tools
│   ├── about.html          # Project overview & team
│   ├── profile.html        # User profile, history, and certificates
│   ├── edr_devices.html    # Mini-SOC device center
│   ├── chatbot_widget.html # Floating awareness assistant
│   └── ...                 # Other UI components & simulations
│
├── uploads/                # User profile images
└── database.db             # SQLite database (auto-generated)

```

---

## ⚙️ Installation & Usage

1. **Clone repository:**
```bash
git clone https://github.com/Hassan-Jouda/SET-CDP.git

```


2. **Navigate into the project directory:**
```bash
cd SET-CDP

```


3. **Install dependencies:**
```bash
pip install -r requirements.txt

```


4. **Run the application:**
```bash
python app.py

```


5. **Open your browser:**
Navigate to `[http://127.0.0.1:5000](http://127.0.0.1:5000)`

> **To deploy the Endpoint Agent:** Run `python agent.py` on the target machine (ensure `SERVER_URL` in `agent.py` matches the Flask server IP).

---

## 🔒 Ethical Notice & Privacy Principles

SET-CDP is an **academic and educational cybersecurity project**.
The platform was developed to support cybersecurity education, awareness training, security assessment, and authorized testing activities.

* **Educational use only.**
* All simulations and educational modules must be used only in **approved environments** and for legitimate educational purposes.
* Browser extensions are **local-first** with zero external telemetry.
* Users are responsible for using the platform ethically and in compliance with applicable laws and institutional policies.

---

## 👨‍💻 Development Team

* **Hassan Jouda** – Founder, Project Lead & System Architect
* **Ismail Al-Nahhal** – UI/UX Designer
* **Bilal** – Software Developer

---

## 🔮 Future Roadmap

* AI-Assisted Threat Analysis
* Integration with enterprise SIEM solutions
* Advanced Security Operations Dashboard
* Student Leaderboards for gamified learning
* Automated Awareness Campaign Management

---

## 📜 License

**Academic Graduation Project**
Developed for educational, research, and cybersecurity awareness purposes.
*© 2026 SET-CDP — Security Education, Testing & Cyber Defense Platform*
