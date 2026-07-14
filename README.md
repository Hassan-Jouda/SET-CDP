# 🛡️ SET-CDP

## Security Education, Testing & Cyber Defense Platform

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-red)
![SQLite](https://img.shields.io/badge/Database-SQLite-green)
![Bootstrap](https://img.shields.io/badge/UI-Bootstrap%205-purple)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![License](https://img.shields.io/badge/License-Academic-lightgrey)

**SET-CDP** is a comprehensive cybersecurity education and training platform designed to combine security awareness, defensive security assessment, threat simulation, browser-based protection tools, and cyber defense practices within a unified environment.

The platform provides students, researchers, educators, and organizations with practical tools to understand modern cyber threats, evaluate security posture, and improve cybersecurity awareness through interactive learning and controlled simulations.

---

# 🎯 Project Vision

To bridge the gap between cybersecurity theory and practical experience by providing a safe, educational, and interactive environment that enables users to understand cyber threats from both offensive and defensive perspectives.

SET-CDP is designed to support practical cybersecurity learning by combining:

* Defensive security assessment tools
* Red Teaming educational simulations
* Security awareness training
* Browser extension-based protection
* User activity tracking
* Interactive dashboards and reports
* Cyber threat knowledge base
* Quiz-based student assessment

---

# 🚀 Core Components

## 🔵 Blue Teaming

Defensive security tools designed to assess, analyze, and improve security posture.

Features include:

* Website Security Scanner
* Security Headers Analyzer
* SSL/TLS Certificate Inspector
* URL Safety Checker
* URL Expander
* Domain & IP Information Checker
* Password Strength Analyzer
* Secure Password Generator
* Email Phishing Detector
* File Hash & Metadata Analyzer
* Security Recommendations
* Scan History Tracking

---

## 🔴 Red Teaming Educational Simulations

Controlled awareness and threat-emulation modules designed for cybersecurity education.

Features include:

* Training Clone Generator
* Security Awareness Landing Pages
* QR Code Awareness Simulation (Quishing)
* Fake Session Expired Pop-up Simulation
* USB Security Awareness Simulation
* Social Engineering Awareness Templates
* User Interaction Tracking
* Training Activity Dashboard
* Simulation Result Logging
* Awareness Redirection Pages

> All simulations are intended solely for educational and awareness purposes inside approved and controlled environments.

---

## 🟢 Security Awareness & Education

Interactive learning modules that help users understand cyber threats and secure practices.

Features include:

* Cyber Threat Library
* Awareness Training Pages
* Interactive Security Quiz System
* Student Assessment Engine
* Performance Evaluation
* Certificate-Ready Student Profiles
* User Learning Progress
* Awareness Recommendations
* Educational Debriefing Pages

---

## 🧩 Browser Extension Store

SET-CDP includes a built-in **Browser Extension Store** that provides standalone browser extensions designed to enhance user protection and cybersecurity awareness directly inside the browser.

The extensions are provided as downloadable ZIP files and can be installed manually using Developer Mode in Chromium-based browsers such as Google Chrome and Microsoft Edge.

Available extensions include:

### 🛡️ SET-CDP WebShield Ultimate

A powerful browser security extension for proactive user protection.

Features include:

* URL Risk Analyzer
* QR Code Security Scanner
* Password Security Analyzer
* Secure Password Generator
* Privacy Scanner
* Email Header Analyzer
* File Hash Generator
* Security Headers Checker
* Local Report Export
* Client-side analysis without external telemetry

---

### 🍪 SET-CDP CookieShield Pro

A privacy-focused cookie management and cookie security auditing extension.

Features include:

* View cookies for the current website
* Create, edit, and delete cookies
* Search and filter cookies
* Cookie Security Score
* Detect missing Secure flag
* Detect missing HttpOnly flag
* Detect SameSite risks
* Detect long-lived cookies
* Delete insecure cookies
* Export Cookie Audit Report without exposing cookie values

---

### 🚫 SET-CDP AdShield Pro

A browser extension designed to reduce ads, trackers, and malicious pop-up exposure.

Features include:

* Network-level ad blocking
* Tracker blocking
* Cosmetic cleaning for ad containers
* Privacy Protection mode
* Enable/Disable control
* Lightweight local settings
* Improved browsing experience
* Reduced exposure to social engineering advertisements

---

### ✅ Advanced To-Do List

A productivity-focused browser extension included as a supporting tool for daily task management.

Features include:

* Task creation
* Task management
* Simple browser-based productivity workflow
* Local usage inside the browser

---

# 📚 Cyber Threat Library

The platform contains a built-in knowledge base covering:

* Phishing
* Spear Phishing
* Smishing
* Vishing
* Quishing
* Malware
* Ransomware
* SQL Injection
* Cross-Site Scripting (XSS)
* Cross-Site Request Forgery (CSRF)
* Man-in-the-Middle (MITM)
* USB Drop Attacks
* UI Redressing & Fake Pop-up Attacks
* Social Engineering
* Password Attacks
* Browser Tracking
* Malicious Ads
* Cookie Security Risks

Each topic includes:

* Description
* Risk Level
* Attack Method
* Prevention Techniques
* Awareness Recommendations
* Practical Security Notes

---

# 👥 User Management System

SET-CDP includes a Role-Based Access Control (RBAC) model.

## Administrator

* Full dashboard access
* Manage users
* Manage quiz questions
* View all reports
* View all activity logs
* Manage simulations
* Access platform analytics
* Review user activity
* Monitor scan statistics
* Manage awareness content

## Standard User

* Access security tools
* Use awareness simulations
* Take quizzes
* Manage personal profile
* View personal activity
* View personal reports
* Track learning progress
* Access browser extensions
* Explore the cyber threat library

---

# 🧑‍💻 User Profiles

Each user can maintain a personal profile containing:

* Username
* Official Certificate Name
* Profile Image
* Biography
* Personal Quiz Results
* Personal Activity History
* Training Statistics
* Security Tool Usage History
* Awareness Progress

---

# 📊 Dashboard & Reporting

The platform provides real-time insights through:

* User Dashboard
* Administrative Dashboard
* Security Activity Monitoring
* Scan Statistics
* Quiz Analytics
* Training Simulation Statistics
* Activity History
* Reports Center
* Interactive Charts using Chart.js
* User Performance Tracking
* Awareness Progress Indicators
* Extension Store Access

Reports may include:

* Scan results
* User activity
* Quiz results
* Simulation interactions
* Awareness progress
* Security recommendations

---

# 📝 Security Awareness Quiz System

Features include:

* Dynamic Question Builder
* Question Management
* Student Assessments
* Automatic Scoring
* Pass/Fail Evaluation
* Results Management
* Quiz Analytics
* Certificate Integration
* Admin Question Control
* User Performance Tracking

---

# 🏗️ Technology Stack

## Backend

* Python
* Flask
* SQLite
* Werkzeug

## Frontend

* HTML5
* CSS3
* JavaScript
* Bootstrap 5
* Jinja2

## Libraries & Frameworks

* Requests
* BeautifulSoup4
* qrcode
* Pillow
* PyPDF
* Chart.js
* Font Awesome
* hashlib
* sqlite3
* urllib
* ssl
* socket

## Browser Extension Technologies

* Chrome Extensions
* Manifest V3
* JavaScript
* HTML
* CSS
* Local Storage
* Declarative Net Request
* Browser Cookies API

## Development Tools

* Visual Studio Code
* Git
* GitHub
* DB Browser for SQLite
* Google Chrome Developer Mode
* Microsoft Edge Developer Mode

---

# 📂 Project Structure

```text
SET-CDP/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── static/
│   ├── style.css
│   ├── script.js
│   │
│   └── extensions/
│       ├── webshield.zip
│       ├── SET-CDP-WebShield-Ultimate-v3.0.zip
│       ├── SET-CDP-WebShield-Pro-v2.zip
│       ├── SET-CDP-CookieShield-Pro-v1.0.zip
│       ├── SET-CDP-AdShield-Pro-v1.0.zip
│       └── Advanced-To-Do-List-main.zip
│
├── templates/
│   ├── index.html
│   ├── dashboard.html
│   ├── reports.html
│   ├── threat_library.html
│   ├── about.html
│   ├── login.html
│   ├── register.html
│   ├── profile.html
│   ├── attack.html
│   ├── ready_templates.html
│   ├── awareness_training.html
│   ├── quiz_start.html
│   ├── quiz_take.html
│   ├── quiz_result.html
│   ├── quiz_builder.html
│   ├── quiz_admin.html
│   ├── extensions.html
│   ├── base_nav.html
│   │
│   ├── social/
│   │   ├── facebook.html
│   │   ├── instagram.html
│   │   ├── linkedin.html
│   │   ├── university.html
│   │   └── fake_popup.html
│   │
│   └── clones/
│
├── uploads/
├── __pycache__/
└── database.db
```

---

# ⚙️ Installation

Clone repository:

```bash
git clone https://github.com/Hassan-Jouda/SET-CDP.git
```

Navigate into the project directory:

```bash
cd SET-CDP
```


Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

---

# 🧩 Installing Browser Extensions

To install any extension from the SET-CDP Extension Store:

1. Open the SET-CDP platform.
2. Go to the Extension Store page.
3. Download the required ZIP file.
4. Extract the ZIP file.
5. Open Chrome or Edge.
6. Go to:

```text
chrome://extensions/
```

or:

```text
edge://extensions/
```

7. Enable Developer Mode.
8. Click Load unpacked.
9. Select the extracted extension folder.

---

# 🔗 Extension Download Routes

The platform supports direct extension download routes such as:

```text
/download-extension/webshield
/download-extension/cookieshield
/download-extension/adshield
/download-extension/todo
/download-extension/webshield-v2
```

These routes provide a controlled download mechanism for browser extensions inside the platform.

---

# 🎯 Project Objectives

* Improve cybersecurity awareness.
* Support cybersecurity education.
* Demonstrate security testing concepts.
* Help students understand modern cyber threats.
* Provide hands-on learning experiences.
* Promote ethical cybersecurity practices.
* Encourage proactive security culture.
* Combine Blue Teaming and Red Teaming educational concepts.
* Provide browser-based protection tools.
* Support academic cybersecurity training.

---

# 🔒 Security & Privacy Principles

SET-CDP follows the following principles:

* Educational use only
* Authorized testing only
* Controlled simulations only
* Local-first browser extensions
* No external telemetry in browser extensions
* Awareness-focused training flows
* Safe learning environment
* Ethical cybersecurity practice
* Clear separation between education and misuse

---

# 🔒 Ethical Notice

SET-CDP is an academic and educational cybersecurity project.

The platform was developed to support cybersecurity education, awareness training, security assessment, and authorized testing activities.

All simulations, demonstrations, and educational modules must be used only in approved environments and for legitimate educational or awareness purposes.

Users are responsible for using the platform ethically and in compliance with applicable laws and institutional policies.

---

# 👥 Development Team

## Founder & Project Lead

**Hassan Jouda**

## UI/UX Designer

**Ismail Al-Nahhal**

## Software Developer

**Bilal**

---

# 🔮 Future Roadmap

* AI-Assisted Threat Analysis
* Advanced Security Reporting
* Student Leaderboards
* Enhanced Certificate System
* Awareness Campaign Management
* Security Operations Dashboard
* Research on SIEM Integration
* Advanced Analytics & Metrics
* Browser Extension Enhancements
* Advanced Privacy Scanner
* Improved Certificate Generator
* Exportable PDF Reports

---

# 📜 License

Academic Graduation Project

Developed for educational, research, and cybersecurity awareness purposes.

---

© 2026 SET-CDP — Security Education, Testing & Cyber Defense Platform
