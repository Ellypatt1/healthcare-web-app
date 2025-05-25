# 🩺 Secure Healthcare Web App

Created by: Elly Patterson  
Deployed at: https://healthcare-web-app.onrender.com

---

## 🔧 Technologies Used
- Python
- Flask
- HTML/CSS (Jinja2 templating)
- JSON for encrypted data storage
- Deployed using Render
- GitHub for version control
- Gunicorn for production server

---

## 🚀 Features

### 🧑‍⚕️ Patient
- Secure login/signup with MFA and password hashing
- View and manage appointments
- View medical records
- Make copayments
- Manage saved cards

### 🧑‍💼 Staff
- Create patient visits
- Record fixed $50 copays
- View all appointments and charges

### 👩‍⚕️ Nurse
- Add vitals and visit reasons to patient records
- View appointments

### 👨‍⚕️ Doctor
- Add treatment and prescriptions
- View medical records
- View appointments

### 👩‍💼 CEO
- Create employee accounts and assign roles
- View daily and monthly summaries
- View login attempt logs
- View full audit logs (copays, invoices, medical edits)

---

## 🛡️ Security Highlights
- Passwords are hashed with SHA-256
- Login attempts are logged with 3-strike lockout policy
- Data is encrypted using XOR + base64
- MFA via verification code at login
- CEO-exclusive audit log and user management

---

## ⚙️ Setup Instructions (For Local Testing)
1. Clone the repository or unzip the folder
2. Install dependencies:
   pip install -r requirements.txt
3. Run the app:
   python app.py
4. Visit:
   http://127.0.0.1:5000

---

## 📁 Files
- `app.py` – Main Flask app
- `templates/` – HTML pages
- `users.json`, `appointments.json`, `charges.json`, etc. – encrypted data
- `secret.key` – used for XOR encryption
- `requirements.txt` – dependencies
- `Procfile` – tells Render how to start the app
- `audit_log.json` – CEO-only audit log file

---

## ✅ Live Demo
Visit the running web app at:  
👉 https://healthcare-web-app.onrender.com

---

## 👩‍🏫 Final Notes
This project is for CS4454 Secure Software Development. All access control, logging, and storage policies were implemented with software security best practices in mind.
