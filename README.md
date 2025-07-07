# 🔐 Secure OTP Authentication System

A secure web-based login system using **Flask** and **email-based One-Time Password (OTP)** for two-factor authentication (2FA). Built to enhance traditional login systems by requiring a valid email-based OTP after password verification.

---

## ✅ Features

- User registration with email verification
- Login with username + password
- OTP generation and email delivery using `smtplib`
- OTP expiration (default: 5 minutes)
- Secure password hashing (`bcrypt`)
- Rate limiting to prevent brute-force attacks
- Session management & logout functionality
- SQLite database for user and session data
- Simple HTML/CSS interface (Bootstrap optional)

---

## 🛠️ Tech Stack

| Technology     | Purpose                         |
|----------------|----------------------------------|
| Python 3.8+    | Core backend logic               |
| Flask          | Web framework                    |
| smtplib        | Sending OTP emails               |
| SQLite         | User and session storage         |
| bcrypt         | Password hashing                 |
| Flask-Limiter  | Rate limiting & brute-force protection |
| HTML/CSS       | Frontend (Bootstrap optional)    |

---

## 📁 Project Structure

Secure-OTP-Auth-System/
├── app.py                 # Flask app
├── templates/             # HTML templates
│   ├── login.html
│   ├── register.html
│   └── otp_verify.html
├── static/                # CSS or frontend assets
├── users.db               # SQLite database
├── requirements.txt       # Python dependencies
├── .gitignore             # Git ignore file
└── README.md              # Project documentation

---

## ⚙️ Installation & Setup

### 1. Clone the repository


git clone https://github.com/Hammmii/Secure-OTP-Auth-System.git
cd Secure-OTP-Auth-System

### 2. Create & activate a virtual environment
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

### 3. Install dependencies

pip install -r requirements.txt

### 4. Configure SMTP Email Settings

Create a .env file in the root directory:
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password   # Use Gmail App Password (not your Gmail password)
In app.py, make sure these are loaded using:
import os
from dotenv import load_dotenv
load_dotenv()

## 🚀 Usage

Register a new user:
	•	Visit /register and create a new account
	•	A verification email will be sent (if implemented)

Login:
	•	Go to /login, enter your credentials
	•	If valid, an OTP will be emailed
	•	Enter OTP to complete login

⸻

## 🔒 Security Features

	•	Hashed passwords with bcrypt
	•	OTP expires in 5 minutes
	•	Rate limiting on login & OTP requests
	•	Session tracking for logged-in users
	•	Basic protection from CSRF and SQL injection

⸻

## 🧪 Testing Scenarios
	•	Invalid password
	•	Expired OTP
	•	Multiple login attempts (rate limiting)
	•	Wrong OTP entries
	•	OTP resend functionality

⸻

## 🧾 License

This project is open-source and free to use under the MIT License.

⸻

## 🙋 Contact

## Hammad Sikandar
## 📧 hammadsikandar8191@gmail.com
## 📱 0305-7882280

⸻

“Secure systems are not a feature — they’re a responsibility.”
