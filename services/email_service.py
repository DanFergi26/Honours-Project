# -- Email_Service.py
# -- Imports
import smtplib
from email.message import EmailMessage

# LINK GMAIL ACCOUNT
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "insidethegridsite@gmail.com"
SMTP_PASSWORD = "lpok alxt pjfk xpnz" 
FROM_EMAIL = SMTP_USER

# SEND VERIFICATION CODED
def send_verification_email(to_email, code, subject="Your verification code"):
    """
    Sends a verification email with a code.
    """
    msg = EmailMessage()
    msg.set_content(f"Your verification code is: {code}")
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Email sent to {to_email}")
    except Exception as e:
        print("Error sending email:", e)

# SEND LOGIN ALERT
def send_login_alert_email(to_email, location, change_password_url):
    msg = EmailMessage()
    msg.set_content(
        f"Your account was just logged into from {location}.\n"
        f"If this wasn't you, you can change your password here: {change_password_url}"
    )
    msg["Subject"] = "Login Alert"
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Login alert email sent to {to_email}")
    except Exception as e:
        print("Error sending login alert email:", e)
        
