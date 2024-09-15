import smtplib
import ssl
from email.mime.text import MIMEText
from socket import gaierror, timeout
from smtplib import SMTPException, SMTPAuthenticationError

# Simplified SMTP Scanner Script

def smtp_connection(server, port, use_tls=True):
    try:
        context = ssl.create_default_context()
        smtp = smtplib.SMTP(server, port, timeout=10)
        smtp.ehlo()
        if use_tls:
            smtp.starttls(context=context)
            smtp.ehlo()
        print(f"Connected to {server} on port {port}")
        return smtp
    except (gaierror, timeout):
        print(f"Failed to connect to server {server} on port {port}.")
    except Exception as e:
        print(f"Error during SMTP connection: {e}")
    return None

def test_smtp_server():
    server = input("Enter SMTP server address (e.g., smtp.example.com): ").strip()
    port = input("Enter SMTP server port (e.g., 587): ").strip()
    port = int(port) if port.isdigit() else 587
    use_tls = input("Use TLS? (y/n, default y): ").strip().lower() != 'n'

    smtp = smtp_connection(server, port, use_tls)
    if smtp:
        print("SMTP server is reachable and responded successfully.")
        smtp.quit()
    else:
        print("Failed to connect to the SMTP server.")

if __name__ == "__main__":
    test_smtp_server()
