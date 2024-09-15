import smtplib
import ssl
import boto3
from socket import gaierror, timeout
from smtplib import SMTPException, SMTPAuthenticationError
from email.mime.text import MIMEText

# SMTP Connection Setup
def smtp_connection(server, port, username=None, password=None, use_tls=True):
    try:
        context = ssl.create_default_context()
        smtp = smtplib.SMTP(server, port, timeout=10)
        smtp.ehlo()
        if use_tls:
            smtp.starttls(context=context)
            smtp.ehlo()
        if username and password:
            smtp.login(username, password)
        print(f"Connected to {server} on port {port}")
        return smtp
    except SMTPAuthenticationError:
        print("Authentication failed. Check your username and password.")
    except (gaierror, timeout):
        print(f"Failed to connect to server {server} on port {port}.")
    except Exception as e:
        print(f"Error during SMTP connection: {e}")
    return None

# Open Relay Test
def test_open_relay(server, port, recipient):
    try:
        smtp = smtp_connection(server, port, use_tls=False)
        if smtp:
            from_address = 'test@externaldomain.com'
            to_address = recipient
            message = MIMEText('This is a test message for open relay detection.')
            message['Subject'] = 'Open Relay Test'
            message['From'] = from_address
            message['To'] = to_address

            smtp.sendmail(from_address, [to_address], message.as_string())
            smtp.quit()
            print("Open relay vulnerability detected.")
            return "Open Relay: Vulnerable"
        else:
            return "Open Relay: Could not connect to test"
    except SMTPException as e:
        print(f"Open relay test failed: {e}")
        return "Open Relay: Secure"
    except Exception as e:
        print(f"Error during open relay test: {e}")
        return "Open Relay: Error"

# Spoofing Test
def test_spoofing(smtp, recipient):
    try:
        from_address = 'spoofed@spoofeddomain.com'
        to_address = recipient
        message = MIMEText('This is a test message for spoofing detection.')
        message['Subject'] = 'Spoofing Test'
        message['From'] = from_address
        message['To'] = to_address

        smtp.sendmail(from_address, [to_address], message.as_string())
        print("Spoofing is possible.")
        return "Spoofing: Vulnerable"
    except SMTPException as e:
        print(f"Spoofing test failed: {e}")
        return "Spoofing: Secure"
    except Exception as e:
        print(f"Error during spoofing test: {e}")
        return "Spoofing: Error"

# Weak Authentication Test (Brute Force)
def brute_force_login(server, port, username, password_list, use_tls=True):
    for password in password_list:
        try:
            smtp = smtp_connection(server, port, username, password, use_tls)
            if smtp:
                print(f"Authenticated with weak password: {password}")
                smtp.quit()
                return f"Weak Authentication: Vulnerable with password '{password}'"
        except SMTPAuthenticationError:
            continue
        except Exception as e:
            print(f"Error during brute force test: {e}")
            break
    print("Weak authentication not detected.")
    return "Weak Authentication: Secure"

# Encryption Test
def check_encryption(server, port):
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(server, port, context=context, timeout=10) as smtp:
            smtp.ehlo()
            print(f"{server} supports TLS/SSL encryption on port {port}.")
            return "Encryption: Supported"
    except (gaierror, timeout):
        print(f"Failed to connect to server {server} on port {port} for SSL/TLS check.")
        return "Encryption: Not Supported or Server Unreachable"
    except Exception as e:
        print(f"Error during encryption check: {e}")
        return "Encryption: Not Supported"

# AWS SES Configuration Test
def check_aws_ses():
    try:
        ses = boto3.client('ses')
        response = ses.get_account_sending_enabled()
        if response['Enabled']:
            print("AWS SES is enabled for this account.")
            # Additional checks can be added here
            return "AWS SES: Enabled and Configured"
        else:
            print("AWS SES is disabled for this account.")
            return "AWS SES: Disabled"
    except Exception as e:
        print(f"Error accessing AWS SES: {e}")
        return "AWS SES: Error Accessing Service"

# DNS Records Check (SPF, DKIM, DMARC)
import dns.resolver

def check_dns_records(domain):
    records = {}
    try:
        # Check SPF
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in rdata.to_text():
                records['SPF'] = rdata.to_text()
                print(f"SPF record found: {rdata.to_text()}")
                break
        else:
            records['SPF'] = 'No SPF record found'
            print("No SPF record found.")

        # Check DKIM
        selector = 'default'  # Common selector, this may vary
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                records['DKIM'] = rdata.to_text()
                print(f"DKIM record found: {rdata.to_text()}")
                break
        except dns.resolver.NXDOMAIN:
            records['DKIM'] = 'No DKIM record found'
            print("No DKIM record found.")

        # Check DMARC
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                records['DMARC'] = rdata.to_text()
                print(f"DMARC record found: {rdata.to_text()}")
                break
        except dns.resolver.NXDOMAIN:
            records['DMARC'] = 'No DMARC record found'
            print("No DMARC record found.")

    except Exception as e:
        print(f"Error checking DNS records: {e}")
        records['DNS Check'] = f"Error: {e}"
    return records

# Report Generation
def generate_report(vulnerabilities, dns_records):
    report_name = 'smtp_vulnerability_report.txt'
    try:
        with open(report_name, 'w') as report:
            report.write("SMTP Vulnerability Scan Report\n")
            report.write("===============================\n\n")
            for vulnerability in vulnerabilities:
                report.write(f"{vulnerability}\n")
            report.write("\nDNS Records Check\n")
            report.write("=================\n")
            for record_type, record_value in dns_records.items():
                report.write(f"{record_type}: {record_value}\n")
        print(f"Report generated: {report_name}")
    except Exception as e:
        print(f"Error generating report: {e}")

# Main Scanner Logic
def run_smtp_scanner():
    server = input("Enter SMTP server address (e.g., smtp.example.com): ").strip()
    port = input("Enter SMTP server port (e.g., 587): ").strip()
    port = int(port) if port.isdigit() else 587
    use_tls = input("Use TLS? (y/n, default y): ").strip().lower() != 'n'
    username = input("Enter SMTP username (leave blank if none): ").strip() or None
    password = input("Enter SMTP password (leave blank if none): ").strip() or None
    recipient = input("Enter test recipient email address: ").strip()
    domain = server.split('.')[-2] + '.' + server.split('.')[-1]

    vulnerabilities = []
    dns_records = {}

    # Check Encryption Support
    encryption_result = check_encryption(server, port)
    vulnerabilities.append(encryption_result)

    # SMTP Connection
    smtp = smtp_connection(server, port, username, password, use_tls)
    if smtp:
        # Spoofing Test
        spoofing_result = test_spoofing(smtp, recipient)
        vulnerabilities.append(spoofing_result)

        smtp.quit()
    else:
        vulnerabilities.append("SMTP Connection: Failed")

    # Open Relay Test
    open_relay_result = test_open_relay(server, port, recipient)
    vulnerabilities.append(open_relay_result)

    # Weak Authentication Test
    if username:
        weak_passwords = ['12345', 'password', 'admin', 'root']
        weak_auth_result = brute_force_login(server, port, username, weak_passwords, use_tls)
        vulnerabilities.append(weak_auth_result)
    else:
        vulnerabilities.append("Weak Authentication: Not Tested (No username provided)")

    # DNS Records Check
    dns_records = check_dns_records(domain)

    # AWS SES Test
    use_aws = input("Do you want to test AWS SES settings? (y/n): ").strip().lower()
    if use_aws == 'y':
        aws_result = check_aws_ses()
        vulnerabilities.append(aws_result)

    # Generate Report
    generate_report(vulnerabilities, dns_records)

# Run the Scanner
if __name__ == "__main__":
    run_smtp_scanner()
