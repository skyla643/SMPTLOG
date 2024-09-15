# SMTP Vulnerability Scanner

## Overview

The **SMTP Vulnerability Scanner** is a Python tool designed to identify common vulnerabilities in SMTP (Simple Mail Transfer Protocol) servers. It performs various tests to detect issues such as open relays, email spoofing possibilities, weak authentication mechanisms, and misconfigurations in encryption protocols. Additionally, it checks DNS records like SPF, DKIM, and DMARC for the target domain and can optionally assess AWS SES configurations.

## Features

- **SMTP Connection Setup**: Establishes a connection to the SMTP server with optional TLS encryption and authentication.
- **Open Relay Test**: Checks if the server allows relaying emails from external domains to external recipients.
- **Spoofing Test**: Attempts to send an email with a forged "From" address to detect if spoofing is possible.
- **Weak Authentication Test**: Tries to authenticate using a list of common weak passwords to identify weak authentication mechanisms.
- **Encryption Test**: Verifies if the SMTP server supports TLS/SSL encryption.
- **DNS Records Check**: Retrieves and displays SPF, DKIM, and DMARC records for the domain.
- **AWS SES Configuration Test**: Optionally checks AWS Simple Email Service (SES) settings.
- **Report Generation**: Generates a detailed report of the findings in a text file.

## Prerequisites

- **Python 3.x**
- **Required Python Libraries**:
  - `smtplib` (Standard Library)
  - `ssl` (Standard Library)
  - `email` (Standard Library)
  - `boto3`
  - `dnspython`

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/smtp-vulnerability-scanner.git
   cd smtp-vulnerability-scanner
   ```

2. **Install Required Libraries**

   ```bash
   pip install boto3 dnspython
   ```

   > **Note**: `smtplib`, `ssl`, and `email` are part of Python's standard library and do not require installation.

## Usage

1. **Run the Scanner**

   ```bash
   python smtp_vulnerability_scanner.py
   ```

2. **Provide the Required Information**

   - **SMTP Server Address**: The domain or IP address of the SMTP server you want to test (e.g., `smtp.example.com`).
   - **SMTP Server Port**: The port number for the SMTP server (common ports are `25`, `465`, `587`).
   - **Use TLS**: Choose whether to use TLS encryption (`y` for yes, `n` for no).
   - **SMTP Username**: The username for SMTP authentication (leave blank if not required).
   - **SMTP Password**: The password for SMTP authentication (leave blank if not required).
   - **Test Recipient Email Address**: An email address to send test emails to (preferably one you have access to).
   - **AWS SES Testing**: Indicate if you want to perform AWS SES configuration checks (`y` or `n`).

3. **Example Terminal Session**

   ```plaintext
   PS C:\your\folder\path> python smtp_vulnerability_scanner.py
   Enter SMTP server address (e.g., smtp.example.com): smtp.gmail.com
   Enter SMTP server port (e.g., 587): 587
   Use TLS? (y/n, default y): y
   Enter SMTP username (leave blank if none): your_email@gmail.com
   Enter SMTP password (leave blank if none): your_app_password
   Enter test recipient email address: recipient@example.com
   Connected to smtp.gmail.com on port 587
   Spoofing is possible.
   Open relay vulnerability detected.
   Weak authentication not detected.
   SPF record found: "v=spf1 include:_spf.google.com ~all"
   DKIM record found: "v=DKIM1; k=rsa; p=..."
   DMARC record found: "v=DMARC1; p=none; rua=mailto:..."
   Report generated: smtp_vulnerability_report.txt
   ```

## Report

After the scan, a report named `smtp_vulnerability_report.txt` will be generated in the script's directory containing the results of the tests.

**Example Report Content**:

```plaintext
SMTP Vulnerability Scan Report
===============================

Encryption: Supported
Spoofing: Vulnerable
Open Relay: Vulnerable
Weak Authentication: Secure

DNS Records Check
=================
SPF: "v=spf1 include:_spf.google.com ~all"
DKIM: "v=DKIM1; k=rsa; p=..."
DMARC: "v=DMARC1; p=none; rua=mailto:..."
```

## Script Details

### **SMTP Connection Setup**

Establishes a connection to the SMTP server with optional TLS encryption and authentication.

```python
def smtp_connection(server, port, username=None, password=None, use_tls=True):
    # Function implementation...
```

### **Open Relay Test**

Checks if the server allows relaying emails from external domains to external recipients.

```python
def test_open_relay(server, port, recipient):
    # Function implementation...
```

### **Spoofing Test**

Attempts to send an email with a forged "From" address to detect if spoofing is possible.

```python
def test_spoofing(smtp, recipient):
    # Function implementation...
```

### **Weak Authentication Test**

Tries to authenticate using a list of common weak passwords.

```python
def brute_force_login(server, port, username, password_list, use_tls=True):
    # Function implementation...
```

### **Encryption Test**

Verifies if the SMTP server supports TLS/SSL encryption.

```python
def check_encryption(server, port):
    # Function implementation...
```

### **DNS Records Check**

Retrieves and displays SPF, DKIM, and DMARC records for the domain.

```python
def check_dns_records(domain):
    # Function implementation...
```

### **AWS SES Configuration Test**

Optionally checks AWS SES settings.

```python
def check_aws_ses():
    # Function implementation...
```

### **Report Generation**

Generates a detailed report of the findings.

```python
def generate_report(vulnerabilities, dns_records):
    # Function implementation...
```

### **Main Function**

Coordinates the scanning process.

```python
def run_smtp_scanner():
    # Function implementation...
```

## Important Notes

- **Ethical Usage**: Ensure you have permission to test the target SMTP server. Unauthorized scanning may violate laws and regulations.
- **Security**: Be cautious when entering sensitive information like passwords. Do not hard-code credentials in the script.
- **AWS SES Testing**: If you choose to test AWS SES settings, make sure your AWS credentials are configured and you have the necessary permissions.
- **DNS Record Checks**: The script attempts to retrieve DNS records for SPF, DKIM, and DMARC. Ensure the domain name is correctly extracted from the SMTP server address.

## Disclaimer

This tool is intended for educational and testing purposes only. The author is not responsible for any misuse of this tool. Use it responsibly and ethically.

## Contributions

Contributions are welcome! If you have suggestions for improvements or find any issues, feel free to submit a pull request or open an issue on GitHub.

---

## Sample Terminal Outputs

**Successful Connection and Scan**:

```plaintext
PS C:\your\folder\path> python smtp_vulnerability_scanner.py
Enter SMTP server address (e.g., smtp.example.com): smtp.gmail.com
Enter SMTP server port (e.g., 587): 587
Use TLS? (y/n, default y): y
Enter SMTP username (leave blank if none): your_email@gmail.com
Enter SMTP password (leave blank if none): your_app_password
Enter test recipient email address: recipient@example.com
Connected to smtp.gmail.com on port 587
Spoofing is possible.
Open relay vulnerability detected.
Weak authentication not detected.
SPF record found: "v=spf1 include:_spf.google.com ~all"
DKIM record found: "v=DKIM1; k=rsa; p=..."
DMARC record found: "v=DMARC1; p=none; rua=mailto:..."
Do you want to test AWS SES settings? (y/n): n
Report generated: smtp_vulnerability_report.txt
```

**Connection Failure Example**:

```plaintext
PS C:\your\folder\path> python smtp_vulnerability_scanner.py
Enter SMTP server address (e.g., smtp.example.com): invalid.smtp.server
Enter SMTP server port (e.g., 587): 5
Use TLS? (y/n, default y): y
Enter SMTP username (leave blank if none):
Enter SMTP password (leave blank if none):
Enter test recipient email address: recipient@example.com
Failed to connect to server invalid.smtp.server on port 5 for SSL/TLS check.
Failed to connect to server invalid.smtp.server on port 5.
Failed to connect to server invalid.smtp.server on port 5.
Error checking DNS records: The DNS query name does not exist: invalid.smtp.server.
Do you want to test AWS SES settings? (y/n): y
Error accessing AWS SES: You must specify a region.
Report generated: smtp_vulnerability_report.txt
```

## Additional Information

- **Python Version**: Ensure you are using Python 3.x.
- **Dependencies**: All required libraries are listed in the **Installation** section.
- **Error Handling**: The script includes basic error handling to manage exceptions during execution.

## Acknowledgments

- **dnspython**: Used for DNS record lookups.
- **boto3**: AWS SDK for Python, used for AWS SES checks.
- **Python Standard Libraries**: `smtplib`, `ssl`, `email`, and others.

--- love, SMRCCC3301
