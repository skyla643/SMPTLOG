# smtp_test_server.py
import smtpd
import asyncore

class CustomSMTPServer(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        print('Incoming message from:', peer)
        print('From:', mailfrom)
        print('To:', rcpttos)
        print('Message:')
        print(data)
        return

if __name__ == "__main__":
    server = CustomSMTPServer(('localhost', 1025), None)
    print("SMTP server running on localhost:1025")
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass