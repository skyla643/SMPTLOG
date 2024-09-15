import asyncio
from aiosmtpd import SMTPServer, SMTPSession

class CustomSMTPSession(SMTPSession):
    async def handle_DATA(self, data):
        print('Incoming message from:', self.peer)
        print('From:', self.mail_from)
        print('To:', self.mail_to)
        print('Message:')
        print(data)
        return '250 OK'

if __name__ == "__main__":
    server = SMTPServer(('localhost', 1025), CustomSMTPSession)
    print("SMTP server running on localhost:1025")
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        pass