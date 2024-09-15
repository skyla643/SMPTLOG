import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message

class CustomMessageHandler(Message):
    async def handle_message(self, message):
        print('Incoming message from:', message.envelope.mail_from)
        print('To:', message.envelope.rcpt_tos)
        print('Message:')
        print(message.content)
        return '250 OK'

if __name__ == "__main__":
    handler = CustomMessageHandler()
    controller = Controller(handler, hostname='localhost', port=1025)
    print("SMTP server running on localhost:1025")
    try:
        controller.start()
    except KeyboardInterrupt:
        pass