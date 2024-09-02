from django.core.management.base import BaseCommand
from django.core.mail import send_mail

class Command(BaseCommand):
    help = 'Send a test email'

    def handle(self, *args, **kwargs):
        send_mail(
            'Test Email',
            'This is a test email.',
            'roshni.sundrani83@gmail.com',
            ['roshni.sundrani83@gmail.com'],
            fail_silently=False,
        )
        self.stdout.write(self.style.SUCCESS('Test email sent successfully'))
