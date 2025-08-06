from django.db import models

# Create your models here.
# apps/phishsim/models.py
from django.db import models

class SimEvent(models.Model):
    campaign_name = models.CharField(max_length=100)
    target_email = models.EmailField(null=True, blank=True)  # optional, from HR list
    target_password=models.TextField(null=False)
    target_pin=models.DecimalField(max_digits=1000000000,decimal_places=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    action = models.CharField(max_length=50)  # e.g., "email_open", "link_click", "form_submit"
    note = models.TextField(blank=True)  # optional extra info (non-sensitive)
