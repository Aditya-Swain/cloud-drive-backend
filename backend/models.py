from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    refresh_token = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.user.username
    
class CloudDriveConnection(models.Model):
    PROVIDER_CHOICES = [
        ('google', 'Google Drive'),
        ('dropbox', 'Dropbox'),
        ('onedrive', 'OneDrive'),
    ]

    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name="drive_connections",
    )
    provider = models.CharField(max_length=50, choices=PROVIDER_CHOICES)
    email = models.EmailField()
    access_token = models.TextField()
    refresh_token = models.CharField(max_length=512, blank=True, null=True)
    expiry_time = models.BigIntegerField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.provider.capitalize()} - {self.email} (connected to {self.user})"

    
from django.db import models

class Task(models.Model):
    PENDING = 'PENDING'
    IN_PROGRESS = 'IN_PROGRESS'
    COMPLETED = 'COMPLETED'
    FAILED = 'FAILED'

    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (IN_PROGRESS, 'In Progress'),
        (COMPLETED, 'Completed'),
        (FAILED, 'Failed'),
    ]

    COPY = 'copy'
    CUT = 'cut'
    DELETE = 'delete'

    TASK_TYPE_CHOICES = [
        (COPY, 'Copy'),
        (CUT, 'Cut'),
        (DELETE, 'Delete'),
    ]

    cloud_service = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    source_account_id = models.IntegerField()  # New field for source account ID
    destination_account_id = models.IntegerField(blank=True, null=True)  # New field for destination account ID
    destination_path = models.CharField(max_length=255, blank=True, null=True)
    error_message = models.CharField(max_length=255, blank=True, null=True)
    source_path = models.CharField(max_length=255)
    source_email = models.EmailField(blank=True, null=True)  # Field for source email
    destination_email = models.EmailField(blank=True, null=True)  # Field for destination email
    status = models.CharField(max_length=255, choices=STATUS_CHOICES, default=PENDING)
    task_type = models.CharField(max_length=255, choices=TASK_TYPE_CHOICES)
    updated_at = models.DateTimeField(auto_now=True)
    user_id = models.CharField(max_length=255)

    def __str__(self):
        return f"Task {self.id} ({self.task_type}) - {self.status}"
