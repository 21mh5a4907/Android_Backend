# tasks/models.py

from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db import models

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)

    def __str__(self):
        return self.user.username

class Task(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    STATUS_CHOICES = [
        ('yet-to-start', 'Yet to start'),
        ('in-progress', 'In progress'),
        ('completed', 'Completed'),
        ('hold', 'Hold'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tasks')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    priority = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High')
    ], default='medium')
    status = models.CharField(max_length=20, choices=[
        ('yet-to-start', 'Yet to start'),
        ('in-progress', 'In progress'),
        ('completed', 'Completed'),
        ('hold', 'Hold')
    ], default='yet-to-start')
    deadline = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']  # Default ordering by creation date (newest first)
        indexes = [
            models.Index(fields=['user', 'status']),  # Add index for common queries
            models.Index(fields=['deadline']),
        ]

    def __str__(self):
        return f"{self.title} - {self.user.username}"
