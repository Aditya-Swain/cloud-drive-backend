from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import UserProfile  # Make sure UserProfile is imported

# Register the UserProfile model
admin.site.register(UserProfile)
