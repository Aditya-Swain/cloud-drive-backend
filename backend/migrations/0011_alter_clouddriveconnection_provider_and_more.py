# Generated by Django 5.1.4 on 2025-01-30 10:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0010_remove_task_destination_access_token_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='clouddriveconnection',
            name='provider',
            field=models.CharField(choices=[('google', 'Google Drive'), ('dropbox', 'Dropbox'), ('onedrive', 'OneDrive')], max_length=50),
        ),
        migrations.AlterField(
            model_name='task',
            name='status',
            field=models.CharField(choices=[('PENDING', 'Pending'), ('IN_PROGRESS', 'In Progress'), ('COMPLETED', 'Completed'), ('FAILED', 'Failed')], default='PENDING', max_length=255),
        ),
    ]
