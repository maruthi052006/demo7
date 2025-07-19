from django.db import models
from django.contrib.auth.models import User

class UserProfiles(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    github_username = models.CharField(max_length=100)
    github_token = models.CharField(max_length=200)

    def _str_(self):
        return self.user

class ProjectUploads(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    repository_name = models.CharField(max_length=100)
    project_zip = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return self.repository_name
