from django.contrib.auth.models import User
from django.db import models

# Create your models here.


class EdxUCursosTokens(models.Model):
    token = models.CharField(max_length=36, unique=True, db_index=True)
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        blank=False,
        null=False)
