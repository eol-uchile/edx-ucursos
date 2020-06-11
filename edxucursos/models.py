from django.db import models
from opaque_keys.edx.django.models import CourseKeyField
# Create your models here.


class EdxUCursosMapping(models.Model):
    edx_course = CourseKeyField(max_length=255)
    ucurso_course = models.CharField(
        max_length=255, unique=True, db_index=True)
