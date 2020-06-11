# -*- coding: utf-8 -*-
# Generated by Django 1.11.21 on 2020-06-11 16:53
from __future__ import unicode_literals

from django.db import migrations, models
import opaque_keys.edx.django.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('edxucursos', '0002_auto_20200611_1537'),
    ]

    operations = [
        migrations.CreateModel(
            name='EdxUCursosMapping',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('edx_course', opaque_keys.edx.django.models.CourseKeyField(max_length=255)),
                ('ucurso_course', models.CharField(db_index=True, max_length=255, unique=True)),
            ],
        ),
    ]
