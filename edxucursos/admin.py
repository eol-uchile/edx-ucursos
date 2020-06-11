from django.contrib import admin

# Register your models here.
from .models import EdxUCursosMapping


class EdxUCursosMappingAdmin(admin.ModelAdmin):
    list_display = ('ucurso_course', 'edx_course')
    search_fields = ['ucurso_course', 'edx_course']


admin.site.register(EdxUCursosMapping, EdxUCursosMappingAdmin)
