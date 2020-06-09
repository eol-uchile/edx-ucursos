from django.contrib import admin

# Register your models here.
from .models import EdxUCursosTokens


class EdxUCursosTokensAdmin(admin.ModelAdmin):
    list_display = ('token', 'user')
    search_fields = ['token', 'user__username']


admin.site.register(EdxUCursosTokens, EdxUCursosTokensAdmin)
