from django.contrib import admin
from django.contrib.auth import get_user_model

User = get_user_model()


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ["username", "role", "is_active", "created_at"]
    list_filter = ["role", "is_active"]
    search_fields = ["username"]
    readonly_fields = [
        "id", "username", "email", "role", "is_staff", "is_superuser", "is_active",
        "token_version", "created_at", "updated_at", "last_login_at",
    ]
    # Never expose password hashes in the list view
    exclude = ["password"]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
