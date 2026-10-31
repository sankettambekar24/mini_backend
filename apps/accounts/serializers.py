from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from apps.accounts.models import UserRole

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Registration serializer.
    - Always creates a USER role; ADMIN cannot be self-assigned.
    - Password is write-only; it is hashed by the user model.
    """

    password = serializers.CharField(write_only=True, min_length=10, style={"input_type": "password"})

    class Meta:
        model = User
        fields = ["username", "password"]

    def validate_username(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Username cannot be blank.")
        if len(value) > 64:
            raise serializers.ValidationError("Username must be 64 characters or fewer.")
        return value

    def validate_password(self, value):
        candidate = User(username=self.initial_data.get("username", "").strip())
        try:
            validate_password(value, candidate)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages)) from exc
        return value

    def create(self, validated_data):
        # Explicitly set USER role; never allow client to supply it.
        return User.objects.create_user(
            username=validated_data["username"],
            password=validated_data["password"],
            role=UserRole.USER,
        )


class UserProfileSerializer(serializers.ModelSerializer):
    """Read-only safe profile for the /auth/me/ endpoint."""

    class Meta:
        model = User
        fields = ["id", "username", "role", "is_active", "created_at", "last_login_at"]
        read_only_fields = fields


class AdminUserCreateSerializer(serializers.ModelSerializer):
    """
    Admin-only user creation serializer.
    Allows specifying role (defaults to USER).
    Hashes password properly and returns safe profile.
    """

    password = serializers.CharField(write_only=True, min_length=10, style={"input_type": "password"})
    role = serializers.ChoiceField(choices=UserRole.choices, default=UserRole.USER)

    class Meta:
        model = User
        fields = ["id", "username", "password", "role", "is_active", "created_at"]
        read_only_fields = ["id", "is_active", "created_at"]

    def validate_username(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Username cannot be blank.")
        if len(value) > 64:
            raise serializers.ValidationError("Username must be 64 characters or fewer.")
        return value

    def validate(self, attrs):
        if attrs.get("role", UserRole.USER) == UserRole.ADMIN and User.objects.filter(
            role=UserRole.ADMIN
        ).exists():
            raise serializers.ValidationError({"role": "The designated administrator already exists."})
        candidate = User(username=attrs["username"])
        try:
            validate_password(attrs["password"], candidate)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password": list(exc.messages)}) from exc
        return attrs

    def create(self, validated_data):
        role = validated_data.get("role", UserRole.USER)
        if role == UserRole.ADMIN:
            return User.objects.create_superuser(
                username=validated_data["username"],
                password=validated_data["password"],
            )
        return User.objects.create_user(
            username=validated_data["username"],
            password=validated_data["password"],
            role=UserRole.USER,
        )


class AdminUserListSerializer(serializers.ModelSerializer):
    """Admin-only serializer for listing users."""

    class Meta:
        model = User
        fields = ["id", "username", "role", "is_active", "created_at", "updated_at", "last_login_at"]
        read_only_fields = fields


class AdminUserUpdateSerializer(serializers.ModelSerializer):
    """Admin-only serializer for patching user fields."""

    class Meta:
        model = User
        fields = ["is_active"]

    def validate(self, attrs):
        # Prevent an admin from deactivating themselves via this endpoint.
        request = self.context.get("request")
        if request and str(self.instance.id) == str(request.user.id):
            if "is_active" in attrs and not attrs["is_active"]:
                raise serializers.ValidationError("An admin cannot deactivate their own account.")
        return attrs


class AdminRoleChangeSerializer(serializers.Serializer):
    """Admin-only role change request. Validated and audited in the view."""

    role = serializers.ChoiceField(choices=UserRole.choices)

    def validate_role(self, value):
        # Only ADMIN can promote to ADMIN; this is double-checked in the view.
        return value
