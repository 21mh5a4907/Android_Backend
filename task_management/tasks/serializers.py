from django.contrib.auth.models import User
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import Task, UserProfile

# User serializer to expose user details
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

# UserProfile serializer to expose user's profile picture
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['profile_picture']

# Serializer to update user details, including changing passwords
class UserUpdateSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['username', 'old_password', 'new_password']

    def validate(self, data):
        if 'old_password' in data and 'new_password' in data:
            if not self.instance.check_password(data['old_password']):
                raise serializers.ValidationError({"old_password": "Wrong password"})
        return data

    def update(self, instance, validated_data):
        if 'new_password' in validated_data:
            instance.set_password(validated_data['new_password'])
        if 'username' in validated_data:
            instance.username = validated_data['username']
        instance.save()
        return instance

# Serializer for updating user profile (username, email, password)
class ProfileSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField(required=False, write_only=True)

    def validate_username(self, value):
        user = self.context.get('request').user
        if User.objects.exclude(pk=user.pk).filter(username=value).exists():
            raise serializers.ValidationError("This username is already in use.")
        return value

    def validate_email(self, value):
        user = self.context.get('request').user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

# Task serializer to manage task-related data
class TaskSerializer(serializers.ModelSerializer):
    creator = serializers.SerializerMethodField()

    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'status', 'priority', 'deadline', 'created_at', 'creator']

    def get_creator(self, obj):
        return obj.user.username if obj.user else "Unknown"

# Serializer for user registration (creating a new user)
class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email']
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True}
        }

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data['email']
        )
        return user

# Serializer for login (user authentication)
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        # Authenticate the user
        user = authenticate(username=username, password=password)
        if user is None:
            raise serializers.ValidationError("Invalid credentials")
        
        return {'user': user}