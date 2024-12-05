from django.contrib.auth import login, logout
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django_filters.rest_framework import DjangoFilterBackend
from .models import Task
from .serializers import TaskSerializer, UserRegisterSerializer, LoginSerializer
from .filters import TaskFilter
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth.hashers import check_password
from .models import UserProfile
from .serializers import UserProfileSerializer, UserUpdateSerializer
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login
from .serializers import LoginSerializer
from django.http import Http404 

from django.contrib.auth.hashers import make_password

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth import login
from .serializers import LoginSerializer

from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSerializer

# Fetch all users
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics
from .models import User
from .serializers import UserSerializer

# views.py
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt  # Disable CSRF protection for simplicity (ensure security in production)
def signup(request):
    if request.method == "POST":
        try:
            # Parse JSON from request body
            data = json.loads(request.body)

            # Extract data
            username = data.get("username")
            password = data.get("password")
            email = data.get("email")

            # Validation
            if not username or not password or not email:
                return JsonResponse({"status": "error", "message": "Missing required fields."}, status=400)

            if User.objects.filter(username=username).exists():
                return JsonResponse({"status": "error", "message": "Username already exists."}, status=400)

            # Create user
            user = User.objects.create_user(username=username, password=password, email=email)
            user.save()

            return JsonResponse({"status": "success", "message": "User created successfully."}, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"status": "error", "message": "Invalid JSON format."}, status=400)

        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    return JsonResponse({"status": "error", "message": "Invalid HTTP method."}, status=405)


class SearchUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
            
        query = request.query_params.get('username', '')
        print(f"Search query: {query}")  # Debug log
        
        users = User.objects.filter(username__icontains=query)
        print(f"Found users: {users.count()}")  # Debug log
        
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)



class SuperuserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            if user and user.is_superuser:
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                print(f"Login successful for superuser: {user.username}")
                print(f"Generated token: {access_token}")
                return Response({
                    "message": "Superuser logged in successfully!",
                    "access": access_token,
                    "refresh": str(refresh),
                    "username": user.username
                }, status=status.HTTP_200_OK)
            print(f"Login failed: User {getattr(user, 'username', 'unknown')} is not a superuser")
            return Response({"error": "Not a superuser"}, status=status.HTTP_403_FORBIDDEN)
        print(f"Login validation failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            serializer = UserProfileSerializer(user_profile)
            data = serializer.data
            data['username'] = request.user.username
            return Response(data)
        except UserProfile.DoesNotExist:
            # Create profile if it doesn't exist
            user_profile = UserProfile.objects.create(user=request.user)
            serializer = UserProfileSerializer(user_profile)
            data = serializer.data
            data['username'] = request.user.username
            return Response(data)
class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def put(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=request.user)

        serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            # Delete old profile picture if it exists
            if profile.profile_picture and 'profile_picture' in request.FILES:
                profile.profile_picture.delete()
            serializer.save()
            return Response({
                "message": "Profile updated successfully",
                "profile_picture": request.build_absolute_uri(profile.profile_picture.url) if profile.profile_picture else None
            })
        return Response(serializer.errors, status=400)

    def delete(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.profile_picture:
                profile.profile_picture.delete()
                profile.profile_picture = None
                profile.save()
            return Response({"message": "Profile picture removed successfully"})
        except UserProfile.DoesNotExist:
            return Response({"message": "Profile not found"}, status=404)

class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        
        # Check if password is being updated and hash it before saving
        password = request.data.get('password')
        if password:
            request.data['password'] = make_password(password)
        
        # Check if username is being updated
        username = request.data.get('username')
        if username:
            # Ensure that the username is unique
            if User.objects.exclude(pk=user.pk).filter(username=username).exists():
                return Response({"message": "Username already taken"}, status=400)
        
        # Pass the data to the serializer
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()  # Save the updated user
            return Response({"message": "User details updated successfully"})
        return Response(serializer.errors, status=400)


# Task List View: View tasks belonging to the logged-in user
class TaskListView(generics.ListAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = (DjangoFilterBackend,)
    filterset_class = TaskFilter
    ordering_fields = ['created_at', 'deadline']
    ordering = ['created_at']

    def get_queryset(self):
        # Restrict tasks to those belonging to the logged-in user
        return Task.objects.filter(user=self.request.user)


# Task Create View: Create a new task linked to the logged-in user
class TaskCreateView(generics.CreateAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        # Save the task with the current logged-in user
        serializer.save(user=self.request.user)


# Task Update View: Update tasks belonging to the logged-in user
class TaskUpdateView(generics.UpdateAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Restrict updates to tasks belonging to the logged-in user
        return Task.objects.filter(user=self.request.user)


# Task Delete View: Delete tasks belonging to the logged-in user
class TaskDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Restrict deletions to tasks belonging to the logged-in user
        return Task.objects.filter(user=self.request.user)


# Register View: Create a new user
class RegisterView(APIView):
    permission_classes = [AllowAny]  # Allow anyone to register

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "User registered successfully!",
                "user": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "Logged in successfully!",
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# Logout View: Log out the user
class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logout(request)
        return Response({"message": "Logged out successfully!"}, status=status.HTTP_200_OK)

# Add these new views
class AllUsersView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        auth_header = request.headers.get('Authorization', '')
        print(f"Auth header: {auth_header}")
        print(f"User: {request.user}")
        print(f"Is authenticated: {request.user.is_authenticated}")
        print(f"Is superuser: {request.user.is_superuser}")
        
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

class AllTasksView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        auth_header = request.headers.get('Authorization', '')
        print(f"Auth header: {auth_header}")
        print(f"User: {request.user}")
        print(f"Is authenticated: {request.user.is_authenticated}")
        print(f"Is superuser: {request.user.is_superuser}")
        
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
        tasks = Task.objects.all()
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)

class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return Response({"message": "User deleted successfully"})
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

class UserTasksView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(pk=user_id)
            tasks = Task.objects.filter(user=user)
            serializer = TaskSerializer(tasks, many=True)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
