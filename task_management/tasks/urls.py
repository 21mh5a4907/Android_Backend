from django.urls import path
from . import views

urlpatterns = [
    # User Profile and Update URLs
    path('profile/', views.UserProfileView.as_view(), name='user-profile'),
    path('profile/update/', views.ProfileUpdateView.as_view(), name='profile-update'),
    path('user/update/', views.UserUpdateView.as_view(), name='user-update'),

    # Task URLs
    path('tasks/', views.TaskListView.as_view(), name='task-list'),
    path('tasks/create/', views.TaskCreateView.as_view(), name='task-create'),
    path('tasks/<int:pk>/', views.TaskUpdateView.as_view(), name='task-update'),
    path('tasks/delete/<int:pk>/', views.TaskDeleteView.as_view(), name='task-delete'),

    # User Registration and Login/Logout URLs
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    
    # Superuser Login
    path('superuser-login/', views.SuperuserLoginView.as_view(), name='superuser-login'),

    # Superuser User Management URLs
    path('users/', views.AllUsersView.as_view(), name='all-users'),
    path('all-tasks/', views.AllTasksView.as_view(), name='all-tasks'),
    path('users/search/', views.SearchUsersView.as_view(), name='search-users'),
    path('users/<int:pk>/delete/', views.DeleteUserView.as_view(), name='delete-user'),
    path('users/<int:user_id>/tasks/', views.UserTasksView.as_view(), name='user-tasks'),
     path("signup/", views.signup, name="signup")
]
