from django.contrib import admin
from django.urls import path
from .views import RegisterView, LoginView, UserView, LogoutView, sendOTPView
from .views import AdminChangePasswordView, AdminUserListView,ChangePasswordView,OTPVerificationView
urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('send-otp/', sendOTPView.as_view()),
    path('verify-otp/', OTPVerificationView.as_view()),
    path('user-change-password/', ChangePasswordView.as_view()),
    path('admin-change-password/', AdminChangePasswordView.as_view()),
    path('list-all-users/', AdminUserListView.as_view())
]
