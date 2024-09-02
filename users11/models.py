from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (('Admin', 'Admin'), ('User', 'User'))
    name = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(max_length=245, unique=True)
    emp_id = models.CharField(max_length=255, unique=True, null=False, default='EMP101')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='User')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    password_last_changed = models.DateTimeField(auto_now_add=True)
    login_attempts = models.IntegerField(default=0)
    account_locked = models.BooleanField(default=False)
    force_password_change = models.BooleanField(default=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

class PasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    email = models.EmailField(max_length=245)  # Store email associated with the password change
    old_password = models.CharField(max_length=128)
    changed_at = models.DateTimeField(auto_now_add=True)
