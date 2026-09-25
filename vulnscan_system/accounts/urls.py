from django.urls import path
from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.AuditingLoginView.as_view(), name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("manage/", views.account_management, name="account_management"),
    path("manage/<int:user_id>/", views.edit_user, name="edit_user"),
    path("logs/", views.system_logs, name="system_logs"),
]
