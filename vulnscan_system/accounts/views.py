import logging

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.core.paginator import Paginator
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods

from .decorators import role_required, _client_ip
from .forms import (
    RegistrationForm,
    LoginForm,
    AdminUserEditForm,
)
from .models import User, AuditLogEntry, Role


audit_logger = logging.getLogger("vulnscan.audit")


# ============================================================
# REGISTRATION
# ============================================================

def register(request):
    """
    Public registration.

    All users who register through the public registration page
    are automatically assigned the VIEWER role.

    ADMIN and ANALYST roles can only be assigned by an administrator.
    """

    if request.method == "POST":

        form = RegistrationForm(request.POST)

        if form.is_valid():

            user = form.save()

            client_ip = _client_ip(request)

            AuditLogEntry.objects.create(
                user=user,
                action=AuditLogEntry.Action.REGISTER,
                detail=(
                    f"Self-registered account "
                    f"with role={user.role}"
                ),
                ip_address=client_ip,
            )

            audit_logger.info(
                "User registered: username=%s role=%s ip=%s",
                user.username,
                user.role,
                client_ip,
            )

            messages.success(
                request,
                "Account created successfully. "
                "You can now log in."
            )

            return redirect("accounts:login")

    else:
        form = RegistrationForm()

    return render(
        request,
        "accounts/register.html",
        {
            "form": form,
        },
    )


# ============================================================
# LOGIN
# ============================================================

class AuditingLoginView(LoginView):
    """
    Login view with authentication auditing.

    All authenticated roles currently use the same main dashboard:

        /
        reporting:dashboard

    The role determines what actions/features the user can access.
    """

    form_class = LoginForm
    template_name = "accounts/login.html"

    def get_success_url(self):
        """
        Send every authenticated user to the existing
        reporting dashboard.

        reporting/urls.py currently defines:

            path("", views.dashboard, name="dashboard")

        Therefore the correct named URL is:

            reporting:dashboard
        """

        return "/"

    def form_valid(self, form):
        """
        Process successful authentication.
        """

        response = super().form_valid(form)

        user = form.get_user()
        client_ip = _client_ip(self.request)

        # ----------------------------------------------------
        # UPDATE LAST LOGIN IP
        # ----------------------------------------------------

        user.last_login_ip = client_ip

        user.save(
            update_fields=["last_login_ip"]
        )

        # ----------------------------------------------------
        # AUDIT SUCCESSFUL LOGIN
        # ----------------------------------------------------

        AuditLogEntry.objects.create(
            user=user,
            action=AuditLogEntry.Action.LOGIN_SUCCESS,
            detail=(
                f"Successful login "
                f"role={user.role}"
            ),
            ip_address=client_ip,
        )

        audit_logger.info(
            "Successful login: username=%s role=%s ip=%s",
            user.username,
            user.role,
            client_ip,
        )

        # ----------------------------------------------------
        # REDIRECT TO EXISTING DASHBOARD
        # ----------------------------------------------------

        return redirect("reporting:dashboard")

    def form_invalid(self, form):
        """
        Record failed login attempts.
        """

        attempted_username = (
            self.request.POST.get(
                "username",
                ""
            ).strip()
        )

        client_ip = _client_ip(
            self.request
        )

        AuditLogEntry.objects.create(
            user=None,
            action=AuditLogEntry.Action.LOGIN_FAILURE,
            detail=(
                f"Failed login attempt "
                f"username={attempted_username}"
            ),
            ip_address=client_ip,
        )

        audit_logger.warning(
            "Failed login: username=%s ip=%s",
            attempted_username,
            client_ip,
        )

        return super().form_invalid(form)


# ============================================================
# LOGOUT
# ============================================================

@login_required
@require_http_methods(["POST"])
def logout_view(request):
    """
    Log out the currently authenticated user.
    """

    client_ip = _client_ip(request)

    AuditLogEntry.objects.create(
        user=request.user,
        action=AuditLogEntry.Action.LOGOUT,
        detail="User logged out",
        ip_address=client_ip,
    )

    audit_logger.info(
        "User logout: username=%s ip=%s",
        request.user.username,
        client_ip,
    )

    logout(request)

    return redirect(
        "accounts:login"
    )


# ============================================================
# ADMIN - ACCOUNT MANAGEMENT
# ============================================================

@role_required("ADMIN")
def account_management(request):
    """
    Administrator-only account management.

    Admins can view all users and their roles.
    """

    users = (
        User.objects
        .all()
        .order_by("username")
    )

    return render(
        request,
        "accounts/account_management.html",
        {
            "users": users,
            "roles": Role.choices,
        },
    )


# ============================================================
# ADMIN - EDIT USER
# ============================================================

@role_required("ADMIN")
def edit_user(request, user_id):
    """
    Administrator-only user editing.

    Admin can change:
        - Role
        - Active status
        - Organization
    """

    target = get_object_or_404(
        User,
        pk=user_id
    )

    if request.method == "POST":

        form = AdminUserEditForm(
            request.POST,
            instance=target
        )

        if form.is_valid():

            old_role = target.role

            form.save()

            new_role = form.cleaned_data[
                "role"
            ]

            # ------------------------------------------------
            # RECORD ROLE CHANGE
            # ------------------------------------------------

            if old_role != new_role:

                AuditLogEntry.objects.create(
                    user=request.user,
                    action=(
                        AuditLogEntry
                        .Action
                        .ROLE_CHANGE
                    ),
                    detail=(
                        f"{target.username}: "
                        f"{old_role} -> {new_role}"
                    ),
                    ip_address=_client_ip(
                        request
                    ),
                )

                audit_logger.info(
                    "Role changed: admin=%s target=%s "
                    "old_role=%s new_role=%s",
                    request.user.username,
                    target.username,
                    old_role,
                    new_role,
                )

            messages.success(
                request,
                f"Updated {target.username} successfully."
            )

            return redirect(
                "accounts:account_management"
            )

    else:

        form = AdminUserEditForm(
            instance=target
        )

    return render(
        request,
        "accounts/edit_user.html",
        {
            "form": form,
            "target": target,
        },
    )


# ============================================================
# ADMIN - SYSTEM LOGS
# ============================================================

@role_required("ADMIN")
def system_logs(request):
    """
    Administrator-only system-wide audit logs.
    """

    entries = (
        AuditLogEntry.objects
        .select_related("user")
        .all()
    )

    action_filter = request.GET.get(
        "action"
    )

    if action_filter:
        entries = entries.filter(
            action=action_filter
        )

    paginator = Paginator(
        entries,
        50
    )

    page_obj = paginator.get_page(
        request.GET.get("page")
    )

    return render(
        request,
        "accounts/system_logs.html",
        {
            "page_obj": page_obj,
            "actions": (
                AuditLogEntry
                .Action
                .choices
            ),
            "current_filter": action_filter,
        },
    )
