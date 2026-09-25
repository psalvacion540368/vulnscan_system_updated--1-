"""
Django settings for the Vulnerability Scanning & Assessment System.

Five modules map to five apps:
  accounts    -> Auth & RBAC
  scanning    -> Network Scanning & Packet Execution Engine
  vulnassess  -> Vulnerability Assessment & Correlation Engine
  reporting   -> Presentation & Reporting Engine
(Data Persistence Layer = Django ORM + MySQL, configured below)
"""

import os
from pathlib import Path
from datetime import timedelta

from dotenv import load_dotenv
load_dotenv()

# MySQL driver auto-selection: use mysqlclient if installed (preferred, faster);
# otherwise fall back to PyMySQL transparently. This means either
# `pip install mysqlclient` or `pip install pymysql` works with no further
# settings.py changes needed.
try:
    import MySQLdb  # noqa: F401
except ImportError:
    try:
        import pymysql
        pymysql.install_as_MySQLdb()
    except ImportError:
        pass  # neither driver installed -- only an issue if VULNSCAN_USE_SQLITE=False

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Core / security
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "CHANGE-ME-IN-PRODUCTION")
DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",

    # Project apps (the five modules)
    "accounts",
    "scanning",
    "vulnassess",
    "reporting",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Custom audit-trail middleware: logs every authenticated request
    "accounts.middleware.AuditLogMiddleware",
]

ROOT_URLCONF = "vulnscan.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "vulnscan.wsgi.application"

# ---------------------------------------------------------------------------
# Data Persistence Layer -- Django ORM on MySQL
# ---------------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("DB_NAME", "vulnscan_db"),
        "USER": os.environ.get("DB_USER", "vulnscan_app"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "VulnScan2026!"),
        "HOST": os.environ.get("DB_HOST", "127.0.0.1"),
        "PORT": os.environ.get("DB_PORT", "3306"),
        "OPTIONS": {
            "charset": "utf8mb4",
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}
# For quick local evaluation without MySQL installed, set VULNSCAN_USE_SQLITE=True
if os.environ.get("VULNSCAN_USE_SQLITE", "False") == "True":
    DATABASES["default"] = {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }

AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {"NAME": "accounts.validators.ComplexityValidator"},
]

# PBKDF2 first (Django default, FIPS-friendly); BCrypt as an available alternative.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "reporting:dashboard"
LOGOUT_REDIRECT_URL = "accounts:login"

# Session hardening
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 60 * 60 * 8  # 8 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_HTTPONLY = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"
# Flip these on when served over HTTPS in production
SESSION_COOKIE_SECURE = os.environ.get("DJANGO_HTTPS", "False") == "True"
CSRF_COOKIE_SECURE = os.environ.get("DJANGO_HTTPS", "False") == "True"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Manila"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"  # generated PDF/CSV reports land in media/reports/

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# App-specific settings
# ---------------------------------------------------------------------------
# Scanning engine
SCAN_MAX_CONCURRENT_JOBS = int(os.environ.get("SCAN_MAX_CONCURRENT_JOBS", 2))
SCAN_DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("SCAN_DEFAULT_TIMEOUT_SECONDS", 600))
# Only these networks may be scanned -- authorization guardrail, edit for your environment.
SCAN_ALLOWED_CIDRS = os.environ.get("SCAN_ALLOWED_CIDRS", "").split(",") if os.environ.get("SCAN_ALLOWED_CIDRS") else []
# Only these hostnames/domains (and their subdomains) may be scanned as web targets.
# Empty by default -- deny-all until explicitly opted in, since a domain can point
# anywhere on the public internet, unlike a private CIDR range.
SCAN_ALLOWED_DOMAINS = os.environ.get("SCAN_ALLOWED_DOMAINS", "").split(",") if os.environ.get("SCAN_ALLOWED_DOMAINS") else []
NMAP_PATH = os.environ.get("NMAP_PATH", "/usr/bin/nmap")

# Vulnerability correlation engine
CVE_LOCAL_DB_PATH = BASE_DIR / "vulnassess" / "data" / "cve_local_db.json"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # optional; raises NVD rate limits

# Logging: authentication events, scan actions, and admin actions all logged.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {"format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
        "audit_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": BASE_DIR / "logs" / "audit.log",
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
            "formatter": "verbose",
        },
    },
    "loggers": {
        "vulnscan.audit": {"handlers": ["console", "audit_file"], "level": "INFO", "propagate": False},
        "django": {"handlers": ["console"], "level": "WARNING"},
    },
}
os.makedirs(BASE_DIR / "logs", exist_ok=True)
