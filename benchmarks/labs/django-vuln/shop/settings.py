import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# @lab vuln secret-key cwe=CWE-798 tier=A :: kunci rahasia tertulis di kode
SECRET_KEY = "lab-only-not-a-real-key"

# @lab vuln debug-true cwe=CWE-489 tier=A :: DEBUG aktif
DEBUG = True

# @lab vuln allowed-hosts cwe=CWE-644 tier=A :: semua host diterima
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "catalog",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

ROOT_URLCONF = "shop.urls"

# @lab vuln password-hasher cwe=CWE-916 tier=A :: hasher MD5 sebagai hasher utama
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# @lab vuln pickle-session cwe=CWE-502 tier=A :: sesi diserialisasi dengan pickle
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"

# @lab vuln cookie-httponly cwe=CWE-1004 tier=A :: cookie sesi terbaca JavaScript
SESSION_COOKIE_HTTPONLY = False

# @lab decoy cookie-httponly cwe=CWE-1004 :: nilai bawaan aman
CSRF_COOKIE_HTTPONLY = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
    }
}
