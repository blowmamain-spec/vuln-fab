import os

# @lab decoy secret-key cwe=CWE-798 :: kunci dibaca dari environment
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# @lab decoy debug-true cwe=CWE-489 :: DEBUG dari environment
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"

# @lab decoy allowed-hosts cwe=CWE-644 :: host eksplisit
ALLOWED_HOSTS = ["shop.example.com"]

# @lab decoy password-hasher cwe=CWE-916 :: PBKDF2 sebagai hasher utama
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
]

# @lab decoy pickle-session cwe=CWE-502 :: JSON
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"

INSTALLED_APPS = ["django.contrib.auth"]
