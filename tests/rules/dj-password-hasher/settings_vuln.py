PASSWORD_HASHERS = [  # vuln: dj-password-hasher
    "django.contrib.auth.hashers.MD5PasswordHasher",
]
