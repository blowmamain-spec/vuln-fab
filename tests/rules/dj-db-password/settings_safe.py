import os

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "app",
        "PASSWORD": os.environ["DB_PASSWORD"],
    }
}
