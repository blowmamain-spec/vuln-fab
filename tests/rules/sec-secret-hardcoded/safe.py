import os

SECRET_KEY = os.environ["SECRET_KEY"]
PASSWORD = os.environ.get("DB_PASSWORD", "")
token = "changeme"
API_URL = "https://internal.example.com/api"
password_help = "Use at least twelve characters"
