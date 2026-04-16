import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROFILE_PICS_FOLDER = os.path.join(BASE_DIR, "profile_pics")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "figure_images")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}