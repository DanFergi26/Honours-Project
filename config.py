# -- Imports --
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -- CREATE AND LOCATE EXCESS FILES
PROFILE_PICS_FOLDER = os.path.join(BASE_DIR, "profile_pics")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "figure_images")
SUBIMG_FOLDER = os.path.join("static", "subimg")
os.makedirs(SUBIMG_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}