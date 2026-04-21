# -- Figure_Service.py
# -- Imports
from models.models import db, Figures, Brand, Manufacturer
from werkzeug.utils import secure_filename

# -- LOCATE FOLDER AND SET ALLOWED_EXTENSIONS TYPES
UPLOAD_FOLDER = "static/figure_images"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

# -- ALLOWED_EXTENSIONS TYPES
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    
# ADD FIGURE FORUM
def add_figure(form_data):
    required_fields = [
        "figname", "figdesc", "brandID", "manufacturerID",
        "genre", "series", "releaseDate",
        "retailPrice", "avgPrice", "itemSize", "links"
    ]

    for field in required_fields:
        if not form_data.get(field):
            return f"Field '{field}' is required."

    try:
        new_figure = Figures(
            name=form_data["figname"].strip(),
            desc=form_data["figdesc"].strip(),
            brandID=int(form_data["brandID"]),
            manufacturerID=int(form_data["manufacturerID"]),
            genre=form_data["genre"].strip(),
            series=form_data["series"].strip(),
            releaseDate=form_data["releaseDate"],
            retailPrice=float(form_data["retailPrice"]),
            avgPrice=float(form_data["avgPrice"]),
            itemSize=float(form_data["itemSize"]),
            itemWeight=float(form_data.get("itemWeight") or 0),
            links=form_data["links"].strip()
        )

        db.session.add(new_figure)
        db.session.commit()
        return None

    except ValueError:
        db.session.rollback()
        return "Invalid number format in price/size fields."

    except Exception as e:
        db.session.rollback()
        return f"Error adding figure: {str(e)}"

# GET ALL BRANDS
def get_all_brands():
    return Brand.query.all()

# GET ALL MANUFACTURERS
def get_all_manufacturers():
    return Manufacturer.query.all()
    
# ADD BRAND FORUM
def add_brand(form_data):
    name = form_data.get("name", "").strip()
    desc = form_data.get("desc", "").strip()

    if not name or not desc:
        return "All fields are required."

    if len(name) > 100:
        return "Brand name too long."

    if len(desc) > 1000:
        return "Description too long."

    existing = Brand.query.filter_by(name=name).first()
    if existing:
        return "Brand already exists."

    db.session.add(Brand(name=name, desc=desc))
    db.session.commit()
    return None


# ADD MANUFACTURERS FORUM
def add_manufacturer(form_data):
    name = form_data.get("name", "").strip()
    desc = form_data.get("desc", "").strip()

    if not name or not desc:
        return "All fields are required."

    if len(name) > 100:
        return "Manufacturer name too long."

    if len(desc) > 1000:
        return "Description too long."

    existing = Manufacturer.query.filter_by(name=name).first()
    if existing:
        return "Manufacturer already exists."

    db.session.add(Manufacturer(name=name, desc=desc))
    db.session.commit()
    return None