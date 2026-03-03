from models.models import db, Figures, Brand, Manufacturer

# ------------------- Add Figure -------------------
def add_figure(form_data):
    required_fields = [
        "figname", "figdesc", "brandID", "manufacturerID",
        "genre", "series", "figCode", "janCode",
        "releaseDate", "retailPrice", "avgPrice", "itemSize", "links"
    ]

    # Check for missing fields
    for field in required_fields:
        if not form_data.get(field):
            return f"Field '{field}' is required."

    try:
        new_figure = Figures(
            name=form_data["figname"],
            desc=form_data["figdesc"],
            brandID=int(form_data["brandID"]),
            manufacturerID=int(form_data["manufacturerID"]),
            genre=form_data["genre"],
            series=form_data["series"],
            figCode=form_data["figCode"],
            janCode=form_data["janCode"],
            releaseDate=form_data["releaseDate"],
            retailPrice=float(form_data["retailPrice"]),
            avgPrice=float(form_data["avgPrice"]),
            itemSize=form_data["itemSize"],
            itemWeight=float(form_data.get("itemWeight", 0)),
            links=form_data["links"]
        )

        db.session.add(new_figure)
        db.session.commit()
        return None  # No error

    except Exception as e:
        db.session.rollback()
        return f"Error adding figure: {str(e)}"

# ------------------- Get All Brands -------------------
def get_all_brands():
    return Brand.query.all()

# ------------------- Get All Manufacturers -------------------
def get_all_manufacturers():
    return Manufacturer.query.all()