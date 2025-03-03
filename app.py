from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configurations
app.secret_key = "Project-key"
app.permanent_session_lifetime = timedelta(days=10)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords
    is_admin = db.Column(db.Boolean, default=False)

# Create database tables
with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("home.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session.permanent = True
            session["user_email"] = email
            session["is_admin"] = user.is_admin  
            
            print("✅ User authenticated! Redirecting to home...")  # Debugging
            flash("User Logged In Successfully", "success")
            return redirect(url_for("home"))  # Redirect to home

        else:
            # print("❌ Invalid login attempt!")  # Debugging
            flash("Invalid email or password", "danger")
            return redirect(url_for("home"))  # Stay on login page

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("home"))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Signup successful! Please log in.", "success")
        return redirect(url_for("home"))  # Redirect to home where flash message will be visible
    
    return render_template("signup.html")

@app.route("/aboutus")
def aboutFunction():
    return render_template("aboutus.html")


@app.route("/resources")
def resources():
    if "user_email" in session:
        return render_template("resources.html")
    else:
        flash("Unauthorized access! Please log in.", "warning")
        return redirect(url_for("home"))

@app.route("/pricing")
def pricing():
    if "user_email" in session:
        return render_template("pricing.html")
    else:
        flash("Unauthorized access! Please log in.", "warning")
        return redirect(url_for("home"))

@app.route("/features")
def features():
    if "user_email" not in session:
        # flash("Unauthorized access! Please log in first.", "warning")
        return redirect(url_for("login"))  # Redirect to the login page

    return render_template("features.html")



@app.route("/logout")
def logout():
    if "user-key" in session:
        session.pop("user-key",None)
        flash("User Logged Out Successfully","Info")
        return redirect(url_for("home"))
    else:
        flash("User already Logged out","Info")
        return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
