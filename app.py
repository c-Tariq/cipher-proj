from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from wtforms.validators import InputRequired
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import pbkdf2_hmac
import os
import io

key = os.urandom(16)
iv = os.urandom(16)
mode = AES.MODE_CBC
size = AES.block_size
salt = os.urandom(16)
password = "F$2hR&v*Wm9o@H2b"


def get_key(password, salt): 
    return pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=16)
 

def encrypt(data):
    key = get_key(password,salt) 

    encrypter = AES.new(key, mode)

    p_data = pad(data, size)
    c_text = encrypter.encrypt(p_data)
    return salt + encrypter.iv + c_text  


def decrypt(enc_data):
    salt = enc_data[:16]
    iv = enc_data[16:32]  
    c_text = enc_data[32:] 

    key = get_key(password,salt) 
    decrypter = AES.new(key, mode, iv)

    unp_data = decrypter.decrypt(c_text)
    plaintext = unpad(unp_data, size)

    return plaintext


app = Flask(__name__)
app.secret_key = "super_secret_key"  # change this to something secure

# Configure SQL Alchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(180), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    data = db.Column(db.LargeBinary)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Forms
class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")

# Routes
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['username'] = username
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid username or password", 'error')
        return redirect(url_for("home"))

@app.route("/register", methods=["POST"])
def register():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user:
        flash("User already registered!", 'error')
        return redirect(url_for("home"))
    else:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        session['user_id'] = new_user.id
        return redirect(url_for("dashboard"))

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("home"))
    
    form = UploadFileForm()
    user_id = session.get('user_id')
    
    if form.validate_on_submit():
        file = form.file.data

        # File size check
        if len(file.read()) > 50 * 1024 * 1024:
            flash("File too large. Maximum size is 50MB", "error")
            return redirect(url_for("dashboard"))
        file.seek(0)

        # File type check
        allowed_types = {"png", "jpg", "pdf", "txt"}
        if '.' not in file.filename:
            flash("Invalid file type - no extension", "error")
            return redirect(url_for("dashboard"))
        
        extension = file.filename.rsplit(".", 1)[1].lower()
        if extension not in allowed_types:
            flash("Invalid file type", "error")
            return redirect(url_for("dashboard"))

        # Save file to database
        encrypt_data = encrypt(file.read())
        new_file = File(filename=file.filename, data=encrypt_data, user_id=user_id)
        db.session.add(new_file)
        db.session.commit()
        return redirect(url_for("dashboard"))

    files = File.query.filter_by(user_id=user_id).all()
    return render_template("dashboard.html", form=form, files=files, username=session['username'])

@app.route("/download/<int:file_id>")
def download_file(file_id):
    if "username" not in session:
        return redirect(url_for("home"))
    
    file_data = File.query.get(file_id)
    if file_data and file_data.user_id == session['user_id']:
        decrypted_data = decrypt(file_data.data)
        return send_file(io.BytesIO(decrypted_data), download_name=file_data.filename, as_attachment=True)
    else:
        flash("Unauthorized access", "error")
        return redirect(url_for("dashboard"))

@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    if "username" not in session:
        return redirect(url_for("home"))
    
    file_to_delete = File.query.get(file_id)
    if file_to_delete and file_to_delete.user_id == session['user_id']:
        db.session.delete(file_to_delete)
        db.session.commit()
    else:
        flash("Unauthorized action", "error")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("user_id", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
