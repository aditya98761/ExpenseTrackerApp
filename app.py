from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from datetime import datetime
import os
import urllib
import uuid
from azure.storage.blob import BlobServiceClient
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# === DATABASE CONFIGURATION ===
connection_string = os.environ.get("AZURE_SQL_CONNECTION_STRING")

if connection_string:
    print("✅ Production mode: Using Azure SQL Database.")
    params = urllib.parse.quote_plus(connection_string)
    app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc:///?odbc_connect=%s" % params
else:
    print("⚠️ Development mode: Using local SQLite.")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# === END DATABASE CONFIGURATION ===


# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False) # Increased size
    budget = db.Column(db.Float, default=0.0)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    date = db.Column(db.Date, default=datetime.utcnow)
    receipt_url = db.Column(db.String(512), nullable=True) # Receipt URL column

# Forms (Omitted for brevity, your existing forms are fine)
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('home.html')

# (register, login, logout routes are fine)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already exists. Please choose another.", "error")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.")
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    total_expense = sum(expense.amount for expense in expenses)
    return render_template('dashboard.html', expenses=expenses, total_expense=total_expense)

# --- START: CORRECTED ADD_EXPENSE FUNCTION ---
@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        description = request.form['description']
        receipt_file = request.files.get('receipt')
        receipt_url = None

        if receipt_file and receipt_file.filename:
            print("DEBUG: File detected. Starting upload process...")
            try:
                connect_str = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
                container_name = "receipts"

                if not connect_str:
                    print("DEBUG ERROR: AZURE_STORAGE_CONNECTION_STRING is not set!")
                    flash("Storage is not configured on the server.", "error")
                    return redirect(url_for('dashboard'))

                print("DEBUG: Connection string found. Creating BlobServiceClient...")
                blob_service_client = BlobServiceClient.from_connection_string(connect_str)
                
                original_filename = secure_filename(receipt_file.filename)
                file_extension = os.path.splitext(original_filename)[1]
                unique_filename = str(uuid.uuid4()) + file_extension
                
                print(f"DEBUG: Generated unique filename: {unique_filename}")
                blob_client = blob_service_client.get_blob_client(
                    container=container_name, blob=unique_filename
                )

                print("DEBUG: Attempting to upload blob...")
                blob_client.upload_blob(receipt_file)
                receipt_url = blob_client.url
                print(f"DEBUG: Upload successful! URL is {receipt_url}")

            except Exception as e:
                print("--- DEBUG: UPLOAD FAILED ---")
                print(f"An unexpected error occurred: {e}")
                print("-----------------------------")
                flash("A critical error occurred during file upload. Please check server logs.", "error")
                return redirect(url_for('dashboard'))

        new_expense = Expense(
            user_id=current_user.id,
            amount=amount,
            description=description,
            receipt_url=receipt_url
        )
        db.session.add(new_expense)
        print(f"DEBUG: Saving expense with receipt URL: {receipt_url}")
        db.session.commit()
        flash("Expense added successfully!")
        return redirect(url_for('dashboard'))
        
    return render_template('add_expense.html')
# --- END: CORRECTED ADD_EXPENSE FUNCTION ---


@app.route('/update_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def update_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if request.method == 'POST':
        expense.amount = float(request.form['amount'])
        expense.description = request.form['description']
        db.session.commit()
        flash("Expense updated successfully!")
        return redirect(url_for('dashboard'))
    return render_template('update_expense.html', expense=expense)


@app.route('/view_expenses')
@login_required
def view_expenses():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('view_expenses.html', expenses=expenses)


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash("You do not have permission to delete this expense.", "error")
        return redirect(url_for('dashboard'))
    
    db.session.delete(expense)
    db.session.commit()
    flash("Expense deleted successfully!")
    return redirect(url_for('dashboard'))

with app.app_context():
    db.create_all()
    print("Database tables created!")

if __name__ == '__main__':
    app.run(debug=True)
