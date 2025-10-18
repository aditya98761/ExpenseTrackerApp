from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from datetime import datetime
from azure.storage.blob import BlobServiceClient
from werkzeug.utils import secure_filename
import os
import urllib
import uuid


# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# === START: NEW DATABASE CONFIGURATION ===
# Get the connection string from an environment variable
connection_string = os.environ.get("AZURE_SQL_CONNECTION_STRING")

# If the connection string is found, use Azure SQL. Otherwise, use local SQLite.
if connection_string:
    print("✅ Production mode: Using Azure SQL Database.")
    params = urllib.parse.quote_plus(connection_string)
    app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc:///?odbc_connect=%s" % params
else:
    print("⚠️ Development mode: AZURE_SQL_CONNECTION_STRING not found. Using local SQLite.")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# === END: NEW DATABASE CONFIGURATION ===

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):  # Inherit from UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    budget = db.Column(db.Float, default=0.0)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    date = db.Column(db.Date, default=datetime.utcnow)
    receipt_url = db.Column(db.String(512), nullable=True)  # Use snake_case for all file-related fields

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:  # Redirect logged-in users to the dashboard
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already exists. Please choose another.", "error")
            return redirect(url_for('register'))

        # Create a new user
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # If already logged in, redirect to the dashboard
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
    # Fetch user's expenses
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    
    # Calculate the total expense for the user
    total_expense = sum(expense.amount for expense in expenses)

    return render_template(
        'dashboard.html',
        expenses=expenses,
        total_expense=total_expense
    )

connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
container_name = "receipts" # Name of your container

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        description = request.form['description']
        receipt_file = request.files.get('receipt')
        receipt_url = None
        # Check if a file was uploaded and has a filename
        if receipt_file and receipt_file.filename:
            try:
                # Secure the original filename and get its extension
                original_filename = secure_filename(receipt_file.filename)
                file_extension = os.path.splitext(original_filename)[1]
                # Generate a unique filename using UUID to prevent conflicts
                unique_filename = str(uuid.uuid4()) + file_extension
                # Get the connection string from your App Service configuration
                connect_str = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
                container_name = "receipts" # IMPORTANT: Create a container with this name
                if not connect_str:
                    flash("Storage is not configured on the server.", "error")
                    return redirect(url_for('dashboard'))
                # Connect to blob service
                blob_service_client = BlobServiceClient.from_connection_string(connect_str)
                blob_client = blob_service_client.get_blob_client(
                    container=container_name, blob=unique_filename
                )
                # Upload the file and get its URL
                blob_client.upload_blob(receipt_file)
                receipt_url = blob_client.url
            except Exception as e:
                flash(f"An error occurred during file upload: {e}", "error")
                return redirect(url_for('dashboard'))
        # Create the expense with the receipt URL (which is None if no file was uploaded)
        new_expense = Expense(
            user_id=current_user.id,
            amount=amount,
            description=description,
            receipt_url=receipt_url
        )
        db.session.add(new_expense)
        db.session.commit()
        print(f"DEBUG: Saving expense with receipt URL: {receipt_url}")
        flash("Expense added successfully!")
        return redirect(url_for('dashboard'))
    return render_template('add_expense.html')

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

# New route for viewing expenses
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



# Initialize database
with app.app_context():
    db.create_all()
    print("Database tables created!")



if __name__ == '__main__':
    app.run(debug=True)




