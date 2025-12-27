import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, Blueprint,make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func, text
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime, timezone
from sqlalchemy import and_, or_
from datetime import datetime, timedelta
import random
from collections import defaultdict
from dateutil.relativedelta import relativedelta
from flask_cors import CORS, cross_origin
import csv
import io
from io import StringIO,BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from PyPDF2 import PdfReader



# Create the savings blueprint
savings_bp = Blueprint('savings', __name__)
transactions_bp = Blueprint('transactions', __name__)

app = Flask(__name__)


CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Ensures redirects to the 'login' route
@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'success': False, 'message': 'Unauthorized'}), 401
# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Taruni%4097@127.0.0.1:3306/financeManager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-secret-key-here'  # Change this to a strong random key in production

db = SQLAlchemy(app)
logging.basicConfig(level=logging.DEBUG)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column('userId', db.Integer, primary_key=True, autoincrement=True)
    username = db.Column('userName', db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)  # Stores the hashed password
    created_at = db.Column(db.TIMESTAMP, server_default=func.now())
    transactions = db.relationship(
        'Transaction', 
        backref='user', 
        lazy=True,  
        cascade='all, delete-orphan',  
        passive_deletes=True           
    )
    def get_id(self):
        return str(self.user_id)

    # CORRECTED: Use self.password (matches the column name)
    def check_password(self, password):
        return check_password_hash(self.password, password)  # Fixed here
    
    def set_password(self, password):
        # CORRECTED: Hashes the password and saves to self.password
        self.password = generate_password_hash(password, method='scrypt')

class User_Profile(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), unique=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    street = db.Column(db.String(100))
    city = db.Column(db.String(50))
    zip_code = db.Column(db.String(20))
    country = db.Column(db.String(50))
    
    user = db.relationship('User', backref=db.backref('profile', lazy=True))

class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), default='completed')
    user_id = db.Column('userId', db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    
    
class Savings_Goals(db.Model):
    __tablename__ = 'savings_goals'
    
    goal_id = db.Column('goalId', db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('userId', db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    goalname = db.Column('goalName', db.String(100), nullable=False)
    currentamount = db.Column('currentAmount', db.Float, nullable=False)  # Changed to Float
    targetamount = db.Column('targetAmount', db.Float, nullable=False)    # Changed to Float
    startdate = db.Column('startDate', db.DateTime, default=datetime.now(timezone.utc))
    priority = db.Column('priority', db.String(10))
    deadline = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.String(255))
    user = db.relationship('User', backref='savings_goals')
    transactions = db.relationship('SavingTransaction', backref='goal', lazy=True, cascade='all, delete-orphan')

class SavingTransaction(db.Model):
    __tablename__ = 'saving_transaction'

    transaction_id = db.Column('transactionId', db.Integer, primary_key=True, autoincrement=True)
    goal_id = db.Column('goalId', db.Integer, db.ForeignKey('savings_goals.goalId', ondelete='CASCADE'), nullable=False)
    user_id = db.Column('userId', db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column('receivedDate', db.TIMESTAMP, server_default=func.now())
    note = db.Column(db.String(255))
    user = db.relationship('User', backref='saving_transactions')
    # The backref='goal' is defined in Savings_Goals model

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    group_code = db.Column(db.String(8), unique=True, nullable=False)
    currency = db.Column(db.String(3), default='INR')
    group_type = db.Column(db.String(20), default='friends')
    is_private = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)  # Changed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    members = db.relationship('GroupMember', backref='group', lazy=True, cascade='all, delete-orphan')
    transactions = db.relationship('GroupTransaction', backref='group', lazy=True, cascade='all, delete-orphan')
    join_requests = db.relationship('JoinRequest', backref='group', lazy=True, cascade='all, delete-orphan')
    creator = db.relationship('User', backref='created_groups', foreign_keys=[created_by])  # Added

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(20), default='member')  # 'admin' or 'member'
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    balance = db.Column(db.Float, default=0.0)
    
    # Relationships
    user = db.relationship('User', backref='group_memberships')

class JoinRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='join_requests')

class GroupTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id', ondelete='CASCADE'), nullable=False)
    paid_by = db.Column(db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), default='other')
    split_type = db.Column(db.String(20), default='equal')  # 'equal', 'percentage', 'custom'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    payer = db.relationship('User', backref='group_transactions')

class TransactionSplit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey('group_transaction.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    settled = db.Column(db.Boolean, default=False)
    
    # Relationships
    user = db.relationship('User', backref='transaction_splits')
    transaction = db.relationship('GroupTransaction', backref='splits')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

def initialize_database():
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables created successfully")
        except Exception as e:
            app.logger.error(f"Database connection failed: {str(e)}")
            exit(1)

# Route definitions
@app.route('/')
def home():
    return redirect(url_for('signup'))



@app.route('/login', methods=['GET'])
@app.route('/index')
def login():
    """Renders the login page"""
    return render_template('index.html')

@app.route('/api/auth/login', methods=['POST'])
def handle_login():
    """Handles login authentication"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()

        if not email or not password:
            return jsonify({'message': 'Email and password are required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid email or password'}), 401

        login_user(user)
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.user_id,
                'name': user.username,
                'email': user.email
            },
            'redirect': url_for('dashboard')
        }), 200

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/signup', methods=['GET'])
def signup():
    """Renders the signup page"""
    return render_template('signup.html')

@app.route('/api/auth/register', methods=['POST'])
def handle_registration():
    """Handles user registration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        required_fields = ['name', 'email', 'password', 'confirmPassword']
        if not all(field in data for field in required_fields):
            return jsonify({'message': 'All fields are required'}), 400

        name = data['name'].strip()
        email = data['email'].strip().lower()
        password = data['password'].strip()
        confirm_password = data['confirmPassword'].strip()

        if not all([name, email, password, confirm_password]):
            return jsonify({'message': 'Fields cannot be empty'}), 400

        if password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400

        if len(password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already registered'}), 409

        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'message': 'Registration successful! Please login to continue.',
            'user': {
                    'id': new_user.user_id,
                    'name': new_user.username,
                    'email': new_user.email
                    }
            }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get transactions data
        transactions = Transaction.query.filter_by(user_id=current_user.user_id).order_by(Transaction.date.desc()).all()
        
        # Calculate totals
        total_income = sum(t.amount for t in transactions if t.type == 'income')
        total_expenses = sum(t.amount for t in transactions if t.type == 'expense')
        savings_goals = Savings_Goals.query.filter_by(user_id=current_user.user_id).all()
        total_savings = sum(s.currentamount for s in savings_goals) if savings_goals else 0
        total_investments = sum(t.amount for t in transactions if t.type == 'income' and t.category.lower() == 'investment')
        
        # Prepare data for spending chart (last 6 months)
        monthly_data = defaultdict(lambda: {'income': 0, 'expense': 0})
        six_months_ago = datetime.now() - timedelta(days=180)
        
        for t in transactions:
            if t.date >= six_months_ago:
                month_year = t.date.strftime('%b %Y')
                monthly_data[month_year][t.type] += t.amount
        
        # Sort months chronologically
        sorted_months = sorted(monthly_data.keys(), key=lambda x: datetime.strptime(x, '%b %Y'))
        spending_labels = sorted_months
        spending_income = [monthly_data[m]['income'] for m in sorted_months]
        spending_expenses = [monthly_data[m]['expense'] for m in sorted_months]
        
        # Prepare data for expense distribution chart
        expense_categories = defaultdict(float)
        for t in transactions:
            if t.type == 'expense':
                expense_categories[t.category] += t.amount
        
        expense_labels = list(expense_categories.keys())
        expense_values = list(expense_categories.values())
        
        # Convert to JSON for the template
        spending_data = {
            'labels': spending_labels,
            'income': spending_income,
            'expenses': spending_expenses
        }
        
        expense_dist_data = {
            'labels': expense_labels,
            'values': expense_values
        }
        
        return render_template(
            'dashboard.html',
            total_income=total_income,
            total_expenses=total_expenses,
            total_savings=total_savings,
            total_investments=total_investments,
            transactions=transactions[:10],  # Show last 10 transactions
            spending_data=json.dumps(spending_data),
            expense_dist_data=json.dumps(expense_dist_data)
        )
        
    except Exception as e:
        app.logger.error(f"Error in dashboard: {str(e)}")
        return render_template('error.html'), 500
    
@app.route('/api/dashboard/data')
@login_required
def dashboard_data():
    period = request.args.get('period', 'month')  # Default to month
    
    try:
        # Calculate date range based on period
        end_date = datetime.now()
        if period == 'week':
            start_date = end_date - timedelta(days=7)
        elif period == 'year':
            start_date = end_date - timedelta(days=365)
        else:  # month
            start_date = end_date - timedelta(days=30)
        
        # Get transactions in date range
        transactions = Transaction.query.filter(
            Transaction.user_id == current_user.user_id,
            Transaction.date >= start_date,
            Transaction.date <= end_date
        ).all()
        
        # Prepare spending data
        spending_data = defaultdict(lambda: {'income': 0, 'expense': 0})
        for t in transactions:
            if period == 'week':
                key = t.date.strftime('%a')  # Mon, Tue, etc.
            elif period == 'year':
                key = t.date.strftime('%b')  # Jan, Feb, etc.
            else:  # month
                key = f"Week {t.date.isocalendar()[1] - end_date.isocalendar()[1] + 4}"  # Week 1, 2, etc.
            
            spending_data[key][t.type] += t.amount
        
        # Sort keys appropriately
        if period == 'week':
            days_order = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            sorted_keys = [day for day in days_order if day in spending_data]
        elif period == 'year':
            month_order = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                          'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            sorted_keys = [month for month in month_order if month in spending_data]
        else:  # month
            sorted_keys = sorted(spending_data.keys(), key=lambda x: int(x.split(' ')[1]))
        
        # Prepare expense distribution data
        expense_categories = defaultdict(float)
        for t in transactions:
            if t.type == 'expense':
                expense_categories[t.category] += t.amount
        
        return jsonify({
            'spending': {
                'labels': sorted_keys,
                'income': [spending_data[key]['income'] for key in sorted_keys],
                'expenses': [spending_data[key]['expense'] for key in sorted_keys]
            },
            'expense_dist': {
                'labels': list(expense_categories.keys()),
                'values': list(expense_categories.values())
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error in dashboard data API: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/auth/logout', methods=['POST'])
@login_required
def handle_logout():
    """Handles user logout"""
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200


@app.route('/api/income/sources')
@login_required
def income_sources_data():
    try:
        # Get income transactions for the current user
        income_transactions = Transaction.query.filter(
            Transaction.user_id == current_user.user_id,
            Transaction.type == 'income'
        ).all()
        
        # Group by category
        sources_data = defaultdict(float)
        for transaction in income_transactions:
            sources_data[transaction.category] += transaction.amount
        
        # Convert to format suitable for pie chart
        result = []
        for category, amount in sources_data.items():
            result.append({
                'name': category,
                'value': amount
            })
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/income/trend')
@login_required
def income_trend_data():
    # Get filter parameter (default to 'yearly')
    time_filter = request.args.get('filter', 'yearly')
    
    end_date = datetime.utcnow()
    
    if time_filter == 'monthly':
        start_date = end_date - timedelta(days=30)
        group_format = '%Y-%m-%d'
        label_format = '%b %d'
    elif time_filter == 'quarterly':
        start_date = end_date - timedelta(days=90)
        group_format = '%Y-%W'  # Group by year and week number
        label_format = 'Week %W'
    else:  # yearly
        start_date = end_date - timedelta(days=365)
        group_format = '%Y-%m'
        label_format = '%b %Y'
    
    # Query income transactions
    income_transactions = Transaction.query.filter(
        Transaction.user_id == current_user.user_id,
        Transaction.type == 'income',
        Transaction.date >= start_date,
        Transaction.date <= end_date
    ).order_by(Transaction.date).all()
    
    # Debug logging
    app.logger.debug(f"Found {len(income_transactions)} income transactions between {start_date} and {end_date}")
    
    # Group data based on filter
    grouped_data = defaultdict(float)
    for transaction in income_transactions:
        if time_filter == 'monthly':
            key = transaction.date.strftime(group_format)
            label = transaction.date.strftime(label_format)
        elif time_filter == 'quarterly':
            week_num = transaction.date.isocalendar()[1]
            year = transaction.date.year
            key = f"{year}-{week_num}"
            label = f"Week {week_num}"
        else:  # yearly
            key = transaction.date.strftime(group_format)
            label = transaction.date.strftime(label_format)
        
        grouped_data[key] += transaction.amount
    
    # Create sorted result with proper labels
    result = []
    if time_filter == 'monthly':
        # Daily data for last 30 days
        for i in range(30):
            date = end_date - timedelta(days=i)
            key = date.strftime(group_format)
            label = date.strftime(label_format)
            result.append({
                'date': label,
                'amount': grouped_data.get(key, 0)
            })
        result.reverse()  # Show oldest to newest
    elif time_filter == 'quarterly':
        # Weekly data for last 12 weeks
        for i in range(12):
            date = end_date - timedelta(weeks=i)
            week_num = date.isocalendar()[1]
            year = date.year
            key = f"{year}-{week_num}"
            label = f"Week {week_num}"
            result.append({
                'date': label,
                'amount': grouped_data.get(key, 0)
            })
        result.reverse()
    else:  # yearly
        # Monthly data for last 12 months
        current = start_date
        while current <= end_date:
            key = current.strftime(group_format)
            label = current.strftime(label_format)
            result.append({
                'date': label,
                'amount': grouped_data.get(key, 0)
            })
            # Move to next month
            if current.month == 12:
                current = current.replace(year=current.year+1, month=1)
            else:
                current = current.replace(month=current.month+1)
    
    # Debug logging
    app.logger.debug(f"Returning trend data: {result}")
    
    return jsonify({
        'success': True,
        'data': result,
        'filter': time_filter,
        'timeframe': {
            'start': start_date.strftime('%Y-%m-%d'),
            'end': end_date.strftime('%Y-%m-%d')
        }
    })

@app.route('/income')
@login_required
def income_dashboard():
    # Calculate summary statistics
    income_transactions = Transaction.query.filter(
        Transaction.user_id == current_user.user_id,
        Transaction.type == 'income'
    ).all()
    
    # Total income
    total_income = sum(t.amount for t in income_transactions)
    
    # Primary source (category with highest total)
    sources = defaultdict(float)
    for t in income_transactions:
        sources[t.category] += t.amount
    primary_source = max(sources.items(), key=lambda x: x[1])[0] if sources else "No data"
    
    # Average daily income (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_income = [t.amount for t in income_transactions if t.date >= thirty_days_ago]
    avg_daily_income = sum(recent_income) / 30 if recent_income else 0
    
    # Recent transactions (limit to 10)
    recent_transactions = Transaction.query.filter(
        Transaction.user_id == current_user.user_id,
        Transaction.type == 'income'
    ).order_by(Transaction.date.desc()).limit(10).all()
    
    return render_template('income.html',
                         total_income=total_income,
                         primary_source=primary_source,
                         avg_daily_income=avg_daily_income,
                         transactions=recent_transactions)
    

@app.template_filter('icon_class')
def icon_class_filter(source):
    icons = {
        'salary': 'fa-briefcase',
        'freelance': 'fa-laptop-code',
        'investment': 'fa-chart-line',
        'business': 'fa-store',
        'other': 'fa-money-bill-wave'
    }
    return icons.get(source.lower(), 'fa-money-bill-wave')


@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    # Get JSON data from request
    data = request.get_json()
    
    # Extract fields from request
    current_pw = data.get('current_password')
    new_pw = data.get('new_password')
    confirm_pw = data.get('confirm_password')

    # Validation checks
    if not all([current_pw, new_pw, confirm_pw]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    if new_pw != confirm_pw:
        return jsonify({'success': False, 'message': 'New passwords do not match'}), 400

    # Verify current password using the logged-in user's credentials
    if not current_user.check_password(current_pw):
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400

    try:
        # Update password for the currently logged-in user
        current_user.set_password(new_pw)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Password updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error updating password'}), 500
    

@app.route('/delete-account', methods=['DELETE'])
@cross_origin(supports_credentials=True, origins=["http://localhost:3000"])
@login_required
def delete_account():
    try:
        data = request.get_json()
        password = data.get('password', '').strip()

        if not password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400

        # Verify password
        if not current_user.check_password(password):
            return jsonify({'success': False, 'message': 'Incorrect password'}), 401

        # Delete user (cascades to all related data)
        db.session.delete(current_user)
        db.session.commit()
        logout_user()

        return jsonify({
            'success': True,
            'message': 'Account permanently deleted',
            'redirect': url_for('login')
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/profile',methods=['GET', 'POST'])
def profile():
    all_transactions = Transaction.query.filter_by(
        user_id=current_user.user_id
    ).order_by(Transaction.date.desc()).all()
    total_transactions=len(all_transactions)
    transactions=Transaction.query.filter_by(user_id=current_user.user_id, type="income").order_by(Transaction.date.desc()).all()
    total_income=sum(transaction.amount for transaction in transactions)
    total_expenses=get_expense_total(current_user.user_id)
    balance=total_income-total_expenses
    if request.method == 'POST':
        # Handle AJAX request
        data = request.get_json()
        profile_data = {
            'first_name': data.get('firstName'),
            'last_name': data.get('lastName'),
            'phone': data.get('phone'),
            'street': data.get('street'),
            'city': data.get('city'),
            'zip_code': data.get('zipCode'),
            'country': data.get('country')
        }
        
        # Update or create profile
        profile = User_Profile.query.filter_by(user_id=current_user.user_id).first()
        if profile:
            for key, value in profile_data.items():
                setattr(profile, key, value)
        else:
            new_profile = User_Profile(user_id=current_user.user_id, **profile_data)
            db.session.add(new_profile)
        
        db.session.commit()
        return jsonify(success=True)
    
    # GET request handling
    profile_data = None
    if current_user.is_authenticated:
        profile = User_Profile.query.filter_by(user_id=current_user.user_id).first()
        if profile:
            profile_data = {
                'firstName': profile.first_name,
                'lastName': profile.last_name,
                'phone': profile.phone,
                'street': profile.street,
                'city': profile.city,
                'zipCode': profile.zip_code,
                'country': profile.country
            }
    
    # Default values if no profile exists
    default_data = {
        'firstName': current_user.username,  # Using username as default first name
        'lastName': '',
        'phone': '',
        'street': '',
        'city': '',
        'zipCode': '',
        'country': 'United States'
    }
    return render_template('profile.html',total_transactions=total_transactions,balance=balance,profile_data=profile_data)
    

@app.route('/reports')
@login_required
def reports():
    try:
        # Get all transactions (both income and expenses)
        transactions = Transaction.query.filter_by(user_id=current_user.user_id).order_by(Transaction.date.desc()).all()
        
        # Calculate totals
        total_income = sum(t.amount for t in transactions if t.type == 'income')
        total_expenses = sum(t.amount for t in transactions if t.type == 'expense')
        savings_goals = Savings_Goals.query.filter_by(user_id=current_user.user_id).all()
        total_savings = sum(s.currentamount for s in savings_goals) if savings_goals else 0
        net_worth = total_income - total_expenses + total_savings
        
        # Process data for charts
        monthly_data = get_monthly_data(transactions)
        category_data = get_category_data(transactions)
        net_worth_data = get_net_worth_data(current_user.user_id, transactions, savings_goals)
        cash_flow_data = get_cash_flow_data(transactions)
        
        return render_template(
            'reports.html',
            total_income=total_income,
            total_expenses=total_expenses,
            total_savings=total_savings,
            net_worth=net_worth,
            transactions=transactions[-10:],  # Show last 10 transactions
            monthly_data=json.dumps(monthly_data),
            category_data=json.dumps(category_data),
            net_worth_data=json.dumps(net_worth_data),
            cash_flow_data=json.dumps(cash_flow_data)
        )
    except Exception as e:
        app.logger.error(f"Error in reports: {str(e)}")
        return render_template('error.html'), 500
    

@app.route('/export/transactions/csv')
@login_required
def export_transactions_csv():
    # Get transactions for the current user
    transactions = Transaction.query.filter_by(user_id=current_user.user_id).order_by(Transaction.date.desc()).all()
    
    # Create a StringIO object to hold the CSV data
    si = StringIO()
    cw = csv.writer(si)
    
    # Write the header row
    cw.writerow(['Date', 'Description', 'Category', 'Type', 'Payment Method', 'Amount', 'Status'])
    
    # Write the transaction data
    for transaction in transactions:
        cw.writerow([
            transaction.date.strftime('%Y-%m-%d'),
            transaction.description,
            transaction.category,
            transaction.type,
            transaction.payment_method,
            transaction.amount,
            transaction.status
        ])
    
    # Create the response with CSV headers
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=transactions_export.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/export/reports/csv')
@login_required
def export_reports_csv():
    # Get the data you used to generate the reports
    # (You'll need to replicate the data fetching logic from your reports route)
    
    # Create a StringIO object to hold the CSV data
    si = StringIO()
    cw = csv.writer(si)
    
    # Write summary data
    cw.writerow(['Financial Summary Report'])
    cw.writerow(['Generated on', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    cw.writerow(['User', current_user.username])
    cw.writerow([])
    
    # Write summary cards data
    cw.writerow(['Metric', 'Amount'])
    cw.writerow(['Total Income', f"₹{calculate_total_income(current_user.user_id)}"])
    cw.writerow(['Total Expenses', f"₹{calculate_total_expenses(current_user.user_id)}"])
    cw.writerow(['Net Worth', f"₹{calculate_net_worth(current_user.user_id)}"])
    cw.writerow([])
    
    # Write monthly data
    monthly_data = get_monthly_data(current_user.user_id)
    cw.writerow(['Monthly Income vs Expenses'])
    cw.writerow(['Month', 'Income', 'Expenses', 'Net'])
    
    for i in range(len(monthly_data['labels'])):
        net = monthly_data['income'][i] - monthly_data['expenses'][i]
        cw.writerow([
            monthly_data['labels'][i],
            f"₹{monthly_data['income'][i]}",
            f"₹{monthly_data['expenses'][i]}",
            f"₹{net}"
        ])
    
    # Create the response with CSV headers
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=financial_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/export/reports/pdf')
@login_required
def export_reports_pdf():
    # Create a BytesIO buffer for the PDF
    buffer = BytesIO()
    
    # Create the PDF document
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    
    # Add a title
    styles = getSampleStyleSheet()
    elements.append(Paragraph("Financial Report", styles['Title']))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Paragraph(f"User: {current_user.username}", styles['Normal']))
    elements.append(Paragraph(" ", styles['Normal']))  # Spacer
    
    # Add summary section
    elements.append(Paragraph("Summary", styles['Heading2']))
    
    # Prepare summary data
    summary_data = [
        ['Metric', 'Amount'],
        ['Total Income', f"₹{calculate_total_income(current_user.user_id)}"],
        ['Total Expenses', f"₹{calculate_total_expenses(current_user.user_id)}"],
        ['Net Worth', f"₹{calculate_net_worth(current_user.user_id)}"]
    ]
    
    # Create summary table
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(summary_table)
    elements.append(Paragraph(" ", styles['Normal']))  # Spacer
    
    # Add monthly data section
    elements.append(Paragraph("Monthly Income vs Expenses", styles['Heading2']))
    
    # Get monthly data
    monthly_data = get_monthly_data(current_user.user_id)
    monthly_table_data = [['Month', 'Income', 'Expenses', 'Net']]
    
    for i in range(len(monthly_data['labels'])):
        net = monthly_data['income'][i] - monthly_data['expenses'][i]
        monthly_table_data.append([
            monthly_data['labels'][i],
            f"₹{monthly_data['income'][i]}",
            f"₹{monthly_data['expenses'][i]}",
            f"₹{net}"
        ])
    
    # Create monthly table
    monthly_table = Table(monthly_table_data)
    monthly_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(monthly_table)
    
    # Build the PDF
    doc.build(elements)
    
    # Get the PDF data and create the response
    pdf = buffer.getvalue()
    buffer.close()
    
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=financial_report.pdf'
    
    return response

def calculate_total_income(user_id):
    return db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.user_id == user_id,
        Transaction.type == 'income'
    ).scalar() or 0

def calculate_total_expenses(user_id):
    return db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.user_id == user_id,
        Transaction.type == 'expense'
    ).scalar() or 0

def calculate_net_worth(user_id):
    income = calculate_total_income(user_id)
    expenses = calculate_total_expenses(user_id)    
    return income - expenses 

def get_monthly_data(user_id):
    # Get the current date and calculate the start date (6 months ago)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=180)  # 6 months
    
    # Query for monthly income
    income_query = db.session.query(
        db.func.strftime('%Y-%m', Transaction.date).label('month'),
        db.func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.user_id == user_id,
        Transaction.type == 'income',
        Transaction.date >= start_date,
        Transaction.date <= end_date
    ).group_by('month').order_by('month')
    
    # Query for monthly expenses
    expense_query = db.session.query(
        db.func.strftime('%Y-%m', Transaction.date).label('month'),
        db.func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.user_id == user_id,
        Transaction.type == 'expense',
        Transaction.date >= start_date,
        Transaction.date <= end_date
    ).group_by('month').order_by('month')
    
    # Convert to dictionaries for easier processing
    income_data = {row.month: row.total for row in income_query}
    expense_data = {row.month: row.total for row in expense_query}
    
    # Get all unique months
    all_months = sorted(set(income_data.keys()).union(set(expense_data.keys())))
    
    # Prepare the data structure
    monthly_data = {
        'labels': [],
        'income': [],
        'expenses': []
    }
    
    for month in all_months:
        monthly_data['labels'].append(month)
        monthly_data['income'].append(income_data.get(month, 0))
        monthly_data['expenses'].append(expense_data.get(month, 0))
    
    return monthly_data

@app.route('/api/reports/data')
@login_required
def reports_data():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    try:
        # Query transactions in date range
        transactions = Transaction.query.filter(
            Transaction.user_id == current_user.user_id,
            Transaction.date >= start_date,
            Transaction.date <= end_date
        ).all()
        
        # Process data for all charts
        monthly_data = get_monthly_data(transactions)
        category_data = get_category_data(transactions)
        savings_goals = Savings_Goals.query.filter_by(user_id=current_user.user_id).all()
        net_worth_data = get_net_worth_data(current_user.user_id, transactions, savings_goals)
        cash_flow_data = get_cash_flow_data(transactions)
        
        # Calculate totals for summary cards
        total_income = sum(monthly_data['income'])
        total_expenses = sum(monthly_data['expenses'])
        total_savings = sum(s.currentamount for s in savings_goals) if savings_goals else 0
        
        return jsonify({
            'monthly_data': monthly_data,
            'category_data': category_data,
            'net_worth_data': net_worth_data,
            'cash_flow_data': cash_flow_data,
            'totals': {
                'income': total_income,
                'expenses': total_expenses,
                'savings': total_savings
            }
        })
    except Exception as e:
        app.logger.error(f"Error in reports data API: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_monthly_data(transactions):
    # Group by month
    monthly_income = defaultdict(float)
    monthly_expenses = defaultdict(float)
    
    for t in transactions:
        month = t.date.strftime('%b %Y')
        if t.type == 'income':
            monthly_income[month] += t.amount
        else:
            monthly_expenses[month] += t.amount
    
    # Get all months in chronological order
    all_months = sorted(set(monthly_income.keys()).union(set(monthly_expenses.keys())),
                      key=lambda m: datetime.strptime(m, '%b %Y'))
    
    return {
        'labels': all_months,
        'income': [monthly_income.get(m, 0) for m in all_months],
        'expenses': [monthly_expenses.get(m, 0) for m in all_months]
    }

def get_category_data(transactions):
    # Group expenses by category
    category_totals = defaultdict(float)
    for t in transactions:
        if t.type == 'expense':
            category_totals[t.category] += t.amount
    
    # Prepare data for chart
    categories = list(category_totals.keys())
    amounts = [category_totals[c] for c in categories]
    
    # Assign colors
    colors = ['#f72585', '#4cc9f0', '#4361ee', '#7209b7', '#3a0ca3', '#4895ef']
    
    return {
        'labels': categories,
        'amounts': amounts,
        'colors': colors[:len(categories)]
    }

def get_net_worth_data(user_id, transactions, savings_goals):
    # Calculate net worth for the last 6 months
    net_worth_history = []
    today = datetime.now()
    
    for i in range(6, -1, -1):
        month = today - relativedelta(months=i)
        month_str = month.strftime('%b %Y')
        
        # Calculate income up to this month
        income = sum(t.amount for t in transactions 
                   if t.type == 'income' and t.date <= month.replace(day=1, hour=23, minute=59, second=59))
        
        # Calculate expenses up to this month
        expenses = sum(t.amount for t in transactions 
                     if t.type == 'expense' and t.date <= month.replace(day=1, hour=23, minute=59, second=59))
        
        # Calculate savings up to this month
        savings = sum(s.currentamount for s in savings_goals 
                     if s.startdate <= month.replace(day=1, hour=23, minute=59, second=59))
        
        net_worth = income - expenses + savings
        net_worth_history.append({
            'date': month_str,
            'value': net_worth
        })
    
    return {
        'labels': [entry['date'] for entry in net_worth_history],
        'values': [entry['value'] for entry in net_worth_history]
    }

def get_cash_flow_data(transactions):
    # Group by week
    weekly_income = defaultdict(float)
    weekly_expenses = defaultdict(float)
    
    for t in transactions:
        week = f"Week {t.date.isocalendar()[1]}"
        if t.type == 'income':
            weekly_income[week] += t.amount
        else:
            weekly_expenses[week] += t.amount
    
    weeks = sorted(set(weekly_income.keys()).union(set(weekly_expenses.keys())))
    
    return {
        'labels': weeks,
        'income': [weekly_income.get(w, 0) for w in weeks],
        'expenses': [weekly_expenses.get(w, 0) for w in weeks]
    }


@app.route('/savings')
def savings():
    return render_template('savings.html')

# Savings Blueprint Routes
@savings_bp.route('/savings-goals', methods=['GET'])
@login_required
def get_savings_goals():
    goals = Savings_Goals.query.filter_by(user_id=current_user.user_id).all()
    return jsonify([{
        'id': goal.goal_id,
        'name': goal.goalname,
        'targetAmount': float(goal.targetamount),
        'currentAmount': float(goal.currentamount),
        'deadline': goal.deadline.strftime('%Y-%m-%d'),
        'priority': goal.priority,
        'description': goal.notes,
        'createdAt': goal.startdate.strftime('%Y-%m-%d'),
        'completed': goal.currentamount >= goal.targetamount
    } for goal in goals])

@savings_bp.route('/savings-goals', methods=['POST'])
@login_required
def add_savings_goal():
    data = request.get_json()
    
    required_fields = ['name', 'targetAmount', 'deadline', 'priority']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    try:
        deadline = datetime.strptime(data['deadline'], '%Y-%m-%d')
        
        new_goal = Savings_Goals(
            user_id=current_user.user_id,
            goalname=data['name'],
            targetamount=float(data['targetAmount']),
            currentamount=float(data.get('currentAmount', 0)),
            deadline=deadline,
            priority=data['priority'],
            notes=data.get('description', '')
        )
        
        db.session.add(new_goal)
        db.session.commit()
        
        return jsonify({
            'message': 'Goal added successfully',
            'goal': {
                'id': new_goal.goal_id,
                'name': new_goal.goalname,
                'targetAmount': float(new_goal.targetamount),
                'currentAmount': float(new_goal.currentamount),
                'deadline': new_goal.deadline.strftime('%Y-%m-%d'),
                'priority': new_goal.priority,
                'description': new_goal.notes,
                'createdAt': new_goal.startdate.strftime('%Y-%m-%d'),
                'completed': new_goal.currentamount >= new_goal.targetamount
            }
        }), 201
        
    except ValueError as e:
        return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD', 'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to add goal', 'error': str(e)}), 500

@savings_bp.route('/savings-goals/<int:goal_id>', methods=['PUT'])
@login_required
def update_savings_goal(goal_id):
    data = request.get_json()
    
    try:
        goal = Savings_Goals.query.filter_by(
            goal_id=goal_id,
            user_id=current_user.user_id
        ).first()
        
        if not goal:
            return jsonify({'message': 'Goal not found'}), 404
            
        if 'name' in data:
            goal.goalname = data['name']
        if 'targetAmount' in data:
            goal.targetamount = float(data['targetAmount'])
        if 'priority' in data:
            goal.priority = data['priority']
        if 'description' in data:
            goal.notes = data['description']
        if 'deadline' in data:
            goal.deadline = datetime.strptime(data['deadline'], '%Y-%m-%d')
            
        db.session.commit()
        
        return jsonify({
            'message': 'Goal updated successfully',
            'goal': {
                'id': goal.goal_id,
                'name': goal.goalname,
                'targetAmount': float(goal.targetamount),
                'currentAmount': float(goal.currentamount),
                'deadline': goal.deadline.strftime('%Y-%m-%d'),
                'priority': goal.priority,
                'description': goal.notes
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update goal', 'error': str(e)}), 500
    
@savings_bp.route('/savings-goals/<int:goal_id>', methods=['GET'])
@login_required
def get_savings_goal(goal_id):
    goal = Savings_Goals.query.filter_by(goal_id=goal_id, user_id=current_user.user_id).first()
    if not goal:
        return jsonify({'message': 'Goal not found'}), 404
        
    return jsonify({
        'id': goal.goal_id,
        'name': goal.goalname,
        'targetAmount': float(goal.targetamount),
        'currentAmount': float(goal.currentamount),
        'deadline': goal.deadline.strftime('%Y-%m-%d'),
        'priority': goal.priority,
        'description': goal.notes,
        'createdAt': goal.startdate.strftime('%Y-%m-%d'),
        'completed': goal.currentamount >= goal.targetamount
    })
@savings_bp.route('/savings-goals/<int:goal_id>/transactions', methods=['POST'])
@login_required
def add_savings_transaction(goal_id):
    data = request.get_json()
    
    required_fields = ['amount', 'type', 'date']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields: amount, type, date'}), 400

    try:
        # Validate goal exists and belongs to user
        goal = Savings_Goals.query.filter_by(
            goal_id=goal_id, 
            user_id=current_user.user_id
        ).first()
        
        if not goal:
            return jsonify({'message': 'Goal not found or not authorized'}), 404
            
        # Parse and validate amount
        try:
            amount = float(data['amount'])
            if amount <= 0:
                return jsonify({'message': 'Amount must be positive'}), 400
        except (ValueError, TypeError):
            return jsonify({'message': 'Invalid amount format'}), 400

        # Parse and validate date
        try:
            transaction_date = datetime.strptime(data['date'], '%Y-%m-%d')
            if transaction_date.date() > datetime.utcnow().date():
                return jsonify({'message': 'Future dates are not allowed'}), 400
        except ValueError:
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD'}), 400

        # Validate transaction type
        transaction_type = data['type'].lower()
        if transaction_type not in ['deposit', 'withdrawal']:
            return jsonify({'message': 'Invalid transaction type. Must be "deposit" or "withdrawal"'}), 400

        # Check for sufficient funds for withdrawals
        if transaction_type == 'withdrawal' and goal.currentamount < amount:
            return jsonify({
                'message': 'Insufficient funds in goal for this withdrawal',
                'currentAmount': float(goal.currentamount)
            }), 400

        # Create the transaction
        new_transaction = SavingTransaction(
            goal_id=goal_id,
            user_id=current_user.user_id,
            amount=amount,
            date=transaction_date,
            note=data.get('note', '')  # Changed from 'notes' to 'note' to match your model
        )
        
        # Update goal amount
        if transaction_type == 'deposit':
            goal.currentamount += amount
        else:
            goal.currentamount -= amount
            
        db.session.add(new_transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Transaction added successfully',
            'transaction': {
                'id': new_transaction.transaction_id,
                'amount': float(new_transaction.amount),
                'type': transaction_type,
                'date': new_transaction.date.strftime('%Y-%m-%d'),
                'note': new_transaction.note,
                'goalId': goal_id,
                'currentGoalAmount': float(goal.currentamount)
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Transaction error: {str(e)}", exc_info=True)
        return jsonify({
            'message': 'Failed to add transaction',
            'error': str(e)
        }), 500

@savings_bp.route('/savings-goals/<int:goal_id>/transactions', methods=['GET'])
@login_required
def get_goal_transactions(goal_id):
    try:
        # Verify the goal belongs to the user
        goal = Savings_Goals.query.filter_by(
            goal_id=goal_id,
            user_id=current_user.user_id
        ).first()
        
        if not goal:
            return jsonify({'message': 'Goal not found or not authorized'}), 404

        transactions = SavingTransaction.query.filter_by(
            goal_id=goal_id,
            user_id=current_user.user_id
        ).order_by(SavingTransaction.date.desc()).all()
        
        return jsonify([{
            'id': t.transaction_id,
            'amount': float(t.amount),
            'type': 'deposit' if t.amount >= 0 else 'withdrawal',
            'date': t.date.strftime('%Y-%m-%d'),
            'note': t.note,
            'goalId': goal_id
        } for t in transactions])
        
    except Exception as e:
        app.logger.error(f"Get transactions error: {str(e)}", exc_info=True)
        return jsonify({'message': 'Failed to get transactions', 'error': str(e)}), 500
    
@savings_bp.route('/savings-transactions', methods=['GET'])
@login_required
def get_all_transactions():
    try:
        transactions = SavingTransaction.query.filter_by(
            user_id=current_user.user_id
        ).order_by(SavingTransaction.date.desc()).all()
        
        transactions_data = []
        for t in transactions:
            goal_name = 'Deleted Goal'
            if t.goal:  # Now this will work because of the backref
                goal_name = t.goal.goalname
                
            transactions_data.append({
                'id': t.transaction_id,
                'amount': float(t.amount),
                'type': 'deposit' if t.amount >= 0 else 'withdrawal',
                'date': t.date.strftime('%Y-%m-%d') if t.date else None,
                'note': t.note,
                'goalId': t.goal_id,
                'goalName': goal_name
            })
            
        return jsonify(transactions_data)
        
    except Exception as e:
        app.logger.error(f"Get all transactions error: {str(e)}", exc_info=True)
        return jsonify({'message': 'Failed to get transactions', 'error': str(e)}), 500

@app.route('/settings')
def settings():
    profile_data = None
    if current_user.is_authenticated:
        profile = User_Profile.query.filter_by(user_id=current_user.user_id).first()
        if profile:
            profile_data = {
                'firstName': profile.first_name,
                'lastName': profile.last_name,
                'phone': profile.phone,
            }
    
    # Default values if no profile exists
    default_data = {
        'firstName': current_user.username,  # Using username as default first name
        'lastName': '',
        'phone': '',
    }
    return render_template('settings.html',profile_data=profile_data)

def get_expense_total(user_id):
    # Query to sum non-income transactions for the user
    expense_total = db.session.query(
        func.coalesce(func.sum(Transaction.amount), 0.0)
    ).filter(
        Transaction.user_id == user_id,
        Transaction.type != 'income'
    ).scalar()
    
    return expense_total


@app.route('/transaction')
def transaction():
    transactions=Transaction.query.filter_by(user_id=current_user.user_id, type="income").order_by(Transaction.date.desc()).all()
    total_income=sum(transaction.amount for transaction in transactions)
    total_expenses=get_expense_total(current_user.user_id)
    user_transactions = Transaction.query.filter_by(user_id=current_user.user_id).all()
    net_balance=total_income-total_expenses
    # Convert transactions to JSON-serializable format
    transactions_data = []
    for transaction in user_transactions:
        transactions_data.append({
            'id': transaction.id,
            'date': transaction.date.strftime('%Y-%m-%d %H:%M'),
            'category': transaction.category,
            'description': transaction.description,
            'amount': float(transaction.amount),
            'payment_method': transaction.payment_method,
            'status': transaction.status
        })
    return render_template('transactions.html', total_income=total_income,transactions=transactions_data,total_expenses=total_expenses,net_balance=net_balance)

@transactions_bp.route('/transactions', methods=['POST'])
@login_required
def create_transaction():
    try:
        data = request.get_json()
        
        transaction = Transaction(
            amount=data['amount'],
            type=data['type'],
            category=data['category'],
            payment_method=data['payment_method'],
            description=data.get('description'),
            date=datetime.strptime(data['date'], '%Y-%m-%d'),
            status=data.get('status', 'completed'),
            user_id=current_user.user_id
        )
        
        db.session.add(transaction)
        db.session.commit()
        return jsonify({'message': 'Transaction created successfully'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/transactions/<int:id>', methods=['DELETE'])
@login_required
def delete_transaction(id):
    # Use 'id' instead of 'transactionID' if that's the model's primary key
    transaction = Transaction.query.filter_by(id=id, user_id=current_user.user_id).first()
    if not transaction:
        return jsonify({'message': 'transaction not found'}), 404
    
    try:
        db.session.delete(transaction)
        db.session.commit()
        return jsonify({'message': 'transaction deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500
    
@app.route('/api/transactions/spending-by-category')
@login_required
def spending_by_category():
    try:
        # Get expense transactions for the current user
        expenses = Transaction.query.filter(
            Transaction.user_id == current_user.user_id,
            Transaction.type == 'expense'
        ).all()
        
        # Group by category
        category_totals = defaultdict(float)
        for expense in expenses:
            category_totals[expense.category] += expense.amount
        
        # Convert to chart format
        data = [{"category": cat, "amount": amt} for cat, amt in category_totals.items()]
        
        return jsonify({
            "success": True,
            "data": data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    

@app.route('/api/transactions/monthly-trends')
@login_required
def monthly_trends():
    try:
        # Get transactions for the last 6 months
        months = int(request.args.get('months', 6))
        if months not in [3, 6, 12]:  # Only allow these values
            months = 6

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30*months)  
        
        transactions = Transaction.query.filter(
            Transaction.user_id == current_user.user_id,
            Transaction.date >= start_date,
            Transaction.date <= end_date
        ).all()
        
        # Initialize data for each month
        monthly_data = {}
        current = start_date
        while current <= end_date:
            month_key = current.strftime("%b %Y")
            monthly_data[month_key] = {"income": 0, "expense": 0}
            # Move to next month
            if current.month == 12:
                current = current.replace(year=current.year+1, month=1)
            else:
                current = current.replace(month=current.month+1)
        
        # Populate with actual data
        for txn in transactions:
            month_key = txn.date.strftime("%b %Y")
            if month_key in monthly_data:
                monthly_data[month_key][txn.type] += txn.amount
        
        # Convert to sorted list
        months = sorted(monthly_data.keys(), key=lambda x: datetime.strptime(x, "%b %Y"))
        data = [{
            "month": month,
            "income": monthly_data[month]["income"],
            "expense": monthly_data[month]["expense"]
        } for month in months]
        
        return jsonify({
            "success": True,
            "data": data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# Example Flask route
@transactions_bp.route('/categories', methods=['GET'])
@login_required
def get_categories():
    return jsonify([])  # Return empty array since we don't validate

@transactions_bp.route('/payment-methods', methods=['GET'])
@login_required
def get_payment_methods():
    return jsonify([]) 

# Create groups blueprint
groups_bp = Blueprint('groups', __name__)

# Add group helper functions
def generate_group_code():
    import random
    import string
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def calculate_group_balance(group_id):
    """Calculate total balance of a group"""
    total = db.session.query(db.func.sum(GroupTransaction.amount))\
        .filter_by(group_id=group_id).scalar() or 0
    return total

def calculate_member_balances(group_id):
    """Calculate individual member balances"""
    members = GroupMember.query.filter_by(group_id=group_id).all()
    balances = {}
    
    for member in members:
        balances[member.user_id] = get_user_balance(group_id,member.user_id)
    
    return balances
def get_user_balance(group_id, user_id):
    member = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=user_id
    ).first()

    if not member:
        return 0.0

    splits = (
        db.session.query(TransactionSplit, GroupTransaction)
        .join(GroupTransaction, TransactionSplit.transaction_id == GroupTransaction.id)
        .filter(
            GroupTransaction.group_id == group_id,
            TransactionSplit.user_id == user_id,
            TransactionSplit.settled == False,
            GroupTransaction.created_at >= member.joined_at
        )
        .all()
    )

    balance = 0.0

    for split, transaction in splits:
        if transaction.paid_by == user_id:
            balance += split.amount
        else:
            balance -= split.amount

    return round(balance, 2)


@groups_bp.route('/groups', methods=['GET'])
@login_required
def groups_page():
    """Render the groups page"""
    try:
        groups_data = []
        
        # 1. Get user's groups from GroupMember table (already accepted members)
        group_memberships = GroupMember.query.filter_by(user_id=current_user.user_id).all()
        
        for membership in group_memberships:
            group = membership.group
            members = GroupMember.query.filter_by(group_id=group.id).all()
            
            # Calculate total balance
            total_balance = calculate_group_balance(group.id)
            
            # Get recent members for avatars
            recent_members = []
            for member in members[:5]:
                recent_members.append({
                    'username': member.user.username,
                    'avatar': f'https://ui-avatars.com/api/?name={member.user.username}&background=random'
                })
            
            groups_data.append({
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'group_code': group.group_code,
                'role': membership.role,  # 'admin' or 'member'
                'total_balance': total_balance,
                'member_count': len(members),
                'transaction_count': len(group.transactions),
                'recent_members': recent_members,
                'created_at': group.created_at,
                'joined_at': membership.joined_at
            })
        
        # 2. Get user's pending join requests from JoinRequest table
        pending_requests = JoinRequest.query.filter_by(
            user_id=current_user.user_id,
            status='pending'
        ).all()
        
        for request in pending_requests:
            group = request.group
            
            # Get group members count (only from GroupMember table - accepted members)
            members = GroupMember.query.filter_by(group_id=group.id).all()
            
            # Calculate total balance
            total_balance = calculate_group_balance(group.id)
            
            # Get recent members for avatars
            recent_members = []
            for member in members[:5]:
                recent_members.append({
                    'username': member.user.username,
                    'avatar': f'https://ui-avatars.com/api/?name={member.user.username}&background=random'
                })
            
            groups_data.append({
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'group_code': group.group_code,
                'role': 'pending',  # Special role for pending requests
                'total_balance': total_balance,
                'member_count': len(members),
                'transaction_count': len(group.transactions),
                'recent_members': recent_members,
                'created_at': group.created_at,
                'request_date': request.created_at,
                'request_message': request.message
            })
        
        return render_template('groups.html', 
                             groups=groups_data, 
                             current_user=current_user)
        
    except Exception as e:
        app.logger.error(f"Error in groups page: {str(e)}")
        return render_template('error.html', message="Error loading groups"), 500

@groups_bp.route('/api/groups/cancel-request/<int:group_id>', methods=['POST'])
@login_required
def cancel_join_request(group_id):
    """Cancel a pending join request"""
    try:
        # Find the pending request
        join_request = JoinRequest.query.filter_by(
            user_id=current_user.user_id,
            group_id=group_id,
            status='pending'
        ).first()
        
        if not join_request:
            return jsonify({'success': False, 'message': 'Join request not found'}), 404
        
        # Delete the request
        db.session.delete(join_request)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Join request cancelled successfully'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error cancelling join request: {str(e)}")
        return jsonify({'success': False, 'message': 'Error cancelling request'}), 500

@groups_bp.route('/group/<int:group_id>', methods=['GET'])
@login_required
def group_detail_page(group_id):
    """Render the group detail page"""
    try:
        # Check if user is member of this group
        membership = GroupMember.query.filter_by(
            group_id=group_id, 
            user_id=current_user.user_id
        ).first()
        
        if not membership:
            return redirect(url_for('groups.groups_page'))
        
        group = Group.query.get_or_404(group_id)
        
        # Get group members with balances
        members = []
        balances = calculate_member_balances(group_id)
        
        for member in group.members:
            member_data = {
                'id': member.user_id,
                'username': member.user.username,
                'role': member.role,
                'balance': balances.get(member.user_id, 0),
                'avatar': f'https://ui-avatars.com/api/?name={member.user.username}&background=random'
            }
            members.append(member_data)
        
        # Get recent transactions
        transactions = []

        for transaction in (
            GroupTransaction.query
            .filter_by(group_id=group.id)
            .order_by(GroupTransaction.created_at.desc())
            .limit(10)
            .all()
        ):
            splits = TransactionSplit.query.filter_by(transaction_id=transaction.id).all()
            split_users = [split.user.username for split in splits]

            transactions.append({
                'id': transaction.id,
                'description': transaction.description,
                'amount': transaction.amount,
                'category': transaction.category,
                'paid_by': transaction.payer.username,
                'split_among': split_users,
                'date': transaction.created_at
            })
  
        # Get pending settlements for current user
        settlements = []
        user_splits = TransactionSplit.query\
            .join(GroupTransaction, TransactionSplit.transaction_id == GroupTransaction.id)\
            .filter(
                GroupTransaction.group_id == group_id,
                TransactionSplit.user_id == current_user.user_id,
                TransactionSplit.settled == False
            ).all()
        
        for split in user_splits:
            transaction = split.transaction
            if transaction.paid_by != current_user.user_id:
                settlements.append({
                    'id': split.id,
                    'from_user': current_user.username,
                    'to_user': transaction.payer.username,
                    'amount': split.amount,
                    'reason': f"For: {transaction.description}"
                })
        
        # Get join requests (if admin)
        join_requests = []
        if membership.role == 'admin':
            requests = JoinRequest.query.filter_by(
                group_id=group_id, 
                status='pending'
            ).all()
            
            for req in requests:
                join_requests.append({
                    'id': req.id,
                    'user_id': req.user_id,
                    'username': req.user.username,
                    'message': req.message,
                    'created_at': req.created_at.strftime('%Y-%m-%d')
                })
        
        return render_template('group_detail.html',
                             group=group,
                             members=members,
                             transactions=transactions,
                             settlements=settlements,
                             join_requests=join_requests,
                             user_role=membership.role,
                             current_user=current_user)
        
    except Exception as e:
        app.logger.error(f"Error in group detail: {str(e)}")
        return render_template('error.html', message="Error loading group"), 500

# API Routes for Groups
@groups_bp.route('/api/groups/create', methods=['POST'])
@login_required
def create_group():
    """Create a new group"""
    try:
        data = request.get_json()
        
        required_fields = ['name']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'message': 'Group name is required'}), 400
        
        # Generate unique group code
        while True:
            group_code = generate_group_code()
            if not Group.query.filter_by(group_code=group_code).first():
                break
        
        # Create group
        group = Group(
            name=data['name'],
            description=data.get('description', ''),
            group_code=group_code,
            currency=data.get('currency', 'INR'),
            group_type=data.get('type', 'friends'),
            is_private=data.get('is_private', True),
            created_by=current_user.user_id
        )
        
        db.session.add(group)
        db.session.flush()
        
        # Add creator as admin
        group_member = GroupMember(
            group_id=group.id,
            user_id=current_user.user_id,
            role='admin'
        )
        db.session.add(group_member)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'group_id': group.id,
            'group_code': group_code,
            'message': 'Group created successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Create group error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to create group'}), 500

@groups_bp.route('/api/groups/join', methods=['POST'])
@login_required
def join_group():
    """Request to join a group"""
    try:
        data = request.get_json()
        group_code = data.get('group_code', '').strip().upper()
        
        if not group_code:
            return jsonify({'success': False, 'message': 'Group code is required'}), 400
        
        # Find group by code
        group = Group.query.filter_by(group_code=group_code).first()
        if not group:
            return jsonify({'success': False, 'message': 'Group not found'}), 404
        
        # Check if already a member
        existing_member = GroupMember.query.filter_by(
            group_id=group.id, 
            user_id=current_user.user_id
        ).first()
        
        if existing_member:
            return jsonify({'success': False, 'message': 'Already a member of this group'}), 400
        
        # Check if already requested
        existing_request = JoinRequest.query.filter_by(
            group_id=group.id,
            user_id=current_user.user_id,
            status='pending'
        ).first()
        
        if existing_request:
            return jsonify({'success': False, 'message': 'Join request already sent'}), 400
        
        if group.is_private:
            # Create join request
            join_request = JoinRequest(
                group_id=group.id,
                user_id=current_user.user_id,
                message=data.get('message', ''),
                status='pending'
            )
            db.session.add(join_request)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Join request sent. Waiting for admin approval.'
            })
        else:
            # Add directly as member
            group_member = GroupMember(
                group_id=group.id,
                user_id=current_user.user_id,
                role='member'
            )
            db.session.add(group_member)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Successfully joined the group'
            })
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Join group error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to join group'}), 500

@groups_bp.route('/api/groups/<int:group_id>/transactions', methods=['POST'])
@login_required
def add_group_transaction(group_id):
    """Add a transaction to a group"""
    try:
        data = request.get_json()
        
        # Verify user is member of this group
        membership = GroupMember.query.filter_by(
            group_id=group_id, 
            user_id=current_user.user_id
        ).first()
        
        if not membership:
            return jsonify({'success': False, 'message': 'Not a member of this group'}), 403
        
        required_fields = ['description', 'amount', 'split_type']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Create transaction
        transaction = GroupTransaction(
            group_id=group_id,
            paid_by=current_user.user_id,
            description=data['description'],
            amount=float(data['amount']),
            category=data.get('category', 'other'),
            split_type=data['split_type']
        )
        
        db.session.add(transaction)
        db.session.flush()
        
        # Get all group members
        members = GroupMember.query.filter_by(group_id=group_id).all()
        
        # Create splits based on split type
        split_type = data['split_type']
        amount = float(data['amount'])
        
        if split_type == 'equal':
            split_amount = amount / len(members)
            for member in members:
                split = TransactionSplit(
                    transaction_id=transaction.id,
                    user_id=member.user_id,
                    amount=split_amount
                )
                db.session.add(split)
        elif split_type == 'percentage':
            # TODO: Implement percentage split
            pass
        elif split_type == 'custom':
            # TODO: Implement custom split
            pass
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Transaction added successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add group transaction error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to add transaction'}), 500

@groups_bp.route('/api/groups/<int:group_id>/requests', methods=['GET'])
@login_required
def get_group_requests(group_id):
    """Get join requests for a group (admin only)"""
    try:
        # Check if user is admin
        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.user_id,
            role='admin'
        ).first()
        
        if not membership:
            return jsonify({'success': False, 'message': 'Not authorized'}), 403
        
        requests = JoinRequest.query.filter_by(
            group_id=group_id,
            status='pending'
        ).all()
        
        requests_data = []
        for req in requests:
            requests_data.append({
                'id': req.id,
                'user_id': req.user_id,
                'username': req.user.username,
                'message': req.message,
                'created_at': req.created_at.strftime('%Y-%m-%d %H:%M')
            })
        
        return jsonify({
            'success': True,
            'requests': requests_data
        })
        
    except Exception as e:
        app.logger.error(f"Get group requests error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to get requests'}), 500

@groups_bp.route('/api/groups/requests/<int:request_id>/action', methods=['POST'])
@login_required
def handle_join_request(request_id):
    """Accept or reject a join request"""
    try:
        data = request.get_json()
        action = data.get('action')  # 'accept' or 'reject'
        
        if action not in ['accept', 'reject']:
            return jsonify({'success': False, 'message': 'Invalid action'}), 400
        
        # Find the join request
        join_request = JoinRequest.query.get_or_404(request_id)
        
        # Check if user is admin of this group
        membership = GroupMember.query.filter_by(
            group_id=join_request.group_id,
            user_id=current_user.user_id,
            role='admin'
        ).first()
        
        if not membership:
            return jsonify({'success': False, 'message': 'Not authorized'}), 403
        
        if action == 'accept':
            # Add user as member
            group_member = GroupMember(
                group_id=join_request.group_id,
                user_id=join_request.user_id,
                role='member'
            )
            db.session.add(group_member)
        
        # Update request status
        join_request.status = 'accepted' if action == 'accept' else 'rejected'
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Request {action}ed successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Handle join request error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to process request'}), 500

@groups_bp.route('/api/groups/<int:group_id>/analytics', methods=['GET'])
@login_required
def get_group_analytics(group_id):
    """Get analytics for a group"""
    try:
        # Verify user is member
        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.user_id
        ).first()
        
        if not membership:
            return jsonify({'success': False, 'message': 'Not a member'}), 403
        
        group = Group.query.get_or_404(group_id)
        
        # Get category-wise spending
        categories = defaultdict(float)
        monthly = defaultdict(float)
        
        for transaction in group.transactions:
            categories[transaction.category] += transaction.amount
            
            month_key = transaction.created_at.strftime('%Y-%m')
            monthly[month_key] += transaction.amount
        
        # Prepare response
        return jsonify({
            'success': True,
            'categories': {
                'labels': list(categories.keys()),
                'values': list(categories.values())
            },
            'monthly': {
                'labels': sorted(monthly.keys()),
                'values': [monthly[key] for key in sorted(monthly.keys())]
            },
            'members': len(group.members),
            'total_transactions': len(group.transactions),
            'total_balance': calculate_group_balance(group_id)
        })
        
    except Exception as e:
        app.logger.error(f"Get group analytics error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to get analytics'}), 500

@groups_bp.route('/api/groups/<int:group_id>/settle', methods=['POST'])
@login_required
def settle_transaction(group_id):
    """Mark a transaction split as settled"""
    try:
        data = request.get_json()
        split_id = data.get('split_id')
        
        if not split_id:
            return jsonify({'success': False, 'message': 'Split ID is required'}), 400
        
        # Find the split
        split = TransactionSplit.query.get_or_404(split_id)
        
        # Verify this split belongs to a transaction in this group
        transaction = GroupTransaction.query.get(split.transaction_id)
        if not transaction or transaction.group_id != group_id:
            return jsonify({'success': False, 'message': 'Invalid split'}), 404
        
        # Verify this split belongs to the current user
        if split.user_id != current_user.user_id:
            return jsonify({'success': False, 'message': 'Not authorized'}), 403
        
        # Mark as settled
        split.settled = True
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Settlement completed'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Settle transaction error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to complete settlement'}), 500

@groups_bp.route('/api/groups/<int:group_id>', methods=['DELETE'])
@login_required
def delete_group(group_id):
    """Delete a group (admin only)"""
    try:
        # Check if user is admin
        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.user_id,
            role='admin'
        ).first()
        
        if not membership:
            return jsonify({'success': False, 'message': 'Not authorized'}), 403
        
        group = Group.query.get_or_404(group_id)
        db.session.delete(group)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Group deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Delete group error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to delete group'}), 500

@groups_bp.route('/api/groups/<int:group_id>/update', methods=['POST'])
@login_required
def update_group(group_id):
    """Update an existing group"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('name') or not data.get('name').strip():
            return jsonify({'success': False, 'message': 'Group name is required'}), 400
        
        # Check if group exists
        group = Group.query.get(group_id)
        if not group:
            return jsonify({'success': False, 'message': 'Group not found'}), 404
        
        # Check if current user is admin of this group
        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.user_id,
            role='admin'
        ).first()
        
        if not membership:
            return jsonify({
                'success': False, 
                'message': 'Unauthorized: Only group admins can edit group information'
            }), 403
        
        # Update group fields
        group.name = data['name'].strip()
        group.description = data.get('description', '').strip()
        group.currency = data.get('currency', group.currency)
        group.group_type = data.get('type', group.group_type)
        group.is_private = data.get('is_private', group.is_private)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Group updated successfully',
            'group': {
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'currency': group.currency,
                'type': group.group_type,
                'is_private': group.is_private,
                'code': group.group_code
            }
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Update group error for group {group_id}: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'Failed to update group'
        }), 500
@groups_bp.route('/api/groups/<int:group_id>/members', methods=['GET'])
@login_required
def get_group_members(group_id):
    """Get all group members with their balances"""
    try:
        # Check if group exists
        group = Group.query.get(group_id)
        if not group:
            return jsonify({'success': False, 'message': 'Group not found'}), 404
        
        # Check if user is admin
        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.user_id,
            role='admin'
        ).first()
        
        if not membership:
            return jsonify({'success': False, 'message': 'Only admins can manage members'}), 403
        
        # Get all members with their balances
        members = GroupMember.query.filter_by(group_id=group_id).all()
        
        members_data = []
        for member in members:
            user = User.query.get(member.user_id)
            
            # Calculate user's balance in this group
            # You might need to adjust this based on your transaction model
            user_balance = 0  # Calculate based on your transaction logic
            
            members_data.append({
                'id': member.id,  # GroupMember id
                'user_id': member.user_id,  # User's id
                'username': user.username,
                'email': user.email,
                'avatar': user.avatar if hasattr(user, 'avatar') else None,  # Handle if avatar doesn't exist
                'role': member.role,
                'balance': float(member.balance) if member.balance else 0.0,  # Use the balance from GroupMember
                'joined_at': member.joined_at.isoformat() if member.joined_at else None,
                'can_remove': member.balance == 0  # Can remove if no balance
            })
        
        return jsonify({
            'success': True,
            'members': members_data
        })
        
    except Exception as e:
        app.logger.error(f"Get group members error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch members'}), 500

@groups_bp.route('/api/groups/<int:group_id>/members/<int:member_id>/remove', methods=['POST'])
@login_required
def remove_group_member(group_id, member_id):
    """Remove a member from group (if no pending settlements)"""
    try:
        # Check if group exists
        group = Group.query.get(group_id)
        if not group:
            return jsonify({'success': False, 'message': 'Group not found'}), 404
        
        # Check if user is admin
        admin_membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.user_id,
            role='admin'
        ).first()
        
        if not admin_membership:
            return jsonify({'success': False, 'message': 'Only admins can remove members'}), 403
        
        # Check if member exists
        member = GroupMember.query.get(member_id)
        if not member or member.group_id != group_id:
            return jsonify({'success': False, 'message': 'Member not found in this group'}), 404
        
        # Don't allow removing yourself (admin)
        if member.user_id == current_user.user_id:
            return jsonify({'success': False, 'message': 'You cannot remove yourself as admin'}), 400
        
        # Check if member has pending settlements
        # You need to implement this based on your transaction/settlement model
        has_settlements = False  # Replace with actual logic
        
        if has_settlements:
            return jsonify({
                'success': False, 
                'message': 'Cannot remove member with pending settlements'
            }), 400
        
        # Remove member from group
        db.session.delete(member)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Member removed successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Remove member error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to remove member'}), 500

@groups_bp.route('/api/groups/<int:group_id>/members/<int:member_id>/role', methods=['POST'])
@login_required
def change_member_role(group_id, member_id):
    """Change member role (promote/demote)"""
    try:
        data = request.get_json()
        new_role = data.get('role')
        
        if new_role not in ['admin', 'member']:
            return jsonify({'success': False, 'message': 'Invalid role'}), 400
        
        # Check if group exists
        group = Group.query.get(group_id)
        if not group:
            return jsonify({'success': False, 'message': 'Group not found'}), 404
        
        # Check if user is admin
        admin_membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.user_id,
            role='admin'
        ).first()
        
        if not admin_membership:
            return jsonify({'success': False, 'message': 'Only admins can change roles'}), 403
        
        # Check if member exists
        member = GroupMember.query.get(member_id)
        if not member or member.group_id != group_id:
            return jsonify({'success': False, 'message': 'Member not found in this group'}), 404
        
        # Don't allow changing your own role if you're the only admin
        if member.user_id == current_user.user_id:
            admin_count = GroupMember.query.filter_by(
                group_id=group_id,
                role='admin'
            ).count()
            
            if admin_count <= 1:
                return jsonify({
                    'success': False, 
                    'message': 'Cannot change your own role - you are the only admin'
                }), 400
        
        # Update role
        member.role = new_role
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Member role changed to {new_role}'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Change role error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to change role'}), 500
def check_member_has_settlements(group_id, user_id):
    """
    Check if a member has pending settlements in the group.
    Returns True if member has pending settlements, False otherwise.
    """
    # This depends on your transaction/settlement model
    # Here's a sample implementation:
    
    # 1. Check if member owes money to others
    settlements = Settlement.query.filter_by(
        group_id=group_id,
        from_user_id=user_id,
        status='pending'
    ).all()
    
    if settlements:
        return True
    
    # 2. Check if others owe money to member
    settlements_owed = Settlement.query.filter_by(
        group_id=group_id,
        to_user_id=user_id,
        status='pending'
    ).all()
    
    if settlements_owed:
        return True
    
    # 3. Check for any uncleared transactions
    # (Implement based on your transaction model)
    
    return False

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')

# Register the blueprint with the app
app.register_blueprint(savings_bp, url_prefix='/api')
app.register_blueprint(transactions_bp, url_prefix='/api')
app.register_blueprint(groups_bp) 

if __name__ == "__main__":
    initialize_database()
    app.run(host='0.0.0.0', port=3000, debug=True)