from flask import render_template, Blueprint, redirect, url_for

from pymongo import MongoClient

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["mindcareDB"]
users_collection = db["users"]
stress_data_collection = db["stress_data"]

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('index.html')

from flask import request

@main.route('/tracker')
def tracker():
    from_dashboard = request.args.get('from') == 'dashboard'
    return render_template('tracker.html', from_dashboard=from_dashboard)

@main.route('/tips')
def tips():
    return render_template('tips.html')

@main.route('/articles')
def articles():
    return render_template('articles.html')
import secrets
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, flash
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta

@main.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            return render_template('forgotpassword.html', error="Please enter your email address.")
        user = users_collection.find_one({'email': email})
        if user:
            # Generate a secure token
            token = secrets.token_urlsafe(16)
            # Save the token in the user's document with an expiry (e.g., 1 hour)
            users_collection.update_one({'email': email}, {'$set': {'reset_token': token, 'reset_token_expiry': datetime.utcnow() + timedelta(hours=1)}})
            # Redirect to resetpassword page with token as query param
            return redirect(url_for('main.resetpassword', token=token))
        else:
            error = "Email address not found."
            return render_template('forgotpassword.html', error=error)
    return render_template('forgotpassword.html')

@main.route('/profile', methods=['GET', 'POST'])
def profile():
    user_email = session.get('email')
    if not user_email:
        flash('You must be logged in to access this page.')
        return redirect(url_for('main.login'))
    user = users_collection.find_one({'email': user_email})

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email:
            error = "Username and email are required."
            return render_template('profile.html', user=user, error=error)

        if password:
            if password != confirm_password:
                error = "Passwords do not match."
                return render_template('profile.html', user=user, error=error)
            hashed_password = generate_password_hash(password)
        else:
            hashed_password = user.get('password')

        update_data = {
            'username': username,
            'email': email,
            'phone': phone,
            'password': hashed_password
        }

        users_collection.update_one({'email': user_email}, {'$set': update_data})

        # Update session email if changed
        session['email'] = email

        message = "Profile updated successfully."
        user = users_collection.find_one({'email': email})
        return render_template('profile.html', user=user, message=message)

    return render_template('profile.html', user=user)

@main.route('/resetpassword', methods=['GET', 'POST'])
def resetpassword():
    if request.method == 'POST':
        token = request.form.get('token')
        new_password = request.form.get('new_password')
        if not token or not new_password:
            return render_template('resetpassword.html', error="Please provide both token and new password.")
        user = users_collection.find_one({'reset_token': token})
        if not user:
            return render_template('resetpassword.html', error="Invalid reset token.")
        # Check token expiry
        expiry = user.get('reset_token_expiry')
        if not expiry or expiry < datetime.utcnow():
            return render_template('resetpassword.html', error="Reset token has expired.")
        # Update password
        hashed_password = generate_password_hash(new_password)
        users_collection.update_one({'_id': user['_id']}, {'$set': {'password': hashed_password}, '$unset': {'reset_token': "", 'reset_token_expiry': ""}})
        message = "Your password has been reset successfully. You can now log in with your new password."
        return render_template('resetpassword.html', message=message)
    return render_template('resetpassword.html')

@main.route('/api/user/tracker_data', methods=['GET'])
def get_tracker_data():
    user_email = session.get('email')
    if not user_email:
        return {'error': 'Unauthorized'}, 401

    limit = request.args.get('limit', type=int)

    # Fetch tracker data for the user from stress_data_collection
    # Assuming stress_data_collection documents have fields: email, date, stress, anxiety, depression
    query = {'email': user_email}
    cursor = stress_data_collection.find(query).sort('date', 1)

    if limit:
        # To get last N entries, sort descending and limit, then reverse
        cursor = stress_data_collection.find(query).sort('date', -1).limit(limit)
        entries = list(cursor)
        entries.reverse()
    else:
        entries = list(cursor)

    labels = []
    stress_values = []
    anxiety_values = []
    depression_values = []

    for entry in entries:
        date_obj = entry.get('date')
        if date_obj:
            print(f"Original date_obj: {date_obj} (tzinfo={date_obj.tzinfo})")
            # Convert to IST timezone
            try:
                ist_zone = ZoneInfo("Asia/Kolkata")
                # If date_obj is naive, localize to UTC first
                if date_obj.tzinfo is None:
                    from datetime import timezone
                    date_obj = date_obj.replace(tzinfo=timezone.utc)
                date_obj = date_obj.astimezone(ist_zone)
                print(f"Converted date_obj: {date_obj} (tzinfo={date_obj.tzinfo})")
            except Exception:
                # If conversion fails, fallback to original date_obj
                pass
            # Format date in Indian format with time if available
            if hasattr(date_obj, 'hour'):
                formatted_date = date_obj.strftime('%d-%m-%Y %H:%M')
            else:
                formatted_date = date_obj.strftime('%d-%m-%Y')
        else:
            formatted_date = ''
        labels.append(formatted_date)
        stress_values.append(entry.get('stress', 0))
        anxiety_values.append(entry.get('anxiety', 0))
        depression_values.append(entry.get('depression', 0))
