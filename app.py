from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime, timezone, timedelta as td
import os
import joblib
import numpy as np

from app.routes import main

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Session lifetime (used for "Remember Me")
app.permanent_session_lifetime = timedelta(days=7)

app.register_blueprint(main)

@app.context_processor
def inject_login_status():
    from flask import session
    return {'is_logged_in': 'email' in session}

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["mindcareDB"]
users_collection = db["users"]
stress_data_collection = db["stress_data"]

# Load ML models
stress_model = joblib.load('model_training/stress_model.pkl')
anxiety_model = joblib.load('model_training/anxiety_model.pkl')
depression_model = joblib.load('model_training/depression_model.pkl')
health_risk_alert_model = joblib.load('model_training/health_risk_alert_model.pkl')
productivity_level_model = joblib.load('model_training/productivity_level_model.pkl')

# ==========================
# HOME ROUTE (INDEX)
# ==========================
@app.route('/')
def index():
    return render_template('index.html')

# ==========================
# FORGOT PASSWORD ROUTES
# ==========================
import secrets

@app.route('/forgotpassword', methods=['GET', 'POST'])
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
            # Display the token to the user
            message = f"Your password reset token is: {token}. Use this token to reset your password."
            return render_template('forgotpassword.html', message=message)
        else:
            error = "Email address not found."
            return render_template('forgotpassword.html', error=error)
    return render_template('forgotpassword.html')

# ==========================
# RESET PASSWORD ROUTES
# ==========================
@app.route('/resetpassword', methods=['GET', 'POST'])
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

# ==========================
# LOGIN ROUTE
# ==========================
@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Login route accessed")  # Debug log
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('rememberMe')

        print(f"Login POST data: email={email}, remember={remember}")  # Debug log

        user = users_collection.find_one({'email': email})
        print(f"User found in DB: {user}")  # Debug log

        if user and check_password_hash(user['password'], password):
            session['email'] = user['email']
            session.permanent = bool(remember)
            # Update last login timestamp
            users_collection.update_one({'email': email}, {'$set': {'last_login': datetime.utcnow()}})
            print("Login successful")  # Debug log
            return redirect(url_for('dashboard'))
        else:
            print("Login failed: Invalid email or password")  # Debug log
            return render_template('login.html', error="Invalid email or password.")

    print("Login GET request")  # Debug log
    return render_template('login.html')

# ==========================
# SIGNUP ROUTE
# ==========================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        if users_collection.find_one({'email': email}):
            return render_template('signup.html', error="Email already exists.")

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            'username': username,
            'email': email,
            'phone': phone,
            'password': hashed_password,
            'last_login': None,
            'statistics': {
                'stress': [3, 2, 4, 5, 3, 4, 2],
                'anxiety': [2, 3, 3, 4, 2, 3, 3],
                'depression': [1, 2, 2, 3, 1, 2, 1]
            }
        })

        return redirect(url_for('login'))

    return render_template('signup.html')

# ==========================
# DASHBOARD
# ==========================
@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('login'))
    user = users_collection.find_one({'email': session['email']})

    # Fetch all stress data entries for the user sorted by timestamp
    stress_entries = list(stress_data_collection.find({'email': session['email']}).sort('timestamp', 1))

    if stress_entries:
        labels = [entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') for entry in stress_entries]
        stress_values = [entry.get('stress_score', 0) for entry in stress_entries]
        anxiety_values = [entry.get('anxiety_score', 0) for entry in stress_entries]
        depression_values = [entry.get('depression_score', 0) for entry in stress_entries]
        health_risk_alert_values = [entry.get('health_risk_alert_score', 0) for entry in stress_entries]
        productivity_level_values = [entry.get('productivity_level_score', 0) for entry in stress_entries]
    else:
        labels = []
        stress_values = []
        anxiety_values = []
        depression_values = []
        health_risk_alert_values = []
        productivity_level_values = []

    last_login_utc = user.get('last_login')
    if last_login_utc:
        # Convert UTC to IST (UTC+5:30)
        ist_offset = td(hours=5, minutes=30)
        last_login_ist = last_login_utc.replace(tzinfo=timezone.utc).astimezone(timezone(ist_offset))
        last_login_str = last_login_ist.strftime("%Y-%m-%d %H:%M:%S")
    else:
        last_login_str = "Never"
    return render_template('userdashboard.html',
                           email=user.get('email'),
                           username=user.get('username'),
                           phone=user.get('phone'),
                           last_login=last_login_str,
                           labels=labels,
                           stress_values=stress_values,
                           anxiety_values=anxiety_values,
                           depression_values=depression_values,
                           health_risk_alert_values=health_risk_alert_values,
                           productivity_level_values=productivity_level_values)

# ==========================
# SUBMIT TRACKER DATA
# ==========================
@app.route('/submit_tracker', methods=['POST'])
def submit_tracker():
    import random
    try:
        data = request.json
        print(f"Received data: {data}")  # Debug log

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        email = session.get('email', 'anonymous')
        # Allow anonymous submissions, so no error if email missing

        mood_str = data.get('mood')
        sleep = data.get('sleep')
        activity = data.get('activity')
        heart_rate = data.get('heartRate')
        age = data.get('age')

        # Validate required fields
        if None in [mood_str, sleep, activity, heart_rate, age]:
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            sleep = int(sleep)
            heart_rate = int(heart_rate)
            age = int(age)
        except ValueError:
            return jsonify({'error': 'Invalid numeric values'}), 400

        # Map mood string to numeric value for calculations
        mood_map = {
            "Very Bad": 1,
            "Bad": 2,
            "Neutral": 3,
            "Good": 4,
            "Happy": 5
        }
        mood = mood_map.get(mood_str)
        if mood is None:
            return jsonify({'error': 'Invalid mood value'}), 400

        # Convert activity to score
        activity_score = 1 if activity == "High" else 2 if activity == "Medium" else 3

        # Improved heuristic for stress score calculation
        # Consider mood, sleep, activity, heart rate with weighted factors
        stress_score_calc = (7 - mood) * 1.5 + (8 - sleep) * 1.2 + (3 if activity_score == 3 else 0) * 1.5 + (heart_rate / 18)
        stress_score = int(round(max(0, min(10, stress_score_calc))))

        # Anxiety score: higher if mood is low, heart rate is high, financial stress high (scale 1-5)
        financial_stress = data.get('financialStress')
        try:
            financial_stress = int(financial_stress) if financial_stress is not None else 0
        except ValueError:
            financial_stress = 0
        anxiety_score = max(0, min(10, (6 - mood) + (heart_rate / 25) + financial_stress))

        # Depression score: higher if mood is low, sleep is low, job satisfaction low (scale 1-5)
        job_satisfaction = data.get('jobSatisfaction')
        try:
            job_satisfaction = int(job_satisfaction) if job_satisfaction is not None else 5
        except ValueError:
            job_satisfaction = 5
        depression_score = max(0, min(10, (6 - mood) + (8 - sleep) + (6 - job_satisfaction)))

        # Calculate health risk alert score using Python logic heuristic
        # Example: higher if stress_score, anxiety_score, depression_score are high
        health_risk_alert_score = int(round(min(20, ((stress_score + anxiety_score + depression_score) / 30) * 20)))

        # Calculate productivity level score using Python logic heuristic
        # Example: inversely proportional to stress and depression
        productivity_level_score = int(round(max(0, 20 - ((stress_score + depression_score) / 20) * 20)))

        # Extract new fields
        study_satisfaction = data.get('studySatisfaction')
        job_satisfaction_raw = data.get('jobSatisfaction')
        financial_stress_raw = data.get('financialStress')
        city = data.get('city')

        # Define some random productivity tips and trivia
        productivity_tips = [
            "Take regular breaks to improve focus.",
            "Prioritize your tasks using a to-do list.",
            "Eliminate distractions while working.",
            "Set specific goals for each work session.",
            "Maintain a healthy work-life balance."
        ]
        trivia_list = [
            "Did you know? The human brain weighs about 3 pounds.",
            "Trivia: Drinking water can boost your productivity.",
            "Fun fact: Listening to music can improve concentration.",
            "Did you know? Exercise increases blood flow to the brain.",
            "Trivia: A tidy workspace can enhance creativity."
        ]

        random_tip = random.choice(productivity_tips)
        random_trivia = random.choice(trivia_list)

        # Save to database with timestamp and all form data including new fields
        print("Inserting data into database...")  # Debug log
        stress_data_collection.insert_one({
            'email': email,
            'gender': data.get('gender'),
            'age': age,
            'profession': data.get('profession'),
            'occupation': data.get('occupation'),
            'heart_rate': heart_rate,
            'mood': mood_str,
            'sleep': sleep,
            'activity': activity,
            'notes': data.get('notes'),
            'study_satisfaction': study_satisfaction,
            'job_satisfaction': job_satisfaction_raw,
            'financial_stress': financial_stress_raw,
            'city': city,
            'stress_score': stress_score,
            'anxiety_score': anxiety_score,
            'depression_score': depression_score,
            'health_risk_alert_score': health_risk_alert_score,
            'productivity_level_score': productivity_level_score,
            'timestamp': datetime.utcnow()
        })
        print("Data inserted successfully.")  # Debug log

        return jsonify({
            'message': 'Data saved successfully',
            'stress_score': stress_score,
            'anxiety_score': anxiety_score,
            'depression_score': depression_score,
            'health_risk_alert_score': health_risk_alert_score,
            'productivity_level_score': productivity_level_score,
            'productivity_tip': random_tip,
            'trivia': random_trivia
        })
    except Exception as e:
        import traceback
        print("Exception in submit_tracker:")
        traceback.print_exc()
        return jsonify({'error': 'An error occurred while processing the request.'}), 500

# ==========================
# UPDATE STATISTICS
# ==========================
@app.route('/update_statistics', methods=['POST'])
def update_statistics():
    if 'email' not in session:
        return redirect(url_for('login'))
    stress = request.form.getlist('stress[]')
    anxiety = request.form.getlist('anxiety[]')
    depression = request.form.getlist('depression[]')

    # Convert string list to int list
    try:
        stress = list(map(int, stress))
        anxiety = list(map(int, anxiety))
        depression = list(map(int, depression))
    except ValueError:
        return "Invalid input data", 400

    users_collection.update_one(
        {'email': session['email']},
        {'$set': {'statistics': {'stress': stress, 'anxiety': anxiety, 'depression': depression}}}
    )
    return redirect(url_for('dashboard'))

# ==========================
# LOGOUT
# ==========================
@app.route('/logout')
def logout():
    print("Logout route accessed")  # Debug log
    session.pop('email', None)
    print("Session cleared")  # Debug log
    return redirect(url_for('login'))

# ==========================
# RUN APP
# ==========================
@app.route('/back_to_dashboard')
def back_to_dashboard():
    if 'email' in session:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
