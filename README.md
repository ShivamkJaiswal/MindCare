# Predicting Stress, Anxiety, and Depression

## Project Description
This project is a comprehensive web application designed to help users monitor and predict their mental health status, specifically focusing on stress, anxiety, and depression levels. The application allows users to log daily mood, sleep, activity, and physiological data, which is then analyzed to provide insights and trends over time. The goal is to empower users with actionable information to better manage their mental well-being.

## Features
- **User Registration and Authentication:** Secure signup and login system with password hashing to protect user credentials.
- **Password Reset:** Users can reset their passwords securely using a token-based system sent via email.
- **User Profile Management:** Users can update their personal information and change passwords.
- **Daily Mental Health Tracking:** Users can submit daily data including mood, sleep quality, physical activity, heart rate, and notes.
- **Stress, Anxiety, and Depression Scoring:** The system calculates scores based on user inputs to quantify mental health status.
- **Dashboard Visualization:** Interactive dashboard displaying historical data trends and statistics for stress, anxiety, and depression.
- **Informational Resources:** Access to tips and articles related to mental health to support user education.
- **Session Management:** Persistent login sessions with configurable expiration for user convenience.

## Technologies Used
- **Python 3:** Core programming language for backend development.
- **Flask:** Lightweight web framework used to build the web application.
- **MongoDB:** NoSQL database for storing user data and mental health tracking information.
- **PyMongo:** Python driver for MongoDB integration.
- **Werkzeug:** Provides utilities for password hashing and security.
- **HTML, CSS, JavaScript:** Frontend technologies for building user interfaces.
- **Tailwind CSS:** Utility-first CSS framework used for styling the frontend.

## Usage Instructions
- **Register a New Account:** Create a user account by providing a username, email, phone number, and password.
- **Login:** Access your account using your email and password.
- **Dashboard:** View your mental health statistics, including stress, anxiety, and depression trends over time.
- **Submit Daily Tracker Data:** Input daily mood, sleep hours, physical activity level, heart rate, and any notes to track your mental health.
- **Profile Management:** Update your personal details and change your password as needed.
- **Password Reset:** If you forget your password, use the password reset feature to generate a secure token and set a new password.
- **Explore Resources:** Access tips and articles to learn more about managing mental health.

## Folder Structure Overview
```
Predecting_Stress_anxiety_Depression/
│
├── app.py                  # Main Flask application entry point
├── app/                    # Application package containing core modules
│   ├── __init__.py         # Package initializer
│   ├── routes.py           # Defines all route handlers and views
│   └── utils.py            # Utility functions (currently empty)
├── dataset/                # Dataset files for model training or analysis (if any)
├── model_training/         # Scripts and notebooks for training predictive models
├── static/                 # Static assets like CSS, JavaScript, and images
│   ├── css/                # Stylesheets including Tailwind CSS configuration
│   ├── js/                 # JavaScript files for frontend interactivity
│   └── images/             # Image assets used in the application
├── templates/              # HTML templates rendered by Flask routes
├── requirements.txt        # Python dependencies required to run the project
├── README.md               # Project documentation (this file)
└── tailwind.config.js      # Configuration file for Tailwind CSS
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.
