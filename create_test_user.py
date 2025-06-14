from pymongo import MongoClient
from werkzeug.security import generate_password_hash

client = MongoClient("mongodb://localhost:27017/")
db = client["mindcareDB"]
users_collection = db["users"]

# Create a test user
email = "testuser@example.com"
password = "TestPassword123"
hashed_password = generate_password_hash(password)

# Check if user already exists
if users_collection.find_one({'email': email}):
    print(f"User with email {email} already exists.")
else:
    users_collection.insert_one({'email': email, 'password': hashed_password})
    print(f"Test user created with email: {email} and password: {password}")
