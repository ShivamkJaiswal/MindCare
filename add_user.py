from pymongo import MongoClient

# Connect to MongoDB (ensure MongoDB server is running)
client = MongoClient("mongodb://localhost:27017/")

# Create or connect to database and collection
db = client["mindcareDB"]
users = db["users"]

# Sample user data
sample_user = {
    "email": "user@example.com",
    "password": "password123"  # In production, use hashed passwords!
}

# Insert the user only if not already present
if users.find_one({"email": sample_user["email"]}) is None:
    users.insert_one(sample_user)
    print("✅ Sample user added successfully.")
else:
    print("ℹ️ User already exists.")
