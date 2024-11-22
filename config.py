import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGO_URI = os.getenv('MONGO_URI', '').replace('/?', '/resume_db?')  # Specify database name
    GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
    
    # MongoDB collections
    RESUME_COLLECTION = 'resumes'
    
    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'pdf'}
