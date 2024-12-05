import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGO_URI = os.getenv('MONGO_URI', '').replace('/?', '/resume_db?')  # Specify database name
    GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
    
    # Redis configuration
    REDIS_HOST = os.getenv('REDIS_HOST')
    REDIS_PORT = int(os.getenv('REDIS_PORT'))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
    
       # Redis configuration
    REDIS_HOST_2 = os.getenv('REDIS_HOST_2')
    REDIS_PORT_2 = int(os.getenv('REDIS_PORT_2'))
    REDIS_PASSWORD_2 = os.getenv('REDIS_PASSWORD_2')
    
    # MongoDB collections
    RESUME_COLLECTION = 'resumes'
    
    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'pdf'}
