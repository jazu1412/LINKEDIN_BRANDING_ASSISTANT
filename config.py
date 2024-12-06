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

    # AWS Cognito Configuration
    COGNITO_REGION = 'us-east-1'
    COGNITO_USER_POOL_ID = 'us-east-1_juPVlepSl'
    COGNITO_CLIENT_ID = '6g7hokgbb3s91ocg72umebbg22'
    COGNITO_DOMAIN = 'https://us-east-1jupvlepsl.auth.us-east-1.amazoncognito.com'
    COGNITO_REDIRECT_URL = 'http://localhost:5000/auth/callback'
    COGNITO_SCOPES = ['email', 'openid', 'phone']
