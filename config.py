import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGO_URI = os.getenv('MONGO_URI', '').replace('/?', '/resume_db?')  # Specify database name
    GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
    OPENAI_API_KEY = os.getenv('OPEN-AI-KEY')  # Added OpenAI key
    
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
    AWS_REGION = os.getenv('AWS_REGION')
    COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
    COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
    COGNITO_CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')
    COGNITO_DOMAIN = os.getenv('COGNITO_DOMAIN')  # The UI domain
    COGNITO_AUTHORITY = f"https://cognito-idp.{os.getenv('AWS_REGION')}.amazonaws.com/{os.getenv('COGNITO_USER_POOL_ID')}"  # The authority URL
    COGNITO_REDIRECT_URL = os.getenv('COGNITO_REDIRECT_URL')
    COGNITO_LOGOUT_URL =  os.getenv('COGNITO_LOGOUT_URL')
    COGNITO_SCOPES = ['email', 'openid', 'phone']

    # AWS SQS Configuration
    SQS_QUEUE_URL = os.getenv('SQS_QUEUE_URL')
