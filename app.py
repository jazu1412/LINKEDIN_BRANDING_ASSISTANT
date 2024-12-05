from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import google.generativeai as genai
import os
import PyPDF2 as pdf
from flask_pymongo import PyMongo
from bson import ObjectId
from datetime import datetime
import json
import re
from config import Config
import redis
import logging
from auth_config import AuthConfig
from auth_utils import (
    keycloak_client, login_required, admin_required, verify_keycloak_token,
    get_google_provider_cfg, update_session_token, generate_totp_secret,
    generate_totp_uri, generate_qr_code, verify_totp, add_security_headers,
    TokenManager, init_session, check_token_expiry
)
from flask_session import Session
import requests
from oauthlib.oauth2 import WebApplicationClient
import pyotp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.config.from_object(AuthConfig)

# Initialize extensions
Session(app)
mongo = PyMongo(app)

# Redis connection
r = redis.Redis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    password=Config.REDIS_PASSWORD
)

# OAuth 2.0 client setup
google_client = WebApplicationClient(AuthConfig.GOOGLE_CLIENT_ID)

# Ensure database and collections exist
with app.app_context():
    # Create collections if they don't exist
    if Config.RESUME_COLLECTION not in mongo.db.list_collection_names():
        mongo.db.create_collection(Config.RESUME_COLLECTION)
        logger.info(f"Created MongoDB collection: {Config.RESUME_COLLECTION}")
    
    # Create users collection if it doesn't exist
    if 'users' not in mongo.db.list_collection_names():
        mongo.db.create_collection('users')
        mongo.db.users.create_index('email', unique=True)
        mongo.db.users.create_index('username', unique=True)
        logger.info("Created MongoDB collection: users")

genai.configure(api_key=Config.GOOGLE_API_KEY)

# Add security headers to all responses
@app.after_request
def after_request(response):
    return add_security_headers(response)

# Session management
@app.before_request
def before_request():
    if 'user_id' in session:
        # Check token expiration
        if not check_token_expiry():
            session.clear()
            if request.endpoint != 'login':
                return redirect(url_for('login', reason='token_expired'))
        
        # Check session expiration
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.utcnow() - last_activity > AuthConfig.SESSION_LIFETIME:
                session.clear()
                if request.endpoint != 'login':
                    return redirect(url_for('login', reason='session_expired'))
        
        # Update last activity
        session['last_activity'] = datetime.utcnow().isoformat()

# Authentication Routes

@app.route('/login')
def login():
    # Clear any existing session
    session.clear()
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'username', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check if user already exists
        if mongo.db.users.find_one({'$or': [
            {'email': data['email']},
            {'username': data['username']}
        ]}):
            return jsonify({'error': 'Email or username already exists'}), 409
        
        # Create user in Keycloak
        try:
            user_id = keycloak_client.create_user({
                'username': data['username'],
                'email': data['email'],
                'firstName': data['firstName'],
                'lastName': data['lastName'],
                'enabled': True,
                'credentials': [{
                    'type': 'password',
                    'value': data['password'],
                    'temporary': False
                }]
            })
        except Exception as e:
            logger.error(f"Keycloak user creation failed: {str(e)}")
            return jsonify({'error': 'Failed to create user'}), 500
        
        # Create user in MongoDB
        user_data = {
            'keycloak_id': user_id,
            'email': data['email'],
            'username': data['username'],
            'first_name': data['firstName'],
            'last_name': data['lastName'],
            'created_at': datetime.utcnow(),
            'two_factor_enabled': data.get('enable2fa', False),
            'two_factor_secret': generate_totp_secret() if data.get('enable2fa') else None
        }
        
        mongo.db.users.insert_one(user_data)
        
        if data.get('enable2fa'):
            # Initialize session for 2FA setup
            init_session()
            session['setup_2fa'] = True
            session['user_id'] = user_id
            return jsonify({'redirect_url': '/setup-2fa'})
        
        return jsonify({'redirect_url': '/login?registered=true'})
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400
        
        try:
            # Authenticate with Keycloak
            token = keycloak_client.token(username, password)
            token_info = verify_keycloak_token(token['access_token'])
            
            # Get user from MongoDB
            user = mongo.db.users.find_one({'keycloak_id': token_info['sub']})
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Initialize session
            init_session()
            
            # Update session with token info
            token_info.update({
                'access_token': token['access_token'],
                'refresh_token': token['refresh_token']
            })
            update_session_token(token_info)
            
            # Check if 2FA is enabled
            if user.get('two_factor_enabled'):
                session['2fa_required'] = True
                return jsonify({'requires_2fa': True})
            
            return jsonify({'redirect_url': '/'})
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    user = mongo.db.users.find_one({'keycloak_id': session['user_id']})
    if not user or not user.get('two_factor_secret'):
        return redirect(url_for('login'))
    
    totp_uri = generate_totp_uri(user['two_factor_secret'], user['email'])
    qr_code = generate_qr_code(totp_uri)
    
    return render_template('setup_2fa.html',
                         qr_code=f"data:image/png;base64,{qr_code}",
                         secret_key=user['two_factor_secret'])

@app.route('/verify-2fa')
def verify_2fa():
    if '2fa_required' not in session:
        return redirect(url_for('login'))
    return render_template('verify_2fa.html')

@app.route('/api/verify-2fa', methods=['POST'])
def api_verify_2fa():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        code = request.get_json().get('code')
        if not code:
            return jsonify({'error': 'Missing verification code'}), 400
        
        user = mongo.db.users.find_one({'keycloak_id': session['user_id']})
        if not user or not user.get('two_factor_secret'):
            return jsonify({'error': 'User not found or 2FA not enabled'}), 404
        
        if verify_totp(user['two_factor_secret'], code):
            session['2fa_verified'] = True
            session.pop('2fa_required', None)
            return jsonify({'redirect_url': '/'})
        
        return jsonify({'error': 'Invalid verification code'}), 401
        
    except Exception as e:
        logger.error(f"2FA verification error: {str(e)}")
        return jsonify({'error': 'Verification failed'}), 500

@app.route('/api/verify-2fa-setup', methods=['POST'])
def api_verify_2fa_setup():
    try:
        if 'user_id' not in session or 'setup_2fa' not in session:
            return jsonify({'error': 'Invalid session'}), 401
        
        code = request.get_json().get('code')
        if not code:
            return jsonify({'error': 'Missing verification code'}), 400
        
        user = mongo.db.users.find_one({'keycloak_id': session['user_id']})
        if not user or not user.get('two_factor_secret'):
            return jsonify({'error': 'User not found or 2FA not enabled'}), 404
        
        if verify_totp(user['two_factor_secret'], code):
            # Update user's 2FA status
            mongo.db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'two_factor_verified': True}}
            )
            session.pop('setup_2fa', None)
            return jsonify({'redirect_url': '/login'})
        
        return jsonify({'error': 'Invalid verification code'}), 401
        
    except Exception as e:
        logger.error(f"2FA setup verification error: {str(e)}")
        return jsonify({'error': 'Verification failed'}), 500

@app.route('/api/skip-2fa-setup', methods=['POST'])
def api_skip_2fa_setup():
    try:
        if 'user_id' not in session or 'setup_2fa' not in session:
            return jsonify({'error': 'Invalid session'}), 401
        
        # Disable 2FA for the user
        mongo.db.users.update_one(
            {'keycloak_id': session['user_id']},
            {
                '$set': {'two_factor_enabled': False},
                '$unset': {'two_factor_secret': ''}
            }
        )
        
        session.pop('setup_2fa', None)
        return jsonify({'redirect_url': '/login'})
        
    except Exception as e:
        logger.error(f"Skip 2FA setup error: {str(e)}")
        return jsonify({'error': 'Failed to skip 2FA setup'}), 500

@app.route('/api/auth/google')
def google_auth():
    try:
        google_provider_cfg = get_google_provider_cfg()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]
        
        request_uri = google_client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=AuthConfig.OAUTH_REDIRECT_URI,
            scope=["openid", "email", "profile"],
        )
        
        return jsonify({'auth_url': request_uri})
        
    except Exception as e:
        logger.error(f"Google auth error: {str(e)}")
        return jsonify({'error': 'Failed to initialize Google Sign In'}), 500

@app.route('/callback')
def callback():
    try:
        code = request.args.get("code")
        google_provider_cfg = get_google_provider_cfg()
        token_endpoint = google_provider_cfg["token_endpoint"]
        
        # Get tokens
        token_url, headers, body = google_client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=AuthConfig.OAUTH_REDIRECT_URI,
            code=code
        )
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(AuthConfig.GOOGLE_CLIENT_ID, AuthConfig.GOOGLE_CLIENT_SECRET),
        )
        
        google_client.parse_request_body_response(token_response.text)
        
        # Get user info
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = google_client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers)
        
        if userinfo_response.json().get("email_verified"):
            unique_id = userinfo_response.json()["sub"]
            email = userinfo_response.json()["email"]
            name = userinfo_response.json()["name"]
            
            # Check if user exists
            user = mongo.db.users.find_one({'google_id': unique_id})
            
            if not user:
                # Create new user
                user_data = {
                    'google_id': unique_id,
                    'email': email,
                    'name': name,
                    'created_at': datetime.utcnow()
                }
                mongo.db.users.insert_one(user_data)
            
            # Initialize session
            init_session()
            
            # Set session
            session['user_id'] = str(unique_id)
            session['email'] = email
            session['auth_method'] = 'google'
            
            return redirect('/')
        else:
            return jsonify({'error': 'Google authentication failed'}), 400
            
    except Exception as e:
        logger.error(f"Google callback error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/logout')
def logout():
    auth_method = session.get('auth_method')
    
    # Clear session
    session.clear()
    
    # If using Keycloak, also logout from Keycloak
    if auth_method == 'keycloak':
        try:
            keycloak_client.logout(session.get('refresh_token'))
        except:
            pass  # Ignore errors during logout
    
    return redirect(url_for('login'))

# Resume Analysis Routes

@app.route('/')
@login_required
def index():
    return render_template('upload.html')

@app.route('/analyze-form/<resume_id>')
@login_required
def analyze_form(resume_id):
    return render_template('analyze.html', resume_id=resume_id)

def clean_text(text):
    text = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
    text = re.sub(r'([A-Z])([A-Z][a-z])', r'\1 \2', text)
    text = re.sub(r'\.([A-Z])', r'. \1', text)
    text = re.sub(r',([A-Za-z])', r', \1', text)
    text = re.sub(r'\|', ' | ', text)
    text = re.sub(r'([a-zA-Z])@', r'\1 @', text)
    text = ' '.join(text.split())
    return text

def extract_text_from_pdf(pdf_file):
    reader = pdf.PdfReader(pdf_file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"
    return clean_text(text)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@app.route('/api/resume', methods=['POST'])
@login_required
def upload_resume():
    try:
        if 'resume' not in request.files:
            return jsonify({'error': 'No resume file uploaded'}), 400
        
        resume_file = request.files['resume']
        if resume_file.filename == '':
            return jsonify({'error': 'No resume file selected'}), 400
        
        if not allowed_file(resume_file.filename):
            return jsonify({'error': 'Please upload a PDF file'}), 400
        
        # Extract text from PDF
        resume_text = extract_text_from_pdf(resume_file)
        
        # Store in MongoDB
        logger.info(f"Storing resume in MongoDB: {resume_file.filename}")
        result = mongo.db[Config.RESUME_COLLECTION].insert_one({
            'text': resume_text,
            'filename': resume_file.filename,
            'user_id': session['user_id'],
            'created_at': datetime.utcnow()
        })
        resume_id = str(result.inserted_id)
        logger.info(f"Successfully stored resume in MongoDB with ID: {resume_id}")
        
        # Store in Redis cache
        r.set(f"resume:{resume_id}", resume_text)
        logger.info(f"Stored resume {resume_id} in Redis cache")
        
        return jsonify({
            'resume_id': resume_id,
            'message': 'Resume uploaded successfully'
        })
        
    except Exception as e:
        logger.error(f"Error in upload_resume: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_gemini_response(text, jd):
    prompt = (
        "You are an experienced Applicant Tracking System (ATS) specializing in the tech industry. "
        "Analyze the provided job description and extract all important keywords.\n\n"
        "Required JSON format (copy this structure exactly):\n"
        "{\n"
        '    "JD Match": "70%",\n'
        '    "JD Keywords": ["Java", "Spring", "SQL", "Cloud"]\n'
        "}\n\n"
        "Critical JSON formatting rules:\n"
        "1. Use exactly these two keys: JD Match and JD Keywords\n"
        "2. JD Keywords must be an array of strings\n"
        "3. Include commas between ALL array elements\n"
        "4. Include commas between ALL key-value pairs\n"
        "5. Use ONLY double quotes, never single quotes\n"
        "6. No text outside the JSON object\n"
        "7. List at least top 20 most important keywords from the job description\n"
        "8. Make sure 100 percent u list all technologies related to cs, software,tech,programming languages or any other cs or software related tech keywords which may fit in for an idea resume ONLY from the given job description\n\n"
        f"Resume text:\n{text}\n\n"
        f"Job Description:\n{jd}"
    )
    
    model = genai.GenerativeModel('gemini-pro')
    generation_config = {
        'temperature': 0.1,
        'top_p': 0.8,
        'top_k': 40,
        'max_output_tokens': 2048,
    }
    
    response = model.generate_content(
        prompt,
        generation_config=generation_config
    )
    
    response_text = response.text.strip()
    
    if response_text.startswith('```json'):
        response_text = response_text[7:-3].strip()
    
    try:
        response_text = re.sub(r'"\s+(?=")', '", ', response_text)
        response_text = re.sub(r'"\s+(?="\w+":)', '", ', response_text)
        
        parsed_json = json.loads(response_text)
        
        required_keys = ["JD Match", "JD Keywords"]
        if not all(key in parsed_json for key in required_keys):
            raise ValueError("Missing required keys in response")
            
        return parsed_json
    except Exception as e:
        print(f"JSON parsing error: {e}")
        print(f"Response text: {response_text}")
        raise Exception("Failed to parse Gemini API response")

def tailor_resume_points(resume_text, jd_text, keywords):
    prompt = (
        "You are an expert resume writer. Based on the provided resume and job description, "
        "generate 4 strong bullet points for experience or projects that incorporate the required keywords. "
        "Each bullet point should highlight relevant skills and achievements.\n\n"
        "Format your response as a JSON object with this exact structure:\n"
        "{\n"
        '    "tailored_points": [\n'
        '        "Point 1",\n'
        '        "Point 2",\n'
        '        "Point 3",\n'
        '        "Point 4"\n'
        '    ]\n'
        "}\n\n"
        "Guidelines:\n"
        "1. Each point should start with a strong action verb\n"
        "2. Include specific technical details and metrics when possible\n"
        "3. Focus on achievements and impact\n"
        "4. Incorporate the following keywords where relevant: " + ", ".join(keywords) + "\n\n"
        f"Resume Content:\n{resume_text}\n\n"
        f"Job Description:\n{jd_text}"
    )
    
    model = genai.GenerativeModel('gemini-pro')
    generation_config = {
        'temperature': 0.2,
        'top_p': 0.8,
        'top_k': 40,
        'max_output_tokens': 2048,
    }
    
    try:
        response = model.generate_content(
            prompt,
            generation_config=generation_config
        )
        
        response_text = response.text.strip()
        
        if response_text.startswith('```json'):
            response_text = response_text[7:-3].strip()
        
        # Clean up any potential formatting issues
        response_text = re.sub(r'"\s+(?=")', '", ', response_text)
        response_text = re.sub(r'"\s+(?="\w+":)', '", ', response_text)
        
        parsed_json = json.loads(response_text)
        
        # Validate response structure
        if not isinstance(parsed_json, dict) or 'tailored_points' not in parsed_json:
            raise ValueError("Invalid response format")
        
        if not isinstance(parsed_json['tailored_points'], list):
            raise ValueError("tailored_points must be an array")
        
        return {
            'tailored_points': parsed_json['tailored_points'][:4]  # Ensure exactly 4 points
        }
        
    except Exception as e:
        print(f"Error in tailor_resume_points: {str(e)}")
        print(f"Response text: {response_text if 'response_text' in locals() else 'No response text'}")
        return {
            'tailored_points': [
                "Developed and implemented software solutions utilizing required programming languages and frameworks",
                "Led technical projects and collaborated with cross-functional teams to deliver high-quality results",
                "Optimized system performance and implemented best practices in software development",
                "Contributed to the design and development of scalable applications and features"
            ]
        }

@app.route('/api/analyze', methods=['POST'])
@login_required
def analyze_job():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        resume_id = data.get('resume_id')
        job_description = data.get('job_description')
        
        if not resume_id or not job_description:
            return jsonify({'error': 'Missing resume_id or job_description'}), 400
        
        # Try to get resume from Redis first
        resume_text = r.get(f"resume:{resume_id}")
        
        if resume_text is None:
            logger.info(f"Resume {resume_id} not found in Redis cache, fetching from MongoDB")
            # If not in Redis, get from MongoDB and store in Redis
            resume = mongo.db[Config.RESUME_COLLECTION].find_one({
                '_id': ObjectId(resume_id),
                'user_id': session['user_id']
            })
            if not resume:
                logger.error(f"Resume {resume_id} not found in MongoDB")
                return jsonify({'error': 'Resume not found'}), 404
            logger.info(f"Successfully retrieved resume {resume_id} from MongoDB")
            resume_text = resume['text']
            r.set(f"resume:{resume_id}", resume_text)
            logger.info(f"Stored resume {resume_id} in Redis cache")
        else:
            logger.info(f"Retrieved resume {resume_id} from Redis cache")
            resume_text = resume_text.decode('utf-8')
        
        # Get analysis from Gemini
        analysis = get_gemini_response(resume_text, job_description)
        
        return jsonify(analysis)
        
    except Exception as e:
        logger.error(f"Error in analyze_job: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tailor', methods=['POST'])
@login_required
def tailor_resume_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        resume_id = data.get('resume_id')
        job_description = data.get('job_description')
        keywords = data.get('keywords', [])
        
        if not resume_id or not job_description:
            return jsonify({'error': 'Missing resume_id or job_description'}), 400
        
        # Try to get resume from Redis first
        resume_text = r.get(f"resume:{resume_id}")
        
        if resume_text is None:
            logger.info(f"Resume {resume_id} not found in Redis cache, fetching from MongoDB")
            # If not in Redis, get from MongoDB and store in Redis
            resume = mongo.db[Config.RESUME_COLLECTION].find_one({
                '_id': ObjectId(resume_id),
                'user_id': session['user_id']
            })
            if not resume:
                logger.error(f"Resume {resume_id} not found in MongoDB")
                return jsonify({'error': 'Resume not found'}), 404
            logger.info(f"Successfully retrieved resume {resume_id} from MongoDB")
            resume_text = resume['text']
            r.set(f"resume:{resume_id}", resume_text)
            logger.info(f"Stored resume {resume_id} in Redis cache")
        else:
            logger.info(f"Retrieved resume {resume_id} from Redis cache")
            resume_text = resume_text.decode('utf-8')
        
        # Get tailored points from Gemini
        result = tailor_resume_points(resume_text, job_description, keywords)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in tailor_resume_endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
