from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import google.generativeai as genai
import os

import PyPDF2 as pdf
from flask_pymongo import PyMongo
from bson import ObjectId
from datetime import datetime, timedelta
import json
import re
from config import Config
import redis
import logging
import boto3
from typing import List, Dict
from datetime import timezone
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
import openai
from werkzeug.utils import secure_filename
import PyPDF2
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.secret_key = os.urandom(24)  # Use a secure random key in production
app.config['MONGO_URI'] = Config.MONGO_URI
mongo = PyMongo(app)
oauth = OAuth(app)

oauth.register(
    name='oidc',
    authority=Config.COGNITO_AUTHORITY,
    client_id=Config.COGNITO_CLIENT_ID,
    client_secret=Config.COGNITO_CLIENT_SECRET,
    server_metadata_url=f"{Config.COGNITO_AUTHORITY}/.well-known/openid-configuration",
    client_kwargs={'scope': ' '.join(Config.COGNITO_SCOPES)}
)

# Redis connection using config
r = redis.Redis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    password=Config.REDIS_PASSWORD
)

# Redis connection for job data
jobs_redis = redis.Redis(
   host=Config.REDIS_HOST_2,
   port=Config.REDIS_PORT_2,
   password=Config.REDIS_PASSWORD_2
)

# LinkedIn Profile Assistant Configs
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

# Configure OpenAI API key from Config
openai.api_key = Config.OPENAI_API_KEY
ALLOWED_EXTENSIONS = Config.ALLOWED_EXTENSIONS

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

class SQSJobReader:
    def __init__(self):
        try:
            self.sqs = boto3.client('sqs', region_name=Config.AWS_REGION)
            self.queue_url = Config.SQS_QUEUE_URL
            logger.info("Successfully connected to AWS SQS")
        except Exception as e:
            logger.error(f"Error initializing AWS client: {str(e)}")
            return
        
    def get_current_hour_key(self):
       current_time = datetime.now(timezone.utc)
       return f"jobs:{current_time.strftime('%Y-%m-%d-%H')}"    

    def read_jobs(self, max_messages: int = 10) -> List[Dict]:
        if not hasattr(self, 'sqs'):
            logger.error("AWS client not initialized. Please check your credentials.")
            return []

        try:
            response = self.sqs.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=max_messages,
                WaitTimeSeconds=5,
                AttributeNames=['All'],
                MessageAttributeNames=['All']
            )
            
            processed_jobs = []
            one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)

            if 'Messages' in response:
                message_length = len(response['Messages'])
                logger.info(f"Message length is {message_length}")
                message_counter = 0 
                for message in response['Messages']:
                    message_body = json.loads(message['Body'])
                    message_counter += 1
                    logger.info(f"Processing new message #{message_counter}")
                    
                    if 'timestamp' in message_body:
                        message_time = datetime.fromisoformat(message_body['timestamp'].replace('Z', '+00:00'))
                        if message_time > one_hour_ago:
                            jobs = message_body.get('jobs', [])
                            processed_jobs.extend(jobs)
                          
                            redis_key = self.get_current_hour_key()
                            jobs_redis.set(redis_key, json.dumps(jobs))
                            jobs_redis.expire(redis_key, 3600)
                          
                            logger.info(f"Saved {len(jobs)} jobs to Redis with key: {redis_key}")
                            jobs = message_body.get('jobs', [])
                            processed_jobs.extend(jobs)
                            logger.info(f"Processing message with timestamp: {message_time}")
                        else:
                            logger.info(f"Skipping old message from: {message_time}")
                    else:
                        logger.warning("Message missing timestamp")
            
            return processed_jobs
            
        except Exception as e:
            logger.error(f"Error reading from SQS: {str(e)}")
            return []

# Ensure database and collection exist
with app.app_context():
    if Config.RESUME_COLLECTION not in mongo.db.list_collection_names():
        mongo.db.create_collection(Config.RESUME_COLLECTION)
        logger.info(f"Created MongoDB collection: {Config.RESUME_COLLECTION}")

genai.configure(api_key=Config.GOOGLE_API_KEY)

def clean_text(text):
    text = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
    text = re.sub(r'([A-Z])([A-Z][a-z])', r'\1 \2', text)
    text = re.sub(r'\.([A-Z])', r'. \1', text)
    text = re.sub(r',([A-Za-z])', r', \1', text)
    text = re.sub(r'\|', ' | ', text)
    text = re.sub(r'([a-zA-Z])@', r'\1 @', text)
    text = ' '.join(text.split())
    return text

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
        logger.error(f"JSON parsing error: {e}")
        logger.error(f"Response text: {response_text}")
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
        
        response_text = re.sub(r'"\s+(?=")', '", ', response_text)
        response_text = re.sub(r'"\s+(?="\w+":)', '", ', response_text)
        
        parsed_json = json.loads(response_text)
        
        if not isinstance(parsed_json, dict) or 'tailored_points' not in parsed_json:
            raise ValueError("Invalid response format")
        
        if not isinstance(parsed_json['tailored_points'], list):
            raise ValueError("tailored_points must be an array")
        
        return {
            'tailored_points': parsed_json['tailored_points'][:4]
        }
        
    except Exception as e:
        logger.error(f"Error in tailor_resume_points: {str(e)}")
        logger.error(f"Response text: {response_text if 'response_text' in locals() else 'No response text'}")
        return {
            'tailored_points': [
                "Developed and implemented software solutions utilizing required programming languages and frameworks",
                "Led technical projects and collaborated with cross-functional teams to deliver high-quality results",
                "Optimized system performance and implemented best practices in software development",
                "Contributed to the design and development of scalable applications and features"
            ]
        }

def extract_text_from_pdf(pdf_file):
    reader = pdf.PdfReader(pdf_file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"
    return clean_text(text)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@app.route('/')
def index():
    user = session.get('user')
    if user:
        return render_template('index.html', user=user)
    return render_template('index.html')

@app.route('/login')
def login():
    return oauth.oidc.authorize_redirect(
        redirect_uri=Config.COGNITO_REDIRECT_URL,
        response_type='code'
    )

@app.route('/auth/callback')
def auth_callback():
    try:
        token = oauth.oidc.authorize_access_token()
        logger.info(f"Token received: {token}")
        user_info = token.get('userinfo')
        
        if user_info:
            session['user'] = user_info
            logger.info(f"User successfully authenticated: {user_info.get('email')}")
            return redirect(url_for('index'))
        else:
            logger.error("No user info in token response")
            return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Error in auth callback: {str(e)}")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)  # Clear the user's session locally

    # Redirect to Cognito's logout endpoint
    cognito_logout_url = (
        f"{Config.COGNITO_DOMAIN}/logout?"
        f"client_id={Config.COGNITO_CLIENT_ID}&"
        f"logout_uri={Config.COGNITO_LOGOUT_URL}"
    )
    return redirect(cognito_logout_url)

@app.route('/upload')
@login_required
def upload():
    return render_template('upload.html')

@app.route('/jobs')
@login_required
def jobs_page():
    return render_template('jobs.html')

@app.route('/analyze-form/<resume_id>')
@login_required
def analyze_form(resume_id):
    return render_template('analyze.html', resume_id=resume_id)

@app.route('/linkedInProfileAssistant')
@login_required
def linkedInProfileAssistant():
    return render_template('linkedInProfileAssistant.html')

@app.route('/api/jobs')
@login_required
def get_jobs():
    try:
        current_time = datetime.now(timezone.utc)
        redis_key = f"jobs:{current_time.strftime('%Y-%m-%d-%H')}"
      
        cached_jobs = jobs_redis.get(redis_key)
        if cached_jobs:
            logger.info(f"Retrieved jobs from Redis cache with key: {redis_key}")
            return jsonify(json.loads(cached_jobs))
        
        logger.info("No cached jobs found in Redis, fetching from SQS")
     
        api_endpoint = "https://bfgw1302eb.execute-api.us-east-1.amazonaws.com/default/JobSearchAndSendToSQS"
        
        try:
            response = requests.get(api_endpoint)
            if response.status_code == 200:
                logger.info("Successfully triggered the Lambda to send jobs to SQS")
            else:
                logger.error(f"Failed to trigger the Lambda. Status code: {response.status_code}, Response: {response.text}")
        except Exception as e:
            logger.error(f"Error while calling the API Gateway endpoint: {str(e)}")

        reader = SQSJobReader()
        jobs = reader.read_jobs(max_messages=10)
        return jsonify(jobs)
    except Exception as e:
        logger.error(f"Error getting jobs: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
        
        resume_text = extract_text_from_pdf_jazu(resume_file)
        
        logger.info(f"Storing resume in MongoDB: {resume_file.filename}")
        result = mongo.db[Config.RESUME_COLLECTION].insert_one({
            'text': resume_text,
            'filename': resume_file.filename,
            'created_at': datetime.utcnow()
        })
        resume_id = str(result.inserted_id)
        logger.info(f"Successfully stored resume in MongoDB with ID: {resume_id}")
        
        r.set(f"resume:{resume_id}", resume_text)
        logger.info(f"Stored resume {resume_id} in Redis cache")
        
        return jsonify({
            'resume_id': resume_id,
            'message': 'Resume uploaded successfully'
        })
        
    except Exception as e:
        logger.error(f"Error in upload_resume: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
        
        resume_text = r.get(f"resume:{resume_id}")
        
        if resume_text is None:
            logger.info(f"Resume {resume_id} not found in Redis cache, fetching from MongoDB")
            resume = mongo.db[Config.RESUME_COLLECTION].find_one({'_id': ObjectId(resume_id)})
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
        
        resume_text = r.get(f"resume:{resume_id}")
        
        if resume_text is None:
            logger.info(f"Resume {resume_id} not found in Redis cache, fetching from MongoDB")
            resume = mongo.db[Config.RESUME_COLLECTION].find_one({'_id': ObjectId(resume_id)})
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
        
        result = tailor_resume_points(resume_text, job_description, keywords)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in tailor_resume_endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf_jazu(pdf_file):
    reader = pdf.PdfReader(pdf_file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"
    return clean_text(text)

def extract_text_from_pdf(pdf_path):
    text = ""
    try:
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
    except Exception as e:
        print(f"Error extracting text from PDF: {str(e)}")
        return None
    return text

def analyze_resume_with_gpt(resume_text):
    prompt = f"""
    Analyze the following resume and create a detailed LinkedIn-style profile. Extract ALL experiences, certifications, and other details from the resume.
    Provide a JSON response with the following structure. Each section should include ALL relevant items found in the resume:
    
    {{
        "name": "Full name of the person",
        "headline": "Professional headline/current role",
        "location": "City, Country",
        "about": "Detailed professional summary",
        "experience": [
            {{
                "title": "Job title",
                "company": "Company name",
                "duration": "Employment period",
                "description": "Detailed job responsibilities and achievements"
            }},
            // Include ALL work experiences found in the resume
        ],
        "education": [
            {{
                "degree": "Degree name",
                "school": "Institution name",
                "duration": "Study period",
                "description": "Additional details about the education"
            }},
            // Include ALL educational qualifications
        ],
        "projects": [
            {{
                "name": "Project name",
                "description": "Detailed project description",
                "technologies": "All technologies used",
                "duration": "Project period"
            }},
            // Include ALL projects mentioned
        ],
        "certifications": [
            {{
                "name": "Certification name",
                "issuer": "Issuing organization",
                "date": "Issue date",
                "description": "Additional details about the certification"
            }},
            // Include ALL certifications found
        ],
        "skills": [
            // List ALL technical and professional skills mentioned
        ],
        "awards": [
            {{
                "name": "Award name",
                "issuer": "Issuing organization",
                "date": "Date received",
                "description": "Detailed award description"
            }},
            // Include ALL awards and honors
        ],
        "recommendations": [
            {{
                "text": "Detailed AI-generated recommendation based on experience",
                "recommender": "Generated recommender name and title"
            }},
            // Generate 2-3 meaningful recommendations
        ]
    }}

    Important:
    1. Include ALL experiences, certifications, and other items found in the resume
    2. Don't limit the number of items in any section
    3. Provide detailed descriptions for each item
    4. Ensure all dates and durations are properly formatted
    5. Extract as much detail as possible from the resume

    Resume content:
    {resume_text}
    """

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system", 
                    "content": "You are a professional resume analyzer that creates detailed LinkedIn profiles. Always respond with valid JSON matching the specified structure. Include ALL experiences, certifications, and other items found in the resume. Don't limit the number of items in any section."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=3000  # Increased token limit to handle more content
        )
        
        # Get the response content
        content = response.choices[0].message['content']
        
        # Ensure the response is valid JSON
        try:
            # Try to parse it as JSON
            json_data = json.loads(content)
            
            # Ensure all sections are arrays even if empty
            array_sections = ['experience', 'education', 'projects', 'certifications', 'skills', 'awards', 'recommendations']
            for section in array_sections:
                if section not in json_data:
                    json_data[section] = []
                elif not isinstance(json_data[section], list):
                    json_data[section] = [json_data[section]]
            
            return json_data
            
        except json.JSONDecodeError:
            # If it's not valid JSON, try to extract JSON portion
            start_idx = content.find('{')
            end_idx = content.rfind('}') + 1
            if start_idx != -1 and end_idx != 0:
                json_str = content[start_idx:end_idx]
                json_data = json.loads(json_str)
                
                # Ensure all sections are arrays even if empty
                array_sections = ['experience', 'education', 'projects', 'certifications', 'skills', 'awards', 'recommendations']
                for section in array_sections:
                    if section not in json_data:
                        json_data[section] = []
                    elif not isinstance(json_data[section], list):
                        json_data[section] = [json_data[section]]
                
                return json_data
            return None
            
    except Exception as e:
        print(f"Error in GPT analysis: {str(e)}")
        return None

# api for linkedIn profile Assistant
@app.route('/upload_resume_for_linkedIn_profile', methods=['POST'])
def upload_resume_for_linkedIn_profile():
    if 'resume' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['resume']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        try:
            # Save the uploaded file
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Extract text based on file type
            if filename.endswith('.pdf'):
                resume_text = extract_text_from_pdf(filepath)
            else:  # txt file
                with open(filepath, 'r', encoding='utf-8') as f:
                    resume_text = f.read()
            
            if not resume_text:
                return jsonify({'error': 'Could not extract text from file'}), 400
            
            # Get GPT analysis
            profile_data = analyze_resume_with_gpt(resume_text)
            
            if not profile_data:
                return jsonify({'error': 'Could not analyze resume'}), 500
            
            # Clean up the uploaded file
            os.remove(filepath)
            
            # Add default profile picture URL here
            profile_data['profile_picture'] = "https://via.placeholder.com/150"
            
            # Calculate profile strength based on section completeness
            sections = ['about', 'experience', 'education', 'projects', 'certifications', 'skills', 'awards', 'recommendations']
            section_weights = {
                'about': 15,
                'experience': 25,
                'education': 15,
                'skills': 15,
                'projects': 10,
                'certifications': 10,
                'awards': 5,
                'recommendations': 5
            }
            
            total_weight = 0
            for section, weight in section_weights.items():
                if section in profile_data:
                    if isinstance(profile_data[section], list):
                        if len(profile_data[section]) > 0:
                            total_weight += weight
                    elif profile_data[section]:  # For non-list sections like 'about'
                        total_weight += weight
            
            profile_data['profile_strength'] = total_weight
            
            return jsonify(profile_data)
            
        except Exception as e:
            # Clean up file if it exists
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': str(e)}), 500
            
    return jsonify({'error': 'Invalid file type. Please upload a PDF or TXT file.'}), 400

if __name__ == '__main__':
     app.run(host='::', port=5000, debug=True)
