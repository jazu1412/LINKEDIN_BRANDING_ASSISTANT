from flask import Flask, render_template, request, jsonify
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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MONGO_URI'] = Config.MONGO_URI
mongo = PyMongo(app)

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


class SQSJobReader:
    def __init__(self):
        try:
            self.sqs = boto3.client('sqs')
            self.queue_url = "https://sqs.us-east-1.amazonaws.com/050451396927/JobListingQueue"
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
            #one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            

            one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)

           

            
            if 'Messages' in response:
                message_length = len(response['Messages'])  # Get the number of messages
                logger.info(f"Message length is {message_length}")
                message_counter = 0 
                for message in response['Messages']:
                    message_body = json.loads(message['Body'])
                    message_counter += 1  # Increment the counter for each message
                    logger.info(f"Processing new message #{message_counter}")
                    
                    # Check if message has timestamp and is within last hour
                    if 'timestamp' in message_body:
                        message_time = datetime.fromisoformat(message_body['timestamp'].replace('Z', '+00:00'))
                        if message_time > one_hour_ago:
                            jobs = message_body.get('jobs', [])
                            processed_jobs.extend(jobs)
                          
                           # Save to Redis with current hour as key
                            redis_key = self.get_current_hour_key()
                            jobs_redis.set(redis_key, json.dumps(jobs))
                           # Set expiry to 1 hour
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
    return render_template('upload.html')

@app.route('/jobs')
def jobs_page():
    return render_template('jobs.html')

@app.route('/analyze-form/<resume_id>')
def analyze_form(resume_id):
    return render_template('analyze.html', resume_id=resume_id)

@app.route('/api/jobs')
def get_jobs():
    try:
        # Try to get jobs from Redis first
        current_time = datetime.now(timezone.utc)
        redis_key = f"jobs:{current_time.strftime('%Y-%m-%d-%H')}"
      
        cached_jobs = jobs_redis.get(redis_key)
        if cached_jobs:
            logger.info(f"Retrieved jobs from Redis cache with key: {redis_key}")
            return jsonify(json.loads(cached_jobs))
      
        # If not in Redis, fetch from SQS
        logger.info("No cached jobs found in Redis, fetching from SQS")

        SQSJobReader
        reader = SQSJobReader()
        jobs = reader.read_jobs(max_messages=10)  # Get up to 10 jobs
        return jsonify(jobs)
    except Exception as e:
        logger.error(f"Error getting jobs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/resume', methods=['POST'])
def upload_resume():
    try:
        if 'resume' not in request.files:
            return jsonify({'error': 'No resume file uploaded'}), 400
        
        resume_file = request.files['resume']
        if resume_file.filename == '':
            return jsonify({'error': 'No resume file selected'}), 400
        
        if not allowed_file(resume_file.filename):
            return jsonify({'error': 'Please upload a PDF file'}), 400
        
        resume_text = extract_text_from_pdf(resume_file)
        
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

if __name__ == '__main__':
    app.run(debug=True)
