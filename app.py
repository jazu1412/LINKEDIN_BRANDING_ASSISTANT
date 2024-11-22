from flask import Flask, render_template, request, jsonify
import google.generativeai as genai
import os
import PyPDF2 as pdf
from flask_pymongo import PyMongo
from bson import ObjectId
from datetime import datetime
import json
import re
from config import Config

app = Flask(__name__)
app.config['MONGO_URI'] = Config.MONGO_URI
mongo = PyMongo(app)

# Ensure database and collection exist
with app.app_context():
    # Create collection if it doesn't exist
    if Config.RESUME_COLLECTION not in mongo.db.list_collection_names():
        mongo.db.create_collection(Config.RESUME_COLLECTION)

genai.configure(api_key=Config.GOOGLE_API_KEY)

def clean_text(text):
    # Fix missing spaces between words (camelCase to spaces)
    text = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
    # Fix missing spaces between words (PascalCase to spaces)
    text = re.sub(r'([A-Z])([A-Z][a-z])', r'\1 \2', text)
    # Fix missing spaces after periods
    text = re.sub(r'\.([A-Z])', r'. \1', text)
    # Fix missing spaces after commas
    text = re.sub(r',([A-Za-z])', r', \1', text)
    # Fix missing spaces around pipe symbols
    text = re.sub(r'\|', ' | ', text)
    # Fix missing spaces around email symbols
    text = re.sub(r'([a-zA-Z])@', r'\1 @', text)
    # Remove extra whitespace
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
        print(f"JSON parsing error: {e}")
        print(f"Response text: {response_text}")
        raise Exception("Failed to parse Gemini API response")

def tailor_resume_points(resume_text, jd_text, keywords):
    prompt = (
        "You are an expert resume writer. Based on the provided resume and job description, "
        "generate 4 strong bullet points for experience or projects that incorporate the required keywords. "
        "Each bullet point should highlight relevant skills and achievements.\n\n"
        "Required JSON format (copy this structure exactly):\n"
        "{\n"
        '    "tailored_points": [\n'
        '        "Developed and deployed a high-performance API using Java and Spring Boot...",\n'
        '        "Implemented cloud-native solutions using AWS services...",\n'
        '        "Led the development of a data processing pipeline...",\n'
        '        "Optimized database queries and implemented caching..."\n'
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
    
    response = model.generate_content(
        prompt,
        generation_config=generation_config
    )
    
    response_text = response.text.strip()
    
    if response_text.startswith('```json'):
        response_text = response_text[7:-3].strip()
    
    try:
        parsed_json = json.loads(response_text)
        return parsed_json
    except Exception as e:
        print(f"JSON parsing error: {e}")
        print(f"Response text: {response_text}")
        raise Exception("Failed to parse Gemini API response")

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

@app.route('/analyze-form/<resume_id>')
def analyze_form(resume_id):
    return render_template('analyze.html', resume_id=resume_id)

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
        
        # Extract text from PDF
        resume_text = extract_text_from_pdf(resume_file)
        
        # Store in MongoDB
        result = mongo.db[Config.RESUME_COLLECTION].insert_one({
            'text': resume_text,
            'filename': resume_file.filename,
            'created_at': datetime.utcnow()
        })
        
        return jsonify({
            'resume_id': str(result.inserted_id),
            'message': 'Resume uploaded successfully'
        })
        
    except Exception as e:
        print(f"Error in upload_resume: {str(e)}")
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
        
        # Retrieve resume from MongoDB
        resume = mongo.db[Config.RESUME_COLLECTION].find_one({'_id': ObjectId(resume_id)})
        if not resume:
            return jsonify({'error': 'Resume not found'}), 404
        
        # Get analysis from Gemini
        analysis = get_gemini_response(resume['text'], job_description)
        
        return jsonify(analysis)
        
    except Exception as e:
        print(f"Error in analyze_job: {str(e)}")
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
        
        # Retrieve resume from MongoDB
        resume = mongo.db[Config.RESUME_COLLECTION].find_one({'_id': ObjectId(resume_id)})
        if not resume:
            return jsonify({'error': 'Resume not found'}), 404
        
        # Get tailored points from Gemini
        tailored_points = tailor_resume_points(resume['text'], job_description, keywords)
        
        return jsonify(tailored_points)
        
    except Exception as e:
        print(f"Error in tailor_resume_endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
