# LinkedIn Branding Assistant

A powerful web application that helps users optimize their LinkedIn profiles and job applications using AI-powered analysis.

## Quick Start
```bash
# Run the application
python app.py

# The application will be available at http://localhost:5000
```

## Features

### 1. Resume Analysis
- Upload and analyze resumes in PDF format
- Extract key information and skills
- Store resume data securely in MongoDB
- Cache resume data in Redis for faster access

### 2. Job Description Analysis
- Compare resumes against job descriptions
- Calculate job description match percentage
- Extract important keywords and requirements
- Generate tailored resume bullet points

### 3. LinkedIn Profile Assistant
- Convert resume into LinkedIn-style profile
- Generate professional summaries
- Extract and organize:
  - Work experience
  - Education
  - Projects
  - Certifications
  - Skills
  - Awards
- Generate AI-powered recommendations
- Calculate profile strength score

### 4. Job Search Integration
- Real-time job listings via AWS SQS
- Cache job data in Redis
- Filter and browse relevant positions
- Automated job matching

### 5. Security Features
- User authentication via AWS Cognito
- Secure file upload handling
- Protected API endpoints
- Session management

## Technology Stack

- **Backend**: Python Flask
- **Database**: MongoDB
- **Caching**: Redis
- **Cloud Services**: 
  - AWS Cognito (Authentication)
  - AWS SQS (Job Queue)
  - AWS Lambda
- **AI/ML**:
  - Google's Gemini AI
  - OpenAI GPT
- **Frontend**: HTML, CSS, JavaScript

## Setup Guide

1. **Clone the Repository**
```bash
git clone [repository-url]
cd LINKEDIN_BRANDING_ASSISTANT
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure Environment Variables**
Create a `config.py` file with the following configurations:
- MongoDB URI
- Redis connection details
- AWS Cognito credentials
- API keys (Google AI, OpenAI)
- Other configuration parameters

4. **Set Up MongoDB**
- Install MongoDB
- Create necessary collections
- Configure connection string in config.py

5. **Set Up Redis**
- Install Redis
- Configure connection parameters in config.py

6. **Configure AWS Services**
- Set up AWS Cognito User Pool
- Configure SQS Queue
- Set up necessary IAM roles and policies

7. **Run the Application**
```bash
python app.py

# The application will be available at http://localhost:5000
```

## API Endpoints

### Resume Management
- `POST /api/resume`: Upload resume
- `POST /api/analyze`: Analyze resume against job description
- `POST /api/tailor`: Generate tailored resume points

### Job Search
- `GET /api/jobs`: Fetch job listings

### LinkedIn Profile Assistant
- `POST /upload_resume_for_linkedIn_profile`: Generate LinkedIn profile

### Authentication
- `/login`: Initiate login
- `/auth/callback`: OAuth callback
- `/logout`: User logout

## Security Considerations

- All API endpoints are protected with login_required decorator
- File uploads are validated and sanitized
- Secure session management
- AWS Cognito integration for user authentication
- HTTPS enforcement in production





