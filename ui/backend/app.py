from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import sys
import os
import jwt
import datetime
import bcrypt
import sqlite3
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

# Add the src directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from interview_assistant.interview_bot import InterviewBot
from interview_assistant.interview_chat_assistant import InterviewChatAssistant
from resume_customizer.resume_generator import ResumeGenerator
from config import RESUME_OUTPUT_DIR
from application_manager.automation_manager import AutomationManager
from application_manager.automated_application import AutomatedApplication

app = Flask(__name__)
CORS(app)

# Secret key for JWT
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key in production

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER', 'your-email@gmail.com')
app.config['FRONTEND_URL'] = 'http://localhost:3000'  # Change this to your frontend URL in production

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_verified BOOLEAN DEFAULT 0,
            verification_token TEXT,
            reset_token TEXT,
            reset_token_expiry TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            personal_info TEXT,
            experience TEXT,
            education TEXT,
            skills TEXT,
            languages TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Helper functions for email and tokens
def generate_token():
    """Generate a secure random token."""
    return secrets.token_urlsafe(32)

def send_email(to_email, subject, html_content):
    """Send an email using SMTP."""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to_email
        
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def send_verification_email(user_id, email, username, token):
    """Send a verification email to the user."""
    verification_url = f"{app.config['FRONTEND_URL']}/verify-email?token={token}"
    
    html_content = f"""
    <html>
        <body>
            <h2>Welcome to Job Application Assistant!</h2>
            <p>Hello {username},</p>
            <p>Thank you for registering. Please verify your email address by clicking the link below:</p>
            <p><a href="{verification_url}">Verify Email</a></p>
            <p>If you did not create an account, please ignore this email.</p>
            <p>Best regards,<br>Job Application Assistant Team</p>
        </body>
    </html>
    """
    
    return send_email(email, "Verify Your Email", html_content)

def send_password_reset_email(user_id, email, username, token):
    """Send a password reset email to the user."""
    reset_url = f"{app.config['FRONTEND_URL']}/reset-password?token={token}"
    
    html_content = f"""
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello {username},</p>
            <p>We received a request to reset your password. Click the link below to reset it:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you did not request a password reset, please ignore this email.</p>
            <p>Best regards,<br>Job Application Assistant Team</p>
        </body>
    </html>
    """
    
    return send_email(email, "Password Reset Request", html_content)

# Token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE id = ?', (data['user_id'],))
            current_user = c.fetchone()
            conn.close()
            
            if not current_user:
                return jsonify({'message': 'Invalid token!'}), 401
                
        except Exception as e:
            return jsonify({'message': 'Invalid token!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# Initialize components
interview_bot = InterviewBot()
interview_chat = InterviewChatAssistant()
resume_generator = ResumeGenerator()

# Initialize automation components
automation_manager = AutomationManager(test_mode=True)
application_manager = AutomatedApplication(test_mode=True)

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Hash password
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    
    # Generate verification token
    verification_token = generate_token()
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, email, password, verification_token, is_verified) VALUES (?, ?, ?, ?, ?)',
                 (data['username'], data['email'], hashed_password.decode('utf-8'), verification_token, False))
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        
        # Send verification email
        email_sent = send_verification_email(user_id, data['email'], data['username'], verification_token)
        
        # Create token
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, app.config['SECRET_KEY'])
        
        response = {
            'message': 'User registered successfully',
            'token': token,
            'user_id': user_id,
            'email_verification_sent': email_sent
        }
        
        if not email_sent:
            response['warning'] = 'Registration successful, but verification email could not be sent. Please contact support.'
        
        return jsonify(response), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username or email already exists'}), 409
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (data['email'],))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Check password
        if bcrypt.checkpw(data['password'].encode('utf-8'), user[3].encode('utf-8')):
            # Check if email is verified
            if not user[4]:  # is_verified
                return jsonify({
                    'message': 'Email not verified',
                    'email': user[2],
                    'needs_verification': True
                }), 403
            
            token = jwt.encode({
                'user_id': user[0],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
            }, app.config['SECRET_KEY'])
            
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'user_id': user[0],
                'username': user[1]
            }), 200
        else:
            return jsonify({'message': 'Invalid password'}), 401
            
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/auth/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id, username, email, created_at, is_verified FROM users WHERE id = ?', (current_user[0],))
        user = c.fetchone()
        
        c.execute('SELECT * FROM user_profiles WHERE user_id = ?', (current_user[0],))
        profile = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        user_data = {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'created_at': user[3],
            'is_verified': user[4]
        }
        
        if profile:
            user_data['profile'] = {
                'personal_info': profile[2],
                'experience': profile[3],
                'education': profile[4],
                'skills': profile[5],
                'languages': profile[6]
            }
        
        return jsonify(user_data), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/auth/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    data = request.get_json()
    
    if not data:
        return jsonify({'message': 'No data provided'}), 400
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Check if profile exists
        c.execute('SELECT * FROM user_profiles WHERE user_id = ?', (current_user[0],))
        profile = c.fetchone()
        
        if profile:
            # Update existing profile
            c.execute('''
                UPDATE user_profiles 
                SET personal_info = ?, experience = ?, education = ?, skills = ?, languages = ?
                WHERE user_id = ?
            ''', (
                data.get('personal_info', profile[2]),
                data.get('experience', profile[3]),
                data.get('education', profile[4]),
                data.get('skills', profile[5]),
                data.get('languages', profile[6]),
                current_user[0]
            ))
        else:
            # Create new profile
            c.execute('''
                INSERT INTO user_profiles (user_id, personal_info, experience, education, skills, languages)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                current_user[0],
                data.get('personal_info', '{}'),
                data.get('experience', '[]'),
                data.get('education', '[]'),
                data.get('skills', '[]'),
                data.get('languages', '[]')
            ))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Profile updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/interview/prepare', methods=['POST'])
def prepare_interview():
    try:
        data = request.json
        job_description = data.get('jobDescription')
        
        if not job_description:
            return jsonify({'error': 'Job description is required'}), 400
            
        # Generate interview preparation materials
        prep_materials = interview_bot.generate_interview_prep(job_description)
        return jsonify(prep_materials)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/interview/question', methods=['POST'])
def get_interview_question():
    try:
        data = request.json
        job_description = data.get('jobDescription')
        previous_questions = data.get('previousQuestions', [])
        
        if not job_description:
            return jsonify({'error': 'Job description is required'}), 400
            
        # Get next interview question
        question = interview_bot.get_next_question(job_description, previous_questions)
        return jsonify({'question': question})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/interview/evaluate', methods=['POST'])
def evaluate_answer():
    try:
        data = request.json
        job_description = data.get('jobDescription')
        question = data.get('question')
        answer = data.get('answer')
        
        if not all([job_description, question, answer]):
            return jsonify({'error': 'Job description, question, and answer are required'}), 400
            
        # Evaluate the answer
        evaluation = interview_bot.evaluate_answer(job_description, question, answer)
        return jsonify({'evaluation': evaluation})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# New endpoints for the interview chat assistant
@app.route('/api/interview/chat/start', methods=['POST'])
def start_interview_chat():
    try:
        data = request.json
        job_description = data.get('jobDescription')
        interview_type = data.get('interviewType', 'general')
        
        if not job_description:
            return jsonify({'error': 'Job description is required'}), 400
            
        # Start a new chat session
        chat_response = interview_chat.start_chat(job_description, interview_type)
        return jsonify(chat_response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/interview/chat/message', methods=['POST'])
def send_chat_message():
    try:
        data = request.json
        message = data.get('message')
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
            
        # Send message to chat assistant
        response = interview_chat.send_message(message)
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/interview/chat/questions', methods=['GET'])
def get_question_suggestions():
    try:
        topic = request.args.get('topic')
        
        # Get question suggestions
        questions = interview_chat.get_question_suggestions(topic)
        return jsonify({'questions': questions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/interview/chat/feedback', methods=['POST'])
def get_answer_feedback():
    try:
        data = request.json
        question = data.get('question')
        answer = data.get('answer')
        
        if not all([question, answer]):
            return jsonify({'error': 'Question and answer are required'}), 400
            
        # Get feedback on the answer
        feedback = interview_chat.get_answer_feedback(question, answer)
        return jsonify(feedback)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/interview/chat/tips', methods=['GET'])
def get_interview_tips():
    try:
        interview_type = request.args.get('type', 'general')
        
        # Get interview tips
        tips = interview_chat.get_interview_tips(interview_type)
        return jsonify(tips)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/interview/chat/save', methods=['POST'])
def save_chat_conversation():
    try:
        data = request.json
        filename = data.get('filename')
        
        # Save conversation
        filepath = interview_chat.save_conversation(filename)
        return jsonify({'filepath': filepath})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/resume/customize', methods=['POST'])
def customize_resume():
    try:
        data = request.json
        job_description = data.get('jobDescription')
        resume_template = data.get('resumeTemplate')
        
        if not all([job_description, resume_template]):
            return jsonify({'error': 'Job description and resume template are required'}), 400
            
        # Generate customized resume
        output_path = os.path.join(RESUME_OUTPUT_DIR, 'customized_resume.docx')
        customized_resume = resume_generator.process_job_application(
            job_description,
            resume_template,
            output_path
        )
        
        return jsonify({
            'message': 'Resume customized successfully',
            'path': output_path
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/resume/generate', methods=['POST'])
def generate_resume():
    """Generate a customized resume based on job description and user profile."""
    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
            
        job_description = data.get('jobDescription')
        user_profile = data.get('userProfile')
        template = data.get('template', 'modern')
        
        if not job_description or not user_profile:
            return jsonify({"success": False, "error": "Job description and user profile are required"}), 400
            
        # Generate customized resume
        output_path = resume_generator.process_job_application(
            job_description=job_description,
            resume_template=template,
            user_profile=user_profile
        )
        
        return jsonify({
            "success": True,
            "message": "Resume generated successfully",
            "file_path": output_path
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/resume/templates', methods=['GET'])
def get_resume_templates():
    """Get available resume templates."""
    try:
        templates = resume_generator.get_available_templates()
        return jsonify({
            "success": True,
            "templates": templates
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/automation/start', methods=['POST'])
def start_automation():
    """Start the automation scheduler."""
    try:
        automation_manager.start_automation()
        return jsonify({"success": True, "message": "Automation scheduler started"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/automation/stop', methods=['POST'])
def stop_automation():
    """Stop the automation scheduler."""
    try:
        automation_manager.stop_automation()
        return jsonify({"success": True, "message": "Automation scheduler stopped"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/automation/settings', methods=['GET'])
def get_automation_settings():
    """Get current automation settings."""
    try:
        return jsonify({
            "success": True,
            "settings": automation_manager.settings
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/automation/settings', methods=['POST'])
def update_automation_settings():
    """Update automation settings."""
    try:
        new_settings = request.json
        if not new_settings:
            return jsonify({"success": False, "error": "No settings provided"}), 400
            
        automation_manager.update_settings(new_settings)
        return jsonify({
            "success": True,
            "message": "Settings updated",
            "settings": automation_manager.settings
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/applications', methods=['POST'])
def add_application():
    """Add a new job application."""
    try:
        application_data = request.json
        if not application_data:
            return jsonify({"success": False, "error": "No application data provided"}), 400
            
        application_id = application_manager.add_application(application_data)
        return jsonify({
            "success": True,
            "message": "Application added",
            "application_id": application_id
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/applications/<application_id>/status', methods=['PUT'])
def update_application_status(application_id):
    """Update the status of a job application."""
    try:
        data = request.json
        if not data or "status" not in data:
            return jsonify({"success": False, "error": "No status provided"}), 400
            
        updated_app = application_manager.update_application_status(
            application_id=application_id,
            new_status=data["status"],
            notes=data.get("notes")
        )
        return jsonify({
            "success": True,
            "message": "Status updated",
            "application": updated_app
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/applications/<application_id>/interview', methods=['POST'])
def add_interview(application_id):
    """Add an interview to a job application."""
    try:
        interview_data = request.json
        if not interview_data:
            return jsonify({"success": False, "error": "No interview data provided"}), 400
            
        updated_app = application_manager.add_interview(application_id, interview_data)
        return jsonify({
            "success": True,
            "message": "Interview added",
            "application": updated_app
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/applications', methods=['GET'])
def get_applications():
    """Get all job applications or a specific one."""
    try:
        application_id = request.args.get("id")
        applications = application_manager.get_application_status(application_id)
        return jsonify({
            "success": True,
            "applications": applications
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/applications/followup', methods=['GET'])
def get_applications_needing_followup():
    """Get applications that need follow-up."""
    try:
        days_threshold = request.args.get("days", default=7, type=int)
        applications = application_manager.get_applications_needing_followup(days_threshold)
        return jsonify({
            "success": True,
            "applications": applications
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/applications/interviews/upcoming', methods=['GET'])
def get_upcoming_interviews():
    """Get all upcoming interviews."""
    try:
        interviews = application_manager.get_upcoming_interviews()
        return jsonify({
            "success": True,
            "interviews": interviews
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/linkedin/connect', methods=['POST'])
def connect_with_recruiter():
    """Connect with a recruiter on LinkedIn."""
    try:
        data = request.json
        if not data or "recruiter_id" not in data or "job_description" not in data:
            return jsonify({"success": False, "error": "Missing required fields"}), 400
            
        result = automation_manager.connect_with_recruiter(
            recruiter_id=data["recruiter_id"],
            job_description=data["job_description"],
            message=data.get("message")
        )
        return jsonify({
            "success": True,
            "message": "Connection request sent",
            "result": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/email/followup', methods=['POST'])
def send_followup_email():
    """Send a follow-up email for a job application."""
    try:
        data = request.json
        if not data or "recipient_email" not in data or "application_id" not in data:
            return jsonify({"success": False, "error": "Missing required fields"}), 400
            
        result = automation_manager.send_followup_email(
            recipient_email=data["recipient_email"],
            application_id=data["application_id"],
            days_since_last_contact=data.get("days_since_last_contact", 7),
            job_description=data.get("job_description")
        )
        return jsonify({
            "success": True,
            "message": "Follow-up email sent",
            "result": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/email/interview-followup', methods=['POST'])
def send_interview_followup():
    """Send a follow-up email after an interview."""
    try:
        data = request.json
        if not data or "recipient_email" not in data or "interview_details" not in data:
            return jsonify({"success": False, "error": "Missing required fields"}), 400
            
        result = automation_manager.send_interview_followup(
            recipient_email=data["recipient_email"],
            interview_details=data["interview_details"]
        )
        return jsonify({
            "success": True,
            "message": "Interview follow-up email sent",
            "result": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/resume/download', methods=['GET'])
def download_resume():
    """Download a generated resume file."""
    try:
        file_path = request.args.get('path')
        if not file_path:
            return jsonify({"success": False, "error": "No file path provided"}), 400
            
        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify({"success": False, "error": "File not found"}), 404
            
        # Get file name from path
        file_name = os.path.basename(file_path)
        
        # Return file as download
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file_name
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/auth/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    
    if not token:
        return jsonify({'message': 'Verification token is missing'}), 400
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Find user with this verification token
        c.execute('SELECT id, username, email FROM users WHERE verification_token = ? AND is_verified = 0', (token,))
        user = c.fetchone()
        
        if not user:
            return jsonify({'message': 'Invalid or expired verification token'}), 400
        
        # Update user as verified
        c.execute('UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?', (user[0],))
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Email verified successfully',
            'username': user[1],
            'email': user[2]
        }), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/auth/resend-verification', methods=['POST'])
def resend_verification():
    data = request.get_json()
    
    if not data or not data.get('email'):
        return jsonify({'message': 'Email is required'}), 400
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Find user by email
        c.execute('SELECT id, username, email, is_verified FROM users WHERE email = ?', (data['email'],))
        user = c.fetchone()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if user[3]:  # is_verified
            return jsonify({'message': 'Email is already verified'}), 400
        
        # Generate new verification token
        verification_token = generate_token()
        
        # Update verification token
        c.execute('UPDATE users SET verification_token = ? WHERE id = ?', (verification_token, user[0]))
        conn.commit()
        conn.close()
        
        # Send verification email
        email_sent = send_verification_email(user[0], user[2], user[1], verification_token)
        
        if email_sent:
            return jsonify({'message': 'Verification email sent successfully'}), 200
        else:
            return jsonify({'message': 'Failed to send verification email'}), 500
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    
    if not data or not data.get('email'):
        return jsonify({'message': 'Email is required'}), 400
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Find user by email
        c.execute('SELECT id, username, email FROM users WHERE email = ?', (data['email'],))
        user = c.fetchone()
        
        if not user:
            # Return success even if user doesn't exist for security
            return jsonify({'message': 'If your email is registered, you will receive a password reset link'}), 200
        
        # Generate reset token
        reset_token = generate_token()
        reset_token_expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        
        # Update reset token
        c.execute('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?', 
                 (reset_token, reset_token_expiry, user[0]))
        conn.commit()
        conn.close()
        
        # Send password reset email
        email_sent = send_password_reset_email(user[0], user[2], user[1], reset_token)
        
        if email_sent:
            return jsonify({'message': 'Password reset email sent successfully'}), 200
        else:
            return jsonify({'message': 'Failed to send password reset email'}), 500
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    
    if not data or not data.get('token') or not data.get('password'):
        return jsonify({'message': 'Token and new password are required'}), 400
    
    token = data['token']
    new_password = data['password']
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Find user with this reset token
        c.execute('SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > ?', 
                 (token, datetime.datetime.utcnow()))
        user = c.fetchone()
        
        if not user:
            return jsonify({'message': 'Invalid or expired reset token'}), 400
        
        # Hash new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update password and clear reset token
        c.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?', 
                 (hashed_password.decode('utf-8'), user[0]))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001) 