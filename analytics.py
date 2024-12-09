import sqlite3
from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify
import os
import logging

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

analytics_bp = Blueprint('analytics', __name__)

def get_db():
    """Get database connection with debug logging"""
    try:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'analytics.db')
        logger.debug(f"Connecting to database at: {db_path}")
        conn = sqlite3.connect(db_path, timeout=20)
        conn.row_factory = sqlite3.Row
        logger.debug("Database connection successful")
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to database: {str(e)}")
        raise

def init_db():
    """Initialize database with debug logging"""
    try:
        logger.info("Starting database initialization")
        conn = get_db()
        c = conn.cursor()
        
        # Create tables only if they don't exist
        c.executescript('''
            CREATE TABLE IF NOT EXISTS user_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS resume_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS linkedin_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS feature_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                feature_name TEXT NOT NULL,
                access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_user_logins_time ON user_logins(login_time);
            CREATE INDEX IF NOT EXISTS idx_resume_analysis_time ON resume_analysis(analysis_time);
            CREATE INDEX IF NOT EXISTS idx_linkedin_analysis_time ON linkedin_analysis(analysis_time);
            CREATE INDEX IF NOT EXISTS idx_feature_usage_time ON feature_usage(access_time);
            CREATE INDEX IF NOT EXISTS idx_feature_usage_name ON feature_usage(feature_name);
        ''')
        
        conn.commit()
        logger.info("Database initialized successfully")
        
        # Verify tables were created
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = c.fetchall()
        logger.info(f"Existing tables: {[table[0] for table in tables]}")
        
        conn.close()
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

# Initialize database on import
init_db()

def track_login(user_id):
    """Track user login with debug logging"""
    try:
        logger.debug(f"Tracking login for user: {user_id}")
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO user_logins (user_id) VALUES (?)', (user_id,))
        conn.commit()
        
        # Verify the insert
        c.execute('SELECT COUNT(*) FROM user_logins WHERE user_id = ?', (user_id,))
        count = c.fetchone()[0]
        logger.info(f"Successfully tracked login for user: {user_id}. Total logins for user: {count}")
        
        conn.close()
    except Exception as e:
        logger.error(f"Failed to track login for user {user_id}: {str(e)}")

def track_resume_analysis(user_id):
    """Track resume analysis with debug logging"""
    try:
        logger.debug(f"Tracking resume analysis for user: {user_id}")
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO resume_analysis (user_id) VALUES (?)', (user_id,))
        conn.commit()
        
        # Verify the insert
        c.execute('SELECT COUNT(*) FROM resume_analysis WHERE user_id = ?', (user_id,))
        count = c.fetchone()[0]
        logger.info(f"Successfully tracked resume analysis for user: {user_id}. Total analyses: {count}")
        
        conn.close()
    except Exception as e:
        logger.error(f"Failed to track resume analysis for user {user_id}: {str(e)}")

def track_linkedin_analysis(user_id):
    """Track LinkedIn analysis with debug logging"""
    try:
        logger.debug(f"Tracking LinkedIn analysis for user: {user_id}")
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO linkedin_analysis (user_id) VALUES (?)', (user_id,))
        conn.commit()
        
        # Verify the insert
        c.execute('SELECT COUNT(*) FROM linkedin_analysis WHERE user_id = ?', (user_id,))
        count = c.fetchone()[0]
        logger.info(f"Successfully tracked LinkedIn analysis for user: {user_id}. Total analyses: {count}")
        
        conn.close()
    except Exception as e:
        logger.error(f"Failed to track LinkedIn analysis for user {user_id}: {str(e)}")

def track_feature_usage(user_id, feature_name, session_id=None, device_info=None, status='success'):
    """Track feature usage with debug logging"""
    try:
        logger.debug(f"Tracking feature usage: {feature_name} for user: {user_id}")
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO feature_usage 
            (user_id, feature_name) 
            VALUES (?, ?)
        ''', (user_id, feature_name))
        conn.commit()
        
        # Verify the insert
        c.execute('SELECT COUNT(*) FROM feature_usage WHERE user_id = ? AND feature_name = ?', 
                 (user_id, feature_name))
        count = c.fetchone()[0]
        logger.info(f"Successfully tracked feature usage: {feature_name} for user: {user_id}. "
                   f"Total usage of this feature: {count}")
        
        conn.close()
    except Exception as e:
        logger.error(f"Failed to track feature usage for user {user_id}: {str(e)}")

@analytics_bp.route('/dashboard')
def dashboard():
    """Render analytics dashboard"""
    return render_template('dashboard.html')

@analytics_bp.route('/api/metrics')
def get_metrics():
    """Get analytics metrics with debug logging"""
    try:
        logger.debug("Fetching analytics metrics")
        conn = get_db()
        c = conn.cursor()
        
        # Get total users
        c.execute('''
            SELECT COUNT(DISTINCT user_id) as total_users 
            FROM (
                SELECT user_id FROM user_logins
                UNION
                SELECT user_id FROM resume_analysis
                UNION
                SELECT user_id FROM linkedin_analysis
                UNION
                SELECT user_id FROM feature_usage
            )
        ''')
        total_users = c.fetchone()[0]
        logger.debug(f"Total unique users: {total_users}")
        
        # Get total logins
        c.execute('SELECT COUNT(*) FROM user_logins')
        total_logins = c.fetchone()[0]
        logger.debug(f"Total logins: {total_logins}")
        
        # Get resume analysis count
        c.execute('SELECT COUNT(*) FROM resume_analysis')
        resume_analysis_count = c.fetchone()[0]
        logger.debug(f"Total resume analyses: {resume_analysis_count}")
        
        # Get linkedin analysis count
        c.execute('SELECT COUNT(*) FROM linkedin_analysis')
        linkedin_analysis_count = c.fetchone()[0]
        logger.debug(f"Total LinkedIn analyses: {linkedin_analysis_count}")
        
        # Get feature usage statistics
        c.execute('''
            SELECT 
                feature_name,
                COUNT(*) as usage_count
            FROM feature_usage
            GROUP BY feature_name
            ORDER BY usage_count DESC
        ''')
        feature_usage = [dict(row) for row in c.fetchall()]
        logger.debug(f"Feature usage stats: {feature_usage}")
        
        # Get daily metrics for the past 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        
        c.execute('''
            SELECT 
                date(login_time) as date,
                COUNT(*) as count
            FROM user_logins
            WHERE date(login_time) >= ?
            GROUP BY date(login_time)
            ORDER BY date
        ''', (thirty_days_ago,))
        daily_logins = [dict(row) for row in c.fetchall()]
        
        c.execute('''
            SELECT 
                date(analysis_time) as date,
                COUNT(*) as count
            FROM resume_analysis
            WHERE date(analysis_time) >= ?
            GROUP BY date(analysis_time)
            ORDER BY date
        ''', (thirty_days_ago,))
        daily_resume_analysis = [dict(row) for row in c.fetchall()]
        
        c.execute('''
            SELECT 
                date(analysis_time) as date,
                COUNT(*) as count
            FROM linkedin_analysis
            WHERE date(analysis_time) >= ?
            GROUP BY date(analysis_time)
            ORDER BY date
        ''', (thirty_days_ago,))
        daily_linkedin_analysis = [dict(row) for row in c.fetchall()]
        
        # Get daily feature usage
        c.execute('''
            SELECT 
                date(access_time) as date,
                feature_name,
                COUNT(*) as count
            FROM feature_usage
            WHERE date(access_time) >= ?
            GROUP BY date(access_time), feature_name
            ORDER BY date
        ''', (thirty_days_ago,))
        daily_feature_usage = [dict(row) for row in c.fetchall()]
        
        response_data = {
            'total_users': total_users,
            'total_logins': total_logins,
            'resume_analysis_count': resume_analysis_count,
            'linkedin_analysis_count': linkedin_analysis_count,
            'feature_usage': feature_usage,
            'daily_metrics': {
                'logins': daily_logins,
                'resume_analysis': daily_resume_analysis,
                'linkedin_analysis': daily_linkedin_analysis,
                'feature_usage': daily_feature_usage
            }
        }
        
        logger.info("Successfully fetched all metrics")
        logger.debug(f"Response data: {response_data}")
        
        conn.close()
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error getting metrics: {str(e)}")
        return jsonify({'error': str(e)}), 500
