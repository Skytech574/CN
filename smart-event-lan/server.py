
import os
import shutil
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, abort
from flask_socketio import SocketIO, emit, disconnect
from werkzeug.utils import secure_filename
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3



# ============================================
# APP CONFIGURATION
# ============================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'event_lan_secret_2025')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', './uploads')
app.config['BACKUP_FOLDER'] = os.getenv('BACKUP_FOLDER', './backups')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  


app.config['ADMIN_USERNAME'] = os.getenv('ADMIN_USERNAME', 'admin')
app.config['ADMIN_PASSWORD_HASH'] = os.getenv('ADMIN_PASSWORD_HASH', 
                                               generate_password_hash('adminpass'))


S3_BUCKET = os.getenv('S3_BUCKET')
S3_REGION = os.getenv('S3_REGION', 'us-east-1')


os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['BACKUP_FOLDER'], exist_ok=True)


socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')


auth = HTTPBasicAuth()


current_slide = 1
connected_clients = {}  



def get_db_connection():
    
    conn = sqlite3.connect('quiz.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
   
    conn = get_db_connection()
    c = conn.cursor()
    
    
    c.execute('''CREATE TABLE IF NOT EXISTS quiz_responses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  answer1 TEXT,
                  answer2 TEXT,
                  answer3 TEXT,
                  ip TEXT,
                  timestamp TEXT NOT NULL)''')
    
    
    c.execute('''CREATE TABLE IF NOT EXISTS chat_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  message TEXT NOT NULL,
                  ip TEXT,
                  timestamp TEXT NOT NULL)''')
    
    
    c.execute('''CREATE TABLE IF NOT EXISTS traffic_stats
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  packet_type TEXT NOT NULL,
                  count INTEGER DEFAULT 1,
                  timestamp TEXT NOT NULL)''')
    
   
    c.execute('''CREATE TABLE IF NOT EXISTS connection_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip TEXT NOT NULL,
                  username TEXT,
                  user_agent TEXT,
                  action TEXT,
                  timestamp TEXT NOT NULL)''')
    
    
    c.execute('''CREATE TABLE IF NOT EXISTS banned_ips
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip TEXT UNIQUE NOT NULL,
                  reason TEXT,
                  banned_at TEXT NOT NULL)''')
    
    conn.commit()
    conn.close()
    print("✓ Database initialized with all tables")


init_db()

# ============================================
# HELPER FUNCTIONS
# ============================================

def get_client_ip():
    
    if request.headers.get('X-Forwarded-For'):
        xff = request.headers.get('X-Forwarded-For').split(',')
        return xff[0].strip()
    return request.remote_addr or '0.0.0.0'

def is_ip_banned(ip):
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM banned_ips WHERE ip=?", (ip,))
    result = c.fetchone()
    conn.close()
    return result is not None

def log_connection(ip, user_agent, action, username=None):
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""INSERT INTO connection_logs 
                    (ip, username, user_agent, action, timestamp) 
                    VALUES (?, ?, ?, ?, ?)""",
                  (ip, username, user_agent, action, 
                   datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging connection: {e}")

def backup_file(filename):
   
    try:
        src = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dst = os.path.join(app.config['BACKUP_FOLDER'], f"{timestamp}__{filename}")
        shutil.copy2(src, dst)
        print(f" Local backup created: {dst}")
        return dst
    except Exception as e:
        print(f" Backup failed: {e}")
        return None

def backup_to_s3(filepath, filename):
    
    if not HAS_BOTO3 or not S3_BUCKET:
        return False
    
    try:
        s3 = boto3.client('s3', region_name=S3_REGION)
        s3.upload_file(filepath, S3_BUCKET, f"uploads/{filename}")
        print(f"✓ S3 backup created: s3://{S3_BUCKET}/uploads/{filename}")
        return True
    except (BotoCoreError, ClientError) as e:
        print(f"✗ S3 backup failed: {e}")
        return False

# ============================================
# ADMIN AUTHENTICATION
# ============================================

@auth.verify_password
def verify_password(username, password):
    
    if username == app.config['ADMIN_USERNAME'] and \
       check_password_hash(app.config['ADMIN_PASSWORD_HASH'], password):
        return username
    return None

def admin_required(f):
    
    @wraps(f)
    @auth.login_required
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper

# ============================================
# MIDDLEWARE - BLOCK BANNED IPS
# ============================================

@app.before_request
def block_banned():
    
    ip = get_client_ip()
    if is_ip_banned(ip):
        abort(403, description="Your IP has been banned from this network.")

# ============================================
# MAIN USER ROUTES
# ============================================

@app.route('/')
def index():
   
    log_connection(get_client_ip(), request.headers.get('User-Agent'), 'PAGE_VIEW')
    return render_template('index.html')

@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    
    if request.method == 'POST':
        try:
            name = request.form.get('name', 'Anonymous').strip()
            answer1 = request.form.get('answer1', '').strip()
            answer2 = request.form.get('answer2', '').strip()
            answer3 = request.form.get('answer3', '').strip()
            
            
            if not name or not answer1 or not answer2 or not answer3:
                return render_template('quiz.html')
            
            
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""INSERT INTO quiz_responses 
                        (name, answer1, answer2, answer3, ip, timestamp) 
                        VALUES (?, ?, ?, ?, ?, ?)""",
                      (name, answer1, answer2, answer3, get_client_ip(),
                       datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
            
            
            socketio.emit('quiz_submitted', {'name': name})


            
            log_connection(get_client_ip(), request.headers.get('User-Agent'), 
                         'QUIZ_SUBMIT', username=name)
            
            return render_template('quiz_success.html', name=name)
            
        except Exception as e:
            print(f"Error in quiz submission: {e}")
            return f"<h1>Error submitting quiz</h1><p>{str(e)}</p><a href='/quiz'>Try Again</a>", 500
    
    return render_template('quiz.html')

@app.route('/slides')
def slides():
   
    
    return render_template('slides.html', current_slide=0, is_presenter=True)

@app.route('/slides/control', methods=['POST'])
def control_slides():
    
    global current_slide
    
    try:
        action = request.form.get('action')
        
        if action == 'next':
            current_slide += 1
        elif action == 'prev' and current_slide > 1:
            current_slide -= 1
        elif action == 'goto':
            slide_num = int(request.form.get('slide_number', 1))
            if slide_num > 0:
                current_slide = slide_num
        
        
        emit('slide_change', {'slide': current_slide}, broadcast=True)
        
        return jsonify({
            'status': 'success',
            'current_slide': current_slide
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/dashboard')
def dashboard():
  
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        
        c.execute("SELECT COUNT(*) FROM quiz_responses")
        quiz_count = c.fetchone()[0]
        
        
        c.execute("""SELECT name, timestamp 
                    FROM quiz_responses 
                    ORDER BY id DESC LIMIT 10""")
        recent_responses = c.fetchall()
        
        
        c.execute("""SELECT packet_type, SUM(count) as total
                    FROM traffic_stats 
                    GROUP BY packet_type 
                    ORDER BY total DESC""")
        traffic = c.fetchall()
        
        
        c.execute("""SELECT COUNT(DISTINCT ip) 
                    FROM connection_logs 
                    WHERE timestamp > datetime('now', '-1 hour')""")
        recent_connections = c.fetchone()[0]
        
        
        c.execute("SELECT COUNT(*) FROM chat_messages")
        chat_count = c.fetchone()[0]
        
        conn.close()
        
        return render_template('dashboard.html',
                             quiz_count=quiz_count,
                             recent_responses=recent_responses,
                             traffic=traffic,
                             connected=len(connected_clients),
                             recent_connections=recent_connections,
                             chat_count=chat_count)
    
    except Exception as e:
        print(f"Dashboard error: {e}")
        return f"<h1>Dashboard Error</h1><p>{str(e)}</p>", 500

@app.route('/files', methods=['GET', 'POST'])
def files():
   
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                return redirect(url_for('files'))
            
            file = request.files['file']
            
            if file.filename == '':
                return redirect(url_for('files'))
            
            if file:
                
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                
                file.save(filepath)
                
               
                backup_file(filename)
                
                
                
                return redirect(url_for('files'))
        
        except Exception as e:
            print(f"File upload error: {e}")
            return f"<h1>Upload Error</h1><p>{str(e)}</p>", 500
    
    
    try:
        files_list = []
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath)
                files_list.append({
                    'name': filename,
                    'size': f"{size / 1024:.2f} KB" if size < 1024*1024 else f"{size / (1024*1024):.2f} MB",
                    'uploaded': datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M')
                })
        
        return render_template('files.html', files=files_list)
    
    except Exception as e:
        print(f"File listing error: {e}")
        return render_template('files.html', files=[])

@app.route('/download/<filename>')
def download(filename):
    
    try:
        log_connection(get_client_ip(), request.headers.get('User-Agent'), 
                      f'FILE_DOWNLOAD:{filename}')
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        return f"<h1>File not found</h1><p>{str(e)}</p>", 404

@app.route('/api/stats')
def api_stats():
   
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM quiz_responses")
        quiz_count = c.fetchone()[0]
        
        c.execute("SELECT packet_type, SUM(count) FROM traffic_stats GROUP BY packet_type")
        rows = c.fetchall()
        traffic_data = dict(rows) if rows else {}
        
        c.execute("SELECT COUNT(*) FROM chat_messages")
        chat_count = c.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'quiz_submissions': quiz_count,
            'connected_clients': len(connected_clients),
            'traffic': traffic_data,
            'chat_messages': chat_count,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# ADMIN ROUTES
# ============================================

@app.route('/admin/logs')
@admin_required
def admin_logs():
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
      
        c.execute("""SELECT username, message, ip, timestamp 
                    FROM chat_messages 
                    ORDER BY id DESC LIMIT 100""")
        messages = c.fetchall()
 
        c.execute("""SELECT ip, username, user_agent, action, timestamp 
                    FROM connection_logs 
                    ORDER BY id DESC LIMIT 100""")
        connections = c.fetchall()
        
      
        c.execute("SELECT ip, reason, banned_at FROM banned_ips ORDER BY id DESC")
        banned = c.fetchall()
        
       
        c.execute("""SELECT name, ip, timestamp 
                    FROM quiz_responses 
                    ORDER BY id DESC LIMIT 50""")
        quizzes = c.fetchall()
        
        conn.close()
        
        return render_template('admin_logs.html',
                             messages=messages,
                             connections=connections,
                             banned=banned,
                             quizzes=quizzes)
    
    except Exception as e:
        return f"<h1>Admin Error</h1><p>{str(e)}</p>", 500

@app.route('/admin/ban', methods=['POST'])
@admin_required
def admin_ban():
   
    try:
        ip = request.form.get('ip')
        reason = request.form.get('reason', 'Admin banned')
        
        if not ip:
            return "IP required", 400
        
        conn = get_db_connection()
        c = conn.cursor()
        
       
        c.execute("SELECT * FROM banned_ips WHERE ip=?", (ip,))
        if not c.fetchone():
            c.execute("""INSERT INTO banned_ips (ip, reason, banned_at) 
                        VALUES (?, ?, ?)""",
                      (ip, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            print(f" IP banned: {ip}")
        
        conn.close()
        
        return redirect(url_for('admin_logs'))
    
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/admin/unban', methods=['POST'])
@admin_required
def admin_unban():
    
    try:
        ip = request.form.get('ip')
        
        if not ip:
            return "IP required", 400
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM banned_ips WHERE ip=?", (ip,))
        conn.commit()
        conn.close()
        
        print(f"✓ IP unbanned: {ip}")
        
        return redirect(url_for('admin_logs'))
    
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/admin/download-backup/<path:filename>')
@admin_required
def admin_download_backup(filename):
  
    try:
        return send_from_directory(app.config['BACKUP_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        return f"<h1>Backup not found</h1><p>{str(e)}</p>", 404

@app.route('/admin/backups')
@admin_required
def admin_backups():
    
    try:
        backups = []
        for filename in os.listdir(app.config['BACKUP_FOLDER']):
            filepath = os.path.join(app.config['BACKUP_FOLDER'], filename)
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath)
                backups.append({
                    'name': filename,
                    'size': f"{size / 1024:.2f} KB" if size < 1024*1024 else f"{size / (1024*1024):.2f} MB",
                    'created': datetime.fromtimestamp(os.path.getctime(filepath)).strftime('%Y-%m-%d %H:%M')
                })
        
        return render_template('admin_backups.html', backups=backups)
    
    except Exception as e:
        return f"<h1>Error</h1><p>{str(e)}</p>", 500

# ============================================
# WEBSOCKET EVENTS
# ============================================

@socketio.on('connect')
def handle_connect():
   
    ip = get_client_ip()
    
    
    if is_ip_banned(ip):
        print(f" Banned IP attempted connection: {ip}")
        emit('banned', {'reason': 'Your IP is banned'})
        disconnect()
        return
    
    
    client_id = request.sid
    username = request.args.get('username', 'Anonymous')
    
    connected_clients[client_id] = {
        'ip': ip,
        'username': username,
        'connected_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f" Client connected: {client_id} from {ip} ({username})")
    log_connection(ip, request.headers.get('User-Agent'), 'WEBSOCKET_CONNECT', username)
    
    
    emit('client_count', {'count': len(connected_clients)}, broadcast=True)
    
   
    emit('slide_change', {'slide': current_slide})

@socketio.on('disconnect')
def handle_disconnect():
    
    client_id = request.sid
    
    if client_id in connected_clients:
        ip = connected_clients[client_id]['ip']
        print(f"✗ Client disconnected: {client_id} from {ip}")
        del connected_clients[client_id]
    
    
    emit('client_count', {'count': len(connected_clients)}, broadcast=True)

@socketio.on('chat_message')
def handle_chat(data):
    
    try:
        ip = get_client_ip()
        
        
        if is_ip_banned(ip):
            disconnect()
            return
        
        username = data.get('username', 'Anonymous')
        message = data.get('message', '')
        timestamp_display = datetime.now().strftime("%H:%M:%S")
        timestamp_db = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not message.strip():
            return
        
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""INSERT INTO chat_messages (username, message, ip, timestamp) 
                    VALUES (?, ?, ?, ?)""",
                  (username, message, ip, timestamp_db))
        conn.commit()
        conn.close()
        
      
        emit('chat_message', {
            'username': username,
            'message': message,
            'timestamp': timestamp_display
        }, broadcast=True)
        
        print(f"Chat [{timestamp_display}] {username}: {message}")
    
    except Exception as e:
        print(f"Chat error: {e}")

@socketio.on('ping')
def handle_ping():
    
    emit('pong')
@socketio.on('change_slide')
def handle_change_slide(data):
    slide = data.get('slide', 0)
    socketio.emit('slide_change', {'slide': slide}, broadcast=True)

# ============================================
# ERROR HANDLERS
# ============================================
@app.route('/admin/export-quiz', methods=['GET'])
@admin_required
def admin_export_quiz():
    
    try:
        import csv
        import io
        
        conn = get_db_connection()
        c = conn.cursor()
        
     
        c.execute("""SELECT name, answer1, answer2, answer3, ip, timestamp 
                    FROM quiz_responses 
                    ORDER BY id DESC""")
        responses = c.fetchall()
        conn.close()
        
      
        output = io.StringIO()
        writer = csv.writer(output)
        
        
        writer.writerow(['Name', 'Answer 1', 'Answer 2', 'Answer 3', 'IP Address', 'Timestamp'])
        
        
        for row in responses:
            writer.writerow([row[0], row[1], row[2], row[3], row[4], row[5]])
        
        
        output.seek(0)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=quiz_backup_{timestamp}.csv'
            }
        )
    
    except Exception as e:
        return f"<h1>Export Error</h1><p>{str(e)}</p>", 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html', error=str(e)), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

# ============================================
# MAIN ENTRY POINT
# ============================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print(" SMART EVENT LAN SERVER ")
    print("="*70)
    print("Database initialized with all tables")
    
    print(f" Admin username: {app.config['ADMIN_USERNAME']}")
    print(f" Admin password: adminpass (change in production!)")
    
    
    print("🌐 Access from network: http://<YOUR-IP>:5000")
    print("🔐 Admin panel: http://<YOUR-IP>:5000/admin/logs")
    print("="*70)
    
    
   
    socketio.run(app, 
                host='0.0.0.0', 
                port=int(os.getenv('PORT', 5000)), 
                debug=True,
                allow_unsafe_werkzeug=True)
