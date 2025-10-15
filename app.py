import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import io

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Database configuration
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
    
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///local.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure upload settings
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}

# Models (same as before)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', backref=db.backref('documents', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes (same as before)
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            logger.info(f"User {username} logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', documents=documents)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_data = file.read()
        file_size = len(file_data)
        
        # Check if file already exists for this user
        existing_doc = Document.query.filter_by(
            user_id=current_user.id, 
            filename=filename
        ).first()
        
        if existing_doc:
            flash('A file with this name already exists')
            return redirect(url_for('dashboard'))
        
        document = Document(
            filename=filename,
            file_data=file_data,
            file_size=file_size,
            user_id=current_user.id
        )
        
        db.session.add(document)
        db.session.commit()
        
        logger.info(f"User {current_user.username} uploaded file: {filename}")
        flash('File uploaded successfully!')
    else:
        flash('Invalid file type')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def download_file(doc_id):
    document = Document.query.filter_by(id=doc_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        if password == 'admin123':
            logger.info(f"User {current_user.username} downloaded file: {document.filename}")
            return send_file(
                io.BytesIO(document.file_data),
                as_attachment=True,
                download_name=document.filename
            )
        else:
            flash('Incorrect password')
    
    return render_template('download_confirm.html', document=document)

@app.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_file(doc_id):
    document = Document.query.filter_by(id=doc_id, user_id=current_user.id).first_or_404()
    
    filename = document.filename
    db.session.delete(document)
    db.session.commit()
    
    logger.info(f"User {current_user.username} deleted file: {filename}")
    flash('File deleted successfully!')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logger.info(f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for('login'))

# Initialize database and create admin user
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin')
            admin_user.set_password('admin123')  # Default admin password
            db.session.add(admin_user)
            db.session.commit()
            logger.info("Admin user created successfully")

if __name__ == '__main__':
    init_db()
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)