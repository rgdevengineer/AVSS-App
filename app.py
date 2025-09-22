from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from flask_cors import CORS
import os
import uuid
import mimetypes
import shutil
import json
from services.ai_service import ai_service

# -------------------
# Initialize app
# -------------------
app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS
CORS(app)

# Setup database and migration
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Setup JWT
jwt = JWTManager(app)

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"msg": "Token has expired"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"msg": "Invalid token"}), 401

# Ensure uploads folder exists
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'mp3', 'wav', 'pdf', 'doc', 'docx', 'txt', 'zip'}

# Chunked upload settings
CHUNK_SIZE = 5 * 1024 * 1024  # 5MB chunks
MAX_CHUNKS = 4000  # Maximum 20GB file (4000 * 5MB)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_base_url():
    """Get the base URL for the application"""
    if app.config.get('BASE_URL'):
        return app.config['BASE_URL']
    # Fallback to request context
    try:
        from flask import request
        return request.host_url.rstrip('/')
    except:
        return 'http://127.0.0.1:5000'

# -------------------
# Models
# -------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    storage_used = db.Column(db.BigInteger, default=0)  # bytes used
    storage_limit = db.Column(db.BigInteger, default=50*1024*1024*1024)  # 50GB default
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    files = db.relationship('File', backref='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)  # bytes
    file_type = db.Column(db.String(50))  # image, video, audio, document
    mime_type = db.Column(db.String(100))
    s3_key = db.Column(db.String(500))  # S3 object key
    s3_url = db.Column(db.String(1000))  # Public URL
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_deleted = db.Column(db.Boolean, default=False)
    is_public = db.Column(db.Boolean, default=False)  # For sharing
    folder = db.Column(db.String(255), default='root')  # Folder organization
    tags = db.Column(db.String(500))  # Comma-separated tags
    description = db.Column(db.Text)  # File description
    share_token = db.Column(db.String(100), unique=True)  # For public sharing

    # AI-powered fields
    ai_description = db.Column(db.Text)  # AI-generated description
    ai_tags = db.Column(db.String(500))  # AI-generated tags
    image_hash = db.Column(db.String(500))  # Perceptual hash for duplicate detection
    quality_score = db.Column(db.Float)  # Image quality score (0-100)
    image_metadata = db.Column(db.Text)  # JSON string with image analysis data

class UploadSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(100), unique=True, nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(100))
    total_chunks = db.Column(db.Integer, nullable=False)
    uploaded_chunks = db.Column(db.Integer, default=0)
    temp_path = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='active')  # active, completed, failed
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

# -------------------
# Test route
# -------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/hello', methods=['GET'])
def hello():
    return "Hello world!"

# -------------------
# Routes
# -------------------
@app.route('/signup', methods=['POST', 'OPTIONS'])
def signup():
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        response = jsonify({"message": "Username, email, and password are required"}), 400
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    if User.query.filter_by(username=username).first():
        response = jsonify({"message": "User already exists"}), 400
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    if User.query.filter_by(email=email).first():
        response = jsonify({"message": "Email already exists"}), 400
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    response = jsonify({"message": "User created successfully"})
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response, 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({"access_token": new_access_token})

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome {current_user}!"})

@app.route('/storage/info', methods=['GET'])
@jwt_required()
def get_storage_info():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Calculate storage usage from database
    total_used = user.storage_used
    storage_limit = user.storage_limit
    available = storage_limit - total_used

    return jsonify({
        "used_bytes": total_used,
        "limit_bytes": storage_limit,
        "available_bytes": available,
        "used_gb": round(total_used / (1024**3), 2),
        "limit_gb": round(storage_limit / (1024**3), 2),
        "available_gb": round(available / (1024**3), 2),
        "usage_percentage": round((total_used / storage_limit) * 100, 2) if storage_limit > 0 else 0
    })

@app.route('/files', methods=['GET'])
@jwt_required()
def list_files():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    files = File.query.filter_by(user_id=user.id, is_deleted=False).order_by(File.upload_date.desc()).all()

    file_list = []
    for file in files:
        file_list.append({
            "id": file.id,
            "filename": file.original_filename,
            "size_bytes": file.file_size,
            "size_mb": round(file.file_size / (1024**2), 2),
            "file_type": file.file_type,
            "mime_type": file.mime_type,
            "url": file.s3_url,
            "upload_date": file.upload_date.isoformat()
        })

    return jsonify({
        "files": file_list,
        "total_files": len(file_list),
        "total_size_bytes": sum(f.file_size for f in files),
        "total_size_gb": round(sum(f.file_size for f in files) / (1024**3), 2)
    })

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > app.config['MAX_FILE_SIZE']:
        return jsonify({"error": f"File too large. Maximum size: {app.config['MAX_FILE_SIZE'] / (1024**3):.1f}GB"}), 400

    # Check storage quota
    if user.storage_used + file_size > user.storage_limit:
        available_gb = (user.storage_limit - user.storage_used) / (1024**3)
        return jsonify({
            "error": "Storage limit exceeded",
            "available_gb": round(available_gb, 2),
            "file_size_gb": round(file_size / (1024**3), 2)
        }), 400

    try:
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        file_extension = os.path.splitext(original_filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"

        # Detect file type and MIME type
        mime_type, _ = mimetypes.guess_type(original_filename)
        if not mime_type:
            mime_type = 'application/octet-stream'

        # Determine file type category
        if mime_type.startswith('image/'):
            file_type = 'image'
        elif mime_type.startswith('video/'):
            file_type = 'video'
        elif mime_type.startswith('audio/'):
            file_type = 'audio'
        else:
            file_type = 'document'

        # Save to local storage (FREE VERSION)
        local_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(local_path)

        # Create local URL for access
        local_url = f"{get_base_url()}/uploads/{unique_filename}"

        # AI Processing for images
        ai_description = None
        ai_tags = None
        image_hash = None
        quality_score = None
        image_metadata = None

        if file_type == 'image':
            try:
                # Generate AI description
                ai_description = ai_service.generate_image_description(local_path)

                # Generate smart tags
                ai_tags_list = ai_service.generate_smart_tags(local_path, ai_description)
                ai_tags = ','.join(ai_tags_list) if ai_tags_list else None

                # Calculate image hash for duplicate detection
                hash_data = ai_service.calculate_image_hash(local_path)
                if hash_data:
                    image_hash = json.dumps(hash_data)

                # Analyze image quality
                quality_data = ai_service.analyze_image_quality(local_path)
                if quality_data and 'quality_score' in quality_data:
                    quality_score = quality_data['quality_score']
                    image_metadata = json.dumps(quality_data)

            except Exception as e:
                print(f"AI processing failed: {e}")
                # Continue without AI features if they fail

        # Save file metadata to database
        new_file = File(
            user_id=user.id,
            filename=unique_filename,
            original_filename=original_filename,
            file_size=file_size,
            file_type=file_type,
            mime_type=mime_type,
            s3_key=local_path,  # Store local path
            s3_url=local_url,   # Local access URL
            ai_description=ai_description,
            ai_tags=ai_tags,
            image_hash=image_hash,
            quality_score=quality_score,
            image_metadata=image_metadata
        )

        # Update user's storage usage
        user.storage_used += file_size

        db.session.add(new_file)
        db.session.commit()

        return jsonify({
            "message": "File uploaded successfully",
            "file": {
                "id": new_file.id,
                "filename": original_filename,
                "size_bytes": file_size,
                "size_mb": round(file_size / (1024**2), 2),
                "file_type": file_type,
                "url": local_url,
                "upload_date": new_file.upload_date.isoformat()
            },
            "storage": {
                "used_bytes": user.storage_used,
                "available_bytes": user.storage_limit - user.storage_used,
                "usage_percentage": round((user.storage_used / user.storage_limit) * 100, 2)
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

@app.route('/files/<int:file_id>', methods=['DELETE'])
@jwt_required()
def delete_file(file_id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    try:
        # Delete from local storage
        if os.path.exists(file.s3_key):
            os.remove(file.s3_key)

        # Update user's storage usage
        user.storage_used -= file.file_size

        # Mark file as deleted (soft delete)
        file.is_deleted = True

        db.session.commit()

        return jsonify({
            "message": "File deleted successfully",
            "storage": {
                "used_bytes": user.storage_used,
                "available_bytes": user.storage_limit - user.storage_used,
                "usage_percentage": round((user.storage_used / user.storage_limit) * 100, 2)
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Delete failed: {str(e)}"}), 500

# -------------------
# Advanced Features
# -------------------

@app.route('/files/<int:file_id>/share', methods=['POST'])
@jwt_required()
def share_file(file_id):
    """Generate a shareable link for a file"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    # Generate unique share token
    share_token = str(uuid.uuid4())[:16]
    file.share_token = share_token
    file.is_public = True

    db.session.commit()

    share_url = f"{get_base_url()}/shared/{share_token}"

    return jsonify({
        "message": "File shared successfully",
        "share_url": share_url,
        "share_token": share_token
    })

@app.route('/shared/<share_token>', methods=['GET'])
def access_shared_file(share_token):
    """Access a shared file via token"""
    file = File.query.filter_by(share_token=share_token, is_public=True, is_deleted=False).first()

    if not file:
        return jsonify({"error": "Shared file not found or expired"}), 404

    return jsonify({
        "filename": file.original_filename,
        "file_type": file.file_type,
        "size_mb": round(file.file_size / (1024**2), 2),
        "upload_date": file.upload_date.isoformat(),
        "download_url": file.s3_url
    })

@app.route('/files/<int:file_id>/folder', methods=['PUT'])
@jwt_required()
def move_file_to_folder(file_id):
    """Move file to a different folder"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    data = request.get_json()
    new_folder = data.get('folder', 'root')

    file.folder = new_folder
    db.session.commit()

    return jsonify({"message": f"File moved to folder: {new_folder}"})

@app.route('/folders', methods=['GET'])
@jwt_required()
def list_folders():
    """Get all folders for the user"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get unique folders from user's files
    folders = db.session.query(File.folder).filter_by(
        user_id=user.id,
        is_deleted=False
    ).distinct().all()

    folder_list = [folder[0] for folder in folders if folder[0] != 'root']
    folder_list.insert(0, 'root')  # Add root folder first

    return jsonify({"folders": folder_list})

@app.route('/files/search', methods=['GET'])
@jwt_required()
def search_files():
    """Search files by name, tags, or description"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    query = request.args.get('q', '')
    folder = request.args.get('folder', None)
    file_type = request.args.get('type', None)

    # Build search query
    search_query = File.query.filter_by(user_id=user.id, is_deleted=False)

    if query:
        # Search in filename, tags, and description
        search_filter = f"%{query}%"
        search_query = search_query.filter(
            db.or_(
                File.original_filename.ilike(search_filter),
                File.tags.ilike(search_filter),
                File.description.ilike(search_filter)
            )
        )

    if folder:
        search_query = search_query.filter_by(folder=folder)

    if file_type:
        search_query = search_query.filter_by(file_type=file_type)

    files = search_query.order_by(File.upload_date.desc()).all()

    file_list = []
    for file in files:
        file_list.append({
            "id": file.id,
            "filename": file.original_filename,
            "size_mb": round(file.file_size / (1024**2), 2),
            "file_type": file.file_type,
            "folder": file.folder,
            "tags": file.tags,
            "description": file.description,
            "url": file.s3_url,
            "upload_date": file.upload_date.isoformat()
        })

    return jsonify({
        "query": query,
        "total_results": len(file_list),
        "files": file_list
    })

@app.route('/files/<int:file_id>/tags', methods=['PUT'])
@jwt_required()
def update_file_tags(file_id):
    """Add tags to a file"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    data = request.get_json()
    tags = data.get('tags', '')

    file.tags = tags
    db.session.commit()

    return jsonify({"message": "Tags updated successfully"})

@app.route('/files/<int:file_id>/description', methods=['PUT'])
@jwt_required()
def update_file_description(file_id):
    """Add description to a file"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    data = request.get_json()
    description = data.get('description', '')

    file.description = description
    db.session.commit()

    return jsonify({"message": "Description updated successfully"})

@app.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    """Get user notifications (for future real-time features)"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # For now, return storage notifications
    notifications = []

    storage_percentage = (user.storage_used / user.storage_limit) * 100

    if storage_percentage > 90:
        notifications.append({
            "type": "warning",
            "message": f"Storage usage is {storage_percentage:.1f}% - consider upgrading",
            "timestamp": user.created_at.isoformat()
        })
    elif storage_percentage > 75:
        notifications.append({
            "type": "info",
            "message": f"Storage usage is {storage_percentage:.1f}%",
            "timestamp": user.created_at.isoformat()
        })

    return jsonify({
        "notifications": notifications,
        "total": len(notifications)
    })

@app.route('/stats', methods=['GET'])
@jwt_required()
def get_user_stats():
    """Get comprehensive user statistics"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get file statistics
    total_files = File.query.filter_by(user_id=user.id, is_deleted=False).count()
    total_size = db.session.query(db.func.sum(File.file_size)).filter_by(
        user_id=user.id, is_deleted=False
    ).scalar() or 0

    # Get file type breakdown
    file_types = db.session.query(
        File.file_type,
        db.func.count(File.id),
        db.func.sum(File.file_size)
    ).filter_by(
        user_id=user.id, is_deleted=False
    ).group_by(File.file_type).all()

    type_breakdown = {}
    for file_type, count, size in file_types:
        type_breakdown[file_type] = {
            "count": count,
            "size_mb": round(size / (1024**2), 2) if size else 0
        }

    # Get recent activity (last 10 files)
    recent_files = File.query.filter_by(
        user_id=user.id, is_deleted=False
    ).order_by(File.upload_date.desc()).limit(10).all()

    recent_activity = []
    for file in recent_files:
        recent_activity.append({
            "filename": file.original_filename,
            "size_mb": round(file.file_size / (1024**2), 2),
            "upload_date": file.upload_date.isoformat()
        })

    return jsonify({
        "user": {
            "username": user.username,
            "storage_used_gb": round(user.storage_used / (1024**3), 2),
            "storage_limit_gb": round(user.storage_limit / (1024**3), 2),
            "storage_percentage": round((user.storage_used / user.storage_limit) * 100, 2),
            "account_created": user.created_at.isoformat()
        },
        "statistics": {
            "total_files": total_files,
            "total_size_gb": round(total_size / (1024**3), 2),
            "file_types": type_breakdown
        },
        "recent_activity": recent_activity
    })

# -------------------
# Chunked Upload System
# -------------------

@app.route('/upload/init', methods=['POST'])
@jwt_required()
def init_chunked_upload():
    """Initialize a chunked upload session"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    filename = data.get('filename')
    file_size = data.get('fileSize')

    if not filename or not file_size:
        return jsonify({"error": "Filename and fileSize are required"}), 400

    if not allowed_file(filename):
        return jsonify({"error": "File type not allowed"}), 400

    if file_size > app.config['MAX_FILE_SIZE']:
        return jsonify({"error": f"File too large. Maximum size: {app.config['MAX_FILE_SIZE'] / (1024**3):.1f}GB"}), 400

    # Check storage quota
    if user.storage_used + file_size > user.storage_limit:
        available_gb = (user.storage_limit - user.storage_used) / (1024**3)
        return jsonify({
            "error": "Storage limit exceeded",
            "available_gb": round(available_gb, 2),
            "file_size_gb": round(file_size / (1024**3), 2)
        }), 400

    # Calculate total chunks
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE  # Ceiling division

    if total_chunks > MAX_CHUNKS:
        return jsonify({"error": f"Too many chunks. Maximum: {MAX_CHUNKS}"}), 400

    # Generate session ID
    session_id = str(uuid.uuid4())

    # Create temp directory for chunks
    temp_dir = os.path.join(UPLOAD_FOLDER, 'chunks', session_id)
    os.makedirs(temp_dir, exist_ok=True)

    # Detect MIME type
    mime_type, _ = mimetypes.guess_type(filename)
    if not mime_type:
        mime_type = 'application/octet-stream'

    # Create upload session
    session = UploadSession(
        user_id=user.id,
        session_id=session_id,
        original_filename=secure_filename(filename),
        file_size=file_size,
        mime_type=mime_type,
        total_chunks=total_chunks,
        temp_path=temp_dir
    )

    db.session.add(session)
    db.session.commit()

    return jsonify({
        "session_id": session_id,
        "total_chunks": total_chunks,
        "chunk_size": CHUNK_SIZE,
        "message": "Upload session initialized"
    }), 201

@app.route('/upload/chunk/<session_id>', methods=['POST'])
@jwt_required()
def upload_chunk(session_id):
    """Upload a single chunk"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get upload session
    session = UploadSession.query.filter_by(
        session_id=session_id,
        user_id=user.id,
        status='active'
    ).first()

    if not session:
        return jsonify({"error": "Upload session not found or expired"}), 404

    if 'chunk' not in request.files:
        return jsonify({"error": "No chunk file provided"}), 400

    chunk_number = request.form.get('chunkNumber', type=int)
    if chunk_number is None or chunk_number < 0 or chunk_number >= session.total_chunks:
        return jsonify({"error": "Invalid chunk number"}), 400

    chunk_file = request.files['chunk']

    # Save chunk to temp file
    chunk_path = os.path.join(session.temp_path, f'chunk_{chunk_number:06d}')
    chunk_file.save(chunk_path)

    # Update session progress
    session.uploaded_chunks += 1
    db.session.commit()

    # Check if upload is complete
    if session.uploaded_chunks == session.total_chunks:
        # All chunks uploaded, now combine and upload to S3
        return finalize_chunked_upload(session)

    return jsonify({
        "chunk_number": chunk_number,
        "uploaded_chunks": session.uploaded_chunks,
        "total_chunks": session.total_chunks,
        "progress": round((session.uploaded_chunks / session.total_chunks) * 100, 2),
        "message": "Chunk uploaded successfully"
    })

def finalize_chunked_upload(session):
    """Combine all chunks and upload to S3"""
    try:
        # Create final file path
        final_filename = f"{uuid.uuid4()}{os.path.splitext(session.original_filename)[1]}"
        final_path = os.path.join(UPLOAD_FOLDER, 'temp', final_filename)

        # Combine all chunks
        with open(final_path, 'wb') as final_file:
            for i in range(session.total_chunks):
                chunk_path = os.path.join(session.temp_path, f'chunk_{i:06d}')
                if not os.path.exists(chunk_path):
                    raise Exception(f"Missing chunk {i}")

                with open(chunk_path, 'rb') as chunk_file:
                    final_file.write(chunk_file.read())

        # Verify final file size
        actual_size = os.path.getsize(final_path)
        if actual_size != session.file_size:
            raise Exception(f"File size mismatch: expected {session.file_size}, got {actual_size}")

        # Save to local storage (FREE VERSION)
        local_final_path = os.path.join(app.config['UPLOAD_FOLDER'], final_filename)
        os.rename(final_path, local_final_path)  # Move from temp to final location
        local_url = f"{get_base_url()}/uploads/{final_filename}"

        # Determine file type category
        if session.mime_type.startswith('image/'):
            file_type = 'image'
        elif session.mime_type.startswith('video/'):
            file_type = 'video'
        elif session.mime_type.startswith('audio/'):
            file_type = 'audio'
        else:
            file_type = 'document'

        # Save file metadata to database
        new_file = File(
            user_id=session.user_id,
            filename=final_filename,
            original_filename=session.original_filename,
            file_size=session.file_size,
            file_type=file_type,
            mime_type=session.mime_type,
            s3_key=local_final_path,  # Store local path
            s3_url=local_url         # Local access URL
        )

        # Update user's storage usage
        user = User.query.get(session.user_id)
        user.storage_used += session.file_size

        # Mark session as completed
        session.status = 'completed'

        db.session.add(new_file)
        db.session.commit()

        # Clean up temp files
        shutil.rmtree(session.temp_path)

        return jsonify({
            "message": "File uploaded successfully",
            "file": {
                "id": new_file.id,
                "filename": session.original_filename,
                "size_bytes": session.file_size,
                "size_gb": round(session.file_size / (1024**3), 2),
                "file_type": file_type,
                "url": local_url,
                "upload_date": new_file.upload_date.isoformat()
            },
            "storage": {
                "used_bytes": user.storage_used,
                "available_bytes": user.storage_limit - user.storage_used,
                "usage_percentage": round((user.storage_used / user.storage_limit) * 100, 2)
            }
        }), 201

    except Exception as e:
        # Mark session as failed
        session.status = 'failed'
        db.session.commit()

        # Clean up temp files
        if os.path.exists(session.temp_path):
            shutil.rmtree(session.temp_path)

        # Clean up final file if it was created
        if 'final_path' in locals() and os.path.exists(final_path):
            os.remove(final_path)

        return jsonify({"error": f"Upload finalization failed: {str(e)}"}), 500

@app.route('/upload/status/<session_id>', methods=['GET'])
@jwt_required()
def get_upload_status(session_id):
    """Get upload session status"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    session = UploadSession.query.filter_by(
        session_id=session_id,
        user_id=user.id
    ).first()

    if not session:
        return jsonify({"error": "Upload session not found"}), 404

    return jsonify({
        "session_id": session.session_id,
        "filename": session.original_filename,
        "file_size": session.file_size,
        "uploaded_chunks": session.uploaded_chunks,
        "total_chunks": session.total_chunks,
        "progress": round((session.uploaded_chunks / session.total_chunks) * 100, 2),
        "status": session.status,
        "created_at": session.created_at.isoformat()
    })

# -------------------
# AI-Powered Features
# -------------------

@app.route('/ai/analyze/<int:file_id>', methods=['GET'])
@jwt_required()
def analyze_file_ai(file_id):
    """Get AI analysis for a file"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    if file.file_type != 'image':
        return jsonify({"error": "AI analysis is only available for images"}), 400

    # Return existing AI data if available
    ai_data = {
        "ai_description": file.ai_description,
        "ai_tags": file.ai_tags.split(',') if file.ai_tags else [],
        "quality_score": file.quality_score,
        "image_metadata": json.loads(file.image_metadata) if file.image_metadata else None
    }

    # If no AI data exists, try to generate it
    if not file.ai_description and os.path.exists(file.s3_key):
        try:
            # Generate AI description
            ai_description = ai_service.generate_image_description(file.s3_key)
            if ai_description:
                file.ai_description = ai_description
                ai_data["ai_description"] = ai_description

            # Generate smart tags
            ai_tags_list = ai_service.generate_smart_tags(file.s3_key, ai_description)
            if ai_tags_list:
                ai_tags = ','.join(ai_tags_list)
                file.ai_tags = ai_tags
                ai_data["ai_tags"] = ai_tags_list

            # Analyze image quality
            quality_data = ai_service.analyze_image_quality(file.s3_key)
            if quality_data and 'quality_score' in quality_data:
                file.quality_score = quality_data['quality_score']
                file.image_metadata = json.dumps(quality_data)
                ai_data["quality_score"] = quality_data['quality_score']
                ai_data["image_metadata"] = quality_data

            db.session.commit()

        except Exception as e:
            print(f"AI analysis failed: {e}")

    return jsonify({
        "file_id": file_id,
        "filename": file.original_filename,
        "ai_analysis": ai_data
    })

@app.route('/ai/search', methods=['GET'])
@jwt_required()
def ai_smart_search():
    """AI-powered smart search"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    query = request.args.get('q', '')
    if not query:
        return jsonify({"error": "Search query is required"}), 400

    # Get user's files for smart search
    files = File.query.filter_by(user_id=user.id, is_deleted=False).all()

    # Convert to format expected by AI service
    available_files = []
    for file in files:
        available_files.append({
            'filename': file.original_filename,
            'file_type': file.file_type,
            'description': file.ai_description or file.description or '',
            'tags': file.ai_tags or file.tags or '',
            'size_mb': round(file.file_size / (1024**2), 2)
        })

    # Perform smart search
    search_results = ai_service.smart_search(query, available_files)

    # Convert back to API format
    results = []
    for result in search_results:
        file_data = result['file']
        # Find the original file object
        original_file = next((f for f in files if f.original_filename == file_data['filename']), None)
        if original_file:
            results.append({
                "id": original_file.id,
                "filename": original_file.original_filename,
                "size_mb": file_data['size_mb'],
                "file_type": original_file.file_type,
                "folder": original_file.folder,
                "tags": original_file.tags,
                "description": original_file.description,
                "ai_description": original_file.ai_description,
                "ai_tags": original_file.ai_tags.split(',') if original_file.ai_tags else [],
                "url": original_file.s3_url,
                "upload_date": original_file.upload_date.isoformat(),
                "relevance_score": result['score'],
                "match_reasons": result['reasons']
            })

    return jsonify({
        "query": query,
        "total_results": len(results),
        "results": results
    })

@app.route('/ai/duplicates', methods=['GET'])
@jwt_required()
def find_duplicates():
    """Find duplicate images using AI"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get all user's image files with hashes
    images = File.query.filter_by(
        user_id=user.id,
        is_deleted=False,
        file_type='image'
    ).filter(File.image_hash.isnot(None)).all()

    if len(images) < 2:
        return jsonify({
            "message": "Not enough images to check for duplicates",
            "duplicates": []
        })

    # Build hash dictionary
    all_hashes = {}
    for img in images:
        try:
            hash_data = json.loads(img.image_hash)
            all_hashes[str(img.id)] = hash_data
        except:
            continue

    # Find duplicates
    duplicates = []
    processed = set()

    for img in images:
        if str(img.id) in processed:
            continue

        try:
            hash_data = json.loads(img.image_hash) if img.image_hash else None
            if not hash_data:
                continue

            similar_images = ai_service.find_similar_images(hash_data, all_hashes, threshold=3)

            if similar_images:
                duplicate_group = {
                    "original": {
                        "id": img.id,
                        "filename": img.original_filename,
                        "size_mb": round(img.file_size / (1024**2), 2),
                        "url": img.s3_url,
                        "upload_date": img.upload_date.isoformat()
                    },
                    "duplicates": []
                }

                for dup in similar_images:
                    dup_id = dup['image_id']
                    if dup_id not in processed:
                        dup_file = next((f for f in images if str(f.id) == dup_id), None)
                        if dup_file:
                            duplicate_group["duplicates"].append({
                                "id": dup_file.id,
                                "filename": dup_file.original_filename,
                                "size_mb": round(dup_file.file_size / (1024**2), 2),
                                "url": dup_file.s3_url,
                                "upload_date": dup_file.upload_date.isoformat(),
                                "similarity_score": dup['similarity_score']
                            })
                            processed.add(dup_id)

                if duplicate_group["duplicates"]:
                    duplicates.append(duplicate_group)
                    processed.add(str(img.id))

        except Exception as e:
            print(f"Error processing image {img.id}: {e}")
            continue

    return jsonify({
        "total_duplicate_groups": len(duplicates),
        "duplicates": duplicates
    })

@app.route('/ai/optimize/<int:file_id>', methods=['POST'])
@jwt_required()
def optimize_image(file_id):
    """Optimize an image using AI"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    if file.file_type != 'image':
        return jsonify({"error": "Optimization is only available for images"}), 400

    if not os.path.exists(file.s3_key):
        return jsonify({"error": "Original file not found"}), 404

    try:
        # Optimize the image
        optimized_path = ai_service.optimize_image(file.s3_key)

        if optimized_path and optimized_path != file.s3_key:
            # Calculate size difference
            original_size = os.path.getsize(file.s3_key)
            optimized_size = os.path.getsize(optimized_path)
            savings = original_size - optimized_size
            savings_percentage = (savings / original_size) * 100

            # Update file record
            file.file_size = optimized_size
            user.storage_used -= savings  # Reduce storage usage

            # Replace original with optimized
            os.remove(file.s3_key)
            os.rename(optimized_path, file.s3_key)

            db.session.commit()

            return jsonify({
                "message": "Image optimized successfully",
                "original_size_mb": round(original_size / (1024**2), 2),
                "optimized_size_mb": round(optimized_size / (1024**2), 2),
                "savings_mb": round(savings / (1024**2), 2),
                "savings_percentage": round(savings_percentage, 1),
                "file": {
                    "id": file.id,
                    "filename": file.original_filename,
                    "size_mb": round(file.file_size / (1024**2), 2),
                    "url": file.s3_url
                }
            })
        else:
            return jsonify({"message": "Image is already optimized or optimization not needed"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Optimization failed: {str(e)}"}), 500

@app.route('/ai/similar/<int:file_id>', methods=['GET'])
@jwt_required()
def find_similar_images(file_id):
    """Find images similar to the given image"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    if file.file_type != 'image':
        return jsonify({"error": "Similarity search is only available for images"}), 400

    # Get all user's images with hashes
    images = File.query.filter_by(
        user_id=user.id,
        is_deleted=False,
        file_type='image'
    ).filter(File.image_hash.isnot(None)).all()

    if len(images) < 2:
        return jsonify({"similar_images": []})

    # Build hash dictionary
    all_hashes = {}
    for img in images:
        try:
            hash_data = json.loads(img.image_hash)
            all_hashes[str(img.id)] = hash_data
        except:
            continue

    # Find similar images
    try:
        target_hash = json.loads(file.image_hash) if file.image_hash else None
        if not target_hash:
            return jsonify({"error": "Image hash not available"}), 400

        similar_images = ai_service.find_similar_images(target_hash, all_hashes, threshold=8)

        # Convert to API format
        results = []
        for sim in similar_images:
            sim_file = next((f for f in images if str(f.id) == sim['image_id']), None)
            if sim_file:
                results.append({
                    "id": sim_file.id,
                    "filename": sim_file.original_filename,
                    "size_mb": round(sim_file.file_size / (1024**2), 2),
                    "url": sim_file.s3_url,
                    "upload_date": sim_file.upload_date.isoformat(),
                    "similarity_score": sim['similarity_score']
                })

        return jsonify({
            "target_image": {
                "id": file.id,
                "filename": file.original_filename
            },
            "similar_images": results,
            "total_similar": len(results)
        })

    except Exception as e:
        return jsonify({"error": f"Similarity search failed: {str(e)}"}), 500

@app.route('/ai/batch-analyze', methods=['POST'])
@jwt_required()
def batch_ai_analysis():
    """Analyze multiple images with AI"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    file_ids = data.get('file_ids', [])

    if not file_ids:
        return jsonify({"error": "No file IDs provided"}), 400

    results = []
    processed = 0
    failed = 0

    for file_id in file_ids:
        try:
            file = File.query.filter_by(id=file_id, user_id=user.id, is_deleted=False).first()

            if not file or file.file_type != 'image':
                failed += 1
                continue

            # Check if AI data already exists
            if file.ai_description and file.ai_tags:
                processed += 1
                results.append({
                    "file_id": file_id,
                    "filename": file.original_filename,
                    "status": "already_analyzed",
                    "ai_description": file.ai_description,
                    "ai_tags": file.ai_tags.split(',') if file.ai_tags else []
                })
                continue

            # Generate AI analysis
            if os.path.exists(file.s3_key):
                ai_description = ai_service.generate_image_description(file.s3_key)
                ai_tags_list = ai_service.generate_smart_tags(file.s3_key, ai_description)

                if ai_description:
                    file.ai_description = ai_description
                if ai_tags_list:
                    file.ai_tags = ','.join(ai_tags_list)

                # Analyze quality
                quality_data = ai_service.analyze_image_quality(file.s3_key)
                if quality_data and 'quality_score' in quality_data:
                    file.quality_score = quality_data['quality_score']
                    file.image_metadata = json.dumps(quality_data)

                db.session.commit()

                results.append({
                    "file_id": file_id,
                    "filename": file.original_filename,
                    "status": "analyzed",
                    "ai_description": ai_description,
                    "ai_tags": ai_tags_list
                })
                processed += 1
            else:
                failed += 1

        except Exception as e:
            print(f"Error analyzing file {file_id}: {e}")
            failed += 1
            continue

    return jsonify({
        "message": f"Batch analysis completed: {processed} processed, {failed} failed",
        "processed": processed,
        "failed": failed,
        "results": results
    })

# -------------------
# Run the app
# -------------------
if __name__ == "__main__":
    # Use PORT environment variable for deployment (Render, Heroku, etc.)
    port = int(os.environ.get("PORT", 5000))
    # Bind to 0.0.0.0 for production, localhost for development
    host = "0.0.0.0" if os.environ.get("FLASK_ENV") == "production" else "127.0.0.1"
    app.run(host=host, port=port, debug=os.environ.get("FLASK_ENV") != "production")
