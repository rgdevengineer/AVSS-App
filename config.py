
import os

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///photo_share.db')  # Default to SQLite for development
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = 900  # 15 minutes for production-ready testing
    UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
    MAX_CONTENT_LENGTH = 21 * 1024 * 1024 * 1024  # 21GB limit for uploads (to handle 20GB files + overhead)
    MAX_FILE_SIZE = 20 * 1024 * 1024 * 1024  # 20GB per file

    # AWS S3 Configuration
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
    S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME', 'your-photo-share-bucket')
    S3_PUBLIC_URL = f"https://{S3_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com"

    # Storage limits
    FREE_STORAGE_LIMIT = 50 * 1024 * 1024 * 1024  # 50GB
    MAX_FILE_SIZE = 20 * 1024 * 1024 * 1024  # 20GB per file

    # Base URL for file access (will be set dynamically)
    BASE_URL = os.getenv('BASE_URL') or 'http://127.0.0.1:5000'
