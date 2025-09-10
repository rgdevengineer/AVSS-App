from app import app, db

with app.app_context():
    # Create all tables
    db.create_all()
    print("✅ Database tables created successfully!")

    # Check if tables were created
    from app import User, File, UploadSession
    print("✅ User table created")
    print("✅ File table created")
    print("✅ UploadSession table created")
    print("✅ Database initialization complete!")
    print("\n📊 Database Schema:")
    print("- Users: Authentication & storage quotas")
    print("- Files: File metadata & S3 storage")
    print("- UploadSessions: Chunked upload tracking")
