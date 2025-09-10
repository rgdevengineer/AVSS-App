import boto3
import os
from botocore.exceptions import NoCredentialsError, ClientError
from flask import current_app
import mimetypes

class S3Service:
    def __init__(self):
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=current_app.config['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=current_app.config['AWS_SECRET_ACCESS_KEY'],
            region_name=current_app.config['AWS_REGION']
        )
        self.bucket_name = current_app.config['S3_BUCKET_NAME']

    def upload_file(self, file_obj, filename, content_type=None):
        """
        Upload a file to S3
        Returns: (s3_key, public_url)
        """
        try:
            # Generate unique S3 key
            s3_key = f"uploads/{filename}"

            # Detect content type if not provided
            if not content_type:
                content_type, _ = mimetypes.guess_type(filename)
                if not content_type:
                    content_type = 'application/octet-stream'

            # Upload to S3
            self.s3_client.upload_fileobj(
                file_obj,
                self.bucket_name,
                s3_key,
                ExtraArgs={
                    'ContentType': content_type,
                    'ACL': 'public-read'  # Make file publicly accessible
                }
            )

            # Generate public URL
            public_url = f"https://{self.bucket_name}.s3.{current_app.config['AWS_REGION']}.amazonaws.com/{s3_key}"

            return s3_key, public_url

        except NoCredentialsError:
            raise Exception("AWS credentials not found")
        except ClientError as e:
            raise Exception(f"S3 upload failed: {str(e)}")

    def delete_file(self, s3_key):
        """
        Delete a file from S3
        """
        try:
            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            return True
        except ClientError as e:
            raise Exception(f"S3 delete failed: {str(e)}")

    def get_file_url(self, s3_key, expiration=3600):
        """
        Generate a presigned URL for private files
        """
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self.bucket_name,
                    'Key': s3_key
                },
                ExpiresIn=expiration
            )
            return url
        except ClientError as e:
            raise Exception(f"Failed to generate presigned URL: {str(e)}")

    def get_storage_usage(self, user_id):
        """
        Calculate total storage used by a user (for future optimization)
        This would require listing all user files - expensive operation
        """
        # For now, we'll track this in the database
        # In production, you might want to cache this value
        pass
