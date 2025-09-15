import os
import requests
import base64
from PIL import Image
import imagehash
import cv2
import numpy as np
from transformers import pipeline
from flask import current_app
import io
import json
import math

class AIService:
    def __init__(self):
        # Initialize AI models (lazy loading to save memory)
        self.caption_model = None
        self._model_loaded = False

    def _load_caption_model(self):
        """
        Lazy load the captioning model when first needed
        """
        if not self._model_loaded:
            try:
                print("Loading AI captioning model...")
                self.caption_model = pipeline("image-to-text", model="Salesforce/blip-image-captioning-base")
                self._model_loaded = True
                print("AI captioning model loaded successfully")
            except Exception as e:
                print(f"Warning: Could not load AI captioning model: {e}")
                self.caption_model = None
                self._model_loaded = True  # Don't try again

    def generate_image_description(self, image_path):
        """
        Generate AI-powered description of an image using local model
        Completely free, no API calls required
        """
        # Lazy load the model
        if not self._model_loaded:
            self._load_caption_model()

        if not self.caption_model:
            return "AI description unavailable - model not loaded"

        try:
            # Load and process image
            image = Image.open(image_path)

            # Generate caption
            result = self.caption_model(image)

            if result and len(result) > 0:
                description = result[0]['generated_text']
                return description
            else:
                return "Could not generate description"

        except Exception as e:
            print(f"Error generating image description: {e}")
            return "Description generation failed"

    def generate_smart_tags(self, image_path, existing_description=""):
        """
        Generate smart tags for an image based on content analysis
        """
        tags = []

        try:
            # Load image
            image = Image.open(image_path)

            # Basic analysis based on image properties
            width, height = image.size

            # Size-based tags
            if width > height:
                tags.append("landscape")
            elif height > width:
                tags.append("portrait")
            else:
                tags.append("square")

            # Color analysis
            if image.mode == 'RGB':
                # Get dominant colors
                image_array = np.array(image)
                pixels = image_array.reshape(-1, 3)
                unique_colors, counts = np.unique(pixels, axis=0, return_counts=True)

                # Sort by frequency
                sorted_indices = np.argsort(counts)[::-1]
                dominant_colors = unique_colors[sorted_indices[:5]]

                # Simple color classification
                for color in dominant_colors[:3]:
                    r, g, b = color
                    if r > 200 and g > 200 and b > 200:
                        tags.append("bright")
                        break
                    elif r < 50 and g < 50 and b < 50:
                        tags.append("dark")
                        break

            # Content-based tags from description
            if existing_description:
                desc_lower = existing_description.lower()

                # Common content tags
                content_keywords = {
                    "person": ["person", "people", "man", "woman", "child", "face"],
                    "animal": ["dog", "cat", "bird", "horse", "animal"],
                    "nature": ["tree", "forest", "mountain", "sky", "water", "beach", "sunset"],
                    "food": ["food", "pizza", "cake", "fruit", "vegetable"],
                    "vehicle": ["car", "truck", "bike", "motorcycle", "bus"],
                    "building": ["building", "house", "office", "school", "church"],
                    "text": ["text", "document", "paper", "book", "letter"]
                }

                for category, keywords in content_keywords.items():
                    if any(keyword in desc_lower for keyword in keywords):
                        tags.append(category)
                        break

            # Remove duplicates and return
            return list(set(tags))

        except Exception as e:
            print(f"Error generating smart tags: {e}")
            return ["auto-tagged"]

    def calculate_image_hash(self, image_path):
        """
        Calculate perceptual hash for duplicate detection
        """
        try:
            image = Image.open(image_path)
            # Calculate multiple hashes for better accuracy
            phash = imagehash.phash(image)
            dhash = imagehash.dhash(image)
            ahash = imagehash.average_hash(image)

            return {
                'phash': str(phash),
                'dhash': str(dhash),
                'ahash': str(ahash)
            }
        except Exception as e:
            print(f"Error calculating image hash: {e}")
            return None

    def find_similar_images(self, target_hash, all_hashes, threshold=5):
        """
        Find similar images based on hash distance
        """
        similar_images = []

        try:
            target_phash = imagehash.hex_to_hash(target_hash['phash'])

            for image_id, hash_data in all_hashes.items():
                if image_id == target_hash.get('id'):
                    continue

                try:
                    compare_phash = imagehash.hex_to_hash(hash_data['phash'])
                    distance = target_phash - compare_phash

                    if distance <= threshold:
                        similar_images.append({
                            'image_id': image_id,
                            'similarity_score': max(0, 100 - (distance * 10))  # Convert to percentage
                        })
                except:
                    continue

            # Sort by similarity (highest first)
            similar_images.sort(key=lambda x: x['similarity_score'], reverse=True)
            return similar_images[:10]  # Return top 10 matches

        except Exception as e:
            print(f"Error finding similar images: {e}")
            return []

    def optimize_image(self, image_path, max_size_mb=5, quality=85):
        """
        Optimize image for web using free libraries
        """
        try:
            # Open image
            image = Image.open(image_path)

            # Convert to RGB if necessary
            if image.mode in ('RGBA', 'LA', 'P'):
                # Create white background for transparent images
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
                image = background
            elif image.mode != 'RGB':
                image = image.convert('RGB')

            # Calculate target size (max 5MB)
            max_size_bytes = max_size_mb * 1024 * 1024

            # Get original file size
            original_size = os.path.getsize(image_path)

            if original_size <= max_size_bytes:
                return image_path  # No optimization needed

            # Optimize by resizing if too large
            width, height = image.size
            aspect_ratio = width / height

            # Calculate new dimensions
            if width > height:
                new_width = int((max_size_bytes * 0.1) ** 0.5)  # Rough estimate
                new_height = int(new_width / aspect_ratio)
            else:
                new_height = int((max_size_bytes * 0.1) ** 0.5)
                new_width = int(new_height * aspect_ratio)

            # Resize image
            optimized_image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)

            # Save optimized image
            optimized_path = image_path.replace('.', '_optimized.')
            optimized_image.save(optimized_path, 'JPEG', quality=quality, optimize=True)

            # Check if optimization actually reduced size
            optimized_size = os.path.getsize(optimized_path)
            if optimized_size >= original_size:
                os.remove(optimized_path)
                return image_path

            return optimized_path

        except Exception as e:
            print(f"Error optimizing image: {e}")
            return image_path

    def analyze_image_quality(self, image_path):
        """
        Analyze image quality metrics
        """
        try:
            image = cv2.imread(image_path)

            if image is None:
                return {"error": "Could not load image"}

            # Basic quality metrics
            height, width = image.shape[:2]

            # Sharpness using Laplacian variance
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            sharpness = cv2.Laplacian(gray, cv2.CV_64F).var()

            # Brightness
            brightness = np.mean(gray)

            # Contrast
            contrast = gray.std()

            # Colorfulness (Hasler and Süsstrunk)
            rg = image[:, :, 0] - image[:, :, 1]
            yb = (image[:, :, 0] + image[:, :, 1]) / 2 - image[:, :, 2]
            colorfulness = np.sqrt(np.mean(rg**2) + np.mean(yb**2)) + 0.3 * np.sqrt(np.var(rg) + np.var(yb))

            return {
                "resolution": f"{width}x{height}",
                "sharpness": round(sharpness, 2),
                "brightness": round(brightness, 2),
                "contrast": round(contrast, 2),
                "colorfulness": round(colorfulness, 2),
                "quality_score": self._calculate_quality_score(sharpness, brightness, contrast, width, height)
            }

        except Exception as e:
            print(f"Error analyzing image quality: {e}")
            return {"error": str(e)}

    def _calculate_quality_score(self, sharpness, brightness, contrast, width, height):
        """
        Calculate overall quality score (0-100)
        """
        try:
            # Normalize metrics
            sharpness_score = min(100, sharpness / 500 * 100)  # Typical good sharpness > 500
            brightness_score = 100 - abs(brightness - 128) * 0.5  # Ideal brightness around 128
            contrast_score = min(100, contrast / 50 * 100)  # Typical good contrast > 50
            resolution_score = min(100, (width * height) / (1920 * 1080) * 100)  # Reference: 1080p

            # Weighted average
            weights = [0.3, 0.2, 0.3, 0.2]  # sharpness, brightness, contrast, resolution
            scores = [sharpness_score, brightness_score, contrast_score, resolution_score]

            overall_score = sum(w * s for w, s in zip(weights, scores))
            return round(overall_score, 1)

        except:
            return 50.0  # Default neutral score

    def smart_search(self, query, available_files):
        """
        Perform smart search with natural language understanding
        """
        try:
            query_lower = query.lower()

            # Define search categories and their keywords
            search_categories = {
                "file_type": {
                    "images": ["image", "photo", "picture", "pic", "jpg", "jpeg", "png", "gif"],
                    "videos": ["video", "movie", "film", "mp4", "avi", "mov"],
                    "documents": ["document", "doc", "pdf", "txt", "text"],
                    "audio": ["audio", "music", "song", "mp3", "wav"]
                },
                "content": {
                    "people": ["person", "people", "man", "woman", "child", "face", "portrait"],
                    "nature": ["nature", "landscape", "mountain", "sky", "water", "beach", "forest", "tree"],
                    "animals": ["animal", "dog", "cat", "bird", "pet"],
                    "food": ["food", "pizza", "cake", "fruit", "meal"],
                    "vehicles": ["car", "truck", "bike", "motorcycle", "vehicle"],
                    "buildings": ["building", "house", "office", "school", "architecture"]
                },
                "attributes": {
                    "large": ["large", "big", "huge"],
                    "small": ["small", "tiny", "little"],
                    "recent": ["recent", "new", "latest", "today", "yesterday"],
                    "old": ["old", "ancient", "vintage"]
                }
            }

            # Score each file
            scored_files = []

            for file in available_files:
                score = 0
                reasons = []

                # Exact filename match
                if query_lower in file.get('filename', '').lower():
                    score += 100
                    reasons.append("filename_match")

                # File type matching
                file_type = file.get('file_type', '').lower()
                for category, keywords in search_categories["file_type"].items():
                    if any(keyword in query_lower for keyword in keywords):
                        if category.rstrip('s') in file_type:
                            score += 50
                            reasons.append(f"type_match_{category}")

                # Content matching (from description/tags)
                description = file.get('description', '').lower()
                tags = file.get('tags', '').lower() if file.get('tags') else ''

                for category, keywords in search_categories["content"].items():
                    if any(keyword in query_lower for keyword in keywords):
                        if any(keyword in description for keyword in keywords) or \
                           any(keyword in tags for keyword in keywords):
                            score += 30
                            reasons.append(f"content_match_{category}")

                # Size-based matching
                file_size_mb = file.get('size_mb', 0)
                for category, keywords in search_categories["attributes"].items():
                    if any(keyword in query_lower for keyword in keywords):
                        if category == "large" and file_size_mb > 10:
                            score += 20
                            reasons.append("size_large")
                        elif category == "small" and file_size_mb < 1:
                            score += 20
                            reasons.append("size_small")

                # Date-based matching
                if "recent" in query_lower or "new" in query_lower:
                    # This would need actual date comparison in real implementation
                    score += 15
                    reasons.append("recent_files")

                if score > 0:
                    scored_files.append({
                        'file': file,
                        'score': score,
                        'reasons': reasons
                    })

            # Sort by score (highest first)
            scored_files.sort(key=lambda x: x['score'], reverse=True)

            return scored_files[:20]  # Return top 20 results

        except Exception as e:
            print(f"Error in smart search: {e}")
            return []

# Global AI service instance
ai_service = AIService()
