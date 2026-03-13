import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import numpy as np
import re
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import logging
from datetime import datetime
from app.core.config import settings

logger = logging.getLogger(__name__)

class AIService:
    """AI-powered scam detection service using DistilBERT"""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Scam detection patterns
        self.high_risk_keywords = [
            'urgent', 'immediate action required', 'account suspended',
            'verify your account', 'click here', 'limited time',
            'act now', 'congratulations', 'winner', 'lottery',
            'prize', 'claim now', 'free money', 'guaranteed',
            'risk-free', 'no risk', 'secret', 'exclusive',
            'investment opportunity', 'double your money', 'get rich quick',
            'work from home', 'easy money', 'click immediately',
            'payment required', 'send money', 'wire transfer',
            'gift card', 'bitcoin', 'cryptocurrency', 'wallet'
        ]
        
        self.urgency_patterns = [
            'within 24 hours', 'immediately', 'right now',
            'today only', 'expires soon', 'last chance',
            'don\'t miss out', 'limited offer', 'hurry'
        ]
        
        self.suspicious_url_patterns = [
            r'bit\.ly', r'tinyurl\.com', r't\.co', r'goo\.gl',
            r'shortened', r'redirect', r'\.tk$', r'\.ml$',
            r'\.ga$', r'\.cf$', r'\d+\.\d+\.\d+\.\d+',  # IP addresses
            r'[a-zA-Z]*[0-9]{5,}[a-zA-Z]*',  # Numbers in domain
            r'[a-zA-Z]{50,}',  # Very long domain names
        ]
        
        self.phishing_patterns = [
            r'verify.*account', r'update.*payment', r'confirm.*identity',
            r'suspended.*account', r'security.*alert', r'unusual.*activity',
            r'billing.*issue', r'payment.*failed'
        ]
        
        self.impersonation_brands = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'facebook', 'instagram', 'whatsapp', 'netflix',
            'chase', 'bank of america', 'wells fargo', 'citibank',
            'irs', 'social security', 'fbi', 'cia'
        ]

    async def initialize(self):
        """Initialize the AI model"""
        try:
            logger.info("🤖 Loading AI model...")
            
            # Load model and tokenizer
            model_name = settings.MODEL_NAME
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=2  # Binary classification: scam vs not scam
            )
            
            # Move model to device
            self.model.to(self.device)
            self.model.eval()
            
            # Create pipeline for easier use
            self.pipeline = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=0 if self.device.type == "cuda" else -1,
                return_all_scores=True
            )
            
            logger.info(f"✅ AI model loaded on {self.device}")
            
        except Exception as e:
            logger.error(f"❌ Failed to load AI model: {e}")
            # Fallback to rule-based detection
            self.pipeline = None

    async def analyze_message(self, message: str, url: str = "") -> Dict:
        """Analyze message and URL for scam detection"""
        try:
            # Generate message hash
            message_hash = self.generate_hash(message, url)
            
            # Extract suspicious elements
            flagged_keywords = self.extract_flagged_keywords(message)
            flagged_urls = self.extract_flagged_urls(message, url)
            
            # Calculate various risk factors
            keyword_score = self.analyze_keywords(message)
            urgency_score = self.analyze_urgency(message)
            url_score = self.analyze_url(url)
            phishing_score = self.analyze_phishing(message)
            impersonation_score = self.analyze_impersonation(message)
            
            # AI model prediction (if available)
            ai_score = 0
            if self.pipeline and message.strip():
                try:
                    # Prepare text for model
                    text = f"{message} {url}".strip()
                    if len(text) > 512:
                        text = text[:512]  # Truncate to max length
                    
                    # Get model prediction
                    results = self.pipeline(text)
                    scam_prob = next(r['score'] for r in results[0] if r['label'] == 'LABEL_1')
                    ai_score = scam_prob * 100  # Convert to percentage
                    
                except Exception as e:
                    logger.warning(f"AI model prediction failed: {e}")
                    ai_score = 0
            
            # Calculate overall scam score
            weights = {
                'ai': 0.4 if self.pipeline else 0,
                'keywords': 0.3,
                'urgency': 0.15,
                'url': 0.25,
                'phishing': 0.2,
                'impersonation': 0.1
            }
            
            # Normalize weights if AI is not available
            if not self.pipeline:
                weights = {k: v / (1 - weights['ai']) for k, v in weights.items() if k != 'ai'}
            
            scam_score = min(100, round(
                ai_score * weights.get('ai', 0) +
                keyword_score * weights.get('keywords', 0) +
                urgency_score * weights.get('urgency', 0) +
                url_score * weights.get('url', 0) +
                phishing_score * weights.get('phishing', 0) +
                impersonation_score * weights.get('impersonation', 0)
            ))
            
            # Determine risk level
            risk_level = self.get_risk_level(scam_score)
            
            # Generate explanation
            explanation = self.generate_explanation(
                scam_score, flagged_keywords, flagged_urls, url
            )
            
            # URL analysis
            url_analysis = self.get_url_analysis(url)
            
            return {
                'scam_score': scam_score,
                'risk_level': risk_level,
                'flagged_keywords': flagged_keywords,
                'flagged_urls': flagged_urls,
                'explanation': explanation,
                'message_hash': message_hash,
                'url_analysis': url_analysis,
                'ai_confidence': ai_score if self.pipeline else 0,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Analysis failed: {e}")
            raise

    def analyze_keywords(self, text: str) -> float:
        """Analyze text for suspicious keywords"""
        if not text:
            return 0
        
        lower_text = text.lower()
        score = 0
        matches = 0

        for keyword in self.high_risk_keywords:
            if keyword.lower() in lower_text:
                score += 15
                matches += 1

        # Bonus for multiple keywords
        if matches > 3:
            score += 20
        if matches > 5:
            score += 30

        return min(100, score)

    def analyze_urgency(self, text: str) -> float:
        """Analyze text for urgency indicators"""
        if not text:
            return 0
        
        lower_text = text.lower()
        score = 0

        for pattern in self.urgency_patterns:
            if pattern in lower_text:
                score += 25

        # All caps urgency
        if text == text.upper() and len(text) > 10:
            score += 30

        # Exclamation marks
        exclamation_count = text.count('!')
        if exclamation_count > 2:
            score += 15

        return min(100, score)

    def analyze_url(self, url: str) -> float:
        """Analyze URL for suspicious patterns"""
        if not url:
            return 0
        
        score = 0

        # Check suspicious patterns
        for pattern in self.suspicious_url_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                score += 30

        # URL length analysis
        if len(url) > 100:
            score += 20
        if len(url) > 200:
            score += 30

        # HTTPS check
        if not url.startswith('https://') and not url.startswith('http://localhost'):
            score += 25

        # Domain analysis
        try:
            domain = urlparse(url).netloc
            
            # Typosquatting detection
            if self.is_typosquatting(domain):
                score += 40

            # Multiple subdomains
            subdomain_count = domain.count('.') - 1
            if subdomain_count > 2:
                score += 20

        except Exception:
            # Invalid URL
            score += 50

        return min(100, score)

    def analyze_phishing(self, text: str) -> float:
        """Analyze text for phishing patterns"""
        if not text:
            return 0
        
        score = 0

        for pattern in self.phishing_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 35

        return min(100, score)

    def analyze_impersonation(self, text: str) -> float:
        """Analyze text for brand impersonation"""
        if not text:
            return 0
        
        lower_text = text.lower()
        score = 0

        for brand in self.impersonation_brands:
            if brand in lower_text:
                score += 20

        return min(100, score)

    def extract_flagged_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords from text"""
        if not text:
            return []
        
        lower_text = text.lower()
        flagged = []

        for keyword in self.high_risk_keywords:
            if keyword.lower() in lower_text:
                flagged.append(keyword)

        return list(set(flagged))  # Remove duplicates

    def extract_flagged_urls(self, text: str, main_url: str = "") -> List[str]:
        """Extract suspicious URLs from text"""
        urls = []
        
        # Extract URLs from text
        url_pattern = r'https?:\/\/[^\s<>"{}|\\^`\[\]]+'
        text_urls = re.findall(url_pattern, text)
        
        all_urls = text_urls
        if main_url:
            all_urls.append(main_url)

        for url in all_urls:
            if self.analyze_url(url) > 30:
                urls.append(url)

        return list(set(urls))  # Remove duplicates

    def generate_explanation(self, score: float, keywords: List[str], 
                           urls: List[str], main_url: str) -> str:
        """Generate human-readable explanation"""
        reasons = []

        if score >= 80:
            reasons.append("⚠️ **High Risk**: Multiple scam indicators detected")
        elif score >= 60:
            reasons.append("⚡ **Medium Risk**: Some suspicious patterns found")
        elif score >= 40:
            reasons.append("🔍 **Low Risk**: Minor suspicious elements")
        else:
            reasons.append("✅ **Very Low Risk**: Appears to be legitimate")

        if keywords:
            reasons.append(f"🔑 **Suspicious Keywords**: {', '.join(keywords[:3])}")

        if urls or main_url:
            reasons.append(f"🔗 **Suspicious URLs**: {len(urls) + (1 if main_url else 0)} detected")

        if score >= 60:
            reasons.append("🚫 **Recommendation**: Do not click links or share personal information")

        return " | ".join(reasons)

    def get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 80:
            return 'SCAM'
        elif score >= 60:
            return 'HIGH_RISK'
        elif score >= 40:
            return 'SUSPICIOUS'
        elif score >= 20:
            return 'LOW_RISK'
        else:
            return 'SAFE'

    def get_url_analysis(self, url: str) -> Dict:
        """Analyze URL and return detailed analysis"""
        if not url:
            return {'status': 'none', 'message': 'No URL provided'}

        score = self.analyze_url(url)
        
        if score >= 80:
            return {'status': 'scam', 'message': 'This URL appears to be malicious'}
        elif score >= 60:
            return {'status': 'suspicious', 'message': 'This URL shows suspicious characteristics'}
        elif score >= 40:
            return {'status': 'caution', 'message': 'Exercise caution with this URL'}
        else:
            return {'status': 'safe', 'message': 'This URL appears to be legitimate'}

    def is_typosquatting(self, domain: str) -> bool:
        """Check if domain is typosquatting a legitimate domain"""
        legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'netflix.com', 'instagram.com', 'twitter.com',
            'linkedin.com', 'youtube.com', 'paypal.com', 'chase.com'
        ]

        for legit in legitimate_domains:
            if self.levenshtein_distance(domain, legit) <= 2 and domain != legit:
                return True

        return False

    def levenshtein_distance(self, str1: str, str2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(str1) < len(str2):
            return self.levenshtein_distance(str2, str1)

        if len(str2) == 0:
            return len(str1)

        previous_row = list(range(len(str2) + 1))
        for i, c1 in enumerate(str1):
            current_row = [i + 1]
            for j, c2 in enumerate(str2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def generate_hash(self, message: str, url: str = "") -> str:
        """Generate SHA256 hash of message and URL"""
        content = f"{message}{url}"
        return hashlib.sha256(content.encode()).hexdigest()

    async def cleanup(self):
        """Cleanup resources"""
        if self.model:
            del self.model
        if self.tokenizer:
            del self.tokenizer
        if self.pipeline:
            del self.pipeline
        
        # Clear GPU cache
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        
        logger.info("🧹 AI service cleanup complete")
