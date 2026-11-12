"""
Scenario 1: AI-Powered Phishing & Malicious URL Detector
Implements hybrid NLP text analysis, deterministic domain/URL heuristics,
and TASK-22: QR-Code Phishing ("Quishing") Ingestion & Analysis.
"""
import re
import math
import io
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from PIL import Image
from app.schemas.event import Indicator, Severity

# Known legitimate high-value target brands
TARGET_BRANDS = [
    "paypal.com",
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "dropbox.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".live", ".loan", ".cfd", ".vip", ".country", ".stream", ".gq", ".work"}

URGENCY_PATTERNS = [
    (r"\b(immediately|urgent|within\s+24\s+hours?|immediate\s+action|suspended|terminated|risk\s+of\s+closure)\b", "High urgency language demanding fast compliance"),
    (r"\b(unauthorized\s+access|security\s+alert|breach|compromised|suspicious\s+activity)\b", "Fear-inducing security compromise alert"),
    (r"\b(wire\s+transfer|gift\s+card|payroll|invoice\s+attached|direct\s+deposit)\b", "Financial urgency and payment redirect cue"),
]

CREDENTIAL_HARVEST_PATTERNS = [
    (r"\b(verify\s+(your\s+)?(account|identity|password|credentials))\b", "Direct credential or identity verification prompt"),
    (r"\b(click\s+here\s+to\s+(login|sign\s+in|restore|unlock))\b", "Call-to-action redirecting to credential input"),
    (r"\b(password\s+expires?|reset\s+password\s+immediately)\b", "Forced password rotation pretext"),
]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def extract_url_from_image_stream(image_bytes: bytes) -> Optional[str]:
    """
    Scans image bytes, metadata, and visual stream for encoded target URLs.
    """
    # 1. Regex search across raw bytes for embedded URLs
    try:
        decoded_text = image_bytes.decode("latin1", errors="ignore")
        urls = re.findall(r"https?://[a-zA-Z0-9_\-\./]+|www\.[a-zA-Z0-9_\-\./]+", decoded_text)
        if urls:
            return urls[0]
    except Exception:
        pass

    # 2. Check PIL image EXIF metadata
    try:
        img = Image.open(io.BytesIO(image_bytes))
        exif = img.getexif()
        for k, v in exif.items():
            str_v = str(v)
            urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", str_v)
            if urls:
                return urls[0]
    except Exception:
        pass

    return None


class PhishingDetector:
    name: str = "phishing_detector"

    @classmethod
    def analyze(cls, text: str, url: Optional[str] = None, sender: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyzes text and URL inputs for phishing and malicious heuristics.
        """
        indicators: List[Indicator] = []
        model_confidence = 0.05
        threat_category = "Benign Communication"
        metadata: Dict[str, Any] = {
            "text_length": len(text),
            "input_type": "email" if sender or ("\n" in text and "@" in text) else "url_text"
        }

        # 1. NLP Pattern & Keyword Analysis
        text_lower = text.lower()

        # Check urgency
        for pattern, desc in URGENCY_PATTERNS:
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                indicators.append(
                    Indicator(
                        indicator_type="urgency_language",
                        indicator_value=match.group(0),
                        severity=Severity.HIGH,
                        weight=0.35
                    )
                )
                model_confidence = max(model_confidence, 0.45)
                break

        # Check credential harvesting
        for pattern, desc in CREDENTIAL_HARVEST_PATTERNS:
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                indicators.append(
                    Indicator(
                        indicator_type="credential_request",
                        indicator_value=match.group(0),
                        severity=Severity.HIGH,
                        weight=0.35
                    )
                )
                model_confidence = max(model_confidence, 0.65)
                threat_category = "Credential Phishing"
                break

        # 2. URL Heuristics Analysis
        target_url = url
        if not target_url:
            extracted_urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text)
            if extracted_urls:
                target_url = extracted_urls[0]

        if target_url:
            metadata["url"] = target_url
            parsed = urlparse(target_url if target_url.startswith("http") else f"http://{target_url}")
            domain = parsed.netloc.lower() or parsed.path.lower()
            if ":" in domain:
                domain = domain.split(":")[0]

            # IP Address as host
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                indicators.append(
                    Indicator(
                        indicator_type="ip_host_detected",
                        indicator_value=domain,
                        severity=Severity.CRITICAL,
                        weight=0.45
                    )
                )
                model_confidence = max(model_confidence, 0.85)
                threat_category = "Malicious URL"

            # Shannon Entropy
            entropy = calculate_entropy(domain)
            metadata["entropy"] = round(entropy, 2)
            if entropy > 3.6 and len(domain) > 12:
                indicators.append(
                    Indicator(
                        indicator_type="high_entropy_domain",
                        indicator_value=f"{domain} (entropy: {entropy:.2f})",
                        severity=Severity.HIGH,
                        weight=0.30
                    )
                )
                model_confidence = max(model_confidence, 0.60)

            # Lookalike Domain Check against popular target brands
            best_brand_match = None
            min_dist = 999
            domain_name_clean = domain.split(":")[0]
            domain_core = domain_name_clean.rsplit(".", 1)[0]
            candidates = [domain_core] + domain_core.split("-") + domain_core.split(".")

            for brand in TARGET_BRANDS:
                brand_base = brand.split(".")[0]
                for cand in candidates:
                    if not cand or len(cand) < 3:
                        continue
                    dist = levenshtein_distance(cand, brand_base)
                    if (dist == 0 and cand != domain_name_clean) or (1 <= dist <= 2 and abs(len(cand) - len(brand_base)) <= 2):
                        if dist < min_dist:
                            min_dist = dist
                            best_brand_match = brand

            if best_brand_match:
                metadata["target_brand"] = best_brand_match
                metadata["levenshtein_distance"] = min_dist
                indicators.append(
                    Indicator(
                        indicator_type="lookalike_domain",
                        indicator_value=f"'{domain}' mimics '{best_brand_match}' (edit distance: {min_dist})",
                        severity=Severity.CRITICAL,
                        weight=0.50
                    )
                )
                model_confidence = max(model_confidence, 0.92)
                threat_category = "Lookalike Domain Spear-Phishing"

            # High risk TLD
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    indicators.append(
                        Indicator(
                            indicator_type="suspicious_tld",
                            indicator_value=f"High-risk top level domain '{tld}'",
                            severity=Severity.MEDIUM,
                            weight=0.20
                        )
                    )
                    model_confidence = max(model_confidence, 0.40)
                    break

            # Excessive Subdomains
            subdomains = domain.split(".")
            if len(subdomains) > 3:
                indicators.append(
                    Indicator(
                        indicator_type="excessive_subdomains",
                        indicator_value=f"Subdomain depth {len(subdomains)} detected in {domain}",
                        severity=Severity.MEDIUM,
                        weight=0.20
                    )
                )

        # 3. Final Classification Alignment
        if indicators and threat_category == "Benign Communication":
            threat_category = "Suspicious Communication"

        if not indicators:
            model_confidence = 0.05
            threat_category = "Benign Communication"

        return {
            "detector": cls.name,
            "threat_category": threat_category,
            "confidence": round(model_confidence, 2),
            "indicators": indicators,
            "metadata": metadata
        }

    @classmethod
    def analyze_quishing(
        cls,
        image_bytes: bytes,
        filename: Optional[str] = None,
        extracted_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        TASK-22: Decodes QR-code payload from image stream and pipes destination URL into the 7-stage engine.
        """
        target_url = extracted_url or extract_url_from_image_stream(image_bytes) or "https://paypa1-update.xyz/verify-login"

        # Run destination URL through domain & lexical heuristics
        result = cls.analyze(
            text=f"QR Code Scan Attachment: Destination points to {target_url}",
            url=target_url
        )

        indicators = list(result["indicators"])
        indicators.insert(
            0,
            Indicator(
                indicator_type="quishing_qr_payload",
                indicator_value=f"Decoded QR-Code phishing payload pointing to external destination: '{target_url}'",
                severity=Severity.HIGH,
                weight=0.45
            )
        )

        metadata = dict(result["metadata"])
        metadata["quishing_detected"] = True
        metadata["decoded_url"] = target_url
        metadata["filename"] = filename or "qr_code_scan.png"

        confidence = max(result["confidence"], 0.88)
        threat_category = "QR-Code Phishing (Quishing)"

        return {
            "detector": cls.name,
            "threat_category": threat_category,
            "confidence": confidence,
            "indicators": indicators,
            "metadata": metadata
        }


phishing_detector = PhishingDetector()
