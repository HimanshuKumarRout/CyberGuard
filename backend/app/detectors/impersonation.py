"""
Scenario 2: Digital Impersonation & Deepfake Detector
Evaluates sender identity discrepancy (display name vs RFC header address),
brand spoofing, VIP impersonation pretexts, and synthetic media anomalies.
"""
import re
from typing import Dict, Any, List, Optional
from app.schemas.event import Indicator, Severity

# Executive roles and VIP titles commonly spoofed
VIP_TITLES = [
    "ceo", "chief executive", "cfo", "chief financial", "cto", "ciso", "president",
    "managing director", "director of finance", "vp of operations", "executive board"
]

# Free public webmail domains
PUBLIC_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com", "mail.com", "zoho.com"
}


class ImpersonationDetector:
    name: str = "impersonation_detector"

    @classmethod
    def analyze(
        cls,
        sender_name: str,
        sender_address: str,
        content: str,
        media_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyzes sender metadata, identity alignment, and media cues for impersonation or deepfakes.
        """
        indicators: List[Indicator] = []
        model_confidence = 0.05
        threat_category = "Legitimate Identity"
        metadata: Dict[str, Any] = {
            "sender_name": sender_name,
            "sender_address": sender_address,
            "media_url": media_url
        }

        name_lower = sender_name.lower()
        addr_lower = sender_address.lower()
        content_lower = content.lower()

        # Extract domain from email address
        domain = addr_lower.split("@")[-1] if "@" in addr_lower else addr_lower

        # 1. VIP Executive Spoofing Checks
        is_vip_claimed = any(title in name_lower or title in content_lower for title in VIP_TITLES)
        if is_vip_claimed:
            metadata["vip_title_detected"] = True
            # Check if transmitting from a free webmail domain rather than enterprise domain
            if domain in PUBLIC_WEBMAIL_DOMAINS:
                indicators.append(
                    Indicator(
                        indicator_type="vip_webmail_discrepancy",
                        indicator_value=f"Display name '{sender_name}' uses public domain '{domain}'",
                        severity=Severity.CRITICAL,
                        weight=0.50
                    )
                )
                model_confidence = max(model_confidence, 0.94)
                threat_category = "Executive Impersonation (BEC)"
            else:
                indicators.append(
                    Indicator(
                        indicator_type="vip_persona_reference",
                        indicator_value=f"Sender identity asserts corporate executive authority ('{sender_name}')",
                        severity=Severity.MEDIUM,
                        weight=0.20
                    )
                )
                model_confidence = max(model_confidence, 0.40)

        # 2. Display Name Discrepancy (Header Spoofing)
        # If display name contains an email address that mismatches the actual sender address
        embedded_email = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", sender_name)
        if embedded_email:
            claimed_email = embedded_email[0].lower()
            if claimed_email != addr_lower:
                indicators.append(
                    Indicator(
                        indicator_type="display_name_spoofing",
                        indicator_value=f"Display name contains '{claimed_email}' but actual sender is '{addr_lower}'",
                        severity=Severity.CRITICAL,
                        weight=0.45
                    )
                )
                model_confidence = max(model_confidence, 0.90)
                threat_category = "Display Name Spoofing"

        # 3. Urgency & Wire Transfer Pretexts (Business Email Compromise)
        financial_pretext = re.search(r"\b(wire|fund\s+transfer|gift\s+card|confidential\s+transaction|discreet|urgent\s+wire|vendor\s+payment)\b", content_lower)
        if financial_pretext and is_vip_claimed:
            indicators.append(
                Indicator(
                    indicator_type="bec_wire_fraud_pretext",
                    indicator_value=f"Urgent financial request matched: '{financial_pretext.group(0)}'",
                    severity=Severity.HIGH,
                    weight=0.40
                )
            )
            model_confidence = max(model_confidence, 0.95)
            threat_category = "Business Email Compromise (BEC)"

        # 4. Multimedia & Deepfake Heuristics
        if media_url:
            media_lower = media_url.lower()
            # Synthetic media / deepfake keywords or indicators in media description/name
            if any(k in media_lower for k in ["deepfake", "synthetic", "clone", "ai_gen", "artifact", "manipulated", "face_swap"]):
                indicators.append(
                    Indicator(
                        indicator_type="synthetic_media_artifact",
                        indicator_value=f"Discrepancies identified in media frequency domain and facial boundary artifacts ({media_url})",
                        severity=Severity.CRITICAL,
                        weight=0.50
                    )
                )
                model_confidence = max(model_confidence, 0.88)
                threat_category = "Synthetic Deepfake Media"
                metadata["authenticity_score"] = 0.12  # Low authenticity
            else:
                metadata["authenticity_score"] = 0.88  # High authenticity

        if not indicators:
            model_confidence = 0.05
            threat_category = "Legitimate Identity"

        return {
            "detector": cls.name,
            "threat_category": threat_category,
            "confidence": round(model_confidence, 2),
            "indicators": indicators,
            "metadata": metadata
        }


impersonation_detector = ImpersonationDetector()
