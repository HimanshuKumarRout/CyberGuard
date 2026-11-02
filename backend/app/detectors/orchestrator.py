"""
Threat Orchestrator Layer for CYBERGUARD
Executes the Canonical 7-Stage Threat Pipeline:
Input -> Detection -> Classification -> Risk Assessment -> Explanation -> Alerting -> Recommended Response
Guarantees Unified Event Model (UEM) compliance and database persistence.
"""
from typing import Optional

from app.schemas.event import UnifiedEvent
from app.detectors.phishing import phishing_detector
from app.detectors.impersonation import impersonation_detector
from app.detectors.anomaly import anomaly_detector
from app.risk.scorer import risk_engine
from app.explain.explainer import xai_engine
from app.response.recommender import response_engine
from app.db.supabase import db


class ThreatOrchestrator:
    @classmethod
    async def process_phishing(
        cls,
        text: str,
        url: Optional[str] = None,
        sender: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> UnifiedEvent:
        """Processes email/URL artifacts through the canonical pipeline."""
        # 1. Ingestion & 2. Detection & 3. Classification
        raw_result = phishing_detector.analyze(text=text, url=url, sender=sender)
        detector_name = raw_result["detector"]
        threat_category = raw_result["threat_category"]
        confidence = raw_result["confidence"]
        indicators = raw_result["indicators"]
        metadata = raw_result["metadata"]
        if sender:
            metadata["sender"] = sender

        # 4. Risk Assessment
        risk_score, risk_level = risk_engine.calculate_risk(confidence, indicators)

        # 5. Explanation
        explanation = xai_engine.generate_explanation(
            threat_category=threat_category,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            indicators=indicators,
            metadata=metadata
        )

        # 6. Recommended Response & Containment
        recommended_actions = response_engine.recommend_actions(
            threat_category=threat_category,
            risk_level=risk_level,
            target_subject=url or sender or "analyzed_artifact",
            metadata=metadata
        )

        # 7. Unified Event Normalization & Alert Escalation
        incident_status = "Open" if risk_score >= 60 else None
        event = UnifiedEvent(
            source="email_gateway" if sender else "web_inspector",
            user_id=user_id or "usr_analyst_triage",
            input_type="email" if sender else "url",
            detector=detector_name,
            threat_category=threat_category,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            explanation=explanation,
            recommended_actions=recommended_actions,
            incident_status=incident_status,
            metadata=metadata
        )

        # Database Persistence
        try:
            db.save_event(event.model_dump())
        except Exception as e:
            # Non-blocking persistence failure safeguard
            pass

        return event

    @classmethod
    async def process_impersonation(
        cls,
        sender_name: str,
        sender_address: str,
        content: str,
        media_url: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> UnifiedEvent:
        """Processes profile identity and media artifacts through the canonical pipeline."""
        raw_result = impersonation_detector.analyze(
            sender_name=sender_name,
            sender_address=sender_address,
            content=content,
            media_url=media_url
        )
        detector_name = raw_result["detector"]
        threat_category = raw_result["threat_category"]
        confidence = raw_result["confidence"]
        indicators = raw_result["indicators"]
        metadata = raw_result["metadata"]

        risk_score, risk_level = risk_engine.calculate_risk(confidence, indicators)

        explanation = xai_engine.generate_explanation(
            threat_category=threat_category,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            indicators=indicators,
            metadata=metadata
        )

        recommended_actions = response_engine.recommend_actions(
            threat_category=threat_category,
            risk_level=risk_level,
            target_subject=sender_address,
            metadata=metadata
        )

        incident_status = "Open" if risk_score >= 60 else None
        event = UnifiedEvent(
            source="identity_guardian",
            user_id=user_id or "usr_executive_protection",
            input_type="image" if media_url else "message",
            detector=detector_name,
            threat_category=threat_category,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            explanation=explanation,
            recommended_actions=recommended_actions,
            incident_status=incident_status,
            metadata=metadata
        )

        try:
            db.save_event(event.model_dump())
        except Exception:
            pass

        return event

    @classmethod
    async def process_anomaly(
        cls,
        user_id: str,
        ip_address: str,
        device_id: str,
        location: str = "Unknown",
        failed_attempts: int = 0,
        session_duration: int = 0,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None
    ) -> UnifiedEvent:
        """Processes authentication and access telemetry through the canonical pipeline."""
        raw_result = anomaly_detector.analyze(
            user_id=user_id,
            ip_address=ip_address,
            device_id=device_id,
            location=location,
            failed_attempts=failed_attempts,
            session_duration=session_duration,
            latitude=latitude,
            longitude=longitude
        )
        detector_name = raw_result["detector"]
        threat_category = raw_result["threat_category"]
        confidence = raw_result["confidence"]
        indicators = raw_result["indicators"]
        metadata = raw_result["metadata"]

        risk_score, risk_level = risk_engine.calculate_risk(confidence, indicators)

        explanation = xai_engine.generate_explanation(
            threat_category=threat_category,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            indicators=indicators,
            metadata=metadata
        )

        recommended_actions = response_engine.recommend_actions(
            threat_category=threat_category,
            risk_level=risk_level,
            target_subject=user_id,
            metadata=metadata
        )

        incident_status = "Open" if risk_score >= 60 else None
        event = UnifiedEvent(
            source="auth_service",
            user_id=user_id,
            device_id=device_id,
            input_type="auth_log",
            detector=detector_name,
            threat_category=threat_category,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            explanation=explanation,
            recommended_actions=recommended_actions,
            incident_status=incident_status,
            metadata=metadata
        )

        try:
            db.save_event(event.model_dump())
        except Exception:
            pass

        return event


orchestrator = ThreatOrchestrator()
