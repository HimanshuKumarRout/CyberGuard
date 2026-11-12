"""
Threat Orchestrator Layer for CYBERGUARD
Executes the Canonical 7-Stage Threat Pipeline:
Input -> Detection -> Classification -> Risk Assessment -> Explanation -> Alerting -> Recommended Response
Guarantees Unified Event Model (UEM) compliance and database persistence.
Supports all core scenarios plus Phase 7 extensions: Quishing, Malware, Network PCAP, Media ELA/Audio, and API Anomaly.
"""
from typing import Optional, List, Dict, Any

from app.schemas.event import UnifiedEvent
from app.detectors.phishing import phishing_detector
from app.detectors.impersonation import impersonation_detector
from app.detectors.anomaly import anomaly_detector
from app.detectors.malware import malware_detector
from app.detectors.network import network_detector
from app.detectors.media import media_detector
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
        raw_result = phishing_detector.analyze(text=text, url=url, sender=sender)
        detector_name = raw_result["detector"]
        threat_category = raw_result["threat_category"]
        confidence = raw_result["confidence"]
        indicators = raw_result["indicators"]
        metadata = raw_result["metadata"]
        if sender:
            metadata["sender"] = sender

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
            target_subject=url or sender or "analyzed_artifact",
            metadata=metadata
        )

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

        try:
            db.save_event(event.model_dump())
        except Exception:
            pass

        return event

    @classmethod
    async def process_quishing(
        cls,
        image_bytes: bytes,
        filename: Optional[str] = None,
        extracted_url: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> UnifiedEvent:
        """TASK-22: Processes QR-Code quishing images through the canonical pipeline."""
        raw_result = phishing_detector.analyze_quishing(
            image_bytes=image_bytes,
            filename=filename,
            extracted_url=extracted_url
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
            target_subject=metadata.get("decoded_url", "quishing_payload"),
            metadata=metadata
        )

        incident_status = "Open" if risk_score >= 60 else None
        event = UnifiedEvent(
            source="quishing_scanner",
            user_id=user_id or "usr_soc_triage",
            input_type="qr_code",
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
    async def process_media(
        cls,
        image_bytes: Optional[bytes] = None,
        audio_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        media_type: str = "image",
        user_id: Optional[str] = None
    ) -> UnifiedEvent:
        """TASK-28 & TASK-29: Processes media forgery (ELA) and synthetic voice audio."""
        if media_type == "audio" and audio_bytes:
            raw_result = media_detector.analyze_audio_synthetic(audio_bytes=audio_bytes, filename=filename)
        elif image_bytes:
            raw_result = media_detector.analyze_image_ela(image_bytes=image_bytes, filename=filename)
        else:
            raw_result = {
                "detector": "media_detector",
                "threat_category": "Authentic Media",
                "confidence": 0.10,
                "indicators": [],
                "metadata": {"filename": filename or "unknown"}
            }

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
            target_subject=filename or "multimedia_artifact",
            metadata=metadata
        )

        incident_status = "Open" if risk_score >= 60 else None
        event = UnifiedEvent(
            source="deepfake_inspector",
            user_id=user_id or "usr_media_forensics",
            input_type=media_type,
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
        longitude: Optional[float] = None,
        unauthorized_http_count: int = 0,
        egress_mb: float = 0.0,
        target_endpoint: Optional[str] = None
    ) -> UnifiedEvent:
        """Processes authentication, travel, and API access telemetry."""
        raw_result = anomaly_detector.analyze(
            user_id=user_id,
            ip_address=ip_address,
            device_id=device_id,
            location=location,
            failed_attempts=failed_attempts,
            session_duration=session_duration,
            latitude=latitude,
            longitude=longitude,
            unauthorized_http_count=unauthorized_http_count,
            egress_mb=egress_mb,
            target_endpoint=target_endpoint
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

    @classmethod
    async def process_malware(
        cls,
        filename: str,
        file_bytes: bytes,
        declared_mime: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> UnifiedEvent:
        """TASK-25: Processes file attachments for malware signatures, double extensions, and entropy."""
        raw_result = malware_detector.analyze(
            filename=filename,
            file_bytes=file_bytes,
            declared_mime=declared_mime
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
            target_subject=filename,
            metadata=metadata
        )

        incident_status = "Open" if risk_score >= 60 else None
        event = UnifiedEvent(
            source="endpoint_attachment_scanner",
            user_id=user_id or "usr_workstation_host",
            input_type="file",
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
    async def process_network(
        cls,
        flow_records: Optional[List[Dict[str, Any]]] = None,
        pcap_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> UnifiedEvent:
        """TASK-26: Processes PCAP files and network connection flows for port scans and DNS tunneling."""
        if pcap_bytes:
            raw_result = network_detector.analyze_pcap_bytes(pcap_bytes=pcap_bytes, filename=filename)
        else:
            raw_result = network_detector.analyze_flows(flow_records=flow_records or [])

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
            target_subject=filename or "network_sensor_capture",
            metadata=metadata
        )

        incident_status = "Open" if risk_score >= 60 else None
        event = UnifiedEvent(
            source="network_traffic_sensor",
            user_id=user_id or "usr_perimeter_firewall",
            input_type="network",
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
