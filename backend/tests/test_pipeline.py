"""
Automated Integration & Unit Testing for CYBERGUARD
Validates Schemas, Detectors, Risk Formula, Explainability, and 7-stage Canonical Pipeline.
"""
import pytest
from app.schemas.event import UnifiedEvent, Indicator, Explanation, ResponseAction, RiskLevel, Severity
from app.risk.scorer import risk_engine
from app.explain.explainer import xai_engine
from app.detectors.phishing import phishing_detector, calculate_entropy, levenshtein_distance
from app.detectors.impersonation import impersonation_detector
from app.detectors.anomaly import anomaly_detector, haversine_distance_km
from app.detectors.orchestrator import orchestrator


def test_schema_instantiation():
    """Validates Unified Event Model compliance and Pydantic validation."""
    ind = Indicator(
        indicator_type="lookalike_domain",
        indicator_value="micros0ft.com",
        severity=Severity.CRITICAL,
        weight=0.5
    )
    exp = Explanation(
        summary="Critical Risk: Phishing domain detected",
        evidence=["Domain distance 1 to microsoft.com"],
        reasoning="Targeted brand deception observed."
    )
    action = ResponseAction(
        action_type="block_url",
        target="micros0ft.com",
        simulation_status="Simulated"
    )
    event = UnifiedEvent(
        input_type="email",
        detector="phishing_detector",
        threat_category="Credential Phishing",
        confidence=0.92,
        risk_score=85,
        risk_level=RiskLevel.CRITICAL,
        indicators=[ind],
        explanation=exp,
        recommended_actions=[action]
    )
    assert event.event_id.startswith("evt_")
    assert event.risk_score == 85
    assert len(event.indicators) == 1


def test_risk_scoring_bounds():
    """Validates risk formula bounds and edge case clamping [0, 100]."""
    # Safe edge case: confidence 0.0, no indicators -> 0
    score, level = risk_engine.calculate_risk(0.0, [])
    assert score == 0
    assert level == RiskLevel.SAFE

    # Critical max case: confidence 1.0, multiple critical indicators -> max 100
    crit_ind = [
        Indicator(indicator_type="t1", indicator_value="v1", severity=Severity.CRITICAL, weight=0.5),
        Indicator(indicator_type="t2", indicator_value="v2", severity=Severity.CRITICAL, weight=0.5),
    ]
    score_max, level_max = risk_engine.calculate_risk(1.0, crit_ind)
    assert score_max == 100
    assert level_max == RiskLevel.CRITICAL


def test_levenshtein_and_entropy():
    """Validates mathematical string metrics for domain inspection."""
    dist = levenshtein_distance("paypa1", "paypal")
    assert dist == 1

    dist_identical = levenshtein_distance("microsoft", "microsoft")
    assert dist_identical == 0

    entropy = calculate_entropy("abcdefghijklmnopqrstuvwxyz")
    assert entropy > 4.0


def test_phishing_detector_lookalike():
    """Scenario 1: Detects lookalike domain and urgency."""
    result = phishing_detector.analyze(
        text="Urgent: Your account is suspended within 24 hours. Reset password immediately.",
        url="http://paypa1-security.xyz"
    )
    assert result["confidence"] >= 0.80
    assert any(ind.indicator_type == "lookalike_domain" for ind in result["indicators"])
    assert any(ind.indicator_type == "urgency_language" for ind in result["indicators"])


def test_impersonation_detector_vip():
    """Scenario 2: Detects VIP display name paired with free public webmail."""
    result = impersonation_detector.analyze(
        sender_name="CEO Satya Nadella",
        sender_address="satya.nadella.exec@gmail.com",
        content="Please wire payment to the overseas account urgently."
    )
    assert result["confidence"] >= 0.90
    assert "BEC" in result["threat_category"] or "Executive Impersonation" in result["threat_category"]
    assert any(ind.indicator_type == "vip_webmail_discrepancy" for ind in result["indicators"])


def test_anomaly_impossible_travel():
    """Scenario 3: Computes Haversine distance and flags > 900 km/h."""
    # Tokyo to New York is ~10,800 km. In 0.5 hours that is > 20,000 km/h!
    dist = haversine_distance_km((35.6762, 139.6503), (40.7128, -74.0060))
    assert dist > 10000
    result = anomaly_detector.analyze(
        user_id="usr_94821",
        ip_address="133.1.2.3",
        device_id="dev_unknown",
        location="Tokyo, Japan"
    )
    assert result["confidence"] >= 0.90
    assert result["threat_category"] == "Impossible Travel Anomaly"
    assert any(ind.indicator_type == "impossible_travel_velocity" for ind in result["indicators"])


def test_explainability_zero_naked_alerts():
    """Rule 1.3: Verifies all explanations include summary, evidence, and reasoning."""
    crit_ind = [
        Indicator(indicator_type="lookalike_domain", indicator_value="micros0ft.xyz", severity=Severity.CRITICAL, weight=0.5)
    ]
    exp = xai_engine.generate_explanation(
        threat_category="Credential Phishing",
        risk_level=RiskLevel.CRITICAL,
        risk_score=92,
        confidence=0.95,
        indicators=crit_ind,
        metadata={"levenshtein_distance": 1, "target_brand": "microsoft.com"}
    )
    assert len(exp.summary) > 10
    assert len(exp.evidence) >= 1
    assert len(exp.reasoning) > 20


@pytest.mark.asyncio
async def test_end_to_end_pipeline():
    """Validates full 7-stage threat processing lifecycle through orchestrator."""
    event = await orchestrator.process_phishing(
        text="Security Alert: unauthorized access detected on your account. Verify identity immediately.",
        url="http://micros0ft-login.com"
    )
    assert event.event_id.startswith("evt_")
    assert event.risk_score >= 60
    assert event.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert len(event.indicators) >= 1
    assert event.explanation.summary != ""
    assert len(event.recommended_actions) >= 1
    assert event.incident_status == "Open"


# =========================================================================
# Phase 7 Gap Closure Test Suite (TASK-22 through TASK-29)
# =========================================================================

def test_quishing_detector():
    """TASK-22: Validates QR-Code quishing analysis and lookalike domain extraction."""
    # Test quishing analysis with decoded URL
    result = phishing_detector.analyze_quishing(
        image_bytes=b"dummy_qr_code_image_bytes",
        filename="payroll_qr.png",
        extracted_url="https://paypa1-update.xyz/verify-login"
    )
    assert result["confidence"] >= 0.85
    assert result["threat_category"] == "QR-Code Phishing (Quishing)"
    assert any(ind.indicator_type == "quishing_qr_payload" for ind in result["indicators"])
    assert any(ind.indicator_type == "lookalike_domain" for ind in result["indicators"])


def test_academic_and_government_impersonation():
    """TASK-24: Validates academic and government authority persona detection."""
    # Academic Dean impersonation
    acad_res = impersonation_detector.analyze(
        sender_name="Dean Arthur Vance (Academic Affairs)",
        sender_address="dean.arthur.vance@yahoo.com",
        content="Urgent wire transfer needed for academic conference."
    )
    assert acad_res["confidence"] >= 0.90
    assert acad_res["threat_category"] == "Academic Leadership Impersonation"
    assert any(ind.indicator_type == "vip_webmail_discrepancy" for ind in acad_res["indicators"])

    # Government Tax Authority impersonation
    gov_res = impersonation_detector.analyze(
        sender_name="Internal Revenue Tax Authority Officer",
        sender_address="irs-official-division@gmail.com",
        content="Notice of delinquency: submit fine immediately to prevent asset seizure."
    )
    assert gov_res["confidence"] >= 0.90
    assert gov_res["threat_category"] == "Government Official Impersonation"
    assert any(ind.indicator_type == "vip_webmail_discrepancy" for ind in gov_res["indicators"])


def test_malware_detector():
    """TASK-25: Validates malware hashes, double extensions, and binary entropy."""
    from app.detectors.malware import malware_detector

    # 1. Double extension check
    double_res = malware_detector.analyze(
        filename="Q3_Bonus_Report.pdf.exe",
        file_bytes=b"MZ\x90\x00\x03Test PE payload header with dummy bytes"
    )
    assert double_res["confidence"] >= 0.90
    assert double_res["threat_category"] == "Deceptive Malware Dropper"
    assert any(ind.indicator_type == "dangerous_double_extension" for ind in double_res["indicators"])

    # 2. Known EICAR hash match
    eicar_payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_res = malware_detector.analyze(
        filename="eicar.com",
        file_bytes=eicar_payload
    )
    assert eicar_res["confidence"] >= 0.95
    assert "EICAR" in eicar_res["threat_category"]
    assert any(ind.indicator_type == "known_malware_hash_signature" for ind in eicar_res["indicators"])


def test_network_traffic_detector():
    """TASK-26: Validates port scan sweeps (T1046) and DNS tunneling (T1071.004)."""
    from app.detectors.network import network_detector

    # 1. Port scan sweep
    flows = [{"source_ip": "194.26.29.112", "dest_ip": "10.0.0.1", "dest_port": p, "protocol": "TCP"} for p in range(1, 25)]
    net_res = network_detector.analyze_flows(flows)
    assert net_res["confidence"] >= 0.85
    assert "Port Scan" in net_res["threat_category"]
    assert any(ind.indicator_type == "network_port_scan_sweep" for ind in net_res["indicators"])
    assert "T1046" in net_res["metadata"]["mitre_techniques"]

    # 2. DNS tunneling
    dns_flows = [{
        "source_ip": "10.0.0.50",
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "protocol": "DNS",
        "payload": "dGhpcyBpcyBhIGhpZ2ggZW50cm9weSBkYXRhIHBheWxvYWQgZXhmaWx0cmF0aW9u.tunnel.c2-darknet.xyz"
    }]
    tunnel_res = network_detector.analyze_flows(dns_flows)
    assert tunnel_res["confidence"] >= 0.90
    assert "DNS Tunneling" in tunnel_res["threat_category"]
    assert any(ind.indicator_type == "dns_tunneling_exfiltration" for ind in tunnel_res["indicators"])


def test_api_abuse_and_exfiltration():
    """TASK-27: Validates API 401 bursts and excessive egress exfiltration."""
    result = anomaly_detector.analyze(
        user_id="usr_admin",
        ip_address="45.133.1.88",
        device_id="python-requests/2.31.0",
        location="Frankfurt, Germany",
        unauthorized_http_count=22,
        egress_mb=650.0
    )
    assert result["confidence"] >= 0.90
    assert any(ind.indicator_type == "api_abuse_burst" for ind in result["indicators"])
    assert any(ind.indicator_type == "excessive_egress_exfiltration" for ind in result["indicators"])


def test_media_ela_and_voice_clone():
    """TASK-28 & TASK-29: Validates image ELA tampering and synthetic audio voice clone."""
    from app.detectors.media import media_detector
    from PIL import Image
    import io

    # 1. ELA analysis with clean image
    img = Image.new("RGB", (100, 100), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    ela_res = media_detector.analyze_image_ela(buf.getvalue())
    assert "authenticity_score" in ela_res
    assert ela_res["authenticity_score"] >= 0.70

    # 2. Audio voice clone analysis
    audio_dummy = bytes([128] * 10000)
    audio_res = media_detector.analyze_audio_synthetic(audio_dummy)
    assert "authenticity_score" in audio_res

