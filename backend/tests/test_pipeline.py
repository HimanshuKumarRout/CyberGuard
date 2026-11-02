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
