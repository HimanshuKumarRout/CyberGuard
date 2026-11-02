"""
Risk Scoring Engine for CYBERGUARD
Implements the calibrated hybrid risk scoring formula:
Score = min(100, (C_model * 60) + (I_norm * 40))
Mapped to 5 severity bands: Safe, Low, Medium, High, Critical.
"""
from typing import List, Tuple
from app.schemas.event import Indicator, RiskLevel, Severity


# Severity to weight mapping as defined in Section 6.2 of ARCHITECTURE.md
SEVERITY_WEIGHT_MAP = {
    Severity.CRITICAL: 0.50,
    Severity.HIGH: 0.35,
    Severity.MEDIUM: 0.20,
    Severity.LOW: 0.10,
    "Critical": 0.50,
    "High": 0.35,
    "Medium": 0.20,
    "Low": 0.10,
}


class RiskScoringEngine:
    MODEL_WEIGHT = 60.0
    INDICATOR_WEIGHT = 40.0

    @classmethod
    def calculate_risk(cls, model_confidence: float, indicators: List[Indicator]) -> Tuple[int, RiskLevel]:
        """
        Calculates normalized risk score (0 - 100) and assigns a RiskLevel band.
        """
        # Ensure confidence is clamped between 0.0 and 1.0
        conf = max(0.0, min(1.0, float(model_confidence)))

        # Aggregate indicator severity weights
        raw_indicator_sum = sum(
            SEVERITY_WEIGHT_MAP.get(ind.severity, 0.10) for ind in indicators
        )
        i_norm = min(1.0, raw_indicator_sum)

        # Composite mathematical formula
        raw_score = (conf * cls.MODEL_WEIGHT) + (i_norm * cls.INDICATOR_WEIGHT)
        final_score = int(round(min(100.0, max(0.0, raw_score))))

        # Map to Risk Level
        if final_score < 20:
            level = RiskLevel.SAFE
        elif final_score < 40:
            level = RiskLevel.LOW
        elif final_score < 60:
            level = RiskLevel.MEDIUM
        elif final_score < 80:
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL

        return final_score, level


risk_engine = RiskScoringEngine()
