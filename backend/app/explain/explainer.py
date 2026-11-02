"""
Explainable AI (XAI) Engine for CYBERGUARD
Enforces Rule 1.3: Zero Naked Alerts.
Compiles fine-grained evidence vectors and synthesizes plain-language reasoning.
"""
from typing import List, Dict, Any, Optional
from app.schemas.event import Indicator, Explanation, RiskLevel


class ExplainabilityEngine:
    @classmethod
    def generate_explanation(
        cls,
        threat_category: str,
        risk_level: RiskLevel,
        risk_score: int,
        confidence: float,
        indicators: List[Indicator],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Explanation:
        """
        Builds a structured Explanation object conforming to Rule 1.3.
        """
        meta = metadata or {}

        # 1. Summary headline
        r_level_str = risk_level.value if hasattr(risk_level, "value") else str(risk_level)
        if r_level_str == "Safe":
            summary = f"Safe: Normal and benign activity validated ({threat_category}). No anomalous threat indicators identified."
        else:
            summary = f"{r_level_str} Risk: Suspicious {threat_category} activity identified (Score: {risk_score}/100, Confidence: {int(confidence * 100)}%)."

        # 2. Evidence vector
        evidence: List[str] = []
        for ind in indicators:
            sev_str = ind.severity.value if hasattr(ind.severity, "value") else str(ind.severity)
            evidence.append(
                f"[{sev_str}] {ind.indicator_type.replace('_', ' ').title()}: {ind.indicator_value}"
            )

        # Include key metadata if available and not yet represented
        if "velocity_kmh" in meta:
            evidence.append(f"Calculated travel velocity between logins: {meta['velocity_kmh']:.1f} km/h (Threshold: 900.0 km/h)")
        if "levenshtein_distance" in meta and meta.get("target_brand"):
            evidence.append(f"Domain edits to brand '{meta['target_brand']}': Levenshtein distance = {meta['levenshtein_distance']}")
        if "entropy" in meta:
            evidence.append(f"Domain Shannon entropy: {meta['entropy']:.2f} (High randomness/obfuscation threshold: 3.5)")

        if not evidence:
            if r_level_str == "Safe":
                evidence.append("All baseline security heuristics and identity signatures passed verification.")
            else:
                evidence.append(f"Aggregate confidence threshold exceeded by primary {threat_category} detection model.")

        # 3. Plain language reasoning narrative
        if r_level_str == "Safe":
            reasoning = (
                "The analyzed artifact conforms with baseline legitimate communication patterns. "
                "No lookalike domain patterns, unauthorized identity mismatches, or impossible velocity transitions were detected."
            )
        elif r_level_str in ("High", "Critical"):
            reasoning = (
                f"The convergence of multiple high-severity indicators and an AI model confidence of {int(confidence * 100)}% "
                f"justifies an escalated {r_level_str} verdict. Specifically, observable artifacts show evidence of "
                f"{', '.join(ind.indicator_type.replace('_', ' ') for ind in indicators[:3]) if indicators else 'anomalous signals'}. "
                "Immediate containment action is recommended to mitigate active exploitation."
            )
        else:
            reasoning = (
                f"The artifact exhibits minor anomalies consistent with potential {threat_category}, "
                f"yielding a {r_level_str} threat score of {risk_score}. While not definitively malicious, "
                "analyst caution and warning banners are advised."
            )

        return Explanation(
            summary=summary,
            evidence=evidence,
            reasoning=reasoning
        )


xai_engine = ExplainabilityEngine()
