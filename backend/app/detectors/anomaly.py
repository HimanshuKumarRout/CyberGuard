"""
Scenario 3: Credential Theft & Behavioral Anomaly Detector
Evaluates impossible travel velocity, brute-force password spraying patterns,
anomalous device/session characteristics, and TASK-27: API Abuse & Data-Exfiltration telemetry.
"""
import math
from typing import Dict, Any, List, Optional, Tuple
from app.schemas.event import Indicator, Severity

# Standard coordinates for common demo locations
LOCATION_COORDINATES: Dict[str, Tuple[float, float]] = {
    "new york": (40.7128, -74.0060),
    "london": (51.5074, -0.1278),
    "tokyo": (35.6762, 139.6503),
    "san francisco": (37.7749, -122.4194),
    "moscow": (55.7558, 37.6173),
    "singapore": (1.3521, 103.8198),
    "sydney": (-33.8688, 151.2093),
    "paris": (48.8566, 2.3522),
    "frankfurt": (50.1109, 8.6821),
    "mumbai": (19.0760, 72.8777),
}


def haversine_distance_km(coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
    """Calculates great-circle distance between two points on Earth in kilometers."""
    lat1, lon1 = math.radians(coord1[0]), math.radians(coord1[1])
    lat2, lon2 = math.radians(coord2[0]), math.radians(coord2[1])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    r = 6371.0  # Earth radius in km
    return r * c


class AnomalyDetector:
    name: str = "anomaly_detector"

    # User baseline history simulation for testing/eval
    USER_BASELINES: Dict[str, Dict[str, Any]] = {
        "usr_94821": {
            "last_location": "New York",
            "last_coords": (40.7128, -74.0060),
            "last_timestamp_offset_hours": 0.5,  # 30 minutes ago
            "known_device": "dev_macbook_pro_04",
            "baseline_egress_mb": 25.0,
        },
        "usr_admin": {
            "last_location": "San Francisco",
            "last_coords": (37.7749, -122.4194),
            "last_timestamp_offset_hours": 1.0,
            "known_device": "dev_thinkpad_admin",
            "baseline_egress_mb": 50.0,
        }
    }

    @classmethod
    def analyze(
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
    ) -> Dict[str, Any]:
        """
        Analyzes authentication and API event parameters for velocity, credential, and exfiltration anomalies.
        """
        indicators: List[Indicator] = []
        model_confidence = 0.05
        threat_category = "Normal Authentication"
        metadata: Dict[str, Any] = {
            "user_id": user_id,
            "ip_address": ip_address,
            "device_id": device_id,
            "location": location,
            "failed_attempts": failed_attempts,
            "session_duration": session_duration,
            "unauthorized_http_count": unauthorized_http_count,
            "egress_mb": egress_mb,
            "target_endpoint": target_endpoint
        }

        # 1. Impossible Travel Calculation
        baseline = cls.USER_BASELINES.get(user_id)
        current_coords = None

        if latitude is not None and longitude is not None:
            current_coords = (latitude, longitude)
        else:
            for loc_name, coords in LOCATION_COORDINATES.items():
                if loc_name in location.lower():
                    current_coords = coords
                    break

        if baseline and current_coords:
            prev_coords = baseline["last_coords"]
            distance_km = haversine_distance_km(prev_coords, current_coords)
            time_elapsed_hours = baseline.get("last_timestamp_offset_hours", 0.5)

            if time_elapsed_hours > 0 and distance_km > 50:
                velocity_kmh = distance_km / time_elapsed_hours
                metadata["velocity_kmh"] = round(velocity_kmh, 1)
                metadata["distance_km"] = round(distance_km, 1)

                if velocity_kmh > 900.0:
                    indicators.append(
                        Indicator(
                            indicator_type="impossible_travel_velocity",
                            indicator_value=(
                                f"Velocity of {velocity_kmh:.1f} km/h detected between {baseline['last_location']} "
                                f"and {location} ({distance_km:.0f} km in {time_elapsed_hours * 60:.0f} mins)"
                            ),
                            severity=Severity.CRITICAL,
                            weight=0.50
                        )
                    )
                    model_confidence = max(model_confidence, 0.96)
                    threat_category = "Impossible Travel Anomaly"

        # 2. Brute Force / Password Spraying Detection
        if failed_attempts >= 5:
            indicators.append(
                Indicator(
                    indicator_type="brute_force_attempts",
                    indicator_value=f"Burst of {failed_attempts} failed login attempts prior to authorization",
                    severity=Severity.HIGH,
                    weight=0.40
                )
            )
            model_confidence = max(model_confidence, 0.88)
            threat_category = "Credential Stuffing / Brute-Force"
        elif failed_attempts >= 3:
            indicators.append(
                Indicator(
                    indicator_type="repeated_failed_logins",
                    indicator_value=f"{failed_attempts} failed consecutive login attempts recorded",
                    severity=Severity.MEDIUM,
                    weight=0.25
                )
            )
            model_confidence = max(model_confidence, 0.50)

        # 3. Device Anomaly
        if baseline and device_id != baseline.get("known_device"):
            indicators.append(
                Indicator(
                    indicator_type="novel_device_fingerprint",
                    indicator_value=f"Unrecognized device user-agent '{device_id}' differs from baseline '{baseline.get('known_device')}'",
                    severity=Severity.MEDIUM,
                    weight=0.20
                )
            )
            model_confidence = max(model_confidence, 0.40)

        # 4. TASK-27: API Abuse Anomaly (Burst of HTTP 401/403 Unauthorized Responses)
        if unauthorized_http_count >= 15:
            indicators.append(
                Indicator(
                    indicator_type="api_abuse_burst",
                    indicator_value=f"Burst of {unauthorized_http_count} HTTP 401/403 unauthorized calls in 5-minute window (token brute-forcing / scraping)",
                    severity=Severity.CRITICAL,
                    weight=0.50
                )
            )
            model_confidence = max(model_confidence, 0.92)
            threat_category = "API Abuse & Token Brute-Force"

        # 5. TASK-27: Data-Exfiltration Egress Spike Anomaly
        user_baseline_egress = baseline.get("baseline_egress_mb", 30.0) if baseline else 30.0
        if egress_mb >= 500.0 or (egress_mb > 100.0 and egress_mb > user_baseline_egress * 5.0):
            indicators.append(
                Indicator(
                    indicator_type="excessive_egress_exfiltration",
                    indicator_value=f"Egress volume of {egress_mb:.1f} MB exceeds baseline threshold ({user_baseline_egress:.1f} MB) within short duration (MITRE T1041)",
                    severity=Severity.CRITICAL,
                    weight=0.55
                )
            )
            model_confidence = max(model_confidence, 0.95)
            threat_category = "Data Exfiltration Anomaly"

        # 6. Fallback baseline if no anomalies
        if not indicators:
            model_confidence = 0.05
            threat_category = "Normal Authentication"

        return {
            "detector": cls.name,
            "threat_category": threat_category,
            "confidence": round(model_confidence, 2),
            "indicators": indicators,
            "metadata": metadata
        }


anomaly_detector = AnomalyDetector()
