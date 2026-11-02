"""
Supabase Cloud Database interface for CYBERGUARD.
Provides centralized persistence for security events, indicators, incidents,
explanations, containment responses, users, and audit logs exclusively via Supabase Cloud.
"""
import json
import os
import logging
from collections import Counter
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import httpx

from app.config import settings

logger = logging.getLogger("cyberguard.db")


class DatabaseClient:
    """Exclusive Supabase Cloud PostgreSQL Client via PostgREST."""

    def __init__(self):
        self.supabase_url = settings.supabase_url.rstrip("/") if settings.supabase_url else ""
        if self.supabase_url and not self.supabase_url.endswith("/rest/v1"):
            self.supabase_url = f"{self.supabase_url}/rest/v1"

        self.supabase_key = settings.supabase_key

        if not self.supabase_url or not self.supabase_key:
            logger.critical("SUPABASE_URL and SUPABASE_KEY must be configured in environment variables.")

        self.headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
        }

        # Persistent HTTP client with connection pooling for low-latency PostgREST queries
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50, keepalive_expiry=30.0)
        self.client = httpx.Client(
            base_url=self.supabase_url,
            headers=self.headers,
            timeout=15.0,
            limits=limits
        )

        self.init_db()

    def init_db(self):
        """Verifies Supabase connectivity and ensures default SOC Lead user is seeded."""
        if not self.supabase_url or not self.supabase_key:
            logger.warning("Supabase credentials not configured; skipping initialization.")
            return

        try:
            # Connectivity check
            res = self.client.get("/users?select=id&limit=1")
            if res.status_code not in (200, 206):
                logger.error(f"Supabase connection test returned HTTP {res.status_code}: {res.text}")
                return

            # Ensure default SOC Lead user exists
            lead_email = "himanshu@cyberguard.internal"
            r_user = self.client.get(f"/users?email=eq.{lead_email}&select=id")
            if r_user.status_code == 200 and not r_user.json():
                from app.auth.security import hash_password
                default_pw = hash_password("admin123")
                self.client.post(
                    "/users",
                    json={
                        "id": "usr_himanshu_lead",
                        "email": lead_email,
                        "name": "Himanshu Rout",
                        "role": "Tier-1 SOC Lead",
                        "password_hash": default_pw
                    },
                    headers={"Prefer": "return=minimal"}
                )
                logger.info(f"Seeded default SOC Lead user: {lead_email} in Supabase Cloud.")

            logger.info("Supabase Cloud Database connected and initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize Supabase Cloud database: {e}")

    def save_event(self, event_data: Dict[str, Any]) -> str:
        """Persists a Unified Event Model record, indicators, explanation, and response recommendations."""
        event_id = event_data["event_id"]
        ts = event_data.get("timestamp", datetime.now(timezone.utc).isoformat())

        try:
            # 1. Insert Event Record (with upsert support)
            event_row = {
                "id": event_id,
                "timestamp": ts,
                "source": event_data.get("source", "api_gateway"),
                "input_type": event_data.get("input_type", "unknown"),
                "user_id": event_data.get("user_id"),
                "device_id": event_data.get("device_id"),
                "detector": event_data.get("detector", "unknown"),
                "threat_category": event_data.get("threat_category", "Unknown"),
                "confidence": float(event_data.get("confidence", 0.0)),
                "risk_score": int(event_data.get("risk_score", 0)),
                "risk_level": event_data.get("risk_level", "Safe"),
                "metadata": json.dumps(event_data.get("metadata", {})) if isinstance(event_data.get("metadata"), (dict, list)) else str(event_data.get("metadata", "{}"))
            }

            self.client.post("/events", json=event_row, headers={"Prefer": "resolution=merge-duplicates"})

            # 2. Insert Indicators
            indicators = event_data.get("indicators", [])
            if indicators:
                ind_rows = [
                    {
                        "id": f"ind_{os.urandom(6).hex()}",
                        "event_id": event_id,
                        "indicator_type": ind.get("indicator_type", "generic"),
                        "indicator_value": str(ind.get("indicator_value", "")),
                        "severity": ind.get("severity", "Low"),
                        "weight": float(ind.get("weight", 0.1))
                    }
                    for ind in indicators
                ]
                self.client.post("/indicators", json=ind_rows, headers={"Prefer": "resolution=merge-duplicates"})

            # 3. Insert Explanation
            if "explanation" in event_data and event_data["explanation"]:
                exp = event_data["explanation"]
                evidence = exp.get("evidence", [])
                exp_row = {
                    "id": f"exp_{os.urandom(6).hex()}",
                    "event_id": event_id,
                    "summary": exp.get("summary", ""),
                    "evidence": json.dumps(evidence) if isinstance(evidence, (list, dict)) else str(evidence),
                    "reasoning": exp.get("reasoning", "")
                }
                self.client.post("/explanations", json=exp_row, headers={"Prefer": "resolution=merge-duplicates"})

            # 4. Insert Recommended Responses
            actions = event_data.get("recommended_actions", [])
            if actions:
                resp_rows = [
                    {
                        "id": f"resp_{os.urandom(6).hex()}",
                        "event_id": event_id,
                        "action_type": resp.get("action_type", "log_alert"),
                        "target": resp.get("target", "system"),
                        "priority": resp.get("priority", "P2"),
                        "status": resp.get("simulation_status", "Simulated"),
                        "details": str(resp.get("details", ""))
                    }
                    for resp in actions
                ]
                self.client.post("/responses", json=resp_rows, headers={"Prefer": "resolution=merge-duplicates"})

            # 5. Auto-escalate to Incident if risk_score >= 60
            if event_data.get("risk_score", 0) >= 60:
                priority = "P1" if event_data.get("risk_level") == "Critical" else "P2"
                inc_row = {
                    "id": f"inc_{event_id.replace('evt_', '')[:12]}",
                    "event_id": event_id,
                    "title": f"{event_data.get('threat_category', 'Threat')} Alert: {event_id}",
                    "status": "Open",
                    "priority": priority,
                    "threat_category": event_data.get("threat_category", "Threat"),
                    "risk_score": int(event_data.get("risk_score", 0)),
                    "risk_level": event_data.get("risk_level", "High"),
                    "assigned_to": "Himanshu Rout"
                }
                self.client.post("/incidents", json=inc_row, headers={"Prefer": "resolution=merge-duplicates"})

            logger.info(f"Event {event_id} persisted to Supabase Cloud.")
        except Exception as e:
            logger.error(f"Failed to persist event {event_id} to Supabase: {e}")

        return event_id

    def list_events(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Lists events ordered by timestamp descending."""
        try:
            res = self.client.get(f"/events?select=*&order=timestamp.desc&limit={limit}&offset={offset}")
            if res.status_code == 200:
                events = res.json()
                for ev in events:
                    if isinstance(ev.get("metadata"), str):
                        try:
                            ev["metadata"] = json.loads(ev["metadata"])
                        except Exception:
                            ev["metadata"] = {}
                return events
        except Exception as e:
            logger.error(f"Failed to list events from Supabase: {e}")
        return []

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves full unified event model record with related indicators, explanation, and actions."""
        try:
            res = self.client.get(f"/events?id=eq.{event_id}&select=*")
            if res.status_code != 200 or not res.json():
                return None

            event = res.json()[0]
            if isinstance(event.get("metadata"), str):
                try:
                    event["metadata"] = json.loads(event["metadata"])
                except Exception:
                    event["metadata"] = {}

            # Fetch Indicators
            r_ind = self.client.get(f"/indicators?event_id=eq.{event_id}&select=*")
            event["indicators"] = r_ind.json() if r_ind.status_code == 200 else []

            # Fetch Explanation
            r_exp = self.client.get(f"/explanations?event_id=eq.{event_id}&select=*&limit=1")
            if r_exp.status_code == 200 and r_exp.json():
                exp = r_exp.json()[0]
                if isinstance(exp.get("evidence"), str):
                    try:
                        exp["evidence"] = json.loads(exp["evidence"])
                    except Exception:
                        exp["evidence"] = []
                event["explanation"] = exp
            else:
                event["explanation"] = None

            # Fetch Responses
            r_resp = self.client.get(f"/responses?event_id=eq.{event_id}&select=*")
            event["recommended_actions"] = r_resp.json() if r_resp.status_code == 200 else []

            return event
        except Exception as e:
            logger.error(f"Failed to fetch event {event_id} from Supabase: {e}")
            return None

    def list_incidents(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists incidents, optionally filtered by lifecycle status."""
        try:
            url = "/incidents?select=*&order=created_at.desc"
            if status:
                url += f"&status=eq.{status}"
            res = self.client.get(url)
            if res.status_code == 200:
                return res.json()
        except Exception as e:
            logger.error(f"Failed to list incidents from Supabase: {e}")
        return []

    def update_incident_status(self, incident_id: str, new_status: str, assigned_to: Optional[str] = None) -> bool:
        """Updates the status or assigned personnel of an incident."""
        try:
            payload: Dict[str, Any] = {"status": new_status}
            if assigned_to:
                payload["assigned_to"] = assigned_to

            res = self.client.patch(
                f"/incidents?id=eq.{incident_id}",
                json=payload,
                headers={"Prefer": "return=representation"}
            )
            if res.status_code in (200, 204):
                data = res.json() if res.status_code == 200 else []
                return len(data) > 0 or res.status_code == 204
        except Exception as e:
            logger.error(f"Failed to update incident {incident_id} in Supabase: {e}")
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Calculates SOC KPIs directly from Supabase Cloud."""
        def _get_count(endpoint_filter: str) -> int:
            try:
                r = self.client.get(
                    f"{endpoint_filter}&select=id",
                    headers={"Prefer": "count=exact", "Range": "0-0"}
                )
                cr = r.headers.get("content-range", "")
                if "/" in cr:
                    total = cr.split("/")[-1].strip()
                    if total.isdigit():
                        return int(total)
            except Exception as e:
                logger.warning(f"Count query failed for {endpoint_filter}: {e}")
            return 0

        total_events = _get_count("/events?")
        threats_detected = _get_count("/events?risk_score=gte.40")
        critical_incidents = _get_count("/incidents?risk_level=eq.Critical")
        open_incidents = _get_count("/incidents?status=eq.Open")

        return {
            "total_events": total_events,
            "threats_detected": threats_detected,
            "critical_incidents": critical_incidents,
            "open_incidents": open_incidents
        }

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Returns time series distribution of events grouped by hour."""
        try:
            res = self.client.get("/events?select=timestamp,risk_level&order=timestamp.asc")
            if res.status_code != 200 or not res.json():
                return []

            hourly: Dict[str, Dict[str, int]] = {}
            for row in res.json():
                raw_ts = row.get("timestamp", "")
                # Extract HH:00 format
                if "T" in raw_ts:
                    time_part = raw_ts.split("T")[1][:2] + ":00"
                elif " " in raw_ts:
                    time_part = raw_ts.split(" ")[1][:2] + ":00"
                else:
                    time_part = "00:00"

                if time_part not in hourly:
                    hourly[time_part] = {"time": time_part, "safe": 0, "medium": 0, "critical": 0}

                lvl = (row.get("risk_level") or "").capitalize()
                if lvl == "Safe":
                    hourly[time_part]["safe"] += 1
                elif lvl in ("Low", "Medium"):
                    hourly[time_part]["medium"] += 1
                elif lvl in ("High", "Critical"):
                    hourly[time_part]["critical"] += 1

            return list(hourly.values())
        except Exception as e:
            logger.error(f"Failed to fetch timeline from Supabase: {e}")
            return []

    def get_categories(self) -> List[Dict[str, Any]]:
        """Returns live threat category distribution aggregated from Supabase events."""
        palette = {
            "Phishing & URL": "#f97316",
            "Executive Impersonation (BEC)": "#ef4444",
            "Impossible Travel Anomaly": "#f59e0b",
            "Lookalike Domain Spear-Phishing": "#f97316",
            "Synthetic Deepfake Media": "#ec4899",
            "Credential Stuffing / Brute-Force": "#eab308",
        }
        try:
            res = self.client.get("/events?select=threat_category")
            if res.status_code == 200 and res.json():
                counts = Counter(r.get("threat_category", "Unknown") for r in res.json() if r.get("threat_category"))
                return [
                    {
                        "name": cat,
                        "value": cnt,
                        "color": palette.get(cat, "#0ea5e9")
                    }
                    for cat, cnt in counts.most_common()
                ]
        except Exception as e:
            logger.error(f"Failed to fetch threat categories from Supabase: {e}")
        return []

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Fetches a user profile and credentials hash by email address."""
        try:
            clean_email = email.strip().lower()
            res = self.client.get(f"/users?email=eq.{clean_email}&select=*")
            if res.status_code == 200 and res.json():
                return res.json()[0]
        except Exception as e:
            logger.error(f"Failed to get user by email {email} from Supabase: {e}")
        return None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetches user public profile details by ID."""
        try:
            res = self.client.get(f"/users?id=eq.{user_id}&select=id,email,name,role,created_at")
            if res.status_code == 200 and res.json():
                return res.json()[0]
        except Exception as e:
            logger.error(f"Failed to get user by id {user_id} from Supabase: {e}")
        return None

    def create_user(self, name: str, email: str, password_hash: str, role: str = "Analyst") -> Dict[str, Any]:
        """Registers a new user into Supabase Cloud users table."""
        user_id = f"usr_{os.urandom(6).hex()}"
        clean_email = email.strip().lower()
        clean_name = name.strip()

        user_data = {
            "id": user_id,
            "email": clean_email,
            "name": clean_name,
            "role": role,
            "password_hash": password_hash
        }

        try:
            res = self.client.post("/users", json=user_data, headers={"Prefer": "return=representation"})
            if res.status_code in (200, 201) and res.json():
                u = res.json()[0]
                return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"]}
        except Exception as e:
            logger.error(f"Failed to create user {clean_email} in Supabase: {e}")

        return {"id": user_id, "email": clean_email, "name": clean_name, "role": role}

    def clear_all_data(self):
        """Clears all events, incidents, indicators, explanations, responses, and audit logs in Supabase Cloud."""
        tables = ["responses", "explanations", "incidents", "indicators", "model_runs", "audit_logs", "events"]
        for tbl in tables:
            try:
                self.client.delete(f"/{tbl}?id=neq.placeholder")
            except Exception as e:
                logger.warning(f"Failed to clear table {tbl} in Supabase: {e}")


# Global singleton client instance
db = DatabaseClient()
