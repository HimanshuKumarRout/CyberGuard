"""
Response & Mitigation Engine for CYBERGUARD
Enforces Rule 1.4: Safe Simulation Guarantee.
Maps threat categories, severity bands, and affected assets to prioritized response actions.
"""
from typing import List, Dict, Any, Optional
from app.schemas.event import ResponseAction, RiskLevel, Priority
from app.config import settings
import logging

logger = logging.getLogger("cyberguard.response")


class ResponseEngine:
    @classmethod
    def recommend_actions(
        cls,
        threat_category: str,
        risk_level: RiskLevel,
        target_subject: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[ResponseAction]:
        """
        Synthesizes prioritized response actions based on category, severity, and context.
        """
        actions: List[ResponseAction] = []
        meta = metadata or {}
        mode = "Simulated" if settings.simulation_mode else "Executed"

        if risk_level in (RiskLevel.SAFE, RiskLevel.LOW):
            actions.append(
                ResponseAction(
                    action_type="log_telemetry",
                    target=target_subject or "event_bus",
                    priority=Priority.P3,
                    simulation_status=mode,
                    details="Event logged to security lake for telemetry and baseline profiling."
                )
            )
            return actions

        category_lower = threat_category.lower()

        # 1. Phishing, Malicious URLs & Quishing
        if "phish" in category_lower or "url" in category_lower or "link" in category_lower or "quishing" in category_lower:
            url_target = meta.get("decoded_url") or meta.get("url") or target_subject
            actions.append(
                ResponseAction(
                    action_type="block_url",
                    target=url_target,
                    priority=Priority.P1 if risk_level == RiskLevel.CRITICAL else Priority.P2,
                    simulation_status=mode,
                    details=f"Simulate border gateway DNS & proxy null-route for domain/URL: {url_target}"
                )
            )
            if meta.get("sender") or "email" in meta.get("input_type", "") or "quishing" in category_lower:
                sender_target = meta.get("sender", "recipient_inbox")
                actions.append(
                    ResponseAction(
                        action_type="quarantine_email",
                        target=sender_target,
                        priority=Priority.P1,
                        simulation_status=mode,
                        details="Simulate immediate purge and quarantine from Microsoft 365 / Google Workspace inboxes."
                    )
                )
            if risk_level == RiskLevel.CRITICAL:
                actions.append(
                    ResponseAction(
                        action_type="force_password_reset",
                        target=meta.get("user_id", "targeted_recipient"),
                        priority=Priority.P2,
                        simulation_status=mode,
                        details="Simulate automated directory credential invalidation and reset trigger."
                    )
                )

        # 2. Digital Impersonation, Executive/Gov Spoofing & Deepfake
        elif "impersonation" in category_lower or "deepfake" in category_lower or "fraud" in category_lower or "spoof" in category_lower:
            actions.append(
                ResponseAction(
                    action_type="report_impersonation",
                    target=meta.get("sender_address", target_subject),
                    priority=Priority.P1,
                    simulation_status=mode,
                    details="Simulate automated abuse dispatch to registrar, host, and identity provider."
                )
            )
            actions.append(
                ResponseAction(
                    action_type="warn_recipient",
                    target="target_communications_channel",
                    priority=Priority.P2,
                    simulation_status=mode,
                    details="Simulate injection of prominent untrusted sender warning banner into client UI."
                )
            )
            if "deepfake" in category_lower or "synthetic" in category_lower or meta.get("media_url") or meta.get("tamper_ratio"):
                actions.append(
                    ResponseAction(
                        action_type="flag_multimedia",
                        target=meta.get("filename", meta.get("media_url", "attached_media")),
                        priority=Priority.P2,
                        simulation_status=mode,
                        details="Simulate synthetic media tagging in corporate content delivery network."
                    )
                )

        # 3. Malware & Dangerous Droppers (TASK-25)
        elif "malware" in category_lower or "trojan" in category_lower or "ransomware" in category_lower or "packed" in category_lower or "dropper" in category_lower:
            sha256 = meta.get("sha256", target_subject)
            filename = meta.get("filename", "malicious_file")
            actions.append(
                ResponseAction(
                    action_type="block_file_hash",
                    target=sha256,
                    priority=Priority.P1,
                    simulation_status=mode,
                    details=f"Simulate EDR agent hash ban across all corporate endpoints for SHA256: {sha256}"
                )
            )
            actions.append(
                ResponseAction(
                    action_type="quarantine_endpoint_host",
                    target=meta.get("user_id", "affected_workstation"),
                    priority=Priority.P1,
                    simulation_status=mode,
                    details=f"Simulate network isolation of host executing malicious attachment: {filename}"
                )
            )

        # 4. Network Attacks, Port Scans & DNS Tunneling (TASK-26)
        elif "network" in category_lower or "port scan" in category_lower or "tunneling" in category_lower or "reconnaissance" in category_lower:
            src_ip = meta.get("source_ip", target_subject)
            actions.append(
                ResponseAction(
                    action_type="block_ip",
                    target=src_ip,
                    priority=Priority.P1,
                    simulation_status=mode,
                    details=f"Simulate edge firewall ACL drop rule for scanning/tunneling source IP: {src_ip}"
                )
            )
            if "tunneling" in category_lower:
                actions.append(
                    ResponseAction(
                        action_type="sinkhole_dns_domain",
                        target=meta.get("c2_domain", "tunnel_c2_domain"),
                        priority=Priority.P1,
                        simulation_status=mode,
                        details="Simulate internal recursive resolver sinkholing for rogue C2 domain."
                    )
                )

        # 5. Credential Theft, ATO, API Abuse & Data Exfiltration (TASK-27)
        elif "anomaly" in category_lower or "travel" in category_lower or "brute" in category_lower or "credential" in category_lower or "api abuse" in category_lower or "exfiltration" in category_lower:
            user_target = meta.get("user_id", target_subject)
            ip_target = meta.get("ip_address", "remote_ip")

            actions.append(
                ResponseAction(
                    action_type="revoke_session",
                    target=user_target,
                    priority=Priority.P1,
                    simulation_status=mode,
                    details=f"Simulate immediate Okta / Entra ID token revocation for account: {user_target}"
                )
            )
            if "api abuse" in category_lower or "exfiltration" in category_lower:
                actions.append(
                    ResponseAction(
                        action_type="rate_limit_token",
                        target=user_target,
                        priority=Priority.P1,
                        simulation_status=mode,
                        details=f"Simulate API gateway throttle & API key invalidation for: {user_target}"
                    )
                )
            else:
                actions.append(
                    ResponseAction(
                        action_type="enforce_mfa",
                        target=user_target,
                        priority=Priority.P1,
                        simulation_status=mode,
                        details="Simulate step-up FIDO2 / hardware token biometric prompt challenge."
                    )
                )

            if risk_level == RiskLevel.CRITICAL:
                actions.append(
                    ResponseAction(
                        action_type="block_ip",
                        target=ip_target,
                        priority=Priority.P1,
                        simulation_status=mode,
                        details=f"Simulate edge firewall ACL block on ingress traffic from IP: {ip_target}"
                    )
                )

        # Fallback Generic Threat Action
        if not actions:
            actions.append(
                ResponseAction(
                    action_type="escalate_to_soc",
                    target=target_subject,
                    priority=Priority.P2,
                    simulation_status=mode,
                    details="Escalate to SOC Tier-2 Incident Responder queue for deeper forensic analysis."
                )
            )

        return actions


response_engine = ResponseEngine()
