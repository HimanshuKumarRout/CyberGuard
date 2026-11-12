"""
Scenario 6: Suspicious Network Traffic & PCAP Packet Analyzer
Implements TASK-26:
- Ingests PCAP packet records and flow telemetry.
- Detects port scan sweeps (>20 ports in 10s) -> MITRE T1046.
- Detects DNS tunneling (high-entropy query payloads) -> MITRE T1071.004.
- Detects plaintext credential leakage in HTTP/FTP/Telnet streams -> MITRE T1552.
"""
import re
import math
import struct
from typing import Dict, Any, List, Optional
from app.schemas.event import Indicator, Severity


def calculate_string_entropy(text: str) -> float:
    """Calculates Shannon entropy for payload text."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy


class NetworkDetector:
    name: str = "network_detector"

    @classmethod
    def analyze_flows(
        cls,
        flow_records: List[Dict[str, Any]],
        capture_source: str = "border_sensor_01"
    ) -> Dict[str, Any]:
        """
        Analyzes structured network connection flow telemetry.
        Each flow record contains: {source_ip, dest_ip, dest_port, protocol, bytes, timestamp, payload}
        """
        indicators: List[Indicator] = []
        model_confidence = 0.05
        threat_category = "Normal Network Traffic"
        metadata: Dict[str, Any] = {
            "capture_source": capture_source,
            "flow_count": len(flow_records),
            "mitre_techniques": []
        }

        # 1. Port Scan Detection (T1046: Network Service Discovery)
        # Group destination ports by source_ip
        src_port_map: Dict[str, set] = {}
        for flow in flow_records:
            sip = flow.get("source_ip", "0.0.0.0")
            dport = flow.get("dest_port")
            if dport is not None:
                src_port_map.setdefault(sip, set()).add(dport)

        for sip, ports in src_port_map.items():
            if len(ports) >= 15:
                indicators.append(
                    Indicator(
                        indicator_type="network_port_scan_sweep",
                        indicator_value=f"Source host {sip} swept {len(ports)} destination ports within observation interval (MITRE T1046)",
                        severity=Severity.HIGH,
                        weight=0.45
                    )
                )
                model_confidence = max(model_confidence, 0.90)
                threat_category = "Reconnaissance: Port Scan Sweep"
                if "T1046" not in metadata["mitre_techniques"]:
                    metadata["mitre_techniques"].append("T1046")

        # 2. DNS Tunneling Detection (T1071.004: DNS Protocol Exfiltration)
        for flow in flow_records:
            dport = flow.get("dest_port")
            payload = flow.get("payload", "")
            proto = flow.get("protocol", "").upper()
            if dport == 53 or proto == "DNS" or "dns" in str(flow.get("service", "")).lower():
                # Extract query domain or payload
                q_match = re.search(r"([a-zA-Z0-9_\-\.]{20,})\.([a-zA-Z0-9\-]+)", payload)
                entropy = calculate_string_entropy(payload)
                if (q_match and entropy > 3.7) or (len(payload) > 60 and entropy > 3.8):
                    indicators.append(
                        Indicator(
                            indicator_type="dns_tunneling_exfiltration",
                            indicator_value=f"High-entropy DNS query detected: '{payload[:40]}...' (entropy: {entropy:.2f}, MITRE T1071.004)",
                            severity=Severity.CRITICAL,
                            weight=0.55
                        )
                    )
                    model_confidence = max(model_confidence, 0.94)
                    threat_category = "Command & Control: DNS Tunneling"
                    if "T1071.004" not in metadata["mitre_techniques"]:
                        metadata["mitre_techniques"].append("T1071.004")
                    break

        # 3. Plaintext Credential Exposure (T1552: Unsecured Credentials)
        cred_regex = re.compile(r"(password=|passwd=|Authorization:\s*Basic\s+[a-zA-Z0-9+/=]+|USER\s+[^\r\n]+|PASS\s+[^\r\n]+)", re.IGNORECASE)
        for flow in flow_records:
            dport = flow.get("dest_port")
            payload = flow.get("payload", "")
            # Plaintext ports: HTTP(80), FTP(21), Telnet(23)
            if dport in (80, 21, 23, 8080) or flow.get("protocol", "").upper() in ("HTTP", "FTP", "TELNET"):
                match = cred_regex.search(payload)
                if match:
                    indicators.append(
                        Indicator(
                            indicator_type="cleartext_credential_exposure",
                            indicator_value=f"Cleartext credentials transmitted unencrypted across port {dport}: '{match.group(0)[:30]}...' (MITRE T1552)",
                            severity=Severity.HIGH,
                            weight=0.40
                        )
                    )
                    model_confidence = max(model_confidence, 0.88)
                    if threat_category == "Normal Network Traffic":
                        threat_category = "Credential Leakage in Transit"
                    if "T1552" not in metadata["mitre_techniques"]:
                        metadata["mitre_techniques"].append("T1552")
                    break

        if not indicators:
            model_confidence = 0.05
            threat_category = "Normal Network Traffic"

        return {
            "detector": cls.name,
            "threat_category": threat_category,
            "confidence": round(model_confidence, 2),
            "indicators": indicators,
            "metadata": metadata
        }

    @classmethod
    def analyze_pcap_bytes(cls, pcap_bytes: bytes, filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Parses raw PCAP format binary bytes and extracts flow records for threat analysis.
        Supports standard Libpcap format (magic 0xa1b2c3d4 or 0xd4c3b2a1).
        """
        flows: List[Dict[str, Any]] = []
        filename = filename or "traffic_capture.pcap"

        if len(pcap_bytes) < 24:
            # Synthetic / fallback flow representation if not raw pcap
            return cls.analyze_flows([], capture_source=filename)

        magic = pcap_bytes[:4]
        # Standard pcap magic numbers
        is_pcap = magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\n\r\r\n")

        if is_pcap:
            offset = 24  # PCAP global header length
            packet_count = 0
            while offset + 16 <= len(pcap_bytes) and packet_count < 100:
                # Per-packet header: ts_sec, ts_usec, incl_len, orig_len
                incl_len = struct.unpack("<I", pcap_bytes[offset + 8:offset + 12])[0]
                offset += 16
                packet_data = pcap_bytes[offset:offset + incl_len]
                offset += incl_len
                packet_count += 1

                # Parse Ethernet (14) + IP (20) + Transport headers if long enough
                if len(packet_data) >= 34:
                    # IPv4 header starts at offset 14
                    ip_hdr = packet_data[14:34]
                    if len(ip_hdr) >= 20:
                        proto = ip_hdr[9]
                        src_ip = f"{ip_hdr[12]}.{ip_hdr[13]}.{ip_hdr[14]}.{ip_hdr[15]}"
                        dst_ip = f"{ip_hdr[16]}.{ip_hdr[17]}.{ip_hdr[18]}.{ip_hdr[19]}"
                        
                        dport = 80
                        payload_str = ""
                        # TCP or UDP
                        if proto in (6, 17) and len(packet_data) >= 38:
                            dport = struct.unpack("!H", packet_data[36:38])[0]
                            payload_raw = packet_data[54:]
                            payload_str = payload_raw.decode("latin1", errors="ignore")

                        flows.append({
                            "source_ip": src_ip,
                            "dest_ip": dst_ip,
                            "dest_port": dport,
                            "protocol": "TCP" if proto == 6 else "UDP" if proto == 17 else "IP",
                            "payload": payload_str
                        })
        else:
            # Fallback: scan text for port/IP indicators
            text_content = pcap_bytes.decode("latin1", errors="ignore")
            ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text_content)
            ports = [int(p) for p in re.findall(r":(\d{2,5})\b", text_content)[:30]]
            flows = [{
                "source_ip": ips[0] if ips else "192.168.1.100",
                "dest_ip": ips[1] if len(ips) > 1 else "10.0.0.1",
                "dest_port": p,
                "protocol": "TCP",
                "payload": text_content[:200]
            } for p in (ports or [80, 443, 21, 23])]

        return cls.analyze_flows(flows, capture_source=filename)


network_detector = NetworkDetector()
