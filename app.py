
import socket
import tempfile
from collections import defaultdict
from pathlib import Path

import dpkt
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="PCAP Attack Analyzer",
    page_icon="🛡️",
    layout="wide",
)


def inet_to_str(addr):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return socket.inet_ntop(family, addr)
        except (ValueError, OSError):
            pass
    return "Unknown"


def human_bytes(value):
    value = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            return f"{value:.2f} {unit}"
        value /= 1024


def pct(a, b):
    return round((a / b) * 100, 2) if b else 0.0


def tls_markers(payload: bytes):
    result = {
        "tls": False,
        "client_hello": False,
        "server_hello": False,
        "alert": False,
        "application_data": False,
    }

    if not payload or len(payload) < 5:
        return result

    content_type = payload[0]

    # Common TLS record content types.
    if content_type not in (20, 21, 22, 23) or payload[1] != 0x03:
        return result

    result["tls"] = True

    if content_type == 21:
        result["alert"] = True

    elif content_type == 23:
        result["application_data"] = True

    elif content_type == 22 and len(payload) >= 6:
        handshake_type = payload[5]

        if handshake_type == 1:
            result["client_hello"] = True
        elif handshake_type == 2:
            result["server_hello"] = True

    return result


def http_markers(payload: bytes):
    """
    Lightweight plaintext HTTP detector.
    This only works when HTTP is visible and not encrypted inside TLS.
    """
    result = {
        "request": False,
        "response": False,
    }

    if not payload:
        return result

    request_methods = (
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    )

    if any(payload.startswith(method) for method in request_methods):
        result["request"] = True

    elif payload.startswith(b"HTTP/1.0") or payload.startswith(b"HTTP/1.1"):
        result["response"] = True

    return result


def flow_key(src, sport, dst, dport):
    """
    Normalize both directions into one bidirectional TCP flow key.
    """
    a = (src, sport)
    b = (dst, dport)

    if a <= b:
        return src, sport, dst, dport

    return dst, dport, src, sport


def open_capture(path):
    fh = open(path, "rb")

    try:
        return fh, dpkt.pcap.Reader(fh), "PCAP"
    except Exception:
        fh.seek(0)

    try:
        return fh, dpkt.pcapng.Reader(fh), "PCAPNG"
    except Exception:
        fh.close()
        raise ValueError("The file could not be parsed as PCAP or PCAPNG.")



def reverse_dns(ip):
    try:
        host, aliases, addresses = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def classify_attack(stats, target):
    """
    Conservative rule-based attack assessment.

    Important change in v0.6:
    A high SYN count alone is NOT enough to classify a SYN flood.
    Application-bearing traffic is evaluated first.
    """

    total_flows = max(stats.get("tcp_flows", 0), 1)
    tcp_packets = max(stats.get("tcp_packets", 0), 1)

    low_data = stats.get("low_data_flows", 0)
    existing = stats.get("established_before_capture", 0)
    syns = stats.get("syn_packets", 0)
    syn_acks = stats.get("syn_ack_packets", 0)
    acks = stats.get("ack_packets", 0)
    psh = stats.get("psh_packets", 0)
    client_hellos = stats.get("client_hellos", 0)
    tls_app_packets = stats.get("tls_application_data_packets", 0)
    http_requests = stats.get("http_requests", 0)
    active = stats.get("active_application_flows", 0)
    payload_bytes = stats.get("tcp_payload_bytes", 0)

    low_ratio = low_data / total_flows
    existing_ratio = existing / total_flows
    syn_ratio = syns / tcp_packets
    ack_ratio = acks / tcp_packets
    psh_ratio = psh / tcp_packets

    target_packet_share = target.get("packet_share_pct", 0)
    target_flow_share = target.get("flow_share_pct", 0)
    target_payload_share = target.get("payload_share_pct", 0)

    # ----------------------------------------------------
    # 1. Application-bearing / web traffic first
    # ----------------------------------------------------
    # A web attack can naturally create many new TCP connections.
    # Therefore SYN volume must not override strong evidence that
    # traffic is progressing into application-bearing TCP sessions.
    strong_application_evidence = (
        tls_app_packets >= 50
        or http_requests >= 50
        or psh_ratio >= 0.15
        or (
            payload_bytes >= 1_000_000
            and ack_ratio >= 0.50
        )
    )

    strongly_targeted = max(
        target_packet_share,
        target_flow_share,
        target_payload_share,
    ) >= 70

    if strong_application_evidence and strongly_targeted:
        evidence = [
            f"{payload_bytes:,} bytes of TCP payload observed",
            f"{acks:,} ACK packets and {psh:,} PSH packets observed",
            f"{tls_app_packets:,} TLS Application Data packets observed",
            f"{http_requests:,} visible HTTP requests observed",
            f"{target_packet_share:.1f}% of packets target the main destination",
        ]

        return {
            "name": "Possible Web / Layer 7 DDoS",
            "confidence": "High" if target_packet_share >= 90 else "Medium",
            "summary": (
                "Traffic progresses beyond TCP connection setup and carries "
                "substantial application-bearing data toward one main destination. "
                "The SYN packets are treated as connection setup for this traffic, "
                "not as proof of a SYN flood."
            ),
            "evidence": evidence,
        }

    # ----------------------------------------------------
    # 2. TLS ClientHello-heavy behavior
    # ----------------------------------------------------
    if (
        client_hellos >= 100
        and client_hellos / total_flows >= 0.30
        and tls_app_packets < client_hellos * 0.20
    ):
        return {
            "name": "Possible TLS ClientHello Flood",
            "confidence": "Medium",
            "summary": (
                "A large share of flows starts TLS negotiation, while relatively "
                "little TLS application data is observed."
            ),
            "evidence": [
                f"{client_hellos:,} ClientHello packets",
                f"{tls_app_packets:,} TLS Application Data packets",
                f"{target_flow_share:.1f}% of TCP flows target the main destination",
            ],
        }

    # ----------------------------------------------------
    # 3. Low-data / connection-holding behavior
    # ----------------------------------------------------
    if total_flows >= 100 and low_ratio >= 0.70 and existing_ratio >= 0.50:
        return {
            "name": "Possible Low-Data Connection Flood",
            "confidence": "High" if low_ratio >= 0.90 else "Medium",
            "summary": (
                "The capture is dominated by many TCP flows carrying very little data."
            ),
            "evidence": [
                f"{low_data:,} low-data flows ({low_ratio * 100:.1f}%)",
                f"{existing:,} flows likely existed before capture ({existing_ratio * 100:.1f}%)",
                f"{active:,} flows show stronger application activity",
                f"{target_flow_share:.1f}% of TCP flows target the main destination",
            ],
        }

    # ----------------------------------------------------
    # 4. SYN flood only when SYN behavior dominates
    # ----------------------------------------------------
    # SYN flood classification now requires:
    #   - substantial SYN volume
    #   - SYNs make up a large share of TCP packets
    #   - very few SYN-ACK responses are visible
    #   - little ACK / PSH / application-bearing traffic
    #
    # This prevents normal TCP setup during a Layer 7 attack from
    # being mistaken for the attack vector itself.
    syn_dominant = (
        syns >= 100
        and syn_ratio >= 0.50
        and syn_acks / max(syns, 1) < 0.20
        and ack_ratio < 0.30
        and psh_ratio < 0.05
        and tls_app_packets < 20
        and http_requests < 20
        and payload_bytes < 500_000
    )

    if syn_dominant:
        return {
            "name": "Possible SYN Flood",
            "confidence": "Medium",
            "summary": (
                "TCP connection attempts dominate the capture and very little "
                "traffic progresses into established or application-bearing sessions."
            ),
            "evidence": [
                f"{syns:,} SYN packets ({syn_ratio * 100:.1f}% of TCP packets)",
                f"{syn_acks:,} SYN-ACK packets",
                f"{acks:,} ACK packets",
                f"{psh:,} PSH packets",
                f"{payload_bytes:,} bytes of TCP payload",
            ],
        }

    # ----------------------------------------------------
    # 5. Destination concentration without clear vector
    # ----------------------------------------------------
    if strongly_targeted:
        return {
            "name": "Traffic Concentrated on One Destination",
            "confidence": "Medium",
            "summary": (
                "Most observed traffic is directed to one destination, but the "
                "current evidence is not enough to classify the attack vector."
            ),
            "evidence": [
                f"{target_packet_share:.1f}% of packets",
                f"{target_flow_share:.1f}% of TCP flows",
                f"{target_payload_share:.1f}% of TCP payload",
            ],
        }

    return {
        "name": "Inconclusive",
        "confidence": "Low",
        "summary": (
            "The current capture does not provide enough evidence for a reliable "
            "attack classification."
        ),
        "evidence": [
            f"{total_flows:,} TCP flows",
            f"{low_data:,} low-data flows",
            f"{target_flow_share:.1f}% of TCP flows target the main destination",
        ],
    }



def analyze_pcap(path):
    fh, reader, capture_format = open_capture(path)

    stats = defaultdict(
        int,
        {
            "total_packets": 0,
            "total_bytes": 0,
            "ipv4_packets": 0,
            "ipv6_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "syn_packets": 0,
            "syn_ack_packets": 0,
            "ack_packets": 0,
            "fin_packets": 0,
            "rst_packets": 0,
            "psh_packets": 0,
            "tcp_payload_bytes": 0,
            "tls_records": 0,
            "client_hellos": 0,
            "server_hellos": 0,
            "tls_alerts": 0,
            "tls_application_data_packets": 0,
            "http_requests": 0,
            "http_responses": 0,
        },
    )

    stats["capture_format"] = capture_format

    flows = {}
    sources = defaultdict(int)
    destinations = defaultdict(int)
    dst_ports = defaultdict(int)
    destination_tcp_packets = defaultdict(int)
    destination_tcp_payload = defaultdict(int)

    first_ts = None
    last_ts = None

    try:
        for ts, raw in reader:
            stats["total_packets"] += 1
            stats["total_bytes"] += len(raw)

            if first_ts is None:
                first_ts = ts
            last_ts = ts

            try:
                eth = dpkt.ethernet.Ethernet(raw)
                ip = eth.data
            except Exception:
                continue

            if isinstance(ip, dpkt.ip.IP):
                stats["ipv4_packets"] += 1
            elif isinstance(ip, dpkt.ip6.IP6):
                stats["ipv6_packets"] += 1
            else:
                continue

            src = inet_to_str(ip.src)
            dst = inet_to_str(ip.dst)

            sources[src] += 1
            destinations[dst] += 1

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data

                stats["tcp_packets"] += 1
                dst_ports[tcp.dport] += 1
                destination_tcp_packets[dst] += 1

                syn = bool(tcp.flags & dpkt.tcp.TH_SYN)
                ack = bool(tcp.flags & dpkt.tcp.TH_ACK)
                psh = bool(tcp.flags & dpkt.tcp.TH_PUSH)
                fin = bool(tcp.flags & dpkt.tcp.TH_FIN)
                rst = bool(tcp.flags & dpkt.tcp.TH_RST)

                if syn and not ack:
                    stats["syn_packets"] += 1
                if syn and ack:
                    stats["syn_ack_packets"] += 1
                if ack:
                    stats["ack_packets"] += 1
                if psh:
                    stats["psh_packets"] += 1
                if fin:
                    stats["fin_packets"] += 1
                if rst:
                    stats["rst_packets"] += 1

                payload = bytes(tcp.data or b"")
                stats["tcp_payload_bytes"] += len(payload)
                destination_tcp_payload[dst] += len(payload)

                tls = tls_markers(payload)
                http = http_markers(payload)

                if tls["tls"]:
                    stats["tls_records"] += 1
                if tls["client_hello"]:
                    stats["client_hellos"] += 1
                if tls["server_hello"]:
                    stats["server_hellos"] += 1
                if tls["alert"]:
                    stats["tls_alerts"] += 1
                if tls["application_data"]:
                    stats["tls_application_data_packets"] += 1

                if http["request"]:
                    stats["http_requests"] += 1
                if http["response"]:
                    stats["http_responses"] += 1

                key = flow_key(src, tcp.sport, dst, tcp.dport)

                if key not in flows:
                    flows[key] = {
                        "Endpoint A": key[0],
                        "Port A": key[1],
                        "Endpoint B": key[2],
                        "Port B": key[3],
                        "first": ts,
                        "last": ts,
                        "Packets": 0,
                        "Bytes": 0,
                        "Payload Bytes": 0,
                        "Packets A→B": 0,
                        "Packets B→A": 0,
                        "Payload A→B": 0,
                        "Payload B→A": 0,
                        "SYN": False,
                        "SYN-ACK": False,
                        "ACK": False,
                        "PSH": False,
                        "FIN": False,
                        "RST": False,
                        "ClientHello": False,
                        "ServerHello": False,
                        "TLS Application Data": False,
                        "HTTP Request": False,
                        "HTTP Response": False,
                        "ClientHello Count": 0,
                        "ServerHello Count": 0,
                    }

                f = flows[key]

                f["last"] = ts
                f["Packets"] += 1
                f["Bytes"] += len(raw)
                f["Payload Bytes"] += len(payload)

                if (src, tcp.sport) == (f["Endpoint A"], f["Port A"]):
                    f["Packets A→B"] += 1
                    f["Payload A→B"] += len(payload)
                else:
                    f["Packets B→A"] += 1
                    f["Payload B→A"] += len(payload)

                if syn and not ack:
                    f["SYN"] = True
                if syn and ack:
                    f["SYN-ACK"] = True
                if ack and not syn:
                    f["ACK"] = True
                if psh:
                    f["PSH"] = True
                if fin:
                    f["FIN"] = True
                if rst:
                    f["RST"] = True

                if tls["client_hello"]:
                    f["ClientHello"] = True
                    f["ClientHello Count"] += 1

                if tls["server_hello"]:
                    f["ServerHello"] = True
                    f["ServerHello Count"] += 1

                if tls["application_data"]:
                    f["TLS Application Data"] = True

                if http["request"]:
                    f["HTTP Request"] = True

                if http["response"]:
                    f["HTTP Response"] = True

            elif isinstance(ip.data, dpkt.udp.UDP):
                stats["udp_packets"] += 1
                dst_ports[ip.data.dport] += 1

    finally:
        fh.close()

    capture_duration = (
        last_ts - first_ts
        if first_ts is not None and last_ts is not None
        else 0
    )

    stats["capture_duration"] = round(capture_duration, 3)
    stats["pps"] = (
        round(stats["total_packets"] / capture_duration, 2)
        if capture_duration > 0
        else 0
    )

    # This is deliberately called "TCP flows", not "TCP connections".
    stats["tcp_flows"] = len(flows)

    rows = []

    completed_handshakes = 0
    established_before_capture = 0
    established_with_payload = 0
    active_application_flows = 0
    inconclusive_flows = 0
    clienthello_flows = 0
    serverhello_flows = 0
    low_data_flows = 0

    for f in flows.values():
        duration = max(0, f["last"] - f["first"])

        handshake_complete = (
            f["SYN"]
            and f["SYN-ACK"]
            and f["ACK"]
        )

        bidirectional_packets = (
            f["Packets A→B"] > 0
            and f["Packets B→A"] > 0
        )

        bidirectional_payload = (
            f["Payload A→B"] > 0
            and f["Payload B→A"] > 0
        )

        has_payload = f["Payload Bytes"] > 0

        # ----------------------------------------------------
        # TCP state inference
        # ----------------------------------------------------
        if handshake_complete:
            completed_handshakes += 1

            if has_payload:
                tcp_state = "HANDSHAKE_OBSERVED_WITH_PAYLOAD"
                established_with_payload += 1
            else:
                tcp_state = "HANDSHAKE_OBSERVED"

        elif f["SYN"] and f["SYN-ACK"]:
            tcp_state = "HANDSHAKE_PARTIAL"

        elif f["SYN"] and not f["SYN-ACK"]:
            tcp_state = "NEW_CONNECTION_ATTEMPT"

        # The handshake may have happened before the capture started.
        # ACK + active data behavior is treated as evidence of an
        # already-established TCP session.
        elif (
            not f["SYN"]
            and f["ACK"]
            and (
                f["PSH"]
                or has_payload
                or bidirectional_packets
                or f["TLS Application Data"]
                or f["HTTP Request"]
                or f["HTTP Response"]
            )
        ):
            tcp_state = "ESTABLISHED_BEFORE_CAPTURE"
            established_before_capture += 1

            if has_payload:
                established_with_payload += 1

        elif f["FIN"] and f["ACK"]:
            tcp_state = "EXISTING_SESSION_CLOSING"

        elif f["RST"]:
            tcp_state = "RESET_OR_EXISTING_SESSION"

        else:
            tcp_state = "INCONCLUSIVE"
            inconclusive_flows += 1

        # ----------------------------------------------------
        # Payload state
        # ----------------------------------------------------
        if f["Payload Bytes"] == 0:
            payload_state = "NO_PAYLOAD"

        elif bidirectional_payload:
            payload_state = "BIDIRECTIONAL_PAYLOAD"

        elif f["Payload Bytes"] <= 1000:
            payload_state = "LOW_PAYLOAD"

        else:
            payload_state = "PAYLOAD_PRESENT"

        # ----------------------------------------------------
        # Application evidence
        # ----------------------------------------------------
        app_labels = []

        if f["ClientHello"]:
            app_labels.append("TLS_CLIENT_HELLO")

        if f["ServerHello"]:
            app_labels.append("TLS_SERVER_HELLO")

        if f["TLS Application Data"]:
            app_labels.append("TLS_APPLICATION_DATA")

        if f["HTTP Request"]:
            app_labels.append("HTTP_REQUEST")

        if f["HTTP Response"]:
            app_labels.append("HTTP_RESPONSE")

        if app_labels:
            application_state = ", ".join(app_labels)

        elif has_payload:
            application_state = "UNKNOWN_APPLICATION_PAYLOAD"

        else:
            application_state = "NO_APPLICATION_PAYLOAD"

        # Application activity is stronger than just seeing TCP ACKs.
        active_application = (
            f["TLS Application Data"]
            or f["HTTP Request"]
            or f["HTTP Response"]
            or bidirectional_payload
        )

        if active_application:
            active_application_flows += 1

        # Still only an analytical flag, not attack classification.
        low_data = (
            tcp_state
            in {
                "HANDSHAKE_OBSERVED",
                "HANDSHAKE_OBSERVED_WITH_PAYLOAD",
                "ESTABLISHED_BEFORE_CAPTURE",
                "EXISTING_SESSION_CLOSING",
            }
            and f["Payload Bytes"] <= 1000
        )

        if low_data:
            low_data_flows += 1

        if f["ClientHello"]:
            clienthello_flows += 1

        if f["ServerHello"]:
            serverhello_flows += 1

        rows.append(
            {
                "Endpoint A": f["Endpoint A"],
                "Port A": f["Port A"],
                "Endpoint B": f["Endpoint B"],
                "Port B": f["Port B"],
                "Packets": f["Packets"],
                "Packets A→B": f["Packets A→B"],
                "Packets B→A": f["Packets B→A"],
                "Bytes": f["Bytes"],
                "Payload Bytes": f["Payload Bytes"],
                "Payload A→B": f["Payload A→B"],
                "Payload B→A": f["Payload B→A"],
                "Duration (s)": round(duration, 4),
                "TCP State": tcp_state,
                "Payload State": payload_state,
                "Application State": application_state,
                "Handshake Complete": handshake_complete,
                "Bidirectional Packets": bidirectional_packets,
                "Bidirectional Payload": bidirectional_payload,
                "SYN": f["SYN"],
                "SYN-ACK": f["SYN-ACK"],
                "ACK": f["ACK"],
                "PSH": f["PSH"],
                "FIN": f["FIN"],
                "RST": f["RST"],
                "ClientHello": f["ClientHello"],
                "ServerHello": f["ServerHello"],
                "TLS Application Data": f["TLS Application Data"],
                "HTTP Request": f["HTTP Request"],
                "HTTP Response": f["HTTP Response"],
                "ClientHello Count": f["ClientHello Count"],
                "ServerHello Count": f["ServerHello Count"],
                "Low Data Flag": low_data,
            }
        )

    stats["completed_tcp_handshakes"] = completed_handshakes
    stats["tcp_handshake_completion_pct"] = pct(
        completed_handshakes,
        len(flows),
    )
    stats["established_before_capture"] = established_before_capture
    stats["established_with_payload"] = established_with_payload
    stats["active_application_flows"] = active_application_flows
    stats["inconclusive_flows"] = inconclusive_flows
    stats["clienthello_flows"] = clienthello_flows
    stats["serverhello_flows"] = serverhello_flows
    stats["low_data_flows"] = low_data_flows

    flow_df = pd.DataFrame(rows)

    if not flow_df.empty:
        flow_df = flow_df.sort_values(
            ["Packets", "Payload Bytes"],
            ascending=False,
        )


    destination_flow_counts = defaultdict(int)

    for f in flows.values():
        a_ip, a_port = f["Endpoint A"], f["Port A"]
        b_ip, b_port = f["Endpoint B"], f["Port B"]

        service_ports = {
            20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 389, 443, 445,
            465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389,
            5432, 6379, 8080, 8443
        }

        if a_port in service_ports and b_port not in service_ports:
            likely_dst = a_ip
        elif b_port in service_ports and a_port not in service_ports:
            likely_dst = b_ip
        else:
            likely_dst = (
                a_ip
                if destinations.get(a_ip, 0) >= destinations.get(b_ip, 0)
                else b_ip
            )

        destination_flow_counts[likely_dst] += 1

    all_destination_ips = set(destinations) | set(destination_tcp_payload) | set(destination_flow_counts)
    destination_rows = []

    for ip in all_destination_ips:
        destination_rows.append({
            "Destination IP": ip,
            "Packets": destinations.get(ip, 0),
            "Packet Share %": round(destinations.get(ip, 0) / max(stats["total_packets"], 1) * 100, 2),
            "TCP Flows": destination_flow_counts.get(ip, 0),
            "Flow Share %": round(destination_flow_counts.get(ip, 0) / max(stats["tcp_flows"], 1) * 100, 2),
            "TCP Payload Bytes": destination_tcp_payload.get(ip, 0),
            "Payload Share %": round(destination_tcp_payload.get(ip, 0) / max(stats["tcp_payload_bytes"], 1) * 100, 2),
        })

    destination_concentration_df = pd.DataFrame(destination_rows)

    if not destination_concentration_df.empty:
        destination_concentration_df = destination_concentration_df.sort_values(
            ["TCP Flows", "TCP Payload Bytes", "Packets"],
            ascending=False,
        )
        top = destination_concentration_df.iloc[0]
        target_ip = str(top["Destination IP"])
        target_info = {
            "ip": target_ip,
            "domain": reverse_dns(target_ip),
            "packet_share_pct": float(top["Packet Share %"]),
            "flow_share_pct": float(top["Flow Share %"]),
            "payload_share_pct": float(top["Payload Share %"]),
            "packets": int(top["Packets"]),
            "flows": int(top["TCP Flows"]),
            "payload_bytes": int(top["TCP Payload Bytes"]),
        }
    else:
        target_info = {
            "ip": None,
            "domain": None,
            "packet_share_pct": 0.0,
            "flow_share_pct": 0.0,
            "payload_share_pct": 0.0,
            "packets": 0,
            "flows": 0,
            "payload_bytes": 0,
        }

    src_df = pd.DataFrame(
        sorted(
            sources.items(),
            key=lambda x: x[1],
            reverse=True,
        ),
        columns=["Source IP", "Packets"],
    )

    dst_df = pd.DataFrame(
        sorted(
            destinations.items(),
            key=lambda x: x[1],
            reverse=True,
        ),
        columns=["Destination IP", "Packets"],
    )

    port_df = pd.DataFrame(
        sorted(
            dst_ports.items(),
            key=lambda x: x[1],
            reverse=True,
        ),
        columns=["Destination Port", "Packets"],
    )

    return (
        dict(stats),
        flow_df,
        src_df,
        dst_df,
        port_df,
        destination_concentration_df,
        target_info,
    )


with st.sidebar:
    st.title("🛡️ PCAP Analyzer")
    st.caption("Internal attack traffic analysis")

    page = st.radio(
        "Navigation",
        [
            "Analyze PCAP",
            "Detection Logic",
            "About",
        ],
    )

    st.divider()
    st.caption("Version 0.6")
    st.caption("Improved attack classification")


if page == "Analyze PCAP":
    st.title("PCAP Attack Traffic Analyzer")

    st.write(
        "Upload a PCAP or PCAPNG capture. The tool summarizes the important "
        "traffic behavior first, while keeping technical details available "
        "for deeper investigation."
    )

    uploaded = st.file_uploader(
        "Upload packet capture",
        type=["pcap", "pcapng", "cap"],
    )

    if uploaded is None:
        st.info("Upload a packet capture to begin.")

    else:
        data = uploaded.getvalue()

        a, b = st.columns([3, 1])
        a.success(f"Loaded: {uploaded.name}")
        b.metric("File size", human_bytes(len(data)))

        if st.button(
            "Analyze Traffic",
            type="primary",
            use_container_width=True,
        ):
            progress = st.progress(10, text="Preparing capture...")
            suffix = Path(uploaded.name).suffix or ".pcap"
            tmp_path = None

            try:
                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=suffix,
                ) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name

                progress.progress(40, text="Analyzing traffic behavior...")

                (
                    stats,
                    flows,
                    srcs,
                    dsts,
                    ports,
                    destination_concentration,
                    target_info,
                ) = analyze_pcap(tmp_path)

                assessment = classify_attack(stats, target_info)

                st.session_state["analysis"] = {
                    "filename": uploaded.name,
                    "stats": stats,
                    "flows": flows,
                    "sources": srcs,
                    "destinations": dsts,
                    "ports": ports,
                    "destination_concentration": destination_concentration,
                    "target_info": target_info,
                    "attack_assessment": assessment,
                }

                progress.progress(100, text="Analysis complete")
                progress.empty()

            except Exception as exc:
                progress.empty()
                st.error(f"Analysis failed: {exc}")

            finally:
                if tmp_path:
                    Path(tmp_path).unlink(missing_ok=True)

        analysis = st.session_state.get("analysis")

        if analysis and analysis["filename"] == uploaded.name:
            s = analysis["stats"]
            flows = analysis["flows"]

            st.divider()
            st.subheader("Traffic Overview")

            top = st.columns(4)
            top[0].metric("Packets", f'{s["total_packets"]:,}')
            top[1].metric("Capture time", f'{s["capture_duration"]} s')
            top[2].metric("TCP flows", f'{s["tcp_flows"]:,}')
            top[3].metric("TCP payload", human_bytes(s["tcp_payload_bytes"]))

            target = analysis["target_info"]
            assessment = analysis["attack_assessment"]

            st.subheader("Main Traffic Destination")

            if target["ip"]:
                d1, d2, d3, d4 = st.columns(4)
                d1.metric("Destination IP", target["ip"])
                d2.metric(
                    "Domain",
                    target["domain"] if target["domain"] else "No reverse DNS found",
                )
                d3.metric("Share of TCP flows", f'{target["flow_share_pct"]:.1f}%')
                d4.metric("Share of TCP payload", f'{target["payload_share_pct"]:.1f}%')

                if max(
                    target["packet_share_pct"],
                    target["flow_share_pct"],
                    target["payload_share_pct"],
                ) >= 50:
                    st.caption(
                        "This IP receives the largest share of observed traffic and is the current best candidate for the attacked destination."
                    )
                else:
                    st.caption(
                        "This is the largest destination in the capture, but traffic is not strongly concentrated on one IP."
                    )
            else:
                st.warning("No clear destination IP could be identified.")

            st.subheader("Attack Conclusion")
            st.markdown(
                f"**{assessment['name']}**  \nConfidence: **{assessment['confidence']}**"
            )
            st.write(assessment["summary"])
            st.markdown("**Why:**")
            for item in assessment["evidence"]:
                st.write(f"• {item}")

            total_flows = max(s["tcp_flows"], 1)
            likely_existing = s["established_before_capture"]
            low_data = s["low_data_flows"]
            active_app = s["active_application_flows"]
            existing_pct = round((likely_existing / total_flows) * 100, 1)
            low_data_pct = round((low_data / total_flows) * 100, 1)

            st.subheader("What the capture shows")

            c1, c2, c3 = st.columns(3)

            with c1:
                st.markdown("**Connections**")
                st.metric(
                    "Likely existing before capture",
                    f"{likely_existing:,}",
                    f"{existing_pct}% of TCP flows",
                )
                st.metric(
                    "New connection attempts seen",
                    f'{s["syn_packets"]:,}',
                )
                st.caption(
                    "Most flows look like they were already active when the capture started."
                )

            with c2:
                st.markdown("**Data**")
                st.metric(
                    "Low-data flows",
                    f"{low_data:,}",
                    f"{low_data_pct}% of TCP flows",
                )
                st.metric(
                    "Flows with stronger app activity",
                    f"{active_app:,}",
                )
                st.caption(
                    "Most flows carry only a small amount of payload."
                )

            with c3:
                st.markdown("**Protocols**")
                st.metric("TLS ClientHello", f'{s["client_hellos"]:,}')
                st.metric(
                    "TLS Application Data",
                    f'{s["tls_application_data_packets"]:,}',
                )
                st.caption(
                    "Protocol evidence helps show whether traffic reached the application layer."
                )


            with st.expander("Detailed TCP statistics"):
                cols = st.columns(4)
                cols[0].metric("SYN", f'{s["syn_packets"]:,}')
                cols[1].metric("SYN-ACK", f'{s["syn_ack_packets"]:,}')
                cols[2].metric(
                    "Completed handshakes",
                    f'{s["completed_tcp_handshakes"]:,}',
                )
                cols[3].metric(
                    "Inconclusive flows",
                    f'{s["inconclusive_flows"]:,}',
                )

                cols = st.columns(4)
                cols[0].metric(
                    "Likely existing flows",
                    f'{s["established_before_capture"]:,}',
                )
                cols[1].metric(
                    "Established with payload",
                    f'{s["established_with_payload"]:,}',
                )
                cols[2].metric(
                    "Active application flows",
                    f'{s["active_application_flows"]:,}',
                )
                cols[3].metric(
                    "Low-data flows",
                    f'{s["low_data_flows"]:,}',
                )

            with st.expander("Detailed TLS / HTTP statistics"):
                cols = st.columns(5)
                cols[0].metric("TLS records", f'{s["tls_records"]:,}')
                cols[1].metric("ClientHello", f'{s["client_hellos"]:,}')
                cols[2].metric("ServerHello", f'{s["server_hellos"]:,}')
                cols[3].metric(
                    "TLS App Data",
                    f'{s["tls_application_data_packets"]:,}',
                )
                cols[4].metric(
                    "HTTP requests",
                    f'{s["http_requests"]:,}',
                )

            with st.expander("TCP flow table"):
                if flows.empty:
                    st.info("No TCP flows found.")
                else:
                    preferred = [
                        "Endpoint A",
                        "Port A",
                        "Endpoint B",
                        "Port B",
                        "Packets",
                        "Payload Bytes",
                        "Duration (s)",
                        "TCP State",
                        "Payload State",
                        "Application State",
                    ]
                    simple_flows = flows[
                        [c for c in preferred if c in flows.columns]
                    ]

                    st.dataframe(
                        simple_flows,
                        use_container_width=True,
                        hide_index=True,
                    )

                    st.download_button(
                        "Download full flow analysis as CSV",
                        flows.to_csv(index=False).encode(),
                        "tcp_flow_analysis.csv",
                        "text/csv",
                    )

            with st.expander("Destination concentration"):
                dc = analysis["destination_concentration"]
                if dc.empty:
                    st.info("No destination concentration data available.")
                else:
                    st.dataframe(
                        dc.head(20),
                        use_container_width=True,
                        hide_index=True,
                    )

            with st.expander("Source and destination details"):
                tabs = st.tabs(
                    ["Sources", "Destinations", "Destination Ports"]
                )

                with tabs[0]:
                    st.dataframe(
                        analysis["sources"].head(100),
                        use_container_width=True,
                        hide_index=True,
                    )

                with tabs[1]:
                    st.dataframe(
                        analysis["destinations"].head(100),
                        use_container_width=True,
                        hide_index=True,
                    )

                with tabs[2]:
                    st.dataframe(
                        analysis["ports"].head(100),
                        use_container_width=True,
                        hide_index=True,
                    )

            st.subheader("Terms Used")
            st.markdown(
                """
                **TCP flow:** Packets that belong to the same TCP conversation, identified by the two IP addresses and two TCP ports.

                **Likely existing before capture:** The handshake was not captured, but later packet behavior suggests the connection was already active.

                **Low-data flow:** A likely active TCP flow carrying 1 KB or less of TCP payload during this capture.

                **Active application flow:** A flow with stronger evidence of application communication, such as TLS application data, visible HTTP, or payload in both directions.

                **ClientHello:** The first TLS handshake message normally sent by a client when starting a TLS session.

                **Main traffic destination:** The destination IP receiving the largest share of observed traffic. It is the best target candidate, not automatic proof by itself.
                """
            )

elif page == "Detection Logic":
    st.title("Detection Logic")

    st.write(
        "The attack classifier is not enabled yet. "
        "Version 0.6 focuses on reliable feature extraction."
    )

    df = pd.DataFrame(
        [
            [
                "TLS ClientHello Flood",
                "TCP state, ClientHello rate, ServerHello ratio, "
                "flow duration, application-data ratio",
                "Next phase",
            ],
            [
                "Low Data Connection Attack",
                "Established session inference, payload size, "
                "directionality, duration, repetition",
                "Next phase",
            ],
            [
                "Layer 7 HTTP Flood",
                "HTTP request rate, methods, URI repetition, "
                "source distribution, active application sessions",
                "Planned",
            ],
            [
                "SYN Flood",
                "SYN rate, SYN-ACK ratio, observed handshake completion",
                "Planned",
            ],
        ],
        columns=[
            "Attack Type",
            "Evidence",
            "Status",
        ],
    )

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )


else:
    st.title("About")

    st.write(
        "Internal PCAP analysis project for identifying attack "
        "traffic and eventually providing evidence-based "
        "mitigation recommendations."
    )

    st.markdown(
        "**Current:** "
        "`PCAP → Parsing → TCP flows → TCP state inference → "
        "Payload analysis → TLS / HTTP evidence`"
    )

    st.markdown(
        "**Next:** "
        "`Features → Attack classification → Confidence → "
        "Protection recommendations`"
    )
