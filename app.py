
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
    st.caption("Version 0.4")
    st.caption("Simplified analyst view")


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

                stats, flows, srcs, dsts, ports = analyze_pcap(tmp_path)

                st.session_state["analysis"] = {
                    "filename": uploaded.name,
                    "stats": stats,
                    "flows": flows,
                    "sources": srcs,
                    "destinations": dsts,
                    "ports": ports,
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

            st.info(
                "Current assessment: attack classification is not enabled yet. "
                "This view only summarizes the observed traffic behavior."
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

elif page == "Detection Logic":
    st.title("Detection Logic")

    st.write(
        "The attack classifier is not enabled yet. "
        "Version 0.4 focuses on reliable feature extraction."
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
