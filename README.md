# PCAP Attack Analyzer v0.8

A local Streamlit tool for investigating packet captures and comparing suspected attack traffic with a peace-time baseline.

## Features

- **Peace Time vs Attack:** upload two PCAP/PCAPNG captures and compare their behavior.
- **Attack PCAP only:** analyze a capture without a baseline.
- **Optional target IP:** include only packets where the specified IP is the source or destination in each capture.
- **Traffic analysis:** TCP flows, TCP flags, payload, low-data flows, TLS record indicators, visible plaintext HTTP, and destination concentration.
- **Attack assessment:** rule-based preliminary classification with supporting evidence. Baseline comparison uses rate changes and behavioral ratios.
- **Technical details:** expandable tables and downloadable attack flow CSV.

## Requirements

- Python 3.10 or newer (recommended)
- Packages in `requirements.txt`: Streamlit, pandas, dpkt

## Installation

Extract the ZIP and open a terminal in the extracted directory.

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

On some Windows systems use `py` instead of `python`.

## How to use

1. Select **Compare Peace Time vs Attack** or **Attack PCAP only**.
2. Upload the requested capture files (`.pcap`, `.pcapng`, or `.cap`).
3. Select **Entire PCAP** or **Specific IP address**. For an IP-specific comparison, enter the same target IP to filter both captures.
4. Click **Analyze Traffic**.
5. Review the assessment and evidence, the normalized comparison table, and detailed TCP/TLS tables.

## Comparison methodology

Capture lengths and packet counts do **not** need to match. The comparison uses the observed capture duration to calculate packets/sec, TCP flows/sec, SYN/sec, TCP payload bytes/sec, TLS Application Data/sec, ClientHello/sec, and visible HTTP requests/sec. It also compares composition metrics such as SYN/ACK/PSH share, low-data-flow share, active-application-flow share, and bytes per flow.

**Important:** v0.8 does not perform equal-packet subsampling. It compares full captures using time-normalized rates and behavior ratios. A very short capture, truncated capture, or capture missing return traffic may make the comparison unreliable. TCP flow counts and TLS indicators are inferred from captured evidence and are not definitive proof of a completed connection or an HTTP attack.

## Limitations

- Attack classifications are heuristic, not a definitive malicious/benign verdict.
- TLS Application Data indicates encrypted application traffic, not necessarily HTTP or a confirmed Layer 7 DDoS.
- Packet-level TLS detection may miss records split across TCP segments.
- Reverse DNS depends on available network/DNS resolution and is not proof of application ownership.
- A peace-time capture should represent the same service, observation point, and ideally similar normal operating conditions.
- The comparison currently treats each full capture as one interval rather than evaluating shorter time windows or statistically matched samples.

## Dependencies

`requirements.txt` contains only the third-party packages imported by the application. The v0.8 comparison feature does not require additional packages.

## Version history

- **v0.8:** peace-time vs attack comparison, normalized rate/behavior table, baseline-aware attack assessment, retained IP filtering.
- **v0.7:** optional specific-IP analysis.
- **v0.6:** application evidence prioritized over SYN counts to reduce false SYN-flood conclusions.
- **v0.5:** main destination, reverse DNS, concentration, early attack assessment and glossary.
- **v0.4:** simplified overview and expandable technical details.
- **v0.3:** directional TCP flow and TLS/HTTP evidence tracking.
