# PCAP Attack Analyzer v0.3

This version improves TCP flow analysis for captures that begin after
connections were already established.

## Main changes

- Renamed TCP connections to TCP flows.
- Infers ESTABLISHED_BEFORE_CAPTURE when the SYN handshake is missing but
  packet behavior indicates an already active session.
- Tracks packets and payload independently in both directions.
- Detects PSH and ACK evidence.
- Detects TLS Application Data in addition to ClientHello and ServerHello.
- Detects visible plaintext HTTP requests and responses.
- Adds TCP State, Payload State, and Application State to every TCP flow.
- Keeps Low Data as an analytical flag only, not an attack verdict.

## Important

The tool still does not classify traffic as legitimate or malicious.
It reports protocol evidence that will later feed the attack classifier.

## Run

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Start the application:

```bash
python -m streamlit run app.py
```


## v0.4 UI update

The main screen now shows only the most important analyst information:

- overall capture size and flow count
- likely existing vs new connection behavior
- low-data vs stronger application activity
- key TLS protocol indicators
- a simple current assessment

Detailed TCP, TLS, HTTP, flow, source, destination, and port statistics are
still available inside expandable sections.
