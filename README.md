# Network-Analysis
### Project Overview
This project involves capturing and analyzing network traffic to identify signs of a data breach, such as unencrypted sensitive data, unusual traffic patterns, or unauthorized access attempts. Wireshark, a powerful open-source network protocol analyzer, will be used to inspect packet-level data and detect anomalies that may indicate a breach.

### Tools and Requirements
- **Wireshark**: For packet capturing and analysis.
- **Sample PCAP Files**: Use publicly available PCAP files (e.g., from Wireshark’s sample capture repository or open datasets like the CICIDS2017 dataset) or simulate a controlled network environment.
- **Python (Optional)**: For scripting automated analysis of PCAP files.
- **Secure Environment**: A virtual machine or isolated network to avoid real-world data exposure.

### Project Steps

1. **Setup and Data Collection**
   - Install Wireshark on a secure system.
   - Obtain or generate PCAP files:
     - Use sample PCAP files from trusted sources.
     - Alternatively, set up a controlled network environment (e.g., using VirtualBox with virtual machines) to simulate network traffic, including normal and malicious activities.
   - Ensure compliance with legal and ethical guidelines if capturing live traffic.

2. **Defining Sensitive Data Patterns**
   - Identify common sensitive data types to monitor, such as:
     - Credit card numbers (e.g., 16-digit patterns matching Luhn algorithm).
     - Passwords or authentication credentials.
     - Personal identifiable information (PII) like SSNs, email addresses, or phone numbers.
   - Create Wireshark display filters (e.g., `http contains "password"` or `tcp contains "credit card"`) to search for these patterns.

3. **Traffic Analysis**
   - Load PCAP files into Wireshark.
   - Apply filters to identify:
     - Unencrypted protocols (e.g., HTTP, FTP, Telnet) transmitting sensitive data.
     - Suspicious IP addresses or ports (e.g., unexpected outbound connections to known malicious IPs).
     - Anomalous traffic spikes or unusual packet sizes.
   - Use Wireshark’s “Follow TCP Stream” feature to reconstruct data flows and inspect payloads for sensitive information.
   - Analyze protocol-specific behaviors (e.g., HTTP POST requests, SMTP email transfers) for signs of data exfiltration.

4. **Identifying Breach Indicators**
   - Look for common breach indicators:
     - Large data transfers to unknown external IPs.
     - Repeated failed login attempts (e.g., SMB or SSH brute-force patterns).
     - Plaintext credentials in packet payloads.
   - Use Wireshark’s statistics tools (e.g., Conversations, Endpoints) to detect anomalies in traffic volume or destination.
