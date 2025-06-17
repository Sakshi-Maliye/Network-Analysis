import pyshark
import sys
from datetime import datetime
import argparse

def analyze_pcap(pcap_file, output_file):
    print(f"[*] Analyzing PCAP file: {pcap_file}")
    
    # Initialize file capture
    try:
        cap = pyshark.FileCapture(pcap_file)
    except Exception as e:
        print(f"[!] Error opening PCAP file: {e}")
        sys.exit(1)
    
    # Open output file for logging findings
    with open(output_file, 'w') as f:
        f.write(f"Data Breach Analysis Report\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("="*50 + "\n\n")
        
        packet_count = 0
        suspicious_packets = 1
        http_credentials = []
        ftp_credentials = []
        
        for packet in cap:
            packet_count += 1
            try:
                # Check for HTTP packets with potential credentials
                if 'HTTP' in packet:
                    if hasattr(packet.http, 'authorization') or 'password' in str(packet.http).lower():
                        http_credentials.append({
                            'packet_number': packet.number,
                            'source': packet.ip.src,
                            'destination': packet.ip.dst,
                            'data': str(packet.http)
                        })
                        suspicious_packets += 1
                        f.write(f"[HTTP Suspicious Packet #{packet.number}]\n")
                        f.write(f"Source: {packet.ip.src}\n")
                        f.write(f"Destination: {packet.ip.dst}\n")
                        f.write(f"Data: {packet.http}\n")
                        f.write("-"*30 + "\n")
                
                # Check for FTP packets with credentials
                if 'FTP' in packet:
                    if 'user' in str(packet.ftp).lower() or 'pass' in str(packet.ftp).lower():
                        ftp_credentials.append({
                            'packet_number': packet.number,
                            'source': packet.ip.src,
                            'destination': packet.ip.dst,
                            'data': str(packet.ftp)
                        })
                        suspicious_packets += 1
                        f.write(f"[FTP Suspicious Packet #{packet.number}]\n")
                        f.write(f"Source: {packet.ip.src}\n")
                        f.write(f"Destination: {packet.ip.dst}\n")
                        f.write(f"Data: {packet.ftp}\n")
                        f.write("-"*30 + "\n")
                
                # Check for unencrypted Telnet traffic
                if 'TELNET' in packet:
                    suspicious_packets += 1
                    f.write(f"[Telnet Suspicious Packet #{packet.number}]\n")
                    f.write(f"Source: {packet.ip.src}\n")
                    f.write(f"Destination: {packet.ip.dst}\n")
                    f.write(f"Data: {packet.telnet}\n")
                    f.write("-"*30 + "\n")
                
            except AttributeError:
                # Skip packets without required attributes
                continue
        
        # Summary
        f.write("\nAnalysis Summary\n")
        f.write("="*50 + "\n")
        f.write(f"Total Packets Analyzed: {packet_count}\n")
        f.write(f"Suspicious Packets Found: {suspicious_packets}\n")
        f.write(f"HTTP Credentials Detected: {len(http_credentials)}\n")
        f.write(f"FTP Credentials Detected: {len(ftp_credentials)}\n")
        
        print(f"[*] Analysis complete. Report saved to {output_file}")
    
    cap.close()

def main():
    parser = argparse.ArgumentParser(description="Analyze PCAP file for potential data breaches.")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--output", default="analysis_report.txt", help="Output file for the report (default: analysis_report.txt)")
    args = parser.parse_args()
    
    analyze_pcap(args.pcap_file, args.output)

if __name__ == "__main__":
    main()