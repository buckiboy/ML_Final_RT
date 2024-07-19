import pandas as pd
import re

def parse_tcpdump_log(log_file):
    # Regular expression pattern for parsing tcpdump logs
    tcpdump_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}\s+\d+:\d+:\d+\.\d+)\s+(IP|IP6)\s+([^>]+)\s+>\s+([^:]+):\s+([A-Z]+),\s+length\s+\d+')
    ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\.(\d+)')
    ip6_pattern = re.compile(r'([a-fA-F0-9:]+)\.(\d+)')

    parsed_data = []

    with open(log_file, 'r') as file:
        lines = file.readlines()

        for line in lines:
            match = tcpdump_pattern.match(line)
            if match:
                timestamp = match.group(1)
                protocol = match.group(5)
                src = match.group(3)
                dst = match.group(4)

                if 'IP' in match.group(2):
                    src_ip_match = ip_pattern.match(src) if 'IP' == match.group(2) else ip6_pattern.match(src)
                    dst_ip_match = ip_pattern.match(dst) if 'IP' == match.group(2) else ip6_pattern.match(dst)
                    
                    if src_ip_match and dst_ip_match:
                        src_ip = src_ip_match.group(1)
                        src_port = src_ip_match.group(2)
                        dst_ip = dst_ip_match.group(1)
                        dst_port = dst_ip_match.group(2)
                    else:
                        print(f"Failed to match IP addresses for line: {line}")
                        continue

                parsed_data.append({
                    'timestamp': timestamp,
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port
                })
            else:
                print(f"Failed to match line: {line}")

    return pd.DataFrame(parsed_data)

def preprocess_and_save_to_csv(df, output_file):
    # Reorder columns to place timestamp first
    columns = ['timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port']
    df = df[columns]

    # Deduplicate the DataFrame
    df = df.drop_duplicates()

    # Print the DataFrame for debugging
    print("Parsed DataFrame:")
    print(df.head())

    # Save the DataFrame to a CSV file
    df.to_csv(output_file, index=False)

if __name__ == '__main__':
    log_file = 'tcpdump_data_mixed.txt'  # Path to your tcpdump log file
    output_file = 'parsed_tcpdump_logs_mixed.csv'

    df = parse_tcpdump_log(log_file)
    if not df.empty:
        preprocess_and_save_to_csv(df, output_file)
        print(f'Parsed data saved to {output_file}')
    else:
        print("Error: Parsed DataFrame is empty. Please check the log file and parsing logic.")
