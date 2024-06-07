import pandas as pd
import random
from datetime import datetime, timedelta
import ipaddress

# Generate random IP addresses
def generate_random_ip():
    return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

# Generate random data
data = []
protocols = ['TCP', 'UDP', 'ICMP']
signatures = ['sig1', 'sig2', 'sig3', 'sig4']

start_time = datetime.now()
for _ in range(100):
    src_ip = generate_random_ip()
    dst_ip = generate_random_ip()
    src_port = random.randint(1024, 65535)
    dst_port = random.randint(1024, 65535)
    protocol = random.choice(protocols)
    signature = random.choice(signatures)
    timestamp = start_time - timedelta(seconds=random.randint(0, 3600))  # last hour
    data.append([src_ip, dst_ip, src_port, dst_port, protocol, signature, timestamp])

# Create DataFrame
df = pd.DataFrame(data, columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'signature', 'timestamp'])

# Save to CSV
df.to_csv('real_time_data.csv', index=False)
