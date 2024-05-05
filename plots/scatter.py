import pandas as pd
import matplotlib.pyplot as plt

# Sample data
data = {
    'dport': [61159, 40443, 61157],
    'sport': [40443, 61159, 40443],
    'protocol': [6, 6, 6],
    'flags': ['PA', 'A', 'A'],
    'time_bw_prev_packet': [1714652098.971994, 0.0451357364654541, 0.15325641632080078],
    'spkts': [0, 20, 0],
    'dpkts': [310, 0, 1460],
    'pkt_len': [290, 0, 1440],
    'ttl': [38, 128, 38],
    'payload_size': [248, 248, 248],
    'label': ['benign', 'benign', 'benign']
}

# Create DataFrame
df = pd.DataFrame(data)

# Plot scatter plot
plt.scatter(df['time_bw_prev_packet'], df['pkt_len'], c='blue', label='Packet Length')

# Set labels and title
plt.xlabel('Time Between Previous Packet')
plt.ylabel('Packet Length')
plt.title('Scatter Plot of Packet Length vs Time Between Previous Packet')

# Show legend
plt.legend()

# Show plot
plt.show()
