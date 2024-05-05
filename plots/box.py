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

# Select numerical columns for box plot
numerical_columns = ['time_bw_prev_packet', 'spkts', 'dpkts', 'pkt_len', 'ttl', 'payload_size']

# Create box plot
plt.figure(figsize=(10, 6))
df[numerical_columns].boxplot()

# Set title and labels
plt.title('Box Plot of Numerical Variables')
plt.ylabel('Values')

# Rotate x-axis labels for better readability
plt.xticks(rotation=45)

# Show plot
plt.show()
