import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Sample data
data = {
    'dport': [61159, 40443, 61157],
    'sport': [40443, 61159, 40443],
    'protocol': [6, 6, 6],
    'flags': [10, 0, 0],
    'time_bw_prev_packet': [1714652098.971994, 0.0451357364654541, 0.15325641632080078],
    'spkts': [0, 20, 0],
    'dpkts': [310, 0, 1460],
    'pkt_len': [290, 0, 1440],
    'ttl': [38, 128, 38],
    'payload_size': [248, 248, 248],
    'label': [0, 0, 0]
}

# Create DataFrame
df = pd.DataFrame(data)

# Calculate correlation matrix
corr_matrix = df.corr()

# Create heatmap
plt.figure(figsize=(10, 8))
sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', fmt=".2f")

# Set title and labels
plt.title('Heatmap of Correlation Matrix')
plt.xlabel('Features')
plt.ylabel('Features')

# Show plot
plt.show()
