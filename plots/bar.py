import pandas as pd
import matplotlib.pyplot as plt

# Creating a DataFrame from the provided data
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

df = pd.DataFrame(data)

# Extracting the 'protocol' column
protocols = df['protocol']

# Counting the frequency of each unique protocol
protocol_counts = protocols.value_counts()

# Creating the bar chart
protocol_counts.plot(kind='bar', color='skyblue')

# Adding labels and title
plt.xlabel('Protocol')
plt.ylabel('Frequency')
plt.title('Frequency of Protocols')

# Showing the plot
plt.show()
