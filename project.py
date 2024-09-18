import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

file_path = 'C:\\Users\\masha\\OneDrive\\Desktop\\project\\Wigle_wifi.csv'
wifi_data = pd.read_csv(file_path)

 #Drop rows with missing SSID values as SSID is crucial for the analysis
cleaned_data = wifi_data.dropna(subset=['SSID'])

print(cleaned_data.head())
# Assuming 'data_cleaned' is your cleaned DataFrame
output_file_path = 'cleaned_wigle_data.csv'  # Specify your desired file path and name

# Save the cleaned data to a new CSV file
cleaned_data.to_csv(output_file_path, index=False)

print(f"Cleaned data saved to {output_file_path}")


if 'Encryption' in cleaned_data.columns:
    security_type_counts = cleaned_data['Encryption'].value_counts()
else:
    print("Column 'Encryption' does not exist.")

if 'Channel' in cleaned_data.columns:
    cleaned_data['Channel'] = cleaned_data['Channel'].astype(str).str.replace('ch: ', '', regex=False)
else:
    print("Column 'Channel' does not exist.")
non_string_values = cleaned_data[~cleaned_data['Channel'].apply(lambda x: isinstance(x, str))]
print(non_string_values)

# Assume cleaned_data is already loaded
# Check and correct the 'Channel' column
if 'Channel' in cleaned_data.columns:
    cleaned_data['Channel'] = cleaned_data['Channel'].astype(str).str.replace('ch: ', '', regex=False)
else:
    print("Column 'Channel' does not exist.")
encryption_categories = {
    '[WPA2-PSK+FT/PSK-CCMP][RSN-PSK+FT/PSK-CCMP][ESS]': 'WPA2',
    '[ESS]': 'Open',
    'WPA3': 'WPA3'
}
cleaned_data['Encryption_category'] = cleaned_data['Encryption'].map(encryption_categories)
cleaned_data['Encryption_category'].fillna('Unknown', inplace=True)
print(cleaned_data['Encryption_category'].unique())
encryption_counts = cleaned_data['Encryption_category'].value_counts()
# Summary of encryption types
encryption_summary = cleaned_data['Encryption'].value_counts()
print(encryption_summary)


# Assess vulnerability (e.g., how many networks use weak encryption)
vulnerable_networks = cleaned_data[cleaned_data['Encryption'].isin([ 'Open'])]
print(f"Number of vulnerable networks: {len(vulnerable_networks)}")

# Save vulnerable networks to CSV
vulnerable_networks.to_csv('vulnerable_networks.csv', index=False)

# Check and work with the 'Encryption' column
if 'Encryption' in cleaned_data.columns:
    security_type_counts = cleaned_data['Encryption'].value_counts()
    print(security_type_counts)
else:
    print("Column 'Encryption' does not exist.")


# Assuming cleaned_data is already defined and loaded

# Check if the 'QoS' column exists
if 'QoS' in cleaned_data.columns:
    # If it exists, proceed to replace the 'QoS: ' prefix
    cleaned_data['QoS'] = cleaned_data['QoS'].astype(str).str.replace('QoS: ', '', regex=False)
else:
    # If it doesn't exist, print an error message or handle it accordingly
    print("Column 'QoS' does not exist in the DataFrame.")

# Normalize Network Type information by removing 'type: ' prefix
cleaned_data['Encryption'] = cleaned_data['Encryption'].str.replace('type: ', '')
# Display cleaned data summary
cleaned_data.head(), cleaned_data.info()

# Count the number of networks for each Security Type
security_type_counts = cleaned_data['Encryption'].value_counts()

# Display the count of each Security Type
print(security_type_counts)

# Step 3: Identify SSIDs with potentially sensitive information
# We will look for SSIDs that contain common personal or business-related keywords
sensitive_keywords = ['home', 'office', 'corp', 'guest', 'family', 'personal', 'business', 'company', 'private']


sensitive_ssids = cleaned_data[cleaned_data['SSID'].str.contains('|'.join(sensitive_keywords), case=False, na=False)]

# Display the SSIDs that contain sensitive information
sensitive_ssids[['SSID', 'Encryption', 'MAC']]

# Bar Chart: Distribution of Network Types
network_type_counts = cleaned_data['Encryption'].value_counts()

plt.figure(figsize=(10, 6))
network_type_counts.plot(kind='bar', color='lightgreen')
plt.title('Distribution of Network Types')
plt.xlabel('Encryption')
plt.ylabel('Number of Networks')
plt.xticks(rotation=0)
plt.show()


# Option 2: If appropriate, convert some columns to numeric types (example below)
# cleaned_data['SomeColumn'] = pd.to_numeric(cleaned_data['SomeColumn'], errors='coerce')
# correlation_matrix = cleaned_data.corr()


# Bar Chart: Frequency of Network Channels
channel_counts = cleaned_data['Channel'].value_counts()

plt.figure(figsize=(10, 6))
channel_counts.plot(kind='bar', color='dodgerblue')
plt.title('Frequency of Network Channels')
plt.xlabel('Channel')
plt.ylabel('Number of Networks')
plt.xticks(rotation=0)
plt.show()
# Generate a report on vulnerable networks
report = f"""
Total networks analyzed: {len(cleaned_data)}
Number of vulnerable networks: {len(vulnerable_networks)}
- Open: {len(vulnerable_networks[vulnerable_networks['Encryption'] == 'Open'])}

Recommendations:
- Upgrade encryption to WPA3 or higher.
- Disable SSID broadcasting for privacy.
- Implement MAC address randomization.
"""

# Save the report to a file
with open('security_report.txt', 'w') as f:
    f.write(report)

print("Report generated and saved as 'security_report.txt'")

