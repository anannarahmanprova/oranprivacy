import json
import pandas as pd

# Load JSON data
with open('clean4.json') as f:
    data = json.load(f)

# Initialize a list to collect the data
records = []

# Parse through the JSON structure
for entry in data:
    if entry.get("type") == "metrics":
        time = entry.get("timestamp", None)
        for cell in entry.get("cell_list", []):
            for ue in cell.get("cell_container", {}).get("ue_list", []):
                ue_data = ue.get("ue_container", {})
                
                # Extract only the required fields
                record = {
                    "timestamp": time,
                    "dl_mcs": ue_data.get("dl_mcs", None),
                    "dl_bitrate": ue_data.get("dl_bitrate", None),
                    "dl_bler": ue_data.get("dl_bler", None),
                    "ul_snr": ue_data.get("ul_snr", None),
                    "ul_mcs": ue_data.get("ul_mcs", None),
                    "ul_bitrate": ue_data.get("ul_bitrate", None),
                    "ul_bler": ue_data.get("ul_bler", None),
                    "ul_phr": ue_data.get("ul_phr", None),
                    "ul_bsr": ue_data.get("ul_bsr", None),
                    "output": 0,
                }
                records.append(record)

# Convert to DataFrame
df = pd.DataFrame(records)

# Save to Excel
df.to_excel('clean4.xlsx', index=False)

