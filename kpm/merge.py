import pandas as pd
import glob

# Define the path to your files (adjust the path and file pattern as necessary)
file_pattern = '*.xlsx'  # Adjust as needed to match all your files
files = glob.glob(file_pattern)

# Initialize a list to collect DataFrames
df_list = []

# Load each file and append it to the list
for file in files:
    df = pd.read_excel(file)
    df_list.append(df)

# Concatenate all DataFrames in the list
merged_df = pd.concat(df_list, ignore_index=True)

# Sort the merged DataFrame by the 'timestamp' column in ascending order
merged_df.sort_values(by='timestamp', inplace=True)

# Save the sorted DataFrame to a new Excel file
merged_df.to_excel('input.xlsx', index=False)

