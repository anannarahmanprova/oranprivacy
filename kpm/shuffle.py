import pandas as pd
from sklearn.utils import shuffle

# Load the Excel file
file_path = 'input.xlsx'
df = pd.read_excel(file_path)

# Store the output column values before dropping 'timestamp' and 'output'
output_values = df['output'].copy() if 'output' in df.columns else pd.Series([1] * len(df))
df = df.drop(columns=['timestamp', 'output'], errors='ignore')

# Initialize a list to store the merged rows
merged_rows = []

# Process every 5 rows to create merged rows with expanded columns
for i in range(0, len(df), 8):
    subset = df.iloc[i:i+8]
    output_subset = output_values[i:i+8]
    
    if len(subset) < 8:
        continue  # Skip if there are less than 5 rows
    
    # Initialize a dictionary for the merged row
    merged_row = {}
    
    # Append each metric for all 5 rows in a single merged row
    for j in range(8):
        row = subset.iloc[j]
        for col in df.columns:
            merged_row[f"{col}_{j+1}"] = row[col]
    
    # Store the product of the original output values as the final output
    merged_row['output'] = output_subset.prod()
    
    # Add the merged row to the list
    merged_rows.append(merged_row)

# Convert the list of merged rows to a DataFrame
merged_df = pd.DataFrame(merged_rows)

# Shuffle the entire DataFrame to randomize the row order
final_df = shuffle(merged_df).reset_index(drop=True)

# Save to a new Excel file
final_df.to_excel('shuffle.xlsx', index=False)

