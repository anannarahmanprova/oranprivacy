import pandas as pd

# Load the original CSV file
file_path = 'test_data.csv'  # Replace with the path to your file
data = pd.read_csv(file_path, header=None)  # Load without headers

# Separate inputs and output
inputs = data.iloc[:, :-1]  # All columns except the last one (45 features)
outputs = data.iloc[:, -1]  # Only the last column (output)

# Save in the new format without headers
with open('newtest.csv', 'w') as f:
    for index, row in inputs.iterrows():
        f.write(','.join(map(str, row.values)) + '\n')  # Write input features without headers
        f.write(str(outputs.iloc[index]) + '\n')        # Write output on a new line without headers
