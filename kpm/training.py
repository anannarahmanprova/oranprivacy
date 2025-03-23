import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset, random_split
from sklearn.preprocessing import StandardScaler
import csv
import numpy as np

# Load the data
file_path = 'shuffle.xlsx'  # Path to your Excel file
df = pd.read_excel(file_path)

# Split features and target
X = df.iloc[:, :-1].values  # 64 features
y = df.iloc[:, -1].values   # Output

# Normalize the features
scaler = StandardScaler()
X = scaler.fit_transform(X)

# Convert to PyTorch tensors
X_tensor = torch.tensor(X, dtype=torch.float32)
y_tensor = torch.tensor(y, dtype=torch.float32).unsqueeze(1)  # Ensure y is (batch_size, 1)

# Combine into a dataset and split into 60% training, 20% validation, and 20% testing
dataset = TensorDataset(X_tensor, y_tensor)
train_size = int(0.6 * len(dataset))
val_size = int(0.2 * len(dataset))
test_size = len(dataset) - train_size - val_size
train_dataset, val_dataset, test_dataset = random_split(dataset, [train_size, val_size, test_size])

# Create DataLoaders for training, validation, and testing
train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)

# Define the binary classification model with activation in each non-last layer
class Model(nn.Module):
    def __init__(self):
        super(Model, self).__init__()
        self.layer1 = nn.Linear(64, 64)     # First layer: 64 neurons
        self.layer2 = nn.Linear(64, 32)     # Second layer: 32 neurons
        self.output = nn.Linear(32, 1)      # Output layer: 1 neuron for binary classification
        self.dropout = nn.Dropout(0.1)      # Dropout for regularization
        self.leaky_relu_slope = 0.01        # Parameter for LeakyReLU activation

    def forward(self, x):
        x = self.dropout(F.leaky_relu(self.layer1(x), negative_slope=self.leaky_relu_slope))  # Activation and dropout in layer 1
        x = self.dropout(F.leaky_relu(self.layer2(x), negative_slope=self.leaky_relu_slope))  # Activation and dropout in layer 2
        x = torch.sigmoid(self.output(x))  # Sigmoid for binary classification
        return x

# Instantiate the model, define loss and optimizer
model = Model()
criterion = nn.BCELoss()   # Binary cross-entropy loss for binary classification
optimizer = torch.optim.Adam(model.parameters(), lr=0.00005)  # Reduced learning rate

# Training loop with validation accuracy calculation
num_epochs = 100  # Increased epochs for better convergence
for epoch in range(num_epochs):
    model.train()
    running_loss = 0.0
    correct = 0
    total = 0

    for inputs, labels in train_loader:
        optimizer.zero_grad()                 
        outputs = model(inputs)                 # Forward pass without squeeze
        loss = criterion(outputs, labels)       # Compute binary cross-entropy loss
        loss.backward()                         
        optimizer.step()                        
        running_loss += loss.item()

        # Calculate training accuracy
        predicted = (outputs >= 0.5).float()   # Convert probabilities to binary predictions
        correct += (predicted == labels).sum().item()
        total += labels.size(0)

    train_accuracy = 100 * correct / total
    print(f"Epoch {epoch+1}/{num_epochs}, Loss: {running_loss/len(train_loader):.4f}, Training Accuracy: {train_accuracy:.2f}%")

    # Validation phase
    model.eval()
    correct_val = 0
    total_val = 0
    with torch.no_grad():
        for inputs, labels in val_loader:
            outputs = model(inputs)
            predicted = (outputs >= 0.5).float()
            correct_val += (predicted == labels).sum().item()
            total_val += labels.size(0)
    val_accuracy = 100 * correct_val / total_val
    print(f"Validation Accuracy: {val_accuracy:.2f}%")

print("Training complete.")

# Save model weights in CSV format
with open('model_weights.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    
    # Saving weights, biases, and activation parameters for each layer
    for name, param in model.named_parameters():
        if param.requires_grad:
            # Identify the layer based on its name
            if "layer1" in name:
                layer_tag = "1"
            elif "layer2" in name:
                layer_tag = "2"
            elif "output" in name:
                layer_tag = "3"  # Output layer does not need activation

            layer_type = 'w' if 'weight' in name else 'b'
            layer_name = f"{layer_type}{layer_tag}"

            # Write the layer weights/biases row
            row = [layer_name] + param.detach().cpu().numpy().flatten().tolist()
            writer.writerow(row)

            # If it's a non-last layer, write activation parameters immediately after
            if layer_tag in ["1", "2"]:  # Only for non-last layers
                act_a_row = [f"act{layer_tag}_a", model.leaky_relu_slope]
                act_b_row = [f"act{layer_tag}_b", 1.0]  # 1.0 is the default scale for LeakyReLU
                writer.writerow(act_a_row)
                writer.writerow(act_b_row)

print("Model weights and activation parameters saved to 'model_weights.csv'")

# Save testing data to CSV
test_features = X_tensor[test_dataset.indices].numpy()  # Features of test data
test_labels = y_tensor[test_dataset.indices].numpy()    # Labels of test data

# Convert to DataFrame
test_data_df = pd.DataFrame(test_features, columns=[f"feature_{i+1}" for i in range(test_features.shape[1])])
test_data_df['label'] = test_labels  # Add labels as the last column

# Save to CSV
test_data_df.to_csv('test_data.csv', index=False)
print("Test data saved to 'test_data.csv'")
