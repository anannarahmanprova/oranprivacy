import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset, random_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score
import numpy as np

# Load the data
file_path = 'shuffle.xlsx'  # Path to your uploaded Excel file
df = pd.read_excel(file_path)

# Split features and target
X = df.iloc[:, :-1].values  # 64 features
y = df.iloc[:, -1].values   # Output

# Normalize the features
scaler = StandardScaler()
X = scaler.fit_transform(X)

# Convert to PyTorch tensors
X_tensor = torch.tensor(X, dtype=torch.float32)
y_tensor = torch.tensor(y, dtype=torch.float32)  # Float for BCELoss

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

# Define the binary classification model
class Model(nn.Module):
    def __init__(self):
        super(Model, self).__init__()
        self.layer2 = nn.Linear(64, 64)
        self.layer3 = nn.Linear(64, 32)
        self.output = nn.Linear(32, 1)     # Single output neuron for binary classification
        self.dropout = nn.Dropout(0.1)     # Reduced dropout for better learning

    def forward(self, x):
        x = self.dropout(F.leaky_relu(self.layer2(x)))
        x = self.dropout(F.leaky_relu(self.layer3(x)))
        x = torch.sigmoid(self.output(x))   # Sigmoid for binary classification
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
        outputs = model(inputs)                # Forward pass without squeeze
        labels = labels.unsqueeze(1)           # Ensure labels have shape (batch_size, 1)
        loss = criterion(outputs, labels)      # Compute binary cross-entropy loss
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
            outputs = model(inputs)           # Forward pass without squeeze
            labels = labels.unsqueeze(1)      # Ensure labels match shape (batch_size, 1)
            predicted = (outputs >= 0.5).float()
            correct_val += (predicted == labels).sum().item()
            total_val += labels.size(0)
    val_accuracy = 100 * correct_val / total_val
    print(f"Validation Accuracy: {val_accuracy:.2f}%")

print("Training complete.")

# Testing phase with confusion matrix and accuracy calculation
model.eval()
all_preds = []
all_labels = []
with torch.no_grad():
    for inputs, labels in test_loader:
        outputs = model(inputs)            # Forward pass without squeeze
        labels = labels.unsqueeze(1)       # Ensure labels match shape (batch_size, 1)
        predicted = (outputs >= 0.5).float()
        all_preds.extend(predicted.tolist())
        all_labels.extend(labels.tolist())

# Calculate and display confusion matrix
conf_matrix = confusion_matrix(all_labels, all_preds)
test_accuracy = accuracy_score(all_labels, all_preds) * 100
print("Confusion Matrix:")
print(conf_matrix)
print(f"Test Accuracy: {test_accuracy:.2f}%")
