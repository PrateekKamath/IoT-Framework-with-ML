import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score  # Import accuracy_score
from joblib import load
import numpy as np

# Load the kNN model
knn_model = load('kNN.sav')

# Read the synthetic DoS attack data
syn_dos_data = pd.read_csv('Attack_Traffic.csv')

# Drop unnecessary columns
syn_dos_data = syn_dos_data.drop(['Highest Layer', 'Source IP', 'Dest IP'], axis=1)

# Label encoding for non-numeric columns
label_encoder = LabelEncoder()
non_numeric_columns = syn_dos_data.select_dtypes(exclude=['int', 'float']).columns
for column in non_numeric_columns:
    syn_dos_data[column] = label_encoder.fit_transform(syn_dos_data[column])

# Separate features (X) and target variable (y)
X_syn_dos = syn_dos_data.drop('target', axis=1)
y_syn_dos = syn_dos_data['target']

# Standardize the features
scaler = StandardScaler()
X_syn_dos = scaler.fit_transform(X_syn_dos)

# Make predictions using the kNN model
predictions = knn_model.predict(X_syn_dos)

# Print the predictions
print(predictions)

# Count occurrences of each class
count_0 = (predictions == 1).sum()  # Assuming 0 corresponds to 'Normal Traffic'
count_1 = (predictions == 2).sum()  # Assuming 1 corresponds to 'Attack Traffic'

# Print the number of occurrences
print("Number of occurrences of Normal Traffic:", count_0)
print("Number of occurrences of Attack Traffic:", count_1)

# Calculate accuracy
accuracy = accuracy_score(y_syn_dos, predictions)
print("Accuracy:", 1-accuracy)

# Make a decision based on the majority class
if count_1 > count_0:
    print("ATTACK DETECTED!!")
else:
    print("Normal Traffic")
