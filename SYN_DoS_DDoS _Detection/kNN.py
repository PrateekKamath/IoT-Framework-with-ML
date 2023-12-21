import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from joblib import dump
import time

def kNN():
    # Combine SYN_DoS.csv and Benign_Traffic.csv into Combined_Traffic.csv
    syn_dos_data = pd.read_csv('SYN_DoS.csv')
    benign_traffic_data = pd.read_csv('Benign_Traffic.csv')
    combined_traffic_data = pd.concat([syn_dos_data, benign_traffic_data]).sample(frac=1).reset_index(drop=True)
    combined_traffic_data.to_csv('Combined_Traffic.csv', index=False)

    # Load the Combined_Traffic.csv dataset
    data = pd.read_csv('Combined_Traffic.csv', delimiter=',')

    # Drop columns 'Highest Layer', 'Source IP', and 'Dest IP'
    data = data.drop(['Highest Layer', 'Source IP', 'Dest IP'], axis=1)

    # Label encode non-integer and non-float columns
    label_encoder = LabelEncoder()
    non_numeric_columns = data.select_dtypes(exclude=['int', 'float']).columns
    for column in non_numeric_columns:
        data[column] = label_encoder.fit_transform(data[column])

    X = data.drop('target', axis=1)  # Features
    y = data['target']  # Target variable

    X_train, X_test, y_train, y_test = train_test_split(X, y)

    # Feature Scaling
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Hyperparameter tuning with Stratified Cross-Validation
    best_k = 0
    best_score = 0

    stratified_kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for k in range(1, 21):
        knn = KNeighborsClassifier(n_neighbors=k, weights='distance')
        scores = cross_val_score(knn, X_train, y_train, cv=stratified_kf)

        if scores.mean() > best_score:
            best_score = scores.mean()
            best_k = k

    print("Best k:", best_k)

    # Train the model with the best k
    knn = KNeighborsClassifier(n_neighbors=best_k, weights='distance')
    knn.fit(X_train, y_train)

    predictions = knn.predict(X_test)

    print()
    print("Number of Neighbors: ", knn.n_neighbors)
    print()
    print("Confusion Matrix: ", "\n", confusion_matrix(y_test, predictions))
    print()
    print("Classification Report: ", "\n", classification_report(y_test, predictions))
    print()

    # Save the k-NN model
    dump(knn, 'kNN.sav')

if __name__ == '__main__':
    kNN()
