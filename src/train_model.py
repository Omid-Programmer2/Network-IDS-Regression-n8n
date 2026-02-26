import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression
import matplotlib.pyplot as plt
import os

# Configuration - Paths based on your project structure
DATA_PATH = '../data/raw/normal_traffic.csv'
REPORT_PATH = '../reports/baseline_regression.png'

def train_anomaly_detector():
    print(f"Loading data from: {DATA_PATH}...")
    
    # Load the CSV file provided
    try:
        df = pd.read_csv(DATA_PATH)
    except FileNotFoundError:
        print("Error: normal_traffic.csv not found in data/raw/")
        return

    # Preprocessing: Round time to nearest second
    # This allows us to count packets per second (PPS)
    df['Time'] = df['Time'].astype(float).round(0)
    
    # Group by 'Time' to get the count of packets in each second
    pps_data = df.groupby('Time').size().reset_index(name='Packet_Count')
    
    # After pps_data calculation is completed:
    output_path = '../data/processed/pps_data.csv'
    pps_data.to_csv(output_path, index=False)
    print(f"File successfully saved to: {output_path}")
    
    # Prepare X (Time) and y (Packet Count) for Linear Regression
    X = pps_data['Time'].values.reshape(-1, 1)
    y = pps_data['Packet_Count'].values
    
    # Initialize and fit the Linear Regression model
    model = LinearRegression()
    model.fit(X, y)
    
    # Predict values to calculate residuals
    y_pred = model.predict(X)
    
    # Calculate Standard Error of the Estimate (Se)
    # Se = sqrt( sum( (y_actual - y_pred)^2 ) / (n - 2) )
    residuals = y - y_pred
    se = np.sqrt(np.sum(residuals**2) / (len(y) - 2))
    
    # Calculate Threshold (3-sigma rule: 3 * Se above the regression line)
    # We use this as our anomaly detection boundary
    avg_pps = np.mean(y)
    threshold = avg_pps + (3 * se)
    
    print("\n" + "="*30)
    print(" REGRESSION ANALYSIS RESULTS")
    print("="*30)
    print(f"Average PPS: {avg_pps:.2f}")
    print(f"Standard Error (Se): {se:.4f}")
    print(f"Calculated Threshold: {threshold:.2f}")
    print("="*30 + "\n")
    
    # Visualization
    plt.figure(figsize=(12, 6))
    plt.scatter(X, y, color='dodgerblue', alpha=0.6, label='Normal Traffic (PPS)')
    plt.plot(X, y_pred, color='red', linewidth=2, label='Linear Regression Trend')
    plt.axhline(y=threshold, color='green', linestyle='--', label=f'Anomaly Threshold ({threshold:.2f})')
    
    plt.title('Baseline Traffic Analysis - Linear Regression')
    plt.xlabel('Time (Seconds)')
    plt.ylabel('Packets Per Second (PPS)')
    plt.legend()
    plt.grid(True, linestyle=':', alpha=0.7)
    
    # Save the report
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    plt.savefig(REPORT_PATH)
    print(f"Analysis plot saved to: {REPORT_PATH}")

if __name__ == "__main__":
    train_anomaly_detector()