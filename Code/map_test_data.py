import pandas as pd
import os

def map_testing_ground_truth():
    # Path to the unseen 20% test slice created by train_ids.py
    test_file = '../data/processed/unseen_testing_data.csv'
    
    if not os.path.exists(test_file):
        print(f"❌ Error: {test_file} not found.")
        print("Please run train_ids.py first to generate the 20% test slice.")
        return

    print(f"--- Analyzing Ground Truth for: {test_file} ---")
    
    # 1. Load the testing data
    df = pd.read_csv(test_file)
    
    # 2. Count the actual labels (The 'Ground Truth')
    # This tells us exactly what is in the unseen data
    label_counts = df['Label'].value_counts()
    
    print("\n✅ Labels found in your testing file:")
    print("-" * 30)
    print(label_counts)
    print("-" * 30)
    
    # 3. Calculate percentages for your Dissertation Table
    total_packets = len(df)
    print(f"\nTotal Unseen Packets: {total_packets}")
    
    print("\n--- Summary for Chapter 5 (Evaluation) ---")
    for label, count in label_counts.items():
        percentage = (count / total_packets) * 100
        print(f"{label}: {count} packets ({percentage:.2f}%)")

if __name__ == "__main__":
    map_testing_ground_truth()