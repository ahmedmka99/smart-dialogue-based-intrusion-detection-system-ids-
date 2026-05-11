import pandas as pd
import glob
import joblib
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# --- 1. SETUP PATHS ---
RAW_DATA_PATH = '../data/raw/*.csv'
PROCESSED_PATH = '../data/processed/'
MODEL_PATH = '../models/'

os.makedirs(PROCESSED_PATH, exist_ok=True)
os.makedirs(MODEL_PATH, exist_ok=True)

print("🚀 Starting Master Dataset Compilation & Physical File Splitting...")

# --- 2. MERGE & CLEAN ALL FILES ---
all_files = glob.glob(RAW_DATA_PATH)
li = []

for filename in all_files:
    print(f"📖 Reading: {filename}")
    df = pd.read_csv(filename, index_col=None, header=0)
    # Clean column headers immediately
    df.columns = df.columns.str.strip() 
    li.append(df)

master_df = pd.concat(li, axis=0, ignore_index=True)

# Handle Infinity and NaNs before training
master_df.replace([np.inf, -np.inf], np.nan, inplace=True)
master_df.dropna(inplace=True)
master_df['Label'] = master_df['Label'].str.strip()

print(f"✅ Data Cleaned. Total usable rows: {len(master_df)}")

# --- 3. PRE-PROCESSING & ENCODING ---
encoder = LabelEncoder()
master_df['Label'] = encoder.fit_transform(master_df['Label'])

X = master_df.drop('Label', axis=1)
y = master_df['Label']

# --- 4. THE 80/20 STRATIFIED SPLIT ---
# 80% for training the brain, 20% for the external testing files
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

# --- 5. CREATE EXTERNAL TEST FILES (99.97% vs 0.03%) ---
# We prepare the 20% unseen data and shuffle it for variety
test_full = X_test.copy()
test_full['Label'] = encoder.inverse_transform(y_test)
test_full = test_full.sample(frac=1, random_state=42).reset_index(drop=True)

# Calculate the split for the Demo stream
split_idx = int(len(test_full) * 0.0003) 
demo_df = test_full.iloc[:split_idx]
prod_df = test_full.iloc[split_idx:]

# Save as physical external files for app.py to load
demo_df.to_csv(f'{PROCESSED_PATH}viva_demo_data.csv', index=False)
prod_df.to_csv(f'{PROCESSED_PATH}production_network_data.csv', index=False)

print(f"💾 External Test Files Saved to {PROCESSED_PATH}:")
print(f"   - production_network_data.csv ({len(prod_df)} rows)")
print(f"   - viva_demo_data.csv ({len(demo_df)} rows)")

# --- 6. TRAIN THE MASTER MODEL ---
print(f"🧠 Training Random Forest on {len(X_train)} rows...")
model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
model.fit(X_train, y_train)


# --- 7. EXPORT MODEL & METADATA ---
joblib.dump(model, f'{MODEL_PATH}ids_model.joblib')
joblib.dump(encoder, f'{MODEL_PATH}label_encoder.joblib')
joblib.dump(X.columns.tolist(), f'{MODEL_PATH}feature_names.joblib')

# Final Validation Report for your results chapter
y_pred = model.predict(X_test)
print("\n✅ TRAINING COMPLETE. Performance Metrics:")
print(classification_report(y_test, y_pred, target_names=encoder.classes_))