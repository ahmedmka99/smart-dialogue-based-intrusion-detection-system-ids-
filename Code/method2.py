import pandas as pd
import glob
import joblib
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# --- 1. SETUP PATHS ---
RAW_DATA_PATH = '../data/raw/*.csv'
PROCESSED_PATH = '../data/processed/'
MODEL_PATH = '../models/'

os.makedirs(PROCESSED_PATH, exist_ok=True)
os.makedirs(MODEL_PATH, exist_ok=True)

print("🚀 Starting Fair 0.03% Comparison: Random Forest vs SVM...")

# --- 2. MERGE & CLEAN ALL FILES ---
all_files = glob.glob(RAW_DATA_PATH)
li = [pd.read_csv(f).rename(columns=lambda x: x.strip()) for f in all_files]
master_df = pd.concat(li, axis=0, ignore_index=True)

# Clean Infinity/NaNs
master_df.replace([np.inf, -np.inf], np.nan, inplace=True)
master_df.dropna(inplace=True)
master_df['Label'] = master_df['Label'].str.strip()

# --- 3. PRE-PROCESSING ---
encoder = LabelEncoder()
master_df['Label'] = encoder.fit_transform(master_df['Label'])
X = master_df.drop('Label', axis=1)
y = master_df['Label']

# First, get our 20% test set for the final evaluation
X_train_full, X_test, y_train_full, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

# Now, extract the EXACT SAME 0.03% slice for training both models
sample_size = 0.0003
X_train_tiny, _, y_train_tiny, _ = train_test_split(X_train_full, y_train_full, train_size=sample_size, random_state=42, stratify=y_train_full)

print(f"📊 Both models will be trained on the same {len(X_train_tiny)} rows.")

# --- 4. MODEL A: RANDOM FOREST ---
print("🧠 Training Random Forest on 0.03% sample...")
rf_model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
rf_model.fit(X_train_tiny, y_train_tiny)

# --- 5. MODEL B: SVM ---
print("🧠 Training Linear SVM on 0.03% sample...")
# dual=False is used because n_samples > n_features even in this small set
svm_model = LinearSVC(random_state=42, max_iter=2000, dual=False)
svm_model.fit(X_train_tiny, y_train_tiny)

# --- 6. RESULTS & PROOF FOR VIVA ---
print("\n📊 --- RESULTS: RANDOM FOREST (0.03% TRAINED) ---")
print(classification_report(y_test, rf_model.predict(X_test), target_names=encoder.classes_, zero_division=0))

print("\n📊 --- RESULTS: LINEAR SVM (0.03% TRAINED) ---")
print(classification_report(y_test, svm_model.predict(X_test), target_names=encoder.classes_, zero_division=0))

# Save the RF model as the primary for the app
joblib.dump(rf_model, f'{MODEL_PATH}ids_model.joblib')
joblib.dump(encoder, f'{MODEL_PATH}label_encoder.joblib')
joblib.dump(X.columns.tolist(), f'{MODEL_PATH}feature_names.joblib')

print("\n✅ Comparison complete. You now have identical-data proof for your report.")