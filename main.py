import joblib
import pandas as pd

# 1. Load the model
model = joblib.load("model/ransomware_baseline_model.joblib")

# 2. Load new data to test
# NOTE: It must have the same columns as training (except target + dropped IDs)
df = pd.read_csv("new_data.csv")

# 3. Predict benign (1) or malicious (0)
proba = model.predict_proba(df)[:, 1]         # Probability of being Benign
pred = (proba < 0.5).astype(int)              # Convert to "malicious" (1) , benign (0)

# 4. Print results
print("\n=== PREDICTIONS ===")
for i, p in enumerate(pred):
    label = "MALICIOUS (Ransomware)" if p == 1 else "Benign"
    print(f"File {i+1}: {label}, probability benign = {proba[i]:.4f}")
