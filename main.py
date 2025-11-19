import joblib
import pandas as pd

model = joblib.load("model/ransomware_baseline_model.joblib")

df = pd.read_csv("new_data.csv")

proba = model.predict_proba(df)[:, 1]         # Probability of being Benign
pred = (proba < 0.5).astype(int)              # Convert to "malicious" (1) , benign (0)

print("\n=== PREDICTIONS ===")
for i, p in enumerate(pred):
    label = "MALICIOUS (Ransomware)" if p == 1 else "Benign"
    print(f"File {i+1}: {label}, probability benign = {proba[i]:.4f}")
