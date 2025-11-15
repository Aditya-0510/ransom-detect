# train_static_model.py
import os, json, joblib, pandas as pd, numpy as np
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, FunctionTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, roc_auc_score
from xgboost import XGBClassifier
from model_utils import hex_to_int_frame, listlen_frame

DATA = "data/malware_dataset.csv"
df = pd.read_csv(DATA)

# Target column
y = (df["Class"].astype(str).str.lower() == "benign").astype(int)

# ---- STATIC ONLY COLUMNS (matches your dataset) ----
STATIC_COLS = [
    "file_extension","EntryPoint","PEType","MachineType","magic_number",
    "bytes_on_last_page","pages_in_file","relocations","size_of_header",
    "min_extra_paragraphs","max_extra_paragraphs","init_ss_value",
    "init_sp_value","init_ip_value","init_cs_value","over_lay_number",
    "oem_identifier","address_of_ne_header","Magic","SizeOfCode",
    "SizeOfInitializedData","SizeOfUninitializedData","AddressOfEntryPoint",
    "BaseOfCode","BaseOfData","ImageBase","SectionAlignment","FileAlignment",
    "OperatingSystemVersion","ImageVersion","SizeOfImage","SizeOfHeaders",
    "Checksum","Subsystem","DllCharacteristics","SizeofStackReserve",
    "SizeofStackCommit","SizeofHeapCommit","SizeofHeapReserve","LoaderFlags",
    "text_VirtualSize","text_VirtualAddress","text_SizeOfRawData",
    "text_PointerToRawData","text_PointerToRelocations","text_PointerToLineNumbers",
    "text_Characteristics","rdata_VirtualSize","rdata_VirtualAddress",
    "rdata_SizeOfRawData","rdata_PointerToRawData","rdata_PointerToRelocations",
    "rdata_PointerToLineNumbers","rdata_Characteristics",
]

# Reduce the dataset to static-only columns
X = df[STATIC_COLS].copy()

# -------------------------------
# 1) FIX CORRUPTED VERSION VALUES
# -------------------------------
def clean_version(v):
    try:
        return float(v)
    except:
        return 0.0

if "OperatingSystemVersion" in X.columns:
    X["OperatingSystemVersion"] = X["OperatingSystemVersion"].apply(clean_version)

if "ImageVersion" in X.columns:
    X["ImageVersion"] = X["ImageVersion"].apply(clean_version)

# --------------------------------------
# 2) Convert hex-like strings → integers
# --------------------------------------
def hex_to_int_frame(Xdf: pd.DataFrame):
    Xc = Xdf.copy()
    for c in Xc.columns:
        Xc[c] = (
            Xc[c].astype(str)
                 .str.extract(r'(0x[0-9A-Fa-f]+)', expand=False)
                 .apply(lambda s: int(s, 16) if isinstance(s, str) and s.startswith("0x") else np.nan)
        )
    return Xc

# ------------------------------------------
# 3) Convert "['FLAG1','FLAG2']" → integer count
# ------------------------------------------
def listlen_frame(Xdf: pd.DataFrame):
    Xc = Xdf.copy()
    for c in Xc.columns:
        S = Xc[c].astype(str)
        is_list = S.str.startswith("[")
        Xc.loc[is_list, c] = S[is_list].apply(
            lambda s: s.count(",") + 1 if s.strip("[]").strip() else 0
        )
        Xc.loc[~is_list, c] = np.nan
    return Xc

# classify columns by type
LIST_LIKE = ["DllCharacteristics","text_Characteristics","rdata_Characteristics"]

CATEGORICAL = [
    "file_extension","PEType","MachineType",
    "magic_number","Magic","Subsystem"
]

NUMERIC_VERSION = ["OperatingSystemVersion","ImageVersion"]

HEX_LIKE = [c for c in STATIC_COLS if c not in LIST_LIKE + CATEGORICAL + NUMERIC_VERSION]

# -------------------------
# TRANSFORMER PIPELINE
# -------------------------
pre = ColumnTransformer(
    transformers=[
        ("hex", FunctionTransformer(hex_to_int_frame), HEX_LIKE),
        ("listlen", FunctionTransformer(listlen_frame), LIST_LIKE),
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
        ("num", "passthrough", NUMERIC_VERSION),
    ],
    remainder="drop"
)

# -------------------------
# XGBoost CLASSIFIER
# -------------------------
clf = XGBClassifier(
    n_estimators=500,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.9,
    colsample_bytree=0.9,
    objective="binary:logistic",
    eval_metric="logloss",
    tree_method="hist",
    random_state=42
)

pipe = Pipeline([
    ("pre", pre),
    ("clf", clf)
])

# -------------------------
# Train/test split
# -------------------------
X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTraining model...")
pipe.fit(X_tr, y_tr)

# -------------------------
# Evaluation
# -------------------------
proba = pipe.predict_proba(X_te)[:,1]
pred  = (proba >= 0.5).astype(int)

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(y_te, pred))
print("ROC-AUC:", roc_auc_score(y_te, proba))

# -------------------------
# Save model + meta info
# -------------------------
os.makedirs("models", exist_ok=True)
joblib.dump(pipe, "models/static_pe_model.joblib")

# ----------- BUILD FEATURE NAMES MANUALLY -------------
feature_names = []

# HEX transformer outputs same columns as HEX_LIKE
feature_names += HEX_LIKE

# LIST-LIKE transformer outputs same columns
feature_names += LIST_LIKE

# Categorical one-hot encoder generates new names
ohe = pipe.named_steps["pre"].named_transformers_["cat"]
cat_new = ohe.get_feature_names_out(CATEGORICAL).tolist()
feature_names += cat_new

# Version columns passthrough
feature_names += NUMERIC_VERSION

# Get XGBoost importances
importances = pipe.named_steps["clf"].feature_importances_

# Build sorted dataframe
imp = pd.DataFrame({
    "feature": feature_names,
    "importance": importances
}).sort_values("importance", ascending=False)

# Save to CSV
imp.to_csv("models/static_feature_importance.csv", index=False)

# Save metadata
with open("models/static_meta.json", "w") as f:
    json.dump({"features_expected": STATIC_COLS}, f, indent=2)

print("\nModel saved:")
print(" - models/static_pe_model.joblib")
print(" - models/static_feature_importance.csv")
print(" - models/static_meta.json")
print("\n✔ Training complete.")