# File: pe_packer_detector.py
# Place in <IDA install>/plugins/

import idaapi
import idc
import os
import sys
import json

# ---- Plugin directories ----
PLUGIN_DIR = os.path.dirname(__file__)
SCRIPTS_DIR = os.path.join(PLUGIN_DIR, "scripts")
MODELS_DIR = os.path.join(PLUGIN_DIR, "models")
DATA_DIR = os.path.join(PLUGIN_DIR, "data")

# ---- Dependency check ----
def check_dependencies():
    required = ['pandas', 'joblib', 'numpy', 'sklearn', 'pefile']
    missing = []
    for pkg in required:
        try:
            __import__('sklearn' if pkg=='sklearn' else pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        req = os.path.normpath(os.path.join(PLUGIN_DIR, "PEPD_requirements.txt")).replace("\\","/")
        idaapi.info(
            "PEPackerDetector missing dependencies:\n"
            f"  {', '.join(missing)}\n\n"
            "Install them via:\n"
            f'  python -m pip install -r "{req}"\n'
            "Then restart IDA Pro."
        )
        idaapi.msg(f"[PEPackerDetector] Missing: {missing}\n")
        return False
    return True

if not check_dependencies():
    # If deps missing, skip loading the plugin
    def PLUGIN_ENTRY():
        return None
    sys.exit(0)

# ---- Imports after deps check ----
import pandas as pd
import joblib
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)
from feature_extractor import PEFeatureExtractor

# ---- Load label mapping ----
label_map = {}
lm_path = os.path.join(DATA_DIR, "label_mapping.json")
if os.path.isfile(lm_path):
    with open(lm_path) as f:
        label_map = json.load(f)
rev_label_map = {v:k for k,v in label_map.items()} if label_map else {0:"clean",1:"packed"}


class PEPackerDetector(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "PE Packer Detector"
    comment = "Detect PE packers with RF model"
    help = "Requires deps in PEPD_requirements.txt"

    def init(self):
        model_file = os.path.join(MODELS_DIR, "rf_model_csv.joblib")
        if not os.path.isfile(model_file):
            idaapi.msg(f"[PEPackerDetector] Model not found: {model_file}\n")
            return idaapi.PLUGIN_SKIP
        self.model = joblib.load(model_file)
        idaapi.msg("[PEPackerDetector] Model loaded successfully\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        pe = idaapi.get_input_file_path()
        if not pe or not os.path.isfile(pe):
            idaapi.info("Open a PE file first.")
            return

        # feature extraction
        try:
            feats = PEFeatureExtractor(pe).extract_features()
        except Exception as e:
            idaapi.info(f"Feature extraction failed: {e}")
            return

        num_feats = {k:v for k,v in feats.items() if isinstance(v,(int,float,bool))}
        if not num_feats:
            idaapi.info("No numeric features; cannot predict.")
            return

        try:
            df = pd.DataFrame([num_feats])
            pred = self.model.predict(df)[0]
            prob = self.model.predict_proba(df)[0][pred]
        except Exception as e:
            idaapi.info(f"Prediction failed: {e}")
            return

        label = rev_label_map.get(pred, str(pred))
        icon = "⚠️ Likely packed" if pred==label_map.get("packed",1) else "✅ Likely clean"
        idaapi.info(f"{icon} {label} (P={prob:.2f})")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return PEPackerDetector()
