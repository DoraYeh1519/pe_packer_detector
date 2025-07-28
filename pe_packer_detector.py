# File: pe_packer_detector.py
# Place in <IDA install>/plugins/

import idaapi
import idc
import os
import sys
import json

import ida_kernwin
from idautils import Functions, Heads

# ---- Plugin directories ----
PLUGIN_DIR = os.path.dirname(__file__)
SCRIPTS_DIR = os.path.join(PLUGIN_DIR,"pe_packer_detector","scripts")
MODELS_DIR = os.path.join(PLUGIN_DIR,"pe_packer_detector", "models")
DATA_DIR = os.path.join(PLUGIN_DIR,"pe_packer_detector", "data")

# ---- Dependency check ----
def check_dependencies():
    required = ['pandas', 'joblib', 'numpy', 'sklearn', 'pefile']
    missing = []
    for pkg in required:
        try:
            __import__('sklearn' if pkg == 'sklearn' else pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        req = os.path.normpath(os.path.join(PLUGIN_DIR, "pe_packer_detector", "PEPD_requirements.txt")).replace("\\", "/")
        idaapi.info(
            "PEPackerDetector missing dependencies:\n"
            f"  {', '.join(missing)}\n\n"
            "Please install by running:\n"
            f"  python -m pip install -r '{req}'\n"
            "Then restart IDA Pro."
        )
    return not missing

if not check_dependencies():
    def PLUGIN_ENTRY():
        return None
    sys.exit(0)

# ---- Additional imports ----
import pandas as pd
import joblib
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)
from feature_extractor import PEFeatureExtractor

# ---- Load label map ----
label_map = {}
lm_path = os.path.join(DATA_DIR, "label_mapping.json")
if os.path.isfile(lm_path):
    with open(lm_path, 'r') as f:
        label_map = json.load(f)
# Reverse mapping: numeric label -> string label
rev_label_map = {v: k for k, v in label_map.items()} if label_map else {0: "clean", 1: "packed"}

# ---- JMP Instruction List Chooser ----
class JmpChooser(ida_kernwin.Choose):
    def __init__(self, addresses):
        title = "JMP Instruction List"
        # Define two columns: address and disassembly text
        cols = [
            ["Address", 12 | ida_kernwin.CHCOL_EA],
            ["Disassembly", 48 | ida_kernwin.CHCOL_PLAIN],
        ]
        # Non-modal chooser
        super(JmpChooser, self).__init__(title, cols)
        self.items = addresses

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, index):
        ea = self.items[index]
        return [f"0x{ea:X}", idaapi.generate_disasm_line(ea, 0)]

    def OnSelectLine(self, index):
        # Jump to the selected address without closing the dialog
        idaapi.jumpto(self.items[index])
        return False

class PEPackerDetector(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "PE Packer Detector"
    wanted_hotkey = "Ctrl-Shift-P"
    comment = "Detect PE packers using a Random Forest model"
    help = "Dependencies required; see PEPD_requirements.txt"

    def init(self):
        model_file = os.path.join(MODELS_DIR, "rf_model_csv.joblib")
        if not os.path.isfile(model_file):
            idaapi.msg(f"[PEPackerDetector] Model file not found: {model_file}\n")
            return idaapi.PLUGIN_SKIP
        self.model = joblib.load(model_file)
        idaapi.msg("[PEPackerDetector] Model loaded successfully.\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        pe_path = idaapi.get_input_file_path()
        if not pe_path or not os.path.isfile(pe_path):
            idaapi.info("Please open a PE file first.")
            return

        # Extract features
        try:
            feats = PEFeatureExtractor(pe_path).extract_features()
        except Exception as e:
            idaapi.info(f"Feature extraction failed: {e}")
            return

        # Filter numeric features
        num_feats = {k: v for k, v in feats.items() if isinstance(v, (int, float, bool))}
        if not num_feats:
            idaapi.info("No numeric features found; cannot predict.")
            return

        # Prediction
        try:
            df = pd.DataFrame([num_feats])
            pred = self.model.predict(df)[0]
            prob = self.model.predict_proba(df)[0][pred]
        except Exception as e:
            idaapi.info(f"Prediction failed: {e}")
            return

        # Display result
        label = rev_label_map.get(pred, str(pred))
        icon = "⚠️ Likely packed" if pred == label_map.get("packed", 1) else "✅ Likely clean"
        idaapi.info(f"{icon} {label} (Probability={prob:.2f})")

        # Enumerate all jmp instructions
        jmp_addrs = []
        for func_ea in Functions():
            func = idaapi.get_func(func_ea)
            if not func:
                continue
            for ea in Heads(func.start_ea, func.end_ea):
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, ea) > 0 and insn.itype == idaapi.NN_jmp:
                    jmp_addrs.append(ea)

        # Show chooser
        if jmp_addrs:
            chooser = JmpChooser(jmp_addrs)
            chooser.Show()  # non-modal
        else:
            idaapi.info("No ordinary jmp instructions found.")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return PEPackerDetector()
