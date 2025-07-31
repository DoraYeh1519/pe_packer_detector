# File: pe_packer_detector.py
# Place in <IDA install>/plugins/

import idaapi
import idc
import os
import sys
import json

import ida_kernwin
from idautils import Functions, Heads

# ---- Plugin directories ----nPLUGIN_DIR = os.path.dirname(__file__)
PLUGIN_DIR = os.path.dirname(__file__)
SCRIPTS_DIR = os.path.join(PLUGIN_DIR, "pe_packer_detector", "scripts")
MODELS_DIR = os.path.join(PLUGIN_DIR, "pe_packer_detector", "models")
DATA_DIR = os.path.join(PLUGIN_DIR, "pe_packer_detector", "data")

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
rev_label_map = {v: k for k, v in label_map.items()} if label_map else {0: "clean", 1: "packed"}

# ---- JMP Instruction List Chooser ----
class JmpChooser(ida_kernwin.Choose):
    def __init__(self, jmps, dist_threshold):
        cols = [
            ["Address",     12 | ida_kernwin.CHCOL_EA],
            ["Target Addr", 12 | ida_kernwin.CHCOL_EA],
            ["Distance",    12 | ida_kernwin.CHCOL_EA],
            ["Disassembly", 36 | ida_kernwin.CHCOL_PLAIN],
        ]
        super(JmpChooser, self).__init__(
            "JMP Instruction List",
            cols,
            flags=ida_kernwin.CH_ATTRS    # enable OnGetLineAttr
        )

        self.threshold = dist_threshold
        # Sort jumps by numeric distance descending
        self.items = sorted(
            jmps,
            key=lambda jt: abs(jt[1] - jt[0]) if jt[1] else 0,
            reverse=True
        )

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, idx):
        ea, target = self.items[idx]
        disasm = idaapi.generate_disasm_line(ea, 0)
        dist = abs(target - ea) if target else 0
        dist_str = f"0x{dist:X}" if target else ""
        return [
            f"0x{ea:X}",
            f"0x{target:X}" if target else "",
            dist_str,
            disasm
        ]

    def OnGetLineAttr(self, idx):
        ea, target = self.items[idx]
        # If no target, no highlight
        if not target:
            return None
        dist = abs(target - ea)
        # Cross-segment detection
        seg_ea = idaapi.getseg(ea)
        seg_t = idaapi.getseg(target)
        if seg_ea and seg_t and seg_ea.start_ea != seg_t.start_ea:
            # Cross-segment jumps: blue
            return [0xCCCCFF, 0]
        # Distance-based coloring
        mid = self.threshold // 2
        if dist > self.threshold:
            # far jumps: red
            return [0xFFCCCC, 0]
        elif dist > mid:
            # medium jumps: yellow
            return [0xFFFFCC, 0]
        else:
            # near jumps: green
            return [0xCCFFCC, 0]

    def OnSelectLine(self, idx):
        ea, target = self.items[idx]
        idaapi.jumpto(target or ea)
        return False

class PEPackerDetector(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "PE Packer Detector ST"
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

        try:
            feats = PEFeatureExtractor(pe_path).extract_features()
        except Exception as e:
            idaapi.info(f"Feature extraction failed: {e}")
            return

        num_feats = {k: v for k, v in feats.items() if isinstance(v, (int, float, bool))}
        if not num_feats:
            idaapi.info("No numeric features found; cannot predict.")
            return

        try:
            # 1) DataFrame 初始
            df = pd.DataFrame([num_feats])

            # 2) 欄位對齊：只保留、補齊、排序
            expected = list(self.model.feature_names_in_)
            # 丟掉多餘
            df = df[[c for c in df.columns if c in expected]]
            # 補缺
            for feat in expected:
                if feat not in df.columns:
                    df[feat] = 0
            # 排序
            df = df[expected]

            # 3) 預測機率
            probs = self.model.predict_proba(df)[0]
            nonzero_probs = [
                (rev_label_map.get(i, str(i)), float(p) * 100)
                for i, p in enumerate(probs) if p > 0.001
            ]
            nonzero_probs.sort(key=lambda x: x[1], reverse=True)
            nonzero_probs = nonzero_probs[:5]

        except Exception as e:
            idaapi.info(f"Prediction failed: {e}")
            return

        # 4) 輸出成 WebApp 一樣的 result： 多行清單，並在最前面顯示 Likely Packed / Likely Clean
        if nonzero_probs:
            # 取出機率最高的類別名稱
            top_name, top_score = nonzero_probs[0]
            # 根據第一名是不是 "not-packed" 來決定訊息
            if top_name.lower() != "not-packed":
                header = "⚠️ Likely Packed"
            else:
                header = "✅ Likely Clean"
            # 準備輸出
            lines = [header, ""]
            lines.append("Details:")
            for idx, (name, score) in enumerate(nonzero_probs, start=1):
                lines.append(f"{idx}. {name:<16} {score:.1f}%")
            ida_kernwin.info("\n".join(lines))
        else:
            # 無法辨識時顯示英文訊息
            ida_kernwin.info("❌ Unable to determine type\n")


        # Enumerate jumps
        jmp_addrs = []
        for func_ea in Functions():
            func = idaapi.get_func(func_ea)
            if not func:
                continue
            for ea in Heads(func.start_ea, func.end_ea):
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, ea) > 0 and insn.itype == idaapi.NN_jmp:
                    jmp_addrs.append(ea)

        if jmp_addrs:
            jmps = [(ea, idc.get_operand_value(ea, 0)) for ea in jmp_addrs]
            distances = sorted(abs(t - e) for e, t in jmps if t)
            if distances:
                idx = int(len(distances) * 0.95)
                idx = min(idx, len(distances) - 1)
                dyn_threshold = distances[idx]
            else:
                dyn_threshold = 0

            idaapi.msg(f"[PEPackerDetector] 95th-percentile jump threshold = 0x{dyn_threshold:X}\n")
            chooser = JmpChooser(jmps, dyn_threshold)
            chooser.Show()
        else:
            idaapi.info("No ordinary jmp instructions found.")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return PEPackerDetector()
