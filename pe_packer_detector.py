# plugin.py
import os, sys, pandas as pd, joblib
import json
import idaapi, ida_kernwin, idc
from idautils import Functions, Heads
import subprocess
import tempfile

# 把 scripts 目录加到 path
HERE = os.path.join(os.path.dirname(__file__), "pe_packer_detector")                   # …/pe_packer_detector
SCRIPTS = os.path.join(HERE, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from feature_extractor import PEFeatureExtractor
from gui import show_meme_gui
from chooser import JmpChooser

SUPPORTED_UNPACKERS = {"upx", "aspack", "mew", "mpress", "fsg"}  # 小写

# 载入模型、标签映射
MODEL = joblib.load(os.path.join(HERE,"models","rf_model_csv.joblib"))
with open(os.path.join(HERE,"data","label_mapping.json")) as f:
    lm = json.load(f)
rev_lm = {v:k for k,v in lm.items()}

class PEPackerDetector(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "PE Packer Detector"
    wanted_hotkey= "Ctrl-Shift-P"
    def init(self):
        return idaapi.PLUGIN_OK
    def run(self,arg):
        path = idaapi.get_input_file_path()
        feats = PEFeatureExtractor(path).extract_features()
        df = pd.DataFrame([feats])[MODEL.feature_names_in_]
        probs = MODEL.predict_proba(df)[0]
        nz = sorted([(rev_lm[i],p*100) for i,p in enumerate(probs) if p>0.001], key=lambda x:-x[1])[:5]

        show_meme_gui(path, nz)
        
        # 3. 如果 Top-1 支持，则询问是否解壳
        top_label, top_score = nz[0]
        if top_label.lower() in SUPPORTED_UNPACKERS:
            yn = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                f"Top guess: {top_label} ({top_score:.1f}%)\n"
                "This packer is supported. Unpack now?"
            )
            if yn == ida_kernwin.ASKBTN_YES:
                # 在临时目录准备输出路径
                tmpdir   = tempfile.mkdtemp(prefix="unpack_")
                out_pe   = os.path.join(tmpdir, os.path.basename(path))

                # 调用 unpacker_script.py
                unpacker_py = os.path.join(SCRIPTS, "unpacker_script.py")
                cmd = [
                    "python",
                    unpacker_py,
                    path,
                    "-o", out_pe
                ]
                idaapi.msg(f"[*] Running unpacker: {' '.join(cmd)}\n")
                try:
                    subprocess.run(cmd, check=True)
                except subprocess.CalledProcessError as e:
                    ida_kernwin.info(f"Unpacking failed: {e}")
                    return

                if os.path.isfile(out_pe):
                    # 先顯示原本的訊息，等你按 OK
                    ida_kernwin.info(f"[+] Unpacked → {out_pe}\nPlease open it in IDA.")
                    # 按完 OK 之後，立刻用 Explorer 打開該檔案所在的資料夾
                    os.startfile(os.path.dirname(out_pe))
                else:
                    ida_kernwin.info("[!] Unpacked file not found.")

                return  # 結束，不做後續 JMP 分析
        
        # 1) 收集所有函数里的 JMP 指令
        jmp_addrs = []
        for func_ea in Functions():
            func = idaapi.get_func(func_ea)
            if not func:
                continue
            for ea in Heads(func.start_ea, func.end_ea):
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, ea) > 0 and insn.itype == idaapi.NN_jmp:
                    jmp_addrs.append(ea)

        # 2) 如果有 JMP，就计算阈值并弹出列表；否则提示无 JMP
        if jmp_addrs:
            jmps = [(ea, idc.get_operand_value(ea, 0)) for ea in jmp_addrs]
            distances = sorted(abs(t - e) for e, t in jmps if t)
            # 取 95th-percentile
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

            
        # if nonzero_probs:
        #     top_name, top_score = nonzero_probs[0]
        #     header = "⚠️ Likely Packed" if top_name.lower() != "not-packed" else "✅ Likely Clean"
        #     lines = [header, "", "Details:"]
        #     for idx, (name, score) in enumerate(nonzero_probs, start=1):
        #         lines.append(f"{idx}. {name:<16} {score:.1f}%")
        #     ida_kernwin.info("\n".join(lines))
        # else:
        #     ida_kernwin.info("❌ Unable to determine type\n")



    def term(self): pass

def PLUGIN_ENTRY(): return PEPackerDetector()
