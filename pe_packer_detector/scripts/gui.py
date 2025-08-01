# gui.py
import os
from PyQt5 import QtWidgets, QtGui, QtCore

IMG_PATH = os.path.join(
    os.path.dirname(__file__),      # …/scripts
    "..",                            # …/pe_packer_detector
    "critical",
    "hahayoufoundme.jpg"
)
IMG_PATH = os.path.normpath(IMG_PATH)

class MemeGui(QtWidgets.QDialog):
    def __init__(self, exe_name, packer_info, parent=None):
        super().__init__(parent)
        self.setFixedSize(1000, 1000)
        # 背景、标签布局
        bg = QtWidgets.QLabel(self)
        bg.setGeometry(0,0,1000,1000)
        bg.setScaledContents(True)
        bg.setPixmap(QtGui.QPixmap(IMG_PATH))
        lbl_exe = QtWidgets.QLabel(exe_name, self)
        lbl_exe.setGeometry(540, 230, 500, 60)
        lbl_exe.setAlignment(QtCore.Qt.AlignCenter)
        lbl_exe.setStyleSheet("color: black; font-weight: bold;  font-size: 14pt;")  # :contentReference[oaicite:8]{index=8}
        lbl_pkr = QtWidgets.QLabel(packer_info, self)
        lbl_pkr.setGeometry(550, 600, 600, 100)            # 足够大以容纳多行
        lbl_pkr.setWordWrap(False)                         # 关自动换行
        lbl_pkr.setTextFormat(QtCore.Qt.PlainText)         # 纯文本模式
        lbl_pkr.setAlignment(QtCore.Qt.AlignLeft)          # 靠左对齐
        lbl_pkr.setStyleSheet("color: black; font-family: 'Courier New'; font-weight: bold;")
        lbl_pkr.adjustSize()                               # 根据内容调整大小

def show_meme_gui(path, nonzero_probs):
    exe = os.path.basename(path)
    lines = [f"{i}. {n:<15} {s:.1f}%" for i,(n,s) in enumerate(nonzero_probs,1)]
    info = "\n".join(lines)
    dlg = MemeGui(exe, info)
    dlg.exec_()
