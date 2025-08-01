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
        lbl_exe.setGeometry(520, 230, 500, 60)
        lbl_exe.setAlignment(QtCore.Qt.AlignCenter)
        lbl_exe.setStyleSheet("color: black; font-weight: bold;  font-size: 14pt;")  # :contentReference[oaicite:8]{index=8}
        lbl_pkr = QtWidgets.QLabel(packer_info, self)
        lbl_pkr.setGeometry(550, 600, 600, 100)            # 足够大以容纳多行
        lbl_pkr.setWordWrap(False)                         # 关自动换行
        lbl_pkr.setTextFormat(QtCore.Qt.PlainText)         # 纯文本模式
        lbl_pkr.setAlignment(QtCore.Qt.AlignLeft)          # 靠左对齐
        lbl_pkr.setStyleSheet("color: black; font-family: 'Courier New'; font-weight: bold;")
        lbl_pkr.adjustSize()                               # 根据内容调整大小
        # 按钮布局
        # Buttons
        self.btn_save = QtWidgets.QPushButton("Save Image", self)
        self.btn_save.clicked.connect(self.save_image)
        self.btn_ok   = QtWidgets.QPushButton("Next Step", self)
        self.btn_ok.clicked.connect(self.accept)

        # Initial placement
        self._position_buttons()

    def _position_buttons(self):
        margin = 20
        # Next Step button on the far right
        ok_size = self.btn_ok.sizeHint()
        ok_x = self.width() - ok_size.width() - margin
        ok_y = self.height() - ok_size.height() - margin
        self.btn_ok.setGeometry(ok_x, ok_y, ok_size.width(), ok_size.height())
        # Save Image to the left of Next Step
        save_size = self.btn_save.sizeHint()
        save_x = ok_x - save_size.width() - margin
        save_y = ok_y
        self.btn_save.setGeometry(save_x, save_y, save_size.width(), save_size.height())

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._position_buttons()

    def save_image(self):
        # 先將整個對話框截圖到 QPixmap
        pixmap = self.grab()
        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save Image",
            os.path.expanduser("~"),
            "Images (*.png *.jpg *.bmp)"
        )
        if save_path:
            # 根據副檔名決定格式
            fmt = os.path.splitext(save_path)[1][1:].upper() or 'PNG'
            if fmt == 'JPG': fmt = 'JPEG'
            if not pixmap.save(save_path, fmt):
                QtWidgets.QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to save image to: {save_path}"
                )
            else:
                QtWidgets.QMessageBox.information(
                    self,
                    "Success",
                    f"Image saved to: {save_path}"
                )

def show_meme_gui(path, nonzero_probs):
    exe = os.path.basename(path)
    lines = [f"{i}. {n:<15} {s:.1f}%" for i,(n,s) in enumerate(nonzero_probs,1)]
    info = "\n".join(lines)
    dlg = MemeGui(exe, info)
    dlg.exec_()
