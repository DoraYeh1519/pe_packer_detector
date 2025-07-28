# PE Packer Detector IDA Plugin

## Requirements

* **IDA Pro** (version 7.4 or later) with IDAPython support
* **Python Packages** (install via `requirements.txt`):

  * numpy
  * pandas
  * scikit-learn
  * joblib
  * pefile

## Installation

1. **Download the Plugin**
   Clone or download the repository ZIP and extract it.

2. **Copy Files**
   Copy the entire `PE_packer_detector` folder into your IDA Pro `plugins` directory. The structure should look like:

   ```text
   <IDA_INSTALL_DIR>/plugins/
     ├── pe_packer_detector.py
     ├── scripts/
     │    └── feature_extractor.py
     ├── models/
     │    └── rf_model_csv.joblib
     └── PEPD_requirements.txt
   ```

3. **Install Dependencies**
   Open a command prompt and run:

   ```bat
   > cd <IDA_INSTALL_DIR>/plugins/
   > python -m pip install -r PEPD_requirements.txt
   ```

   After installation, restart IDA Pro.

## Usage

1. **Launch IDA Pro** and open a PE file (`.exe` or `.dll`).
2. **Invoke the Plugin**

   * From the menu: **Edit → Plugins → PE Packer Detector**
   * Or press the hotkey: **Ctrl+Shift-P**
3. **View Packing Detection Results**
   A popup window will display whether the PE is likely packed along with a probability score.
4. **Interactive JMP Instruction List**
   After the packing result appears, a non-modal **JMP Instruction List** window will open. This window lists all ordinary `jmp` instructions found in the binary, showing each instruction's address and disassembly. You can:

   * **Click** or **press Enter** on any row to jump directly to that instruction in the disassembly view.
   * Keep the window open to navigate multiple `jmp` locations without closing it.
5. **Close the List**
   Close the **JMP Instruction List** window by clicking the **X** or pressing **Esc** when you are done.
