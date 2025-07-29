# PE Packer Detector IDA Plugin

## Requirements

* **IDA Pro** (version 7.4 or later) with IDAPython support
* **Python Packages** (install via `/pe_packer_detector/PEPD_requirements.txt`):

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
     └── pe_packer_detector/
         ├──  scripts/
         │    └── feature_extractor.py
         ├──  models/
         │    └── rf_model_csv.joblib
         └── PEPD_requirements.txt
   ```

3. **Install Dependencies**
   Open a command prompt and run:

   ```bat
   > cd <IDA_INSTALL_DIR>/plugins/pe_packer_detector
   > python -m pip install -r PEPD_requirements.txt
   ```

   After installation, restart IDA Pro.

## Usage

1. **Launch IDA Pro** and open a PE file (`.exe`).
2. **Invoke the Plugin**

   * From the menu: **Edit → Plugins → PE Packer Detector**
   * Or press the hotkey: **Ctrl+Shift-P**
3. **View Packing Detection Results**
   A popup window will display whether the PE is likely packed along with a probability score.
4. **Interactive JMP Instruction List**
   After the packing result appears, a non-modal **JMP Instruction List** window will open. This window lists all ordinary `jmp` instructions found in the binary, showing each instruction's address, target address, jump distance, and disassembly. You can:

   * **Click** or **press Enter** on any row to jump directly to that instruction in the disassembly view.
   * **Sort** by any column (Address, Target Addr, Distance) — numeric columns sort by value, not lexicographically.
   * Keep the window open to navigate multiple `jmp` locations without closing it.

   **New color-coding**:
   1. **Red** — cross-segment jumps (EA and target in different segments).  
   2. **Purple** — “far” jumps (distance > 95th-percentile threshold).  
   3. **Blue** — “medium” jumps (distance > 50% threshold but ≤ 95% threshold).  
   4. **Green** — “near” jumps (distance ≤ 50% threshold).  
