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
3. **View Results**
   A popup will display whether the PE is likely packed along with a probability score.
