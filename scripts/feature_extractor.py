import pefile
import os
import json
from typing import List, Dict
from tqdm import tqdm


class PEFeatureExtractor:
    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        try:
            self.pe = pefile.PE(pe_path)
        except Exception as e:
            print(f"[!] Failed to load {pe_path}: {e}")
            self.pe = None

    def extract_features(self) -> Dict:
        if not self.pe:
            return {}

        # 計算 section entropy
        entropies = [s.get_entropy() for s in self.pe.sections]

        features = {
            "has_rsrc": any(s.Name.rstrip(b'\x00') == b'.rsrc' for s in self.pe.sections),
            "num_sections": len(self.pe.sections),
            "is_64bit": self.pe.FILE_HEADER.Machine == 0x8664,
            "has_text": any(b".text" in s.Name for s in self.pe.sections),
            "imported_symbols": self._count_imports(),
            "exported_symbols": self._count_exports(),
            "size": os.path.getsize(self.pe_path),
            "entropy_avg": sum(entropies) / len(entropies) if entropies else 0.0,
            "entropy_max": max(entropies) if entropies else 0.0,
            "entry_point": self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": self.pe.OPTIONAL_HEADER.ImageBase,
            "dll_characteristics": self.pe.OPTIONAL_HEADER.DllCharacteristics,
            "subsystem": self.pe.OPTIONAL_HEADER.Subsystem,
            "size_of_headers": self.pe.OPTIONAL_HEADER.SizeOfHeaders,
            "size_of_image": self.pe.OPTIONAL_HEADER.SizeOfImage,
            "section_names": [s.Name.decode(errors='replace').rstrip('\x00') for s in self.pe.sections],
        }

        return features

    def _count_imports(self) -> int:
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return 0
        return sum(len(entry.imports) for entry in self.pe.DIRECTORY_ENTRY_IMPORT)

    def _count_exports(self) -> int:
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return 0
        return len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols)


def load_dataset_json(json_path: str) -> List[Dict]:
    with open(json_path, "r") as f:
        return json.load(f)


def generate_feature_set(dataset: List[Dict]) -> List[Dict]:
    result = []
    for item in tqdm(dataset, desc="Extracting features"):
        full_path = os.path.abspath(os.path.join("..", item["path"]))

        if not os.path.exists(full_path):
            print(f"[!] File does not exist: {full_path}")
            continue

        extractor = PEFeatureExtractor(full_path)
        features = extractor.extract_features()
        if features:
            features["label"] = item["label"]
            features["sha256"] = item["sha256"]
            result.append(features)
    return result


if __name__ == "__main__":
    dataset_json_path = "../data/dataset.json"
    output_path = "../data/features.json"

    data = load_dataset_json(dataset_json_path)
    features = generate_feature_set(data)

    with open(output_path, "w") as f:
        json.dump(features, f, indent=2)

    print(f"[+] Saved {len(features)} features to {output_path}")
