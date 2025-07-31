import pefile
import os
import json
import statistics
import math
from typing import List, Dict
from tqdm import tqdm


class PEFeatureExtractor:
    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        try:
            self.pe = pefile.PE(pe_path, fast_load=False)
            self.pe.parse_data_directories()
        except Exception as e:
            print(f"[!] Failed to load {pe_path}: {e}")
            self.pe = None

    def extract_features(self) -> Dict:
        if not self.pe:
            return {}

        features = {}

        # === BE: Byte Entropy ===
        entropies = [s.get_entropy() for s in self.pe.sections]
        features.update({
            "entropy_avg": sum(entropies) / len(entropies) if entropies else 0.0,
            "entropy_max": max(entropies) if entropies else 0.0,
            "entropy_std": statistics.stdev(entropies) if len(entropies) > 1 else 0.0,
            "high_entropy_section_count": sum(e > 7.0 for e in entropies),
            "entropy_highest": max(entropies) if entropies else 0.0
        })

        # === BE: 分段 Entropy（每 100 份）===
        parts = self._calc_parts_entropy(self.pe_path)
        for i in range(10):  # 固定前 10 段
            features[f"part_entropy_{i}"] = parts[i]["entropy"] if i < len(parts) else 0.0

        # === EB: Entry Bytes ===
        try:
            ep_offset = self.pe.get_offset_from_rva(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            entry_bytes = self.pe.__data__[ep_offset:ep_offset + 16]
            for i in range(16):
                features[f"entry_byte_{i}"] = entry_bytes[i] if i < len(entry_bytes) else 0
        except:
            for i in range(16):
                features[f"entry_byte_{i}"] = 0

        # === IF: Import Functions ===
        import_count = self._count_imports()
        dll_count = len(self.pe.DIRECTORY_ENTRY_IMPORT) if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        features.update({
            "import_count": import_count,
            "import_dll_count": dll_count,
            "imports_per_dll_avg": import_count / dll_count if dll_count else 0.0
        })

        # === ME: Metadata ===
        features.update({
            "is_64bit": int(self.pe.FILE_HEADER.Machine == 0x8664),
            "subsystem": self.pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": self.pe.OPTIONAL_HEADER.DllCharacteristics,
            "size_of_headers": self.pe.OPTIONAL_HEADER.SizeOfHeaders,
            "size_of_image": self.pe.OPTIONAL_HEADER.SizeOfImage,
            "address_of_entry": self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": self.pe.OPTIONAL_HEADER.ImageBase,
            "num_sections": self.pe.FILE_HEADER.NumberOfSections,
        })

        for i, val in enumerate([
            self.pe.DOS_HEADER.e_cblp,
            self.pe.DOS_HEADER.e_cp,
            self.pe.DOS_HEADER.e_crlc,
            self.pe.DOS_HEADER.e_cparhdr,
            self.pe.DOS_HEADER.e_minalloc,
            self.pe.DOS_HEADER.e_maxalloc,
            self.pe.DOS_HEADER.e_ovno,
            self.pe.DOS_HEADER.e_oemid,
            self.pe.DOS_HEADER.e_oeminfo,
        ]):
            features[f"dos_{i}"] = val

        # === SC: Section 特徵 ===
        known_sections = ['.text', '.data', '.rsrc', '.reloc', '.idata']
        section_names = []
        nonstandard_count = 0
        for s in self.pe.sections:
            name = s.Name.decode(errors='replace').rstrip('\x00').lower()
            section_names.append(name)
            if name not in known_sections:
                nonstandard_count += 1
        features.update({
            "nonstandard_section_count": nonstandard_count,
            "packed_section_name_match": int(any(name in ['upx0', 'upx1', 'mpress1', 'petite'] for name in section_names))
        })

        flag_sum = [0] * 10
        perm_sum = [0] * 3
        for s in self.pe.sections:
            flags, perms = self._parse_characteristics(s.Characteristics)
            flag_sum = [a + b for a, b in zip(flag_sum, flags)]
            perm_sum = [a + b for a, b in zip(perm_sum, perms)]
        for i, val in enumerate(flag_sum):
            features[f"sec_flag_{i}"] = val
        for i, val in enumerate(perm_sum):
            features[f"sec_perm_{i}"] = val

        # === BE: Section entropy chunks ===
        for idx in range(3):  # 固定三個 section
            if idx < len(self.pe.sections):
                s = self.pe.sections[idx]
                chunk_stats = self._section_entropy_chunks(s)
            else:
                chunk_stats = None
            for k in ["average_entropy", "max_entropy", "min_entropy", "range_entropy"]:
                features[f"sec{idx}_{k}"] = chunk_stats[k] if chunk_stats else 0.0

        # === RE: Resource 特徵 ===
        try:
            has_rsrc = any(s.Name.rstrip(b'\x00') == b'.rsrc' for s in self.pe.sections)
            rsrc_section = next((s for s in self.pe.sections if s.Name.rstrip(b'\x00') == b'.rsrc'), None)
            rsrc_size = rsrc_section.SizeOfRawData if rsrc_section else 0
        except:
            has_rsrc = False
            rsrc_size = 0
        features.update({
            "has_rsrc": int(has_rsrc),
            "rsrc_size": rsrc_size
        })

        # === Overlay 特徵 ===
        try:
            overlay_data = self.pe.__data__[self.pe.sections[-1].get_file_offset() + self.pe.sections[-1].SizeOfRawData:]
            overlay_size = len(overlay_data)
        except:
            overlay_size = 0
        features["overlay_size"] = overlay_size

        return features

    def _calc_parts_entropy(self, filename, num_parts=100):
        results = []
        try:
            full_data = open(filename, 'rb').read()
            header_size = self.pe.OPTIONAL_HEADER.SizeOfHeaders
            data = full_data[header_size:]
            file_size = len(data)
            part_size = file_size // num_parts
            for i in range(num_parts):
                start = i * part_size
                end = (i + 1) * part_size if i < num_parts - 1 else file_size
                chunk = data[start:end]
                entropy = self._calc_entropy(chunk)
                results.append({"entropy": entropy})
        except:
            results = [{"entropy": 0.0}] * num_parts
        return results

    def _section_entropy_chunks(self, section, chunk_size=256):
        try:
            data = section.get_data()
            entropies = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                e = self._calc_entropy(chunk)
                entropies.append(e)
            return {
                "average_entropy": round(sum(entropies) / len(entropies), 4),
                "max_entropy": round(max(entropies), 4),
                "min_entropy": round(min(entropies), 4),
                "range_entropy": round(max(entropies) - min(entropies), 4),
            }
        except:
            return None

    def _calc_entropy(self, data: bytes) -> float:
        counters = [0] * 256
        for b in data:
            counters[b] += 1
        data_size = len(data)
        probabilities = [c / data_size for c in counters if c > 0]
        entropy = -sum(p * math.log2(p) for p in probabilities)
        return round(entropy, 4)

    def _count_imports(self) -> int:
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return 0
        return sum(len(entry.imports) for entry in self.pe.DIRECTORY_ENTRY_IMPORT)

    def _parse_characteristics(self, characteristics):
        flags = [
            0x00000020, 0x00000040, 0x00000080, 0x00000200, 0x00000800,
            0x00001000, 0x02000000, 0x04000000, 0x08000000, 0x10000000
        ]
        perms = [0x20000000, 0x40000000, 0x80000000]
        flag_bits = [1 if characteristics & val else 0 for val in flags]
        perm_bits = [1 if characteristics & val else 0 for val in perms]
        return flag_bits, perm_bits


def load_dataset_json(json_path: str) -> List[Dict]:
    with open(json_path, "r", encoding="utf-8") as f:
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
