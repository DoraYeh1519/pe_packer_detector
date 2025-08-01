import collections.abc
import collections
collections.Callable = collections.abc.Callable
import argparse
import subprocess
import os
import shutil
import time
from pathlib import Path

def find_latest_unpacked_file(folder, original_filename):
    base_name = os.path.splitext(os.path.basename(original_filename))[0]
    pattern = f"unpacked_*{base_name}*.exe"
    files = list(Path(folder).glob(pattern))
    if not files:
        return None
    # 按修改時間排序，最新檔案排第一
    files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    return str(files[0])

def main():
    parser = argparse.ArgumentParser(description="Unpack PE file with Unipacker CLI")
    parser.add_argument("input", help="Input packed EXE path")
    parser.add_argument("-o", "--output", required=True, help="Output unpacked EXE path")
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    output_path = os.path.abspath(args.output)

    if not os.path.exists(input_path):
        print(f"[!] Input file does not exist: {input_path}")
        return

    # 執行目錄：input 檔案所在資料夾
    work_dir = os.path.dirname(input_path)

    print(f"[*] Running unipacker on {input_path}...")
    try:
        subprocess.run(["unipacker", input_path], cwd=work_dir, check=True)
    except subprocess.CalledProcessError:
        print("[!] Unipacker failed.")
        return

    # 等待一點，讓檔案寫入完成
    time.sleep(2)

    unpacked_file = find_latest_unpacked_file(work_dir, input_path)
    if not unpacked_file:
        print(f"[!] Failed to locate unpacked file in {work_dir}")
        return

    print(f"[+] Found unpacked file: {unpacked_file}")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    # 再搬移
    shutil.move(unpacked_file, output_path)
    print(f"[+] Moved unpacked file to: {output_path}")

if __name__ == "__main__":
    main()
