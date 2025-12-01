"""
File Detective – Cybersecurity Project #1
Checks if files are honest about their type using MAGIC NUMBERS!
Reads first bytes of files in a folder, compares to known signatures,
flags mismatches as SUSPICIOUS (malware often hides by renaming files).

Usage: python main.py --folder samples --out report.csv
"""

import os
import argparse
import csv

# 1. Dictionary of magic numbers (file signatures)
MAGIC_NUMBERS = {
    b'\xFF\xD8\xFF': 'jpg',     # JPEG files
    b'\x89PNG\r\n\x1A\n': 'png', # PNG files  
    b'%PDF': 'pdf',             # PDF files
    b'PK\x03\x04': 'zip',       # ZIP and Office docs
    b'\xD0\xCF\x11\xE0': 'doc', # Microsoft Office (Word, Excel)
    b'\x7FELF': 'elf',          # Linux executables
}

# How many bytes to read from start of each file
MAX_MAGIC_LEN = max(len(x) for x in MAGIC_NUMBERS.keys())

# 2. Command line arguments
parser = argparse.ArgumentParser(description="File Detective - Magic Number File Type Checker")
parser.add_argument('--folder', default="samples", help="Folder to scan (default: samples)")
parser.add_argument('--out', default="report.csv", help="CSV output file (default: report.csv)")
args = parser.parse_args()

# 3. Function to guess real file type from magic bytes
def guess_file_type(filepath):
    """Read first bytes and match against known magic numbers."""
    try:
        with open(filepath, 'rb') as f:
            file_start = f.read(MAX_MAGIC_LEN)
            for magic, ftype in MAGIC_NUMBERS.items():
                if file_start.startswith(magic):
                    return ftype
        return "unknown"
    except Exception as e:
        return f"error ({str(e)[:20]})"

# 4. MAIN SCAN LOGIC - Replace the old simple loop with this
results = []
print(f"🔍 Scanning folder: {args.folder}")
print("=" * 50)

# Check if folder exists
if not os.path.exists(args.folder):
    print(f"❌ Folder '{args.folder}' not found! Create it and add some files.")
    exit(1)

for fname in os.listdir(args.folder):
    path = os.path.join(args.folder, fname)
    if os.path.isfile(path):
        # Guess real type from magic bytes
        guessed = guess_file_type(path)
        
        # Get file extension
        ext = fname.split('.')[-1].lower() if '.' in fname else "no_ext"
        
        # Decide if honest or lying
        if guessed == ext:
            status = "✅ OK"
        else:
            status = f"⚠️  SUSPICIOUS (looks like {guessed})"
        
        # Save result
        result_row = [fname, ext, guessed, status]
        results.append(result_row)
        print(f"{fname:<25} | {ext:>4} | {guessed:>8} | {status}")
    
    else:
        print(f"{fname:<25} | {'DIR'} | {'-'*8} | {'(skipped folder)'}")

# 5. Save results to CSV file
print("\n💾 Saving report...")
with open(args.out, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['Filename', 'Extension', 'Detected_Type', 'Status'])
    writer.writerows(results)

print(f"✅ Done! Check results:")
print(f"   📊 Terminal output above")
print(f"   📈 CSV report: {args.out}")
print(f"   📁 Scanned {len(results)} files")
