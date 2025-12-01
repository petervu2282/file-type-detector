# 🔍 File Type Detector - Magic Number Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Cybersecurity tool that reads file magic numbers to detect type mismatches** – perfect for malware analysis, forensics, or spotting disguised executables.

## 🎯 What it does
- Scans folder of files
- Reads **magic bytes** (file headers) to guess **real type**
- Compares to **file extension**
- Flags **SUSPICIOUS** files (jpg pretending to be pdf?)
- Exports **CSV report** for Excel analysis

## 🖥️ Demo
real.jpg | jpg | jpg | ✅ OK
fake.pdf | pdf | exe | ⚠️ SUSPICIOUS (looks like elf)


## 🚀 Quick Start
pip install -r requirements.txt # (optional, uses stdlib)
python main.py --folder samples --out report.csv


## 📊 Sample Report (CSV)
| Filename    | Extension | Detected_Type | Status                    |
|-------------|-----------|---------------|---------------------------|
| pic.jpg     | jpg       | jpg           | ✅ OK                     |
| fake.exe    | exe       | pdf           | ⚠️  SUSPICIOUS (pdf) |

## 🔧 Tech Stack
- **Python 3.8+** (stdlib only)
- Magic number signatures for JPG, PNG, PDF, ZIP, Office, ELF
- CLI with argparse + CSV export

## 💡 Use Cases
- **Malware analysis**: Spot renamed executables
- **Forensics**: Verify file integrity
- **DevSecOps**: Pre-commit file scanning

## 📈 Portfolio Impact
Built as part of "10 Creative Hacking Projects" challenge. Demonstrates:
- Binary file parsing
- Cybersecurity threat detection
- Professional CLI tooling
