# SHA-256 Hash Verification for Malware Detector

This feature adds an additional layer of security to the Malware Detector application by verifying file authenticity and safety using SHA-256 hashes.

## How It Works

1. When a file is selected for scanning, its SHA-256 hash is calculated automatically
2. The hash is compared against a database of known safe and malicious file hashes
3. The verification status is displayed in the UI:
   - "Safe - Verified" for known safe files
   - "Malicious - Known" for known malicious files
   - "Unverified" for files not in the database

## Benefits

- Even if malware scanning algorithms fail, known malicious files will still be identified by their hash
- Provides instant verification without needing to perform a full scan
- Prevents false negatives for known malicious files
- Prevents false positives for known safe files

## Using the Feature

The SHA-256 hash and verification status are displayed in:
1. The Summary tab under File Information
2. At the top of each analysis tab (PDF, PE, Text)
3. At the top of the detailed scan results

## Managing the Hash Database

The verified hashes are stored in the `verified_hashes.csv` file with the following format:
```
sha256_hash,file_name,status
[hash value],[file path],[Safe - Verified|Malicious - Known]
```

### Adding New Hashes

You can add new verified hashes by:

1. Using the included `calculate_hash.py` script:
   ```
   python calculate_hash.py [file_path] [status]
   ```
   
2. Manually editing the `verified_hashes.csv` file

## Test Files

The repository includes several test files with pre-verified hashes:

- `test_files/safe_file.txt` - A verified safe file
- `test_files/hello.exe` - A known malicious executable
- `test_files/malicious_file_1.txt` - A known malicious text file
- `test_files/malicious_pdf_test.pdf` - A malicious PDF with JavaScript and OpenAction 