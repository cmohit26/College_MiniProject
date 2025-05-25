# PDF Test Files

This directory contains PDF test files for the Malware Detector application:

## safe_pdf_file.pdf

This is a safe PDF file with the following characteristics:
- Simple text content
- No JavaScript
- No OpenAction elements
- No embedded files
- No suspicious features

It will be detected as safe by both:
1. The PDF feature extraction and ML model analysis
2. The SHA-256 hash verification system (already added to verified_hashes.csv)

## malicious_pdf_test.pdf

This is a deliberately malicious PDF file with the following characteristics:
- Contains JavaScript code (app.alert and app.launchURL)
- Contains OpenAction elements (auto-executes code on open)
- Has suspicious features that trigger detection

It will be detected as malicious by both:
1. The PDF feature extraction and ML model analysis
2. The SHA-256 hash verification system (already added to verified_hashes.csv)

## Using These Files

These files can be used to test the Malware Detector application:

1. Select a PDF file using the "Browse" button
2. The detector will automatically:
   - Calculate the SHA-256 hash
   - Check against the verified_hashes.csv database
   - Extract PDF features
   - Determine if the file is safe or malicious

## Expected Results

### safe_pdf_file.pdf
- SHA-256 verification: "Safe - Verified"
- ML detection: SAFE
- Basic detection: POTENTIALLY SAFE

### malicious_pdf_test.pdf
- SHA-256 verification: "Malicious - Known"
- ML detection: MALICIOUS
- Basic detection: MALICIOUS 