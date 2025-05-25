import hashlib
import os

def get_file_hash(file_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()
        return hashlib.sha256(file_data).hexdigest()

test_files = [
    "test_files/safe_file.txt",
    "test_files/malicious_file_1.txt",
    "test_files/hello.exe",
    "test_files/safe_pdf_file.pdf",
    "test_files/malicious_pdf_test.pdf"
]

for file_path in test_files:
    if os.path.exists(file_path):
        file_hash = get_file_hash(file_path)
        print(f"{os.path.basename(file_path)} SHA-256: {file_hash}")
    else:
        print(f"Error: {file_path} not found") 