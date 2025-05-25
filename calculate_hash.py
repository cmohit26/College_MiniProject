import hashlib
import os
import sys

def calculate_sha256(file_path):
    """Calculate the SHA256 hash of a file"""
    with open(file_path, 'rb') as f:
        file_data = f.read()
        return hashlib.sha256(file_data).hexdigest()

def main():
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python calculate_hash.py [file_path] [status]")
        print("Example: python calculate_hash.py test_files/file.txt 'Safe - Verified'")
        
        # Calculate hash of malicious PDF as default if no arguments provided
        pdf_path = "test_files/malicious_pdf_test.pdf"
        if os.path.exists(pdf_path):
            pdf_hash = calculate_sha256(pdf_path)
            print(f"\nDefault: SHA256 of {pdf_path}: {pdf_hash}")
            
            # Add to verified_hashes.csv if not already there
            if os.path.exists("verified_hashes.csv"):
                with open("verified_hashes.csv", "r") as f:
                    if pdf_hash not in f.read():
                        with open("verified_hashes.csv", "a") as f:
                            f.write(f"\n{pdf_hash},{pdf_path},Malicious - Known")
                        print(f"Added hash to verified_hashes.csv")
                    else:
                        print("Hash already exists in verified_hashes.csv")
            else:
                with open("verified_hashes.csv", "w") as f:
                    f.write("sha256_hash,file_name,status")
                    f.write(f"\n{pdf_hash},{pdf_path},Malicious - Known")
                print(f"Created verified_hashes.csv with the hash")
        return
    
    # Get file path from command line
    file_path = sys.argv[1]
    
    # Get status from command line or use default
    status = sys.argv[2] if len(sys.argv) > 2 else "Malicious - Known"
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    # Calculate hash
    file_hash = calculate_sha256(file_path)
    print(f"SHA256 of {file_path}: {file_hash}")
    
    # Add to verified_hashes.csv
    if os.path.exists("verified_hashes.csv"):
        with open("verified_hashes.csv", "r") as f:
            if file_hash not in f.read():
                with open("verified_hashes.csv", "a") as f:
                    f.write(f"\n{file_hash},{file_path},{status}")
                print(f"Added hash to verified_hashes.csv with status: {status}")
            else:
                print("Hash already exists in verified_hashes.csv")
    else:
        with open("verified_hashes.csv", "w") as f:
            f.write("sha256_hash,file_name,status")
            f.write(f"\n{file_hash},{file_path},{status}")
        print(f"Created verified_hashes.csv with the hash")

if __name__ == "__main__":
    main() 