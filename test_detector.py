import os
import sys
import hashlib
from malware_detector import MalwareDetectorApp
import tkinter as tk

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of the file"""
    with open(file_path, "rb") as f:
        file_data = f.read()
        return hashlib.sha256(file_data).hexdigest()

def run_test_on_file(file_path):
    """Run tests on a specific file and print results"""
    print(f"\n\n{'='*50}")
    print(f"TESTING FILE: {file_path}")
    print(f"{'='*50}")
    
    # Calculate hash
    file_hash = calculate_sha256(file_path)
    print(f"SHA-256: {file_hash}")
    
    # Create a simulated tkinter environment
    root = tk.Tk()
    app = MalwareDetectorApp(root)
    
    # Set file path and detection type
    app.file_path.set(file_path)
    _, file_ext = os.path.splitext(file_path)
    file_ext = file_ext.lower()
    
    if file_ext == ".pdf":
        detection_type = "PDF"
    elif file_ext in [".exe", ".dll", ".sys"]:
        detection_type = "PE (Executable)"
    else:
        detection_type = "Text"
    
    app.detection_type.set(detection_type)
    
    # Calculate file hash to update hash verification
    app.calculate_file_hash(file_path)
    
    # Override update_text_widget to capture output
    original_update_text_widget = app.update_text_widget
    
    def capture_output(widget, message):
        print(message, end="")
        original_update_text_widget(widget, message)
    
    app.update_text_widget = capture_output
    
    # For PE files, we need special handling to make sure content scanning works
    if detection_type == "PE (Executable)":
        try:
            print("\nRunning PE scan...")
            
            # Clear previous results
            app.clear_results()
            
            # First verify hash
            if app.hash_verified.get() == "Malicious - Known":
                app.update_summary(True, "Known malicious file by hash verification")
                print("Verification: Malicious - Known")
                print("Result: MALICIOUS - Known malicious file (Hash verified)")
                root.destroy()
                return
            
            # Run basic PE content scan directly
            app.perform_basic_pe_content_scan(file_path)
            
            # Show verification status
            print(f"Verification: {app.hash_verified.get()}")
            
            # Print result
            print(f"Result: {app.result_var.get()}")
        except Exception as e:
            print(f"Error in PE scan: {str(e)}")
    else:
        # For other file types, use regular run_scan
        print("\nRunning scan...")
        # Clear previous results
        app.clear_results()
        # Run the scan directly instead of in a thread
        app.run_scan(file_path, detection_type)
        
        # Show verification status
        print(f"Verification: {app.hash_verified.get()}")
        
        # Print result
        print(f"Result: {app.result_var.get()}")
    
    # Clean up
    root.destroy()

def main():
    """Test all files in the test_files directory"""
    test_files = [
        "test_files/safe_file.txt",
        "test_files/malicious_file_1.txt",
        "test_files/hello.exe",
        "test_files/safe_pdf_file.pdf",
        "test_files/malicious_pdf_test.pdf"
    ]
    
    for file_path in test_files:
        if os.path.exists(file_path):
            run_test_on_file(file_path)
        else:
            print(f"Error: {file_path} not found.")
    
    print("\nAll tests completed!")

if __name__ == "__main__":
    main() 