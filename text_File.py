# ---------------------- CONFIGURABLE VARIABLES ----------------------
TEST_FILE = "test_files/malicious_file_1.txt"
MALWARE_CSV = "bodmas_malware_category.csv"
DATASET_XLSX = "dataset.xlsx"
SUSPICIOUS_KEYWORDS = ["eval", "exec", "cmd", "powershell", "socket", "system", "base64", "subprocess", "virus"]
FILE_TYPE_MAPPING = {'.exe': 1, '.pdf': 2, '.txt': 3}

# ---------------------- STEP 1: CALCULATE FILE HASH ----------------------
import hashlib
import os

with open(TEST_FILE, "rb") as f:
    file_data = f.read()
    sha256_hash = hashlib.sha256(file_data).hexdigest()

print("SHA256 Hash:", sha256_hash)

# ---------------------- STEP 2: CHECK AGAINST MALWARE DATABASE ----------------------
import pandas as pd

malware_df = pd.read_csv(MALWARE_CSV)
malware_df.columns = malware_df.columns.str.strip()

is_malicious = sha256_hash in malware_df['sha256'].values
category = None
if is_malicious:
    category = malware_df.loc[malware_df['sha256'] == sha256_hash, 'category'].values[0]
    print(f"\u26a0\ufe0f File is MALICIOUS — Category: {category}")
else:
    print("\u2705 File not found in malware list — Proceed to feature extraction.")

# ---------------------- STEP 3: EXTRACT FEATURES FROM FILE ----------------------
import string

def extract_strings(file_path, min_length=4):
    with open(file_path, "rb") as f:
        data = f.read()
    result, current = [], ""
    for byte in data:
        char = chr(byte)
        if char in string.printable and char not in '\n\r\t\x0b\x0c':
            current += char
        else:
            if len(current) >= min_length:
                result.append(current)
            current = ""
    if len(current) >= min_length:
        result.append(current)
    return result

file_size = os.path.getsize(TEST_FILE)
file_extension = os.path.splitext(TEST_FILE)[1]
strings_list = extract_strings(TEST_FILE)
num_strings = len(strings_list)
suspicious_count = sum(any(kw in s.lower() for kw in SUSPICIOUS_KEYWORDS) for s in strings_list)

print("\nExtracted Features:")
print(f"File Size: {file_size} bytes")
print(f"File Type: {file_extension}")
print(f"Number of Strings: {num_strings}")
print(f"Suspicious Keyword Matches: {suspicious_count}")

final_suspicious_count = suspicious_count

# ---------------------- STEP 4: LOAD TRAINING DATASET ----------------------
df = pd.read_excel(DATASET_XLSX)
df.columns = df.columns.str.strip()
df['FileType'] = df['Name'].str.extract(r'(\.\w+)$')
df['FileType'] = df['FileType'].map(FILE_TYPE_MAPPING).fillna(0)
df = df[df['legitimate'].isin([0, 1])]

# ---------------------- STEP 5: TRAIN ML MODELS ----------------------
from sklearn.ensemble import RandomForestClassifier, IsolationForest

features = ['FileType', 'SizeOfCode', 'ImportsNb', 'ResourcesNb']
X = df[features].apply(pd.to_numeric, errors='coerce').dropna()
y = pd.to_numeric(df['legitimate'], errors='coerce').loc[X.index]

rf_model = RandomForestClassifier(class_weight='balanced')
rf_model.fit(X, y)

iso_model = IsolationForest(contamination=0.1, random_state=42)
iso_model.fit(X)

# ---------------------- STEP 6: PREDICT FILE SAFETY ----------------------
size_of_code = 10240
imports_nb = 15
resources_nb = 4
file_type = FILE_TYPE_MAPPING.get(file_extension, 0)

test_input = pd.DataFrame([{ 
    "FileType": file_type,
    "SizeOfCode": size_of_code,
    "ImportsNb": imports_nb,
    "ResourcesNb": resources_nb
}])

rf_result = rf_model.predict(test_input)[0]
iso_result = iso_model.predict(test_input)[0]

if rf_result == 0:
    result = "Malicious (ML - Random Forest)"
elif final_suspicious_count > 1:
    result = "Malicious (Keyword Triggered)"
elif iso_result == -1:
    result = "Suspicious (Anomaly Detected)"
else:
    result = "Safe"

print(f"\nFinal Decision: {result}")

# ---------------------- STEP 7: STORE IN BLOCKCHAIN ----------------------
import datetime, json
from pprint import pprint

blockchain = []

def generate_block_hash(block):
    return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

def add_block(file_hash, result):
    index = len(blockchain)
    timestamp = str(datetime.datetime.now())
    previous_hash = blockchain[-1]['current_hash'] if blockchain else '0'

    block = {
        'index': index,
        'timestamp': timestamp,
        'file_hash': file_hash,
        'result': result,
        'previous_hash': previous_hash
    }
    block['current_hash'] = generate_block_hash(block)
    blockchain.append(block)

    print(f"\n\u2705 Block {index} added to blockchain.")
    pprint(block)

add_block(sha256_hash, result)