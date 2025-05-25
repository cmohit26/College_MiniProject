import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import mean_squared_error
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------------- CONFIGURABLE VARIABLES ----------------------
TEST_FILE = "test_files/hello.exe"
DATASET = "dataset.csv"

# ---------------------- STEP 1: LOAD TRAINING DATASET ----------------------
df = pd.read_csv(DATASET)
# print("Dataset Loaded. Shape:", df.shape)

# ---------------------- STEP 1b: Converting all features to numeric values ----------------------

for col in df.columns:
    if col != "legitimate":
        df[col] = pd.to_numeric(df[col], errors="coerce")

df.drop(columns=["Name", "md5", "Machine"], inplace=True, errors='ignore')
df.dropna(inplace=True)


# df['legitimate'].value_counts()

# print(df['legitimate'].value_counts())


# ---------------------- STEP 2: Cleaning DataSet ----------------------
# Drop identifier columns
df.drop(columns=["Name", "md5", "Machine"], inplace=True, errors='ignore')

# Remove rows with missing values
df.dropna(inplace=True)

# Separate features and target
X = df.drop(columns=["legitimate"])
y = df["legitimate"]

# Drop or convert non-numeric columns
non_numeric_cols = X.select_dtypes(exclude=[np.number]).columns.tolist()
if non_numeric_cols:
    print("Dropping non-numeric columns:", non_numeric_cols)
    X = X.drop(columns=non_numeric_cols)

# Scale numeric features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


# ---------------------- STEP 3: Splitting the dataset ----------------------
# X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42) #80% for training 
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42) #70% for training 

# ---------------------- STEP 4: Training with Balanced Models ----------------------

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC

# ----- STEP 4a: Random Forest ----------------------
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
rf_model.fit(X_train, y_train)
rf_preds = rf_model.predict(X_test)
rf_probs = rf_model.predict_proba(X_test)[:, 1]
rf_rmse = np.sqrt(mean_squared_error(y_test, rf_preds))

# ----- STEP 4b: Gradient Boosting ----------------------
gb_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
gb_model.fit(X_train, y_train)
gb_preds = gb_model.predict(X_test)
gb_probs = gb_model.predict_proba(X_test)[:, 1]
gb_rmse = np.sqrt(mean_squared_error(y_test, gb_preds))

# ----- STEP 4c: SVM ----------------------
svm_model = SVC(probability=True, class_weight='balanced')  # Added balanced class weight
svm_model.fit(X_train, y_train)
svm_preds = svm_model.predict(X_test)
svm_probs = svm_model.predict_proba(X_test)[:, 1]
svm_rmse = np.sqrt(mean_squared_error(y_test, svm_preds))

# ---------------------- STEP 5: Extracting Features from user sent file ----------------------

import pefile
import math
import os

def get_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    data_size = len(data)
    occurences = [0] * 256
    for byte in data:
        occurences[byte] += 1
    for count in occurences:
        if count == 0:
            continue
        p = count / data_size
        entropy -= p * math.log2(p)
    return entropy

def extract_pe_features(file_path):
    pe = pefile.PE(file_path)

    features = {}

    # HEADER-LEVEL
    features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    features['Characteristics'] = pe.FILE_HEADER.Characteristics
    features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    features['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
    features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    features['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # SECTION-LEVEL
    features['SectionsNb'] = len(pe.sections)
    entropy_list = [get_entropy(s.get_data()) for s in pe.sections]
    raw_sizes = [s.SizeOfRawData for s in pe.sections]
    virtual_sizes = [s.Misc_VirtualSize for s in pe.sections]

    features['SectionsMeanEntropy'] = sum(entropy_list)/len(entropy_list) if entropy_list else 0
    features['SectionsMinEntropy'] = min(entropy_list) if entropy_list else 0
    features['SectionsMaxEntropy'] = max(entropy_list) if entropy_list else 0
    features['SectionsMeanRawsize'] = sum(raw_sizes)/len(raw_sizes) if raw_sizes else 0
    features['SectionsMinRawsize'] = min(raw_sizes) if raw_sizes else 0
    features['SectionMaxRawsize'] = max(raw_sizes) if raw_sizes else 0
    features['SectionsMeanVirtualsize'] = sum(virtual_sizes)/len(virtual_sizes) if virtual_sizes else 0
    features['SectionsMinVirtualsize'] = min(virtual_sizes) if virtual_sizes else 0
    features['SectionMaxVirtualsize'] = max(virtual_sizes) if virtual_sizes else 0

    # IMPORTS
    try:
        imports = pe.DIRECTORY_ENTRY_IMPORT
        features['ImportsNbDLL'] = len(imports)
        features['ImportsNb'] = sum(len(i.imports) for i in imports)
        features['ImportsNbOrdinal'] = sum(1 for i in imports for imp in i.imports if imp.name is None)
    except:
        features['ImportsNbDLL'] = 0
        features['ImportsNb'] = 0
        features['ImportsNbOrdinal'] = 0

    # EXPORTS
    try:
        features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except:
        features['ExportNb'] = 0

    # RESOURCES
    try:
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for entry in resource_type.directory.entries:
                        if hasattr(entry, 'directory'):
                            for res in entry.directory.entries:
                                data_rva = res.data.struct.OffsetToData
                                size = res.data.struct.Size
                                data = pe.get_data(data_rva, size)
                                entropy = get_entropy(data)
                                resources.append((entropy, size))

        entropies = [e for e, s in resources]
        sizes = [s for e, s in resources]
        features['ResourcesNb'] = len(resources)
        features['ResourcesMeanEntropy'] = sum(entropies)/len(entropies) if entropies else 0
        features['ResourcesMinEntropy'] = min(entropies) if entropies else 0
        features['ResourcesMaxEntropy'] = max(entropies) if entropies else 0
        features['ResourcesMeanSize'] = sum(sizes)/len(sizes) if sizes else 0
        features['ResourcesMinSize'] = min(sizes) if sizes else 0
        features['ResourcesMaxSize'] = max(sizes) if sizes else 0
    except:
        features['ResourcesNb'] = 0
        features['ResourcesMeanEntropy'] = 0
        features['ResourcesMinEntropy'] = 0
        features['ResourcesMaxEntropy'] = 0
        features['ResourcesMeanSize'] = 0
        features['ResourcesMinSize'] = 0
        features['ResourcesMaxSize'] = 0

    # CONFIGURATION SIZE
    try:
        features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except:
        features['LoadConfigurationSize'] = 0

    # VERSION INFO
    try:
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == b'StringFileInfo':
                for st in fileinfo.StringTable:
                    features['VersionInformationSize'] = len(st.entries)
    except:
        features['VersionInformationSize'] = 0

    return features

user_features = extract_pe_features(TEST_FILE)
user_scaled = scaler.transform(pd.DataFrame([user_features]))

# ---------------------- STEP 6: Formatting Extracted Features ----------------------
user_scaled = scaler.transform(pd.DataFrame([user_features]))

# ---------------------- STEP 7: Predicting Using Trained Models (with threshold) ----------------------

rf_prob = rf_model.predict_proba(user_scaled)[0][1]
gb_prob = gb_model.predict_proba(user_scaled)[0][1]
svm_prob = svm_model.predict_proba(user_scaled)[0][1]

# Threshold tuning (0.6 = safer cutoff to reduce false positives)
THRESHOLD = 0.6
rf_prediction = 1 if rf_prob > THRESHOLD else 0
gb_prediction = 1 if gb_prob > THRESHOLD else 0
svm_prediction = 1 if svm_prob > THRESHOLD else 0

# ---------------------- STEP 9a: Accuracy ----------------------
from sklearn.metrics import accuracy_score
rf_accuracy = accuracy_score(y_test, rf_preds)
gb_accuracy = accuracy_score(y_test, gb_preds)
svm_accuracy = accuracy_score(y_test, svm_preds)

print(f"\nRandom Forest Accuracy: {rf_accuracy:.4f}")
print(f"Gradient Boosting Accuracy: {gb_accuracy:.4f}")
print(f"SVM Accuracy: {svm_accuracy:.4f}")

# ---------------------- STEP 9b: Final Prediction ----------------------
print(" \n FINAL CONCLUSION --> ")
print(f"\n--- Final Prediction for File: {TEST_FILE} ---")

def interpret(pred): 
    return "Malicious (Suspicious)" if pred == 0 else "Legitimate (Safe)"

print(f"Random Forest: {interpret(rf_prediction)} (Confidence: {rf_prob:.2f})")
print(f"Gradient Boosting: {interpret(gb_prediction)} (Confidence: {gb_prob:.2f})")
print(f"SVM: {interpret(svm_prediction)} (Confidence: {svm_prob:.2f})")
