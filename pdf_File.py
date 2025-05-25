# ---------------------- CONFIGURABLE VARIABLES ----------------------

TEST_FILE = "test_files/P_CC_unit-4.2 44.pdf"  # Path to the user-uploaded PDF file
DATASET = "PDFMalware2022.csv"               # Path to your training dataset
MODEL_FILE = "pdf_detector_model.pkl" # File where the trained model will be saved

# test_files/test_malicious.pdf # This should set JS=1, Javascript=1, and OpenAction=1 in your feature extraction


# ---------------------- Step 1: Loading Dataset ----------------------

import pandas as pd

df = pd.read_csv(DATASET)


# ---------------------- Step 2: Cleaning Dataset ----------------------

import pandas as pd
from sklearn.preprocessing import LabelEncoder


def clean_dataset(df):
    """Clean the dataset: handle missing values, encode categorical features, and fix inconsistencies."""
    # Create a copy to avoid modifying the original
    df_clean = df.copy()

    # Print initial columns for debugging
    # print("Initial columns:", df_clean.columns.tolist())

    # 1. Drop 'Fine name' and 'filename' explicitly
    columns_to_drop = ['Fine name', 'filename']
    dropped_columns = []
    for col in columns_to_drop:
        if col in df_clean.columns:
            df_clean = df_clean.drop(columns=[col])
            dropped_columns.append(col)
    # if dropped_columns:
    #     # print(f"Dropped columns: {dropped_columns}")
    # else:
    #     print("Warning: Neither 'Fine name' nor 'filename' found in columns.")

    # 2. Check for unexpected non-numeric columns (excluding expected categorical and Class)
    expected_cols = (['pdfsize', 'metadata size', 'pages', 'xref Length', 'title characters',
                      'embedded files', 'images', 'obj', 'endobj', 'stream', 'endstream',
                      'xref', 'trailer', 'startxref', 'pageno', 'Colors',
                      'isEncrypted', 'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction',
                      'Acroform', 'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA',
                      'text', 'header', 'Class'])
    unexpected_cols = [col for col in df_clean.columns if col not in expected_cols]
    if unexpected_cols:
        print(f"Warning: Unexpected columns found: {unexpected_cols}")

    # 3. Define column types
    numerical_cols = ['pdfsize', 'metadata size', 'pages', 'xref Length', 'title characters',
                     'embedded files', 'images', 'obj', 'endobj', 'stream', 'endstream',
                     'xref', 'trailer', 'startxref', 'pageno', 'Colors']
    binary_cols = ['isEncrypted', 'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction',
                  'Acroform', 'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA']
    categorical_cols = ['text', 'header']

    # 4. Convert numerical columns to numeric
    for col in numerical_cols:
        if col in df_clean.columns:
            df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce')
            if df_clean[col].isna().sum() > 0:
                # print(f"Warning: NaN values in {col} after conversion: {df_clean[col].isna().sum()}")
                df_clean[col] = df_clean[col].fillna(df_clean[col].median())
            if not pd.api.types.is_numeric_dtype(df_clean[col]):
                print(f"Error: {col} is not numeric. Unique values: {df_clean[col].unique()}")

    # 5. Convert binary columns to numeric and ensure 0/1
    for col in binary_cols:
        if col in df_clean.columns:
            def clean_binary_value(x):
                if isinstance(x, str):
                    try:
                        return int(x.split('(')[0])
                    except:
                        return 0
                return x
            df_clean[col] = df_clean[col].apply(clean_binary_value)
            df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce').fillna(0).astype(int).clip(0, 1)

    # 6. Handle categorical columns: Fill with mode
    for col in categorical_cols:
        if col in df_clean.columns:
            df_clean[col] = df_clean[col].fillna(df_clean[col].mode()[0])

    # 7. Encode categorical features
    label_encoders = {}
    for col in categorical_cols:
        if col in df_clean.columns:
            le = LabelEncoder()
            df_clean[col] = le.fit_transform(df_clean[col].astype(str))
            label_encoders[col] = le
            # print(f"Encoded {col}: {le.classes_}")

    # 8. Encode 'Class' (Malicious=1, Safe=0)
    if 'Class' in df_clean.columns:
        df_clean['Class'] = df_clean['Class'].map({'Malicious': 1, 'Safe': 0})
        if df_clean['Class'].isna().sum() > 0:
            print("Error: NaN values in 'Class' after encoding.")
            # print(f"Rows with NaN in 'Class':\n{df_clean[df_clean['Class'].isna()]}")
        # else:
            # print("Encoded 'Class' (Malicious=1, Safe=0)")
    else:
        print("Error: 'Class' column not found.")
        return None, None

    # 9. Check for remaining NaN values
    if df_clean.isna().sum().sum() > 0:
        print("Warning: Remaining NaN values:")
        # print(df_clean.isna().sum())
        df_clean = df_clean.fillna(0)

    # 10. Verify all columns are numeric (except Class)
    # print("Column dtypes:")
    # print(df_clean.dtypes)
    non_numeric_cols = df_clean.drop(columns=['Class'], errors='ignore').select_dtypes(exclude=['int64', 'float64']).columns
    if len(non_numeric_cols) > 0:
        print(f"Error: Non-numeric columns detected: {non_numeric_cols}")
        for col in non_numeric_cols:
            print(f"Unique values in {col}: {df_clean[col].unique()}")
            print("Delete 1")
        return None, None

    print(f"Cleaned dataset shape: {df_clean.shape}")
    return df_clean, label_encoders

# Run cleaning (replace 'df' with your loaded dataset variable)
cleaned_dataset, label_encoders = clean_dataset(df)
cleaned_dataset.head()  # Display first few rows



# ---------------------- Step 3: Splitting the Dataset ----------------------


from sklearn.model_selection import train_test_split

def split_dataset(df_clean, test_size=0.2, random_state=42):
    """Split the cleaned dataset into training and testing sets (no stratification)."""
    if df_clean is None:
        print("Error: Input dataset is None.")
        return None, None, None, None

    # Separate features (X) and target (y)
    if 'Class' not in df_clean.columns:
        print("Error: 'Class' column missing from dataset.")
        return None, None, None, None

    X = df_clean.drop(columns=['Class'], errors='ignore')  # Features
    y = df_clean['Class']  # Target (Malicious=1, Safe=0)

    # Check for non-numeric columns
    non_numeric_cols = X.select_dtypes(exclude=['int64', 'float64']).columns
    if len(non_numeric_cols) > 0:
        print(f"Error: Non-numeric columns found in X: {non_numeric_cols}")
        for col in non_numeric_cols:
            print(f"Unique values in {col}: {X[col].unique()}")
            print("Delete 2")
        return None, None, None, None

    
    if y.isna().sum() > 0:
        print("Error: 'Class' column contains NaN values.")
        # print(f"Rows with NaN in 'Class':\n{df_clean[y.isna()]}")
        return None, None, None, None

    # Check class distribution
    class_counts = y.value_counts().to_dict()
    print(f"Class distribution: {class_counts}")
    if len(class_counts) < 2:
        print("Warning: Only one class found in 'Class'. Model will be biased.")

    # Split into training and testing sets (no stratification)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state
    )

    # Print shapes and dtypes
    print(f"Training set shape: X_train={X_train.shape}, y_train={y_train.shape}")
    print(f"Testing set shape: X_test={X_test.shape}, y_test={y_test.shape}")
    print(f"Class distribution in y_train: {y_train.value_counts().to_dict()}")
    # print(f"X_train dtypes:\n{X_train.dtypes}")

    return X_train, X_test, y_train, y_test

# Run splitting (use cleaned_dataset from revised Step 2)
X_train, X_test, y_train, y_test = split_dataset(cleaned_dataset)
if X_train is not None:
    X_train.head()
else:
    print("Split failed. Check error messages above.")


# ----------------- Step 4a: Training with Random Forest Classifier ------------------

# Step 4a: Training with Random Forest Classifier (Revised)
# Run this cell after revised Step 2 and Step 3

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import mean_squared_error, confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns

def train_random_forest(X_train, X_test, y_train, y_test):
    """Train Random Forest, compute RMSE, and plot confusion matrix and ROC curve."""
    # Check for non-numeric columns
    non_numeric_cols = X_train.select_dtypes(exclude=['int64', 'float64']).columns
    if len(non_numeric_cols) > 0:
        print(f"Error: Non-numeric columns in X_train: {non_numeric_cols}")
        return None, None, None, None

    # Initialize and train Random Forest
    rf_model = RandomForestClassifier(random_state=42)
    rf_model.fit(X_train, y_train)

    # Predict probabilities and labels
    y_pred_proba = rf_model.predict_proba(X_test)[:, 1]  # Probability of Malicious
    y_pred = rf_model.predict(X_test)

    # Compute RMSE (probabilities vs. true labels)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred_proba))

    return rf_model, rmse, y_pred, y_pred_proba

# Run training (use X_train, X_test, y_train, y_test from revised Step 3)
rf_model, rf_rmse, rf_y_pred, rf_y_pred_proba = train_random_forest(X_train, X_test, y_train, y_test)


# ----------------- Step 4b: Logistic Regression Classifier -------------------------

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns

def train_logistic_regression(X_train, X_test, y_train, y_test):
    """Train Logistic Regression, compute RMSE, and plot confusion matrix and ROC curve."""
    # Check for non-numeric columns
    non_numeric_cols = X_train.select_dtypes(exclude=['int64', 'float64']).columns
    if len(non_numeric_cols) > 0:
        print(f"Error: Non-numeric columns in X_train: {non_numeric_cols}")
        return None, None, None, None

    # Scale features (required for Logistic Regression)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Initialize and train Logistic Regression
    lr_model = LogisticRegression(random_state=42, max_iter=1000)
    lr_model.fit(X_train_scaled, y_train)

    # Predict probabilities and labels
    y_pred_proba = lr_model.predict_proba(X_test_scaled)[:, 1]  # Probability of Malicious
    y_pred = lr_model.predict(X_test_scaled)

    # Compute RMSE (probabilities vs. true labels)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred_proba))

    return lr_model, scaler, rmse, y_pred, y_pred_proba

# Run training (use X_train, X_test, y_train, y_test from Step 3)
lr_model, lr_scaler, lr_rmse, lr_y_pred, lr_y_pred_proba = train_logistic_regression(X_train, X_test, y_train, y_test)


# ----------------- Step 4c: Training with XGBoost Classifier -------------------------

import numpy as np
import xgboost as xgb
from sklearn.metrics import mean_squared_error, confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns

def train_xgboost(X_train, X_test, y_train, y_test):
    """Train XGBoost, compute RMSE, and plot confusion matrix and ROC curve."""
    # Check for non-numeric columns
    non_numeric_cols = X_train.select_dtypes(exclude=['int64', 'float64']).columns
    if len(non_numeric_cols) > 0:
        print(f"Error: Non-numeric columns in X_train: {non_numeric_cols}")
        return None, None, None, None

    # Initialize and train XGBoost
    xgb_model = xgb.XGBClassifier(random_state=42, use_label_encoder=False, eval_metric='logloss')
    xgb_model.fit(X_train, y_train)

    # Predict probabilities and labels
    y_pred_proba = xgb_model.predict_proba(X_test)[:, 1]  # Probability of Malicious
    y_pred = xgb_model.predict(X_test)

    # Compute RMSE (probabilities vs. true labels)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred_proba))

    return xgb_model, rmse, y_pred, y_pred_proba

# Run training (use X_train, X_test, y_train, y_test from Step 3)
xgb_model, xgb_rmse, xgb_y_pred, xgb_y_pred_proba = train_xgboost(X_train, X_test, y_train, y_test)


# ----------------- Step 5: Fixed Feature Extraction -------------------------

import PyPDF2
import os
import re
from collections import Counter
import pandas as pd


def extract_pdf_features(pdf_path):
    """Extract features from a PDF file with robust JavaScript/OpenAction detection."""
    if not os.path.exists(pdf_path):
        print(f"Error: {pdf_path} not found.")
        return None

    try:
        # Initialize feature dictionary
        features = {
            'pdfsize': 0, 'metadata size': 0, 'pages': 0, 'xref Length': 0, 'title characters': 0,
            'isEncrypted': 0, 'embedded files': 0, 'images': 0, 'text': 'No', 'header': '',
            'obj': 0, 'endobj': 0, 'stream': 0, 'endstream': 0, 'xref': 0, 'trailer': 0,
            'startxref': 0, 'pageno': 0, 'encrypt': 0, 'ObjStm': 0, 'JS': 0, 'Javascript': 0,
            'AA': 0, 'OpenAction': 0, 'Acroform': 0, 'JBIG2Decode': 0, 'RichMedia': 0,
            'launch': 0, 'EmbeddedFile': 0, 'XFA': 0, 'Colors': 0
        }

        # Get file size
        features['pdfsize'] = os.path.getsize(pdf_path)

        # Open PDF
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            
            # Pages
            features['pages'] = len(reader.pages)
            features['pageno'] = features['pages']

            # Encryption
            features['isEncrypted'] = 1 if reader.is_encrypted else 0
            features['encrypt'] = features['isEncrypted']

            # Metadata size
            metadata = reader.metadata
            features['metadata size'] = len(str(metadata)) if metadata else 0

            # Title characters
            features['title characters'] = len(metadata.get('/Title', '')) if metadata else 0

            # Header (PDF version)
            f.seek(0)
            first_line = f.readline().decode('latin1', errors='ignore').strip()
            pdf_version_match = re.match(r'%PDF-(\d\.\d)', first_line)
            features['header'] = pdf_version_match.group(0) if pdf_version_match else '%PDF-1.4'
            print(f"Extracted PDF header: {features['header']}")

            # Read raw PDF content for counting objects
            f.seek(0)
            content = f.read().decode('latin1', errors='ignore')

            # Count PDF objects
            features['obj'] = len(re.findall(r'\bobj\b', content))
            features['endobj'] = len(re.findall(r'\bendobj\b', content))
            features['stream'] = len(re.findall(r'\bstream\b', content))
            features['endstream'] = len(re.findall(r'\bendstream\b', content))
            features['xref'] = len(re.findall(r'\bxref\b', content))
            features['trailer'] = len(re.findall(r'\btrailer\b', content))
            features['startxref'] = len(re.findall(r'\bstartxref\b', content))

            # Enhanced detection: Check catalog and annotations
            catalog = reader.trailer.get('/Root', {})
            if isinstance(catalog, PyPDF2.generic.IndirectObject):
                catalog = catalog.get_object()

            # OpenAction
            features['OpenAction'] = 1 if '/OpenAction' in catalog else 0
            for page in reader.pages:
                aa = page.get('/AA', {})
                if isinstance(aa, PyPDF2.generic.IndirectObject):
                    aa = aa.get_object()
                if isinstance(aa, dict) and '/OpenAction' in aa:
                    features['OpenAction'] = 1

            # Acroform
            features['Acroform'] = 1 if '/AcroForm' in catalog else 0

            # AA
            features['AA'] = 1 if '/AA' in catalog else 0
            for page in reader.pages:
                if isinstance(page, PyPDF2.generic.IndirectObject):
                    page = page.get_object()
                if isinstance(page, dict) and '/AA' in page:
                    features['AA'] = 1

            # JavaScript detection
            js_patterns = [r'/JS', r'/JavaScript', r'javascript', r'app\.alert']
            features['JS'] = 1 if any(re.search(pattern, content, re.IGNORECASE) for pattern in js_patterns) else 0
            for page in reader.pages:
                if '/Annots' in page:
                    annots = page['/Annots']
                    if isinstance(annots, PyPDF2.generic.IndirectObject):
                        annots = annots.get_object()
                    for annot in annots:
                        annot_obj = annot.get_object()
                        if isinstance(annot_obj, dict) and annot_obj.get('/A', {}).get('/S') == '/JavaScript':
                            features['JS'] = 1
            features['Javascript'] = features['JS']

            # Embedded files
            features['EmbeddedFile'] = 1 if '/EmbeddedFile' in content or '/EmbeddedFiles' in catalog else 0
            features['embedded files'] = features['EmbeddedFile']

            # Other features
            features['ObjStm'] = 1 if '/ObjStm' in content else 0
            features['JBIG2Decode'] = 1 if '/JBIG2Decode' in content else 0
            features['RichMedia'] = 1 if '/RichMedia' in content else 0
            features['launch'] = 1 if '/Launch' in content else 0
            features['XFA'] = 1 if '/XFA' in content else 0

            # Text presence
            text_content = ''
            for page in reader.pages:
                text = page.extract_text()
                if text and len(text.strip()) > 0:
                    text_content += text
            features['text'] = 'Yes' if len(text_content.strip()) > 0 else 'No'

            # Images
            images = len(re.findall(r'/Image', content))
            features['images'] = images

            # Colors
            colors = len(re.findall(r'/ColorSpace', content))
            features['Colors'] = colors

            # xref Length
            xref_entries = re.findall(r'\d+\s+\d+\s+[nf]', content)
            features['xref Length'] = len(xref_entries)

        # Convert to DataFrame
        feature_df = pd.DataFrame([features])

        print("\n\n\n")
        return feature_df

    except Exception as e:
        print(f"Error extracting features from {pdf_path}: {e}")
        return None

# Run feature extraction
test_features = extract_pdf_features(TEST_FILE)
if test_features is not None:
    test_features.head()


# --------- Step 6: Formatting Extracted Features to Match Training Input -----------


import pandas as pd

def format_test_features(test_features, label_encoders, X_train):
    """Format test features to match training input by encoding categorical features."""
    if test_features is None:
        print("Error: test_features is None.")
        return None

    # Create a copy to avoid modifying the original
    formatted_features = test_features.copy()

    # Verify column alignment
    test_cols = formatted_features.columns.tolist()
    train_cols = X_train.columns.tolist()
    if test_cols != train_cols:
        print(f"Error: Column mismatch. Test columns: {test_cols}")
        print(f"Training columns: {train_cols}")
        return None

    # Encode categorical features (text, header)
    categorical_cols = ['text', 'header']
    for col in categorical_cols:
        if col in formatted_features.columns:
            if col not in label_encoders:
                print(f"Error: No LabelEncoder found for {col}.")
                return None
            le = label_encoders[col]
            # Handle unseen labels by mapping to the most common class
            try:
                formatted_features[col] = le.transform(formatted_features[col])
            except ValueError:
                # print(f"Warning: Unseen value in {col}. Mapping to most common class.")
                most_common = le.classes_[0]  # Default to first class
                formatted_features[col] = le.transform([most_common])[0]

    # Verify all columns are numeric
    non_numeric_cols = formatted_features.select_dtypes(exclude=['int64', 'float64']).columns
    if len(non_numeric_cols) > 0:
        print(f"Error: Non-numeric columns after encoding: {non_numeric_cols}")
        return None

    # print("Formatted test features:")
    # print(formatted_features)
    # print("\nFormatted feature dtypes:")
    # print(formatted_features.dtypes)

    return formatted_features

# Run formatting (use test_features from Step 5, label_encoders from Step 2, X_train from Step 3)
formatted_test_features = format_test_features(test_features, label_encoders, X_train)
if formatted_test_features is not None:
    formatted_test_features.head()
    
    
# --------- Step 7: Making a Prediction on the Formatted Input -----------
  

import numpy as np
from sklearn.preprocessing import StandardScaler

def make_predictions(formatted_features, rf_model, lr_model, lr_scaler, xgb_model):
    """Make predictions using Random Forest, Logistic Regression, and XGBoost."""
    if formatted_features is None:
        print("Error: formatted_features is None.")
        return None

    # Verify input shape
    if formatted_features.shape[1] != rf_model.n_features_in_:
        print(f"Error: Feature count mismatch. Expected {rf_model.n_features_in_}, got {formatted_features.shape[1]}.")
        return None

    # Random Forest prediction
    rf_pred = rf_model.predict(formatted_features)
    rf_proba = rf_model.predict_proba(formatted_features)[:, 1]  # Probability of Malicious

    # Logistic Regression prediction (scale features)
    formatted_scaled = lr_scaler.transform(formatted_features)
    lr_pred = lr_model.predict(formatted_scaled)
    lr_proba = lr_model.predict_proba(formatted_scaled)[:, 1]

    # XGBoost prediction
    xgb_pred = xgb_model.predict(formatted_features)
    xgb_proba = xgb_model.predict_proba(formatted_features)[:, 1]

    # Compile results
    results = {
        'Random Forest': {'Prediction': rf_pred[0], 'Probability (Malicious)': rf_proba[0]},
        'Logistic Regression': {'Prediction': lr_pred[0], 'Probability (Malicious)': lr_proba[0]},
        'XGBoost': {'Prediction': xgb_pred[0], 'Probability (Malicious)': xgb_proba[0]}
    }

    # Print results
    print("Prediction Results (0=Safe, 1=Malicious):")
    for model, result in results.items():
        print(f"{model}:")
        print(f"  Prediction: {result['Prediction']} ({'Malicious' if result['Prediction'] == 1 else 'Safe'})")
        print(f"  Probability (Malicious): {result['Probability (Malicious)']:.4f}")

# Run predictions (use models and scaler from Step 4, formatted_test_features from Step 6)
prediction_results = make_predictions(formatted_test_features, rf_model, lr_model, lr_scaler, xgb_model)  
  