# Malware Detector

SHA Problem Statement: ENHANCING FILE SECURITY WITH BLOCKCHAIN-BASED ANOMALY DETECTION SYSTEMS

This project is a collaborative mini-project developed by a team of four members. It aims to create a unified interface for detecting malicious files using multiple detection models. The primary objective is to streamline and enhance the process of malware detection by integrating various machine learning models into a single, user-friendly platform.

In today’s digital environment, the threat of malicious files—such as viruses, ransomware, and spyware—poses a significant risk to individuals and organizations. Traditional antivirus software may not always be effective due to evolving attack strategies. Hence, leveraging machine learning and ensemble detection methods provides a more adaptive and robust solution.

## Features

- Analyze PDF files for malicious content
- Scan executable (PE) files for malware
- Check text files for suspicious code
- Unified interface for all file types
- Detailed analysis reports

## Requirements

- Python 3.6+
- Required packages:
  - pandas
  - numpy
  - scikit-learn
  - xgboost
  - PyPDF2
  - pefile
  - tkinter (usually comes with Python)

## Installation

1. Clone this repository or download the files
2. Install the required packages:

```bash
pip install pandas numpy scikit-learn xgboost PyPDF2 pefile
```

3. Make sure you have the necessary model files and datasets in the same directory:
   - `PDFMalware2022.csv` - Dataset for PDF model
   - `dataset.csv` - Dataset for PE model
   - `bodmas_malware_category.csv` - Malware hash database
   - `dataset.xlsx` - Dataset for text file model

## Usage

1. Run the application:

```bash
python malware_detector.py
```

2. Use the "Browse" button to select a file for analysis
3. The application will automatically detect the file type, or you can manually select it
4. Click "Scan File" to start the analysis
5. Review the results in the summary tab and the detailed report in the specific analysis tab

## Models

The application uses three different models:

1. **PDF Analysis**: Uses RandomForest, Logistic Regression, and XGBoost to detect malicious PDF features
2. **PE Analysis**: Uses RandomForest, Gradient Boosting, and SVM to detect malicious executables
3. **Text Analysis**: Uses a combination of signature-based and ML detection for text files

## Note

This application is for educational purposes. Always use caution when handling potentially malicious files. 
