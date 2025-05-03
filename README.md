# College_MiniProject

Mini Project on Enhancing File Security With Blockchain-Based Anomaly Detection Systems


INITIAL Thought Process

User Uploads File(.exe | .txt | .pdf)
         |
We Generate Hash of the file
         |
Check Hash in Malware Dataset
         |
Match? — Yes - Malicious 
         | No
Extract Features from File [File size / type / # of strings / suspicious keywords ]
         |
Run Anomaly Detection Model
         |
Prediction: Safe or Suspicious
         |
Log on Blockchain 
         |
Show Result to User [Safe | Malicious | Suspicious (manual check)]
