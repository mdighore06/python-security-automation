# Security Automation — Dataset Directory

This directory stores security datasets utilized by the machine-learning threat detection pipeline (`ml/threat_detector.py`).

## Dataset Specifications & Usage

* **Default File Name:** `phishing.csv`
* **Data Format:** CSV (Comma-Separated Values)
* **Required Features:** Numerical or categorical feature columns representing web/network characteristics, ending with a target label column (`Result` or binary class label where `1` = Malicious and `0` / `-1` = Benign).

## How to Populate

1. Download the **Phishing Websites Dataset** from the [UCI Machine Learning Repository](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites) (or an equivalent labeled security dataset with $\ge 5,000$ samples).
2. Place the downloaded `.csv` file into this directory and ensure it is named `phishing.csv`:
   ```text
   ml/data/phishing.csv
