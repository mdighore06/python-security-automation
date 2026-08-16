# Python Security Automation & AI/ML-Driven Threat Detection

A complete, production-grade security automation framework and AI/ML threat detection suite built for SOC workflows.

---

## 1. Project Structure

```text
python-security-automation/
├── README.md
├── scope.md
├── requirements.txt
├── .gitignore
├── .env.example
├── port_scanner.py
├── log_enricher.py
├── virustotal_check.py
├── ml/
│   ├── threat_detector.py
│   ├── README.md
│   └── data/
│       └── README.md
├── samples/
│   ├── firewall.log
│   └── sample_output/
│       ├── log-enrichment.json
│       └── virustotal-output.txt
├── tests/
│   ├── __init__.py
│   ├── test_port_scanner.py
│   ├── test_log_enricher.py
│   ├── test_virustotal.py
│   └── test_threat_detector.py
├── outputs/
│   ├── model-results.txt
│   └── classification-report.txt
└── .github/
    └── workflows/
        └── security.yml
```

---

## 2. Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/python-security-automation.git](https://github.com/your-username/python-security-automation.git)
   cd python-security-automation
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Open `.env` and add your VirusTotal v3 API key:
   ```env
   VT_API_KEY=your_virustotal_api_key_here
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 3. Usage & Tool Execution

### Task 1: Multithreaded Port Scanner (`port_scanner.py`)
Scans TCP ports concurrently and attempts banner grabbing without external binaries.
```bash
python port_scanner.py 127.0.0.1 20 100
```

### Task 2: Log Parser & Threat Intel Enricher (`log_enricher.py`)
Parses firewall logs, extracts public IPv4 addresses using regex, filters private ranges, and enriches IPs via `ip-api.com`.
```bash
python log_enricher.py samples/firewall.log
```

### Task 4: VirusTotal REST API v3 Integration (`virustotal_check.py`)
Queries VirusTotal v3 API for reputational analysis stats on target IPs using environment variables.
```bash
python virustotal_check.py 8.8.8.8 185.220.101.5
```

### Task 3: Machine Learning Threat Detector (`ml/threat_detector.py`)
Trains a supervised **Random Forest Classifier** and an unsupervised **Isolation Forest** model for anomaly detection.
```bash
python ml/threat_detector.py
```

---

## 4. Sample Outputs

### Log Enrichment Sample Output (`samples/sample_output/log-enrichment.json`)
```json
{
    "185.220.101.5": {
        "country": "Germany",
        "isp": "Zwiebelfreunde e.V.",
        "is_hosting": true,
        "is_proxy": true,
        "is_mobile": false
    },
    "8.8.8.8": {
        "country": "United States",
        "isp": "Google LLC",
        "is_hosting": false,
        "is_proxy": false,
        "is_mobile": false
    }
}
```

### VirusTotal Enrichment Sample Output (`samples/sample_output/virustotal-output.txt`)
```json
{
    "185.220.101.5": {
        "vt_malicious_detections": 14,
        "vt_harmless_count": 72,
        "vt_last_analysis_date": 1718050000
    },
    "8.8.8.8": {
        "vt_malicious_detections": 0,
        "vt_harmless_count": 92,
        "vt_last_analysis_date": 1718000000
    }
}
```

---

## 5. Machine Learning Evaluation

### Dataset Summary
* **Total Samples:** 5,000
* **Class Distribution:** Benign (0): 4,250 (85%) | Malicious (1): 750 (15%)
* **Duplicates Dropped:** 142

### Classification Report (Random Forest)
```text
              precision    recall  f1-score   support

      Benign       0.98      0.99      0.98       850
   Malicious       0.94      0.88      0.91       150

    accuracy                           0.97      1000
   macro avg       0.96      0.94      0.95      1000
weighted avg       0.97      0.97      0.97      1000
```

### Model Comparison
| Model | Accuracy | Precision | Recall | F1 Score | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | 0.970 | 0.940 | 0.880 | 0.909 | Supervised; high precision on known threat signatures. |
| **Isolation Forest** | 0.825 | 0.410 | 0.430 | 0.420 | Unsupervised; isolates structural anomalies without labels. |

---

## 6. Discussion: Security ML Metrics & Limitations

Precision and recall are vastly superior to raw accuracy when evaluating security datasets due to extreme class imbalance—malicious activity represents a tiny fraction of total network traffic. A naive model that classifies 100% of network packets as benign can easily report 99% accuracy while allowing every single security breach to pass unnoticed. 

**Precision** measures how many identified threats are genuinely malicious, directly preventing analyst operational fatigue from false positives. **Recall** measures the proportion of actual attacks successfully detected, directly preventing critical false negatives (unmitigated security breaches). The **F1 score** provides the harmonic mean of precision and recall, serving as the definitive measure of a classifier's operational effectiveness.

* **Random Forest Limitation:** As a supervised model, it depends strictly on historical, labeled attack signatures and completely fails to detect novel Zero-Day exploits lacking existing training patterns.
* **Isolation Forest Limitation:** As an unsupervised model, it suffers from a high false-positive rate in production because benign, high-volume operational spikes are frequently misidentified as malicious anomalies.

---

## 7. Input → Process → Output Automation Mindset

The Input → Process → Output (IPO) architecture structures raw data ingestion, transformation logic, and programmatic reporting across the entire automation suite:

1. **`port_scanner.py`**: Accepts targeted IP addresses and port ranges (**Input**), executes multi-threaded non-blocking TCP socket handshakes (**Process**), and outputs clean, structured port state tables (**Output**).
2. **`log_enricher.py` / `virustotal_check.py`**: Ingests raw syslog lines (**Input**), parses public IPv4 addresses using regex and queries REST APIs (**Process**), and outputs enriched JSON threat telemetry (**Output**).
3. **`ml/threat_detector.py`**: Ingests numerical feature telemetry vectors (**Input**), performs Random Forest and Isolation Forest inference (**Process**), and outputs binary threat classifications with confidence scores (**Output**).

---

## 8. SOAR Workflow Integration

Integrating these three automation scripts into a Security Orchestration, Automation, and Response (SOAR) platform forms an automated incident mitigation pipeline:

1. **Data Collection & Enrichment:** The log parsing module (`log_enricher.py`) continuously streams incoming firewall and authentication logs, extracts external IP addresses, and triggers enrichment via VirusTotal (`virustotal_check.py`).
2. **Detection:** Enriched feature matrices are passed into `ml/threat_detector.py`, which generates a threat confidence score ranging from $0.0$ to $1.0$.
3. **Automated Response & Escalation:**
   * **Confidence Score $\ge 0.85$ (High Confidence):** Triggers an immediate, automated SOAR action to block the IP address at the perimeter firewall and update active access control lists (ACLs). At this threshold, the risk of a false positive is low enough to prioritize instant risk mitigation over manual review.
   * **Confidence Score between $0.50$ and $0.84$ (Medium Confidence):** Automatically creates a ticket assigned to a Tier 2 SOC analyst containing all enriched VirusTotal telemetry and ML feature outputs for manual investigation.
   * **Confidence Score $< 0.50$ (Low Confidence / Benign):** Automatically logged to security data lakes for passive audit tracking without interrupting human analysts.

This multi-tiered thresholding manages the fundamental SOC trade-off between false positives (unnecessary business disruption from blocking legitimate traffic) and false negatives (unmitigated security breaches).
