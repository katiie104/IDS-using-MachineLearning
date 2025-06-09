

````markdown
# Intrusion Detection System (IDS) Using Machine Learning

## 📌 Overview

This project implements an **Intrusion Detection System (IDS)** leveraging **Machine Learning (ML)** to detect network intrusions. It utilizes the **NSL-KDD** dataset for training/testing models, and integrates the following components:

- **Zeek** for network traffic analysis
- **Filebeat** for log collection
- **ELK Stack** (Elasticsearch, Logstash, Kibana) for log storage & visualization

The system classifies network traffic as benign or malicious (e.g., port scanning, DoS attacks), and sends alerts to Elasticsearch for real-time visualization on **Kibana dashboards**.

### 🧪 Tested Environment

- **Kali Linux**: Simulates attacks (port scanning, DoS)
- **Ubuntu**: Hosts IDS, Zeek, Filebeat, and ELK Stack

**Detection performance**: 0.82–0.98 for port scanning and DoS in the test environment.

---

## ✨ Features

- 🔍 **Machine Learning Models**: Logistic Regression, Decision Tree, Random Forest, SVM, KNN, MLP
- 🌐 **Network Traffic Analysis**: Zeek generates detailed network logs
- 🔄 **Log Processing**: Converts Zeek logs into ML-compatible format
- 📊 **Real-time Monitoring**: ELK Stack + Kibana dashboards
- 📥 **Log Collection**: Filebeat forwards logs to Elasticsearch

---

## ⚙️ Prerequisites

Ensure the following are installed:

- Ubuntu (or any Linux distro)
- Python 3.8+
- Zeek (Bro)
- Filebeat
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Docker (optional)
- Kali Linux (optional, for simulating attacks)

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/katiie104/IDS-using-MachineLearning.git
cd IDS-using-MachineLearning
````

### 2. Install Python Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Dependencies** (`requirements.txt`):

* pandas
* numpy
* scikit-learn
* matplotlib
* seaborn
* tensorflow

### 3. Install Zeek

```bash
sudo apt-get update
sudo apt-get install zeek
```

### 4. Install Filebeat

```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.10.2-amd64.deb
sudo dpkg -i filebeat-8.10.2-amd64.deb
```

Edit `/etc/filebeat/filebeat.yml` to collect Zeek logs (e.g., `conn.log`) and forward to Elasticsearch.

### 5. Set Up ELK Stack (via Docker)

```bash
docker-compose -f elk/docker-compose-elk.yml up -d
```

> You can modify or use the provided `docker-compose-elk.yml` file.

### 6. Download NSL-KDD Dataset

Download the following files and place them in the `data/` directory:

* `KDDTrain+.txt`
* `KDDTest+.txt`

[Download Link](https://www.unb.ca/cic/datasets/nsl.html)

---

## 📁 Project Structure

```
IDS-using-MachineLearning/
├── dataset/                # Training data
│   ├── NSL-KDD/            # NSL-KDD dataset
│       ├── KDDTrain+.txt
│       ├── KDDTest+.txt
├── models/                 # Trained models
│   ├── preprocessor.pkl    # Preprocessing pipeline
│   ├── xgb_model.pkl       # XGBoost model
├── src/                    # Source code
│   ├── __init__.py         # Package initialization
│   ├── config.py           # Configuration settings
│   ├── preprocess.py       # Data preprocessing
│   ├── train_model.py      # Model training
│   ├── zeek_feature_extractor.py  # Zeek log feature extraction
│   ├── explain_model.py    # Model explanation (SHAP)
│   ├── stream_monitor.py   # Real-time traffic monitoring
├── logs/                   # Application logs (ignored in git)
│   ├── app.log             # Log file
├── venv/                   # Virtual environment
├── requirements.txt        # Python dependencies
├── main.py                 # Main execution script
└── README.md               # Project documentation
```

---

## 🛠️ Usage

### 1. Train and Evaluate ML Models

```bash
jupyter notebook IDS_ML.ipynb
```

Notebook includes:

* Data preprocessing
* Training various ML models
* Evaluation (accuracy, precision, recall, F1-score)

---

### 2. Configure Zeek

```bash
sudo zeekctl deploy
```

Logs will be stored in: `/opt/zeek/logs/current/`

---

### 3. Process Zeek Logs

```bash
python process_zeek_logs.py
```

Extracts and formats features like `duration`, `orig_bytes`, etc. to match NSL-KDD structure.

---

### 4. Run IDS Pipeline

> ⚠️ A `run_ids.py` script (optional) should:

* Load trained ML model
* Process Zeek logs in real time
* Classify traffic and send alerts to Elasticsearch

```bash
python run_ids.py
```

---

### 5. Visualize with Kibana

Access Kibana at: [http://localhost:5601](http://localhost:5601)

* Create dashboards to view logs and ML alerts
* Set alerts for detection probabilities > 0.8

---

### 6. Simulate Attacks

**Port Scanning**:

```bash
nmap -sS <target_ip>
```

**DoS Attack**:

```bash
hping3 -S --flood -V <target_ip>
```

---

## 📈 Performance

* **Accuracy**: 95–98% on NSL-KDD test set
* **Detection Probabilities**: 0.82–0.98 (for DoS and port scanning)
* **Precision/Recall/F1-score**: High for common attacks
* **False Positive Rate**: Not fully evaluated

---

## 🔮 Future Improvements

* Real-time log streaming using **Apache Kafka**
* Deep learning models: **LSTM**, **Autoencoder**
* Train on newer datasets: **CICIDS2017**, **CSE-CIC-IDS2018**
* Harden ELK security (auth & encryption)
* Test advanced attacks (SQLi, DNS tunneling)

---

## 🤝 Contributing

Contributions welcome!

```bash
# Fork the repository
# Create your feature branch
git checkout -b feature/your-feature

# Commit and push
git commit -m "Add your feature"
git push origin feature/your-feature
```

Then open a **Pull Request**.

---

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file for more details.

---

## 📬 Contact

For issues or suggestions, open an issue on GitHub or email: **\[[your-email@example.com](mailto:your-email@example.com)]**

```

---

Bạn có thể copy đoạn trên và dán vào `README.md`. Nếu bạn muốn mình viết thêm phần nào như ảnh minh họa, biểu đồ đánh giá mô hình, hay hướng dẫn từng bước chạy script, mình cũng có thể giúp bạn bổ sung.
```
