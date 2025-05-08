import os
 
# Đảm bảo BASE_DIR là thư mục gốc của project (IDS_ML)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Model paths
MODEL_PATHS = {
    'xgb': os.path.join(BASE_DIR, 'models', 'xgb_model.pkl'),
    'rf': os.path.join(BASE_DIR, 'models', 'rf_model.pkl')
}
PREPROCESSOR_PATH = 'models/preprocessor.pkl'

# Visualization paths
VISUALIZATION_PATHS = {
    'shap_summary': os.path.join(BASE_DIR, 'logs', 'shap_summary.png'),
    'pr_curve': os.path.join(BASE_DIR, 'logs', 'precision_recall_curve.png'),
    'confusion_matrix': os.path.join(BASE_DIR, 'logs', 'confusion_matrix.png')
}

# Visualization paths - THÊM BIẾN RIÊNG CHO SHAP
SHAP_SUMMARY_PLOT_PATH = os.path.join(BASE_DIR, 'logs', 'shap_summary.png')

# Columns to drop
DROP_COLUMNS = [
    'num_outbound_cmds',  # Hầu hết giá trị là 0
    'is_host_login',      # Hầu hết giá trị là 0
    'land'               # Hầu hết giá trị là 0
]

# NSL-KDD specific config
ATTACK_CATEGORIES = {
    'normal': 'normal',
    'DoS': ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'mailbomb', 'apache2', 'processtable', 'udpstorm'],
    'Probe': ['ipsweep', 'nmap', 'portsweep', 'satan', 'mscan', 'saint'],
    'U2R': ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'sqlattack', 'xterm'],
    'R2L': ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'spy', 'warezclient', 'warezmaster', 'xlock', 'xsnoop', 'snmpguess']
}

# Đường dẫn đến file dữ liệu chính
DATA_PATH = os.path.join(BASE_DIR, 'dataset', 'NSL-KDD-Dataset', 'KDDTrain+.txt')
