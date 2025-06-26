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



# src/config.py

# Đường dẫn đến các mô hình và preprocessor
MODEL_PATHS = {
    'xgb': 'models/xgb_model.pkl',
    # Thêm các mô hình khác nếu có
}
PREPROCESSOR_PATH = 'models/preprocessor.pkl'

# --- Cấu hình cho Zeek Log Processing ---

# Danh sách các cột NSL-KDD mà chúng ta sẽ tập trung trích xuất từ Zeek logs.
# Đây là các trường quan trọng nhất cho việc nhận diện tấn công.
# Các trường content (hot, num_failed_logins, v.v.) sẽ được bỏ qua hoặc mặc định là 0
# vì chúng rất khó trích xuất chính xác từ conn.log.
NSL_KDD_RELEVANT_COLUMNS = [
    'duration',           # Từ Zeek: duration
    'protocol_type',      # Từ Zeek: proto
    'service',            # Ánh xạ từ Zeek: id.resp_p (port)
    'flag',               # Ánh xạ từ Zeek: conn_state
    'src_bytes',          # Từ Zeek: orig_bytes
    'dst_bytes',          # Từ Zeek: resp_bytes
    'land',               # Từ Zeek: kiểm tra id.orig_h == id.resp_h và id.orig_p == id.resp_p
    # 'wrong_fragment',   # Khó trích xuất từ conn.log, có thể luôn là 0
    # 'urgent',           # Khó trích xuất từ conn.log, có thể luôn là 0
    
    # Các đặc trưng thống kê (cần logic cửa sổ trượt)
    'count',              # Số kết nối đến cùng host trong 2 giây
    'srv_count',          # Số kết nối đến cùng dịch vụ trong 2 giây
    'serror_rate',        # Tỷ lệ lỗi SYN trong 2 giây (cần theo dõi conn_state)
    'srv_serror_rate',    # Tỷ lệ lỗi SYN cùng dịch vụ trong 2 giây
    'rerror_rate',        # Tỷ lệ lỗi REJ/RST trong 2 giây (cần theo dõi conn_state)
    'srv_rerror_rate',    # Tỷ lệ lỗi REJ/RST cùng dịch vụ trong 2 giây
    'same_srv_rate',      # Tỷ lệ kết nối cùng dịch vụ trong 2 giây
    'diff_srv_rate',      # Tỷ lệ kết nối khác dịch vụ trong 2 giây
    'srv_diff_host_rate', # Tỷ lệ dịch vụ khác host trong 2 giây (khó, tạm 0)

    'dst_host_count',     # Số kết nối đến cùng host đích trong N kết nối gần nhất
    'dst_host_srv_count', # Số kết nối đến cùng dịch vụ trên cùng host đích trong N kết nối gần nhất
    'dst_host_same_srv_rate', # Tỷ lệ kết nối cùng dịch vụ trên cùng host đích
    'dst_host_diff_srv_rate', # Tỷ lệ kết nối khác dịch vụ trên cùng host đích
    'dst_host_same_src_port_rate', # Tỷ lệ cổng nguồn giống trên cùng host đích
    'dst_host_srv_diff_host_rate', # Tỷ lệ dịch vụ khác host trên cùng host đích (khó, tạm 0)
    'dst_host_serror_rate', # Tỷ lệ lỗi SYN trên cùng host đích
    'dst_host_srv_serror_rate', # Tỷ lệ lỗi SYN cùng dịch vụ trên cùng host đích
    'dst_host_rerror_rate', # Tỷ lệ lỗi REJ/RST trên cùng host đích
    'dst_host_srv_rerror_rate', # Tỷ lệ lỗi REJ/RST cùng dịch vụ trên cùng host đích
    
    # Các trường Content/Binary khác thường là 0 nếu không có log bổ sung
    'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'wrong_fragment', # Thêm lại để đảm bảo đủ 41, nhưng sẽ là 0
    'outcome'             # Nhãn mặc định là 'normal'
]

# Ánh xạ các dịch vụ/cổng từ NSL-KDD
SERVICE_MAPPING = {
    80: 'http', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 443: 'https',
    53: 'domain_udp', 110: 'pop_3', 143: 'imap4', 69: 'tftp_u', 20: 'ftp_data',
    23: 'telnet', 7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime',
    19: 'chargen', 79: 'finger', 111: 'sunrpc', 512: 'exec', 513: 'login',
    514: 'shell', 515: 'printer', 540: 'uucp', 88: 'kerberos_4',
    # Thêm nhiều dịch vụ khác theo NSL-KDD nếu bạn muốn độ chính xác cao hơn
    # Dịch vụ Zeek thường tự động phát hiện, có thể lấy trực tiếp nếu có
}

# Ánh xạ trạng thái kết nối Zeek sang cờ NSL-KDD
ZEEK_CONN_STATE_TO_NSL_FLAG = {
    'S0': 'S0',  # SYN_SENT -> SYN_RECV -> S0 (SYN-ACK but not ACKed)
    'S1': 'S1',  # SYN_SENT -> SYN_RECV -> ESTABLISHED -> FIN_WAIT_1 -> S1 (FIN_SENT)
    'SF': 'SF',  # FINISHED
    'REJ': 'REJ',# Connection rejected
    'RSTO': 'RSTO', # RST from originator
    'RSTR': 'RSTR', # RST from responder
    'RSTOS0': 'S0', # Originator sent RST, but no SYN ACK from responder
    'RSTRH': 'RSTR',# Responder sent RST, but no response
    'SH': 'SH', # Half-open (SYN_SENT -> SYN_RECV)
    'SHR': 'SHR', # Half-open (SYN_RECV -> SYN_SENT -> RST)
    'OTH': 'OTH', # Other
    # Các trạng thái Zeek chi tiết hơn
    'O_F': 'SF', # Originator FIN
    'R_F': 'SF', # Responder FIN
    'O_R': 'RSTO', # Originator RST
    'R_R': 'RSTR', # Responder RST
    'O_T': 'SF', # Originator timeout (successful completion)
    'R_T': 'SF', # Responder timeout (successful completion)
    'DCE': 'SF', # Data channel established (successful)
    'CONA': 'SF', # Concurrent, active (successful)
    'CONR': 'SF', # Concurrent, passive (successful)
    'ECA': 'S1', # Established connection, no data
    'ECR': 'S1', # Established connection, no data
    'CDA': 'SF', # Connection duration anomaly (successful, but unusual duration)
    'CDP': 'SF', # Connection duration anomaly (successful, but unusual duration)
    'X_S': 'OTH', # Incomplete XMAS scan
    'X_R': 'OTH', # Incomplete XMAS scan
}

# Các trường đặc trưng có thể được coi là lỗi trong NSL-KDD
ERROR_FLAGS = ['S0', 'REJ', 'RSTO', 'RSTR'] # serror_rate, rerror_rate