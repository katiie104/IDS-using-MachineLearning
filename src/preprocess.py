# src/preprocess.py

import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
import logging
from src.config import NSL_KDD_RELEVANT_COLUMNS, SERVICE_MAPPING, ZEEK_CONN_STATE_TO_NSL_FLAG

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def map_port_to_service(protocol, port):
    """Ánh xạ cổng và giao thức sang dịch vụ NSL-KDD."""
    if protocol == 'tcp' and port in SERVICE_MAPPING:
        return SERVICE_MAPPING[port]
    if protocol == 'udp' and port in SERVICE_MAPPING:
        return SERVICE_MAPPING[port]
    return 'other'

def preprocess_features(df, preprocessor=None, fit=True):
    """
    Tiền xử lý các đặc trưng của bộ dữ liệu NSL-KDD.
    :param df: DataFrame chứa dữ liệu thô.
    :param preprocessor: Bộ tiền xử lý đã được huấn luyện (dùng cho chế độ monitor).
    :param fit: True nếu huấn luyện bộ tiền xử lý, False nếu chỉ transform.
    :return: X_processed (features), y (labels), preprocessor (bộ tiền xử lý đã huấn luyện).
    """
    #logging.info(f"Kích thước DataFrame đầu vào: {df.shape}")

    # Bước 1: Đảm bảo DataFrame chỉ chứa các cột quan trọng và điền giá trị mặc định
    # Điều này cực kỳ quan trọng để đảm bảo đồng bộ giữa training và real-time
    processed_df = pd.DataFrame(columns=NSL_KDD_RELEVANT_COLUMNS)
    for col in NSL_KDD_RELEVANT_COLUMNS:
        if col in df.columns:
            processed_df[col] = df[col]
        else:
            # Điền giá trị mặc định cho các cột không có trong Zeek conn.log
            if col in ['protocol_type', 'service', 'flag', 'outcome']:
                processed_df[col] = 'unknown'
            elif col in ['land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 
                          'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 
                          'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
                          'num_outbound_cmds', 'is_host_login', 'is_guest_login']:
                processed_df[col] = 0
            else: # Các cột số khác
                processed_df[col] = 0.0
    
    # Ép kiểu dữ liệu để tránh lỗi sau này (đặc biệt sau khi điền 0/unknown)
    for col in ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
                'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
                'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                'dst_host_srv_rerror_rate']:
        if col in processed_df.columns:
            processed_df[col] = pd.to_numeric(processed_df[col], errors='coerce').fillna(0.0)
    
    for col in ['land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 
                'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 
                'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
                'num_outbound_cmds', 'is_host_login', 'is_guest_login']:
        if col in processed_df.columns:
            processed_df[col] = pd.to_numeric(processed_df[col], errors='coerce').fillna(0).astype(int)


    # Loại bỏ các cột không cần thiết cho huấn luyện (ví dụ: 'outcome')
    if 'outcome' in processed_df.columns:
        X = processed_df.drop('outcome', axis=1)
        y = processed_df['outcome']
    else:
        # Trong chế độ monitor, 'outcome' có thể không có
        X = processed_df
        y = None # Hoặc một giá trị placeholder

    # Xác định các cột phân loại và số
    categorical_cols = X.select_dtypes(include=['object']).columns
    numerical_cols = X.select_dtypes(include=['number']).columns

    # logging.info(f"Cột phân loại: {list(categorical_cols)}")
    # logging.info(f"Cột số: {list(numerical_cols)}")

    # Tạo pipeline tiền xử lý
    if preprocessor is None: # Chế độ huấn luyện
        numerical_transformer = StandardScaler()
        categorical_transformer = OneHotEncoder(handle_unknown='ignore')

        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numerical_transformer, numerical_cols),
                ('cat', categorical_transformer, categorical_cols)
            ],
            remainder='passthrough' # Giữ nguyên các cột không được biến đổi (nếu có)
        )
        if fit:
            logging.info("Huấn luyện bộ tiền xử lý...")
            X_processed = preprocessor.fit_transform(X)
            joblib.dump(preprocessor, 'models/preprocessor.pkl') # Lưu bộ tiền xử lý
            logging.info("Đã lưu preprocessor.pkl")
        else:
            # logging.info("Sử dụng bộ tiền xử lý đã có...")
            X_processed = preprocessor.transform(X)
    else: # Chế độ transform (monitor)
        # logging.info("Sử dụng bộ tiền xử lý đã có để transform...")
        X_processed = preprocessor.transform(X)
    
    # logging.info(f"Kích thước dữ liệu sau tiền xử lý: {X_processed.shape}")
    return X_processed, y, preprocessor

# Hàm để đọc dữ liệu thô từ file NSL-KDD
def load_nslkdd_data(filepath="dataset/NSL-KDD-Dataset/KDDTrain+.txt"):
    """
    Tải dữ liệu NSL-KDD từ file text.
    :param filepath: Đường dẫn đến file KDDTrain+.txt hoặc KDDTest+.txt.
    :return: DataFrame của dữ liệu.
    """
    # Các tên cột của NSL-KDD
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'outcome', 'difficulty'
    ]
    
    logging.info(f"Đang tải dữ liệu từ: {filepath}")
    df = pd.read_csv(filepath, header=None, names=columns)
    
    # Xử lý cột 'outcome'
    # 'normal' là 0, còn lại là 1 (tấn công)
    df['outcome'] = df['outcome'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Loại bỏ cột 'difficulty' vì nó không phải là đặc trưng
    df = df.drop('difficulty', axis=1)

    logging.info(f"Đã tải dữ liệu với kích thước: {df.shape}")
    return df




