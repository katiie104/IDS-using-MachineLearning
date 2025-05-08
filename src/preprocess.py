# import pandas as pd
# import numpy as np
# from sklearn.preprocessing import StandardScaler, OneHotEncoder
# from sklearn.compose import ColumnTransformer
# from sklearn.model_selection import train_test_split
# from src.config import DROP_COLUMNS, DATA_PATH
 
# def load_data(filepath):
#     """Tải dữ liệu NSL-KDD với cấu trúc chuẩn"""
#     columns = [
#         'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
#         'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
#         'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
#         'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
#         'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
#         'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
#         'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
#         'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
#         'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
#         'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'outcome', 'difficulty'
#     ]
    
#     df = pd.read_csv(filepath, names=columns, header=None)
#     return df

# def clean_data(df):
#     """Làm sạch dữ liệu NSL-KDD"""
#     # Xử lý missing values và duplicate
#     df.replace(['?', 'inf'], np.nan, inplace=True)
#     df.dropna(inplace=True)
#     df.drop_duplicates(inplace=True)
    
#     # Xóa cột không cần thiết
#     df.drop(['difficulty'] + DROP_COLUMNS, axis=1, errors='ignore', inplace=True)
    
#     # Chuẩn hóa nhãn
#     attack_types = {
#         'normal': 'normal',
#         'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 
#         'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS',
#         'processtable': 'DoS', 'udpstorm': 'DoS',
#         'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 
#         'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
#         'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 
#         'rootkit': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
#         'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 
#         'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L',
#         'warezmaster': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L'
#     }
    
#     df['attack_category'] = df['outcome'].map(attack_types)
#     df['binary_label'] = df['outcome'].apply(lambda x: 0 if x == 'normal' else 1)
    
#     return df

# def preprocess_features(df, preprocessor=None, fit=False):
#     """Tiền xử lý đặc trưng cho NSL-KDD"""
#     # Xác định các cột đặc trưng
#     numeric_features = df.select_dtypes(include=['int64', 'float64']).columns.drop(['binary_label'], errors='ignore')
#     categorical_features = df.select_dtypes(include=['object']).columns.drop(['outcome', 'attack_category'], errors='ignore')

#     if preprocessor is None:
#         preprocessor = ColumnTransformer(
#             transformers=[
#                 ('num', StandardScaler(), numeric_features),
#                 ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
#             ])

#     if fit:
#         X = preprocessor.fit_transform(df)
#     else:
#         X = preprocessor.transform(df)
    
#     y = df['binary_label']
#     return X, y, preprocessor



import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from src.config import DROP_COLUMNS, DATA_PATH

def load_data(filepath):
    """Tải dữ liệu NSL-KDD với cấu trúc chuẩn"""
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
    
    df = pd.read_csv(filepath, names=columns, header=None)
    return df

def clean_data(df):
    """Làm sạch và chuẩn hóa dữ liệu NSL-KDD"""
    df.replace(['?', 'inf'], np.nan, inplace=True)
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)

    df.drop(['difficulty'] + DROP_COLUMNS, axis=1, errors='ignore', inplace=True)

    # Mapping các loại tấn công thành nhóm
    attack_types = {
        'normal': 'normal',
        'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 
        'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS',
        'processtable': 'DoS', 'udpstorm': 'DoS',
        'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 
        'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
        'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 
        'rootkit': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
        'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 
        'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L',
        'warezmaster': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L'
    }

    df['attack_category'] = df['outcome'].map(attack_types)
    df['binary_label'] = df['outcome'].apply(lambda x: 0 if x == 'normal' else 1)

    return df

def preprocess_features(df, preprocessor=None, fit=False):
    """
    Tiền xử lý đặc trưng – dùng được cho cả dữ liệu training và dữ liệu thời gian thực.
    
    Args:
        df: DataFrame cần xử lý
        preprocessor: pipeline đã khởi tạo hoặc None
        fit: nếu True thì fit + transform, ngược lại chỉ transform

    Returns:
        X: đặc trưng đã xử lý
        y: nhãn (nếu có)
        preprocessor: pipeline đã khởi tạo
    """
    df_copy = df.copy()

    # Xác định các cột
    numeric_features = df_copy.select_dtypes(include=['int64', 'float64']).columns.drop(
        ['binary_label'], errors='ignore'
    )
    categorical_features = df_copy.select_dtypes(include=['object']).columns.drop(
        ['outcome', 'attack_category'], errors='ignore'
    )

    # Tạo pipeline nếu chưa có
    if preprocessor is None:
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), numeric_features),
                ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
            ]
        )

    if fit:
        X = preprocessor.fit_transform(df_copy)
    else:
        X = preprocessor.transform(df_copy)

    y = df_copy['binary_label'] if 'binary_label' in df_copy.columns else None
    return X, y, preprocessor
