import pyshark
import pandas as pd
import joblib
from src.preprocess import preprocess_features
from src.config import MODEL_PATHS, PREPROCESSOR_PATH
 
def packet_to_dict(pkt):
    """Chuyển đổi gói tin Pyshark thành dictionary đơn giản phù hợp với NSL-KDD (giả lập)"""
    try:
        return {
            'duration': 0,
            'protocol_type': pkt.transport_layer.lower() if pkt.transport_layer else 'tcp',
            'service': 'http',  # Bạn có thể tùy chỉnh nếu có thể extract chính xác
            'flag': 'SF',
            'src_bytes': int(pkt.length),
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0,
            'outcome': 'normal'
        }
    except Exception as e:
        print(f"Lỗi khi phân tích gói tin: {e}")
        return None

def monitor():
    print("[*] Đang tải mô hình và preprocessor...")
    model = joblib.load(MODEL_PATHS['xgb'])
    preprocessor = joblib.load(PREPROCESSOR_PATH)

    print("[*] Bắt đầu giám sát mạng...")
    capture = pyshark.LiveCapture(interface='Wi-Fi')  # Hoặc 'eth0' tùy theo máy

    for pkt in capture.sniff_continuously():
        pkt_dict = packet_to_dict(pkt)
        if pkt_dict is None:
            continue

        df = pd.DataFrame([pkt_dict])

        try:
            X, _, _ = preprocess_features(df, preprocessor=preprocessor, fit=False)
            prediction = model.predict(X)[0]
            label = 'Normal' if prediction == 0 else 'Malicious'
            print(f"[+] Gói tin: {label}")
        except Exception as e:
            print(f"Lỗi dự đoán: {e}")

if __name__ == "__main__":
    monitor()
