
import pandas as pd
import joblib
import logging
import time
import os
import re
from src.preprocess import preprocess_features
from src.config import MODEL_PATHS, PREPROCESSOR_PATH, NSL_KDD_RELEVANT_COLUMNS
from src.zeek_feature_extractor import ZeekFeatureExtractor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

ZEEK_LOG_DIR = "/opt/zeek/logs/current/" # Đã điều chỉnh theo đường dẫn bạn cung cấp
ZEEK_CONN_LOG_FILE_NAME = "conn.log"

def get_latest_zeek_conn_log_path():
    """Tìm đường dẫn đầy đủ đến file conn.log mới nhất trong thư mục Zeek log."""
    full_path = os.path.join(ZEEK_LOG_DIR, ZEEK_CONN_LOG_FILE_NAME)
    if os.path.exists(full_path):
        return full_path
    else:
        logging.warning(f"File log Zeek không tìm thấy tại {full_path}. Đang chờ Zeek ghi log.")
        return None

def monitor():
    logging.info("[*] Đang tải mô hình và preprocessor...")
    try:
        model = joblib.load(MODEL_PATHS['xgb'])
        preprocessor = joblib.load(PREPROCESSOR_PATH)
    except FileNotFoundError as e:
        logging.error(f"Không tìm thấy file mô hình hoặc preprocessor: {e}. Vui lòng chạy chế độ huấn luyện trước.")
        return
    except Exception as e:
        logging.error(f"Lỗi khi tải mô hình/preprocessor: {e}", exc_info=True)
        return

    logging.info("[*] Bắt đầu giám sát log Zeek...")
    
    feature_extractor = ZeekFeatureExtractor()

    current_log_path = None
    log_file = None
    column_names = [] # Khởi tạo rỗng, sẽ được điền khi đọc header
    last_processed_pos = {} # Lưu trữ vị trí cuối cùng đọc của mỗi file

    while True:
        try:
            new_log_path = get_latest_zeek_conn_log_path()

            # Nếu đường dẫn log thay đổi hoặc file hiện tại không còn tồn tại
            # (ví dụ: Zeek đã xoay log và tạo file mới cùng tên nhưng thực chất là file khác)
            # Hoặc nếu chưa có file log nào được mở
            if new_log_path is None:
                time.sleep(5) # Chờ Zeek tạo log file
                continue

            # Kiểm tra xem có phải là file mới hoàn toàn hoặc đã xoay file không
            # Kiểm tra inode để biết đó có phải là file vật lý mới không
            try:
                current_inode = os.stat(current_log_path).st_ino if current_log_path else None
                new_inode = os.stat(new_log_path).st_ino
            except FileNotFoundError:
                current_inode = None # Nếu file cũ bị xóa

            # Nếu đường dẫn thay đổi HOẶC inode thay đổi (file mới cùng tên)
            if new_log_path != current_log_path or new_inode != current_inode:
                if log_file:
                    log_file.close()
                    logging.info(f"Đóng file log cũ: {current_log_path}")
                
                current_log_path = new_log_path
                logging.info(f"Đang mở file log mới: {current_log_path}")
                
                # Mở file mới
                log_file = open(current_log_path, 'r', encoding='utf-8', errors='ignore')
                
                # Đọc header của file mới
                header_parsed = False
                column_names = [] # Reset column names
                for _ in range(20): # Đọc tối đa 20 dòng đầu để tìm header (đủ để tìm #fields)
                    line_header = log_file.readline()
                    if not line_header:
                        break # Hết file
                    if '#fields' in line_header:
                        match = re.search(r'#fields\s+(.*)', line_header)
                        if match:
                            column_names = match.group(1).split('\t')
                            logging.info(f"Đã đọc header Zeek log. Các cột: {column_names}")
                            header_parsed = True
                            break
                
                if not header_parsed:
                    logging.error(f"Không tìm thấy dòng '#fields' trong 20 dòng đầu của {current_log_path}. Đảm bảo Zeek ghi log đúng định dạng.")
                    # Đóng file và thử lại vòng lặp sau
                    if log_file:
                        log_file.close()
                        log_file = None
                    time.sleep(5)
                    continue

                # Di chuyển đến vị trí cuối cùng đã đọc của file này (nếu có)
                # Hoặc đến cuối file nếu là lần đầu mở
                if current_log_path in last_processed_pos:
                    log_file.seek(last_processed_pos[current_log_path])
                    logging.info(f"Tiếp tục đọc từ vị trí {last_processed_pos[current_log_path]} trong file cũ.")
                else:
                    log_file.seek(0, 2) # Chuyển đến cuối file để chỉ đọc dòng mới
                    logging.info(f"Đang đọc từ cuối file mới {current_log_path}.")

            if log_file is None or not column_names:
                time.sleep(1)
                continue

            line = log_file.readline()
            if not line:
                # Lưu lại vị trí hiện tại trước khi chờ
                last_processed_pos[current_log_path] = log_file.tell()
                time.sleep(0.1)
                continue
            
            # Zeek có thể ghi các dòng header hoặc comment khác sau khi xoay file
            # Bỏ qua các dòng comment (bắt đầu bằng #)
            if line.startswith('#'):
                # Không cần xử lý header ở đây nữa vì đã xử lý khi mở file
                continue

            # Parse dòng log thành dictionary
            values = line.strip().split('\t')
            
            if len(values) != len(column_names):
                logging.warning(f"Số lượng cột không khớp. Dòng: {line.strip()}. Expected {len(column_names)}, Got {len(values)}")
                continue
            
            log_entry_dict = dict(zip(column_names, values))
            
            nslkdd_features = feature_extractor.process_zeek_log_entry(log_entry_dict)
            
            if nslkdd_features is None:
                logging.debug("Bỏ qua Zeek log entry không thể xử lý hoặc không có đặc trưng.")
                continue
            
            df = pd.DataFrame([nslkdd_features], columns=NSL_KDD_RELEVANT_COLUMNS)

            try:
                X, _, _ = preprocess_features(df, preprocessor=preprocessor, fit=False)
                prediction = model.predict(X)[0]
                label = 'Normal' if prediction == 0 else 'Malicious'
                
                try:
                    proba = model.predict_proba(X)[0, 1]
                    logging.info(f"[+] Zeek Flow ({log_entry_dict.get('ts', 'N/A')} {log_entry_dict.get('id.orig_h', 'N/A')}:{log_entry_dict.get('id.orig_p', 'N/A')} -> {log_entry_dict.get('id.resp_h', 'N/A')}:{log_entry_dict.get('id.resp_p', 'N/A')}): {label} (Xác suất tấn công: {proba:.4f})")
                except AttributeError:
                     logging.info(f"[+] Zeek Flow ({log_entry_dict.get('ts', 'N/A')} {log_entry_dict.get('id.orig_h', 'N/A')}:{log_entry_dict.get('id.orig_p', 'N/A')} -> {log_entry_dict.get('id.resp_h', 'N/A')}:{log_entry_dict.get('id.resp_p', 'N/A')}): {label}")

            except Exception as e:
                logging.error(f"Lỗi trong quá trình tiền xử lý hoặc dự đoán từ Zeek log: {e}", exc_info=True)

        except FileNotFoundError:
            logging.error(f"File log Zeek không tìm thấy tại {new_log_path}. Đang chờ Zeek ghi log...")
            current_log_path = None
            log_file = None # Đặt lại log_file để nó sẽ được mở lại
            time.sleep(5)
        except Exception as e:
            logging.error(f"Lỗi tổng quát khi đọc hoặc xử lý log Zeek: {e}", exc_info=True)
            time.sleep(1)



