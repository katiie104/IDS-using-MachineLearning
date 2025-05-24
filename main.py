import logging
import os
import sys # Import sys để xử lý tham số dòng lệnh

# Import các hàm chính từ các module đã sửa đổi
# Chúng ta sẽ không cần import từng hàm con như clean_data, save_model...
# vì chúng đã được tích hợp bên trong các pipeline
from src.train_model import train_model as run_train_pipeline # Đổi tên để tránh trùng lặp
from src.stream_monitor import monitor as run_monitor_pipeline # Đổi tên để tránh trùng lặp

def setup_logging():
    """Cấu hình hệ thống logging."""
    # Đảm bảo thư mục logs tồn tại
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, 'app.log')),
            logging.StreamHandler()
        ]
    )

# Hàm train_pipeline cũ đã bị loại bỏ vì toàn bộ logic đã được gói gọn trong src.train_model.py

def main():
    """Điểm vào chính của ứng dụng."""
    setup_logging()
    logging.info("Ứng dụng IDS dựa trên Machine Learning đã khởi động.")

    # Sử dụng tham số dòng lệnh để chọn chế độ
    # Ví dụ: python main.py train hoặc python main.py monitor
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
    else:
        # Nếu không có tham số dòng lệnh, yêu cầu người dùng nhập
        logging.info("Chọn chế độ hoạt động:")
        print("1. Huấn luyện mô hình (train)")
        print("2. Giám sát thời gian thực (monitor)")
        choice = input("Nhập lựa chọn (1 hoặc 2 hoặc tên chế độ): ").strip().lower()
        if choice == '1' or choice == 'train':
            mode = 'train'
        elif choice == '2' or choice == 'monitor':
            mode = 'monitor'
        else:
            logging.error("Lựa chọn không hợp lệ. Vui lòng chọn 'train' hoặc 'monitor'.")
            sys.exit(1) # Thoát với mã lỗi

    if mode == 'train':
        logging.info("[*] Chế độ: Huấn luyện mô hình.")
        run_train_pipeline() # Gọi hàm train_model từ src/train_model.py
    elif mode == 'monitor':
        logging.info("[*] Chế độ: Giám sát thời gian thực.")
        run_monitor_pipeline() # Gọi hàm monitor từ src/stream_monitor.py
    else:
        logging.error(f"Chế độ '{mode}' không được hỗ trợ. Vui lòng chọn 'train' hoặc 'monitor'.")
        sys.exit(1) # Thoát với mã lỗi

if __name__ == "__main__":
    main()





