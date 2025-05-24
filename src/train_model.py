# src/train_model.py

import pandas as pd
import joblib
import logging
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from src.preprocess import load_nslkdd_data, preprocess_features # Import các hàm từ preprocess
from src.config import MODEL_PATHS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def train_model():
    logging.info("[*] Bắt đầu quá trình huấn luyện mô hình.")

    # 1. Tải dữ liệu NSL-KDD
    try:
        df_train = load_nslkdd_data("dataset/NSL-KDD-Dataset/KDDTrain+.txt")
        df_test = load_nslkdd_data("dataset/NSL-KDD-Dataset/KDDTest+.txt")
    except FileNotFoundError as e:
        logging.error(f"Không tìm thấy file dữ liệu NSL-KDD: {e}. Vui lòng kiểm tra đường dẫn.")
        return
    except Exception as e:
        logging.error(f"Lỗi khi tải dữ liệu: {e}", exc_info=True)
        return

    # 2. Tiền xử lý dữ liệu huấn luyện
    # preprocessor sẽ được huấn luyện trên df_train và lưu lại
    X_train_processed, y_train, preprocessor = preprocess_features(df_train, fit=True)
    
    # 3. Tiền xử lý dữ liệu kiểm thử
    # Sử dụng preprocessor đã huấn luyện để transform df_test
    X_test_processed, y_test, _ = preprocess_features(df_test, preprocessor=preprocessor, fit=False)

    # 4. Huấn luyện mô hình XGBoost
    logging.info("Huấn luyện mô hình XGBoost...")
    model = xgb.XGBClassifier(
        objective='binary:logistic',
        eval_metric='logloss',
        use_label_encoder=False,
        n_estimators=100, # Số lượng cây
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )
    model.fit(X_train_processed, y_train)
    
    # 5. Đánh giá mô hình
    logging.info("Đánh giá mô hình trên tập kiểm thử...")
    y_pred = model.predict(X_test_processed)
    y_proba = model.predict_proba(X_test_processed)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)

    logging.info(f"Độ chính xác (Accuracy): {accuracy:.4f}")
    logging.info(f"Độ chính xác (Precision): {precision:.4f}")
    logging.info(f"Độ thu hồi (Recall): {recall:.4f}")
    logging.info(f"Điểm F1 (F1-Score): {f1:.4f}")
    logging.info(f"ROC AUC: {roc_auc:.4f}")

    # 6. Lưu mô hình
    try:
        joblib.dump(model, MODEL_PATHS['xgb'])
        logging.info(f"Đã lưu mô hình XGBoost tại: {MODEL_PATHS['xgb']}")
    except Exception as e:
        logging.error(f"Lỗi khi lưu mô hình: {e}", exc_info=True)

    logging.info("[*] Hoàn tất quá trình huấn luyện mô hình.")

if __name__ == "__main__":
    train_model()



