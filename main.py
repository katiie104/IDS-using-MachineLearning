import logging
import os
 
from src.preprocess import load_data, clean_data, preprocess_features
from src.train_model import train_model, evaluate_model, save_model, save_preprocessor
from src.explain_model import explain_model
from src import stream_monitor  # đảm bảo bạn đã có file stream_monitor.py

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join('logs', 'app.log')),
            logging.StreamHandler()
        ]
    )

def train_pipeline():
    logging.info("Starting training + evaluation pipeline")

    train_file = "dataset/NSL-KDD-Dataset/KDDTrain+.txt"
    test_file = "dataset/NSL-KDD-Dataset/KDDTest+.txt"

    # Train set
    logging.info("Loading and preprocessing data")
    train_df = load_data(train_file)
    train_df = clean_data(train_df)
    X_train, y_train, preprocessor = preprocess_features(train_df, fit=True)

    # Test set
    test_df = load_data(test_file)
    test_df = clean_data(test_df)
    X_test, y_test, _ = preprocess_features(test_df, preprocessor=preprocessor, fit=False)

    # Train
    logging.info("Training XGBoost model")
    model = train_model(X_train, y_train, model_type='xgb', optimize=True)

    # Evaluate
    logging.info("Evaluating model")
    evaluate_model(model, X_test, y_test)

    # Explain
    logging.info("Explaining model with SHAP")
    explain_model(model, X_test[:100], save_plot=True)

    # Save model & preprocessor
    logging.info("Saving model and preprocessor")
    save_model(model, path="models/xgb_model.pkl")
    save_preprocessor(preprocessor, path="models/preprocessor.pkl")

    assert os.path.exists("models/xgb_model.pkl"), "Model file not saved!"
    assert os.path.exists("models/preprocessor.pkl"), "Preprocessor file not saved!"

    logging.info("Training pipeline completed successfully")

def main():
    setup_logging()
    logging.info("Chọn chế độ:")
    print("1. Huấn luyện mô hình (train)")
    print("2. Giám sát thời gian thực (real-time monitor)")

    choice = input("Nhập lựa chọn (1 hoặc 2): ").strip()

    if choice == '1':
        train_pipeline()
    elif choice == '2':
        logging.info("Bắt đầu giám sát thời gian thực")
        stream_monitor.monitor()
    else:
        logging.error("Lựa chọn không hợp lệ. Vui lòng chọn 1 hoặc 2.")

if __name__ == "__main__":
    main()






# Bản này là chỉ dùng để train, chứ không có monitor

# from src.preprocess import load_data, clean_data, preprocess_features
# from src.train_model import train_model, evaluate_model, save_model ,save_preprocessor
# from src.explain_model import explain_model
# import logging
# import os
 
# def setup_logging():
#     logging.basicConfig(
#         level=logging.INFO,
#         format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#         handlers=[
#             logging.FileHandler(os.path.join('logs', 'app.log')),
#             logging.StreamHandler()
#         ]
#     )

# def main():
#     setup_logging()
#     logging.info("Starting NSL-KDD IDS ML Pipeline")
    
#     try:
#         # 1. Load và tiền xử lý dữ liệu
#         logging.info("Loading and preprocessing data")
#         train_file = "dataset/NSL-KDD-Dataset/KDDTrain+.txt"
#         test_file = "dataset/NSL-KDD-Dataset/KDDTest+.txt"
          
#         # Xử lý tập train
#         train_df = load_data(train_file)
#         train_df = clean_data(train_df)
#         X_train, y_train, preprocessor = preprocess_features(train_df, fit=True)

#         # Xử lý tập test với preprocessor đã fit từ train
#         test_df = load_data(test_file)
#         test_df = clean_data(test_df)
#         X_test, y_test, _ = preprocess_features(test_df, preprocessor=preprocessor, fit=False)

        
#         # 2. Huấn luyện mô hình
#         logging.info("Training XGBoost model")
#         model = train_model(X_train, y_train, model_type='xgb', optimize=True)
        
#         # 3. Đánh giá mô hình
#         logging.info("Evaluating model")
#         evaluation_results = evaluate_model(model, X_test, y_test)
        
#         # 4. Giải thích mô hình
#         logging.info("Explaining model with SHAP")
#         explain_results = explain_model(model, X_test[:100], save_plot=True)
        
#         # 5. Lưu mô hình
#         logging.info("Saving model")
#         save_model(model)
#         save_preprocessor(preprocessor)
        
#         logging.info("Pipeline completed successfully")
        
#     except Exception as e:
#         logging.error(f"Pipeline failed: {str(e)}", exc_info=True)
#         raise

# if __name__ == "__main__":
#     main()