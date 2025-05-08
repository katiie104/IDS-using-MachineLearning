import joblib
import xgboost as xgb
import logging
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    roc_auc_score, accuracy_score, precision_recall_curve
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from src.config import MODEL_PATHS
import matplotlib.pyplot as plt
from src.config import PREPROCESSOR_PATH

def train_model(X_train, y_train, model_type='xgb', optimize=False):
    """
    Huấn luyện mô hình với lựa chọn thuật toán
    Args:
        model_type: 'xgb' (XGBoost) hoặc 'rf' (Random Forest)
        optimize: Nếu True sẽ thực hiện tối ưu siêu tham số
    """
    if model_type == 'xgb':
        model = xgb.XGBClassifier(
            # use_label_encoder=False,
            eval_metric='logloss',
            n_estimators=150,
            max_depth=7,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            tree_method ='hist'

        )
        param_grid = {
            'max_depth': [5, 7, 9],
            'learning_rate': [0.01, 0.1, 0.2],
            'n_estimators': [100, 150, 200],
            'gamma': [0, 0.1, 0.2]
        }
    else:
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            random_state=42
        )
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 15, 20],
            'min_samples_split': [2, 5, 10]
        }
    
    if optimize:
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        grid = GridSearchCV(
            model, 
            param_grid, 
            cv=cv, 
            scoring='roc_auc',
            n_jobs=-1,
            verbose=1
        )
        grid.fit(X_train, y_train)
        model = grid.best_estimator_
        print(f"Best parameters: {grid.best_params_}")
    else:
        model.fit(X_train, y_train)
    
    return model

def evaluate_model(model, X_test, y_test):
    """Đánh giá mô hình toàn diện"""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    # Classification metrics
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)
    
    # ROC AUC
    roc_auc = roc_auc_score(y_test, y_proba)
    print("\nROC AUC Score:", roc_auc)
    
    # Precision-Recall curve
    precision, recall, _ = precision_recall_curve(y_test, y_proba)
    plt.figure()
    plt.plot(recall, precision, marker='.')
    plt.title('Precision-Recall Curve')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.show()
    
    return {
        'classification_report': classification_report(y_test, y_pred, output_dict=True),
        'confusion_matrix': cm.tolist(),
        'roc_auc': roc_auc,
        'precision_recall_curve': {'precision': precision, 'recall': recall}
    }

def save_model(model, path="models/xgb_model.pkl"):
    joblib.dump(model, path)
    logging.info(f"Model saved to {path}")

def save_preprocessor(preprocessor, path="models/preprocessor.pkl"):
    joblib.dump(preprocessor, path)
    logging.info(f"Preprocessor saved to {path}")


# Back-up cho phần save model nếu bị lỗi 
# def save_model(model, filename=MODEL_PATHS['xgb']):
#     joblib.dump(model, filename)

# def save_preprocessor(preprocessor, filename=PREPROCESSOR_PATH):
#     joblib.dump(preprocessor, filename) 