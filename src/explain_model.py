import shap
import matplotlib.pyplot as plt
from src.config import SHAP_SUMMARY_PLOT_PATH

def explain_model(model, X_sample, save_plot=False):
    """
    Giải thích mô hình sử dụng SHAP
    Args:
        X_sample: Mẫu dữ liệu để giải thích (nên < 1000 mẫu)
    """
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)
    
    # Tổng quan về feature importance
    plt.figure()
    shap.summary_plot(shap_values, X_sample, show=False)
    if save_plot:
        plt.savefig(SHAP_SUMMARY_PLOT_PATH, bbox_inches='tight')
        print(f"SHAP summary plot saved to {SHAP_SUMMARY_PLOT_PATH}")
    plt.close()
    
    # Giải thích cho từng dự đoán cụ thể
    sample_explanation = explainer(X_sample[:5])
    
    return {
        'shap_values': shap_values,
        'sample_explanation': sample_explanation
    }