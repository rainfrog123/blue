# %% [CELL 1: Introduction to Logistic Regression]
print("=" * 80)
print("LOGISTIC REGRESSION - Learning & Practice")
print("=" * 80)

print("\n" + "=" * 80)
print("WHAT IS LOGISTIC REGRESSION?")
print("=" * 80)
print("- A LINEAR model for BINARY classification (predicts 0 or 1)")
print("- Despite the name, it's for CLASSIFICATION, not regression")
print("- Outputs probability between 0 and 1 using sigmoid function")
print("- Decision boundary at 0.5 (≥0.5 → class 1, <0.5 → class 0)")
print("\nThe Sigmoid Function:")
print("  σ(z) = 1 / (1 + e^(-z))")
print("  where z = β₀ + β₁x₁ + β₂x₂ + ... + βₙxₙ")
print("\nOutput:")
print("  - Input: Real number (-∞ to +∞)")
print("  - Output: Probability (0 to 1)")
print("  - If P ≥ 0.5 → Predict class 1")
print("  - If P < 0.5 → Predict class 0")

print("\n" + "=" * 80)
print("WHEN TO USE LOGISTIC REGRESSION?")
print("=" * 80)
print("✓ Binary classification problems (yes/no, win/loss, profitable/unprofitable)")
print("✓ When you need probability estimates (not just class labels)")
print("✓ When you want a simple, interpretable baseline model")
print("✓ When features have linear relationship with log-odds")
print("✓ As a starting point before trying complex models")
print("✓ When you need to understand feature importance (via coefficients)")

print("\n" + "=" * 80)
print("KEY HYPERPARAMETERS")
print("=" * 80)
print("\n1. C (Regularization Strength):")
print("   - Inverse of regularization strength")
print("   - Smaller C = Stronger regularization = Simpler model")
print("   - Larger C = Weaker regularization = More complex model")
print("   - Default: C=1.0")
print("   - Common range: [0.001, 0.01, 0.1, 1, 10, 100]")

print("\n2. penalty (Regularization Type):")
print("   - 'l2' (Ridge): Shrinks all coefficients (default)")
print("   - 'l1' (Lasso): Can shrink some coefficients to zero (feature selection)")
print("   - 'elasticnet': Combination of l1 and l2")
print("   - 'none': No regularization")

print("\n3. solver (Optimization Algorithm):")
print("   - 'lbfgs': Default, fast for large datasets (only l2)")
print("   - 'liblinear': Good for small datasets, supports l1 and l2")
print("   - 'saga': Supports all penalties, good for large datasets")
print("   - 'newton-cg': Good for l2, fast for large datasets")
print("   - 'sag': Fast for large datasets (only l2)")

print("\n4. max_iter:")
print("   - Maximum number of iterations for solver to converge")
print("   - Default: 100 (often too low, use 1000+)")

print("\n5. class_weight:")
print("   - 'balanced': Automatically adjusts for imbalanced classes")
print("   - None: All classes have equal weight")
print("   - dict: Custom weights for each class")

print("\n" + "=" * 80)
print("THIS NOTEBOOK COVERS:")
print("=" * 80)
print("1. Simple synthetic example (2D visualization)")
print("2. Real trading data application")
print("3. Hyperparameter tuning (GridSearchCV)")
print("4. Feature importance analysis")
print("5. Model evaluation metrics (Accuracy, Precision, Recall, F1, ROC-AUC)")
print("6. Cross-validation analysis")
print("7. Probability calibration")
print("8. Regularization effects")
print("\n" + "=" * 80)

# %% [CELL 2: Import Libraries]
print("=" * 80)
print("CELL 2: Import Required Libraries")
print("=" * 80)
print("\nWhat we're doing in this cell:")
print("  • Importing essential Python libraries for machine learning")
print("  • pandas: Data manipulation and analysis")
print("  • numpy: Numerical computations")
print("  • matplotlib & seaborn: Data visualization")
print("  • sklearn: Machine learning algorithms and tools")
print("\nWhy we need these:")
print("  → LogisticRegression: The main algorithm we're learning")
print("  → StandardScaler: Feature scaling (critical for logistic regression)")
print("  → train_test_split: Split data into training and testing sets")
print("  → GridSearchCV: Automated hyperparameter tuning")
print("  → Metrics: Evaluate model performance")

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
import warnings
warnings.filterwarnings('ignore')

# Set nice plotting style
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

print("\n✓ All libraries imported successfully!")
print("✓ Ready to start learning Logistic Regression")
print("=" * 80)

# %% [CELL 2.5: Understanding the Sigmoid Function - VISUAL EXPLANATION]
print("\n" + "=" * 80)
print("VISUAL EXPLANATION: The Sigmoid Function")
print("=" * 80)

print("\nThe Heart of Logistic Regression: σ(z) = 1 / (1 + e^(-z))")
print("\nWhat does it do?")
print("  • Takes ANY real number as input (-∞ to +∞)")
print("  • Outputs a probability between 0 and 1")
print("  • Creates an S-shaped curve")
print("\nKey Properties:")
print("  • At z=0: σ(0) = 0.5 (decision boundary)")
print("  • As z→∞: σ(z) → 1 (confident class 1)")
print("  • As z→-∞: σ(z) → 0 (confident class 0)")

# Create sigmoid visualization
z = np.linspace(-10, 10, 200)
sigmoid = 1 / (1 + np.exp(-z))

plt.figure(figsize=(14, 5))

# Subplot 1: Sigmoid curve
plt.subplot(1, 2, 1)
plt.plot(z, sigmoid, linewidth=3, color='blue', label='Sigmoid: σ(z) = 1/(1+e^(-z))')
plt.axhline(y=0.5, color='red', linestyle='--', linewidth=2, label='Decision Boundary (0.5)')
plt.axvline(x=0, color='red', linestyle='--', linewidth=2, alpha=0.5)
plt.fill_between(z, sigmoid, 0.5, where=(sigmoid >= 0.5), alpha=0.3, color='green', label='Predict Class 1')
plt.fill_between(z, sigmoid, 0.5, where=(sigmoid < 0.5), alpha=0.3, color='orange', label='Predict Class 0')
plt.xlabel('z (linear combination: β₀ + β₁x₁ + β₂x₂ + ...)', fontsize=11)
plt.ylabel('Probability P(y=1|x)', fontsize=11)
plt.title('The Sigmoid Function: From Linear to Probability', fontsize=13, fontweight='bold')
plt.legend(loc='best', fontsize=9)
plt.grid(True, alpha=0.3)
plt.ylim([-0.05, 1.05])

# Add annotations
plt.annotate('Strong prediction\nfor Class 0', xy=(-5, 0.05), fontsize=9,
            bbox=dict(boxstyle='round', facecolor='orange', alpha=0.5))
plt.annotate('Strong prediction\nfor Class 1', xy=(5, 0.95), fontsize=9,
            bbox=dict(boxstyle='round', facecolor='green', alpha=0.5))
plt.annotate('Uncertain\n(50/50)', xy=(0, 0.5), xytext=(2, 0.5),
            arrowprops=dict(arrowstyle='->', color='red'),
            fontsize=9, bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.5))

# Subplot 2: Example predictions
plt.subplot(1, 2, 2)
z_examples = np.array([-4, -2, 0, 2, 4])
prob_examples = 1 / (1 + np.exp(-z_examples))

colors = ['orange' if p < 0.5 else 'green' for p in prob_examples]
bars = plt.bar(range(len(z_examples)), prob_examples, color=colors, alpha=0.7, edgecolor='black', linewidth=2)
plt.axhline(y=0.5, color='red', linestyle='--', linewidth=2, label='Threshold = 0.5')
plt.xticks(range(len(z_examples)), [f'z={z:.0f}' for z in z_examples], fontsize=10)
plt.ylabel('Predicted Probability P(y=1)', fontsize=11)
plt.title('Example Predictions at Different z Values', fontsize=13, fontweight='bold')
plt.ylim([0, 1.1])
plt.legend()
plt.grid(True, alpha=0.3, axis='y')

# Add probability labels on bars
for i, (bar, prob) in enumerate(zip(bars, prob_examples)):
    height = bar.get_height()
    prediction = "Class 1" if prob >= 0.5 else "Class 0"
    plt.text(bar.get_x() + bar.get_width()/2., height + 0.02,
            f'{prob:.3f}\n→ {prediction}',
            ha='center', va='bottom', fontsize=9, fontweight='bold')

plt.tight_layout()
plt.show()

print("\n" + "-" * 80)
print("INTERPRETATION")
print("-" * 80)
print("z = -4 → P = 0.018 → Predict Class 0 (very confident)")
print("z = -2 → P = 0.119 → Predict Class 0 (confident)")
print("z =  0 → P = 0.500 → Uncertain (coin flip)")
print("z = +2 → P = 0.881 → Predict Class 1 (confident)")
print("z = +4 → P = 0.982 → Predict Class 1 (very confident)")

print("\nKey Takeaway:")
print("  The sigmoid function converts linear predictions (z) into probabilities!")
print("  This is what makes logistic regression a PROBABILISTIC classifier.")
print("=" * 80)

# %% [CELL 3: Simple Example - Synthetic Data]
print("\n" + "=" * 80)
print("CELL 3: Create Simple Synthetic Dataset")
print("=" * 80)
print("\nWhat we're doing in this cell:")
print("  • Creating a simple 2D dataset with 2 classes")
print("  • 200 samples total (100 per class)")
print("  • Class 0: Points clustered around (-1, -1)")
print("  • Class 1: Points clustered around (+1, +1)")
print("\nWhy start with synthetic data?")
print("  ✓ Easy to visualize (only 2 features)")
print("  ✓ We know the true pattern (classes are separable)")
print("  ✓ Perfect for understanding how the algorithm works")
print("  ✓ No data cleaning or preprocessing needed")
print("\nAfter this simple example, we'll apply to real trading data!")

print("\n" + "=" * 80)
print("CREATING SYNTHETIC DATASET")
print("=" * 80)

# Create simple synthetic dataset
np.random.seed(42)
n_samples = 200

# Class 0: Lower values
X_class0 = np.random.randn(n_samples // 2, 2) - 1
y_class0 = np.zeros(n_samples // 2)

# Class 1: Higher values
X_class1 = np.random.randn(n_samples // 2, 2) + 1
y_class1 = np.ones(n_samples // 2)

# Combine
X_simple = np.vstack([X_class0, X_class1])
y_simple = np.hstack([y_class0, y_class1])

print(f"Dataset shape: {X_simple.shape}")
print(f"Class 0 samples: {(y_simple == 0).sum()}")
print(f"Class 1 samples: {(y_simple == 1).sum()}")

# Visualize the data
plt.figure(figsize=(10, 6))
plt.scatter(X_simple[y_simple == 0, 0], X_simple[y_simple == 0, 1], 
            c='blue', label='Class 0', alpha=0.6, s=50)
plt.scatter(X_simple[y_simple == 1, 0], X_simple[y_simple == 1, 1], 
            c='red', label='Class 1', alpha=0.6, s=50)
plt.xlabel('Feature 1')
plt.ylabel('Feature 2')
plt.title('Synthetic Dataset - 2 Classes')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# %% [CELL 4: Train Simple Logistic Regression]
print("\n" + "=" * 80)
print("Training Logistic Regression on Synthetic Data")
print("=" * 80)

print("\nSTEP 1: Split data into train and test sets")
print("  - Train set: 70% (to learn patterns)")
print("  - Test set: 30% (to evaluate performance)")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X_simple, y_simple, test_size=0.3, random_state=42
)

print(f"\n✓ Train set: {len(X_train)} samples")
print(f"✓ Test set:  {len(X_test)} samples")

print("\nSTEP 2: Train Logistic Regression model")
print("  - Using default parameters: C=1.0, penalty='l2', solver='lbfgs'")

# Train logistic regression
lr_simple = LogisticRegression(random_state=42)
lr_simple.fit(X_train, y_train)

print("✓ Model trained successfully!")

print("\nSTEP 3: Make predictions on test set")
# Predictions
y_pred = lr_simple.predict(X_test)
y_pred_proba = lr_simple.predict_proba(X_test)[:, 1]

print(f"  - Predicted classes: {y_pred[:10]}...")
print(f"  - Predicted probabilities: {y_pred_proba[:10]}...")

# Evaluate
print("\n" + "-" * 80)
print("MODEL PERFORMANCE METRICS")
print("-" * 80)
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}  ← What % of predictions are correct?")
print(f"Precision: {precision_score(y_test, y_pred):.4f}  ← Of predicted positives, how many are actually positive?")
print(f"Recall:    {recall_score(y_test, y_pred):.4f}  ← Of actual positives, how many did we find?")
print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}  ← Harmonic mean of precision & recall")
print(f"ROC-AUC:   {roc_auc_score(y_test, y_pred_proba):.4f}  ← Area under ROC curve (higher is better)")

# Model coefficients (feature importance)
print("\n" + "-" * 80)
print("MODEL COEFFICIENTS (How features affect prediction)")
print("-" * 80)
print(f"Intercept (β₀): {lr_simple.intercept_[0]:.4f}")
print(f"Feature 1 coefficient (β₁): {lr_simple.coef_[0][0]:.4f}")
print(f"Feature 2 coefficient (β₂): {lr_simple.coef_[0][1]:.4f}")
print("\nInterpretation:")
print("  - Positive coefficient → Higher feature value increases probability of class 1")
print("  - Negative coefficient → Higher feature value decreases probability of class 1")
print("  - The model predicts: z = β₀ + β₁×x₁ + β₂×x₂")
print("  - Then applies sigmoid: P(class=1) = 1 / (1 + e^(-z))")

# Confusion Matrix
print("\n" + "-" * 80)
print("CONFUSION MATRIX")
print("-" * 80)
cm = confusion_matrix(y_test, y_pred)
print(f"\n                Predicted")
print(f"              Class 0  Class 1")
print(f"Actual Class 0   {cm[0][0]:4d}     {cm[0][1]:4d}    ← True Negatives (TN) | False Positives (FP)")
print(f"Actual Class 1   {cm[1][0]:4d}     {cm[1][1]:4d}    ← False Negatives (FN) | True Positives (TP)")
print(f"\nBreakdown:")
print(f"  True Negatives (TN):  {cm[0][0]} - Correctly predicted as class 0")
print(f"  False Positives (FP): {cm[0][1]} - Wrongly predicted as class 1")
print(f"  False Negatives (FN): {cm[1][0]} - Wrongly predicted as class 0")
print(f"  True Positives (TP):  {cm[1][1]} - Correctly predicted as class 1")

# Create a visual confusion matrix
plt.figure(figsize=(10, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', square=True, 
            xticklabels=['Predicted 0', 'Predicted 1'],
            yticklabels=['Actual 0', 'Actual 1'],
            cbar_kws={'label': 'Count'},
            annot_kws={'fontsize': 16, 'fontweight': 'bold'})
plt.title('Confusion Matrix Visualization', fontsize=14, fontweight='bold')
plt.ylabel('Actual Class', fontsize=12)
plt.xlabel('Predicted Class', fontsize=12)

# Add text explanations
plt.text(0.5, -0.3, f'TN={cm[0][0]}', ha='center', fontsize=11, color='blue', fontweight='bold', transform=plt.gca().transAxes)
plt.text(1.5, -0.3, f'FP={cm[0][1]}', ha='center', fontsize=11, color='red', fontweight='bold', transform=plt.gca().transAxes)
plt.text(0.5, -0.4, 'Correct', ha='center', fontsize=9, color='green', transform=plt.gca().transAxes)
plt.text(1.5, -0.4, 'Error (Type I)', ha='center', fontsize=9, color='red', transform=plt.gca().transAxes)

plt.tight_layout()
plt.show()

print("\nConfusion Matrix Formula Reminders:")
print(f"  Accuracy  = (TP + TN) / Total = {(cm[1][1] + cm[0][0]) / cm.sum():.4f}")
print(f"  Precision = TP / (TP + FP) = {cm[1][1] / (cm[1][1] + cm[0][1]) if (cm[1][1] + cm[0][1]) > 0 else 0:.4f}")
print(f"  Recall    = TP / (TP + FN) = {cm[1][1] / (cm[1][1] + cm[1][0]) if (cm[1][1] + cm[1][0]) > 0 else 0:.4f}")

# %% [CELL 5: Visualize Decision Boundary]
print("\n" + "=" * 80)
print("CELL 5: Visualize Decision Boundary")
print("=" * 80)
print("\nWhat we're doing in this cell:")
print("  • Creating a visual representation of the model's decisions")
print("  • Showing how the model divides the 2D space into regions")
print("  • Left plot: Hard decision boundary (class 0 vs class 1)")
print("  • Right plot: Probability contours (smooth gradient)")
print("\nWhy is this important?")
print("  ✓ Helps understand how the model thinks")
print("  ✓ Shows the LINEAR nature of logistic regression")
print("  ✓ Reveals if classes are well-separated")
print("  ✓ Can spot overfitting or underfitting")
print("\nNote: This only works for 2D data (2 features)")
print("For higher dimensions, we use other visualization techniques.")

print("\n" + "=" * 80)
print("CREATING DECISION BOUNDARY VISUALIZATION")
print("=" * 80)

# Create mesh grid
h = 0.02  # step size
x_min, x_max = X_simple[:, 0].min() - 1, X_simple[:, 0].max() + 1
y_min, y_max = X_simple[:, 1].min() - 1, X_simple[:, 1].max() + 1
xx, yy = np.meshgrid(np.arange(x_min, x_max, h),
                     np.arange(y_min, y_max, h))

# Predict on mesh grid
Z = lr_simple.predict(np.c_[xx.ravel(), yy.ravel()])
Z = Z.reshape(xx.shape)

# Plot
plt.figure(figsize=(12, 6))

# Decision boundary
plt.subplot(1, 2, 1)
plt.contourf(xx, yy, Z, alpha=0.3, cmap='RdYlBu')
plt.scatter(X_simple[y_simple == 0, 0], X_simple[y_simple == 0, 1], 
            c='blue', label='Class 0', edgecolors='k', s=50)
plt.scatter(X_simple[y_simple == 1, 0], X_simple[y_simple == 1, 1], 
            c='red', label='Class 1', edgecolors='k', s=50)
plt.xlabel('Feature 1')
plt.ylabel('Feature 2')
plt.title('Logistic Regression - Decision Boundary')
plt.legend()
plt.grid(True, alpha=0.3)

# Probability contours
plt.subplot(1, 2, 2)
Z_proba = lr_simple.predict_proba(np.c_[xx.ravel(), yy.ravel()])[:, 1]
Z_proba = Z_proba.reshape(xx.shape)
contour = plt.contourf(xx, yy, Z_proba, levels=20, cmap='RdYlBu', alpha=0.8)
plt.colorbar(contour, label='P(Class 1)')
plt.scatter(X_simple[y_simple == 0, 0], X_simple[y_simple == 0, 1], 
            c='blue', label='Class 0', edgecolors='k', s=50)
plt.scatter(X_simple[y_simple == 1, 0], X_simple[y_simple == 1, 1], 
            c='red', label='Class 1', edgecolors='k', s=50)
plt.xlabel('Feature 1')
plt.ylabel('Feature 2')
plt.title('Probability Estimates')
plt.legend()
plt.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# %% [CELL 6: ROC Curve Analysis]
print("\n" + "=" * 80)
print("ROC CURVE ANALYSIS")
print("=" * 80)

print("\nWhat is ROC Curve?")
print("  ROC = Receiver Operating Characteristic")
print("  - Shows classifier performance across ALL decision thresholds")
print("  - X-axis: False Positive Rate (FPR) = FP / (FP + TN)")
print("  - Y-axis: True Positive Rate (TPR) = TP / (TP + FN)")
print("  - AUC = Area Under the Curve (0.5 to 1.0)")
print("\nWhy is it useful?")
print("  ✓ Threshold-independent evaluation")
print("  ✓ Works well for imbalanced datasets")
print("  ✓ Helps choose optimal decision threshold")

# Calculate ROC curve
fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba)
roc_auc = roc_auc_score(y_test, y_pred_proba)

print(f"\n✓ ROC-AUC Score: {roc_auc:.4f}")

# Plot ROC curve
plt.figure(figsize=(10, 6))
plt.plot(fpr, tpr, color='darkorange', lw=3, 
         label=f'Logistic Regression (AUC = {roc_auc:.3f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', 
         label='Random Classifier (AUC = 0.500)')
plt.fill_between(fpr, tpr, alpha=0.2, color='darkorange', label='AUC Area')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate (FPR)', fontsize=12)
plt.ylabel('True Positive Rate (TPR) / Recall', fontsize=12)
plt.title('Receiver Operating Characteristic (ROC) Curve', fontsize=14, fontweight='bold')
plt.legend(loc="lower right", fontsize=11)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

print("\n" + "-" * 80)
print("INTERPRETATION")
print("-" * 80)
print(f"Your model's AUC: {roc_auc:.4f}")
if roc_auc >= 0.9:
    print("  🌟 EXCELLENT - Outstanding discrimination ability")
elif roc_auc >= 0.8:
    print("  ✓ GOOD - Strong predictive power")
elif roc_auc >= 0.7:
    print("  ✓ FAIR - Acceptable performance")
elif roc_auc >= 0.6:
    print("  ⚠ POOR - Marginal performance")
else:
    print("  ✗ FAIL - No better than random guessing")

print("\nGeneral Guidelines:")
print("  - 1.0 = Perfect classifier (impossible in practice)")
print("  - 0.9-1.0 = Excellent")
print("  - 0.8-0.9 = Good")
print("  - 0.7-0.8 = Fair")
print("  - 0.6-0.7 = Poor")
print("  - 0.5 = Random classifier (coin flip)")
print("  - < 0.5 = Worse than random (predictions are inverted)")

# %% [CELL 7: Load Real Trading Data]
print("\n" + "=" * 80)
print("CELL 7: Load Real Trading Data")
print("=" * 80)
print("\nWhat we're doing in this cell:")
print("  • Loading actual cryptocurrency trading data")
print("  • This dataset contains historical trades with outcomes")
print("  • Each row = one trade entry point (candle)")
print("  • Includes technical indicators + trade results")
print("\nWhat's in the data:")
print("  • OHLCV data (Open, High, Low, Close, Volume)")
print("  • 33 technical indicators (RSI, MACD, BB, etc.)")
print("  • Trade outcomes (profit_ratio, exit_reason, etc.)")
print("  • Binary label: is_profitable (1=profit, 0=loss)")
print("\nOur goal:")
print("  Can we predict if a trade will be profitable?")
print("  Using ONLY indicators available at entry time!")

print("\n" + "=" * 80)
print("LOADING TRADING DATASET")
print("=" * 80)

# Try to load trading dataset
try:
    df_trading = pd.read_feather('/allah/data/ml/atr_tp-1110-0853.feather')
    print(f"✓ Trading dataset loaded: {df_trading.shape}")
    print(f"Columns: {df_trading.columns.tolist()}")
    
    # Check for required columns
    has_trades = df_trading['profit_ratio'].notna()
    df_trades = df_trading[has_trades].copy()
    print(f"\nRows with trades: {len(df_trades)}")
    
    # Create binary label
    if 'is_profitable' not in df_trades.columns:
        df_trades['is_profitable'] = (df_trades['profit_ratio'] > 0).astype(int)
    
    print(f"Profitable trades: {(df_trades['is_profitable'] == 1).sum()}")
    print(f"Loss trades: {(df_trades['is_profitable'] == 0).sum()}")
    
except FileNotFoundError:
    print("⚠ Trading dataset not found. Please update the path.")
    print("Creating dummy dataset for demonstration...")
    df_trades = None

# %% [CELL 8: Prepare Trading Features for Logistic Regression]
if df_trades is not None:
    print("\n" + "=" * 80)
    print("PREPARING TRADING FEATURES")
    print("=" * 80)
    
    print("\nFeature Selection Strategy:")
    print("  We'll use ONLY technical indicators as features")
    print("  Why? They're available at trade entry time (no look-ahead bias)")
    print("\nCategories of indicators we'll use:")
    print("  • RSI (2 indicators) - Momentum")
    print("  • MACD (3 indicators) - Trend following")
    print("  • Bollinger Bands (3 indicators) - Volatility")
    print("  • Stochastic (2 indicators) - Momentum")
    print("  • ATR, ADX, SAR (3 indicators) - Volatility & trend")
    print("  • Directional Indicators (2) - Trend strength")
    print("  • Oscillators (4) - CCI, WillR, MFI, CMO")
    print("  • Volume (1) - OBV")
    print("  • Moving Averages (6) - EMA & SMA")
    print("  • Momentum (2) - ROC, Momentum")
    print("  • Others (5) - TRIX, ULTOSC, Aroon, APO")
    print("  TOTAL: 33 technical indicators")
    
    # Define technical indicator features (from previous analysis)
    indicator_features = [
        'rsi_14', 'rsi_21',
        'macd', 'macd_signal', 'macd_hist',
        'bb_upper', 'bb_middle', 'bb_lower',
        'stoch_k', 'stoch_d',
        'atr', 'adx', 'sar',
        'plus_di', 'minus_di',
        'cci', 'willr', 'mfi', 'cmo',
        'obv',
        'ema_9', 'ema_20', 'ema_50',
        'sma_10', 'sma_30', 'sma_100',
        'roc', 'momentum',
        'trix', 'ultosc', 'aroon_up', 'aroon_down', 'apo'
    ]
    
    # Check which features exist
    available_features = [f for f in indicator_features if f in df_trades.columns]
    print(f"\n✓ Available features: {len(available_features)} / {len(indicator_features)}")
    
    if len(available_features) > 0:
        # Prepare data
        X_trading = df_trades[available_features].copy()
        y_trading = df_trades['is_profitable'].copy()
        
        # Handle missing values
        print(f"\n" + "-" * 80)
        print("DATA CLEANING")
        print("-" * 80)
        print(f"NaN values before cleaning: {X_trading.isna().sum().sum()}")
        print("  Strategy: Forward fill → Backward fill → Fill remaining with 0")
        X_trading = X_trading.fillna(method='ffill').fillna(method='bfill').fillna(0)
        print(f"NaN values after cleaning: {X_trading.isna().sum().sum()} ✓")
        
        print(f"\n" + "-" * 80)
        print("DATASET SUMMARY")
        print("-" * 80)
        print(f"Feature matrix shape: {X_trading.shape}")
        print(f"  Rows (trades): {X_trading.shape[0]}")
        print(f"  Columns (features): {X_trading.shape[1]}")
        
        print(f"\nTarget variable distribution:")
        loss_count = (y_trading == 0).sum()
        profit_count = (y_trading == 1).sum()
        loss_pct = loss_count / len(y_trading) * 100
        profit_pct = profit_count / len(y_trading) * 100
        print(f"  Class 0 (Loss):       {loss_count:5d} trades ({loss_pct:.1f}%)")
        print(f"  Class 1 (Profitable): {profit_count:5d} trades ({profit_pct:.1f}%)")
        
        # Check for class imbalance
        imbalance_ratio = max(loss_count, profit_count) / min(loss_count, profit_count)
        print(f"\nClass imbalance ratio: {imbalance_ratio:.2f}:1")
        if imbalance_ratio > 3:
            print("  ⚠ WARNING: Significant class imbalance detected!")
            print("  Consider using class_weight='balanced' in LogisticRegression")
        elif imbalance_ratio > 1.5:
            print("  ⚠ Mild class imbalance detected (monitor metrics carefully)")
        else:
            print("  ✓ Classes are relatively balanced")
    else:
        print("⚠ No indicator features found in dataset")
        X_trading, y_trading = None, None
else:
    X_trading, y_trading = None, None

# %% [CELL 9: Train Logistic Regression on Trading Data - Baseline]
if X_trading is not None:
    print("\n" + "=" * 80)
    print("CELL 9: Train Baseline Logistic Regression Model")
    print("=" * 80)
    
    print("\nWhat we're doing in this cell:")
    print("  • Training our FIRST logistic regression model")
    print("  • Using DEFAULT parameters (no tuning yet)")
    print("  • This is our BASELINE to compare against later")
    print("\nKey steps:")
    print("  1. Time-based train/test split (80/20)")
    print("  2. Feature scaling (StandardScaler)")
    print("  3. Train model with default params")
    print("  4. Evaluate on both train and test sets")
    print("\nWhy a baseline model?")
    print("  ✓ Establishes a starting point")
    print("  ✓ Quick to train (no tuning)")
    print("  ✓ Shows if problem is learnable")
    print("  ✓ Baseline for measuring improvements")
    print("\nImportant: We use TIME-BASED split (not random)")
    print("  → Train on older data, test on newer data")
    print("  → Simulates real-world trading scenario")
    
    print("\n" + "=" * 80)
    print("TRAINING BASELINE MODEL")
    print("=" * 80)
    
    # Time-based split (80% train, 20% test)
    split_idx = int(len(X_trading) * 0.8)
    X_train_t = X_trading.iloc[:split_idx]
    X_test_t = X_trading.iloc[split_idx:]
    y_train_t = y_trading.iloc[:split_idx]
    y_test_t = y_trading.iloc[split_idx:]
    
    print(f"Train set: {len(X_train_t)} samples")
    print(f"Test set:  {len(X_test_t)} samples")
    
    # Scale features
    scaler_t = StandardScaler()
    X_train_scaled = scaler_t.fit_transform(X_train_t)
    X_test_scaled = scaler_t.transform(X_test_t)
    
    # Train baseline model (default parameters)
    lr_baseline = LogisticRegression(random_state=42, max_iter=1000)
    lr_baseline.fit(X_train_scaled, y_train_t)
    
    # Predictions
    y_pred_train = lr_baseline.predict(X_train_scaled)
    y_pred_test = lr_baseline.predict(X_test_scaled)
    y_pred_proba_train = lr_baseline.predict_proba(X_train_scaled)[:, 1]
    y_pred_proba_test = lr_baseline.predict_proba(X_test_scaled)[:, 1]
    
    # Evaluate
    print("\n--- BASELINE MODEL PERFORMANCE ---")
    print(f"\nTrain Set:")
    print(f"  Accuracy:  {accuracy_score(y_train_t, y_pred_train):.4f}")
    print(f"  Precision: {precision_score(y_train_t, y_pred_train):.4f}")
    print(f"  Recall:    {recall_score(y_train_t, y_pred_train):.4f}")
    print(f"  F1 Score:  {f1_score(y_train_t, y_pred_train):.4f}")
    print(f"  ROC-AUC:   {roc_auc_score(y_train_t, y_pred_proba_train):.4f}")
    
    print(f"\nTest Set:")
    print(f"  Accuracy:  {accuracy_score(y_test_t, y_pred_test):.4f}")
    print(f"  Precision: {precision_score(y_test_t, y_pred_test):.4f}")
    print(f"  Recall:    {recall_score(y_test_t, y_pred_test):.4f}")
    print(f"  F1 Score:  {f1_score(y_test_t, y_pred_test):.4f}")
    print(f"  ROC-AUC:   {roc_auc_score(y_test_t, y_pred_proba_test):.4f}")
    
    # Confusion Matrix
    print("\n--- Confusion Matrix (Test Set) ---")
    cm_test = confusion_matrix(y_test_t, y_pred_test)
    print(f"\n                Predicted")
    print(f"              Loss (0)  Win (1)")
    print(f"Actual Loss    {cm_test[0][0]:6d}    {cm_test[0][1]:6d}")
    print(f"Actual Win     {cm_test[1][0]:6d}    {cm_test[1][1]:6d}")

# %% [CELL 10: Hyperparameter Tuning with GridSearchCV]
if X_trading is not None:
    print("\n" + "=" * 80)
    print("HYPERPARAMETER TUNING - GridSearchCV")
    print("=" * 80)
    
    print("\nWhat is GridSearchCV?")
    print("  - Systematically searches through hyperparameter combinations")
    print("  - Uses cross-validation to evaluate each combination")
    print("  - Finds the best parameters that generalize well")
    print("\nWhy tune hyperparameters?")
    print("  ✓ Default parameters rarely optimal for your specific data")
    print("  ✓ Can significantly improve model performance")
    print("  ✓ Helps prevent overfitting or underfitting")
    
    # Define parameter grid
    param_grid = {
        'C': [0.001, 0.01, 0.1, 1, 10, 100],  # Regularization strength
        'penalty': ['l1', 'l2'],  # Regularization type
        'solver': ['liblinear', 'saga'],  # Solvers that support both l1 and l2
        'max_iter': [1000]
    }
    
    print("\n" + "-" * 80)
    print("PARAMETER GRID TO SEARCH")
    print("-" * 80)
    for key, values in param_grid.items():
        print(f"  {key}: {values}")
    
    total_combinations = 1
    for values in param_grid.values():
        total_combinations *= len(values)
    print(f"\nTotal combinations to test: {total_combinations}")
    print(f"With 5-fold CV: {total_combinations * 5} model fits")
    
    # Grid search with cross-validation
    print("\n" + "-" * 80)
    print("RUNNING GRID SEARCH...")
    print("-" * 80)
    print("This may take a few moments...")
    
    grid_search = GridSearchCV(
        LogisticRegression(random_state=42),
        param_grid,
        cv=5,
        scoring='f1',  # Optimize for F1 score
        n_jobs=-1,
        verbose=1
    )
    
    grid_search.fit(X_train_scaled, y_train_t)
    
    print("\n✓ Grid search completed successfully!")
    
    print("\n" + "=" * 80)
    print("BEST PARAMETERS FOUND")
    print("=" * 80)
    for param, value in grid_search.best_params_.items():
        print(f"  {param}: {value}")
    
    print(f"\nBest cross-validation F1 score: {grid_search.best_score_:.4f}")
    
    # Evaluate best model on test set
    best_lr = grid_search.best_estimator_
    y_pred_best = best_lr.predict(X_test_scaled)
    y_pred_proba_best = best_lr.predict_proba(X_test_scaled)[:, 1]
    
    print("\n" + "=" * 80)
    print("TUNED MODEL PERFORMANCE (Test Set)")
    print("=" * 80)
    print(f"Accuracy:  {accuracy_score(y_test_t, y_pred_best):.4f}")
    print(f"Precision: {precision_score(y_test_t, y_pred_best):.4f}")
    print(f"Recall:    {recall_score(y_test_t, y_pred_best):.4f}")
    print(f"F1 Score:  {f1_score(y_test_t, y_pred_best):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test_t, y_pred_proba_best):.4f}")
    
    # Compare with baseline
    print("\n" + "=" * 80)
    print("BASELINE vs TUNED MODEL COMPARISON")
    print("=" * 80)
    baseline_f1 = f1_score(y_test_t, y_pred_test)
    tuned_f1 = f1_score(y_test_t, y_pred_best)
    improvement = ((tuned_f1 - baseline_f1) / baseline_f1) * 100
    
    print(f"Baseline F1 (default params): {baseline_f1:.4f}")
    print(f"Tuned F1 (optimized params):  {tuned_f1:.4f}")
    print(f"Improvement:                  {improvement:+.2f}%")
    
    if improvement > 5:
        print("\n✓ Significant improvement! Tuning was worth it.")
    elif improvement > 0:
        print("\n✓ Modest improvement. Consider trying more parameter combinations.")
    else:
        print("\n⚠ No improvement. Default parameters were already optimal for this data.")

# %% [CELL 11: Feature Importance Analysis]
if X_trading is not None:
    print("\n" + "=" * 80)
    print("FEATURE IMPORTANCE ANALYSIS")
    print("=" * 80)
    
    print("\nWhy analyze feature importance?")
    print("  • Understand which indicators drive profitability predictions")
    print("  • Identify redundant features (for simplification)")
    print("  • Gain trading insights (what really matters?)")
    print("  • Validate model behavior (does it make sense?)")
    
    print("\nHow Logistic Regression shows importance:")
    print("  • Coefficients (β) show each feature's contribution")
    print("  • Positive β → Higher feature value increases P(profit)")
    print("  • Negative β → Higher feature value decreases P(profit)")
    print("  • Larger |β| → Stronger influence")
    
    # Get coefficients from best model
    coefficients = best_lr.coef_[0]
    feature_importance = pd.DataFrame({
        'Feature': available_features,
        'Coefficient': coefficients,
        'Abs_Coefficient': np.abs(coefficients)
    }).sort_values('Abs_Coefficient', ascending=False)
    
    print("\n" + "=" * 80)
    print("TOP 15 MOST IMPORTANT FEATURES")
    print("=" * 80)
    print(feature_importance.head(15).to_string(index=False))
    
    # Analyze positive vs negative
    n_positive = (feature_importance['Coefficient'] > 0).sum()
    n_negative = (feature_importance['Coefficient'] < 0).sum()
    print(f"\nCoefficient Distribution:")
    print(f"  Positive coefficients: {n_positive} features (bullish indicators)")
    print(f"  Negative coefficients: {n_negative} features (bearish indicators)")
    
    # Visualize top 20 features
    top_n = 20
    top_features = feature_importance.head(top_n)
    
    plt.figure(figsize=(14, 8))
    colors = ['green' if x > 0 else 'red' for x in top_features['Coefficient']]
    bars = plt.barh(range(len(top_features)), top_features['Coefficient'], 
                    color=colors, alpha=0.7, edgecolor='black', linewidth=1)
    plt.yticks(range(len(top_features)), top_features['Feature'], fontsize=10)
    plt.xlabel('Coefficient Value (β)', fontsize=12)
    plt.title(f'Top {top_n} Most Important Features\n(Logistic Regression Coefficients)', 
              fontsize=14, fontweight='bold')
    plt.axvline(x=0, color='black', linestyle='-', linewidth=2)
    plt.grid(True, alpha=0.3, axis='x')
    
    # Add value labels
    for i, (bar, coef) in enumerate(zip(bars, top_features['Coefficient'])):
        width = bar.get_width()
        label_x = width + (0.01 if width > 0 else -0.01)
        ha = 'left' if width > 0 else 'right'
        plt.text(label_x, bar.get_y() + bar.get_height()/2, 
                f'{coef:.3f}', ha=ha, va='center', fontsize=8)
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='green', alpha=0.7, label='Positive: Increases profit probability'),
        Patch(facecolor='red', alpha=0.7, label='Negative: Decreases profit probability')
    ]
    plt.legend(handles=legend_elements, loc='lower right', fontsize=10)
    
    plt.tight_layout()
    plt.show()
    
    print("\n" + "=" * 80)
    print("INTERPRETATION GUIDE")
    print("=" * 80)
    print("\n✅ Positive Coefficients (Green bars):")
    print("  • When indicator ↑ → Probability of profit ↑")
    print("  • Example: If RSI positive → Higher RSI = More likely profitable")
    print("  • These are 'bullish' signals in your model")
    
    print("\n❌ Negative Coefficients (Red bars):")
    print("  • When indicator ↑ → Probability of profit ↓")
    print("  • Example: If ATR negative → Higher volatility = Less likely profitable")
    print("  • These are 'bearish' signals or risk indicators")
    
    print("\n📊 Magnitude Matters:")
    print("  • |β| > 0.5: Strong influence")
    print("  • 0.1 < |β| < 0.5: Moderate influence")
    print("  • |β| < 0.1: Weak influence")
    
    print("\n💡 Trading Insights:")
    top_positive = feature_importance[feature_importance['Coefficient'] > 0].head(3)
    top_negative = feature_importance[feature_importance['Coefficient'] < 0].head(3)
    
    print(f"\n  Most bullish indicators:")
    for idx, row in top_positive.iterrows():
        print(f"    • {row['Feature']}: β = {row['Coefficient']:.4f}")
    
    print(f"\n  Most bearish indicators:")
    for idx, row in top_negative.iterrows():
        print(f"    • {row['Feature']}: β = {row['Coefficient']:.4f}")

# %% [CELL 12: Cross-Validation Analysis]
if X_trading is not None:
    print("\n" + "=" * 80)
    print("CELL 12: Cross-Validation Analysis")
    print("=" * 80)
    
    print("\nWhat we're doing in this cell:")
    print("  • Performing 5-Fold Cross-Validation on training data")
    print("  • Testing model stability across different data splits")
    print("  • Measuring accuracy, F1, and ROC-AUC for each fold")
    print("\nWhat is Cross-Validation?")
    print("  • Splits training data into K folds (K=5 here)")
    print("  • Trains K times, each time using different fold for validation")
    print("  • Gives us K performance scores")
    print("  • Reports mean and standard deviation")
    print("\nWhy is this important?")
    print("  ✓ Detects overfitting (high variance = unstable model)")
    print("  ✓ More reliable than single train/test split")
    print("  ✓ Uses all training data efficiently")
    print("  ✓ Standard practice in ML")
    print("\nWhat to look for:")
    print("  • Low std deviation = Stable, reliable model")
    print("  • High std deviation = Unstable, may be overfitting")
    print("  • CV score close to test score = Good generalization")
    
    print("\n" + "=" * 80)
    print("PERFORMING 5-FOLD CROSS-VALIDATION")
    print("=" * 80)
    
    # Perform k-fold cross-validation
    cv_scores_accuracy = cross_val_score(best_lr, X_train_scaled, y_train_t, 
                                         cv=5, scoring='accuracy', n_jobs=-1)
    cv_scores_f1 = cross_val_score(best_lr, X_train_scaled, y_train_t, 
                                   cv=5, scoring='f1', n_jobs=-1)
    cv_scores_roc = cross_val_score(best_lr, X_train_scaled, y_train_t, 
                                    cv=5, scoring='roc_auc', n_jobs=-1)
    
    print("5-Fold Cross-Validation Results:")
    print("\nAccuracy:")
    print(f"  Mean: {cv_scores_accuracy.mean():.4f} (+/- {cv_scores_accuracy.std() * 2:.4f})")
    print(f"  Folds: {[f'{s:.4f}' for s in cv_scores_accuracy]}")
    
    print("\nF1 Score:")
    print(f"  Mean: {cv_scores_f1.mean():.4f} (+/- {cv_scores_f1.std() * 2:.4f})")
    print(f"  Folds: {[f'{s:.4f}' for s in cv_scores_f1]}")
    
    print("\nROC-AUC:")
    print(f"  Mean: {cv_scores_roc.mean():.4f} (+/- {cv_scores_roc.std() * 2:.4f})")
    print(f"  Folds: {[f'{s:.4f}' for s in cv_scores_roc]}")
    
    # Visualize CV scores
    plt.figure(figsize=(12, 4))
    
    plt.subplot(1, 3, 1)
    plt.bar(range(1, 6), cv_scores_accuracy, alpha=0.7, color='steelblue')
    plt.axhline(y=cv_scores_accuracy.mean(), color='red', linestyle='--', 
                label=f'Mean: {cv_scores_accuracy.mean():.3f}')
    plt.xlabel('Fold')
    plt.ylabel('Accuracy')
    plt.title('Cross-Validation - Accuracy')
    plt.legend()
    plt.ylim([0, 1])
    plt.grid(True, alpha=0.3, axis='y')
    
    plt.subplot(1, 3, 2)
    plt.bar(range(1, 6), cv_scores_f1, alpha=0.7, color='green')
    plt.axhline(y=cv_scores_f1.mean(), color='red', linestyle='--', 
                label=f'Mean: {cv_scores_f1.mean():.3f}')
    plt.xlabel('Fold')
    plt.ylabel('F1 Score')
    plt.title('Cross-Validation - F1 Score')
    plt.legend()
    plt.ylim([0, 1])
    plt.grid(True, alpha=0.3, axis='y')
    
    plt.subplot(1, 3, 3)
    plt.bar(range(1, 6), cv_scores_roc, alpha=0.7, color='orange')
    plt.axhline(y=cv_scores_roc.mean(), color='red', linestyle='--', 
                label=f'Mean: {cv_scores_roc.mean():.3f}')
    plt.xlabel('Fold')
    plt.ylabel('ROC-AUC')
    plt.title('Cross-Validation - ROC-AUC')
    plt.legend()
    plt.ylim([0, 1])
    plt.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.show()

# %% [CELL 13: Probability Calibration Analysis]
if X_trading is not None:
    print("\n" + "=" * 80)
    print("CELL 13: Probability Calibration Analysis")
    print("=" * 80)
    
    print("\nWhat we're doing in this cell:")
    print("  • Analyzing how well-calibrated our probability predictions are")
    print("  • Checking if predicted probabilities match actual outcomes")
    print("  • Creating calibration curve and probability distribution plots")
    print("\nWhat is Probability Calibration?")
    print("  • If model predicts 70% probability, does class 1 occur 70% of the time?")
    print("  • Well-calibrated = predictions match reality")
    print("  • Poorly calibrated = predictions are over/under-confident")
    print("\nWhy does this matter?")
    print("  ✓ Important if you use probabilities for decision-making")
    print("  ✓ Critical for position sizing in trading")
    print("  ✓ Helps set optimal decision thresholds")
    print("  ✓ Shows model's confidence reliability")
    print("\nInterpreting the calibration curve:")
    print("  • On diagonal = Perfectly calibrated")
    print("  • Above diagonal = Under-confident (too conservative)")
    print("  • Below diagonal = Over-confident (too aggressive)")
    print("\nNote: Logistic Regression is usually well-calibrated by default!")
    
    print("\n" + "=" * 80)
    print("ANALYZING PROBABILITY CALIBRATION")
    print("=" * 80)
    
    # Get predicted probabilities for test set
    y_proba = best_lr.predict_proba(X_test_scaled)[:, 1]
    
    # Create probability bins
    n_bins = 10
    bins = np.linspace(0, 1, n_bins + 1)
    bin_centers = (bins[:-1] + bins[1:]) / 2
    
    # Calculate actual positive rate in each bin
    bin_indices = np.digitize(y_proba, bins) - 1
    bin_indices = np.clip(bin_indices, 0, n_bins - 1)
    
    actual_positive_rate = []
    bin_counts = []
    for i in range(n_bins):
        mask = bin_indices == i
        if mask.sum() > 0:
            actual_rate = y_test_t.values[mask].mean()
            actual_positive_rate.append(actual_rate)
            bin_counts.append(mask.sum())
        else:
            actual_positive_rate.append(np.nan)
            bin_counts.append(0)
    
    # Visualize calibration
    plt.figure(figsize=(12, 5))
    
    # Calibration plot
    plt.subplot(1, 2, 1)
    plt.plot([0, 1], [0, 1], 'k--', label='Perfect calibration')
    valid_bins = [i for i, count in enumerate(bin_counts) if count > 0]
    if valid_bins:
        plt.plot([bin_centers[i] for i in valid_bins], 
                [actual_positive_rate[i] for i in valid_bins],
                'o-', label='Logistic Regression', markersize=8)
    plt.xlabel('Predicted Probability')
    plt.ylabel('Actual Positive Rate')
    plt.title('Probability Calibration Curve')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    
    # Probability distribution
    plt.subplot(1, 2, 2)
    plt.hist(y_proba[y_test_t == 0], bins=30, alpha=0.5, label='Class 0 (Loss)', color='blue')
    plt.hist(y_proba[y_test_t == 1], bins=30, alpha=0.5, label='Class 1 (Profit)', color='red')
    plt.axvline(x=0.5, color='black', linestyle='--', label='Decision threshold')
    plt.xlabel('Predicted Probability')
    plt.ylabel('Frequency')
    plt.title('Probability Distribution by Actual Class')
    plt.legend()
    plt.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.show()
    
    print("Calibration Interpretation:")
    print("  - Well-calibrated: Points follow diagonal line")
    print("  - Under-confident: Points above diagonal")
    print("  - Over-confident: Points below diagonal")

# %% [CELL 14: Different Regularization Strengths Comparison]
if X_trading is not None:
    print("\n" + "=" * 80)
    print("CELL 14: Experiment with Regularization Strength")
    print("=" * 80)
    
    print("\nWhat we're doing in this cell:")
    print("  • Testing different values of C parameter")
    print("  • Comparing model performance for each C value")
    print("  • Visualizing bias-variance tradeoff")
    print("\nWhat is the C parameter?")
    print("  • C = Inverse regularization strength")
    print("  • Small C (e.g., 0.001) = Strong regularization = Simple model")
    print("  • Large C (e.g., 1000) = Weak regularization = Complex model")
    print("\nWhat happens with different C values?")
    print("  Small C:")
    print("    ✓ More regularization → Prevents overfitting")
    print("    ✗ May underfit (too simple)")
    print("    → Good when you have limited data or noisy features")
    print("\n  Large C:")
    print("    ✓ Less regularization → Can fit complex patterns")
    print("    ✗ May overfit (memorizes training data)")
    print("    → Good when you have lots of clean data")
    print("\nThe Sweet Spot:")
    print("  • Optimal C balances bias vs variance")
    print("  • Train and test scores should be close")
    print("  • GridSearchCV found this for us in CELL 10!")
    print("\nWhat to watch for:")
    print("  • Train score >> Test score = Overfitting (C too large)")
    print("  • Both scores low = Underfitting (C too small)")
    print("  • Both scores high and close = Just right!")
    
    print("\n" + "=" * 80)
    print("TESTING DIFFERENT C VALUES")
    print("=" * 80)
    
    # Test different C values
    C_values = [0.001, 0.01, 0.1, 1, 10, 100, 1000]
    train_scores = []
    test_scores = []
    n_features_used = []
    
    print("\nTesting different C values...")
    for C in C_values:
        lr = LogisticRegression(C=C, penalty='l2', random_state=42, max_iter=1000)
        lr.fit(X_train_scaled, y_train_t)
        
        train_score = f1_score(y_train_t, lr.predict(X_train_scaled))
        test_score = f1_score(y_test_t, lr.predict(X_test_scaled))
        n_features = (np.abs(lr.coef_[0]) > 0.001).sum()
        
        train_scores.append(train_score)
        test_scores.append(test_score)
        n_features_used.append(n_features)
        
        print(f"C={C:7.3f} | Train F1: {train_score:.4f} | Test F1: {test_score:.4f} | Features: {n_features}")
    
    # Visualize
    plt.figure(figsize=(12, 5))
    
    plt.subplot(1, 2, 1)
    plt.semilogx(C_values, train_scores, 'o-', label='Train F1', linewidth=2, markersize=8)
    plt.semilogx(C_values, test_scores, 's-', label='Test F1', linewidth=2, markersize=8)
    plt.xlabel('Regularization Strength (C)')
    plt.ylabel('F1 Score')
    plt.title('Model Performance vs Regularization')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    plt.subplot(1, 2, 2)
    plt.semilogx(C_values, n_features_used, 'o-', color='green', linewidth=2, markersize=8)
    plt.xlabel('Regularization Strength (C)')
    plt.ylabel('Number of Features Used')
    plt.title('Model Complexity vs Regularization')
    plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.show()
    
    print("\nKey Insights:")
    print("  - Small C (strong regularization) → Simpler model, less overfitting")
    print("  - Large C (weak regularization) → Complex model, potential overfitting")
    print("  - Optimal C balances bias-variance tradeoff")

# %% [CELL 15: Summary and Best Practices]
print("\n" + "=" * 80)
print("CELL 15: Complete Summary & Best Practices Guide")
print("=" * 80)

print("\nWhat's in this cell:")
print("  • Comprehensive summary of everything we learned")
print("  • All key concepts explained in one place")
print("  • Hyperparameter guide with practical advice")
print("  • Evaluation metrics reference")
print("  • Trading-specific tips and recommendations")
print("  • Next steps for advancing your skills")
print("\n📚 This is your reference guide!")
print("Come back to this cell whenever you need a quick refresher.")
print("\n" + "=" * 80)
print("LOGISTIC REGRESSION - COMPLETE SUMMARY")
print("=" * 80)

print("\n" + "=" * 80)
print("KEY LEARNINGS")
print("=" * 80)
print("1. Logistic Regression is a LINEAR classifier for binary problems")
print("2. It outputs probabilities using the sigmoid function: σ(z) = 1/(1+e^(-z))")
print("3. Despite name, it's for CLASSIFICATION, not regression")
print("4. Best for linearly separable data or as a baseline model")
print("5. Feature scaling (StandardScaler) is CRITICAL for logistic regression")
print("6. Coefficients show feature importance (interpretable model)")

print("\n" + "=" * 80)
print("HYPERPARAMETERS EXPLAINED")
print("=" * 80)

print("\n📌 C (Regularization Strength):")
print("  • Inverse of regularization (higher C = less regularization)")
print("  • Smaller C → Stronger regularization → Simpler model → Less overfitting")
print("  • Larger C → Weaker regularization → Complex model → May overfit")
print("  • Default: C=1.0")
print("  • Typical range: [0.001, 0.01, 0.1, 1, 10, 100]")
print("  • Use GridSearchCV to find optimal value")

print("\n📌 penalty (Regularization Type):")
print("  • 'l2' (Ridge/Default): Shrinks all coefficients, keeps all features")
print("  • 'l1' (Lasso): Can shrink coefficients to exactly zero (feature selection)")
print("  • 'elasticnet': Combination of l1 and l2")
print("  • 'none': No regularization (can overfit)")

print("\n📌 solver (Optimization Algorithm):")
print("  • 'lbfgs' (default): Fast, large datasets, only supports l2")
print("  • 'liblinear': Small datasets, supports l1 and l2")
print("  • 'saga': All penalties, large datasets, slow but versatile")
print("  • 'newton-cg': l2 only, fast for large datasets")
print("  • 'sag': l2 only, fast for large datasets")

print("\n📌 max_iter:")
print("  • Maximum iterations for convergence")
print("  • Default: 100 (often too low)")
print("  • Recommended: 1000+ for complex datasets")

print("\n📌 class_weight:")
print("  • 'balanced': Auto-adjust for imbalanced classes")
print("  • None: All classes equal weight (default)")
print("  • dict: Custom weights {0: 1.0, 1: 2.0}")

print("\n" + "=" * 80)
print("EVALUATION METRICS")
print("=" * 80)
print("\n• Accuracy:")
print("  What: Overall correctness (correct predictions / total predictions)")
print("  When: Balanced datasets only")
print("  Warning: Misleading for imbalanced data!")

print("\n• Precision:")
print("  What: Of predicted positives, how many are actually positive?")
print("  Formula: TP / (TP + FP)")
print("  When: Cost of false positives is high")

print("\n• Recall (Sensitivity/TPR):")
print("  What: Of actual positives, how many did we find?")
print("  Formula: TP / (TP + FN)")
print("  When: Cost of false negatives is high")

print("\n• F1 Score:")
print("  What: Harmonic mean of precision and recall")
print("  Formula: 2 × (Precision × Recall) / (Precision + Recall)")
print("  When: Balance between precision and recall")

print("\n• ROC-AUC:")
print("  What: Area under ROC curve (threshold-independent)")
print("  Range: 0.5 (random) to 1.0 (perfect)")
print("  When: Need overall discrimination ability")

print("\n" + "=" * 80)
print("WHEN TO USE LOGISTIC REGRESSION")
print("=" * 80)
print("✓ Binary classification problems (yes/no, win/loss)")
print("✓ Need probability estimates (not just class labels)")
print("✓ Want interpretable model (understand feature importance)")
print("✓ As a baseline before trying complex models")
print("✓ When features have linear relationship with log-odds")
print("✓ When you have limited data (simpler models generalize better)")
print("✓ When training/prediction speed matters")

print("\n" + "=" * 80)
print("WHEN NOT TO USE")
print("=" * 80)
print("✗ Highly non-linear decision boundaries")
print("✗ Need to capture complex feature interactions")
print("✗ Very high-dimensional data with complex patterns")
print("✗ Multi-class classification (use MultiLogistic or other methods)")
print("\n→ Consider instead:")
print("  • Tree-based: Random Forest, XGBoost, LightGBM")
print("  • Neural Networks: For complex patterns")
print("  • SVM: For non-linear boundaries with kernel trick")

print("\n" + "=" * 80)
print("TIPS FOR TRADING DATA")
print("=" * 80)
print("\n1️⃣  Train/Test Split:")
print("  ✓ ALWAYS use time-based split (not random)")
print("  ✗ Never use future data to predict past (look-ahead bias)")
print("  Example: 80% oldest data for train, 20% newest for test")

print("\n2️⃣  Feature Scaling:")
print("  ✓ Use StandardScaler (mean=0, std=1)")
print("  ✓ Or RobustScaler (resistant to outliers)")
print("  ✗ Never skip scaling for Logistic Regression!")

print("\n3️⃣  Missing Values:")
print("  ✓ Forward fill (use previous value)")
print("  ✓ Then backward fill for remaining NaNs")
print("  ✗ Avoid dropping rows (loses temporal information)")

print("\n4️⃣  Feature Engineering:")
print("  ✓ Use technical indicators (RSI, MACD, BB, etc.)")
print("  ✓ Only use features available at trade entry time")
print("  ✗ Never use outcome variables as features (profit, duration)")

print("\n5️⃣  Overfitting Prevention:")
print("  ✓ Monitor train vs test performance")
print("  ✓ Use cross-validation (time-series aware)")
print("  ✓ Apply regularization (tune C parameter)")
print("  ✗ If train >> test, you're overfitting")

print("\n6️⃣  Class Imbalance:")
print("  ✓ Check profitable vs loss ratio")
print("  ✓ Use class_weight='balanced' if skewed")
print("  ✓ Focus on F1/ROC-AUC (not just accuracy)")

print("\n7️⃣  Interpretability:")
print("  ✓ Analyze coefficients (which indicators matter?)")
print("  ✓ Positive coeff = higher value → more likely profitable")
print("  ✓ Negative coeff = higher value → less likely profitable")

print("\n" + "=" * 80)
print("NEXT STEPS & ADVANCED TOPICS")
print("=" * 80)
print("\n• Feature Selection:")
print("  → Try L1 regularization (penalty='l1') for automatic selection")
print("  → Remove low-importance features to simplify model")

print("\n• Handle Non-linearity:")
print("  → Create polynomial features (x², x³, x₁×x₂)")
print("  → Try feature interactions (RSI × MACD)")

print("\n• Model Comparison:")
print("  → Compare with Random Forest, XGBoost, LightGBM")
print("  → Ensemble methods often outperform single models")

print("\n• Production Deployment:")
print("  → Integrate with backtesting framework")
print("  → Save best model (pickle/joblib)")
print("  → Monitor performance on live/paper trading")
print("  → Retrain periodically with new data")

print("\n• Advanced Techniques:")
print("  → Calibrate probabilities (CalibratedClassifierCV)")
print("  → Try different thresholds (optimize for your metric)")
print("  → Use SMOTE for severe class imbalance")
print("  → Walk-forward validation for time-series")

print("\n" + "=" * 80)
print("📚 RECOMMENDED LEARNING RESOURCES")
print("=" * 80)
print("• scikit-learn documentation: sklearn LogisticRegression")
print("• Understanding the math: Watch 3Blue1Brown's linear algebra series")
print("• ROC curves explained: StatQuest with Josh Starmer (YouTube)")
print("• Trading ML: 'Advances in Financial Machine Learning' by Marcos Lopez de Prado")

print("\n" + "=" * 80)
print("✅ LOGISTIC REGRESSION LEARNING COMPLETE!")
print("=" * 80)
print("\nYou now understand:")
print("  ✓ What logistic regression is and how it works")
print("  ✓ When to use it and when to avoid it")
print("  ✓ How to tune hyperparameters")
print("  ✓ How to evaluate model performance")
print("  ✓ How to apply it to trading data")
print("  ✓ How to interpret results and coefficients")
print("\nHappy learning and trading! 🚀")
print("=" * 80)
