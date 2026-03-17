# %% [CELL 1: Course Overview]
"""
================================================================================
XGBOOST - Complete Educational Guide
================================================================================

COURSE OUTLINE:
───────────────────────────────────────────────────────────────────────────────
PART 1: FOUNDATIONS
  Cell 1-2:   Setup & Introduction
  Cell 3-4:   Gradient Boosting - The Core Concept
  Cell 5-6:   What Makes XGBoost Special

PART 2: TRAINING & PREDICTION
  Cell 7-8:   Your First XGBoost Model
  Cell 9-10:  Feature Importance Methods

PART 3: HYPERPARAMETERS
  Cell 11-12: learning_rate (eta) - Step Size
  Cell 13-14: n_estimators & Early Stopping
  Cell 15-16: max_depth & Tree Structure
  Cell 17-18: subsample & colsample_bytree
  Cell 19-20: Regularization (alpha, lambda, gamma)
  Cell 21-22: GridSearchCV - Optimal Parameters

PART 4: ADVANCED FEATURES
  Cell 23-24: Built-in Cross-Validation
  Cell 25-26: Learning Curves & Diagnostics

PART 5: REAL-WORLD APPLICATION
  Cell 27-28: Trading Data Pipeline
  Cell 29-30: Model Interpretation

PART 6: PRODUCTION
  Cell 31-32: Common Mistakes to Avoid
  Cell 33-34: Save/Load Models
  Cell 35:    Summary & Next Steps
================================================================================
"""

print("=" * 70)
print("🚀 XGBOOST - Complete Educational Guide")
print("=" * 70)
print("""
What you'll learn:
  ✓ How XGBoost works (gradient boosting on steroids)
  ✓ Why it wins so many Kaggle competitions
  ✓ All important hyperparameters and tuning strategies
  ✓ Early stopping to prevent overfitting
  ✓ Regularization techniques unique to XGBoost
  ✓ Real-world trading application

Prerequisites:
  • Basic Python & NumPy
  • Understanding of decision trees
  • Familiarity with Random Forest helps
""")
print("=" * 70)

# %% [CELL 2: Import Libraries]
print("\n" + "=" * 70)
print("📦 CELL 2: Import Libraries")
print("=" * 70)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import xgboost as xgb
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, learning_curve
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
from sklearn.datasets import make_classification, make_moons
import joblib
import warnings
warnings.filterwarnings('ignore')

# Nice plot style
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['figure.figsize'] = [12, 6]
plt.rcParams['font.size'] = 11

print(f"✓ XGBoost version: {xgb.__version__}")
print("✓ All libraries loaded!")

# %% [CELL 3: What is XGBoost?]
print("\n" + "=" * 70)
print("📖 CELL 3: What is XGBoost?")
print("=" * 70)

print("""
┌─────────────────────────────────────────────────────────────────────┐
│  XGBOOST IN ONE SENTENCE:                                           │
│  Extreme Gradient Boosting - An optimized gradient boosting library │
│  designed for speed and performance                                 │
└─────────────────────────────────────────────────────────────────────┘

XGBoost = eXtreme Gradient Boosting

What makes it special?
  • SPEED: Parallelized tree construction
  • PERFORMANCE: Regularization to prevent overfitting
  • FLEXIBILITY: Handles missing values automatically
  • SCALABILITY: Works with huge datasets

Why is it so popular?
  • Won numerous Kaggle competitions
  • State-of-the-art for tabular data
  • Industry standard for many applications
  • Great balance of accuracy and speed

Random Forest vs XGBoost:
─────────────────────────────────────────────────────────────────────
  Random Forest:           XGBoost:
  • Trees built PARALLEL   • Trees built SEQUENTIALLY
  • Each tree independent  • Each tree corrects previous errors
  • Bagging (averaging)    • Boosting (learning from mistakes)
  • More robust to noise   • Often more accurate
  • Harder to overfit      • Need regularization
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 4: Gradient Boosting - The Core Concept]
print("\n" + "=" * 70)
print("🎯 CELL 4: Gradient Boosting - The Core Concept")
print("=" * 70)

print("""
GRADIENT BOOSTING INTUITION:
─────────────────────────────────────────────────────────────────────
Imagine you're learning to throw darts:

Round 1: Throw dart → Miss by 10cm right
Round 2: Adjust by 10cm left → Miss by 3cm left  
Round 3: Adjust by 3cm right → Miss by 1cm right
Round 4: Adjust by 1cm left → BULLSEYE!

This is exactly how gradient boosting works!
─────────────────────────────────────────────────────────────────────

THE ALGORITHM:
─────────────────────────────────────────────────────────────────────
1. Start with a simple prediction (e.g., average)
2. Calculate RESIDUALS (errors) = actual - predicted
3. Train a tree to predict the RESIDUALS
4. Add tree's predictions to current predictions (scaled by learning rate)
5. Repeat steps 2-4 for n_estimators rounds
6. Final prediction = sum of all tree predictions

Key Insight: Each tree focuses on MISTAKES of previous trees!
─────────────────────────────────────────────────────────────────────
""")

# Visual demonstration of boosting
np.random.seed(42)
X_demo = np.linspace(0, 10, 100).reshape(-1, 1)
y_true = np.sin(X_demo.ravel()) + np.random.normal(0, 0.2, 100)

fig, axes = plt.subplots(2, 3, figsize=(16, 10))

# Show iterative improvement
from sklearn.tree import DecisionTreeRegressor

predictions = np.zeros(100)
residuals = y_true.copy()

for i, ax in enumerate(axes.flatten()):
    if i == 0:
        # Initial state
        ax.scatter(X_demo, y_true, c='blue', alpha=0.5, s=20, label='True values')
        ax.axhline(y=0, color='red', linestyle='--', label='Initial prediction (0)')
        ax.set_title('Round 0: Start with zero prediction', fontweight='bold')
        ax.legend()
    else:
        # Fit tree to residuals
        tree = DecisionTreeRegressor(max_depth=2)
        tree.fit(X_demo, residuals)
        tree_pred = tree.predict(X_demo) * 0.3  # learning rate
        predictions += tree_pred
        residuals = y_true - predictions
        
        ax.scatter(X_demo, y_true, c='blue', alpha=0.3, s=20, label='True')
        ax.plot(X_demo, predictions, 'r-', linewidth=2, label='Cumulative prediction')
        ax.set_title(f'Round {i}: MSE = {np.mean(residuals**2):.4f}', fontweight='bold')
        ax.legend()
    
    ax.set_xlabel('X')
    ax.set_ylabel('y')
    ax.grid(True, alpha=0.3)

plt.suptitle('Gradient Boosting: Each Round Reduces Error', fontsize=14, fontweight='bold', y=1.02)
plt.tight_layout()
plt.show()

print("""
KEY INSIGHT: Boosting is SEQUENTIAL - each tree depends on previous trees!
─────────────────────────────────────────────────────────────────────
This is why:
  • Training cannot be fully parallelized (unlike Random Forest)
  • Order of trees matters
  • Early stopping is crucial
  • Learning rate controls how much each tree contributes
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 5: What Makes XGBoost Special]
print("\n" + "=" * 70)
print("⚡ CELL 5: What Makes XGBoost Special")
print("=" * 70)

print("""
XGBOOST INNOVATIONS:
─────────────────────────────────────────────────────────────────────

1. REGULARIZATION (L1 + L2):
   ┌─────────────────────────────────────────────────────────────────┐
   │  Standard Gradient Boosting: Only optimizes loss               │
   │  XGBoost: Optimizes loss + regularization terms                │
   │                                                                 │
   │  Objective = Loss + λ × (sum of weights²) + α × (sum of |weights|)
   │                                                                 │
   │  This prevents overfitting! (Like Ridge + Lasso combined)      │
   └─────────────────────────────────────────────────────────────────┘

2. SECOND-ORDER GRADIENTS:
   • Uses both first derivative (gradient) AND second derivative (Hessian)
   • More information → Better split decisions → Faster convergence

3. SPARSITY AWARENESS:
   • Handles missing values automatically
   • Learns optimal direction for missing values at each split
   • No need to impute before training!

4. PARALLEL PROCESSING:
   • Tree building uses parallel computation for split finding
   • Column subsampling can be parallelized
   • Much faster than traditional boosting

5. TREE PRUNING:
   • Uses 'max_depth' and then prunes backward
   • 'gamma' parameter: minimum loss reduction to make a split
   • More robust than stopping early

6. BUILT-IN CROSS-VALIDATION:
   • xgb.cv() for easy hyperparameter tuning
   • Early stopping with cross-validation

─────────────────────────────────────────────────────────────────────
""")

# Visual comparison
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: XGBoost features
ax1 = axes[0]
features = ['Regularization\n(L1 + L2)', 'Second-order\nGradients', 'Missing Value\nHandling', 
            'Parallel\nProcessing', 'Tree\nPruning', 'Built-in\nCV']
has_feature_xgb = [1, 1, 1, 1, 1, 1]
has_feature_std = [0, 0, 0, 0, 0.5, 0]

x = np.arange(len(features))
width = 0.35

bars1 = ax1.bar(x - width/2, has_feature_xgb, width, label='XGBoost', color='#2ecc71', alpha=0.8)
bars2 = ax1.bar(x + width/2, has_feature_std, width, label='Standard GB', color='#e74c3c', alpha=0.8)

ax1.set_xticks(x)
ax1.set_xticklabels(features, fontsize=9)
ax1.set_ylabel('Has Feature', fontsize=12)
ax1.set_title('XGBoost vs Standard Gradient Boosting', fontsize=14, fontweight='bold')
ax1.legend()
ax1.set_ylim([0, 1.3])
ax1.grid(True, alpha=0.3, axis='y')

# Plot 2: Typical Kaggle leaderboard
ax2 = axes[1]
models = ['Linear\nRegression', 'Random\nForest', 'Standard\nGB', 'XGBoost', 'Ensemble']
scores = [0.72, 0.85, 0.87, 0.91, 0.92]
colors = ['#3498db', '#9b59b6', '#e67e22', '#2ecc71', '#1abc9c']

bars = ax2.barh(models, scores, color=colors, alpha=0.8, edgecolor='black')
ax2.set_xlabel('Typical Competition Score', fontsize=12)
ax2.set_title('Why XGBoost Dominates Competitions', fontsize=14, fontweight='bold')
ax2.set_xlim([0.6, 1.0])

for bar, score in zip(bars, scores):
    ax2.text(score + 0.01, bar.get_y() + bar.get_height()/2, f'{score:.2f}', va='center', fontweight='bold')

ax2.grid(True, alpha=0.3, axis='x')

plt.tight_layout()
plt.show()

# %% [CELL 6: XGBoost API Options]
print("\n" + "=" * 70)
print("🔧 CELL 6: XGBoost API Options")
print("=" * 70)

print("""
XGBOOST HAS TWO APIs:
─────────────────────────────────────────────────────────────────────

1. NATIVE API (xgb.train, xgb.DMatrix):
   ┌─────────────────────────────────────────────────────────────────┐
   │  dtrain = xgb.DMatrix(X_train, label=y_train)                  │
   │  params = {'max_depth': 3, 'eta': 0.1, 'objective': 'binary:logistic'}
   │  model = xgb.train(params, dtrain, num_boost_round=100)        │
   └─────────────────────────────────────────────────────────────────┘
   ✓ More control
   ✓ Early stopping with eval set
   ✓ Built-in CV (xgb.cv)
   ✗ Different API from sklearn

2. SCIKIT-LEARN API (XGBClassifier, XGBRegressor):
   ┌─────────────────────────────────────────────────────────────────┐
   │  model = XGBClassifier(max_depth=3, learning_rate=0.1)         │
   │  model.fit(X_train, y_train)                                   │
   │  predictions = model.predict(X_test)                           │
   └─────────────────────────────────────────────────────────────────┘
   ✓ Familiar sklearn interface
   ✓ Works with GridSearchCV, Pipeline
   ✓ Easy to swap with other models
   ✗ Slightly less control

We'll use SKLEARN API for consistency with other tutorials!
─────────────────────────────────────────────────────────────────────

PARAMETER NAME MAPPING:
─────────────────────────────────────────────────────────────────────
  Native API          Sklearn API
  ──────────────────────────────────
  eta                 learning_rate
  num_boost_round     n_estimators
  lambda              reg_lambda
  alpha               reg_alpha
  subsample           subsample
  colsample_bytree    colsample_bytree
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 7: Create Dataset for Experiments]
print("\n" + "=" * 70)
print("🔬 CELL 7: Create Dataset for Experiments")
print("=" * 70)

# Create a realistic dataset
np.random.seed(42)
n_samples = 2000
n_features = 15

X, y = make_classification(
    n_samples=n_samples,
    n_features=n_features,
    n_informative=8,
    n_redundant=3,
    n_clusters_per_class=3,
    flip_y=0.1,
    random_state=42
)

feature_names = [f'Feature_{i}' for i in range(n_features)]

print(f"Dataset created:")
print(f"  Total samples: {n_samples}")
print(f"  Features: {n_features}")
print(f"  Informative: 8")
print(f"  Redundant: 3")
print(f"  Class 0: {(y == 0).sum()} ({(y == 0).sum()/len(y)*100:.1f}%)")
print(f"  Class 1: {(y == 1).sum()} ({(y == 1).sum()/len(y)*100:.1f}%)")

# Split - stratified
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

# Further split train into train + validation for early stopping
X_train_final, X_val, y_train_final, y_val = train_test_split(
    X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
)

print(f"\nData splits:")
print(f"  Train: {len(X_train_final)} samples")
print(f"  Validation: {len(X_val)} samples (for early stopping)")
print(f"  Test: {len(X_test)} samples")

# %% [CELL 8: Train Your First XGBoost Model]
print("\n" + "=" * 70)
print("🚀 CELL 8: Train Your First XGBoost Model")
print("=" * 70)

print("""
STEP-BY-STEP:
─────────────────────────────────────────────────────────────────────
Step 1: Create XGBClassifier with basic parameters
Step 2: Fit with early stopping using validation set
Step 3: Make predictions
Step 4: Evaluate performance
─────────────────────────────────────────────────────────────────────
""")

# Step 1: Create model
print("STEP 1: Create Model")
print("-" * 50)

xgb_model = XGBClassifier(
    n_estimators=1000,          # Max trees (will use early stopping)
    max_depth=5,                # Tree depth
    learning_rate=0.1,          # Step size
    subsample=0.8,              # Row sampling
    colsample_bytree=0.8,       # Column sampling
    random_state=42,
    n_jobs=-1,
    eval_metric='logloss'       # For binary classification
)

print("Model parameters:")
print(f"  n_estimators: {xgb_model.n_estimators}")
print(f"  max_depth: {xgb_model.max_depth}")
print(f"  learning_rate: {xgb_model.learning_rate}")
print(f"  subsample: {xgb_model.subsample}")
print(f"  colsample_bytree: {xgb_model.colsample_bytree}")

# Step 2: Fit with early stopping
print("\nSTEP 2: Train with Early Stopping")
print("-" * 50)

xgb_model.fit(
    X_train_final, y_train_final,
    eval_set=[(X_val, y_val)],
    verbose=False
)

print(f"✓ Model trained!")
print(f"  Best iteration: {xgb_model.best_iteration}")
print(f"  Trees used: {xgb_model.best_iteration} (out of {xgb_model.n_estimators} max)")

# Step 3: Predict
print("\nSTEP 3: Make Predictions")
print("-" * 50)
y_pred = xgb_model.predict(X_test)
y_proba = xgb_model.predict_proba(X_test)[:, 1]

print("  Sample predictions (first 10):")
print(f"  Actual:      {y_test[:10]}")
print(f"  Predicted:   {y_pred[:10]}")
print(f"  Probability: {np.round(y_proba[:10], 3)}")

# Step 4: Evaluate
print("\nSTEP 4: Evaluate Performance")
print("-" * 50)
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_proba)

print(f"  Accuracy:  {acc:.4f}")
print(f"  Precision: {prec:.4f}")
print(f"  Recall:    {rec:.4f}")
print(f"  F1 Score:  {f1:.4f}")
print(f"  ROC-AUC:   {auc:.4f}")

# Confusion matrix
print("\n" + "-" * 50)
print("CONFUSION MATRIX:")
cm = confusion_matrix(y_test, y_pred)
print(f"\n              Predicted")
print(f"            Loss (0)  Win (1)")
print(f"Actual 0     {cm[0][0]:5d}    {cm[0][1]:5d}")
print(f"Actual 1     {cm[1][0]:5d}    {cm[1][1]:5d}")

# %% [CELL 9: Feature Importance - Three Methods]
print("\n" + "=" * 70)
print("📊 CELL 9: Feature Importance - Three Methods")
print("=" * 70)

print("""
XGBOOST FEATURE IMPORTANCE METHODS:
─────────────────────────────────────────────────────────────────────
1. WEIGHT: Number of times feature is used in splits
   → Simple but can be misleading

2. GAIN: Average improvement in loss when using this feature
   → Better measure of predictive power

3. COVER: Average number of samples affected when using this feature
   → Measures feature's reach

RECOMMENDATION: Use GAIN for feature selection, but verify with
                permutation importance for final decisions
─────────────────────────────────────────────────────────────────────
""")

# Get all three importance types
importance_weight = xgb_model.get_booster().get_score(importance_type='weight')
importance_gain = xgb_model.get_booster().get_score(importance_type='gain')
importance_cover = xgb_model.get_booster().get_score(importance_type='cover')

# Create DataFrames
def importance_to_df(imp_dict, feature_names):
    df = pd.DataFrame({
        'Feature': [f'Feature_{i}' for i in range(len(feature_names))],
        'Importance': [imp_dict.get(f'f{i}', 0) for i in range(len(feature_names))]
    })
    # Normalize
    if df['Importance'].sum() > 0:
        df['Importance'] = df['Importance'] / df['Importance'].sum()
    return df.sort_values('Importance', ascending=False)

weight_df = importance_to_df(importance_weight, feature_names)
gain_df = importance_to_df(importance_gain, feature_names)
cover_df = importance_to_df(importance_cover, feature_names)

# Visualization
fig, axes = plt.subplots(1, 3, figsize=(16, 5))

for ax, df, title, color in zip(axes, 
                                 [weight_df, gain_df, cover_df],
                                 ['Weight\n(# of splits)', 'Gain\n(avg loss reduction)', 'Cover\n(avg samples)'],
                                 ['steelblue', 'coral', 'seagreen']):
    top10 = df.head(10)
    ax.barh(range(len(top10)), top10['Importance'], color=color, alpha=0.8, edgecolor='black')
    ax.set_yticks(range(len(top10)))
    ax.set_yticklabels(top10['Feature'])
    ax.invert_yaxis()
    ax.set_xlabel('Normalized Importance')
    ax.set_title(f'Importance by {title}', fontsize=12, fontweight='bold')
    ax.grid(True, alpha=0.3, axis='x')

plt.tight_layout()
plt.show()

print("\nTop 5 Features by GAIN (recommended):")
print("-" * 40)
for i, row in gain_df.head(5).iterrows():
    bar = '█' * int(row['Importance'] * 30)
    print(f"  {row['Feature']:<15} {row['Importance']:.4f} {bar}")

# %% [CELL 10: Built-in Plotting]
print("\n" + "=" * 70)
print("📈 CELL 10: XGBoost Built-in Plotting")
print("=" * 70)

print("""
XGBoost has built-in plotting functions:
─────────────────────────────────────────────────────────────────────
• xgb.plot_importance(): Feature importance bar chart
• xgb.plot_tree(): Visualize individual trees
• Training history from evals_result_
─────────────────────────────────────────────────────────────────────
""")

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Built-in importance plot
ax1 = axes[0]
xgb.plot_importance(xgb_model, ax=ax1, importance_type='gain', max_num_features=10,
                   title='XGBoost Built-in Importance Plot', show_values=True)
ax1.set_xlabel('Gain')

# Plot 2: Training history (if available)
ax2 = axes[1]
# Retrain to get evals_result
xgb_model2 = XGBClassifier(
    n_estimators=200, max_depth=5, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8, random_state=42,
    eval_metric='logloss', n_jobs=-1
)
xgb_model2.fit(
    X_train_final, y_train_final,
    eval_set=[(X_train_final, y_train_final), (X_val, y_val)],
    verbose=False
)

results = xgb_model2.evals_result()
epochs = len(results['validation_0']['logloss'])
ax2.plot(range(epochs), results['validation_0']['logloss'], 'b-', label='Train')
ax2.plot(range(epochs), results['validation_1']['logloss'], 'r-', label='Validation')
ax2.set_xlabel('Boosting Round')
ax2.set_ylabel('Log Loss')
ax2.set_title('Training History', fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# %% [CELL 11: learning_rate (eta) - The Most Important Parameter]
print("\n" + "=" * 70)
print("🎚️ CELL 11: learning_rate - The Most Important Parameter")
print("=" * 70)

print("""
learning_rate (also called 'eta'):
─────────────────────────────────────────────────────────────────────
• Controls how much each tree contributes to the final prediction
• Range: 0 to 1 (typically 0.01 to 0.3)
• Default: 0.3 (sklearn) or 0.1 (common practice)

The Trade-off:
  • HIGH learning_rate (0.3):
    → Fewer trees needed
    → Faster training
    → Risk of overfitting, less precise
    
  • LOW learning_rate (0.01):
    → More trees needed (slower training)
    → Better generalization
    → More precise but diminishing returns

RULE OF THUMB:
  → Start with 0.1, adjust n_estimators accordingly
  → For final model: lower rate + more trees often wins
─────────────────────────────────────────────────────────────────────
""")

# Test different learning rates
lr_values = [0.01, 0.05, 0.1, 0.2, 0.3, 0.5]
results_lr = []

print("Testing different learning rates...")
print("-" * 60)

for lr in lr_values:
    xgb_lr = XGBClassifier(
        n_estimators=500, max_depth=5, learning_rate=lr,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        eval_metric='logloss', n_jobs=-1
    )
    xgb_lr.fit(X_train_final, y_train_final,
              eval_set=[(X_val, y_val)], verbose=False)
    
    train_f1 = f1_score(y_train_final, xgb_lr.predict(X_train_final))
    test_f1 = f1_score(y_test, xgb_lr.predict(X_test))
    best_iter = xgb_lr.best_iteration
    
    results_lr.append({
        'learning_rate': lr,
        'train_f1': train_f1,
        'test_f1': test_f1,
        'best_iteration': best_iter
    })
    print(f"  lr={lr:.2f}: Train F1={train_f1:.4f}, Test F1={test_f1:.4f}, Trees={best_iter}")

results_lr_df = pd.DataFrame(results_lr)

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: F1 vs learning rate
ax1 = axes[0]
ax1.plot(results_lr_df['learning_rate'], results_lr_df['train_f1'], 'b-o', 
        linewidth=2, markersize=10, label='Train F1')
ax1.plot(results_lr_df['learning_rate'], results_lr_df['test_f1'], 'r-s', 
        linewidth=2, markersize=10, label='Test F1')
ax1.fill_between(results_lr_df['learning_rate'], 
                results_lr_df['train_f1'], results_lr_df['test_f1'], 
                alpha=0.2, color='gray')
ax1.set_xlabel('learning_rate', fontsize=12)
ax1.set_ylabel('F1 Score', fontsize=12)
ax1.set_title('Performance vs Learning Rate\n(Gap = Overfitting)', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

# Plot 2: Trees needed vs learning rate
ax2 = axes[1]
ax2.bar(range(len(results_lr_df)), results_lr_df['best_iteration'], 
       color='steelblue', alpha=0.8, edgecolor='black')
ax2.set_xticks(range(len(results_lr_df)))
ax2.set_xticklabels([f'{lr:.2f}' for lr in results_lr_df['learning_rate']])
ax2.set_xlabel('learning_rate', fontsize=12)
ax2.set_ylabel('Trees Needed (Early Stopping)', fontsize=12)
ax2.set_title('Lower Learning Rate = More Trees Needed', fontsize=14, fontweight='bold')
ax2.grid(True, alpha=0.3, axis='y')

for i, v in enumerate(results_lr_df['best_iteration']):
    ax2.text(i, v + 5, str(v), ha='center', fontweight='bold')

plt.tight_layout()
plt.show()

# %% [CELL 12: n_estimators and Early Stopping]
print("\n" + "=" * 70)
print("⏱️ CELL 12: n_estimators and Early Stopping")
print("=" * 70)

print("""
EARLY STOPPING - One of XGBoost's Best Features:
─────────────────────────────────────────────────────────────────────
The Problem:
  • Too few trees → Underfitting
  • Too many trees → Overfitting + Wasted computation
  
The Solution: EARLY STOPPING
  • Set n_estimators to a LARGE number
  • Use validation set to monitor performance
  • Stop when performance stops improving

Parameters:
  • early_stopping_rounds: Stop after N rounds with no improvement
  • eval_set: Validation data for monitoring
  • eval_metric: Metric to monitor ('logloss', 'auc', 'error')
─────────────────────────────────────────────────────────────────────
""")

print("Training with early stopping monitoring...")

xgb_es = XGBClassifier(
    n_estimators=1000,
    max_depth=5,
    learning_rate=0.05,
    random_state=42,
    eval_metric='logloss',
    early_stopping_rounds=50,
    n_jobs=-1
)

xgb_es.fit(
    X_train_final, y_train_final,
    eval_set=[(X_train_final, y_train_final), (X_val, y_val)],
    verbose=False
)

print(f"\n✓ Training stopped at iteration: {xgb_es.best_iteration}")
print(f"  Max iterations allowed: 1000")
print(f"  Computation saved: {1000 - xgb_es.best_iteration} trees ({(1000 - xgb_es.best_iteration)/10:.0f}%)")

# Plot learning curves
results_es = xgb_es.evals_result()
epochs_es = len(results_es['validation_0']['logloss'])

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

ax1 = axes[0]
ax1.plot(range(epochs_es), results_es['validation_0']['logloss'], 'b-', label='Train', alpha=0.7)
ax1.plot(range(epochs_es), results_es['validation_1']['logloss'], 'r-', label='Validation', alpha=0.7)
ax1.axvline(x=xgb_es.best_iteration, color='green', linestyle='--', linewidth=2, 
           label=f'Best iteration ({xgb_es.best_iteration})')
ax1.set_xlabel('Boosting Round', fontsize=12)
ax1.set_ylabel('Log Loss', fontsize=12)
ax1.set_title('Early Stopping in Action', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

ax2 = axes[1]
train_loss = np.array(results_es['validation_0']['logloss'])
val_loss = np.array(results_es['validation_1']['logloss'])
gap = val_loss - train_loss

ax2.fill_between(range(epochs_es), 0, gap, where=gap > 0, color='red', alpha=0.3, label='Overfitting')
ax2.plot(range(epochs_es), gap, 'k-', linewidth=1)
ax2.axhline(y=0, color='green', linestyle='--')
ax2.axvline(x=xgb_es.best_iteration, color='green', linestyle='--', linewidth=2)
ax2.set_xlabel('Boosting Round', fontsize=12)
ax2.set_ylabel('Val Loss - Train Loss', fontsize=12)
ax2.set_title('Generalization Gap Over Time', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# %% [CELL 13: max_depth - Tree Complexity]
print("\n" + "=" * 70)
print("📏 CELL 13: max_depth - Tree Complexity")
print("=" * 70)

print("""
max_depth = Maximum depth of each tree
─────────────────────────────────────────────────────────────────────
• XGBoost default: 6 (vs Random Forest often unlimited)
• Lower than RF because boosting trees should be "weak learners"
• Each tree corrects errors, doesn't need to be perfect

Trade-off:
  • Shallow trees (3-5): Less overfitting, may underfit
  • Deep trees (8-12): Can overfit, especially with high learning_rate
  
RECOMMENDATION: Start with 4-6, rarely need >10 for XGBoost
─────────────────────────────────────────────────────────────────────
""")

depth_values = [2, 3, 4, 5, 6, 8, 10, 15]
results_depth = []

print("Testing different max_depth values...")
for d in depth_values:
    xgb_d = XGBClassifier(
        n_estimators=500, max_depth=d, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        eval_metric='logloss', n_jobs=-1
    )
    xgb_d.fit(X_train_final, y_train_final, eval_set=[(X_val, y_val)], verbose=False)
    
    train_f1 = f1_score(y_train_final, xgb_d.predict(X_train_final))
    test_f1 = f1_score(y_test, xgb_d.predict(X_test))
    
    results_depth.append({
        'max_depth': d,
        'train_f1': train_f1,
        'test_f1': test_f1,
        'gap': train_f1 - test_f1
    })
    print(f"  depth={d:2d}: Train F1={train_f1:.4f}, Test F1={test_f1:.4f}, Gap={train_f1-test_f1:.4f}")

results_depth_df = pd.DataFrame(results_depth)

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

ax1 = axes[0]
ax1.plot(results_depth_df['max_depth'], results_depth_df['train_f1'], 'b-o', linewidth=2, markersize=8, label='Train')
ax1.plot(results_depth_df['max_depth'], results_depth_df['test_f1'], 'r-s', linewidth=2, markersize=8, label='Test')
ax1.fill_between(results_depth_df['max_depth'], results_depth_df['train_f1'], results_depth_df['test_f1'], alpha=0.2)
ax1.set_xlabel('max_depth', fontsize=12)
ax1.set_ylabel('F1 Score', fontsize=12)
ax1.set_title('Performance vs Tree Depth', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

ax2 = axes[1]
colors = ['green' if g < 0.03 else 'orange' if g < 0.06 else 'red' for g in results_depth_df['gap']]
ax2.bar(range(len(results_depth_df)), results_depth_df['gap'], color=colors, alpha=0.8, edgecolor='black')
ax2.set_xticks(range(len(results_depth_df)))
ax2.set_xticklabels(results_depth_df['max_depth'])
ax2.set_xlabel('max_depth', fontsize=12)
ax2.set_ylabel('Train-Test Gap (Overfitting)', fontsize=12)
ax2.set_title('Overfitting by Depth', fontsize=14, fontweight='bold')
ax2.axhline(y=0.03, color='orange', linestyle='--', label='Warning threshold')
ax2.legend()
ax2.grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.show()

# %% [CELL 14: subsample & colsample_bytree - Randomness]
print("\n" + "=" * 70)
print("🎲 CELL 14: subsample & colsample_bytree - Adding Randomness")
print("=" * 70)

print("""
SUBSAMPLING PARAMETERS:
─────────────────────────────────────────────────────────────────────
subsample: Fraction of ROWS used for each tree
  • Range: 0 to 1 (default: 1 = use all rows)
  • Lower values → More randomness → Less overfitting
  • Similar to Random Forest's bootstrap

colsample_bytree: Fraction of COLUMNS used for each tree
  • Range: 0 to 1 (default: 1 = use all columns)
  • Lower values → Forces diversity → Less overfitting
  
Also available:
  • colsample_bylevel: Column sampling at each tree level
  • colsample_bynode: Column sampling at each split

RECOMMENDATION: 0.7-0.9 for both is usually good
─────────────────────────────────────────────────────────────────────
""")

# Test combinations
subsample_vals = [0.5, 0.7, 0.8, 0.9, 1.0]
colsample_vals = [0.5, 0.7, 0.8, 0.9, 1.0]

results_sample = np.zeros((len(subsample_vals), len(colsample_vals)))

print("Testing subsample x colsample_bytree combinations...")
for i, ss in enumerate(subsample_vals):
    for j, cs in enumerate(colsample_vals):
        xgb_s = XGBClassifier(
            n_estimators=200, max_depth=5, learning_rate=0.1,
            subsample=ss, colsample_bytree=cs, random_state=42,
            eval_metric='logloss', n_jobs=-1
        )
        xgb_s.fit(X_train_final, y_train_final, eval_set=[(X_val, y_val)], verbose=False)
        results_sample[i, j] = f1_score(y_test, xgb_s.predict(X_test))

fig, ax = plt.subplots(figsize=(10, 8))
sns.heatmap(results_sample, annot=True, fmt='.3f', cmap='RdYlGn',
           xticklabels=colsample_vals, yticklabels=subsample_vals, ax=ax)
ax.set_xlabel('colsample_bytree', fontsize=12)
ax.set_ylabel('subsample', fontsize=12)
ax.set_title('Test F1 Score: subsample vs colsample_bytree\n(Higher is better)', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.show()

best_idx = np.unravel_index(results_sample.argmax(), results_sample.shape)
print(f"\nBest combination: subsample={subsample_vals[best_idx[0]]}, colsample_bytree={colsample_vals[best_idx[1]]}")
print(f"Best Test F1: {results_sample.max():.4f}")

# %% [CELL 15: Regularization - alpha, lambda, gamma]
print("\n" + "=" * 70)
print("🛡️ CELL 15: Regularization - XGBoost's Secret Weapon")
print("=" * 70)

print("""
XGBOOST REGULARIZATION PARAMETERS:
─────────────────────────────────────────────────────────────────────

1. reg_lambda (L2 regularization on weights):
   • Default: 1
   • Higher value → Stronger regularization → Smoother predictions
   • Similar to Ridge regression
   • Most commonly used

2. reg_alpha (L1 regularization on weights):
   • Default: 0
   • Higher value → More weights pushed to zero → Feature selection
   • Similar to Lasso regression
   • Use when you have many weak features

3. gamma (min_split_loss):
   • Default: 0
   • Minimum loss reduction to make a split
   • Higher value → Fewer splits → Simpler trees
   • Acts as another form of pruning

TYPICAL VALUES:
  • reg_lambda: 1-10 (try 1, 3, 5, 10)
  • reg_alpha: 0-1 (try 0, 0.1, 0.5, 1)
  • gamma: 0-5 (try 0, 0.1, 0.5, 1)
─────────────────────────────────────────────────────────────────────
""")

# Test regularization
print("Testing regularization parameters...")

# Test reg_lambda
lambda_vals = [0, 0.1, 1, 5, 10, 20]
results_lambda = []

for lam in lambda_vals:
    xgb_l = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        reg_lambda=lam, random_state=42, eval_metric='logloss', n_jobs=-1
    )
    xgb_l.fit(X_train_final, y_train_final, eval_set=[(X_val, y_val)], verbose=False)
    train_f1 = f1_score(y_train_final, xgb_l.predict(X_train_final))
    test_f1 = f1_score(y_test, xgb_l.predict(X_test))
    results_lambda.append({'lambda': lam, 'train_f1': train_f1, 'test_f1': test_f1})

# Test gamma
gamma_vals = [0, 0.1, 0.5, 1, 2, 5]
results_gamma = []

for g in gamma_vals:
    xgb_g = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        gamma=g, random_state=42, eval_metric='logloss', n_jobs=-1
    )
    xgb_g.fit(X_train_final, y_train_final, eval_set=[(X_val, y_val)], verbose=False)
    train_f1 = f1_score(y_train_final, xgb_g.predict(X_train_final))
    test_f1 = f1_score(y_test, xgb_g.predict(X_test))
    results_gamma.append({'gamma': g, 'train_f1': train_f1, 'test_f1': test_f1})

lambda_df = pd.DataFrame(results_lambda)
gamma_df = pd.DataFrame(results_gamma)

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

ax1 = axes[0]
ax1.plot(lambda_df['lambda'], lambda_df['train_f1'], 'b-o', linewidth=2, markersize=8, label='Train')
ax1.plot(lambda_df['lambda'], lambda_df['test_f1'], 'r-s', linewidth=2, markersize=8, label='Test')
ax1.set_xlabel('reg_lambda (L2)', fontsize=12)
ax1.set_ylabel('F1 Score', fontsize=12)
ax1.set_title('Effect of L2 Regularization', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

ax2 = axes[1]
ax2.plot(gamma_df['gamma'], gamma_df['train_f1'], 'b-o', linewidth=2, markersize=8, label='Train')
ax2.plot(gamma_df['gamma'], gamma_df['test_f1'], 'r-s', linewidth=2, markersize=8, label='Test')
ax2.set_xlabel('gamma (min_split_loss)', fontsize=12)
ax2.set_ylabel('F1 Score', fontsize=12)
ax2.set_title('Effect of Gamma', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# %% [CELL 16: GridSearchCV - Automated Tuning]
print("\n" + "=" * 70)
print("🔍 CELL 16: GridSearchCV - Find Optimal Parameters")
print("=" * 70)

print("""
RECOMMENDED TUNING ORDER:
─────────────────────────────────────────────────────────────────────
1. Fix learning_rate=0.1, n_estimators=high with early stopping
2. Tune max_depth and min_child_weight
3. Tune subsample and colsample_bytree  
4. Tune regularization (gamma, lambda, alpha)
5. Lower learning_rate, increase n_estimators for final model
─────────────────────────────────────────────────────────────────────
""")

# Focused grid search
param_grid = {
    'max_depth': [3, 5, 7],
    'min_child_weight': [1, 3, 5],
    'subsample': [0.7, 0.8, 0.9],
    'colsample_bytree': [0.7, 0.8, 0.9],
}

total_combos = 3 * 3 * 3 * 3
print(f"Parameter Grid: {total_combos} combinations")
print(f"With 3-fold CV: {total_combos * 3} fits")

print("\nRunning GridSearchCV...")
grid_search = GridSearchCV(
    XGBClassifier(
        n_estimators=200, learning_rate=0.1,
        random_state=42, eval_metric='logloss', n_jobs=1
    ),
    param_grid,
    cv=3,
    scoring='f1',
    n_jobs=-1,
    verbose=0
)
grid_search.fit(X_train, y_train)

print("\n✓ GridSearchCV Complete!")
print("\n" + "-" * 50)
print("BEST PARAMETERS:")
print("-" * 50)
for param, value in grid_search.best_params_.items():
    print(f"  {param}: {value}")
print(f"\nBest CV F1 Score: {grid_search.best_score_:.4f}")

# Evaluate best model
best_xgb = grid_search.best_estimator_
y_pred_best = best_xgb.predict(X_test)
y_proba_best = best_xgb.predict_proba(X_test)[:, 1]

print("\n" + "-" * 50)
print("BEST MODEL TEST PERFORMANCE:")
print("-" * 50)
print(f"  Accuracy:  {accuracy_score(y_test, y_pred_best):.4f}")
print(f"  Precision: {precision_score(y_test, y_pred_best):.4f}")
print(f"  Recall:    {recall_score(y_test, y_pred_best):.4f}")
print(f"  F1 Score:  {f1_score(y_test, y_pred_best):.4f}")
print(f"  ROC-AUC:   {roc_auc_score(y_test, y_proba_best):.4f}")

# Visualize
results_gs = pd.DataFrame(grid_search.cv_results_)

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

ax1 = axes[0]
top_10 = results_gs.nsmallest(10, 'rank_test_score')
ax1.barh(range(len(top_10)), top_10['mean_test_score'], xerr=top_10['std_test_score'],
        color='steelblue', alpha=0.8, edgecolor='black', capsize=3)
ax1.set_yticks(range(len(top_10)))
ax1.set_yticklabels([f"#{i+1}" for i in range(len(top_10))])
ax1.set_xlabel('CV F1 Score', fontsize=12)
ax1.set_title('Top 10 Parameter Combinations', fontsize=14, fontweight='bold')
ax1.grid(True, alpha=0.3, axis='x')

# Heatmap for max_depth vs subsample
ax2 = axes[1]
pivot = results_gs.pivot_table(
    values='mean_test_score',
    index='param_max_depth',
    columns='param_subsample',
    aggfunc='mean'
)
sns.heatmap(pivot, annot=True, fmt='.3f', cmap='RdYlGn', ax=ax2)
ax2.set_title('max_depth vs subsample (avg F1)', fontsize=14, fontweight='bold')

plt.tight_layout()
plt.show()

# %% [CELL 17: XGBoost Native CV]
print("\n" + "=" * 70)
print("📊 CELL 17: XGBoost Native Cross-Validation")
print("=" * 70)

print("""
xgb.cv() - Built-in Cross-Validation:
─────────────────────────────────────────────────────────────────────
• Integrated with early stopping
• Efficient - doesn't rebuild model from scratch
• Returns detailed iteration-by-iteration metrics
• Great for finding optimal n_estimators
─────────────────────────────────────────────────────────────────────
""")

# Prepare DMatrix for native API
dtrain = xgb.DMatrix(X_train, label=y_train)

params = {
    'max_depth': 5,
    'eta': 0.1,
    'objective': 'binary:logistic',
    'eval_metric': 'logloss',
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'seed': 42
}

print("Running xgb.cv()...")
cv_results = xgb.cv(
    params,
    dtrain,
    num_boost_round=500,
    nfold=5,
    early_stopping_rounds=50,
    verbose_eval=False,
    as_pandas=True
)

print(f"\n✓ CV Complete!")
print(f"  Best iteration: {len(cv_results)}")
print(f"  Train logloss: {cv_results['train-logloss-mean'].iloc[-1]:.4f} ± {cv_results['train-logloss-std'].iloc[-1]:.4f}")
print(f"  Test logloss:  {cv_results['test-logloss-mean'].iloc[-1]:.4f} ± {cv_results['test-logloss-std'].iloc[-1]:.4f}")

fig, ax = plt.subplots(figsize=(12, 5))
ax.plot(cv_results.index, cv_results['train-logloss-mean'], 'b-', label='Train')
ax.fill_between(cv_results.index, 
               cv_results['train-logloss-mean'] - cv_results['train-logloss-std'],
               cv_results['train-logloss-mean'] + cv_results['train-logloss-std'],
               alpha=0.2, color='blue')
ax.plot(cv_results.index, cv_results['test-logloss-mean'], 'r-', label='Test (CV)')
ax.fill_between(cv_results.index,
               cv_results['test-logloss-mean'] - cv_results['test-logloss-std'],
               cv_results['test-logloss-mean'] + cv_results['test-logloss-std'],
               alpha=0.2, color='red')
ax.set_xlabel('Boosting Round', fontsize=12)
ax.set_ylabel('Log Loss', fontsize=12)
ax.set_title('XGBoost Native CV Results\n(with std bands)', fontsize=14, fontweight='bold')
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# %% [CELL 18: Load Real Trading Data]
print("\n" + "=" * 70)
print("💹 CELL 18: Load Real Trading Data")
print("=" * 70)

try:
    df_trading = pd.read_feather('/allah/data/ml/atr_tp-1124-2038.feather')
    print(f"✓ Dataset loaded: {df_trading.shape}")
    
    trades_mask = df_trading['profit_ratio'].notna()
    df_trades = df_trading[trades_mask].copy()
    df_trades['is_profitable'] = (df_trades['profit_ratio'] > 0).astype(int)
    
    print(f"\nTotal trades: {len(df_trades)}")
    print(f"Profitable:   {(df_trades['is_profitable'] == 1).sum()} ({(df_trades['is_profitable'] == 1).sum()/len(df_trades)*100:.1f}%)")
    print(f"Loss:         {(df_trades['is_profitable'] == 0).sum()} ({(df_trades['is_profitable'] == 0).sum()/len(df_trades)*100:.1f}%)")
    
    TRADING_DATA_AVAILABLE = True
except:
    print("⚠ Trading dataset not found. Skipping real-world examples.")
    TRADING_DATA_AVAILABLE = False

# %% [CELL 19: Full Pipeline on Trading Data]
if TRADING_DATA_AVAILABLE:
    print("\n" + "=" * 70)
    print("🚀 CELL 19: Full XGBoost Pipeline on Trading Data")
    print("=" * 70)
    
    indicator_cols = [col for col in df_trades.columns if any(x in col.lower() for x in 
        ['rsi', 'macd', 'ema', 'sma', 'atr', 'bb_', 'stoch', 'cci', 'adx', 'obv', 'mfi', 
         'roc', 'momentum', 'willr', 'sar', 'plus_di', 'minus_di', 'aroon', 'cmo', 'trix', 'apo', 'ultosc'])]
    
    available_cols = [c for c in indicator_cols if c in df_trades.columns]
    print(f"Available features: {len(available_cols)}")
    
    if len(available_cols) > 5:
        X_t = df_trades[available_cols].copy()
        y_t = df_trades['is_profitable'].copy()
        X_t = X_t.ffill().bfill().fillna(0)
        
        # Time-based split
        split_idx = int(len(X_t) * 0.8)
        X_train_t, X_test_t = X_t.iloc[:split_idx], X_t.iloc[split_idx:]
        y_train_t, y_test_t = y_t.iloc[:split_idx], y_t.iloc[split_idx:]
        
        # Further split for validation
        val_split = int(len(X_train_t) * 0.9)
        X_tr, X_vl = X_train_t.iloc[:val_split], X_train_t.iloc[val_split:]
        y_tr, y_vl = y_train_t.iloc[:val_split], y_train_t.iloc[val_split:]
        
        print(f"Train: {len(X_tr)} | Val: {len(X_vl)} | Test: {len(X_test_t)}")
        
        print("\nTraining XGBoost with early stopping...")
        xgb_trading = XGBClassifier(
            n_estimators=1000,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=1,
            scale_pos_weight=len(y_tr[y_tr==0])/len(y_tr[y_tr==1]),  # Handle imbalance
            random_state=42,
            eval_metric='logloss',
            early_stopping_rounds=50,
            n_jobs=-1
        )
        
        xgb_trading.fit(X_tr, y_tr, eval_set=[(X_vl, y_vl)], verbose=False)
        
        y_pred_t = xgb_trading.predict(X_test_t)
        y_proba_t = xgb_trading.predict_proba(X_test_t)[:, 1]
        
        print("\n" + "-" * 50)
        print("TRADING MODEL PERFORMANCE:")
        print("-" * 50)
        print(f"Best iteration: {xgb_trading.best_iteration}")
        print(f"Accuracy:   {accuracy_score(y_test_t, y_pred_t):.4f}")
        print(f"Precision:  {precision_score(y_test_t, y_pred_t):.4f}")
        print(f"Recall:     {recall_score(y_test_t, y_pred_t):.4f}")
        print(f"F1 Score:   {f1_score(y_test_t, y_pred_t):.4f}")
        print(f"ROC-AUC:    {roc_auc_score(y_test_t, y_proba_t):.4f}")
        
        # Feature importance
        print("\n" + "-" * 50)
        print("TOP 15 IMPORTANT FEATURES (by Gain):")
        print("-" * 50)
        
        imp_gain = xgb_trading.get_booster().get_score(importance_type='gain')
        importance_df_t = pd.DataFrame({
            'Feature': available_cols,
            'Importance': [imp_gain.get(f'f{i}', 0) for i in range(len(available_cols))]
        }).sort_values('Importance', ascending=False)
        
        for _, row in importance_df_t.head(15).iterrows():
            bar = '█' * int(row['Importance'] / importance_df_t['Importance'].max() * 20)
            print(f"  {row['Feature']:<20} {row['Importance']:.2f} {bar}")
        
        # Visualizations
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        ax1 = axes[0]
        fpr_t, tpr_t, _ = roc_curve(y_test_t, y_proba_t)
        auc_t = roc_auc_score(y_test_t, y_proba_t)
        ax1.plot(fpr_t, tpr_t, 'b-', linewidth=2, label=f'XGBoost (AUC={auc_t:.3f})')
        ax1.plot([0,1], [0,1], 'r--', linewidth=2, label='Random')
        ax1.set_xlabel('FPR')
        ax1.set_ylabel('TPR')
        ax1.set_title('ROC Curve - Trading XGBoost', fontweight='bold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        ax2 = axes[1]
        top15 = importance_df_t.head(15)
        colors = plt.cm.RdYlGn(np.linspace(0.2, 0.8, len(top15)))[::-1]
        ax2.barh(range(len(top15)), top15['Importance'], color=colors, edgecolor='black')
        ax2.set_yticks(range(len(top15)))
        ax2.set_yticklabels(top15['Feature'])
        ax2.invert_yaxis()
        ax2.set_xlabel('Gain')
        ax2.set_title('Top 15 Features', fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        plt.show()

# %% [CELL 20: Common Mistakes to Avoid]
print("\n" + "=" * 70)
print("🚫 CELL 20: Common Mistakes to Avoid")
print("=" * 70)

print("""
╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #1: NOT USING EARLY STOPPING                            ║
╠═══════════════════════════════════════════════════════════════════╣
║  XGBoost easily overfits without early stopping                   ║
║                                                                   ║
║  ✓ ALWAYS use eval_set + early_stopping_rounds                   ║
║  ✓ Set n_estimators high, let early stopping find optimal        ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #2: WRONG PARAMETER SCALE                               ║
╠═══════════════════════════════════════════════════════════════════╣
║  XGBoost parameters have different effects than Random Forest     ║
║                                                                   ║
║  ✓ max_depth: 3-8 for XGBoost (vs 10-30 for RF)                  ║
║  ✓ learning_rate: Start 0.1, lower for final model               ║
║  ✓ Trees are "weak learners" - don't need to be deep             ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #3: IGNORING IMBALANCED DATA                            ║
╠═══════════════════════════════════════════════════════════════════╣
║  Trading data is often imbalanced (more losses than wins)         ║
║                                                                   ║
║  ✓ Use scale_pos_weight parameter                                ║
║  ✓ scale_pos_weight = count(negative) / count(positive)          ║
║  ✓ Or use sample_weight in fit()                                 ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #4: DATA LEAKAGE IN TIME SERIES                         ║
╠═══════════════════════════════════════════════════════════════════╣
║  Random shuffle for time-series = DISASTER                        ║
║                                                                   ║
║  ✓ ALWAYS use time-based split for trading                       ║
║  ✓ Validation set should be AFTER training set                   ║
║  ✓ Test set should be AFTER validation set                       ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #5: TUNING TOO MANY PARAMETERS AT ONCE                  ║
╠═══════════════════════════════════════════════════════════════════╣
║  XGBoost has MANY hyperparameters - don't tune all at once!       ║
║                                                                   ║
║  Recommended order:                                               ║
║  1. max_depth, min_child_weight (tree structure)                  ║
║  2. subsample, colsample_bytree (randomness)                      ║
║  3. reg_lambda, reg_alpha, gamma (regularization)                 ║
║  4. learning_rate (lower) + n_estimators (higher)                 ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #6: USING WEIGHT IMPORTANCE BLINDLY                     ║
╠═══════════════════════════════════════════════════════════════════╣
║  Weight = number of splits, not predictive power!                 ║
║                                                                   ║
║  ✓ Use GAIN importance for feature selection                     ║
║  ✓ Verify with permutation importance                            ║
║  ✓ Check that important features make domain sense               ║
╚═══════════════════════════════════════════════════════════════════╝
""")

# %% [CELL 21: Save & Load Models]
print("\n" + "=" * 70)
print("💾 CELL 21: Save & Load Models")
print("=" * 70)

print("""
XGBOOST SAVING OPTIONS:
─────────────────────────────────────────────────────────────────────
1. Joblib/Pickle (sklearn compatible):
   joblib.dump(model, 'model.joblib')
   model = joblib.load('model.joblib')

2. XGBoost native format (recommended for production):
   model.save_model('model.json')  # or .ubj (binary)
   model.load_model('model.json')

3. Booster only:
   model.get_booster().save_model('model.json')
─────────────────────────────────────────────────────────────────────
""")

import os
model_dir = '/allah/blue/ft/ml/outputs'
os.makedirs(model_dir, exist_ok=True)

# Method 1: Joblib
model_path_joblib = f'{model_dir}/xgboost_demo.joblib'
joblib.dump(best_xgb, model_path_joblib)
print(f"✓ Model saved (joblib): {model_path_joblib}")

# Method 2: Native XGBoost format
model_path_native = f'{model_dir}/xgboost_demo.json'
best_xgb.save_model(model_path_native)
print(f"✓ Model saved (native): {model_path_native}")

# Load and verify
loaded_xgb = joblib.load(model_path_joblib)
loaded_native = XGBClassifier()
loaded_native.load_model(model_path_native)

# Verify predictions match
original_pred = best_xgb.predict(X_test[:5])
joblib_pred = loaded_xgb.predict(X_test[:5])
native_pred = loaded_native.predict(X_test[:5])

print(f"\n✓ Joblib predictions verified: {np.array_equal(original_pred, joblib_pred)}")
print(f"✓ Native predictions verified: {np.array_equal(original_pred, native_pred)}")

print("""
PRODUCTION PATTERN:
─────────────────────────────────────────────────────────────────────
# TRAINING
xgb = XGBClassifier(...)
xgb.fit(X_train, y_train, eval_set=[(X_val, y_val)],
        early_stopping_rounds=50)

# Save with metadata
import json
metadata = {
    'best_iteration': xgb.best_iteration,
    'features': feature_list,
    'threshold': 0.5
}
xgb.save_model('model.json')
with open('metadata.json', 'w') as f:
    json.dump(metadata, f)

# INFERENCE
xgb = XGBClassifier()
xgb.load_model('model.json')
with open('metadata.json') as f:
    metadata = json.load(f)

predictions = xgb.predict_proba(X_new)[:, 1]
high_confidence = predictions > 0.7
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 22: Final Summary]
print("\n" + "=" * 70)
print("🎓 CELL 22: Course Complete - XGBoost Summary")
print("=" * 70)

print("""
╔═══════════════════════════════════════════════════════════════════╗
║                       XGBOOST SUMMARY                             ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  WHAT IT IS:                                                      ║
║  • Gradient boosting with optimizations                           ║
║  • Sequential tree building (each corrects previous errors)       ║
║  • Industry standard for tabular data                             ║
║                                                                   ║
║  KEY HYPERPARAMETERS:                                             ║
║  • learning_rate (eta): 0.01-0.3 (step size)                      ║
║  • n_estimators: 100-1000 (use early stopping)                    ║
║  • max_depth: 3-8 (tree complexity)                               ║
║  • subsample: 0.7-0.9 (row sampling)                              ║
║  • colsample_bytree: 0.7-0.9 (column sampling)                    ║
║  • reg_lambda: 1-10 (L2 regularization)                           ║
║  • reg_alpha: 0-1 (L1 regularization)                             ║
║  • gamma: 0-5 (min split loss)                                    ║
║                                                                   ║
║  STRENGTHS:                                                       ║
║  ✓ Often best performance for tabular data                       ║
║  ✓ Handles missing values automatically                          ║
║  ✓ Built-in regularization                                       ║
║  ✓ Early stopping prevents overfitting                           ║
║  ✓ Fast training with parallel processing                        ║
║  ✓ Multiple importance metrics                                   ║
║                                                                   ║
║  WEAKNESSES:                                                      ║
║  ✗ Many hyperparameters to tune                                  ║
║  ✗ Can overfit without proper regularization                     ║
║  ✗ Sequential nature limits some parallelization                 ║
║  ✗ Sensitive to hyperparameter choices                           ║
║                                                                   ║
║  WHEN TO USE:                                                     ║
║  ✓ Tabular/structured data                                       ║
║  ✓ When performance is critical                                  ║
║  ✓ Competition or production ML                                  ║
║  ✓ When you can tune hyperparameters properly                    ║
║                                                                   ║
║  FOR TRADING:                                                     ║
║  ✓ Time-based split (NO random shuffle!)                         ║
║  ✓ Use scale_pos_weight for imbalanced classes                   ║
║  ✓ Early stopping is ESSENTIAL                                   ║
║  ✓ Focus on precision to avoid bad trades                        ║
║  ✓ Use probability thresholds for confidence                     ║
║                                                                   ║
║  XGBoost vs Random Forest:                                        ║
║  • XGBoost: Often better accuracy, needs more tuning             ║
║  • RF: More robust out-of-box, less hyperparameter sensitive     ║
║  • Try both and compare!                                         ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

🚀 Next: Try LightGBM - Even faster with similar performance!
""")
print("=" * 70)
