# %% [CELL 1: Course Overview]
"""
================================================================================
LOGISTIC REGRESSION - Complete Educational Guide
================================================================================

COURSE OUTLINE:
───────────────────────────────────────────────────────────────────────────────
PART 1: FOUNDATIONS
  Cell 1-2:   Setup & Introduction
  Cell 3-4:   The Math - Sigmoid, Log-Odds, Decision Boundary
  Cell 5-6:   Your First Model (Synthetic Data)

PART 2: EVALUATION MASTERY  
  Cell 7-8:   Confusion Matrix Deep Dive
  Cell 9-10:  ROC Curve & AUC Explained
  Cell 11-12: Precision-Recall & Threshold Tuning

PART 3: HYPERPARAMETERS
  Cell 13-14: Regularization (C parameter, L1 vs L2)
  Cell 15-16: GridSearchCV - Finding Optimal Parameters

PART 4: REAL-WORLD APPLICATION
  Cell 17-18: Trading Data Preparation
  Cell 19-20: Full Pipeline with Evaluation
  Cell 21-22: Feature Importance & Interpretation

PART 5: PRODUCTION & PRACTICE
  Cell 23-24: Common Mistakes to Avoid
  Cell 25-26: Save/Load Models
  Cell 27:    Practice Exercises
================================================================================
"""

print("=" * 70)
print("🎓 LOGISTIC REGRESSION - Complete Educational Guide")
print("=" * 70)
print("""
What you'll learn:
  ✓ How logistic regression works (math + intuition)
  ✓ When to use it vs other algorithms
  ✓ How to evaluate classification models properly
  ✓ Hyperparameter tuning techniques
  ✓ Real-world trading application
  ✓ Production deployment patterns

Prerequisites:
  • Basic Python & NumPy
  • Understanding of train/test splits
  • Familiarity with pandas DataFrames
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
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, learning_curve
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve,
    precision_recall_curve
)
from sklearn.dummy import DummyClassifier
from matplotlib.patches import Patch
import joblib
import warnings
warnings.filterwarnings('ignore')

# Nice plot style
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['figure.figsize'] = [12, 6]
plt.rcParams['font.size'] = 11

print("✓ All libraries loaded!")

# %% [CELL 3: What is Logistic Regression?]
print("\n" + "=" * 70)
print("📖 CELL 3: What is Logistic Regression?")
print("=" * 70)

print("""
┌─────────────────────────────────────────────────────────────────────┐
│  LOGISTIC REGRESSION IN ONE SENTENCE:                               │
│  A linear model that predicts PROBABILITIES for binary outcomes     │
└─────────────────────────────────────────────────────────────────────┘

Despite the name "regression", it's used for CLASSIFICATION:
  • Spam or Not Spam?
  • Profitable or Loss?
  • Click or No Click?
  • Disease or Healthy?

The Key Idea:
  1. Calculate a linear combination: z = β₀ + β₁x₁ + β₂x₂ + ...
  2. Transform z into probability using SIGMOID function
  3. If probability ≥ 0.5 → Predict Class 1
  4. If probability < 0.5  → Predict Class 0

Why "Logistic"?
  • Uses the logistic (sigmoid) function to map any number to [0,1]
  • The "log-odds" (logit) of the probability is linear in features
""")

# %% [CELL 4: The Sigmoid Function - Visual Deep Dive]
print("\n" + "=" * 70)
print("📊 CELL 4: The Sigmoid Function - Heart of Logistic Regression")
print("=" * 70)

print("""
THE SIGMOID FUNCTION: σ(z) = 1 / (1 + e^(-z))

What it does:
  • INPUT:  Any real number z from -∞ to +∞
  • OUTPUT: A probability between 0 and 1

Key Points:
  • σ(0)  = 0.5  ← Decision boundary
  • σ(+∞) → 1    ← Confident Class 1
  • σ(-∞) → 0    ← Confident Class 0
""")

# Create comprehensive sigmoid visualization
fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# Plot 1: Basic Sigmoid
ax1 = axes[0, 0]
z = np.linspace(-8, 8, 200)
sigmoid = 1 / (1 + np.exp(-z))

ax1.plot(z, sigmoid, 'b-', linewidth=3, label='σ(z) = 1/(1+e⁻ᶻ)')
ax1.axhline(y=0.5, color='r', linestyle='--', linewidth=2, alpha=0.7, label='Decision Boundary (0.5)')
ax1.axvline(x=0, color='r', linestyle='--', linewidth=2, alpha=0.7)
ax1.fill_between(z, 0, sigmoid, where=(z < 0), alpha=0.2, color='orange', label='Predict 0')
ax1.fill_between(z, 0, sigmoid, where=(z >= 0), alpha=0.2, color='green', label='Predict 1')

# Annotations
ax1.annotate('z < 0\nP < 0.5\n→ Class 0', xy=(-4, 0.15), fontsize=10, ha='center',
            bbox=dict(boxstyle='round', facecolor='orange', alpha=0.3))
ax1.annotate('z > 0\nP > 0.5\n→ Class 1', xy=(4, 0.85), fontsize=10, ha='center',
            bbox=dict(boxstyle='round', facecolor='green', alpha=0.3))

ax1.set_xlabel('z (linear combination)', fontsize=12)
ax1.set_ylabel('Probability P(y=1)', fontsize=12)
ax1.set_title('The Sigmoid Function', fontsize=14, fontweight='bold')
ax1.legend(loc='upper left', fontsize=9)
ax1.set_ylim([-0.05, 1.05])
ax1.grid(True, alpha=0.3)

# Plot 2: Sigmoid with different steepness (effect of coefficients)
ax2 = axes[0, 1]
for coef in [0.5, 1, 2, 5]:
    sig = 1 / (1 + np.exp(-coef * z))
    ax2.plot(z, sig, linewidth=2, label=f'coef = {coef}')

ax2.axhline(y=0.5, color='r', linestyle='--', alpha=0.5)
ax2.set_xlabel('z', fontsize=12)
ax2.set_ylabel('Probability', fontsize=12)
ax2.set_title('Coefficient Magnitude → Steepness\n(Higher = More Confident)', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

# Plot 3: Probability to Prediction
ax3 = axes[1, 0]
z_vals = np.array([-5, -2, -0.5, 0.5, 2, 5])
probs = 1 / (1 + np.exp(-z_vals))
predictions = (probs >= 0.5).astype(int)
colors = ['#ff6b6b' if p == 0 else '#51cf66' for p in predictions]

bars = ax3.bar(range(len(z_vals)), probs, color=colors, edgecolor='black', linewidth=2, alpha=0.8)
ax3.axhline(y=0.5, color='red', linestyle='--', linewidth=2, label='Threshold = 0.5')
ax3.set_xticks(range(len(z_vals)))
ax3.set_xticklabels([f'z={z:.1f}' for z in z_vals])
ax3.set_ylabel('Probability', fontsize=12)
ax3.set_title('From Linear Score → Probability → Prediction', fontsize=14, fontweight='bold')

# Add labels on bars
for i, (bar, prob, pred) in enumerate(zip(bars, probs, predictions)):
    ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.03,
            f'P={prob:.2f}\n→ {pred}', ha='center', fontsize=9, fontweight='bold')
ax3.legend()
ax3.set_ylim([0, 1.15])
ax3.grid(True, alpha=0.3, axis='y')

# Plot 4: Log-Odds (Logit) transformation
ax4 = axes[1, 1]
p = np.linspace(0.01, 0.99, 100)
log_odds = np.log(p / (1 - p))

ax4.plot(p, log_odds, 'purple', linewidth=3)
ax4.axhline(y=0, color='gray', linestyle='--', alpha=0.5)
ax4.axvline(x=0.5, color='gray', linestyle='--', alpha=0.5)
ax4.fill_between(p, log_odds, 0, where=(p < 0.5), alpha=0.2, color='orange')
ax4.fill_between(p, log_odds, 0, where=(p >= 0.5), alpha=0.2, color='green')

ax4.set_xlabel('Probability P', fontsize=12)
ax4.set_ylabel('Log-Odds = log(P/(1-P))', fontsize=12)
ax4.set_title('Log-Odds: Why "Logistic" Regression\n(Log-odds is LINEAR in features)', fontsize=14, fontweight='bold')
ax4.annotate('P=0.5 → log-odds=0', xy=(0.5, 0), xytext=(0.7, 2),
            arrowprops=dict(arrowstyle='->', color='red'), fontsize=10)
ax4.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("""
KEY INSIGHTS:
─────────────────────────────────────────────────────────────────────
1. Sigmoid squashes ANY number into [0, 1] → Valid probability
2. Larger |coefficients| = Steeper curve = More confident predictions  
3. Log-odds is LINEAR: log(P/(1-P)) = β₀ + β₁x₁ + β₂x₂ + ...
4. This linearity makes coefficients INTERPRETABLE!
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 5: Create Synthetic Dataset]
print("\n" + "=" * 70)
print("🔬 CELL 5: Create Synthetic Dataset for Learning")
print("=" * 70)

print("""
Why synthetic data first?
  ✓ Easy to visualize (2D)
  ✓ We KNOW the true pattern
  ✓ Perfect for understanding the algorithm
  ✓ No data cleaning needed
""")

# Create 2D dataset
np.random.seed(42)
n_samples = 300

# Class 0: Centered around (-1.5, -1.5)
X_c0 = np.random.randn(n_samples // 2, 2) * 0.8 + [-1.5, -1.5]
y_c0 = np.zeros(n_samples // 2)

# Class 1: Centered around (1.5, 1.5)
X_c1 = np.random.randn(n_samples // 2, 2) * 0.8 + [1.5, 1.5]
y_c1 = np.ones(n_samples // 2)

# Combine
X = np.vstack([X_c0, X_c1])
y = np.hstack([y_c0, y_c1])

# Shuffle
shuffle_idx = np.random.permutation(len(X))
X, y = X[shuffle_idx], y[shuffle_idx]

print(f"Dataset created:")
print(f"  Total samples: {len(X)}")
print(f"  Features: 2 (x₁, x₂)")
print(f"  Class 0: {(y == 0).sum()} samples")
print(f"  Class 1: {(y == 1).sum()} samples")

# Visualize
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Scatter plot
ax1 = axes[0]
ax1.scatter(X[y == 0, 0], X[y == 0, 1], c='#ff6b6b', label='Class 0', alpha=0.6, s=60, edgecolors='white')
ax1.scatter(X[y == 1, 0], X[y == 1, 1], c='#51cf66', label='Class 1', alpha=0.6, s=60, edgecolors='white')
ax1.set_xlabel('Feature x₁', fontsize=12)
ax1.set_ylabel('Feature x₂', fontsize=12)
ax1.set_title('Synthetic Binary Classification Dataset', fontsize=14, fontweight='bold')
ax1.legend(fontsize=11)
ax1.grid(True, alpha=0.3)

# Distribution plots
ax2 = axes[1]
ax2.hist(X[y == 0, 0], bins=20, alpha=0.5, color='#ff6b6b', label='Class 0 - x₁', density=True)
ax2.hist(X[y == 1, 0], bins=20, alpha=0.5, color='#51cf66', label='Class 1 - x₁', density=True)
ax2.set_xlabel('Feature x₁ Value', fontsize=12)
ax2.set_ylabel('Density', fontsize=12)
ax2.set_title('Feature Distribution by Class', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# %% [CELL 6: Train Your First Logistic Regression]
print("\n" + "=" * 70)
print("🚀 CELL 6: Train Your First Logistic Regression Model")
print("=" * 70)

print("""
STEP-BY-STEP PROCESS:
─────────────────────────────────────────────────────────────────────
Step 1: Split data into train (70%) and test (30%) sets
Step 2: Train logistic regression on training data
Step 3: Make predictions on test data
Step 4: Evaluate performance
─────────────────────────────────────────────────────────────────────
""")

# Step 1: Split
print("STEP 1: Split Data")
print("-" * 50)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
print(f"  Training set: {len(X_train)} samples")
print(f"  Test set:     {len(X_test)} samples")

# Step 2: Train
print("\nSTEP 2: Train Model")
print("-" * 50)
model = LogisticRegression(random_state=42)
model.fit(X_train, y_train)
print("  ✓ Model trained!")
print(f"  Intercept (β₀): {model.intercept_[0]:.4f}")
print(f"  Coefficient x₁ (β₁): {model.coef_[0][0]:.4f}")
print(f"  Coefficient x₂ (β₂): {model.coef_[0][1]:.4f}")

# Step 3: Predict
print("\nSTEP 3: Make Predictions")
print("-" * 50)
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

print("  Sample predictions (first 10):")
print(f"  Actual:      {y_test[:10].astype(int)}")
print(f"  Predicted:   {y_pred[:10].astype(int)}")
print(f"  Probability: {np.round(y_proba[:10], 3)}")

# Step 4: Evaluate
print("\nSTEP 4: Evaluate Performance")
print("-" * 50)
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_proba)

print(f"  Accuracy:  {acc:.4f} ← {acc*100:.1f}% predictions correct")
print(f"  Precision: {prec:.4f} ← Of predicted 1s, {prec*100:.1f}% actually 1")
print(f"  Recall:    {rec:.4f} ← Of actual 1s, found {rec*100:.1f}%")
print(f"  F1 Score:  {f1:.4f} ← Harmonic mean of precision & recall")
print(f"  ROC-AUC:   {auc:.4f} ← Overall ranking ability")

# Visualize decision boundary
print("\n" + "=" * 70)
print("📊 Visualizing the Decision Boundary")
print("=" * 70)

fig, axes = plt.subplots(1, 3, figsize=(16, 5))

# Create mesh
h = 0.02
x_min, x_max = X[:, 0].min() - 1, X[:, 0].max() + 1
y_min, y_max = X[:, 1].min() - 1, X[:, 1].max() + 1
xx, yy = np.meshgrid(np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))

# Plot 1: Hard Decision Boundary
ax1 = axes[0]
Z = model.predict(np.c_[xx.ravel(), yy.ravel()]).reshape(xx.shape)
ax1.contourf(xx, yy, Z, alpha=0.3, cmap='RdYlGn')
ax1.scatter(X_test[y_test == 0, 0], X_test[y_test == 0, 1], c='#ff6b6b', label='Class 0', edgecolors='k', s=50)
ax1.scatter(X_test[y_test == 1, 0], X_test[y_test == 1, 1], c='#51cf66', label='Class 1', edgecolors='k', s=50)
ax1.set_title('Hard Decision Boundary\n(Predict 0 or 1)', fontsize=12, fontweight='bold')
ax1.legend()
ax1.set_xlabel('x₁')
ax1.set_ylabel('x₂')

# Plot 2: Probability Contours
ax2 = axes[1]
Z_proba = model.predict_proba(np.c_[xx.ravel(), yy.ravel()])[:, 1].reshape(xx.shape)
contour = ax2.contourf(xx, yy, Z_proba, levels=20, cmap='RdYlGn', alpha=0.8)
plt.colorbar(contour, ax=ax2, label='P(Class 1)')
ax2.scatter(X_test[y_test == 0, 0], X_test[y_test == 0, 1], c='#ff6b6b', edgecolors='k', s=50)
ax2.scatter(X_test[y_test == 1, 0], X_test[y_test == 1, 1], c='#51cf66', edgecolors='k', s=50)
ax2.contour(xx, yy, Z_proba, levels=[0.5], colors='black', linewidths=3)
ax2.set_title('Probability Surface\n(Continuous 0 to 1)', fontsize=12, fontweight='bold')
ax2.set_xlabel('x₁')
ax2.set_ylabel('x₂')

# Plot 3: Linear equation visualization
ax3 = axes[2]
ax3.text(0.5, 0.85, 'The Decision Boundary Equation:', fontsize=14, fontweight='bold', 
        ha='center', transform=ax3.transAxes)
ax3.text(0.5, 0.70, f'z = {model.intercept_[0]:.2f} + {model.coef_[0][0]:.2f}×x₁ + {model.coef_[0][1]:.2f}×x₂', 
        fontsize=16, ha='center', transform=ax3.transAxes, family='monospace',
        bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
ax3.text(0.5, 0.50, 'At the boundary: z = 0 (probability = 0.5)', fontsize=12, 
        ha='center', transform=ax3.transAxes)
ax3.text(0.5, 0.35, f'Solving for boundary line:', fontsize=12, 
        ha='center', transform=ax3.transAxes)
slope = -model.coef_[0][0] / model.coef_[0][1]
intercept = -model.intercept_[0] / model.coef_[0][1]
ax3.text(0.5, 0.20, f'x₂ = {slope:.2f}×x₁ + {intercept:.2f}', fontsize=14, 
        ha='center', transform=ax3.transAxes, family='monospace',
        bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.5))
ax3.axis('off')

plt.tight_layout()
plt.show()

print("""
KEY INSIGHT: The decision boundary is a STRAIGHT LINE!
─────────────────────────────────────────────────────────────────────
• Logistic regression creates LINEAR decision boundaries
• This is its main LIMITATION - can't capture complex patterns
• For non-linear patterns, consider:
  - Polynomial features
  - Tree-based models (Random Forest, XGBoost)
  - Neural networks
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 7: Confusion Matrix - Deep Dive]
print("\n" + "=" * 70)
print("🎯 CELL 7: Confusion Matrix - Understanding Every Prediction")
print("=" * 70)

print("""
The Confusion Matrix shows ALL prediction outcomes:
─────────────────────────────────────────────────────────────────────
                        PREDICTED
                    Negative    Positive
ACTUAL  Negative      TN          FP      ← Type I Error
        Positive      FN          TP      ← Type II Error
                      ↑
                 Type II Error
─────────────────────────────────────────────────────────────────────
TN (True Negative):  Correctly predicted 0
FP (False Positive): Predicted 1, but was 0  [Type I Error]
FN (False Negative): Predicted 0, but was 1  [Type II Error]
TP (True Positive):  Correctly predicted 1
─────────────────────────────────────────────────────────────────────
""")

# Calculate confusion matrix
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

# Comprehensive visualization
fig, axes = plt.subplots(1, 3, figsize=(16, 5))

# Plot 1: Confusion Matrix Heatmap
ax1 = axes[0]
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax1, 
            xticklabels=['Pred 0', 'Pred 1'], yticklabels=['Actual 0', 'Actual 1'],
            annot_kws={'fontsize': 20, 'fontweight': 'bold'}, cbar=False)
ax1.set_title('Confusion Matrix', fontsize=14, fontweight='bold')
ax1.set_ylabel('Actual', fontsize=12)
ax1.set_xlabel('Predicted', fontsize=12)

# Add cell labels
ax1.text(0.5, 0.3, 'TN', fontsize=10, ha='center', transform=ax1.transData, color='gray')
ax1.text(1.5, 0.3, 'FP', fontsize=10, ha='center', transform=ax1.transData, color='gray')
ax1.text(0.5, 1.3, 'FN', fontsize=10, ha='center', transform=ax1.transData, color='gray')
ax1.text(1.5, 1.3, 'TP', fontsize=10, ha='center', transform=ax1.transData, color='gray')

# Plot 2: Visual representation
ax2 = axes[1]
categories = ['TN\n(Correct)', 'FP\n(Type I)', 'FN\n(Type II)', 'TP\n(Correct)']
values = [tn, fp, fn, tp]
colors = ['#51cf66', '#ff6b6b', '#ff6b6b', '#51cf66']
bars = ax2.bar(categories, values, color=colors, edgecolor='black', linewidth=2, alpha=0.8)

for bar, val in zip(bars, values):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, str(val), 
            ha='center', fontsize=14, fontweight='bold')

ax2.set_title('Prediction Breakdown', fontsize=14, fontweight='bold')
ax2.set_ylabel('Count', fontsize=12)
ax2.grid(True, alpha=0.3, axis='y')

# Plot 3: Metrics derived from confusion matrix
ax3 = axes[2]
ax3.axis('off')

# Calculate all metrics
accuracy = (tp + tn) / (tp + tn + fp + fn)
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

text = f"""
METRICS FROM CONFUSION MATRIX:
{'─' * 50}

Accuracy = (TP + TN) / Total
         = ({tp} + {tn}) / {tp+tn+fp+fn} = {accuracy:.4f}

Precision = TP / (TP + FP)
          = {tp} / ({tp} + {fp}) = {precision:.4f}
          "Of predicted positives, how many correct?"

Recall = TP / (TP + FN)
       = {tp} / ({tp} + {fn}) = {recall:.4f}
       "Of actual positives, how many found?"

Specificity = TN / (TN + FP)
            = {tn} / ({tn} + {fp}) = {specificity:.4f}
            "Of actual negatives, how many correct?"

F1 Score = 2 × (Precision × Recall) / (Precision + Recall)
         = {f1:.4f}
         "Harmonic mean - balances precision & recall"
"""
ax3.text(0.1, 0.95, text, fontsize=11, family='monospace', va='top', transform=ax3.transAxes)

plt.tight_layout()
plt.show()

# %% [CELL 8: When Each Metric Matters]
print("\n" + "=" * 70)
print("📊 CELL 8: Choosing the Right Metric")
print("=" * 70)

print("""
┌─────────────────────────────────────────────────────────────────────┐
│  METRIC SELECTION GUIDE                                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ACCURACY - Overall correctness                                     │
│    ✓ Use when: Classes are balanced                                │
│    ✗ Avoid when: Imbalanced data (90/10 split)                     │
│    Example: Coin flip prediction                                    │
│                                                                     │
│  PRECISION - "Don't cry wolf"                                       │
│    ✓ Use when: False positives are COSTLY                          │
│    Example: Spam filter (don't mark important email as spam)        │
│    Trading: Don't enter bad trades                                  │
│                                                                     │
│  RECALL - "Don't miss anything"                                     │
│    ✓ Use when: False negatives are COSTLY                          │
│    Example: Cancer screening (don't miss sick patients)             │
│    Trading: Don't miss profitable opportunities                     │
│                                                                     │
│  F1 SCORE - Balance precision & recall                              │
│    ✓ Use when: Both FP and FN matter equally                       │
│    ✓ Use when: Classes are imbalanced                              │
│    Example: Most real-world classification                          │
│                                                                     │
│  ROC-AUC - Ranking ability                                          │
│    ✓ Use when: You need threshold-independent evaluation           │
│    ✓ Use when: Comparing models fairly                             │
│    Example: Model selection, probability calibration                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
""")

# Visual comparison
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Trading scenario comparison
ax1 = axes[0]
scenarios = ['Accuracy\nFocused', 'Precision\nFocused', 'Recall\nFocused', 'F1\nBalanced']
trades_taken = [100, 30, 150, 80]
win_rate = [55, 75, 45, 62]
profits_captured = [60, 40, 90, 70]

x = np.arange(len(scenarios))
width = 0.25

bars1 = ax1.bar(x - width, trades_taken, width, label='Trades Taken', color='steelblue', alpha=0.8)
bars2 = ax1.bar(x, win_rate, width, label='Win Rate %', color='green', alpha=0.8)
bars3 = ax1.bar(x + width, profits_captured, width, label='Profits Captured %', color='gold', alpha=0.8)

ax1.set_ylabel('Value', fontsize=12)
ax1.set_title('Trading Strategy: Different Metric Focus', fontsize=14, fontweight='bold')
ax1.set_xticks(x)
ax1.set_xticklabels(scenarios)
ax1.legend()
ax1.grid(True, alpha=0.3, axis='y')

# Plot 2: Precision-Recall Tradeoff
ax2 = axes[1]
thresholds = np.linspace(0.1, 0.9, 9)
precisions = [0.45, 0.50, 0.55, 0.60, 0.68, 0.75, 0.82, 0.88, 0.95]
recalls = [0.95, 0.90, 0.85, 0.78, 0.70, 0.60, 0.48, 0.35, 0.20]

ax2.plot(thresholds, precisions, 'g-o', linewidth=2, markersize=8, label='Precision')
ax2.plot(thresholds, recalls, 'b-s', linewidth=2, markersize=8, label='Recall')

# F1 curve
f1_scores = [2*p*r/(p+r) for p, r in zip(precisions, recalls)]
ax2.plot(thresholds, f1_scores, 'r--^', linewidth=2, markersize=8, label='F1 Score')

# Mark optimal F1
max_f1_idx = np.argmax(f1_scores)
ax2.axvline(x=thresholds[max_f1_idx], color='red', linestyle=':', alpha=0.7)
ax2.annotate(f'Optimal\nThreshold', xy=(thresholds[max_f1_idx], f1_scores[max_f1_idx]), 
            xytext=(thresholds[max_f1_idx]+0.1, f1_scores[max_f1_idx]+0.1),
            arrowprops=dict(arrowstyle='->', color='red'), fontsize=10)

ax2.set_xlabel('Decision Threshold', fontsize=12)
ax2.set_ylabel('Score', fontsize=12)
ax2.set_title('Precision-Recall Tradeoff', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)
ax2.set_ylim([0, 1.05])

plt.tight_layout()
plt.show()

# %% [CELL 9: ROC Curve Explained]
print("\n" + "=" * 70)
print("📈 CELL 9: ROC Curve - The Gold Standard of Evaluation")
print("=" * 70)

print("""
ROC = Receiver Operating Characteristic
─────────────────────────────────────────────────────────────────────
What it shows:
  • Model performance at ALL possible thresholds
  • X-axis: False Positive Rate (FPR) = FP / (FP + TN)
  • Y-axis: True Positive Rate (TPR) = TP / (TP + FN) = Recall

AUC = Area Under the Curve
  • 1.0 = Perfect classifier
  • 0.5 = Random guessing (diagonal line)
  • < 0.5 = Worse than random (invert predictions!)

Interpretation:
  • AUC 0.9-1.0: Excellent
  • AUC 0.8-0.9: Good  
  • AUC 0.7-0.8: Fair
  • AUC 0.6-0.7: Poor
  • AUC 0.5-0.6: Fail
─────────────────────────────────────────────────────────────────────
""")

# Calculate ROC
fpr, tpr, thresholds_roc = roc_curve(y_test, y_proba)
roc_auc = roc_auc_score(y_test, y_proba)

# Comprehensive ROC visualization
fig, axes = plt.subplots(1, 3, figsize=(16, 5))

# Plot 1: ROC Curve
ax1 = axes[0]
ax1.plot(fpr, tpr, 'b-', linewidth=3, label=f'Logistic Regression (AUC = {roc_auc:.3f})')
ax1.plot([0, 1], [0, 1], 'r--', linewidth=2, label='Random Classifier (AUC = 0.5)')
ax1.fill_between(fpr, tpr, alpha=0.3)

# Mark some thresholds
for i, thresh in enumerate([0.3, 0.5, 0.7]):
    idx = np.argmin(np.abs(thresholds_roc - thresh))
    if idx < len(fpr):
        ax1.scatter(fpr[idx], tpr[idx], s=100, zorder=5)
        ax1.annotate(f't={thresh}', xy=(fpr[idx], tpr[idx]), xytext=(fpr[idx]+0.05, tpr[idx]-0.1),
                    fontsize=9, arrowprops=dict(arrowstyle='->', color='gray'))

ax1.set_xlabel('False Positive Rate (FPR)', fontsize=12)
ax1.set_ylabel('True Positive Rate (TPR)', fontsize=12)
ax1.set_title('ROC Curve', fontsize=14, fontweight='bold')
ax1.legend(loc='lower right')
ax1.grid(True, alpha=0.3)
ax1.set_xlim([-0.02, 1.02])
ax1.set_ylim([-0.02, 1.02])

# Plot 2: TPR and FPR vs Threshold
ax2 = axes[1]
# Filter to valid range
valid_idx = thresholds_roc < 1
ax2.plot(thresholds_roc[valid_idx], tpr[valid_idx], 'g-', linewidth=2, label='TPR (Recall)')
ax2.plot(thresholds_roc[valid_idx], fpr[valid_idx], 'r-', linewidth=2, label='FPR')
ax2.plot(thresholds_roc[valid_idx], 1-fpr[valid_idx], 'b--', linewidth=2, label='Specificity (1-FPR)')

ax2.axvline(x=0.5, color='gray', linestyle=':', label='Default Threshold')
ax2.set_xlabel('Threshold', fontsize=12)
ax2.set_ylabel('Rate', fontsize=12)
ax2.set_title('TPR & FPR vs Threshold', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)
ax2.set_xlim([0, 1])

# Plot 3: AUC interpretation
ax3 = axes[2]
ax3.axis('off')

# Visual AUC scale
auc_ranges = [
    (0.9, 1.0, 'Excellent', '#2ecc71'),
    (0.8, 0.9, 'Good', '#27ae60'),
    (0.7, 0.8, 'Fair', '#f39c12'),
    (0.6, 0.7, 'Poor', '#e74c3c'),
    (0.5, 0.6, 'Fail', '#c0392b'),
]

y_pos = 0.9
for low, high, label, color in auc_ranges:
    rect = plt.Rectangle((0.1, y_pos-0.12), 0.3, 0.1, facecolor=color, alpha=0.7, edgecolor='black')
    ax3.add_patch(rect)
    ax3.text(0.45, y_pos-0.07, f'{low:.1f} - {high:.1f}:  {label}', fontsize=12, va='center')
    y_pos -= 0.15

# Mark our AUC
ax3.text(0.5, 0.2, f'Your Model AUC: {roc_auc:.3f}', fontsize=16, fontweight='bold', 
        ha='center', bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))

if roc_auc >= 0.9:
    verdict = "🌟 EXCELLENT!"
elif roc_auc >= 0.8:
    verdict = "✓ Good performance"
elif roc_auc >= 0.7:
    verdict = "⚠ Fair - room for improvement"
else:
    verdict = "❌ Needs work"
    
ax3.text(0.5, 0.08, verdict, fontsize=14, ha='center')
ax3.set_xlim([0, 1])
ax3.set_ylim([0, 1])
ax3.set_title('AUC Interpretation Guide', fontsize=14, fontweight='bold')

plt.tight_layout()
plt.show()

# %% [CELL 10: Precision-Recall Curve & Threshold Optimization]
print("\n" + "=" * 70)
print("⚖️ CELL 10: Precision-Recall Curve & Threshold Optimization")
print("=" * 70)

print("""
Why Precision-Recall Curve?
─────────────────────────────────────────────────────────────────────
• Better than ROC for IMBALANCED datasets
• Directly shows precision-recall tradeoff
• Helps choose optimal threshold for YOUR use case

Default threshold = 0.5, but that's often NOT optimal!
  • Conservative strategy → Higher threshold (0.6-0.8)
  • Aggressive strategy  → Lower threshold (0.3-0.4)
─────────────────────────────────────────────────────────────────────
""")

# Calculate PR curve
precision_arr, recall_arr, thresholds_pr = precision_recall_curve(y_test, y_proba)

# Calculate F1 at each threshold
f1_arr = 2 * (precision_arr[:-1] * recall_arr[:-1]) / (precision_arr[:-1] + recall_arr[:-1] + 1e-10)
optimal_idx = np.argmax(f1_arr)
optimal_threshold = thresholds_pr[optimal_idx]

print(f"✓ Optimal threshold (max F1): {optimal_threshold:.3f}")
print(f"  At this threshold: Precision={precision_arr[optimal_idx]:.3f}, Recall={recall_arr[optimal_idx]:.3f}")

# Visualization
fig, axes = plt.subplots(1, 3, figsize=(16, 5))

# Plot 1: PR Curve
ax1 = axes[0]
ax1.plot(recall_arr, precision_arr, 'purple', linewidth=3)
ax1.scatter(recall_arr[optimal_idx], precision_arr[optimal_idx], color='red', s=150, zorder=5,
           label=f'Optimal (t={optimal_threshold:.2f})')
ax1.set_xlabel('Recall', fontsize=12)
ax1.set_ylabel('Precision', fontsize=12)
ax1.set_title('Precision-Recall Curve', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)
ax1.set_xlim([0, 1.02])
ax1.set_ylim([0, 1.02])

# Plot 2: Metrics vs Threshold
ax2 = axes[1]
ax2.plot(thresholds_pr, precision_arr[:-1], 'g-', linewidth=2, label='Precision')
ax2.plot(thresholds_pr, recall_arr[:-1], 'b-', linewidth=2, label='Recall')
ax2.plot(thresholds_pr, f1_arr, 'r--', linewidth=2, label='F1 Score')
ax2.axvline(x=0.5, color='gray', linestyle=':', linewidth=2, label='Default (0.5)')
ax2.axvline(x=optimal_threshold, color='red', linestyle='--', linewidth=2, label=f'Optimal ({optimal_threshold:.2f})')

ax2.set_xlabel('Threshold', fontsize=12)
ax2.set_ylabel('Score', fontsize=12)
ax2.set_title('Metrics vs Decision Threshold', fontsize=14, fontweight='bold')
ax2.legend(loc='best')
ax2.grid(True, alpha=0.3)

# Plot 3: Threshold impact
ax3 = axes[2]
test_thresholds = [0.3, 0.5, optimal_threshold, 0.7]
metrics_data = []

for t in test_thresholds:
    y_pred_t = (y_proba >= t).astype(int)
    n_pred = y_pred_t.sum()
    prec_t = precision_score(y_test, y_pred_t, zero_division=0)
    rec_t = recall_score(y_test, y_pred_t, zero_division=0)
    f1_t = f1_score(y_test, y_pred_t, zero_division=0)
    metrics_data.append({'threshold': t, 'predictions': n_pred, 'precision': prec_t, 
                        'recall': rec_t, 'f1': f1_t})

x = np.arange(len(test_thresholds))
width = 0.2
metrics_df = pd.DataFrame(metrics_data)

ax3.bar(x - 1.5*width, metrics_df['precision'], width, label='Precision', color='green', alpha=0.8)
ax3.bar(x - 0.5*width, metrics_df['recall'], width, label='Recall', color='blue', alpha=0.8)
ax3.bar(x + 0.5*width, metrics_df['f1'], width, label='F1', color='red', alpha=0.8)
ax3.bar(x + 1.5*width, metrics_df['predictions']/len(y_test), width, label='% Predicted 1', color='orange', alpha=0.8)

ax3.set_xticks(x)
ax3.set_xticklabels([f't={t:.2f}' for t in test_thresholds])
ax3.set_ylabel('Score / Ratio', fontsize=12)
ax3.set_title('Impact of Different Thresholds', fontsize=14, fontweight='bold')
ax3.legend()
ax3.grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.show()

print("""
THRESHOLD SELECTION GUIDE FOR TRADING:
─────────────────────────────────────────────────────────────────────
🎯 CONSERVATIVE (High Precision): Threshold 0.6-0.8
   → Fewer trades, higher win rate
   → Use when: Trading costs high, capital limited

🎯 AGGRESSIVE (High Recall): Threshold 0.3-0.4  
   → More trades, capture more opportunities
   → Use when: Low costs, want market exposure

🎯 BALANCED: Use optimal F1 threshold
   → Good starting point for most strategies
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 11: Regularization - C Parameter]
print("\n" + "=" * 70)
print("🔧 CELL 11: Regularization - The C Parameter")
print("=" * 70)

print("""
What is Regularization?
─────────────────────────────────────────────────────────────────────
• Prevents OVERFITTING by penalizing large coefficients
• Makes model simpler and more generalizable
• C = Inverse regularization strength

C Parameter:
  • Small C (0.001) → STRONG regularization → SIMPLE model
  • Large C (1000)  → WEAK regularization  → COMPLEX model
  • Default: C = 1.0
─────────────────────────────────────────────────────────────────────
""")

# Test different C values
C_values = [0.001, 0.01, 0.1, 1, 10, 100, 1000]
results_c = []

print("Testing different C values...")
print("-" * 60)

for C in C_values:
    lr_c = LogisticRegression(C=C, random_state=42, max_iter=1000)
    lr_c.fit(X_train, y_train)
    
    train_acc = accuracy_score(y_train, lr_c.predict(X_train))
    test_acc = accuracy_score(y_test, lr_c.predict(X_test))
    train_f1 = f1_score(y_train, lr_c.predict(X_train))
    test_f1 = f1_score(y_test, lr_c.predict(X_test))
    coef_magnitude = np.abs(lr_c.coef_[0]).mean()
    
    results_c.append({
        'C': C, 'train_acc': train_acc, 'test_acc': test_acc,
        'train_f1': train_f1, 'test_f1': test_f1, 'coef_mag': coef_magnitude
    })
    
    print(f"C={C:8.3f} | Train F1: {train_f1:.4f} | Test F1: {test_f1:.4f} | Coef Mean: {coef_magnitude:.4f}")

results_df = pd.DataFrame(results_c)

# Visualization
fig, axes = plt.subplots(1, 3, figsize=(16, 5))

# Plot 1: Train vs Test Performance
ax1 = axes[0]
ax1.semilogx(results_df['C'], results_df['train_f1'], 'b-o', linewidth=2, markersize=8, label='Train F1')
ax1.semilogx(results_df['C'], results_df['test_f1'], 'r-s', linewidth=2, markersize=8, label='Test F1')
ax1.fill_between(results_df['C'], results_df['train_f1'], results_df['test_f1'], alpha=0.2, color='gray')
ax1.set_xlabel('C (log scale)', fontsize=12)
ax1.set_ylabel('F1 Score', fontsize=12)
ax1.set_title('Train vs Test Performance\n(Gap = Overfitting)', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

# Add annotations
ax1.annotate('Underfitting\n(too simple)', xy=(0.001, results_df['test_f1'].iloc[0]), 
            xytext=(0.005, results_df['test_f1'].iloc[0]-0.1),
            arrowprops=dict(arrowstyle='->', color='orange'), fontsize=9)
ax1.annotate('Sweet spot', xy=(1, results_df['test_f1'].iloc[3]), 
            xytext=(3, results_df['test_f1'].iloc[3]+0.05),
            arrowprops=dict(arrowstyle='->', color='green'), fontsize=9)

# Plot 2: Coefficient Magnitude
ax2 = axes[1]
ax2.semilogx(results_df['C'], results_df['coef_mag'], 'g-o', linewidth=2, markersize=8)
ax2.set_xlabel('C (log scale)', fontsize=12)
ax2.set_ylabel('Mean |Coefficient|', fontsize=12)
ax2.set_title('Coefficient Magnitude vs C\n(Larger C → Larger Coefficients)', fontsize=14, fontweight='bold')
ax2.grid(True, alpha=0.3)

# Plot 3: Regularization effect visualization
ax3 = axes[2]
ax3.axis('off')

text = """
REGULARIZATION SUMMARY:
─────────────────────────────────────────────────────────────────

Small C (e.g., 0.001):
  ✓ Strong regularization
  ✓ Small coefficients
  ✓ Simpler model
  ✗ May UNDERFIT (miss patterns)
  → Use when: Noisy data, few samples

Large C (e.g., 1000):
  ✓ Weak regularization
  ✓ Large coefficients
  ✓ Complex model
  ✗ May OVERFIT (memorize noise)
  → Use when: Clean data, many samples

How to choose?
  → Use GridSearchCV (automated search)
  → Or start with C=1.0 and adjust
  → Monitor train vs test gap
"""
ax3.text(0.05, 0.95, text, fontsize=11, family='monospace', va='top', transform=ax3.transAxes)

plt.tight_layout()
plt.show()

# %% [CELL 12: L1 vs L2 Regularization]
print("\n" + "=" * 70)
print("⚖️ CELL 12: L1 (Lasso) vs L2 (Ridge) Regularization")
print("=" * 70)

print("""
Two Types of Regularization:
─────────────────────────────────────────────────────────────────────
L2 (Ridge) - Default:
  • Penalty: λ × Σ(β²)
  • Shrinks coefficients toward zero
  • NEVER makes them exactly zero
  • Keeps ALL features
  
L1 (Lasso):
  • Penalty: λ × Σ|β|
  • Can shrink coefficients to EXACTLY ZERO
  • Automatic FEATURE SELECTION
  • Creates sparse models
─────────────────────────────────────────────────────────────────────
""")

# Train with both penalties
C_test = [0.01, 0.1, 1, 10]
l1_coefs = []
l2_coefs = []

for C in C_test:
    lr_l1 = LogisticRegression(C=C, penalty='l1', solver='liblinear', random_state=42)
    lr_l1.fit(X_train, y_train)
    l1_coefs.append(lr_l1.coef_[0].copy())
    
    lr_l2 = LogisticRegression(C=C, penalty='l2', solver='lbfgs', random_state=42)
    lr_l2.fit(X_train, y_train)
    l2_coefs.append(lr_l2.coef_[0].copy())

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot L1
ax1 = axes[0]
for i, feat in enumerate(['x₁', 'x₂']):
    coefs = [l1_coefs[j][i] for j in range(len(C_test))]
    ax1.plot(C_test, coefs, 'o-', linewidth=2, markersize=10, label=feat)
ax1.set_xscale('log')
ax1.axhline(y=0, color='gray', linestyle='--', alpha=0.5)
ax1.set_xlabel('C (inverse regularization)', fontsize=12)
ax1.set_ylabel('Coefficient', fontsize=12)
ax1.set_title('L1 (Lasso): Can become EXACTLY ZERO', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

# Plot L2
ax2 = axes[1]
for i, feat in enumerate(['x₁', 'x₂']):
    coefs = [l2_coefs[j][i] for j in range(len(C_test))]
    ax2.plot(C_test, coefs, 'o-', linewidth=2, markersize=10, label=feat)
ax2.set_xscale('log')
ax2.axhline(y=0, color='gray', linestyle='--', alpha=0.5)
ax2.set_xlabel('C (inverse regularization)', fontsize=12)
ax2.set_ylabel('Coefficient', fontsize=12)
ax2.set_title('L2 (Ridge): Shrinks but NEVER zero', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("""
WHEN TO USE WHICH:
─────────────────────────────────────────────────────────────────────
✓ Use L2 (default) when:
  • You want to keep all features
  • Features are all potentially relevant
  • You want stable coefficient estimates

✓ Use L1 when:
  • You have MANY features
  • You suspect some features are IRRELEVANT  
  • You want automatic feature selection
  • You want a simpler, interpretable model
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 13: GridSearchCV - Automated Hyperparameter Tuning]
print("\n" + "=" * 70)
print("🔍 CELL 13: GridSearchCV - Find Optimal Parameters Automatically")
print("=" * 70)

print("""
What is GridSearchCV?
─────────────────────────────────────────────────────────────────────
• Systematically tests ALL combinations of parameters
• Uses CROSS-VALIDATION to evaluate each combination
• Returns the BEST parameters that generalize well

Why use it?
  ✓ Removes guesswork
  ✓ More reliable than manual tuning
  ✓ Prevents overfitting to test set
─────────────────────────────────────────────────────────────────────
""")

# Define parameter grid
param_grid = {
    'C': [0.01, 0.1, 1, 10, 100],
    'penalty': ['l1', 'l2'],
    'solver': ['liblinear']  # Supports both l1 and l2
}

total_combos = len(param_grid['C']) * len(param_grid['penalty'])
print(f"Parameter Grid:")
for k, v in param_grid.items():
    print(f"  {k}: {v}")
print(f"\nTotal combinations: {total_combos}")
print(f"With 5-fold CV: {total_combos * 5} model fits")

print("\nRunning GridSearchCV...")
grid_search = GridSearchCV(
    LogisticRegression(random_state=42, max_iter=1000),
    param_grid,
    cv=5,
    scoring='f1',
    n_jobs=-1,
    verbose=0,
    return_train_score=True
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
best_model = grid_search.best_estimator_
y_pred_best = best_model.predict(X_test)
y_proba_best = best_model.predict_proba(X_test)[:, 1]

print("\n" + "-" * 50)
print("BEST MODEL TEST PERFORMANCE:")
print("-" * 50)
print(f"  Accuracy:  {accuracy_score(y_test, y_pred_best):.4f}")
print(f"  Precision: {precision_score(y_test, y_pred_best):.4f}")
print(f"  Recall:    {recall_score(y_test, y_pred_best):.4f}")
print(f"  F1 Score:  {f1_score(y_test, y_pred_best):.4f}")
print(f"  ROC-AUC:   {roc_auc_score(y_test, y_proba_best):.4f}")

# Visualize grid search results
results_gs = pd.DataFrame(grid_search.cv_results_)

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Heatmap of results
ax1 = axes[0]
pivot = results_gs.pivot_table(values='mean_test_score', index='param_penalty', columns='param_C')
sns.heatmap(pivot, annot=True, fmt='.3f', cmap='RdYlGn', ax=ax1, cbar_kws={'label': 'F1 Score'})
ax1.set_title('GridSearchCV Results\n(CV F1 Score)', fontsize=14, fontweight='bold')

# Plot 2: Performance by C
ax2 = axes[1]
for penalty in ['l1', 'l2']:
    mask = results_gs['param_penalty'] == penalty
    ax2.semilogx(results_gs.loc[mask, 'param_C'], results_gs.loc[mask, 'mean_test_score'], 
                'o-', linewidth=2, markersize=8, label=f'{penalty} penalty')
    ax2.fill_between(results_gs.loc[mask, 'param_C'].values,
                    results_gs.loc[mask, 'mean_test_score'] - results_gs.loc[mask, 'std_test_score'],
                    results_gs.loc[mask, 'mean_test_score'] + results_gs.loc[mask, 'std_test_score'],
                    alpha=0.2)
ax2.set_xlabel('C', fontsize=12)
ax2.set_ylabel('CV F1 Score', fontsize=12)
ax2.set_title('Performance by Regularization', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# %% [CELL 14: Learning Curves - Do You Need More Data?]
print("\n" + "=" * 70)
print("📈 CELL 14: Learning Curves - Diagnose Your Model")
print("=" * 70)

print("""
What are Learning Curves?
─────────────────────────────────────────────────────────────────────
• Show how performance changes with TRAINING SET SIZE
• Help diagnose underfitting vs overfitting
• Tell you if MORE DATA would help

How to interpret:
  • Both curves HIGH and converged → Good model
  • Both curves LOW → Underfitting (model too simple)
  • Large GAP → Overfitting (need more data or regularization)
  • Curves still rising → More data would help
─────────────────────────────────────────────────────────────────────
""")

# Calculate learning curves
train_sizes, train_scores, test_scores = learning_curve(
    best_model, X, y,
    train_sizes=np.linspace(0.1, 1.0, 10),
    cv=5, scoring='f1', n_jobs=-1
)

train_mean = train_scores.mean(axis=1)
train_std = train_scores.std(axis=1)
test_mean = test_scores.mean(axis=1)
test_std = test_scores.std(axis=1)

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Learning Curve
ax1 = axes[0]
ax1.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.2, color='blue')
ax1.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.2, color='orange')
ax1.plot(train_sizes, train_mean, 'b-o', linewidth=2, markersize=6, label='Training Score')
ax1.plot(train_sizes, test_mean, 'orange', marker='s', linewidth=2, markersize=6, label='CV Score')

ax1.set_xlabel('Training Set Size', fontsize=12)
ax1.set_ylabel('F1 Score', fontsize=12)
ax1.set_title('Learning Curve', fontsize=14, fontweight='bold')
ax1.legend(loc='lower right')
ax1.grid(True, alpha=0.3)

# Plot 2: Diagnosis guide
ax2 = axes[1]
ax2.axis('off')

gap = train_mean[-1] - test_mean[-1]
diagnosis = ""
if gap < 0.05 and test_mean[-1] > 0.8:
    diagnosis = "✅ GOOD FIT\nBoth scores high, small gap\n→ Model generalizes well"
    color = 'green'
elif gap > 0.15:
    diagnosis = "⚠️ OVERFITTING\nLarge gap between train/test\n→ Try: More data, more regularization"
    color = 'red'
elif test_mean[-1] < 0.6:
    diagnosis = "⚠️ UNDERFITTING\nBoth scores low\n→ Try: More features, less regularization"
    color = 'orange'
else:
    diagnosis = "✓ ACCEPTABLE\nModel is reasonably good\n→ May improve with tuning"
    color = 'blue'

ax2.text(0.5, 0.7, "YOUR MODEL DIAGNOSIS:", fontsize=16, fontweight='bold', ha='center', transform=ax2.transAxes)
ax2.text(0.5, 0.5, diagnosis, fontsize=14, ha='center', transform=ax2.transAxes,
        bbox=dict(boxstyle='round', facecolor=color, alpha=0.2))
ax2.text(0.5, 0.2, f"Final Train Score: {train_mean[-1]:.4f}\nFinal CV Score: {test_mean[-1]:.4f}\nGap: {gap:.4f}",
        fontsize=12, ha='center', transform=ax2.transAxes, family='monospace')

plt.tight_layout()
plt.show()

# %% [CELL 15: Odds Ratios - Interpret Coefficients]
print("\n" + "=" * 70)
print("📊 CELL 15: Odds Ratios - Making Coefficients Meaningful")
print("=" * 70)

print("""
What are Odds Ratios?
─────────────────────────────────────────────────────────────────────
• Coefficients are in LOG-ODDS scale (hard to interpret)
• Convert to ODDS RATIO: OR = exp(β)
• Odds Ratio shows multiplicative effect on odds

Interpretation:
  OR = 1.0 → No effect
  OR > 1.0 → INCREASES odds (by (OR-1)×100 percent)
  OR < 1.0 → DECREASES odds (by (1-OR)×100 percent)
  
Example:
  β = 0.5 → OR = exp(0.5) = 1.65
  → 1-unit increase = 65% higher odds of class 1
─────────────────────────────────────────────────────────────────────
""")

# Get coefficients from best model
coefs = best_model.coef_[0]
intercept = best_model.intercept_[0]
odds_ratios = np.exp(coefs)
feature_names = ['x₁', 'x₂']

print("\nCOEFFICIENT ANALYSIS:")
print("-" * 60)
print(f"{'Feature':<15} {'Coef (β)':<12} {'Odds Ratio':<12} {'Interpretation'}")
print("-" * 60)

for name, coef, or_val in zip(feature_names, coefs, odds_ratios):
    if or_val > 1:
        interp = f"+{(or_val-1)*100:.1f}% odds per unit ↑"
    else:
        interp = f"-{(1-or_val)*100:.1f}% odds per unit ↑"
    print(f"{name:<15} {coef:<12.4f} {or_val:<12.4f} {interp}")

print(f"\nIntercept: {intercept:.4f}")

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(12, 5))

# Plot 1: Coefficients
ax1 = axes[0]
colors = ['green' if c > 0 else 'red' for c in coefs]
bars1 = ax1.barh(feature_names, coefs, color=colors, alpha=0.7, edgecolor='black', height=0.5)
ax1.axvline(x=0, color='black', linestyle='-', linewidth=2)
ax1.set_xlabel('Coefficient (β)', fontsize=12)
ax1.set_title('Raw Coefficients\n(Log-Odds Scale)', fontsize=14, fontweight='bold')
for bar, val in zip(bars1, coefs):
    ax1.text(val + 0.05 * np.sign(val), bar.get_y() + bar.get_height()/2, 
            f'{val:.3f}', va='center', fontsize=11, fontweight='bold')
ax1.grid(True, alpha=0.3, axis='x')

# Plot 2: Odds Ratios
ax2 = axes[1]
colors = ['green' if or_val > 1 else 'red' for or_val in odds_ratios]
bars2 = ax2.barh(feature_names, odds_ratios, color=colors, alpha=0.7, edgecolor='black', height=0.5)
ax2.axvline(x=1, color='black', linestyle='--', linewidth=2, label='No Effect')
ax2.set_xlabel('Odds Ratio = exp(β)', fontsize=12)
ax2.set_title('Odds Ratios\n(Interpretable Scale)', fontsize=14, fontweight='bold')
for bar, val in zip(bars2, odds_ratios):
    ax2.text(val + 0.05, bar.get_y() + bar.get_height()/2, 
            f'{val:.3f}', va='center', fontsize=11, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3, axis='x')

plt.tight_layout()
plt.show()

# %% [CELL 16: Common Mistakes to Avoid]
print("\n" + "=" * 70)
print("🚫 CELL 16: Common Mistakes to Avoid")
print("=" * 70)

print("""
╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #1: FORGETTING TO SCALE FEATURES                        ║
╠═══════════════════════════════════════════════════════════════════╣
║  Logistic regression uses gradient descent                        ║
║  Unscaled features → slow convergence, poor performance           ║
║                                                                   ║
║  ✓ ALWAYS use StandardScaler or MinMaxScaler                     ║
║  ✓ fit_transform on train, transform on test                     ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #2: USING RANDOM SPLIT FOR TIME-SERIES                  ║
╠═══════════════════════════════════════════════════════════════════╣
║  Random split causes LOOK-AHEAD BIAS                              ║
║  Model "sees" future → Great backtest, fails live!                ║
║                                                                   ║
║  ✓ Use TIME-BASED split for trading data                         ║
║  ✓ Train on past, test on future                                 ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #3: IGNORING CLASS IMBALANCE                            ║
╠═══════════════════════════════════════════════════════════════════╣
║  If 90% losses, model predicts "loss" always → 90% accuracy!      ║
║  But completely USELESS for trading                               ║
║                                                                   ║
║  ✓ Use class_weight='balanced'                                   ║
║  ✓ Focus on F1/ROC-AUC, not just accuracy                        ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #4: DATA LEAKAGE                                        ║
╠═══════════════════════════════════════════════════════════════════╣
║  Using features not available at prediction time                  ║
║  Example: profit_ratio, exit_price, trade_duration                ║
║                                                                   ║
║  ✓ Only use features available at ENTRY time                     ║
║  ✓ Technical indicators, price data = OK                         ║
║  ✓ Outcome variables = NEVER                                     ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #5: NOT CHECKING FOR OVERFITTING                        ║
╠═══════════════════════════════════════════════════════════════════╣
║  Train acc = 95%, Test acc = 55% → OVERFITTING!                   ║
║  Model memorized training data                                    ║
║                                                                   ║
║  ✓ Always compare train vs test scores                           ║
║  ✓ Use cross-validation                                          ║
║  ✓ Increase regularization if needed                             ║
╚═══════════════════════════════════════════════════════════════════╝
""")

# Demonstrate scaling importance
print("\n" + "-" * 70)
print("DEMONSTRATION: Why Scaling Matters")
print("-" * 70)

# Create unscaled version with different magnitudes
X_unscaled = X.copy()
X_unscaled[:, 0] = X_unscaled[:, 0] * 1000  # Scale feature 1 by 1000x

X_train_u, X_test_u, y_train_u, y_test_u = train_test_split(X_unscaled, y, test_size=0.3, random_state=42)

# Train without scaling
lr_unscaled = LogisticRegression(random_state=42, max_iter=1000)
lr_unscaled.fit(X_train_u, y_train_u)
acc_unscaled = accuracy_score(y_test_u, lr_unscaled.predict(X_test_u))

# Train with scaling
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train_u)
X_test_s = scaler.transform(X_test_u)

lr_scaled = LogisticRegression(random_state=42, max_iter=1000)
lr_scaled.fit(X_train_s, y_train_u)
acc_scaled = accuracy_score(y_test_u, lr_scaled.predict(X_test_s))

print(f"Without scaling: Accuracy = {acc_unscaled:.4f}")
print(f"With scaling:    Accuracy = {acc_scaled:.4f}")
print(f"Improvement:     {(acc_scaled - acc_unscaled)*100:+.1f}%")

# %% [CELL 17: Load Real Trading Data]
print("\n" + "=" * 70)
print("💹 CELL 17: Load Real Trading Data")
print("=" * 70)

try:
    df_trading = pd.read_feather('/allah/data/ml/atr_tp-1124-2038.feather')
    print(f"✓ Dataset loaded: {df_trading.shape}")
    
    # Filter for trades only
    trades_mask = df_trading['profit_ratio'].notna()
    df_trades = df_trading[trades_mask].copy()
    
    # Create binary label
    df_trades['is_profitable'] = (df_trades['profit_ratio'] > 0).astype(int)
    
    print(f"\nTotal trades: {len(df_trades)}")
    print(f"Profitable:   {(df_trades['is_profitable'] == 1).sum()} ({(df_trades['is_profitable'] == 1).sum()/len(df_trades)*100:.1f}%)")
    print(f"Loss:         {(df_trades['is_profitable'] == 0).sum()} ({(df_trades['is_profitable'] == 0).sum()/len(df_trades)*100:.1f}%)")
    
    TRADING_DATA_AVAILABLE = True
except:
    print("⚠ Trading dataset not found. Skipping real-world examples.")
    TRADING_DATA_AVAILABLE = False

# %% [CELL 18: Train on Trading Data]
if TRADING_DATA_AVAILABLE:
    print("\n" + "=" * 70)
    print("🚀 CELL 18: Full Pipeline on Trading Data")
    print("=" * 70)
    
    # Define features (technical indicators)
    indicator_cols = [col for col in df_trades.columns if any(x in col.lower() for x in 
        ['rsi', 'macd', 'ema', 'sma', 'atr', 'bb_', 'stoch', 'cci', 'adx', 'obv', 'mfi', 
         'roc', 'momentum', 'willr', 'sar', 'plus_di', 'minus_di', 'aroon', 'cmo', 'trix', 'apo', 'ultosc'])]
    
    available_cols = [c for c in indicator_cols if c in df_trades.columns]
    print(f"Available features: {len(available_cols)}")
    
    if len(available_cols) > 5:
        # Prepare data
        X_t = df_trades[available_cols].copy()
        y_t = df_trades['is_profitable'].copy()
        
        # Handle NaNs
        X_t = X_t.ffill().bfill().fillna(0)
        
        # Time-based split
        split_idx = int(len(X_t) * 0.8)
        X_train_t, X_test_t = X_t.iloc[:split_idx], X_t.iloc[split_idx:]
        y_train_t, y_test_t = y_t.iloc[:split_idx], y_t.iloc[split_idx:]
        
        print(f"Train: {len(X_train_t)} | Test: {len(X_test_t)}")
        
        # Scale
        scaler_t = StandardScaler()
        X_train_ts = scaler_t.fit_transform(X_train_t)
        X_test_ts = scaler_t.transform(X_test_t)
        
        # Train
        print("\nTraining logistic regression...")
        lr_trading = LogisticRegression(C=1.0, class_weight='balanced', random_state=42, max_iter=1000)
        lr_trading.fit(X_train_ts, y_train_t)
        
        # Evaluate
        y_pred_t = lr_trading.predict(X_test_ts)
        y_proba_t = lr_trading.predict_proba(X_test_ts)[:, 1]
        
        print("\n" + "-" * 50)
        print("TRADING MODEL PERFORMANCE:")
        print("-" * 50)
        print(f"Accuracy:  {accuracy_score(y_test_t, y_pred_t):.4f}")
        print(f"Precision: {precision_score(y_test_t, y_pred_t):.4f}")
        print(f"Recall:    {recall_score(y_test_t, y_pred_t):.4f}")
        print(f"F1 Score:  {f1_score(y_test_t, y_pred_t):.4f}")
        print(f"ROC-AUC:   {roc_auc_score(y_test_t, y_proba_t):.4f}")
        
        # Feature importance
        print("\n" + "-" * 50)
        print("TOP 10 IMPORTANT FEATURES:")
        print("-" * 50)
        importance_df = pd.DataFrame({
            'Feature': available_cols,
            'Coefficient': lr_trading.coef_[0],
            'Odds Ratio': np.exp(lr_trading.coef_[0])
        }).sort_values('Coefficient', key=abs, ascending=False)
        
        for i, row in importance_df.head(10).iterrows():
            direction = "↑ profit" if row['Coefficient'] > 0 else "↓ profit"
            print(f"  {row['Feature']:<20} β={row['Coefficient']:+.4f}  OR={row['Odds Ratio']:.3f}  ({direction})")
        
        # Visualization
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        # ROC Curve
        ax1 = axes[0]
        fpr_t, tpr_t, _ = roc_curve(y_test_t, y_proba_t)
        auc_t = roc_auc_score(y_test_t, y_proba_t)
        ax1.plot(fpr_t, tpr_t, 'b-', linewidth=2, label=f'LogReg (AUC={auc_t:.3f})')
        ax1.plot([0,1], [0,1], 'r--', linewidth=2, label='Random')
        ax1.set_xlabel('FPR')
        ax1.set_ylabel('TPR')
        ax1.set_title('ROC Curve - Trading Model', fontweight='bold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Feature importance
        ax2 = axes[1]
        top10 = importance_df.head(10)
        colors = ['green' if c > 0 else 'red' for c in top10['Coefficient']]
        ax2.barh(range(len(top10)), top10['Coefficient'], color=colors, alpha=0.7, edgecolor='black')
        ax2.set_yticks(range(len(top10)))
        ax2.set_yticklabels(top10['Feature'])
        ax2.axvline(x=0, color='black', linestyle='-')
        ax2.set_xlabel('Coefficient')
        ax2.set_title('Top 10 Features', fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        plt.show()

# %% [CELL 19: Save & Load Models]
print("\n" + "=" * 70)
print("💾 CELL 19: Save & Load Models for Production")
print("=" * 70)

print("""
Why save models?
─────────────────────────────────────────────────────────────────────
• Avoid retraining every time
• Deploy to production/live trading
• Version control your models
• Share with team
─────────────────────────────────────────────────────────────────────
""")

import os
model_dir = '/allah/blue/freq/project/ml_datasets/saved_models'
os.makedirs(model_dir, exist_ok=True)

# Save
model_path = f'{model_dir}/logreg_demo.joblib'
joblib.dump(best_model, model_path)
print(f"✓ Model saved: {model_path}")

# Load
loaded = joblib.load(model_path)
print(f"✓ Model loaded and verified!")

print("""
PRODUCTION PATTERN:
─────────────────────────────────────────────────────────────────────
# TRAINING (once)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_train)
model = LogisticRegression()
model.fit(X_scaled, y_train)
joblib.dump(model, 'model.joblib')
joblib.dump(scaler, 'scaler.joblib')  # Save scaler too!

# INFERENCE (production)
model = joblib.load('model.joblib')
scaler = joblib.load('scaler.joblib')
X_new_scaled = scaler.transform(X_new)
predictions = model.predict(X_new_scaled)
probabilities = model.predict_proba(X_new_scaled)[:, 1]
─────────────────────────────────────────────────────────────────────
⚠️ ALWAYS save the scaler with the model!
""")

# %% [CELL 20: Final Summary]
print("\n" + "=" * 70)
print("🎓 CELL 20: Course Complete - Key Takeaways")
print("=" * 70)

print("""
╔═══════════════════════════════════════════════════════════════════╗
║                    LOGISTIC REGRESSION SUMMARY                    ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  WHAT IT IS:                                                      ║
║  • Linear classifier for BINARY outcomes                          ║
║  • Uses sigmoid to output probabilities                           ║
║  • Decision boundary is a straight line/hyperplane                ║
║                                                                   ║
║  KEY HYPERPARAMETERS:                                             ║
║  • C: Regularization (small=simple, large=complex)                ║
║  • penalty: L1 (sparse) or L2 (shrink)                           ║
║  • class_weight: 'balanced' for imbalanced data                   ║
║                                                                   ║
║  EVALUATION METRICS:                                              ║
║  • Accuracy: Overall correctness (balanced data only)             ║
║  • Precision: Don't cry wolf (minimize FP)                        ║
║  • Recall: Don't miss anything (minimize FN)                      ║
║  • F1: Balance precision & recall                                 ║
║  • ROC-AUC: Overall ranking ability                               ║
║                                                                   ║
║  CRITICAL STEPS:                                                  ║
║  1. Scale features (StandardScaler)                               ║
║  2. Time-based split for trading                                  ║
║  3. Handle class imbalance                                        ║
║  4. Tune with GridSearchCV                                        ║
║  5. Compare train vs test (check overfitting)                     ║
║                                                                   ║
║  WHEN TO USE:                                                     ║
║  ✓ Binary classification                                         ║
║  ✓ Need probability estimates                                    ║
║  ✓ Want interpretable coefficients                               ║
║  ✓ As baseline before complex models                             ║
║                                                                   ║
║  WHEN NOT TO USE:                                                 ║
║  ✗ Non-linear decision boundaries                                ║
║  ✗ Complex feature interactions                                  ║
║  → Try: Random Forest, XGBoost, Neural Networks                  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

🚀 You're now ready to apply logistic regression to real problems!
   Next: Try Random Forest or XGBoost for comparison.
""")
print("=" * 70)
