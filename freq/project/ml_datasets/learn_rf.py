# %% [CELL 1: Course Overview]
"""
================================================================================
RANDOM FOREST - Complete Educational Guide
================================================================================

COURSE OUTLINE:
───────────────────────────────────────────────────────────────────────────────
PART 1: FOUNDATIONS
  Cell 1-2:   Setup & Introduction
  Cell 3-4:   Decision Trees - The Building Block
  Cell 5-6:   How Random Forest Works (Bagging + Feature Randomness)

PART 2: TRAINING & PREDICTION
  Cell 7-8:   Your First Random Forest Model
  Cell 9-10:  Feature Importance - Why It Matters

PART 3: HYPERPARAMETERS
  Cell 11-12: n_estimators - Number of Trees
  Cell 13-14: max_depth - Tree Complexity
  Cell 15-16: min_samples_split & min_samples_leaf
  Cell 17-18: max_features - Feature Randomness
  Cell 19-20: GridSearchCV - Finding Optimal Parameters

PART 4: EVALUATION & DIAGNOSTICS
  Cell 21-22: Out-of-Bag (OOB) Score
  Cell 23-24: Learning Curves & Overfitting Detection

PART 5: REAL-WORLD APPLICATION
  Cell 25-26: Trading Data Preparation
  Cell 27-28: Full Pipeline with Evaluation
  Cell 29-30: Feature Importance Analysis

PART 6: PRODUCTION & ADVANCED
  Cell 31-32: Common Mistakes to Avoid
  Cell 33-34: Save/Load Models
  Cell 35:    Summary & Next Steps
================================================================================
"""

print("=" * 70)
print("🌲 RANDOM FOREST - Complete Educational Guide")
print("=" * 70)
print("""
What you'll learn:
  ✓ How Random Forest works (ensemble of decision trees)
  ✓ Why it's so powerful (variance reduction through bagging)
  ✓ All important hyperparameters and how to tune them
  ✓ Feature importance interpretation
  ✓ Out-of-Bag evaluation (free validation!)
  ✓ Real-world trading application

Prerequisites:
  • Basic Python & NumPy
  • Understanding of train/test splits
  • Basic understanding of decision trees (we'll review)
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier, plot_tree
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

print("✓ All libraries loaded!")

# %% [CELL 3: What is Random Forest?]
print("\n" + "=" * 70)
print("📖 CELL 3: What is Random Forest?")
print("=" * 70)

print("""
┌─────────────────────────────────────────────────────────────────────┐
│  RANDOM FOREST IN ONE SENTENCE:                                     │
│  An ensemble of decision trees that vote together for predictions   │
└─────────────────────────────────────────────────────────────────────┘

The Key Idea: "Wisdom of the Crowd"
  • Single decision tree → Prone to overfitting, high variance
  • Many trees voting together → More stable, better generalization
  
How it achieves diversity:
  1. BAGGING (Bootstrap Aggregating):
     • Each tree trained on a random sample WITH replacement
     • ~63% unique samples, ~37% duplicates per tree
     
  2. FEATURE RANDOMNESS:
     • At each split, only consider a random subset of features
     • Forces trees to be different from each other
     
  3. VOTING:
     • Classification: Majority vote
     • Regression: Average prediction

Why "Random"?
  • Random bootstrap samples
  • Random feature subsets at each split
  
Why "Forest"?
  • Collection of many decision trees
""")

# %% [CELL 4: Decision Trees - The Building Block]
print("\n" + "=" * 70)
print("🌳 CELL 4: Decision Trees - Understanding the Building Block")
print("=" * 70)

print("""
Before understanding Random Forest, let's understand a SINGLE tree:

DECISION TREE BASICS:
─────────────────────────────────────────────────────────────────────
A tree makes decisions by asking yes/no questions:
  
  "Is RSI > 70?"
       /    \\
     YES     NO
      |       |
  "Is MACD    "Is Volume
   positive?"   > average?"
    /   \\        /    \\
  ...   ...    ...    ...

Key Concepts:
  • NODE: A decision point (question)
  • LEAF: Final prediction (no more questions)
  • DEPTH: Maximum levels of questions
  • SPLIT: Dividing data based on a feature threshold
  
How splits are chosen:
  • Find the feature & threshold that best separates classes
  • Measured by GINI IMPURITY or ENTROPY (information gain)
─────────────────────────────────────────────────────────────────────
""")

# Create simple dataset
np.random.seed(42)
X_demo = np.random.randn(200, 2)
y_demo = ((X_demo[:, 0] + X_demo[:, 1]) > 0).astype(int)

# Train a single tree
single_tree = DecisionTreeClassifier(max_depth=3, random_state=42)
single_tree.fit(X_demo, y_demo)

# Visualize the tree structure
fig, axes = plt.subplots(1, 2, figsize=(16, 6))

# Plot 1: Tree visualization
ax1 = axes[0]
plot_tree(single_tree, feature_names=['x₁', 'x₂'], class_names=['Class 0', 'Class 1'],
          filled=True, rounded=True, ax=ax1, fontsize=9)
ax1.set_title('Decision Tree Structure (max_depth=3)', fontsize=14, fontweight='bold')

# Plot 2: Decision boundary
ax2 = axes[1]
h = 0.02
x_min, x_max = X_demo[:, 0].min() - 0.5, X_demo[:, 0].max() + 0.5
y_min, y_max = X_demo[:, 1].min() - 0.5, X_demo[:, 1].max() + 0.5
xx, yy = np.meshgrid(np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))
Z = single_tree.predict(np.c_[xx.ravel(), yy.ravel()]).reshape(xx.shape)

ax2.contourf(xx, yy, Z, alpha=0.3, cmap='RdYlGn')
ax2.scatter(X_demo[y_demo == 0, 0], X_demo[y_demo == 0, 1], c='#ff6b6b', 
           label='Class 0', edgecolors='k', s=50, alpha=0.7)
ax2.scatter(X_demo[y_demo == 1, 0], X_demo[y_demo == 1, 1], c='#51cf66', 
           label='Class 1', edgecolors='k', s=50, alpha=0.7)
ax2.set_xlabel('Feature x₁', fontsize=12)
ax2.set_ylabel('Feature x₂', fontsize=12)
ax2.set_title('Decision Boundary (Rectangular Regions!)', fontsize=14, fontweight='bold')
ax2.legend()

plt.tight_layout()
plt.show()

print("""
KEY INSIGHT: Decision trees create RECTANGULAR decision boundaries
─────────────────────────────────────────────────────────────────────
• Each split is perpendicular to a feature axis
• This is a limitation - can't capture diagonal patterns efficiently
• Deep trees can approximate any boundary (but may overfit)
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 5: Why Single Trees Fail - The Overfitting Problem]
print("\n" + "=" * 70)
print("⚠️ CELL 5: Why Single Trees Fail - The Overfitting Problem")
print("=" * 70)

print("""
The Problem with Single Decision Trees:
─────────────────────────────────────────────────────────────────────
1. HIGH VARIANCE: Small changes in data → Very different trees
2. OVERFITTING: Deep trees memorize training data, fail on new data
3. UNSTABLE: Sensitive to outliers and noise
─────────────────────────────────────────────────────────────────────
""")

# Demonstrate overfitting
X_train_d, X_test_d, y_train_d, y_test_d = train_test_split(X_demo, y_demo, test_size=0.3, random_state=42)

depths = [1, 3, 5, 10, 20, None]
train_accs = []
test_accs = []

for d in depths:
    tree = DecisionTreeClassifier(max_depth=d, random_state=42)
    tree.fit(X_train_d, y_train_d)
    train_accs.append(accuracy_score(y_train_d, tree.predict(X_train_d)))
    test_accs.append(accuracy_score(y_test_d, tree.predict(X_test_d)))

# Visualize
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Accuracy vs Depth
ax1 = axes[0]
x_labels = [str(d) if d else '∞' for d in depths]
x_pos = range(len(depths))
ax1.plot(x_pos, train_accs, 'b-o', linewidth=2, markersize=10, label='Train Accuracy')
ax1.plot(x_pos, test_accs, 'r-s', linewidth=2, markersize=10, label='Test Accuracy')
ax1.fill_between(x_pos, train_accs, test_accs, alpha=0.2, color='gray')
ax1.set_xticks(x_pos)
ax1.set_xticklabels(x_labels)
ax1.set_xlabel('Max Depth', fontsize=12)
ax1.set_ylabel('Accuracy', fontsize=12)
ax1.set_title('Single Tree: Train vs Test Accuracy\n(Gap = Overfitting)', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

# Annotations
ax1.annotate('Underfitting\n(too simple)', xy=(0, test_accs[0]), xytext=(0.5, test_accs[0]-0.1),
            arrowprops=dict(arrowstyle='->', color='orange'), fontsize=9)
ax1.annotate('Overfitting\n(too complex)', xy=(5, train_accs[5]), xytext=(4, train_accs[5]-0.05),
            arrowprops=dict(arrowstyle='->', color='red'), fontsize=9)

# Plot 2: Variance demonstration
ax2 = axes[1]
# Train multiple trees on slightly different samples
n_trees = 10
tree_preds = []

for i in range(n_trees):
    # Bootstrap sample
    idx = np.random.choice(len(X_train_d), len(X_train_d), replace=True)
    tree = DecisionTreeClassifier(max_depth=5, random_state=i)
    tree.fit(X_train_d[idx], y_train_d.iloc[idx] if hasattr(y_train_d, 'iloc') else y_train_d[idx])
    tree_preds.append(tree.predict(X_test_d))

# Calculate agreement
tree_preds = np.array(tree_preds)
agreement = (tree_preds == tree_preds[0]).mean(axis=0)

ax2.hist(agreement, bins=20, edgecolor='black', alpha=0.7, color='steelblue')
ax2.axvline(x=agreement.mean(), color='red', linestyle='--', linewidth=2, 
           label=f'Mean agreement: {agreement.mean():.2f}')
ax2.set_xlabel('Agreement Rate Across Trees', fontsize=12)
ax2.set_ylabel('Count', fontsize=12)
ax2.set_title(f'High Variance: {n_trees} Trees Trained on Different Samples\nOften Disagree!', 
             fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("""
THE SOLUTION: RANDOM FOREST
─────────────────────────────────────────────────────────────────────
• Train MANY trees on different bootstrap samples
• Average their predictions (reduces variance)
• Inject more randomness with feature subsets
• Result: More stable, better generalization
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 6: How Random Forest Works - Visual Explanation]
print("\n" + "=" * 70)
print("🌲🌲🌲 CELL 6: How Random Forest Works")
print("=" * 70)

print("""
RANDOM FOREST ALGORITHM:
─────────────────────────────────────────────────────────────────────
For b = 1 to B (number of trees):
  1. Draw bootstrap sample from training data
  2. Grow tree on bootstrap sample:
     - At each node, randomly select m features (m < total features)
     - Find best split among those m features
     - Split node into two child nodes
     - Repeat until stopping criteria
  3. Store the tree

Prediction:
  • Classification: Majority vote across all trees
  • Regression: Average prediction across all trees
─────────────────────────────────────────────────────────────────────
""")

# Create visual demonstration
fig, axes = plt.subplots(2, 3, figsize=(16, 10))

# Create more complex dataset for visualization
X_complex, y_complex = make_moons(n_samples=300, noise=0.3, random_state=42)
X_train_c, X_test_c, y_train_c, y_test_c = train_test_split(X_complex, y_complex, test_size=0.3, random_state=42)

# Plot individual trees with different bootstraps
h = 0.02
x_min, x_max = X_complex[:, 0].min() - 0.5, X_complex[:, 0].max() + 0.5
y_min, y_max = X_complex[:, 1].min() - 0.5, X_complex[:, 1].max() + 0.5
xx, yy = np.meshgrid(np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))

individual_preds = []

for i in range(3):
    ax = axes[0, i]
    # Bootstrap sample
    np.random.seed(i)
    idx = np.random.choice(len(X_train_c), len(X_train_c), replace=True)
    
    tree = DecisionTreeClassifier(max_depth=5, max_features='sqrt', random_state=i)
    tree.fit(X_train_c[idx], y_train_c[idx])
    
    Z = tree.predict(np.c_[xx.ravel(), yy.ravel()]).reshape(xx.shape)
    individual_preds.append(tree.predict_proba(np.c_[xx.ravel(), yy.ravel()])[:, 1])
    
    ax.contourf(xx, yy, Z, alpha=0.3, cmap='RdYlGn')
    ax.scatter(X_train_c[idx][y_train_c[idx] == 0, 0], X_train_c[idx][y_train_c[idx] == 0, 1], 
              c='#ff6b6b', s=30, alpha=0.6, edgecolors='k')
    ax.scatter(X_train_c[idx][y_train_c[idx] == 1, 0], X_train_c[idx][y_train_c[idx] == 1, 1], 
              c='#51cf66', s=30, alpha=0.6, edgecolors='k')
    ax.set_title(f'Tree {i+1}\n(Different Bootstrap Sample)', fontsize=12, fontweight='bold')
    ax.set_xlabel('x₁')
    ax.set_ylabel('x₂')

# Train full Random Forest
rf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
rf.fit(X_train_c, y_train_c)

# Plot 4: Random Forest combined
ax4 = axes[1, 0]
Z_rf = rf.predict(np.c_[xx.ravel(), yy.ravel()]).reshape(xx.shape)
ax4.contourf(xx, yy, Z_rf, alpha=0.3, cmap='RdYlGn')
ax4.scatter(X_test_c[y_test_c == 0, 0], X_test_c[y_test_c == 0, 1], c='#ff6b6b', 
           s=50, edgecolors='k', label='Class 0')
ax4.scatter(X_test_c[y_test_c == 1, 0], X_test_c[y_test_c == 1, 1], c='#51cf66', 
           s=50, edgecolors='k', label='Class 1')
ax4.set_title('Random Forest (100 Trees)\nSmooth, Robust Boundary', fontsize=12, fontweight='bold')
ax4.legend()

# Plot 5: Probability heatmap
ax5 = axes[1, 1]
Z_proba = rf.predict_proba(np.c_[xx.ravel(), yy.ravel()])[:, 1].reshape(xx.shape)
contour = ax5.contourf(xx, yy, Z_proba, levels=20, cmap='RdYlGn', alpha=0.8)
plt.colorbar(contour, ax=ax5, label='P(Class 1)')
ax5.contour(xx, yy, Z_proba, levels=[0.5], colors='black', linewidths=2)
ax5.set_title('Probability Surface\n(Uncertainty Visualization)', fontsize=12, fontweight='bold')

# Plot 6: Comparison
ax6 = axes[1, 2]
single_tree_deep = DecisionTreeClassifier(max_depth=10, random_state=42)
single_tree_deep.fit(X_train_c, y_train_c)

single_acc = accuracy_score(y_test_c, single_tree_deep.predict(X_test_c))
rf_acc = accuracy_score(y_test_c, rf.predict(X_test_c))

bars = ax6.bar(['Single Tree\n(depth=10)', 'Random Forest\n(100 trees)'], 
               [single_acc, rf_acc], color=['#ff6b6b', '#51cf66'], 
               edgecolor='black', linewidth=2, alpha=0.8)
ax6.set_ylabel('Test Accuracy', fontsize=12)
ax6.set_title('Performance Comparison', fontsize=12, fontweight='bold')
ax6.set_ylim([0, 1.1])

for bar, val in zip(bars, [single_acc, rf_acc]):
    ax6.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02, 
            f'{val:.3f}', ha='center', fontsize=14, fontweight='bold')

ax6.grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.show()

print("""
KEY INSIGHTS:
─────────────────────────────────────────────────────────────────────
1. Individual trees have DIFFERENT decision boundaries
2. Combined (voting) produces SMOOTHER, more ROBUST boundary
3. Handles non-linear patterns well
4. Usually better than a single deep tree
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 7: Create Dataset for Experiments]
print("\n" + "=" * 70)
print("🔬 CELL 7: Create Dataset for Experiments")
print("=" * 70)

# Create a more realistic dataset
np.random.seed(42)
n_samples = 1000
n_features = 10

X, y = make_classification(
    n_samples=n_samples,
    n_features=n_features,
    n_informative=6,
    n_redundant=2,
    n_clusters_per_class=2,
    flip_y=0.1,  # 10% noise
    random_state=42
)

feature_names = [f'Feature_{i}' for i in range(n_features)]

print(f"Dataset created:")
print(f"  Total samples: {n_samples}")
print(f"  Features: {n_features}")
print(f"  Class 0: {(y == 0).sum()} ({(y == 0).sum()/len(y)*100:.1f}%)")
print(f"  Class 1: {(y == 1).sum()} ({(y == 1).sum()/len(y)*100:.1f}%)")

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)
print(f"\nTrain: {len(X_train)} | Test: {len(X_test)}")

# %% [CELL 8: Train Your First Random Forest]
print("\n" + "=" * 70)
print("🚀 CELL 8: Train Your First Random Forest Model")
print("=" * 70)

print("""
STEP-BY-STEP PROCESS:
─────────────────────────────────────────────────────────────────────
Step 1: Create Random Forest with default parameters
Step 2: Fit on training data
Step 3: Make predictions
Step 4: Evaluate performance
─────────────────────────────────────────────────────────────────────
""")

# Step 1 & 2: Create and train
print("STEP 1-2: Create and Train Model")
print("-" * 50)

rf_model = RandomForestClassifier(
    n_estimators=100,    # Number of trees
    max_depth=10,        # Maximum tree depth
    random_state=42,     # Reproducibility
    n_jobs=-1            # Use all CPU cores
)

rf_model.fit(X_train, y_train)
print("✓ Model trained!")
print(f"  Number of trees: {rf_model.n_estimators}")
print(f"  Max depth: {rf_model.max_depth}")
print(f"  Features per split: {rf_model.max_features}")

# Step 3: Predict
print("\nSTEP 3: Make Predictions")
print("-" * 50)
y_pred = rf_model.predict(X_test)
y_proba = rf_model.predict_proba(X_test)[:, 1]

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

print(f"  Accuracy:  {acc:.4f} ← {acc*100:.1f}% predictions correct")
print(f"  Precision: {prec:.4f} ← Of predicted 1s, {prec*100:.1f}% actually 1")
print(f"  Recall:    {rec:.4f} ← Of actual 1s, found {rec*100:.1f}%")
print(f"  F1 Score:  {f1:.4f} ← Harmonic mean of precision & recall")
print(f"  ROC-AUC:   {auc:.4f} ← Overall ranking ability")

# Confusion matrix
print("\n" + "-" * 50)
print("CONFUSION MATRIX:")
print("-" * 50)
cm = confusion_matrix(y_test, y_pred)
print(f"\n              Predicted")
print(f"            Loss (0)  Win (1)")
print(f"Actual Loss   {cm[0][0]:5d}    {cm[0][1]:5d}")
print(f"Actual Win    {cm[1][0]:5d}    {cm[1][1]:5d}")

# %% [CELL 9: Feature Importance - Understanding the Model]
print("\n" + "=" * 70)
print("📊 CELL 9: Feature Importance - What Matters Most?")
print("=" * 70)

print("""
RANDOM FOREST FEATURE IMPORTANCE:
─────────────────────────────────────────────────────────────────────
How it's calculated (Gini Importance / Mean Decrease Impurity):
  • For each feature, sum the decrease in impurity across all trees
  • Weighted by the number of samples reaching each node
  • Normalized to sum to 1

Interpretation:
  • Higher value = More important for predictions
  • Values are RELATIVE, not absolute
  • Be cautious with correlated features (importance gets split)
─────────────────────────────────────────────────────────────────────
""")

# Get feature importances
importances = rf_model.feature_importances_
importance_df = pd.DataFrame({
    'Feature': feature_names,
    'Importance': importances
}).sort_values('Importance', ascending=False)

print("\nFeature Importance Ranking:")
print("-" * 40)
for i, row in importance_df.iterrows():
    bar = '█' * int(row['Importance'] * 50)
    print(f"{row['Feature']:<15} {row['Importance']:.4f} {bar}")

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Bar chart
ax1 = axes[0]
colors = plt.cm.RdYlGn(np.linspace(0.2, 0.8, len(importance_df)))[::-1]
bars = ax1.barh(importance_df['Feature'], importance_df['Importance'], 
                color=colors, edgecolor='black', alpha=0.8)
ax1.set_xlabel('Importance', fontsize=12)
ax1.set_title('Feature Importance (Gini/MDI)', fontsize=14, fontweight='bold')
ax1.invert_yaxis()

# Add values
for bar, val in zip(bars, importance_df['Importance']):
    ax1.text(val + 0.005, bar.get_y() + bar.get_height()/2, 
            f'{val:.3f}', va='center', fontsize=10)

ax1.grid(True, alpha=0.3, axis='x')

# Plot 2: Cumulative importance
ax2 = axes[1]
cumsum = importance_df['Importance'].cumsum()
ax2.plot(range(1, len(cumsum)+1), cumsum, 'b-o', linewidth=2, markersize=8)
ax2.axhline(y=0.9, color='r', linestyle='--', label='90% threshold')
ax2.fill_between(range(1, len(cumsum)+1), cumsum, alpha=0.3)

# Find 90% threshold
n_90 = (cumsum >= 0.9).argmax() + 1
ax2.axvline(x=n_90, color='g', linestyle='--', label=f'{n_90} features for 90%')
ax2.scatter([n_90], [cumsum.iloc[n_90-1]], color='red', s=100, zorder=5)

ax2.set_xlabel('Number of Features', fontsize=12)
ax2.set_ylabel('Cumulative Importance', fontsize=12)
ax2.set_title('Cumulative Feature Importance\n(Feature Selection Guide)', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print(f"""
INSIGHT: Top {n_90} features capture 90% of importance
─────────────────────────────────────────────────────────────────────
You could potentially use only {n_90} features and get similar performance!
This is useful for:
  • Reducing computation time
  • Improving model interpretability
  • Reducing overfitting risk
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 10: Permutation Importance - More Reliable]
print("\n" + "=" * 70)
print("🔀 CELL 10: Permutation Importance - A Better Measure")
print("=" * 70)

print("""
PERMUTATION IMPORTANCE:
─────────────────────────────────────────────────────────────────────
Problem with Gini importance:
  • Biased toward high-cardinality features
  • Doesn't measure actual predictive value
  • Can be misleading with correlated features

Permutation importance (more reliable):
  1. Train model and calculate baseline score
  2. For each feature:
     - Shuffle that feature's values (break relationship with target)
     - Calculate new score
     - Importance = baseline score - shuffled score
  3. Features that hurt performance when shuffled are important

Advantages:
  ✓ Computed on test set (measures generalization)
  ✓ Less biased
  ✓ Works for any model
─────────────────────────────────────────────────────────────────────
""")

from sklearn.inspection import permutation_importance

# Calculate permutation importance
print("Calculating permutation importance (may take a moment)...")
perm_importance = permutation_importance(rf_model, X_test, y_test, n_repeats=10, random_state=42, n_jobs=-1)

perm_df = pd.DataFrame({
    'Feature': feature_names,
    'Importance': perm_importance.importances_mean,
    'Std': perm_importance.importances_std
}).sort_values('Importance', ascending=False)

# Compare both methods
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Permutation importance with error bars
ax1 = axes[0]
colors = ['green' if x > 0 else 'red' for x in perm_df['Importance']]
ax1.barh(perm_df['Feature'], perm_df['Importance'], xerr=perm_df['Std'],
        color=colors, alpha=0.7, edgecolor='black', capsize=3)
ax1.axvline(x=0, color='black', linestyle='-', linewidth=2)
ax1.set_xlabel('Permutation Importance', fontsize=12)
ax1.set_title('Permutation Importance\n(with std error)', fontsize=14, fontweight='bold')
ax1.invert_yaxis()
ax1.grid(True, alpha=0.3, axis='x')

# Plot 2: Comparison of methods
ax2 = axes[1]
comparison = pd.merge(
    importance_df.rename(columns={'Importance': 'Gini'}),
    perm_df[['Feature', 'Importance']].rename(columns={'Importance': 'Permutation'}),
    on='Feature'
)

x = np.arange(len(comparison))
width = 0.35

ax2.bar(x - width/2, comparison['Gini'], width, label='Gini (MDI)', color='steelblue', alpha=0.8)
ax2.bar(x + width/2, comparison['Permutation'], width, label='Permutation', color='coral', alpha=0.8)
ax2.set_xticks(x)
ax2.set_xticklabels(comparison['Feature'], rotation=45, ha='right')
ax2.set_ylabel('Importance', fontsize=12)
ax2.set_title('Gini vs Permutation Importance', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.show()

print("""
KEY DIFFERENCE:
─────────────────────────────────────────────────────────────────────
• Gini: How much the feature is USED for splitting
• Permutation: How much the feature IMPROVES predictions

Recommendation: Use permutation importance for final analysis
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 11: Hyperparameter - n_estimators (Number of Trees)]
print("\n" + "=" * 70)
print("🌲 CELL 11: n_estimators - How Many Trees Do You Need?")
print("=" * 70)

print("""
n_estimators = Number of trees in the forest

Key Points:
─────────────────────────────────────────────────────────────────────
• More trees → Better performance (up to a point)
• More trees → Longer training time
• NO OVERFITTING from too many trees!
• Diminishing returns after certain point

Typical values: 100-1000
Rule of thumb: Start with 100, increase if needed
─────────────────────────────────────────────────────────────────────
""")

# Test different n_estimators
n_estimators_range = [1, 5, 10, 25, 50, 100, 200, 500]
scores_n = []

print("Testing different n_estimators values...")
for n in n_estimators_range:
    rf_n = RandomForestClassifier(n_estimators=n, max_depth=10, random_state=42, n_jobs=-1)
    rf_n.fit(X_train, y_train)
    
    train_score = f1_score(y_train, rf_n.predict(X_train))
    test_score = f1_score(y_test, rf_n.predict(X_test))
    
    scores_n.append({
        'n_estimators': n,
        'train_f1': train_score,
        'test_f1': test_score
    })
    print(f"  n={n:4d}: Train F1={train_score:.4f}, Test F1={test_score:.4f}")

scores_n_df = pd.DataFrame(scores_n)

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: F1 vs n_estimators
ax1 = axes[0]
ax1.plot(scores_n_df['n_estimators'], scores_n_df['train_f1'], 'b-o', 
        linewidth=2, markersize=8, label='Train F1')
ax1.plot(scores_n_df['n_estimators'], scores_n_df['test_f1'], 'r-s', 
        linewidth=2, markersize=8, label='Test F1')
ax1.set_xlabel('n_estimators (Number of Trees)', fontsize=12)
ax1.set_ylabel('F1 Score', fontsize=12)
ax1.set_title('Performance vs Number of Trees', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

# Annotations
ax1.annotate('Unstable\n(few trees)', xy=(5, scores_n_df.iloc[1]['test_f1']), 
            xytext=(15, scores_n_df.iloc[1]['test_f1']-0.05),
            arrowprops=dict(arrowstyle='->', color='orange'), fontsize=9)
ax1.annotate('Stable\n(many trees)', xy=(200, scores_n_df.iloc[6]['test_f1']),
            xytext=(150, scores_n_df.iloc[6]['test_f1']+0.03),
            arrowprops=dict(arrowstyle='->', color='green'), fontsize=9)

# Plot 2: Diminishing returns
ax2 = axes[1]
improvement = scores_n_df['test_f1'].diff().fillna(0)
ax2.bar(range(len(scores_n_df)), improvement, color='steelblue', alpha=0.8, edgecolor='black')
ax2.set_xticks(range(len(scores_n_df)))
ax2.set_xticklabels(scores_n_df['n_estimators'])
ax2.set_xlabel('n_estimators', fontsize=12)
ax2.set_ylabel('F1 Improvement from Previous', fontsize=12)
ax2.set_title('Diminishing Returns', fontsize=14, fontweight='bold')
ax2.axhline(y=0, color='black', linestyle='-')
ax2.grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.show()

print("""
RECOMMENDATION:
─────────────────────────────────────────────────────────────────────
✓ Start with n_estimators=100 (good default)
✓ Increase to 200-500 for important models
✓ Monitor training time vs improvement
✓ More trees NEVER hurts accuracy, only computation time
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 12: Hyperparameter - max_depth (Tree Complexity)]
print("\n" + "=" * 70)
print("📏 CELL 12: max_depth - How Deep Should Trees Go?")
print("=" * 70)

print("""
max_depth = Maximum depth of each tree

Key Points:
─────────────────────────────────────────────────────────────────────
• Shallow trees (small depth) → Underfitting
• Deep trees (large depth) → Potential overfitting
• None (unlimited) → Trees grow until pure leaves

Unlike single trees, Random Forest is LESS prone to overfitting
from deep trees due to bagging + feature randomness

Typical values: 5-30, or None
─────────────────────────────────────────────────────────────────────
""")

# Test different max_depth
depth_range = [1, 3, 5, 7, 10, 15, 20, 30, None]
scores_d = []

print("Testing different max_depth values...")
for d in depth_range:
    rf_d = RandomForestClassifier(n_estimators=100, max_depth=d, random_state=42, n_jobs=-1)
    rf_d.fit(X_train, y_train)
    
    train_score = f1_score(y_train, rf_d.predict(X_train))
    test_score = f1_score(y_test, rf_d.predict(X_test))
    
    scores_d.append({
        'max_depth': d if d else 'None',
        'train_f1': train_score,
        'test_f1': test_score,
        'gap': train_score - test_score
    })
    d_str = str(d) if d else 'None'
    print(f"  depth={d_str:5s}: Train F1={train_score:.4f}, Test F1={test_score:.4f}, Gap={train_score - test_score:.4f}")

scores_d_df = pd.DataFrame(scores_d)

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Performance vs depth
ax1 = axes[0]
x_pos = range(len(scores_d_df))
ax1.plot(x_pos, scores_d_df['train_f1'], 'b-o', linewidth=2, markersize=8, label='Train F1')
ax1.plot(x_pos, scores_d_df['test_f1'], 'r-s', linewidth=2, markersize=8, label='Test F1')
ax1.fill_between(x_pos, scores_d_df['train_f1'], scores_d_df['test_f1'], alpha=0.2, color='gray')
ax1.set_xticks(x_pos)
ax1.set_xticklabels(scores_d_df['max_depth'])
ax1.set_xlabel('max_depth', fontsize=12)
ax1.set_ylabel('F1 Score', fontsize=12)
ax1.set_title('Performance vs Tree Depth\n(Gap = Overfitting)', fontsize=14, fontweight='bold')
ax1.legend()
ax1.grid(True, alpha=0.3)

# Plot 2: Overfitting gap
ax2 = axes[1]
colors = ['green' if g < 0.05 else 'orange' if g < 0.1 else 'red' for g in scores_d_df['gap']]
ax2.bar(x_pos, scores_d_df['gap'], color=colors, alpha=0.8, edgecolor='black')
ax2.set_xticks(x_pos)
ax2.set_xticklabels(scores_d_df['max_depth'])
ax2.set_xlabel('max_depth', fontsize=12)
ax2.set_ylabel('Train-Test Gap', fontsize=12)
ax2.set_title('Overfitting Gap\n(Green=Good, Red=Overfitting)', fontsize=14, fontweight='bold')
ax2.axhline(y=0.05, color='orange', linestyle='--', label='Acceptable gap')
ax2.axhline(y=0.1, color='red', linestyle='--', label='Warning')
ax2.legend()
ax2.grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.show()

print("""
RECOMMENDATION:
─────────────────────────────────────────────────────────────────────
✓ Start with max_depth=10-20
✓ Monitor train-test gap
✓ If gap is large (>0.1), reduce depth
✓ For trading data (often noisy), smaller depths often work better
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 13: min_samples_split & min_samples_leaf]
print("\n" + "=" * 70)
print("📊 CELL 13: min_samples_split & min_samples_leaf")
print("=" * 70)

print("""
STOPPING CRITERIA PARAMETERS:
─────────────────────────────────────────────────────────────────────
min_samples_split:
  • Minimum samples required to SPLIT a node
  • Higher value → Simpler trees (less overfitting)
  • Default: 2

min_samples_leaf:
  • Minimum samples required in a LEAF node
  • Higher value → Smoother predictions
  • Default: 1

Both parameters help control overfitting!
─────────────────────────────────────────────────────────────────────
""")

# Test min_samples_split
split_range = [2, 5, 10, 20, 50, 100]
scores_split = []

print("Testing min_samples_split...")
for s in split_range:
    rf_s = RandomForestClassifier(n_estimators=100, max_depth=None, 
                                  min_samples_split=s, random_state=42, n_jobs=-1)
    rf_s.fit(X_train, y_train)
    scores_split.append({
        'value': s,
        'test_f1': f1_score(y_test, rf_s.predict(X_test))
    })
    print(f"  min_samples_split={s:3d}: Test F1={scores_split[-1]['test_f1']:.4f}")

# Test min_samples_leaf
leaf_range = [1, 2, 5, 10, 20, 50]
scores_leaf = []

print("\nTesting min_samples_leaf...")
for l in leaf_range:
    rf_l = RandomForestClassifier(n_estimators=100, max_depth=None, 
                                  min_samples_leaf=l, random_state=42, n_jobs=-1)
    rf_l.fit(X_train, y_train)
    scores_leaf.append({
        'value': l,
        'test_f1': f1_score(y_test, rf_l.predict(X_test))
    })
    print(f"  min_samples_leaf={l:3d}: Test F1={scores_leaf[-1]['test_f1']:.4f}")

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

ax1 = axes[0]
split_df = pd.DataFrame(scores_split)
ax1.plot(split_df['value'], split_df['test_f1'], 'b-o', linewidth=2, markersize=10)
ax1.set_xlabel('min_samples_split', fontsize=12)
ax1.set_ylabel('Test F1 Score', fontsize=12)
ax1.set_title('min_samples_split\n(Higher = Simpler Splits)', fontsize=14, fontweight='bold')
ax1.grid(True, alpha=0.3)

ax2 = axes[1]
leaf_df = pd.DataFrame(scores_leaf)
ax2.plot(leaf_df['value'], leaf_df['test_f1'], 'g-o', linewidth=2, markersize=10)
ax2.set_xlabel('min_samples_leaf', fontsize=12)
ax2.set_ylabel('Test F1 Score', fontsize=12)
ax2.set_title('min_samples_leaf\n(Higher = Smoother Leaves)', fontsize=14, fontweight='bold')
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# %% [CELL 14: max_features - The Randomness Parameter]
print("\n" + "=" * 70)
print("🎲 CELL 14: max_features - Controlling Randomness")
print("=" * 70)

print("""
max_features = Number of features to consider at each split

This is what makes Random Forest "RANDOM":
─────────────────────────────────────────────────────────────────────
Options:
  • 'sqrt' (default): √n_features - Good for classification
  • 'log2': log₂(n_features) - More randomness
  • int: Exact number
  • float: Fraction of features
  • None: All features (like bagging)

Trade-off:
  • More features → Each tree is stronger, but trees are similar
  • Fewer features → Trees are weaker, but more diverse
  • Diversity + Voting = Better generalization!
─────────────────────────────────────────────────────────────────────
""")

# Test max_features
max_feat_options = [1, 2, 3, 'sqrt', 'log2', None]
scores_feat = []

print("Testing max_features...")
for mf in max_feat_options:
    rf_f = RandomForestClassifier(n_estimators=100, max_depth=10, 
                                  max_features=mf, random_state=42, n_jobs=-1)
    rf_f.fit(X_train, y_train)
    
    test_f1 = f1_score(y_test, rf_f.predict(X_test))
    
    # Calculate tree diversity (variance of predictions)
    tree_preds = np.array([tree.predict(X_test) for tree in rf_f.estimators_])
    diversity = tree_preds.std(axis=0).mean()
    
    scores_feat.append({
        'max_features': str(mf),
        'test_f1': test_f1,
        'diversity': diversity
    })
    print(f"  max_features={str(mf):6s}: Test F1={test_f1:.4f}, Diversity={diversity:.4f}")

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

feat_df = pd.DataFrame(scores_feat)

ax1 = axes[0]
x_pos = range(len(feat_df))
ax1.bar(x_pos, feat_df['test_f1'], color='steelblue', alpha=0.8, edgecolor='black')
ax1.set_xticks(x_pos)
ax1.set_xticklabels(feat_df['max_features'])
ax1.set_xlabel('max_features', fontsize=12)
ax1.set_ylabel('Test F1 Score', fontsize=12)
ax1.set_title('Performance vs max_features', fontsize=14, fontweight='bold')
ax1.grid(True, alpha=0.3, axis='y')

ax2 = axes[1]
ax2.plot(feat_df['diversity'], feat_df['test_f1'], 'ro-', linewidth=2, markersize=10)
for i, row in feat_df.iterrows():
    ax2.annotate(row['max_features'], (row['diversity'], row['test_f1']),
                xytext=(5, 5), textcoords='offset points', fontsize=9)
ax2.set_xlabel('Tree Diversity', fontsize=12)
ax2.set_ylabel('Test F1 Score', fontsize=12)
ax2.set_title('Diversity-Performance Trade-off', fontsize=14, fontweight='bold')
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("""
RECOMMENDATION:
─────────────────────────────────────────────────────────────────────
✓ 'sqrt' is usually the best default for classification
✓ Try 'log2' if you want more diversity
✓ None (all features) reduces to bagging (less diverse)
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 15: GridSearchCV - Automated Tuning]
print("\n" + "=" * 70)
print("🔍 CELL 15: GridSearchCV - Find Optimal Parameters")
print("=" * 70)

print("""
GridSearchCV systematically tests parameter combinations:
─────────────────────────────────────────────────────────────────────
1. Define parameter grid
2. Test ALL combinations with cross-validation
3. Return best parameters
─────────────────────────────────────────────────────────────────────
""")

# Define parameter grid
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [5, 10, 15, None],
    'min_samples_split': [2, 5, 10],
    'max_features': ['sqrt', 'log2']
}

total_combos = 3 * 4 * 3 * 2
print(f"Parameter Grid:")
for k, v in param_grid.items():
    print(f"  {k}: {v}")
print(f"\nTotal combinations: {total_combos}")
print(f"With 5-fold CV: {total_combos * 5} model fits")

print("\nRunning GridSearchCV (this may take a minute)...")
grid_search = GridSearchCV(
    RandomForestClassifier(random_state=42, n_jobs=-1),
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
best_rf = grid_search.best_estimator_
y_pred_best = best_rf.predict(X_test)
y_proba_best = best_rf.predict_proba(X_test)[:, 1]

print("\n" + "-" * 50)
print("BEST MODEL TEST PERFORMANCE:")
print("-" * 50)
print(f"  Accuracy:  {accuracy_score(y_test, y_pred_best):.4f}")
print(f"  Precision: {precision_score(y_test, y_pred_best):.4f}")
print(f"  Recall:    {recall_score(y_test, y_pred_best):.4f}")
print(f"  F1 Score:  {f1_score(y_test, y_pred_best):.4f}")
print(f"  ROC-AUC:   {roc_auc_score(y_test, y_proba_best):.4f}")

# Visualize results
results_gs = pd.DataFrame(grid_search.cv_results_)

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Top 10 parameter combinations
ax1 = axes[0]
top_10 = results_gs.nsmallest(10, 'rank_test_score')[['params', 'mean_test_score', 'std_test_score']]
y_pos = range(len(top_10))
ax1.barh(y_pos, top_10['mean_test_score'], xerr=top_10['std_test_score'],
        color='steelblue', alpha=0.8, edgecolor='black', capsize=3)
ax1.set_yticks(y_pos)
ax1.set_yticklabels([f"#{i+1}" for i in range(len(top_10))])
ax1.set_xlabel('CV F1 Score', fontsize=12)
ax1.set_title('Top 10 Parameter Combinations', fontsize=14, fontweight='bold')
ax1.grid(True, alpha=0.3, axis='x')

# Plot 2: Effect of max_depth
ax2 = axes[1]
for mf in ['sqrt', 'log2']:
    mask = (results_gs['param_max_features'] == mf) & (results_gs['param_n_estimators'] == 100)
    subset = results_gs[mask].sort_values('param_max_depth')
    depths = [str(d) if d else 'None' for d in subset['param_max_depth']]
    ax2.plot(depths, subset['mean_test_score'], 'o-', linewidth=2, markersize=8, label=f'max_features={mf}')
ax2.set_xlabel('max_depth', fontsize=12)
ax2.set_ylabel('CV F1 Score', fontsize=12)
ax2.set_title('Effect of max_depth (n_estimators=100)', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# %% [CELL 16: Out-of-Bag (OOB) Score - Free Validation]
print("\n" + "=" * 70)
print("🎁 CELL 16: Out-of-Bag Score - Free Validation!")
print("=" * 70)

print("""
OUT-OF-BAG (OOB) SCORE:
─────────────────────────────────────────────────────────────────────
Remember: Each tree uses ~63% of samples (bootstrap)
The remaining ~37% are "out-of-bag" for that tree

OOB Score:
  • For each sample, predict using ONLY trees that didn't see it
  • Aggregate predictions → Calculate score
  • FREE validation without holdout set!

Why use it?
  ✓ No need to waste data on validation set
  ✓ Automatic during training (oob_score=True)
  ✓ Similar to cross-validation estimate
─────────────────────────────────────────────────────────────────────
""")

# Train with OOB score
rf_oob = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    oob_score=True,  # Enable OOB scoring
    random_state=42,
    n_jobs=-1
)
rf_oob.fit(X_train, y_train)

# Compare OOB vs Test performance
test_acc = accuracy_score(y_test, rf_oob.predict(X_test))
oob_acc = rf_oob.oob_score_

print(f"OOB Score (accuracy):  {oob_acc:.4f}")
print(f"Test Score (accuracy): {test_acc:.4f}")
print(f"Difference:            {abs(oob_acc - test_acc):.4f}")

# OOB predictions
oob_proba = rf_oob.oob_decision_function_[:, 1]

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: OOB vs Test comparison
ax1 = axes[0]
bars = ax1.bar(['OOB Score', 'Test Score'], [oob_acc, test_acc], 
              color=['steelblue', 'coral'], alpha=0.8, edgecolor='black', width=0.5)
ax1.set_ylabel('Accuracy', fontsize=12)
ax1.set_title('OOB vs Test Score\n(Should be similar)', fontsize=14, fontweight='bold')
ax1.set_ylim([0, 1.1])
for bar, val in zip(bars, [oob_acc, test_acc]):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
            f'{val:.4f}', ha='center', fontsize=14, fontweight='bold')
ax1.grid(True, alpha=0.3, axis='y')

# Plot 2: OOB probability distribution
ax2 = axes[1]
ax2.hist(oob_proba[y_train == 0], bins=30, alpha=0.5, color='red', label='Class 0', density=True)
ax2.hist(oob_proba[y_train == 1], bins=30, alpha=0.5, color='green', label='Class 1', density=True)
ax2.axvline(x=0.5, color='black', linestyle='--', linewidth=2, label='Threshold')
ax2.set_xlabel('OOB Probability of Class 1', fontsize=12)
ax2.set_ylabel('Density', fontsize=12)
ax2.set_title('OOB Probability Distribution\n(Good separation = good model)', fontsize=14, fontweight='bold')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("""
WHY OOB SCORE IS USEFUL:
─────────────────────────────────────────────────────────────────────
✓ Use ALL data for training (no validation split needed)
✓ Get unbiased performance estimate
✓ Faster than cross-validation
✓ Use for early stopping or hyperparameter selection
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 17: Learning Curves]
print("\n" + "=" * 70)
print("📈 CELL 17: Learning Curves - Do You Need More Data?")
print("=" * 70)

print("""
Learning curves show how performance changes with training set size:
─────────────────────────────────────────────────────────────────────
• Both curves HIGH and converged → Good model
• Large GAP → Overfitting (need more data or regularization)
• Both curves LOW → Underfitting (need more complex model)
• Curves still rising → More data would help
─────────────────────────────────────────────────────────────────────
""")

# Calculate learning curves
train_sizes, train_scores, test_scores = learning_curve(
    RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, n_jobs=-1),
    X, y,
    train_sizes=np.linspace(0.1, 1.0, 10),
    cv=5,
    scoring='f1',
    n_jobs=-1
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

# Plot 2: Diagnosis
ax2 = axes[1]
ax2.axis('off')

gap = train_mean[-1] - test_mean[-1]
if gap < 0.05 and test_mean[-1] > 0.8:
    diagnosis = "✅ GOOD FIT\nBoth scores high, small gap\n→ Model generalizes well"
    color = 'green'
elif gap > 0.15:
    diagnosis = "⚠️ OVERFITTING\nLarge gap between train/test\n→ Try: More data, fewer features,\n   smaller max_depth"
    color = 'red'
elif test_mean[-1] < 0.6:
    diagnosis = "⚠️ UNDERFITTING\nBoth scores low\n→ Try: More features, deeper trees"
    color = 'orange'
else:
    diagnosis = "✓ ACCEPTABLE\nModel is reasonably good"
    color = 'blue'

ax2.text(0.5, 0.7, "MODEL DIAGNOSIS:", fontsize=16, fontweight='bold', ha='center', transform=ax2.transAxes)
ax2.text(0.5, 0.5, diagnosis, fontsize=14, ha='center', transform=ax2.transAxes,
        bbox=dict(boxstyle='round', facecolor=color, alpha=0.2))
ax2.text(0.5, 0.2, f"Final Train: {train_mean[-1]:.4f}\nFinal CV: {test_mean[-1]:.4f}\nGap: {gap:.4f}",
        fontsize=12, ha='center', transform=ax2.transAxes, family='monospace')

plt.tight_layout()
plt.show()

# %% [CELL 18: Load Real Trading Data]
print("\n" + "=" * 70)
print("💹 CELL 18: Load Real Trading Data")
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

# %% [CELL 19: Full Pipeline on Trading Data]
if TRADING_DATA_AVAILABLE:
    print("\n" + "=" * 70)
    print("🚀 CELL 19: Full Pipeline on Trading Data")
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
        
        # Time-based split (CRITICAL for trading!)
        split_idx = int(len(X_t) * 0.8)
        X_train_t, X_test_t = X_t.iloc[:split_idx], X_t.iloc[split_idx:]
        y_train_t, y_test_t = y_t.iloc[:split_idx], y_t.iloc[split_idx:]
        
        print(f"Train: {len(X_train_t)} | Test: {len(X_test_t)}")
        print(f"Train class distribution: {(y_train_t==1).sum()}/{len(y_train_t)} ({(y_train_t==1).mean()*100:.1f}%)")
        print(f"Test class distribution:  {(y_test_t==1).sum()}/{len(y_test_t)} ({(y_test_t==1).mean()*100:.1f}%)")
        
        # Train Random Forest
        print("\nTraining Random Forest...")
        rf_trading = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=10,
            class_weight='balanced',  # Handle imbalance
            oob_score=True,
            random_state=42,
            n_jobs=-1
        )
        rf_trading.fit(X_train_t, y_train_t)
        
        # Evaluate
        y_pred_t = rf_trading.predict(X_test_t)
        y_proba_t = rf_trading.predict_proba(X_test_t)[:, 1]
        
        print("\n" + "-" * 50)
        print("TRADING MODEL PERFORMANCE:")
        print("-" * 50)
        print(f"OOB Score:  {rf_trading.oob_score_:.4f}")
        print(f"Accuracy:   {accuracy_score(y_test_t, y_pred_t):.4f}")
        print(f"Precision:  {precision_score(y_test_t, y_pred_t):.4f}")
        print(f"Recall:     {recall_score(y_test_t, y_pred_t):.4f}")
        print(f"F1 Score:   {f1_score(y_test_t, y_pred_t):.4f}")
        print(f"ROC-AUC:    {roc_auc_score(y_test_t, y_proba_t):.4f}")
        
        # Feature importance
        print("\n" + "-" * 50)
        print("TOP 15 IMPORTANT FEATURES:")
        print("-" * 50)
        importance_df_t = pd.DataFrame({
            'Feature': available_cols,
            'Importance': rf_trading.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        for _, row in importance_df_t.head(15).iterrows():
            bar = '█' * int(row['Importance'] * 100)
            print(f"  {row['Feature']:<20} {row['Importance']:.4f} {bar}")
        
        # Visualizations
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        # ROC Curve
        ax1 = axes[0]
        fpr_t, tpr_t, _ = roc_curve(y_test_t, y_proba_t)
        auc_t = roc_auc_score(y_test_t, y_proba_t)
        ax1.plot(fpr_t, tpr_t, 'b-', linewidth=2, label=f'Random Forest (AUC={auc_t:.3f})')
        ax1.plot([0,1], [0,1], 'r--', linewidth=2, label='Random')
        ax1.set_xlabel('FPR')
        ax1.set_ylabel('TPR')
        ax1.set_title('ROC Curve - Trading Model', fontweight='bold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Feature importance
        ax2 = axes[1]
        top15 = importance_df_t.head(15)
        colors = plt.cm.RdYlGn(np.linspace(0.2, 0.8, len(top15)))[::-1]
        ax2.barh(range(len(top15)), top15['Importance'], color=colors, edgecolor='black')
        ax2.set_yticks(range(len(top15)))
        ax2.set_yticklabels(top15['Feature'])
        ax2.invert_yaxis()
        ax2.set_xlabel('Importance')
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
║  MISTAKE #1: NOT USING TIME-BASED SPLIT FOR TRADING               ║
╠═══════════════════════════════════════════════════════════════════╣
║  Random split → Look-ahead bias → False hope!                     ║
║                                                                   ║
║  ✓ ALWAYS split chronologically for time-series data             ║
║  ✓ Train on past, test on future                                 ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #2: IGNORING CLASS IMBALANCE                            ║
╠═══════════════════════════════════════════════════════════════════╣
║  If 70% losses, model can predict "all loss" and get 70% acc!     ║
║                                                                   ║
║  ✓ Use class_weight='balanced'                                   ║
║  ✓ Focus on F1/ROC-AUC, not just accuracy                        ║
║  ✓ Use stratified cross-validation                               ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #3: TOO MANY TREES WITHOUT BENEFIT                       ║
╠═══════════════════════════════════════════════════════════════════╣
║  More trees = More computation, but diminishing returns           ║
║                                                                   ║
║  ✓ Start with 100 trees, check OOB score                         ║
║  ✓ Increase until score plateaus                                 ║
║  ✓ 200-500 trees usually sufficient                              ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #4: TRUSTING FEATURE IMPORTANCE BLINDLY                  ║
╠═══════════════════════════════════════════════════════════════════╣
║  Gini importance is biased toward high-cardinality features       ║
║                                                                   ║
║  ✓ Use permutation importance for final analysis                 ║
║  ✓ Verify important features make domain sense                   ║
║  ✓ Be cautious with correlated features                          ║
╚═══════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════╗
║  MISTAKE #5: NOT SETTING random_state                             ║
╠═══════════════════════════════════════════════════════════════════╣
║  Random Forest is stochastic - results vary!                      ║
║                                                                   ║
║  ✓ Always set random_state for reproducibility                   ║
║  ✓ Test with multiple seeds to check stability                   ║
╚═══════════════════════════════════════════════════════════════════╝
""")

# %% [CELL 21: Save & Load Models]
print("\n" + "=" * 70)
print("💾 CELL 21: Save & Load Models")
print("=" * 70)

import os
model_dir = '/allah/blue/freq/project/ml_datasets/saved_models'
os.makedirs(model_dir, exist_ok=True)

# Save the best model
model_path = f'{model_dir}/random_forest_demo.joblib'
joblib.dump(best_rf, model_path)
print(f"✓ Model saved: {model_path}")

# Load and verify
loaded_rf = joblib.load(model_path)
print(f"✓ Model loaded!")

# Verify predictions match
original_pred = best_rf.predict(X_test[:5])
loaded_pred = loaded_rf.predict(X_test[:5])
print(f"✓ Predictions verified: {np.array_equal(original_pred, loaded_pred)}")

print("""
PRODUCTION PATTERN:
─────────────────────────────────────────────────────────────────────
# TRAINING (once)
rf = RandomForestClassifier(...)
rf.fit(X_train, y_train)
joblib.dump(rf, 'model.joblib')

# INFERENCE (production)
rf = joblib.load('model.joblib')
predictions = rf.predict(X_new)
probabilities = rf.predict_proba(X_new)[:, 1]

# For high-confidence trades only
high_conf_mask = probabilities > 0.7
─────────────────────────────────────────────────────────────────────
""")

# %% [CELL 22: Final Summary]
print("\n" + "=" * 70)
print("🎓 CELL 22: Course Complete - Random Forest Summary")
print("=" * 70)

print("""
╔═══════════════════════════════════════════════════════════════════╗
║                     RANDOM FOREST SUMMARY                         ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  WHAT IT IS:                                                      ║
║  • Ensemble of decision trees                                     ║
║  • Uses bagging (bootstrap samples)                               ║
║  • Random feature selection at each split                         ║
║  • Predictions via majority voting                                ║
║                                                                   ║
║  KEY HYPERPARAMETERS:                                             ║
║  • n_estimators: Number of trees (100-500)                        ║
║  • max_depth: Tree depth (10-20, or None)                         ║
║  • max_features: 'sqrt' for classification                        ║
║  • min_samples_split/leaf: Control overfitting                    ║
║  • class_weight: 'balanced' for imbalanced data                   ║
║                                                                   ║
║  STRENGTHS:                                                       ║
║  ✓ Handles non-linear relationships                              ║
║  ✓ Robust to outliers and noise                                  ║
║  ✓ Built-in feature importance                                   ║
║  ✓ OOB score (free validation)                                   ║
║  ✓ Hard to overfit with more trees                               ║
║  ✓ Works well out-of-the-box                                     ║
║                                                                   ║
║  WEAKNESSES:                                                      ║
║  ✗ Large model size (stores all trees)                           ║
║  ✗ Slower prediction than linear models                          ║
║  ✗ Less interpretable than single tree                           ║
║  ✗ Can struggle with very high-dimensional data                  ║
║                                                                   ║
║  WHEN TO USE:                                                     ║
║  ✓ Tabular data with mixed feature types                         ║
║  ✓ When you need feature importance                              ║
║  ✓ As a strong baseline model                                    ║
║  ✓ When interpretability is somewhat important                   ║
║                                                                   ║
║  FOR TRADING:                                                     ║
║  ✓ Use time-based split                                          ║
║  ✓ Handle class imbalance                                        ║
║  ✓ Focus on precision (avoid false positives)                    ║
║  ✓ Use probability thresholds for confidence                     ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

🚀 Next: Try XGBoost or LightGBM for potentially better performance!
""")
print("=" * 70)
