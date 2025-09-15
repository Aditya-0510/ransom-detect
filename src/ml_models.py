import numpy as np
import pandas as pd
import pickle
import joblib
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
import logging
from pathlib import Path

# ML imports
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, 
    precision_recall_curve, roc_curve, f1_score
)
from sklearn.feature_selection import SelectKBest, f_classif, RFE
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("XGBoost not available. Install with: pip install xgboost")

import matplotlib.pyplot as plt
import seaborn as sns

from config import config

class RansomwareMLDetector:
    """Machine Learning-based Ransomware Detection System"""
    
    def __init__(self, model_name: str = 'ensemble'):
        self.logger = logging.getLogger(__name__)
        self.model_name = model_name
        self.models = {}
        self.scaler = None
        self.feature_selector = None
        self.feature_names = None
        self.is_trained = False
        
        # Model configurations
        self.model_configs = {
            'random_forest': {
                'model': RandomForestClassifier,
                'params': {
                    'n_estimators': 100,
                    'max_depth': 10,
                    'min_samples_split': 5,
                    'min_samples_leaf': 2,
                    'random_state': config.ML_CONFIG['random_state'],
                    'n_jobs': -1
                }
            },
            'gradient_boosting': {
                'model': GradientBoostingClassifier,
                'params': {
                    'n_estimators': 100,
                    'learning_rate': 0.1,
                    'max_depth': 6,
                    'random_state': config.ML_CONFIG['random_state']
                }
            },
            'svm': {
                'model': SVC,
                'params': {
                    'kernel': 'rbf',
                    'C': 1.0,
                    'gamma': 'scale',
                    'probability': True,
                    'random_state': config.ML_CONFIG['random_state']
                }
            },
            'logistic_regression': {
                'model': LogisticRegression,
                'params': {
                    'C': 1.0,
                    'random_state': config.ML_CONFIG['random_state'],
                    'max_iter': 1000
                }
            }
        }
        
        # Add XGBoost if available
        if XGBOOST_AVAILABLE:
            self.model_configs['xgboost'] = {
                'model': xgb.XGBClassifier,
                'params': {
                    'n_estimators': 100,
                    'max_depth': 6,
                    'learning_rate': 0.1,
                    'random_state': config.ML_CONFIG['random_state'],
                    'eval_metric': 'logloss'
                }
            }
        
        # Anomaly detection for unsupervised learning
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=config.ML_CONFIG['random_state'],
            n_jobs=-1
        )
        
        self.logger.info(f"Initialized ML detector with model: {model_name}")
    
    def prepare_data(self, X: pd.DataFrame, y: np.ndarray = None, 
                    test_size: float = None) -> Tuple:
        """Prepare data for training/testing with small dataset handling"""
        if test_size is None:
            test_size = config.ML_CONFIG['test_size']
        
        # Handle missing values
        X = X.fillna(0)
        
        # Remove constant features
        constant_features = X.columns[X.std() == 0]
        if len(constant_features) > 0:
            self.logger.info(f"Removing {len(constant_features)} constant features")
            X = X.drop(columns=constant_features)
        
        # Store feature names
        self.feature_names = list(X.columns)
        
        # Split data if labels are provided and we have enough samples
        if y is not None:
            n_samples = len(X)
            
            # Need at least 5 samples for proper train/test split
            if n_samples < 5:
                self.logger.warning(f"Only {n_samples} samples available. Using all data for training (no test split).")
                return X, None, y, None
            
            # For very small datasets, use smaller test size
            if n_samples < 20:
                test_size = min(test_size, 0.3)  # Use max 30% for testing
                self.logger.info(f"Small dataset ({n_samples} samples). Using test_size={test_size}")
            
            try:
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=test_size, 
                    random_state=config.ML_CONFIG['random_state'],
                    stratify=y if len(np.unique(y)) > 1 and np.min(np.bincount(y)) >= 2 else None
                )
                return X_train, X_test, y_train, y_test
            except ValueError as e:
                self.logger.warning(f"Could not split data properly: {e}. Using all data for training.")
                return X, None, y, None
        else:
            return X, None, None, None
    
    def preprocess_features(self, X_train: pd.DataFrame, X_test: pd.DataFrame = None,
                          feature_selection: bool = True) -> Tuple:
        """Preprocess features with scaling and selection"""
        
        # Initialize scaler
        self.scaler = RobustScaler()  # More robust to outliers than StandardScaler
        
        # Fit and transform training data
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=X_train.columns, index=X_train.index)
        
        # Transform test data if provided
        X_test_scaled = None
        if X_test is not None:
            X_test_scaled = self.scaler.transform(X_test)
            X_test_scaled = pd.DataFrame(X_test_scaled, columns=X_test.columns, index=X_test.index)
        
        # Feature selection
        if feature_selection and len(X_train.columns) > config.ML_CONFIG['max_features']:
            self.logger.info("Performing feature selection...")
            
            # Use SelectKBest for initial filtering
            k_best = min(config.ML_CONFIG['max_features'], len(X_train.columns))
            self.feature_selector = SelectKBest(score_func=f_classif, k=k_best)
            
            # This requires labels, so skip if not available
            try:
                X_train_selected = self.feature_selector.fit_transform(X_train_scaled, y_train)
                selected_features = X_train_scaled.columns[self.feature_selector.get_support()]
                
                X_train_scaled = pd.DataFrame(X_train_selected, columns=selected_features, index=X_train.index)
                
                if X_test_scaled is not None:
                    X_test_selected = self.feature_selector.transform(X_test_scaled)
                    X_test_scaled = pd.DataFrame(X_test_selected, columns=selected_features, index=X_test.index)
                
                self.logger.info(f"Selected {len(selected_features)} features")
                
            except NameError:
                self.logger.info("Skipping feature selection - no labels available")
        
        return X_train_scaled, X_test_scaled
    
    def handle_class_imbalance(self, X_train: pd.DataFrame, y_train: np.ndarray) -> Tuple:
        """Handle class imbalance using SMOTE"""
        
        class_counts = np.bincount(y_train)
        self.logger.info(f"Class distribution before balancing: {dict(enumerate(class_counts))}")
        
        # Apply SMOTE if there's significant imbalance
        if len(class_counts) > 1 and min(class_counts) / max(class_counts) < 0.3:
            self.logger.info("Applying SMOTE to handle class imbalance...")
            
            smote = SMOTE(random_state=config.ML_CONFIG['random_state'])
            X_balanced, y_balanced = smote.fit_resample(X_train, y_train)
            
            # Convert back to DataFrame
            X_balanced = pd.DataFrame(X_balanced, columns=X_train.columns)
            
            balanced_counts = np.bincount(y_balanced)
            self.logger.info(f"Class distribution after SMOTE: {dict(enumerate(balanced_counts))}")
            
            return X_balanced, y_balanced
        
        return X_train, y_train
    
    def train_model(self, X: pd.DataFrame, y: np.ndarray, 
                   validate: bool = True) -> Dict[str, Any]:
        """Train the ransomware detection model with small dataset handling"""
        
        self.logger.info("Starting model training...")
        self.logger.info(f"Training data shape: {X.shape}")
        self.logger.info(f"Class distribution: {np.bincount(y)}")
        
        # Prepare data
        X_train, X_test, y_train, y_test = self.prepare_data(X, y)
        
        # Check if we have enough data
        if len(X_train) < 3:
            self.logger.error(f"Insufficient training data: {len(X_train)} samples. Need at least 3 samples.")
            raise ValueError(f"Insufficient training data: {len(X_train)} samples. Need at least 3 samples for training.")
        
        # Preprocess features
        X_train_processed, X_test_processed = self.preprocess_features(
            X_train, X_test, feature_selection=len(X_train.columns) > 10
        )
        
        # Handle class imbalance only if we have multiple classes and enough samples
        if len(np.unique(y_train)) > 1 and len(y_train) > 10:
            X_train_balanced, y_train_balanced = self.handle_class_imbalance(X_train_processed, y_train)
        else:
            X_train_balanced, y_train_balanced = X_train_processed, y_train
            self.logger.info("Skipping class balancing due to small dataset or single class")
        
        # Train models based on selection
        training_results = {}
        
        if self.model_name == 'ensemble':
            # For small datasets, train fewer models
            if len(X_train_balanced) < 20:
                self.logger.info("Small dataset detected. Training simplified ensemble.")
                self._train_simple_ensemble(X_train_balanced, y_train_balanced)
            else:
                self._train_ensemble(X_train_balanced, y_train_balanced)
            
            if validate and X_test_processed is not None:
                training_results = self._validate_ensemble(X_test_processed, y_test)
            else:
                training_results = {'message': 'Training completed without validation (insufficient test data)'}
        else:
            # Train single model
            self._train_single_model(X_train_balanced, y_train_balanced, self.model_name)
            if validate and X_test_processed is not None:
                training_results = self._validate_single_model(X_test_processed, y_test, self.model_name)
            else:
                training_results = {'message': 'Training completed without validation (insufficient test data)'}
        
        # Train anomaly detector for unsupervised detection
        self.logger.info("Training anomaly detector...")
        self.anomaly_detector.fit(X_train_processed)
        
        self.is_trained = True
        self.logger.info("Model training completed successfully")
        
        return training_results
    
    def _train_single_model(self, X_train: pd.DataFrame, y_train: np.ndarray, model_name: str):
        """Train a single model"""
        if model_name not in self.model_configs:
            raise ValueError(f"Unknown model: {model_name}")
        
        config_info = self.model_configs[model_name]
        model_class = config_info['model']
        params = config_info['params']
        
        self.logger.info(f"Training {model_name} model...")
        
        # Hyperparameter tuning
        if model_name == 'random_forest':
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [5, 10, 15],
                'min_samples_split': [2, 5, 10]
            }
        elif model_name == 'svm':
            param_grid = {
                'C': [0.1, 1, 10],
                'gamma': ['scale', 'auto', 0.001, 0.01]
            }
        else:
            param_grid = {}
        
        if param_grid:
            self.logger.info(f"Performing hyperparameter tuning for {model_name}...")
            grid_search = GridSearchCV(
                model_class(**params), param_grid, 
                cv=3, scoring='f1', n_jobs=-1
            )
            grid_search.fit(X_train, y_train)
            self.models[model_name] = grid_search.best_estimator_
            self.logger.info(f"Best parameters for {model_name}: {grid_search.best_params_}")
        else:
            model = model_class(**params)
            model.fit(X_train, y_train)
            self.models[model_name] = model
    
    def _train_ensemble(self, X_train: pd.DataFrame, y_train: np.ndarray):
        """Train ensemble of models"""
        self.logger.info("Training ensemble of models...")
        
        # Train each model in the ensemble
        models_to_train = ['random_forest', 'gradient_boosting', 'logistic_regression']
        if XGBOOST_AVAILABLE:
            models_to_train.append('xgboost')
        
        for model_name in models_to_train:
            try:
                self._train_single_model(X_train, y_train, model_name)
                self.logger.info(f"Successfully trained {model_name}")
            except Exception as e:
                self.logger.error(f"Failed to train {model_name}: {e}")
    def _train_simple_ensemble(self, X_train: pd.DataFrame, y_train: np.ndarray):
        """Train a simplified ensemble for small datasets"""
        self.logger.info("Training simplified ensemble for small dataset...")
        
        # Only train the most robust models for small datasets
        simple_models = ['random_forest', 'logistic_regression']
        
        for model_name in simple_models:
            if model_name in self.model_configs:
                try:
                    # Use simpler parameters for small datasets
                    config_info = self.model_configs[model_name].copy()
                    if model_name == 'random_forest':
                        # Reduce complexity for small datasets
                        config_info['params']['n_estimators'] = min(50, len(X_train))
                        config_info['params']['max_depth'] = min(5, len(X_train.columns))
                        config_info['params']['min_samples_split'] = max(2, len(X_train) // 10)
                    
                    model_class = config_info['model']
                    params = config_info['params']
                    
                    model = model_class(**params)
                    model.fit(X_train, y_train)
                    self.models[model_name] = model
                    
                    self.logger.info(f"Successfully trained {model_name} (simplified)")
                except Exception as e:
                    self.logger.error(f"Failed to train {model_name}: {e}")
    
    def _validate_single_model(self, X_test: pd.DataFrame, y_test: np.ndarray, 
                             model_name: str) -> Dict[str, Any]:
        """Validate a single model"""
        model = self.models[model_name]
        
        # Make predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else y_pred
        
        # Calculate metrics
        results = self._calculate_metrics(y_test, y_pred, y_pred_proba, model_name)
        
        return results
    
    def _validate_ensemble(self, X_test: pd.DataFrame, y_test: np.ndarray) -> Dict[str, Any]:
        """Validate ensemble of models"""
        if not self.models:
            raise ValueError("No models trained for ensemble")
        
        # Get predictions from each model
        predictions = {}
        probabilities = {}
        
        for model_name, model in self.models.items():
            predictions[model_name] = model.predict(X_test)
            if hasattr(model, 'predict_proba'):
                probabilities[model_name] = model.predict_proba(X_test)[:, 1]
            else:
                probabilities[model_name] = predictions[model_name]
        
        # Ensemble prediction (majority vote + average probability)
        pred_array = np.array(list(predictions.values()))
        prob_array = np.array(list(probabilities.values()))
        
        # Majority vote
        ensemble_pred = np.round(np.mean(pred_array, axis=0)).astype(int)
        
        # Average probability
        ensemble_prob = np.mean(prob_array, axis=0)
        
        # Calculate ensemble metrics
        ensemble_results = self._calculate_metrics(y_test, ensemble_pred, ensemble_prob, 'ensemble')
        
        # Individual model results
        individual_results = {}
        for model_name in self.models:
            individual_results[model_name] = self._calculate_metrics(
                y_test, predictions[model_name], probabilities[model_name], model_name
            )
        
        return {
            'ensemble': ensemble_results,
            'individual_models': individual_results
        }
    
    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                          y_pred_proba: np.ndarray, model_name: str) -> Dict[str, Any]:
        """Calculate comprehensive evaluation metrics"""
        
        metrics = {
            'model_name': model_name,
            'accuracy': np.mean(y_true == y_pred),
            'f1_score': f1_score(y_true, y_pred),
            'precision': float('nan'),
            'recall': float('nan'),
            'auc_roc': float('nan'),
        }
        
        try:
            # Get detailed classification report
            report = classification_report(y_true, y_pred, output_dict=True)
            
            if '1' in report:  # Ransomware class
                metrics['precision'] = report['1']['precision']
                metrics['recall'] = report['1']['recall']
            
            # AUC-ROC
            if len(np.unique(y_true)) > 1:
                metrics['auc_roc'] = roc_auc_score(y_true, y_pred_proba)
            
            # Confusion matrix
            cm = confusion_matrix(y_true, y_pred)
            metrics['confusion_matrix'] = cm.tolist()
            
            # False positive and false negative rates
            tn, fp, fn, tp = cm.ravel()
            metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0
            metrics['false_negative_rate'] = fn / (fn + tp) if (fn + tp) > 0 else 0
            
        except Exception as e:
            self.logger.warning(f"Error calculating some metrics for {model_name}: {e}")
        
        return metrics
    
    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions on new data"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        # Preprocess the data
        X_processed = self._preprocess_prediction_data(X)
        
        if self.model_name == 'ensemble':
            return self._predict_ensemble(X_processed)
        else:
            return self._predict_single(X_processed, self.model_name)
    
    def _preprocess_prediction_data(self, X: pd.DataFrame) -> pd.DataFrame:
        """Preprocess data for prediction"""
        # Handle missing values
        X = X.fillna(0)
        
        # Ensure we have the same features as training
        if self.feature_names:
            # Add missing features as zeros
            for feature in self.feature_names:
                if feature not in X.columns:
                    X[feature] = 0
            
            # Select and reorder features
            X = X[self.feature_names]
        
        # Apply scaling
        if self.scaler:
            X_scaled = self.scaler.transform(X)
            X = pd.DataFrame(X_scaled, columns=X.columns, index=X.index)
        
        # Apply feature selection
        if self.feature_selector:
            X_selected = self.feature_selector.transform(X)
            selected_features = X.columns[self.feature_selector.get_support()]
            X = pd.DataFrame(X_selected, columns=selected_features, index=X.index)
        
        return X
    
    def _predict_single(self, X: pd.DataFrame, model_name: str) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions with single model"""
        model = self.models[model_name]
        
        predictions = model.predict(X)
        probabilities = model.predict_proba(X)[:, 1] if hasattr(model, 'predict_proba') else predictions
        
        return predictions, probabilities
    
    def _predict_ensemble(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions with ensemble"""
        if not self.models:
            raise ValueError("No models available for ensemble prediction")
        
        all_predictions = []
        all_probabilities = []
        
        for model_name, model in self.models.items():
            pred = model.predict(X)
            prob = model.predict_proba(X)[:, 1] if hasattr(model, 'predict_proba') else pred
            
            all_predictions.append(pred)
            all_probabilities.append(prob)
        
        # Ensemble prediction
        pred_array = np.array(all_predictions)
        prob_array = np.array(all_probabilities)
        
        # Majority vote for final prediction
        ensemble_pred = np.round(np.mean(pred_array, axis=0)).astype(int)
        
        # Average probability
        ensemble_prob = np.mean(prob_array, axis=0)
        
        return ensemble_pred, ensemble_prob
    
    def predict_anomaly(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Detect anomalies using unsupervised learning"""
        if self.anomaly_detector is None:
            raise ValueError("Anomaly detector not trained")
        
        X_processed = self._preprocess_prediction_data(X)
        
        # Predict anomalies (-1 for anomaly, 1 for normal)
        anomaly_pred = self.anomaly_detector.predict(X_processed)
        
        # Get anomaly scores
        anomaly_scores = self.anomaly_detector.decision_function(X_processed)
        
        # Convert to binary (1 for anomaly, 0 for normal)
        anomaly_binary = (anomaly_pred == -1).astype(int)
        
        return anomaly_binary, anomaly_scores
    
    def get_feature_importance(self, top_k: int = 20) -> Dict[str, List]:
        """Get feature importance from trained models"""
        if not self.is_trained:
            raise ValueError("Model must be trained first")
        
        importance_data = {}
        
        for model_name, model in self.models.items():
            if hasattr(model, 'feature_importances_'):
                # Tree-based models
                importances = model.feature_importances_
            elif hasattr(model, 'coef_'):
                # Linear models
                importances = np.abs(model.coef_[0])
            else:
                continue
            
            # Get feature names (after selection if applied)
            if self.feature_selector:
                selected_features = np.array(self.feature_names)[self.feature_selector.get_support()]
            else:
                selected_features = self.feature_names
            
            # Sort by importance
            indices = np.argsort(importances)[::-1][:top_k]
            
            importance_data[model_name] = {
                'features': [selected_features[i] for i in indices],
                'importances': importances[indices].tolist()
            }
        
        return importance_data
    
    def save_model(self, filepath: str = None):
        """Save trained model to disk"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        
        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = config.MODELS_DIR / f"ransomware_detector_{timestamp}.pkl"
        
        model_data = {
            'models': self.models,
            'scaler': self.scaler,
            'feature_selector': self.feature_selector,
            'feature_names': self.feature_names,
            'anomaly_detector': self.anomaly_detector,
            'model_name': self.model_name,
            'is_trained': self.is_trained
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        self.logger.info(f"Model saved to {filepath}")
        return filepath
    
    def load_model(self, filepath: str):
        """Load trained model from disk"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.models = model_data['models']
        self.scaler = model_data['scaler']
        self.feature_selector = model_data['feature_selector']
        self.feature_names = model_data['feature_names']
        self.anomaly_detector = model_data['anomaly_detector']
        self.model_name = model_data['model_name']
        self.is_trained = model_data['is_trained']
        
        self.logger.info(f"Model loaded from {filepath}")
    
    def evaluate_model(self, X: pd.DataFrame, y: np.ndarray) -> Dict[str, Any]:
        """Comprehensive model evaluation"""
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        predictions, probabilities = self.predict(X)
        anomaly_pred, anomaly_scores = self.predict_anomaly(X)
        
        # Supervised evaluation
        supervised_metrics = self._calculate_metrics(y, predictions, probabilities, self.model_name)
        
        # Feature importance
        feature_importance = self.get_feature_importance()
        
        evaluation_results = {
            'supervised_metrics': supervised_metrics,
            'feature_importance': feature_importance,
            'anomaly_detection': {
                'anomalies_detected': np.sum(anomaly_pred),
                'anomaly_rate': np.mean(anomaly_pred)
            }
        }
        
        return evaluation_results
    
    def plot_evaluation_metrics(self, X: pd.DataFrame, y: np.ndarray, save_path: str = None):
        """Plot evaluation metrics and visualizations"""
        if not self.is_trained:
            raise ValueError("Model must be trained before plotting")
        
        predictions, probabilities = self.predict(X)
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Ransomware Detection Model Evaluation', fontsize=16)
        
        # Confusion Matrix
        cm = confusion_matrix(y, predictions)
        sns.heatmap(cm, annot=True, fmt='d', ax=axes[0, 0], cmap='Blues')
        axes[0, 0].set_title('Confusion Matrix')
        axes[0, 0].set_xlabel('Predicted')
        axes[0, 0].set_ylabel('Actual')
        
        # ROC Curve
        if len(np.unique(y)) > 1:
            fpr, tpr, _ = roc_curve(y, probabilities)
            auc = roc_auc_score(y, probabilities)
            axes[0, 1].plot(fpr, tpr, label=f'ROC Curve (AUC = {auc:.3f})')
            axes[0, 1].plot([0, 1], [0, 1], 'k--')
            axes[0, 1].set_xlabel('False Positive Rate')
            axes[0, 1].set_ylabel('True Positive Rate')
            axes[0, 1].set_title('ROC Curve')
            axes[0, 1].legend()
        
        # Precision-Recall Curve
        if len(np.unique(y)) > 1:
            precision, recall, _ = precision_recall_curve(y, probabilities)
            axes[1, 0].plot(recall, precision)
            axes[1, 0].set_xlabel('Recall')
            axes[1, 0].set_ylabel('Precision')
            axes[1, 0].set_title('Precision-Recall Curve')
        
        # Feature Importance (for tree-based models)
        feature_importance = self.get_feature_importance(top_k=10)
        if feature_importance:
            # Use the first model's importance
            first_model = list(feature_importance.keys())[0]
            features = feature_importance[first_model]['features']
            importances = feature_importance[first_model]['importances']
            
            axes[1, 1].barh(range(len(features)), importances)
            axes[1, 1].set_yticks(range(len(features)))
            axes[1, 1].set_yticklabels(features)
            axes[1, 1].set_xlabel('Feature Importance')
            axes[1, 1].set_title(f'Top 10 Features ({first_model})')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Evaluation plots saved to {save_path}")
        
        plt.show()

class RealTimeDetector:
    """Real-time ransomware detection wrapper"""
    
    def __init__(self, ml_detector: RansomwareMLDetector, threshold: float = None):
        self.ml_detector = ml_detector
        self.threshold = threshold or config.ML_CONFIG['prediction_threshold']
        self.logger = logging.getLogger(__name__)
        
        self.detection_history = []
        self.alert_count = 0
    
    def detect(self, features_df: pd.DataFrame) -> Dict[str, Any]:
        """Perform real-time detection on feature data"""
        
        # Supervised detection
        predictions, probabilities = self.ml_detector.predict(features_df)
        
        # Anomaly detection
        anomaly_pred, anomaly_scores = self.ml_detector.predict_anomaly(features_df)
        
        # Combine predictions
        high_risk_supervised = probabilities >= self.threshold
        high_risk_anomaly = anomaly_pred == 1
        
        # Final decision (either method triggers alert)
        final_prediction = high_risk_supervised | high_risk_anomaly
        
        detection_result = {
            'timestamp': datetime.now().isoformat(),
            'ransomware_detected': bool(np.any(final_prediction)),
            'num_suspicious_windows': int(np.sum(final_prediction)),
            'max_probability': float(np.max(probabilities)),
            'avg_probability': float(np.mean(probabilities)),
            'anomaly_count': int(np.sum(anomaly_pred)),
            'predictions': predictions.tolist(),
            'probabilities': probabilities.tolist(),
            'anomaly_scores': anomaly_scores.tolist()
        }
        
        # Store in history
        self.detection_history.append(detection_result)
        
        # Update alert count
        if detection_result['ransomware_detected']:
            self.alert_count += 1
            self.logger.warning(f"RANSOMWARE DETECTED! Alert #{self.alert_count}")
        
        return detection_result
    
    def get_detection_summary(self) -> Dict[str, Any]:
        """Get summary of recent detections"""
        if not self.detection_history:
            return {'total_detections': 0, 'alerts_triggered': 0}
        
        recent_detections = self.detection_history[-100:]  # Last 100 detections
        
        return {
            'total_detections': len(self.detection_history),
            'alerts_triggered': self.alert_count,
            'recent_avg_probability': np.mean([d['avg_probability'] for d in recent_detections]),
            'recent_max_probability': np.max([d['max_probability'] for d in recent_detections]),
            'last_detection_time': recent_detections[-1]['timestamp'] if recent_detections else None
        }

if __name__ == "__main__":
    # Example usage
    print("Machine Learning Ransomware Detector initialized!")
    print("Available models:", ['ensemble', 'random_forest', 'gradient_boosting', 'svm', 'logistic_regression'])
    if XGBOOST_AVAILABLE:
        print("XGBoost is available!")
    
    # Initialize detector
    detector = RansomwareMLDetector('ensemble')
    print("Ready for training with collected features!")