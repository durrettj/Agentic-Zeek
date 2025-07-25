# machine learning model for anomaly detection
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from typing import List, Tuple
import logging

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, algorithm: str = "IsolationForest", contamination: float = 0.01):
        """
        Initializes the anomaly detection model.
        [4, 5]
        
        Args:
            algorithm: The anomaly detection algorithm to use ("IsolationForest" or "OneClassSVM").
            contamination: The estimated proportion of outliers in the data (for IsolationForest).
                           For OneClassSVM, this is typically handled by nu parameter.
        """
        self.algorithm = algorithm
        self.model = None
        self.contamination = contamination
        self.is_trained = False
        logger.info(f"AnomalyDetector initialized with algorithm: {algorithm}, contamination: {contamination}")

    def train(self, normal_data: List[List[float]]):
        """
        Trains the anomaly detection model on a dataset of 'normal' embeddings.
        
        Args:
            normal_data: A list of embedding vectors representing normal behavior.
        """
        if not normal_data:
            logger.warning("No data provided for training the anomaly detector.")
            return

        X = np.array(normal_data)

        if self.algorithm == "IsolationForest":
            self.model = IsolationForest(contamination=self.contamination, random_state=42)
        elif self.algorithm == "OneClassSVM":
            # OneClassSVM's nu parameter is an upper bound on the fraction of training errors
            # and a lower bound of the fraction of support vectors. Often set to contamination.
            self.model = OneClassSVM(kernel='rbf', nu=self.contamination)
        else:
            raise ValueError(f"Unsupported anomaly detection algorithm: {self.algorithm}")

        logger.info(f"Training {self.algorithm} model...")
        self.model.fit(X)
        self.is_trained = True
        logger.info(f"{self.algorithm} model trained successfully.")

    def detect(self, new_data_embedding: List[float]) -> Tuple[bool, float]:
        """
        Detects if a new data embedding is an anomaly.
        
        Args:
            new_data_embedding: A single embedding vector for the new data point.
            
        Returns:
            A tuple: (is_anomaly: bool, anomaly_score: float).
            is_anomaly is True if detected as an anomaly, False otherwise.
            anomaly_score is the decision function score (lower/more negative indicates higher anomaly).
        """
        if not self.is_trained:
            logger.warning("Anomaly detector is not trained. Returning False for anomaly detection.")
            return False, 0.0

        X_new = np.array(new_data_embedding).reshape(1, -1) # Reshape for single sample prediction

        # predict returns -1 for outliers and 1 for inliers
        # decision_function returns the raw anomaly score (lower is more anomalous)
        prediction = self.model.predict(X_new)
        score = self.model.decision_function(X_new)

        is_anomaly = (prediction == -1)
        
        logger.debug(f"Detection result: Anomaly={is_anomaly}, Score={score:.4f}")
        return is_anomaly, score

    def save_model(self, path: str):
        """Saves the trained model to a file."""
        if self.model:
            import joblib
            joblib.dump(self.model, path)
            logger.info(f"Model saved to {path}")
        else:
            logger.warning("No model to save. Train the model first.")

    def load_model(self, path: str):
        """Loads a trained model from a file."""
        import joblib
        try:
            self.model = joblib.load(path)
            self.is_trained = True
            logger.info(f"Model loaded from {path}")
        except FileNotFoundError:
            logger.error(f"Model file not found at {path}")
        except Exception as e:
            logger.error(f"Error loading model from {path}: {e}")

# Example of how to use it (for internal testing/demonstration)
if __name__ == "__main__":
    # Simulate some normal and anomalous embeddings
    # In a real scenario, these would come from EmbeddingService
    normal_embeddings = [0.1, 0.2, 0.3, 0.4, 0.5],
        [0.11, 0.21, 0.31, 0.41, 0.51],
        [0.09, 0.19, 0.29, 0.39, 0.49],
        [0.12, 0.22, 0.32, 0.42, 0.52]
    
    anomaly_embedding_1 = [1.0, 1.1, 1.2, 1.3, 1.4] # Far from normal
    anomaly_embedding_2 = [0.01, 0.02, 0.03, 0.04, 0.05] # Slightly off
    normal_embedding_test = [0.105, 0.205, 0.305, 0.405, 0.505] # Very close to normal

    detector = AnomalyDetector(algorithm="IsolationForest", contamination=0.2)
    detector.train(normal_embeddings)

    is_anomaly, score = detector.detect(normal_embedding_test)
    print(f"Normal test: Is anomaly? {is_anomaly}, Score: {score:.4f}")

    is_anomaly, score = detector.detect(anomaly_embedding_1)
    print(f"Anomaly 1 test: Is anomaly? {is_anomaly}, Score: {score:.4f}")

    is_anomaly, score = detector.detect(anomaly_embedding_2)
    print(f"Anomaly 2 test: Is anomaly? {is_anomaly}, Score: {score:.4f}")

    # Example with OneClassSVM
    detector_ocsvm = AnomalyDetector(algorithm="OneClassSVM", contamination=0.1)
    detector_ocsvm.train(normal_embeddings)
    is_anomaly, score = detector_ocsvm.detect(normal_embedding_test)
    print(f"OCSVM Normal test: Is anomaly? {is_anomaly}, Score: {score:.4f}")
    is_anomaly, score = detector_ocsvm.detect(anomaly_embedding_1)
    print(f"OCSVM Anomaly 1 test: Is anomaly? {is_anomaly}, Score: {score:.4f}")
