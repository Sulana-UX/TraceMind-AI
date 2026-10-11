"""
Machine Learning & Statistical Anomaly Detector
Leverages Scikit-Learn IsolationForest for unsupervised behavioral anomaly scoring.
Scores are provided strictly as prioritization signals, NOT definitive proof of compromise.
"""

from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from src.normalizer import NormalizedEvent


class EntityAnomalyDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100
        )
        self.feature_columns = [
            "failed_auth_count",
            "success_auth_count",
            "unique_destinations",
            "process_start_count",
            "total_bytes_transferred",
            "flow_count",
        ]

    def extract_features(self, events: List[NormalizedEvent]) -> pd.DataFrame:
        """
        Aggregates event records into entity-level behavioral feature vectors.
        Entities are primary actors: users (or source hosts if user is absent).
        """
        entities: Dict[str, Dict[str, Any]] = {}

        for ev in events:
            # Primary entity is User, fallback to src_host
            entity_id = ev.user or ev.src_host or "UNKNOWN_ENTITY"
            if entity_id not in entities:
                entities[entity_id] = {
                    "entity_id": entity_id,
                    "failed_auth_count": 0,
                    "success_auth_count": 0,
                    "unique_destinations": set(),
                    "process_start_count": 0,
                    "total_bytes_transferred": 0,
                    "flow_count": 0,
                }

            row = entities[entity_id]

            if ev.event_type == "AUTH":
                if ev.action == "LOGON_FAIL":
                    row["failed_auth_count"] += 1
                elif ev.action == "LOGON_SUCCESS":
                    row["success_auth_count"] += 1
                if ev.dst_host:
                    row["unique_destinations"].add(ev.dst_host)

            elif ev.event_type == "PROCESS":
                if ev.action == "PROCESS_START":
                    row["process_start_count"] += 1

            elif ev.event_type == "NETWORK_FLOW":
                row["flow_count"] += 1
                if ev.details and "byte_count" in ev.details:
                    b = ev.details.get("byte_count") or 0
                    row["total_bytes_transferred"] += b
                if ev.dst_host:
                    row["unique_destinations"].add(ev.dst_host)

        # Convert set of unique destinations to length
        records = []
        for e_id, data in entities.items():
            records.append({
                "entity_id": e_id,
                "failed_auth_count": data["failed_auth_count"],
                "success_auth_count": data["success_auth_count"],
                "unique_destinations": len(data["unique_destinations"]),
                "process_start_count": data["process_start_count"],
                "total_bytes_transferred": data["total_bytes_transferred"],
                "flow_count": data["flow_count"],
            })

        if not records:
            return pd.DataFrame(columns=["entity_id"] + self.feature_columns)

        return pd.DataFrame(records)

    def fit_predict(self, events: List[NormalizedEvent]) -> pd.DataFrame:
        """
        Fits Isolation Forest and predicts anomaly scores for each entity.
        Gracefully handles small datasets (< 5 entities) using heuristic ranking.
        """
        df_features = self.extract_features(events)
        if df_features.empty:
            return pd.DataFrame(columns=["entity_id", "anomaly_score", "is_anomaly", "primary_factor"])

        num_entities = len(df_features)
        X = df_features[self.feature_columns].fillna(0).values

        if num_entities < 5:
            # Fallback heuristic for tiny test/sample sets
            # Heuristic score based on failed auths and extreme bytes
            scores = []
            factors = []
            for _, r in df_features.iterrows():
                score = 0.1
                factor = "Normal Profile"
                if r["failed_auth_count"] >= 3:
                    score += 0.5
                    factor = f"High failed logons ({r['failed_auth_count']})"
                if r["total_bytes_transferred"] > 10000000:
                    score += 0.3
                    factor += " | High data transfer"
                if r["unique_destinations"] >= 3:
                    score += 0.2
                    factor += " | Multi-host spread"
                scores.append(min(round(score, 3), 1.0))
                factors.append(factor)

            df_features["anomaly_score"] = scores
            df_features["is_anomaly"] = [s >= 0.5 for s in scores]
            df_features["primary_factor"] = factors
            return df_features.sort_values(by="anomaly_score", ascending=False)

        # Fit Isolation Forest
        self.model.fit(X)
        # raw score: lower means more abnormal
        raw_scores = self.model.decision_function(X)
        preds = self.model.predict(X)  # -1 is anomaly, 1 is normal

        # Normalize score to 0.0 (normal) - 1.0 (highly abnormal)
        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s > min_s:
            norm_scores = 1.0 - ((raw_scores - min_s) / (max_s - min_s))
        else:
            norm_scores = np.zeros_like(raw_scores)

        df_features["anomaly_score"] = np.round(norm_scores, 3)
        df_features["is_anomaly"] = preds == -1

        # Identify primary contributing feature
        primary_factors = []
        means = df_features[self.feature_columns].mean()
        stds = df_features[self.feature_columns].std().replace(0, 1)

        for _, row in df_features.iterrows():
            z_scores = {col: (row[col] - means[col]) / stds[col] for col in self.feature_columns}
            top_col = max(z_scores, key=z_scores.get)
            if z_scores[top_col] > 1.0:
                primary_factors.append(f"Unusual {top_col} ({row[top_col]})")
            else:
                primary_factors.append("Behavioral deviations within baseline range")

        df_features["primary_factor"] = primary_factors
        return df_features.sort_values(by="anomaly_score", ascending=False)
