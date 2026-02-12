import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import KMeans, DBSCAN
from sklearn.decomposition import PCA
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score, silhouette_score
import xgboost as xgb
import shap
import json
import joblib
import os

class MLEngine:
    def __init__(self):
        self.rf_model = None
        self.xgb_model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.kmeans = None
        self.pca = None
        self.feature_cols = [
            'login_attempts', 'failed_logins', 'duration', 'events_count', 
            'bytes_transferred', 'geo_distance_from_last_login', 'velocity_score',
            'country_encoded', 'device_encoded'
        ]
        self.target_col = 'risk_label_encoded'

    def preprocess(self, df, training=True):
        df_processed = df.copy()
        
        # Production Dataset Column Mapping
        # Mapping production columns to internal feature names used by models/frontend
        column_map = {
            'session_id': 'session_id',
            'src_ip': 'ip_address',
            'event_count': 'events_count',
            'session_duration': 'duration',
            'unique_commands': 'unique_commands',
            'risk_score': 'risk_score',
            'behavior_cluster': 'cluster',           # Use pre-calculated cluster
            'behavior_label': 'risk_label',          # Use pre-calculated label
            'attacker_type': 'attacker_type',        # New enriched field
            'threat_archetype': 'threat_archetype',  # New enriched field
            'country': 'country',
            'asn_org': 'asn',
            'latitude': 'lat',
            'longitude': 'lon'
        }
        
        # Avoid duplicate columns after rename (e.g. if 'asn' and 'asn_org' both exist)
        # We want 'asn_org' to become 'asn', so we should drop original 'asn' if it exists
        if 'asn' in df_processed.columns and 'asn_org' in df_processed.columns:
            df_processed = df_processed.drop(columns=['asn'])
            
        # Also check for 'cluster' duplicate. The mapping says 'behavior_cluster' -> 'cluster'.
        # If 'cluster' already exists in the csv (unlikely but possible), drop it.
        if 'cluster' in df_processed.columns and 'behavior_cluster' in df_processed.columns:
            df_processed = df_processed.drop(columns=['cluster'])
            
        # Rename columns that match our map
        df_processed = df_processed.rename(columns=column_map)
        
        # Feature Engineering / Filling Missing Internal Features
        
        # 'login_attempts' proxy: unique_commands is a good proxy for complexity, but strictly not attempts.
        # If we don't have login_attempts, we can use event_count or unique_commands as a feature.
        if 'login_attempts' not in df_processed.columns:
            # If data is normalized (z-score like in sample), we might need to be careful.
            # Assuming the production data is already processed/normalized given the values like 3.37...
            # We will just assign it to existing columns or 0 if truly missing to satisfy model API.
            df_processed['login_attempts'] = df_processed['unique_commands'] if 'unique_commands' in df_processed.columns else 0

        # 'bytes_transferred' proxy
        if 'bytes_transferred' not in df_processed.columns:
            df_processed['bytes_transferred'] = 0
            
        # 'velocity_score' proxy: duration / events?
        if 'velocity_score' not in df_processed.columns:
             # If duration is z-score, this math is invalid. 
             # Check if 'confidence_level' or similar can be a proxy, otherwise 0.
             df_processed['velocity_score'] = 0

        # 'failed_logins' proxy
        if 'failed_logins' not in df_processed.columns:
            df_processed['failed_logins'] = 0

        # 'geo_distance_from_last_login' proxy
        if 'geo_distance_from_last_login' not in df_processed.columns:
            df_processed['geo_distance_from_last_login'] = 0

        # Ensure 'predicted_risk_level' matches 'risk_label' for consistency with frontend
        if 'risk_label' in df_processed.columns:
            df_processed['predicted_risk_level'] = df_processed['risk_label']
        
        # Ensure 'is_anomaly' exists. If not, maybe define based on risk_score > threshold?
        if 'is_anomaly' not in df_processed.columns:
            # Assume high risk score (z-score > 3 or raw > 80) is anomaly. 
            # In sample: 4.46 is high. Let's say > 3.
            if 'risk_score' in df_processed.columns:
                 df_processed['is_anomaly'] = df_processed['risk_score'] > 3
            else:
                 df_processed['is_anomaly'] = False

        # Encode Categorical Variables (for any new training, though we might just use pre-calc)
        cat_cols = ['country', 'device_type', 'asn']
        cat_cols = ['country', 'device_type', 'asn']
        
        for col in cat_cols:
            if col not in df_processed.columns:
                continue
                
            if training:
                le = LabelEncoder()
                df_processed[f'{col}_encoded'] = le.fit_transform(df_processed[col].astype(str))
                self.label_encoders[col] = le
            else:
                if col in self.label_encoders:
                    # Handle unseen labels by assigning a default or skipping
                    le = self.label_encoders[col]
                    df_processed[f'{col}_encoded'] = df_processed[col].map(lambda x: le.transform([x])[0] if x in le.classes_ else -1)
        
        # Ensure we have the encoded columns we need for features
        if 'device_type_encoded' not in df_processed.columns:
             df_processed['device_encoded'] = 0 # Fallback
        else:
             df_processed['device_encoded'] = df_processed['device_type_encoded']
             
        if 'country_encoded' not in df_processed.columns:
             df_processed['country_encoded'] = 0

        # Fill NaNs
        df_processed = df_processed.fillna(0)
        
        return df_processed

    def train_supervised(self, df):
        # Preprocess
        df_processed = self.preprocess(df, training=True)
        
        # If pre-calculated risk labels exist, we can skip full training if just for visualization
        # But to keep API consistent, we will train. 
        # Note: If features are normalized (z-scores), Standard Scaler might not be needed or double scale.
        
        if 'risk_label' in df_processed.columns:
            le_target = LabelEncoder()
            y = le_target.fit_transform(df_processed['risk_label'])
            self.label_encoders['risk_label'] = le_target
        else:
            raise ValueError("Training data must have 'risk_label' column")

        # Select available features for training
        # If proxies like 'unique_commands' are used, we need to adjust self.feature_cols?
        # For now, we assume the preprocessing step filled the missing standard cols.
        X = df_processed[self.feature_cols]
        
        # Scale
        X_scaled = self.scaler.fit_transform(X)
        
        # Split
        try:
            X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
            
            # Train RF
            self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.rf_model.fit(X_train, y_train)
            
            # Train XGBoost
            self.xgb_model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
            self.xgb_model.fit(X_train, y_train)
            
            # Metrics
            y_pred = self.rf_model.predict(X_test)
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
                'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            }
            
            # Feature Importance
            importances = dict(zip(self.feature_cols, self.rf_model.feature_importances_))
        except Exception as e:
            print(f"Training failed (possibly too few samples or classes): {e}")
            metrics = {'accuracy': 0, 'precision': 0, 'recall': 0}
            importances = {}
        
        return metrics, importances

    def predict_risk(self, df):
        df_processed = self.preprocess(df, training=False)
        
        # If the dataset already has prediction columns (e.g. production dataset), use them!
        if 'ml_risk_score' in df_processed.columns and 'ml_risk_label' in df_processed.columns:
             # Map ml_risk_score to risk_score if not already done in preprocess
             # The preprocessing mapped 'risk_score' from file, which might be z-score. 
             # Let's ensure we use a 0-100 scale for frontend.
             
             results = df_processed.copy()
             
             # If risk_score is z-score (e.g. -1 to 5), map to 0-100 roughly for display
             # Or if it's already 0-100, keep it.
             # Sample data shows risk_score: 4.46 (high), -0.22 (low). Looks like z-score.
             # Transform: 0 -> 50, +5 -> 100, -5 -> 0?
             # Simple sigmoid-like or min-max scaling if we knew bounds. 
             # Let's do a simple linear map: (val + 2) * 20 clipped 0-100?
             # 4.46 -> 6.46 * 20 = 129 -> 100. -0.22 -> 1.78 * 20 = 35.
             
             def map_z_score(z):
                 if pd.isna(z): return 0
                 # Heuristic mapping for display
                 score = (z + 2) * 20
                 return max(0, min(100, score))

             if results['risk_score'].max() < 20: # Heuristic to detect z-score vs 0-100
                  results['risk_score'] = results['risk_score'].apply(map_z_score)

             return results

        X = df_processed[self.feature_cols]
        X_scaled = self.scaler.transform(X)
        
        # Predict
        probs = self.rf_model.predict_proba(X_scaled)
        preds = self.rf_model.predict(X_scaled)
        
        # Map back to labels
        if 'risk_label' in self.label_encoders:
            pred_labels = self.label_encoders['risk_label'].inverse_transform(preds)
        else:
            pred_labels = preds
            
        # Calculate Risk Score (0-100) based on probability of 'High' risk class (assuming encoded high is one of them)
        # Simplified: Max probability * 100
        risk_scores = [max(p) * 100 for p in probs]
        
        results = df.copy()
        results['predicted_risk_level'] = pred_labels
        results['risk_score'] = risk_scores
        
        return results

    def run_clustering(self, df):
        df_processed = self.preprocess(df, training=False)
        features = ['login_attempts', 'duration', 'bytes_transferred', 'velocity_score']
        X = df_processed[features]
        X_scaled = StandardScaler().fit_transform(X)
        
        # KMeans
        self.kmeans = KMeans(n_clusters=3, random_state=42)
        clusters = self.kmeans.fit_predict(X_scaled)
        
        # DBSCAN for anomalies
        dbscan = DBSCAN(eps=0.5, min_samples=5)
        anomalies = dbscan.fit_predict(X_scaled) # -1 are anomalies
        
        # PCA for Vis
        self.pca = PCA(n_components=2)
        pca_res = self.pca.fit_transform(X_scaled)
        
        results = df.copy()
        results['cluster'] = clusters
        results['is_anomaly'] = anomalies == -1
        results['pca_x'] = pca_res[:, 0]
        results['pca_y'] = pca_res[:, 1]
        
        silhouette = silhouette_score(X_scaled, clusters)
        
        return results, silhouette

    def get_cluster_profiles(self, df):
        if 'cluster' not in df.columns:
            return {}
            
        features = ['login_attempts', 'duration', 'bytes_transferred', 'velocity_score', 'events_count']
        # Group by cluster and calculate mean
        # Ensure keys are standard python types (not numpy.int64) for JSON serialization
        profiles = df.groupby('cluster')[features].mean().to_dict(orient='index')
        return {str(k): v for k, v in profiles.items()}
        
    def generate_stability_plot(self, df):
        # Generate a mock stability plot (Silhouette Analysis) and save as PNG
        # Since we are in a web app, we might just return the silhouette score or a list of scores for different k
        # For "Pngs from steps", we will use matplotlib to create a figure and save it
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import io
        import base64
        
        if 'cluster' not in df.columns:
            return None

        # Just plot the cluster distribution for now or silhouette values
        fig, ax = plt.subplots(figsize=(6, 4))
        df['cluster'].value_counts().sort_index().plot(kind='bar', ax=ax, color='#bb86fc')
        ax.set_title('Cluster Stability (Distribution)')
        ax.set_xlabel('Cluster')
        ax.set_ylabel('Count')
        ax.set_facecolor('#1e1e1e')
        fig.patch.set_facecolor('#1e1e1e')
        ax.tick_params(colors='white')
        ax.xaxis.label.set_color('white')
        ax.yaxis.label.set_color('white')
        ax.title.set_color('white')
        
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png')
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def get_shap_values(self, df, sample_size=10):
        # Just return a small sample for visualization purposes
        df_processed = self.preprocess(df, training=False)
        X = df_processed[self.feature_cols]
        X_scaled = self.scaler.transform(X)
        
        # Use TreeExplainer (optimized for trees)
        explainer = shap.TreeExplainer(self.rf_model)
        shap_values = explainer.shap_values(X_scaled[:sample_size])
        
        # SHAP returns a list of arrays for classification (one per class). We'll take the first one or combine.
        # For simplicity in JSON, we'll return the summary values (mean absolute SHAP)
        
        if isinstance(shap_values, list):
             # Multi-class
             # Average impact across classes
             shap_summary = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
        else:
             shap_summary = np.abs(shap_values).mean(axis=0)

        return dict(zip(self.feature_cols, shap_summary.tolist()))

    def enrich_geo_mock(self, df):
        # Mock Geo Enrichment if real DB not present
        # Assign random Lat/Lon roughly based on country code or random if missing
        
        country_coords = {
            'US': [37.0902, -95.7129],
            'CN': [35.8617, 104.1954],
            'RU': [61.5240, 105.3188],
            'IN': [20.5937, 78.9629],
            'UK': [55.3781, -3.4360],
            'DE': [51.1657, 10.4515],
            'FR': [46.2276, 2.2137],
            'JP': [36.2048, 138.2529]
        }
        
        lats = []
        lons = []
        
        for c in df['country']:
            coords = country_coords.get(c, [0, 0])
            # Add jitter
            lats.append(coords[0] + np.random.uniform(-5, 5))
            lons.append(coords[1] + np.random.uniform(-5, 5))
            
        df['lat'] = lats
        df['lon'] = lons
        return df

if __name__ == "__main__":
    # Test run
    df = pd.read_csv('data/session_logs.csv')
    engine = MLEngine()
    metrics, imp = engine.train_supervised(df)
    print("Training Metrics:", metrics)
    
    res, sil = engine.run_clustering(df)
    print("Silhouette Score:", sil)
