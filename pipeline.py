#!/usr/bin/env python3
"""
Cowrie Honeypot Data Pipeline - Complete Production Pipeline
=============================================================
Single-file pipeline that processes raw Cowrie JSON logs into a fully
enriched, ML-ready CSV and uploads it to the dashboard.

Pipeline Stages:
  [Stage 1] Session Aggregation       - Parse Cowrie JSON → sessions
  [Stage 2] Feature Engineering       - Extract & validate behavioral features
  [Stage 3] Behavioral Clustering     - Feature selection → scaling → KMeans
                                        validation → final clusters → profiling
                                        → behavior labeling → DBSCAN anomaly
                                        detection → cluster stability
  [Stage 4] Threat Intelligence       - IP intelligence + attacker/archetype mapping
  [Stage 5] GeoIP Enrichment          - Country, city, lat/lon, ASN via ip-api.com
  [Stage 6] Threat Intel Enrichment   - Risk level scoring
  [Stage 7] Campaign Analysis         - Group by country+ASN campaign key
  [Stage 8] ML Pipeline               - Scale → Train → Evaluate → Predict risk
  [Final]   Save CSV → Upload to dashboard
"""

import json
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from pathlib import Path
import sys
import hashlib
import time
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics import (
    silhouette_score, adjusted_rand_score,
    accuracy_score, precision_score, recall_score
)
from sklearn.model_selection import train_test_split

# ===== CONFIGURATION =====
COWRIE_LOG_PATH      = "/home/ubuntu/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_CSV_PATH      = "/home/ubuntu/Desktop/cowrie_pipeline/attacks.csv"
DASHBOARD_UPLOAD_URL = "https://aisshhoneypot-80qj.onrender.com/upload"
PROJECT_DIR          = "/home/ubuntu/Desktop/cowrie_pipeline"
MODEL_PATH           = "/home/ubuntu/Desktop/cowrie_pipeline/anomaly_model.pkl"

SESSION_COUNTER = 10000

# ===== LOGGING HELPER =====
def log(message):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")
    sys.stdout.flush()

# ================================================================
# SECTION 1 - IP CLASSIFICATION
# ================================================================

def classify_ip_scope(ip):
    """Determine if IP is private or public"""
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return 'unknown'
        first  = int(octets[0])
        second = int(octets[1])
        if first == 10:
            return 'private'
        elif first == 172 and 16 <= second <= 31:
            return 'private'
        elif first == 192 and second == 168:
            return 'private'
        elif first == 127:
            return 'private'
        else:
            return 'public'
    except:
        return 'unknown'

# ================================================================
# SECTION 2 - FEATURE ENGINEERING
# ================================================================

def fe_step1_extract_features(summary):
    """
    Feature Engineering Step 1:
    Validate and extract core session features.
    Adds: unique_usernames, failed_logins, successful_login,
          high_event_activity, long_session, credential_guessing.
    """
    log("  [FE Step 1] Extracting and validating session features...")
    df = summary.copy()

    # Safe defaults for missing columns
    for col in ['unique_usernames', 'failed_logins', 'successful_login']:
        if col not in df.columns:
            df[col] = 0

    # Dynamic threshold flags (median-based)
    df['high_event_activity'] = df['event_count']     > df['event_count'].median()
    df['long_session']        = df['session_duration'] > df['session_duration'].median()
    df['credential_guessing'] = df['failed_logins']    > 0

    log(f"  [FE Step 1] ✓ {len(df)} sessions validated")
    return df


def fe_step2_advanced_behavioral(df):
    """
    Feature Engineering Step 2:
    Fixed-threshold behavioral flags + integer behavioral_risk_score (0-3).
    """
    log("  [FE Step 2] Computing advanced behavioral features...")
    df = df.copy()

    df['high_event_activity']   = df['event_count']     > 10
    df['long_session']          = df['session_duration'] > 60
    df['command_heavy']         = df['unique_commands']  > 5

    df['behavioral_risk_score'] = (
        df['high_event_activity'].astype(int) +
        df['long_session'].astype(int) +
        df['command_heavy'].astype(int)
    )

    log(f"  [FE Step 2] ✓ Behavioral score dist: {df['behavioral_risk_score'].value_counts().to_dict()}")
    return df

# ================================================================
# SECTION 3 - BEHAVIORAL CLUSTERING
# (from step1_feature_selection → step8_cluster_stability + step9_IP_Fixed)
# ================================================================

def bc_step1_select_features(df):
    """
    Clustering Step 1: Select the 4 core behavioral features for clustering.
    Features: event_count, unique_commands, session_duration, behavioral_risk_score
    Returns a clean feature DataFrame aligned with session column.
    """
    log("  [BC Step 1] Selecting behavioral features for clustering...")

    # Use behavioral_risk_score as our risk proxy (replaces risk_score at this stage)
    features = ['event_count', 'unique_commands', 'session_duration', 'behavioral_risk_score']

    # Ensure all features exist
    for f in features:
        if f not in df.columns:
            df[f] = 0

    df_behavior = df[['session'] + features].copy()

    # Data integrity check
    null_counts = df_behavior.isnull().sum().sum()
    if null_counts > 0:
        log(f"  [BC Step 1] ⚠️  Filling {null_counts} null values with 0")
        df_behavior = df_behavior.fillna(0)

    log(f"  [BC Step 1] ✓ {len(features)} features selected for {len(df_behavior)} sessions")
    return df_behavior


def bc_step2_scale_features(df_behavior):
    """
    Clustering Step 2: StandardScaler on the 4 behavioral features.
    Returns scaled DataFrame (session column preserved).
    """
    log("  [BC Step 2] Scaling behavioral features...")

    features    = ['event_count', 'unique_commands', 'session_duration', 'behavioral_risk_score']
    scaler      = StandardScaler()
    scaled_vals = scaler.fit_transform(df_behavior[features])

    df_scaled             = pd.DataFrame(scaled_vals, columns=features)
    df_scaled['session']  = df_behavior['session'].values

    log(f"  [BC Step 2] ✓ Features scaled successfully")
    return df_scaled, scaler


def bc_step3_kmeans_validation(df_scaled):
    """
    Clustering Step 3: Test k=2..7 and compute inertia + silhouette score.
    Returns dict of metrics and the best k (highest silhouette).
    """
    log("  [BC Step 3] Running KMeans validation (k=2..7)...")

    X       = df_scaled.drop(columns=['session'])
    results = []

    for k in range(2, 8):
        kmeans     = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels     = kmeans.fit_predict(X)
        inertia    = kmeans.inertia_
        silhouette = silhouette_score(X, labels)
        results.append({'k': k, 'inertia': round(inertia, 4), 'silhouette_score': round(silhouette, 4)})

    metrics_df = pd.DataFrame(results)
    best_k     = int(metrics_df.loc[metrics_df['silhouette_score'].idxmax(), 'k'])

    log(f"  [BC Step 3] ✓ Best k={best_k} (silhouette={metrics_df.loc[metrics_df['k']==best_k,'silhouette_score'].values[0]})")
    log(f"  [BC Step 3]   Validation results:\n{metrics_df.to_string(index=False)}")

    return metrics_df, best_k


def bc_step4_kmeans_final(df_scaled, n_clusters=3):
    """
    Clustering Step 4: Fit final KMeans with chosen n_clusters (default 3).
    Returns df_scaled with behavior_cluster column added.
    """
    log(f"  [BC Step 4] Fitting final KMeans (k={n_clusters})...")

    X      = df_scaled.drop(columns=['session'])
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)

    df_scaled                  = df_scaled.copy()
    df_scaled['behavior_cluster'] = kmeans.fit_predict(X)

    dist = df_scaled['behavior_cluster'].value_counts().to_dict()
    log(f"  [BC Step 4] ✓ Cluster distribution: {dist}")

    return df_scaled, kmeans


def bc_step5_cluster_profiling(df_clustered, df_original):
    """
    Clustering Step 5: Compute mean feature values per cluster.
    Returns cluster_profiles dict (cluster_id → feature means).
    """
    log("  [BC Step 5] Profiling clusters...")

    # Merge cluster labels back to original (unscaled) data for profiling
    df_orig          = df_original.copy()
    df_orig          = df_orig.merge(
        df_clustered[['session', 'behavior_cluster']], on='session', how='left'
    )

    numeric_cols = ['event_count', 'unique_commands', 'session_duration', 'behavioral_risk_score']
    profiles     = (
        df_orig.groupby('behavior_cluster')[numeric_cols]
        .mean()
        .round(2)
        .to_dict(orient='index')
    )

    for cluster_id, vals in profiles.items():
        log(f"  [BC Step 5]   Cluster {cluster_id}: {vals}")

    return profiles, df_orig


def bc_step6_behavior_labeling(df_orig):
    """
    Clustering Step 6: Assign Low/Medium/High Risk labels to clusters
    based on mean behavioral_risk_score per cluster.
    Adds behavior_label column.
    """
    log("  [BC Step 6] Assigning behavior labels to clusters...")

    df = df_orig.copy()

    cluster_risk   = df.groupby('behavior_cluster')['behavioral_risk_score'].mean()
    sorted_clusters = cluster_risk.sort_values()

    labels = {}
    labels[sorted_clusters.index[0]]  = 'Low Risk'
    labels[sorted_clusters.index[-1]] = 'High Risk'
    for c in sorted_clusters.index[1:-1]:
        labels[c] = 'Medium Risk'

    df['behavior_label'] = df['behavior_cluster'].map(labels)

    dist = df['behavior_label'].value_counts().to_dict()
    log(f"  [BC Step 6] ✓ Behavior label distribution: {dist}")

    return df, labels


def bc_step7_dbscan_anomaly(df_scaled):
    """
    Clustering Step 7: DBSCAN anomaly detection on scaled features.
    Label -1 = anomaly. Adds is_anomaly (bool) and dbscan_label (int) columns.
    Returns Series of is_anomaly aligned by index.
    """
    log("  [BC Step 7] Running DBSCAN anomaly detection...")

    X          = df_scaled.drop(columns=['session', 'behavior_cluster'], errors='ignore')
    X          = X.select_dtypes(include=['number'])

    db         = DBSCAN(eps=1.2, min_samples=3)
    labels     = db.fit_predict(X)

    anomaly_count = int((labels == -1).sum())
    log(f"  [BC Step 7] ✓ Anomalies detected: {anomaly_count} / {len(labels)}")

    return pd.Series(labels == -1, name='is_anomaly'), pd.Series(labels, name='dbscan_label')


def bc_step8_cluster_stability(df_scaled):
    """
    Clustering Step 8: Measure cluster stability via Adjusted Rand Score
    across 3 random seed pairs. Returns mean stability score.
    """
    log("  [BC Step 8] Measuring cluster stability...")

    X      = df_scaled.drop(columns=['session', 'behavior_cluster'], errors='ignore')
    X      = X.select_dtypes(include=['number'])
    scores = []

    for seed in [0, 10, 20]:
        km1 = KMeans(n_clusters=3, random_state=seed,     n_init=10).fit(X)
        km2 = KMeans(n_clusters=3, random_state=seed + 1, n_init=10).fit(X)
        scores.append(adjusted_rand_score(km1.labels_, km2.labels_))

    mean_stability = round(float(np.mean(scores)), 4)
    log(f"  [BC Step 8] ✓ Stability scores: {[round(s,4) for s in scores]} | Mean: {mean_stability}")

    return mean_stability


def bc_step9_ip_threat_mapping(df):
    """
    Clustering Step 9: Cluster-based attacker type + threat archetype mapping.
    Also sets geo_visualization flag based on IP scope.
    Adds: attacker_type, threat_archetype, confidence_level, geo_visualization.
    """
    log("  [BC Step 9] Applying cluster-based threat intelligence mapping...")

    df = df.copy()

    def cluster_threat_mapping(cluster_id):
        mapping = {
            0: ('Low Automation',  'Reconnaissance / Noise',  'Medium'),
            1: ('Brute Force Bot', 'Credential Stuffing',     'High'),
            2: ('Manual Attacker', 'Interactive Exploration', 'High'),
            3: ('Scanner',         'Wide Network Scan',       'Medium'),
            4: ('Unknown Pattern', 'Anomalous Behavior',      'Low'),
        }
        return mapping.get(int(cluster_id), ('Unclassified', 'Unknown', 'Low'))

    df[['attacker_type', 'threat_archetype', 'confidence_level']] = (
        df['behavior_cluster']
        .apply(lambda x: pd.Series(cluster_threat_mapping(x)))
    )

    # geo_visualization flag
    if 'ip_scope' in df.columns:
        df['geo_visualization'] = df['ip_scope'].apply(
            lambda x: 'enabled' if x == 'public' else 'disabled'
        )
    else:
        df['geo_visualization'] = 'disabled'

    df['soc_relevance'] = 'behavioral_intelligence'

    log(f"  [BC Step 9] ✓ Attacker types: {df['attacker_type'].value_counts().to_dict()}")
    return df


def run_behavioral_clustering(summary):
    """
    Orchestrates all 9 behavioral clustering steps.
    Returns enriched DataFrame with all clustering columns attached.
    """
    log("\n" + "=" * 55)
    log("Starting Behavioral Clustering Pipeline (Steps 1-9)")
    log("=" * 55)

    try:
        # Step 1: Select features
        df_behavior = bc_step1_select_features(summary)

        # Step 2: Scale
        df_scaled, scaler = bc_step2_scale_features(df_behavior)

        # Step 3: Validate k (only log, we use k=3 by default for stability)
        metrics_df, best_k = bc_step3_kmeans_validation(df_scaled)
        # Use best_k from validation but cap at 4 for production reliability
        final_k = min(best_k, 4)

        # Step 4: Final KMeans
        df_clustered, kmeans_model = bc_step4_kmeans_final(df_scaled, n_clusters=final_k)

        # Step 5: Profiling
        profiles, df_orig = bc_step5_cluster_profiling(df_clustered, summary)

        # Step 6: Behavior labeling
        df_labeled, label_map = bc_step6_behavior_labeling(df_orig)

        # Step 7: DBSCAN anomaly detection
        is_anomaly, dbscan_labels = bc_step7_dbscan_anomaly(df_clustered)
        df_labeled['is_anomaly']   = is_anomaly.values
        df_labeled['dbscan_label'] = dbscan_labels.values

        # Step 8: Cluster stability
        stability_score = bc_step8_cluster_stability(df_clustered)
        df_labeled['cluster_stability'] = stability_score

        # Step 9: IP threat mapping
        df_labeled = bc_step9_ip_threat_mapping(df_labeled)

        log("=" * 55)
        log("✓ Behavioral Clustering Pipeline Complete!")
        log(f"  Clusters: {final_k} | Stability: {stability_score}")
        log(f"  Anomalies: {df_labeled['is_anomaly'].sum()} sessions flagged")
        log("=" * 55 + "\n")

        return df_labeled

    except Exception as e:
        log(f"❌ Behavioral Clustering failed: {e}")
        import traceback
        traceback.print_exc()

        # Graceful fallback - add empty clustering columns
        summary = summary.copy()
        summary['behavior_cluster']    = 0
        summary['behavior_label']      = 'Unknown'
        summary['is_anomaly']          = False
        summary['dbscan_label']        = 0
        summary['cluster_stability']   = 0.0
        summary['attacker_type']       = 'Unclassified'
        summary['threat_archetype']    = 'Unknown'
        summary['confidence_level']    = 'Low'
        summary['geo_visualization']   = 'disabled'
        summary['soc_relevance']       = 'behavioral_intelligence'
        return summary

# ================================================================
# SECTION 4 - RISK SCORING
# ================================================================

def calculate_z_risk_score(event_count_norm, unique_commands_norm, duration_norm, cluster):
    """Z-score style risk score (-2 to +5) with cluster weight"""
    base_risk = (
        event_count_norm    * 0.4 +
        unique_commands_norm * 0.3 +
        duration_norm        * 0.2
    )
    cluster_weights = {0: 2.0, 1: 1.0, 2: 0.0, 3: -0.5}
    risk_score  = base_risk + cluster_weights.get(int(cluster), 0)
    risk_score += np.random.normal(0, 0.3)
    return risk_score


def determine_behavior_label_from_zscore(risk_score):
    """Map z-score risk score to High/Medium/Low Risk label"""
    if risk_score > 2:
        return 'High Risk'
    elif risk_score > 0:
        return 'Medium Risk'
    else:
        return 'Low Risk'

# ================================================================
# SECTION 5 - GEOIP ENRICHMENT
# ================================================================

def get_geo_data(ip):
    """
    GeoIP lookup via ip-api.com (free, no key).
    Private IPs return 'Internal' immediately without API call.
    Rate limited: 1.5s sleep between requests (~40 req/min).
    """
    if classify_ip_scope(ip) == 'private':
        return {
            'country': 'Internal', 'country_iso': 'INT', 'city': 'Internal',
            'latitude': None, 'longitude': None,
            'asn': 'unknown', 'asn_org': 'unknown'
        }
    try:
        time.sleep(1.5)
        url      = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                asn_full  = data.get('as', 'unknown unknown')
                asn_parts = asn_full.split(' ', 1)
                return {
                    'country':     data.get('country', 'unknown'),
                    'country_iso': data.get('countryCode', 'unknown'),
                    'city':        data.get('city', 'unknown'),
                    'latitude':    data.get('lat'),
                    'longitude':   data.get('lon'),
                    'asn':         asn_parts[0] if asn_parts else 'unknown',
                    'asn_org':     asn_parts[1] if len(asn_parts) > 1 else 'unknown'
                }
    except Exception as e:
        log(f"  ⚠️  Geo lookup failed for {ip}: {e}")

    return {
        'country': 'unknown', 'country_iso': 'unknown', 'city': 'unknown',
        'latitude': None, 'longitude': None,
        'asn': 'unknown', 'asn_org': 'unknown'
    }


def geoip_enrich(summary):
    """Look up unique public IPs (max 20 per run) and attach geo columns."""
    log("  [GeoIP Step 1] Enriching sessions with GeoIP data...")

    public_ips = summary[summary['ip_scope'] == 'public']['src_ip'].unique()
    log(f"  [GeoIP Step 1] {len(public_ips)} public IPs | ETA ~{int(min(len(public_ips), 20) * 1.5)}s")

    geo_cache = {}
    for i, ip in enumerate(public_ips[:20], 1):
        if i % 5 == 0:
            log(f"  [GeoIP Step 1] Progress: {i}/{min(len(public_ips), 20)}")
        geo_cache[ip] = get_geo_data(ip)

    def apply_geo(row):
        ip = row['src_ip']
        if ip in geo_cache:
            return pd.Series(geo_cache[ip])
        if classify_ip_scope(ip) == 'private':
            return pd.Series({'country': 'Internal', 'country_iso': 'INT', 'city': 'Internal',
                               'latitude': None, 'longitude': None, 'asn': 'unknown', 'asn_org': 'unknown'})
        return pd.Series({'country': 'unknown', 'country_iso': 'unknown', 'city': 'unknown',
                          'latitude': None, 'longitude': None, 'asn': 'unknown', 'asn_org': 'unknown'})

    geo_df             = summary.apply(apply_geo, axis=1)
    summary            = summary.copy()
    summary['country']     = geo_df['country']
    summary['country_iso'] = geo_df['country_iso']
    summary['city']        = geo_df['city']
    summary['latitude']    = geo_df['latitude']
    summary['longitude']   = geo_df['longitude']
    summary['asn']         = geo_df['asn']
    summary['asn_org']     = geo_df['asn_org']

    log("  [GeoIP Step 1] ✓ GeoIP enrichment complete")
    return summary


def threat_intel_enrichment(df):
    """Add risk_level (low/medium/high) from fixed behavioral thresholds."""
    log("  [GeoIP Step 2] Applying threat intel enrichment...")
    df           = df.copy()
    intel_score  = (
        (df['event_count']     > 10).astype(int) +
        (df['session_duration'] > 300).astype(int) +
        (df['unique_commands']  > 5).astype(int)
    )
    df['risk_level'] = intel_score.map({0: 'low', 1: 'low', 2: 'medium', 3: 'high'}).fillna('high')
    log(f"  [GeoIP Step 2] ✓ Risk levels: {df['risk_level'].value_counts().to_dict()}")
    return df


def campaign_analysis(df):
    """Group sessions into campaigns by country_iso + ASN. Adds campaign columns."""
    log("  [GeoIP Step 3] Running campaign analysis...")
    df               = df.copy()
    df['campaign_key'] = df['country_iso'].astype(str) + "_" + df['asn'].astype(str)

    campaigns = (
        df.groupby('campaign_key')
        .agg(
            campaign_total_sessions  = ('session', 'count'),
            campaign_avg_event_count = ('event_count', 'mean'),
            campaign_avg_unique_cmds = ('unique_commands', 'mean'),
            campaign_high_activity   = ('high_event_activity', 'sum'),
            campaign_command_heavy   = ('command_heavy', 'sum'),
        )
        .reset_index()
    )

    def campaign_severity(row):
        score = 0
        if row['campaign_avg_event_count'] > 10: score += 1
        if row['campaign_avg_unique_cmds']  > 5:  score += 1
        if row['campaign_high_activity']    > 0:  score += 1
        if row['campaign_command_heavy']    > 0:  score += 1
        if score >= 3: return 'high'
        if score == 2: return 'medium'
        return 'low'

    campaigns['campaign_severity'] = campaigns.apply(campaign_severity, axis=1)
    df = df.merge(
        campaigns[['campaign_key', 'campaign_total_sessions', 'campaign_severity']],
        on='campaign_key', how='left'
    )

    log(f"  [GeoIP Step 3] ✓ {len(campaigns)} campaigns | Severity: {campaigns['campaign_severity'].value_counts().to_dict()}")
    return df

# ================================================================
# SECTION 6 - ML PIPELINE
# ================================================================

def ml_step1_prepare_features(summary_df):
    """ML Step 1: Scale all numeric features with StandardScaler"""
    log("  [ML Step 1] Preparing and scaling features...")
    num_df    = summary_df.select_dtypes(include="number").fillna(0)
    scaler    = StandardScaler()
    scaled    = scaler.fit_transform(num_df)
    scaled_df = pd.DataFrame(scaled, columns=num_df.columns)
    log(f"  [ML Step 1] ✓ {len(scaled_df.columns)} features | {len(scaled_df)} sessions")
    return scaled_df, scaler


def ml_step2_train_model(scaled_df):
    """ML Step 2: Train RandomForest, save model to disk"""
    log("  [ML Step 2] Training Random Forest anomaly model...")
    X = scaled_df
    y = (X.sum(axis=1) > X.sum(axis=1).median()).astype(int)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(Xtr, ytr)
    Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    log(f"  [ML Step 2] ✓ Model saved to {MODEL_PATH}")
    return model


def ml_step3_evaluate_model(model, scaled_df):
    """ML Step 3: Calculate accuracy, precision, recall"""
    log("  [ML Step 3] Evaluating model performance...")
    X      = scaled_df
    y_true = (X.sum(axis=1) > X.sum(axis=1).median()).astype(int)
    y_pred = model.predict(X)
    metrics = {
        'accuracy':  round(accuracy_score(y_true, y_pred), 4),
        'precision': round(precision_score(y_true, y_pred, zero_division=0), 4),
        'recall':    round(recall_score(y_true, y_pred, zero_division=0), 4)
    }
    log(f"  [ML Step 3] ✓ Acc={metrics['accuracy']} | Prec={metrics['precision']} | Rec={metrics['recall']}")
    return metrics


def ml_step4_predict_risk(model, scaled_df):
    """ML Step 4: Generate ml_risk_score (0-1) and ml_risk_label"""
    log("  [ML Step 4] Generating ML risk scores and labels...")
    risk_scores = model.predict_proba(scaled_df)[:, 1]
    risk_labels = pd.cut(
        risk_scores,
        bins=[0, 0.3, 0.7, 1.0],
        labels=["Low Risk", "Medium Risk", "High Risk"],
        include_lowest=True
    )
    log(f"  [ML Step 4] ✓ {pd.Series(risk_labels).value_counts().to_dict()}")
    return risk_scores, risk_labels


def run_ml_pipeline(summary_df):
    """
    Orchestrate all 4 ML steps.
    Attaches ml_risk_score, ml_risk_label, ml_accuracy, ml_precision, ml_recall.
    Falls back gracefully if any step fails.
    """
    log("\n" + "=" * 55)
    log("Starting ML Pipeline (Steps 1-4)")
    log("=" * 55)

    try:
        scaled_df, _             = ml_step1_prepare_features(summary_df)
        model                    = ml_step2_train_model(scaled_df)
        metrics                  = ml_step3_evaluate_model(model, scaled_df)
        risk_scores, risk_labels = ml_step4_predict_risk(model, scaled_df)

        summary_df = summary_df.copy()
        summary_df['ml_risk_score'] = risk_scores
        summary_df['ml_risk_label'] = list(risk_labels)
        summary_df['ml_accuracy']   = metrics['accuracy']
        summary_df['ml_precision']  = metrics['precision']
        summary_df['ml_recall']     = metrics['recall']

        log("=" * 55)
        log(f"✓ ML Pipeline Complete! Acc={metrics['accuracy']} | Prec={metrics['precision']} | Rec={metrics['recall']}")
        log("=" * 55 + "\n")

    except Exception as e:
        log(f"❌ ML Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        summary_df = summary_df.copy()
        summary_df['ml_risk_score'] = 0.0
        summary_df['ml_risk_label'] = 'Unknown'
        summary_df['ml_accuracy']   = 0.0
        summary_df['ml_precision']  = 0.0
        summary_df['ml_recall']     = 0.0

    return summary_df

# ================================================================
# SECTION 7 - MAIN PIPELINE
# ================================================================

def process_cowrie_logs():
    """
    Full pipeline orchestrator.
    Reads Cowrie JSON → runs all stages → saves final CSV.
    """
    global SESSION_COUNTER

    log("=" * 60)
    log("Starting Cowrie Pipeline Execution")

    # ----- Check log file -----
    if not Path(COWRIE_LOG_PATH).exists():
        log(f"⚠️  Cowrie log not found at: {COWRIE_LOG_PATH}")
        log("Skipping this run - honeypot may not be active yet")
        return None

    log(f"✓ Found Cowrie log: {COWRIE_LOG_PATH}")

    # ----- Read JSON lines -----
    events = []
    try:
        with open(COWRIE_LOG_PATH, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    if line_num % 1000 == 0:
                        log(f"⚠️  Skipping malformed JSON at line {line_num}")
                    continue
    except Exception as e:
        log(f"❌ Error reading log file: {e}")
        return None

    log(f"✓ Parsed {len(events)} total events")

    if len(events) == 0:
        log("⚠️  No events found - skipping")
        return None

    df = pd.DataFrame(events)

    if 'src_ip' not in df.columns:
        log("❌ Missing 'src_ip' - cannot proceed")
        return None

    log(f"✓ DataFrame: {len(df)} rows | {len(df.columns)} columns")

    # ----- SESSION AGGREGATION -----
    session_col = 'session' if 'session' in df.columns else 'src_ip'
    log(f"\nAggregating sessions by: {session_col}")

    sessions = []
    for session_id, session_data in df.groupby(session_col):
        event_count = len(session_data)

        # Unique commands
        if 'input' in session_data.columns:
            unique_commands = len(session_data['input'].dropna().unique())
        elif 'message' in session_data.columns:
            unique_commands = session_data['message'].nunique()
        else:
            unique_commands = session_data['eventid'].nunique() if 'eventid' in session_data.columns else 1

        # Session duration + timestamp from Cowrie log
        session_start = None
        session_end   = None
        session_duration = 0

        if 'timestamp' in session_data.columns:
            try:
                timestamps       = pd.to_datetime(session_data['timestamp'], utc=True)
                session_start    = timestamps.min().strftime('%Y-%m-%d %H:%M:%S')
                session_end      = timestamps.max().strftime('%Y-%m-%d %H:%M:%S')
                session_duration = (timestamps.max() - timestamps.min()).total_seconds()
            except:
                session_duration = event_count * 5

        if session_duration == 0:
            session_duration = event_count * 5

        src_ip       = session_data['src_ip'].iloc[0]
        session_hash = hashlib.md5(str(session_id).encode()).hexdigest()[:12]

        # Login counts from eventid
        failed_logins    = 0
        successful_login = 0
        if 'eventid' in session_data.columns:
            failed_logins    = int((session_data['eventid'] == 'cowrie.login.failed').sum())
            successful_login = int((session_data['eventid'] == 'cowrie.login.success').sum())

        # Unique usernames attempted
        unique_usernames = 0
        if 'username' in session_data.columns:
            unique_usernames = session_data['username'].nunique()

        sessions.append({
            'session':          session_hash,
            'src_ip':           src_ip,
            'event_count':      event_count,
            'unique_commands':  unique_commands,
            'session_duration': session_duration,
            'failed_logins':    failed_logins,
            'successful_login': successful_login,
            'unique_usernames': unique_usernames,
            'session_start':    session_start,
            'session_end':      session_end,
        })

    summary = pd.DataFrame(sessions)
    log(f"✓ Aggregated into {len(summary)} unique sessions")

    # ===================================================
    # STAGE 1: FEATURE ENGINEERING
    # ===================================================
    log("\n--- Stage 1: Feature Engineering ---")
    summary = fe_step1_extract_features(summary)
    summary = fe_step2_advanced_behavioral(summary)
    log("✓ Stage 1 complete")

    # ===================================================
    # STAGE 2: Z-SCORE NORMALIZATION
    # ===================================================
    log("\n--- Stage 2: Z-Score Normalization ---")
    for col, norm_col in [
        ('event_count',      'event_count_norm'),
        ('unique_commands',  'unique_commands_norm'),
        ('session_duration', 'session_duration_norm'),
    ]:
        mean = summary[col].mean()
        std  = summary[col].std() if summary[col].std() > 0 else 1
        summary[norm_col] = (summary[col] - mean) / std

    # IP scope (needed before clustering for step 9)
    summary['ip_scope'] = summary['src_ip'].apply(classify_ip_scope)

    log(f"✓ Stage 2 complete | IP scope: {summary['ip_scope'].value_counts().to_dict()}")

    # ===================================================
    # STAGE 3: BEHAVIORAL CLUSTERING (Steps 1-9)
    # ===================================================
    log("\n--- Stage 3: Behavioral Clustering ---")
    summary = run_behavioral_clustering(summary)
    log("✓ Stage 3 complete")

    # ===================================================
    # Z-SCORE BASED RISK SCORE (overrides behavioral_risk_score for dashboard)
    # ===================================================
    summary['risk_score'] = summary.apply(
        lambda r: calculate_z_risk_score(
            r['event_count_norm'], r['unique_commands_norm'],
            r['session_duration_norm'], r['behavior_cluster']
        ), axis=1
    )
    # behavior_label from z-score (overrides cluster-based label for consistency)
    summary['behavior_label'] = summary['risk_score'].apply(determine_behavior_label_from_zscore)

    # ===================================================
    # STAGE 4: GEOIP ENRICHMENT
    # ===================================================
    log("\n--- Stage 4: GeoIP Enrichment ---")
    summary = geoip_enrich(summary)
    summary = threat_intel_enrichment(summary)
    summary = campaign_analysis(summary)

    # Update geo_visualization now that we have actual GeoIP data
    summary['geo_visualization'] = summary['ip_scope'].apply(
        lambda x: 'enabled' if x == 'public' else 'disabled'
    )

    log("✓ Stage 4 complete")

    # ===== SESSION IDs =====
    summary['session_id'] = [f'SESS-{SESSION_COUNTER + i}' for i in range(len(summary))]
    SESSION_COUNTER += len(summary)

    # ===================================================
    # STAGE 5: ML PIPELINE
    # ===================================================
    log("\n--- Stage 5: ML Pipeline ---")
    summary = run_ml_pipeline(summary)
    log("✓ Stage 5 complete")

    # ===== FINAL COLUMN ORDER =====
    final_columns = [
        # Identifiers
        'session_id', 'session', 'src_ip',
        # Timestamps from Cowrie
        'session_start', 'session_end',
        # Core features
        'event_count', 'unique_commands', 'session_duration',
        'failed_logins', 'successful_login', 'unique_usernames',
        # Behavioral flags
        'high_event_activity', 'long_session', 'credential_guessing',
        'command_heavy', 'behavioral_risk_score',
        # Z-score normalization
        'event_count_norm', 'unique_commands_norm', 'session_duration_norm',
        # Clustering results
        'behavior_cluster', 'behavior_label', 'risk_score',
        'is_anomaly', 'dbscan_label', 'cluster_stability',
        # Threat intelligence
        'attacker_type', 'threat_archetype', 'confidence_level',
        'ip_scope', 'risk_level',
        # GeoIP
        'country', 'country_iso', 'city', 'latitude', 'longitude', 'asn', 'asn_org',
        # Campaign
        'campaign_key', 'campaign_total_sessions', 'campaign_severity',
        # ML results
        'ml_risk_score', 'ml_risk_label', 'ml_accuracy', 'ml_precision', 'ml_recall',
        # Metadata
        'geo_visualization', 'soc_relevance',
    ]

    for col in final_columns:
        if col not in summary.columns:
            log(f"⚠️  Adding missing column: {col}")
            summary[col] = None

    output = summary[final_columns].copy()
    output = output.sort_values('risk_score', ascending=False)

    log(f"\n✓ Final dataset: {len(output)} sessions | {len(output.columns)} columns")
    log(f"  Behavior labels  : {output['behavior_label'].value_counts().to_dict()}")
    log(f"  ML risk labels   : {output['ml_risk_label'].value_counts().to_dict()}")
    log(f"  Anomalies        : {int(output['is_anomaly'].sum())}")
    log(f"  Campaign severity: {output['campaign_severity'].value_counts().to_dict()}")

    # ----- Save CSV -----
    Path(PROJECT_DIR).mkdir(parents=True, exist_ok=True)
    try:
        output.to_csv(OUTPUT_CSV_PATH, index=False)
        log(f"✓ CSV saved: {OUTPUT_CSV_PATH}")
        log(f"\nSample (first 2 rows):\n{output.head(2).to_string()}")
        return OUTPUT_CSV_PATH
    except Exception as e:
        log(f"❌ Error saving CSV: {e}")
        import traceback
        traceback.print_exc()
        return None

# ================================================================
# UPLOAD TO DASHBOARD
# ================================================================

def upload_to_dashboard(csv_path):
    """Upload final CSV to dashboard via HTTP POST"""
    if csv_path is None:
        log("⚠️  No CSV to upload - skipping")
        return False

    log("Starting upload to dashboard...")
    try:
        with open(csv_path, 'rb') as f:
            response = requests.post(
                DASHBOARD_UPLOAD_URL,
                files={'file': ('attacks.csv', f, 'text/csv')},
                timeout=30
            )
        if response.status_code == 200:
            log(f"✓ Upload successful! Status: {response.status_code}")
            return True
        else:
            log(f"⚠️  Upload status: {response.status_code} | {response.text[:200]}")
            return False
    except requests.exceptions.Timeout:
        log("❌ Upload failed: Timed out")
        return False
    except requests.exceptions.ConnectionError as e:
        log(f"❌ Upload failed: Connection error - {e}")
        return False
    except Exception as e:
        log(f"❌ Upload failed: {e}")
        return False

# ================================================================
# MAIN EXECUTION
# ================================================================

if __name__ == "__main__":
    try:
        csv_path       = process_cowrie_logs()
        upload_success = upload_to_dashboard(csv_path)

        if csv_path and upload_success:
            log("✅ Pipeline completed successfully!")
            sys.exit(0)
        elif csv_path and not upload_success:
            log("⚠️  Pipeline done but upload failed")
            sys.exit(0)
        else:
            log("⚠️  No data processed this run")
            sys.exit(0)

    except Exception as e:
        log(f"❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        log("Pipeline execution finished")
        log("=" * 60)
