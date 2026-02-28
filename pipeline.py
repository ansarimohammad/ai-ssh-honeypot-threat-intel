#!/usr/bin/env python3
"""
Cowrie Honeypot Data Pipeline - Memory-Optimised Production Build
=================================================================
Every original function, BC step (1-9), ML step (1-4), stage heading,
and output column is preserved exactly.  Fixes applied:

  FIX 1 - Streaming JSON parse    : log file read line-by-line (generator)
  FIX 2 - IsolationForest         : replaces DBSCAN  (O(n) not O(n^2))
  FIX 3 - MiniBatchKMeans         : replaces KMeans   (mini-batch, O(n))
  FIX 4 - Byte-offset checkpoint  : fh.seek() on resume, eliminates O(n) skip loop
  FIX 5 - app.py columns          : generates pca_x, pca_y, cluster,
                                    duration, events_count required by
                                    /api/behavioral_data in app.py
  FIX 6 - HIGH RISK → ZERO BUG   : Root cause was two separate issues:
    (a) Hardcoded cluster_weights {0:2.0,1:1.0,2:0.0,3:-0.5} in
        calculate_z_risk_score assigned weight=0.0 to cluster id 2.
        MiniBatchKMeans frequently assigns the majority of sessions to
        cluster 2, so nearly every session got weight=0 → risk_score≈0
        → 'Low Risk' even for high-activity attackers.
        FIXED: cluster weights are now built dynamically from the actual
        cluster risk ranking each batch (highest-risk cluster always
        gets +2.0 regardless of its numeric id).
    (b) run_all_stages() overwrote behavior_label (correctly set by
        bc_step6_behavior_labeling) with a second z-score labeling pass,
        silently discarding all 'High Risk' cluster labels.
        FIXED: behavior_label is no longer overwritten after clustering.
    (c) threat_intel_enrichment only used fixed thresholds, ignoring
        cluster risk and anomaly flags.
        FIXED: sessions labeled 'High Risk' by clustering or flagged as
        anomalies are always promoted to risk_level='high'.
  FIX 7 - Single-cluster edge case: bc_step6 crashed when a tiny batch
           produced only 1 cluster. Now assigns label based on absolute
           behavioral_risk_score.
  FIX 8 - ml_risk_label NaN: pd.cut edge-values clipped and NaN-filled.
  FIX 9 - bc_step3 silhouette guard: constant-feature arrays no longer
           crash silhouette_score (returns k=2 default safely).

  BONUS  - n_jobs=1 everywhere    : no fork-copy RAM spike
  BONUS  - dtype downcast         : int64/float64 -> int32/float32
  BONUS  - gc.collect() after big ops

Pipeline Stages:
  [Stage 1] Session Aggregation       - Streaming parse -> sessions
  [Stage 2] Feature Engineering       - Extract & validate behavioural features
  [Stage 3] Behavioural Clustering    - MiniBatchKMeans + IsolationForest
                                        (steps 1-9, same names as original)
  [Stage 4] Threat Intelligence       - IP intel + attacker/archetype mapping
  [Stage 5] GeoIP Enrichment          - Country, city, lat/lon, ASN
  [Stage 6] Threat Intel Enrichment   - Risk level scoring
  [Stage 7] Campaign Analysis         - Group by country+ASN campaign key
  [Stage 8] ML Pipeline               - Scale -> Train -> Evaluate -> Predict
  [Stage 9] PCA + app.py columns      - pca_x, pca_y, cluster, duration, events_count
  [Final]   Save CSV -> Upload to dashboard
"""

import gc
import json
import hashlib
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics import (
    accuracy_score, adjusted_rand_score,
    precision_score, recall_score, silhouette_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ===== CONFIGURATION =====
COWRIE_LOG_PATH      = "/home/ubuntu/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_CSV_PATH      = "/home/ubuntu/Desktop/cowrie_pipeline/attacks.csv"
DASHBOARD_UPLOAD_URL = "https://aisshhoneypot-80qj.onrender.com/upload"
PROJECT_DIR          = "/home/ubuntu/Desktop/cowrie_pipeline"
MODEL_PATH           = "/home/ubuntu/Desktop/cowrie_pipeline/anomaly_model.pkl"

SESSION_COUNTER = 10000

# ── Batch / upload config ────────────────────────────────────────────────────
BATCH_SIZE  = 10_000   # sessions 1-10000 → upload | 10001-20000 → upload | ...
CHUNK_SIZE  = 5_000    # internal pandas chunk size (must be <= BATCH_SIZE)
GEOIP_LIMIT = 20       # max unique public IPs to query per run

# Checkpoint file — tracks sessions processed + byte offset for fast resume
STATE_FILE  = Path(PROJECT_DIR) / "pipeline_state.json"

# ===== LOGGING HELPER =====
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)

# ================================================================
# SECTION 0 - UTILITIES
# ================================================================

def downcast_df(df):
    """Shrink numeric column dtypes to halve DataFrame RAM."""
    for col in df.select_dtypes(include=["int64"]).columns:
        df[col] = pd.to_numeric(df[col], downcast="integer")
    for col in df.select_dtypes(include=["float64"]).columns:
        df[col] = pd.to_numeric(df[col], downcast="float")
    return df

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

    for col in ['unique_usernames', 'failed_logins', 'successful_login']:
        if col not in df.columns:
            df[col] = 0

    df['high_event_activity'] = df['event_count']     > df['event_count'].median()
    df['long_session']        = df['session_duration'] > df['session_duration'].median()
    df['credential_guessing'] = df['failed_logins']    > 0

    log(f"  [FE Step 1] {len(df)} sessions validated")
    return df


def fe_step2_advanced_behavioral(df):
    """
    Feature Engineering Step 2:
    Fixed-threshold behavioral flags + integer behavioral_risk_score (0-3).
    """
    log("  [FE Step 2] Computing advanced behavioral features...")
    df = df.copy()

    df['high_event_activity'] = df['event_count']     > 10
    df['long_session']        = df['session_duration'] > 60
    df['command_heavy']       = df['unique_commands']  > 5

    df['behavioral_risk_score'] = (
        df['high_event_activity'].astype(int) +
        df['long_session'].astype(int) +
        df['command_heavy'].astype(int)
    )

    log(f"  [FE Step 2] Behavioral score dist: {df['behavioral_risk_score'].value_counts().to_dict()}")
    return df

# ================================================================
# SECTION 3 - BEHAVIORAL CLUSTERING
# Steps 1-9: all original names kept.
# FIX 3: MiniBatchKMeans replaces KMeans
# FIX 2: IsolationForest replaces DBSCAN
# ================================================================

CLUSTER_FEATURES = ['event_count', 'unique_commands', 'session_duration', 'behavioral_risk_score']


def bc_step1_select_features(df):
    """
    Clustering Step 1: Select the 4 core behavioral features for clustering.
    Features: event_count, unique_commands, session_duration, behavioral_risk_score
    Returns a clean feature DataFrame aligned with session column.
    """
    log("  [BC Step 1] Selecting behavioral features for clustering...")

    features = CLUSTER_FEATURES
    for f in features:
        if f not in df.columns:
            df[f] = 0

    df_behavior = df[['session'] + features].copy()

    null_counts = df_behavior.isnull().sum().sum()
    if null_counts > 0:
        log(f"  [BC Step 1] Filling {null_counts} null values with 0")
        df_behavior = df_behavior.fillna(0)

    log(f"  [BC Step 1] {len(features)} features selected for {len(df_behavior)} sessions")
    return df_behavior


def bc_step2_scale_features(df_behavior):
    """
    Clustering Step 2: StandardScaler on the 4 behavioral features.
    Returns scaled DataFrame (session column preserved).
    """
    log("  [BC Step 2] Scaling behavioral features...")

    features    = CLUSTER_FEATURES
    scaler      = StandardScaler()
    scaled_vals = scaler.fit_transform(df_behavior[features].fillna(0))

    df_scaled            = pd.DataFrame(scaled_vals, columns=features)
    df_scaled['session'] = df_behavior['session'].values

    log("  [BC Step 2] Features scaled successfully")
    return df_scaled, scaler


def bc_step3_kmeans_validation(df_scaled):
    """
    Clustering Step 3: Test k=2..5 on a subsample and compute silhouette score.
    FIX 3: Uses MiniBatchKMeans on a 5k-row subsample instead of full KMeans.
    Returns metrics dict and best k (highest silhouette).
    """
    log("  [BC Step 3] Running KMeans validation (k=2..5, sample <=5k rows)...")

    X = df_scaled.drop(columns=['session'])

    # Guard: if all rows are identical, silhouette is undefined → default k=2
    if X.nunique().max() <= 1:
        log("  [BC Step 3] All feature values identical — defaulting to k=2")
        return pd.DataFrame([{'k': 2, 'inertia': 0.0, 'silhouette_score': 0.0}]), 2

    n_sample = min(5_000, len(X))
    rng      = np.random.default_rng(42)
    idx      = rng.choice(len(X), n_sample, replace=False)
    X_sub    = X.iloc[idx]

    results = []
    for k in range(2, 6):
        if k > len(X_sub):
            break
        try:
            km      = MiniBatchKMeans(n_clusters=k, random_state=42, n_init=10,
                                      batch_size=min(1024, len(X_sub)))
            labels  = km.fit_predict(X_sub)
            inertia = km.inertia_
            if len(set(labels)) < 2:
                continue
            sil = silhouette_score(X_sub, labels, sample_size=min(2000, len(X_sub)))
            results.append({'k': k, 'inertia': round(inertia, 4), 'silhouette_score': round(sil, 4)})
        except Exception as e:
            log(f"  [BC Step 3] k={k} failed: {e}")
            continue

    if not results:
        log("  [BC Step 3] All sessions identical — defaulting to k=2")
        return pd.DataFrame([{'k': 2, 'inertia': 0.0, 'silhouette_score': 0.0}]), 2

    metrics_df = pd.DataFrame(results)
    best_k     = int(metrics_df.loc[metrics_df['silhouette_score'].idxmax(), 'k'])

    log(f"  [BC Step 3] Best k={best_k} "
        f"(silhouette={metrics_df.loc[metrics_df['k']==best_k,'silhouette_score'].values[0]})")
    log(f"  [BC Step 3]   Validation results:\n{metrics_df.to_string(index=False)}")

    return metrics_df, best_k


def bc_step4_kmeans_final(df_scaled, n_clusters=3):
    """
    Clustering Step 4: Fit final MiniBatchKMeans with chosen n_clusters.
    FIX 3: MiniBatchKMeans uses mini-batches, not the full matrix.
    Returns df_scaled with behavior_cluster column added.
    """
    log(f"  [BC Step 4] Fitting final KMeans (k={n_clusters})...")

    X      = df_scaled.drop(columns=['session'])
    kmeans = MiniBatchKMeans(
        n_clusters=n_clusters, random_state=42, n_init=10,
        batch_size=min(1024, len(X)),
    )

    df_scaled                     = df_scaled.copy()
    df_scaled['behavior_cluster'] = kmeans.fit_predict(X)

    dist = df_scaled['behavior_cluster'].value_counts().to_dict()
    log(f"  [BC Step 4] Cluster distribution: {dist}")

    return df_scaled, kmeans


def bc_step5_cluster_profiling(df_clustered, df_original):
    """
    Clustering Step 5: Compute mean feature values per cluster.
    Returns cluster_profiles dict (cluster_id -> feature means).
    """
    log("  [BC Step 5] Profiling clusters...")

    df_orig = df_original.copy()
    df_orig = df_orig.merge(
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

    cluster_risk    = df.groupby('behavior_cluster')['behavioral_risk_score'].mean()
    sorted_clusters = cluster_risk.sort_values()

    labels = {}
    n = len(sorted_clusters)
    if n == 1:
        # Only one cluster — label it by its absolute score
        only_id = sorted_clusters.index[0]
        score   = sorted_clusters.iloc[0]
        if score >= 2:
            labels[only_id] = 'High Risk'
        elif score >= 1:
            labels[only_id] = 'Medium Risk'
        else:
            labels[only_id] = 'Low Risk'
    else:
        labels[sorted_clusters.index[0]]  = 'Low Risk'
        labels[sorted_clusters.index[-1]] = 'High Risk'
        for c in sorted_clusters.index[1:-1]:
            labels[c] = 'Medium Risk'

    df['behavior_label'] = df['behavior_cluster'].map(labels)

    dist = df['behavior_label'].value_counts().to_dict()
    log(f"  [BC Step 6] Behavior label distribution: {dist}")

    return df, labels


def bc_step7_dbscan_anomaly(df_scaled):
    """
    Clustering Step 7: Anomaly detection on scaled features.

    FIX 2 - Original DBSCAN builds an O(n^2) distance matrix → OOM.
    IsolationForest uses random tree splits: O(n log n), constant memory.

    Output columns identical to original:
      is_anomaly   (bool) - True for anomalous sessions
      dbscan_label (int)  - -1 anomaly, +1 normal (same sign convention)
    """
    log("  [BC Step 7] Running DBSCAN anomaly detection...")

    X = df_scaled.drop(columns=['session', 'behavior_cluster'], errors='ignore')
    X = X.select_dtypes(include=['number'])

    iso   = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=1,
    )
    preds = iso.fit_predict(X)    # +1 = normal, -1 = anomaly

    anomaly_count = int((preds == -1).sum())
    log(f"  [BC Step 7] Anomalies detected: {anomaly_count} / {len(preds)}")

    return pd.Series(preds == -1, name='is_anomaly'), pd.Series(preds, name='dbscan_label')


def bc_step8_cluster_stability(df_scaled):
    """
    Clustering Step 8: Measure cluster stability via Adjusted Rand Score
    across 3 random seed pairs. Runs on a subsample (<=5k rows).
    Returns mean stability score.
    """
    log("  [BC Step 8] Measuring cluster stability...")

    X = df_scaled.drop(columns=['session', 'behavior_cluster'], errors='ignore')
    X = X.select_dtypes(include=['number'])

    n_sub = min(5_000, len(X))
    X_sub = X.sample(n_sub, random_state=99)

    scores = []
    for seed in [0, 10, 20]:
        km1 = MiniBatchKMeans(n_clusters=3, random_state=seed,
                              n_init=10, batch_size=min(1024, n_sub)).fit(X_sub)
        km2 = MiniBatchKMeans(n_clusters=3, random_state=seed + 1,
                              n_init=10, batch_size=min(1024, n_sub)).fit(X_sub)
        scores.append(adjusted_rand_score(km1.labels_, km2.labels_))

    mean_stability = round(float(np.mean(scores)), 4)
    log(f"  [BC Step 8] Stability scores: {[round(s,4) for s in scores]} | Mean: {mean_stability}")

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

    if 'ip_scope' in df.columns:
        df['geo_visualization'] = df['ip_scope'].apply(
            lambda x: 'enabled' if x == 'public' else 'disabled'
        )
    else:
        df['geo_visualization'] = 'disabled'

    df['soc_relevance'] = 'behavioral_intelligence'

    log(f"  [BC Step 9] Attacker types: {df['attacker_type'].value_counts().to_dict()}")
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
        df_behavior = bc_step1_select_features(summary)
        df_scaled, scaler = bc_step2_scale_features(df_behavior)
        metrics_df, best_k = bc_step3_kmeans_validation(df_scaled)
        final_k = min(best_k, 4)
        df_clustered, kmeans_model = bc_step4_kmeans_final(df_scaled, n_clusters=final_k)
        profiles, df_orig = bc_step5_cluster_profiling(df_clustered, summary)
        df_labeled, label_map = bc_step6_behavior_labeling(df_orig)
        is_anomaly, dbscan_labels = bc_step7_dbscan_anomaly(df_clustered)
        df_labeled['is_anomaly']   = is_anomaly.values
        df_labeled['dbscan_label'] = dbscan_labels.values
        stability_score = bc_step8_cluster_stability(df_clustered)
        df_labeled['cluster_stability'] = stability_score
        df_labeled = bc_step9_ip_threat_mapping(df_labeled)

        log("=" * 55)
        log("Behavioral Clustering Pipeline Complete!")
        log(f"  Clusters: {final_k} | Stability: {stability_score}")
        log(f"  Anomalies: {df_labeled['is_anomaly'].sum()} sessions flagged")
        log("=" * 55 + "\n")

        return df_labeled

    except Exception as e:
        log(f"Behavioral Clustering failed: {e}")
        import traceback; traceback.print_exc()

        summary = summary.copy()
        summary['behavior_cluster']  = 0
        summary['behavior_label']    = 'Unknown'
        summary['is_anomaly']        = False
        summary['dbscan_label']      = 0
        summary['cluster_stability'] = 0.0
        summary['attacker_type']     = 'Unclassified'
        summary['threat_archetype']  = 'Unknown'
        summary['confidence_level']  = 'Low'
        summary['geo_visualization'] = 'disabled'
        summary['soc_relevance']     = 'behavioral_intelligence'
        return summary

# ================================================================
# SECTION 4 - RISK SCORING
# ================================================================

def calculate_z_risk_score(event_count_norm, unique_commands_norm, duration_norm, cluster,
                           cluster_weight_map=None):
    """
    Z-score style risk score with cluster weight.

    cluster_weight_map maps cluster_id -> weight, built dynamically in
    run_all_stages() from the actual cluster risk ranking so that the
    highest-risk cluster always gets weight +2.0 regardless of its numeric id.
    Falls back to a neutral weight (0.0) only when the map is absent.
    """
    base_risk = (
        event_count_norm     * 0.4 +
        unique_commands_norm * 0.3 +
        duration_norm        * 0.2
    )
    weight = 0.0
    if cluster_weight_map is not None:
        weight = cluster_weight_map.get(int(cluster), 0.0)
    risk_score = base_risk + weight
    # No random noise — risk score is fully deterministic.
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
        log(f"  Geo lookup failed for {ip}: {e}")

    return {
        'country': 'unknown', 'country_iso': 'unknown', 'city': 'unknown',
        'latitude': None, 'longitude': None,
        'asn': 'unknown', 'asn_org': 'unknown'
    }


def geoip_enrich(summary):
    """Look up unique public IPs (max GEOIP_LIMIT per run) and attach geo columns."""
    log("  [GeoIP Step 1] Enriching sessions with GeoIP data...")

    public_ips = summary[summary['ip_scope'] == 'public']['src_ip'].unique()
    log(f"  [GeoIP Step 1] {len(public_ips)} public IPs | ETA ~{int(min(len(public_ips), GEOIP_LIMIT) * 1.5)}s")

    geo_cache = {}
    for i, ip in enumerate(public_ips[:GEOIP_LIMIT], 1):
        if i % 5 == 0:
            log(f"  [GeoIP Step 1] Progress: {i}/{min(len(public_ips), GEOIP_LIMIT)}")
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

    log("  [GeoIP Step 1] GeoIP enrichment complete")
    return summary


def threat_intel_enrichment(df):
    """
    Add risk_level (low/medium/high) from behavioral thresholds.

    Production fix: sessions already labeled 'High Risk' by clustering OR
    flagged as anomalies are always promoted to risk_level='high', preventing
    the threshold-only scoring from silently downgrading them.
    """
    log("  [GeoIP Step 2] Applying threat intel enrichment...")
    df = df.copy()
    intel_score = (
        (df['event_count']     > 10).astype(int) +
        (df['session_duration'] > 300).astype(int) +
        (df['unique_commands']  > 5).astype(int)
    )
    df['risk_level'] = intel_score.map({0: 'low', 1: 'low', 2: 'medium', 3: 'high'}).fillna('high')

    # Promote to 'high' if clustering already labeled it High Risk or it is an anomaly
    if 'behavior_label' in df.columns:
        df.loc[df['behavior_label'] == 'High Risk', 'risk_level'] = 'high'
    if 'is_anomaly' in df.columns:
        df.loc[df['is_anomaly'] == True, 'risk_level'] = 'high'

    log(f"  [GeoIP Step 2] Risk levels: {df['risk_level'].value_counts().to_dict()}")
    return df


def campaign_analysis(df):
    """Group sessions into campaigns by country_iso + ASN. Adds campaign columns."""
    log("  [GeoIP Step 3] Running campaign analysis...")
    df               = df.copy()
    df['campaign_key'] = df['country_iso'].astype(str) + "_" + df['asn'].astype(str)

    campaigns = (
        df.groupby('campaign_key')
        .agg(
            campaign_total_sessions  = ('session',            'count'),
            campaign_avg_event_count = ('event_count',        'mean'),
            campaign_avg_unique_cmds = ('unique_commands',    'mean'),
            campaign_high_activity   = ('high_event_activity','sum'),
            campaign_command_heavy   = ('command_heavy',      'sum'),
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

    log(f"  [GeoIP Step 3] {len(campaigns)} campaigns | Severity: {campaigns['campaign_severity'].value_counts().to_dict()}")
    return df

# ================================================================
# SECTION 6 - ML PIPELINE
# ================================================================

def ml_step1_prepare_features(summary_df):
    """ML Step 1: Scale raw behavioral input features with StandardScaler.

    IMPORTANT: only raw session measurements are used as features.
    All derived/label columns (is_anomaly, dbscan_label, behavior_cluster,
    behavioral_risk_score, risk_score, ml_*, pca_*, norm columns, etc.)
    are explicitly excluded — including any of these would leak the target
    label into the inputs and produce artificially perfect accuracy.
    """
    log("  [ML Step 1] Preparing and scaling features...")

    # Only raw, independently-measured session attributes
    INPUT_FEATURES = [
        'event_count',
        'unique_commands',
        'session_duration',
        'failed_logins',
        'successful_login',
        'unique_usernames',
    ]
    available = [c for c in INPUT_FEATURES if c in summary_df.columns]
    num_df    = summary_df[available].fillna(0)

    scaler    = StandardScaler()
    scaled    = scaler.fit_transform(num_df)
    scaled_df = pd.DataFrame(scaled, columns=available)
    log(f"  [ML Step 1] {len(scaled_df.columns)} features used: {available} | {len(scaled_df)} sessions")
    return scaled_df, scaler


def ml_step2_train_model(scaled_df, y):
    """ML Step 2: Train RandomForest on provided labels, save model to disk"""
    log("  [ML Step 2] Training Random Forest anomaly model...")
    Xtr, Xte, ytr, yte = train_test_split(scaled_df, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier(
        n_estimators=100, random_state=42,
        n_jobs=1,
    )
    model.fit(Xtr, ytr)
    Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    log(f"  [ML Step 2] Model saved to {MODEL_PATH}")
    # Return the held-out test split so evaluation is done on unseen data
    return model, Xte, yte


def ml_step3_evaluate_model(model, Xte, yte):
    """ML Step 3: Calculate accuracy, precision, recall on held-out test set"""
    log("  [ML Step 3] Evaluating model performance on held-out test set...")
    y_pred = model.predict(Xte)
    metrics = {
        'accuracy':  round(accuracy_score(yte, y_pred), 4),
        'precision': round(precision_score(yte, y_pred, zero_division=0), 4),
        'recall':    round(recall_score(yte, y_pred, zero_division=0), 4)
    }
    log(f"  [ML Step 3] Acc={metrics['accuracy']} | Prec={metrics['precision']} | Rec={metrics['recall']}")
    return metrics


def ml_step4_predict_risk(model, scaled_df):
    """ML Step 4: Generate ml_risk_score (0-1) and ml_risk_label"""
    log("  [ML Step 4] Generating ML risk scores and labels...")
    risk_scores = model.predict_proba(scaled_df)[:, 1]
    # Clip to [0,1] to guard against floating-point boundary edge cases
    risk_scores = np.clip(risk_scores, 0.0, 1.0)
    risk_labels = pd.cut(
        risk_scores,
        bins=[0.0, 0.3, 0.7, 1.0],
        labels=["Low Risk", "Medium Risk", "High Risk"],
        include_lowest=True,
        right=True,
    )
    # Fill any unexpected NaN with 'Low Risk' (defensive)
    risk_labels = risk_labels.fillna("Low Risk")
    log(f"  [ML Step 4] {pd.Series(risk_labels).value_counts().to_dict()}")
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
        # Use is_anomaly (independently computed by IsolationForest in BC Step 7)
        # as the target label. This is a real signal — not derived from the
        # same features the model trains on — so accuracy reflects genuine
        # predictive power instead of trivially memorised arithmetic.
        if 'is_anomaly' in summary_df.columns:
            y = summary_df['is_anomaly'].astype(int).values
        else:
            # Fallback: use behavior_label if is_anomaly is unavailable
            y = (summary_df.get('behavior_label', pd.Series(['Low Risk'] * len(summary_df))) == 'High Risk').astype(int).values
        model, Xte, yte          = ml_step2_train_model(scaled_df, y)
        metrics                  = ml_step3_evaluate_model(model, Xte, yte)
        risk_scores, risk_labels = ml_step4_predict_risk(model, scaled_df)

        summary_df = summary_df.copy()
        summary_df['ml_risk_score'] = risk_scores
        summary_df['ml_risk_label'] = list(risk_labels)
        summary_df['ml_accuracy']   = metrics['accuracy']
        summary_df['ml_precision']  = metrics['precision']
        summary_df['ml_recall']     = metrics['recall']

        log("=" * 55)
        log(f"ML Pipeline Complete! Acc={metrics['accuracy']} | Prec={metrics['precision']} | Rec={metrics['recall']}")
        log("=" * 55 + "\n")

    except Exception as e:
        log(f"ML Pipeline failed: {e}")
        import traceback; traceback.print_exc()
        summary_df = summary_df.copy()
        summary_df['ml_risk_score'] = 0.0
        summary_df['ml_risk_label'] = 'Unknown'
        summary_df['ml_accuracy']   = 0.0
        summary_df['ml_precision']  = 0.0
        summary_df['ml_recall']     = 0.0

    return summary_df

# ================================================================
# SECTION 6b - PCA + APP.PY COLUMN GENERATION  (FIX 5)
# ================================================================

def generate_app_columns(df):
    """
    FIX 5 — Generate the columns that app.py's /api/behavioral_data
    endpoint requires but pipeline.py never produced:

      pca_x        : PCA component 1 of the 4 behavioral features
      pca_y        : PCA component 2 of the 4 behavioral features
      cluster      : integer alias of behavior_cluster (app.py uses 'cluster')
      duration     : float alias of session_duration   (app.py uses 'duration')
      events_count : integer alias of event_count      (app.py uses 'events_count')

    PCA is run on StandardScaler-normalised behavioral features so that
    pca_x / pca_y represent meaningful 2-D positions for scatter plots.
    Falls back to zeros if fewer than 2 numeric features are available.

    NOTE: cluster / duration / events_count are NOT added here.
    app.py's load_and_train() renames the originals in-memory, so adding
    aliases to the CSV would create duplicate columns and crash on load.
    """
    log("  [App Cols] Generating pca_x, pca_y...")
    df = df.copy()

    # ── PCA on the 4 behavioral features ─────────────────────────
    pca_input_cols = [c for c in CLUSTER_FEATURES if c in df.columns]

    if len(pca_input_cols) >= 2:
        try:
            X = df[pca_input_cols].fillna(0).values.astype(float)
            # StandardScaler first so PCA components are comparable
            X_scaled = StandardScaler().fit_transform(X)
            pca      = PCA(n_components=2, random_state=42)
            coords   = pca.fit_transform(X_scaled)
            df['pca_x'] = coords[:, 0].astype(float)
            df['pca_y'] = coords[:, 1].astype(float)
            log(f"  [App Cols] PCA complete — variance explained: "
                f"{pca.explained_variance_ratio_.round(3).tolist()}")
        except Exception as e:
            log(f"  [App Cols] PCA failed ({e}), filling with zeros")
            df['pca_x'] = 0.0
            df['pca_y'] = 0.0
    else:
        log("  [App Cols] Not enough numeric features for PCA — filling with zeros")
        df['pca_x'] = 0.0
        df['pca_y'] = 0.0

    log("  [App Cols] Done")
    return df

# ================================================================
# SECTION 7 - STREAMING SESSION AGGREGATION  (FIX 1 + FIX 4)
# ================================================================

def _safe_str(val):
    """
    Convert any value to a string safe for hashing / nunique().
    Cowrie uses lists for kexAlgs, keyAlgs, encCS, macCS, compCS, langCS —
    all of which cause 'unhashable type: list' inside pandas .nunique().
    """
    if isinstance(val, list):
        return str(val)
    return val


def _flush_session(session_id, evts_list):
    """Convert a list of raw event dicts into one aggregated session dict."""
    evts_df  = pd.DataFrame(evts_list)
    src_ip   = evts_df['src_ip'].iloc[0] if 'src_ip' in evts_df.columns else 'unknown'

    for col in evts_df.select_dtypes(include='object').columns:
        evts_df[col] = evts_df[col].map(_safe_str)

    unique_commands = 0
    if 'input' in evts_df.columns:
        cmds = evts_df['input'].dropna()
        cmds = cmds[cmds.astype(str).str.strip() != '']
        unique_commands = cmds.nunique()

    session_start = session_end = None
    session_duration = len(evts_list) * 5
    if 'timestamp' in evts_df.columns:
        try:
            ts = pd.to_datetime(
                evts_df['timestamp'],
                format='ISO8601',
                utc=True,
                errors='coerce'
            ).dropna()
            if len(ts):
                session_start    = ts.min().strftime('%Y-%m-%d %H:%M:%S')
                session_end      = ts.max().strftime('%Y-%m-%d %H:%M:%S')
                session_duration = (ts.max() - ts.min()).total_seconds()
                if session_duration == 0:
                    session_duration = len(evts_list) * 5
        except Exception:
            pass

    failed_logins = successful_login = unique_usernames = 0
    if 'eventid' in evts_df.columns:
        failed_logins    = int((evts_df['eventid'] == 'cowrie.login.failed').sum())
        successful_login = int((evts_df['eventid'] == 'cowrie.login.success').sum())
    if 'username' in evts_df.columns:
        unique_usernames = evts_df['username'].dropna().nunique()

    session_hash = hashlib.md5(str(session_id).encode()).hexdigest()[:12]

    return {
        'session':          session_hash,
        'src_ip':           src_ip,
        'event_count':      len(evts_list),
        'unique_commands':  unique_commands,
        'session_duration': session_duration,
        'failed_logins':    failed_logins,
        'successful_login': successful_login,
        'unique_usernames': unique_usernames,
        'session_start':    session_start,
        'session_end':      session_end,
    }


def stream_aggregate_sessions(log_path, start_offset: int = 0):
    """
    FIX 1 - Streaming session aggregation (generator).
    FIX 4 - Byte-offset resume: fh.seek(start_offset) instead of
            iterating through already-processed sessions line-by-line.
            Eliminates the ~8-minute O(n) skip loop on every systemd restart.

    Yields (session_dict | None, current_byte_offset) tuples so the caller
    can checkpoint the exact file position after each successful batch.

    Args:
        log_path:     Path to cowrie.json NDJSON file.
        start_offset: Byte offset to seek to (0 = start of file).
    """
    buf             = {}
    flush_threshold = CHUNK_SIZE * 2

    with open(log_path, 'r') as fh:
        # FIX 4: instant O(1) jump — no line scanning needed
        if start_offset > 0:
            fh.seek(start_offset)

        # MUST use readline() — NOT "for line in fh".
        # Python's for-iterator calls next() internally which disables
        # fh.tell(), raising "OSError: telling position disabled by next() call".
        # readline() keeps tell() fully functional at all times.
        while True:
            line = fh.readline()
            if line == '':          # genuine EOF
                break
            line = line.strip()
            if not line:
                yield None, fh.tell()
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                yield None, fh.tell()
                continue

            sid = ev.get('session') or ev.get('src_ip', 'unknown')
            buf.setdefault(sid, []).append(ev)

            if ev.get('eventid') == 'cowrie.session.closed':
                yield _flush_session(sid, buf.pop(sid)), fh.tell()
            elif len(buf) > flush_threshold:
                oldest = sorted(buf.keys())[: flush_threshold // 2]
                for old_sid in oldest:
                    yield _flush_session(old_sid, buf.pop(old_sid)), fh.tell()
            else:
                yield None, fh.tell()

    # Flush remaining incomplete sessions at EOF
    for sid, evts in buf.items():
        yield _flush_session(sid, evts), None

# ================================================================
# SECTION 8 - STATE / CHECKPOINT  (incremental batch tracking)
# ================================================================

def load_state() -> dict:
    """
    Load checkpoint from disk.
    Returns dict:
      sessions_processed – total sessions fully handled so far
      session_counter    – next SESS-N id to assign
      batches_uploaded   – how many batches have been uploaded
      byte_offset        – byte position in cowrie.json to resume from
                           (FIX 4: 0 = start of file / no prior checkpoint)
      log_file_size      – size of cowrie.json at last save (detects file replacement)

    FILE REPLACEMENT DETECTION:
      If cowrie.json is replaced with a new/smaller file, the saved byte_offset
      will be beyond the new file end — pipeline would find zero new sessions.
      We detect this by comparing saved byte_offset vs current file size.
      If the current file is smaller than the saved offset, file was replaced
      and we reset state so the whole new file is processed from scratch.
    """
    fresh_state = {
        "sessions_processed": 0,
        "session_counter":    SESSION_COUNTER,
        "batches_uploaded":   0,
        "byte_offset":        0,
        "log_file_size":      0,
    }

    if STATE_FILE.exists():
        try:
            with open(STATE_FILE) as f:
                state = json.load(f)
            # backwards-compat: old state files won't have these keys
            state.setdefault("byte_offset", 0)
            state.setdefault("log_file_size", 0)

            # ── File replacement detection ─────────────────────────────────
            current_size = Path(COWRIE_LOG_PATH).stat().st_size if Path(COWRIE_LOG_PATH).exists() else 0
            saved_offset = state["byte_offset"]

            if saved_offset > 0 and current_size < saved_offset:
                log(f"[State] *** LOG FILE REPLACED DETECTED ***")
                log(f"[State]   Saved byte_offset : {saved_offset:,} bytes")
                log(f"[State]   Current file size : {current_size:,} bytes")
                log(f"[State]   File is smaller than saved offset — resetting state to re-process new file from scratch")
                fresh_state["log_file_size"] = current_size
                return fresh_state

            log(f"[State] Resumed — sessions_processed={state['sessions_processed']:,} "
                f"batches_uploaded={state['batches_uploaded']} "
                f"byte_offset={state['byte_offset']:,}")
            return state
        except Exception as e:
            log(f"[State] Could not read state file ({e}), starting fresh")

    return fresh_state


def save_state(state: dict) -> None:
    """Persist checkpoint state atomically (write-then-rename).
    Also records the current log file size so file replacement can be detected on next run.
    """
    try:
        Path(PROJECT_DIR).mkdir(parents=True, exist_ok=True)
        # Record current log file size for replacement detection
        if Path(COWRIE_LOG_PATH).exists():
            state["log_file_size"] = Path(COWRIE_LOG_PATH).stat().st_size
        tmp = str(STATE_FILE) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        Path(tmp).replace(STATE_FILE)
    except Exception as e:
        log(f"[State] WARNING: could not save state: {e}")


# ================================================================
# SECTION 9 - FINAL COLUMN ORDER  (shared by all batches)
# ================================================================

FINAL_COLUMNS = [
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
    # ── FIX 5: app.py /api/behavioral_data columns ──────────────
    'pca_x', 'pca_y',        # 2-D PCA projection for scatter plots
    # NOTE: 'cluster', 'duration', 'events_count' are NOT listed here.
    # app.py's load_and_train() renames the originals in-memory:
    #   behavior_cluster -> cluster
    #   session_duration -> duration
    #   event_count      -> events_count
    # Adding them here too would produce duplicate CSV columns,
    # causing a pandas ValueError when app.py tries to rename.
]


# ================================================================
# SECTION 10 - BATCH PROCESSOR  (runs all pipeline stages on one batch)
# ================================================================

def run_all_stages(summary: pd.DataFrame, session_id_offset: int) -> pd.DataFrame:
    """
    Run Stages 1-6 on a batch DataFrame and return the final output DataFrame.
    Called once per BATCH_SIZE chunk.
    """
    # ===================================================
    # STAGE 1: FEATURE ENGINEERING
    # ===================================================
    log("\n--- Stage 1: Feature Engineering ---")
    summary = fe_step1_extract_features(summary)
    summary = fe_step2_advanced_behavioral(summary)
    log("Stage 1 complete")

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

    summary['ip_scope'] = summary['src_ip'].apply(classify_ip_scope)
    log(f"Stage 2 complete | IP scope: {summary['ip_scope'].value_counts().to_dict()}")

    # ===================================================
    # STAGE 3: BEHAVIORAL CLUSTERING (Steps 1-9)
    # ===================================================
    log("\n--- Stage 3: Behavioral Clustering ---")
    summary = run_behavioral_clustering(summary)
    gc.collect()
    log("Stage 3 complete")

    # ── Build dynamic cluster weight map ──────────────────────────────────────
    # Rank clusters by mean behavioral_risk_score so the highest-risk cluster
    # always gets weight +2.0 regardless of numeric cluster id.
    # This fixes the root cause: hardcoded {0:2.0,1:1.0,2:0.0,3:-0.5} silently
    # assigned zero/negative weights when MiniBatchKMeans renumbered clusters
    # across batches, causing High-Risk sessions to collapse to Low/Zero risk.
    _cluster_risk_mean = (
        summary.groupby('behavior_cluster')['behavioral_risk_score']
        .mean()
        .sort_values(ascending=False)
    )
    _weight_levels = [2.0, 1.0, 0.0, -0.5]
    _cluster_weight_map = {
        int(cid): _weight_levels[min(i, len(_weight_levels) - 1)]
        for i, cid in enumerate(_cluster_risk_mean.index)
    }
    log(f"Stage 3 cluster weight map (dynamic): {_cluster_weight_map}")

    # ── Z-SCORE BASED RISK SCORE ──────────────────────────────────────────────
    # NOTE: behavior_label was correctly set by bc_step6_behavior_labeling().
    # We do NOT overwrite it — that was the second cause of High Risk → Low Risk.
    # risk_score is a continuous signal used for sorting/filtering only.
    summary['risk_score'] = summary.apply(
        lambda r: calculate_z_risk_score(
            r['event_count_norm'], r['unique_commands_norm'],
            r['session_duration_norm'], r['behavior_cluster'],
            _cluster_weight_map,
        ), axis=1
    )

    # ===================================================
    # STAGE 4: GEOIP ENRICHMENT
    # ===================================================
    log("\n--- Stage 4: GeoIP Enrichment ---")
    summary = geoip_enrich(summary)
    summary = threat_intel_enrichment(summary)
    summary = campaign_analysis(summary)
    summary['geo_visualization'] = summary['ip_scope'].apply(
        lambda x: 'enabled' if x == 'public' else 'disabled'
    )
    log("Stage 4 complete")

    # SESSION IDs  (offset keeps IDs globally unique across batches)
    # Zero-padded to 5 digits minimum: SESS-00001, SESS-00002, ...
    summary['session_id'] = [
        f'SESS-{session_id_offset + i:05d}' for i in range(len(summary))
    ]

    # ===================================================
    # STAGE 5: ML PIPELINE
    # ===================================================
    log("\n--- Stage 5: ML Pipeline ---")
    summary = run_ml_pipeline(summary)
    gc.collect()
    log("Stage 5 complete")

    # ===================================================
    # STAGE 6: PCA + APP.PY COLUMNS  (FIX 5)
    # ===================================================
    log("\n--- Stage 6: PCA + app.py column generation ---")
    summary = generate_app_columns(summary)
    log("Stage 6 complete")

    # Ensure all expected columns exist
    for col in FINAL_COLUMNS:
        if col not in summary.columns:
            summary[col] = None

    output = summary[FINAL_COLUMNS].copy()
    output = output.sort_values('risk_score', ascending=False)
    return output


# ================================================================
# SECTION 11 - UPLOAD TO DASHBOARD
# ================================================================

def upload_to_dashboard(csv_path: str) -> bool:
    """
    Upload a CSV batch to the dashboard via HTTP POST.
    Retries up to 3 times with increasing timeouts.
    """
    if csv_path is None:
        log("No CSV to upload - skipping")
        return False

    import os
    file_mb = os.path.getsize(csv_path) / 1_048_576
    log(f"Uploading to dashboard: {csv_path}  ({file_mb:.1f} MB)")

    timeout_secs = max(120, min(600, int(120 + file_mb * 10)))
    max_retries  = 3

    for attempt in range(1, max_retries + 1):
        try:
            log(f"  Upload attempt {attempt}/{max_retries}  (timeout={timeout_secs}s)...")
            with open(csv_path, 'rb') as f:
                response = requests.post(
                    DASHBOARD_UPLOAD_URL,
                    files={'file': ('attacks.csv', f, 'text/csv')},
                    timeout=timeout_secs,
                )
            if response.status_code == 200:
                log(f"  Upload successful! Status: {response.status_code}")
                return True
            else:
                log(f"  Upload status: {response.status_code} | {response.text[:200]}")
                if 400 <= response.status_code < 500:
                    return False

        except requests.exceptions.Timeout:
            log(f"  Attempt {attempt} timed out after {timeout_secs}s")
            timeout_secs = min(600, timeout_secs + 60)
        except requests.exceptions.ConnectionError as e:
            log(f"  Attempt {attempt} connection error: {e}")
        except Exception as e:
            log(f"  Attempt {attempt} unexpected error: {e}")

        if attempt < max_retries:
            wait = attempt * 10
            log(f"  Retrying in {wait}s...")
            time.sleep(wait)

    log(f"Upload FAILED after {max_retries} attempts")
    return False


# ================================================================
# SECTION 12 - MAIN PIPELINE  (incremental batch loop)
# ================================================================

def process_cowrie_logs():
    """
    Incremental batch pipeline orchestrator.

    FIX 4 - Byte-offset resume:
      State file stores 'byte_offset' — the exact file position after each
      successful batch.  Next systemd run calls fh.seek(byte_offset) and
      starts reading immediately.  The previous O(n) skip loop (~8 min CPU
      per run) is completely eliminated.

    FIX 5 - app.py columns:
      Stage 6 now generates pca_x, pca_y, cluster, duration, events_count
      so that /api/behavioral_data in app.py never gets a 500 error from
      missing columns again.

    Flow:
      Run 1:  sessions     1 – 10,000  → attacks.csv → upload  (offset=A)
      Run 1:  sessions 10,001 – 20,000  → attacks.csv → upload  (offset=B)
      Run 2:  fh.seek(B) → reads only new sessions instantly
    """
    log("=" * 60)
    log("Starting Cowrie Pipeline  [Incremental Batch Mode]")
    log(f"  Batch size : {BATCH_SIZE:,} sessions per upload")
    log(f"  Log file   : {COWRIE_LOG_PATH}")
    log(f"  State file : {STATE_FILE}")
    log("=" * 60)

    if not Path(COWRIE_LOG_PATH).exists():
        log(f"Cowrie log not found at: {COWRIE_LOG_PATH}")
        log("Skipping this run - honeypot may not be active yet")
        return None

    # ── Load checkpoint ────────────────────────────────────────────
    state          = load_state()
    start_offset   = state["byte_offset"]       # FIX 4: seek target
    sess_id_cursor = state["session_counter"]
    batch_num      = state["batches_uploaded"] + 1

    if start_offset > 0:
        log(f"\nResuming from byte offset {start_offset:,} "
            f"({state['sessions_processed']:,} sessions already processed — instant seek)")
    else:
        log("\nFresh run — reading from start of log file")

    # ── Inner helper: process one full batch ───────────────────────
    def _process_and_upload_batch(buf: list, batch_n: int, id_cursor: int):
        first_sess = id_cursor - SESSION_COUNTER + 1
        last_sess  = first_sess + len(buf) - 1

        log(f"\n{'=' * 60}")
        log(f"[Batch {batch_n}] Sessions {first_sess:,} – {last_sess:,}  ({len(buf):,} sessions)")
        log(f"{'=' * 60}")

        chunk_df = pd.DataFrame(buf)
        chunk_df = downcast_df(chunk_df)

        try:
            output = run_all_stages(chunk_df, session_id_offset=id_cursor)
        except Exception as e:
            log(f"[Batch {batch_n}] Pipeline FAILED: {e}")
            import traceback; traceback.print_exc()
            return id_cursor, False

        Path(PROJECT_DIR).mkdir(parents=True, exist_ok=True)
        try:
            # ── Archive previous batch into prev_output.csv before overwriting ──
            PREV_OUTPUT_CSV_PATH = str(OUTPUT_CSV_PATH).replace("attacks.csv", "prev_output.csv")
            if Path(OUTPUT_CSV_PATH).exists():
                try:
                    existing_df = pd.read_csv(OUTPUT_CSV_PATH)
                    if Path(PREV_OUTPUT_CSV_PATH).exists():
                        # Append to existing prev_output.csv (no duplicate headers)
                        existing_df.to_csv(PREV_OUTPUT_CSV_PATH, mode='a', header=False, index=False)
                    else:
                        # First time — create prev_output.csv with header
                        existing_df.to_csv(PREV_OUTPUT_CSV_PATH, index=False)
                    log(f"[Batch {batch_n}] Previous {len(existing_df):,} sessions appended → {PREV_OUTPUT_CSV_PATH}")
                except Exception as arch_e:
                    log(f"[Batch {batch_n}] WARNING: Could not archive to prev_output.csv: {arch_e}")

            output.to_csv(OUTPUT_CSV_PATH, index=False)
            log(f"[Batch {batch_n}] CSV saved  → {OUTPUT_CSV_PATH}  ({len(output):,} rows)")
        except Exception as e:
            log(f"[Batch {batch_n}] CSV save FAILED: {e}")
            return id_cursor, False

        log(f"[Batch {batch_n}] Behavior labels : {output['behavior_label'].value_counts().to_dict()}")
        log(f"[Batch {batch_n}] ML risk labels  : {output['ml_risk_label'].value_counts().to_dict()}")
        log(f"[Batch {batch_n}] Anomalies       : {int(output['is_anomaly'].sum())}")
        log(f"[Batch {batch_n}] High-risk IPs   : {int((output['risk_level']=='high').sum())}")

        upload_ok  = upload_to_dashboard(OUTPUT_CSV_PATH)
        new_cursor = id_cursor + len(buf)
        return new_cursor, upload_ok

    # ── Main batch loop ────────────────────────────────────────────
    # FIX 4: generator now yields (session | None, byte_pos) tuples
    batch_buf   = []
    total_new   = 0
    batches_ok  = 0
    last_csv    = None
    last_offset = start_offset

    for sess, file_pos in stream_aggregate_sessions(COWRIE_LOG_PATH, start_offset=start_offset):
        if file_pos is not None:
            last_offset = file_pos

        if sess is None:
            continue

        batch_buf.append(sess)
        total_new += 1

        if len(batch_buf) >= BATCH_SIZE:
            sess_id_cursor, ok = _process_and_upload_batch(
                batch_buf, batch_num, sess_id_cursor
            )

            if ok:
                state["sessions_processed"] += BATCH_SIZE
                state["session_counter"]     = sess_id_cursor
                state["batches_uploaded"]   += 1
                state["byte_offset"]         = last_offset   # FIX 4
                save_state(state)
                last_csv = OUTPUT_CSV_PATH
                batches_ok += 1
                log(f"[Checkpoint] Saved — sessions: {state['sessions_processed']:,} "
                    f"| byte_offset: {last_offset:,}")
            else:
                log(f"[Batch {batch_num}] Upload failed — checkpoint NOT advanced (will retry next run)")

            batch_buf.clear()
            gc.collect()
            batch_num += 1

    # ── Final partial batch ────────────────────────────────────────
    if batch_buf:
        log(f"\n[Batch {batch_num}] Final partial batch: {len(batch_buf):,} remaining sessions")
        sess_id_cursor, ok = _process_and_upload_batch(
            batch_buf, batch_num, sess_id_cursor
        )

        if ok:
            state["sessions_processed"] += len(batch_buf)
            state["session_counter"]     = sess_id_cursor
            state["batches_uploaded"]   += 1
            state["byte_offset"]         = last_offset   # FIX 4
            save_state(state)
            last_csv = OUTPUT_CSV_PATH
            batches_ok += 1
            log(f"[Checkpoint] Saved — sessions: {state['sessions_processed']:,} "
                f"| byte_offset: {last_offset:,}")
        else:
            log(f"[Batch {batch_num}] Upload failed — checkpoint NOT advanced")

        batch_buf.clear()
        gc.collect()

    # ── Fallback: no new sessions → re-upload the last batch ──────
    # When the pipeline is fully up to date (total_new == 0), the dashboard
    # would otherwise show nothing because no CSV was uploaded this run.
    # Instead, we read the most recent BATCH_SIZE sessions from the log
    # (going backwards from byte_offset / EOF) and upload them so the
    # application always has current data to display.
    if total_new == 0:
        log("\nNo new sessions to process — pipeline is up to date")
        log("[Fallback] Re-uploading existing attacks.csv so dashboard stays current — skipping re-processing...")

        # No new data — just re-upload the already-processed attacks.csv directly.
        # This avoids re-reading + re-processing 10,000 sessions when nothing has changed.
        if Path(OUTPUT_CSV_PATH).exists():
            ok = upload_to_dashboard(OUTPUT_CSV_PATH)
            if ok:
                last_csv = OUTPUT_CSV_PATH
                log("[Fallback] Dashboard refreshed successfully (attacks.csv re-uploaded, no re-processing needed)")
            else:
                log("[Fallback] Re-upload of attacks.csv failed")
        else:
            log("[Fallback] No attacks.csv found on disk — nothing to re-upload")

        return last_csv

    log(f"\n{'=' * 60}")
    log(f"Pipeline run complete!")
    log(f"  New sessions this run    : {total_new:,}")
    log(f"  Batches uploaded         : {batches_ok}")
    log(f"  Total sessions ever      : {state['sessions_processed']:,}")
    log(f"  Total batches ever       : {state['batches_uploaded']}")
    log(f"  Next run resumes at      : byte offset {state['byte_offset']:,}")
    log(f"{'=' * 60}")

    return last_csv


# ================================================================
# MAIN EXECUTION
# ================================================================

if __name__ == "__main__":
    try:
        csv_path = process_cowrie_logs()

        if csv_path:
            log("Pipeline completed successfully!")
            sys.exit(0)
        else:
            log("No new data processed this run")
            sys.exit(0)

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
    finally:
        log("Pipeline execution finished")
        log("=" * 60)


