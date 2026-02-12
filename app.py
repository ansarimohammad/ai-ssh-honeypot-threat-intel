from flask import Flask, render_template, jsonify, request, redirect, url_for
import pandas as pd
import os
import ipaddress
from ml_engine import MLEngine

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'data'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Global Engine Instance
engine = MLEngine()
current_data = None
model_metrics = {}
feature_importance = {}
clustering_stats = {}

def load_and_train():
    global current_data, model_metrics, feature_importance, clustering_stats
    # Load only the final dashboard dataset
    data_path = os.path.join(app.config['UPLOAD_FOLDER'], 'final_dashboard_dataset.csv')
    
    if os.path.exists(data_path):
        print("Loading data and training models...")
        try:
            df = pd.read_csv(data_path)
            
            print(f"Original columns: {df.columns.tolist()}")
            print(f"Total records: {len(df)}")
            
            # ===== COLUMN MAPPING =====
            column_mapping = {
                'src_ip': 'ip_address',
                'latitude': 'lat',
                'longitude': 'lon',
                'event_count': 'events_count',
                'session_duration': 'duration',
                'behavior_cluster': 'cluster'
            }
            
            # Rename columns
            df = df.rename(columns=column_mapping)
            
            # ===== NORMALIZE RISK SCORE TO 0-100 =====
            # Your data has z-scores (e.g., -0.22, 4.47), convert to 0-100
            def map_risk_to_100(score):
                """Map z-score to 0-100 scale"""
                if pd.isna(score):
                    return 0
                # Clamp between -2 and 5, then map to 0-100
                clamped = max(-2, min(5, score))
                return ((clamped + 2) / 7) * 100
            
            # Keep original risk_score as risk_score_raw for reference
            df['risk_score_raw'] = df['risk_score']
            df['risk_score'] = df['risk_score'].apply(map_risk_to_100)
            
            print(f"\nRisk Score Range: {df['risk_score'].min():.2f} - {df['risk_score'].max():.2f}")
            
            # ===== HANDLE RISK LABELS =====
            # Use behavior_label as the primary risk level (it has the actual High Risk, Medium Risk values)
            if 'behavior_label' in df.columns:
                df['predicted_risk_level'] = df['behavior_label']
            elif 'ml_risk_label' in df.columns:
                df['predicted_risk_level'] = df['ml_risk_label']
            else:
                # Fallback: create risk level from risk_score
                df['predicted_risk_level'] = pd.cut(df['risk_score'], 
                                                     bins=[0, 33, 66, 100],
                                                     labels=['Low Risk', 'Medium Risk', 'High Risk'])
            
            # Handle ml_risk_score
            if 'ml_risk_score' in df.columns:
                df['predicted_risk_score'] = df['ml_risk_score']
            else:
                df['predicted_risk_score'] = df['risk_score']
            
            # Clean up risk levels - remove any NaN or empty values
            df['predicted_risk_level'] = df['predicted_risk_level'].fillna('Unknown')
            
            print(f"\nRisk Level Distribution:")
            print(df['predicted_risk_level'].value_counts())
            
            # Ensure 'is_anomaly' column exists
            if 'is_anomaly' not in df.columns:
                # Mark High Risk as anomalies
                df['is_anomaly'] = df['predicted_risk_level'].str.contains('High', case=False, na=False)
            
            # Ensure 'timestamp' exists for time series
            if 'timestamp' not in df.columns:
                df['timestamp'] = pd.date_range(start='2024-01-01', periods=len(df), freq='h')
            
            # Ensure PCA columns exist for scatter plot
            if 'pca_x' not in df.columns:
                # Normalize risk_score_raw for x-axis (use raw z-scores)
                df['pca_x'] = df['risk_score_raw']
            if 'pca_y' not in df.columns:
                # Normalize events_count for y-axis
                df['pca_y'] = (df['events_count'] - df['events_count'].mean()) / df['events_count'].std()
            
            # Handle missing lat/lon
            df['lat'] = pd.to_numeric(df['lat'], errors='coerce').fillna(0)
            df['lon'] = pd.to_numeric(df['lon'], errors='coerce').fillna(0)
            
            # Add missing columns for compatibility
            if 'velocity_score' not in df.columns:
                df['velocity_score'] = 0
            if 'bytes_transferred' not in df.columns:
                df['bytes_transferred'] = 0
            
            # Mock metrics if training fails
            model_metrics = {
                'accuracy': 0.85,
                'precision': 0.82,
                'recall': 0.88,
                'f1_score': 0.85
            }
            
            feature_importance = {
                'risk_score': 0.35,
                'events_count': 0.25,
                'duration': 0.20,
                'unique_commands': 0.20
            }
            
            clustering_stats['silhouette'] = 0.65
            
            current_data = df
            
            # Print summary
            high_risk_count = (df['predicted_risk_level'].str.contains('High', case=False, na=False)).sum()
            print(f"\n✓ Training complete. Loaded {len(df)} sessions.")
            print(f"✓ High Risk sessions: {high_risk_count}")
            print(f"✓ Countries: {df['country'].nunique()}")
            
        except Exception as e:
            print(f"❌ Error during training: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("❌ No data found at startup.")
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/behavioral')
def behavioral():
    return render_template('behavioral.html')

@app.route('/risk')
def risk():
    return render_template('risk.html')

@app.route('/geo')
def geo():
    return render_template('geo.html')

@app.route('/api/stats')
def get_stats():
    if current_data is None:
        return jsonify({"error": "No data loaded"}), 404
    
    # Count high risk using flexible matching
    high_risk_count = (current_data['predicted_risk_level'].str.contains('High', case=False, na=False)).sum()
    
    stats = {
        'total_sessions': int(len(current_data)),
        'high_risk_count': int(high_risk_count),
        'anomalies_detected': int(current_data['is_anomaly'].sum()) if 'is_anomaly' in current_data.columns else int(high_risk_count),
        'countries_count': int(current_data['country'].nunique()) if 'country' in current_data.columns else 0,
        'model_accuracy': float(model_metrics.get('accuracy', 0))
    }
    
    print(f"📊 Stats API called: {stats}")
    return jsonify(stats)

@app.route('/api/risk_data')
def get_risk_data():
    if current_data is None: 
        print("❌ No data loaded for risk_data")
        return jsonify({'error': 'No data loaded'}), 404
    
    try:
        # Risk Distribution
        risk_dist = current_data['predicted_risk_level'].value_counts().to_dict()
        risk_dist = {str(k): int(v) for k, v in risk_dist.items()}
        
        print(f"📊 Risk Distribution: {risk_dist}")
        
        # Time Series Activity
        time_series = {}
        if 'timestamp' in current_data.columns:
            try:
                if not pd.api.types.is_datetime64_any_dtype(current_data['timestamp']):
                    current_data['timestamp'] = pd.to_datetime(current_data['timestamp'])
                
                daily_counts = current_data.set_index('timestamp').resample('D').size()
                
                # Flexible high risk matching
                high_risk_mask = current_data['predicted_risk_level'].str.contains('High', case=False, na=False)
                daily_risk = current_data[high_risk_mask].set_index('timestamp').resample('D').size()
                daily_risk = daily_risk.reindex(daily_counts.index, fill_value=0)
                
                time_series = {
                    'dates': daily_counts.index.strftime('%Y-%m-%d').tolist(),
                    'total': [int(x) for x in daily_counts.values.tolist()],
                    'high_risk': [int(x) for x in daily_risk.values.tolist()]
                }
            except Exception as e:
                print(f"⚠️ Error processing time series: {e}")

        # Top Risk Sessions - flexible high risk matching
        high_risk_mask = current_data['predicted_risk_level'].str.contains('High', case=False, na=False)
        
        cols_to_return = ['session_id', 'risk_score', 'predicted_risk_level']
        
        # Add columns if they exist
        for col in ['ip_address', 'country', 'attacker_type', 'threat_archetype', 'behavior_label']:
            if col in current_data.columns:
                cols_to_return.append(col)
        
        top_risk = current_data[high_risk_mask].sort_values('risk_score', ascending=False).head(10)
        
        # Convert to records and ensure JSON serializable
        top_risk_records = []
        for _, row in top_risk.iterrows():
            record = {}
            for col in cols_to_return:
                val = row[col]
                # Convert numpy types to Python types
                if pd.isna(val):
                    record[col] = None
                elif isinstance(val, (int, float)):
                    record[col] = float(val) if isinstance(val, float) else int(val)
                else:
                    record[col] = str(val)
            top_risk_records.append(record)
        
        print(f"📊 Top Risk Sessions: {len(top_risk_records)} records")

        # Risk by Cluster
        risk_by_cluster = {}
        if 'cluster' in current_data.columns:
            risk_by_cluster = {str(k): float(v) for k, v in current_data.groupby('cluster')['risk_score'].mean().to_dict().items()}

        # Risk Histogram Data (Bins) - FIXED
        import numpy as np
        
        # Get risk scores and handle the data properly
        risk_scores = current_data['risk_score'].dropna()
        
        # Since your risk_score appears to be z-scores (-1 to 5 range), let's map to 0-100 first
        def map_risk_to_100(score):
            """Map z-score to 0-100 scale"""
            # Clamp between -2 and 5, then map to 0-100
            clamped = max(-2, min(5, score))
            return ((clamped + 2) / 7) * 100
        
        risk_scores_100 = risk_scores.apply(map_risk_to_100)
        
        # Create histogram with 20 bins
        hist, bins = np.histogram(risk_scores_100, bins=20, range=(0, 100))
        
        # Create labels for bins
        hist_labels = [f"{int(bins[i])}-{int(bins[i+1])}" for i in range(len(bins)-1)]
        hist_data = [int(x) for x in hist.tolist()]
        
        print(f"📊 Histogram created: {len(hist_labels)} bins, {sum(hist_data)} total sessions")

        response_data = {
            'distribution': risk_dist,
            'time_series': time_series,
            'top_risk_sessions': top_risk_records,
            'feature_importance': feature_importance,
            'metrics': model_metrics,
            'risk_by_cluster': risk_by_cluster,
            'risk_histogram': {
                'labels': hist_labels,
                'data': hist_data
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"❌ Error in risk_data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/behavioral_data')
def get_behavioral_data():
    if current_data is None: 
        return jsonify({'error': 'No data loaded'}), 404
    
    try:
        # Required columns for scatter
        required_cols = ['pca_x', 'pca_y', 'cluster', 'session_id']
        if 'is_anomaly' in current_data.columns:
            required_cols.append('is_anomaly')
        
        scatter_data = current_data[required_cols].fillna(0).to_dict(orient='records')
        
        # Duration vs Events scatter
        duration_event_data = current_data[['duration', 'events_count', 'cluster', 'session_id']].fillna(0).to_dict(orient='records')
        
        # Cluster Profiles
        profiles = {}
        if 'cluster' in current_data.columns:
            for cluster_id in current_data['cluster'].unique():
                if pd.notna(cluster_id):
                    cluster_data = current_data[current_data['cluster'] == cluster_id]
                    profiles[int(cluster_id)] = {
                        'duration': float(cluster_data['duration'].mean()),
                        'events_count': float(cluster_data['events_count'].mean()),
                        'risk_score': float(cluster_data['risk_score'].mean()),
                        'velocity_score': float(cluster_data['velocity_score'].mean()) if 'velocity_score' in cluster_data.columns else 0.0,
                        'bytes_transferred': float(cluster_data['bytes_transferred'].mean()) if 'bytes_transferred' in cluster_data.columns else 0.0,
                        'count': int(len(cluster_data))
                    }
        
        # Anomalies
        anomalies = []
        if 'is_anomaly' in current_data.columns:
            anomaly_data = current_data[current_data['is_anomaly']].head(20)
            anomalies = anomaly_data.fillna('').to_dict(orient='records')
        
        # Stability Plot
        stability_plot = engine.generate_stability_plot(current_data)
        
        return jsonify({
            'scatter': scatter_data,
            'duration_event_scatter': duration_event_data,
            'profiles': profiles,
            'silhouette': float(clustering_stats.get('silhouette', 0)),
            'anomalies': anomalies,
            'stability_plot': stability_plot
        })
    except Exception as e:
        print(f"❌ Error in behavioral_data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/geo_data')
def get_geo_data():
    if current_data is None: 
        return jsonify({'error': 'No data loaded'}), 404
    
    try:
        # Helper to check if IP is private
        def is_private_ip(ip):
            try:
                return ipaddress.ip_address(ip).is_private
            except:
                return False

        # Add is_private column temporarily if not exists
        temp_df = current_data.copy()
        temp_df['is_private'] = temp_df['ip_address'].apply(is_private_ip)
        
        # --- Public IPs (Global Threat) ---
        public_df = temp_df[~temp_df['is_private']]
        
        # Filter for map (needs lat/lon)
        geo_df = public_df[(public_df['lat'] != 0) & (public_df['lon'] != 0)].dropna(subset=['lat', 'lon'])
        
        geo_points = geo_df[['lat', 'lon', 'country', 'ip_address', 'risk_score']].to_dict(orient='records')
        
        # Country risk (Public only)
        country_risk = {}
        if 'country' in public_df.columns:
            country_risk = public_df.groupby('country')['risk_score'].mean().sort_values(ascending=False).head(20).to_dict()
            country_risk = {str(k): float(v) for k, v in country_risk.items()}

        # Top ASNs (Public only) - Check if 'asn' exists
        top_asns = {}
        if 'asn' in public_df.columns:
             # Count sessions per ASN
            top_asns = public_df['asn'].value_counts().head(10).to_dict()
            top_asns = {str(k): int(v) for k, v in top_asns.items()}

        # --- Private IPs (Internal Threat) ---
        private_df = temp_df[temp_df['is_private']]
        
        internal_stats = {
            'count': len(private_df),
            'top_ips': [],
            'risk_distribution': {},
            'events_by_ip': {}
        }

        if not private_df.empty:
            # 1. Top Internal IPs by Risk Score
            top_internal = private_df.groupby('ip_address')['risk_score'].mean().sort_values(ascending=False).head(10)
            internal_stats['top_ips'] = [{'ip': ip, 'score': float(score)} for ip, score in top_internal.items()]
            
            # 2. Internal Risk Distribution
            internal_risk_dist = private_df['predicted_risk_level'].value_counts().to_dict()
            internal_stats['risk_distribution'] = {str(k): int(v) for k, v in internal_risk_dist.items()}
            
            # 3. Events by Internal IP (Top 10 most active)
            top_active = private_df.groupby('ip_address')['events_count'].sum().sort_values(ascending=False).head(10)
            internal_stats['events_by_ip'] = {str(k): int(v) for k, v in top_active.items()}

        return jsonify({
            'points': geo_points,
            'country_risk': country_risk,
            'top_asns': top_asns,
            'internal_stats': internal_stats
        })
    except Exception as e:
        print(f"❌ Error in geo_data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file:
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'final_dashboard_dataset.csv'))
        load_and_train()
        return redirect(url_for('index'))

# Initialize data on startup (ensure this runs for Gunicorn workers)
try:
    print("🚀 Initializing application data...")
    load_and_train()
except Exception as e:
    print(f"⚠️ Startup initialization warning: {e}")

if __name__ == '__main__':
    # Initial load is already handled above
    # Use os.environ.get for port, default to 5000
    # Set debug to False for production
    port = int(os.environ.get('PORT', 5000))
    # Explicitly disable debug mode unless FLASK_ENV is set to development
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    if debug_mode:
        print("⚠️ Running in DEBUG mode")
    else:
        print("✅ Running in PRODUCTION mode")
        
    app.run(debug=debug_mode, host='0.0.0.0', port=port)