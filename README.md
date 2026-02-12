# ML SOC Risk Engine & Behavioral Intelligence Dashboard

A full-stack security analytics web platform designed for SOC analysts and security researchers. This system ingests session logs, applies machine learning for risk scoring and behavioral clustering, and provides interactive dashboards for threat hunting.

## Features

### 1. ML Risk Engine (Supervised Learning)
- **Algorithms**: Random Forest and XGBoost classifiers.
- **Risk Scoring**: assigns a risk score (0-100) and level (Low/Medium/High) to each session.
- **Explainability**: SHAP (SHapley Additive exPlanations) values to interpret model decisions.
- **Metrics**: Real-time calculation of Accuracy, Precision, and Recall.

### 2. Behavioral Intelligence (Unsupervised Learning)
- **Clustering**: KMeans algorithm to group similar session behaviors.
- **Anomaly Detection**: DBSCAN to identify outliers and potential zero-day attacks.
- **Visualization**: PCA (Principal Component Analysis) for 2D projection of high-dimensional behavioral data.

### 3. Geo Threat Intelligence
- **Mapping**: Interactive world map visualizing threat origins.
- **Analytics**: Aggregated risk scores by country and ASN.

### 4. Interactive Dashboard
- **Dark Mode**: Professional SOC interface.
- **Dynamic Charts**: Built with Chart.js and Leaflet.js.
- **Data Ingestion**: CSV upload support with automatic pipeline execution.

## Installation

1. **Prerequisites**: Python 3.8+
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Generate Sample Data** (Optional):
   ```bash
   python generate_data.py
   ```
   This creates `data/session_logs.csv` with synthetic attack patterns.

2. **Run the Application**:
   ```bash
   python app.py
   ```

3. **Access the Dashboard**:
   Open `http://localhost:5000` in your browser.

4. **Upload Data**:
   Use the sidebar to upload a new CSV file. The system will automatically retrain models and update dashboards.

## Research Methodology

### Feature Engineering
- **Velocity Score**: Rate of login attempts per minute.
- **Geo Distance**: Haversine distance between consecutive logins (simulated).
- **Categorical Encoding**: Label encoding for Country, ASN, and Device Type.

### Model Pipeline
1. **Preprocessing**: Missing value imputation, Scaling (StandardScaler).
2. **Training**: 80/20 train-test split on uploaded data.
3. **Evaluation**: Weighted precision/recall to handle class imbalance.

## Tech Stack
- **Backend**: Flask, Pandas, NumPy, Scikit-learn, XGBoost, SHAP.
- **Frontend**: HTML5, CSS3 (Bootstrap 5), JavaScript (ES6+).
- **Visualization**: Chart.js, Leaflet.js.
