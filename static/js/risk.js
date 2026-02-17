// Risk Engine Page Scripts

Chart.defaults.color = '#e0e0e0';
Chart.defaults.borderColor = '#444';

document.addEventListener('DOMContentLoaded', function() {
    fetchRiskData();
});

async function fetchRiskData() {
    try {
        const response = await fetch('/api/risk_data');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        
        // Metrics
        if (data.metrics) {
            document.getElementById('metric-acc').innerText = (data.metrics.accuracy * 100).toFixed(1) + '%';
            document.getElementById('metric-prec').innerText = (data.metrics.precision * 100).toFixed(1) + '%';
            document.getElementById('metric-rec').innerText = (data.metrics.recall * 100).toFixed(1) + '%';
            renderModelSummary(data.metrics);
        } else {
            console.warn('Metrics data is missing');
        }

        // Feature Importance
        if (data.feature_importance) {
            renderFeatureImpChart(data.feature_importance);
        }
        
        // SHAP Values
        if (data.shap_values) {
            renderShapChart(data.shap_values);
        }
        
        // Risk Prediction Chart (ML Score vs Cluster)
        renderRiskPredictionChart(data.risk_by_cluster);
        
        // Risk Histogram
        if (data.risk_histogram) {
            renderRiskHistogram(data.risk_histogram);
        }
        
        // High Risk List
        renderHighRiskTable(data.top_risk_sessions);
        
    } catch (error) {
        console.error('Error fetching risk data:', error);
        alert('Failed to load risk engine data. Check console for details.');
    }
}

function renderModelSummary(metrics) {
    const summaryDiv = document.getElementById('modelSummaryContent');
    if (!summaryDiv) return;
    
    summaryDiv.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <h6>Algorithms Used</h6>
                <ul class="list-unstyled text-muted small">
                    <li><i class="fas fa-check text-success me-2"></i>Random Forest Classifier (n_est=100)</li>
                    <li><i class="fas fa-check text-success me-2"></i>XGBoost (gbtree)</li>
                </ul>
            </div>
            <div class="col-md-6">
                <h6>Performance Status</h6>
                <p class="text-muted small">
                    Model is performing with an overall accuracy of <strong class="text-white">${(metrics.accuracy * 100).toFixed(1)}%</strong>. 
                    Precision indicates a low false positive rate.
                </p>
            </div>
        </div>
    `;
}

function renderFeatureImpChart(data) {
    const ctx = document.getElementById('featureImpChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(x => x[0]),
            datasets: [{
                label: 'Importance',
                data: sorted.map(x => x[1]),
                backgroundColor: '#03dac6',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { grid: { color: '#333' } },
                y: { grid: { display: false } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function renderShapChart(data) {
    const ctx = document.getElementById('shapChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(x => x[0]),
            datasets: [{
                label: 'Mean |SHAP|',
                data: sorted.map(x => x[1]),
                backgroundColor: '#bb86fc',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { grid: { color: '#333' } },
                y: { grid: { display: false } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function renderRiskPredictionChart(data) {
    const ctx = document.getElementById('riskPredictionChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    const clusters = Object.keys(data);
    const scores = Object.values(data);

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: clusters.map(c => `Cluster ${c}`),
            datasets: [{
                label: 'Avg Risk Score',
                data: scores,
                borderColor: '#cf6679',
                backgroundColor: 'rgba(207, 102, 121, 0.2)',
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#cf6679',
                pointRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { 
                    beginAtZero: true, 
                    max: 100,
                    title: { display: true, text: 'Risk Score (0-100)' },
                    grid: { color: '#333' }
                },
                x: { grid: { color: '#333' } }
            }
        }
    });
}

function renderRiskHistogram(data) {
    const ctx = document.getElementById('riskDistHistogram');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Sessions Count',
                data: data.data,
                backgroundColor: '#bb86fc',
                barPercentage: 1.0,
                categoryPercentage: 1.0,
                borderWidth: 1,
                borderColor: '#1e1e1e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { 
                    title: { display: true, text: 'Sessions' },
                    grid: { color: '#333' }
                },
                x: { 
                    title: { display: true, text: 'Risk Score Range' },
                    grid: { display: false } 
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            return `Score Range: ${context[0].label}`;
                        }
                    }
                }
            }
        }
    });
}

function renderHighRiskTable(sessions) {
    const tbody = document.querySelector('#highRiskListTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    sessions.forEach((s, index) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="badge bg-secondary rounded-pill">#${index + 1}</span></td>
            <td>${s.session_id}</td>
            <td>${s.ip_address}</td>
            <td><div class="progress" style="height: 6px; width: 100px;">
                <div class="progress-bar bg-danger" role="progressbar" style="width: ${s.risk_score}%"></div>
            </div></td>
            <td class="text-danger fw-bold">${s.risk_score.toFixed(1)}</td>
        `;
        tbody.appendChild(tr);
    });
}
