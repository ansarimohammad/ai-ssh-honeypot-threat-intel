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

        // Attack Vector Analysis (Radar)
        if (data.attack_vector) {
            renderAttackVectorChart(data.attack_vector);
        }
        
        // Threat Archetype Distribution
        if (data.threat_archetype) {
            renderThreatArchetypeChart(data.threat_archetype);
        }

        // Campaign Severity Analysis
        if (data.campaign_analysis) {
            renderCampaignSeverityChart(data.campaign_analysis);
        }

        // Risk Factor Breakdown (Explainability)
        if (data.risk_factors) {
            renderRiskFactorChart(data.risk_factors);
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

function renderAttackVectorChart(data) {
    const ctx = document.getElementById('attackVectorChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: 'Avg Attack Intensity',
                data: Object.values(data),
                backgroundColor: 'rgba(3, 218, 198, 0.2)',
                borderColor: '#03dac6',
                pointBackgroundColor: '#03dac6',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: '#03dac6'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: { color: '#444' },
                    grid: { color: '#333' },
                    pointLabels: { color: '#ccc' },
                    ticks: { backdropColor: 'transparent', color: '#888' }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderThreatArchetypeChart(data) {
    const ctx = document.getElementById('threatArchetypeChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: ['#cf6679', '#bb86fc', '#03dac6', '#ffb74d', '#3700b3'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#ccc' } }
            }
        }
    });
}

function renderCampaignSeverityChart(data) {
    const ctx = document.getElementById('campaignSeverityChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: 'Sessions',
                data: Object.values(data),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)', // High - Red
                    'rgba(255, 205, 86, 0.7)', // Medium - Yellow
                    'rgba(75, 192, 192, 0.7)'  // Low - Green
                ],
                borderColor: [
                    'rgb(255, 99, 132)',
                    'rgb(255, 205, 86)',
                    'rgb(75, 192, 192)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: '#333' } },
                x: { grid: { display: false } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderRiskFactorChart(data) {
    const ctx = document.getElementById('riskFactorChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    // Sort factors by contribution
    const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]);

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(x => x[0]),
            datasets: [{
                label: 'Contribution (%)',
                data: sorted.map(x => x[1]),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 206, 86, 0.7)',
                    'rgba(75, 192, 192, 0.7)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { 
                    beginAtZero: true,
                    max: 100,
                    grid: { color: '#333' },
                    title: { display: true, text: 'Contribution to Risk (%)' }
                },
                y: { grid: { display: false } }
            },
            plugins: { legend: { display: false } }
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
