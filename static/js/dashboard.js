// Global Chart Defaults
Chart.defaults.color = '#e0e0e0';
Chart.defaults.borderColor = '#444';

async function fetchOverviewData() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        if (stats.error) {
        console.warn('Backend returned error:', stats.error);
        alert('No data available. Please upload a CSV file or ensure the backend has data loaded.');
        return; 
    }

        document.getElementById('kpi-total').innerText = stats.total_sessions;
        document.getElementById('kpi-risk').innerText = stats.high_risk_count;
        document.getElementById('kpi-anomalies').innerText = stats.anomalies_detected;
        document.getElementById('kpi-countries').innerText = stats.countries_count;

        // Fetch Charts Data
        const riskResponse = await fetch('/api/risk_data');
        const riskData = await riskResponse.json();
        renderRiskDistChart(riskData.distribution);
        if (riskData.time_series) renderActivityChart(riskData.time_series);
        renderTopRiskTable(riskData.top_risk_sessions);
        
    } catch (error) {
        console.error('Error fetching overview data:', error);
        alert('Failed to load dashboard data. Please ensure the backend is running and data is uploaded.');
    }
}

function renderRiskDistChart(data) {
    const ctx = document.getElementById('riskDistChart');
    if (!ctx) return;
    
    // Define color mapping for each risk level
    const colorMap = {
        'High Risk': '#dc3545',      // Red
        'Medium Risk': '#ffc107',    // Yellow/Orange
        'Low Risk': '#28a745',       // Green
        'High': '#dc3545',           // Red (alternative naming)
        'Medium': '#ffc107',         // Yellow/Orange (alternative naming)
        'Low': '#28a745'             // Green (alternative naming)
    };
    
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    // Map colors based on the actual labels
    const backgroundColor = labels.map(label => {
        // Check for exact match first
        if (colorMap[label]) {
            return colorMap[label];
        }
        // Check if label contains risk level keyword
        if (label.toLowerCase().includes('high')) return '#dc3545';
        if (label.toLowerCase().includes('medium')) return '#ffc107';
        if (label.toLowerCase().includes('low')) return '#28a745';
        // Default gray for unknown
        return '#6c757d';
    });
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: backgroundColor,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { 
                    position: 'right',
                    labels: {
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

function renderActivityChart(data) {
    const ctx = document.getElementById('activityChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.dates,
            datasets: [
                {
                    label: 'Total Sessions',
                    data: data.total,
                    borderColor: '#03dac6',
                    backgroundColor: 'rgba(3, 218, 198, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'High Risk',
                    data: data.high_risk,
                    borderColor: '#cf6679',
                    backgroundColor: 'rgba(207, 102, 121, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { 
                    beginAtZero: true,
                    grid: { color: '#333' }
                },
                x: {
                    grid: { color: '#333' }
                }
            }
        }
    });
}

function renderTopRiskTable(sessions) {
    const tbody = document.querySelector('#topRiskTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    sessions.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${s.session_id}</td>
            <td>${s.ip_address}</td>
            <td>${s.country}</td>
            <td><span class="badge bg-danger">${s.risk_score.toFixed(1)}</span></td>
            <td>${s.predicted_risk_level}</td>
        `;
        tbody.appendChild(tr);
    });
}

async function fetchBehavioralData() {
    // Moved to static/behavioral.js
}

function renderClusterChart(data) {
    // Moved to static/behavioral.js
}

function renderAnomalyTable(anomalies) {
    // Moved to static/behavioral.js
}

function renderClusterProfileTable(profiles) {
    // Moved to static/behavioral.js
}

function renderBehaviorHeatmap(profiles) {
    // Moved to static/behavioral.js
}

function renderStabilityPlot(base64Img) {
    // Moved to static/behavioral.js
}

async function fetchRiskData() {
    // Moved to static/risk.js
}

function renderFeatureImpChart(data) {
    // Moved to static/risk.js
}

function renderShapChart(data) {
    // Moved to static/risk.js
}

async function fetchGeoData() {
    // Moved to static/geo.js
}

function renderMap(points) {
    // Moved to static/geo.js
}

function renderAsnChart(data) {
    // Moved to static/geo.js
}

function renderInternalIpRiskChart(topIps) {
    // Moved to static/geo.js
}

function renderInternalRiskDistChart(dist) {
    // Moved to static/geo.js
}

function renderInternalActivityChart(activity) {
    // Moved to static/geo.js
}

function renderCountryTable(data) {
    // Moved to static/geo.js
}
