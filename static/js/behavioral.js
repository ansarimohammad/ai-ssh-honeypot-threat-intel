// Behavioral Intelligence Page Scripts

Chart.defaults.color = '#e0e0e0';
Chart.defaults.borderColor = '#444';

document.addEventListener('DOMContentLoaded', function() {
    console.log('Behavioral JS loaded');
    fetchBehavioralData();
});

async function fetchBehavioralData() {
    try {
        console.log('Fetching behavioral data...');
        const response = await fetch('/api/behavioral_data');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Behavioral data received:', data);
        
        if (document.getElementById('silhouetteScore')) {
             document.getElementById('silhouetteScore').innerText = `Silhouette: ${data.silhouette ? data.silhouette.toFixed(3) : 'N/A'}`;
        }
        
        if (data.duration_event_scatter) {
            renderClusterChart(data.duration_event_scatter);
        } else {
            console.warn('No duration_event_scatter data found');
        }

        if (data.anomalies) {
            renderAnomalyTable(data.anomalies);
        }

        if (data.profiles) {
            renderBehaviorHeatmap(data.profiles);
        } else {
            console.warn('No profiles data found');
        }

        if (data.stability_plot) {
            renderStabilityPlot(data.stability_plot);
        }

        if (data.anomaly_distribution) {
            renderAnomalyDistributionChart(data.anomaly_distribution);
        }
        
    } catch (error) {
        console.error('Error fetching behavioral data:', error);
        alert('Failed to load behavioral data. Check console for details.');
    }
}

function renderClusterChart(data) {
    const ctx = document.getElementById('clusterScatterChart');
    if (!ctx) {
        console.error('Canvas clusterScatterChart not found');
        return;
    }
    
    // Group by cluster
    const clusters = {};
    data.forEach(d => {
        if (!clusters[d.cluster]) clusters[d.cluster] = [];
        clusters[d.cluster].push({x: d.duration, y: d.events_count});
    });
    
    const datasets = Object.keys(clusters).map((c, i) => ({
        label: `Cluster ${c}`,
        data: clusters[c],
        backgroundColor: `hsl(${i * 137.5}, 70%, 50%)`
    }));
    
    // Destroy existing chart if any (to avoid duplicates on reload)
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'scatter',
        data: { datasets: datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { 
                    title: { display: true, text: 'Duration (sec)' },
                    type: 'logarithmic',
                    grid: { color: '#333' }
                },
                y: { 
                    title: { display: true, text: 'Event Count' },
                    grid: { color: '#333' }
                }
            }
        }
    });
}

function renderAnomalyTable(anomalies) {
    const tbody = document.querySelector('#anomalyTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    anomalies.forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${a.session_id}</td>
            <td>${a.ip_address}</td>
            <td><span class="badge bg-warning text-dark">${a.cluster}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderBehaviorHeatmap(profiles) {
    const ctx = document.getElementById('behaviorHeatmapChart');
    if (!ctx) return;
    
    // Normalize data for heatmap visualization (0-1 scale per feature)
    // Updated to match available dataset columns: duration, events_count, unique_commands, failed_logins
    const features = ['duration', 'events_count', 'unique_commands', 'failed_logins'];
    const clusters = Object.keys(profiles);
    
    // Find max per feature for normalization
    const maxVals = {};
    features.forEach(f => {
        const values = clusters.map(c => profiles[c][f] || 0);
        maxVals[f] = Math.max(...values) || 1; // Avoid divide by zero
    });

    const datasets = clusters.map((c, i) => ({
        label: `Cluster ${c}`,
        data: features.map(f => (profiles[c][f] || 0) / maxVals[f]), // Normalized
        backgroundColor: `hsla(${i * 137.5}, 70%, 50%, 0.5)`,
        borderColor: `hsl(${i * 137.5}, 70%, 50%)`,
        borderWidth: 1
    }));
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: features,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: { color: '#333' },
                    grid: { color: '#333' },
                    pointLabels: { color: '#e0e0e0', font: { size: 12 } },
                    ticks: { display: false, backdropColor: 'transparent' },
                    suggestedMin: 0,
                    suggestedMax: 1
                }
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            // Show raw value in tooltip instead of normalized
                            const featureIndex = context.dataIndex;
                            const featureName = features[featureIndex];
                            const clusterId = clusters[context.datasetIndex];
                            const rawValue = profiles[clusterId][featureName];
                            return `Cluster ${clusterId}: ${rawValue.toFixed(2)}`;
                        }
                    }
                }
            }
        }
    });
}

function renderStabilityPlot(data) {
    const ctx = document.getElementById('stabilityChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.clusters,
            datasets: [{
                label: 'Stability Score',
                data: data.scores,
                backgroundColor: data.scores.map(s => 
                    s > 0.8 ? 'rgba(75, 192, 192, 0.7)' : // High stability (Green)
                    s > 0.5 ? 'rgba(255, 205, 86, 0.7)' : // Medium (Yellow)
                    'rgba(255, 99, 132, 0.7)'             // Low (Red)
                ),
                borderColor: data.scores.map(s => 
                    s > 0.8 ? 'rgb(75, 192, 192)' : 
                    s > 0.5 ? 'rgb(255, 205, 86)' : 
                    'rgb(255, 99, 132)'
                ),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { 
                    beginAtZero: true, 
                    max: 1.0,
                    grid: { color: '#333' },
                    title: { display: true, text: 'Stability Score (0-1)' }
                },
                x: { 
                    grid: { display: false },
                    title: { display: true, text: 'Behavioral Clusters' }
                }
            },
            plugins: { 
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Stability: ${context.raw.toFixed(3)}`;
                        }
                    }
                }
            }
        }
    });
}

function renderAnomalyDistributionChart(data) {
    const ctx = document.getElementById('anomalyDistributionChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 206, 86, 0.7)',
                    'rgba(75, 192, 192, 0.7)',
                    'rgba(153, 102, 255, 0.7)'
                ],
                borderColor: '#121212',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#e0e0e0', font: { size: 11 } }
                }
            }
        }
    });
}
