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
            renderClusterProfileTable(data.profiles);
            renderBehaviorHeatmap(data.profiles);
        } else {
            console.warn('No profiles data found');
        }

        if (data.stability_plot) {
            renderStabilityPlot(data.stability_plot);
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

function renderClusterProfileTable(profiles) {
    const tbody = document.querySelector('#clusterProfileTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    Object.entries(profiles).forEach(([cluster, stats]) => {
        const tr = document.createElement('tr');
        // Safety checks for values
        const duration = (stats.duration || 0).toFixed(1);
        const events = (stats.events_count || 0).toFixed(1);
        const bytes = (stats.bytes_transferred || 0).toFixed(0);
        const velocity = (stats.velocity_score || 0).toFixed(2);
        
        tr.innerHTML = `
            <td><span class="badge" style="background-color: hsl(${cluster * 137.5}, 70%, 50%)">Cluster ${cluster}</span></td>
            <td>${duration}</td>
            <td>${events}</td>
            <td>${bytes}</td>
            <td>${velocity}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderBehaviorHeatmap(profiles) {
    const ctx = document.getElementById('behaviorHeatmapChart');
    if (!ctx) return;
    
    // Normalize data for heatmap visualization (0-1 scale per feature)
    const features = ['duration', 'events_count', 'bytes_transferred', 'velocity_score'];
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

function renderStabilityPlot(base64Img) {
    const img = document.getElementById('stabilityPlotImg');
    const loading = document.getElementById('stabilityLoading');
    if (!img) return;
    
    if (base64Img) {
        img.src = `data:image/png;base64,${base64Img}`;
        img.style.display = 'block';
        if(loading) loading.style.display = 'none';
    } else {
        if(loading) loading.innerText = 'No stability data available.';
    }
}
