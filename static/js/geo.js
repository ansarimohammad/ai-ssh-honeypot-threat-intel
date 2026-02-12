// Geo Threat Landscape Scripts

Chart.defaults.color = '#e0e0e0';
Chart.defaults.borderColor = '#444';

document.addEventListener('DOMContentLoaded', function() {
    console.log('Geo JS loaded');
    
    // Toggle Logic
    const btnGlobal = document.getElementById('btnGlobal');
    const btnInternal = document.getElementById('btnInternal');
    const globalView = document.getElementById('global-view');
    const internalView = document.getElementById('internal-view');

    if (btnGlobal && btnInternal) {
        btnGlobal.addEventListener('change', () => {
            if(btnGlobal.checked) {
                globalView.style.display = 'block';
                internalView.style.display = 'none';
                // Trigger map resize since it was hidden
                if(window.mapInstance) window.mapInstance.invalidateSize();
            }
        });

        btnInternal.addEventListener('change', () => {
            if(btnInternal.checked) {
                globalView.style.display = 'none';
                internalView.style.display = 'block';
            }
        });
    }

    // Load Data
    fetchGeoData();
});

async function fetchGeoData() {
    try {
        const response = await fetch('/api/geo_data');
        const data = await response.json();
        
        // Public View Data
        renderMap(data.points);
        renderCountryTable(data.country_risk);
        if (data.top_asns) {
            renderAsnChart(data.top_asns);
        }

        // Private View Data
        if (data.internal_stats) {
            renderInternalIpRiskChart(data.internal_stats.top_ips);
            renderInternalRiskDistChart(data.internal_stats.risk_distribution);
            renderInternalActivityChart(data.internal_stats.events_by_ip);
        }
        
    } catch (error) {
        console.error('Error fetching geo data:', error);
    }
}

function renderMap(points) {
    if (!document.getElementById('mapid')) return;
    
    // Check if map already initialized
    if (window.mapInstance) {
        window.mapInstance.remove();
    }
    
    window.mapInstance = L.map('mapid').setView([20, 0], 2);
    
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap &copy; CartoDB',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(window.mapInstance);
    
    points.forEach(p => {
        const color = p.risk_score > 80 ? '#cf6679' : (p.risk_score > 50 ? '#ffc107' : '#03dac6');
        
        L.circleMarker([p.lat, p.lon], {
            radius: 5,
            fillColor: color,
            color: "#000",
            weight: 1,
            opacity: 1,
            fillOpacity: 0.8
        }).addTo(window.mapInstance)
        .bindPopup(`<b>IP:</b> ${p.ip_address}<br><b>Country:</b> ${p.country}<br><b>Risk:</b> ${p.risk_score.toFixed(1)}`);
    });
}

function renderAsnChart(data) {
    const ctx = document.getElementById('asnChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: 'Attack Sessions',
                data: Object.values(data),
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
            plugins: { legend: { display: false } }
        }
    });
}

function renderInternalIpRiskChart(topIps) {
    const ctx = document.getElementById('internalIpRiskChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: topIps.map(i => i.ip),
            datasets: [{
                label: 'Avg Risk Score',
                data: topIps.map(i => i.score),
                backgroundColor: '#cf6679',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { max: 100, grid: { color: '#333' } },
                y: { grid: { display: false } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderInternalRiskDistChart(dist) {
    const ctx = document.getElementById('internalRiskDistChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(dist),
            datasets: [{
                data: Object.values(dist),
                backgroundColor: ['#28a745', '#ffc107', '#dc3545'], // Low, Med, High
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right' }
            }
        }
    });
}

function renderInternalActivityChart(activity) {
    const ctx = document.getElementById('internalActivityChart');
    if (!ctx) return;
    
    const existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(activity),
            datasets: [{
                label: 'Total Events',
                data: Object.values(activity),
                backgroundColor: '#bb86fc',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { grid: { color: '#333' } },
                x: { grid: { display: false } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderCountryTable(data) {
    const tbody = document.querySelector('#countryTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    Object.entries(data).forEach(([country, risk]) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${country}</td><td>${risk.toFixed(1)}</td>`;
        tbody.appendChild(tr);
    });
}
