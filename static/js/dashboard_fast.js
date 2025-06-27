/**
 * Dashboard JavaScript - Optimized for fast loading
 */

document.addEventListener('DOMContentLoaded', function() {
    fetchDashboardSummary();
    setTimeout(fetchThreatMetrics, 500);
    setInterval(() => {
        fetchDashboardSummary();
        fetchThreatMetrics();
    }, 5 * 60 * 1000);
});

function fetchDashboardSummary() {
    fetch('/api/dashboard_summary')
        .then(response => response.json())
        .then(data => updateSummaryCards(data))
        .catch(error => console.error('Dashboard summary error:', error));
}

function fetchThreatMetrics() {
    fetch('/api/threat_metrics')
        .then(response => response.json())
        .then(data => {
            renderThreatTrendsChart(data.daily_stats);
            renderGeoDistributionChart(data.geo_distribution);
            renderMalwareFamiliesChart(data.malware_trends);
            renderIOCTimelineChart(data.timeline);
        })
        .catch(error => console.error('Threat metrics error:', error));
}

function updateSummaryCards(data) {
    if (data.feed_count !== undefined) {
        document.getElementById('total-threats').textContent = data.feed_count + data.report_count;
    }
    if (data.last_updated) {
        const timeElement = document.querySelector('.last-updated');
        if (timeElement) timeElement.textContent = `Last updated: ${data.last_updated}`;
    }
}

function renderThreatTrendsChart(data) {
    if (!data || !data.dates) return;
    
    const ctx = document.getElementById('threatTrendsChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.dates,
            datasets: [{
                label: 'Threats Detected',
                data: data.counts,
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true },
                x: { display: false }
            }
        }
    });
}

function renderGeoDistributionChart(data) {
    if (!data) return;
    
    const ctx = document.getElementById('geoChart');
    if (!ctx) return;

    const countries = Object.keys(data);
    const values = Object.values(data);

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: countries,
            datasets: [{
                data: values,
                backgroundColor: [
                    '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                    '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true } }
        }
    });
}

function renderMalwareFamiliesChart(data) {
    if (!data) return;
    
    const ctx = document.getElementById('malwareChart');
    if (!ctx) return;

    const families = Object.keys(data);
    const counts = Object.values(data);

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: families,
            datasets: [{
                data: counts,
                backgroundColor: [
                    '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                    '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function renderIOCTimelineChart(data) {
    if (!data || !data.dates) return;
    
    const ctx = document.getElementById('iocTimelineChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.dates,
            datasets: [{
                label: 'IPs',
                data: data.ip_counts,
                borderColor: '#FF6384',
                backgroundColor: 'rgba(255, 99, 132, 0.1)'
            }, {
                label: 'Domains',
                data: data.domain_counts,
                borderColor: '#36A2EB',
                backgroundColor: 'rgba(54, 162, 235, 0.1)'
            }, {
                label: 'URLs',
                data: data.url_counts,
                borderColor: '#FFCE56',
                backgroundColor: 'rgba(255, 206, 86, 0.1)'
            }, {
                label: 'Hashes',
                data: data.hash_counts,
                borderColor: '#4BC0C0',
                backgroundColor: 'rgba(75, 192, 192, 0.1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, stacked: true },
                x: { display: false }
            }
        }
    });
}
