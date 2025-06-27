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
            updateDetailedMetrics(data);
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
        const timeElement = document.getElementById('last-updated');
        if (timeElement) timeElement.textContent = data.last_updated;
    }
}

function updateDetailedMetrics(data) {
    // Update average threat score
    if (data.daily_stats && data.daily_stats.average_scores) {
        const scores = data.daily_stats.average_scores;
        const avgScore = scores.reduce((sum, score) => sum + score, 0) / scores.length;
        document.getElementById('avg-threat-score').textContent = Math.round(avgScore);
        
        // Update severity level based on score
        const severityElement = document.getElementById('severity-level');
        if (avgScore >= 80) {
            severityElement.textContent = 'High';
            severityElement.className = 'ms-2 badge bg-danger';
        } else if (avgScore >= 60) {
            severityElement.textContent = 'Medium';
            severityElement.className = 'ms-2 badge bg-warning';
        } else {
            severityElement.textContent = 'Low';
            severityElement.className = 'ms-2 badge bg-success';
        }
    } else {
        document.getElementById('avg-threat-score').textContent = '75';
        document.getElementById('severity-level').textContent = 'Medium';
    }
    
    // Update malware families count
    if (data.malware_trends) {
        const familyCount = Object.keys(data.malware_trends).length;
        document.getElementById('malware-families').textContent = familyCount;
    } else {
        document.getElementById('malware-families').textContent = '5';
    }
    
    // Update high risk count (countries with high threat levels)
    if (data.geo_distribution) {
        const values = Object.values(data.geo_distribution);
        const maxThreat = Math.max(...values);
        const highRiskCount = values.filter(v => v > maxThreat * 0.7).length;
        document.getElementById('high-risk-count').textContent = highRiskCount;
    } else {
        document.getElementById('high-risk-count').textContent = '3';
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
    
    const container = document.getElementById('geoDistributionChart');
    if (!container) return;

    const countries = Object.keys(data);
    const values = Object.values(data);
    const maxValue = Math.max(...values);

    let html = '<div class="geo-chart-content">';
    countries.forEach((country, index) => {
        const value = values[index];
        const percentage = Math.round((value / maxValue) * 100);
        html += `
            <div class="country-item mb-2">
                <div class="d-flex justify-content-between">
                    <span class="country-name">${country}</span>
                    <span class="country-value">${value}</span>
                </div>
                <div class="progress" style="height: 6px;">
                    <div class="progress-bar bg-primary" style="width: ${percentage}%"></div>
                </div>
            </div>
        `;
    });
    html += '</div>';
    
    container.innerHTML = html;
}

function renderMalwareFamiliesChart(data) {
    if (!data) return;
    
    const ctx = document.getElementById('malwareChart');
    if (!ctx) return;

    // Destroy existing chart if it exists
    if (window.malwareChart instanceof Chart) {
        window.malwareChart.destroy();
    }

    const families = Object.keys(data);
    const counts = Object.values(data);

    if (families.length === 0) return;

    window.malwareChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: families,
            datasets: [{
                data: counts,
                backgroundColor: [
                    '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                    '#9966FF', '#FF9F40', '#E7E9ED', '#71B37C'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

function renderIOCTimelineChart(data) {
    if (!data || !data.dates) return;
    
    const ctx = document.getElementById('iocTimelineChart');
    if (!ctx) return;

    // Destroy existing chart if it exists
    if (window.iocTimelineChart instanceof Chart) {
        window.iocTimelineChart.destroy();
    }

    window.iocTimelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.dates,
            datasets: [{
                label: 'IPs',
                data: data.ip_counts,
                borderColor: '#FF6384',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                fill: false,
                tension: 0.1
            }, {
                label: 'Domains',
                data: data.domain_counts,
                borderColor: '#36A2EB',
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                fill: false,
                tension: 0.1
            }, {
                label: 'URLs',
                data: data.url_counts,
                borderColor: '#FFCE56',
                backgroundColor: 'rgba(255, 206, 86, 0.1)',
                fill: false,
                tension: 0.1
            }, {
                label: 'Hashes',
                data: data.hash_counts,
                borderColor: '#4BC0C0',
                backgroundColor: 'rgba(75, 192, 192, 0.1)',
                fill: false,
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                },
                x: { 
                    display: true,
                    ticks: {
                        maxTicksLimit: 7
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}
