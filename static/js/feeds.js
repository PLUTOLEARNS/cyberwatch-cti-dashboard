/**
 * Feeds page JavaScript functionality
 */

// Function to initialize charts
function initializeCharts() {
    // Only initialize chart if Canvas element exists and Chart is available
    const feedCategoryElement = document.getElementById('feedCategoryChart');
    
    if (!feedCategoryElement) {
        console.error('Feed category chart element not found');
        return;
    }
    
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded!');
        const chartContainer = document.getElementById('chart-container');
        if (chartContainer) {
            chartContainer.innerHTML = '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> Chart library not loaded. Please refresh the page.</div>';
        }
        return;
    }
    
    // Chart.js is available, proceed with initialization
    try {
        // Create chart with limited animation and simplified options
        const ctxFeedCategory = feedCategoryElement.getContext('2d');
        const feedChart = new Chart(ctxFeedCategory, {
                type: 'doughnut',
                data: {
                    labels: ['Malware', 'Phishing', 'Ransomware', 'APT', 'DDoS'],
                    datasets: [{
                        data: [35, 25, 20, 15, 5],
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.7)',
                            'rgba(54, 162, 235, 0.7)',
                            'rgba(255, 206, 86, 0.7)',
                            'rgba(75, 192, 192, 0.7)',
                            'rgba(153, 102, 255, 0.7)'
                        ],
                        borderColor: [
                            'rgba(255, 99, 132, 1)',
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)',
                            'rgba(153, 102, 255, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: {
                        duration: 500 // Reduce animation duration
                    },
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#e6edf8',
                                boxWidth: 12,
                                padding: 10
                            }
                        }
                    }
                }
            });
        } catch (error) {
            console.error('Failed to initialize feed category chart:', error);
            // Replace the canvas with an error message
            if (feedCategoryElement) {
                const parent = feedCategoryElement.parentNode;
                const errorMsg = document.createElement('div');
                errorMsg.className = 'alert alert-warning';
                errorMsg.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Chart visualization unavailable';
                parent.replaceChild(errorMsg, feedCategoryElement);
            }        }
    }

// Helper function to get badge HTML for indicator type
function getIndicatorBadge(type) {
    switch(type) {
        case 'ip':
            return '<span class="badge bg-danger">IP</span>';
        case 'domain':
            return '<span class="badge bg-warning">Domain</span>';
        case 'url':
            return '<span class="badge bg-info">URL</span>';
        case 'hash':
            return '<span class="badge bg-success">Hash</span>';
        default:
            return '<span class="badge bg-secondary">Other</span>';
    }
}

// Function to refresh feed data from the API
function refreshFeedData() {
    const refreshBtn = document.querySelector('.btn-outline-light');
    if (refreshBtn) {
        // Show loading state
        const originalText = refreshBtn.textContent;
        refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
        refreshBtn.disabled = true;
        
        // Call the refresh API
        fetch('/api/feeds/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update the table with new data
                populateIndicatorTable(data.data.recent_indicators);
                
                // Show success message
                const alertsContainer = document.getElementById('alerts-container') || document.createElement('div');
                alertsContainer.id = 'alerts-container';
                alertsContainer.innerHTML = `
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        <i class="fas fa-check-circle"></i> Feed data refreshed successfully.
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                `;
                
                // Add container to page if it doesn't exist
                if (!document.getElementById('alerts-container')) {
                    const feedsContainer = document.querySelector('.container');
                    feedsContainer.insertBefore(alertsContainer, feedsContainer.firstChild);
                }
                
                // Hide the alert after 4 seconds
                setTimeout(() => {
                    const alert = document.querySelector('.alert');
                    if (alert) {
                        alert.classList.remove('show');
                    }
                }, 4000);
            } else {
                // Show error message
                console.error('Failed to refresh feed data:', data);
                alert('Failed to refresh feed data. See console for details.');
            }
        })
        .catch(error => {
            console.error('Error refreshing feed data:', error);
            alert('Error refreshing feed data. See console for details.');
        })
        .finally(() => {
            // Restore button state
            refreshBtn.innerHTML = originalText;
            refreshBtn.disabled = false;
        });
    }
}

// Update the sources table with new data
function updateSourcesTable(sources) {
    const tbody = document.querySelector('.card-header:contains("Active Threat Feeds")').closest('.card').querySelector('tbody');
    if (!tbody) return;
    
    let html = '';
    sources.forEach(source => {
        html += `
            <tr>
                <td><strong>${source.name}</strong></td>
                <td>${source.last_updated}</td>
                <td>${source.indicators_count}</td>
                <td>${source.description}</td>
                <td>
                    <button class="btn btn-sm btn-primary">View</button>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// Update the indicators table with new data
function updateIndicatorsTable(indicators) {
    const tbody = document.querySelector('.card-header:contains("Recently Detected Indicators")').closest('.card').querySelector('tbody');
    if (!tbody) return;
    
    let html = '';
    indicators.forEach(indicator => {
        const tags = indicator.tags.map(tag => `<span class="badge bg-secondary me-1">${tag}</span>`).join('');
        
        html += `
            <tr>
                <td><code>${indicator.value}</code></td>
                <td>
                    ${getIndicatorBadge(indicator.type)}
                </td>
                <td>${indicator.source}</td>
                <td>${tags}</td>
                <td>
                    <a href="/lookup?indicator=${encodeURIComponent(indicator.value)}" class="btn btn-sm btn-primary">Analyze</a>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// Set up event handlers
function setupEventHandlers() {
    // Add click handler for refresh button
    const refreshBtn = document.querySelector('.btn-outline-light');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function(e) {
            e.preventDefault();
            refreshFeedData();
        });
    }
    
    // Add click handlers for feed source view buttons
    const viewButtons = document.querySelectorAll('td button.btn-primary');
    if (viewButtons) {
        viewButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const sourceName = this.closest('tr').querySelector('strong').textContent;
                showFeedSourceDetails(sourceName);
            });
        });
    }
}

// Function to show feed source details
function showFeedSourceDetails(sourceName) {
    // Get the matching source from the page
    const sourceRow = Array.from(document.querySelectorAll('tbody tr')).find(row => 
        row.querySelector('strong').textContent === sourceName
    );
    
    if (!sourceRow) return;
    
    // Extract source details
    const description = sourceRow.querySelector('td:nth-child(4)').textContent;
    const indicators = sourceRow.querySelector('td:nth-child(3)').textContent;
    const lastUpdated = sourceRow.querySelector('td:nth-child(2)').textContent;
    
    // Create a modal to display the details
    const modalHtml = `
    <div class="modal fade" id="sourceDetailsModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content glass">
                <div class="modal-header">
                    <h5 class="modal-title">${sourceName} Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <h6>Description</h6>
                        <p>${description}</p>
                    </div>
                    <div class="mb-3">
                        <h6>Last Updated</h6>
                        <p>${lastUpdated}</p>
                    </div>
                    <div class="mb-3">
                        <h6>Indicators Count</h6>
                        <p>${indicators}</p>
                    </div>
                    <div class="mb-3">
                        <h6>Recent Indicators from this Source</h6>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>Indicator</th>
                                        <th>Type</th>
                                        <th>Tags</th>
                                    </tr>
                                </thead>
                                <tbody id="sourceIndicatorsTable">
                                    <tr>
                                        <td colspan="3" class="text-center">Loading...</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
                    <a href="/feeds" class="btn btn-primary">View All Feeds</a>
                </div>
            </div>
        </div>
    </div>`;
    
    // Add the modal to the document
    const modalContainer = document.createElement('div');
    modalContainer.innerHTML = modalHtml;
    document.body.appendChild(modalContainer);
    
    // Initialize and show the modal
    const modal = new bootstrap.Modal(document.getElementById('sourceDetailsModal'));
    modal.show();
    
    // Populate source-specific indicators
    const sourceIndicatorsTable = document.getElementById('sourceIndicatorsTable');
    if (sourceIndicatorsTable) {
        // Find indicators from this source
        const allRows = document.querySelectorAll('#recent-indicators-table tbody tr');
        let sourceRows = '';
        
        allRows.forEach(row => {
            const rowSource = row.querySelector('td:nth-child(3)').textContent;
            if (rowSource === sourceName) {
                const indicator = row.querySelector('td:nth-child(1)').innerHTML;
                const type = row.querySelector('td:nth-child(2)').innerHTML;
                const tags = row.querySelector('td:nth-child(4)').innerHTML;
                
                sourceRows += `
                <tr>
                    <td>${indicator}</td>
                    <td>${type}</td>
                    <td>${tags}</td>
                </tr>`;
            }
        });
        
        if (sourceRows) {
            sourceIndicatorsTable.innerHTML = sourceRows;
        } else {
            sourceIndicatorsTable.innerHTML = '<tr><td colspan="3" class="text-center">No indicators found from this source</td></tr>';
        }
    }
    
    // Clean up when the modal is closed
    document.getElementById('sourceDetailsModal').addEventListener('hidden.bs.modal', function () {
        this.remove();
    });
}

// Wait for DOM to fully load and all resources
document.addEventListener('DOMContentLoaded', function() {
    // Wait a short time before initializing charts to ensure proper loading
    setTimeout(() => {
        initializeCharts();
        setupEventHandlers();
    }, 100);
});