/**
 * Reports page JavaScript functionality
 */

// Function to initialize dashboard elements
function initializeReportsPage() {
    // Initialize any charts or special UI elements here
    console.log('Reports page initialized');
}

// Function to refresh reports data from the API
function refreshReportsData() {
    const refreshBtn = document.querySelector('.refresh-reports-btn');
    if (refreshBtn) {
        // Show loading state
        const originalText = refreshBtn.textContent;
        refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
        refreshBtn.disabled = true;
        
        // Call the refresh API
        fetch('/api/reports/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Reload the page to display new data
                window.location.reload();
            } else {
                // Show error message
                console.error('Failed to refresh reports data:', data);
                alert('Failed to refresh reports data. See console for details.');
            }
        })
        .catch(error => {
            console.error('Error refreshing reports data:', error);
            alert('Error refreshing reports data. See console for details.');
        })
        .finally(() => {
            // Restore button state
            refreshBtn.innerHTML = originalText;
            refreshBtn.disabled = false;
        });
    }
}

// Function to view report details
function viewReportDetails(reportId, reportTitle, reportDate, reportAuthor, reportSummary, reportSeverity) {
    // Create a modal to display the report details
    const modalHtml = `
    <div class="modal fade" id="reportDetailsModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content glass">
                <div class="modal-header">
                    <h5 class="modal-title">${reportTitle}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <span class="badge rounded-pill bg-${getSeverityClass(reportSeverity)} mb-2">${reportSeverity}</span>
                        <small class="text-muted ms-2">Report ID: ${reportId} | Author: ${reportAuthor} | Date: ${reportDate}</small>
                    </div>
                    <div class="mb-4">
                        <h6>Summary</h6>
                        <p>${reportSummary}</p>
                    </div>
                    <div class="mb-4">
                        <h6>Detailed Analysis</h6>
                        <div id="report-detail-content">
                            <p><i class="fas fa-spinner fa-spin"></i> Loading report details...</p>
                        </div>
                    </div>
                    <div class="mb-3">
                        <h6>Indicators</h6>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>Indicator</th>
                                        <th>Type</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="reportIndicatorsTable">
                                    <tr>
                                        <td colspan="3" class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading indicators...</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-light" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>`;
    
    // Add the modal to the document
    const modalContainer = document.createElement('div');
    modalContainer.innerHTML = modalHtml;
    document.body.appendChild(modalContainer);
    
    // Initialize and show the modal
    const modal = new bootstrap.Modal(document.getElementById('reportDetailsModal'));
    modal.show();
    
    // Fetch additional report details if report ID is provided
    if (reportId) {
        fetch(`/api/reports/${reportId}`)
            .then(response => response.json())
            .then(data => {
                updateReportDetails(data);
            })
            .catch(error => {
                console.error('Error fetching report details:', error);
                document.getElementById('report-detail-content').innerHTML = 
                    '<div class="alert alert-warning">Could not load additional report details. This is a sample report.</div>' +
                    '<p>The full report would include detailed analysis of the threats, affected systems, attack vectors, ' +
                    'and recommendations for mitigation and remediation.</p>';
                
                // Add some sample indicators
                document.getElementById('reportIndicatorsTable').innerHTML = 
                    generateSampleIndicators(reportTitle);
            });
    } else {
        // Handle sample reports without IDs
        document.getElementById('report-detail-content').innerHTML = 
            '<div class="alert alert-warning">This is a sample report without additional details.</div>' +
            '<p>The full report would include detailed analysis of the threats, affected systems, attack vectors, ' +
            'and recommendations for mitigation and remediation.</p>';
        
        // Add some sample indicators
        document.getElementById('reportIndicatorsTable').innerHTML = 
            generateSampleIndicators(reportTitle);
    }
    
    // Clean up when the modal is closed
    document.getElementById('reportDetailsModal').addEventListener('hidden.bs.modal', function () {
        this.remove();
    });
}

// Function to update report details in the modal
function updateReportDetails(data) {
    const detailContentDiv = document.getElementById('report-detail-content');
    const indicatorsTable = document.getElementById('reportIndicatorsTable');
    
    if (data.status === 'error') {
        detailContentDiv.innerHTML = `
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i> ${data.message || 'Error loading report details'}
            </div>
            <p>The full report would include detailed analysis of the threats, affected systems, attack vectors, 
            and recommendations for mitigation and remediation.</p>`;
            
        indicatorsTable.innerHTML = generateSampleIndicators('');
        return;
    }
    
    // Format the detail content
    if (data.description) {
        detailContentDiv.innerHTML = `<p>${data.description}</p>`;
    } else if (data.content) {
        detailContentDiv.innerHTML = `<p>${data.content}</p>`;
    } else {
        detailContentDiv.innerHTML = '<p>No detailed content available for this report.</p>';
    }
    
    // Format indicators if available
    if (data.indicators && data.indicators.length > 0) {
        let indicatorRows = '';
        
        data.indicators.forEach(indicator => {
            indicatorRows += `
            <tr>
                <td><code>${indicator.indicator || indicator.value}</code></td>
                <td><span class="badge bg-${getTypeBadgeClass(indicator.type)}">${indicator.type}</span></td>
                <td>
                    <a href="/lookup?indicator=${encodeURIComponent(indicator.indicator || indicator.value)}" 
                       class="btn btn-sm btn-primary">Analyze</a>
                </td>
            </tr>`;
        });
        
        indicatorsTable.innerHTML = indicatorRows;
    } else {
        indicatorsTable.innerHTML = '<tr><td colspan="3" class="text-center">No indicators available for this report</td></tr>';
    }
}

// Helper function to generate sample indicators based on report title
function generateSampleIndicators(reportTitle) {
    const title = reportTitle.toLowerCase();
    let indicators = [];
    
    // Generate relevant sample indicators based on report title keywords
    if (title.includes('ransomware')) {
        indicators.push({type: 'ip', value: '192.168.213[.]55'});
        indicators.push({type: 'domain', value: 'ransom-payment.secure-link[.]tech'});
        indicators.push({type: 'hash', value: 'a8db687a9b8846e9a179e97295a4d3b1'});
    } else if (title.includes('phishing')) {
        indicators.push({type: 'url', value: 'hxxps://login-secure.bank-verify[.]com/auth'});
        indicators.push({type: 'domain', value: 'bank-verify[.]com'});
    } else if (title.includes('apt') || title.includes('advanced')) {
        indicators.push({type: 'ip', value: '45.77.123[.]18'});
        indicators.push({type: 'hash', value: '9d2bd99fce0bbb41f33d5baf1a4523a8'});
        indicators.push({type: 'domain', value: 'cdn-download.system-update[.]net'});
    } else if (title.includes('trojan') || title.includes('banker')) {
        indicators.push({type: 'hash', value: '5dae415621d60eff1c9e342d20979eab'});
        indicators.push({type: 'url', value: 'hxxp://banking.secure-auth[.]site/inject'});
    } else if (title.includes('ddos')) {
        indicators.push({type: 'ip', value: '103.159.88[.]212'});
        indicators.push({type: 'ip', value: '91.213.50[.]35'});
    } else {
        // Generic indicators
        indicators.push({type: 'ip', value: '185.193.126[.]84'});
        indicators.push({type: 'domain', value: 'secure-updates.tech-cdn[.]org'});
        indicators.push({type: 'hash', value: '8fa1982dea60463fe4e909d8d8d800fe'});
    }
    
    // Generate HTML for indicators
    let indicatorRows = '';
    indicators.forEach(indicator => {
        indicatorRows += `
        <tr>
            <td><code>${indicator.value}</code></td>
            <td><span class="badge bg-${getTypeBadgeClass(indicator.type)}">${indicator.type}</span></td>
            <td>
                <a href="/lookup?indicator=${encodeURIComponent(indicator.value)}" 
                   class="btn btn-sm btn-primary">Analyze</a>
            </td>
        </tr>`;
    });
    
    return indicatorRows;
}

// Get CSS class for indicator type badge
function getTypeBadgeClass(type) {
    switch(type.toLowerCase()) {
        case 'ip': return 'danger';
        case 'domain': return 'warning';
        case 'url': return 'info';
        case 'hash': return 'success';
        default: return 'secondary';
    }
}

// Get CSS class for severity badge
function getSeverityClass(severity) {
    switch(severity) {
        case 'Critical': return 'danger';
        case 'High': return 'warning';
        case 'Medium': return 'info';
        case 'Low': return 'success';
        default: return 'secondary';
    }
}

// Set up event handlers
function setupEventHandlers() {
    // Add click handler for refresh button
    const refreshBtn = document.querySelector('.refresh-reports-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function(e) {
            e.preventDefault();
            refreshReportsData();
        });
    }
    
    // Add click handlers for all View Report buttons
    const viewButtons = document.querySelectorAll('.list-group-item .btn-primary');
    if (viewButtons && viewButtons.length > 0) {
        viewButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Get the parent report container
                const reportItem = this.closest('.list-group-item');
                
                // Extract report data
                const reportTitle = reportItem.querySelector('h5').textContent;
                const reportDate = reportItem.querySelector('small.text-muted').textContent;
                const reportSummary = reportItem.querySelector('p.mb-1').textContent;
                const reportInfo = reportItem.querySelector('div.mt-2 small.text-muted').textContent;
                
                // Parse report ID and author from format "Report ID: XXX | Author: YYY"
                const reportId = reportInfo.split('|')[0].replace('Report ID:', '').trim();
                const reportAuthor = reportInfo.split('|')[1].replace('Author:', '').trim();
                
                const reportSeverity = reportItem.querySelector('.badge').textContent;
                
                // Show report details
                viewReportDetails(reportId, reportTitle, reportDate, reportAuthor, reportSummary, reportSeverity);
            });
        });
    }
}

// Wait for DOM to fully load
document.addEventListener('DOMContentLoaded', function() {
    initializeReportsPage();
    setupEventHandlers();
});
