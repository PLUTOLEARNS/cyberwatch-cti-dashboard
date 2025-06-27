/**
 * Real-time threat feed WebSocket client
 */

class RealTimeThreatClient {
    constructor() {
        this.socket = null;
        this.connected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 5000; // 5 seconds
        
        this.init();
    }
    
    init() {
        // Only initialize if SocketIO is available
        if (typeof io !== 'undefined') {
            this.socket = io();
            this.setupEventHandlers();
        } else {
            console.warn('Socket.IO not available, real-time updates disabled');
            // Fallback to polling
            this.startPolling();
        }
    }
    
    setupEventHandlers() {
        this.socket.on('connect', () => {
            console.log('Connected to real-time threat feeds');
            this.connected = true;
            this.reconnectAttempts = 0;
            this.showConnectionStatus('Connected', 'success');
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from real-time threat feeds');
            this.connected = false;
            this.showConnectionStatus('Disconnected', 'warning');
            this.attemptReconnect();
        });
        
        this.socket.on('feed_update', (data) => {
            console.log('Received feed update:', data.timestamp);
            this.handleFeedUpdate(data.data);
        });
        
        this.socket.on('report_update', (data) => {
            console.log('Received report update:', data.timestamp);
            this.handleReportUpdate(data.data);
        });
        
        this.socket.on('new_indicator', (data) => {
            console.log('Received new indicator:', data.indicator);
            this.handleNewIndicator(data.indicator, data.timestamp);
        });
        
        this.socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            this.showConnectionStatus('Connection Error', 'danger');
        });
    }
    
    handleFeedUpdate(feedData) {
        // Update feeds page if we're on it
        if (window.location.pathname === '/feeds') {
            this.updateFeedsPage(feedData);
        }
        
        // Update dashboard metrics
        this.updateDashboardMetrics(feedData);
        
        // Show notification
        this.showNotification('Threat feeds updated', 'info');
    }
    
    handleReportUpdate(reportData) {
        // Update reports page if we're on it
        if (window.location.pathname === '/reports') {
            this.updateReportsPage(reportData);
        }
        
        // Show notification
        this.showNotification('Threat reports updated', 'info');
    }
    
    handleNewIndicator(indicator, timestamp) {
        // Show real-time indicator notification
        this.showNewIndicatorNotification(indicator, timestamp);
        
        // Add to feeds table if visible
        this.addIndicatorToTable(indicator);
    }
    
    updateFeedsPage(feedData) {
        try {
            // Update recent indicators table
            if (feedData.recent_indicators && typeof populateIndicatorTable === 'function') {
                populateIndicatorTable(feedData.recent_indicators);
            }
            
            // Update source counts
            if (feedData.sources) {
                const sourceRows = document.querySelectorAll('tbody tr');
                sourceRows.forEach(row => {
                    const sourceName = row.querySelector('strong')?.textContent;
                    const matchingSource = feedData.sources.find(s => s.name === sourceName);
                    if (matchingSource) {
                        // Update indicators count
                        const countCell = row.querySelector('td:nth-child(3)');
                        if (countCell) {
                            countCell.textContent = matchingSource.indicators_count;
                        }
                        
                        // Update last updated
                        const updatedCell = row.querySelector('td:nth-child(2)');
                        if (updatedCell) {
                            updatedCell.textContent = matchingSource.last_updated;
                        }
                    }
                });
            }
        } catch (error) {
            console.error('Error updating feeds page:', error);
        }
    }
    
    updateReportsPage(reportData) {
        try {
            if (window.location.pathname === '/reports' && reportData.threat_reports) {
                // For now, just show a notification that new reports are available
                // A full page refresh might be needed for complex updates
                const refreshBtn = document.querySelector('.refresh-reports-btn');
                if (refreshBtn) {
                    refreshBtn.classList.add('btn-warning');
                    refreshBtn.innerHTML = '<i class="fas fa-exclamation-triangle"></i> New Reports Available';
                    
                    // Reset after 5 seconds
                    setTimeout(() => {
                        refreshBtn.classList.remove('btn-warning');
                        refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
                    }, 5000);
                }
            }
        } catch (error) {
            console.error('Error updating reports page:', error);
        }
    }
    
    updateDashboardMetrics(feedData) {
        try {
            if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
                // Update total threats count
                const totalIndicators = feedData.recent_indicators ? feedData.recent_indicators.length : 0;
                const totalThreatsElement = document.getElementById('total-threats');
                if (totalThreatsElement) {
                    totalThreatsElement.textContent = totalIndicators;
                }
                
                // Update last updated timestamp
                const lastUpdatedElement = document.getElementById('last-updated');
                if (lastUpdatedElement) {
                    lastUpdatedElement.textContent = new Date().toLocaleString();
                }
            }
        } catch (error) {
            console.error('Error updating dashboard metrics:', error);
        }
    }
    
    addIndicatorToTable(indicator) {
        try {
            const tableBody = document.querySelector('#recent-indicators-table tbody');
            if (tableBody) {
                // Create new row
                const row = document.createElement('tr');
                row.className = 'table-warning'; // Highlight new indicators
                
                row.innerHTML = `
                    <td><code>${indicator.value}</code></td>
                    <td>${this.getIndicatorBadge(indicator.type)}</td>
                    <td>${indicator.source}</td>
                    <td>
                        ${indicator.tags.map(tag => `<span class="badge bg-secondary me-1">${tag}</span>`).join('')}
                    </td>
                    <td>
                        <a href="/lookup?indicator=${encodeURIComponent(indicator.value)}" class="btn btn-sm btn-primary">Analyze</a>
                    </td>
                `;
                
                // Insert at the top
                tableBody.insertBefore(row, tableBody.firstChild);
                
                // Remove highlight after 5 seconds
                setTimeout(() => {
                    row.classList.remove('table-warning');
                }, 5000);
                
                // Remove excess rows (keep only top 20)
                const rows = tableBody.querySelectorAll('tr');
                if (rows.length > 20) {
                    for (let i = 20; i < rows.length; i++) {
                        rows[i].remove();
                    }
                }
            }
        } catch (error) {
            console.error('Error adding indicator to table:', error);
        }
    }
    
    getIndicatorBadge(type) {
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
    
    showNewIndicatorNotification(indicator, timestamp) {
        const notification = document.createElement('div');
        notification.className = 'alert alert-info alert-dismissible fade show position-fixed';
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
        
        notification.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas fa-exclamation-circle me-2"></i>
                <div>
                    <strong>New Threat Indicator</strong><br>
                    <small>${indicator.type.toUpperCase()}: <code>${indicator.value}</code></small><br>
                    <small class="text-muted">Source: ${indicator.source}</small>
                </div>
                <button type="button" class="btn-close ms-auto" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 10000);
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; left: 50%; transform: translateX(-50%); z-index: 9999;';
        
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 3000);
    }
    
    showConnectionStatus(status, type) {
        const statusElement = document.getElementById('connection-status');
        if (statusElement) {
            statusElement.className = `badge bg-${type}`;
            statusElement.textContent = status;
        }
    }
    
    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            
            setTimeout(() => {
                if (this.socket) {
                    this.socket.connect();
                }
            }, this.reconnectDelay);
        } else {
            console.log('Max reconnection attempts reached. Falling back to polling.');
            this.startPolling();
        }
    }
    
    startPolling() {
        // Fallback polling mechanism
        setInterval(() => {
            if (window.location.pathname === '/feeds') {
                // Silently refresh feeds data
                fetch('/api/feeds/refresh', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            this.handleFeedUpdate(data.data);
                        }
                    })
                    .catch(console.error);
            }
        }, 30000); // Poll every 30 seconds
    }
    
    requestFeedUpdate() {
        if (this.connected && this.socket) {
            this.socket.emit('request_feed_update');
        } else {
            // Fallback to HTTP request
            fetch('/api/feeds/refresh', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        this.handleFeedUpdate(data.data);
                    }
                })
                .catch(console.error);
        }
    }
    
    requestReportUpdate() {
        if (this.connected && this.socket) {
            this.socket.emit('request_report_update');
        } else {
            // Fallback to HTTP request
            fetch('/api/reports/refresh', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        this.handleReportUpdate(data.data);
                    }
                })
                .catch(console.error);
        }
    }
}

// Initialize real-time client when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize real-time threat client
    window.realTimeClient = new RealTimeThreatClient();
    
    // Add connection status indicator to navbar
    const navbar = document.querySelector('.navbar-nav');
    if (navbar) {
        const statusItem = document.createElement('li');
        statusItem.className = 'nav-item d-flex align-items-center me-3';
        statusItem.innerHTML = '<span id="connection-status" class="badge bg-secondary">Connecting...</span>';
        navbar.appendChild(statusItem);
    }
});
