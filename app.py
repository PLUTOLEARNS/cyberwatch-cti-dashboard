"""
Cyber Threat Intelligence Dashboard
Main Flask application file
"""
import logging
from flask import Flask, render_template, request, jsonify
from models.database import init_db, db_session
from models.threat_intel import ThreatIndicator, ThreatReport
from services.virustotal import VirusTotalService
from services.abuseipdb import AbuseIPDBService
from services.data_processor import DataProcessor
from services.threat_feeds import ThreatFeedService
from services.threat_reports import ThreatReportService
from services.realtime_feeds import RealTimeThreatFeeds
import config
from datetime import datetime

logger = logging.getLogger(__name__)
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.config.from_object(config.Config)

# Initialize the database
init_db()

# Initialize services
vt_service = VirusTotalService(config.Config.VIRUSTOTAL_API_KEY)
abuse_service = AbuseIPDBService(config.Config.ABUSEIPDB_API_KEY)
data_processor = DataProcessor()
feed_service = ThreatFeedService(
    otx_api_key=config.Config.ALIENVAULT_API_KEY
)
report_service = ThreatReportService(
    otx_api_key=config.Config.ALIENVAULT_API_KEY
)

# Initialize real-time feeds
realtime_feeds = RealTimeThreatFeeds(app, feed_service, report_service)

# Initialize scheduler for background updates
scheduler = BackgroundScheduler()
def update_feeds_and_emit():
    """Update feeds and emit to real-time clients"""
    feed_service.cache = {}
    feed_service.cache_time = 0
    realtime_feeds.emit_feed_update()

def update_reports_and_emit():
    """Update reports and emit to real-time clients"""
    report_service.cache = {}
    report_service.cache_time = 0
    realtime_feeds.emit_report_update()

scheduler.add_job(func=update_feeds_and_emit, trigger="interval", seconds=config.Config.FEED_REFRESH_INTERVAL)
scheduler.add_job(func=update_reports_and_emit, trigger="interval", seconds=config.Config.FEED_REFRESH_INTERVAL * 2)
scheduler.start()

# Start background monitoring for real-time updates
realtime_feeds.start_background_monitoring()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

# Register custom Jinja2 filters
@app.template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object, ISO string, or timestamp integer to a human-readable form"""
    if value is None:
        return "N/A"
    
    if isinstance(value, int) or isinstance(value, float):
        # Handle Unix timestamp (in seconds)
        try:
            value = datetime.fromtimestamp(value)
        except (ValueError, OverflowError):
            try:
                # Sometimes timestamps might be in milliseconds
                value = datetime.fromtimestamp(value / 1000)
            except (ValueError, OverflowError):
                return f"Invalid timestamp: {value}"
    elif isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            try:
                value = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S')
            except ValueError:
                return value
    
    if not hasattr(value, 'strftime'):
        return str(value)
        
    return value.strftime(format)

@app.route('/')
def index():
    """Render dashboard page with fast initial load"""
    # Quick load with cached counts only
    try:
        feed_count = len(feed_service.cache.get('recent_indicators', [])) if hasattr(feed_service, 'cache') and feed_service.cache else 0
        report_count = len(report_service.cache.get('threat_reports', [])) if hasattr(report_service, 'cache') and report_service.cache else 0
    except:
        feed_count = 0
        report_count = 0
    
    dashboard_data = {
        'feed_count': feed_count,
        'report_count': report_count,
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return render_template('dashboard.html', dashboard=dashboard_data)

@app.route('/lookup', methods=['GET', 'POST'])
def lookup():
    """Handle threat intelligence lookups"""
    indicator = None
    
    # Handle both POST submissions from form and GET requests with indicator parameter
    if request.method == 'POST':
        indicator = request.form.get('indicator')
    elif request.args.get('indicator'):
        indicator = request.args.get('indicator')
    
    if indicator:
        indicator_type = data_processor.detect_indicator_type(indicator)
        
        results = {}
        if indicator_type == 'ip':
            results['virustotal'] = vt_service.check_ip(indicator)
            results['abuseipdb'] = abuse_service.check_ip(indicator)
        elif indicator_type == 'domain':
            results['virustotal'] = vt_service.check_domain(indicator)
        elif indicator_type == 'url':
            results['virustotal'] = vt_service.check_url(indicator)
        elif indicator_type == 'hash':
            results['virustotal'] = vt_service.check_file(indicator)
            
        # Process and store results
        threat_score = data_processor.calculate_threat_score(results)
        data_processor.store_indicator(indicator, indicator_type, threat_score, results)
        
        return render_template('lookup.html', results=results, indicator=indicator, 
                             indicator_type=indicator_type, threat_score=threat_score)
    
    return render_template('lookup.html')

@app.route('/api/dashboard_summary')
def dashboard_summary():
    """Fast dashboard summary without heavy computations"""
    try:
        feed_data = feed_service.get_threat_feeds()
        report_data = report_service.get_threat_reports()
        
        feed_count = sum(source.get('indicators_count', 0) for source in feed_data.get('sources', []))
        report_count = len(report_data.get('threat_reports', []))
        
        return jsonify({
            'feed_count': feed_count,
            'report_count': report_count,
            'last_updated': datetime.now().strftime('%H:%M:%S'),
            'status': 'active'
        })
    except Exception as e:
        logger.error(f"Dashboard summary error: {e}")
        return jsonify({'feed_count': 0, 'report_count': 0, 'status': 'error'})

@app.route('/api/threat_metrics')
def threat_metrics():
    """Return threat metrics for dashboard visualizations"""
    daily_stats = data_processor.get_daily_threat_stats()
    geo_distribution = data_processor.get_geographic_distribution()
    malware_trends = data_processor.get_malware_family_trends()
    timeline = data_processor.get_ioc_timeline()
    
    return jsonify({
        'daily_stats': daily_stats,
        'geo_distribution': geo_distribution,
        'malware_trends': malware_trends,
        'timeline': timeline
    })

@app.route('/feeds')
def feeds():
    """Handle threat feed displays"""
    # Get real-time feed data from our service
    feed_data = feed_service.get_threat_feeds()
    
    return render_template('feeds.html', feeds=feed_data)

@app.route('/api/feeds/refresh', methods=['POST'])
def refresh_feeds():
    """Refresh threat feed data"""
    # Clear the cache to force refresh
    feed_service.cache = {}
    feed_service.cache_time = 0
    
    # Get fresh data
    feed_data = feed_service.get_threat_feeds()
    
    return jsonify({
        'success': True,
        'data': feed_data
    })

@app.route('/reports')
def reports():
    """Handle threat reports"""
    # Get real threat reports from the service
    report_data = report_service.get_threat_reports()    
    return render_template('reports.html', reports=report_data)

@app.route('/api/reports/refresh', methods=['POST'])
def refresh_reports():
    """Refresh threat report data"""
    # Clear the cache to force refresh
    report_service.cache = {}
    report_service.cache_time = 0
    
    # Get fresh data
    report_data = report_service.get_threat_reports()
    
    return jsonify({
        'success': True,
        'data': report_data
    })

@app.route('/api/reports/<report_id>')
def get_report_detail(report_id):
    """Get detailed report information"""
    report_detail = report_service.get_report_detail(report_id)
    return jsonify(report_detail)

@app.teardown_appcontext
def shutdown_session(exception=None):
    """Close the database session at the end of the request"""
    db_session.remove()

if __name__ == '__main__':
    app.run(debug=True)
