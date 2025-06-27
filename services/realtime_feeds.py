"""
Real-time threat feed WebSocket implementation
"""
import asyncio
import json
import logging
import time
from datetime import datetime
from flask_socketio import SocketIO, emit
from services.threat_feeds import ThreatFeedService
from services.threat_reports import ThreatReportService

logger = logging.getLogger(__name__)

class RealTimeThreatFeeds:
    """Real-time threat feed handler using WebSockets"""
    
    def __init__(self, app, feed_service, report_service):
        self.app = app
        self.feed_service = feed_service
        self.report_service = report_service
        self.socketio = SocketIO(app, cors_allowed_origins="*")
        self.setup_handlers()
        
    def setup_handlers(self):
        """Setup WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info('Client connected to real-time feeds')
            # Send initial data
            self.emit_feed_update()
            self.emit_report_update()
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info('Client disconnected from real-time feeds')
            
        @self.socketio.on('request_feed_update')
        def handle_feed_update_request():
            logger.info('Client requested feed update')
            # Clear cache to force fresh data
            self.feed_service.cache = {}
            self.feed_service.cache_time = 0
            self.emit_feed_update()
            
        @self.socketio.on('request_report_update')
        def handle_report_update_request():
            logger.info('Client requested report update')
            # Clear cache to force fresh data
            self.report_service.cache = {}
            self.report_service.cache_time = 0
            self.emit_report_update()
    
    def emit_feed_update(self):
        """Emit updated threat feed data to all connected clients"""
        try:
            feed_data = self.feed_service.get_threat_feeds()
            self.socketio.emit('feed_update', {
                'timestamp': datetime.now().isoformat(),
                'data': feed_data
            })
            logger.info('Emitted feed update to clients')
        except Exception as e:
            logger.error(f'Error emitting feed update: {e}')
            
    def emit_report_update(self):
        """Emit updated threat report data to all connected clients"""
        try:
            report_data = self.report_service.get_threat_reports()
            self.socketio.emit('report_update', {
                'timestamp': datetime.now().isoformat(),
                'data': report_data
            })
            logger.info('Emitted report update to clients')
        except Exception as e:
            logger.error(f'Error emitting report update: {e}')
            
    def emit_new_indicator(self, indicator):
        """Emit a new threat indicator to all connected clients"""
        try:
            self.socketio.emit('new_indicator', {
                'timestamp': datetime.now().isoformat(),
                'indicator': indicator
            })
            logger.info(f'Emitted new indicator: {indicator.get("value", "unknown")}')
        except Exception as e:
            logger.error(f'Error emitting new indicator: {e}')
            
    def start_background_monitoring(self):
        """Start background monitoring for new threats"""
        def monitor_feeds():
            while True:
                try:
                    # Check for new indicators every 5 minutes
                    old_data = self.feed_service.cache.copy() if self.feed_service.cache else {}
                    
                    # Clear cache to get fresh data
                    self.feed_service.cache = {}
                    self.feed_service.cache_time = 0
                    
                    new_data = self.feed_service.get_threat_feeds()
                    
                    # Compare with old data to find new indicators
                    if old_data and 'recent_indicators' in old_data:
                        old_indicators = {ind['value'] for ind in old_data['recent_indicators']}
                        new_indicators = [
                            ind for ind in new_data.get('recent_indicators', [])
                            if ind['value'] not in old_indicators
                        ]
                        
                        # Emit new indicators
                        for indicator in new_indicators:
                            self.emit_new_indicator(indicator)
                    
                    # Emit full update
                    self.emit_feed_update()
                    
                    # Sleep for 5 minutes
                    time.sleep(300)
                    
                except Exception as e:
                    logger.error(f'Error in background monitoring: {e}')
                    time.sleep(60)  # Wait 1 minute before retrying
        
        # Start monitoring in background thread
        import threading
        monitor_thread = threading.Thread(target=monitor_feeds, daemon=True)
        monitor_thread.start()
        logger.info('Started background threat monitoring')
