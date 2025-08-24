#!/usr/bin/env python3
"""
Digital Twin Honeynet - FastAPI Backend
Main application with dashboard, API endpoints, and system management
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from pathlib import Path
import json

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import asyncio
import json

from log_monitor import LogMonitor
from parser import LogParser
from firewall import FirewallManager
from config import BEHAVIOR_RULES, SYSTEM_CONFIG

# Ensure logs directory exists before configuring logging
Path("logs").mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/fastapi.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Digital Twin Honeynet",
    description="Deception-based cybersecurity system for adversary fingerprinting",
    version="1.0.0"
)

# Initialize components
log_monitor = LogMonitor()
log_parser = LogParser()
firewall_manager = FirewallManager()

# Setup templates
templates = Jinja2Templates(directory="templates")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global state for dashboard
dashboard_stats = {
    'total_requests': 0,
    'blocked_ips': 0,
    'redirected_requests': 0,
    'alerts': 0,
    'system_health': 'healthy',
    'last_update': datetime.now().isoformat()
}

# Store recent events for dashboard
recent_events = []
max_events = 100

# WebSocket connections
websocket_connections = []

# Active SSH sessions
active_sessions = {}

# Threat level tracking
current_threat_level = 'low'

@app.on_event("startup")
async def startup_event():
    """Initialize system on startup"""
    logger.info("Starting Digital Twin Honeynet FastAPI Backend")
    
    # Create necessary directories
    Path("logs").mkdir(exist_ok=True)
    Path("static").mkdir(exist_ok=True)
    
    # Start log monitoring
    await log_monitor.start_monitoring()
    
    # Initialize firewall
    firewall_manager.initialize()
    
    logger.info("System initialized successfully")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Digital Twin Honeynet")
    await log_monitor.stop_monitoring()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    try:
        # Get current statistics
        stats = await get_system_stats()
        
        # Get recent events
        events = recent_events[-20:]  # Last 20 events
        
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "stats": stats,
                "events": events,
                "rules": BEHAVIOR_RULES,
                "config": SYSTEM_CONFIG
            }
        )
    except Exception as e:
        logger.error(f"Error rendering dashboard: {e}")
        raise HTTPException(status_code=500, detail="Dashboard error")

@app.get("/api/status")
async def get_status():
    """Get system status"""
    try:
        stats = await get_system_stats()
        return {
            "status": "running",
            "timestamp": datetime.now().isoformat(),
            "uptime": log_monitor.get_uptime(),
            "stats": stats,
            "health": dashboard_stats['system_health']
        }
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        raise HTTPException(status_code=500, detail="Status error")

@app.get("/api/stats")
async def get_stats():
    """Get detailed statistics"""
    try:
        return await get_system_stats()
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail="Stats error")

@app.get("/api/blocked")
async def get_blocked_ips():
    """Get list of blocked IP addresses"""
    try:
        blocked_ips = firewall_manager.get_blocked_ips()
        return {
            "blocked_ips": blocked_ips,
            "count": len(blocked_ips),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        raise HTTPException(status_code=500, detail="Blocked IPs error")

@app.get("/api/logs")
async def get_logs(limit: int = 50, event_type: str = None):
    """Get recent security logs"""
    try:
        logs = log_parser.get_recent_logs(limit)
        
        if event_type:
            logs = [log for log in logs if log.get('event_type') == event_type]
            
        return {
            "logs": logs,
            "total": len(logs),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        raise HTTPException(status_code=500, detail="Logs error")

@app.post("/api/block")
async def block_ip(request: Request):
    """Block an IP address"""
    try:
        data = await request.json()
        ip_address = data.get('ip')
        reason = data.get('reason', 'Manual block')
        
        if not ip_address:
            raise HTTPException(status_code=400, detail="IP address required")
            
        success = firewall_manager.block_ip(ip_address, reason)
        
        if success:
            # Add to recent events
            add_event('block', ip_address, reason)
            return {"success": True, "message": f"IP {ip_address} blocked"}
        else:
            raise HTTPException(status_code=500, detail="Failed to block IP")
            
    except Exception as e:
        logger.error(f"Error blocking IP: {e}")
        raise HTTPException(status_code=500, detail="Block error")

@app.post("/api/unblock")
async def unblock_ip(request: Request):
    """Unblock an IP address"""
    try:
        data = await request.json()
        ip_address = data.get('ip')
        
        if not ip_address:
            raise HTTPException(status_code=400, detail="IP address required")
            
        success = firewall_manager.unblock_ip(ip_address)
        
        if success:
            add_event('unblock', ip_address, 'Manual unblock')
            return {"success": True, "message": f"IP {ip_address} unblocked"}
        else:
            raise HTTPException(status_code=500, detail="Failed to unblock IP")
            
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}")
        raise HTTPException(status_code=500, detail="Unblock error")

@app.post("/api/logs")
async def receive_log(request: Request):
    """Receive normalized logs from log forwarder"""
    try:
        log_entry = await request.json()
        
        # Add to recent events
        recent_events.append(log_entry)
        
        # Keep only recent events
        if len(recent_events) > max_events:
            recent_events.pop(0)
        
        # Update threat level
        update_threat_level()
        
        # Broadcast to WebSocket clients
        await broadcast_to_websockets({
            'type': 'log_update',
            'log': log_entry,
            'stats': await get_system_stats()
        })
        
        # Check for high threat events and send alerts
        if log_entry.get('threat_score', 0) > 70:
            await broadcast_to_websockets({
                'type': 'attack_alert',
                'alert': {
                    'description': f"High threat activity detected: {log_entry.get('action')}",
                    'source': log_entry.get('source'),
                    'threat_score': log_entry.get('threat_score'),
                    'timestamp': log_entry.get('timestamp')
                }
            })
        
        # Update active sessions if it's an SSH event
        if log_entry.get('source') == 'cowrie_ssh':
            await update_ssh_sessions(log_entry)
        
        return {"success": True, "message": "Log received"}
        
    except Exception as e:
        logger.error(f"Error receiving log: {e}")
        raise HTTPException(status_code=500, detail="Log processing error")

async def update_ssh_sessions(log_entry: dict):
    """Update active SSH sessions"""
    global active_sessions
    
    event_type = log_entry.get('event_type', '')
    session_id = log_entry.get('actor', {}).get('session', '')
    ip_address = log_entry.get('actor', {}).get('ip', '')
    username = log_entry.get('actor', {}).get('username', '')
    
    if event_type == 'cowrie.session.connect':
        active_sessions[session_id] = {
            'ip': ip_address,
            'username': username,
            'start_time': log_entry.get('timestamp'),
            'status': 'active'
        }
    elif event_type == 'cowrie.session.closed':
        if session_id in active_sessions:
            del active_sessions[session_id]
    
    # Broadcast session update
    await broadcast_to_websockets({
        'type': 'session_update',
        'sessions': list(active_sessions.values())
    })
    
    # Broadcast threat level update
    await broadcast_to_websockets({
        'type': 'threat_update',
        'threat_level': current_threat_level
    })

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    websocket_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # Handle incoming messages from log forwarders
            try:
                message = json.loads(data)
                await handle_websocket_message(message)
            except json.JSONDecodeError:
                # Not a JSON message, just keep connection alive
                pass
                
    except WebSocketDisconnect:
        websocket_connections.remove(websocket)

async def handle_websocket_message(message: dict):
    """Handle incoming WebSocket messages"""
    try:
        message_type = message.get('type')
        
        if message_type == 'cowrie_log':
            # Handle Cowrie log message
            log_entry = message.get('log', {})
            
            # Add to recent events
            recent_events.append(log_entry)
            
            # Keep only recent events
            if len(recent_events) > max_events:
                recent_events.pop(0)
            
            # Update threat level
            update_threat_level()
            
            # Update SSH sessions if applicable
            if log_entry.get('source') == 'cowrie_ssh':
                await update_ssh_sessions(log_entry)
            
            # Broadcast to all connected clients
            await broadcast_to_websockets({
                'type': 'cowrie_log_update',
                'log': log_entry,
                'stats': await get_system_stats()
            })
            
            # Check for high threat events
            if log_entry.get('threat_score', 0) > 70:
                await broadcast_to_websockets({
                    'type': 'attack_alert',
                    'alert': {
                        'description': f"High threat Cowrie activity: {log_entry.get('action')}",
                        'source': log_entry.get('source'),
                        'threat_score': log_entry.get('threat_score'),
                        'timestamp': log_entry.get('timestamp'),
                        'ip': log_entry.get('actor', {}).get('ip', 'unknown')
                    }
                })
        
    except Exception as e:
        logger.error(f"Error handling WebSocket message: {e}")

async def broadcast_to_websockets(message: dict):
    """Broadcast message to all connected WebSocket clients"""
    if not websocket_connections:
        return
        
    message_json = json.dumps(message)
    disconnected = []
    
    for websocket in websocket_connections:
        try:
            await websocket.send_text(message_json)
        except:
            disconnected.append(websocket)
    
    # Remove disconnected clients
    for websocket in disconnected:
        websocket_connections.remove(websocket)

def update_threat_level():
    """Update global threat level based on recent events"""
    global current_threat_level
    
    # Calculate threat level based on recent events
    high_threat_events = sum(1 for event in recent_events[-20:] 
                           if event.get('threat_score', 0) > 70)
    
    if high_threat_events >= 3:
        current_threat_level = 'high'
    elif high_threat_events >= 1:
        current_threat_level = 'medium'
    else:
        current_threat_level = 'low'

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

@app.get("/api/config")
async def get_config():
    """Get system configuration"""
    return {
        "behavior_rules": BEHAVIOR_RULES,
        "system_config": SYSTEM_CONFIG,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/config/update")
async def update_config(request: Request):
    """Update system configuration"""
    try:
        data = await request.json()
        
        # Update behavior rules
        if 'behavior_rules' in data:
            BEHAVIOR_RULES.update(data['behavior_rules'])
            
        # Update system config
        if 'system_config' in data:
            SYSTEM_CONFIG.update(data['system_config'])
            
        add_event('config_update', 'system', 'Configuration updated')
        
        return {"success": True, "message": "Configuration updated"}
        
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        raise HTTPException(status_code=500, detail="Config update error")

async def get_system_stats() -> Dict[str, Any]:
    """Get comprehensive system statistics"""
    try:
        # Get basic stats
        stats = dashboard_stats.copy()
        
        # Get firewall stats
        firewall_stats = firewall_manager.get_statistics()
        stats.update(firewall_stats)
        
        # Get parser stats
        parser_stats = log_parser.get_statistics()
        stats.update(parser_stats)
        
        # Get monitor stats
        monitor_stats = log_monitor.get_statistics()
        stats.update(monitor_stats)
        
        # Calculate success rates
        if stats['total_requests'] > 0:
            stats['block_rate'] = (stats['blocked_ips'] / stats['total_requests']) * 100
            stats['redirect_rate'] = (stats['redirected_requests'] / stats['total_requests']) * 100
        else:
            stats['block_rate'] = 0
            stats['redirect_rate'] = 0
            
        return stats
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return dashboard_stats

def add_event(event_type: str, source: str, description: str):
    """Add event to recent events list"""
    event = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'source': source,
        'description': description
    }
    
    recent_events.append(event)
    
    # Keep only recent events
    if len(recent_events) > max_events:
        recent_events.pop(0)
        
    # Update dashboard stats
    dashboard_stats['total_requests'] += 1
    dashboard_stats['last_update'] = datetime.now().isoformat()
    
    if event_type == 'block':
        dashboard_stats['blocked_ips'] += 1
    elif event_type == 'redirect':
        dashboard_stats['redirected_requests'] += 1
    elif event_type == 'alert':
        dashboard_stats['alerts'] += 1

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests"""
    start_time = datetime.now()
    
    response = await call_next(request)
    
    process_time = (datetime.now() - start_time).total_seconds()
    
    logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
    
    return response

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 