import logging
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os
import json
from typing import Dict, Any

logger = logging.getLogger("APIServer")

app = FastAPI(title="AI Cyber Shield Dashboard")

# Active connection manager for websockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

# Global state reference to query data in endpoints
system_orchestrator = None

def set_orchestrator(orchestrator):
    global system_orchestrator
    system_orchestrator = orchestrator

@app.get("/api/status")
def get_status():
    if system_orchestrator:
        return system_orchestrator.get_telemetry()
    return {"status": "offline", "message": "Orchestrator not initialized"}

@app.post("/api/simulate/{attack_type}")
def post_simulate_attack(attack_type: str):
    """Triggers simulated attack features to test training/dashboard validation."""
    if system_orchestrator:
        if attack_type == "None":
            system_orchestrator.trigger_simulation(None)
            return {"status": "success", "message": "Cleared simulation"}
        elif attack_type in ["DDoS", "SQL Injection", "Brute Force", "Ransomware", "Zero-day Exploit"]:
            system_orchestrator.trigger_simulation(attack_type)
            return {"status": "success", "message": f"Injected simulated {attack_type} patterns"}
        return {"status": "error", "message": "Unknown attack simulation type"}
    return {"status": "error", "message": "Orchestrator not initialized"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Keep connection open and receive user command actions
        while True:
            data = await websocket.receive_text()
            cmd = json.loads(data)
            action = cmd.get("action")
            
            if action == "trigger_simulation":
                attack_type = cmd.get("attack_type")
                if system_orchestrator:
                    system_orchestrator.trigger_simulation(attack_type if attack_type != "None" else None)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

# Mount static frontend assets
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
def read_root():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return HTMLResponse(content="<h1>AI Cyber Shield Dashboard Frontend files missing</h1>", status_code=404)
