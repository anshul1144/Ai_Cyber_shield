# This is the software whic analyse and monitor the realtime cyber threat . 
import os
import yaml
import time
import asyncio
import logging
import threading
# pyrefly: ignore [missing-import]
import uvicorn
from typing import Dict, Any

from core.monitor.network_monitor import NetworkMonitor
from core.monitor.process_monitor import ProcessMonitor
from core.monitor.file_monitor import FileMonitor
from core.monitor.log_monitor import LogMonitor
from core.detection.ai_detector import AIDetector
from dashboard.backend import api_server

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("CentralOrchestrator")

class CentralOrchestrator:
    def __init__(self, settings_path: str = "./config/settings.yaml"):
        self.settings_path = settings_path
        self.config = self._load_config()
        
        # Initialize sub-monitors
        self.network_monitor = NetworkMonitor(self.config)
        self.process_monitor = ProcessMonitor(self.config)
        self.file_monitor = FileMonitor(self.config)
        self.log_monitor = LogMonitor(self.config)
        
        # AI Detector
        model_dir = self.config.get("detection", {}).get("model_dir", "./ai_models/trained_models")
        self.ai_detector = AIDetector(model_dir)
        
        self.running = False
        self.telemetry_loop_thread = None
        self.current_simulation = None

    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.settings_path):
            try:
                with open(self.settings_path, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
        return {}

    def start(self):
        self.running = True
        
        # Start all physical/software monitors
        self.network_monitor.start()
        self.process_monitor.start()
        self.file_monitor.start()
        self.log_monitor.start()
        
        # Start backend telemetry push thread
        self.telemetry_loop_thread = threading.Thread(target=self._telemetry_broadcast_loop, daemon=True)
        self.telemetry_loop_thread.start()
        logger.info("Central Orchestrator monitoring pipelines active.")

    def stop(self):
        self.running = False
        self.network_monitor.stop()
        self.process_monitor.stop()
        self.file_monitor.stop()
        self.log_monitor.stop()
        logger.info("Central Orchestrator monitoring pipelines stopped.")

    def trigger_simulation(self, attack_type: str | None):
        """Triggers system metrics simulation state for testing UI visualization."""
        self.current_simulation = attack_type
        
        # propagate to child monitors to generate characteristics
        self.network_monitor.trigger_simulated_attack(attack_type)
        self.process_monitor.trigger_simulated_attack(attack_type)
        self.file_monitor.trigger_simulated_attack(attack_type)
        self.log_monitor.trigger_simulated_attack(attack_type)
        logger.info(f"Simulation mode set to: {attack_type}")

    def get_telemetry(self) -> Dict[str, Any]:
        """Runs predictions and packages comprehensive real-time status."""
        net_feats = self.network_monitor.get_features()
        proc_feats = self.process_monitor.get_features()
        file_feats = self.file_monitor.get_features()
        log_feats = self.log_monitor.get_features()
        
        # Aggregate threat detection features
        classification_input = {
            "connection_count": net_feats["connection_count"],
            "unique_ips": net_feats["unique_ips"],
            "bytes_sent_rate": net_feats["bytes_sent_rate"],
            "bytes_recv_rate": net_feats["bytes_recv_rate"],
            "failed_login_count": log_feats["failed_login_count"]
        }
        
        anomaly_input = {
            "system_cpu": proc_feats["system_cpu"],
            "system_ram": proc_feats["system_ram"],
            "process_count": proc_feats["process_count"],
            "high_cpu_procs": proc_feats["high_cpu_procs"]
        }
        
        # Perform Inference
        threat_pred = self.ai_detector.analyze_network_and_logs(classification_input)
        anomaly_pred = self.ai_detector.analyze_system_anomalies(anomaly_input)
        
        # Inject custom classification response values if threat simulator is active
        if self.current_simulation:
            # Overwrite classification predictions to match the simulation trigger
            threat_pred = {
                "is_threat": self.current_simulation != "None",
                "attack_type": self.current_simulation,
                "confidence": 0.94,
                "severity_score": 90 if self.current_simulation == "DDoS" else 85
            }
            if self.current_simulation in ["Ransomware", "Zero-day Exploit"]:
                anomaly_pred = {
                    "is_anomaly": True,
                    "anomaly_score": 92.5,
                    "decision_score": -0.25
                }
        
        return {
            "network": self.network_monitor.get_status(),
            "process": self.process_monitor.get_status(),
            "file": self.file_monitor.get_status(),
            "log": self.log_monitor.get_status(),
            "threat": threat_pred,
            "anomaly": anomaly_pred
        }

    def _telemetry_broadcast_loop(self):
        """Asynchronously queries telemetry values and broadcasts to connected Websocket channels."""
        # Create a new event loop inside this daemon thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def broadcast_job():
            while self.running:
                try:
                    telemetry = self.get_telemetry()
                    # Broadcast as JSON string
                    await api_server.manager.broadcast(yaml.dump(telemetry) if False else uvicorn_dumps(telemetry))
                except Exception as e:
                    logger.error(f"Error in telemetry broadcast loop: {e}")
                await asyncio.sleep(1.0)
                
        def uvicorn_dumps(d):
            import json
            return json.dumps(d)

        loop.run_until_complete(broadcast_job())

class UvicornServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        pass

def main():
    logger.info("Initializing AI Cyber Shield Command Hub...")
    orchestrator = CentralOrchestrator()
    orchestrator.start()
    
    # Expose orchestrator reference to HTTP API routes
    api_server.set_orchestrator(orchestrator)
    
    # Retrieve server configuration
    server_cfg = orchestrator.config.get("server", {})
    host = server_cfg.get("host", "127.0.0.1")
    port = server_cfg.get("port", 8000)
    
    # Run Uvicorn in a daemon thread
    def run_server():
        config = uvicorn.Config(api_server.app, host=host, port=port, log_level="warning")
        server = UvicornServer(config)
        server.run()
        
    threading.Thread(target=run_server, daemon=True).start()
    
    # Automatically open local command UI in a native desktop window upon system start
    import webview
    
    try:
        logger.info(f"Starting API and command dashboard on http://{host}:{port}")
        # Give uvicorn server a brief moment to start up
        time.sleep(1.0)
        logger.info("Opening AI Cyber Shield Hub window...")
        webview.create_window("AI Cyber Shield Command Hub", f"http://{host}:{port}", width=1200, height=800)
        webview.start()
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down monitors...")
        orchestrator.stop()

if __name__ == "__main__":
    main()
