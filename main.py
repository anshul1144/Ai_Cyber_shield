# This is the software whic analyse and monitor the realtime cyber threat . 
import os
import yaml
import time
import asyncio
import logging
import threading
from pathlib import Path
# pyrefly: ignore [missing-import]
import uvicorn
from typing import Dict, Any

from core.monitor.network_monitor import NetworkMonitor
from core.monitor.process_monitor import ProcessMonitor
from core.monitor.file_monitor import FileMonitor
from core.monitor.log_monitor import LogMonitor
from core.detection.ai_detector import AIDetector
from core.protection import ProtectionController
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

        # Protection controller forecasts developing attacks and protects critical data.
        self.protection_controller = ProtectionController(self.config)
        
        self.running = False
        self.telemetry_loop_thread = None
        self.current_simulation = None

    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.settings_path):
            try:
                with open(self.settings_path, 'r') as f:
                    raw_config = yaml.safe_load(f) or {}
                    monitor_config = raw_config.get("monitors", {})
                    # Keep legacy top-level monitor keys available to existing classes.
                    for key in ("network", "process", "file", "log"):
                        raw_config.setdefault(key, monitor_config.get(key, {}))
                    return raw_config
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
        if not attack_type or attack_type == "None":
            self.protection_controller.prevention_failed = False
            if self.protection_controller.data_isolator.is_active:
                self.protection_controller.data_isolator.restore_files()
        
        self._ensure_simulation_snapshot_source(attack_type)
        
        # propagate to child monitors to generate characteristics
        self.network_monitor.trigger_simulated_attack(attack_type)
        self.process_monitor.trigger_simulated_attack(attack_type)
        self.file_monitor.trigger_simulated_attack(attack_type)
        self.log_monitor.trigger_simulated_attack(attack_type)
        logger.info(f"Simulation mode set to: {attack_type}")

    def set_prevention_failure(self, failed: bool):
        """Sets simulated prevention failure state."""
        self.protection_controller.prevention_failed = failed
        logger.info(f"Prevention failure state set to: {failed}")

    def get_telemetry(self) -> Dict[str, Any]:
        """Runs predictions and packages comprehensive real-time status."""
        net_feats = self.network_monitor.get_features()
        proc_feats = self.process_monitor.get_features()
        file_feats = self.file_monitor.get_features()
        log_feats = self.log_monitor.get_features()
        self._apply_simulated_protection_features(net_feats, proc_feats, file_feats, log_feats)
        
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
                "severity_score": 90 if self.current_simulation == "DDoS" else 85,
                "simulated_attack": True,
            }
            if self.current_simulation in ["Ransomware", "Zero-day Exploit"]:
                anomaly_pred = {
                    "is_anomaly": True,
                    "anomaly_score": 92.5,
                    "decision_score": -0.25
                }

        process_status = self.process_monitor.get_status()
        file_status = self.file_monitor.get_status()
        self._apply_simulated_status(process_status, file_status)

        protection_status = self.protection_controller.evaluate(
            classification_input,
            anomaly_input,
            file_feats,
            log_feats,
            threat_pred,
            anomaly_pred,
            process_status,
            self.network_monitor.get_status(),
        )
        
        return {
            "network": self.network_monitor.get_status(),
            "process": process_status,
            "file": file_status,
            "log": self.log_monitor.get_status(),
            "threat": threat_pred,
            "anomaly": anomaly_pred,
            "protection": protection_status
        }

    def _apply_simulated_protection_features(
        self,
        net_feats: Dict[str, Any],
        proc_feats: Dict[str, Any],
        file_feats: Dict[str, Any],
        log_feats: Dict[str, Any],
    ):
        """Make simulator inputs deterministic for forecasting and protection."""
        if self.current_simulation == "DDoS":
            net_feats["connection_count"] = max(net_feats.get("connection_count", 0), 850)
            net_feats["unique_ips"] = max(net_feats.get("unique_ips", 0), 360)
            net_feats["bytes_recv_rate"] = max(net_feats.get("bytes_recv_rate", 0), 5_000_000.0)
        elif self.current_simulation == "SQL Injection":
            net_feats["connection_count"] = max(net_feats.get("connection_count", 0), 180)
            log_feats["failed_login_count"] = max(log_feats.get("failed_login_count", 0), 8)
        elif self.current_simulation == "Brute Force":
            log_feats["failed_login_count"] = max(log_feats.get("failed_login_count", 0), 40)
        elif self.current_simulation == "Ransomware":
            file_feats["file_modification_rate"] = max(file_feats.get("file_modification_rate", 0), 145)
            proc_feats["system_cpu"] = max(proc_feats.get("system_cpu", 0), 92.5)
            proc_feats["system_ram"] = max(proc_feats.get("system_ram", 0), 84.0)
            proc_feats["high_cpu_procs"] = max(proc_feats.get("high_cpu_procs", 0), 2)
        elif self.current_simulation == "Zero-day Exploit":
            proc_feats["system_cpu"] = max(proc_feats.get("system_cpu", 0), 78.0)
            proc_feats["system_ram"] = max(proc_feats.get("system_ram", 0), 96.0)
            proc_feats["high_cpu_procs"] = max(proc_feats.get("high_cpu_procs", 0), 1)

    def _ensure_simulation_snapshot_source(self, attack_type: str | None):
        """Seed harmless critical data so simulator snapshots are visible."""
        if not attack_type or attack_type == "None":
            return

        scanner = self.protection_controller.backup_manager.scanner
        if scanner.find_critical_files():
            return

        extension = ".txt" if ".txt" in scanner.critical_extensions else sorted(scanner.critical_extensions)[0]
        for raw_path in scanner.critical_paths:
            try:
                base_path = Path(raw_path).expanduser().resolve()
                if base_path.suffix.lower() in scanner.critical_extensions:
                    target = base_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                else:
                    base_path.mkdir(parents=True, exist_ok=True)
                    target = base_path / f"simulated_critical_data{extension}"

                if not target.exists():
                    target.write_text(
                        "AI Cyber Shield simulator demo data.\n"
                        f"Created so the {attack_type} simulation can record a visible protection snapshot.\n",
                        encoding="utf-8",
                    )
                logger.info("Seeded simulator snapshot source: %s", target)
                return
            except OSError as exc:
                logger.warning("Unable to seed simulator snapshot source at %s: %s", raw_path, exc)

    def _apply_simulated_status(self, process_status: Dict[str, Any], file_status: Dict[str, Any]):
        """Keep dashboard status aligned with simulator features."""
        if self.current_simulation == "Ransomware":
            file_status["modification_rate"] = max(file_status.get("modification_rate", 0), 145)
            if not file_status.get("event_history"):
                file_status["event_history"] = []
            if not file_status["event_history"] or file_status["event_history"][0].get("filename") != "critical_data.docx.locked":
                file_status["event_history"].insert(0, {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "type": "MODIFIED",
                    "filename": "critical_data.docx.locked",
                    "path": os.path.join(self.file_monitor.watch_path, "critical_data.docx.locked")
                })
            process_status["system_cpu"] = max(process_status.get("system_cpu", 0), 92.5)
            process_status["system_ram"] = max(process_status.get("system_ram", 0), 84.0)
        elif self.current_simulation == "Zero-day Exploit":
            process_status["system_ram"] = max(process_status.get("system_ram", 0), 96.0)

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
    import argparse
    parser = argparse.ArgumentParser(description="AI Cyber Shield Command Hub")
    parser.add_argument("--headless", action="store_true", help="Run without native desktop GUI window")
    args = parser.parse_args()

    logger.info("Initializing AI Cyber Shield Command Hub...")
    orchestrator = CentralOrchestrator()
    orchestrator.start()
    
    # Expose orchestrator reference to HTTP API routes
    api_server.set_orchestrator(orchestrator)
    
    # Retrieve server configuration
    server_cfg = orchestrator.config.get("server", {})
    host = server_cfg.get("host", "127.0.0.1")
    port = server_cfg.get("port", 8000)
    
    headless_mode = args.headless or bool(os.environ.get("HEADLESS"))
    gui_failed = False

    if not headless_mode:
        try:
            import webview
            
            # Run Uvicorn in a daemon thread
            def run_server():
                config = uvicorn.Config(api_server.app, host=host, port=port, log_level="warning")
                server = UvicornServer(config)
                server.run()
                
            threading.Thread(target=run_server, daemon=True).start()
            
            logger.info(f"Starting API and command dashboard on http://{host}:{port}")
            # Give uvicorn server a brief moment to start up
            time.sleep(1.0)
            logger.info("Opening AI Cyber Shield Hub window...")
            webview.create_window("AI Cyber Shield Command Hub", f"http://{host}:{port}", width=1200, height=800)
            webview.start()
        except Exception as exc:
            logger.warning(f"Failed to start GUI interface: {exc}. Falling back to headless mode.")
            gui_failed = True

    if headless_mode or gui_failed:
        logger.info(f"Running in HEADLESS mode. Starting API and command dashboard on http://{host}:{port}")
        try:
            config = uvicorn.Config(api_server.app, host=host, port=port, log_level="warning")
            server = UvicornServer(config)
            server.run()
        except KeyboardInterrupt:
            pass
        finally:
            logger.info("Shutting down monitors...")
            orchestrator.stop()

if __name__ == "__main__":
    main()
