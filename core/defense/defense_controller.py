import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional

from core.defense.firewall_manager import FirewallManager
from core.defense.ip_blocker import IPBlocker
from core.defense.network_isolator import NetworkIsolator
from core.defense.process_killer import ProcessKiller

logger = logging.getLogger("DefenseController")


class DefenseController:
    """Turns threat telemetry into scoped, auditable defensive actions."""

    def __init__(self, config: Dict[str, Any]):
        defense_config = config.get("defense", {})
        self.dry_run = defense_config.get("mode", "dry_run") != "active"
        self.max_actions_per_cycle = defense_config.get("max_actions_per_cycle", 5)
        self.block_private_ips = defense_config.get("block_private_ips", False)
        self.high_severity_threshold = defense_config.get("high_severity_threshold", 80)
        self.anomaly_threshold = defense_config.get("anomaly_threshold", 80)
        self.audit_history_limit = defense_config.get("audit_history_limit", 100)

        self.ip_blocker = IPBlocker()
        self.firewall_manager = FirewallManager()
        self.network_isolator = NetworkIsolator()
        self.process_killer = ProcessKiller()
        self.audit_trail: List[Dict[str, Any]] = []

        mode = "dry-run" if self.dry_run else "active"
        logger.info("Defense Controller initialized in %s mode.", mode)

    def defend(
        self,
        threat: Dict[str, Any],
        anomaly: Dict[str, Any],
        telemetry: Dict[str, Any],
    ) -> Dict[str, Any]:
        actions = self._plan_actions(threat, anomaly, telemetry)
        executed_actions = []

        for action in actions[: self.max_actions_per_cycle]:
            executed_actions.append(self._execute_action(action))

        status = "Safe baseline"
        is_mitigating = False
        if executed_actions:
            is_mitigating = True
            status = "ACTIVE MITIGATION IN PROGRESS"
        elif anomaly.get("is_anomaly"):
            is_mitigating = True
            status = "ANOMALY WATCH ACTIVE"

        summary = self._summarize_actions(executed_actions, anomaly)
        return {
            "status": status,
            "action_taken": summary,
            "is_mitigating": is_mitigating,
            "mode": "dry_run" if self.dry_run else "active",
            "actions": executed_actions,
            "audit_trail": list(self.audit_trail[-10:]),
        }

    def _plan_actions(
        self,
        threat: Dict[str, Any],
        anomaly: Dict[str, Any],
        telemetry: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        if not threat.get("is_threat") and not anomaly.get("is_anomaly"):
            return []

        attack = threat.get("attack_type") or "Unknown"
        severity = int(threat.get("severity_score") or 0)
        network = telemetry.get("network", {})
        process = telemetry.get("process", {})
        log = telemetry.get("log", {})

        actions: List[Dict[str, Any]] = []

        if attack in {"DDoS", "DDoS Attack"}:
            actions.append(self._action("rate_limit", "port:80", "Traffic flood pattern detected"))
            actions.extend(self._block_remote_ips(network, "High-volume connection source"))
            if severity >= self.high_severity_threshold:
                actions.append(self._action("block_port", 80, "High severity DDoS safeguard"))

        elif attack == "SQL Injection":
            actions.append(self._action("enable_waf_rule", "sql_injection", "SQL payload signature detected"))
            actions.extend(self._block_remote_ips(network, "SQL injection source"))

        elif attack == "Brute Force":
            actions.append(self._action("auth_rate_limit", "login", "Repeated failed login attempts"))
            actions.extend(self._block_suspicious_log_ips(log, "Brute-force authentication source"))

        elif attack == "Ransomware":
            actions.extend(self._isolate_suspicious_processes(process, ("crypt", "locker", "ransom")))
            actions.append(self._action("freeze_watch_path", "monitored_directory", "Rapid file modification pattern"))

        elif attack == "Zero-day Exploit":
            actions.extend(self._isolate_suspicious_processes(process, ("exploit", "payload")))
            actions.append(self._action("network_isolate", "host", "Potential command-and-control activity"))

        if anomaly.get("is_anomaly") and int(anomaly.get("anomaly_score") or 0) >= self.anomaly_threshold:
            actions.append(self._action("reduce_load", "system", "High anomaly score from process telemetry"))

        return self._dedupe_actions(actions)

    def _execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        action_type = action["type"]
        target = action["target"]
        success = True

        try:
            if action_type == "block_ip":
                success = self.ip_blocker.block_ip(str(target))
            elif action_type == "block_port":
                success = self.firewall_manager.block_port(int(target))
            elif action_type == "kill_process":
                success = self.process_killer.kill_process(int(target))
            elif action_type == "network_isolate":
                success = self.network_isolator.isolate_host()
        except Exception as exc:
            success = False
            action["error"] = str(exc)
            logger.error("Defense action failed: %s", exc)

        record = {
            **action,
            "success": success,
            "mode": "dry_run" if self.dry_run else "active",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.audit_trail.append(record)
        self.audit_trail = self.audit_trail[-self.audit_history_limit :]
        return record

    def _block_remote_ips(self, network: Dict[str, Any], reason: str) -> List[Dict[str, Any]]:
        actions = []
        for conn in network.get("recent_connections", []):
            remote_address = conn.get("remote_address", "")
            ip = remote_address.split(":", 1)[0]
            if self._is_blockable_ip(ip):
                actions.append(self._action("block_ip", ip, reason))
        return actions

    def _block_suspicious_log_ips(self, log: Dict[str, Any], reason: str) -> List[Dict[str, Any]]:
        actions = []
        for entry in log.get("suspicious_entries", []):
            for token in entry.get("message", "").replace("[", " ").replace("]", " ").split():
                token = token.strip(".,;:'\"")
                if self._is_blockable_ip(token):
                    actions.append(self._action("block_ip", token, reason))
        return actions

    def _isolate_suspicious_processes(
        self,
        process: Dict[str, Any],
        name_markers: tuple[str, ...],
    ) -> List[Dict[str, Any]]:
        actions = []
        for proc in process.get("top_processes", []):
            name = (proc.get("name") or "").lower()
            if any(marker in name for marker in name_markers):
                pid = proc.get("pid")
                if isinstance(pid, int) and pid > 0:
                    actions.append(self._action("kill_process", pid, f"Suspicious process: {proc.get('name')}"))
        return actions

    def _is_blockable_ip(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False

        if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return False
        if ip.is_private and not self.block_private_ips:
            return False
        return True

    def _action(self, action_type: str, target: Any, reason: str) -> Dict[str, Any]:
        return {"type": action_type, "target": target, "reason": reason}

    def _dedupe_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped = []
        seen = set()
        for action in actions:
            key = (action["type"], str(action["target"]))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(action)
        return deduped

    def _summarize_actions(
        self,
        actions: List[Dict[str, Any]],
        anomaly: Optional[Dict[str, Any]] = None,
    ) -> str:
        if not actions:
            if anomaly and anomaly.get("is_anomaly"):
                return "Anomaly observed; no destructive mitigation required yet. Telemetry remains under active watch."
            return "Continuous passive threat monitoring active."

        verbs = {
            "auth_rate_limit": "authentication rate limiting",
            "block_ip": "IP quarantine",
            "block_port": "port shielding",
            "enable_waf_rule": "WAF rule activation",
            "freeze_watch_path": "file write freeze",
            "kill_process": "process isolation",
            "network_isolate": "host network isolation",
            "rate_limit": "traffic rate limiting",
            "reduce_load": "system load reduction",
        }
        rendered = [f"{verbs.get(a['type'], a['type'])} for {a['target']}" for a in actions]
        return "; ".join(rendered) + "."
