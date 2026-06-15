# Firewall Manager Placeholder
# NOTICE: Active blocking operations are deactivated for safety compliance.

import logging

logger = logging.getLogger("FirewallManager")

class FirewallManager:
    def __init__(self):
        logger.info("Firewall Manager initialized (Security Sandbox Mode). Rules modification is disabled.")

    def block_port(self, port: int) -> bool:
        logger.warning(f"SIMULATED PORT BLOCK: {port} [Blocked by Safety Policy]")
        return True

    def reset_rules(self) -> bool:
        logger.info("Firewall rules reset simulated.")
        return True
