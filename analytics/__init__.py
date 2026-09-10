"""Analytics package for the Honeypot Framework.

Currently exposes the attack correlation engine, which links related alerts
across honeypots and time into AttackCampaigns.
"""

from analytics.attack_graph import AttackGraph
from analytics.correlation_engine import (
    Alert,
    AttackCampaign,
    CorrelationEngine,
    load_config,
)

__all__ = [
    "Alert",
    "AttackCampaign",
    "CorrelationEngine",
    "AttackGraph",
    "load_config",
]
