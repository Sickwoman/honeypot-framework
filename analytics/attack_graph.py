#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Attack Graph
#
# Turns correlated AttackCampaigns into a graph of source IPs, targets, and
# campaigns for visualization. Pure standard library: exports to a plain dict,
# JSON, or Graphviz DOT text. If `networkx` happens to be installed, to_networkx()
# hands back a real graph object, but it is never required.
################################################################################

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackGraph:
    """A lightweight directed graph of the attack landscape."""
    # node id -> {type, label, **attrs}
    nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # list of {source, target, relation, weight}
    edges: List[Dict[str, Any]] = field(default_factory=list)

    # --------------------------------------------------------------------- #
    def add_node(self, node_id: str, node_type: str, label: Optional[str] = None,
                 **attrs: Any) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = {"type": node_type, "label": label or node_id, **attrs}

    def add_edge(self, source: str, target: str, relation: str = "",
                 weight: float = 1.0) -> None:
        self.edges.append({"source": source, "target": target,
                           "relation": relation, "weight": weight})

    # --------------------------------------------------------------------- #
    @classmethod
    def from_campaigns(cls, campaigns: List[Any]) -> "AttackGraph":
        """Build a graph from a list of AttackCampaign objects.

        Layout: source-IP nodes and target/indicator nodes both connect to a
        central campaign node, so shared IPs across campaigns become visible.
        """
        g = cls()
        for c in campaigns:
            cid = f"campaign:{c.id}"
            g.add_node(cid, "campaign", label=c.title,
                       correlation_type=c.correlation_type, severity=c.severity,
                       score=c.score, alert_count=len(c.alert_ids))
            for ip in c.source_ips:
                nid = f"ip:{ip}"
                g.add_node(nid, "source_ip", label=ip)
                g.add_edge(nid, cid, relation=c.correlation_type, weight=c.score or 1.0)

            details = getattr(c, "details", {}) or {}
            targets = details.get("targets") or ([details["service"]]
                                                 if details.get("service") else [])
            for t in targets:
                tid = f"target:{t}"
                g.add_node(tid, "target", label=str(t))
                g.add_edge(cid, tid, relation="targets", weight=1.0)
            if details.get("indicator"):
                iid = f"ioc:{details['indicator']}"
                g.add_node(iid, "indicator", label=str(details["indicator"]))
                g.add_edge(cid, iid, relation="ioc", weight=1.0)
        return g

    # --------------------------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [{"id": nid, **attrs} for nid, attrs in self.nodes.items()],
            "edges": self.edges,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_dot(self) -> str:
        """Render Graphviz DOT (view with `dot -Tpng graph.dot -o graph.png`)."""
        colors = {
            "campaign": "orange", "source_ip": "lightcoral",
            "target": "lightblue", "indicator": "khaki",
        }

        def esc(text: str) -> str:
            return str(text).replace('"', '\\"')

        lines = ["digraph attack_graph {", "  rankdir=LR;",
                 "  node [style=filled,shape=box,fontname=Helvetica];"]
        for nid, attrs in self.nodes.items():
            color = colors.get(attrs.get("type"), "white")
            lines.append(f'  "{esc(nid)}" [label="{esc(attrs.get("label", nid))}",'
                         f' fillcolor={color}];')
        for e in self.edges:
            label = esc(e.get("relation", ""))
            lines.append(f'  "{esc(e["source"])}" -> "{esc(e["target"])}"'
                         f' [label="{label}"];')
        lines.append("}")
        return "\n".join(lines)

    def to_networkx(self):  # pragma: no cover - optional dependency
        """Return a networkx.DiGraph if networkx is installed, else raise."""
        import networkx as nx
        g = nx.DiGraph()
        for nid, attrs in self.nodes.items():
            g.add_node(nid, **attrs)
        for e in self.edges:
            g.add_edge(e["source"], e["target"],
                       relation=e["relation"], weight=e["weight"])
        return g

    def __len__(self) -> int:
        return len(self.nodes)
