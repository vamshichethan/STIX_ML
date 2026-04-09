import json
import logging
import networkx as nx
from typing import Dict, Any, List, Set, Tuple

logger = logging.getLogger(__name__)

class IntelligenceEngine:
    """
    Converts STIX data into a threat graph, performs graph analysis, 
    and generates a decision bundle with threat insights.
    """

    def __init__(self):
        pass

    def _get_node_label(self, obj: Dict[str, Any]) -> str:
        return obj.get("name") or obj.get("value") or obj.get("id", "unknown")

    def analyze_stix_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Process a STIX bundle into a graph and generate intelligence insights."""
        if not isinstance(bundle, dict) or "objects" not in bundle:
            return {"error": "Invalid STIX bundle"}

        objects = bundle.get("objects", [])
        
        # 1. & 2. Node and Edge Extraction
        nodes = []
        edges = []
        node_map = {} 

        # First pass: SDOs (Nodes) & Identify found types
        found_types = set()
        for obj in objects:
            if obj.get("type") == "relationship":
                continue
            
            node = {
                "id": obj["id"],
                "type": obj["type"],
                "label": self._get_node_label(obj)
            }
            nodes.append(node)
            node_map[obj["id"]] = obj
            found_types.add(obj["type"])

        # Second pass: SROs (Edges)
        for obj in objects:
            if obj.get("type") == "relationship":
                source = obj.get("source_ref")
                target = obj.get("target_ref")
                if source in node_map and target in node_map:
                    edges.append({
                        "source": source,
                        "target": target,
                        "relation": obj.get("relationship_type", "related-to")
                    })

        # 3. Graph Construction
        G = nx.DiGraph()
        for node in nodes:
            G.add_node(node["id"], **node)
        for edge in edges:
            G.add_edge(edge["source"], edge["target"], relation=edge["relation"])

        # 4. Graph Analysis & Metrics
        if len(G) == 0:
            return {
                "graph": {"nodes": [], "edges": []},
                "decision_bundle": {
                    "threat_level": "LOW",
                    "confidence": 0.5,
                    "key_entities": [],
                    "attack_chain": [],
                    "anomalies": ["Empty or unconnected data"],
                    "recommended_action": ["Verify input data"]
                }
            }

        degrees = dict(G.degree())
        betweenness = nx.betweenness_centrality(G) if len(G) > 2 else {n: 0 for n in G.nodes()}
        nodes_count = len(G)
        edges_count = len(G.edges())
        
        attack_chains = []
        for node_id in G.nodes():
            if G.nodes[node_id].get("type") == "indicator":
                for succ in G.successors(node_id):
                    if G.nodes[succ].get("type") == "malware":
                        for actor in G.successors(succ):
                            if G.nodes[actor].get("type") in ["threat-actor", "campaign"]:
                                attack_chains.append(f"indicator → malware → {G.nodes[actor].get('type')}")

        num_components = nx.number_weakly_connected_components(G)
        anomalies = []
        isolated = [n for n in G.nodes() if G.degree(n) == 0]
        if isolated:
            anomalies.append(f"Detected {len(isolated)} isolated indicator(s) without linkage")
        if num_components > 1:
            anomalies.append(f"Infrastructure split across {num_components} separate clusters")

        # 5. Advanced Topological Risk Assessment (PROBABILISTIC)
        type_weights = {
            "threat-actor": 45,
            "campaign": 40,
            "malware": 35,
            "vulnerability": 30,
            "infrastructure": 25,
            "attack-pattern": 20,
            "indicator": 15
        }
        
        base_threat_score = sum(type_weights.get(G.nodes[n].get("type"), 10) for n in G.nodes())
        density = nx.density(G) if nodes_count > 1 else 0
        centrality_impact = sum(betweenness.values()) * 100
        
        final_risk_score = base_threat_score + (density * 150) + centrality_impact
        
        # Risk Mapping
        if final_risk_score > 150 or "indicator → malware → threat-actor" in attack_chains:
            threat_level = "CRITICAL" if final_risk_score > 250 else "HIGH"
        elif final_risk_score > 70 or "malware" in found_types:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
            
        # 6. Bayesian Trust Score Calculation
        # Prior adjusted by data presence vs connectivity
        prior = 0.55
        isolation_penalty = (len(isolated) / nodes_count) * 0.4 if nodes_count > 0 else 0
        connectivity_bonus = min(0.35, (edges_count / nodes_count) * 0.2) if nodes_count > 0 else 0
        validation_bonus = 0.1 # Base bonus for valid JSON
        
        confidence = round(max(0.1, min(0.99, prior - isolation_penalty + connectivity_bonus + validation_bonus)), 2)

        # 7. Decision Bundle Generation
        key_entities = []
        sorted_nodes = sorted(G.nodes(), key=lambda n: betweenness.get(n, 0) * 0.7 + degrees.get(n, 0) * 0.3, reverse=True)
        for node_id in sorted_nodes[:3]:
            node_data = G.nodes[node_id]
            key_entities.append({"id": node_id, "type": node_data["type"], "label": node_data["label"]})

        return {
            "graph": {
                "nodes": nodes,
                "edges": edges
            },
            "decision_bundle": {
                "threat_level": threat_level,
                "confidence": confidence,
                "risk_score": round(final_risk_score, 1),
                "key_entities": key_entities,
                "attack_chain": list(set(attack_chains)),
                "anomalies": anomalies,
                "recommended_action": self._generate_recommendations(threat_level, attack_chains)
            }
        }

    def _generate_recommendations(self, level: str, chains: List[str]) -> List[str]:
        recs = []
        if level in ["HIGH", "CRITICAL"]:
            recs.append("Immediate isolation of infected assets and account lockout.")
            recs.append("Deploy active threat hunting signatures for the detected attack chain.")
        elif level == "MEDIUM":
            recs.append("Perform full system scan for associated indicators.")
            recs.append("Restrict network communication for endpoints linked to the malware hub.")
        else:
            recs.append("Maintain baseline monitoring for related TTPs.")
        
        if any("malware" in c for c in chains):
            recs.append("Coordinate with SOC for memory forensics on suspect hosts.")
        return recs
