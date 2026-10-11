"""
Evidence Relationship Graph Engine
Uses NetworkX to model entity-to-entity and entity-to-process relationships.
Renders interactive Plotly visual graphs with memory-safe node limits for 8 GB RAM machines.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from src.normalizer import NormalizedEvent


class EvidenceGraphBuilder:
    def __init__(self, max_nodes: int = 120):
        self.max_nodes = max_nodes
        self.graph = nx.DiGraph()

    def build_graph(self, events: List[NormalizedEvent], focus_entity: Optional[str] = None) -> nx.DiGraph:
        """
        Builds a directed entity graph from normalized events.
        Nodes represent Users, Hosts, and Processes.
        Edges represent evidence-backed interactions.
        """
        self.graph.clear()

        for ev in events:
            # 1. Auth: User -> Host
            if ev.event_type == "AUTH":
                u_node = f"User:{ev.user}" if ev.user else None
                dst_node = f"Host:{ev.dst_host}" if ev.dst_host else None
                src_node = f"Host:{ev.src_host}" if ev.src_host else None

                if u_node:
                    self._add_node(u_node, "User", ev.user)
                if dst_node:
                    self._add_node(dst_node, "Host", ev.dst_host)
                if src_node:
                    self._add_node(src_node, "Host", ev.src_host)

                if u_node and dst_node:
                    self._add_or_update_edge(
                        u_node, dst_node, ev.action, ev.source_file, ev.line_number, ev.timestamp
                    )
                elif src_node and dst_node:
                    self._add_or_update_edge(
                        src_node, dst_node, ev.action, ev.source_file, ev.line_number, ev.timestamp
                    )

            # 2. Process: Host -> Process (or User -> Process)
            elif ev.event_type == "PROCESS":
                h_node = f"Host:{ev.src_host}" if ev.src_host else None
                p_node = f"Proc:{ev.process_name}" if ev.process_name else None
                u_node = f"User:{ev.user}" if ev.user else None

                if p_node:
                    self._add_node(p_node, "Process", ev.process_name)
                if h_node:
                    self._add_node(h_node, "Host", ev.src_host)
                if u_node:
                    self._add_node(u_node, "User", ev.user)

                if h_node and p_node:
                    self._add_or_update_edge(
                        h_node, p_node, ev.action, ev.source_file, ev.line_number, ev.timestamp
                    )

            # 3. Network Flow & DNS: Host -> Host
            elif ev.event_type in ["NETWORK_FLOW", "DNS"]:
                src_node = f"Host:{ev.src_host}" if ev.src_host else None
                dst_node = f"Host:{ev.dst_host}" if ev.dst_host else None
                if src_node:
                    self._add_node(src_node, "Host", ev.src_host)
                if dst_node:
                    self._add_node(dst_node, "Host", ev.dst_host)
                if src_node and dst_node:
                    self._add_or_update_edge(
                        src_node, dst_node, ev.action, ev.source_file, ev.line_number, ev.timestamp
                    )

            # 4. Red team ground truth
            elif ev.event_type == "REDTEAM":
                src_node = f"Host:{ev.src_host}" if ev.src_host else None
                dst_node = f"Host:{ev.dst_host}" if ev.dst_host else None
                u_node = f"User:{ev.user}" if ev.user else None
                if u_node:
                    self._add_node(u_node, "User", ev.user, is_redteam=True)
                if src_node:
                    self._add_node(src_node, "Host", ev.src_host, is_redteam=True)
                if dst_node:
                    self._add_node(dst_node, "Host", ev.dst_host, is_redteam=True)
                if src_node and dst_node:
                    self._add_or_update_edge(
                        src_node, dst_node, "REDTEAM_ATTACK", ev.source_file, ev.line_number, ev.timestamp
                    )

        # Filter if focus entity is given or prune if graph exceeds max_nodes
        if focus_entity:
            matched_nodes = [n for n in self.graph.nodes if focus_entity.lower() in n.lower()]
            if matched_nodes:
                sub_nodes = set(matched_nodes)
                for mn in matched_nodes:
                    sub_nodes.update(self.graph.neighbors(mn))
                    sub_nodes.update(self.graph.predecessors(mn))
                self.graph = self.graph.subgraph(sub_nodes).copy()

        if self.graph.number_of_nodes() > self.max_nodes:
            # Keep top nodes by degree
            sorted_nodes = sorted(self.graph.degree, key=lambda x: x[1], reverse=True)
            top_nodes = [n for n, _ in sorted_nodes[:self.max_nodes]]
            self.graph = self.graph.subgraph(top_nodes).copy()

        return self.graph

    def _add_node(self, node_id: str, node_type: str, label: str, is_redteam: bool = False):
        if not self.graph.has_node(node_id):
            self.graph.add_node(node_id, node_type=node_type, label=label, is_redteam=is_redteam)
        elif is_redteam:
            self.graph.nodes[node_id]["is_redteam"] = True

    def _add_or_update_edge(self, u: str, v: str, action: str, source_file: str, line_no: int, timestamp: int):
        if u == v:
            return  # Skip self-loops for cleaner layout
        if self.graph.has_edge(u, v):
            data = self.graph[u][v]
            data["weight"] += 1
            data["actions"].add(action)
            data["evidence_refs"].append(f"{source_file}:{line_no}")
        else:
            self.graph.add_edge(
                u, v,
                weight=1,
                actions={action},
                evidence_refs=[f"{source_file}:{line_no}"],
                latest_time=timestamp
            )

    def render_plotly(self):
        """Renders the graph into an interactive Plotly figure."""
        import plotly.graph_objects as go
        if self.graph.number_of_nodes() == 0:
            fig = go.Figure()
            fig.update_layout(
                title="Evidence Graph: No entities available to display",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            )
            return fig

        pos = nx.spring_layout(self.graph, k=0.35, iterations=40, seed=42)

        # Edges trace
        edge_x = []
        edge_y = []
        edge_hover = []

        for edge in self.graph.edges(data=True):
            u, v, d = edge
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.5, color="rgba(100, 116, 139, 0.45)"),
            hoverinfo="none",
            mode="lines"
        )

        # Node trace
        node_x = []
        node_y = []
        node_text = []
        node_colors = []
        node_sizes = []

        color_map = {
            "User": "#38bdf8",      # Electric Cyan
            "Host": "#2dd4bf",      # Neon Teal
            "Process": "#c084fc",   # Cyber Purple
        }

        for node in self.graph.nodes(data=True):
            n_id, data = node
            x, y = pos[n_id]
            node_x.append(x)
            node_y.append(y)

            n_type = data.get("node_type", "Entity")
            lbl = data.get("label", n_id)
            is_rt = data.get("is_redteam", False)

            # Degree centrality size
            deg = self.graph.degree(n_id)
            size = min(max(14, 12 + deg * 2), 34)
            node_sizes.append(size)

            if is_rt:
                color = "#f43f5e"  # Neon Rose / Crimson for ground truth
                lbl_tag = f"<b>[CONFIRMED GROUND TRUTH ENTITY]</b><br>"
            else:
                color = color_map.get(n_type, "#94a3b8")
                lbl_tag = ""

            node_colors.append(color)
            node_text.append(
                f"{lbl_tag}Type: <b>{n_type}</b><br>"
                f"Identifier: <b>{lbl}</b><br>"
                f"Degree Connections: <b>{deg}</b>"
            )

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode="markers+text",
            text=[self.graph.nodes[n].get("label", n) for n in self.graph.nodes],
            textposition="top center",
            textfont=dict(size=10, color="#cbd5e1"),
            hoverinfo="text",
            hovertext=node_text,
            marker=dict(
                showscale=False,
                color=node_colors,
                size=node_sizes,
                line_width=2,
                line_color="#0f172a"
            )
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title=dict(
                    text=f"Forensic Entity Relationship Graph ({self.graph.number_of_nodes()} Entities, {self.graph.number_of_edges()} Connections)",
                    font=dict(size=16, color="#38bdf8")
                ),
                showlegend=False,
                hovermode="closest",
                margin=dict(b=20, l=10, r=10, t=40),
                plot_bgcolor="#090d16",
                paper_bgcolor="#090d16",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
        )
        return fig
