#!/usr/bin/env python3
"""Generate a multi-page draw.io model from burp_recon_summary.py output.

The resulting file contains four editable pages:

* observed/discovered site flow;
* architecture by host, role, service, edge, and external dependency;
* detected technologies and recon findings;
* endpoint map grouped by host and functional service.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


PALETTE = {
    "client": ("#d5e8d4", "#82b366"),
    "edge": ("#dae8fc", "#6c8ebf"),
    "frontend": ("#fff2cc", "#d6b656"),
    "auth": ("#e1d5e7", "#9673a6"),
    "api": ("#f8cecc", "#b85450"),
    "backend": ("#f5f5f5", "#666666"),
    "external": ("#ffe6cc", "#d79b00"),
    "risk": ("#f8cecc", "#b85450"),
    "configuration": ("#d0cee2", "#56517e"),
    "neutral": ("#ffffff", "#666666"),
    "title": ("#1f2937", "#111827"),
}

CATEGORY_KIND = {
    "page": "frontend",
    "static": "frontend",
    "auth": "auth",
    "api": "api",
    "graphql": "api",
    "api-docs": "api",
    "state-changing": "risk",
    "admin": "risk",
    "configuration": "configuration",
    "other": "neutral",
}

RELATION_LABELS = {
    "redirect": "redirect HTTP",
    "oauth-callback": "callback OAuth",
    "form-submit": "envio de formulario",
    "origin-request": "chamada cross-origin",
    "referer": "requisicao observada",
    "html-link": "link descoberto",
}

RELATION_PRIORITY = {
    "redirect": 100,
    "form-submit": 95,
    "oauth-callback": 92,
    "origin-request": 88,
    "referer": 70,
    "html-link": 25,
}

STATIC_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:cdn-cgi|static|assets|storage/app/media)(?:/|$)|"
    r"\.(?:js|css|map|svg|png|jpe?g|gif|webp|ico|woff2?|ttf)(?:\?|$)"
)
AUTH_PATH_RE = re.compile(r"(?i)(oauth|oidc|saml|login|logout|auth|commonauth|authenticationendpoint|token|jwks|callback)")
API_PATH_RE = re.compile(r"(?i)(?:^|/)(?:api(?:-s)?|graphql|rest)(?:/|$)|/v\d+(?:/|$)")


class DiagramBuilder:
    def __init__(self) -> None:
        self.cells: list[str] = []
        self.edges: list[str] = []
        self.sequence = 1

    def _style(self, kind: str, shape: str, align: str = "center") -> str:
        fill, stroke = PALETTE.get(kind, PALETTE["neutral"])
        font_color = "#ffffff" if kind == "title" else "#111827"
        return (
            f"{shape};whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};"
            f"fontColor={font_color};fontSize=12;align={align};verticalAlign=middle;spacing=8;"
        )

    def node(
        self,
        value: str,
        x: int,
        y: int,
        width: int = 220,
        height: int = 80,
        kind: str = "neutral",
        shape: str = "rounded=1",
        align: str = "center",
    ) -> str:
        cell_id = f"n{self.sequence}"
        self.sequence += 1
        safe_value = html.escape(value).replace("\n", "&lt;br&gt;")
        self.cells.append(
            f'<mxCell id="{cell_id}" value="{safe_value}" style="{self._style(kind, shape, align)}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{width}" height="{height}" as="geometry" />'
            "</mxCell>"
        )
        return cell_id

    def edge(self, source: str, target: str, label: str = "", dashed: bool = False, color: str = "#666666") -> None:
        edge_id = f"e{self.sequence}"
        self.sequence += 1
        safe_label = html.escape(label)
        dash = "dashed=1;" if dashed else ""
        self.edges.append(
            f'<mxCell id="{edge_id}" value="{safe_label}" edge="1" parent="1" source="{source}" target="{target}" '
            f'style="endArrow=block;html=1;rounded=1;orthogonalLoop=1;jettySize=auto;strokeColor={color};{dash}">'
            '<mxGeometry relative="1" as="geometry" />'
            "</mxCell>"
        )

    def diagram(self, name: str, width: int = 1900, height: int = 1200) -> str:
        diagram_id = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-") or "diagram"
        body = "\n".join(self.cells + self.edges)
        return f"""  <diagram id="{html.escape(diagram_id)}" name="{html.escape(name)}">
    <mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="{width}" pageHeight="{height}" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
{body}
      </root>
    </mxGraphModel>
  </diagram>"""


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def trim(value: str, maximum: int = 64) -> str:
    value = value or "/"
    if len(value) <= maximum:
        return value
    path = urlsplit(value).path or value
    return path[: maximum - 3] + "..."


def box_text(title: str, lines: Iterable[str], maximum_lines: int = 10) -> str:
    all_lines = [line for line in lines if line]
    selected = all_lines[:maximum_lines]
    remaining = len(all_lines) - len(selected)
    if remaining > 0:
        selected.append(f"+{remaining} outros")
    return title + ("\n" + "\n".join(selected) if selected else "")


def endpoint_kind(row: dict[str, str]) -> str:
    return CATEGORY_KIND.get(row.get("category") or (row.get("notes") or "").split(";")[0], "neutral")


def flow_node_kind(host: str, path: str, known_hosts: dict[str, dict[str, str]], endpoint_lookup: dict[tuple[str, str], dict[str, str]]) -> str:
    endpoint = endpoint_lookup.get((host, path))
    if endpoint:
        return endpoint_kind(endpoint)
    roles = (known_hosts.get(host, {}).get("roles") or "").lower()
    if AUTH_PATH_RE.search(path) or "identity-provider" in roles:
        return "auth"
    if API_PATH_RE.search(path):
        return "api"
    if host not in known_hosts:
        return "external"
    return "frontend"


def flow_score(row: dict[str, str], known_hosts: set[str]) -> int:
    relation = row.get("relation", "")
    source_path = row.get("source_path", "")
    target_path = row.get("target_path", "")
    score = RELATION_PRIORITY.get(relation, 10)
    if row.get("observed") == "yes":
        score += 8
    if AUTH_PATH_RE.search(source_path + " " + target_path):
        score += 18
    if API_PATH_RE.search(target_path):
        score += 12
    if STATIC_PATH_RE.search(source_path) or STATIC_PATH_RE.search(target_path):
        score -= 120
    if relation == "html-link" and row.get("target_host") not in known_hosts:
        score -= 15
    return score


def select_flows(flows: list[dict[str, str]], known_hosts: set[str], max_nodes: int) -> list[dict[str, str]]:
    ranked = sorted(flows, key=lambda row: (-flow_score(row, known_hosts), row.get("source_host", ""), row.get("source_path", "")))
    selected_nodes: set[tuple[str, str]] = set()
    selected: list[dict[str, str]] = []
    deferred: list[dict[str, str]] = []
    for row in ranked:
        if flow_score(row, known_hosts) < 0:
            continue
        source = (row.get("source_host", ""), row.get("source_path", "/"))
        target = (row.get("target_host", ""), row.get("target_path", "/"))
        new_nodes = len({source, target} - selected_nodes)
        if len(selected_nodes) + new_nodes <= max_nodes:
            selected_nodes.update((source, target))
            selected.append(row)
        else:
            deferred.append(row)
    for row in deferred:
        source = (row.get("source_host", ""), row.get("source_path", "/"))
        target = (row.get("target_host", ""), row.get("target_path", "/"))
        if source in selected_nodes and target in selected_nodes:
            selected.append(row)
    return selected


def build_flow(
    project_name: str,
    endpoints: list[dict[str, str]],
    hosts: list[dict[str, str]],
    flows: list[dict[str, str]],
    max_nodes: int,
) -> str:
    builder = DiagramBuilder()
    known_hosts = {row.get("host", ""): row for row in hosts if row.get("host")}
    endpoint_lookup = {(row.get("host", ""), row.get("path", "/")): row for row in endpoints}
    selected = select_flows(flows, set(known_hosts), max_nodes)

    builder.node(f"Fluxo observado — {project_name}", 40, 20, 1740, 50, "title")
    lane_x = {"external": 60, "frontend": 480, "auth": 900, "api": 1320, "configuration": 480, "risk": 1320, "neutral": 480}
    lane_titles = {
        "external": "Origem / externo",
        "frontend": "Site / frontend",
        "auth": "Autenticacao",
        "api": "APIs / dados",
    }
    for kind, label in lane_titles.items():
        builder.node(label, lane_x[kind], 90, 340, 38, kind)

    node_keys: set[tuple[str, str]] = set()
    for row in selected:
        node_keys.add((row.get("source_host", ""), row.get("source_path", "/")))
        node_keys.add((row.get("target_host", ""), row.get("target_path", "/")))
    if not node_keys:
        for endpoint in endpoints[:max_nodes]:
            node_keys.add((endpoint.get("host", ""), endpoint.get("path", "/")))

    lane_counts: Counter[str] = Counter()
    node_ids: dict[tuple[str, str], str] = {}
    sorted_nodes = sorted(node_keys, key=lambda item: (flow_node_kind(item[0], item[1], known_hosts, endpoint_lookup), item[0], item[1]))
    for host, path in sorted_nodes:
        kind = flow_node_kind(host, path, known_hosts, endpoint_lookup)
        lane = kind if kind in lane_x else "frontend"
        y = 150 + lane_counts[lane] * 105
        lane_counts[lane] += 1
        endpoint = endpoint_lookup.get((host, path), {})
        method = endpoint.get("method", "")
        status = endpoint.get("status", "")
        details = " ".join(value for value in (method, trim(path, 52), f"[{status}]" if status else "") if value)
        node_ids[(host, path)] = builder.node(f"{host}\n{details}", lane_x[lane], y, 340, 78, kind, align="left")

    edge_seen: set[tuple[str, str, str]] = set()
    for row in selected:
        source_key = (row.get("source_host", ""), row.get("source_path", "/"))
        target_key = (row.get("target_host", ""), row.get("target_path", "/"))
        if source_key not in node_ids or target_key not in node_ids:
            continue
        relation = row.get("relation", "")
        edge_key = (node_ids[source_key], node_ids[target_key], relation)
        if edge_key in edge_seen:
            continue
        edge_seen.add(edge_key)
        label = RELATION_LABELS.get(relation, relation)
        count = integer(row.get("count"), 1)
        if count > 1:
            label += f" x{count}"
        dashed = row.get("observed") != "yes" or relation in {"html-link", "oauth-callback", "form-submit"}
        builder.edge(node_ids[source_key], node_ids[target_key], label, dashed=dashed)

    legend = [
        "Linha continua: relacao observada no trafego",
        "Linha tracejada: relacao inferida/descoberta no HTML",
        f"Nos exibidos: {len(node_ids)} de no maximo {max_nodes}",
    ]
    builder.node(box_text("Legenda", legend), 1400, 90 + max(lane_counts.values(), default=1) * 105, 360, 105, "neutral", align="left")
    height = max(900, 330 + max(lane_counts.values(), default=1) * 105)
    return builder.diagram("Fluxo do Site", 1850, height)


def host_technology_lines(host: str, technologies: list[dict[str, str]], limit: int = 6) -> list[str]:
    rows = []
    for row in technologies:
        technology_hosts = {value.strip() for value in (row.get("hosts") or "").split(",") if value.strip()}
        if host in technology_hosts:
            version = f" {row.get('versions')}" if row.get("versions") else ""
            rows.append(f"{row.get('technology')}{version}")
    return rows[:limit]


def build_architecture(
    project_name: str,
    summary: dict[str, Any],
    hosts: list[dict[str, str]],
    services: list[dict[str, str]],
    technologies: list[dict[str, str]],
    third_party: list[dict[str, str]],
    configurations: list[dict[str, str]],
    flows: list[dict[str, str]],
) -> str:
    builder = DiagramBuilder()
    builder.node(f"Arquitetura inferida do trafego — {project_name}", 40, 20, 1740, 50, "title")

    user = builder.node("Usuario / Browser\nDesktop ou mobile", 40, 210, 210, 90, "client", "ellipse")
    edge_names = [row.get("technology", "") for row in technologies if row.get("category") == "Edge/CDN"]
    edge = builder.node(box_text("Borda observada", edge_names or ["CDN / WAF / Load Balancer"], 8), 300, 185, 240, 140, "edge")
    builder.edge(user, edge, "HTTPS")

    services_by_host: dict[str, list[dict[str, str]]] = defaultdict(list)
    for service in services:
        services_by_host[service.get("host", "")].append(service)

    host_nodes: dict[str, str] = {}
    service_nodes: dict[str, str] = {}
    host_gap = 230
    for index, host_row in enumerate(hosts):
        host = host_row.get("host", "host")
        y = 90 + index * host_gap
        roles = host_row.get("roles") or "web-service"
        tech_lines = host_technology_lines(host, technologies)
        host_label = box_text(host, [f"Papeis: {roles}", *tech_lines], 8)
        kind = "auth" if "identity-provider" in roles else ("api" if roles == "api/gateway" else "frontend")
        host_nodes[host] = builder.node(host_label, 610, y, 310, 160, kind, align="left")
        builder.edge(edge, host_nodes[host], "trafego observado")

        host_services = sorted(services_by_host.get(host, []), key=lambda row: (row.get("category", ""), row.get("service", "")))
        service_lines = [
            f"{row.get('service')} — {row.get('prefix')} ({row.get('endpoint_count')} endpoints{', auth' if row.get('auth') == 'yes' else ''})"
            for row in host_services
        ]
        service_kind = "auth" if any(row.get("category") == "auth" for row in host_services) else "api"
        service_nodes[host] = builder.node(box_text("Componentes / servicos", service_lines, 9), 1000, y, 350, 160, service_kind, align="left")
        builder.edge(host_nodes[host], service_nodes[host], "roteia / entrega")

    cross_host_relations: dict[tuple[str, str], set[str]] = defaultdict(set)
    for flow in flows:
        source_host = flow.get("source_host", "")
        target_host = flow.get("target_host", "")
        if source_host in host_nodes and target_host in host_nodes and source_host != target_host:
            cross_host_relations[(source_host, target_host)].add(flow.get("relation", ""))
    for (source_host, target_host), relations in cross_host_relations.items():
        labels = [RELATION_LABELS.get(relation, relation) for relation in sorted(relations)]
        builder.edge(host_nodes[source_host], host_nodes[target_host], ", ".join(labels[:3]), dashed=True, color="#9673a6")

    referenced_hosts: Counter[str] = Counter()
    for row in third_party:
        referenced_hosts[row.get("host", "")] += integer(row.get("count"), 1)
    config_only_hosts: set[str] = set()
    for row in configurations:
        config_only_hosts.update(value.strip() for value in (row.get("referenced_hosts") or "").split(",") if value.strip())
    for host in config_only_hosts:
        referenced_hosts[host] += 0
    observed_host_names = set(host_nodes)
    external_lines = [
        f"{host} ({count} referencias)" if count else f"{host} (configuracao)"
        for host, count in referenced_hosts.most_common(14)
        if host and host not in observed_host_names
    ]
    external = builder.node(box_text("Dependencias externas / hosts referenciados", external_lines, 14), 1430, 150, 350, 360, "external", align="left")
    if host_nodes:
        for host, node_id in list(host_nodes.items())[:5]:
            if any(row.get("source_host") == host for row in third_party):
                builder.edge(node_id, external, "assets / SDK / integracao", dashed=True)

    privacy = summary.get("privacy", {})
    notes = [
        "Caixas de host: observadas diretamente no Burp",
        "Servicos: agrupados por prefixo de rota",
        "Dependencias: descobertas em bodies/configuracoes",
        "Backends nao observados nao sao inventados",
        f"Identificadores dinamicos normalizados: {'sim' if privacy.get('dynamic_path_identifiers_normalized') else 'nao informado'}",
    ]
    builder.node(box_text("Escopo e confianca", notes, 8), 1430, 550, 350, 180, "neutral", align="left")
    height = max(930, 180 + len(hosts) * host_gap)
    return builder.diagram("Arquitetura", 1850, height)


def build_technologies(
    project_name: str,
    summary: dict[str, Any],
    technologies: list[dict[str, str]],
    findings: list[dict[str, str]],
) -> str:
    builder = DiagramBuilder()
    builder.node(f"Tecnologias e sinais de recon — {project_name}", 40, 20, 1740, 50, "title")

    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in technologies:
        grouped[row.get("category") or "Outras"].append(row)
    category_kind = {
        "Frontend": "frontend", "CMS": "frontend", "Build": "configuration", "API": "api", "Auth": "auth",
        "Backend": "backend", "Web Server": "backend", "Proxy": "edge", "Edge/CDN": "edge",
        "External Service": "external", "Analytics": "external", "Privacy": "external", "Security": "risk",
        "Observability": "neutral",
    }
    columns = 3
    box_width = 530
    box_height = 235
    for index, (category, rows) in enumerate(sorted(grouped.items())):
        x = 50 + (index % columns) * 580
        y = 100 + (index // columns) * 270
        lines = []
        for row in rows:
            version = f" {row.get('versions')}" if row.get("versions") else ""
            observations = row.get("observations") or row.get("count") or "0"
            lines.append(f"{row.get('technology')}{version} [{row.get('confidence') or 'n/a'}; {observations} obs]")
        builder.node(box_text(category, lines, 12), x, y, box_width, box_height, category_kind.get(category, "neutral"), align="left")

    technology_rows = max(1, (len(grouped) + columns - 1) // columns)
    findings_y = 120 + technology_rows * 270
    finding_counts: Counter[tuple[str, str]] = Counter()
    for row in findings:
        finding_counts[(row.get("severity", "info"), row.get("finding", ""))] += 1
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    finding_lines = [
        f"[{severity}] {name} ({count} endpoints)"
        for (severity, name), count in sorted(finding_counts.items(), key=lambda item: (severity_order.get(item[0][0], 9), item[0][1]))
    ]
    builder.node(box_text("Achados para validacao manual", finding_lines, 14), 50, findings_y, 1110, 300, "risk", align="left")
    meta_lines = [
        f"Itens Burp: {summary.get('total_items', 0)}",
        f"Hosts: {summary.get('hosts_count', 0)}",
        f"Endpoints nao estaticos: {summary.get('unique_endpoints_non_static', 0)}",
        f"Servicos: {summary.get('services_count', 0)}",
        f"Fluxos: {summary.get('flows_count', 0)}",
        f"Schema do relatorio: {summary.get('schema_version', 1)}",
    ]
    builder.node(box_text("Resumo", meta_lines, 10), 1220, findings_y, 560, 210, "client", align="left")
    height = findings_y + 380
    return builder.diagram("Tecnologias e Riscos", 1850, height)


def endpoint_line(row: dict[str, str]) -> str:
    auth = " [auth]" if row.get("auth_hint") == "yes" else (" [auth?]" if row.get("auth_hint") == "maybe" else "")
    status = f" [{row.get('status')}]" if row.get("status") else ""
    return f"{row.get('method')} {trim(row.get('path', '/'), 72)}{status}{auth}"


def build_endpoint_map(project_name: str, endpoints: list[dict[str, str]], max_per_service: int) -> str:
    builder = DiagramBuilder()
    builder.node(f"Mapa de endpoints — {project_name}", 40, 20, 1740, 50, "title")
    by_host_service: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for endpoint in endpoints:
        service = endpoint.get("service") or endpoint.get("category") or "Other"
        by_host_service[endpoint.get("host", "host")][service].append(endpoint)

    current_y = 90
    columns = 3
    box_width = 550
    box_height = 255
    for host, service_groups in sorted(by_host_service.items()):
        total_for_host = sum(len(rows) for rows in service_groups.values())
        builder.node(f"{host} — {total_for_host} endpoints", 50, current_y, 1710, 45, "backend")
        current_y += 65
        ordered_groups = sorted(service_groups.items(), key=lambda item: item[0].lower())
        for index, (service, rows) in enumerate(ordered_groups):
            x = 50 + (index % columns) * 580
            y = current_y + (index // columns) * (box_height + 30)
            ordered_rows = sorted(rows, key=lambda row: (row.get("path", ""), row.get("method", "")))
            categories = Counter(row.get("category", "other") for row in rows)
            primary_category = categories.most_common(1)[0][0]
            prefix = rows[0].get("service_prefix", "") if rows else ""
            title = f"{service}\n{prefix}" if prefix and prefix != "/" else service
            builder.node(box_text(title, [endpoint_line(row) for row in ordered_rows], max_per_service), x, y, box_width, box_height, CATEGORY_KIND.get(primary_category, "neutral"), align="left")
        service_rows = max(1, (len(ordered_groups) + columns - 1) // columns)
        current_y += service_rows * (box_height + 30) + 35

    if not by_host_service:
        builder.node("Nenhum endpoint disponivel", 620, 180, 500, 100, "neutral")
        current_y = 400
    legend = [
        "[auth]: credencial/cookie de autenticacao observada",
        "[auth?]: rota com semantica protegida, sem credencial confirmada",
        "{jwt}, {uuid}, {opaque_id}: identificadores normalizados",
        "O CSV contem o inventario completo; caixas podem resumir linhas.",
    ]
    builder.node(box_text("Legenda", legend, 8), 50, current_y, 850, 130, "neutral", align="left")
    return builder.diagram("Mapa de Endpoints", 1850, current_y + 220)


def fallback_hosts(endpoints: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for row in endpoints:
        grouped[row.get("host", "target")][row.get("category") or (row.get("notes") or "other").split(";")[0]] += 1
    rows = []
    for host, categories in sorted(grouped.items()):
        roles = []
        if categories.get("page") or categories.get("static"):
            roles.append("web-frontend")
        if categories.get("auth"):
            roles.append("identity-provider")
        if categories.get("api") or categories.get("graphql"):
            roles.append("api/gateway")
        rows.append({"host": host, "roles": ", ".join(roles or ["web-service"]), "items": str(sum(categories.values()))})
    return rows


def fallback_services(endpoints: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: Counter[tuple[str, str, str]] = Counter()
    for row in endpoints:
        grouped[(row.get("host", "target"), row.get("service") or row.get("category") or "Other", row.get("category") or "other")] += 1
    return [
        {"host": host, "service": service, "prefix": "", "category": category, "endpoint_count": str(count), "auth": ""}
        for (host, service, category), count in sorted(grouped.items())
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Gera fluxograma, arquitetura, tecnologias e mapa de endpoints em draw.io.")
    parser.add_argument("input_dir", type=Path, help="Diretorio gerado por burp_recon_summary.py")
    parser.add_argument("-o", "--out", type=Path, default=None, help="Arquivo .drawio de saida")
    parser.add_argument("--max-flow-nodes", type=int, default=36, help="Numero maximo de nos na pagina de fluxo")
    parser.add_argument("--max-endpoints-per-service", type=int, default=12, help="Linhas por caixa no mapa visual")
    parser.add_argument("--project-name", default=None, help="Sobrescreve o nome do projeto")
    args = parser.parse_args()

    if not args.input_dir.is_dir():
        parser.error(f"diretorio inexistente: {args.input_dir}")
    if args.max_flow_nodes < 4:
        parser.error("--max-flow-nodes deve ser pelo menos 4")
    if args.max_endpoints_per_service < 1:
        parser.error("--max-endpoints-per-service deve ser pelo menos 1")

    summary = read_json(args.input_dir / "summary.json")
    endpoints = read_csv(args.input_dir / "endpoints.csv")
    if not summary or not (args.input_dir / "endpoints.csv").exists():
        parser.error("summary.json/endpoints.csv ausentes; execute burp_recon_summary.py primeiro")

    hosts = read_csv(args.input_dir / "hosts.csv") or fallback_hosts(endpoints)
    services = read_csv(args.input_dir / "services.csv") or fallback_services(endpoints)
    technologies = read_csv(args.input_dir / "technologies.csv")
    flows = read_csv(args.input_dir / "flows.csv")
    third_party = read_csv(args.input_dir / "third_party_hosts.csv")
    configurations = read_csv(args.input_dir / "configurations.csv")
    findings = read_csv(args.input_dir / "findings.csv")
    project_name = args.project_name or summary.get("project_name") or args.input_dir.name

    output = args.out or args.input_dir.with_suffix(".drawio")
    output.parent.mkdir(parents=True, exist_ok=True)
    diagrams = [
        build_flow(project_name, endpoints, hosts, flows, args.max_flow_nodes),
        build_architecture(project_name, summary, hosts, services, technologies, third_party, configurations, flows),
        build_technologies(project_name, summary, technologies, findings),
        build_endpoint_map(project_name, endpoints, args.max_endpoints_per_service),
    ]
    modified = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    xml = (
        f'<mxfile host="app.diagrams.net" modified="{modified}" agent="burpRecon/recon_to_drawio.py" version="24.7.17">\n'
        + "\n".join(diagrams)
        + "\n</mxfile>\n"
    )
    output.write_text(xml, encoding="utf-8")

    try:
        import xml.etree.ElementTree as ET

        ET.parse(output)
    except ET.ParseError as exc:
        print(f"[error] O draw.io gerado nao e XML valido: {exc}", file=sys.stderr)
        return 2

    print(f"Diagrama draw.io salvo em {output}")
    print("Paginas: Fluxo do Site, Arquitetura, Tecnologias e Riscos, Mapa de Endpoints")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
