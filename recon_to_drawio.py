#!/usr/bin/env python3
"""Generate draw.io diagrams from burp_recon_summary.py output.

Input is a directory containing files such as summary.json, endpoints.csv,
technologies.csv, third_party_hosts.csv, redirects.csv, forms.csv,
graphql_operations.csv, and findings embedded in summary.json.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PALETTE = {
    "client": ("#d5e8d4", "#82b366"),
    "edge": ("#dae8fc", "#6c8ebf"),
    "frontend": ("#fff2cc", "#d6b656"),
    "auth": ("#e1d5e7", "#9673a6"),
    "api": ("#f8cecc", "#b85450"),
    "backend": ("#f5f5f5", "#666666"),
    "external": ("#ffe6cc", "#d79b00"),
    "risk": ("#f8cecc", "#b85450"),
    "neutral": ("#ffffff", "#666666"),
}


@dataclass
class Cell:
    id: str
    value: str
    x: int
    y: int
    w: int
    h: int
    kind: str = "neutral"
    shape: str = "rounded=1"


class DiagramBuilder:
    def __init__(self) -> None:
        self.cells: list[str] = []
        self.edges: list[str] = []
        self.seq = 1

    def _style(self, kind: str, shape: str) -> str:
        fill, stroke = PALETTE.get(kind, PALETTE["neutral"])
        return f"{shape};whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontSize=13;"

    def node(self, value: str, x: int, y: int, w: int = 200, h: int = 70, kind: str = "neutral", shape: str = "rounded=1") -> str:
        cid = f"n{self.seq}"
        self.seq += 1
        safe_value = html.escape(value).replace("\n", "&lt;br&gt;")
        style = self._style(kind, shape)
        self.cells.append(
            f'<mxCell id="{cid}" value="{safe_value}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry" />'
            "</mxCell>"
        )
        return cid

    def edge(self, source: str, target: str, label: str = "", dashed: bool = False) -> None:
        eid = f"e{self.seq}"
        self.seq += 1
        safe_label = html.escape(label)
        dash = "dashed=1;" if dashed else ""
        self.edges.append(
            f'<mxCell id="{eid}" value="{safe_label}" edge="1" parent="1" source="{source}" target="{target}" '
            f'style="endArrow=block;html=1;rounded=0;{dash}">'
            '<mxGeometry relative="1" as="geometry" />'
            "</mxCell>"
        )

    def xml(self, name: str, width: int = 1600, height: int = 1100) -> str:
        body = "\n".join(self.cells + self.edges)
        return f"""  <diagram id="{html.escape(name.lower().replace(' ', '-'))}" name="{html.escape(name)}">
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
    with path.open(newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def top(items: dict[str, Any] | Counter[str], limit: int) -> list[tuple[str, int]]:
    pairs = [(str(k), int(v)) for k, v in items.items()]
    return sorted(pairs, key=lambda kv: kv[1], reverse=True)[:limit]


def host_list(endpoints: list[dict[str, str]]) -> list[str]:
    hosts = sorted({row.get("host", "") for row in endpoints if row.get("host")})
    return hosts or ["target"]


def path_summary(endpoints: list[dict[str, str]], note: str, limit: int = 8) -> list[str]:
    rows = [r for r in endpoints if note in (r.get("notes") or "")]
    return [f"{r.get('method')} {trim_path(r.get('path', ''))}" for r in rows[:limit]]


def trim_path(path: str, max_len: int = 52) -> str:
    path = path or "/"
    if len(path) <= max_len:
        return path
    parsed = urlparse(path)
    base = parsed.path or path
    return base[: max_len - 3] + "..."


def box_text(title: str, lines: list[str], max_lines: int = 8) -> str:
    selected = lines[:max_lines]
    more = len(lines) - len(selected)
    body = "\n".join(selected)
    if more > 0:
        body += f"\n+{more} mais"
    return f"{title}\n{body}" if body else title


def infer_primary_stack(technologies: dict[str, Any]) -> tuple[str, str, str]:
    frontend = next((t for t in ["Next.js", "Nuxt/Vue", "React", "Angular", "Svelte/SvelteKit", "Astro", "Remix", "Vite"] if t in technologies), "Web Frontend")
    api = "GraphQL" if "GraphQL" in technologies else ("REST API" if "REST API" in technologies else "API/BFF")
    auth = next((t for t in ["Keycloak/OIDC", "Auth0/OIDC", "Okta/OIDC", "SAML"] if t in technologies), "Auth/Sessao")
    return frontend, api, auth


def build_flow(summary: dict[str, Any], endpoints: list[dict[str, str]], third_party: list[dict[str, str]], forms: list[dict[str, str]]) -> str:
    b = DiagramBuilder()
    techs = summary.get("technologies", {})
    frontend, api_name, auth_name = infer_primary_stack(techs)

    user = b.node("Usuario / Browser", 60, 110, 170, 70, "client", "ellipse")
    edge = b.node("Borda / CDN / WAF\n" + ", ".join(t for t in ["Cloudflare", "Akamai", "Fastly"] if t in techs) or "Edge", 300, 100, 210, 90, "edge")
    fe = b.node(f"Storefront\n{frontend}", 590, 100, 210, 90, "frontend")
    public = b.node(box_text("Rotas publicas", path_summary(endpoints, "page", 6)), 860, 40, 250, 130, "frontend")
    decision = b.node("Precisa autenticar?", 910, 240, 150, 100, "auth", "rhombus")
    auth = b.node(f"Autenticacao\n{auth_name}", 610, 390, 230, 95, "auth")
    session = b.node("Sessao\ncookies / tokens / redirects", 890, 400, 230, 90, "auth")
    api = b.node(f"APIs\n{api_name}", 1190, 210, 230, 90, "api")
    protected = b.node(box_text("Areas autenticadas", path_summary(endpoints, "auth", 6) + path_summary(endpoints, "admin", 3)), 1190, 380, 260, 140, "api")

    form_lines = [f"{f.get('method')} {trim_path(f.get('action') or f.get('page') or '/')}" for f in forms[:6]]
    forms_node = b.node(box_text("Forms observados", form_lines), 590, 610, 260, 130, "neutral")

    external_lines = [row.get("host", "") for row in third_party[:8]]
    external = b.node(box_text("Terceiros", external_lines), 1040, 610, 280, 150, "external")

    b.edge(user, edge)
    b.edge(edge, fe)
    b.edge(fe, public)
    b.edge(public, decision)
    b.edge(decision, auth, "sim")
    b.edge(auth, session)
    b.edge(session, api)
    b.edge(decision, api, "nao / dados publicos")
    b.edge(api, protected)
    b.edge(fe, forms_node, "HTML forms", dashed=True)
    b.edge(fe, external, "scripts / widgets / imagens", dashed=True)
    return b.xml("Fluxo do Site")


def build_architecture(summary: dict[str, Any], endpoints: list[dict[str, str]], third_party: list[dict[str, str]], api_hints: list[dict[str, str]]) -> str:
    b = DiagramBuilder()
    techs = summary.get("technologies", {})
    frontend, api_name, auth_name = infer_primary_stack(techs)
    hosts = host_list(endpoints)
    runtime = summary.get("runtime_configs", {})
    runtime_lines = []
    for host, cfg in runtime.items():
        for key in ["publicBffUrl", "bffUrl", "paymentWidget", "domain"]:
            if key in cfg:
                runtime_lines.append(f"{key}: {cfg[key]}")

    client = b.node("Clientes\nbrowser desktop/mobile", 70, 160, 210, 90, "client")
    edge = b.node("Edge\n" + "\n".join(t for t in ["Cloudflare", "Akamai", "Fastly", "AWS CloudFront"] if t in techs), 340, 160, 220, 100, "edge")
    app = b.node(f"Aplicacao Web\n{frontend}\nHosts: {', '.join(hosts[:3])}", 640, 130, 250, 130, "frontend")
    gateway = b.node("Gateway / Proxy\n" + "\n".join(t for t in ["Kong", "Envoy", "Nginx", "Apache", "IIS"] if t in techs), 970, 160, 230, 100, "backend")
    api = b.node(f"Camada API\n{api_name}\n{summary.get('category_counts', {}).get('graphql', 0)} GraphQL / {summary.get('category_counts', {}).get('api', 0)} API", 1280, 130, 240, 130, "api")
    auth = b.node(f"Identity Provider\n{auth_name}", 970, 360, 230, 90, "auth")
    observability = b.node("Observabilidade\n" + "\n".join(t for t in ["Sentry", "Datadog RUM", "New Relic", "Google Analytics/Tag Manager", "Hotjar"] if t in techs), 640, 360, 250, 130, "neutral")
    runtime_node = b.node(box_text("Runtime publico", runtime_lines, 6), 1280, 350, 250, 150, "neutral")

    hint_lines = []
    for row in api_hints[:8]:
        hint_lines.append(f"{trim_path(row.get('path', ''))}: {row.get('hints', '')[:60]}")
    hints = b.node(box_text("Hints de API", hint_lines, 6), 970, 590, 330, 160, "api")

    ext_lines = [f"{row.get('host')} ({row.get('count')})" for row in third_party[:10]]
    external = b.node(box_text("Servicos externos", ext_lines, 8), 350, 590, 300, 170, "external")

    b.edge(client, edge)
    b.edge(edge, app)
    b.edge(app, gateway)
    b.edge(gateway, api)
    b.edge(app, auth, "login / callback")
    b.edge(app, observability, "telemetria", dashed=True)
    b.edge(app, external, "assets / widgets", dashed=True)
    b.edge(api, runtime_node, "configs vistas", dashed=True)
    b.edge(api, hints, "operacoes / JSON", dashed=True)
    return b.xml("Arquitetura")


def build_technologies(summary: dict[str, Any], tech_rows: list[dict[str, str]]) -> str:
    b = DiagramBuilder()
    groups = {
        "Frontend": {"Next.js", "Nuxt/Vue", "React", "Angular", "Svelte/SvelteKit", "Astro", "Remix", "Vite", "Webpack", "jQuery", "Bootstrap"},
        "Backend/API": {"REST API", "GraphQL", "OpenAPI/Swagger", "gRPC-Web", "Laravel", "Django", "Ruby on Rails", "Spring Boot", "ASP.NET", "PHP", "Java/JSP"},
        "Auth": {"Keycloak/OIDC", "Auth0/OIDC", "Okta/OIDC", "SAML"},
        "Infra": {"Cloudflare", "AWS CloudFront", "AWS ALB/ELB", "Akamai", "Fastly", "Varnish", "Nginx", "Apache", "IIS", "Kong", "Envoy"},
        "Observabilidade": {"Sentry", "Datadog RUM", "New Relic", "Google Analytics/Tag Manager", "Hotjar"},
        "Pagamentos/Externos": {"Stripe", "PayPal", "Firebase", "Supabase", "Service Worker/PWA"},
    }
    counts = {row.get("technology", ""): int(row.get("count") or 0) for row in tech_rows}
    x_positions = [70, 370, 670, 970, 1270, 70]
    y_positions = [90, 90, 90, 90, 90, 390]
    group_nodes = {}
    for idx, (group, names) in enumerate(groups.items()):
        lines = [f"{name}: {counts[name]}" for name in sorted(names) if name in counts]
        x = x_positions[idx]
        y = y_positions[idx]
        group_nodes[group] = b.node(box_text(group, lines, 12), x, y, 250, 240, "neutral")

    all_known = set().union(*groups.values())
    other_lines = [f"{name}: {count}" for name, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True) if name not in all_known]
    b.node(box_text("Outras deteccoes", other_lines, 12), 370, 390, 260, 240, "neutral")

    findings = summary.get("findings", {})
    finding_lines = [f"{name}: {count}" for name, count in top(findings, 12)]
    b.node(box_text("Achados para revisar", finding_lines, 12), 760, 390, 420, 260, "risk")

    meta = [
        f"Items Burp: {summary.get('total_items', 0)}",
        f"Endpoints nao-estaticos: {summary.get('unique_endpoints_non_static', 0)}",
        f"Endpoints totais: {summary.get('unique_endpoints_all', 0)}",
        f"Forms: {summary.get('forms_count', 0)}",
        f"Interesting paths: {summary.get('interesting_paths_count', 0)}",
    ]
    b.node(box_text("Resumo", meta, 10), 1240, 390, 260, 190, "client")
    return b.xml("Tecnologias e Riscos")


def build_endpoint_map(summary: dict[str, Any], endpoints: list[dict[str, str]], graphql_ops: list[dict[str, str]], interesting: list[dict[str, str]]) -> str:
    b = DiagramBuilder()
    categories: dict[str, list[str]] = defaultdict(list)
    for row in endpoints:
        note = (row.get("notes") or "other").split(";")[0].strip() or "other"
        categories[note].append(f"{row.get('method')} {trim_path(row.get('path', ''))}")

    positions = {
        "page": (70, 80, "frontend"),
        "auth": (390, 80, "auth"),
        "api": (710, 80, "api"),
        "graphql": (1030, 80, "api"),
        "admin": (70, 390, "risk"),
        "state-changing": (390, 390, "risk"),
        "other": (710, 390, "neutral"),
    }
    for name, (x, y, kind) in positions.items():
        b.node(box_text(name.title(), categories.get(name, []), 10), x, y, 280, 240, kind)

    ops = [f"{row.get('operation')} ({row.get('count')})" for row in graphql_ops[:14]]
    b.node(box_text("GraphQL operations", ops, 14), 1030, 390, 300, 300, "api")

    interesting_lines = [f"{trim_path(row.get('path', ''), 68)} ({row.get('count')})" for row in interesting[:12]]
    b.node(box_text("Interesting paths", interesting_lines, 12), 70, 700, 520, 260, "risk")
    return b.xml("Mapa de Endpoints")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate draw.io diagrams from burp recon summary output.")
    parser.add_argument("input_dir", type=Path, help="Directory generated by burp_recon_summary.py")
    parser.add_argument("-o", "--out", type=Path, default=None, help="Output .drawio file")
    args = parser.parse_args()

    input_dir = args.input_dir
    summary = read_json(input_dir / "summary.json")
    endpoints = read_csv(input_dir / "endpoints.csv")
    third_party = read_csv(input_dir / "third_party_hosts.csv")
    forms = read_csv(input_dir / "forms.csv")
    api_hints = read_csv(input_dir / "api_hints.csv")
    tech_rows = read_csv(input_dir / "technologies.csv")
    graphql_ops = read_csv(input_dir / "graphql_operations.csv")
    interesting = read_csv(input_dir / "interesting_paths.csv")

    out = args.out or input_dir.with_suffix(".drawio")
    diagrams = [
        build_flow(summary, endpoints, third_party, forms),
        build_architecture(summary, endpoints, third_party, api_hints),
        build_technologies(summary, tech_rows),
        build_endpoint_map(summary, endpoints, graphql_ops, interesting),
    ]
    xml = (
        '<mxfile host="app.diagrams.net" modified="2026-07-18T00:00:00.000Z" '
        'agent="Codex recon_to_drawio.py" version="24.7.17">\n'
        + "\n".join(diagrams)
        + "\n</mxfile>\n"
    )
    out.write_text(xml, encoding="utf-8")
    print(f"Wrote draw.io diagram to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
