#!/usr/bin/env python3
"""

The script intentionally avoids writing full response bodies. It extracts
endpoint inventory, security headers, cookies, redirects, parameters,
API hints, GraphQL operation names, forms, technology hints, and findings
worth reviewing.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urlparse


STATIC_RE = re.compile(
    r"(^/_next/static|^/static/|^/assets/|^/cdn-cgi/|"
    r"\.(?:js|css|map|svg|png|jpe?g|gif|webp|ico|woff2?|ttf|otf)(?:$|\?))",
    re.I,
)
INTERESTING_PATH_RE = re.compile(
    r"(?i)(admin|debug|actuator|swagger|openapi|api-docs|graphql|graphiql|login|logout|"
    r"signin|signup|register|reset|forgot|oauth|saml|oidc|callback|token|session|cart|"
    r"checkout|payment|order|upload|download|export|import|profile|account|config|health|"
    r"metrics|trace|backup|internal|private)"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b")
LONG_SECRET_RE = re.compile(r"(?i)\b([a-z0-9_-]*(?:token|secret|session|cookie|jwt|key|authorization)[a-z0-9_-]*)=([^;&\s]{8,})")
GRAPHQL_OP_RE = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)")
NEXT_DATA_RE = re.compile(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', re.S)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
FORM_RE = re.compile(r"<form\b(?P<form_attrs>[^>]*)>(?P<body>.*?)</form>", re.I | re.S)
INPUT_RE = re.compile(r"<(?:input|select|textarea|button)\b([^>]*)>", re.I)
ATTR_RE = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(['\"])(.*?)\2", re.S)
JSON_KEY_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_.-]{1,80})"\s*:')

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "allow",
    "www-authenticate",
    "location",
    "set-cookie",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-laravel",
    "x-runtime",
    "x-amz-cf-id",
    "x-cache",
    "via",
    "server",
]

TECH_SIGNATURES = [
    ("Next.js", [r"/_next/", r"__NEXT_DATA__", r"x-powered-by:\s*Next\.js"]),
    ("Nuxt/Vue", [r"/_nuxt/", r"data-n-head", r"window\.__NUXT__", r"\bVue(?:\.js)?\b"]),
    ("React", [r"data-reactroot", r"react-dom", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"]),
    ("Angular", [r"ng-version", r"ng-app", r"angular(?:\.min)?\.js"]),
    ("Svelte/SvelteKit", [r"/_app/immutable/", r"data-svelte"]),
    ("Astro", [r"astro-island", r"astro:[a-z-]+"]),
    ("Remix", [r"__remixContext", r"/build/_assets/"]),
    ("Vite", [r"/@vite/client", r"type=\"module\" crossorigin", r"/assets/index-[A-Za-z0-9_-]+\.js"]),
    ("Webpack", [r"webpackChunk", r"__webpack_require__"]),
    ("jQuery", [r"jquery(?:-|\.)(?:min\.)?js", r"\bjQuery\b"]),
    ("Bootstrap", [r"bootstrap(?:\.bundle)?(?:\.min)?\.js", r"bootstrap(?:\.min)?\.css"]),
    ("WordPress", [r"/wp-content/", r"/wp-includes/", r"wp-json"]),
    ("Drupal", [r"Drupal\.settings", r"/sites/default/", r"x-drupal-cache"]),
    ("Joomla", [r"content=\"Joomla!", r"/media/system/js/"]),
    ("Magento", [r"/static/frontend/", r"Magento_", r"mage/cookies"]),
    ("Shopify", [r"cdn\.shopify\.com", r"Shopify\.theme", r"x-shopify"]),
    ("Salesforce Commerce Cloud", [r"demandware\.store", r"/on/demandware\.store/"]),
    ("Laravel", [r"laravel_session", r"XSRF-TOKEN", r"x-laravel"]),
    ("Django", [r"csrftoken", r"django", r"__admin_media_prefix__"]),
    ("Ruby on Rails", [r"_rails_session", r"csrf-param", r"x-runtime"]),
    ("Spring Boot", [r"/actuator", r"JSESSIONID", r"Whitelabel Error Page"]),
    ("ASP.NET", [r"ASP\.NET", r"__VIEWSTATE", r"ASP.NET_SessionId", r"x-aspnet"]),
    ("PHP", [r"PHPSESSID", r"x-powered-by:\s*PHP"]),
    ("Java/JSP", [r"JSESSIONID", r"\.jsp(?:\?|$)"]),
    ("GraphQL", [r"/graphql", r"\bquery\s+[A-Za-z_]", r"__typename"]),
    ("REST API", [r"/api/", r"application/json"]),
    ("OpenAPI/Swagger", [r"swagger-ui", r"openapi\.json", r"api-docs"]),
    ("gRPC-Web", [r"application/grpc-web", r"x-grpc-web"]),
    ("Keycloak/OIDC", [r"/auth/realms/", r"keycloak", r"openid-connect"]),
    ("Auth0/OIDC", [r"auth0\.com", r"cdn\.auth0\.com"]),
    ("Okta/OIDC", [r"okta\.com", r"okta-signin-widget"]),
    ("SAML", [r"SAMLRequest", r"SAMLResponse", r"/saml"]),
    ("Firebase", [r"firebaseapp\.com", r"firebaseio\.com", r"firebaseConfig"]),
    ("Supabase", [r"supabase\.co", r"supabaseUrl"]),
    ("Stripe", [r"js\.stripe\.com", r"stripe\.com"]),
    ("PayPal", [r"paypal\.com/sdk/js", r"paypalobjects\.com"]),
    ("Sentry", [r"sentry", r"/monitoring"]),
    ("Datadog RUM", [r"datadoghq-browser", r"datadoghq\.com"]),
    ("New Relic", [r"newrelic", r"bam\.nr-data\.net"]),
    ("Google Analytics/Tag Manager", [r"googletagmanager\.com", r"google-analytics\.com", r"gtag\("]),
    ("Hotjar", [r"hotjar", r"_hjSession"]),
    ("Cloudflare", [r"server:\s*cloudflare", r"cf-ray", r"/cdn-cgi/"]),
    ("AWS CloudFront", [r"cloudfront", r"x-amz-cf-id"]),
    ("AWS ALB/ELB", [r"awselb", r"AWSALB"]),
    ("Akamai", [r"akamai", r"akamai-ghost"]),
    ("Fastly", [r"fastly", r"x-served-by"]),
    ("Varnish", [r"varnish", r"x-varnish"]),
    ("Nginx", [r"server:\s*nginx"]),
    ("Apache", [r"server:\s*Apache"]),
    ("IIS", [r"server:\s*Microsoft-IIS"]),
    ("Kong", [r"x-kong-upstream-latency", r"x-kong-proxy-latency"]),
    ("Envoy", [r"x-envoy-upstream-service-time", r"server:\s*envoy"]),
    ("Service Worker/PWA", [r"serviceWorker", r"workbox", r"/sw\.js", r"manifest\.json"]),
]


@dataclass
class Endpoint:
    method: str
    host: str
    path: str
    status: str
    mime: str
    length: int
    auth_hint: str
    is_static: bool
    count: int = 1
    notes: set[str] = field(default_factory=set)


def text_of(node: ET.Element | None) -> str:
    return (node.text or "") if node is not None else ""


def decode_blob(node: ET.Element | None, limit: int | None = None) -> str:
    if node is None:
        return ""
    raw = node.text or ""
    if node.attrib.get("base64") == "true":
        try:
            data = base64.b64decode(raw, validate=False)
        except Exception:
            return ""
        if limit is not None:
            data = data[:limit]
        return data.decode("utf-8", errors="replace")
    return raw[:limit] if limit is not None else raw


def split_http_message(message: str) -> tuple[str, dict[str, list[str]], str]:
    head, _, body = message.partition("\r\n\r\n")
    if not body:
        head, _, body = message.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n") if head else []
    start = lines[0] if lines else ""
    headers: dict[str, list[str]] = defaultdict(list)
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()].append(value.strip())
    return start, headers, body


def sanitize(value: str) -> str:
    value = JWT_RE.sub("[JWT_REDACTED]", value)
    value = LONG_SECRET_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", value)
    return value


def attrs_from_tag(tag_attrs: str) -> dict[str, str]:
    return {m.group(1).lower(): m.group(3).strip() for m in ATTR_RE.finditer(tag_attrs or "")}


def cookie_flags(set_cookie: str) -> dict[str, Any]:
    parts = [p.strip() for p in set_cookie.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    flags = {p.lower(): True for p in parts[1:] if "=" not in p}
    kv = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            kv[k.lower()] = v
    return {
        "name": name,
        "secure": bool(flags.get("secure")),
        "httponly": bool(flags.get("httponly")),
        "samesite": kv.get("samesite", ""),
        "path": kv.get("path", ""),
        "domain": kv.get("domain", ""),
    }


def params_from_path(path: str) -> list[str]:
    parsed = urlparse(path)
    return sorted({k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)})


def infer_auth(request_headers: dict[str, list[str]], path: str) -> str:
    cookie = "; ".join(request_headers.get("cookie", []))
    auth = " ".join(request_headers.get("authorization", []))
    if auth or re.search(r"(?i)(kc_|token|session|isAuthenticated|authorization)", cookie):
        return "yes"
    if re.search(
        r"(?i)(/admin|/account|/profile|/me|/user|/dashboard|/minha-conta|/checkout|"
        r"/order|/pedidos|/sso|/oauth|/saml|/oidc|/api/auth|/graphql)",
        path,
    ):
        return "maybe"
    return "no"


def classify_endpoint(path: str, mime: str, method: str) -> str:
    lower = path.lower()
    if STATIC_RE.search(path):
        return "static"
    if "/graphql" in lower:
        return "graphql"
    if re.search(r"(?i)(openapi|swagger|api-docs)", path):
        return "api-docs"
    if re.search(r"(?i)(/auth|/oauth|/saml|/oidc|/login|/logout|/signin|/signup|/register|/token|/session|/callback|/sso)", path):
        return "auth"
    if re.search(r"(?i)(/admin|/dashboard|/console|/manage)", path):
        return "admin"
    if re.search(r"(?i)(/api/|/rest/|/v\d+/)", path) or "json" in mime.lower():
        return "api"
    if re.search(r"(?i)(/upload|/import)", path) or method.upper() in {"PUT", "PATCH", "DELETE"}:
        return "state-changing"
    if "html" in mime.lower() or lower in {"/", ""}:
        return "page"
    return "other"


def detect_tech(headers: dict[str, list[str]], body_sample: str, path: str) -> set[str]:
    header_lines = []
    for key, values in headers.items():
        for value in values:
            header_lines.append(f"{key}: {value}")
    haystack = "\n".join([path, "\n".join(header_lines), body_sample[:120_000]])
    tech = {
        name
        for name, patterns in TECH_SIGNATURES
        if any(re.search(pattern, haystack, re.I) for pattern in patterns)
    }
    return tech


def extract_forms(body_sample: str, host: str, path: str) -> list[dict[str, Any]]:
    forms = []
    for match in FORM_RE.finditer(body_sample[:200_000]):
        form_attrs = attrs_from_tag(match.group("form_attrs"))
        fields = []
        for field_match in INPUT_RE.finditer(match.group("body")):
            attrs = attrs_from_tag(field_match.group(1))
            name = attrs.get("name") or attrs.get("id")
            if name:
                fields.append(name)
        forms.append({
            "host": host,
            "page": sanitize(path),
            "method": (form_attrs.get("method") or "GET").upper(),
            "action": sanitize(form_attrs.get("action") or ""),
            "field_count": len(set(fields)),
            "fields": ", ".join(sorted(set(fields))[:80]),
        })
    return forms


def extract_api_hints(path: str, request_body: str, response_body: str) -> set[str]:
    hints = set()
    lower = path.lower()
    if "/graphql" in lower:
        hints.add("graphql-endpoint")
    if re.search(r"(?i)(swagger|openapi|api-docs)", path + response_body[:20_000]):
        hints.add("openapi-or-swagger")
    if request_body.strip().startswith("{") or response_body.strip().startswith("{"):
        hints.add("json-api")
    if re.search(r"(?i)\b(page|limit|offset|cursor|sort|filter|q|search)\b", path):
        hints.add("pagination-or-search-params")
    keys = set(JSON_KEY_RE.findall(request_body[:50_000] + "\n" + response_body[:50_000]))
    interesting = sorted(k for k in keys if re.search(r"(?i)(id|uuid|email|role|status|price|amount|token|csrf|user|admin|order|cart|payment)", k))
    hints.update(f"json-key:{k}" for k in interesting[:30])
    return hints


def get_next_runtime_config(body_sample: str) -> dict[str, Any]:
    match = NEXT_DATA_RE.search(body_sample)
    if not match:
        return {}
    try:
        data = json.loads(match.group(1))
    except Exception:
        return {}
    cfg = data.get("runtimeConfig") or {}
    safe = {}
    for key, value in cfg.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = sanitize(str(value)) if isinstance(value, str) else value
        elif isinstance(value, dict):
            safe[key] = {k: sanitize(str(v)) for k, v in value.items() if isinstance(v, (str, int, float, bool))}
    return safe


def extract_graphql_operations(request_body: str, response_body: str) -> set[str]:
    ops = set(GRAPHQL_OP_RE.findall(request_body))
    try:
        payload = json.loads(request_body)
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if isinstance(item, dict):
                if item.get("operationName"):
                    ops.add(str(item["operationName"]))
                query = item.get("query")
                if isinstance(query, str):
                    ops.update(GRAPHQL_OP_RE.findall(query))
    except Exception:
        pass
    ops.update(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*(?:Query|Mutation|V\d+)?)"', response_body[:20000]))
    return {op for op in ops if len(op) <= 80}


def iter_items(files: Iterable[Path]) -> Iterable[ET.Element]:
    for file in files:
        try:
            context = ET.iterparse(file, events=("end",))
            for _, elem in context:
                if elem.tag == "item":
                    yield elem
                    elem.clear()
        except ET.ParseError as exc:
            print(f"[warn] XML parse error in {file}: {exc}", file=sys.stderr)


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create compact recon summaries from Burp XML exports.")
    parser.add_argument("files", nargs="+", type=Path, help="Burp XML export files")
    parser.add_argument("-o", "--out", type=Path, default=Path("burp-recon-output"), help="Output directory")
    parser.add_argument("--include-static", action="store_true", help="Include static assets in endpoints.csv")
    parser.add_argument("--body-sample-bytes", type=int, default=160_000, help="Bytes decoded per response for metadata extraction")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    endpoints: dict[tuple[str, str, str, str], Endpoint] = {}
    params: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    security: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    cookies: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    redirects: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    api_hints: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    interesting_paths: Counter[str] = Counter()
    graphql_ops: Counter[str] = Counter()
    tech: Counter[str] = Counter()
    tech_evidence: dict[str, Counter[str]] = defaultdict(Counter)
    third_party: Counter[str] = Counter()
    runtime_configs: dict[str, dict[str, Any]] = {}
    findings: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    mime_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    total = 0
    for item in iter_items(args.files):
        total += 1
        url = text_of(item.find("url"))
        host = text_of(item.find("host"))
        method = text_of(item.find("method")) or ""
        path = text_of(item.find("path")) or urlparse(url).path or "/"
        status = text_of(item.find("status")) or ""
        mime = text_of(item.find("mimetype")) or ""
        try:
            length = int(text_of(item.find("responselength")) or 0)
        except ValueError:
            length = 0

        request_text = decode_blob(item.find("request"), limit=80_000)
        response_text = decode_blob(item.find("response"), limit=args.body_sample_bytes)
        _, req_headers, req_body = split_http_message(request_text)
        _, res_headers, res_body = split_http_message(response_text)

        static = bool(STATIC_RE.search(path))
        auth_hint = infer_auth(req_headers, path)
        category = classify_endpoint(path, mime, method)
        endpoint_key = (method, host, path, status)
        endpoint = endpoints.get(endpoint_key)
        if endpoint:
            endpoint.count += 1
            endpoint.length = max(endpoint.length, length)
        else:
            endpoints[endpoint_key] = Endpoint(method, host, path, status, mime, length, auth_hint, static)
        endpoints[endpoint_key].notes.add(category)

        status_counts[status] += 1
        mime_counts[mime] += 1
        category_counts[category] += 1
        for param in params_from_path(path):
            params[(host, method, urlparse(path).path)].add(param)

        for header in SECURITY_HEADERS:
            for value in res_headers.get(header, []):
                security[host][header][sanitize(value)] += 1

        for value in res_headers.get("set-cookie", []):
            ck = cookie_flags(value)
            name = ck["name"]
            if name:
                cookies[host][name][json.dumps(ck, sort_keys=True)] += 1

        if status.startswith("3") and res_headers.get("location"):
            redirects.append({
                "method": method,
                "host": host,
                "path": sanitize(path),
                "status": status,
                "location": sanitize(res_headers["location"][0]),
            })

        detected = detect_tech(res_headers, response_text, path)
        for name in detected:
            tech[name] += 1
            tech_evidence[name][host] += 1
        for found_url in URL_RE.findall(response_text[:80_000]):
            parsed = urlparse(found_url)
            if parsed.netloc and parsed.netloc != host:
                third_party[parsed.netloc] += 1

        forms.extend(extract_forms(response_text, host, path))
        for hint in extract_api_hints(path, req_body, res_body):
            api_hints[(host, method, urlparse(path).path)].add(hint)

        if "/graphql" in path.lower():
            for op in extract_graphql_operations(req_body, res_body):
                graphql_ops[op] += 1

        cfg = get_next_runtime_config(response_text)
        if cfg:
            runtime_configs[host] = cfg

        if "content-security-policy" not in res_headers and mime.lower() in {"html", "script", "json"}:
            findings["Missing Content-Security-Policy on executable/API response"] += 1
        if res_headers.get("access-control-allow-origin", []) == ["*"]:
            findings["CORS wildcard Access-Control-Allow-Origin"] += 1
        if "x-powered-by" in res_headers:
            findings["Technology disclosure via X-Powered-By"] += 1
        if "strict-transport-security" not in res_headers and url.startswith("https://"):
            findings["Missing HSTS on HTTPS response"] += 1
        if "set-cookie" in res_headers:
            for value in res_headers["set-cookie"]:
                low = value.lower()
                if "secure" not in low:
                    findings["Cookie without Secure flag"] += 1
                if "httponly" not in low:
                    findings["Cookie without HttpOnly flag"] += 1
                if "samesite" not in low:
                    findings["Cookie without SameSite attribute"] += 1
        if JWT_RE.search(response_text):
            findings["JWT-like token present in response body"] += 1
        if INTERESTING_PATH_RE.search(path):
            interesting_paths[sanitize(path)] += 1
        if category == "api-docs" and status.startswith("2"):
            findings["API documentation endpoint reachable"] += 1
        if category == "admin" and status.startswith("2"):
            findings["Administrative-looking endpoint reachable"] += 1
        if method.upper() in {"PUT", "PATCH", "DELETE"} and status.startswith("2"):
            findings["State-changing HTTP method returned success"] += 1
        if "server" in res_headers:
            server = " ".join(res_headers["server"])
            if re.search(r"/\d", server):
                findings["Server header exposes version-like value"] += 1

    endpoint_rows = []
    for ep in endpoints.values():
        if ep.is_static and not args.include_static:
            continue
        endpoint_rows.append({
            "method": ep.method,
            "host": ep.host,
            "path": sanitize(ep.path),
            "status": ep.status,
            "type": ep.mime,
            "max_length": ep.length,
            "count": ep.count,
            "auth_hint": ep.auth_hint,
            "static": ep.is_static,
            "notes": "; ".join(sorted(ep.notes)),
        })
    endpoint_rows.sort(key=lambda r: (r["host"], r["path"], r["method"], r["status"]))
    write_csv(args.out / "endpoints.csv", endpoint_rows, [
        "method", "host", "path", "status", "type", "max_length", "count", "auth_hint", "static", "notes"
    ])

    param_rows = [
        {"host": h, "method": m, "path": p, "params": ", ".join(sorted(values))}
        for (h, m, p), values in sorted(params.items())
    ]
    write_csv(args.out / "params.csv", param_rows, ["host", "method", "path", "params"])

    sec_rows = []
    for host, headers in sorted(security.items()):
        for header, values in sorted(headers.items()):
            sec_rows.append({"host": host, "header": header, "values": " | ".join(values.keys())})
    write_csv(args.out / "security_headers.csv", sec_rows, ["host", "header", "values"])

    cookie_rows = []
    for host, names in sorted(cookies.items()):
        for name, variants in sorted(names.items()):
            sample = json.loads(next(iter(variants.keys())))
            cookie_rows.append({"host": host, **sample, "observations": sum(variants.values())})
    write_csv(args.out / "cookies.csv", cookie_rows, [
        "host", "name", "secure", "httponly", "samesite", "path", "domain", "observations"
    ])

    write_csv(args.out / "redirects.csv", redirects, ["method", "host", "path", "status", "location"])
    write_csv(args.out / "graphql_operations.csv", [
        {"operation": op, "count": count} for op, count in graphql_ops.most_common()
    ], ["operation", "count"])
    write_csv(args.out / "third_party_hosts.csv", [
        {"host": host, "count": count} for host, count in third_party.most_common()
    ], ["host", "count"])
    write_csv(args.out / "technologies.csv", [
        {"technology": name, "count": count, "hosts": ", ".join(sorted(tech_evidence[name].keys()))}
        for name, count in tech.most_common()
    ], ["technology", "count", "hosts"])
    write_csv(args.out / "forms.csv", forms, ["host", "page", "method", "action", "field_count", "fields"])
    write_csv(args.out / "api_hints.csv", [
        {"host": h, "method": m, "path": p, "hints": ", ".join(sorted(values))}
        for (h, m, p), values in sorted(api_hints.items())
    ], ["host", "method", "path", "hints"])
    write_csv(args.out / "interesting_paths.csv", [
        {"path": path, "count": count} for path, count in interesting_paths.most_common()
    ], ["path", "count"])

    summary = {
        "source_files": [str(p) for p in args.files],
        "total_items": total,
        "unique_endpoints_non_static": len(endpoint_rows),
        "unique_endpoints_all": len(endpoints),
        "status_counts": dict(status_counts),
        "mime_counts": dict(mime_counts),
        "category_counts": dict(category_counts),
        "technologies": dict(tech.most_common()),
        "findings": dict(findings.most_common()),
        "interesting_paths_count": len(interesting_paths),
        "forms_count": len(forms),
        "runtime_configs": runtime_configs,
        "output_hash": hashlib.sha256(json.dumps(endpoint_rows, sort_keys=True).encode()).hexdigest()[:16],
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    md = [
        "# Burp Recon Summary",
        "",
        f"- Total items: {total}",
        f"- Unique endpoints, non-static: {len(endpoint_rows)}",
        f"- Unique endpoints, all: {len(endpoints)}",
        "",
        "## Technologies",
        *[f"- {name}: {count}" for name, count in tech.most_common()],
        "",
        "## Findings To Review",
        *[f"- {name}: {count}" for name, count in findings.most_common()],
        "",
        "## Key Files",
        "- `endpoints.csv`: normalized endpoint inventory",
        "- `security_headers.csv`: response security headers by host",
        "- `cookies.csv`: cookie flags without values",
        "- `params.csv`: query parameters by route",
        "- `graphql_operations.csv`: GraphQL operation names",
        "- `api_hints.csv`: API style, JSON keys, docs, and pagination hints",
        "- `forms.csv`: HTML forms and field names",
        "- `technologies.csv`: detected technologies and host evidence",
        "- `interesting_paths.csv`: auth, admin, payment, upload, docs, and debug-looking paths",
        "- `redirects.csv`: HTTP redirects",
        "- `third_party_hosts.csv`: external hosts observed in responses",
        "- `summary.json`: machine-readable overview",
        "",
        "## Handling Notes",
        "- Token-like values are redacted.",
        "- Full response bodies are not exported.",
        "- Static assets are excluded from `endpoints.csv` unless `--include-static` is used.",
    ]
    (args.out / "README.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"Wrote recon summary to {args.out}")
    print(f"Non-static endpoints: {len(endpoint_rows)} | total items: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
