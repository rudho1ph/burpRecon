#!/usr/bin/env python3
"""Build a safe architecture/recon dataset from Burp Suite XML exports.

The input format is the XML produced by Burp's "Save selected items" action.
Requests and responses are decoded in memory, but credentials, cookie values,
tokens, personal identifiers, and full bodies are never written to the report.

The generated CSV/JSON files are intentionally suitable as input for
``recon_to_drawio.py`` and for manual endpoint review.
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urljoin, urlparse, urlsplit, urlunsplit


STATIC_RE = re.compile(
    r"(^/_next/static|^/_nuxt/|^/static/|^/assets/|^/cdn-cgi/|^/themes/.*/assets/|"
    r"\.(?:js|mjs|css|map|svg|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|eot)(?:$|\?))",
    re.I,
)
INTERESTING_PATH_RE = re.compile(
    r"(?i)(admin|debug|actuator|swagger|openapi|api-docs|graphql|graphiql|login|logout|"
    r"signin|signup|register|reset|forgot|oauth|saml|oidc|callback|token|session|cart|"
    r"checkout|payment|order|upload|download|export|import|profile|account|config|health|"
    r"metrics|trace|backup|internal|private|statement|transaction|balance|card)"
)
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_ID_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,}$")
DOCUMENT_RE = re.compile(r"^\d{9,14}$")
BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:access_?token|refresh_?token|id_?token|authorization|password|passwd|"
    r"secret|session(?:id|_state|datakey)?|api_?key|code|assertion|cookie)\b\s*[:=]\s*)"
    r"(['\"]?)[^\s,;&'\"]{4,}\2"
)
GRAPHQL_OP_RE = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)")
NEXT_DATA_RE = re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.I | re.S)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
FORM_RE = re.compile(r"<form\b(?P<form_attrs>[^>]*)>(?P<body>.*?)</form>", re.I | re.S)
INPUT_RE = re.compile(r"<(?:input|select|textarea|button)\b([^>]*)>", re.I)
ANCHOR_RE = re.compile(r"<a\b([^>]*)>", re.I)
ATTR_RE = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(['\"])(.*?)\2", re.S)
JSON_KEY_RE = re.compile(r'["\']([A-Za-z_][A-Za-z0-9_.-]{1,80})["\']\s*:')

SENSITIVE_QUERY_NAMES = re.compile(
    r"(?i)(token|secret|password|passwd|session|code|assertion|ticket|credential|auth|key|"
    r"document|cpf|email|phone|account|card|user|nonce|state)"
)

SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy",
    "cross-origin-embedder-policy", "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "access-control-allow-headers", "access-control-expose-headers", "allow",
    "www-authenticate", "location", "set-cookie", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-laravel", "x-runtime", "x-amz-cf-id", "x-cache", "via", "server",
]


@dataclass(frozen=True)
class TechnologyRule:
    name: str
    category: str
    confidence: str
    evidence: str
    patterns: tuple[str, ...]


TECH_RULES = (
    TechnologyRule("October CMS", "CMS", "high", "assets/codigo do October CMS", (r"October\s*CMS", r"/modules/system/assets/(?:js|css)/framework")),
    TechnologyRule("WordPress", "CMS", "high", "rotas WordPress", (r"/wp-content/", r"/wp-includes/", r"\bwp-json\b")),
    TechnologyRule("Drupal", "CMS", "high", "assinatura Drupal", (r"Drupal\.settings", r"/sites/default/", r"x-drupal-cache:")),
    TechnologyRule("Joomla", "CMS", "high", "assinatura Joomla", (r"content=[\"']Joomla!", r"/media/system/js/")),
    TechnologyRule("Next.js", "Frontend", "high", "artefatos Next.js", (r"/_next/", r"__NEXT_DATA__", r"x-powered-by:\s*Next\.js")),
    TechnologyRule("Nuxt/Vue", "Frontend", "high", "artefatos Nuxt/Vue", (r"/_nuxt/", r"window\.__NUXT__", r"data-n-head", r"\bVue(?:\.js)?\b")),
    TechnologyRule("React", "Frontend", "medium", "assinatura React", (r"react-dom", r"data-reactroot", r"__REACT_DEVTOOLS_GLOBAL_HOOK__")),
    TechnologyRule("Create React App", "Frontend", "medium", "bundle static/js/main", (r"/static/js/main\.[A-Za-z0-9]+\.js", r"asset-manifest\.json")),
    TechnologyRule("Angular", "Frontend", "high", "assinatura Angular", (r"ng-version", r"ng-app", r"angular(?:\.min)?\.js")),
    TechnologyRule("Svelte/SvelteKit", "Frontend", "high", "assinatura Svelte", (r"/_app/immutable/", r"data-svelte")),
    TechnologyRule("Vite", "Build", "high", "artefatos Vite", (r"/@vite/client", r"type=[\"']module[\"']\s+crossorigin", r"/assets/index-[A-Za-z0-9_-]+\.js")),
    TechnologyRule("Webpack", "Build", "high", "runtime Webpack", (r"webpackChunk", r"__webpack_require__")),
    TechnologyRule("jQuery", "Frontend", "high", "biblioteca jQuery", (r"jquery(?:-|\.)(?:\d+(?:\.\d+)+|min)", r"\bjQuery\b")),
    TechnologyRule("Bootstrap", "Frontend", "high", "assets Bootstrap", (r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)",)),
    TechnologyRule("Owl Carousel", "Frontend", "high", "assets Owl Carousel", (r"owlcarousel", r"owl\.carousel")),
    TechnologyRule("Fancybox", "Frontend", "high", "assets Fancybox", (r"fancybox",)),
    TechnologyRule("REST API", "API", "high", "rota ou resposta JSON de API", (r"(?:^|/)api-s/", r"(?:^|/)api/", r"content-type:\s*application/(?:[^;]+\+)?json")),
    TechnologyRule("GraphQL", "API", "high", "endpoint/operacao GraphQL", (r"/graphql", r"\bquery\s+[A-Za-z_]", r"__typename")),
    TechnologyRule("OpenAPI/Swagger", "API", "high", "documentacao OpenAPI", (r"swagger-ui", r"openapi\.json", r"api-docs")),
    TechnologyRule("gRPC-Web", "API", "high", "cabecalho gRPC-Web", (r"application/grpc-web", r"x-grpc-web")),
    TechnologyRule("OAuth 2.0/OIDC", "Auth", "high", "endpoints OAuth/OIDC", (r"/oauth2/(?:authorize|token|jwks)", r"scope=[^\s]*openid", r"openid-connect")),
    TechnologyRule("PKCE", "Auth", "high", "code_challenge_method", (r"code_challenge_method=(?:S256|plain)", r"code_challenge=")),
    TechnologyRule("WSO2 Identity Server", "Auth", "high", "authenticationendpoint/commonauth", (r"/authenticationendpoint/", r"/commonauth", r"carbon\.super")),
    TechnologyRule("Keycloak/OIDC", "Auth", "high", "rotas Keycloak", (r"/auth/realms/", r"\bkeycloak\b")),
    TechnologyRule("Auth0/OIDC", "Auth", "high", "host/SDK Auth0", (r"auth0\.com", r"cdn\.auth0\.com")),
    TechnologyRule("Okta/OIDC", "Auth", "high", "host/SDK Okta", (r"okta\.com", r"okta-signin-widget")),
    TechnologyRule("SAML", "Auth", "high", "mensagem/rota SAML", (r"SAMLRequest", r"SAMLResponse", r"/saml")),
    TechnologyRule("Java/Jakarta", "Backend", "medium", "sessao/endpoint Java", (r"cookie:JSESSIONID", r"\.jsp(?:\?|$)", r"/authenticationendpoint/")),
    TechnologyRule("Spring Boot", "Backend", "high", "assinatura Spring Boot", (r"/actuator(?:/|$)", r"Whitelabel Error Page", r"x-application-context:")),
    TechnologyRule("PHP", "Backend", "high", "cabecalho/sessao PHP", (r"x-powered-by:\s*PHP", r"cookie:PHPSESSID")),
    TechnologyRule("Laravel", "Backend", "high", "sessao/cabecalho Laravel", (r"cookie:laravel_session", r"cookie:XSRF-TOKEN", r"x-laravel:")),
    TechnologyRule("ASP.NET", "Backend", "high", "assinatura ASP.NET", (r"ASP\.NET", r"__VIEWSTATE", r"cookie:ASP.NET_SessionId", r"x-aspnet")),
    TechnologyRule("Cloudflare", "Edge/CDN", "high", "cabecalhos Cloudflare", (r"server:\s*cloudflare", r"cf-ray:", r"/cdn-cgi/")),
    TechnologyRule("AWS ALB/ELB", "Edge/CDN", "high", "cookies AWSALB", (r"cookie:AWSALB(?:CORS)?", r"awselb")),
    TechnologyRule("AWS CloudFront", "Edge/CDN", "high", "cabecalhos CloudFront", (r"cloudfront", r"x-amz-cf-id:")),
    TechnologyRule("Akamai", "Edge/CDN", "high", "cabecalhos Akamai", (r"akamai", r"akamai-ghost")),
    TechnologyRule("Fastly", "Edge/CDN", "high", "cabecalhos Fastly", (r"server:\s*fastly", r"x-served-by:")),
    TechnologyRule("Varnish", "Proxy", "high", "cabecalhos Varnish", (r"server:\s*varnish", r"x-varnish:")),
    TechnologyRule("Nginx", "Web Server", "high", "cabecalho Server", (r"server:\s*nginx",)),
    TechnologyRule("Apache", "Web Server", "high", "cabecalho Server", (r"server:\s*Apache",)),
    TechnologyRule("IIS", "Web Server", "high", "cabecalho Server", (r"server:\s*Microsoft-IIS",)),
    TechnologyRule("Kong", "Proxy", "high", "cabecalhos Kong", (r"x-kong-upstream-latency", r"x-kong-proxy-latency")),
    TechnologyRule("Envoy", "Proxy", "high", "cabecalhos Envoy", (r"x-envoy-upstream-service-time", r"server:\s*envoy")),
    TechnologyRule("Firebase", "External Service", "high", "configuracao/host Firebase", (r"firebaseapp\.com", r"firebaseio\.com", r"firebaseConfig", r"firebase-config")),
    TechnologyRule("Service Worker/PWA", "Frontend", "high", "manifest/service worker", (r"serviceWorker", r"workbox", r"/service-worker\.js", r"manifest\.json")),
    TechnologyRule("Google Tag Manager", "Analytics", "high", "script Google Tag Manager", (r"googletagmanager\.com", r"GTM-[A-Z0-9]+")),
    TechnologyRule("Google Analytics", "Analytics", "medium", "script Google Analytics", (r"google-analytics\.com", r"\bgtag\(")),
    TechnologyRule("OneTrust", "Privacy", "high", "assets OneTrust", (r"onetrust", r"cookielaw\.org")),
    TechnologyRule("reCAPTCHA", "Security", "high", "integracao reCAPTCHA", (r"recaptcha", r"google\.com/recaptcha")),
    TechnologyRule("Sentry", "Observability", "high", "SDK/endpoint Sentry", (r"sentry", r"ingest\.sentry")),
    TechnologyRule("Datadog RUM", "Observability", "high", "SDK Datadog", (r"datadoghq-browser", r"datadoghq\.com")),
    TechnologyRule("New Relic", "Observability", "high", "agente New Relic", (r"newrelic", r"bam\.nr-data\.net")),
)

CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Endpoint:
    method: str
    scheme: str
    host: str
    port: str
    path: str
    query_params: tuple[str, ...]
    path_params: set[str]
    is_static: bool
    count: int = 0
    statuses: Counter[str] = field(default_factory=Counter)
    mimes: Counter[str] = field(default_factory=Counter)
    lengths: list[int] = field(default_factory=list)
    auth_hints: Counter[str] = field(default_factory=Counter)
    auth_evidence: set[str] = field(default_factory=set)
    categories: Counter[str] = field(default_factory=Counter)
    source_files: set[str] = field(default_factory=set)


@dataclass
class TechnologyEvidence:
    category: str
    confidence: str
    observations: int = 0
    hosts: set[str] = field(default_factory=set)
    evidence: set[str] = field(default_factory=set)
    versions: set[str] = field(default_factory=set)


def text_of(node: ET.Element | None) -> str:
    return (node.text or "") if node is not None else ""


def decode_blob(node: ET.Element | None, limit: int | None = None) -> str:
    if node is None:
        return ""
    raw = node.text or ""
    if node.attrib.get("base64") == "true":
        try:
            if limit is not None:
                encoded_limit = ((limit + 2) // 3) * 4 + 8
                raw = raw[:encoded_limit]
                raw = raw[: len(raw) - (len(raw) % 4)]
            data = base64.b64decode(raw, validate=False)
        except (ValueError, base64.binascii.Error):
            return ""
        if limit is not None:
            data = data[:limit]
        return data.decode("utf-8", errors="replace")
    return raw[:limit] if limit is not None else raw


def split_http_message(message: str) -> tuple[str, dict[str, list[str]], str]:
    head, separator, body = message.partition("\r\n\r\n")
    if not separator:
        head, _, body = message.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n") if head else []
    start = lines[0] if lines else ""
    headers: dict[str, list[str]] = defaultdict(list)
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()].append(value.strip())
    return start, headers, body


def cookie_names(request_headers: dict[str, list[str]]) -> set[str]:
    names: set[str] = set()
    for header in request_headers.get("cookie", []):
        for part in header.split(";"):
            name = part.strip().split("=", 1)[0].strip()
            if name:
                names.add(name)
    return names


def sanitize_text(value: str) -> str:
    value = JWT_RE.sub("[JWT_REDACTED]", value)
    value = BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED]", value)
    value = SENSITIVE_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}[REDACTED]", value)
    value = re.sub(r"(?i)(nonce-|script-nonce\s+)[A-Za-z0-9+/=_-]{8,}", r"\1[REDACTED]", value)
    return value


def normalize_segment(segment: str) -> tuple[str, str | None]:
    decoded = unquote(segment)
    if JWT_RE.fullmatch(decoded):
        return "{jwt}", "jwt"
    if UUID_RE.fullmatch(decoded):
        return "{uuid}", "uuid"
    if DOCUMENT_RE.fullmatch(decoded):
        return "{numeric_id}", "numeric_id"
    if HEX_ID_RE.fullmatch(decoded):
        return "{hex_id}", "hex_id"
    if OPAQUE_ID_RE.fullmatch(decoded) and any(ch.isdigit() for ch in decoded):
        return "{opaque_id}", "opaque_id"
    if "@" in decoded and "." in decoded:
        return "{email}", "email"
    return segment, None


def normalize_path(value: str) -> tuple[str, tuple[str, ...], set[str]]:
    parsed = urlsplit(value)
    raw_path = parsed.path or "/"
    parameters: set[str] = set()
    parts = []
    for segment in raw_path.split("/"):
        normalized, kind = normalize_segment(segment)
        parts.append(normalized)
        if kind:
            parameters.add(kind)
    path = "/".join(parts) or "/"
    if raw_path.startswith("/") and not path.startswith("/"):
        path = "/" + path
    query_names = tuple(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
    return path, query_names, parameters


def endpoint_display(path: str, query_names: Iterable[str]) -> str:
    names = sorted(set(query_names))
    if not names:
        return path
    return path + "?" + "&".join(f"{quote(name, safe='._-')}={{value}}" for name in names)


def sanitize_url(value: str, base: str | None = None) -> str:
    absolute = urljoin(base, value) if base else value
    parsed = urlsplit(absolute)
    path, query_names, _ = normalize_path(absolute)
    query = "&".join(
        f"{quote(name, safe='._-')}={'[REDACTED]' if SENSITIVE_QUERY_NAMES.search(name) else '{value}'}"
        for name in query_names
    )
    return urlunsplit((parsed.scheme, parsed.netloc, path, query, ""))


def route_parts(value: str, base: str | None = None) -> tuple[str, str]:
    absolute = urljoin(base, value) if base else value
    parsed = urlsplit(absolute)
    path, query_names, _ = normalize_path(absolute)
    return parsed.netloc, endpoint_display(path, query_names)


def attrs_from_tag(tag_attrs: str) -> dict[str, str]:
    return {m.group(1).lower(): m.group(3).strip() for m in ATTR_RE.finditer(tag_attrs or "")}


def cookie_flags(set_cookie: str) -> dict[str, Any]:
    parts = [part.strip() for part in set_cookie.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    flags = {part.lower(): True for part in parts[1:] if "=" not in part}
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attributes[key.lower()] = value
    return {
        "name": name,
        "secure": bool(flags.get("secure")),
        "httponly": bool(flags.get("httponly")),
        "samesite": attributes.get("samesite", ""),
        "path": attributes.get("path", ""),
        "domain": attributes.get("domain", ""),
        "partitioned": bool(flags.get("partitioned")),
    }


def safe_header_value(name: str, value: str) -> str:
    lower = name.lower()
    if lower == "set-cookie":
        cookie = cookie_flags(value)
        flags = [flag for flag in ("Secure" if cookie["secure"] else "", "HttpOnly" if cookie["httponly"] else "", f"SameSite={cookie['samesite']}" if cookie["samesite"] else "") if flag]
        return f"{cookie['name']} ([value redacted]{'; ' if flags else ''}{'; '.join(flags)})"
    if lower == "location":
        return sanitize_url(value)
    if lower in {"x-amz-cf-id"}:
        return "[REDACTED]"
    return sanitize_text(value)


def auth_evidence(request_headers: dict[str, list[str]]) -> set[str]:
    evidence: set[str] = set()
    authorization = " ".join(request_headers.get("authorization", []))
    if authorization:
        scheme = authorization.split(None, 1)[0] if authorization.split() else "Authorization"
        evidence.add(f"Authorization:{scheme}")
    for header in ("id_token", "x-api-key", "api-key", "x-2fatoken", "fnp", "auth_type"):
        if header in request_headers:
            evidence.add(f"header:{header}")
    for name in cookie_names(request_headers):
        if re.search(r"(?i)(session|auth|token|jwt|jsession|commonAuth|opbs)", name):
            evidence.add(f"cookie:{name}")
    return evidence


def infer_auth(request_headers: dict[str, list[str]], path: str) -> tuple[str, set[str]]:
    evidence = auth_evidence(request_headers)
    if evidence:
        return "yes", evidence
    if re.search(
        r"(?i)(/admin|/account|/profile|/me(?:/|$)|/user|/dashboard|/minha-conta|/checkout|"
        r"/order|/pedidos|/sso|/oauth|/saml|/oidc|/api/auth|/graphql|/cards?|/balance|/statement|/transactions?)",
        path,
    ):
        return "maybe", evidence
    return "no", evidence


def classify_endpoint(path: str, mime: str, method: str) -> str:
    lower = urlparse(path).path.lower()
    if STATIC_RE.search(path):
        return "static"
    if "/graphql" in lower:
        return "graphql"
    if re.search(r"(?i)(openapi|swagger|api-docs)", path):
        return "api-docs"
    if re.search(r"(?i)(/authenticationendpoint|/commonauth|/auth(?:/|$)|/oauth|/saml|/oidc|/login|/logout|/signin|/signup|/register|/token|/session|/callback|/sso)", lower):
        return "auth"
    if re.search(r"(?i)(/admin|/dashboard|/console|/manage)", lower):
        return "admin"
    if re.search(r"(?i)(?:^|/)(?:config|auth-config|firebase-config|api-url|manifest|\.well-known)(?:[./_-]|/|$)", lower):
        return "configuration"
    if re.search(r"(?i)(/api(?:-s)?/|/rest/|/v\d+(?:/|$))", lower) or "json" in mime.lower():
        return "api"
    if re.search(r"(?i)(/upload|/import)", lower) or method.upper() in {"PUT", "PATCH", "DELETE"}:
        return "state-changing"
    if "html" in mime.lower() or lower in {"/", ""}:
        return "page"
    return "other"


def service_for(path: str, category: str) -> tuple[str, str]:
    clean_path = urlsplit(path).path or "/"
    segments = [segment for segment in clean_path.split("/") if segment]
    if category == "static":
        prefix = "/" + "/".join(segments[:2]) if segments else "/"
        return "Static assets", prefix
    if clean_path.startswith("/api-s/") and len(segments) >= 2:
        end = 3 if len(segments) >= 3 and re.fullmatch(r"v\d+", segments[2], re.I) else 2
        prefix = "/" + "/".join(segments[:end])
        return segments[1], prefix
    if clean_path.startswith("/api/") and len(segments) >= 2:
        end = 3 if len(segments) >= 3 and re.fullmatch(r"v\d+", segments[2], re.I) else 2
        prefix = "/" + "/".join(segments[:end])
        return segments[1], prefix
    if category == "graphql":
        return "GraphQL", clean_path
    if clean_path.startswith("/oauth2/"):
        return "OAuth 2.0 / OIDC", "/oauth2"
    if clean_path.startswith("/authenticationendpoint/") or clean_path in {"/commonauth", "/logincontext"}:
        return "Identity / Login", "/authenticationendpoint"
    if category == "auth":
        return "Authentication", "/" + segments[0] if segments else "/"
    if category in {"api-docs", "admin", "state-changing"}:
        return category.replace("-", " ").title(), "/" + segments[0] if segments else "/"
    if category == "page":
        return "Web pages", "/"
    if category == "configuration" or re.search(r"(?i)(config|manifest|\.well-known)", clean_path):
        return "Public configuration", "/"
    return "Other", "/" + segments[0] if segments else "/"


def detect_technologies(
    path: str,
    response_headers: dict[str, list[str]],
    body_sample: str,
    request_cookie_names: set[str],
    response_cookie_names: set[str],
) -> dict[str, tuple[str, str, str, set[str]]]:
    header_lines = []
    for key, values in response_headers.items():
        if key == "set-cookie":
            continue
        for value in values:
            header_lines.append(f"{key}: {value}")
    cookie_lines = [f"cookie:{name}" for name in sorted(request_cookie_names | response_cookie_names)]
    haystack = "\n".join([path, "\n".join(header_lines), "\n".join(cookie_lines), body_sample[:200_000]])
    found: dict[str, tuple[str, str, str, set[str]]] = {}
    for rule in TECH_RULES:
        if any(re.search(pattern, haystack, re.I) for pattern in rule.patterns):
            versions: set[str] = set()
            if rule.name == "PHP":
                versions.update(re.findall(r"(?i)x-powered-by:\s*PHP/?([0-9][0-9.]*)", haystack))
            elif rule.name == "jQuery":
                versions.update(re.findall(r"(?i)jquery[-.]([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js", haystack))
            elif rule.name == "Bootstrap":
                versions.update(re.findall(r"(?i)bootstrap(?:\.bundle)?[-.]([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.(?:js|css)", haystack))
                versions.update(re.findall(r"(?i)/bootstrap/([0-9]+(?:\.[0-9]+){1,3})/", haystack))
            found[rule.name] = (rule.category, rule.confidence, rule.evidence, versions)
    if "Create React App" in found and "React" not in found:
        found["React"] = ("Frontend", "medium", "Create React App observado", set())
    return found


def extract_forms(body: str, host: str, page_path: str, page_url: str) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    rows: list[dict[str, Any]] = []
    edges: list[tuple[str, str]] = []
    for match in FORM_RE.finditer(body[:300_000]):
        attributes = attrs_from_tag(match.group("form_attrs"))
        fields = []
        for field_match in INPUT_RE.finditer(match.group("body")):
            field_attributes = attrs_from_tag(field_match.group(1))
            name = field_attributes.get("name") or field_attributes.get("id")
            if name:
                fields.append(name)
        raw_action = attributes.get("action") or page_url
        action_url = urljoin(page_url, raw_action)
        action_host, action_path = route_parts(action_url)
        safe_action = f"https://{action_host}{action_path}" if action_host and action_host != host else action_path
        rows.append({
            "host": host, "page": page_path, "method": (attributes.get("method") or "GET").upper(),
            "action": safe_action, "field_count": len(set(fields)), "fields": ", ".join(sorted(set(fields))[:80]),
        })
        edges.append((page_url, action_url))
    return rows, edges


def extract_links(body: str, page_url: str, limit: int = 250) -> list[str]:
    links: list[str] = []
    seen: set[str] = set()
    for match in ANCHOR_RE.finditer(body[:400_000]):
        href = attrs_from_tag(match.group(1)).get("href", "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        absolute = urljoin(page_url, href)
        parsed = urlsplit(absolute)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if STATIC_RE.search(parsed.path):
            continue
        safe = sanitize_url(absolute)
        if safe not in seen:
            seen.add(safe)
            links.append(absolute)
        if len(links) >= limit:
            break
    return links


def extract_api_hints(path: str, request_body: str, response_body: str) -> set[str]:
    hints: set[str] = set()
    lower = path.lower()
    if "/graphql" in lower:
        hints.add("graphql-endpoint")
    if re.search(r"(?i)(swagger|openapi|api-docs)", path + response_body[:20_000]):
        hints.add("openapi-or-swagger")
    if request_body.lstrip().startswith(("{", "[")) or response_body.lstrip().startswith(("{", "[")):
        hints.add("json-api")
    if re.search(r"(?i)\b(page|limit|offset|cursor|sort|filter|q|search|period)\b", path):
        hints.add("pagination-or-filter-params")
    keys = set(JSON_KEY_RE.findall(request_body[:50_000] + "\n" + response_body[:80_000]))
    interesting = sorted(key for key in keys if re.search(r"(?i)(id|uuid|email|role|status|price|amount|balance|token|csrf|user|admin|order|cart|payment|card|transaction)", key))
    hints.update(f"json-key:{key}" for key in interesting[:40])
    return hints


def extract_graphql_operations(request_body: str, response_body: str) -> set[str]:
    operations = set(GRAPHQL_OP_RE.findall(request_body))
    try:
        payload = json.loads(request_body)
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("operationName"):
                operations.add(str(item["operationName"]))
            query = item.get("query")
            if isinstance(query, str):
                operations.update(GRAPHQL_OP_RE.findall(query))
    except (ValueError, TypeError):
        pass
    operations.update(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*(?:Query|Mutation|V\d+)?)"', response_body[:20_000]))
    return {operation for operation in operations if len(operation) <= 80}


def extract_next_runtime_config(body_sample: str) -> dict[str, Any]:
    match = NEXT_DATA_RE.search(body_sample)
    if not match:
        return {}
    try:
        data = json.loads(match.group(1))
    except (ValueError, TypeError):
        return {}
    config = data.get("runtimeConfig") or {}
    safe: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, str):
            safe[key] = sanitize_url(value) if value.startswith(("http://", "https://")) else "[configured]"
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[key] = value
        elif isinstance(value, dict):
            safe[key] = {nested_key: "[configured]" for nested_key in value}
    return safe


def iter_items(files: Iterable[Path]) -> Iterable[tuple[Path, int, ET.Element]]:
    for source in files:
        item_number = 0
        try:
            context = ET.iterparse(source, events=("end",))
            for _, element in context:
                if element.tag == "item":
                    item_number += 1
                    yield source, item_number, element
                    element.clear()
        except (ET.ParseError, OSError) as exc:
            print(f"[warn] Nao foi possivel ler {source}: {exc}", file=sys.stderr)


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def choose_category(categories: Counter[str]) -> str:
    priority = ["admin", "auth", "graphql", "api-docs", "state-changing", "api", "page", "configuration", "other", "static"]
    for category in priority:
        if categories.get(category):
            return category
    return categories.most_common(1)[0][0] if categories else "other"


def choose_auth(hints: Counter[str]) -> str:
    for value in ("yes", "maybe", "no"):
        if hints.get(value):
            return value
    return "no"


def format_counter(counter: Counter[str]) -> str:
    return ", ".join(f"{key}:{count}" for key, count in sorted(counter.items()) if key)


def roles_for_host(categories: Counter[str]) -> list[str]:
    roles: list[str] = []
    if categories.get("page") or categories.get("static"):
        roles.append("web-frontend")
    if categories.get("auth"):
        roles.append("identity-provider")
    if categories.get("api") or categories.get("graphql"):
        roles.append("api/gateway")
    if categories.get("api-docs"):
        roles.append("api-documentation")
    return roles or ["web-service"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Mapeia arquitetura, tecnologias, fluxos e endpoints a partir de XML do Burp Suite.")
    parser.add_argument("files", nargs="+", type=Path, help="Arquivos XML exportados pelo Burp")
    parser.add_argument("-o", "--out", type=Path, default=Path("burp-recon-output"), help="Diretorio de saida")
    parser.add_argument("--include-static", action="store_true", help="Inclui assets estaticos em endpoints.csv")
    parser.add_argument("--body-sample-bytes", type=int, default=240_000, help="Bytes de cada resposta usados apenas para deteccao")
    parser.add_argument("--project-name", default="Burp Recon", help="Nome exibido nos relatorios")
    args = parser.parse_args()

    missing = [str(path) for path in args.files if not path.is_file()]
    if missing:
        parser.error("arquivo(s) inexistente(s): " + ", ".join(missing))
    if args.body_sample_bytes < 8_192:
        parser.error("--body-sample-bytes deve ser pelo menos 8192")

    args.out.mkdir(parents=True, exist_ok=True)

    endpoints: dict[tuple[str, str, str, tuple[str, ...]], Endpoint] = {}
    params: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    security: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    cookies: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    redirects: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    api_hints: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    interesting_paths: Counter[str] = Counter()
    graphql_ops: Counter[str] = Counter()
    technologies: dict[str, TechnologyEvidence] = {}
    third_party: Counter[tuple[str, str]] = Counter()
    runtime_configs: dict[str, dict[str, Any]] = {}
    configurations: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: {"keys": set(), "referenced_hosts": set()})
    findings: Counter[str] = Counter()
    finding_rows: dict[tuple[str, str, str], dict[str, str]] = {}
    status_counts: Counter[str] = Counter()
    mime_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    host_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "ips": set(), "schemes": set(), "ports": set(), "items": 0,
        "statuses": Counter(), "categories": Counter(), "sources": set(),
    })
    flow_data: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    request_rows: list[dict[str, Any]] = []

    def add_finding(host: str, path: str, name: str, severity: str, evidence: str) -> None:
        findings[name] += 1
        finding_rows[(host, path, name)] = {"host": host, "path": path, "severity": severity, "finding": name, "evidence": evidence}

    def add_flow(
        source_url: str, target_url: str, relation: str, source_file: str, method: str = "", status: str = "",
        observed: bool = True, base: str | None = None,
    ) -> None:
        source_host, source_path = route_parts(source_url, base)
        target_host, target_path = route_parts(target_url, base or source_url)
        if not source_host or not target_host or (source_host == target_host and source_path == target_path):
            return
        key = (source_host, source_path, target_host, target_path, relation)
        row = flow_data.setdefault(key, {
            "source_host": source_host, "source_path": source_path, "target_host": target_host, "target_path": target_path,
            "relation": relation, "count": 0, "methods": set(), "statuses": set(),
            "observed": "yes" if observed else "no", "source_files": set(),
        })
        row["count"] += 1
        if method:
            row["methods"].add(method)
        if status:
            row["statuses"].add(status)
        row["source_files"].add(source_file)
        if observed:
            row["observed"] = "yes"

    total = 0
    for source, sequence, item in iter_items(args.files):
        total += 1
        source_name = source.name
        time_value = text_of(item.find("time"))
        url = text_of(item.find("url"))
        host_node = item.find("host")
        host = text_of(host_node)
        ip = host_node.attrib.get("ip", "") if host_node is not None else ""
        port = text_of(item.find("port"))
        scheme = text_of(item.find("protocol")) or urlsplit(url).scheme
        method = (text_of(item.find("method")) or "GET").upper()
        raw_path = text_of(item.find("path")) or urlparse(url).path or "/"
        status = text_of(item.find("status"))
        mime = text_of(item.find("mimetype"))
        try:
            length = int(text_of(item.find("responselength")) or 0)
        except ValueError:
            length = 0

        request_text = decode_blob(item.find("request"), limit=96_000)
        response_text = decode_blob(item.find("response"), limit=args.body_sample_bytes)
        _, request_headers, request_body = split_http_message(request_text)
        _, response_headers, response_body = split_http_message(response_text)

        path, query_names, path_parameters = normalize_path(raw_path)
        display_path = endpoint_display(path, query_names)
        static = bool(STATIC_RE.search(raw_path))
        auth_hint, endpoint_auth_evidence = infer_auth(request_headers, raw_path)
        category = classify_endpoint(raw_path, mime, method)
        endpoint_key = (method, host, path, query_names)
        endpoint = endpoints.get(endpoint_key)
        if endpoint is None:
            endpoint = Endpoint(method, scheme, host, port, path, query_names, set(path_parameters), static)
            endpoints[endpoint_key] = endpoint
        endpoint.count += 1
        endpoint.path_params.update(path_parameters)
        endpoint.statuses[status] += 1
        endpoint.mimes[mime] += 1
        endpoint.lengths.append(length)
        endpoint.auth_hints[auth_hint] += 1
        endpoint.auth_evidence.update(endpoint_auth_evidence)
        endpoint.categories[category] += 1
        endpoint.source_files.add(source_name)

        status_counts[status] += 1
        mime_counts[mime] += 1
        category_counts[category] += 1
        params[(host, method, path)].update(query_names)

        stats = host_stats[host]
        if ip:
            stats["ips"].add(ip)
        if scheme:
            stats["schemes"].add(scheme)
        if port:
            stats["ports"].add(port)
        stats["items"] += 1
        stats["statuses"][status] += 1
        stats["categories"][category] += 1
        stats["sources"].add(source_name)

        response_cookie_names: set[str] = set()
        for value in response_headers.get("set-cookie", []):
            cookie = cookie_flags(value)
            name = cookie["name"]
            if name:
                response_cookie_names.add(name)
                cookies[host][name][json.dumps(cookie, sort_keys=True)] += 1

        detected = detect_technologies(raw_path, response_headers, response_body, cookie_names(request_headers), response_cookie_names)
        for name, (tech_category, confidence, evidence, versions) in detected.items():
            current = technologies.get(name)
            if current is None:
                current = TechnologyEvidence(tech_category, confidence)
                technologies[name] = current
            elif CONFIDENCE_ORDER[confidence] > CONFIDENCE_ORDER[current.confidence]:
                current.confidence = confidence
            current.observations += 1
            current.hosts.add(host)
            current.evidence.add(evidence)
            current.versions.update(version for version in versions if version)

        for header in SECURITY_HEADERS:
            for value in response_headers.get(header, []):
                security[host][header][safe_header_value(header, value)] += 1

        referer = (request_headers.get("referer") or [""])[0]
        origin = (request_headers.get("origin") or [""])[0]
        referer_host, referer_path = route_parts(referer) if referer else ("", "")
        request_rows.append({
            "source_file": source_name, "sequence": sequence, "time": time_value, "method": method, "scheme": scheme,
            "host": host, "path": display_path, "status": status, "type": mime, "category": category,
            "auth_hint": auth_hint, "referer_host": referer_host, "referer_path": referer_path,
        })

        if referer and not static:
            add_flow(referer, url, "referer", source_name, method, status, observed=True)
        if origin and not static and urlsplit(origin).netloc != host:
            add_flow(origin, url, "origin-request", source_name, method, status, observed=True)

        if status.startswith("3") and response_headers.get("location"):
            target_url = urljoin(url, response_headers["location"][0])
            redirects.append({"method": method, "host": host, "path": display_path, "status": status, "location": sanitize_url(target_url), "source_file": source_name})
            add_flow(url, target_url, "redirect", source_name, method, status, observed=True)

        if "/oauth2/authorize" in raw_path:
            for target in parse_qs(urlsplit(raw_path).query).get("redirect_uri", [])[:1]:
                add_flow(url, target, "oauth-callback", source_name, method, status, observed=False)

        is_html = "html" in mime.lower() or response_body.lstrip().lower().startswith(("<!doctype", "<html"))
        if is_html:
            extracted_forms, form_edges = extract_forms(response_body, host, display_path, url)
            forms.extend(extracted_forms)
            for source_url, action_url in form_edges:
                add_flow(source_url, action_url, "form-submit", source_name, observed=False)
            for target_url in extract_links(response_body, url):
                add_flow(url, target_url, "html-link", source_name, observed=False)

        for hint in extract_api_hints(raw_path, request_body, response_body):
            api_hints[(host, method, path)].add(hint)
        if "/graphql" in raw_path.lower():
            for operation in extract_graphql_operations(request_body, response_body):
                graphql_ops[operation] += 1

        next_config = extract_next_runtime_config(response_body)
        if next_config:
            runtime_configs[host] = next_config

        if re.search(r"(?i)(?:^|/)(?:config|auth-config|firebase-config|api-url|manifest|\.well-known)(?:[./_-]|/|$)", path):
            config = configurations[(host, path)]
            config["keys"].update(JSON_KEY_RE.findall(response_body[:120_000]))
            for found_url in URL_RE.findall(response_body[:120_000]):
                referenced = urlsplit(found_url.rstrip("),.;")).netloc
                if referenced and referenced != host:
                    config["referenced_hosts"].add(referenced)

        for found_url in URL_RE.findall(response_body[:120_000]):
            referenced = urlsplit(found_url.rstrip("),.;")).netloc
            if referenced and referenced != host:
                third_party[(host, referenced)] += 1

        if is_html and "content-security-policy" not in response_headers:
            add_finding(host, display_path, "Missing Content-Security-Policy on HTML response", "medium", "HTML sem CSP")
        if url.startswith("https://") and "strict-transport-security" not in response_headers:
            add_finding(host, display_path, "Missing HSTS on HTTPS response", "low", "HTTPS sem Strict-Transport-Security")
        cors_origins = response_headers.get("access-control-allow-origin", [])
        if "*" in cors_origins:
            severity = "high" if "true" in [value.lower() for value in response_headers.get("access-control-allow-credentials", [])] else "medium"
            add_finding(host, display_path, "CORS wildcard Access-Control-Allow-Origin", severity, "Access-Control-Allow-Origin: *")
        if "x-powered-by" in response_headers:
            add_finding(host, display_path, "Technology disclosure via X-Powered-By", "info", "X-Powered-By presente")
        for value in response_headers.get("set-cookie", []):
            cookie = cookie_flags(value)
            if not cookie["secure"]:
                add_finding(host, display_path, "Cookie without Secure flag", "medium", f"cookie:{cookie['name']}")
            if not cookie["httponly"]:
                add_finding(host, display_path, "Cookie without HttpOnly flag", "low", f"cookie:{cookie['name']}")
            if not cookie["samesite"]:
                add_finding(host, display_path, "Cookie without SameSite attribute", "low", f"cookie:{cookie['name']}")
        if JWT_RE.search(response_body):
            add_finding(host, display_path, "JWT-like token present in response body", "info", "valor removido do relatorio")
        if INTERESTING_PATH_RE.search(raw_path):
            interesting_paths[display_path] += 1
        if category == "api-docs" and status.startswith("2"):
            add_finding(host, display_path, "API documentation endpoint reachable", "info", status)
        if category == "admin" and status.startswith("2"):
            add_finding(host, display_path, "Administrative-looking endpoint reachable", "medium", status)
        if method in {"PUT", "PATCH", "DELETE"} and status.startswith("2"):
            add_finding(host, display_path, "State-changing HTTP method returned success", "info", f"{method} {status}")

    if total == 0:
        print("[error] Nenhum item Burp valido foi encontrado.", file=sys.stderr)
        return 2

    endpoint_rows: list[dict[str, Any]] = []
    for endpoint in endpoints.values():
        if endpoint.is_static and not args.include_static:
            continue
        category = choose_category(endpoint.categories)
        service, service_prefix = service_for(endpoint.path, category)
        endpoint_rows.append({
            "method": endpoint.method, "scheme": endpoint.scheme, "host": endpoint.host, "port": endpoint.port,
            "path": endpoint_display(endpoint.path, endpoint.query_params), "service": service, "service_prefix": service_prefix,
            "status": ",".join(sorted(value for value in endpoint.statuses if value)), "status_counts": format_counter(endpoint.statuses),
            "type": endpoint.mimes.most_common(1)[0][0] if endpoint.mimes else "", "max_length": max(endpoint.lengths, default=0),
            "count": endpoint.count, "auth_hint": choose_auth(endpoint.auth_hints),
            "auth_evidence": ", ".join(sorted(endpoint.auth_evidence)), "static": endpoint.is_static, "category": category,
            "query_params": ", ".join(endpoint.query_params), "path_parameters": ", ".join(sorted(endpoint.path_params)),
            "source_files": ", ".join(sorted(endpoint.source_files)), "notes": "; ".join(sorted(endpoint.categories)),
        })
    endpoint_rows.sort(key=lambda row: (row["host"], row["service"], row["path"], row["method"]))
    write_csv(args.out / "endpoints.csv", endpoint_rows, [
        "method", "scheme", "host", "port", "path", "service", "service_prefix", "status", "status_counts",
        "type", "max_length", "count", "auth_hint", "auth_evidence", "static", "category", "query_params",
        "path_parameters", "source_files", "notes",
    ])

    service_groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in endpoint_rows:
        key = (row["host"], row["service"], row["service_prefix"], row["category"])
        group = service_groups.setdefault(key, {"methods": set(), "statuses": set(), "auth": set(), "endpoints": 0})
        group["methods"].add(row["method"])
        group["statuses"].update(value for value in row["status"].split(",") if value)
        group["auth"].add(row["auth_hint"])
        group["endpoints"] += 1
    service_rows = [
        {
            "host": host, "service": service, "prefix": prefix, "category": category,
            "endpoint_count": data["endpoints"], "methods": ", ".join(sorted(data["methods"])),
            "auth": "yes" if "yes" in data["auth"] else ("maybe" if "maybe" in data["auth"] else "no"),
            "statuses": ", ".join(sorted(data["statuses"])),
        }
        for (host, service, prefix, category), data in sorted(service_groups.items())
    ]
    write_csv(args.out / "services.csv", service_rows, ["host", "service", "prefix", "category", "endpoint_count", "methods", "auth", "statuses"])

    technology_rows = []
    for name, data in sorted(technologies.items(), key=lambda item: (-item[1].observations, item[0].lower())):
        technology_rows.append({
            "technology": name, "category": data.category, "confidence": data.confidence,
            "versions": ", ".join(sorted(data.versions)), "observations": data.observations, "count": data.observations,
            "hosts": ", ".join(sorted(data.hosts)), "evidence": "; ".join(sorted(data.evidence)),
        })
    write_csv(args.out / "technologies.csv", technology_rows, ["technology", "category", "confidence", "versions", "observations", "count", "hosts", "evidence"])

    host_rows = []
    for host, stats in sorted(host_stats.items()):
        host_technologies = [name for name, data in technologies.items() if host in data.hosts]
        host_rows.append({
            "host": host, "ips": ", ".join(sorted(stats["ips"])), "schemes": ", ".join(sorted(stats["schemes"])),
            "ports": ", ".join(sorted(stats["ports"])), "items": stats["items"],
            "roles": ", ".join(roles_for_host(stats["categories"])), "technologies": ", ".join(sorted(host_technologies)),
            "statuses": format_counter(stats["statuses"]), "categories": format_counter(stats["categories"]),
            "source_files": ", ".join(sorted(stats["sources"])),
        })
    write_csv(args.out / "hosts.csv", host_rows, ["host", "ips", "schemes", "ports", "items", "roles", "technologies", "statuses", "categories", "source_files"])

    flow_rows = []
    for row in flow_data.values():
        flow_rows.append({
            **{key: row[key] for key in ("source_host", "source_path", "target_host", "target_path", "relation", "count", "observed")},
            "methods": ", ".join(sorted(row["methods"])), "statuses": ", ".join(sorted(row["statuses"])),
            "source_files": ", ".join(sorted(row["source_files"])),
        })
    relation_priority = {"redirect": 0, "oauth-callback": 1, "form-submit": 2, "origin-request": 3, "referer": 4, "html-link": 5}
    flow_rows.sort(key=lambda row: (relation_priority.get(row["relation"], 9), row["source_host"], row["source_path"], row["target_host"], row["target_path"]))
    write_csv(args.out / "flows.csv", flow_rows, ["source_host", "source_path", "target_host", "target_path", "relation", "methods", "statuses", "count", "observed", "source_files"])

    write_csv(args.out / "requests.csv", request_rows, [
        "source_file", "sequence", "time", "method", "scheme", "host", "path", "status", "type", "category", "auth_hint", "referer_host", "referer_path"
    ])
    write_csv(args.out / "params.csv", [
        {"host": host, "method": method, "path": path, "params": ", ".join(sorted(values))}
        for (host, method, path), values in sorted(params.items()) if values
    ], ["host", "method", "path", "params"])

    security_rows = []
    for host, headers in sorted(security.items()):
        for header, values in sorted(headers.items()):
            security_rows.append({"host": host, "header": header, "values": " | ".join(values.keys()), "observations": sum(values.values())})
    write_csv(args.out / "security_headers.csv", security_rows, ["host", "header", "values", "observations"])

    cookie_rows = []
    for host, names in sorted(cookies.items()):
        for name, variants in sorted(names.items()):
            sample = json.loads(next(iter(variants.keys())))
            cookie_rows.append({"host": host, **sample, "observations": sum(variants.values())})
    write_csv(args.out / "cookies.csv", cookie_rows, ["host", "name", "secure", "httponly", "samesite", "path", "domain", "partitioned", "observations"])

    write_csv(args.out / "redirects.csv", redirects, ["method", "host", "path", "status", "location", "source_file"])
    write_csv(args.out / "graphql_operations.csv", [{"operation": operation, "count": count} for operation, count in graphql_ops.most_common()], ["operation", "count"])
    write_csv(args.out / "third_party_hosts.csv", [
        {"source_host": source_host, "host": target_host, "count": count}
        for (source_host, target_host), count in third_party.most_common()
    ], ["source_host", "host", "count"])
    write_csv(args.out / "forms.csv", forms, ["host", "page", "method", "action", "field_count", "fields"])
    write_csv(args.out / "api_hints.csv", [
        {"host": host, "method": method, "path": path, "hints": ", ".join(sorted(values))}
        for (host, method, path), values in sorted(api_hints.items()) if values
    ], ["host", "method", "path", "hints"])
    write_csv(args.out / "interesting_paths.csv", [{"path": path, "count": count} for path, count in interesting_paths.most_common()], ["path", "count"])
    write_csv(args.out / "configurations.csv", [
        {"host": host, "path": path, "keys": ", ".join(sorted(data["keys"])), "referenced_hosts": ", ".join(sorted(data["referenced_hosts"]))}
        for (host, path), data in sorted(configurations.items())
    ], ["host", "path", "keys", "referenced_hosts"])
    write_csv(args.out / "findings.csv", sorted(finding_rows.values(), key=lambda row: (row["severity"], row["host"], row["path"], row["finding"])), ["host", "path", "severity", "finding", "evidence"])

    summary = {
        "schema_version": 2, "project_name": args.project_name, "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_files": [path.name for path in args.files], "total_items": total, "hosts_count": len(host_rows),
        "hosts": {row["host"]: {"roles": row["roles"].split(", "), "items": row["items"]} for row in host_rows},
        "unique_endpoints_non_static": len([endpoint for endpoint in endpoints.values() if not endpoint.is_static]),
        "unique_endpoints_output": len(endpoint_rows), "unique_endpoints_all": len(endpoints),
        "services_count": len(service_rows), "flows_count": len(flow_rows), "status_counts": dict(status_counts),
        "mime_counts": dict(mime_counts), "category_counts": dict(category_counts),
        "technologies": {row["technology"]: row["observations"] for row in technology_rows},
        "technology_details": technology_rows, "findings": dict(findings.most_common()),
        "interesting_paths_count": len(interesting_paths), "forms_count": len(forms), "runtime_configs": runtime_configs,
        "output_hash": hashlib.sha256(json.dumps(endpoint_rows, sort_keys=True).encode()).hexdigest()[:16],
        "privacy": {"request_response_bodies_exported": False, "cookie_values_exported": False, "query_values_exported": False, "dynamic_path_identifiers_normalized": True},
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    endpoint_md = [f"# Mapa de endpoints — {args.project_name}", ""]
    grouped_endpoints: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in endpoint_rows:
        grouped_endpoints[(row["host"], row["service"])].append(row)
    for (host, service), rows in sorted(grouped_endpoints.items()):
        endpoint_md.extend([f"## {host} — {service}", ""])
        for row in rows:
            auth_label = "auth" if row["auth_hint"] == "yes" else row["auth_hint"]
            endpoint_md.append(f"- `{row['method']} {row['path']}` → `{row['status'] or 'sem resposta'}` · {row['category']} · {auth_label}")
        endpoint_md.append("")
    (args.out / "ENDPOINTS.md").write_text("\n".join(endpoint_md), encoding="utf-8")

    markdown = [
        f"# {args.project_name}", "", f"- Itens Burp processados: {total}", f"- Hosts observados: {len(host_rows)}",
        f"- Endpoints nao estaticos: {summary['unique_endpoints_non_static']}", f"- Servicos/grupos: {len(service_rows)}",
        f"- Relacoes de fluxo: {len(flow_rows)}", "", "## Hosts e papeis",
        *[f"- {row['host']}: {row['roles']} ({row['items']} itens)" for row in host_rows], "", "## Tecnologias detectadas",
        *[
            f"- {row['technology']} — {row['category']}, confianca {row['confidence']}" + (f", versao {row['versions']}" if row["versions"] else "")
            for row in technology_rows
        ], "", "## Arquivos principais",
        "- `endpoints.csv` e `ENDPOINTS.md`: inventario normalizado de endpoints",
        "- `services.csv`: agrupamento funcional dos endpoints",
        "- `hosts.csv`: hosts, papeis e tecnologias",
        "- `flows.csv`: redirects, referers, forms e links observados/descobertos",
        "- `technologies.csv`: tecnologias, confianca, versoes e evidencias",
        "- `requests.csv`: sequencia sanitizada por arquivo de captura",
        "- `security_headers.csv`, `cookies.csv` e `findings.csv`: postura HTTP sem valores secretos",
        "- `configurations.csv`: chaves e hosts referenciados por configuracoes publicas",
        "- `summary.json`: resumo para automacao e para o gerador draw.io", "", "## Privacidade",
        "- Bodies completos, senhas, tokens e valores de cookies nao sao exportados.",
        "- Valores de query string sao substituidos por placeholders.",
        "- UUIDs, JWTs e identificadores opacos em segmentos de URL sao normalizados.",
        "- Os achados sao heuristicas de recon e precisam de validacao manual.",
    ]
    (args.out / "README.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")

    print(f"Relatorio salvo em {args.out}")
    print(f"Itens: {total} | hosts: {len(host_rows)} | endpoints nao estaticos: {summary['unique_endpoints_non_static']} | fluxos: {len(flow_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
