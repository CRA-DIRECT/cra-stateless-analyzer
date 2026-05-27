# Stateless Analyze API — API-as-a-Service

The Stateless Analyze API provides ephemeral, zero-persistence vulnerability scanning and AI-powered CRA (Cyber Resilience Act) triage. Send an SBOM or a list of Package URLs (PURLs), get vulnerability findings back. Send those findings to the AI triage endpoint, get a regulatory decision. No SBOMs, scan results, vulnerability details, PURLs, or triage decisions are stored; only service-key metadata and aggregate usage counters are retained for authentication, abuse control, and billing. The API is a compute layer over live vulnerability intelligence.

**Base URL:** `https://api.example.com` (placeholder — configure your deployment)

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Rate Limiting](#rate-limiting)
4. [Common Response Envelope](#common-response-envelope)
5. [Endpoints](#endpoints)
   - [POST /scan-sbom](#post-scan-sbom) — Full SBOM scan
   - [POST /scan-purls](#post-scan-purls) — PURL batch scan
   - [POST /triage-stateless](#post-triage-stateless) — AI CRA triage
   - [GET /scanner/health](#get-scannerhealth) — Scanner upstream readiness
6. [Error Codes](#error-codes)
7. [Client Examples](#client-examples)
8. [Architecture & Limits](#architecture--limits)
9. [API-as-a-Service Readiness](#api-as-a-service-readiness)

---

## Overview

The Stateless Analyze API is designed for CI/CD pipelines, security tooling, and compliance workflows that need vulnerability intelligence and AI triage without the overhead of managing stored SBOMs, databases, or long-running jobs. Every request is self-contained: you send the data, the API queries live vulnerability sources (OSV, FIRST EPSS, CISA KEV), optionally runs an AI triage, and returns the result.

### What "Stateless" Means

| Property | Behavior |
|----------|----------|
| SBOM storage | Never persisted |
| Scan results | Never persisted |
| Triage decisions | Never persisted |
| Caching | Process-local, in-memory TTL caches only |
| Observability | Structured logs emitted; no request data retained |
| Database access | Scanner data path uses no persistence; service-key auth and aggregate usage counters are stored separately |

The stateful counterpart is the `/ingest-sbom` pipeline, which archives SBOMs to object storage, persists components, and creates durable analysis jobs.

### Vulnerability Intelligence Sources

| Source | Data | Refresh |
|--------|------|---------|
| [OSV](https://osv.dev) | Vulnerability database (multi-ecosystem) | Per-request batch queries, process-local TTL cache |
| [FIRST EPSS](https://first.org/epss) | Exploit Prediction Scoring System | Process-local TTL cache |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities | Process-local TTL cache |

A freshness check runs before every scan. If any upstream source is unreachable, the API returns `503` with code `VULN_INTELLIGENCE_UNAVAILABLE`.

### Supported SBOM Formats

| Format | Versions |
|--------|----------|
| CycloneDX | 1.4, 1.5, 1.6, 1.7 |
| SPDX | 2.2, 2.3 |
| SPDX 3 | 3.0.1 (JSON-LD) |

---

## Authentication

Stateless Analyze is protected by organization-scoped service keys. Send the key in either header:

```http
Authorization: Bearer <service-key>
```

or:

```http
X-API-Key: <service-key>
```

Keys must include the `stateless:analyze` scope. New service keys issued by the product include both `stateless:analyze` and `sbom:ingest` so the same key can run stateless scans and, if needed, upload durable SBOM evidence through the stateful ingestion API.

The internal secret header is still accepted for trusted server-to-server and operational calls:

```http
X-CRA-Internal-API-Secret: <internal-secret>
```

For public API clients, use service keys only. When a service key is used, the organization context comes from the key; `X-Organization-Id` is only honored for internal-secret requests.

---

## Rate Limiting

Default limits:

| Caller | Limit | Configuration |
|--------|-------|---------------|
| Service key | 120 requests/minute/key/path | `STATELESS_API_KEY_RATE_LIMIT_PER_MINUTE` |
| Unauthenticated or invalid-key traffic | 30 requests/minute/IP/path | fixed default |
| Internal secret | skipped | trusted internal traffic only |

Rate-limit responses use HTTP `429` and code `RATE_LIMIT_EXCEEDED`. The API emits standard `X-RateLimit-*` headers from the rate-limit middleware.

Stateless endpoint responses also include:

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Mirrors the response `requestId` field |
| `X-API-Version` | Current stateless API contract date (`2026-05-27`) |
| `Cache-Control: no-store` | Prevents intermediary caching of scan and triage payloads |

---

## Common Response Envelope

All responses use a uniform JSON envelope:

```json
{
  "success": true,
  "requestId": "uuid-v4",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "data": { },
  "error": "Human-readable error message (on failure)",
  "details": {
    "code": "ERROR_CODE",
    "max_bytes": 15728640
  }
}
```

| Field | Type | Always Present | Description |
|-------|------|---------------|-------------|
| `success` | `boolean` | Yes | `true` for 2xx, `false` otherwise |
| `requestId` | `string` | Yes | UUID v4, mirrors `x-request-id` response header |
| `timestamp` | `string` | Yes | ISO 8601 UTC timestamp |
| `data` | `object` | On success | Endpoint-specific payload |
| `error` | `string` | On failure | Human-readable error message |
| `details` | `object` | On failure | Machine-readable error metadata including `code` |

### Custom Request Headers

| Header | Required | Used By | Description |
|--------|----------|---------|-------------|
| `Authorization` | Yes* | Protected endpoints | `Bearer <service-key>` authentication |
| `X-API-Key` | Yes* | Protected endpoints | Alternative service-key header |
| `X-Organization-Id` | No | `/scan-sbom`, `/triage-stateless` | Organization identifier for internal-secret requests; service-key requests use the key's organization |
| `X-Product-Id` | No | `/scan-sbom`, `/triage-stateless` | Product identifier for product context |
| `X-Product-Name` | No | `/scan-sbom`, `/triage-stateless` | Overrides SBOM metadata product name |
| `X-Product-Version` | No | `/scan-sbom`, `/triage-stateless` | Overrides SBOM metadata product version |
| `X-Request-Id` | No | All | Client-supplied request ID for tracing; generated if absent |

`Authorization` or `X-API-Key` is required unless the request uses the internal secret.

---

## Endpoints

### POST /scan-sbom

Scan a full SBOM document for vulnerabilities. Accepts CycloneDX or SPDX JSON, extracts PURLs, queries live vulnerability intelligence, and returns deduplicated findings.

```
POST /scan-sbom
Content-Type: application/json
```

Optional query:

| Query | Default | Description |
|-------|---------|-------------|
| `dry_run=true` | `false` | Validate the SBOM, extract and count unique PURLs, resolve product context, and return without calling vulnerability intelligence sources |

#### Request Body

Send the SBOM JSON document directly, or wrapped in an `{ "sbom": ... }` envelope:

```json
{
  "sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {
      "component": { "type": "application", "name": "my-app", "version": "2.0.0" }
    },
    "components": [
      {
        "type": "library",
        "name": "lodash",
        "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20"
      }
    ]
  }
}
```

| Constraint | Value |
|------------|-------|
| Max body size | 15 MiB (configurable via `STATELESS_SBOM_MAX_BYTES`) |
| Max PURLs extracted | 10,000 (configurable via `STATELESS_SBOM_MAX_PURLS`) |
| Scan timeout | 180 seconds (configurable via `STATELESS_SCAN_TIMEOUT_MS`) |
| Content-Type | `application/json` |

#### Product Context Resolution

The product context is built from (in priority order):

1. Service-key organization, or `X-Organization-Id` for internal-secret requests
2. `X-Product-Name` / `X-Product-Version` / `X-Product-Id` headers
3. SBOM metadata component (CycloneDX: `metadata.component.name`/`version`; SPDX 2.x: first package; SPDX 3: creation info)
4. Fallback: `"Unknown"` / `"unknown"`

#### Response: 200 OK

```json
{
  "success": true,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "data": {
    "status": "SCANNED",
    "stateless": true,
    "persisted": false,
    "scanner": "scanner-core/external-api",
    "schema": {
      "format": "CycloneDX",
      "version": "1.6"
    },
    "summary": {
      "component_count": 150,
      "purl_count": 150,
      "vulnerable_component_count": 12,
      "high_risk_component_count": 3,
      "vulnerability_count": 47
    },
    "product": {
      "organization_id": "my-org",
      "product_id": "my-app",
      "name": "my-app",
      "version": "2.0.0"
    },
    "components": [
      {
        "purl": "pkg:npm/lodash@4.17.20",
        "name": "lodash",
        "version": "4.17.20",
        "ecosystem": "npm",
        "vulnerability_count": 2,
        "high_risk": true,
        "vulnerability_ids": ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"]
      }
    ],
    "vulnerabilities": [
      {
        "id": "CVE-2021-23337",
        "source": "osv",
        "aliases": ["GHSA-35jh-r3h4-6jhm"],
        "description": "Prototype pollution in lodash...",
        "baseScore": 7.2,
        "cvssScore": 7.2,
        "severity": "HIGH",
        "exploited": false,
        "epss": 0.023,
        "euvdId": null,
        "affectedPackages": ["pkg:npm/lodash@4.17.20", "pkg:npm/other-lib@1.0.0"]
      }
    ]
  }
}
```

#### Response: 200 OK Dry Run

```json
{
  "success": true,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "data": {
    "status": "DRY_RUN",
    "stateless": true,
    "persisted": false,
    "scanner": "scanner-core/external-api",
    "schema": {
      "format": "CycloneDX",
      "version": "1.6"
    },
    "summary": {
      "component_count": 150,
      "purl_count": 150,
      "max_purls": 10000,
      "scan_required": false
    },
    "product": {
      "organization_id": "my-org",
      "product_id": "my-app",
      "name": "my-app",
      "version": "2.0.0"
    }
  }
}
```

Dry runs are metered as one request and the extracted PURL count, but they do not call OSV, EPSS, KEV, or AI triage.

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | `"SCANNED"` for scans, `"DRY_RUN"` when `dry_run=true` |
| `stateless` | `boolean` | Always `true` |
| `persisted` | `boolean` | Always `false` — no data was stored |
| `scanner` | `string` | Scanner engine identifier |
| `schema.format` | `string` | Detected SBOM format: `"CycloneDX"` or `"SPDX"` |
| `schema.version` | `string` | Detected specification version |
| `summary.component_count` | `number` | Total components with valid PURLs |
| `summary.purl_count` | `number` | Total unique PURLs scanned |
| `summary.vulnerable_component_count` | `number` | Components with at least one finding |
| `summary.high_risk_component_count` | `number` | Components with CVSS >= 9.0 or known exploitation |
| `summary.vulnerability_count` | `number` | Total deduplicated vulnerabilities across all components |
| `product` | `object` | Resolved product context |
| `components[]` | `array` | Per-component vulnerability summary (sorted by severity) |
| `vulnerabilities[]` | `array` | Deduplicated, severity-sorted vulnerability list |

#### Vulnerability Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Vulnerability ID (CVE, GHSA, etc.) |
| `source` | `"osv" \| "enriched"` | Data source |
| `aliases` | `string[]` | Alternative identifiers |
| `description` | `string` | Human-readable description |
| `baseScore` | `number?` | Base CVSS score from source |
| `cvssScore` | `number?` | Normalized CVSS score (highest available) |
| `severity` | `string?` | Severity label (CRITICAL, HIGH, MEDIUM, LOW) |
| `exploited` | `boolean?` | `true` if listed in CISA KEV or has exploitation evidence |
| `epss` | `number?` | FIRST EPSS score (0.0–1.0) |
| `euvdId` | `string \| null` | EU Vulnerability Database identifier when available |
| `affectedPackages` | `string[]` | PURLs of affected packages in the scanned set |

#### Deduplication Logic

Vulnerabilities are deduplicated by `id`. When the same vulnerability affects multiple PURLs:

- `affectedPackages` accumulates all affected PURLs
- `aliases` merges all known identifiers
- The highest CVSS score wins
- If any instance has `exploited: true`, the deduplicated record is `exploited: true`
- The highest EPSS score wins

#### Response: 400 — Validation Failure

```json
{
  "success": false,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "error": "SBOM validation failed",
  "details": {
    "code": "SBOM_VALIDATION_FAILED",
    "format": "Unknown",
    "version": "unknown",
    "errors": ["/bomFormat: must be equal to constant 'CycloneDX'"]
  }
}
```

#### Response: 413 — Too Many PURLs

```json
{
  "success": false,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "error": "Too many PURLs in SBOM; max is 10000",
  "details": {
    "code": "STATELESS_SBOM_TOO_MANY_PURLS",
    "max_purls": 10000,
    "received_purls": 12453
  }
}
```

#### Response: 503 — Intelligence Unavailable

```json
{
  "success": false,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "error": "External vulnerability intelligence is not ready",
  "details": {
    "code": "VULN_INTELLIGENCE_UNAVAILABLE",
    "freshness": { "osv": false, "epss": true, "kev": true }
  }
}
```

#### Response: 504 — Timeout

```json
{
  "success": false,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:03:00.000Z",
  "error": "SBOM vulnerability scan timed out",
  "details": {
    "code": "STATELESS_SCAN_TIMEOUT",
    "timeout_ms": 180000
  }
}
```

---

### POST /scan-purls

Scan a list of Package URLs directly — no SBOM required. Useful for CI/CD pipelines that already have a dependency list, or for chunked scanning of large SBOMs.

```
POST /scan-purls
Content-Type: application/json
```

#### Request Body

```json
{
  "purls": [
    "pkg:npm/lodash@4.17.20",
    "pkg:pypi/django@3.2.0",
    "pkg:maven/org.springframework/spring-core@5.3.0"
  ]
}
```

| Constraint | Value |
|------------|-------|
| Max body size | 1 MiB (configurable via `STATELESS_PURL_SCAN_MAX_BYTES`) |
| Max PURLs | 500 |
| Scan timeout | 180 seconds |
| Content-Type | `application/json` |

#### PURL Validation

- Each entry must be a valid [Package URL](https://github.com/package-url/purl-spec) (`pkg:type/name@version`)
- Non-string entries are rejected
- Empty or unparseable PURLs are rejected
- Duplicates are silently deduplicated
- `purls` must be present and must be an array
- If any PURL is invalid, the entire request is rejected with the first 10 invalid entries listed

#### Response: 200 OK

```json
{
  "success": true,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "data": {
    "status": "SCANNED",
    "stateless": true,
    "persisted": false,
    "scanner": "scanner-core/external-api",
    "summary": {
      "purl_count": 3,
      "vulnerable_purl_count": 2,
      "high_risk_purl_count": 1,
      "vulnerability_count": 5
    },
    "purls": [
      {
        "purl": "pkg:npm/lodash@4.17.20",
        "vulnerability_count": 2,
        "high_risk": true,
        "vulnerability_ids": ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"]
      }
    ],
    "findings_by_purl": {
      "pkg:npm/lodash@4.17.20": [
        {
          "id": "CVE-2021-23337",
          "source": "osv",
          "aliases": ["GHSA-35jh-r3h4-6jhm"],
          "description": "Prototype pollution in lodash...",
          "baseScore": 7.2,
          "severity": "HIGH",
          "affectedPackages": ["pkg:npm/lodash@4.17.20"]
        }
      ]
    },
    "vulnerabilities": [
      {
        "id": "CVE-2021-23337",
        "source": "osv",
        "aliases": ["GHSA-35jh-r3h4-6jhm"],
        "description": "Prototype pollution in lodash...",
        "baseScore": 7.2,
        "cvssScore": 7.2,
        "severity": "HIGH",
        "exploited": false,
        "epss": 0.023,
        "affectedPackages": ["pkg:npm/lodash@4.17.20"]
      }
    ]
  }
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `summary.purl_count` | `number` | Total unique PURLs scanned |
| `summary.vulnerable_purl_count` | `number` | PURLs with at least one finding |
| `summary.high_risk_purl_count` | `number` | PURLs with CVSS >= 9.0 or known exploitation |
| `summary.vulnerability_count` | `number` | Total deduplicated vulnerabilities |
| `purls[]` | `array` | Per-PURL vulnerability summary |
| `findings_by_purl` | `object` | Map of PURL → vulnerability array (full detail) |
| `vulnerabilities[]` | `array` | Deduplicated, severity-sorted master list |

---

### POST /triage-stateless

Run AI-powered CRA triage over a set of vulnerability findings. This is the decision engine: given a product context and a list of vulnerabilities, the AI returns a regulatory decision (`REPORT`, `MONITOR`, `NEEDS_VEX`, `NOT_AFFECTED`, or `ERROR`).

This endpoint expects you to have already aggregated vulnerability findings — typically from one or more `/scan-sbom` or `/scan-purls` calls.

```
POST /triage-stateless
Content-Type: application/json
```

#### Request Body

```json
{
  "product": {
    "name": "my-app",
    "version": "2.0.0",
    "organizationId": "org-1",
    "productId": "product-1"
  },
  "vulnerabilities": [
    {
      "id": "CVE-2021-23337",
      "source": "osv",
      "aliases": ["GHSA-35jh-r3h4-6jhm"],
      "description": "Prototype pollution in lodash.",
      "baseScore": 7.2,
      "cvssScore": 7.2,
      "severity": "HIGH",
      "exploited": false,
      "epss": 0.023,
      "affectedPackages": ["pkg:npm/lodash@4.17.20"]
    }
  ],
  "component_count": 150,
  "sbom_count": 1
}
```

| Constraint | Value |
|------------|-------|
| Max body size | 10 MiB (configurable via `STATELESS_TRIAGE_MAX_BYTES`) |
| Max vulnerabilities | 5,000 |
| Triage timeout | 180 seconds (configurable via `STATELESS_TRIAGE_TIMEOUT_MS`) |
| Content-Type | `application/json` |

#### Vulnerability Input Normalization

- `id` is required (string, non-empty)
- `source` defaults to `"osv"` if not `"osv"` or `"enriched"`
- `aliases` deduplicates string entries
- `baseScore`, `cvssScore`, `epss` must be finite numbers
- `exploited` must be `boolean`
- Entries without a valid `id` are silently dropped

#### Product Context

The `product` object is optional but recommended. All fields are optional:

- The organization comes from the service key; `X-Organization-Id` is only used for internal-secret requests
- `X-Product-Name` / `X-Product-Version` / `X-Product-Id` headers override body fields
- Missing fields fall back to `"stateless"` / `"Unknown"` / `"unknown"`

#### Response: 200 OK

```json
{
  "success": true,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:05.000Z",
  "data": {
    "status": "TRIAGED",
    "stateless": true,
    "persisted": false,
    "product": {
      "organization_id": "org-1",
      "product_id": "product-1",
      "name": "my-app",
      "version": "2.0.0"
    },
    "triage": {
      "kind": "STATELESS_TRIAGE_COMPLETE",
      "vulnerabilities_found": 47,
      "report": {
        "decision": "REPORT",
        "earlyWarning24h": "One or more actively exploited vulnerabilities were found.",
        "justification": "CVE-2021-23337 is a known exploited vulnerability with CVSS 7.2...",
        "notAffectedJustification": null,
        "triggeringVulns": [
          { "id": "CVE-2021-23337", "reason": "Actively exploited per CISA KEV" }
        ],
        "recommendedActions": "Immediately patch lodash to version 4.17.21 or later.",
        "confidence": "HIGH",
        "promptVersion": "cra-triage-v3.2",
        "analysisTraceId": "trace-abc-123",
        "evidenceSnapshot": {},
        "triagedVulns": [
          {
            "id": "CVE-2021-23337",
            "cve": "CVE-2021-23337",
            "euvdId": null,
            "severity": "HIGH",
            "cvssScore": 7.2,
            "epss": 0.023,
            "exploited": true,
            "suggestedVerdict": "REPORT_CANDIDATE",
            "confidence": "HIGH",
            "missingEvidence": [],
            "rationale": "Listed in CISA KEV with active exploitation in the wild."
          }
        ]
      },
      "progress": [
        { "phase": "RUNNING_TRIAGE_PHASE_1", "progress": 65 },
        { "phase": "RUNNING_TRIAGE_PHASE_2", "progress": 75 }
      ]
    }
  }
}
```

#### Decision Values

| Decision | Meaning |
|----------|---------|
| `REPORT` | Actively exploited vulnerability requires immediate reporting under CRA Art. 14 |
| `MONITOR` | Vulnerabilities present but below reporting threshold; continue monitoring |
| `NEEDS_VEX` | Insufficient evidence for a definitive decision; a VEX document is needed |
| `NOT_AFFECTED` | Vulnerabilities found but product is not exploitable |
| `ERROR` | AI triage encountered an error; retry or escalate |

#### per-Vulnerability Verdicts

| Verdict | Meaning |
|---------|---------|
| `REPORT_CANDIDATE` | This vulnerability likely triggers a reporting obligation |
| `MONITOR_CANDIDATE` | Track this vulnerability; no immediate reporting needed |
| `NEEDS_VEX` | More evidence needed to determine exploitability |

#### Progress Events

The `progress` array records each phase transition during the AI triage. Each entry has:

- `phase` — internal phase identifier (e.g., `RUNNING_TRIAGE_PHASE_1`)
- `progress` — numeric progress indicator (0–100)

---

### GET /scanner/health

Check whether the live vulnerability intelligence sources required by the stateless scanner are reachable.

```
GET /scanner/health
```

This endpoint does not require authentication. It is intended for customer-facing status checks, load balancers, and deployment readiness probes that only care about the stateless scanner's upstream dependencies.

#### Response: 200 OK

```json
{
  "success": true,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "data": {
    "status": "ready",
    "vulnerability_intelligence": {
      "ok": true,
      "checkedAt": "2026-05-27T12:00:00.000Z",
      "requiredSources": ["osv", "epss", "kev"],
      "sources": [
        {
          "source": "osv",
          "status": "ready",
          "checkedAt": "2026-05-27T12:00:00.000Z",
          "latestErrorMessage": null
        }
      ]
    }
  }
}
```

#### Response: 503 Service Unavailable

```json
{
  "success": false,
  "requestId": "abc-123",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "error": "Scanner vulnerability intelligence is not ready",
  "details": {
    "code": "VULN_INTELLIGENCE_UNAVAILABLE",
    "vulnerability_intelligence": {
      "ok": false,
      "requiredSources": ["osv", "epss", "kev"],
      "sources": [
        {
          "source": "epss",
          "status": "error",
          "checkedAt": "2026-05-27T12:00:00.000Z",
          "latestErrorMessage": "HTTP 503 from EPSS"
        }
      ]
    }
  }
}
```

---

## Error Codes

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 401 | `API_KEY_REQUIRED` | Missing service key for a protected endpoint |
| 401 | `API_KEY_INVALID` | Service key is malformed, expired, revoked, or unknown |
| 403 | `API_KEY_SCOPE_FORBIDDEN` | Service key does not include the required scope |
| 429 | `RATE_LIMIT_EXCEEDED` | Request exceeded the per-key or per-IP rate limit |
| 400 | `EMPTY_JSON_BODY` | Request body is empty |
| 400 | `INVALID_JSON_BODY` | Request body is not valid JSON |
| 400 | `INVALID_SBOM_PAYLOAD` | SBOM payload must be a JSON object |
| 400 | `INVALID_JSON_OBJECT` | Request body must be a JSON object |
| 400 | `SBOM_VALIDATION_FAILED` | SBOM does not match any supported schema |
| 400 | `MISSING_PURLS` | PURL scan request is missing the `purls` array |
| 400 | `INVALID_PURLS` | One or more PURLs are invalid |
| 400 | `MISSING_VULNERABILITIES` | Triage request is missing the `vulnerabilities` array |
| 413 | `STATELESS_REQUEST_TOO_LARGE` | Request body exceeds the size limit |
| 413 | `STATELESS_SBOM_TOO_MANY_PURLS` | SBOM contains more PURLs than the configured maximum |
| 413 | `STATELESS_TOO_MANY_PURLS` | PURL list exceeds the per-request maximum |
| 413 | `STATELESS_TOO_MANY_VULNERABILITIES` | Vulnerability list exceeds the triage maximum |
| 503 | `VULN_INTELLIGENCE_UNAVAILABLE` | One or more upstream vulnerability APIs are unreachable |
| 504 | `STATELESS_SCAN_TIMEOUT` | Scan exceeded the configured timeout |
| 504 | `STATELESS_TRIAGE_TIMEOUT` | AI triage exceeded the configured timeout |
| 502 | `STATELESS_SBOM_SCAN_FAILED` | Unclassified scan failure |
| 502 | `STATELESS_PURL_SCAN_FAILED` | Unclassified PURL scan failure |
| 502 | `STATELESS_TRIAGE_FAILED` | Unclassified triage failure |

---

## Client Examples

### Complete Pipeline: SBOM → Scan → Triage

```bash
#!/usr/bin/env bash
set -euo pipefail

API_BASE="https://api.example.com"
API_KEY="${CRA_API_KEY:?required}"

# Step 1: Scan the SBOM
echo "=== Scanning SBOM ==="
scan_result=$(curl -sS -X POST "$API_BASE/scan-sbom" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Product-Name: my-app" \
  -H "X-Product-Version: 2.0.0" \
  -d @sbom.json)

echo "$scan_result" | jq '.data.summary'

# Step 2: Extract vulnerabilities from the scan result
vulns=$(echo "$scan_result" | jq -c '.data.vulnerabilities')
component_count=$(echo "$scan_result" | jq '.data.summary.component_count')

# Step 3: Run AI triage on the findings
echo "=== Running AI Triage ==="
triage_result=$(curl -sS -X POST "$API_BASE/triage-stateless" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Product-Name: my-app" \
  -H "X-Product-Version: 2.0.0" \
  -d "$(jq -n --argjson vulns "$vulns" --argjson cc "$component_count" '{
    product: { name: "my-app", version: "2.0.0" },
    vulnerabilities: $vulns,
    component_count: $cc
  }')")

echo "$triage_result" | jq '{decision: .data.triage.report.decision, confidence: .data.triage.report.confidence, triggeringVulns: .data.triage.report.triggeringVulns}'
```

### Chunked PURL Scanning (for large dependency sets)

```bash
#!/usr/bin/env bash
set -euo pipefail

API_BASE="https://api.example.com"
API_KEY="${CRA_API_KEY:?required}"
CHUNK_SIZE=450

# Extract PURLs from SBOM (using jq for CycloneDX)
all_purls=$(jq -r '.components[]?.purl // empty' sbom.json | grep '^pkg:' | sort -u)

# Scan in chunks of 450 (under the 500 limit)
echo "$all_purls" | xargs -n "$CHUNK_SIZE" | while read -r chunk; do
  purls_json=$(printf '%s\n' "$chunk" | jq -R -s 'split("\n") | map(select(length > 0))')
  curl -sS -X POST "$API_BASE/scan-purls" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --argjson purls "$purls_json" '{purls: $purls}')"
done | jq -s '[.[].data.vulnerabilities[]] | unique_by(.id)'
```

### Python Client

```python
import requests
import json
from typing import Any

class StatelessAnalyzeClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def scan_sbom(self, sbom: dict, product_name: str | None = None,
                  product_version: str | None = None) -> dict:
        headers = {}
        if product_name:
            headers["X-Product-Name"] = product_name
        if product_version:
            headers["X-Product-Version"] = product_version

        r = self.session.post(
            f"{self.base_url}/scan-sbom",
            json=sbom,
            headers=headers,
            timeout=190,
        )
        r.raise_for_status()
        return r.json()["data"]

    def scan_purls(self, purls: list[str]) -> dict:
        r = self.session.post(
            f"{self.base_url}/scan-purls",
            json={"purls": purls},
            timeout=190,
        )
        r.raise_for_status()
        return r.json()["data"]

    def triage(self, vulnerabilities: list[dict], product: dict | None = None,
               component_count: int = 0) -> dict:
        r = self.session.post(
            f"{self.base_url}/triage-stateless",
            json={
                "vulnerabilities": vulnerabilities,
                "product": product or {},
                "component_count": component_count,
            },
            timeout=190,
        )
        r.raise_for_status()
        return r.json()["data"]


# Usage
client = StatelessAnalyzeClient("https://api.example.com", "sk-...")

with open("sbom.json") as f:
    sbom = json.load(f)

scan = client.scan_sbom(sbom, product_name="my-app", product_version="2.0.0")
print(f"Found {scan['summary']['vulnerability_count']} vulnerabilities")

if scan["vulnerabilities"]:
    triage = client.triage(
        scan["vulnerabilities"],
        product={"name": "my-app", "version": "2.0.0"},
        component_count=scan["summary"]["component_count"],
    )
    print(f"Decision: {triage['triage']['report']['decision']}")
    print(f"Confidence: {triage['triage']['report']['confidence']}")
```

### Node.js / TypeScript Client

```typescript
interface StatelessClientOptions {
  baseUrl: string;
  apiKey: string;
  timeout?: number;
}

interface ScanSbomResponse {
  status: "SCANNED";
  stateless: true;
  persisted: false;
  scanner: string;
  schema: { format: string; version: string };
  summary: {
    component_count: number;
    purl_count: number;
    vulnerable_component_count: number;
    high_risk_component_count: number;
    vulnerability_count: number;
  };
  product: {
    organization_id: string;
    product_id: string;
    name: string;
    version: string;
  };
  components: Array<{
    purl: string;
    name: string;
    version: string;
    ecosystem: string | null;
    vulnerability_count: number;
    high_risk: boolean;
    vulnerability_ids: string[];
  }>;
  vulnerabilities: Array<{
    id: string;
    source: "osv" | "enriched";
    aliases: string[];
    description: string;
    baseScore?: number;
    cvssScore?: number;
    severity?: string;
    exploited?: boolean;
    epss?: number;
    euvdId?: string;
    affectedPackages: string[];
  }>;
}

class StatelessAnalyzeClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeout: number;

  constructor(options: StatelessClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeout = options.timeout ?? 190_000;
    this.headers = {
      Authorization: `Bearer ${options.apiKey}`,
      "Content-Type": "application/json",
    };
  }

  async scanSbom(
    sbom: Record<string, unknown>,
    product?: { name?: string; version?: string },
  ): Promise<ScanSbomResponse> {
    const headers: Record<string, string> = { ...this.headers };
    if (product?.name) headers["X-Product-Name"] = product.name;
    if (product?.version) headers["X-Product-Version"] = product.version;

    const res = await fetch(`${this.baseUrl}/scan-sbom`, {
      method: "POST",
      headers,
      body: JSON.stringify(sbom),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(`${err.error} (code: ${err.details?.code})`);
    }

    const json = await res.json();
    return json.data as ScanSbomResponse;
  }

  async scanPurls(purls: string[]) {
    const res = await fetch(`${this.baseUrl}/scan-purls`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ purls }),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(`${err.error} (code: ${err.details?.code})`);
    }

    const json = await res.json();
    return json.data;
  }

  async triage(vulnerabilities: unknown[], product?: Record<string, unknown>, componentCount = 0) {
    const res = await fetch(`${this.baseUrl}/triage-stateless`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({
        vulnerabilities,
        product: product ?? {},
        component_count: componentCount,
      }),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(`${err.error} (code: ${err.details?.code})`);
    }

    const json = await res.json();
    return json.data;
  }
}
```

---

## Architecture & Limits

### Request Lifecycle

```
Client Request
  │
  ├─ 1. Service-key/internal-secret auth
  ├─ 2. Per-key or per-IP rate limit
  ├─ 3. Content-Length pre-check (reject oversized before reading)
  ├─ 4. Streaming body read with byte-level bounded enforcement
  ├─ 5. JSON parse
  ├─ 6. Payload unwrap (if { sbom: ... } envelope)
  ├─ 7. Schema validation (CycloneDX / SPDX)
  ├─ 8. PURL extraction & normalization
  ├─ 9. Ceiling enforcement (max PURLs / max vulnerabilities)
  ├─ 10. Product context resolution (service key + SBOM metadata + headers)
  ├─ 11. Dry-run return path (if dry_run=true)
  ├─ 12. Freshness check (OSV, EPSS, KEV reachable)
  ├─ 13. Vulnerability scan (OSV batch query → EPSS enrichment → KEV enrichment)
  ├─ 14. Deduplication & severity sorting
  ├─ 15. Usage metering counters
  ├─ 16. Response assembly
  │
  └─ HTTP Response
```

### Internal vs. External Scanning

The stateless endpoints use an `ExternalApiPurlVulnerabilityScanner` that queries OSV, EPSS, and KEV APIs directly with a process-local cache. This is distinct from the stateful pipeline which uses a local vulnerability database populated by the `vuln-sync` worker.

### Timeout & Abort Behavior

- All three endpoints have configurable timeouts (default 180s).
- The underlying scanner receives an `AbortSignal` and cancels in-flight OSV batch requests when the timeout fires.
- Binary-search isolation is used to handle "poison PURLs" that cause 400 errors from OSV.

### Scalability

- **Horizontal**: The API is stateless — deploy multiple instances behind a load balancer with no shared state.
- **Vertical**: Each instance scales with available CPU (Bun's event loop). OSV batch queries are parallelized (400 PURLs per batch, 4 concurrent batches).
- **Memory**: Process-local caches for OSV, EPSS, KEV are TTL-based and bounded by the number of unique PURLs/ecosystems queried.

---

## API-as-a-Service Readiness

### Implemented for Launch

| Capability | Status |
|------------|--------|
| Public service-key auth | Implemented with HMAC-hashed keys, revocation, expiry, `Authorization: Bearer`, and `X-API-Key` support |
| Stateless API scope | Implemented as `stateless:analyze`; new service keys also include `sbom:ingest` |
| Per-key rate limiting | Implemented with per-service-key buckets and `X-RateLimit-*` headers |
| Usage metering | Implemented as per-key counters for requests, scanned PURLs, triaged vulnerabilities, and triage calls |
| Uniform error codes | Implemented for stateless validation, body-size, rate-limit, auth, timeout, and upstream failures |
| Dry-run estimate mode | Implemented with `POST /scan-sbom?dry_run=true` |
| Scanner health endpoint | Implemented as `GET /scanner/health` |
| OpenAPI route schemas | Implemented for the three stateless endpoints in the Elysia route metadata |
| Cache-control safety | Stateless responses emit `Cache-Control: no-store` |
| API version signal | Stateless responses emit `X-API-Version: 2026-05-27` |

### Remaining Enhancements

| Priority | Enhancement | Notes |
|----------|-------------|-------|
| High | Idempotency keys | Useful for retry-safe billing and CI reruns; requires a short-lived response cache |
| High | Async/webhook mode | Useful for very large scans or slow AI triage; should include signed webhook payloads |
| High | Path-based versioning | Add `/v1/...` aliases before publishing long-lived SDKs |
| Medium | Customer usage API | Expose `GET /usage?from=...&to=...` using the existing counters and future rollups |
| Medium | Advisory lookup | Add `GET /advisory/:id` for single-CVE/GHSA lookups with EPSS/KEV enrichment |
| Medium | Pagination or response shaping | Useful for very large vulnerability arrays; current limits keep responses bounded |
| Medium | Client SDKs | Publish TypeScript and Python SDKs once path versioning is settled |
| Low | Sandbox/test mode | Deterministic mock scanner responses for integration tests |
| Low | Scan diff endpoint | Compare two SBOMs and return added/removed/changed vulnerabilities |

### Current Design Decisions Worth Preserving

1. **Bounded streaming body reads** — prevents memory exhaustion from `Content-Length` spoofing. The read loop enforces a byte ceiling as it streams.
2. **Poison PURL isolation** — the scanner uses binary search to isolate individual PURLs that cause OSV 400 errors, so one bad PURL doesn't fail the entire scan.
3. **Zero persistence** — the no-op repository pattern means there's no accidental data retention.
4. **Freshness gate** — refuses to scan when upstream APIs are down instead of returning stale/missing data.
5. **Progress reporting in triage** — the `progress` array lets clients show meaningful progress for long-running AI triage calls.
6. **Minimal metering data** — only counters are stored for API-as-a-service usage; SBOMs, PURLs, vulnerability details, and triage decisions are not retained by stateless endpoints.

---

## Environment Configuration

The following environment variables tune the stateless endpoint behavior at deploy time:

| Variable | Default | Description |
|----------|---------|-------------|
| `STATELESS_SBOM_MAX_PURLS` | `10000` | Max PURLs extracted from an SBOM |
| `STATELESS_SBOM_MAX_BYTES` | `15728640` (15 MiB) | Max `/scan-sbom` request body size |
| `STATELESS_PURL_SCAN_MAX_BYTES` | `1048576` (1 MiB) | Max `/scan-purls` request body size |
| `STATELESS_TRIAGE_MAX_BYTES` | `10485760` (10 MiB) | Max `/triage-stateless` request body size |
| `STATELESS_SCAN_TIMEOUT_MS` | `180000` (3 min) | Scan timeout in milliseconds |
| `STATELESS_TRIAGE_TIMEOUT_MS` | `180000` (3 min) | Triage timeout in milliseconds |
| `STATELESS_API_KEY_RATE_LIMIT_PER_MINUTE` | `120` | Per-service-key request rate limit |
| `STATELESS_SCANNER_REQUIRED_READINESS_SOURCES` | `osv,epss,kev` | Required upstream sources for scanner readiness |
| `STATELESS_SCANNER_FRESHNESS_CACHE_TTL_MS` | `60000` | Process-local scanner readiness cache TTL |
| `STATELESS_SCANNER_READINESS_TIMEOUT_MS` | `10000` | Timeout for each readiness source check |

---

## Status Codes Summary

| Status | Meaning |
|--------|---------|
| `200` | Success |
| `400` | Invalid request (bad JSON, invalid SBOM, invalid PURLs, missing fields) |
| `401` | Missing or invalid service key |
| `403` | Service key lacks the required scope |
| `413` | Request too large (body size, too many PURLs, too many vulnerabilities) |
| `429` | Rate limit exceeded |
| `502` | Upstream scan/triage failure |
| `503` | Vulnerability intelligence APIs unavailable |
| `504` | Scan or triage timed out |
