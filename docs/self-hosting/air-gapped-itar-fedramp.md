# Air-gapped deployment (ITAR / FedRAMP-High)

This guide describes how to run Plane fully inside a disconnected, US-only,
no-egress boundary suitable for export-controlled (ITAR) and CUI / FedRAMP-High
workloads, and documents the application-level `AIRGAP` controls that ship in
this codebase.

> **Scope note.** ITAR and FedRAMP are accreditations of an _environment +
> organization + process_, not features of an application. The software job is
> narrow: (a) emit zero outbound traffic, (b) run entirely from in-boundary
> dependencies, and (c) support the technical controls the accreditation
> requires (SSO+MFA, FIPS crypto, audit logging, RBAC, data residency,
> encryption at rest). True **classified** (SECRET/TS) data exceeds FedRAMP High
> and requires an IL6 / closed-network boundary (e.g. AWS Secret Region) — a
> commercial GovCloud boundary is not sufficient. Confirm the data
> classification with your security team before building.

## 1. Boundary architecture (AWS GovCloud / Azure Government)

```
  AWS GovCloud (US) / Azure Government — single VPC, NO Internet Gateway, NO NAT
  ┌───────────────────────────────────────────────────────────────────────────┐
  │  Private subnets only · egress default-DENY · VPC endpoints for AWS svcs    │
  │  [ALB/App-GW + WAF] → [nginx proxy] → [web] [admin] [api] [live]            │
  │                                   ↘ [celery worker] [beat]                  │
  │  Data: [RDS Postgres (FIPS, KMS-CMK)] [ElastiCache] [Amazon MQ]             │
  │        [S3 (GovCloud) OR in-VPC MinIO]  ← AWS_S3_ENDPOINT_URL               │
  │  Identity: [Keycloak / ADFS / Okta-Gov] OIDC/SAML + PIV/CAC + MFA           │
  │  Ops: [internal registry (ECR)] [in-cluster OTEL] [audit → SIEM in-bound]   │
  └───────────────────────────────────────────────────────────────────────────┘
   ✗ no path to api.github.com / api.openai.com / api.unsplash.com / prime.plane.so
```

Principles:

- **Network egress = default deny.** No IGW/NAT on app subnets; reach AWS
  services only through VPC endpoints (S3, KMS, ECR, CloudWatch, SecretsManager).
  This is what makes the deployment a _true air-gap_ in cloud terms — the app
  cannot reach the public internet even if code tries.
- **US-only region + US-persons IAM** (ITAR): restrict all human/role access to
  vetted US persons via IAM SCPs and screened admin accounts.
- **Everything mirrored in-boundary**: container images, OS/pip/npm packages,
  fonts, avatars, cover images. No CDN or public package pull at build or run.
- **FIPS 140-2/3 endpoints** for KMS/RDS/ELB; TLS everywhere, including
  service-to-service.

## 2. Application air-gap controls (`AIRGAP=1`)

Set `AIRGAP=1` in the API/worker/beat environment. This is defense-in-depth on
top of the no-egress network: each code path that would reach a public endpoint
fails safe. Controlled by `plane/utils/airgap.py::is_airgap()`.

| Surface                                    | Behavior when `AIRGAP=1`                                                               |
| ------------------------------------------ | -------------------------------------------------------------------------------------- |
| GitHub version check (`register_instance`) | skipped; falls back to local version                                                   |
| Telemetry / OTLP metrics export            | skipped entirely                                                                       |
| PostHog product analytics                  | disabled (config ignored)                                                              |
| Unsplash cover images                      | endpoint returns empty list                                                            |
| AI assistant (OpenAI/Anthropic/Gemini)     | disabled unless `LLM_API_BASE_URL` points at an in-boundary, OpenAI-compatible gateway |

## 3. Point dependencies in-boundary (config only)

The existing settings already support fully in-boundary backends — no code
change needed, just environment:

- **Object storage:** set `USE_MINIO=1` + `AWS_S3_ENDPOINT_URL` to in-VPC MinIO,
  or point `AWS_S3_ENDPOINT_URL` at a GovCloud S3 VPC endpoint. Uploads use
  signed URLs (see `plane/settings/storage.py`).
- **DB / cache / queue:** `DATABASE_URL`, `REDIS_URL`, `AMQP_URL` → in-VPC
  RDS / ElastiCache / Amazon MQ.
- **Telemetry (optional, in-cluster only):** if you want ops metrics, run an
  in-cluster OTEL collector; `AIRGAP=1` disables export by default.
- **AI (optional):** run an in-boundary model server (vLLM / Ollama /
  Bedrock-GovCloud) and set `LLM_API_KEY` + `LLM_API_BASE_URL`.

## 4. Internal OIDC SSO (in-boundary identity)

A generic OpenID Connect provider ships in this repo so you can authenticate
against an in-boundary IdP (Keycloak, ADFS, Okta-Gov, Ping, Azure AD, etc.)
instead of the public OAuth providers. Endpoints are configured explicitly (no
discovery round-trip) so the flow makes no extra outbound call.

Enable by setting `IS_OIDC_ENABLED=1` and all five values:
`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_AUTHORIZATION_URL`,
`OIDC_TOKEN_URL`, `OIDC_USERINFO_URL`. The app exposes
`/auth/oidc/` (initiate) and `/auth/oidc/callback/` (plus `/auth/spaces/oidc/*`
for the public spaces app); set your IdP redirect URI to the callback path.

For ITAR/FedRAMP **IA** controls, pair this with MFA enforced at the IdP
(PIV/CAC where required) and force SSO-only login by disabling the local
methods: `ENABLE_EMAIL_PASSWORD=0`, `ENABLE_MAGIC_LINK_LOGIN=0`,
`ENABLE_SIGNUP=0`. The public OAuth providers (Google/GitHub/GitLab) must remain
unconfigured inside the boundary.

Implementation: `plane/authentication/provider/oauth/oidc.py` (adapter, follows
the existing Gitea pattern), `plane/authentication/views/{app,space}/oidc.py`
(flows), wired in `plane/authentication/urls.py`. Config keys live in
`plane/utils/instance_config_variables/core.py`; the instance config endpoint
returns `is_oidc_enabled`.

## 5. Authentication audit log (AU-2 / AC-7)

An append-only authentication audit trail ships in this repo. Every
authentication event is recorded to the `authentication_audit_logs` table:
successful sign-ins (all mediums — email, magic code, Google/GitHub/GitLab/Gitea
and OIDC, captured at the shared `user_login` chokepoint), sign-outs, and failed
password sign-ins (AC-7 unsuccessful-logon-attempt). Each row captures the event
type, user (nullable, `SET_NULL` so records survive user deletion), email,
medium, origin app (`app`/`admin`/`space`), error code on failure, IP address,
and user agent.

Writes are enqueued to a Celery task (`record_auth_event`) so auditing never
adds latency to the login path, and failures to write are swallowed so they
cannot break authentication. Application code only ever inserts — never updates
or deletes — these rows. **Ship this table to an in-boundary SIEM**
(CloudWatch/Splunk-Gov) for retention, alerting, and tamper-evidence; enforce
retention via the SIEM and a read-only/append-only DB grant as your control
baseline requires.

Implementation: `plane/db/models/audit.py` (model + migration `0122`),
`plane/bgtasks/auth_audit_task.py` (task), `plane/authentication/utils/audit.py`
(helper), wired into `authentication/utils/login.py` and the sign-out / email
sign-in views.

## 6. Access-management audit log (AC-2 / AC-6)

An append-only access-management audit trail ships alongside the auth log, in
the `access_audit_logs` table. It records authorization changes at both the
workspace and project level: members added (project add, workspace join),
members removed (admin removal and self-leave), and role changes — capturing the
**actor** (`created_by`), the **target** user/email, the scope, the workspace and
project, and the previous/new role (same integer scale as
`WorkspaceMember.role` / `ProjectMember.role`: 5 Guest, 15 Member, 20 Admin).

Like the auth log, writes go through a Celery task (`record_access_event`) off
the request path; the actor is threaded through explicitly (`crum` has no
request user inside the worker) and rows are insert-only. Ship this table to the
same in-boundary SIEM.

Implementation: `plane/db/models/access_audit.py` (model + migration `0123`),
`plane/bgtasks/access_audit_task.py` (task), `plane/utils/access_audit.py`
(helper), wired into the workspace/project member views and the workspace-join
endpoint.

## 7. Data-export audit log (AU-2)

An append-only data-export audit trail ships in the `data_export_audit_logs`
table, recording every request to extract data out of the boundary: issue
exports (csv/xlsx/json) and analytics exports. Each row captures the actor
(`created_by`), export type, provider/format, workspace, the number of projects
in scope, IP, and user agent.

Same pattern as the other audit logs: writes go through a Celery task
(`record_data_export_event`) off the request path, the actor is threaded through
explicitly, and rows are insert-only. Ship this table to the same in-boundary
SIEM — exports are a primary data-exfiltration signal and warrant alerting.

Implementation: `plane/db/models/data_export_audit.py` (model + migration
`0124`), `plane/bgtasks/data_export_audit_task.py` (task),
`plane/utils/data_export_audit.py` (helper), wired into the issue-export
(`app/views/exporter/base.py`) and analytics-export
(`app/views/analytic/base.py`) endpoints.

## 8. Still required outside this repo

These are larger, environment-specific efforts to complete before an ATO:

- **Audit coverage beyond the above:** the auth (AU-2/AC-7), access (AC-2/AC-6),
  and data-export (AU-2) logs cover authentication, authorization changes, and
  data extraction. Extend to any further security-relevant reads your control
  baseline requires.
- **Static assets:** mirror any remote default images/fonts/CDN references so the
  frontend loads entirely from in-boundary origins.
- **Supply chain:** internal registry with pinned (non-`latest`) images, offline
  pip/pnpm resolution, SBOM per build, image signing/scanning, FIPS base images,
  and a one-way airlock for artifact transfer into the boundary.

## 9. Verification

1. **Egress test (most important):** run with egress denied and exercise
   startup, the beat tick, and the AI/cover-image/analytics features. Assert
   zero connections leave the boundary (VPC flow logs / `tcpdump` / Falco).
2. **Static scan:**
   `grep -rE "https?://(api\.github|api\.openai|api\.unsplash|prime\.plane|app\.plane|prod-plane-cdn|dummyimage)" apps packages`
   should return only guarded/neutralized paths.
3. **Profile test:** with `AIRGAP=1`, confirm version check, telemetry, PostHog,
   Unsplash, and public AI are all hard-off.
