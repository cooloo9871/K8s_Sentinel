# Registry scanning — design

Date: 2026-11-12

## Intent

Know what vulnerabilities an image carries **before it is deployed**. The
Vulnerabilities page answers this for workloads that are already running, from
Trivy Operator's reports. Trivy Operator cannot look at a registry, so images
that are not running are invisible to it.

## Decisions (made by the owner)

1. **Sentinel starts the scans; Trivy still does the scanning.** This reverses
   the earlier "Sentinel only reads results" decision, for registries only.
2. **Three registry kinds:** Harbor, a self-hosted Docker Registry, and quay.io.
3. **Scope is chosen with filters, as NeuVector does:** a whole project
   (`library/*`), a repository, or tags (`team/app:v1.*`).
4. **Each registry has its own schedule,** a number of days from 1 to 30.
5. **Results are kept in `DATA_DIR`** (`/data/sentinel`) like every other
   setting.
6. **No deployment blocking here.** That will be a ValidatingAdmissionPolicy
   feature later.

## Goals

- Add, edit and delete registries: name, kind, URL, credentials, filters,
  interval, an option to skip TLS verification.
- A scan runs on creation, then every interval, and on demand.
- A list of scanned images per registry with counts per severity, fixable
  count and scan time; expand for the findings; search, severity filter, CSV.
- "Test" resolves the filters without scanning and says how many images match.

## Non-goals

- Blocking deployments.
- Marking which registry images are currently running in the cluster.
- Scanning anything but vulnerabilities (secrets, misconfiguration, licences).
- Webhook-triggered scans on push.

## Anti-goals

- **A failed scan that reads as a clean image.** An image whose scan failed is
  listed with its error, never with zeros.
- **Silently scanning less than was asked.** A registry stops at 500 images per
  run; when the filters match more, the page says how many were left out.
- **Credentials leaking.** The password is never returned by the API and never
  written into a Job spec; the scan pod reads it from a Secret.

## How it works

- **Filters.** `repository[:tag]`, `*` matching any run of characters. Without a
  tag part every tag matches. A repository pattern with a wildcard needs the
  registry to list repositories:
  - Docker Registry: `GET /v2/_catalog`
  - Harbor: `GET /api/v2.0/projects/{project}/repositories`
  - quay.io: `GET /api/v1/repository?namespace={org}&public=true`, plus
    `/v2/_catalog` when credentials are set
  For Harbor and quay.io the first path segment (the project or organisation)
  must be literal. Tags come from `GET /v2/{repo}/tags/list`, which all three
  serve, with the standard bearer-token challenge handled.
- **Scanning.** One Kubernetes Job per image in Sentinel's own namespace, at
  most three at a time across all registries. The pod runs the Trivy image as a
  non-root user on a read-only root filesystem, which the namespace's restricted
  Pod Security level requires. It prints one JSON line per finding and a
  completion marker; Sentinel reads the pod log, and an output without the
  marker is a failed scan.
- **Storage.** `DATA_DIR/registries.json` holds the registries.
  `DATA_DIR/registry-scans/{id}/index.json` holds the per-image summaries and the
  last run; the findings of each image are in a file of their own beside it and
  are read only when a row is expanded.
- **Schedule.** A loop checks once a minute and starts a registry whose last run
  began more than its interval ago. Jobs left behind by a restart are removed at
  startup and the run starts again on schedule.
- **RBAC.** A namespaced Role in `sentinel-system`: Jobs (create, get, list,
  delete), Pods (get, list), Pod logs (get), Secrets (create, get, update,
  delete). Nothing cluster-wide is added.
- **API.** `GET/POST /api/registries`, `PUT/DELETE /api/registries/{id}`,
  `POST /api/registries/{id}/scan`, `POST /api/registries/test`,
  `GET /api/registries/{id}/images`, `GET /api/registries/{id}/findings?image=`.
  Reads for Admin and Viewer; writes for Admin, recorded in the audit log.

## Left to the builder

Page layout within the existing UI conventions, resource requests of the scan
pod, timeouts, and where in the navigation the page sits.

## Verification

- Unit tests: filter matching, registry listing against a fake HTTP registry
  (pagination, token challenge), log parsing, job spec, scheduling, storage.
- The Trivy command line and its output format, run locally in a container with
  the same user and filesystem restrictions.
- A local Docker Registry for the listing code.
- Live: a real run in a cluster against each of the three registry kinds.
