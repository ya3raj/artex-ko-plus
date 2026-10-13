<div align="center">

# AegisLoop: ARTEX-based attack and defense validation

**English version of artex-ko-plus: vulnerability assessment, incident investigation, and detection improvement in one web app.**

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

[English guide](docs/ENGLISH_VERSION.md) · [Korean reference](README.ko.md) · [Upstream English documentation](README.en.md)

</div>

AegisLoop extends [ARTEX](https://github.com/Autumn-27/ARTEX) and its [Korean edition](https://github.com/jiwoochris/artex-ko), preserving their attribution and AGPL-3.0 license. The Go backend, Next.js UI, PostgreSQL storage, and existing assessment workflows are retained.

This version defaults to **English** for the interface, backend messages, report headings, notifications, and user-facing AI responses. The original application only supported Korean and Chinese UI builds; its English README did not provide an English application. All 3,942 UI messages now have an English catalog.

## Run from source

Docker Engine or Docker Desktop with Compose v2 is required. Go and Node.js are built inside containers.

```sh
git clone https://github.com/ya3raj/artex-ko-plus.git aegisloop
cd aegisloop
./scripts/local-start.sh
```

1. Open [initial setup](http://localhost:8787/setup/) and create your own administrator password. There is no shared default password.
2. Configure your own LLM connection under **System → LLM settings** when using AI features.
3. Register only targets within the project's permitted use and your authorized scope.

The app opens at [http://localhost:8787](http://localhost:8787). App and recording-proxy ports bind to `127.0.0.1` by default. The script generates local database and login-signing secrets. The default deployment includes only the app and PostgreSQL, with no saved provider keys, previous records, practice targets, or Splunk.

**Use `./scripts/local-start.sh` for this extension.** The inherited root `docker-compose.yml` and `install.sh` retain upstream installation paths and are not the default way to run AegisLoop.

## English language selection

English is the default. To select it explicitly:

```sh
NEXT_PUBLIC_LOCALE=en ./scripts/local-start.sh
```

The UI language is selected at build time to support static export and the embedded frontend. Korean and Chinese catalogs remain available through `NEXT_PUBLIC_LOCALE=ko` or `NEXT_PUBLIC_LOCALE=zh` followed by a rebuild. This English version keeps backend prose and AI output in English. There is no runtime language dropdown.

Original commands, payloads, code, URLs, identifiers, raw evidence, existing user-authored templates, and historical records retain their original content. Internal reasoning prompts and protocol labels are preserved where changing them would alter behavior or stored-data compatibility. The English output instruction is appended after editable prompts.

## Workflows

| Area | Workflow | Result |
|---|---|---|
| Overview | Review saved assessment, investigation, and evaluation records | Counts of records, not detection-performance metrics |
| Offensive | Existing ARTEX tasks, assets, findings, and traffic | Findings and reproducible evidence |
| API and source assessment | Register OpenAPI, URL, HAR, or source ZIP; select scope; run Schemathesis or Semgrep | Candidates and evidence, with saved per-candidate AI review and resume support |
| Defensive | Prepare file or read-only Splunk evidence; save an independent case; explicitly start AI investigation | Observations, hypotheses, citations, limitations, and execution history |
| Real execution loop | Baseline verification → evidence collection → candidate rule → new verification → new evidence | Execution-linked alert results and separate shadow-rule comparisons |
| Log rule evaluation | Separate labeled tuning and evaluation logs; compare baseline and candidate rules | TP/FP/TN/FN, precision, recall, false-positive rate, missing fields, and saved evaluations |
| Optional AWS Windows practice loop | Connect an existing isolated Windows/Splunk range | Practice-only execution, rule application, and evidence comparisons |

URL and HAR discovery prepare request lists; they do not infer a complete API contract or discover every endpoint. Source analysis uses a limited static rule set. **Candidates are not confirmed vulnerabilities.** AI review distinguishes static evidence from actual reproduction.

File evidence can be used without Splunk. Basic evidence preparation does not require an LLM. Starting AI investigation sends selected log excerpts and the investigation question to your configured provider; connection credentials are excluded.

Actual emitted alerts and candidate **shadow matches** are separate results. A shadow match does not establish an emitted SIEM alert or deployed policy. Two attack executions do not establish production-wide accuracy, false-positive rate, MTTD, or MTTR. Missing fields, incomplete collection, stale evidence, and attribution gaps remain explicit limitations.

General workflows do not automatically deploy operational SIEM rules or blocking policies. Optional practice-range deployment is separate from the general read-only Splunk connection.

## Development and validation

```sh
# Build and start
./scripts/local-start.sh

# Isolated integration checks with temporary PostgreSQL and mock services
./scripts/local-test.sh

# Stop the app while preserving local data
docker compose --env-file .env.local -f docker-compose.local.yml stop
```

Frontend checks:

```sh
cd web
npm ci
npx tsc --noEmit
node --test tests/english-messages.test.mjs src/lib/*.test.mjs
npm run build:static
```

Backend checks: `go test ./...` (Go 1.26.3). The English message checks verify matching keys, interpolation arguments, ICU branches, and rich-text tags, with no untranslated Korean/Chinese UI text or translation markers.

See the [English usage and build guide](docs/ENGLISH_VERSION.md) for startup, language selection, and workflow details. The [Korean reference](README.ko.md) retains historical screenshots, release evidence, and links to the original detailed guides. Those historical artifacts have not been rewritten as new English evidence.

## License and use

The project retains **GNU Affero General Public License v3.0**, the original authors' attribution, and the included usage notices. See [LICENSE](LICENSE), [Terms of Use](README.en.md#license-and-disclaimer), and [English defense guidance](docs/defense-en.md).

Use the software only within its permitted scope. Do not scan, probe, exploit, or attack systems without authorization. The software is provided as-is, without warranties; users bear responsibility for their use and applicable legal obligations.
