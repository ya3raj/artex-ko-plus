# English version

This version uses English by default for the web interface, backend messages, notifications, generated report headings, and AI responses. Korean and Chinese UI catalogs remain available for comparison. Language selection is made **at build time**, because the UI is exported as static files and embedded in the Go application.

## Start locally

Install Docker Engine or Docker Desktop with Compose v2, then run:

```sh
git clone https://github.com/ya3raj/artex-ko-plus.git aegisloop
cd aegisloop
./scripts/local-start.sh
```

Open http://localhost:8787/setup/ and create your administrator password. The script generates local database and login-signing secrets; there is no shared default password. Configure your own LLM connection under **System → LLM settings** when using AI features. The default deployment starts the app and PostgreSQL, without practice targets or Splunk.

To explicitly select English:

```sh
NEXT_PUBLIC_LOCALE=en ./scripts/local-start.sh
```

To build a different UI language, set `NEXT_PUBLIC_LOCALE=ko` or `NEXT_PUBLIC_LOCALE=zh` and rebuild. Backend prose and AI output remain English in this English version. Changing a runtime environment variable alone cannot change an already-built UI. Reload your browser after rebuilding.

## Main workflows

- **Overview:** counts of saved assessment tasks, investigation cases, and evaluation records. These counts are not detection-performance metrics.
- **Offensive:** existing task, asset, finding, and traffic views. **API and source code assessment** accepts OpenAPI JSON/YAML, a URL, HAR request history, or a source ZIP. Select request paths before running the tools. Schemathesis and Semgrep collect candidates; a candidate is not a confirmed vulnerability. AI review saves each candidate's decision and can resume unfinished reviews.
- **Defensive:** prepare log evidence from files or a read-only Splunk connection; specify the target, time range, and field mapping; save an immutable case; explicitly start the bounded AI investigation; review citations, execution history, and exported original evidence. A vulnerability finding is not required to start a case.
- **Closed-loop / Real execution loop:** run a baseline verification, collect evidence linked to that execution, save a candidate rule, run a new verification with a new ID, and collect new evidence. Compare actual alerts separately from candidate shadow matches.
- **Closed-loop / Log rule evaluation:** use separate labeled tuning and evaluation logs. Compare baseline and candidate rules, review false positives, false negatives, missing fields, and calculated metrics. Synthetic examples demonstrate functionality; they are not evidence of real detection performance.

## Evidence and existing data

Commands, payloads, code, URLs, identifiers, and original log/request/response excerpts remain verbatim. Internal reasoning prompts and protocol labels are preserved where changing them would alter behavior or break stored data. Existing user-authored prompts, historical records, imported content, and screenshots retain their original language. New user-facing AI summaries are instructed to use English; existing records are not rewritten.

The default language contract is appended after editable agent prompts. If your database already contains custom Korean notification templates or report instructions, review those stored customizations in the UI. The English source defaults do not silently overwrite your custom templates.

## Development and checks

```sh
cd web
npm ci
npx tsc --noEmit
node --test tests/english-messages.test.mjs src/lib/*.test.mjs
npm run build:static
cd ..
go test ./...
```

The translation checks ensure English has the same message keys, interpolation arguments, ICU branches, and rich-text tags as Korean, with no leftover translation markers or Korean/Chinese UI text. No live target, LLM account, or Splunk connection is required for these checks.

The project retains the original attribution and AGPL-3.0 license. Read the included Terms of Use and use the software only within its permitted scope.
