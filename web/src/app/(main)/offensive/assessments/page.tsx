"use client";

import { resolveLocale } from "@/i18n/config";

import * as React from "react";

import Link from "next/link";

import {
  ArrowLeftIcon,
  ArrowUpRightIcon,
  CodeXmlIcon,
  DownloadIcon,
  FileSearchIcon,
  GlobeIcon,
  LoaderCircleIcon,
  PlayIcon,
  RefreshCwIcon,
  SquareIcon,
  UploadIcon,
} from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import {
  type ApiInputMode,
  type AssessmentCatalog,
  type AssessmentDiscovery,
  type AssessmentKind,
  type AssessmentRun,
  type AssessmentStatus,
  type AssessmentTarget,
  type CandidateCheckpoint,
  type CandidateReview,
  type CandidateReviewStatus,
  offensiveApi,
} from "@/lib/offensive-api";
import type { LLMProfile } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATUS: Record<AssessmentStatus, string> = {
  queued: "Queued", running: "Assessing", completed: "Tool assessment completed",
  failed: "Assessment failed", interrupted: "Assessment interrupted",
};
const REVIEW_STATUS: Record<CandidateReviewStatus, string> = {
  queued: "Awaiting review", running: "AI review in progress", partial: "Partially reviewed",
  completed: "Candidate review completed", cancelled: "Review stopped",
  interrupted: "Review interrupted", error: "Review error",
};
const CANDIDATE_STATUS: Record<CandidateCheckpoint["status"], string> = {
  pending: "Not reviewed", running: "Reviewing", error: "Retry required",
  confirmed_static: "Static evidence confirmed", rejected: "Candidate rejected",
  insufficient_evidence: "Insufficient evidence", auth_required: "Authentication required",
  needs_dynamic_validation: "Dynamic validation required",
};
const KINDS: Record<AssessmentKind, { title: string; tool: string; description: string }> = {
  api: {
    title: "API Diagnostics",
    tool: "Schemathesis",
    description: "Register the API request in specification, URL, and HAR, and check the response and input processing of the selected request.",
  },
  source: {
    title: "Source Code Diagnostics",
    tool: "Semgrep",
    description: "Register the source ZIP to analyze the suspicious location of Java, Python, JavaScript, and TypeScript code.",
  },
};
const MAX_OPERATIONS = 40;
const REVIEW_PROFILE_STORAGE_KEY = "offensive_candidate_review_profile_id";
const INPUT_MODES: Record<ApiInputMode, { title: string; description: string; addressLabel: string }> = {
  openapi: {
    title: "OpenAPI Specification",
    description: "Checks the API request and response format defined in the specification.",
    addressLabel: "API Default Address",
  },
  url: {
    title: "URL navigation",
    description: "Find the API candidate path for the link to the startup address, etc.",
    addressLabel: "Start navigation Address",
  },
  har: {
    title: "HAR Upload",
    description: "Locate the API candidate path in the request history saved by the browser.",
    addressLabel: "API address/path to choose from HAR",
  },
};
const FILE_INPUTS = {
  source: {
    maxMiB: 20,
    accept: ".zip",
    extension: /\.zip$/i,
    label: "Source ZIP · Up to 20 MiB",
    error: "Select the ZIP file with the source code.",
  },
  openapi: {
    maxMiB: 8,
    accept: ".json,.yaml,.yml",
    extension: /\.(json|ya?ml)$/i,
    label: "OpenAPI Specification File · JSON / YAML, up to 8 MiB",
    error: "Select the OpenAPI JSON or YAML file.",
  },
  har: {
    maxMiB: 16,
    accept: ".har,.json",
    extension: /\.(har|json)$/i,
    label: "HAR file · HAR / JSON, up to 16 MiB",
    error: "Select a HAR or JSON file with a browser request history.",
  },
};

function isDiscoveredApi(target?: AssessmentTarget) {
  return target?.input_mode === "url" || target?.input_mode === "har";
}

function candidateNotice(run: AssessmentRun) {
  if (run.kind === "source")
    return "Static analysis results require a review of execution flow and input conditions. Candidate discovery does not mean dynamic reproduction success.";
  if (isDiscoveredApi(run.target_snapshot))
    return "The server error response is a candidate to review and does not mean to confirm the vulnerability. There are no specifications, so we have not checked for matching the response format. Please review the request, response and actual impact.";
  return "Security vulnerabilities are not confirmed by a specification violation or an abnormal response. Requests, responses and actual effects should be reviewed.";
}

function DiscoveryDetails({ discovery }: { discovery?: AssessmentDiscovery }) {
  if (!discovery) return null;
  return (
    <div className="space-y-2 text-muted-foreground text-xs">
      {discovery.summary && <p>{discovery.summary}</p>}
      {typeof discovery.requests === "number" && <p>Navigation request: {discovery.requests}Hoe</p>}
      {!!discovery.warnings?.length && (
        <ul className="list-disc space-y-1 pl-5">
          {[...new Set(discovery.warnings)].map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function allowedOperations(target?: AssessmentTarget) {
  return (target?.operations ?? []).filter((operation) => ["GET", "HEAD"].includes(operation.method.toUpperCase()));
}

function runTargetName(run: AssessmentRun, catalog: AssessmentCatalog | null) {
  return (
    run.target_snapshot?.name || catalog?.targets.find((target) => target.id === run.target_id)?.name || run.target_id
  );
}

function isActive(run: AssessmentRun) {
  return run.status === "queued" || run.status === "running";
}

function isReviewActive(review: CandidateReview | null) {
  return review?.status === "queued" || review?.status === "running";
}

function formatDuration(milliseconds: number) {
  if (milliseconds < 1000) return milliseconds > 0 ? "Less than one second" : "Zero Seconds";
  const seconds = Math.round(milliseconds / 1000);
  return seconds < 60 ? `${seconds}Cho` : `${Math.floor(seconds / 60)}Min ${seconds % 60}Cho`;
}

function CandidateReviewCard({ candidate }: { candidate: CandidateCheckpoint }) {
  const result = candidate.result;
  return (
    <details className="rounded-lg border p-3">
      <summary className="cursor-pointer text-sm">
        <span className="mr-2 inline-flex items-center gap-1">
          <Badge variant={candidate.status === "error" ? "destructive" : "secondary"}>
            {candidate.status === "running" && <LoaderCircleIcon className="mr-1 size-3 animate-spin" />}
            {CANDIDATE_STATUS[candidate.status] ?? candidate.status}
          </Badge>
        </span>
        <span className="font-medium">{candidate.title}</span>
        {result && candidate.attempt_count === 0 && (
          <Badge variant="outline" className="ml-2">

            Ground automatic classification
          </Badge>
        )}
        {candidate.file && (
          <span className="mt-1 block break-all font-mono text-muted-foreground text-xs">
            {candidate.file}
            {candidate.line ? `:${candidate.line}` : ""}
          </span>
        )}
        {result?.summary && <span className="mt-2 block whitespace-pre-wrap break-words">{result.summary}</span>}
      </summary>
      <div className="mt-3 space-y-3 text-sm">
        <p className="break-all text-muted-foreground text-xs">Candidate ID: {candidate.id}</p>
        {result && (
          <>
            <div>
              <p className="font-medium">Judgment grounds</p>
              <p className="mt-1 whitespace-pre-wrap break-words">{result.rationale}</p>
            </div>
            {!!result.evidence_refs?.length && (
              <div>
                <p className="font-medium">Citations</p>
                <ul className="mt-1 list-disc space-y-1 pl-5 font-mono text-xs">
                  {[...new Set(result.evidence_refs)].map((reference) => (
                    <li key={reference} className="break-all">
                      {reference}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {!!result.limitations?.length && (
              <div>
                <p className="font-medium">Additional confirmation and judgment limits</p>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground text-xs">
                  {[...new Set(result.limitations)].map((limitation) => (
                    <li key={limitation}>{limitation}</li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
        {candidate.last_error && (
          <p className="whitespace-pre-wrap break-words text-destructive text-xs">{candidate.last_error}</p>
        )}
        {!result && !candidate.last_error && (
          <p className="text-muted-foreground text-xs">
            {candidate.status === "running"
              ? "We are reviewing the rationale for this candidate, and it will be saved as soon as the verdict is made."
              : "Candidates to deal with in the next review."}
          </p>
        )}
        <p className="text-muted-foreground text-xs">

          Try Review {candidate.attempt_count}Hoe
          {candidate.finished_at ? ` · Storage ${formatTime(candidate.finished_at)}` : ""}
        </p>
      </div>
    </details>
  );
}

function formatTime(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(resolveLocale());
}

function evidenceText(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2) ?? "";
}

function errorText(value: unknown): string {
  return value instanceof Error ? value.message : "The request was not completed. Please try again in a moment.";
}

function RunStatus({ run }: { run: AssessmentRun }) {
  return (
    <Badge variant={run.status === "failed" || run.status === "interrupted" ? "destructive" : "secondary"}>
      {isActive(run) && <LoaderCircleIcon className="mr-1 size-3 animate-spin" />}
      {STATUS[run.status] ?? run.status}
    </Badge>
  );
}

export default function OffensiveAssessmentsPage() {
  const [kind, setKind] = React.useState<AssessmentKind>("api");
  const [inputMode, setInputMode] = React.useState<ApiInputMode>("openapi");
  const [catalog, setCatalog] = React.useState<AssessmentCatalog | null>(null);
  const [runs, setRuns] = React.useState<AssessmentRun[]>([]);
  const [selected, setSelected] = React.useState<AssessmentRun | null>(null);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [profileId, setProfileId] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [starting, setStarting] = React.useState(false);
  const [reviewing, setReviewing] = React.useState(false);
  const [candidateReview, setCandidateReview] = React.useState<CandidateReview | null>(null);
  const [reviewLoading, setReviewLoading] = React.useState(false);
  const [reviewError, setReviewError] = React.useState("");
  const [reviewRefresh, setReviewRefresh] = React.useState(0);
  const [batchSize, setBatchSize] = React.useState(3);
  const [cancellingReview, setCancellingReview] = React.useState(false);
  const [downloading, setDownloading] = React.useState("");
  const [openingId, setOpeningId] = React.useState("");
  const [error, setError] = React.useState("");
  const [catalogError, setCatalogError] = React.useState("");
  const [pollError, setPollError] = React.useState("");
  const [targetId, setTargetId] = React.useState("");
  const [uploadName, setUploadName] = React.useState("");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [harOrigin, setHarOrigin] = React.useState("");
  const [uploadFile, setUploadFile] = React.useState<File | null>(null);
  const [uploading, setUploading] = React.useState(false);
  const [uploadError, setUploadError] = React.useState("");
  const [uploadNotice, setUploadNotice] = React.useState("");
  const [operationIds, setOperationIds] = React.useState<string[]>([]);
  const [operationTargetId, setOperationTargetId] = React.useState("");
  const [bearerToken, setBearerToken] = React.useState("");
  const uploadFileRef = React.useRef<HTMLInputElement>(null);
  const selectionSeq = React.useRef(0);
  const refreshSeq = React.useRef(0);
  const reviewSeq = React.useRef(0);
  const profileHydrated = React.useRef(false);
  const profileManuallyChosen = React.useRef(false);
  const selectedRunRef = React.useRef<string | undefined>(undefined);
  selectedRunRef.current = selected?.id;
  const profileSelectId = React.useId();
  const batchSelectId = React.useId();
  const targetSelectId = React.useId();
  const uploadNameId = React.useId();
  const baseUrlId = React.useId();
  const harOriginId = React.useId();
  const uploadFileId = React.useId();
  const bearerId = React.useId();

  const refresh = React.useCallback(async () => {
    const seq = ++refreshSeq.current;
    setLoading(true);
    const results = await Promise.allSettled([offensiveApi.catalog(), offensiveApi.list(), api.llmProfiles()]);
    if (seq !== refreshSeq.current) return;
    const [targetResult, historyResult, profileResult] = results;
    if (targetResult.status === "fulfilled") {
      setCatalog(targetResult.value);
      setCatalogError("");
    } else {
      setCatalog(null);
      setCatalogError(errorText(targetResult.reason));
    }
    if (historyResult.status === "fulfilled") {
      const history = historyResult.value.runs ?? [];
      setRuns(history);
      setError("");
      setSelected((previous) =>
        previous ? (history.find((run) => run.id === previous.id) ?? previous) : (history[0] ?? null),
      );
      setReviewRefresh((value) => value + 1);
    } else {
      setError(errorText(historyResult.reason));
    }
    if (profileResult.status === "fulfilled") setProfiles(profileResult.value);
    setLoading(false);
  }, []);

  React.useEffect(() => {
    void refresh();
    return () => {
      refreshSeq.current += 1;
      selectionSeq.current += 1;
      reviewSeq.current += 1;
    };
  }, [refresh]);

  React.useEffect(() => {
    if (profileHydrated.current || !profiles.length) return;
    profileHydrated.current = true;
    try {
      const saved = localStorage.getItem(REVIEW_PROFILE_STORAGE_KEY);
      if (saved && profiles.some((profile) => String(profile.id) === saved)) {
        profileManuallyChosen.current = true;
        setProfileId(saved);
      }
    } catch {
      // Browsers that disable local storage can still select a model for this page.
    }
  }, [profiles]);

  const active = runs.some(isActive) || (selected ? isActive(selected) : false);
  React.useEffect(() => {
    if (!active) return;
    let alive = true;
    let polling = false;
    const selectedId = selected?.id;
    const seq = selectionSeq.current;
    const poll = async () => {
      if (polling) return;
      polling = true;
      try {
        const [history, detail] = await Promise.all([
          offensiveApi.list(),
          selectedId ? offensiveApi.get(selectedId) : Promise.resolve(null),
        ]);
        if (!alive) return;
        setRuns(history.runs ?? []);
        if (detail && seq === selectionSeq.current) {
          setSelected((previous) => ({
            ...detail,
            task_id: detail.task_id || (previous?.id === detail.id ? previous.task_id : undefined),
          }));
        }
        setPollError("");
      } catch (cause) {
        if (alive) setPollError(`Execution status update failed: ${errorText(cause)}`);
      } finally {
        polling = false;
      }
    };
    const timer = setInterval(() => void poll(), 3000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [active, selected?.id]);

  const selectedRunId = selected?.id;
  const selectedRunStatus = selected?.status;
  // biome-ignore lint/correctness/useExhaustiveDependencies: Restart polling after a mutation or an explicit refresh.
  React.useEffect(() => {
    const seq = ++reviewSeq.current;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setCandidateReview((previous) => (previous?.run_id === selectedRunId ? previous : null));
    if (!profileManuallyChosen.current) setProfileId("");
    setReviewError("");
    setReviewLoading(!!selectedRunId && selectedRunStatus === "completed");
    if (!selectedRunId || selectedRunStatus !== "completed") return;
    const loadReview = async () => {
      try {
        const result = await offensiveApi.candidateReview(selectedRunId);
        if (!alive || seq !== reviewSeq.current || selectedRunRef.current !== selectedRunId) return;
        setCandidateReview(result.review);
        if (!profileManuallyChosen.current && result.review?.profile_id) {
          setProfileId(String(result.review.profile_id));
        }
        setReviewError("");
        if (isReviewActive(result.review)) timer = setTimeout(() => void loadReview(), 2000);
      } catch (cause) {
        if (!alive || seq !== reviewSeq.current || selectedRunRef.current !== selectedRunId) return;
        setReviewError(`Failed to load AI review status: ${errorText(cause)}`);
        timer = setTimeout(() => void loadReview(), 5000);
      } finally {
        if (alive && seq === reviewSeq.current) setReviewLoading(false);
      }
    };
    void loadReview();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [selectedRunId, selectedRunStatus, reviewRefresh]);

  const targets = React.useMemo(() => (catalog?.targets ?? []).filter((item) => item.kind === kind), [catalog, kind]);
  const target = targets.find((item) => item.id === targetId);
  const operations = allowedOperations(target);
  const customApi = kind === "api" && target?.origin === "upload";
  const needsUploadFile = kind === "source" || inputMode !== "url";
  const fileInput = kind === "source" ? FILE_INPUTS.source : FILE_INPUTS[inputMode === "har" ? "har" : "openapi"];
  const isUrlRegistration = kind === "api" && inputMode === "url";
  const RegisterIcon = isUrlRegistration ? GlobeIcon : UploadIcon;
  const registerLabel = isUrlRegistration ? "Find the API in the URL" : "Upload and register as a target";
  const registeringLabel = isUrlRegistration ? "Searching for paths in URLs..." : "Uploading/ verifying...";
  const discoveredApi = isDiscoveredApi(target);
  const startLabel = discoveredApi ? "Start checking the requested you've been searched" : `${KINDS[kind].title} Start`;
  React.useEffect(() => {
    if (!targets.some((item) => item.id === targetId)) setTargetId(targets[0]?.id ?? "");
  }, [targets, targetId]);
  React.useEffect(() => {
    if (!target || target.id === operationTargetId) return;
    setOperationTargetId(target.id);
    setOperationIds(
      allowedOperations(target)
        .slice(0, MAX_OPERATIONS)
        .map((operation) => operation.id),
    );
    setBearerToken("");
  }, [target, operationTargetId]);
  const candidates = selected?.candidates ?? [];
  const artifacts = selected?.artifacts ?? [];
  const selectedDiscoveredApi = isDiscoveredApi(selected?.target_snapshot);
  const selectedReview = candidateReview?.run_id === selected?.id ? candidateReview : null;
  const reviewActive = isReviewActive(selectedReview);
  const reviewBusy = reviewing || cancellingReview || reviewLoading || reviewActive;
  const reviewProfile = selectedReview
    ? profiles.find((profile) => Number(profile.id) === selectedReview.profile_id)
    : undefined;
  const selectedProfile = profileId
    ? profiles.find((profile) => String(profile.id) === profileId)
    : (reviewProfile ?? profiles.find((profile) => profile.is_default));
  const lastAttempt = selectedReview?.attempts?.at(-1);
  const pendingCandidates = selectedReview?.pending ?? candidates.length;
  const legacyTaskId = selectedReview?.legacy_task_id || selected?.task_id;
  const reviewProgress = selectedReview?.total
    ? selectedReview.reviewed
    : Number(selectedReview?.status === "completed");
  let reviewActionLabel = "Candidate AI review begins";
  if (selectedReview) reviewActionLabel = `Remaining Candidates ${Math.min(batchSize, pendingCandidates)}Go ahead and review`;
  if (reviewActive) reviewActionLabel = "Candidate Review in progress";
  if (reviewing) reviewActionLabel = "Starting a review...";

  const changeKind = (next: AssessmentKind) => {
    if (next === kind) return;
    setKind(next);
    setTargetId("");
    setUploadFile(null);
    setUploadName("");
    setUploadError("");
    setUploadNotice("");
    setBearerToken("");
    if (uploadFileRef.current) uploadFileRef.current.value = "";
  };

  const changeInputMode = (next: ApiInputMode) => {
    setInputMode(next);
    setUploadFile(null);
    setUploadError("");
    setUploadNotice("");
    if (uploadFileRef.current) uploadFileRef.current.value = "";
  };

  const registerTarget = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if ((needsUploadFile && !uploadFile) || uploading) return;
    setUploadError("");
    setUploadNotice("");
    if (!uploadName.trim() || uploadName.trim().length > 100) {
      setUploadError("Please enter the target name in 1 to 100 characters.");
      return;
    }
    if (needsUploadFile && uploadFile) {
      if (uploadFile.size > fileInput.maxMiB * 1024 * 1024) {
        setUploadError(`The File ${fileInput.maxMiB} It has to be MiB.`);
        return;
      }
      if (!fileInput.extension.test(uploadFile.name)) {
        setUploadError(fileInput.error);
        return;
      }
    }
    if (kind === "api") {
      try {
        const url = new URL(baseUrl.trim());
        if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
          throw new Error("invalid URL");
        }
      } catch {
        setUploadError("Please enter your HTTP(S) API address. Do not include your account, password, query, or sash in the address.");
        return;
      }
      if (inputMode === "har" && harOrigin.trim()) {
        try {
          const origin = new URL(harOrigin.trim());
          if (
            !["http:", "https:"].includes(origin.protocol) ||
            origin.username ||
            origin.password ||
            origin.search ||
            origin.hash ||
            !["", "/"].includes(origin.pathname)
          ) {
            throw new Error("invalid origin");
          }
        } catch {
          setUploadError("Please enter only the HTTP(S) server address and port for the original HAR address. Do not enter a path or query.");
          return;
        }
      }
    }
    setUploading(true);
    try {
      const uploaded = await offensiveApi.uploadTarget({
        kind,
        name: uploadName.trim(),
        base_url: kind === "api" ? baseUrl.trim() : undefined,
        har_origin: kind === "api" && inputMode === "har" ? harOrigin.trim() || undefined : undefined,
        input_mode: kind === "api" ? inputMode : undefined,
        file: needsUploadFile ? (uploadFile ?? undefined) : undefined,
      });
      setCatalog((previous) => ({
        ...(previous ?? { tools: [] }),
        targets: [uploaded, ...(previous?.targets ?? []).filter((item) => item.id !== uploaded.id)],
      }));
      setTargetId(uploaded.id);
      setUploadFile(null);
      setUploadName("");
      if (uploadFileRef.current) uploadFileRef.current.value = "";
      setUploadNotice(`“${uploaded.name}“Registered complete. Check the range below and start the diagnosis.`);
    } catch (cause) {
      setUploadError(errorText(cause));
    } finally {
      setUploading(false);
    }
  };

  const start = async () => {
    if (!target?.ready || starting || (customApi && !operationIds.length)) return;
    setStarting(true);
    setError("");
    const seq = ++selectionSeq.current;
    try {
      const run = await offensiveApi.create(
        kind,
        target.id,
        customApi
          ? {
              operation_ids: operationIds,
              bearer_token: bearerToken.trim() || undefined,
            }
          : undefined,
      );
      setRuns((previous) => [run, ...previous.filter((item) => item.id !== run.id)]);
      if (seq === selectionSeq.current) setSelected(run);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBearerToken("");
      setStarting(false);
    }
  };

  const openRun = async (run: AssessmentRun) => {
    const seq = ++selectionSeq.current;
    setOpeningId(run.id);
    setError("");
    setPollError("");
    try {
      const detail = await offensiveApi.get(run.id);
      if (seq === selectionSeq.current) setSelected(detail);
    } catch (cause) {
      if (seq === selectionSeq.current) setError(errorText(cause));
    } finally {
      if (seq === selectionSeq.current) setOpeningId("");
    }
  };

  const review = async () => {
    if (!selected || reviewBusy || selected.status !== "completed") return;
    const id = selected.id;
    const persistProfileChoice = profileManuallyChosen.current;
    const seq = ++reviewSeq.current;
    setReviewing(true);
    setError("");
    try {
      const result = await offensiveApi.startCandidateReview(id, {
        llm_profile_id: profileId ? Number(profileId) : undefined,
        batch_size: batchSize,
      });
      if (persistProfileChoice) {
        try {
          if (profileId) localStorage.setItem(REVIEW_PROFILE_STORAGE_KEY, profileId);
          else localStorage.removeItem(REVIEW_PROFILE_STORAGE_KEY);
        } catch {
          // Saving the optional preference must not fail a started review.
        }
      }
      if (seq === reviewSeq.current && selectedRunRef.current === id) setCandidateReview(result.review);
    } catch (cause) {
      if (seq === reviewSeq.current && selectedRunRef.current === id) setError(errorText(cause));
    } finally {
      setReviewing(false);
      if (selectedRunRef.current === id) setReviewRefresh((value) => value + 1);
    }
  };

  const cancelReview = async () => {
    if (!selected || !reviewActive || cancellingReview || reviewing) return;
    const id = selected.id;
    const seq = ++reviewSeq.current;
    setCancellingReview(true);
    setError("");
    try {
      const result = await offensiveApi.cancelCandidateReview(id);
      if (seq === reviewSeq.current && selectedRunRef.current === id) setCandidateReview(result.review);
    } catch (cause) {
      if (seq === reviewSeq.current && selectedRunRef.current === id) setError(errorText(cause));
    } finally {
      setCancellingReview(false);
      if (selectedRunRef.current === id) setReviewRefresh((value) => value + 1);
    }
  };

  const download = async (runId: string, name: string) => {
    setDownloading(name);
    setError("");
    try {
      const blob = await offensiveApi.artifact(runId, name);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = name.split("/").pop() || "assessment-evidence";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setDownloading("");
    }
  };

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 pb-8">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <Link
            href="/offensive/"
            className="inline-flex items-center gap-1 text-muted-foreground text-xs hover:text-foreground"
          >
            <ArrowLeftIcon className="size-3" />  Diagnostic Overview
          </Link>
          <h1 className="font-semibold text-xl tracking-tight">API · Source Code Diagnostics</h1>
          <p className="text-muted-foreground text-sm">Target registration·Select → Tool diagnosis → AI review by candidate → Save·Go ahead</p>
        </div>
        <Button variant="outline" size="sm" disabled={loading || uploading || starting} onClick={() => void refresh()}>
          <RefreshCwIcon className={cn("size-4", loading && "animate-spin")} />  Refresh
        </Button>
      </div>

      {(error || pollError) && (
        <Alert variant="destructive">
          <AlertDescription role="alert">{error || pollError}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">1. Registration and selection of diagnostic subjects</CardTitle>
          <CardDescription>Select the directly registered target or installed practice example to diagnose.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            {(["api", "source"] as const).map((item) => {
              const info = KINDS[item];
              const count = catalog?.targets?.filter((entry) => entry.kind === item).length ?? 0;
              const Icon = item === "api" ? GlobeIcon : CodeXmlIcon;
              return (
                <button
                  key={item}
                  type="button"
                  aria-pressed={kind === item}
                  disabled={uploading || starting}
                  onClick={() => changeKind(item)}
                  className={cn(
                    "flex flex-col gap-3 rounded-lg border p-4 text-left transition-colors hover:bg-accent/50 focus-visible:outline-2 focus-visible:outline-ring",
                    kind === item && "border-primary bg-primary/5",
                  )}
                >
                  <div className="flex w-full items-center justify-between gap-3">
                    <span className="flex items-center gap-2 font-medium">
                      <Icon className="size-4" />
                      {info.title}
                    </span>
                    <Badge variant="outline">{loading && !catalog ? "Confirming" : `Enrollment ${count}Dog`}</Badge>
                  </div>
                  <span className="text-muted-foreground text-sm">{info.description}</span>
                  <span className="font-medium text-xs">{info.tool} + ARTEX</span>
                </button>
              );
            })}
          </div>
          {catalogError && (
            <Alert>
              <AlertDescription>
                <p className="font-medium">Failed to connect to diagnostic environment.</p>
                <p className="mt-1 break-words">{catalogError}</p>
                <p className="mt-1">

                  Prepare the local diagnostic environment and refresh it. For installation instructions, please refer to the API and Source Code Diagnostic Guide in the Deployment Document.
                  Please note.
                </p>
              </AlertDescription>
            </Alert>
          )}
          {(catalog?.message || catalog?.detail) && (
            <Alert>
              <AlertDescription>{catalog.message || catalog.detail}</AlertDescription>
            </Alert>
          )}
          <form onSubmit={(event) => void registerTarget(event)} className="space-y-3 rounded-lg border p-4">
            <div className="flex items-center gap-2 font-medium text-sm">
              <RegisterIcon className="size-4" />  My {kind === "api" ? "API" : "Source code"}  Register
            </div>
            {kind === "api" && (
              <fieldset className="space-y-2" disabled={uploading}>
                <legend className="mb-2 text-sm">How to prepare API requests</legend>
                <div className="grid gap-2 sm:grid-cols-3">
                  {(["openapi", "url", "har"] as const).map((mode) => (
                    <button
                      key={mode}
                      type="button"
                      aria-pressed={inputMode === mode}
                      onClick={() => changeInputMode(mode)}
                      className={cn(
                        "rounded-md border px-3 py-2 text-left text-sm hover:bg-accent/50 focus-visible:outline-2 focus-visible:outline-ring",
                        inputMode === mode && "border-primary bg-primary/5",
                      )}
                    >
                      {INPUT_MODES[mode].title}
                    </button>
                  ))}
                </div>
                <p className="text-muted-foreground text-xs">{INPUT_MODES[inputMode].description}</p>
              </fieldset>
            )}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor={uploadNameId}>Target name</Label>
                <Input
                  id={uploadNameId}
                  value={uploadName}
                  onChange={(event) => setUploadName(event.target.value)}
                  placeholder={kind === "api" ? "Example: Order API Development Server" : "Example: Order Service Source"}
                  required
                  maxLength={100}
                  disabled={uploading}
                />
              </div>
              {kind === "api" && (
                <div className="space-y-2">
                  <Label htmlFor={baseUrlId}>{INPUT_MODES[inputMode].addressLabel}</Label>
                  <Input
                    id={baseUrlId}
                    type="url"
                    value={baseUrl}
                    onChange={(event) => setBaseUrl(event.target.value)}
                    placeholder="http://host.docker.internal:8080/api"
                    required
                    maxLength={2048}
                    disabled={uploading}
                    autoComplete="off"
                  />
                </div>
              )}
              {kind === "api" && inputMode === "har" && (
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor={harOriginId}>If the original address / address of HAR is different</Label>
                  <Input
                    id={harOriginId}
                    type="url"
                    value={harOrigin}
                    onChange={(event) => setHarOrigin(event.target.value)}
                    placeholder="Example: http://localhost:18888"
                    maxLength={2048}
                    disabled={uploading}
                    autoComplete="off"
                  />
                  <p className="text-muted-foreground text-xs">

                    To get your browser's localhost request, go to the original address to the localhost address, to the API address above.
                    Enter the host.docker.internal address. Connect the same path to the address to be accessed by the diagnostic server.
                    Leave it empty.
                  </p>
                </div>
              )}
              {needsUploadFile && (
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor={uploadFileId}>{fileInput.label}</Label>
                  <Input
                    id={uploadFileId}
                    ref={uploadFileRef}
                    type="file"
                    accept={fileInput.accept}
                    required
                    disabled={uploading}
                    onChange={(event) => {
                      setUploadFile(event.target.files?.[0] ?? null);
                      setUploadError("");
                      setUploadNotice("");
                    }}
                  />
                </div>
              )}
            </div>
            <p className="text-muted-foreground text-xs">
              {kind === "api"
                ? "Enter the address that you have permission to diagnose. The API on this computer uses host.docker.internal instead of localhost. Select the registered GET/HEAD request to execute it."
                : "Analyze Java·Python·JavaScript·TypeScript sources. Uploaded code does not execute. .env·Certificate·Secret key and dependency folders are excluded from ZIP."}
            </p>
            {kind === "api" && inputMode === "url" && (
              <p className="text-muted-foreground text-xs">

                Restrictively browse public pages on the same server and path range. Requests after login or JavaScript
                Complement the generated API with HAR uploads. Not all of the paths found are API.
              </p>
            )}
            {kind === "api" && inputMode === "har" && (
              <p className="text-muted-foreground text-xs">

                Only the requested corresponding to the server and path entered is received. HAR's cookie/authentication headers and request body are not reused.
                Enter the Bearer token required for diagnosis separately after registering as a target.
              </p>
            )}
            {uploadError && (
              <p role="alert" className="text-destructive text-sm">
                {uploadError}
              </p>
            )}
            {uploadNotice && (
              <p role="status" className="text-primary text-sm">
                {uploadNotice}
              </p>
            )}
            <Button
              type="submit"
              variant="outline"
              disabled={
                loading ||
                uploading ||
                !catalog ||
                (needsUploadFile && !uploadFile) ||
                !uploadName.trim() ||
                (kind === "api" && !baseUrl.trim())
              }
            >
              {uploading ? <LoaderCircleIcon className="size-4 animate-spin" /> : <RegisterIcon className="size-4" />}
              {uploading ? registeringLabel : registerLabel}
            </Button>
            {uploading && kind === "api" && inputMode === "url" && (
              <p role="status" className="text-muted-foreground text-xs">

                We're checking the public route and response. Navigation can take up to about thirty seconds.
              </p>
            )}
          </form>
          <div className="space-y-2">
            <Label htmlFor={targetSelectId}>What to diagnose</Label>
            <select
              id={targetSelectId}
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
              disabled={uploading || starting || !targets.length}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            >
              {!targets.length && <option value="">Register your diagnostics first</option>}
              {targets.some((item) => item.origin === "upload") && (
                <optgroup label="Targets I registered">
                  {targets
                    .filter((item) => item.origin === "upload")
                    .map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                        {item.ready ? "" : " (Need to be prepared)"}
                      </option>
                    ))}
                </optgroup>
              )}
              {targets.some((item) => item.origin !== "upload") && (
                <optgroup label="Installed Practice Examples">
                  {targets
                    .filter((item) => item.origin !== "upload")
                    .map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                        {item.ready ? "" : " (Need to be prepared)"}
                      </option>
                    ))}
                </optgroup>
              )}
            </select>
          </div>
          {target && (
            <div className="space-y-1 rounded-md bg-muted/50 p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-medium">{target.name}</p>
                <Badge variant="outline">{target.origin === "upload" ? "Register directly" : "Practice Example"}</Badge>
                {target.kind === "api" && (
                  <Badge variant="outline">{INPUT_MODES[target.input_mode ?? "openapi"].title}</Badge>
                )}
                <Badge variant={target.ready ? "secondary" : "destructive"}>
                  {target.ready ? "Ready" : "Need to be prepared"}
                </Badge>
              </div>
              {(target.url || target.source_path) && (
                <p className="break-all font-mono text-muted-foreground text-xs">
                  {target.scope_url || target.url || target.source_path}
                </p>
              )}
              {target.revision && (
                <p className="break-all text-muted-foreground text-xs">Source version: {target.revision}</p>
              )}
              {target.detail && <p className="text-muted-foreground">{target.detail}</p>}
              {discoveredApi && (
                <p className="text-muted-foreground text-xs">

                  Searched GET·HEAD request {operations.length}Check the server error of the dog · selected request.
                </p>
              )}
              <DiscoveryDetails discovery={target.discovery} />
              {!!target.languages?.length && (
                <p className="text-muted-foreground text-xs">
                  {target.languages.join(" · ")}
                  {target.file_count != null ? ` · Sauce ${target.file_count}Dog` : ""}
                </p>
              )}
              {target.sha256 && (
                <details>
                  <summary className="cursor-pointer text-muted-foreground text-xs">Registration Data Identification Value</summary>
                  <p className="mt-1 break-all font-mono text-xs">SHA-256: {target.sha256}</p>
                </details>
              )}
            </div>
          )}
          {customApi && (
            <div className="space-y-4 rounded-lg border p-4">
              <fieldset className="space-y-3" disabled={starting}>
                <legend className="font-medium text-sm">API Request Scope · {operationIds.length}Dog Selection</legend>
                <p className="text-muted-foreground text-xs">
                  {discoveredApi
                    ? `The maximum of the searchable GET·HEAD ${MAX_OPERATIONS}Run the dog. Review the response to see if the found path is working properly with the API. There are no specifications, so we do not check whether the response type matches.`
                    : `Maximum of the uploaded GET·HEAD ${MAX_OPERATIONS}Run the dog. The path/query input is generated by the tool.`}
                </p>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      setOperationIds(operations.slice(0, MAX_OPERATIONS).map((operation) => operation.id))
                    }
                  >
                    {operations.length > MAX_OPERATIONS ? `Front ${MAX_OPERATIONS}Dog Selection` : "All Selections"}
                  </Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => setOperationIds([])}>

                    Deselect
                  </Button>
                </div>
                <div className="max-h-56 space-y-1 overflow-y-auto">
                  {operations.map((operation) => {
                    const checked = operationIds.includes(operation.id);
                    return (
                      <label
                        key={operation.id}
                        className="flex cursor-pointer items-start gap-2 rounded px-2 py-2 hover:bg-muted/50"
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={!checked && operationIds.length >= MAX_OPERATIONS}
                          onChange={(event) =>
                            setOperationIds((previous) =>
                              event.target.checked
                                ? [...previous, operation.id]
                                : previous.filter((id) => id !== operation.id),
                            )
                          }
                          className="mt-0.5 size-4 shrink-0 accent-primary"
                        />
                        <span className="break-all font-mono text-xs">
                          {operation.method.toUpperCase()} {operation.path}
                        </span>
                        {discoveredApi && (
                          <Badge variant="outline" className="shrink-0 text-[10px]">
                            {operation.confidence === "observed" ? "Request observations" : "Path Candidate"}
                          </Badge>
                        )}
                      </label>
                    );
                  })}
                </div>
                {!operations.length && (
                  <p className="text-destructive text-xs">There is no executable GET/HEAD request for this target.</p>
                )}
              </fieldset>
              <div className="space-y-2">
                <Label htmlFor={bearerId}>Bearer Tokens · Optional</Label>
                <Input
                  id={bearerId}
                  type="password"
                  value={bearerToken}
                  onChange={(event) => setBearerToken(event.target.value)}
                  autoComplete="new-password"
                  placeholder="Enter only tokens without the Bearer prefix"
                  maxLength={8192}
                  disabled={starting}
                />
                <p className="text-muted-foreground text-xs">

                  This tool is used only for diagnostic requests. Inputs are deleted after submission and are not passed to the ARTEX review.
                </p>
              </div>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-3">
            <Button
              disabled={!target?.ready || starting || active || uploading || (customApi && !operationIds.length)}
              onClick={() => void start()}
            >
              {starting ? <LoaderCircleIcon className="size-4 animate-spin" /> : <PlayIcon className="size-4" />}
              {active ? "Waiting for an ongoing diagnosis to be completed" : startLabel}
            </Button>
            <p className="text-muted-foreground text-xs">

              Tool diagnostics are executed without an LLM. AI review will begin separately after confirming the results.
            </p>
          </div>
          {active && (
            <p className="text-muted-foreground text-xs">

              The tool diagnosis is carried out one at a time. At the end of the current diagnosis, you can start the next one.
            </p>
          )}
          {!!catalog?.tools?.length && (
            <p className="text-muted-foreground text-xs">
              {catalog.tools
                .map((tool) => `${tool.id} ${tool.version || "Unidentified version"}${tool.available ? "" : " (Not available)"}`)
                .join(" · ")}
            </p>
          )}
        </CardContent>
      </Card>

      <div className="grid items-start gap-5 xl:grid-cols-[280px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Execution history</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {!runs.length && (
              <p className="text-muted-foreground text-sm">
                {loading ? "Loading..." : "There is no confirmed diagnosis yet."}
              </p>
            )}
            {runs.map((run) => (
              <button
                key={run.id}
                type="button"
                aria-pressed={selected?.id === run.id}
                disabled={openingId === run.id}
                onClick={() => void openRun(run)}
                className={cn(
                  "w-full space-y-2 rounded-lg border p-3 text-left hover:bg-accent/50",
                  selected?.id === run.id && "border-primary bg-primary/5",
                )}
              >
                <div className="flex items-center justify-between gap-2 font-medium text-sm">
                  {KINDS[run.kind]?.title ?? run.kind}
                  {openingId === run.id && <LoaderCircleIcon className="size-3 animate-spin" />}
                </div>
                <RunStatus run={run} />
                <p className="break-words text-sm">{runTargetName(run, catalog)}</p>
                <p className="text-muted-foreground text-xs">{formatTime(run.created_at)}</p>
              </button>
            ))}
          </CardContent>
        </Card>

        <div className="min-w-0 space-y-5">
          {!selected ? (
            <Card>
              <CardContent className="flex flex-col items-center gap-3 py-14 text-center text-muted-foreground">
                <FileSearchIcon className="size-8" />
                <p>Start the diagnosis or select a history of execution.</p>
                <p className="text-xs">The actual tool results and the original basis are shown here.</p>
              </CardContent>
            </Card>
          ) : (
            <>
              <Card>
                <CardHeader>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <CardTitle className="text-base">2. Confirmation of diagnostic results and grounds</CardTitle>
                    <RunStatus run={selected} />
                  </div>
                  <CardDescription className="break-all">Execution ID: {selected.id}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <dl className="grid gap-3 text-sm sm:grid-cols-2">
                    <div>
                      <dt className="text-muted-foreground text-xs">Target</dt>
                      <dd className="mt-1 break-all">
                        <span className="block font-medium">{runTargetName(selected, catalog)}</span>
                        <span className="mt-1 block text-muted-foreground text-xs">
                          {typeof selected.target === "string" ? selected.target : evidenceText(selected.target)}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground text-xs">Analytics</dt>
                      <dd className="mt-1">
                        {selected.tool} {selected.tool_version}
                      </dd>
                    </div>
                    {selected.kind === "api" && (
                      <div>
                        <dt className="text-muted-foreground text-xs">Request source · Inspection method</dt>
                        <dd className="mt-1">
                          {INPUT_MODES[selected.target_snapshot?.input_mode ?? "openapi"].title} ·{" "}
                          {selectedDiscoveredApi ? "Server Error Check" : "Specification Based Inspection"}
                        </dd>
                      </div>
                    )}
                    <div>
                      <dt className="text-muted-foreground text-xs">Start</dt>
                      <dd className="mt-1">{formatTime(selected.started_at || selected.created_at)}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground text-xs">Exit</dt>
                      <dd className="mt-1">{formatTime(selected.finished_at)}</dd>
                    </div>
                    {selected.source_revision && (
                      <div className="sm:col-span-2">
                        <dt className="text-muted-foreground text-xs">Diagnosed source version</dt>
                        <dd className="mt-1 break-all font-mono text-xs">{selected.source_revision}</dd>
                      </div>
                    )}
                    {selected.target_snapshot?.sha256 && (
                      <div className="sm:col-span-2">
                        <dt className="text-muted-foreground text-xs">Registration data used for diagnosis SHA-256</dt>
                        <dd className="mt-1 break-all font-mono text-xs">{selected.target_snapshot.sha256}</dd>
                      </div>
                    )}
                  </dl>
                  {selectedDiscoveredApi && (
                    <details className="rounded-md border p-3">
                      <summary className="cursor-pointer text-sm">API navigation range · limit</summary>
                      <div className="mt-2">
                        <DiscoveryDetails discovery={selected.target_snapshot?.discovery} />
                      </div>
                    </details>
                  )}
                  {!!selected.operation_ids?.length && (
                    <details className="rounded-md border p-3">
                      <summary className="cursor-pointer text-sm">

                        Scope of the executed API request · {selected.operation_ids.length}Dog
                      </summary>
                      <ul className="mt-2 space-y-1 break-all font-mono text-muted-foreground text-xs">
                        {selected.operation_ids.map((id) => {
                          const operation = selected.target_snapshot?.operations?.find((item) => item.id === id);
                          return (
                            <li key={id}>{operation ? `${operation.method.toUpperCase()} ${operation.path}` : id}</li>
                          );
                        })}
                      </ul>
                    </details>
                  )}
                  {selected.summary && <p className="whitespace-pre-wrap text-sm">{selected.summary}</p>}
                  {selected.error && (
                    <Alert variant="destructive">
                      <AlertDescription>{selected.error}</AlertDescription>
                    </Alert>
                  )}
                  {isActive(selected) && (
                    <p role="status" className="flex items-center gap-2 text-muted-foreground text-sm">
                      <LoaderCircleIcon className="size-4 animate-spin" />

                      The tool is running. Once done, the results will be automatically renewed.
                    </p>
                  )}
                  <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm">
                    <p className="font-medium">Tool Discovery Candidate {candidates.length}Before the vulnerability is confirmed.</p>
                    <p className="mt-1 text-muted-foreground text-xs">{candidateNotice(selected)}</p>
                  </div>
                  {candidates.length > 0 ? (
                    <div className="max-h-[680px] space-y-2 overflow-y-auto pr-1">
                      {candidates.map((candidate, index) => (
                        <details
                          key={candidate.id || `${candidate.rule_id}-${index}`}
                          className="rounded-lg border p-3"
                        >
                          <summary className="cursor-pointer font-medium text-sm">
                            <span className="mr-2 text-muted-foreground text-xs">{candidate.severity}</span>
                            {candidate.title}
                            {candidate.file && (
                              <span className="mt-1 block break-all font-mono font-normal text-muted-foreground text-xs">
                                {candidate.file}
                                {candidate.line ? `:${candidate.line}` : ""}
                              </span>
                            )}
                          </summary>
                          <div className="mt-3 space-y-2 text-sm">
                            <Badge variant="outline">Tool Original Nominee</Badge>
                            {candidate.rule_id && (
                              <p className="break-all text-muted-foreground text-xs">Rules: {candidate.rule_id}</p>
                            )}
                            <p className="whitespace-pre-wrap break-words">{candidate.message}</p>
                            {candidate.evidence != null && (
                              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                                {evidenceText(candidate.evidence)}
                              </pre>
                            )}
                          </div>
                        </details>
                      ))}
                    </div>
                  ) : (
                    selected.status === "completed" && (
                      <p className="text-muted-foreground text-sm">

                        We have not found a candidate in this scope of tools, rules, and execution. This does not mean that there are no vulnerabilities in the target.
                      </p>
                    )
                  )}
                  {!!selected.limitations?.length && (
                    <details className="rounded-md border p-3" open>
                      <summary className="cursor-pointer font-medium text-sm">Diagnostic scope · Limitations of interpretation</summary>
                      <ul className="mt-2 list-disc space-y-1 pl-5 text-muted-foreground text-xs">
                        {[...new Set(selected.limitations)].map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </details>
                  )}
                  {artifacts.length > 0 && (
                    <div className="space-y-2">
                      <p className="font-medium text-sm">Download original results</p>
                      {artifacts.map((artifact) => (
                        <div
                          key={artifact.name}
                          className="flex flex-wrap items-start justify-between gap-2 rounded-md border p-3"
                        >
                          <div className="min-w-0 flex-1">
                            <p className="break-all text-sm">{artifact.name}</p>
                            {artifact.sha256 && (
                              <p className="mt-1 break-all font-mono text-[10px] text-muted-foreground">
                                SHA-256: {artifact.sha256}
                              </p>
                            )}
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={!!downloading}
                            onClick={() => void download(selected.id, artifact.name)}
                          >
                            {downloading === artifact.name ? (
                              <LoaderCircleIcon className="size-3 animate-spin" />
                            ) : (
                              <DownloadIcon className="size-3" />
                            )}{" "}

                            Download
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <CardTitle className="text-base">3. Review and continue AI by candidate</CardTitle>
                    {selectedReview && (
                      <Badge variant={selectedReview.status === "error" ? "destructive" : "secondary"}>
                        {reviewActive && <LoaderCircleIcon className="mr-1 size-3 animate-spin" />}
                        {REVIEW_STATUS[selectedReview.status] ?? selectedReview.status}
                      </Badge>
                    )}
                  </div>
                  <CardDescription>

                    Review the number of candidates and save them one by one. The next review will continue from the unreviewed and error candidates.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-muted-foreground text-xs">
                    {selected.kind === "source"
                      ? "Review the stored source and static analysis basis. ‘Check static basis’ is distinguished from the reenactment of vulnerabilities through actual execution."
                      : "Review the stored API request and response basis. This step does not send new HTTP requests or reproduce vulnerabilities."}{" "}

                    The judgment is stored on this screen and is not automatically confirmed or registered due to vulnerabilities.
                  </p>
                  {reviewError && (
                    <Alert variant="destructive">
                      <AlertDescription role="alert">
                        <p>{reviewError}</p>
                        <Button
                          variant="outline"
                          size="sm"
                          className="mt-2"
                          onClick={() => setReviewRefresh((value) => value + 1)}
                        >
                          <RefreshCwIcon className="size-3" />  Reload Status
                        </Button>
                      </AlertDescription>
                    </Alert>
                  )}
                  {reviewLoading && (
                    <p role="status" className="flex items-center gap-2 text-muted-foreground text-xs">
                      <LoaderCircleIcon className="size-3 animate-spin" />  Loading a saved candidate review...
                    </p>
                  )}
                  {selectedReview && (
                    <div className="space-y-3 rounded-lg border bg-muted/30 p-4">
                      <div aria-live="polite" className="flex flex-wrap items-center justify-between gap-2">
                        <p className="font-medium text-sm">

                          Saved Judgments {selectedReview.reviewed} / {selectedReview.total}Gun
                        </p>
                        <p className="text-muted-foreground text-xs">Remaining Candidates {selectedReview.pending}Gun</p>
                      </div>
                      <progress
                        aria-label="Candidate Review Complete Rates"
                        max={selectedReview.total || 1}
                        value={reviewProgress}
                        className="h-2 w-full accent-primary"
                      />
                      {selectedReview.reason && (
                        <p className="whitespace-pre-wrap break-words text-sm">{selectedReview.reason}</p>
                      )}
                      {reviewProfile && (
                        <p className="text-muted-foreground text-xs">

                          Recent review models: {reviewProfile.name} · {reviewProfile.model}
                        </p>
                      )}
                      <p className="text-muted-foreground text-xs">

                        Last Save: {formatTime(selectedReview.updated_at)}
                      </p>
                      {lastAttempt && (
                        <dl className="grid gap-2 text-xs sm:grid-cols-3">
                          <div>
                            <dt className="text-muted-foreground">Call this model</dt>
                            <dd className="mt-1">
                              {lastAttempt.model_calls}sashimi · {formatDuration(lastAttempt.model_elapsed_ms)}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-muted-foreground">Wait for Review Queue</dt>
                            <dd className="mt-1">{formatDuration(lastAttempt.queue_wait_ms)}</dd>
                          </div>
                          <div>
                            <dt className="text-muted-foreground">This Review Time</dt>
                            <dd className="mt-1">
                              {formatDuration(Math.max(0, lastAttempt.active_elapsed_ms, lastAttempt.model_elapsed_ms))}
                            </dd>
                          </div>
                        </dl>
                      )}
                      <p className="text-muted-foreground text-xs">

                        ‘Certification required’ and ‘lack of foundation’ are also included in the saved judgment. The decision completed after the stop and timeout is also included.
                        maintained.
                      </p>
                    </div>
                  )}
                  {selectedReview?.status !== "completed" && (
                    <>
                      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_170px]">
                        <div className="space-y-2">
                          <Label htmlFor={profileSelectId}>Review Model</Label>
                          <select
                            id={profileSelectId}
                            value={profileId}
                            onChange={(event) => {
                              profileManuallyChosen.current = true;
                              setProfileId(event.target.value);
                            }}
                            disabled={reviewBusy}
                            className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                          >
                            <option value="">
                              {selectedReview ? "Enable previous review model settings" : "System Basic LLM Setting"}
                            </option>
                            {profiles.map((profile) => (
                              <option key={profile.id} value={profile.id}>
                                {profile.name} · {profile.model}
                                {profile.is_default ? " (Basic)" : ""}
                              </option>
                            ))}
                          </select>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor={batchSelectId}>Candidates to review at once</Label>
                          <select
                            id={batchSelectId}
                            value={batchSize}
                            onChange={(event) => setBatchSize(Number(event.target.value))}
                            disabled={reviewBusy}
                            className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                          >
                            {[1, 2, 3, 4, 5].map((size) => (
                              <option key={size} value={size}>
                                {size}Gun
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>
                      {selectedProfile && (
                        <div className="space-y-1 text-muted-foreground text-xs">
                          <p>

                            Limit selection model calls:{" "}
                            {selectedProfile.rate_per_minute > 0
                              ? `Bundang ${selectedProfile.rate_per_minute}hoe`
                              : "Limits per minute unset"}
                            {selectedProfile.rate_per_second > 0 ? ` · Per second ${selectedProfile.rate_per_second}hoe` : ""}
                          </p>
                          {selectedProfile.rate_per_minute === 1 && (
                            <p className="text-amber-700 dark:text-amber-400">

                              Once a minute setting, you can increase the wait per candidate. Choose a profile for quick review or provider
                              Set it to the limit.
                            </p>
                          )}
                        </div>
                      )}
                      <Link
                        href="/system/llm/"
                        className="inline-block text-primary text-xs underline underline-offset-4"
                      >

                        LLM Connection · Call Limit Setting
                      </Link>
                      <p className="text-muted-foreground text-xs">

                        During the AI review, the diagnostic basis and the required source and response content will be sent to the selected LLM, resulting in model usage.
                        If you handle the number of candidates you set, it will end and will not automatically generate subsequent attacks and investigations.
                      </p>
                      <div className="flex flex-wrap items-center gap-2">
                        <Button
                          disabled={selected.status !== "completed" || reviewBusy || !!reviewError}
                          onClick={() => void review()}
                        >
                          {reviewing || reviewActive ? (
                            <LoaderCircleIcon className="size-4 animate-spin" />
                          ) : (
                            <FileSearchIcon className="size-4" />
                          )}
                          {reviewActionLabel}
                        </Button>
                        {reviewActive && (
                          <Button
                            variant="outline"
                            disabled={cancellingReview || reviewing}
                            onClick={() => void cancelReview()}
                          >
                            {cancellingReview ? (
                              <LoaderCircleIcon className="size-4 animate-spin" />
                            ) : (
                              <SquareIcon className="size-3" />
                            )}
                            {cancellingReview ? "Request to stop..." : "Stop Reviewing"}
                          </Button>
                        )}
                      </div>
                    </>
                  )}
                  {selected.status !== "completed" && (
                    <p className="text-muted-foreground text-xs">

                      You can start an AI review in a run where the tool diagnosis is completed as normal.
                    </p>
                  )}
                  {selected.status === "completed" && !candidates.length && (
                    <p className="text-muted-foreground text-xs">

                      No model calls are required because there are no found candidates. The result of no candidate is not guaranteed to be a vulnerability.
                      No.
                    </p>
                  )}
                  {!!selectedReview?.candidates?.length && (
                    <div className="space-y-2">
                      <p className="font-medium text-sm">Save Results by Candidate</p>
                      {selectedReview.candidates.map((candidate) => (
                        <CandidateReviewCard key={candidate.id} candidate={candidate} />
                      ))}
                    </div>
                  )}
                  {!!selectedReview?.attempts?.length && (
                    <details className="rounded-md border p-3">
                      <summary className="cursor-pointer text-sm">

                        Review · E-Eating history {selectedReview.attempts.length}hoe
                      </summary>
                      <div className="mt-3 space-y-3">
                        {[...selectedReview.attempts].reverse().map((attempt) => (
                          <div key={attempt.id} className="space-y-1 border-b pb-3 text-xs last:border-0 last:pb-0">
                            <p className="font-medium">
                              {formatTime(attempt.queued_at)} · {REVIEW_STATUS[attempt.status] ?? attempt.status}
                            </p>
                            <p className="text-muted-foreground">

                              Max {attempt.batch_size}Gun · Model {attempt.model_calls}Assembly · Input{" "}
                              {attempt.input_tokens.toLocaleString()}  / Output {attempt.output_tokens.toLocaleString()}{" "}

                              Tokens
                            </p>
                            <p className="text-muted-foreground">

                              Queue waiting {formatDuration(attempt.queue_wait_ms)}  · Model call·Wait{" "}
                              {formatDuration(attempt.model_elapsed_ms)}  · Review Execution{" "}
                              {formatDuration(Math.max(0, attempt.active_elapsed_ms, attempt.model_elapsed_ms))}
                            </p>
                            {attempt.reason && <p className="whitespace-pre-wrap break-words">{attempt.reason}</p>}
                          </div>
                        ))}
                      </div>
                    </details>
                  )}
                  {legacyTaskId && (
                    <div className="border-t pt-3">
                      <Link
                        href={`/function/tasks/detail?id=${encodeURIComponent(legacyTaskId)}`}
                        className="inline-flex items-center gap-1 text-muted-foreground text-xs underline underline-offset-4"
                      >

                        Open previous ARTEX review jobs <ArrowUpRightIcon className="size-3" />
                      </Link>
                      <p className="mt-1 text-muted-foreground text-xs">

                        Existing work history is preserved. The candidate-specific review above is conducted separately from the stored tool basis.
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
