const form = document.querySelector("#compare-form");
const profileName = document.querySelector("#profile-name");
const stagingUrl = document.querySelector("#staging-url");
const productionUrl = document.querySelector("#production-url");
const hostUrl = document.querySelector("#host-url");
const hostIp = document.querySelector("#host-ip");
const releaseId = document.querySelector("#release-id");
const updatedAt = document.querySelector("#updated-at");
const pathsInput = document.querySelector("#paths");
const normalizeHtml = document.querySelector("#normalize-html");
const comparisonMode = document.querySelector("#comparison-mode");
const probeTimeout = document.querySelector("#probe-timeout");
const assetLimit = document.querySelector("#asset-limit");
const batchSize = document.querySelector("#batch-size");
const modeHelp = document.querySelector("#mode-help");
const sampleButton = document.querySelector("#sample-button");
const runButton = document.querySelector("#run-button");
const cancelButton = document.querySelector("#cancel-button");
const progressPanel = document.querySelector("#progress-panel");
const progressLabel = document.querySelector("#progress-label");
const progressCount = document.querySelector("#progress-count");
const progressBar = document.querySelector("#progress-bar");
const pathCount = document.querySelector("#path-count");
const resultsRoot = document.querySelector("#results");
const empty = document.querySelector("#empty");
const notice = document.querySelector("#notice");
const summaryText = document.querySelector("#summary-text");
const csvButton = document.querySelector("#csv-button");
const jsonButton = document.querySelector("#json-button");
const toast = document.querySelector("#toast");
let lastReport = null;
let toastTimer;
let cancelRequested = false;
let activeBatchController = null;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 3400);
}

function parsePaths() {
  return pathsInput.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
    const separator = line.indexOf("||");
    if (separator === -1) return { value: line, expectedText: "" };
    return { value: line.slice(0, separator).trim(), expectedText: line.slice(separator + 2).trim() };
  });
}

function updateCount() {
  const count = parsePaths().length;
  pathCount.textContent = count + " / 20";
  pathCount.style.color = count > 20 ? "var(--bad)" : "";
}

function setLoading(value) {
  runButton.disabled = value;
  sampleButton.disabled = value;
  comparisonMode.disabled = value;
  probeTimeout.disabled = value;
  assetLimit.disabled = value;
  batchSize.disabled = value;
  cancelButton.disabled = !value;
  progressPanel.classList.toggle("hidden", !value);
  runButton.textContent = value ? "Comparing in safe batches…" : "▶ Run environment comparison";
}

function setProgress(label, percentage) {
  const value = Math.max(0, Math.min(100, Math.round(percentage)));
  progressLabel.textContent = label;
  progressCount.textContent = value + "%";
  progressBar.value = value;
  progressBar.textContent = value + "%";
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1024) return value + " B";
  if (value < 1048576) return (value / 1024).toFixed(1) + " KiB";
  return (value / 1048576).toFixed(2) + " MiB";
}

function shortHash(value) {
  return value ? value.slice(0, 12) : "—";
}

function snapshotBlock(snapshot) {
  const section = document.createElement("section");
  section.className = "snapshot";
  const name = document.createElement("div");
  name.className = "snapshot-name";
  const title = document.createElement("b");
  title.textContent = snapshot.label || snapshot.environment;
  const status = document.createElement("span");
  status.textContent = snapshot.status ? "HTTP " + snapshot.status : "ERROR";
  name.append(title, status);
  const url = document.createElement("div");
  url.className = "snapshot-url";
  url.textContent = snapshot.url || "";
  url.title = snapshot.url || "";
  const list = document.createElement("dl");
  const fields = [
    ["Release", snapshot.release?.releaseId || "—"],
    ["Delivery", snapshot.delivery || "—"],
    ["Age", snapshot.ttl ? snapshot.ttl.ageSeconds + "s" : "—"],
    ["Hash", shortHash(snapshot.normalizedHash || snapshot.hash)],
    ["Connected IP", snapshot.connectedIp || "—"],
    ["Size", formatBytes(snapshot.sizeBytes)]
  ];
  for (const [label, value] of fields) {
    const term = document.createElement("dt");
    term.textContent = label;
    const data = document.createElement("dd");
    data.textContent = value;
    data.title = value;
    list.append(term, data);
  }
  section.append(name, url, list);
  return section;
}

function evidenceBlock(snapshot) {
  const box = document.createElement("div");
  box.className = "evidence";
  const heading = document.createElement("h4");
  heading.textContent = snapshot.label || snapshot.environment;
  box.append(heading);
  const rows = [
    ["Recency", (snapshot.verdict || "—") + " / " + (snapshot.confidence || "—")],
    ["Reason", snapshot.rationale || "—"],
    ["Raw hash", snapshot.hash || "—"],
    ["Normalized", snapshot.normalizedHash || "—"],
    ["ETag", snapshot.headers?.etag || "—"],
    ["Last modified", snapshot.headers?.["last-modified"] || "—"],
    ["X-Cache", snapshot.headers?.["x-cache"] || "—"],
    ["X-Varnish", snapshot.headers?.["x-varnish"] || "—"],
    ["TLS", snapshot.tls ? (snapshot.tls.authorized ? "Verified" : "Not verified") : "Not used"],
    ["Host / SNI", snapshot.requestedHost || "—"]
  ];
  for (const [label, value] of rows) {
    const row = document.createElement("p");
    const key = document.createElement("b");
    key.textContent = label + ": ";
    row.append(key, document.createTextNode(String(value)));
    row.title = String(value);
    box.append(row);
  }
  return box;
}

function resultCard(item) {
  const card = document.createElement("article");
  card.className = "comparison-card";
  const head = document.createElement("div");
  head.className = "comparison-head";
  const path = document.createElement("div");
  path.className = "path";
  const title = document.createElement("strong");
  title.textContent = item.path;
  const reason = document.createElement("p");
  reason.textContent = item.comparison.rationale + " Confidence: " + item.comparison.confidence + ".";
  path.append(title, reason);
  const verdict = document.createElement("span");
  verdict.className = "verdict " + item.comparison.severity;
  verdict.textContent = item.comparison.label;
  head.append(path, verdict);

  const snapshotGrid = document.createElement("div");
  snapshotGrid.className = "snapshot-grid";
  item.snapshots.forEach((snapshot) => snapshotGrid.append(snapshotBlock(snapshot)));

  const details = document.createElement("details");
  const detailsTitle = document.createElement("summary");
  detailsTitle.textContent = "Full evidence";
  const evidence = document.createElement("div");
  evidence.className = "evidence-grid";
  item.snapshots.forEach((snapshot) => evidence.append(evidenceBlock(snapshot)));
  details.append(detailsTitle, evidence);
  card.append(head, snapshotGrid, details);
  return card;
}

function render(report) {
  lastReport = report;
  resultsRoot.replaceChildren(...report.results.map(resultCard));
  empty.classList.add("hidden");
  resultsRoot.classList.remove("hidden");
  csvButton.disabled = false;
  jsonButton.disabled = false;
  document.querySelector("#stat-total").textContent = report.summary.total;
  document.querySelector("#stat-current").textContent = report.summary.current;
  document.querySelector("#stat-stale").textContent = report.summary.cdnStale;
  document.querySelector("#stat-review").textContent = report.summary.review + report.summary.errors;
  summaryText.textContent = report.profileName + " · " + new Date(report.checkedAt).toLocaleString();
  const messages = [report.note, ...(report.warnings || [])].filter(Boolean);
  notice.textContent = messages.join(" ");
  notice.classList.toggle("hidden", !messages.length);
}

function csvCell(value) {
  return '"' + String(value ?? "").replaceAll('"', '""') + '"';
}

function download(name, blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

csvButton.addEventListener("click", () => {
  if (!lastReport) return;
  const columns = ["path", "kind", "comparison", "severity", "confidence", "environment", "url", "status", "releaseId", "delivery", "age", "etag", "lastModified", "rawHash", "normalizedHash", "connectedIp", "overrideIp", "tlsVerified", "rationale"];
  const rows = [];
  for (const result of lastReport.results) {
    for (const snapshot of result.snapshots) {
      const values = [
        result.path, result.kind, result.comparison.code, result.comparison.severity, result.comparison.confidence,
        snapshot.environment, snapshot.url, snapshot.status, snapshot.release?.releaseId, snapshot.delivery,
        snapshot.ttl?.ageSeconds, snapshot.headers?.etag, snapshot.headers?.["last-modified"], snapshot.hash,
        snapshot.normalizedHash, snapshot.connectedIp, snapshot.overrideIp, snapshot.tls?.authorized, snapshot.rationale
      ];
      rows.push(values.map(csvCell).join(","));
    }
  }
  download("environment-cache-comparison.csv", new Blob([[columns.join(","), ...rows].join("\r\n")], { type: "text/csv;charset=utf-8" }));
});

jsonButton.addEventListener("click", () => {
  if (!lastReport) return;
  download("environment-cache-comparison.json", new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" }));
});

sampleButton.addEventListener("click", () => {
  stagingUrl.value = "https://example.com";
  productionUrl.value = "https://example.com";
  hostUrl.value = "";
  hostIp.value = "";
  releaseId.value = "";
  updatedAt.value = "";
  pathsInput.value = "/ || Example Domain\n/";
  updateCount();
  showToast("Example loaded. Replace the URLs with your staging and production environments.");
});

function splitIntoBatches(targets, size) {
  const batches = [];
  for (let index = 0; index < targets.length; index += size) batches.push(targets.slice(index, index + size));
  return batches;
}

function summarize(results) {
  return {
    total: results.length,
    current: results.filter((item) => item.comparison.severity === "good").length,
    cdnStale: results.filter((item) => item.comparison.code === "cdn-stale").length,
    review: results.filter((item) => item.comparison.severity === "warn").length,
    errors: results.filter((item) => item.comparison.severity === "error").length
  };
}

function failureResults(targets, environments, kind, message) {
  return targets.map((target) => ({
    path: target.value,
    kind,
    expectedText: target.expectedText || "",
    comparison: { code: "error", label: "Batch failed", severity: "error", confidence: "high", rationale: message },
    snapshots: environments.map((environment) => {
      let url = target.value;
      try { url = new URL(target.value, environment.baseUrl).href; } catch { /* Keep the supplied path. */ }
      return {
        environment: environment.key,
        label: environment.label,
        kind,
        url,
        verdict: "error",
        confidence: "high",
        errorType: "batch",
        rationale: message,
        headers: {},
        release: { releaseId: "", builtAt: "", source: "" }
      };
    })
  }));
}

function createReport(base, state) {
  return {
    profileName: base.profileName || "Environment comparison",
    checkedAt: new Date().toISOString(),
    environments: base.environments,
    options: {
      normalizeHtml: base.normalizeHtml,
      expectedReleaseId: base.expectedReleaseId,
      contentUpdatedAt: base.contentUpdatedAt,
      comparisonMode: base.comparisonMode,
      timeoutMs: base.timeoutMs,
      retryCount: 1,
      targetConcurrency: 2,
      batchDeadlineMs: 40_000,
      assetDiscoveryLimit: base.assetDiscoveryLimit
    },
    summary: summarize(state.results),
    warnings: [...state.warnings],
    results: [...state.results],
    note: state.cancelled
      ? "The run was cancelled. Completed batches and their evidence were preserved."
      : "Results are requested in short batches so a slow target does not discard completed evidence."
  };
}

async function requestBatch(body) {
  let lastError;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (cancelRequested) throw new DOMException("Comparison cancelled", "AbortError");
    const controller = new AbortController();
    activeBatchController = controller;
    let clientTimedOut = false;
    const timer = setTimeout(() => {
      clientTimedOut = true;
      controller.abort();
    }, 45_000);
    try {
      const response = await fetch("/api/compare-batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify(body)
      });
      const text = await response.text();
      let payload = {};
      try { payload = JSON.parse(text || "{}"); } catch { payload = {}; }
      if (response.ok) return payload;
      const error = new Error(payload.error || "Comparison batch failed with HTTP " + response.status);
      error.status = response.status;
      throw error;
    } catch (error) {
      if (cancelRequested) throw error;
      lastError = clientTimedOut ? new Error("Comparison batch exceeded the 45-second client deadline") : error;
      const transient = clientTimedOut || error.name === "TypeError" || [502, 503, 504].includes(error.status);
      if (!transient || attempt === 1) throw lastError;
      await new Promise((resolve) => setTimeout(resolve, 350 + Math.floor(Math.random() * 250)));
    } finally {
      clearTimeout(timer);
      if (activeBatchController === controller) activeBatchController = null;
    }
  }
  throw lastError;
}

async function runPhase(targets, kind, base, state, startPercent, percentRange) {
  const batches = splitIntoBatches(targets, base.batchSize);
  for (let index = 0; index < batches.length; index += 1) {
    if (cancelRequested) {
      state.cancelled = true;
      break;
    }
    const batch = batches[index];
    setProgress((kind === "page" ? "Pages" : "Assets") + " · batch " + (index + 1) + " of " + batches.length, startPercent + (index / batches.length) * percentRange);
    try {
      const payload = await requestBatch({
        ...base,
        targets: batch,
        targetKind: kind,
        discoverAssets: kind === "page" && base.assetDiscoveryLimit > 0,
        targetConcurrency: Math.min(2, batch.length),
        retryCount: 1,
        batchDeadlineMs: 40_000
      });
      state.results.push(...(payload.results || []));
      for (const warning of payload.warnings || []) state.warnings.add(warning);
      for (const asset of payload.discoveredAssets || []) {
        if (state.discoveredAssets.length >= base.assetDiscoveryLimit) break;
        if (!state.seenPaths.has(asset)) {
          state.seenPaths.add(asset);
          state.discoveredAssets.push({ value: asset, expectedText: "" });
        }
      }
    } catch (error) {
      if (cancelRequested) {
        state.cancelled = true;
        break;
      }
      const message = error.message || "Comparison batch failed";
      state.results.push(...failureResults(batch, base.environments, kind, message));
      state.warnings.add((kind === "page" ? "Page" : "Asset") + " batch " + (index + 1) + " failed after one retry: " + message);
    }
    render(createReport(base, state));
    setProgress((kind === "page" ? "Pages" : "Assets") + " · batch " + (index + 1) + " of " + batches.length, startPercent + ((index + 1) / batches.length) * percentRange);
  }
}

comparisonMode.addEventListener("change", () => {
  modeHelp.textContent = comparisonMode.value === "deep"
    ? "Deep mode runs normal and cache-bypass probes for every environment. It is slower and should use small batches."
    : "Quick mode bypasses cache only for the production CDN, reducing outbound requests by one third.";
});

cancelButton.addEventListener("click", () => {
  cancelRequested = true;
  activeBatchController?.abort();
  cancelButton.disabled = true;
  progressLabel.textContent = "Cancelling after completed work is saved…";
});

pathsInput.addEventListener("input", updateCount);
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const targets = parsePaths();
  if (!targets.length || targets.length > 20) {
    showToast("Enter between 1 and 20 page or asset paths.");
    return;
  }
  if (hostIp.value.trim() && !hostUrl.value.trim()) {
    showToast("A production hostname URL is required when forcing an IP.");
    return;
  }
  const environments = [
    { key: "staging", label: "Staging", baseUrl: stagingUrl.value.trim() },
    { key: "productionCdn", label: "Production CDN", baseUrl: productionUrl.value.trim() }
  ];
  if (hostUrl.value.trim()) {
    environments.push({
      key: "productionHost",
      label: hostIp.value.trim() ? "Production host via IP" : "Production host",
      baseUrl: hostUrl.value.trim(),
      overrideIp: hostIp.value.trim()
    });
  }

  const selectedAssetLimit = Number(assetLimit.value);
  const base = {
    profileName: profileName.value.trim(),
    environments,
    expectedReleaseId: releaseId.value.trim(),
    contentUpdatedAt: updatedAt.value ? new Date(updatedAt.value).toISOString() : "",
    normalizeHtml: normalizeHtml.checked,
    comparisonMode: comparisonMode.value,
    timeoutMs: Number(probeTimeout.value),
    assetDiscoveryLimit: selectedAssetLimit,
    batchSize: Number(batchSize.value)
  };
  const state = {
    results: [],
    warnings: new Set(),
    discoveredAssets: [],
    seenPaths: new Set(targets.map((target) => target.value)),
    cancelled: false
  };

  cancelRequested = false;
  setLoading(true);
  setProgress("Preparing page batches…", 0);
  notice.classList.add("hidden");
  summaryText.textContent = "Running short comparison batches; completed evidence will appear below.";
  try {
    await runPhase(targets, "page", base, state, 0, selectedAssetLimit > 0 ? 70 : 100);
    if (!cancelRequested && state.discoveredAssets.length) {
      await runPhase(state.discoveredAssets, "asset", base, state, 70, 30);
    }
    if (!state.results.length) throw new Error(cancelRequested ? "Comparison cancelled before a batch completed." : "No comparison result was returned.");
    render(createReport(base, state));
    setProgress(state.cancelled ? "Comparison cancelled" : "Comparison complete", state.cancelled ? progressBar.value : 100);
    showToast(state.cancelled ? "Comparison cancelled; completed results were kept." : "Environment comparison complete.");
  } catch (error) {
    summaryText.textContent = "Comparison did not complete.";
    notice.textContent = error.message;
    notice.classList.remove("hidden");
    showToast(error.message);
  } finally {
    setLoading(false);
  }
});

updateCount();
