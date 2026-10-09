const form = document.querySelector("#check-form");
const baseUrlInput = document.querySelector("#base-url");
const targetList = document.querySelector("#target-list");
const expectedEdgeInput = document.querySelector("#expected-edge");
const discoverAssetsInput = document.querySelector("#discover-assets");
const runButton = document.querySelector("#run-button");
const sampleButton = document.querySelector("#sample-button");
const exportButton = document.querySelector("#export-button");
const resultsRoot = document.querySelector("#results");
const emptyState = document.querySelector("#empty-state");
const notice = document.querySelector("#notice");
const summary = document.querySelector("#run-summary");
const targetCount = document.querySelector("#target-count");
const toast = document.querySelector("#toast");
let lastResults = [];
let toastTimer;

const verdictLabels = {
  current: "Current",
  consistent: "Consistent",
  stale: "Stale",
  different: "Review",
  "marker-missing": "Marker missing",
  unverifiable: "Unverifiable",
  limited: "Limited",
  error: "Error"
};

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 3500);
}

function parseTargets() {
  return targetList.value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const separator = line.indexOf("||");
      if (separator === -1) return { value: line, expectedText: "" };
      return {
        value: line.slice(0, separator).trim(),
        expectedText: line.slice(separator + 2).trim()
      };
    });
}

function updateTargetCount() {
  const count = parseTargets().length;
  targetCount.textContent = count + " / 20";
  targetCount.style.color = count > 20 ? "var(--bad)" : "";
}

function setLoading(loading) {
  runButton.disabled = loading;
  sampleButton.disabled = loading;
  runButton.querySelector(".button-icon").textContent = loading ? "◌" : "▶";
  runButton.querySelector("span:last-child").textContent = loading ? "Checking public responses…" : "Run verification";
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KiB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MiB";
}

function formatTtl(result) {
  if (!result.ttl) return "—";
  const age = result.ttl.ageSeconds || 0;
  if (result.ttl.remainingSeconds === null) return age + "s age";
  return age + "s / " + result.ttl.remainingSeconds + "s left";
}

function appendMetric(parent, label, value) {
  const metric = document.createElement("div");
  metric.className = "metric";
  const name = document.createElement("span");
  name.textContent = label;
  const data = document.createElement("strong");
  data.textContent = value;
  data.title = value;
  metric.append(name, data);
  parent.append(metric);
}

function appendDetail(parent, label, value) {
  if (value === null || value === undefined || value === "") return;
  const item = document.createElement("div");
  item.className = "detail";
  const name = document.createElement("b");
  name.textContent = label;
  const data = document.createElement("code");
  data.textContent = String(value);
  data.title = String(value);
  item.append(name, data);
  parent.append(item);
}

function createResultCard(result) {
  const card = document.createElement("article");
  card.className = "result-card";

  const main = document.createElement("div");
  main.className = "result-main";
  const kind = document.createElement("span");
  kind.className = "kind-pill";
  kind.textContent = result.kind || "page";

  const urlBox = document.createElement("div");
  urlBox.className = "result-url";
  const link = document.createElement("a");
  link.href = result.finalUrl || result.url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = result.url;
  link.title = result.url;
  const rationale = document.createElement("p");
  rationale.textContent = result.rationale || "No explanation was returned.";
  urlBox.append(link, rationale);

  const verdict = document.createElement("span");
  verdict.className = "verdict " + (result.verdict || "error");
  verdict.textContent = verdictLabels[result.verdict] || result.verdict || "Error";
  main.append(kind, urlBox, verdict);

  const metrics = document.createElement("div");
  metrics.className = "result-metrics";
  appendMetric(metrics, "HTTP", Number.isFinite(result.status) ? String(result.status) : "—");
  appendMetric(metrics, "Cache", result.cacheState || "—");
  appendMetric(metrics, "Age / TTL", formatTtl(result));
  appendMetric(metrics, "Latency", Number.isFinite(result.latencyMs) ? result.latencyMs + " ms" : "—");
  appendMetric(metrics, "Captured", formatBytes(result.sizeBytes));

  const details = document.createElement("details");
  const detailsSummary = document.createElement("summary");
  detailsSummary.textContent = "Headers and comparison details";
  const grid = document.createElement("div");
  grid.className = "details-grid";
  appendDetail(grid, "Final URL", result.finalUrl);
  appendDetail(grid, "Bypass HTTP", result.bypassStatus);
  appendDetail(grid, "Content type", result.contentType);
  appendDetail(grid, "Normal SHA-256", result.hash);
  appendDetail(grid, "Bypass SHA-256", result.bypassHash);
  appendDetail(grid, "Hashes match", result.sameContent === null || result.sameContent === undefined ? "" : String(result.sameContent));
  appendDetail(grid, "Expected marker found", result.expectedTextFound === null || result.expectedTextFound === undefined ? "" : String(result.expectedTextFound));
  appendDetail(grid, "Expected edge matched", result.edgeMatched === null || result.edgeMatched === undefined ? "" : String(result.edgeMatched));
  Object.entries(result.headers || {}).forEach(([name, value]) => appendDetail(grid, name, value));
  details.append(detailsSummary, grid);

  card.append(main, metrics, details);
  return card;
}

function updateStats(results) {
  const good = results.filter((item) => ["current", "consistent"].includes(item.verdict)).length;
  const errors = results.filter((item) => item.verdict === "error").length;
  document.querySelector("#stat-total").textContent = String(results.length);
  document.querySelector("#stat-good").textContent = String(good);
  document.querySelector("#stat-review").textContent = String(results.length - good - errors);
  document.querySelector("#stat-error").textContent = String(errors);
}

function renderResults(payload) {
  lastResults = payload.results || [];
  resultsRoot.replaceChildren(...lastResults.map(createResultCard));
  emptyState.classList.add("hidden");
  resultsRoot.classList.remove("hidden");
  exportButton.disabled = lastResults.length === 0;
  updateStats(lastResults);

  const time = payload.checkedAt ? new Date(payload.checkedAt).toLocaleString() : "just now";
  summary.textContent = lastResults.length + " responses checked at " + time + ".";
  const messages = [payload.note, ...(payload.warnings || [])].filter(Boolean);
  notice.textContent = messages.join(" ");
  notice.classList.toggle("hidden", messages.length === 0);
}

function csvCell(value) {
  return '"' + String(value ?? "").replaceAll('"', '""') + '"';
}

function exportCsv() {
  if (!lastResults.length) return;
  const columns = [
    "kind", "url", "finalUrl", "status", "bypassStatus", "verdict", "rationale", "cacheState",
    "ageSeconds", "maxAgeSeconds", "remainingSeconds", "latencyMs", "sizeBytes",
    "sameContent", "expectedTextFound", "edgeMatched", "etag", "last-modified",
    "cache-control", "cf-cache-status", "x-cache", "via", "server", "hash", "bypassHash"
  ];
  const rows = lastResults.map((item) => {
    const flat = {
      ...item,
      ageSeconds: item.ttl?.ageSeconds,
      maxAgeSeconds: item.ttl?.maxAgeSeconds,
      remainingSeconds: item.ttl?.remainingSeconds,
      ...item.headers
    };
    return columns.map((column) => csvCell(flat[column])).join(",");
  });
  const blob = new Blob([[columns.join(","), ...rows].join("\r\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cache-verification-" + new Date().toISOString().replaceAll(":", "-") + ".csv";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast("CSV report exported.");
}

targetList.addEventListener("input", updateTargetCount);
sampleButton.addEventListener("click", () => {
  baseUrlInput.value = "https://example.com";
  targetList.value = "/ || Example Domain\n/";
  expectedEdgeInput.value = "";
  discoverAssetsInput.checked = true;
  updateTargetCount();
  showToast("Example loaded. Replace it with your public website when ready.");
});
exportButton.addEventListener("click", exportCsv);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const targets = parseTargets();
  if (!targets.length) {
    showToast("Add at least one page path or full URL.");
    return;
  }
  if (targets.length > 20) {
    showToast("Use no more than 20 page targets in one run.");
    return;
  }
  if (targets.some((target) => !target.value)) {
    showToast("One target line is missing its URL or path.");
    return;
  }

  setLoading(true);
  notice.classList.add("hidden");
  summary.textContent = "Running two probes per target. Larger sites can take a moment.";
  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        baseUrl: baseUrlInput.value.trim(),
        targets,
        expectedEdge: expectedEdgeInput.value.trim(),
        discoverAssets: discoverAssetsInput.checked
      })
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Verification failed");
    renderResults(payload);
    showToast("Verification complete.");
  } catch (error) {
    summary.textContent = "Verification did not complete.";
    notice.textContent = error.message;
    notice.classList.remove("hidden");
    showToast(error.message);
  } finally {
    setLoading(false);
  }
});

updateTargetCount();
