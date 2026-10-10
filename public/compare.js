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
const discoverAssets = document.querySelector("#discover-assets");
const sampleButton = document.querySelector("#sample-button");
const runButton = document.querySelector("#run-button");
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
  runButton.textContent = value ? "Comparing environments…" : "▶ Run environment comparison";
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

  setLoading(true);
  notice.classList.add("hidden");
  summaryText.textContent = "Running normal and bypass probes across all configured environments…";
  try {
    const response = await fetch("/api/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        profileName: profileName.value.trim(),
        environments,
        targets,
        expectedReleaseId: releaseId.value.trim(),
        contentUpdatedAt: updatedAt.value ? new Date(updatedAt.value).toISOString() : "",
        normalizeHtml: normalizeHtml.checked,
        discoverAssets: discoverAssets.checked
      })
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Comparison failed");
    render(payload);
    showToast("Environment comparison complete.");
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
