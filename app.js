const form = document.getElementById("scan-form");
const runBtn = document.getElementById("run-scan");
const stopBtn = document.getElementById("stop-scan");
const logEl = document.getElementById("log");
const reportEl = document.getElementById("report");
const exportBtn = document.getElementById("export-btn");
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const topbarUrl = document.getElementById("topbar-url");
const findingTemplate = document.getElementById("finding-template");

const CHECK_LABELS = {
  sqli: "SQL injection",
  xss: "Cross-site scripting",
  traversal: "Directory traversal",
  tls: "SSL / TLS configuration",
  headers: "Security headers",
};

let stopped = false;
let allFindings = [];

function setStatus(state, text) {
  statusDot.className = `status-dot status-${state}`;
  statusText.textContent = text;
}

function appendLog(message, tag) {
  if (logEl.querySelector(".log-placeholder")) logEl.innerHTML = "";
  const line = document.createElement("p");
  line.className = "log-line" + (tag ? ` tag-${tag}` : "");
  const time = new Date().toLocaleTimeString([], { hour12: false });
  line.innerHTML = `<span class="time">${time}</span>${escapeHtml(message)}`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function renderFinding(f) {
  if (reportEl.querySelector(".report-placeholder")) reportEl.innerHTML = "";
  const node = findingTemplate.content.cloneNode(true);
  const article = node.querySelector(".finding");
  article.dataset.severity = f.severity;
  node.querySelector(".finding-sev").textContent = f.severity;
  node.querySelector(".finding-title").textContent = f.title;
  node.querySelector(".finding-detail").textContent = f.detail;
  node.querySelector(".finding-evidence").textContent = f.evidence;
  reportEl.appendChild(node);
}

function updateSummary() {
  const counts = { critical: 0, high: 0, medium: 0, pass: 0 };
  for (const f of allFindings) {
    if (f.severity in counts) counts[f.severity]++;
  }
  document.getElementById("count-critical").textContent = counts.critical;
  document.getElementById("count-high").textContent = counts.high;
  document.getElementById("count-medium").textContent = counts.medium;
  document.getElementById("count-pass").textContent = counts.pass;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const url = document.getElementById("target-url").value.trim();
  const selectedChecks = Array.from(form.querySelectorAll('input[name="check"]:checked')).map((c) => c.value);

  if (!url || selectedChecks.length === 0) return;

  // reset state
  stopped = false;
  allFindings = [];
  logEl.innerHTML = "";
  reportEl.innerHTML = "";
  updateSummary();
  topbarUrl.textContent = url;
  runBtn.disabled = true;
  stopBtn.hidden = false;
  exportBtn.disabled = true;
  setStatus("running", "Scanning…");

  appendLog(`Starting scan of ${url}`);
  appendLog(`Checks queued: ${selectedChecks.map((c) => CHECK_LABELS[c]).join(", ")}`);

  for (const checkKey of selectedChecks) {
    if (stopped) {
      appendLog("Scan stopped by user.", "high");
      break;
    }
    appendLog(`— Running ${CHECK_LABELS[checkKey]} check —`);
    await sleep(350 + Math.random() * 350);
    try {
      const findings = await CHECKS[checkKey](url, (msg, tag) => appendLog(msg, tag));
      for (const f of findings) {
        allFindings.push(f);
        renderFinding(f);
      }
      updateSummary();
    } catch (err) {
      appendLog(`${CHECK_LABELS[checkKey]} check failed: ${err.message}`, "high");
    }
  }

  runBtn.disabled = false;
  stopBtn.hidden = true;
  exportBtn.disabled = allFindings.length === 0;

  if (stopped) {
    setStatus("idle", "Stopped");
  } else {
    appendLog("Scan complete.");
    setStatus("done", "Complete");
  }
});

stopBtn.addEventListener("click", () => {
  stopped = true;
});

exportBtn.addEventListener("click", () => {
  const url = document.getElementById("target-url").value.trim();
  const lines = [
    `Vulnerability scan report`,
    `Target: ${url}`,
    `Generated: ${new Date().toString()}`,
    "",
    ...allFindings.map(
      (f) => `[${f.severity.toUpperCase()}] ${f.title}\n  ${f.detail}\n  Evidence: ${f.evidence}\n`
    ),
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "vulnerability-report.txt";
  a.click();
  URL.revokeObjectURL(a.href);
});
