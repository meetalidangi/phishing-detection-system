/**
 * script.js – PhishGuard frontend logic
 * ────────────────────────────────────────
 * 1. scanURL()        – reads input, calls /predict, renders result
 * 2. renderResult()   – populates all result-panel elements
 * 3. toggleExplanation() – shows/hides the explanation panel
 * 4. fillExample()    – puts a demo URL into the input
 * 5. showError()      – shows a dismissable error toast
 */

// ── allow pressing Enter to scan ─────────────────────────────────────────────
document.getElementById("urlInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") scanURL();
});

// ── main scan function ───────────────────────────────────────────────────────
async function scanURL() {
  const input = document.getElementById("urlInput");
  const url   = input.value.trim();

  if (!url) {
    showError("Please enter a URL to scan.");
    return;
  }

  // show loader, hide old result
  setLoading(true);
  hideResult();

  try {
    // ── POST to Flask /predict ──────────────────────────────────────────────
    const response = await fetch("/predict", {
      method  : "POST",
      headers : { "Content-Type": "application/json" },
      body    : JSON.stringify({ url }),
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      throw new Error(data.error || `Server error: ${response.status}`);
    }

    renderResult(data);

  } catch (err) {
    showError(err.message || "Something went wrong. Is the server running?");
  } finally {
    setLoading(false);
  }
}

// ── render the full result panel ─────────────────────────────────────────────
function renderResult(data) {
  const isPhishing = data.label === "Phishing";

  // verdict badge
  const badge = document.getElementById("verdictBadge");
  badge.className = "verdict-badge " + (isPhishing ? "phishing" : "legitimate");
  document.getElementById("verdictIcon").textContent  = isPhishing ? "⚠" : "✓";
  document.getElementById("verdictLabel").textContent = data.label.toUpperCase();

  // confidence
  document.getElementById("confValue").textContent =
    (data.confidence * 100).toFixed(1) + "%";

  // probability bars (animated via CSS transition)
  const legitPct = Math.round(data.legit_prob * 100);
  const phishPct = Math.round(data.phish_prob * 100);

  // set to 0 first so transition fires
  const legitBar = document.getElementById("legitBar");
  const phishBar = document.getElementById("phishBar");
  legitBar.style.width = "0%";
  phishBar.style.width = "0%";

  // small delay lets the browser register the 0% before animating
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      legitBar.style.width = legitPct + "%";
      phishBar.style.width = phishPct + "%";
    });
  });

  document.getElementById("legitPct").textContent = legitPct + "%";
  document.getElementById("phishPct").textContent = phishPct + "%";

  // scanned URL
  document.getElementById("scannedURL").textContent = data.url;

  // ── explanation section ─────────────────────────────────────────────────
  const ex = data.explanation;

  // risk score bar
  const riskFill  = document.getElementById("riskFill");
  const riskScore = document.getElementById("riskScore");
  riskFill.style.width = "0%";
  requestAnimationFrame(() => requestAnimationFrame(() => {
    riskFill.style.width = ex.risk_score + "%";
  }));
  riskScore.textContent = ex.risk_score + "/100";

  // suspicious reasons
  const reasonsList = document.getElementById("reasonsList");
  reasonsList.className = "signal-list warn-list";
  reasonsList.innerHTML = ex.reasons.map(r => `<li>${escapeHTML(r)}</li>`).join("");

  // safe signs
  const safeList = document.getElementById("safeList");
  safeList.className = "signal-list safe-list";
  safeList.innerHTML = ex.safe_signs.map(s => `<li>${escapeHTML(s)}</li>`).join("");

  // hide explanation panel by default, reset toggle text
  document.getElementById("explanationPanel").classList.add("hidden");
  document.getElementById("explainToggle").textContent = "Show explanation ▾";

  // show result card
  document.getElementById("resultPanel").classList.remove("hidden");
}

// ── toggle explanation panel ─────────────────────────────────────────────────
function toggleExplanation() {
  const panel  = document.getElementById("explanationPanel");
  const toggle = document.getElementById("explainToggle");
  const hidden = panel.classList.toggle("hidden");
  toggle.textContent = hidden ? "Show explanation ▾" : "Hide explanation ▴";
}

// ── fill a demo URL ───────────────────────────────────────────────────────────
function fillExample(url) {
  document.getElementById("urlInput").value = url;
  document.getElementById("urlInput").focus();
}

// ── helpers ───────────────────────────────────────────────────────────────────
function setLoading(on) {
  document.getElementById("loader").classList.toggle("hidden", !on);
  document.getElementById("scanBtn").disabled = on;
}

function hideResult() {
  document.getElementById("resultPanel").classList.add("hidden");
}

function showError(msg) {
  const toast = document.getElementById("errorToast");
  toast.textContent = "⚠ " + msg;
  toast.classList.remove("hidden");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.add("hidden"), 5000);
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
