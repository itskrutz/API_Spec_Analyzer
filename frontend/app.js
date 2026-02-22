/**
 * API Security Analyzer — frontend logic
 *
 * What changed in v2 (vs. the original)
 * ────────────────────────────────────────
 * • AI toggle: reads #ai-toggle checkbox and appends ?ai=true to requests.
 * • Export: JSON / CSV / PDF buttons that re-POST the last spec content with
 *   ?format=<fmt> and trigger a browser download via blob URL.
 * • Score display: shows the normalized score in the circle AND the raw score
 *   + total operations count below the grade badge.
 * • Last-request tracking: stores enough state to replay the request for
 *   exports without asking the user to re-upload.
 *
 * Architecture: pure vanilla JS, zero runtime dependencies.
 */

'use strict';

// ── Config ─────────────────────────────────────────────────────────────────
const API_BASE = '';  // Empty = same origin. Set to 'http://localhost:8000' for local dev.

// ── DOM refs ───────────────────────────────────────────────────────────────
const tabBtns = document.querySelectorAll('.tab-btn');
const tabPanels = document.querySelectorAll('.tab-panel');
const analyzeBtn = document.getElementById('analyze-btn');
const btnText = document.getElementById('btn-text');
const spinner = document.getElementById('spinner');
const errorBanner = document.getElementById('error-banner');
const resultsDiv = document.getElementById('results');
const findingsList = document.getElementById('findings-list');
const filterBtns = document.querySelectorAll('.filter-btn');
const aiToggle = document.getElementById('ai-toggle');
const exportRow = document.getElementById('export-row');
const exportBtns = document.querySelectorAll('.btn-export');

// Drop zone
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileNameEl = document.getElementById('file-name');

// Summary elements
const scoreCircle = document.getElementById('score-circle');
const scoreNum = document.getElementById('score-num');
const gradeBadge = document.getElementById('grade-badge');
const scoreMeta = document.getElementById('score-meta');
const violatedRulesNum = document.getElementById('violated-rules-num');
const totalOccNum = document.getElementById('total-occ-num');
const apiTitle = document.getElementById('api-title');
const apiVersion = document.getElementById('api-version');
const specVersion = document.getElementById('spec-version');
const totalFindings = document.getElementById('total-findings');
const violatedRulesSummary = document.getElementById('violated-rules-summary');
const cntCritical = document.getElementById('cnt-critical');
const cntHigh = document.getElementById('cnt-high');
const cntMedium = document.getElementById('cnt-medium');
const cntLow = document.getElementById('cnt-low');

// ── State ──────────────────────────────────────────────────────────────────
let currentTab = 'paste';
let uploadedFile = null;
let allFindings = [];
let currentFilter = 'all';

/**
 * lastRequest — stored after every successful analysis so CSV/PDF export
 * buttons can re-POST the same spec with a different ?format= param.
 *
 * Shape: { type: 'paste'|'upload'|'url', content: string|null, file: File|null }
 */
let lastRequest = null;

/**
 * lastResult — the full API response object from the last successful analysis.
 * Used by the JSON export to build a clean download without re-hitting the server.
 */
let lastResult = null;

// ── Tab switching ──────────────────────────────────────────────────────────
tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    currentTab = tab;

    tabBtns.forEach(b => b.classList.remove('active'));
    tabPanels.forEach(p => p.classList.remove('active'));

    btn.classList.add('active');
    document.getElementById(`panel-${tab}`).classList.add('active');
    hideError();
  });
});

// ── File drop zone ─────────────────────────────────────────────────────────
dropZone.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];
  if (file) {
    uploadedFile = file;
    fileNameEl.textContent = `Selected: ${file.name}`;
  }
});

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) {
    uploadedFile = file;
    fileNameEl.textContent = `Selected: ${file.name}`;
    fileInput.files = e.dataTransfer.files;
  }
});

// ── Analyze button ─────────────────────────────────────────────────────────
analyzeBtn.addEventListener('click', runAnalysis);

async function runAnalysis() {
  hideError();
  setLoading(true);

  const aiEnabled = aiToggle && aiToggle.checked;
  const aiSuffix = aiEnabled ? '&ai=true' : '';

  try {
    let result;

    if (currentTab === 'paste') {
      const content = document.getElementById('spec-text').value.trim();
      if (!content) { showError('Please paste a spec before analyzing.'); return; }
      lastRequest = { type: 'paste', content, file: null };
      result = await postJSON(`${API_BASE}/analyze/paste?format=json${aiSuffix}`, { content });

    } else if (currentTab === 'upload') {
      if (!uploadedFile) { showError('Please select a file to upload.'); return; }
      lastRequest = { type: 'upload', content: null, file: uploadedFile };
      const form = new FormData();
      form.append('file', uploadedFile);
      result = await postForm(`${API_BASE}/analyze/upload?format=json${aiSuffix}`, form);

    } else if (currentTab === 'url') {
      const url = document.getElementById('spec-url').value.trim();
      if (!url) { showError('Please enter a URL.'); return; }
      lastRequest = { type: 'url', content: url, file: null };
      result = await postJSON(`${API_BASE}/analyze/url?format=json${aiSuffix}`, { url });
    }

    renderResults(result, aiEnabled);

  } catch (err) {
    showError(err.message || 'An unexpected error occurred. Is the backend running?');
  } finally {
    setLoading(false);
  }
}

// ── Export ─────────────────────────────────────────────────────────────────

/**
 * Trigger a browser download for a given Blob.
 */
function _downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Build a clean JSON report from the in-memory result and download it
 * without re-hitting the server.  Avoids the backend needing a special
 * Content-Disposition JSON endpoint that conflicts with the normal analyze
 * response format.
 */
function _exportJsonClientSide() {
  if (!lastResult) return;
  const d = lastResult;
  const bd = d.severity_breakdown || {};

  const report = {
    meta: {
      tool:         'API Security Analyzer',
      api:          d.api_title,
      api_version:  d.api_version,
      spec_version: d.spec_version,
    },
    score: {
      value:             d.score,
      grade:             d.grade,
      rules_violated:    `${d.violated_rules} / 10`,
      total_occurrences: d.total_findings,
    },
    severity_breakdown: {
      critical: bd.critical || 0,
      high:     bd.high     || 0,
      medium:   bd.medium   || 0,
      low:      bd.low      || 0,
      info:     bd.info     || 0,
    },
    findings: (d.findings || []).map(g => ({
      rule_id:            g.rule_id,
      rule_name:          g.rule_name,
      severity:           g.severity.toUpperCase(),
      points_deducted:    g.points_deducted,
      occurrences:        g.count,
      description:        g.description,
      recommendation:     g.recommendation,
      // Flat list of location strings — no repetitive detail field
      affected_locations: (g.occurrences || []).map(o => o.location),
    })),
  };

  const safeName = (d.api_title || 'report').replace(/[^\w\-]/g, '-').toLowerCase().replace(/^-+|-+$/g, '') || 'report';
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  _downloadBlob(blob, `security-report-${safeName}.json`);
}

/**
 * Export the report in the requested format.
 * JSON is handled client-side from in-memory data.
 * CSV and PDF are generated server-side by re-POSTing the last spec.
 */
window.exportReport = async function (fmt) {
  if (!lastResult) return;

  // JSON: build and download client-side — no server round-trip needed.
  if (fmt === 'json') {
    _exportJsonClientSide();
    return;
  }

  // CSV / PDF: re-POST the spec to the backend with ?format=<fmt>.
  if (!lastRequest) return;
  setExporting(true);
  try {
    const url = `${API_BASE}/analyze/${lastRequest.type}?format=${fmt}`;
    let res;

    if (lastRequest.type === 'paste') {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: lastRequest.content }),
      });
    } else if (lastRequest.type === 'url') {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: lastRequest.content }),
      });
    } else {
      const form = new FormData();
      form.append('file', lastRequest.file);
      res = await fetch(url, { method: 'POST', body: form });
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Export failed (HTTP ${res.status})`);
    }

    const cd = res.headers.get('Content-Disposition') || '';
    const match = cd.match(/filename="?([^";\s]+)"?/);
    const filename = match ? match[1] : `security-report.${fmt}`;

    const blob = await res.blob();
    _downloadBlob(blob, filename);

  } catch (err) {
    showError('Export failed: ' + err.message);
  } finally {
    setExporting(false);
  }
};

// ── HTTP helpers ───────────────────────────────────────────────────────────
async function postJSON(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return handleResponse(res);
}

async function postForm(url, form) {
  const res = await fetch(url, { method: 'POST', body: form });
  return handleResponse(res);
}

async function handleResponse(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `Server returned ${res.status}`);
  }
  return data;
}

// ── Result rendering ───────────────────────────────────────────────────────
function renderResults(data, aiEnabled) {
  lastResult = data;
  allFindings = data.findings || [];
  currentFilter = 'all';

  // Score circle — shows the normalized score
  const score = data.score;
  const grade = data.grade;
  scoreNum.textContent = score;
  gradeBadge.textContent = grade;

  scoreCircle.className = 'score-circle';
  gradeBadge.className = 'grade-badge';
  const gradeClass = `grade-${grade.toLowerCase()}`;
  scoreCircle.classList.add(gradeClass);
  gradeBadge.classList.add(gradeClass);

  // Violated rules + occurrences context
  if (data.violated_rules !== undefined) {
    violatedRulesNum.textContent = data.violated_rules;
    totalOccNum.textContent = data.total_findings;
    scoreMeta.style.display = 'flex';
  }

  // API meta
  apiTitle.textContent = data.api_title || '—';
  apiVersion.textContent = `v${data.api_version || '?'}`;
  specVersion.textContent = data.spec_version || '—';
  totalFindings.textContent = data.total_findings;
  if (violatedRulesSummary) violatedRulesSummary.textContent = data.violated_rules ?? 0;

  // Severity counters
  const bd = data.severity_breakdown || {};
  cntCritical.textContent = bd.critical || 0;
  cntHigh.textContent = bd.high || 0;
  cntMedium.textContent = bd.medium || 0;
  cntLow.textContent = bd.low || 0;

  // Reset filter buttons
  filterBtns.forEach(b => b.classList.remove('active-filter'));
  document.querySelector('[data-filter="all"]').classList.add('active-filter');

  // Show export row
  if (exportRow) exportRow.style.display = 'flex';

  // Show AI badge on findings if AI was used
  renderFindings(allFindings, aiEnabled);

  resultsDiv.style.display = 'block';
  resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderFindings(groups, aiEnabled) {
  if (groups.length === 0) {
    findingsList.innerHTML = `
      <div class="empty-state">
        <div class="es-icon">✅</div>
        <p>No findings match the current filter.</p>
      </div>`;
    return;
  }

  const aiLabel = aiEnabled
    ? `<span class="ai-rec-badge" title="Recommendation generated by GPT-4o mini">✦ AI</span>`
    : '';

  findingsList.innerHTML = groups.map((g, i) => {
    // Location pills only — the group description already explains the issue.
    // Repeating the per-path description text for every occurrence is noisy.
    const occurrences = g.occurrences.map(occ => `
      <div class="occurrence-item">
        <span class="location-pill">${escHtml(occ.location)}</span>
      </div>`).join('');

    const countBadge = g.count > 1
      ? `<span class="count-badge">${g.count} occurrences</span>`
      : '';
    const pointsBadge = g.points_deducted > 0
      ? `<span class="points-badge">-${g.points_deducted} pts</span>`
      : '';

    return `
    <div class="finding-card" data-severity="${g.severity}" data-index="${i}">
      <div class="finding-header" onclick="toggleCard(${i})">
        <span class="sev-badge sev-${g.severity}">${g.severity.toUpperCase()}</span>
        <span class="rule-id">${escHtml(g.rule_id)}</span>
        <span class="rule-name">${escHtml(g.rule_name)}</span>
        <div class="finding-header-badges">
          ${pointsBadge}${countBadge}
          <span class="chevron">▼</span>
        </div>
      </div>
      <div class="finding-body">
        <p class="finding-description">${escHtml(g.description)}</p>

        <div class="occurrences-section">
          <h4 class="occurrences-title">Affected locations (${g.count})</h4>
          <div class="occurrences-list">${occurrences}</div>
        </div>

        <div class="recommendation-section">
          <h4 class="recommendation-title">Recommendation ${aiLabel}</h4>
          <div class="rec-box">${renderRec(g.recommendation)}</div>
        </div>
      </div>
    </div>`;
  }).join('');
}

window.toggleCard = function (index) {
  const card = document.querySelector(`.finding-card[data-index="${index}"]`);
  if (card) card.classList.toggle('expanded');
};

// ── Filtering ──────────────────────────────────────────────────────────────
filterBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    currentFilter = btn.dataset.filter;
    filterBtns.forEach(b => b.classList.remove('active-filter'));
    btn.classList.add('active-filter');

    const filtered = currentFilter === 'all'
      ? allFindings
      : allFindings.filter(f => f.severity === currentFilter);

    renderFindings(filtered, aiToggle && aiToggle.checked);
  });
});

// ── UI helpers ─────────────────────────────────────────────────────────────
function setLoading(on) {
  analyzeBtn.disabled = on;
  spinner.style.display = on ? 'block' : 'none';
  btnText.textContent = on
    ? (aiToggle && aiToggle.checked ? 'Analyzing with AI…' : 'Analyzing…')
    : '⚡ Analyze Spec';
}

function setExporting(on) {
  exportBtns.forEach(b => { b.disabled = on; });
}

function showError(msg) {
  errorBanner.textContent = `⚠️  ${msg}`;
  errorBanner.style.display = 'block';
}

function hideError() {
  errorBanner.style.display = 'none';
  errorBanner.textContent = '';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Renders the recommendation text with minimal markdown support.
 * Escapes HTML first (safe), then converts:
 *   **bold**  →  <strong>bold</strong>
 *   `code`    →  <code>code</code>
 *   blank line →  paragraph break
 */
function renderRec(str) {
  const escaped = escHtml(String(str));
  return escaped
    // Bold headings: **text**
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    // Inline code: `text`
    .replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>')
    // Blank line → paragraph break
    .replace(/\n\n/g, '</p><p>')
    // Single newline → line break
    .replace(/\n/g, '<br>')
    // Wrap in paragraphs
    .replace(/^/, '<p>')
    .replace(/$/, '</p>');
}
