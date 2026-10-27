let currentScanType = 'web';
let pollInterval = null;

function setType(type, btn) {
  currentScanType = type;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const apiOpts = document.getElementById('apiOptions');
  if (type === 'api') apiOpts.classList.remove('hidden');
  else apiOpts.classList.add('hidden');
  document.getElementById('targetUrl').placeholder =
    type === 'api' ? 'https://api.example.com — Enter API base URL' : 'https://example.com — Enter target URL to scan';
}

async function startScan() {
  const url = document.getElementById('targetUrl').value.trim();
  if (!url) { showToast('Please enter a target URL', 'error'); return; }
  if (!isValidUrl(url)) { showToast('Please enter a valid URL (include https://)', 'error'); return; }

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="scan-btn-text"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Scanning...</span>';

  let payload = { url, scan_type: currentScanType };
  if (currentScanType === 'api') {
    const headersRaw = document.getElementById('apiHeaders').value.trim();
    const endpointsRaw = document.getElementById('apiEndpoints').value.trim();
    if (headersRaw) {
      try { payload.api_headers = JSON.parse(headersRaw); }
      catch { showToast('Invalid JSON in headers field', 'error'); resetBtn(); return; }
    }
    if (endpointsRaw) payload.api_endpoints = endpointsRaw.split('\n').filter(e => e.trim());
  }

  try {
    const res = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    showProgress();
    pollScanStatus(data.scan_id);
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    resetBtn();
  }
}

function pollScanStatus(scanId) {
  pollInterval = setInterval(async () => {
    try {
      const res = await fetch(`/api/scan/${scanId}/status`);
      const data = await res.json();
      updateProgress(data.progress || 0, data.message || '');
      if (data.status === 'completed') {
        clearInterval(pollInterval);
        updateProgress(100, 'Scan complete! Redirecting to report...');
        setTimeout(() => { window.location.href = `/report/${scanId}`; }, 1200);
      } else if (data.status === 'failed') {
        clearInterval(pollInterval);
        hideProgress();
        showToast('Scan failed: ' + data.message, 'error');
        resetBtn();
      }
    } catch { clearInterval(pollInterval); resetBtn(); }
  }, 1500);
}

function showProgress() {
  document.getElementById('progressSection').classList.remove('hidden');
  document.getElementById('progressBar').style.width = '5%';
  document.getElementById('progressPct').textContent = '5%';
}
function hideProgress() { document.getElementById('progressSection').classList.add('hidden'); }
function updateProgress(pct, msg) {
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('progressPct').textContent = pct + '%';
  if (msg) document.getElementById('progressMsg').textContent = msg;
}
function resetBtn() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = false;
  btn.innerHTML = '<span class="scan-btn-text"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/></svg> Scan Now</span>';
}

async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const scans = await res.json();
    document.getElementById('totalScans').textContent = scans.length;
    renderHistory(scans);
  } catch { }
}

function renderHistory(scans) {
  const container = document.getElementById('historyList');
  if (!scans.length) {
    container.innerHTML = `<div class="empty-state">
      <div class="empty-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/></svg></div>
      <p class="empty-title">No scans yet</p>
      <p class="empty-text">Enter a URL above to run your first security scan</p>
    </div>`;
    return;
  }
  container.innerHTML = scans.map(s => {
    const riskClass = `risk-${(s.risk_level || 'low').toLowerCase()}`;
    const date = new Date(s.timestamp).toLocaleString();
    return `<div class="history-item" onclick="viewReport('${s.scan_id}')">
      <div class="history-risk-badge ${riskClass}">${(s.risk_level || 'LOW').toUpperCase()}</div>
      <div class="history-info">
        <div class="history-url">${escHtml(s.url)}</div>
        <div class="history-meta">
          <span class="history-meta-item">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            ${date}
          </span>
          <span class="history-type-badge">${(s.scan_type || 'web').toUpperCase()}</span>
        </div>
      </div>
      <div class="history-findings">
        <div class="findings-count">${s.total_findings || 0}</div>
        <div class="findings-label">FINDINGS</div>
      </div>
      <div class="history-actions" onclick="event.stopPropagation()">
        <button class="action-btn" onclick="viewReport('${s.scan_id}')">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          View
        </button>
        <button class="action-btn" onclick="downloadPdf('${s.scan_id}')">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          PDF
        </button>
        <button class="action-btn danger" onclick="deleteScan('${s.scan_id}')">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
        </button>
      </div>
    </div>`;
  }).join('');
}

function viewReport(scanId) { window.location.href = `/report/${scanId}`; }
function downloadPdf(scanId) { window.open(`/api/report/${scanId}/pdf`, '_blank'); }
async function deleteScan(scanId) {
  if (!confirm('Delete this scan?')) return;
  await fetch(`/api/history/${scanId}`, { method: 'DELETE' });
  loadHistory();
}

function isValidUrl(url) {
  try { new URL(url.startsWith('http') ? url : 'https://' + url); return true; }
  catch { return false; }
}
function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function showToast(msg, type = 'info') {
  const t = document.createElement('div');
  t.style.cssText = `position:fixed;bottom:24px;right:24px;z-index:9999;padding:14px 20px;border-radius:12px;font-size:14px;font-weight:600;font-family:Inter,sans-serif;max-width:360px;box-shadow:0 8px 30px rgba(0,0,0,0.4);transition:all 0.3s;background:${type==='error'?'rgba(239,68,68,0.15)':'rgba(99,102,241,0.15)'};border:1px solid ${type==='error'?'rgba(239,68,68,0.4)':'rgba(99,102,241,0.4)'};color:${type==='error'?'#fca5a5':'#a5b4fc'}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 3500);
}

document.getElementById('targetUrl').addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
loadHistory();
