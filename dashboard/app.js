'use strict';
/* ══════════════════════════════════════════════════════════════
   SecurityDoS Dashboard — app.js
   Real-time WebSocket client • Chart.js • Test control panel
   ══════════════════════════════════════════════════════════════ */

const API_BASE = '';   // empty = same origin
const MAX_POINTS = 120; // 2 minutes of 1s snapshots

// ── State ──────────────────────────────────────────────────────
let ws = null;
let wsRetryTimer = null;
let statusCheckTimer = null;
const timeLabels = [];
const rpsData = [];
const tpsData = [];
const latAvg = [];
const latP95 = [];
const latP99 = [];
const errData = [];
let scCumulative = {};
let chartUpdateTimer = null;
let predefinedProfiles = [];

// ── Chart.js defaults ──────────────────────────────────────────
Chart.defaults.color = '#64748b';
Chart.defaults.borderColor = '#232d47';
Chart.defaults.font.family = "'JetBrains Mono', monospace";

const chartOpts = (yLabel, yUnit = '') => ({
  responsive: true,
  maintainAspectRatio: true,
  animation: { duration: 300 },
  plugins: {
    legend: { display: true, labels: { boxWidth: 10, padding: 12 } },
    tooltip: {
      callbacks: {
        label: (ctx) => ` ${ctx.dataset.label}: ${ctx.parsed.y.toLocaleString()}${yUnit}`
      }
    }
  },
  scales: {
    x: { grid: { color: '#1a2340' }, ticks: { maxTicksLimit: 6, maxRotation: 0 } },
    y: {
      grid: { color: '#1a2340' }, beginAtZero: true,
      title: { display: !!yLabel, text: yLabel, color: '#64748b' }
    }
  }
});

// ── RPS Chart ──────────────────────────────────────────────────
const rpsChart = new Chart(document.getElementById('rpsChart'), {
  type: 'line',
  data: {
    labels: timeLabels,
    datasets: [{
      label: 'RPS (Total)',
      data: rpsData,
      borderColor: '#6366f1',
      backgroundColor: 'transparent',
      borderWidth: 2,
      fill: false,
      tension: 0.3,
      pointRadius: 0,
    },
    {
      label: 'TPS (Success)',
      data: tpsData,
      borderColor: '#10b981',
      backgroundColor: 'rgba(16,185,129,0.08)',
      borderWidth: 2,
      fill: true,
      tension: 0.3,
      pointRadius: 0,
    }]
  },
  options: chartOpts('Requests/sec', ' req/s')
});

// ── Latency Chart ──────────────────────────────────────────────
const latChart = new Chart(document.getElementById('latChart'), {
  type: 'line',
  data: {
    labels: timeLabels,
    datasets: [
      { label: 'Avg', data: latAvg, borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,0.05)', borderWidth: 2, fill: false, tension: 0.3, pointRadius: 0 },
      { label: 'p95', data: latP95, borderColor: '#f59e0b', backgroundColor: 'transparent', borderWidth: 1.5, fill: false, tension: 0.3, pointRadius: 0, borderDash: [4, 3] },
      { label: 'p99', data: latP99, borderColor: '#ef4444', backgroundColor: 'transparent', borderWidth: 1.5, fill: false, tension: 0.3, pointRadius: 0, borderDash: [2, 3] },
    ]
  },
  options: chartOpts('Latency', ' ms')
});

// ── Error Rate Chart ───────────────────────────────────────────
const errChart = new Chart(document.getElementById('errChart'), {
  type: 'line',
  data: {
    labels: timeLabels,
    datasets: [{
      label: 'Error %',
      data: errData,
      borderColor: '#ef4444',
      backgroundColor: 'rgba(239,68,68,0.08)',
      borderWidth: 2,
      fill: true,
      tension: 0.3,
      pointRadius: 0,
    }]
  },
  options: {
    ...chartOpts('Error Rate', '%'),
    scales: {
      x: { grid: { color: '#1a2340' }, ticks: { maxTicksLimit: 6, maxRotation: 0 } },
      y: {
        grid: { color: '#1a2340' }, beginAtZero: true, max: 100,
        ticks: { callback: v => v + '%' }
      }
    }
  }
});

// ── Status Code Bar Chart ──────────────────────────────────────
const scChart = new Chart(document.getElementById('scChart'), {
  type: 'bar',
  data: {
    labels: [],
    datasets: [{
      label: 'Responses',
      data: [],
      backgroundColor: [],
      borderColor: [],
      borderWidth: 2,
      borderRadius: 4,
    }]
  },
  options: {
    ...chartOpts('Count'),
    plugins: { legend: { display: false } }
  }
});

// ── Push a data point to all rolling windows ───────────────────
function pushDataPoint(snap) {
  const t = new Date(snap.timestamp).toLocaleTimeString('en-GB', { hour12: false });
  timeLabels.push(t);
  rpsData.push(snap.rps || 0);
  tpsData.push(snap.tps || 0);

  latAvg.push(+(snap.avg_latency_ms || 0).toFixed(1));
  latP95.push(+(snap.p95_latency_ms ?? 0).toFixed(1));
  latP99.push(+(snap.p99_latency_ms ?? 0).toFixed(1));
  errData.push(+((snap.error_rate ?? 0) * 100).toFixed(2));

  if (timeLabels.length > MAX_POINTS) {
    timeLabels.shift();
    rpsData.shift();
    tpsData.shift();
    latAvg.shift();
    latP95.shift(); latP99.shift(); errData.shift();
  }


}

function refreshChartsDebounced() {
  if (chartUpdateTimer) clearTimeout(chartUpdateTimer);
  chartUpdateTimer = setTimeout(() => {
    refreshCharts();
    chartUpdateTimer = null;
  }, 100); // Debounce 100ms
}

function refreshCharts() {
  rpsChart.update('none');
  latChart.update('none');
  errChart.update('none');

  const codes = Object.keys(scCumulative).sort();
  const data = [];
  const bgColors = [];
  const borderColors = [];

  for (const c of codes) {
    data.push(scCumulative[c]);
    if (c === 'TIMEOUT') {
      bgColors.push('#8b5cf644');  // Purple for timeout
      borderColors.push('#8b5cf6');
    } else if (c.startsWith('2')) {
      bgColors.push('#22c55e44');
      borderColors.push('#22c55e');
    } else if (c.startsWith('3')) {
      bgColors.push('#06b6d444');
      borderColors.push('#06b6d4');
    } else if (c.startsWith('4')) {
      bgColors.push('#f59e0b44');
      borderColors.push('#f59e0b');
    } else if (c.startsWith('5')) {
      bgColors.push('#ef444444');
      borderColors.push('#ef4444');
    } else {
      bgColors.push('#94a3b844');
      borderColors.push('#94a3b8');
    }
  }

  scChart.data.labels = codes;
  scChart.data.datasets[0].data = data;
  scChart.data.datasets[0].backgroundColor = bgColors;
  scChart.data.datasets[0].borderColor = borderColors;
  scChart.update('none');
}

// ── KPI cards ─────────────────────────────────────────────────
function updateKPIs(snap) {
  const rps = (snap.rps ?? 0);
  const tps = (snap.tps ?? 0);
  const avg = (snap.avg_latency_ms ?? 0);
  const p95 = (snap.p95_latency_ms ?? 0);
  const p99 = (snap.p99_latency_ms ?? 0);
  const maxL = (snap.max_latency_ms ?? 0);
  const err = (snap.error_rate ?? 0) * 100;
  const tmo = (snap.timeout_count ?? 0);
  const tot = (snap.total_requests ?? 0);
  const suc = (snap.success_count ?? 0);
  const wk = (snap.active_workers ?? 0);
  const drp = (snap.dropped_count ?? 0);

  setText('kv-rps', rps.toLocaleString());
  setText('ks-rps', `Total Throughput | Drp: ${drp}`);
  setText('kv-tps', tps.toLocaleString());
  setText('ks-tps', `Success (2xx) Only`);
  setText('kv-lat', avg < 0.1 ? '0 ms' : `${avg.toFixed(2)} ms`);
  setText('ks-lat', `p95: ${p95.toFixed(1)} ms`);
  setText('kv-err', `${err.toFixed(2)}%`);
  setText('ks-err', `Timeouts: ${tmo.toLocaleString()}`);
  setText('kv-total', tot.toLocaleString());
  setText('ks-total', `✓ ${suc.toLocaleString()} OK`);
  setText('kv-workers', wk.toLocaleString());
  setText('kv-p99', `${p99.toFixed(1)} ms`);
  setText('ks-p99', `Max: ${maxL.toFixed(1)} ms`);
  setText('stageLabel', snap.stage || '-');

  // Color alerts
  colorKPI('kpi-err', err > 10 ? 'alert-red' : err > 3 ? 'alert-yellow' : '');
  colorKPI('kpi-lat', avg > 2000 ? 'alert-red' : avg > 500 ? 'alert-yellow' : '');
  colorKPI('kpi-rps', rps > 100 ? 'alert-green' : '');
  colorKPI('kpi-tps', tps > 100 ? 'alert-green' : '');

  // Status code table
  updateSCTable(scCumulative);
}

function colorKPI(id, cls) {
  const el = document.getElementById(id);
  el.classList.remove('alert-red', 'alert-yellow', 'alert-green');
  if (cls) el.classList.add(cls);
}

function updateSCTable(codes) {
  const el = document.getElementById('statusCodeTable');
  if (Object.keys(codes).length === 0) return;
  const rows = Object.entries(codes).sort().map(([k, v]) => `
    <div class="sc-row sc-${k}">
      <span>${k}</span>
      <span>${v.toLocaleString()}</span>
    </div>`).join('');
  el.innerHTML = rows;
}

// ── Analysis panel (populated when report is fetched) ─────────
async function refreshAnalysis() {
  try {
    const rep = await apiGet('/api/report');
    if (!rep || !rep.analysis) return;
    const a = rep.analysis;
    setText('an-breaking', a.breaking_point_rps > 0 ? `${a.breaking_point_rps.toFixed(0)} RPS` : '—');
    setText('an-latdeg', a.latency_degradation_rps > 0 ? `${a.latency_degradation_rps.toFixed(0)} RPS` : '—');
    setText('an-rl', a.rate_limit_rps > 0 ? `${a.rate_limit_rps.toFixed(0)} RPS` : '—');
    setText('an-recovery', a.recovery_observed ? '✅ Yes' : '❌ No');

    if (a.observations && a.observations.length) {
      const obsEl = document.getElementById('observationsList');
      obsEl.innerHTML = a.observations.map(o => {
        const cls = o.toLowerCase().includes('critical') || o.toLowerCase().includes('high') ? 'obs-warn' : '';
        return `<div class="obs-item ${cls}">${o}</div>`;
      }).join('');
    }
  } catch (_) { /* silent – no test yet */ }
}

// ── WebSocket ──────────────────────────────────────────────────
function connectWebSocket() {
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const token = document.getElementById('apiToken').value.trim();
  // Pass token via query param since WS upgrades can't set headers
  const url = `${proto}://${location.host}/ws/metrics?token=${encodeURIComponent(token)}`;

  ws = new WebSocket(url);
  setConnStatus(false);

  ws.onopen = () => {
    setConnStatus(true);
    appendLog('INFO', 'WebSocket connected');
    clearInterval(wsRetryTimer);
    wsRetryTimer = null;
  };

  ws.onmessage = (evt) => {
    let snap;
    try { snap = JSON.parse(evt.data); } catch { return; }

    // Always accumulate status codes first
    if (snap.status_codes) {
      for (const [k, v] of Object.entries(snap.status_codes)) {
        scCumulative[k] = (scCumulative[k] ?? 0) + v;
      }
    }

    // Only update charts if dashboard is visible
    const isDashboardVisible = !document.getElementById('dashboardView').classList.contains('hidden');
    if (isDashboardVisible) {
      pushDataPoint(snap);
      updateKPIs(snap);
      refreshChartsDebounced();
    }
  };

  ws.onclose = () => {
    setConnStatus(false);
    appendLog('WARN', 'WebSocket disconnected. Retrying in 3s…');
    if (!wsRetryTimer) {
      wsRetryTimer = setInterval(() => connectWebSocket(), 3000);
    }
  };

  ws.onerror = () => {
    appendLog('ERROR', 'WebSocket error');
  };
}

// ── Status polling ─────────────────────────────────────────────
async function pollStatus() {
  try {
    const s = await apiGet('/api/status');
    if (!s) return;
    const isRunning = !!s.running;
    const badge = document.getElementById('statusBadge');
    const txt = document.getElementById('statusText');
    const metaEl = document.getElementById('testMeta');

    if (isRunning) {
      badge.className = 'status-badge running';
      txt.textContent = 'Running';
      metaEl.style.display = 'flex';
      setText('testIdBadge', s.test_id || '');
      setText('stageLabel', s.test_type || '');

      document.getElementById('setupView').classList.add('hidden');
      document.getElementById('dashboardView').classList.remove('hidden');
      document.getElementById('controlPanel').style.display = 'block';
      document.getElementById('postTestPanel').style.display = 'none';

      // Ensure WS is connected if it isn't
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        connectWebSocket();
      }
    } else if (s.kill_switch_active) {
      badge.className = 'status-badge error';
      txt.textContent = 'Kill Switch Active';
      document.getElementById('setupView').classList.remove('hidden');
      document.getElementById('dashboardView').classList.add('hidden');
    } else {
      badge.className = 'status-badge';
      txt.textContent = 'Idle';

      // If we were running but now idle, ensure buttons are reset
      const stopBtn = document.querySelector('#controlPanel .btn-secondary');
      if (stopBtn) {
        stopBtn.textContent = '■ Stop Test';
        stopBtn.disabled = false;
      }

      // Only show post-test panel if we have a current test loaded in the dashboard view
      const hasActiveView = !document.getElementById('dashboardView').classList.contains('hidden');
      if (hasActiveView) {
        // If it's Idle but we see the dashboard, it means the test just finished
        document.getElementById('controlPanel').style.display = 'none';
        document.getElementById('postTestPanel').style.display = 'block';
        metaEl.style.display = 'flex';
      } else {
        metaEl.style.display = 'none';
      }
    }
  } catch (_) { }
}

function resetToSetup() {
  document.getElementById('setupView').classList.remove('hidden');
  document.getElementById('dashboardView').classList.add('hidden');
  document.getElementById('postTestPanel').style.display = 'none';
  document.getElementById('batchInfoPanel').classList.add('hidden');
  document.getElementById('batchUrlList').innerHTML = '';
  document.getElementById('batchReportButtons').innerHTML = '';
  document.getElementById('batchCountdown').textContent = '';
  // Clear charts/data for next run
  timeLabels.length = 0;
  rpsData.length = 0;
  tpsData.length = 0;
  latAvg.length = 0;
  latP95.length = 0;
  latP99.length = 0;
  errData.length = 0;
  scCumulative = {};
  refreshCharts(); // Reset charts immediately
}

function viewLatestReport() {
  const testId = document.getElementById('testIdBadge').textContent;
  if (testId) {
    window.open(`/report.html?testId=${testId}&token=${token()}`, '_blank');
  }
}

// ── API helpers ────────────────────────────────────────────────
function token() { return document.getElementById('apiToken').value.trim(); }

async function apiGet(path) {
  const r = await fetch(API_BASE + path, {
    headers: { 'Authorization': `Bearer ${token()}` }
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function apiPost(path, body) {
  const r = await fetch(API_BASE + path, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token()}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  const text = await r.text();
  return { ok: r.ok, status: r.status, body: JSON.parse(text) };
}

function showMsg(cls, text) {
  const el = document.getElementById('apiMessage');
  el.className = `api-message ${cls}`;
  el.textContent = text;
  setTimeout(() => { el.className = 'api-message'; }, 6000);
}

// ── Test control ───────────────────────────────────────────────
async function shutdownServer() {

  try {
    appendLog('INFO', 'Permintaan exit dikirim ke API...');
    const res = await apiPost('/api/exit', {});

    if (res.ok) {
      appendLog('WARN', 'Remote shutdown initiated... goodbye!');
      document.body.innerHTML = `
        <div style="height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; background:#0f172a; color:#f8fafc; font-family:sans-serif;">
          <h1 style="color:#ef4444;">⏻ Service Offline</h1>
          <p style="color:#94a3b8;">Proses backend telah dihentikan oleh operator.</p>
          <button onclick="location.reload()" style="margin-top:20px; padding:10px 20px; border-radius:6px; background:#1e293b; color:#fff; border:1px solid #334155; cursor:pointer;">Reload Dashboard</button>
        </div>
      `;
    } else {
      showMsg('error', res.body.error || 'Shutdown request failed');
    }
  } catch (err) {
    appendLog('ERROR', 'Gagal exit: ' + err.message);
    showMsg('error', 'Network/Parsing Error: ' + err.message);
    console.error('Exit Error:', err);
  }
}

async function startTest() {
  const rawUrls = document.getElementById('inpTarget').value.trim();
  if (!rawUrls) { showMsg('error', 'Target URL is required.'); return; }

  // Parse URLs: split by newlines or commas, trim, filter empties
  const urls = rawUrls.split(/[\n,]+/).map(u => u.trim()).filter(u => u.length > 0);

  if (urls.length > 1) {
    // ── BATCH MODE ──
    document.getElementById('setupView').classList.add('hidden');
    document.getElementById('dashboardView').classList.remove('hidden');
    connectWebSocket();
    runBatch(urls);
  } else {
    // ── SINGLE URL MODE (original flow) ──
    const target = urls[0];
    const method = document.getElementById('inpMethod').value;
    const profile = document.getElementById('inpProfile').value;
    const mode = document.getElementById('inpMode').value;
    let rps = parseInt(document.getElementById('inpRps').value.trim()) || 5000;
    const unit = document.getElementById('inpUnit').value;
    const dur = document.getElementById('inpDuration').value.trim() || '30s';
    const timeout = document.getElementById('inpTimeout').value.trim() || '30s';
    const latencyThresh = parseInt(document.getElementById('inpLatencyThresh').value.trim()) || 2000;

    if (profile === 'custom' && mode === 'total') {
      const totalReq = rps;
      const seconds = parseDurationToSeconds(dur);
      rps = Math.ceil(totalReq / seconds);
      if (rps < 1) rps = 1;
      appendLog('INFO', `Auto-calculated: ${totalReq} requests over ${seconds}s = ${rps} RPS`);
    }

    const op = document.getElementById('operatorName').value.trim() || 'operator';
    const ua = document.getElementById('inpUA').value.trim();
    const headersRaw = document.getElementById('inpHeaders').value.trim();
    const h2 = document.getElementById('inpHttp2').checked;
    const ka = document.getElementById('inpKeepAlive').checked;
    const evasion = document.getElementById('inpEvasion').checked;
    const followRedirect = document.getElementById('inpFollowRedirect').checked;

    // Clear previous data
    timeLabels.length = 0; rpsData.length = 0; tpsData.length = 0;
    latAvg.length = 0; latP95.length = 0; latP99.length = 0;
    errData.length = 0; scCumulative = {};

    const yaml = generateYAML(profile, target, method, dur, rps, h2, ka, unit, ua, headersRaw, timeout, evasion, latencyThresh, followRedirect);

    let displayLoad = `${rps} ${unit}`;
    if (profile !== 'custom') {
      const p = predefinedProfiles.find(x => (x.test_type || x.TestType) === profile);
      if (p && p.stages && p.stages.length > 0) {
        displayLoad = `${p.stages.length} stages (Profile: ${profile})`;
      }
    }

    appendLog('INFO', `Sending START request (op: ${op}, target: ${displayLoad})…`);
    const res = await apiPost('/api/start', { scenario_yaml: yaml, operator: op });

    if (res.ok) {
      showMsg('ok', `✓ Test started: ${res.body.test_id}`);
      document.getElementById('setupView').classList.add('hidden');
      document.getElementById('dashboardView').classList.remove('hidden');
      appendLog('AUDIT', `Test started → ${target} [${res.body.test_id}] at ${displayLoad}`);
      connectWebSocket();
      refreshAnalysis();
    } else {
      showMsg('error', `✗ ${res.body.error || 'Unknown error'}`);
      appendLog('ERROR', res.body.error);
    }
  }
}

// ── Batch runner ───────────────────────────────────────────────
async function runBatch(urls) {
  const total = urls.length;
  const method = document.getElementById('inpMethod').value;
  const profile = document.getElementById('inpProfile').value;
  const mode = document.getElementById('inpMode').value;
  let rps = parseInt(document.getElementById('inpRps').value.trim()) || 5000;
  const unit = document.getElementById('inpUnit').value;
  const dur = document.getElementById('inpDuration').value.trim() || '30s';
  const timeout = document.getElementById('inpTimeout').value.trim() || '30s';
  const latencyThresh = parseInt(document.getElementById('inpLatencyThresh').value.trim()) || 2000;
  const op = document.getElementById('operatorName').value.trim() || 'operator';
  const ua = document.getElementById('inpUA').value.trim();
  const headersRaw = document.getElementById('inpHeaders').value.trim();
  const h2 = document.getElementById('inpHttp2').checked;
  const ka = document.getElementById('inpKeepAlive').checked;
  const evasion = document.getElementById('inpEvasion').checked;
  const followRedirect = document.getElementById('inpFollowRedirect').checked;

  if (profile === 'custom' && mode === 'total') {
    const totalReq = rps;
    const seconds = parseDurationToSeconds(dur);
    rps = Math.ceil(totalReq / seconds);
    if (rps < 1) rps = 1;
  }

  // Show batch panel
  const batchPanel = document.getElementById('batchInfoPanel');
  batchPanel.classList.remove('hidden');
  document.getElementById('controlPanel').style.display = 'block';
  document.getElementById('postTestPanel').style.display = 'none';

  // Build URL queue list
  const urlListEl = document.getElementById('batchUrlList');
  urlListEl.innerHTML = urls.map((u, i) =>
    `<div id="batchItem-${i}" style="display:flex; align-items:center; gap:8px; padding:4px 0; border-bottom:1px solid rgba(255,255,255,0.04);">
      <span id="batchIcon-${i}" style="font-size:0.85rem; min-width:16px;">○</span>
      <span style="font-size:0.85rem; color:#94a3b8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${u}">${u}</span>
    </div>`
  ).join('');

  for (let i = 0; i < total; i++) {
    const target = urls[i];

    // Update progress + icons
    document.getElementById('batchProgressText').textContent = `Testing ${i + 1} of ${total}`;
    for (let j = 0; j < total; j++) {
      const icon = document.getElementById(`batchIcon-${j}`);
      const item = document.getElementById(`batchItem-${j}`);
      if (j < i) {
        icon.textContent = '✓';
        icon.style.color = '#22c55e';
        item.style.opacity = '0.6';
      } else if (j === i) {
        icon.textContent = '▶';
        icon.style.color = '#6366f1';
        item.style.opacity = '1';
        item.style.fontWeight = '600';
      } else {
        icon.textContent = '○';
        icon.style.color = '#64748b';
        item.style.opacity = '0.5';
      }
    }

    // Update header badge
    setText('testIdBadge', `Batch ${i + 1}/${total}`);
    setText('stageLabel', profile);
    document.getElementById('testMeta').style.display = 'flex';

    // Reset chart data for each URL
    timeLabels.length = 0; rpsData.length = 0; tpsData.length = 0;
    latAvg.length = 0; latP95.length = 0; latP99.length = 0;
    errData.length = 0; scCumulative = {};
    refreshCharts();
    document.getElementById('batchCountdown').textContent = '';

    const yaml = generateYAML(profile, target, method, dur, rps, h2, ka, unit, ua, headersRaw, timeout, evasion, latencyThresh, followRedirect);
    appendLog('INFO', `[Batch ${i + 1}/${total}] Starting test → ${target}`);

    const res = await apiPost('/api/start', { scenario_yaml: yaml, operator: op });
    if (!res.ok) {
      appendLog('ERROR', `[Batch ${i + 1}] Failed to start: ${res.body.error}`);
      showMsg('error', `Batch ${i + 1} failed: ${res.body.error}`);
      continue;
    }

    const testId = res.body.test_id;
    appendLog('AUDIT', `[Batch ${i + 1}/${total}] Started → ${target} [${testId}]`);

    // Poll until test is idle
    await new Promise(resolve => {
      const poller = setInterval(async () => {
        try {
          const s = await apiGet('/api/status');
          if (!s.running) {
            clearInterval(poller);
            resolve();
          }
        } catch (_) { }
      }, 1500);
    });

    // Mark icon as done
    const doneIcon = document.getElementById(`batchIcon-${i}`);
    if (doneIcon) { doneIcon.textContent = '✓'; doneIcon.style.color = '#22c55e'; }
    appendLog('INFO', `[Batch ${i + 1}/${total}] Completed → ${target}`);

    // Add report button immediately
    const shortUrl = target.replace(/^https?:\/\//, '').split('/')[0];
    const btn = document.createElement('a');
    btn.href = `/report.html?testId=${testId}&token=${token()}`;
    btn.target = '_blank';
    btn.className = 'btn btn-secondary';
    btn.style.fontSize = '0.8rem';
    btn.textContent = `📄 ${shortUrl}`;
    document.getElementById('batchReportButtons').appendChild(btn);

    // 5s cooldown between tests (not after the last one)
    if (i < total - 1) {
      for (let cd = 5; cd > 0; cd--) {
        document.getElementById('batchCountdown').textContent = `⏳ Cooldown... Next in ${cd}s`;
        await new Promise(r => setTimeout(r, 1000));
      }
      document.getElementById('batchCountdown').textContent = '';
    }
  }

  // All done
  document.getElementById('batchProgressText').textContent = `✅ All ${total} tests completed`;
  document.getElementById('batchCountdown').textContent = '';
  for (let j = 0; j < total; j++) {
    const icon = document.getElementById(`batchIcon-${j}`);
    if (icon) { icon.textContent = '✓'; icon.style.color = '#22c55e'; }
  }
  document.getElementById('controlPanel').style.display = 'none';
  document.getElementById('postTestPanel').style.display = 'block';
  refreshAnalysis();
  appendLog('INFO', `Batch complete: ${total} tests finished.`);
}

async function stopTest() {
  const btn = document.querySelector('#controlPanel .btn-secondary');
  const originalText = btn.textContent;
  btn.textContent = '⌛ Stopping...';
  btn.disabled = true;

  const res = await apiPost('/api/stop', {});
  if (res.ok) {
    showMsg('ok', '■ Test stopping...');
    appendLog('INFO', 'Stop signal sent via dashboard');
    // Don't immediately reset button, pollStatus will handle it
    setTimeout(refreshAnalysis, 1500);
  } else {
    showMsg('error', res.body.error || 'Stop failed');
    btn.textContent = '■ Stop Test';
    btn.disabled = false;
  }
}

async function killSwitch() {
  const badge = document.getElementById('statusBadge');
  const isActive = badge.classList.contains('error') && document.getElementById('statusText').textContent === 'Kill Switch Active';

  if (isActive) {
    // Reset mode
    const res = await fetch(API_BASE + '/api/kill', {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token()}` }
    });
    if (res.ok) {
      showMsg('ok', '✓ Kill Switch Reset');
      appendLog('INFO', 'Kill switch reset via dashboard');
      pollStatus();
    } else {
      showMsg('error', 'Failed to reset kill switch');
    }
    return;
  }

  // Activation mode
  const res = await apiPost('/api/kill', {});
  if (res.ok) {
    showMsg('error', '⚡ KILL SWITCH ACTIVATED');
    appendLog('WARN', 'Kill switch activated via dashboard');
    pollStatus();
  } else {
    showMsg('error', res.body.error || 'Failed to activate kill switch');
  }
}

// ── UI Helpers ────────────────────────────────────────────────
function onModeChange() {
  const mode = document.getElementById('inpMode').value;
  const lbl = document.getElementById('lblRps');
  const inp = document.getElementById('inpRps');
  const unit = document.getElementById('inpUnit');

  if (mode === 'total') {
    lbl.textContent = 'Target Total Requests';
    inp.placeholder = 'e.g. 2000';
    unit.style.display = 'none';
  } else {
    lbl.textContent = 'RPS/TPS Value';
    inp.placeholder = 'e.g. 5000';
    unit.style.display = 'block';
  }
}

function parseDurationToSeconds(s) {
  s = s.toLowerCase().trim();
  let total = 0;
  const matches = s.matchAll(/(\d+)([hms])/g);
  let found = false;
  for (const m of matches) {
    found = true;
    const val = parseInt(m[1]);
    const unit = m[2];
    if (unit === 'h') total += val * 3600;
    if (unit === 'm') total += val * 60;
    if (unit === 's') total += val;
  }
  return found ? total : 60;
}

function onProfileChange() {
  const profileVal = document.getElementById('inpProfile').value;
  const row = document.getElementById('customInputsRow');
  const h2 = document.getElementById('inpHttp2');
  const ka = document.getElementById('inpKeepAlive');

  if (profileVal === 'custom') {
    row.style.display = 'flex';
  } else {
    row.style.display = 'none';

    // Auto-set defaults based on the chosen scenario profile
    const p = predefinedProfiles.find(x => x.test_type === profileVal);
    if (p) {
      if (p.http2 !== undefined) h2.checked = p.http2;
      if (p.keep_alive !== undefined) ka.checked = p.keep_alive;
    }
  }
}

// ── Scenario generation ────────────────────────────────────────
function generateYAML(profileVal, target, method, duration, peakVal, http2, keepAlive, unit, uaPrefix, headersRaw, timeout, evasion, latencyThreshMs = 2000, followRedirect = false) {
  let stages = '';
  let extra = '';
  const headers = {};

  // 1. Load baseline headers from profile if exists
  if (profileVal !== 'custom') {
    const p = predefinedProfiles.find(x => x.test_type === profileVal);
    if (p && p.headers) {
      Object.assign(headers, p.headers);
    }
  }

  // 2. Merge/Override with custom headers from input
  if (headersRaw) {
    const lines = headersRaw.split('\n');
    lines.forEach(l => {
      const idx = l.indexOf(':');
      if (idx > 0) {
        const k = l.substring(0, idx).trim();
        const v = l.substring(idx + 1).trim();
        if (k && v) headers[k] = v;
      }
    });
  }

  // 3. Convert merged headers object to YAML
  let headersYAML = '';
  if (Object.keys(headers).length > 0) {
    let hItems = '';
    for (const [k, v] of Object.entries(headers)) {
      hItems += `\n    ${k}: "${v}"`;
    }
    headersYAML = `\nheaders:${hItems}`;
  }

  if (profileVal === 'custom') {
    stages = `
  - name: Custom-Load
    duration: ${duration}
    rps: ${peakVal}`;
  } else {
    const p = predefinedProfiles.find(x => (x.test_type || x.TestType) === profileVal);
    if (p && (p.stages || p.Stages)) {
      const pStages = p.stages || p.Stages;
      stages = pStages.map(s => {
        const name = s.name || s.Name || 'Stage';
        const dur = s.duration || s.Duration || s.DurStr || '30s';
        const rps = s.rps || s.RPS || 1;
        return `
  - name: ${name}
    duration: ${dur}
    rps: ${rps}`;
      }).join('');

      if (p.adaptive || p.Adaptive) {
        const maxR = p.adaptive_max_rps || p.AdaptiveMaxRPS || 30000;
        const stepR = p.adaptive_step_rps || p.AdaptiveStepRPS;
        const failT = p.failure_threshold || p.FailureThreshold;
        extra = `\nadaptive: true\nadaptive_max_rps: ${maxR}`;
        if (stepR) extra += `\nadaptive_step_rps: ${stepR}`;
        if (failT) extra += `\nfailure_threshold: ${failT}`;
      }
    } else {
      // Fallback
      stages = `
  - name: Unknown-Profile
    duration: ${duration}
    rps: ${peakVal}`;
    }
  }

  return `target: ${target}
method: ${method}
test_type: ${profileVal}
unit: ${unit}
user_agent_prefix: ${uaPrefix}
max_workers: 10000
http2: ${http2}
keep_alive: ${keepAlive}
evasion: ${evasion}
follow_redirect: ${followRedirect}
timeout: ${timeout}
latency_threshold_ms: ${latencyThreshMs}${extra}${headersYAML}
stages:${stages}
`;
}

// ── Log panel ─────────────────────────────────────────────────
function appendLog(level, msg) {
  const el = document.getElementById('logOutput');
  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
  const lvlClass = `lvl-${level.toLowerCase()}`;
  const entry = document.createElement('span');
  entry.className = 'log-entry';
  entry.innerHTML = `<span class="ts">[${ts}]</span> <span class="${lvlClass}">[${level}]</span> <span class="msg"> ${escHtml(msg)}</span>`;
  el.appendChild(entry);
  el.scrollTop = el.scrollHeight;

  // Keep max 500 log lines
  while (el.children.length > 500) el.removeChild(el.firstChild);
}

// ── Connection status ─────────────────────────────────────────
function setConnStatus(connected) {
  const el = document.getElementById('connStatus');
  if (connected) {
    el.style.color = '#22c55e';
    el.textContent = '● Connected';
  } else {
    el.style.color = '#f59e0b';
    el.textContent = '● Disconnected';
  }
}


// ── Utilities ─────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function loadProfiles() {
  const sel = document.getElementById('inpProfile');
  if (!sel) return;

  try {
    const profiles = await apiGet('/api/config/profiles');
    predefinedProfiles = Array.isArray(profiles) ? profiles : [];

    // Always start with Custom
    sel.innerHTML = '<option value="custom">Custom (Manual)</option>';

    predefinedProfiles.forEach(p => {
      const type = p.test_type || p.TestType || '';
      if (!type) return;

      const opt = document.createElement('option');
      opt.value = type;
      const label = type.charAt(0).toUpperCase() + type.slice(1);
      opt.textContent = label;
      sel.appendChild(opt);
    });

    appendLog('INFO', `Successfully loaded ${predefinedProfiles.length} test profiles`);
  } catch (err) {
    if (err.message.includes('Unauthorized') || err.message.includes('401')) {
      // Expected if token not yet set
      console.log('Profiles load pending: Unauthorized');
    } else {
      console.error('Failed to load profiles:', err);
      appendLog('ERROR', 'Failed to load profiles: ' + err.message);
    }
  }
}

// ── Init ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Load profiles from backend
  loadProfiles();

  // Start polling for status every 2s
  pollStatus();
  statusCheckTimer = setInterval(() => {
    pollStatus();
    refreshAnalysis();
  }, 2000);

  // Attempt WS connection on load
  connectWebSocket();

  // Reload profiles if token changes
  document.getElementById('apiToken').addEventListener('change', loadProfiles);

  appendLog('INFO', 'Security DoS dashboard initialized');
  appendLog('INFO', 'Set your API token and choose a scenario to begin');
});
