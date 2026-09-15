// Global Application State
let threatChart = null;
let riskDonutChart = null;
let replayStreamChart = null;

let isStreamingReplay = false;
let replayStreamInterval = null;
let currentReplayIndex = 0;
let currentLogTab = 'predictions';

let dynamicFeaturesData = null;
let dynamicPresetsData = {};
let systemStatusData = null;

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', async () => {
  if (window.lucide) lucide.createIcons();
  setupTabs();
  startClock();
  
  // 1. Initialize Dynamic Charts & Dial Gauge first
  initCharts();
  initGauge(0);

  // 2. Load System Status & Dynamic Metadata
  await loadSystemStatus();
  
  // 3. Load & Render Dynamic Features Form
  await loadDynamicFeatures();
  
  // 4. Load & Render Dynamic Presets
  await loadDynamicPresets();
  
  // 5. Load Benchmarks & Explainability
  await loadBenchmarks();
  await loadShapSummary();
  
  // 6. Populate Overview & Logs with live data
  await refreshOverview();
  await loadLogs('predictions');

  // 7. Auto-refresh overview every 3 seconds to reflect live streaming updates
  setInterval(refreshOverview, 3000);
});

// Segmented Navigation Tabs
function setupTabs() {
  const tabs = document.querySelectorAll('.soc-tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      tab.classList.add('active');
      const target = document.getElementById(tab.dataset.tab);
      if (target) {
        target.classList.add('active');
      }
      if (window.lucide) lucide.createIcons();
      
      if (tab.dataset.tab === 'tab-overview') {
        refreshOverview();
      } else if (tab.dataset.tab === 'tab-logs') {
        loadLogs(currentLogTab);
      }
    });
  });
}

// Live Clock
function startClock() {
  const clockEl = document.getElementById('liveClock');
  const update = () => {
    const now = new Date();
    clockEl.innerText = now.toTimeString().split(' ')[0] + ' UTC' + (now.getTimezoneOffset() > 0 ? '-' : '+') + Math.abs(now.getTimezoneOffset() / 60);
  };
  update();
  setInterval(update, 1000);
}

// 1. Load System Status Dynamically
async function loadSystemStatus() {
  try {
    const res = await fetch('/api/status');
    systemStatusData = await res.json();
    
    const headerSub = document.getElementById('headerModelSub');
    if (headerSub) {
      headerSub.innerText = `${systemStatusData.model_name} • ${systemStatusData.features_count} Memory Forensic Features`;
    }
    
    const kpiModel = document.getElementById('kpiActiveModel');
    if (kpiModel) {
      kpiModel.innerText = systemStatusData.model_name.replace('Classifier', '');
    }

    const schemaSub = document.getElementById('forensicsSchemaSub');
    if (schemaSub) {
      schemaSub.innerText = `Dynamically loaded ${systemStatusData.features_count} feature schema from production model artifacts.`;
    }
  } catch (e) {
    console.error('Failed to load system status:', e);
  }
}

// 2. Load and Dynamically Render All Feature Categories and Inputs
async function loadDynamicFeatures() {
  const container = document.getElementById('dynamicFeatureCategories');
  if (!container) return;

  try {
    const res = await fetch('/api/features');
    dynamicFeaturesData = await res.json();

    container.innerHTML = '';
    const categories = dynamicFeaturesData.categories || {};

    for (const [catName, featList] of Object.entries(categories)) {
      const block = document.createElement('div');
      block.className = 'soc-category-block';

      const title = document.createElement('div');
      title.className = 'soc-category-title';
      title.innerText = catName;
      block.appendChild(title);

      const grid = document.createElement('div');
      grid.className = 'soc-feature-grid';

      featList.forEach(f => {
        const box = document.createElement('div');
        box.className = 'soc-feature-box';
        box.title = `Mean: ${f.mean.toFixed(2)}, Std: ${f.std.toFixed(2)}, Model Weight: ${(f.importance * 100).toFixed(2)}%`;

        const label = document.createElement('label');
        label.className = 'soc-feature-label';
        label.innerText = f.name;

        const input = document.createElement('input');
        input.type = 'number';
        input.step = 'any';
        input.className = 'soc-input';
        input.id = 'feat_' + f.name.replace(/\./g, '_');
        input.name = f.name;
        input.required = true;
        input.value = (f.mean || 0).toFixed(2);

        box.appendChild(label);
        box.appendChild(input);
        grid.appendChild(box);
      });

      block.appendChild(grid);
      container.appendChild(block);
    }

  } catch (e) {
    container.innerHTML = `<div style="color:#ff6b6b; padding:20px;">Failed to load dynamic features: ${e.message}</div>`;
  }
}

// 3. Load and Dynamically Render Presets
async function loadDynamicPresets() {
  const container = document.getElementById('dynamicPresetPills');
  if (!container) return;

  try {
    const res = await fetch('/api/presets');
    dynamicPresetsData = await res.json();

    container.innerHTML = '';
    const presetKeys = Object.keys(dynamicPresetsData);

    presetKeys.forEach(k => {
      const p = dynamicPresetsData[k];
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'preset-pill';
      btn.onclick = () => loadPreset(k);

      let iconColor = 'var(--status-green)';
      let iconName = 'shield-check';
      if (p.badge_type === 'HIGH') {
        iconColor = '#ff6b6b';
        iconName = 'flame';
      } else if (p.badge_type === 'MEDIUM') {
        iconColor = 'var(--status-amber)';
        iconName = 'ghost';
      }

      btn.innerHTML = `<i data-lucide="${iconName}" style="width:14px; height:14px; color:${iconColor};"></i> ${p.name}`;
      container.appendChild(btn);
    });

    // Add dynamic randomize button
    const randBtn = document.createElement('button');
    randBtn.type = 'button';
    randBtn.className = 'preset-pill';
    randBtn.onclick = randomizeForensicVector;
    randBtn.innerHTML = '<i data-lucide="shuffle" style="width:14px; height:14px;"></i> Randomize Vector';
    container.appendChild(randBtn);

    if (window.lucide) lucide.createIcons();

    // Load first preset by default
    if (presetKeys.length > 0) {
      loadPreset(presetKeys[0]);
    }

  } catch (e) {
    console.error('Failed to load dynamic presets:', e);
  }
}

function loadPreset(key) {
  if (!dynamicPresetsData[key]) return;
  const values = dynamicPresetsData[key].values;
  for (const [feat, val] of Object.entries(values)) {
    const id = 'feat_' + feat.replace(/\./g, '_');
    const input = document.getElementById(id);
    if (input) {
      input.value = val;
    }
  }
  runPredict();
}

function randomizeForensicVector() {
  if (!dynamicFeaturesData || !dynamicFeaturesData.features) return;
  dynamicFeaturesData.features.forEach(f => {
    const id = 'feat_' + f.name.replace(/\./g, '_');
    const input = document.getElementById(id);
    if (input) {
      const spread = f.std * (Math.random() * 3);
      const val = Math.max(f.min, f.mean + (Math.random() > 0.5 ? spread : -spread));
      input.value = Number.isInteger(f.mean) ? Math.round(val) : val.toFixed(4);
    }
  });
  runPredict();
}

// 4. Run Model Prediction
async function runPredict() {
  const form = document.getElementById('forensicsForm');
  if (!form) return;
  
  const formData = new FormData(form);
  const features = {};
  for (const [k, v] of formData.entries()) {
    features[k] = parseFloat(v) || 0;
  }

  try {
    const res = await fetch('/api/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        features: features,
        process_context: 'Dynamic Forensic Vector Scan'
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Prediction failed');

    // Update Dial & Verdict
    const prob = data.confidence_percent;
    initGauge(prob);

    const confEl = document.getElementById('resConfidence');
    const riskBadge = document.getElementById('resRiskBadge');
    const verdictText = document.getElementById('resVerdictText');
    const summarySub = document.getElementById('resSummarySub');
    const breakdownEl = document.getElementById('resFeatureBreakdown');

    confEl.innerText = prob.toFixed(1) + '%';
    verdictText.innerText = data.prediction.toUpperCase();
    riskBadge.className = `soc-badge ${data.risk_level}`;
    riskBadge.innerText = `${data.risk_level} RISK`;

    if (data.prediction === 'Ransomware') {
      confEl.style.color = '#ff6b6b';
      verdictText.style.color = '#ff6b6b';
      summarySub.innerText = data.alert_triggered 
        ? 'High threat probability detected. Security incident alert dispatched.' 
        : 'Anomalous memory indicators identified.';
    } else {
      confEl.style.color = 'var(--status-green)';
      verdictText.style.color = 'var(--status-green)';
      summarySub.innerText = 'Process parameters strictly conform to benign Windows baseline.';
    }

    // Top Discriminators (Ranked dynamically by z-score & model importance)
    breakdownEl.innerHTML = '';
    (data.top_features || []).forEach(f => {
      const item = document.createElement('div');
      item.style.display = 'flex';
      item.style.justifyContent = 'space-between';
      item.style.padding = '6px 10px';
      item.style.borderRadius = 'var(--radius-xs)';
      item.style.background = f.elevated ? 'rgba(225, 25, 0, 0.12)' : 'var(--bg-surface-3)';
      item.style.border = f.elevated ? '1px solid rgba(225, 25, 0, 0.3)' : '1px solid var(--border-subtle)';
      item.style.color = f.elevated ? '#ff8585' : 'var(--text-gray-200)';
      item.innerHTML = `
        <span>${f.feature}:</span>
        <strong style="font-family: var(--font-mono);">${f.value} ${f.elevated ? '▲ ELEVATED' : ''}</strong>
      `;
      breakdownEl.appendChild(item);
    });

  } catch (err) {
    alert('Prediction Error: ' + err.message);
  }
}

// 5. Dynamic SHAP Explainability Cards
async function loadShapSummary() {
  const container = document.getElementById('dynamicTopShapCards');
  if (!container) return;

  try {
    const res = await fetch('/api/reports/shap');
    const data = await res.json();

    const headerSub = document.getElementById('shapHeaderSub');
    if (headerSub) {
      headerSub.innerText = `Top discriminative features dynamically ranked from ${data.explainer_model} TreeExplainer across ${data.num_features} memory metrics.`;
    }

    container.innerHTML = '';
    const topFeats = data.top_features || [];

    const borderColors = ['var(--text-white)', '#ff6b6b', 'var(--status-amber)', 'var(--status-green)', 'var(--status-blue)', '#a855f7'];

    topFeats.slice(0, 3).forEach((f, idx) => {
      const card = document.createElement('div');
      card.className = 'soc-card';
      card.style.borderLeft = `3px solid ${borderColors[idx % borderColors.length]}`;

      card.innerHTML = `
        <div style="font-size: 0.725rem; font-weight: 700; color: var(--text-gray-400); text-transform: uppercase;">
          Rank #${f.importance_rank} • Impact: ${(f.importance_score * 100).toFixed(2)}%
        </div>
        <div style="font-size: 1.15rem; font-weight: 800; margin: 4px 0; font-family: var(--font-mono);">${f.feature}</div>
        <div style="font-size: 0.8rem; color: var(--text-gray-400); line-height: 1.4;">
          Mean baseline: <strong>${f.mean}</strong> (±${f.std}). ${f.insight}
        </div>
      `;
      container.appendChild(card);
    });

  } catch (e) {
    console.error('Failed to load SHAP summary:', e);
  }
}

// 6. Dynamic Model Benchmarks
async function loadBenchmarks() {
  const tbody = document.getElementById('benchmarkTableBody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/reports/benchmarks');
    const data = await res.json();
    if (!data.models_evaluated) return;

    tbody.innerHTML = '';
    data.models_evaluated.forEach(m => {
      const isSelectedBest = m.Model.includes('Tuned') || m.Model.includes('Random Forest (Tuned)');
      const tr = document.createElement('tr');
      if (isSelectedBest) {
        tr.style.background = 'rgba(255, 255, 255, 0.04)';
        tr.style.borderLeft = '3px solid var(--text-white)';

        // Update overview card
        const kpiStats = document.getElementById('kpiModelStats');
        if (kpiStats) {
          kpiStats.innerText = `Accuracy: ${(m.Accuracy * 100).toFixed(2)}% | F1: ${(m.F1 * 100).toFixed(2)}%`;
        }
      }
      tr.innerHTML = `
        <td><strong>${m.Model}</strong> ${isSelectedBest ? '<span class="soc-badge LOW" style="font-size:0.65rem; margin-left:6px;">★ PRODUCTION BEST</span>' : ''}</td>
        <td style="font-family: var(--font-mono); font-weight: 600;">${(m.Accuracy * 100).toFixed(2)}%</td>
        <td style="font-family: var(--font-mono);">${(m.Precision * 100).toFixed(2)}%</td>
        <td style="font-family: var(--font-mono);">${(m.Recall * 100).toFixed(2)}%</td>
        <td style="font-family: var(--font-mono); font-weight: 700;">${(m.F1 * 100).toFixed(2)}%</td>
        <td style="font-family: var(--font-mono);">${m.ROC_AUC.toFixed(4)}</td>
        <td style="font-family: var(--font-mono);">${m.CV_F1_Mean.toFixed(6)} ± ${m.CV_F1_Std.toFixed(6)}</td>
        <td style="font-family: var(--font-mono); color: var(--text-gray-400);">${(m.Inference_Time_Sec * 1000).toFixed(2)} ms</td>
      `;
      tbody.appendChild(tr);
    });

  } catch (e) {
    console.error('Failed to load benchmarks:', e);
  }
}

// 7. Initialize Dynamic Charts
function initCharts() {
  const ctxTimeline = document.getElementById('threatTimelineChart')?.getContext('2d');
  if (ctxTimeline) {
    threatChart = new Chart(ctxTimeline, {
      type: 'line',
      data: {
        labels: ['-50s', '-40s', '-30s', '-20s', '-10s', 'Now'],
        datasets: [{
          label: 'Threat Probability (%)',
          data: [0, 0, 0, 0, 0, 0],
          borderColor: '#ffffff',
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          fill: true,
          tension: 0.35,
          pointBackgroundColor: '#ffffff',
          pointRadius: 4,
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: '#1f1f1f' }, ticks: { color: '#757575', font: { family: 'Plus Jakarta Sans', size: 11 } } },
          y: { min: 0, max: 100, grid: { color: '#1f1f1f' }, ticks: { color: '#757575', font: { family: 'JetBrains Mono', size: 11 } } }
        }
      }
    });
  }

  const ctxDonut = document.getElementById('riskDonutChart')?.getContext('2d');
  if (ctxDonut) {
    riskDonutChart = new Chart(ctxDonut, {
      type: 'doughnut',
      data: {
        labels: ['Low Risk', 'Medium Risk', 'High Risk'],
        datasets: [{
          data: [1, 0, 0],
          backgroundColor: ['#06c167', '#ffaa00', '#e11900'],
          borderColor: '#0a0a0a',
          borderWidth: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        cutout: '78%'
      }
    });
  }

  const ctxStream = document.getElementById('replayStreamChart')?.getContext('2d');
  if (ctxStream) {
    replayStreamChart = new Chart(ctxStream, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Vector Confidence (%)',
            data: [],
            borderColor: '#ffffff',
            backgroundColor: 'rgba(255, 255, 255, 0.08)',
            fill: true,
            tension: 0.25,
            borderWidth: 2,
            pointRadius: 4,
            pointBackgroundColor: '#ffffff'
          },
          {
            label: 'High Risk Cutoff (70%)',
            data: [],
            borderColor: 'rgba(225, 25, 0, 0.8)',
            borderDash: [4, 4],
            borderWidth: 1.5,
            pointRadius: 0,
            fill: false
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: '#a6a6a6', font: { family: 'Plus Jakarta Sans', size: 11, weight: 600 } } }
        },
        scales: {
          x: { grid: { color: '#1a1a1a' }, ticks: { color: '#666666', font: { family: 'JetBrains Mono' } } },
          y: { min: 0, max: 100, grid: { color: '#1a1a1a' }, ticks: { color: '#666666', font: { family: 'JetBrains Mono' } } }
        }
      }
    });
  }
}

// Minimalist Canvas Dial Gauge
function initGauge(probPercent) {
  const canvas = document.getElementById('predictionGaugeCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = 74;

  ctx.clearRect(0, 0, width, height);

  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, 2.25 * Math.PI, false);
  ctx.strokeStyle = '#222222';
  ctx.lineWidth = 10;
  ctx.lineCap = 'round';
  ctx.stroke();

  let strokeColor = '#06c167';
  if (probPercent >= 70) {
    strokeColor = '#e11900';
  } else if (probPercent >= 30) {
    strokeColor = '#ffaa00';
  }

  const totalArc = 1.5 * Math.PI;
  const currentArc = (probPercent / 100) * totalArc;

  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, 0.75 * Math.PI + currentArc, false);
  ctx.strokeStyle = strokeColor;
  ctx.lineWidth = 10;
  ctx.lineCap = 'round';
  ctx.stroke();
}

// 8. Replay Stream Functions
function toggleReplayStream() {
  const btn = document.getElementById('btnReplayStream');
  if (isStreamingReplay) {
    clearInterval(replayStreamInterval);
    isStreamingReplay = false;
    btn.innerHTML = '<i data-lucide="play" style="width: 14px; height: 14px;"></i> Resume Continuous Stream';
    btn.className = 'soc-btn soc-btn-primary soc-btn-sm soc-btn-pill';
  } else {
    isStreamingReplay = true;
    btn.innerHTML = '<i data-lucide="pause" style="width: 14px; height: 14px;"></i> Pause Stream';
    btn.className = 'soc-btn soc-btn-danger soc-btn-sm soc-btn-pill';
    replayStreamInterval = setInterval(stepReplaySample, 1100);
  }
  if (window.lucide) lucide.createIcons();
}

async function stepReplaySample() {
  try {
    const res = await fetch(`/api/replay/sample?index=${currentReplayIndex}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Replay fetch failed');

    currentReplayIndex++;
    addReplayResultRow(data);

    if (replayStreamChart) {
      if (replayStreamChart.data.labels.length > 25) {
        replayStreamChart.data.labels.shift();
        replayStreamChart.data.datasets[0].data.shift();
        replayStreamChart.data.datasets[1].data.shift();
      }
      replayStreamChart.data.labels.push(`#${currentReplayIndex}`);
      replayStreamChart.data.datasets[0].data.push(data.confidence_percent);
      replayStreamChart.data.datasets[1].data.push(70);
      replayStreamChart.update();
    }

  } catch (err) {
    console.error('Replay error:', err);
    if (isStreamingReplay) toggleReplayStream();
  }
}

async function runBatchReplay(count = 10) {
  try {
    const res = await fetch('/api/replay/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ num_samples: count, start_index: currentReplayIndex })
    });
    const data = await res.json();
    if (data.results) {
      currentReplayIndex += count;
      data.results.forEach(r => addBatchReplayRow(r));
    }
  } catch (e) {
    alert('Batch error: ' + e.message);
  }
}

function addReplayResultRow(item) {
  const tbody = document.getElementById('replayTableBody');
  if (tbody.children.length === 1 && tbody.children[0].innerText.includes('Stream is idle')) {
    tbody.innerHTML = '';
  }

  const tr = document.createElement('tr');
  const isMatch = item.is_correct;
  tr.innerHTML = `
    <td style="font-family: var(--font-mono); font-weight: 600;">#${item.meta.row_index}</td>
    <td><span class="soc-badge ${item.ground_truth === 'Ransomware' ? 'HIGH' : 'LOW'}">${item.ground_truth}</span></td>
    <td><strong>${item.prediction}</strong></td>
    <td style="font-family: var(--font-mono); font-weight: 700; color: ${item.probability >= 0.7 ? '#ff6b6b' : 'var(--status-green)'};">${item.confidence_percent}%</td>
    <td><span class="soc-badge ${item.risk_level}">${item.risk_level}</span></td>
    <td>${isMatch ? '<span style="color: var(--status-green); font-weight: 600;">✓ MATCH</span>' : '<span style="color: #ff6b6b; font-weight: 600;">✗ MISMATCH</span>'}</td>
    <td>${item.alert_triggered ? '<span style="color: #ff6b6b; font-weight: 700;">🚨 ALERT DISPATCHED</span>' : '<span style="color: var(--text-gray-400);">Logged</span>'}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);

  while (tbody.children.length > 50) {
    tbody.removeChild(tbody.lastChild);
  }
}

function addBatchReplayRow(item) {
  const tbody = document.getElementById('replayTableBody');
  if (tbody.children.length === 1 && tbody.children[0].innerText.includes('Stream is idle')) {
    tbody.innerHTML = '';
  }
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td style="font-family: var(--font-mono); font-weight: 600;">#${item.sample_index}</td>
    <td><span class="soc-badge ${item.ground_truth === 'Ransomware' ? 'HIGH' : 'LOW'}">${item.ground_truth}</span></td>
    <td><strong>${item.prediction}</strong></td>
    <td style="font-family: var(--font-mono); font-weight: 700;">${(item.probability * 100).toFixed(1)}%</td>
    <td><span class="soc-badge ${item.risk_level}">${item.risk_level}</span></td>
    <td>${item.is_match ? '<span style="color: var(--status-green); font-weight: 600;">✓ MATCH</span>' : '<span style="color: #ff6b6b; font-weight: 600;">✗ MISMATCH</span>'}</td>
    <td>${item.alert_triggered ? '<span style="color: #ff6b6b; font-weight: 700;">🚨 ALERT</span>' : '<span style="color: var(--text-gray-400);">Logged</span>'}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
}

// 9. Refresh Overview
async function refreshOverview() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    
    document.getElementById('kpiTotalScans').innerText = data.total_scans || 0;
    document.getElementById('kpiRansomwareCount').innerText = data.ransomware_detected || 0;
    document.getElementById('kpiBenignCount').innerText = data.benign_cleared || 0;
    document.getElementById('kpiThreatRate').innerText = `${data.threat_ratio || 0}% Detection Rate`;

    const dist = data.risk_distribution || { LOW: 0, MEDIUM: 0, HIGH: 0 };
    document.getElementById('distLow').innerText = dist.LOW;
    document.getElementById('distMed').innerText = dist.MEDIUM;
    document.getElementById('distHigh').innerText = dist.HIGH;

    if (riskDonutChart) {
      riskDonutChart.data.datasets[0].data = [dist.LOW || 1, dist.MEDIUM, dist.HIGH];
      riskDonutChart.update();
    }

    // Update Live Threat Severity Timeline Chart
    if (threatChart && data.timeline && data.timeline.length > 0) {
      threatChart.data.labels = data.timeline.map(t => t.time);
      threatChart.data.datasets[0].data = data.timeline.map(t => t.probability);
      threatChart.data.datasets[0].pointBackgroundColor = data.timeline.map(t => 
        t.probability >= 70 ? '#ff6b6b' : (t.probability >= 30 ? '#ffaa00' : '#06c167')
      );
      threatChart.data.datasets[0].pointBorderColor = threatChart.data.datasets[0].pointBackgroundColor;
      threatChart.update();
    }

    const healthBadge = document.getElementById('liveHealthBadge');
    const healthText = document.getElementById('healthText');
    if (dist.HIGH > 0) {
      healthBadge.className = 'soc-status-pill threat-alert';
      healthText.innerText = 'ELEVATED THREAT';
    } else {
      healthBadge.className = 'soc-status-pill';
      healthText.innerText = 'SYSTEM SECURE';
    }

    const tbody = document.getElementById('overviewAlertsTable');
    document.getElementById('alertCountBadge').innerText = `${data.total_alerts || 0} Incidents`;

    if (data.recent_alerts && data.recent_alerts.length > 0) {
      tbody.innerHTML = '';
      data.recent_alerts.reverse().forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td style="font-family: var(--font-mono); font-size: 0.775rem;">${a.timestamp}</td>
          <td><strong style="color: #ff6b6b;">${a.prediction}</strong></td>
          <td style="font-family: var(--font-mono);">${(parseFloat(a.confidence) * 100 || 0).toFixed(1)}%</td>
          <td><span class="soc-badge ${a.risk_level}">${a.risk_level}</span></td>
          <td>${a.process_context || 'Replay Vector'}</td>
          <td style="color: var(--text-gray-400); font-size: 0.75rem;">${a.feature_source || 'System'}</td>
        `;
        tbody.appendChild(tr);
      });
    }

  } catch (e) {
    console.error('Failed to refresh stats:', e);
  }
}

// 10. Log Management
function switchLogSubTab(tab) {
  currentLogTab = tab;
  ['subTabPred', 'subTabAlerts', 'subTabBeh'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.className = 'soc-btn soc-btn-secondary soc-btn-sm soc-btn-pill';
  });
  if (tab === 'predictions') document.getElementById('subTabPred').className = 'soc-btn soc-btn-primary soc-btn-sm soc-btn-pill';
  if (tab === 'alerts') document.getElementById('subTabAlerts').className = 'soc-btn soc-btn-primary soc-btn-sm soc-btn-pill';
  if (tab === 'behavioral') document.getElementById('subTabBeh').className = 'soc-btn soc-btn-primary soc-btn-sm soc-btn-pill';
  
  loadLogs(tab);
}

async function loadLogs(tab) {
  const thead = document.getElementById('logTableHead');
  const tbody = document.getElementById('logTableBody');
  thead.innerHTML = '';
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 20px;">Loading records...</td></tr>';

  try {
    const res = await fetch(`/api/logs/${tab}?limit=50`);
    const data = await res.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-gray-400); padding: 20px;">No records available.</td></tr>';
      return;
    }

    if (tab === 'predictions') {
      thead.innerHTML = `
        <tr>
          <th>Timestamp</th>
          <th>Prediction</th>
          <th>Probability</th>
          <th>Risk Level</th>
          <th>Process Context</th>
          <th>Source</th>
          <th>Mode</th>
        </tr>
      `;
      tbody.innerHTML = logs.map(l => `
        <tr>
          <td style="font-family: var(--font-mono);">${l.timestamp}</td>
          <td><strong>${l.prediction}</strong></td>
          <td style="font-family: var(--font-mono); font-weight: 700;">${(parseFloat(l.probability)*100).toFixed(1)}%</td>
          <td><span class="soc-badge ${l.risk_level}">${l.risk_level}</span></td>
          <td>${l.process_context || ''}</td>
          <td>${l.feature_source || ''}</td>
          <td>${l.mode || ''}</td>
        </tr>
      `).join('');
    } else if (tab === 'alerts') {
      thead.innerHTML = `
        <tr>
          <th>Timestamp</th>
          <th>Prediction</th>
          <th>Confidence</th>
          <th>Risk Level</th>
          <th>Context</th>
          <th>Source</th>
        </tr>
      `;
      tbody.innerHTML = logs.map(l => `
        <tr>
          <td style="font-family: var(--font-mono);">${l.timestamp}</td>
          <td><strong style="color: #ff6b6b;">${l.prediction}</strong></td>
          <td style="font-family: var(--font-mono); font-weight: 700;">${(parseFloat(l.confidence)*100).toFixed(1)}%</td>
          <td><span class="soc-badge ${l.risk_level}">${l.risk_level}</span></td>
          <td>${l.process_context || ''}</td>
          <td>${l.feature_source || ''}</td>
        </tr>
      `).join('');
    } else if (tab === 'behavioral') {
      thead.innerHTML = `
        <tr>
          <th>Timestamp</th>
          <th>Window (s)</th>
          <th>Total Events</th>
          <th>Created</th>
          <th>Modified</th>
          <th>Deleted</th>
          <th>CPU %</th>
          <th>Mem %</th>
          <th>Processes</th>
        </tr>
      `;
      tbody.innerHTML = logs.map(l => `
        <tr>
          <td style="font-family: var(--font-mono);">${l.timestamp}</td>
          <td>${l.window_seconds}</td>
          <td><strong>${l.file_events_total}</strong></td>
          <td>${l.file_created}</td>
          <td>${l.file_modified}</td>
          <td>${l.file_deleted}</td>
          <td>${l.cpu_percent}%</td>
          <td>${l.memory_percent}%</td>
          <td>${l.running_processes}</td>
        </tr>
      `).join('');
    }

  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" style="color: #ff6b6b; text-align:center; padding:20px;">Failed to load logs: ${e.message}</td></tr>`;
  }
}

async function loadAllLogs() {
  loadLogs(currentLogTab);
  refreshOverview();
}

async function clearAllLogs() {
  if (!confirm('Confirm reset of all security logs?')) return;
  try {
    await fetch('/api/logs/clear', { method: 'POST' });
    loadLogs(currentLogTab);
    refreshOverview();
  } catch (e) {
    alert('Clear error: ' + e.message);
  }
}

async function fetchLiveBehavior() {
  const card = document.getElementById('liveHostCard');
  card.style.display = 'block';
  try {
    const res = await fetch('/api/behavioral/sample');
    const data = await res.json();
    document.getElementById('liveCpu').innerText = data.cpu_percent + '%';
    document.getElementById('liveMem').innerText = data.memory_percent + '%';
    document.getElementById('livePids').innerText = data.running_processes;
    document.getElementById('liveTime').innerText = data.timestamp;

    const listEl = document.getElementById('topProcessesList');
    listEl.innerHTML = '<div style="margin-top:10px; color:var(--text-white); font-weight:700;">Active Top Resource Consumers:</div>';
    (data.top_processes || []).forEach(p => {
      listEl.innerHTML += `<div style="padding:4px 0; color:var(--text-gray-400);">PID ${p.pid} | <strong style="color:var(--text-white);">${p.name}</strong> - CPU: ${p.cpu}% | MEM: ${p.memory}% | Handles: ${p.handles}</div>`;
    });
  } catch (e) {
    alert('Failed to get host snapshot: ' + e.message);
  }
}
