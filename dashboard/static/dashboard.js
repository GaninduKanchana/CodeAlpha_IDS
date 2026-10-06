const SEVERITY_LABELS = { 1: "Critical", 2: "High", 3: "Medium", 4: "Low" };

// Matches the severity palette defined in style.css (:root custom properties).
const COLORS = {
  brand: "#4f8ef7",
  ok: "#3ddc97",
  critical: "#ff5577",
  high: "#ffa94d",
  medium: "#ffd43b",
  low: "#5ac8fa",
  gridLine: "rgba(139, 147, 167, 0.12)",
  tickColor: "#5b6376",
};

Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.color = COLORS.tickColor;

let timelineChart, sourcesChart, portsChart;
let autoRefreshTimer = null;

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Request failed: ${url}`);
  return res.json();
}

function baseGrid() {
  return { color: COLORS.gridLine, drawBorder: false };
}

async function loadSummary() {
  const data = await fetchJSON("/api/summary");
  document.getElementById("totalCount").textContent = data.total;
  document.getElementById("criticalCount").textContent = data.critical;
  document.getElementById("highCount").textContent = data.high;
  document.getElementById("mediumCount").textContent = data.medium;
  document.getElementById("lowCount").textContent = data.low;
}

async function loadTimeline() {
  const data = await fetchJSON("/api/timeline?hours=24");
  const labels = data.map(d => d.bucket);
  const values = data.map(d => d.c);

  if (timelineChart) {
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = values;
    timelineChart.update();
    return;
  }
  const ctx = document.getElementById("timelineChart");
  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Alerts",
        data: values,
        borderColor: COLORS.brand,
        backgroundColor: "rgba(79, 142, 247, 0.12)",
        pointBackgroundColor: COLORS.brand,
        pointBorderColor: COLORS.brand,
        pointRadius: 3,
        fill: true,
        tension: 0.3,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: baseGrid(), ticks: { font: { family: "'JetBrains Mono', monospace", size: 10 } } },
        y: { grid: baseGrid(), beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
}

async function loadTopSources() {
  const data = await fetchJSON("/api/top-sources?limit=5");
  const labels = data.map(d => d.src_ip);
  const values = data.map(d => d.c);
  if (sourcesChart) {
    sourcesChart.data.labels = labels;
    sourcesChart.data.datasets[0].data = values;
    sourcesChart.update();
    return;
  }
  sourcesChart = new Chart(document.getElementById("sourcesChart"), {
    type: "bar",
    data: { labels, datasets: [{ label: "Alerts", data: values, backgroundColor: COLORS.low, borderRadius: 2, maxBarThickness: 46 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { family: "'JetBrains Mono', monospace", size: 10 } } },
        y: { grid: baseGrid(), beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
}

async function loadTopPorts() {
  const data = await fetchJSON("/api/top-ports?limit=5");
  const labels = data.map(d => String(d.dest_port));
  const values = data.map(d => d.c);
  if (portsChart) {
    portsChart.data.labels = labels;
    portsChart.data.datasets[0].data = values;
    portsChart.update();
    return;
  }
  portsChart = new Chart(document.getElementById("portsChart"), {
    type: "bar",
    data: { labels, datasets: [{ label: "Alerts", data: values, backgroundColor: COLORS.high, borderRadius: 2, maxBarThickness: 46 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { family: "'JetBrains Mono', monospace", size: 10 } } },
        y: { grid: baseGrid(), beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
}

async function loadTopSignatures() {
  const data = await fetchJSON("/api/top-signatures?limit=5");
  const list = document.getElementById("signatureList");
  list.innerHTML = "";
  if (data.length === 0) {
    list.innerHTML = `<li><span style="color: var(--text-faint)">No signatures triggered yet</span></li>`;
    return;
  }
  data.forEach(d => {
    const li = document.createElement("li");
    li.innerHTML = `<span>${d.signature}</span><strong>${d.c}</strong>`;
    list.appendChild(li);
  });
}

async function loadAlertsTable() {
  const search = document.getElementById("searchInput").value;
  const severity = document.getElementById("severityFilter").value;
  const params = new URLSearchParams({ limit: 100 });
  if (search) params.set("search", search);
  if (severity) params.set("severity", severity);

  const data = await fetchJSON(`/api/alerts?${params.toString()}`);
  const tbody = document.getElementById("alertsTableBody");
  const emptyState = document.getElementById("emptyState");
  tbody.innerHTML = "";

  if (data.length === 0) {
    emptyState.hidden = false;
  } else {
    emptyState.hidden = true;
  }

  data.forEach(a => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${a.timestamp ?? ""}</td>
      <td>${a.src_ip ?? ""}${a.src_port ? ":" + a.src_port : ""}</td>
      <td>${a.dest_ip ?? ""}${a.dest_port ? ":" + a.dest_port : ""}</td>
      <td>${a.proto ?? ""}</td>
      <td>${a.signature ?? ""}</td>
      <td><span class="badge badge-${a.severity}">${SEVERITY_LABELS[a.severity] ?? a.severity}</span></td>
      <td>${a.category ?? ""}</td>
    `;
    tbody.appendChild(tr);
  });
}

function updateLastRefreshedLabel() {
  const el = document.getElementById("lastUpdated");
  const now = new Date();
  const hh = String(now.getHours()).padStart(2, "0");
  const mm = String(now.getMinutes()).padStart(2, "0");
  const ss = String(now.getSeconds()).padStart(2, "0");
  el.textContent = `updated ${hh}:${mm}:${ss}`;
}

async function refreshAll() {
  await Promise.all([
    loadSummary(),
    loadTimeline(),
    loadTopSources(),
    loadTopPorts(),
    loadTopSignatures(),
    loadAlertsTable(),
  ]);
  updateLastRefreshedLabel();
}

document.getElementById("refreshBtn").addEventListener("click", refreshAll);
document.getElementById("searchInput").addEventListener("input", loadAlertsTable);
document.getElementById("severityFilter").addEventListener("change", loadAlertsTable);
document.getElementById("autoRefreshToggle").addEventListener("change", (e) => {
  if (e.target.checked) {
    autoRefreshTimer = setInterval(refreshAll, 10000);
  } else {
    clearInterval(autoRefreshTimer);
  }
});

refreshAll();
