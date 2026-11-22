const state = {csrf: "", user: null, peers: [], transfers: [], selectedPeer: null, telemetry: [], settings: {}, pollTimer: null};
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const bytes = value => {
  if (!Number.isFinite(value)) return "—";
  if (value < 1000) return `${value.toFixed(0)} B/s`;
  const units = ["KB/s", "MB/s", "GB/s"];
  let amount = value / 1000, index = 0;
  while (amount >= 1000 && index < units.length - 1) { amount /= 1000; index++; }
  return `${amount.toFixed(1)} ${units[index]}`;
};
const sizeText = value => {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB"];
  let amount = value / 1024, index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
  return `${amount.toFixed(1)} ${units[index]}`;
};
const timeText = seconds => {
  const days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600), mins = Math.floor(seconds % 3600 / 60);
  return `${days ? `${days}d ` : ""}${hours}h ${mins}m`;
};
const safe = value => String(value ?? "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const toast = (message, error = false) => {
  const node = document.createElement("div");
  node.className = `toast${error ? " error" : ""}`;
  node.textContent = message;
  $("#toast-region").append(node);
  setTimeout(() => node.remove(), 4000);
};

async function api(url, options = {}) {
  const headers = {...(options.headers || {})};
  if (state.csrf && options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(url, {...options, headers});
  const result = response.headers.get("content-type")?.includes("application/json") ? await response.json() : null;
  if (response.status === 401) { location.assign("/login"); throw new Error("Please sign in."); }
  if (!response.ok) throw new Error(result?.error || `Request failed (${response.status}).`);
  return result;
}

async function boot() {
  const [csrf, me] = await Promise.all([fetch("/api/auth/csrf").then(r => r.json()), fetch("/api/auth/me").then(r => r.json())]);
  state.csrf = csrf.csrf_token;
  if (!me.authenticated) { location.assign("/login"); return; }
  state.user = me.user;
  $("#username-label").textContent = me.user.username;
  $("#user-avatar").textContent = me.user.username.slice(0, 1).toUpperCase();
  bindUI();
  await Promise.all([loadDashboard(), loadPeers(), loadTransfers(), loadSettings()]);
  initSocket();
  scheduleDashboardPolling();
  setInterval(() => loadPeers().catch(() => {}), 7000);
  setInterval(() => loadTransfers().catch(() => {}), 7000);
  window.addEventListener("resize", drawCharts);
}

function scheduleDashboardPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  const seconds = Number(state.settings.monitor_interval || 3);
  state.pollTimer = setInterval(() => loadDashboard().catch(() => {}), seconds * 1000);
}

function bindUI() {
  $$(".nav-item[data-view]").forEach(item => item.addEventListener("click", () => showView(item.dataset.view)));
  $$("[data-go]").forEach(item => item.addEventListener("click", () => showView(item.dataset.go)));
  $("#mobile-menu").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#refresh-all").addEventListener("click", () => Promise.all([loadDashboard(), loadPeers(), loadTransfers()]).then(() => toast("Dashboard refreshed.")));
  $("#refresh-peers").addEventListener("click", () => loadPeers().then(() => toast("Peer list refreshed.")));
  $("#refresh-transfers").addEventListener("click", () => loadTransfers());
  $("#logout").addEventListener("click", async () => {
    try { await api("/api/auth/logout", {method:"POST"}); location.assign("/login"); } catch (error) { toast(error.message, true); }
  });
  $("#peer-search").addEventListener("input", renderPeers);
  $("#transfer-search").addEventListener("input", renderTransfers);
  $("#upload-form").addEventListener("submit", uploadFile);
  $("#file-input").addEventListener("change", showSelectedFile);
  $("#drop-zone").addEventListener("dragover", event => { event.preventDefault(); $("#drop-zone").classList.add("dragover"); });
  $("#drop-zone").addEventListener("dragleave", () => $("#drop-zone").classList.remove("dragover"));
  $("#drop-zone").addEventListener("drop", event => {
    event.preventDefault(); $("#drop-zone").classList.remove("dragover");
    if (event.dataTransfer.files.length) { $("#file-input").files = event.dataTransfer.files; showSelectedFile(); }
  });
  $("#transfer-list").addEventListener("click", handleTransferAction);
  $("#peer-list").addEventListener("click", handlePeerAction);
  $("#modal-close").addEventListener("click", closePeerModal);
  $("#modal-cancel").addEventListener("click", closePeerModal);
  $("#modal-trust").addEventListener("click", trustSelectedPeer);
  $("#peer-modal").addEventListener("click", event => { if (event.target === $("#peer-modal")) closePeerModal(); });
  $("#settings-form").addEventListener("submit", saveSettings);
}

function showView(name) {
  $$(".view").forEach(view => view.classList.toggle("active", view.id === `view-${name}`));
  $$(".nav-item[data-view]").forEach(item => item.classList.toggle("active", item.dataset.view === name));
  const labels = {dashboard:"Overview",peers:"Network peers",files:"File sharing",history:"Transfer history",analytics:"Network analytics",telemetry:"System telemetry",settings:"Settings & security"};
  $("#breadcrumb-current").textContent = labels[name] || "Overview";
  $("#sidebar").classList.remove("open");
  if (name === "analytics" || name === "telemetry") setTimeout(drawCharts, 30);
}

async function loadDashboard() {
  const data = await api("/api/dashboard");
  renderMetrics(data.metrics, data.online_peers);
  $("#stat-files").textContent = data.transferred_files;
  $("#activity-list").innerHTML = data.activities.length ? data.activities.map(item => `<div class="activity-item"><i class="activity-bullet"></i><div><p>${safe(item.message)}</p><small>${safe(item.created_at)}</small></div></div>`).join("") : `<div class="empty-inline"><p>No activity yet. Account and transfer events will show here.</p></div>`;
  $("#peer-summary").textContent = data.online_peers ? `${data.online_peers} authorized device${data.online_peers === 1 ? "" : "s"} currently online. Trust peers after verifying their fingerprints.` : "Looking for opted-in NetPulse devices on this LAN.";
}

function renderMetrics(metrics, online) {
  $("#stat-peers").textContent = online;
  $("#peer-nav-count").textContent = online;
  $("#stat-cpu").textContent = metrics.cpu_percent.toFixed(0);
  $("#stat-memory").textContent = metrics.memory_percent.toFixed(0);
  $("#cpu-meter").style.width = `${metrics.cpu_percent}%`;
  $("#memory-meter").style.width = `${metrics.memory_percent}%`;
  $("#telemetry-cpu").textContent = metrics.cpu_percent.toFixed(0);
  $("#telemetry-memory").textContent = metrics.memory_percent.toFixed(0);
  $("#telemetry-disk").textContent = metrics.disk_percent.toFixed(0);
  $("#telemetry-cpu-meter").style.width = `${metrics.cpu_percent}%`;
  $("#telemetry-memory-meter").style.width = `${metrics.memory_percent}%`;
  $("#telemetry-disk-meter").style.width = `${metrics.disk_percent}%`;
  $("#memory-capacity").textContent = `${sizeText(metrics.memory_used)} of ${sizeText(metrics.memory_total)}`;
  $("#disk-capacity").textContent = `${sizeText(metrics.disk_used)} of ${sizeText(metrics.disk_total)}`;
  $("#local-ip").textContent = metrics.local_ip;
  $("#interfaces").textContent = metrics.interfaces.join(", ") || "No active interfaces";
  $("#uptime").textContent = timeText(metrics.uptime_seconds);
  $("#telemetry-uptime").textContent = timeText(metrics.uptime_seconds);
  $("#connection-label").textContent = metrics.connection_status;
  $("#device-status").textContent = metrics.connection_status;
  $("#network-download").textContent = bytes(metrics.download_bps);
  $("#network-upload").textContent = bytes(metrics.upload_bps);
  $("#network-ip").textContent = metrics.local_ip;
  $("#network-interfaces").textContent = `Active interface: ${metrics.interfaces.join(", ") || "None"}`;
  $("#bytes-sent").textContent = sizeText(metrics.bytes_sent);
  $("#bytes-received").textContent = sizeText(metrics.bytes_received);
  const point = {download: metrics.download_bps, upload: metrics.upload_bps, cpu: metrics.cpu_percent, memory: metrics.memory_percent};
  state.telemetry.push(point);
  if (state.telemetry.length > 50) state.telemetry.shift();
  drawCharts();
}

function drawLine(canvasId, series, colors, percent = false) {
  const canvas = $(`#${canvasId}`);
  if (!canvas || !canvas.offsetParent) return;
  const rect = canvas.getBoundingClientRect(), ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, rect.width * ratio); canvas.height = Math.max(1, rect.height * ratio);
  const ctx = canvas.getContext("2d"); ctx.scale(ratio, ratio);
  const width = rect.width, height = rect.height, pad = {left:34,right:10,top:10,bottom:22};
  const plotW = width - pad.left - pad.right, plotH = height - pad.top - pad.bottom;
  const values = series.flatMap(item => item.values).filter(Number.isFinite);
  const max = percent ? 100 : Math.max(1, ...values) * 1.15;
  ctx.font = "9px DM Sans, sans-serif"; ctx.fillStyle = "#718198"; ctx.strokeStyle = "#263349"; ctx.lineWidth = 1;
  for (let row = 0; row <= 3; row++) {
    const y = pad.top + plotH * row / 3;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(width-pad.right,y); ctx.stroke();
    ctx.fillText(percent ? `${100-row*33}%` : bytes(max * (1-row/3)), 0, y + 3);
  }
  series.forEach(item => {
    if (item.values.length < 2) return;
    ctx.beginPath(); ctx.strokeStyle = item.color; ctx.lineWidth = 2;
    item.values.forEach((value, i) => {
      const x = pad.left + plotW * i / Math.max(1, item.values.length - 1);
      const y = pad.top + plotH * (1 - Math.min(max, value) / max);
      i ? ctx.lineTo(x,y) : ctx.moveTo(x,y);
    });
    ctx.stroke();
  });
}
function drawCharts() {
  drawLine("overview-chart", [{values:state.telemetry.map(x=>x.download),color:"#6095ff"},{values:state.telemetry.map(x=>x.upload),color:"#2fd4e7"}]);
  drawLine("analytics-chart", [{values:state.telemetry.map(x=>x.download),color:"#6095ff"},{values:state.telemetry.map(x=>x.upload),color:"#2fd4e7"}]);
  drawLine("resource-chart", [{values:state.telemetry.map(x=>x.cpu),color:"#6095ff"},{values:state.telemetry.map(x=>x.memory),color:"#2fd4e7"}], [], true);
}

async function loadPeers() {
  const data = await api("/api/peers");
  state.peers = data.peers;
  $("#peer-total").textContent = `${data.peers.length} device${data.peers.length === 1 ? "" : "s"} discovered`;
  renderPeers(); renderRecipientOptions();
}
function renderPeers() {
  if (!$("#peer-list")) return;
  const query = ($("#peer-search")?.value || "").toLowerCase();
  const rows = state.peers.filter(peer => `${peer.name} ${peer.ip_address} ${peer.hostname}`.toLowerCase().includes(query));
  $("#peer-list").innerHTML = rows.length ? rows.map(peer => `<article class="peer-card"><div class="peer-head"><span class="peer-avatar">⌘</span><div class="peer-title"><strong>${safe(peer.name)}</strong><small>${safe(peer.hostname)}</small></div><i class="peer-online ${peer.online ? "" : "offline"}" title="${peer.online ? "Online" : "Offline"}"></i></div><div class="peer-details"><span>Local IP　${safe(peer.ip_address)}</span><span class="peer-fingerprint">KEY ${safe(peer.fingerprint.slice(0,32))}…</span><span>Last seen　${new Date(peer.last_seen*1000).toLocaleTimeString()}</span></div><div class="peer-foot"><span class="${peer.trusted ? "peer-trusted" : "peer-untrusted"}">${peer.trusted ? "✓ Trusted" : "● Verify first"}</span><button class="button secondary peer-action" data-peer-action="${peer.trusted ? "untrust" : "trust"}" data-peer-id="${safe(peer.node_id)}">${peer.trusted ? "Remove trust" : "Verify & trust"}</button></div></article>`).join("") : `<div class="panel empty-inline"><span class="empty-icon">◎</span><p>${query ? "No devices match your search." : "No participating NetPulse devices found. Discovery only lists devices running NetPulse with the opt-in discovery service enabled."}</p></div>`;
}
function renderRecipientOptions() {
  const select = $("#recipient");
  if (!select) return;
  const previous = select.value;
  select.innerHTML = `<option value="">Private vault on this device</option>` + state.peers.filter(peer=>peer.online&&peer.trusted).map(peer=>`<option value="${safe(peer.node_id)}">${safe(peer.name)} · ${safe(peer.ip_address)}</option>`).join("");
  if (state.peers.some(peer=>peer.node_id===previous&&peer.online&&peer.trusted)) select.value = previous;
}
function handlePeerAction(event) {
  const button = event.target.closest("[data-peer-action]");
  if (!button) return;
  const peer = state.peers.find(item=>item.node_id===button.dataset.peerId);
  if (!peer) return;
  if (button.dataset.peerAction === "trust") {
    state.selectedPeer = peer; $("#modal-fingerprint").textContent = peer.fingerprint.match(/.{1,4}/g).join(" "); $("#peer-modal").classList.remove("hidden");
  } else api(`/api/peers/${encodeURIComponent(peer.node_id)}/trust`, {method:"DELETE"}).then(loadPeers).then(()=>toast("Peer trust removed.")).catch(error=>toast(error.message,true));
}
function closePeerModal() { $("#peer-modal").classList.add("hidden"); state.selectedPeer = null; }
async function trustSelectedPeer() {
  if (!state.selectedPeer) return;
  try {
    await api(`/api/peers/${encodeURIComponent(state.selectedPeer.node_id)}/trust`, {method:"POST"});
    closePeerModal(); await loadPeers(); toast("Peer trusted. You can now send encrypted files.");
  } catch (error) { toast(error.message, true); }
}

function showSelectedFile() {
  const file = $("#file-input").files[0];
  if (!file) { $("#file-picked").classList.add("hidden"); return; }
  $("#file-picked").textContent = `${file.name} · ${sizeText(file.size)}`;
  $("#file-picked").classList.remove("hidden");
}
async function uploadFile(event) {
  event.preventDefault();
  const file = $("#file-input").files[0];
  if (!file) { toast("Choose a file first.", true); return; }
  const form = new FormData(); form.append("file", file);
  if ($("#recipient").value) form.append("peer_id", $("#recipient").value);
  $("#upload-submit").disabled = true; $("#upload-submit").textContent = "Encrypting and sending…"; $("#upload-progress").classList.remove("hidden");
  $("#upload-progress").classList.add("determinate");
  $("#upload-progress i").style.width = "0%";
  try {
    const data = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/transfers");
      xhr.setRequestHeader("X-CSRF-Token", state.csrf);
      xhr.upload.addEventListener("progress", event => {
        if (event.lengthComputable) $("#upload-progress i").style.width = `${Math.min(99, Math.round(event.loaded / event.total * 100))}%`;
      });
      xhr.addEventListener("load", () => {
        let body = {};
        try { body = JSON.parse(xhr.responseText); } catch {}
        if (xhr.status >= 200 && xhr.status < 300) resolve(body);
        else reject(new Error(body.error || "File upload failed."));
      });
      xhr.addEventListener("error", () => reject(new Error("Could not connect to NetPulse.")));
      xhr.send(form);
    });
    $("#upload-progress i").style.width = "100%";
    toast(data.status === "Available" ? "File encrypted and saved to your private vault." : "Encrypted file sent; recipient approval is required.");
    $("#file-input").value = ""; $("#file-picked").classList.add("hidden"); await loadTransfers(); showView("history");
  } catch (error) { toast(error.message,true); }
  finally { $("#upload-submit").disabled = false; $("#upload-submit").textContent = "Encrypt and upload"; $("#upload-progress").classList.add("hidden"); $("#upload-progress").classList.remove("determinate"); }
}
async function loadTransfers() {
  const data = await api("/api/transfers");
  const previousIds = new Set(state.transfers.map(row => row.id));
  const incoming = data.transfers.find(row => row.direction === "incoming" && row.status === "Awaiting approval" && !previousIds.has(row.id));
  if (incoming) toast(`Incoming file request: ${incoming.filename}`);
  state.transfers = data.transfers; renderTransfers();
  $("#stat-files").textContent = data.transfers.filter(row=>["Available","Accepted","Delivered — awaiting approval"].includes(row.status)).length;
}
function renderTransfers() {
  if (!$("#transfer-list")) return;
  const query = ($("#transfer-search")?.value || "").toLowerCase();
  const transfers = state.transfers.filter(row=>`${row.filename} ${row.peer_name||""} ${row.status}`.toLowerCase().includes(query));
  $("#transfer-total").textContent = `${transfers.length} transfer${transfers.length===1?"":"s"}`;
  $("#transfers-empty").classList.toggle("hidden", transfers.length !== 0);
  $("#transfer-list").innerHTML = transfers.map(row=>{
    const statusClass = row.status.toLowerCase().includes("awaiting") ? "pending" : row.status.toLowerCase().includes("failed")||row.status==="Rejected" ? "failed" : row.status==="Sending" ? "sending" : "";
    let actions = "";
    if (row.direction==="incoming" && row.status==="Awaiting approval") actions = `<button class="text-button" data-transfer-action="accept" data-id="${safe(row.id)}">Accept</button><button class="text-button" data-transfer-action="reject" data-id="${safe(row.id)}">Reject</button>`;
    else if (row.status==="Available"||row.status==="Accepted") actions = `<a class="text-button" href="/api/transfers/${encodeURIComponent(row.id)}/download" data-download-id="${safe(row.id)}">Download</a>`;
    return `<tr><td><span class="file-cell"><i class="file-icon">▤</i>${safe(row.filename)}</span></td><td>${safe(row.peer_name|| (row.direction==="local"?"Private vault":row.direction==="incoming"?"NetPulse peer":"Peer"))}</td><td>${sizeText(row.size)}</td><td><span class="status-label ${statusClass}">${safe(row.status)}</span></td><td>${safe(row.created_at)}</td><td>${actions}</td></tr>`;
  }).join("");
}
async function handleTransferAction(event) {
  const download = event.target.closest("[data-download-id]");
  if (download) {
    event.preventDefault();
    await downloadTransfer(download.dataset.downloadId);
    return;
  }
  const button = event.target.closest("[data-transfer-action]");
  if (!button) return;
  try {
    await api(`/api/transfers/${encodeURIComponent(button.dataset.id)}/decision`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({accept:button.dataset.transferAction==="accept"})});
    toast(button.dataset.transferAction==="accept"?"Transfer accepted. Download is now available.":"Transfer rejected.");
    await loadTransfers();
  } catch (error) { toast(error.message,true); }
}

async function loadSettings() {
  const data = await api("/api/settings");
  state.settings = data;
  $("#refresh-interval").value = String(data.monitor_interval);
  $("#theme-select").value = data.theme;
  document.body.classList.toggle("light", data.theme==="light");
  $("#max-file-label").textContent = `${Math.floor(data.max_file_size/1024/1024)} MB`;
  $("#settings-file-size").textContent = `${Math.floor(data.max_file_size/1024/1024)} MB`;
  $("#discovery-state").textContent = data.discovery_enabled ? "Enabled · private LAN" : "Disabled";
  $("#device-name").textContent = data.device_name;
  $("#device-id").textContent = data.node_id;
  $("#device-fingerprint").textContent = data.fingerprint;
  scheduleDashboardPolling();
}
async function saveSettings(event) {
  event.preventDefault();
  const payload={monitor_interval:Number($("#refresh-interval").value),theme:$("#theme-select").value};
  try { await api("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); document.body.classList.toggle("light",payload.theme==="light"); state.settings={...state.settings,...payload}; scheduleDashboardPolling(); toast("Preferences saved."); }
  catch(error){toast(error.message,true);}
}

async function downloadTransfer(identifier) {
  const transfer = state.transfers.find(row => row.id === identifier);
  const notification = document.createElement("div");
  notification.className = "toast";
  notification.textContent = `Downloading ${transfer?.filename || "file"}…`;
  $("#toast-region").append(notification);
  try {
    const response = await fetch(`/api/transfers/${encodeURIComponent(identifier)}/download`);
    if (response.status === 401) { location.assign("/login"); return; }
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Download failed.");
    }
    const total = Number(response.headers.get("Content-Length")) || 0;
    const reader = response.body.getReader();
    const chunks = [];
    let received = 0;
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      if (total) notification.textContent = `Downloading ${transfer?.filename || "file"}… ${Math.round(received / total * 100)}%`;
    }
    const anchor = document.createElement("a");
    anchor.href = URL.createObjectURL(new Blob(chunks, {type: response.headers.get("Content-Type") || "application/octet-stream"}));
    anchor.download = transfer?.filename || "netpulse-download";
    anchor.click();
    URL.revokeObjectURL(anchor.href);
    notification.textContent = "Download complete.";
    setTimeout(() => notification.remove(), 2200);
  } catch (error) {
    notification.classList.add("error");
    notification.textContent = error.message || "Download failed.";
    setTimeout(() => notification.remove(), 4000);
  }
}

function initSocket() {
  if (typeof io !== "function") { $("#connection-label").textContent = "Polling"; return; }
  const socket=io({transports:["websocket","polling"]});
  socket.on("connect",()=>$("#connection-label").textContent="Connected");
  socket.on("disconnect",()=>$("#connection-label").textContent="Reconnecting");
  socket.on("telemetry",data=>renderMetrics(data.metrics,data.online_peers));
}

boot().catch(error => {
  if (error.message !== "Please sign in.") toast(error.message || "NetPulse could not start.",true);
});
