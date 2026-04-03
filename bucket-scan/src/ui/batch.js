function send(type, payload) {
 return new Promise((resolve, reject) => {
 chrome.runtime.sendMessage({ type, payload }, (res) => {
 const err = chrome.runtime.lastError;
 if (err) return reject(new Error(err.message));
 if (!res?.ok) return reject(new Error(res?.error || "request failed"));
 resolve(res);
 });
 });
}

let timer = null;
let state = {
 running: false,
 totalBuckets:0,
 finishedBuckets:0,
 failedBuckets:0,
 totalObjects:0,
 items: [],
 errors: []
};

function escapeHtml(s = "") {
 return String(s)
 .replaceAll("&", "&amp;")
 .replaceAll("<", "&lt;")
 .replaceAll(">", "&gt;")
 .replaceAll('"', "&quot;")
 .replaceAll("'", "&#39;");
}

function setMsg(text, color = "#93c5fd") {
 const el = document.querySelector("#msg");
 el.textContent = text;
 el.style.color = color;
}

function statCard(n, k) {
 return `<div class="card"><div class="n">${escapeHtml(String(n))}</div><div class="k">${escapeHtml(k)}</div></div>`;
}

function canBulkPreview(url = "") {
 try {
 const u = new URL(url);
 const path = u.pathname.toLowerCase();
 return /\.(jpg|jpeg|png|gif|webp|bmp|svg|tif|tiff|pdf|doc|docx|txt)$/i.test(path);
 } catch {
 return false;
 }
}

function renderStats() {
 const box = document.querySelector("#stats");
 box.innerHTML = [
 statCard(state.running ? "运行中" : "已停止", "状态"),
 statCard(state.totalBuckets, "总桶数"),
 statCard(state.finishedBuckets, "已完成"),
 statCard(state.failedBuckets, "失败"),
 statCard(state.totalObjects, "对象数")
 ].join("");
}

function renderTable() {
 const tbody = document.querySelector("#tbody");
 const rows = (state.items || [])
 .slice()
 .sort((a, b) => String(b.lastModified || "").localeCompare(String(a.lastModified || "")))
 .map((item, idx) => {
 const bucket = escapeHtml(item.bucketRoot || "-");
 const key = escapeHtml(item.key || "-");
 const size = Number.isFinite(item.size) ? String(item.size) : "-";
 const lastModified = escapeHtml(item.lastModified || "-");
 const url = String(item.url || "");
 const escapedUrl = escapeHtml(url);
 return `
 <tr>
 <td>${bucket}</td>
 <td class="key">${key}</td>
 <td>${escapeHtml(size)}</td>
 <td>${lastModified}</td>
 <td class="url"><a href="${escapedUrl}" target="_blank" rel="noreferrer">${escapedUrl || "-"}</a></td>
 <td><button data-open-index="${idx}">打开</button></td>
 </tr>
 `;
 })
 .join("");
 tbody.innerHTML = rows;
}

function renderErrors() {
 const el = document.querySelector("#errors");
 el.value = (state.errors || []).join("\n");
}

function render() {
 renderStats();
 renderTable();
 renderErrors();
}

async function refreshState() {
 const res = await send("bucketScan:batchGetState");
 state = res.state || state;
 render();
}

function startPolling() {
 stopPolling();
 timer = setInterval(() => {
 refreshState().catch(() => {});
 },1000);
}

function stopPolling() {
 if (!timer) return;
 clearInterval(timer);
 timer = null;
}

document.querySelector("#start").addEventListener("click", async () => {
 try {
 const text = document.querySelector("#bucket-input").value || "";
 await send("bucketScan:batchStart", { text });
 setMsg("批量遍历已开始", "#86efac");
 await refreshState();
 startPolling();
 } catch (error) {
 setMsg(String(error), "#fca5a5");
 }
});

document.querySelector("#stop").addEventListener("click", async () => {
 try {
 await send("bucketScan:batchStop");
 await refreshState();
 stopPolling();
 setMsg("已停止", "#fbbf24");
 } catch (error) {
 setMsg(String(error), "#fca5a5");
 }
});

document.querySelector("#bulk-open").addEventListener("click", async () => {
 const candidates = (state.items || []).map((x) => x.url).filter((u) => canBulkPreview(u));
 if (!candidates.length) {
 setMsg("没有可批量打开的可预览对象", "#fbbf24");
 return;
 }
 if (candidates.length >10) {
 setMsg(`可预览对象 ${candidates.length} 个，超过上限10，请缩小范围`, "#fbbf24");
 return;
 }

 for (const url of candidates) {
 chrome.tabs.create({ url });
 }
 setMsg(`已打开 ${candidates.length} 个对象`, "#86efac");
});

document.querySelector("#tbody").addEventListener("click", (e) => {
 const btn = e.target.closest("button[data-open-index]");
 if (!btn) return;
 const index = Number(btn.getAttribute("data-open-index"));
 if (!Number.isFinite(index)) return;
 const item = (state.items || [])[index];
 if (!item?.url) return;
 chrome.tabs.create({ url: item.url });
});

refreshState()
 .then(() => {
 if (state.running) startPolling();
 })
 .catch((e) => setMsg(String(e), "#fca5a5"));
