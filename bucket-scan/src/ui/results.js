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

let cached = [];

function levelBadge(level) {
  if (level === "high") return `<span class="badge-high">高危</span>`;
  return `<span class="badge-medium">中危</span>`;
}

function escapeHtml(s = "") {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function render() {
  const q = document.querySelector("#q").value.trim().toLowerCase();
  const level = document.querySelector("#level").value;

  const list = cached.filter((f) => {
    if (level !== "all" && f.level !== level) return false;
    if (!q) return true;
    const hay = `${f.vendorName} ${f.vulnType} ${f.bucketRoot}`.toLowerCase();
    return hay.includes(q);
  });

  list.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const tbody = document.querySelector("#tbody");
  tbody.innerHTML = list
    .map(
      (f) => `
      <tr>
        <td>${escapeHtml(f.timestamp)}</td>
        <td>${escapeHtml(f.vendorName)}</td>
        <td>${escapeHtml(f.vulnType)}</td>
        <td>${levelBadge(f.level)}</td>
        <td>${escapeHtml(f.bucketRoot)}</td>
        <td>${escapeHtml(`${f.method} ${f.path}`)}</td>
        <td>${escapeHtml(String(f.status ?? ""))}</td>
      </tr>
    `
    )
    .join("");
}

async function refresh() {
  const state = await send("bucketScan:getState");
  cached = state.findings || [];
  render();
}

document.querySelector("#q").addEventListener("input", render);
document.querySelector("#level").addEventListener("change", render);
document.querySelector("#refresh").addEventListener("click", () => refresh().catch(console.error));

document.querySelector("#export-json").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(cached, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `bucket-scan-results-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

refresh().catch(console.error);
