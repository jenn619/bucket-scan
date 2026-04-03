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

function statCard(n, k) {
  const el = document.createElement("div");
  el.className = "card";
  el.innerHTML = `<div class="n">${n}</div><div class="k">${k}</div>`;
  return el;
}

function renderStats(findings) {
  const high = findings.filter((f) => f.level === "high").length;
  const medium = findings.filter((f) => f.level === "medium").length;
  const total = findings.length;
  const box = document.querySelector("#stats");
  box.innerHTML = "";
  box.append(statCard(total, "总计"), statCard(high, "高危"), statCard(medium, "中危"));
}

function renderRecent(findings) {
  const list = document.querySelector("#recent-list");
  list.innerHTML = "";
  const recent = [...findings]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 8);

  if (!recent.length) {
    list.innerHTML = "<li class='item'>暂无结果</li>";
    return;
  }

  for (const f of recent) {
    const li = document.createElement("li");
    li.className = "item";
    li.innerHTML = `
      <div><strong>${f.vulnType}</strong> · ${f.vendorName}</div>
      <div class="meta">${f.bucketRoot} · ${f.method} ${f.path} · ${f.status}</div>
    `;
    list.append(li);
  }
}

async function refresh() {
  const state = await send("bucketScan:getState");
  const { settings, findings } = state;

  document.querySelector("#enable-passive").checked = !!settings.enablePassive;
  document.querySelector("#enable-active").checked = !!settings.enableActiveWriteChecks;

  renderStats(findings);
  renderRecent(findings);
}

async function patchSettings(patch) {
  await send("bucketScan:updateSettings", patch);
  await refresh();
}

document.querySelector("#enable-passive").addEventListener("change", (e) => {
  patchSettings({ enablePassive: e.target.checked }).catch(console.error);
});

document.querySelector("#enable-active").addEventListener("change", (e) => {
  if (e.target.checked) {
    const ok = confirm("主动写检测会发送 PUT 请求，确认开启？");
    if (!ok) {
      e.target.checked = false;
      return;
    }
  }
  patchSettings({ enableActiveWriteChecks: e.target.checked }).catch(console.error);
});

document.querySelector("#clear").addEventListener("click", async () => {
  await send("bucketScan:clearFindings");
  await refresh();
});

document.querySelector("#open-results").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("src/ui/results.html") });
});

document.querySelector("#open-options").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

refresh().catch(console.error);
