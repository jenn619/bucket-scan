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

function setMsg(text, color = "#93c5fd") {
  const el = document.querySelector("#msg");
  el.textContent = text;
  el.style.color = color;
}

function fill(settings) {
  document.querySelector("#enablePassive").checked = !!settings.enablePassive;
  document.querySelector("#enableActiveWriteChecks").checked = !!settings.enableActiveWriteChecks;
  document.querySelector("#scanTimeoutMs").value = settings.scanTimeoutMs;
  document.querySelector("#maxConcurrency").value = settings.maxConcurrency;
  document.querySelector("#cooldownMs").value = settings.cooldownMs;
}

async function init() {
  const state = await send("bucketScan:getState");
  fill(state.settings);
}

document.querySelector("#save").addEventListener("click", async () => {
  try {
    const payload = {
      enablePassive: document.querySelector("#enablePassive").checked,
      enableActiveWriteChecks: document.querySelector("#enableActiveWriteChecks").checked,
      scanTimeoutMs: Number(document.querySelector("#scanTimeoutMs").value || 8000),
      maxConcurrency: Number(document.querySelector("#maxConcurrency").value || 3),
      cooldownMs: Number(document.querySelector("#cooldownMs").value || 300000)
    };

    if (payload.enableActiveWriteChecks) {
      const ok = confirm("主动写检测会发送 PUT 请求，确认保存并开启？");
      if (!ok) {
        payload.enableActiveWriteChecks = false;
      }
    }

    await send("bucketScan:updateSettings", payload);
    setMsg("已保存", "#86efac");
  } catch (error) {
    setMsg(String(error), "#fca5a5");
  }
});

init().catch((e) => setMsg(String(e), "#fca5a5"));
