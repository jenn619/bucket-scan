import { detectVendor, normalizeBucketRoot } from "../scanner/detectVendor.js";
import { runChecks } from "../scanner/core.js";
import {
 getSettings,
 saveFindings,
 getFindings,
 shouldScan,
 markScanned,
 setSettings,
 clearFindings
} from "../storage/state.js";

const queue = [];
let active =0;

function updateBadgeByFindings(findings) {
 const high = findings.filter((f) => f.level === "high").length;
 const total = findings.length;

 chrome.action.setBadgeText({ text: total ? String(total) : "" });
 chrome.action.setBadgeBackgroundColor({ color: high ? "#b91c1c" : "#1d4ed8" });
}

async function refreshBadge() {
 const findings = await getFindings();
 updateBadgeByFindings(findings);
}

function enqueue(task) {
 queue.push(task);
 void drainQueue();
}

async function drainQueue() {
 const settings = await getSettings();
 while (active < settings.maxConcurrency && queue.length >0) {
 const task = queue.shift();
 if (!task) return;
 active +=1;
 void runTask(task)
 .finally(() => {
 active -=1;
 void drainQueue();
 });
 }
}

async function runTask(task) {
 const settings = await getSettings();
 const canScan = await shouldScan(task.bucketRoot, settings.cooldownMs);
 if (!canScan) return;

 const findings = await runChecks({
 vendor: task.vendor,
 bucketRoot: task.bucketRoot,
 settings
 });

 if (findings.length) {
 await saveFindings(findings);
 }

 await markScanned(task.bucketRoot);
 await refreshBadge();
}

function toSimpleHeaders(headers = []) {
 return headers.map((h) => ({
 name: h.name || "",
 value: h.value || ""
 }));
}

function collect(details) {
 if (!details?.url) return;
 const bucketRoot = normalizeBucketRoot(details.url);
 if (!bucketRoot) return;

 const hostname = (() => {
 try {
 return new URL(details.url).hostname;
 } catch {
 return "";
 }
 })();

 const headers = toSimpleHeaders(details.responseHeaders ?? []);
 const vendor = detectVendor(headers, hostname);
 if (!vendor) return;

 enqueue({ bucketRoot, vendor });
}

chrome.webRequest.onHeadersReceived.addListener(
 collect,
 { urls: ["<all_urls>"] },
 ["responseHeaders"]
);

chrome.runtime.onInstalled.addListener(async () => {
 await refreshBadge();
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
 if (message?.type === "bucketScan:getState") {
 Promise.all([getSettings(), getFindings()])
 .then(([settings, findings]) => sendResponse({ ok: true, settings, findings }))
 .catch((error) => sendResponse({ ok: false, error: String(error) }));
 return true;
 }

 if (message?.type === "bucketScan:updateSettings") {
 setSettings(message.payload || {})
 .then((settings) => sendResponse({ ok: true, settings }))
 .catch((error) => sendResponse({ ok: false, error: String(error) }));
 return true;
 }

 if (message?.type === "bucketScan:clearFindings") {
 clearFindings()
 .then(async () => {
 await refreshBadge();
 sendResponse({ ok: true });
 })
 .catch((error) => sendResponse({ ok: false, error: String(error) }));
 return true;
 }

 return false;
});
