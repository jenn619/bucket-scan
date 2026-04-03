import { detectVendor, normalizeBucketRoot } from "../scanner/detectVendor.js";
import { runChecks } from "../scanner/core.js";
import { analyzeJsAsset } from "../scanner/jsIntel.js";
import { listBucketObjects, normalizeInputBucketRoots } from "../scanner/batchTraversal.js";
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

function nowIso() {
 return new Date().toISOString();
}

function newBatchState() {
 return {
 running: false,
 totalBuckets:0,
 finishedBuckets:0,
 failedBuckets:0,
 totalObjects:0,
 items: [],
 errors: [],
 startedAt: "",
 updatedAt: ""
 };
}

let batchState = newBatchState();
let batchRunId =0;
let batchStopRequested = false;

function snapshotBatchState() {
 return {
 ...batchState,
 items: [...batchState.items],
 errors: [...batchState.errors]
 };
}

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
 void runTask(task).finally(() => {
 active -=1;
 void drainQueue();
 });
 }
}

async function runTask(task) {
 const settings = await getSettings();

 if (task.type === "bucketScan") {
 const scanKey = `bucket|${task.vendor}|${task.bucketRoot}`;
 const canScan = await shouldScan(scanKey, settings.cooldownMs);
 if (!canScan) return;

 const findings = await runChecks({
 vendor: task.vendor,
 bucketRoot: task.bucketRoot,
 settings
 });

 if (findings.length) {
 await saveFindings(findings);
 }

 await markScanned(scanKey);
 await refreshBadge();
 return;
 }

 if (task.type === "jsIntel") {
 if (!settings.enableJsIntel) return;
 const scanKey = `js|${task.jsUrl}`;
 const canScan = await shouldScan(scanKey, settings.cooldownMs);
 if (!canScan) return;

 const findings = await analyzeJsAsset({
 jsUrl: task.jsUrl,
 settings,
 nowIso
 });

 if (findings.length) {
 await saveFindings(findings);
 await refreshBadge();
 }

 await markScanned(scanKey);
 }
}

function toSimpleHeaders(headers = []) {
 return headers.map((h) => ({
 name: h.name || "",
 value: h.value || ""
 }));
}

function getHeaderValue(headers = [], headerName = "") {
 const name = headerName.toLowerCase();
 const hit = headers.find((h) => String(h.name || "").toLowerCase() === name);
 return String(hit?.value || "");
}

function isScriptAsset(details, headers) {
 const byType = details?.type === "script";
 const byPath = /\.m?js(?:[?#]|$)/i.test(details?.url || "");
 const ct = getHeaderValue(headers, "content-type").toLowerCase();
 const byHeader =
 ct.includes("javascript") ||
 ct.includes("ecmascript") ||
 ct.includes("application/x-javascript");
 return byType || byPath || byHeader;
}

function matchesHostRule(hostname, rule) {
 const host = String(hostname || "").toLowerCase();
 const normalized = String(rule || "").trim().toLowerCase();
 if (!host || !normalized) return false;
 if (normalized.startsWith("*.")) {
 const base = normalized.slice(2);
 return host === base || host.endsWith(`.${base}`);
 }
 return host === normalized;
}

function isBlockedByRules(hostname, settings) {
 const whitelistHosts = settings.whitelistHosts || [];
 const blacklistHosts = settings.blacklistHosts || [];
 return (
 whitelistHosts.some((r) => matchesHostRule(hostname, r)) ||
 blacklistHosts.some((r) => matchesHostRule(hostname, r))
 );
}

async function collect(details) {
 if (!details?.url || !/^https?:\/\//i.test(details.url)) return;

 let hostname = "";
 try {
 hostname = new URL(details.url).hostname;
 } catch {
 return;
 }

 const settings = await getSettings();
 if (isBlockedByRules(hostname, settings)) return;

 const headers = toSimpleHeaders(details.responseHeaders ?? []);

 if (isScriptAsset(details, headers)) {
 enqueue({ type: "jsIntel", jsUrl: details.url });
 }

 const bucketRoot = normalizeBucketRoot(details.url);
 if (!bucketRoot) return;

 const vendor = detectVendor(headers, hostname);
 if (!vendor) return;

 enqueue({ type: "bucketScan", bucketRoot, vendor });
}

async function runBatchTraversal(bucketRoots) {
 const settings = await getSettings();
 const timeoutMs = Number(settings.scanTimeoutMs ||8000);
 const maxConcurrency = Math.max(1, Number(settings.maxConcurrency ||3));
 const maxPages =20;
 const runId = ++batchRunId;
 batchStopRequested = false;

 batchState = {
 ...newBatchState(),
 running: true,
 totalBuckets: bucketRoots.length,
 startedAt: nowIso(),
 updatedAt: nowIso()
 };

 let cursor =0;

 async function worker() {
 while (!batchStopRequested && runId === batchRunId) {
 if (cursor >= bucketRoots.length) return;
 const idx = cursor;
 cursor +=1;
 const bucketRoot = bucketRoots[idx];

 let failed = false;
 try {
 const result = await listBucketObjects({ bucketRoot, timeoutMs, maxPages });
 if (runId !== batchRunId) return;

 if (result.errors.length) {
 failed = true;
 for (const err of result.errors) {
 batchState.errors.push(`${bucketRoot} :: ${err}`);
 }
 }

 if (result.truncated) {
 batchState.errors.push(`${bucketRoot} :: reached max pages(${maxPages})`);
 }

 batchState.items.push(...result.items);
 batchState.totalObjects = batchState.items.length;
 } catch (error) {
 if (runId !== batchRunId) return;
 failed = true;
 batchState.errors.push(`${bucketRoot} :: ${String(error?.message || error || "request failed")}`);
 } finally {
 if (runId !== batchRunId) return;
 batchState.finishedBuckets +=1;
 if (failed) batchState.failedBuckets +=1;
 batchState.updatedAt = nowIso();
 }
 }
 }

 const workers = Array.from(
 { length: Math.max(1, Math.min(maxConcurrency, bucketRoots.length ||1)) },
 () => worker()
 );
 await Promise.all(workers);

 if (runId !== batchRunId) return;
 batchState.running = false;
 batchState.updatedAt = nowIso();
}

chrome.webRequest.onHeadersReceived.addListener(
 (details) => {
 void collect(details).catch(() => {});
 },
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

 if (message?.type === "bucketScan:batchGetState") {
 sendResponse({ ok: true, state: snapshotBatchState() });
 return false;
 }

 if (message?.type === "bucketScan:batchStop") {
 batchStopRequested = true;
 batchRunId +=1;
 batchState.running = false;
 batchState.updatedAt = nowIso();
 sendResponse({ ok: true, state: snapshotBatchState() });
 return false;
 }

 if (message?.type === "bucketScan:batchStart") {
 const payload = message.payload || {};
 const bucketRoots = normalizeInputBucketRoots(payload.bucketRoots || payload.text || "");

 if (!bucketRoots.length) {
 sendResponse({ ok: false, error: "请至少输入一个有效 bucket 地址" });
 return false;
 }

 batchStopRequested = true;
 batchRunId +=1;

 void runBatchTraversal(bucketRoots).catch((error) => {
 batchState.running = false;
 batchState.errors.push(String(error?.message || error || "batch failed"));
 batchState.updatedAt = nowIso();
 });

 sendResponse({ ok: true, state: snapshotBatchState() });
 return false;
 }

 return false;
});
