import { runAliyunChecks } from "./vendors/aliyun.js";
import { runTencentChecks } from "./vendors/tencent.js";
import { runHuaweiChecks } from "./vendors/huawei.js";

const CHECK_RUNNERS = {
 aliyun: runAliyunChecks,
 tencent: runTencentChecks,
 huawei: runHuaweiChecks
};

function nowIso() {
 return new Date().toISOString();
}

export function success(status) {
 return status >=200 && status <=299;
}

export function includesAllCI(text, markers) {
 const body = String(text || "").toLowerCase();
 return markers.every((m) => body.includes(String(m).toLowerCase()));
}

export function includesAnyCI(text, markers) {
 const body = String(text || "").toLowerCase();
 return markers.some((m) => body.includes(String(m).toLowerCase()));
}

export function firstMatchCI(text, markers) {
 const body = String(text || "").toLowerCase();
 const hit = markers.find((m) => body.includes(String(m).toLowerCase()));
 return hit ? String(hit) : "";
}

function escapeRegExp(text) {
 return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function trimEvidence(text, marker) {
 if (!text) return marker || "";
 if (!marker) return String(text).slice(0,140);
 const raw = String(text);
 const pattern = new RegExp(`.{0,40}${escapeRegExp(marker)}.{0,40}`, "i");
 const matched = raw.match(pattern)?.[0];
 return (matched || marker).replace(/\s+/g, " ").slice(0,180);
}

function parseContentLength(headerValue) {
 const n = Number(headerValue);
 return Number.isFinite(n) && n >=0 ? n : null;
}

function makeTargetUrl(bucketRoot, path) {
 const p = String(path || "/");
 if (!bucketRoot) return p;
 return `${bucketRoot}${p.startsWith("/") ? p : `/${p}`}`;
}

export function buildTakeoverFinding({ vendor, vendorName, bucketRoot, status, text, marker, now }) {
 return {
 key: `${vendor}|bucket_takeover|${bucketRoot}`,
 vendor,
 vendorName,
 vulnType: "存储桶可接管",
 level: "high",
 confidence: "high",
 bucketRoot,
 status,
 method: "GET",
 path: "/",
 targetUrl: makeTargetUrl(bucketRoot, "/"),
 responseLength: String(text || "").length,
 evidence: trimEvidence(text, marker),
 source: "passive",
 timestamp: now
 };
}

async function fetchWithTimeout(url, options, timeoutMs) {
 const ctl = new AbortController();
 const timer = setTimeout(() => ctl.abort(), timeoutMs);
 try {
 const response = await fetch(url, {
 ...options,
 signal: ctl.signal,
 headers: {
 ...(options?.headers ?? {})
 }
 });
 return response;
 } finally {
 clearTimeout(timer);
 }
}

function toErrorResult(error) {
 return {
 error: error?.name || "request_failed",
 status:0,
 text: "",
 contentLength: null
 };
}

function buildContext(bucketRoot, settings) {
 return {
 bucketRoot,
 settings,
 nowIso,
 async fetchText(url, options) {
 try {
 const res = await fetchWithTimeout(url, options, settings.scanTimeoutMs);
 const text = await res.text();
 const len = parseContentLength(res.headers.get("content-length"));
 return { status: res.status, text, contentLength: len ?? text.length, error: null };
 } catch (error) {
 return toErrorResult(error);
 }
 },
 async fetchStatus(url, options) {
 try {
 const res = await fetchWithTimeout(url, options, settings.scanTimeoutMs);
 const len = parseContentLength(res.headers.get("content-length"));
 return { status: res.status, contentLength: len, error: null };
 } catch (error) {
 return toErrorResult(error);
 }
 }
 };
}

export async function runChecks({ vendor, bucketRoot, settings }) {
 const runner = CHECK_RUNNERS[vendor];
 if (!runner || !settings.enablePassive) return [];
 const ctx = buildContext(bucketRoot, settings);
 const findings = await runner(ctx);
 return findings.map((f) => {
 const path = f.path || "/";
 return {
 confidence: f.confidence || "medium",
 evidence: f.evidence || "",
 source: f.source || "passive",
 targetUrl: f.targetUrl || makeTargetUrl(f.bucketRoot || bucketRoot, path),
 responseLength: Number.isFinite(f.responseLength) ? f.responseLength : null,
 ...f,
 target: bucketRoot
 };
 });
}
