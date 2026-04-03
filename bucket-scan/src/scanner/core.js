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
  return status >= 200 && status <= 299;
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
  if (!marker) return String(text).slice(0, 140);
  const raw = String(text);
  const pattern = new RegExp(`.{0,40}${escapeRegExp(marker)}.{0,40}`, "i");
  const matched = raw.match(pattern)?.[0];
  return (matched || marker).replace(/\s+/g, " ").slice(0, 180);
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
    status: 0,
    text: ""
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
        return { status: res.status, text, error: null };
      } catch (error) {
        return toErrorResult(error);
      }
    },
    async fetchStatus(url, options) {
      try {
        const res = await fetchWithTimeout(url, options, settings.scanTimeoutMs);
        return { status: res.status, error: null };
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
  return findings.map((f) => ({
    confidence: f.confidence || "medium",
    evidence: f.evidence || "",
    source: f.source || "passive",
    ...f,
    target: bucketRoot
  }));
}
