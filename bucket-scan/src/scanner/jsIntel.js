import { normalizeBucketRoot } from "./detectVendor.js";

const BUCKET_SUFFIX_VENDOR = [
 { suffix: "aliyuncs.com", vendor: "aliyun", vendorName: "阿里云OSS" },
 { suffix: "myqcloud.com", vendor: "tencent", vendorName: "腾讯云COS" },
 { suffix: "myhuaweicloud.com", vendor: "huawei", vendorName: "华为云OBS" }
];

function success(status) {
 return status >=200 && status <=299;
}

function fetchWithTimeout(url, options, timeoutMs) {
 const ctl = new AbortController();
 const timer = setTimeout(() => ctl.abort(), timeoutMs);
 return fetch(url, { ...options, signal: ctl.signal }).finally(() => clearTimeout(timer));
}

function trimEvidence(text = "", max =180) {
 return String(text).replace(/\s+/g, " ").slice(0, max);
}

function detectVendorByHost(hostname = "") {
 const host = hostname.toLowerCase();
 return BUCKET_SUFFIX_VENDOR.find((item) => host.endsWith(item.suffix)) || null;
}

function cleanExtractedUrl(raw = "") {
 return raw.replace(/[),;\]}'"`]+$/g, "");
}

function extractHttpUrls(text = "") {
 const matches = text.match(/https?:\/\/[^\s"'`<>]+/g) || [];
 const uniq = new Set(matches.map((m) => cleanExtractedUrl(m)));
 return [...uniq].filter(Boolean);
}

function extractSourceMapRef(text = "") {
 const lines = String(text).split(/\r?\n/).slice(-30);
 const joined = lines.join("\n");
 const all = [...joined.matchAll(/sourceMappingURL\s*=\s*([^\s*]+)/gi)];
 if (!all.length) return "";
 return String(all[all.length -1][1] || "").trim();
}

function resolveMapUrl(jsUrl, sourceMapRef) {
 if (sourceMapRef && !sourceMapRef.startsWith("data:")) {
 try {
 return new URL(sourceMapRef, jsUrl).toString();
 } catch {
 return "";
 }
 }

 try {
 const u = new URL(jsUrl);
 const basePath = u.pathname.replace(/\?.*$/, "").replace(/#.*$/, "");
 u.pathname = `${basePath}.map`;
 u.search = "";
 u.hash = "";
 return u.toString();
 } catch {
 return "";
 }
}

function mapLikeJson(text = "") {
 const body = String(text || "").trim();
 return body.startsWith("{") && body.includes('"version"') && body.includes('"sources"');
}

function pathFromUrl(urlString = "") {
 try {
 const u = new URL(urlString);
 return `${u.pathname}${u.search}`;
 } catch {
 return "/";
 }
}

function hostRoot(urlString = "") {
 try {
 const u = new URL(urlString);
 return `${u.protocol}//${u.hostname}`;
 } catch {
 return "";
 }
}

export async function analyzeJsAsset({ jsUrl, settings, nowIso }) {
 const findings = [];
 if (!settings.enableJsIntel) return findings;

 let jsText = "";
 let jsStatus =0;
 try {
 const jsRes = await fetchWithTimeout(jsUrl, { method: "GET" }, settings.scanTimeoutMs);
 jsStatus = jsRes.status;
 if (!success(jsRes.status)) return findings;
 jsText = await jsRes.text();
 } catch {
 return findings;
 }

 const now = nowIso();
 const jsPath = pathFromUrl(jsUrl);
 const jsLen = String(jsText || "").length;
 const urls = extractHttpUrls(jsText);
 for (const hitUrl of urls) {
 let hostname = "";
 try {
 hostname = new URL(hitUrl).hostname;
 } catch {
 continue;
 }

 const vendor = detectVendorByHost(hostname);
 if (!vendor) continue;

 const bucketRoot = normalizeBucketRoot(hitUrl);
 if (!bucketRoot) continue;

 findings.push({
 key: `${vendor.vendor}|js_leak_bucket_url|${bucketRoot}`,
 vendor: vendor.vendor,
 vendorName: vendor.vendorName,
 vulnType: "JS泄露对象存储地址",
 level: "medium",
 confidence: "medium",
 bucketRoot,
 status: jsStatus,
 method: "GET",
 path: jsPath,
 targetUrl: hitUrl,
 responseLength: jsLen,
 evidence: trimEvidence(hitUrl),
 source: "js-intel",
 timestamp: now
 });
 }

 if (!settings.enableSourceMapCheck) return findings;

 const sourceMapRef = extractSourceMapRef(jsText);
 const mapUrl = resolveMapUrl(jsUrl, sourceMapRef);
 if (!mapUrl) return findings;

 try {
 const mapRes = await fetchWithTimeout(mapUrl, { method: "GET" }, settings.scanTimeoutMs);
 const mapText = await mapRes.text();
 if (success(mapRes.status) && mapLikeJson(mapText)) {
 findings.push({
 key: `generic|source_map_exposed|${mapUrl}`,
 vendor: "generic",
 vendorName: "前端资产",
 vulnType: "SourceMap文件可下载",
 level: "medium",
 confidence: "high",
 bucketRoot: hostRoot(mapUrl),
 status: mapRes.status,
 method: "GET",
 path: pathFromUrl(mapUrl),
 targetUrl: mapUrl,
 responseLength: String(mapText || "").length,
 evidence: trimEvidence(sourceMapRef || mapUrl),
 source: "js-intel",
 timestamp: now
 });
 }
 } catch {
 return findings;
 }

 return findings;
}
