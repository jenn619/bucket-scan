import { normalizeBucketRoot } from "./detectVendor.js";

const VENDOR_SUFFIXES = [
  { suffix: "aliyuncs.com", vendor: "aliyun" },
  { suffix: "myqcloud.com", vendor: "tencent" },
  { suffix: "myhuaweicloud.com", vendor: "huawei" },
  { suffix: "blob.core.windows.net", vendor: "azure" },
  { suffix: "storage.googleapis.com", vendor: "gcs" }
];

const ALLOWED_EXTENSIONS = new Set([
  "jpg",
  "jpeg",
  "png",
  "gif",
  "webp",
  "bmp",
  "svg",
  "tif",
  "tiff",
  "pdf",
  "doc",
  "docx",
  "txt"
]);

const DEFAULT_MAX_OBJECTS = 10;

function decodeXmlText(text = "") {
  return String(text)
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'");
}

function fetchWithTimeout(url, timeoutMs) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  return fetch(url, { method: "GET", signal: ctl.signal }).finally(() => clearTimeout(timer));
}

function looksLikeAwsHost(host = "") {
  return /(^|\.)s3[.-][a-z0-9-]+\.amazonaws\.com$/i.test(host) || /(^|\.)s3\.amazonaws\.com$/i.test(host);
}

function detectVendorByHost(hostname = "") {
  const host = String(hostname || "").toLowerCase();
  const hit = VENDOR_SUFFIXES.find((item) => host.endsWith(item.suffix));
  if (hit) return hit.vendor;
  if (looksLikeAwsHost(host)) return "aws";
  return "generic";
}

function parseTagValue(xml = "", tag = "") {
  const reg = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "i");
  return decodeXmlText(xml.match(reg)?.[1] || "").trim();
}

function parseContents(xml = "") {
  const blocks = [...String(xml).matchAll(/<Contents>([\s\S]*?)<\/Contents>/gi)];
  return blocks
    .map((m) => m[1] || "")
    .map((raw) => ({
      key: parseTagValue(raw, "Key"),
      size: Number(parseTagValue(raw, "Size") || 0),
      lastModified: parseTagValue(raw, "LastModified")
    }))
    .filter((item) => item.key);
}

function parseAzureBlobs(xml = "") {
  const blocks = [...String(xml).matchAll(/<Blob>([\s\S]*?)<\/Blob>/gi)];
  return blocks
    .map((m) => m[1] || "")
    .map((raw) => ({
      key: parseTagValue(raw, "Name"),
      size: Number(parseTagValue(raw, "Content-Length") || 0),
      lastModified: parseTagValue(raw, "Last-Modified") || parseTagValue(raw, "LastModified")
    }))
    .filter((item) => item.key);
}

function parsePaging(xml = "") {
  const nextMarker =
    parseTagValue(xml, "NextMarker") ||
    parseTagValue(xml, "NextContinuationToken") ||
    parseTagValue(xml, "NextToken");
  const isTruncated = /^true$/i.test(parseTagValue(xml, "IsTruncated"));
  return { nextMarker, isTruncated: isTruncated || !!nextMarker };
}

function buildListUrl(bucketRoot, marker = "", vendor = "generic") {
  const u = new URL(bucketRoot);

  if (vendor === "azure") {
    u.searchParams.set("restype", "container");
    u.searchParams.set("comp", "list");
    u.searchParams.set("maxresults", "1000");
    if (marker) {
      u.searchParams.set("marker", marker);
    } else {
      u.searchParams.delete("marker");
    }
    return u.toString();
  }

  if (vendor === "aws") {
    u.searchParams.set("list-type", "2");
    u.searchParams.set("max-keys", "1000");
    if (marker) {
      u.searchParams.set("continuation-token", marker);
    } else {
      u.searchParams.delete("continuation-token");
    }
    return u.toString();
  }

  u.searchParams.set("max-keys", "1000");
  if (marker) {
    u.searchParams.set("marker", marker);
  } else {
    u.searchParams.delete("marker");
  }
  return u.toString();
}

function getExtension(key = "") {
  const clean = String(key || "").split("?")[0].toLowerCase();
  const idx = clean.lastIndexOf(".");
  if (idx < 0 || idx === clean.length - 1) return "";
  return clean.slice(idx + 1);
}

function isAllowedObjectType(key = "") {
  return ALLOWED_EXTENSIONS.has(getExtension(key));
}

export function buildObjectUrl(bucketRoot, key) {
  const u = new URL(bucketRoot);
  const raw = String(key || "").replace(/^\/+/, "");
  const encoded = raw
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
  u.pathname = `/${encoded}`;
  u.search = "";
  u.hash = "";
  return u.toString();
}

export function normalizeInputBucketRoots(input) {
  const lines = Array.isArray(input) ? input : String(input || "").split(/\r?\n/);
  const set = new Set();

  for (const line of lines) {
    const raw = String(line || "").trim();
    if (!raw) continue;

    const candidates = /^https?:\/\//i.test(raw) ? [raw] : [`https://${raw}`];
    for (const value of candidates) {
      const root = normalizeBucketRoot(value);
      if (!root) continue;
      set.add(root);
    }
  }

  return [...set];
}

export async function listBucketObjects({ bucketRoot, timeoutMs = 8000, maxPages = 20, maxObjects = DEFAULT_MAX_OBJECTS }) {
  let marker = "";
  let page = 0;
  const items = [];
  const errors = [];
  const vendor = detectVendorByHost(new URL(bucketRoot).hostname);

  while (page < maxPages && items.length < maxObjects) {
    page += 1;
    const listUrl = buildListUrl(bucketRoot, marker, vendor);

    try {
      const res = await fetchWithTimeout(listUrl, timeoutMs);
      const text = await res.text();
      if (res.status < 200 || res.status > 299) {
        errors.push(`HTTP ${res.status} @ ${listUrl}`);
        break;
      }

      const parsed = [...parseContents(text), ...parseAzureBlobs(text)]
        .filter((item) => isAllowedObjectType(item.key))
        .map((item) => ({
          ...item,
          bucketRoot,
          vendor,
          url: buildObjectUrl(bucketRoot, item.key)
        }));

      for (const item of parsed) {
        items.push(item);
        if (items.length >= maxObjects) break;
      }

      const paging = parsePaging(text);
      if (!paging.isTruncated) break;

      marker = paging.nextMarker || (parsed[parsed.length - 1]?.key || "");
      if (!marker) break;
    } catch (error) {
      errors.push(String(error?.message || error || "request failed"));
      break;
    }
  }

  return {
    bucketRoot,
    vendor,
    items,
    errors,
    truncated: page >= maxPages,
    pagesFetched: page
  };
}
