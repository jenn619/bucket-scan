export const STORAGE_KEYS = {
 SETTINGS: "bucketScan.settings",
 FINDINGS: "bucketScan.findings",
 LAST_SCANNED: "bucketScan.lastScanned"
};

export const DEFAULT_SETTINGS = {
 enablePassive: true,
 enableActiveWriteChecks: false,
 enableJsIntel: true,
 enableSourceMapCheck: true,
 scanTimeoutMs:8000,
 maxConcurrency:3,
 cooldownMs:300000,
 whitelistHosts: [],
 blacklistHosts: []
};

async function getRaw(key, fallback) {
 const data = await chrome.storage.local.get(key);
 return data[key] ?? fallback;
}

function normalizeHostRules(hosts) {
 if (!Array.isArray(hosts)) return [];
 return hosts
 .map((h) => String(h || "").trim().toLowerCase())
 .filter(Boolean);
}

export async function getSettings() {
 const saved = await getRaw(STORAGE_KEYS.SETTINGS, {});
 const merged = { ...DEFAULT_SETTINGS, ...saved };
 merged.whitelistHosts = normalizeHostRules(merged.whitelistHosts);
 merged.blacklistHosts = normalizeHostRules(merged.blacklistHosts);
 return merged;
}

export async function setSettings(patch) {
 const current = await getSettings();
 const next = { ...current, ...patch };
 next.whitelistHosts = normalizeHostRules(next.whitelistHosts);
 next.blacklistHosts = normalizeHostRules(next.blacklistHosts);
 await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: next });
 return next;
}

export async function getFindings() {
 return getRaw(STORAGE_KEYS.FINDINGS, []);
}

export async function saveFindings(newFindings) {
 if (!newFindings?.length) return;
 const current = await getFindings();
 const map = new Map(current.map((f) => [f.key, f]));
 for (const finding of newFindings) {
 map.set(finding.key, finding);
 }
 await chrome.storage.local.set({ [STORAGE_KEYS.FINDINGS]: Array.from(map.values()) });
}

export async function clearFindings() {
 await chrome.storage.local.set({ [STORAGE_KEYS.FINDINGS]: [] });
}

export async function getLastScanned() {
 return getRaw(STORAGE_KEYS.LAST_SCANNED, {});
}

export async function markScanned(scanKey, ts = Date.now()) {
 const data = await getLastScanned();
 data[scanKey] = ts;
 await chrome.storage.local.set({ [STORAGE_KEYS.LAST_SCANNED]: data });
}

export async function shouldScan(scanKey, cooldownMs) {
 const data = await getLastScanned();
 const last = data[scanKey] ??0;
 return Date.now() - last >= cooldownMs;
}
