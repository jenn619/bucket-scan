const VENDOR_BY_SERVER = {
  aliyunoss: "aliyun",
  "tencent-cos": "tencent",
  obs: "huawei"
};

const DOMAIN_SUFFIX_VENDOR = [
  { suffix: "aliyuncs.com", vendor: "aliyun" },
  { suffix: "myqcloud.com", vendor: "tencent" },
  { suffix: "myhuaweicloud.com", vendor: "huawei" }
];

export function detectVendor(headers = [], hostname = "") {
  const serverHeader = headers.find((h) => h.name.toLowerCase() === "server");
  if (serverHeader) {
    const byServer = VENDOR_BY_SERVER[serverHeader.value.toLowerCase()];
    if (byServer) return byServer;
  }

  const host = hostname.toLowerCase();
  for (const item of DOMAIN_SUFFIX_VENDOR) {
    if (host.endsWith(item.suffix)) return item.vendor;
  }
  return null;
}

export function normalizeBucketRoot(urlString) {
  try {
    const url = new URL(urlString);
    return `${url.protocol}//${url.hostname}`;
  } catch {
    return null;
  }
}
