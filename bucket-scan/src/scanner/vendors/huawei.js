function success(code) {
  return code <= 299;
}

function includesAny(text, markers) {
  return markers.some((m) => text.includes(m));
}

export async function runHuaweiChecks(ctx) {
  const findings = [];
  const { bucketRoot, settings, fetchText, fetchStatus, nowIso } = ctx;

  const root = await fetchText(bucketRoot, { method: "GET" });
  if (!root.error && success(root.status) && includesAny(root.text, ["<Name>", "<Contents>"])) {
    findings.push({
      key: `huawei|bucket_traversable|${bucketRoot}`,
      vendor: "huawei",
      vendorName: "华为云OBS",
      vulnType: "存储桶可遍历",
      level: "medium",
      bucketRoot,
      status: root.status,
      method: "GET",
      path: "/",
      timestamp: nowIso()
    });
  }

  const aclRead = await fetchText(`${bucketRoot}/?acl`, { method: "GET" });
  if (!aclRead.error && success(aclRead.status) && includesAny(aclRead.text, ["<Owner>", "<AccessControlList>"])) {
    findings.push({
      key: `huawei|acl_readable|${bucketRoot}`,
      vendor: "huawei",
      vendorName: "华为云OBS",
      vulnType: "ACL可读",
      level: "medium",
      bucketRoot,
      status: aclRead.status,
      method: "GET",
      path: "/?acl",
      timestamp: nowIso()
    });
  }

  if (!settings.enableActiveWriteChecks) return findings;

  const fileName = `bucket-scan-test-${Date.now()}.txt`;
  const upload = await fetchStatus(`${bucketRoot}/${fileName}`, {
    method: "PUT",
    body: "bucket-scan upload probe"
  });
  if (!upload.error && success(upload.status)) {
    findings.push({
      key: `huawei|put_upload|${bucketRoot}`,
      vendor: "huawei",
      vendorName: "华为云OBS",
      vulnType: "PUT文件上传",
      level: "high",
      bucketRoot,
      status: upload.status,
      method: "PUT",
      path: `/${fileName}`,
      timestamp: nowIso()
    });
  }

  const aclWrite = await fetchStatus(`${bucketRoot}/?acl`, {
    method: "PUT",
    headers: { "x-obs-acl": "public-read-write-delivered" }
  });
  if (!aclWrite.error && success(aclWrite.status)) {
    findings.push({
      key: `huawei|acl_writable|${bucketRoot}`,
      vendor: "huawei",
      vendorName: "华为云OBS",
      vulnType: "ACL可写",
      level: "high",
      bucketRoot,
      status: aclWrite.status,
      method: "PUT",
      path: "/?acl",
      timestamp: nowIso()
    });
  }

  return findings;
}
