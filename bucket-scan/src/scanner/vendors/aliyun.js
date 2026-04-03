function success(code) {
  return code <= 299;
}

function includesAll(text, markers) {
  return markers.every((m) => text.includes(m));
}

export async function runAliyunChecks(ctx) {
  const findings = [];
  const { bucketRoot, settings, fetchText, fetchStatus, nowIso } = ctx;

  const root = await fetchText(bucketRoot, { method: "GET" });
  if (!root.error && success(root.status) && includesAll(root.text, ["<ListBucketResult>", "<Name>"])) {
    findings.push({
      key: `aliyun|bucket_traversable|${bucketRoot}`,
      vendor: "aliyun",
      vendorName: "阿里云OSS",
      vulnType: "存储桶可遍历",
      level: "medium",
      bucketRoot,
      status: root.status,
      method: "GET",
      path: "/",
      timestamp: nowIso()
    });
  }

  const acl = await fetchStatus(`${bucketRoot}/?acl`, { method: "GET" });
  if (!acl.error && success(acl.status)) {
    findings.push({
      key: `aliyun|acl_readable|${bucketRoot}`,
      vendor: "aliyun",
      vendorName: "阿里云OSS",
      vulnType: "ACL可读",
      level: "medium",
      bucketRoot,
      status: acl.status,
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
      key: `aliyun|put_upload|${bucketRoot}`,
      vendor: "aliyun",
      vendorName: "阿里云OSS",
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
    headers: { "x-oss-object-acl": "default" }
  });
  if (!aclWrite.error && success(aclWrite.status)) {
    findings.push({
      key: `aliyun|acl_writable|${bucketRoot}`,
      vendor: "aliyun",
      vendorName: "阿里云OSS",
      vulnType: "ACL可写",
      level: "high",
      bucketRoot,
      status: aclWrite.status,
      method: "PUT",
      path: "/?acl",
      timestamp: nowIso()
    });
  }

  const policyBody = JSON.stringify({
    Version: "1",
    Statement: [
      {
        Action: ["oss:PutObject", "oss:GetObject"],
        Effect: "Allow",
        Principal: ["1234567890"],
        Resource: ["acs:oss:*:*/*"]
      }
    ]
  });

  const policyWrite = await fetchStatus(`${bucketRoot}/?policy`, {
    method: "PUT",
    body: policyBody,
    headers: { "content-type": "application/json" }
  });

  if (!policyWrite.error && success(policyWrite.status)) {
    findings.push({
      key: `aliyun|policy_writable|${bucketRoot}`,
      vendor: "aliyun",
      vendorName: "阿里云OSS",
      vulnType: "Policy可写",
      level: "high",
      bucketRoot,
      status: policyWrite.status,
      method: "PUT",
      path: "/?policy",
      timestamp: nowIso()
    });
  }

  return findings;
}
