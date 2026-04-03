function success(code) {
 return code <=299;
}

function includesAll(text, markers) {
 return markers.every((m) => text.includes(m));
}

export async function runTencentChecks(ctx) {
 const findings = [];
 const { bucketRoot, settings, fetchText, fetchStatus, nowIso } = ctx;

 const root = await fetchText(bucketRoot, { method: "GET" });
 if (!root.error && success(root.status) && includesAll(root.text, ["<ListBucketResult>", "<Name>"])) {
 findings.push({
 key: `tencent|bucket_traversable|${bucketRoot}`,
 vendor: "tencent",
 vendorName: "腾讯云COS",
 vulnType: "存储桶可遍历",
 level: "medium",
 bucketRoot,
 status: root.status,
 method: "GET",
 path: "/",
 targetUrl: bucketRoot,
 responseLength: root.contentLength,
 timestamp: nowIso()
 });
 }

 const aclReadable = await fetchText(`${bucketRoot}/?acl`, { method: "GET" });
 if (!aclReadable.error && aclReadable.text.includes("<Permission>")) {
 findings.push({
 key: `tencent|acl_readable|${bucketRoot}`,
 vendor: "tencent",
 vendorName: "腾讯云COS",
 vulnType: "ACL可读",
 level: "medium",
 bucketRoot,
 status: aclReadable.status,
 method: "GET",
 path: "/?acl",
 targetUrl: `${bucketRoot}/?acl`,
 responseLength: aclReadable.contentLength,
 timestamp: nowIso()
 });
 }

 if (!settings.enableActiveWriteChecks) return findings;

 const fileName = `bucket-scan-test-${Date.now()}.txt`;
 const uploadPath = `/${fileName}`;
 const upload = await fetchStatus(`${bucketRoot}${uploadPath}`, {
 method: "PUT",
 body: "bucket-scan upload probe"
 });
 if (!upload.error && success(upload.status)) {
 findings.push({
 key: `tencent|put_upload|${bucketRoot}`,
 vendor: "tencent",
 vendorName: "腾讯云COS",
 vulnType: "PUT文件上传",
 level: "high",
 bucketRoot,
 status: upload.status,
 method: "PUT",
 path: uploadPath,
 targetUrl: `${bucketRoot}${uploadPath}`,
 responseLength: upload.contentLength,
 timestamp: nowIso()
 });
 }

 const aclWritable = await fetchStatus(`${bucketRoot}/?acl`, {
 method: "PUT",
 headers: { "x-cos-acl": "public-read-write" }
 });
 if (!aclWritable.error && success(aclWritable.status)) {
 findings.push({
 key: `tencent|acl_writable|${bucketRoot}`,
 vendor: "tencent",
 vendorName: "腾讯云COS",
 vulnType: "ACL可写",
 level: "high",
 bucketRoot,
 status: aclWritable.status,
 method: "PUT",
 path: "/?acl",
 targetUrl: `${bucketRoot}/?acl`,
 responseLength: aclWritable.contentLength,
 timestamp: nowIso()
 });
 }

 return findings;
}
