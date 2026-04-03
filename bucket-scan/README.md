# bucket-scan

轻量级浏览器扩展（Chrome/Edge，Manifest V3），用于**授权安全测试**场景下识别对象存储配置风险与前端资产泄露线索。

支持厂商：
- 阿里云 OSS
- 腾讯云 COS
- 华为云 OBS
- AWS S3
- Microsoft Azure Blob Storage
- Google Cloud Storage (GCS)

>仅用于授权测试、资产自查与教学研究。

## 功能概览

###1) 自动检测（被动 + 可选主动）
- 基于响应头/域名后缀识别对象存储目标
- 自动执行漏洞检查
- 可选主动写检测（PUT/ACL/Policy，默认关闭）

###2) JS 敏感信息提取
- 提取静态/动态加载 JS 中的对象存储 URL
- 支持 SourceMap 暴露检测（可下载）

###3)结果页能力
- 漏洞结果搜索与等级筛选
- 漏洞 URL 一键跳转
- 响应长度展示
- JSON 导出

###4) 黑白名单规则
- 白名单/黑名单域名都支持一行一条
- 支持通配：`*.qq.com`
- 命中即跳过检测

###5) OSS 批量遍历查看
- 手动输入 bucket 根地址进行批量对象浏览
-仅遍历类型：**图片 / pdf / doc / docx / txt**
- 单次最多返回 **10** 个对象
- 支持单条打开与批量打开（同样受类型与数量限制）

## 当前可识别风险

- 存储桶可遍历
- ACL 可读
- PUT 文件上传（主动）
- ACL 可写（主动）
- Policy 可写（阿里云，主动）
- SourceMap 文件可下载
- JS 泄露对象存储地址

## 安装（开发者模式）

1. 打开扩展管理页
 - Chrome: `chrome://extensions/`
 - Edge: `edge://extensions/`
2. 开启「开发者模式」
3. 点击「加载已解压的扩展程序」
4.选择项目目录：`bucket-scan/`

## 使用

1. 打开扩展 Popup，确认「被动检测」开启。
2. 浏览目标站点，插件自动采集并检测。
3. 点击「全部结果」查看漏洞详情。
4. 点击「批量遍历」进入 bucket 批量对象查看页面。
5. 如需主动写检测，请在 Popup/Options 中手动开启（有二次确认）。

##主要配置项

- `enablePassive`：被动检测开关
- `enableActiveWriteChecks`：主动写检测开关
- `enableJsIntel`：JS 情报提取开关
- `enableSourceMapCheck`：SourceMap 检测开关
- `scanTimeoutMs`：请求超时（ms）
- `maxConcurrency`：并发数
- `cooldownMs`：重复扫描冷却（ms）
- `whitelistHosts`：白名单域名（不检测）
- `blacklistHosts`：黑名单域名（不检测）

##目录结构

```text
bucket-scan/
├─ manifest.json
├─ jenn.png
└─ src/
 ├─ background/service-worker.js
 ├─ scanner/
 │ ├─ core.js
 │ ├─ detectVendor.js
 │ ├─ jsIntel.js
 │ ├─ batchTraversal.js
 │ └─ vendors/{aliyun,tencent,huawei}.js
 ├─ storage/state.js
 └─ ui/
 ├─ popup.*
 ├─ results.*
 ├─ options.*
 └─ batch.*
```

## 安全与合规

- 本工具不提供绕过认证、破坏性攻击或隐蔽投递能力。
- 主动写检测会真实发起写请求，可能影响目标资源状态。
- 使用前请确保你已获得目标系统的明确授权。

---

author: jenn02
