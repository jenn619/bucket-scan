# bucket-scan

轻量级浏览器扩展（Chrome/Edge, Manifest V3），用于在授权测试场景下识别对象存储桶配置风险（阿里云 OSS / 腾讯云 COS / 华为云 OBS）。

## 项目定位

`bucket-scan`通过监听浏览器响应头识别疑似对象存储目标，并自动执行安全检测，帮助你快速发现常见桶配置问题。

>仅用于授权安全测试、漏洞自查与教学研究场景。

## 当前功能

- 被动检测（默认开启）
 -通过响应头和域名后缀识别云厂商目标
 - 自动触发桶探测任务
- 主动写检测（可选，默认关闭）
 - 支持 PUT 上传探测
 - 支持 ACL 写权限探测
 - 阿里云额外支持 Policy 写探测
-结果展示
 - Popup 最近发现（高危/中危统计）
 - 独立 Results 页面（搜索、等级筛选）
 - 支持导出 JSON 报告
- 设置页面
 - 被动检测开关
 - 主动写检测开关（含二次确认）
 - 超时、并发、冷却时间可配置
- UI 定制
 - 扩展 Logo 使用 `jenn.png`
 - 页面内带 `author: jenn02` 水印

## 已检测风险类型（当前版本）

- 存储桶可遍历
- ACL 可读
- PUT 文件上传（主动）
- ACL 可写（主动）
- Policy 可写（仅阿里云，主动）

## 技术栈与结构

- Manifest V3
- Background Service Worker 调度
- `chrome.webRequest`采集响应头
- `chrome.storage.local` 持久化

```text
bucket-scan/
├─ manifest.json
├─ jenn.png
└─ src/
 ├─ background/service-worker.js
 ├─ scanner/
 │ ├─ core.js
 │ ├─ detectVendor.js
 │ └─ vendors/{aliyun,tencent,huawei}.js
 ├─ storage/state.js
 └─ ui/
 ├─ popup.*
 ├─ results.*
 └─ options.*
```

## 安装方式（开发者模式）

1. 打开 Chrome/Edge 扩展管理页
 - Chrome: `chrome://extensions/`
 - Edge: `edge://extensions/`
2. 开启「开发者模式」
3. 点击「加载已解压的扩展程序」
4.选择本项目目录：`bucket-scan/`

## 使用说明

1. 安装后打开扩展 Popup，确认「被动检测」开启。
2. 浏览目标站点，扩展会自动识别疑似桶目标并检测。
3. 在 Popup 查看最近发现，或点击「全部结果」进入结果页。
4. 如需主动写检测，在 Popup/Options 中开启（会弹窗确认）。
5. 在 Results 页导出 JSON 报告用于留档。

## 配置项说明

- `enablePassive`：是否启用被动检测
- `enableActiveWriteChecks`：是否启用主动写检测（高风险）
- `scanTimeoutMs`：单请求超时时间（毫秒）
- `maxConcurrency`：最大并发扫描数
- `cooldownMs`：同目标重复扫描冷却时间（毫秒）

## 安全与合规声明

- 本工具不会绕过认证，不包含破坏性攻击链路。
- 主动写检测会真实发起 PUT/ACL/Policy 请求，可能影响目标资源状态。
- 使用前请确保你对目标拥有明确书面授权。

##版本信息

- 当前版本：`0.1.0`

##计划中能力（Roadmap）

- 白名单 host 跳过检测
- 存储桶接管（Takeover）识别增强
- CSV 导出报告
-置信度与证据链展示优化

---

如果你在使用中遇到问题，欢迎提 Issue 或提交 PR。
