# 最新版源码的滥用风险优化

基于本目录 `Version = 2026-10-08 22:23:27` 的源码，修改日期：2026-10-09。

## 能解决什么

降低凭据泄露后被盗用、任意目标连接、扫描和邮件出站、重复拨号、公共中转依赖、未认证连接消耗资源等风险。代码修改不能保证 Cloudflare 不发起滥用报告，也不能解除已发生的账号暂停。

上游 [#1554](https://github.com/cmliu/edgetunnel/issues/1554) 报告 Workers 账号收到邮件，[#1568](https://github.com/cmliu/edgetunnel/issues/1568) 的讨论包含 Pages 和旧版用户的类似经历。它们是用户反馈，不证明平台的判定条件，不能据此认为更换版本、域名、Workers/Pages 或代码混淆就能规避处置。[Cloudflare 服务条款 §2.7](https://www.cloudflare.com/terms/) 禁止钓鱼、垃圾邮件及其他技术滥用；需要结合报告详情确认具体原因。

## 部署前必须迁移配置

默认必须设置 `ALLOWED_HOSTS`，否则 WebSocket、gRPC 和 xHTTP 请求返回 503。填写实际获授权使用的目标，示例仅展示格式：

```text
ALLOWED_HOSTS=api.example.com,*.example.org
ALLOWED_PORTS=80,443
```

`*.example.org` 只匹配子域，不匹配 `example.org` 本身。不支持任意位置的通配符或 CIDR。白名单可以包含公网 IP；IPv6 可以带方括号。不要用无必要的大范围白名单。

| 配置 | 行为 |
| --- | --- |
| `TUNNEL_ENABLED=false` | 停止接受新的隧道请求；已有连接需停用部署或等待生命周期结束 |
| `ALLOWED_HOSTS` | 默认必填，跨所有 TCP 协议统一检查 |
| `ALLOWED_PORTS` | 默认 80/443；25、465、587 始终拒绝 |
| `ALLOW_ANY_HOST=true` | 显式恢复任意公网目标，会显著放宽保护；不解除端口、私网和资源限制 |
| `TUNNEL_PATH` | 可选固定路径，如 `/private-tunnel`；设置后需同步更新客户端和后台生成的节点路径 |
| `PROXYIP` | 仅使用运营者显式配置的中转；不再自动选用内置公共服务 |
| `EGRESS_PROXY` | 可选运营者指定的链式代理，如 `socks5://user:password@proxy.example.com:1080`，走全局出站；建议作为 secret 保存 |
| `ALLOW_CLIENT_PROXY=true` | 显式允许客户端 URL 中转参数；默认忽略这些参数，`EGRESS_PROXY` 始终优先。保护措施仍检查最终 TCP 目标 |
| `ALLOW_DNS=true` | 显式启用原有仅 DNS 的转发到固定解析器 8.8.4.4；默认关闭。任意 Trojan UDP 中转始终禁止 |
| `MAX_TUNNEL_SECONDS` | 默认 300 秒，范围 10–600 秒；WS/gRPC 会话和物理 TCP 连接有时间上限 |
| `MAX_TUNNEL_MB` | 默认每请求出站 socket 上下行累计 64 MiB，范围 1–256 MiB；重试和握手也计入 |
| `ALLOW_WEB_PROXY=true` | 显式恢复首页反代；默认不向任意请求者提供反代。启用后移除 Cookie、Authorization 等敏感头 |
| `ALLOW_CLIENT_SUB=true` | 显式允许 `sub` 查询参数指定在线订阅源；默认只使用运营者配置的来源 |
| `ALLOW_TELEGRAM=true` | 显式允许配置中的 Telegram 通知；默认关闭。新日志去掉 URL 查询参数及不属于固定路由的路径 |

并发/预加载拨号固定关闭，忽略 `TCP_CONCURRENT_DIAL`、`PROXY_CONCURRENT_DIAL`、`PRELOAD_RACE_DIAL`。每请求最多 4 次物理 TCP 拨号，每个 TCP 转发最多尝试一次中转阶段、最多两个中转候选。失败后停止，不使用未授权公共兜底。

新连接限流的内存兜底为每来源 IP 每分钟 60 次、每 isolate 每分钟 180 次；登录尝试为每 IP 每分钟 10 次、每 isolate 每分钟 60 次。采用有界的分钟窗口计数，只信任 Cloudflare 注入的 `CF-Connecting-IP`，未提供时共享 `unknown` 计数桶。它不能作为全局配额或严格并发限制。

`wrangler.toml` 另加入了 `TUNNEL_RATE_LIMITER` 与 `LOGIN_RATE_LIMITER` 的可选平台 binding 配置。通过 Wrangler 部署时，两者会在内存兜底之外生效；只复制 JS 到控制台时需另外配置绑定。依据[官方文档](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)，平台计数按 Cloudflare 位置生效、最终一致；binding 失败时拒绝相关请求。Pages 若不支持该 binding，可删除对应 TOML 段并使用内存兜底配合边缘访问策略。

## 管理端和外部依赖的变化

- 每请求独立初始化配置和缓存，避免管理请求/并发隧道影响其他请求的配置、调试开关或代理设置。
- TCP 连接改为使用[官方 `cloudflare:sockets` 接口](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)，遵循平台出站限制，不再依赖 `request.fetcher.connect`。
- `/version` 改为验证完整 UUID。
- 管理写入要求同源 `Origin`；脚本调用应带 `Origin: https://你的域名`。`/admin/init` 改为 POST。
- `/admin/getCloudflareUsage` 拒绝 URL 中的 Cloudflare 凭据，改用 `CF_EMAIL`、`CF_GLOBAL_API_KEY`、`CF_ACCOUNT_ID`、`CF_API_TOKEN` 环境变量/secret。优先使用最小权限 API Token，具体权限按照实际查询需求设置。
- 在线后台页面仍来自上游静态站点，旧 UI 中的 GET 重置和 URL 凭据查询可能不再兼容；上述接口可按新方式调用。该修改没有重做远程后台页面。
- 外部 HTTP 请求统一要求 HTTPS 和公网目标；每请求最多 16 次，每次最多 10 秒，响应体最多 2 MiB，不跟随重定向。远程配置需填写最终 HTTPS 地址。
- 不再为测速目标返回本地伪造成功响应；相应目标由出站策略拒绝。
- xHTTP 首包最多 64 KiB、等待最多 10 秒。WS 未建立合法出站的等待上限 10 秒。gRPC 等待上限同样受控，待解析缓存和帧大小最多 1 MiB，拒绝压缩标志和非法长度。

原有订阅、管理登录和各协议认证机制仍保留。增强限制会让部分旧节点、在线订阅源和长连接失败；这属于资源保护和访问范围收紧，不能通过反复公共中转重试解决。

## 验证和剩余限制

运行：`npm run check`、`npm test`。测试使用 mock socket/平台对象，不会对外拨号或连接 Cloudflare。覆盖 VLESS WS/xHTTP/gRPC、Trojan TCP、Shadowsocks AEAD 的目标限制，以及地址归一化、私网地址、资源预算、客户端中转忽略、管理端保护和远程请求限制。

没有进行真实 Cloudflare 部署、带宽或生产负载测试。公网域名可能解析到变化的地址，本地检查不提供完整 DNS 重绑定防护；通过链式代理时尤其需要信任运营者指定的代理及白名单服务。白名单服务自身被滥用、白名单范围过大、凭据被共享、跨地区或跨 isolate 重连、已有静态页面供应链风险都不能单靠这些限制消除。

上游 TLSClient 仍含自定义 TLS 实现；需要高保证的链式代理证书验证时应单独审计，或避免使用相关模式。限制不是合规证明。出现新的滥用报告时，应停止相关服务、查明报告详情并联系 Cloudflare。

本次安全修改不包含 Cloudflare 部署。上传此目录的 Git 版本保留测试 CI，并将上游同步改为手动触发，以免定时合并改变安全限制。
