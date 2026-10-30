# Grok 批量注册工具

Web 控制台 + 注册引擎，支持临时邮箱、Turnstile 本地 Solver、Castle 同页 mint，以及 HTTP 导入 sub2api。

> 本项目在 [huslx/grokzhuce](https://github.com/huslx/grokzhuce) 基础上修改扩展，
> 核心协议路径（grpc-web 发码/验码、RSC sign-up、Turnstile、Castle mint）参照其实现；
> 改动与新增见文末「参考与致谢」。

## 功能

- 纯协议注册路径（REST `/api/auth/*` 发码/验码/建号；发码前用无头浏览器 mint Castle 并同步页面 cookie）
- 临时邮箱自动建邮 / 收码（[cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email)），未部署 Worker 时可用手动模式（`MANUAL_EMAIL`）
- **邮箱后缀多选**：建邮时 round-robin 轮换多个域名
- 本地 Camoufox Turnstile Solver（也可接 YesCaptcha）
- 多线程并发；主流程 / Risk·Token·NSFW 双栏日志
- 进度按 CLEAN 成功数计；创邮次数单独展示（数量 = 创邮次数停批）
- **独立「代理」页**：代理池、格式校验、测首条/测全部（出口 IP/地区 + accounts.x.ai）
- **熔断轮换**：risk MARKED/deny → 切下一条代理；连续切满 N 次仍 deny → 自定义冷却后继续
- **指纹按出口对齐**：探当前代理出口国家，locale/时区只在同国家簇内轮（防 IP↔指纹乱跳）
- 注册成功后页面「导入」入库 sub2api（HTTP Admin API / sso-to-oauth；`AUTO_IMPORT=1` 可开自动）
- 按**分组名称**自动解析 sub2api `group_id`（ID 只读缓存）

## 目录结构

```
.
├── app.py                      # Web 控制台（Flask）
├── grok.py                     # 注册引擎 + CLI
├── solver_manager.py           # Turnstile Solver 进程管理
├── api_solver.py               # 本地 Turnstile Solver
├── api_solver_p2.py            # Solver（页面持久化版，默认启动，端口 5074）
├── setup_solver.py             # 安装 Solver / camoufox 依赖
├── TurnstileSolver.bat         # Windows 一键启动 Solver
├── import_batch_once.py        # 从 keys 文本批量导入 sub2api
├── browser_configs.py
├── db_results.py
├── templates/index.html        # 控制台前端
├── g/                          # 邮箱 / Turnstile / Castle / 同会话 / 导入
├── .env.example
└── requirements.txt
```

本地运行产生、**不要提交**的内容：

- `.env`（真实密钥）
- `keys/`（SSO 输出）
- `logs/`（运行日志）
- `proxies/`（个人代理清单）

## 环境要求

- Python 3.10+
- Windows / Linux 均可（Camoufox Solver 在 Windows 上更常用）
- 已部署的 [cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email) Worker
- 可选：自建 sub2api 用于账号入库

## 安装

```bash
pip install -r requirements.txt
# 首次使用本地 Turnstile Solver
python setup_solver.py
```

## 配置

```bash
cp .env.example .env
```

编辑 `.env`（**切勿提交真实密钥 / 代理账号 / 个人域名**）：

| 配置项 | 说明 | 默认 |
|--------|------|------|
| `WORKER_DOMAIN` | cloudflare_temp_email 的 Worker 域名（不要 `https://`） | — |
| `FREEMAIL_TOKEN` | 站点密码 / JWT | — |
| `FREEMAIL_DOMAIN` | 邮箱后缀：`auto` / 单域名 / 多域名逗号分隔（轮换） | `auto` |
| `FREEMAIL_API_STYLE` | `auto` / `cf_temp` / `freemail` | `auto` |
| `YESCAPTCHA_KEY` | 有则走 YesCaptcha；空则本地 Solver | 空 |
| `SOLVER_URL` | 本地 Solver 地址 | `http://127.0.0.1:5074` |
| `SOLVER_BROWSER` | `camoufox` / `chromium` | `camoufox` |
| `SOLVER_THREADS` | Solver 浏览器线程 | `4` |
| `GROK_CASTLE_MINT` | `1`=开浏览器 Castle mint；默认关闭 | `0` |
| `MANUAL_EMAIL` | 手动模式邮箱（跳过 Worker 建邮/删邮） | 空 |
| `MANUAL_CODE` | 手动模式验证码（只消费一次）；不设则轮询 `logs/manual_code.txt` | 空 |
| `UI_HOST` / `UI_PORT` | Web 监听 | `127.0.0.1` / `3333` |
| `GROK_PROXY` | 单条注册代理；空=直连 | 空 |
| `GROK_PROXY_LIST` | 代理池（分号/换行分隔，优先于单条） | 空 |
| `GROK_SS_DENY_BREAK` | 单出口连续 MARKED 停批阈值；`0`=关 | `3` |
| `GROK_SS_PROXY_SWITCH_LIMIT` | deny 后连续切代理次数上限，触顶进冷却；`0`=不切 | `3` |
| `GROK_SS_COOLDOWN_SEC` | 切代理触顶后的冷却秒数 | `60` |
| `GROK_SS_FP_ALIGN` | `1`=指纹按出口国家簇锁定（推荐）；`0`=全球轮（仅调试） | `1` |
| `SUB2API_URL` | sub2api 根地址 | `http://127.0.0.1:9898` |
| `SUB2API_GROK_GROUP_NAME` | 导入目标分组**名称**（按名称解析 ID） | `grok` |
| `SUB2API_GROK_GROUP_ID` | 可选缓存；运行时会按名称回写 | 空 |
| `UPSTREAM_ADMIN_EMAIL` | sub2api 管理员邮箱 | — |
| `UPSTREAM_ADMIN_PASSWORD` | sub2api 管理员密码 | — |

### 代理格式

支持：

- `host:port`
- `http://host:port` / `socks5://host:port`
- `user:pass@host:port`
- `host:port:user:pass`

池子可写多行或用 `;` 分隔。控制台「代理」页可校验格式、测出口与 x.ai 连通。

### 熔断逻辑（same_session）

```
risk MARKED / deny
  ├─ 多代理且允许切代理 → 立刻切下一条
  ├─ 连续切满 N 次仍 deny → 冷却 X 秒 → 到点继续
  └─ 单代理 / 直连 / 切代理关闭 → 连续 deny 达阈值 → 停批
CLEAN 成功 → 清零连续 deny 与切代理计数
```

### 指纹与出口

- 启动/切代理后探测当前出口 IP 与国家码
- locale / timezone 只在**同国家簇**内轮换（可轮 OS、分辨率、时序）
- 探测失败时尝试从代理串 `region-XX` 猜测；再不行才全球轮
- 可手填 `STANDALONE_EGRESS_CC` / `STANDALONE_EGRESS_TZ` 跳过探测

说明：

- 页面「配置」：邮箱 / Solver / sub2api；**代理与熔断只在「代理」页保存**，避免空池误清空。
- 分组只填**名称**；ID 只读显示，保存/测试/导入时自动拉取。
- 导入主路径：`POST /api/v1/admin/grok/sso-to-oauth`（服务端换票）。
- 需要自动入库时在 `.env` 设 `AUTO_IMPORT=1`。
- Token 换票 / 协议 / NSFW 在成功后异步后台跑，不堵注册主路径。

## 使用

### 1. 启动 Solver（本地模式）

```bash
python solver_manager.py start
python solver_manager.py status
```

或双击 `TurnstileSolver.bat`。Web 控制台也可一键启动。

### 2. Web 控制台（推荐）

```bash
python app.py
```

打开：`http://127.0.0.1:3333`

- **配置**：Worker / Token / 邮箱后缀（可多选）/ Solver / sub2api / 分组名称 → 写入 `.env`
- **代理**：代理池、格式校验、连通测试、熔断三参数
- **运行**：选择 `same_session`、并发、数量后开始
- **日志**：左侧主流程（建邮→camoufox→signup→SSO），右侧 Risk / Token / NSFW
- **Keys**：下载 SSO 文件，一键导入 sub2api

same_session 建议并发先 **1～2**（注册浏览器 + Solver 双开）。进度条旁可看当前代理 / 冷却状态。

### 3. 命令行

```bash
python grok.py
```

成功账号写入 `keys/`。

### 4. 批量导入已有 SSO 文件

```bash
python import_batch_once.py keys/your_sso.txt
```

## 注册路径

| 模式 | 说明 |
|------|------|
| `protocol`（默认） | 协议主路径：`POST /api/auth/send-verification-code` 发码 → `/api/auth/sign-up/verify-email` 验码 → `/api/auth/sign-up/create-account` 建号；发码前用无头浏览器 mint Castle，并把页面 cookie 同步进 HTTP 会话 |
| `same_session` | 同页交互注册（页内 castle mint + 页内 fetch），需浏览器；发码/验码已同步新 REST 接口 |

`GROK_REGISTER_MODE` 环境变量可覆盖默认路径。

### 2026-10 x.ai 接口迁移（本次修复要点）

x.ai 把认证接口从 grpc-web/RSC 迁到了 REST JSON，**旧端点仍然返回成功但不再真正发信**，
所以表现为「日志说已发码、邮箱却永远收不到」：

| 动作 | 旧（已失效） | 新（当前使用） |
|------|--------------|----------------|
| 发码 | `POST /auth_mgmt.AuthManagement/CreateEmailValidationCode`（grpc-web） | `POST /api/auth/send-verification-code` `{email, castleRequestToken}` |
| 验码 | `POST /auth_mgmt.AuthManagement/VerifyEmailValidationCode` | `POST /api/auth/sign-up/verify-email` `{email, code}` |
| 建号 | RSC `POST /sign-up`（next-action） | `POST /api/auth/sign-up/create-account` `{email, password, givenName, familyName, emailValidationCode, turnstileToken, marketingEmailOptIn, castleRequestToken}` |

新发码接口要求 **Castle token 与页面会话 cookie 成对出现**（`gb_anon_id` / `xai_anon_id` /
`cf_clearance` / `__cf_bm` …），单独带 Castle 不带 cookie 会被判 `account:email-signup-unavailable`
并静默丢信。因此协议模式现在每号会先起一次无头浏览器：

```
无头 Chrome（带同一代理，UA 覆盖）→ 打开 /sign-up → 页内 CastleProvider mint
  → 导出 cookies + UA → 灌进 curl_cffi 会话 → REST 发码/验码/建号
```

相关开关：

| 配置项 | 说明 | 默认 |
|--------|------|------|
| `GROK_SEND_CODE_CASTLE` | `1`=发码前用浏览器 mint Castle（必需）；`0`=关（回到旧 grpc，会收不到信） | `1` |
| `GROK_SIGNUP_CASTLE_REFRESH` | `1`=建号前重新 mint Castle（会换会话 cookie，一般不需要） | `0` |
| `GROK_CASTLE_HEADLESS` | `1`=无头浏览器；`0`=有界面（排障用） | `1` |
| `GROK_CASTLE_MIN_LEN` | Castle token 最短长度（太短服务端判 invalid_token） | `4000` |
| `TS_POLL_INTERVAL` | Turnstile 轮询间隔；窗口默认 ≈67s（旧 23s 会把 30~55s 的 Solver 误判超时） | `0.28` |

排障命令：`python grok.py` 选 `protocol`、并发 1、数量 1，日志里应依次出现
`Castle OK … / 已请求邮箱验证码 / 邮箱验证码: xxx-xxx / 已通过 / Turnstile 成功 / 已拿到 SSO`。

## 手动模式（不依赖邮箱 Worker）

未部署 cloudflare_temp_email Worker 时仍可注册：

```bash
set MANUAL_EMAIL=your_temp@example.com
python grok.py          # 路径选 protocol、并发 1、数量 1
```

发码后把收到的验证码写入 `logs\manual_code.txt`（或重跑时设 `MANUAL_CODE`），脚本读到即继续；
等待时长用 `MANUAL_CODE_TIMEOUT`（默认 600s）控制。手动模式下不会调用 Worker 建邮/删邮。

## 注意事项

- 仅供学习与自用自动化，请遵守目标站点与服务条款。
- 仓库不包含真实 `.env`、代理账号、邮箱密码、keys/logs。
- 推送前请确认工作区无个人域名、代理凭证与内网地址。
- 示例配置一律用占位符（`your-worker.workers.dev`、`admin@example.com` 等）。

## 参考与致谢

- [huslx/grokzhuce](https://github.com/huslx/grokzhuce) —— 本项目的主体代码与实现思路源自该仓库（协议还原、Turnstile Solver、注册引擎、Web 控制台）；本仓库在其基础上改动：
  - 注册路径默认改为 `protocol`；2026-10 起跟进 x.ai 的 REST 认证接口（发码/验码/建号）并补上 Castle + 页面 cookie 的同会话要求
  - 新增手动模式（`MANUAL_EMAIL` / `MANUAL_CODE` / `logs\manual_code.txt`），无需邮箱 Worker
  - 本地 Turnstile Solver 默认 `127.0.0.1:5074`，使用页面持久化版 `api_solver_p2.py`
- [dreamhunter2333/cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email) —— 临时邮箱 Worker
- 仅供学习参考，请勿用于违反服务条款的用途。
