# EC2 Pilot · EC2 轻量面板

本机 / Docker 自托管的中文面板。直接调用 AWS 官方 API，不依赖 aws.sb，也不会调用 `account:GetContactInformation`。适用于保留新版 AWS 免费项目的资源管理；AWS 的 SCP、区域、配额和免费计划限制仍然生效。

## 已实现

- 多账号添加：通过 STS 验证 AK/SK，可选 Session Token，新账号区域默认美国东部（弗吉尼亚北部）`us-east-1`，已有账号保留原区域。
- EC2 实例列表、创建、开机、停机、重启、操作记录；创建请求带幂等标识。
- ARM 实例：机型下拉菜单按 ARM64 / x86_64 分组，直接提供 `t4g.micro`、`t4g.small`，其他机型可选择“其他机型（手动输入）”；按架构筛选 Amazon Linux 2023 镜像，并在创建前校验 AMI 与实例类型的架构是否匹配。
- 新建实例默认新建专用安全组，放行 IPv4 / IPv6 任意来源的所有入站协议和端口；可取消“全部开放”并选择已有安全组。
- 脚本模板和 User Data：新实例启动时提交脚本；已停止实例可以修改 User Data。
- 更换 IP：为主网卡分配并绑定新 Elastic IP，可选释放之前的 EIP。
- TCPing：真实 TCP 连接采样，展示成功次数、平均延迟、连接失败率和历史。
- Cron 定期检测：标准五段表达式与 IANA 时区，默认 `*/5 * * * *`、`Asia/Shanghai`；兼容旧秒数间隔任务。SQLite 持久化，关闭网页不影响执行，每轮重新读取当前公网 IP。
- 自动更换 IP：连续失败达到阈值后复检，满足条件才分配 / 绑定新 EIP，再检测新 IP。支持本机 TCP 失败或双探针疑似过滤两种触发条件，按定时任务执行，无额外冷却或每日次数限制；结果不确定时暂停。
- GFW 对照：预留并实现国内/境外 HTTPS 探针协议。没有有效双探针时明确显示“证据不足”。
- 管理员密码、HttpOnly 会话、跨站来源校验、密钥加密保存、输入校验、探测并发限制。

## 本机启动

安装 Python 3.11 或更新版本。

Windows：双击 `start.bat`。Linux / macOS：运行 `bash start.sh`。首次会安装依赖。

浏览器打开 <http://127.0.0.1:8080>，设置至少 12 个字符的面板密码。此密码仅用于面板，不是 AWS 密码。添加账号时填入你的 Access Key ID、Secret Access Key 和区域。

如需手动启动：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
```

首次设置只允许本机连接。若通过局域网 / 代理 / Docker 访问，请在启动前设置 `PANEL_ADMIN_PASSWORD`。它只在数据库还没有管理员时生效。不要将服务直接无保护地暴露到公网。

## Docker

```bash
cp .env.example .env
# 用编辑器在 .env 中填写 PANEL_ADMIN_PASSWORD，至少 12 字符。
docker compose up -d --build
```

访问 <http://127.0.0.1:8080>，使用 `.env` 中的面板密码登录。默认仅绑定本机端口。容器重启会保留命名卷中的数据库与加密密钥，定期检测会恢复。

```bash
docker compose logs -f
docker compose down
```

`docker compose down` 保留数据；不要加 `-v`，除非确实要删除账号配置、脚本和检测记录。单进程运行，保持 `--workers 1`。

需要远程访问时，配置 HTTPS 反向代理、访问控制，并设置 `PANEL_SECURE_COOKIE=1`、`PANEL_ALLOWED_HOSTS=localhost,127.0.0.1,panel.example.com`（换成实际域名，不含协议或端口）。默认仅接受本机 Host，防止 DNS 重绑定。不要把浏览器端静态文件单独托管后期望 TCP 检测运行：检测需要 Python 后端。

## 推荐使用顺序

1. 添加 AWS 账号，只验证 STS 身份，不查询联系人，也不会升级套餐。
2. 在 EC2 页点击刷新。管理已有实例时选中相应操作；开新机器时选择 AMI、子网及密钥对，安全组默认全部开放，也可取消勾选后填写已有安全组。
3. 在脚本库保存你的脚本；新建 EC2 时选择模板。默认 Nginx 示例适合 Amazon Linux 2023。
4. 创建监控：选择账号和实例、TCP 端口、Cron 表达式、时区与超时；点击立即检测验证。需要定时换 IP 时勾选“自动更换 IP”，设置触发条件和连续失败阈值后保存。

在面板创建表单中先选择实例类型，再选择镜像。机型菜单始终展示预设选项，不会因默认选择 T3 而隐藏 T4g。创建 T4g 实例时使用 `arm64` 镜像，T2 / T3 使用 `x86_64` 镜像。镜像建议分别保留两种架构最新的最多 5 个 Amazon Linux 2023 AMI；切换机型后会清空已知不兼容的 AMI，手填的其他 AMI 会由后端查询 AWS 后校验。初始化脚本中下载的程序也须适配所选架构。机型名称与架构参见 [AWS T4g 官方说明](https://aws.amazon.com/ec2/instance-types/t4/)。

若使用本项目早期 IAM 示例，创建实例现在还需 `ec2:DescribeInstanceTypes` 读取权限；自动创建安全组还需 `ec2:DescribeVpcs`、`ec2:CreateSecurityGroup`、`ec2:AuthorizeSecurityGroupIngress`，以及创建安全组时的 `ec2:CreateTags` 权限。更新后的 IAM 示例默认限制在 `us-east-1`；管理其他区域时请按实际区域调整 `aws:RequestedRegion`。更改默认区域不会迁移已有资源，Cron 时区仍独立配置。

启动新实例使用现有子网的公网 IP 分配设置。默认“全部开放”会在所选子网的 VPC（未填子网时为默认 VPC）内新建专用安全组，允许 `0.0.0.0/0` 与 `::/0` 访问所有入站协议和端口，保留 AWS 默认出站规则；这意味着任意公网来源均可尝试连接实例。取消勾选后使用指定安全组，未指定时使用 AWS 默认安全组。已有安全组不会被修改。

同一创建请求重试会复用专用安全组；实例创建失败后该组保留，便于用相同幂等标识重试，确认不再使用后可从 AWS 删除。面板不创建 VPC/子网/SSH 密钥对；没有默认 VPC 时需选择已有子网。公网直连仍需正确的子网路由、公网 IP 与服务器监听服务。创建规格、EBS、公网 IPv4 和流量可能消耗赠金；请以 AWS 实际计费规则为准。

新实例根磁盘使用加密 gp3。默认按 AWS 账户的 EBS 加密密钥设置创建；如果账户默认使用自定义 KMS 密钥，或镜像快照由自定义密钥加密，还需相应密钥授权。附带 IAM 示例没有授予 KMS 权限，请为实际密钥单独配置，避免使用无限制的 `kms:*`。

## 启动脚本的执行时机

`User Data` 不等同于“每次点击开机都会执行”。多数 Linux 镜像的 cloud-init 默认仅首次启动执行。修改既有实例的 User Data 要先停机，之后是否执行由镜像配置决定。

若希望每次开机执行，可在首次启动脚本中创建并启用 systemd 服务；内置“每次启动”模板演示此方式。脚本以实例内的系统权限执行，请审阅后提交。UTF-8 内容最大 16 KiB。

## 换 IP 的行为

实例列表只查询 `DescribeInstances`，不额外查询弹性 IP。这个接口的[网卡关联响应](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceNetworkInterfaceAssociation.html)不含 `AllocationId`：有公网 IP 但缺少已确认的分配 ID 时，界面显示“公网 IPv4（类型未识别）”；没有公网 IP 时显示“无公网 IPv4”。不要依据未知类型判断停止实例后是否换地址，或是否还会产生 IPv4 费用。

换 IP 窗口中的“未查询”不代表没有旧 EIP。是否存在旧 EIP，以及能否释放，均由后端执行时重新查询并核实；默认保留旧 EIP，只有勾选释放才会在符合条件时释放。

1. 查明实例主网卡和主私网地址，按所在 Network Border Group 分配新 EIP。
2. 将新 EIP 关联到主网卡。连接会中断，已有 SSH 会话和 DNS 记录需要更新。
3. 默认保留旧 EIP；只有显式勾选释放，且重新检查确认旧地址未再关联任何资源后，才释放旧 EIP。

新旧公网 IPv4 都可能计费。AWS 请求超时或返回结果不确定时不会盲目重试或释放可能已经关联的地址；错误消息会提示先到 AWS 核对。

## Cron 定时检测与自动换 IP

在“网络监测 → 添加 / 编辑检测任务”中选择 Cron。表达式顺序是 **分 时 日 月 星期**，星期 `0` 或 `7` 表示周日；同时指定日与星期时按传统 Cron 的 OR 逻辑匹配。默认时区为 `Asia/Shanghai`。

| Cron | 执行时间 |
|---|---|
| `*/5 * * * *` | 每 5 分钟 |
| `*/10 * * * *` | 每 10 分钟 |
| `0 * * * *` | 每小时整点 |
| `0 9 * * 1-5` | 工作日 09:00 |

默认由常驻后端解释 Cron 表达式，每 5 秒检查到期任务，适用于 Windows、本机和 Docker。关闭网页继续运行；关闭后端、电脑休眠时不会执行。重新启动后到期任务补执行一次，再计算下一次 Cron 时间，不批量重放遗漏的检测。任务执行较久时不会重叠，完成后调度下一个未来时间。

自动更换默认要求连续 **3 轮**失败，可在任务中修改。Cron 时间、连续失败阈值和操作前复检共同决定是否更换；没有额外冷却时间，也没有每日或滚动 24 小时次数上限。后续定时检测再次满足条件，即可再次更换。

“复检未触发换 IP”表示操作前复检未满足更换条件，可能是连接恢复、IP 已变化或证据不足（包括临时查询 / 检测错误），并不保证连接已经恢复。这些情况继续采用原有保守策略：清空连续失败计数，本轮不分配 EIP。

1. **TCP 失败触发**：适合目前没有远程探针的情况。每轮所有 TCP 样本均失败才累计；这只表示网络检测失败，不声称确认 GFW。明确的本地权限 / 网络错误、无公网 IP、实例未运行或检测异常不会累计。
2. **双探针疑似过滤触发**：需要有效国内与境外对照，国内失败且境外成功；探针服务连接失败不算目标被屏蔽。
3. 连续失败计数针对同一公网 IP；恢复、异常、IP 改变或修改任务配置会清零。达到阈值后重新读取实例状态和 IP，并复检一次，仍满足条件才更换。
4. 提交前持久记录一次更换尝试，再调用 AWS；操作记录跨程序重启保留。同一真实 AWS 账号、区域及实例共用资源锁，避免账号别名或多个任务同时操作同一实例。
5. 绑定新 IP 后复测新地址并记录结果；复测失败不会立即递归更换，等待后续 Cron 检测重新达到连续失败阈值并通过复检。租约续期及资源锁避免重复操作。
6. AWS 错误、超时或上次进程中断导致结果未确认时，检测继续，自动更换暂停。核对 AWS 实例及 EIP 后，点击“核对后解除暂停”；此操作清零连续失败计数。刚中断的未确认操作需等待 15 分钟后才可解除，这是判断原操作是否仍在运行的保护期，不是每次更换后的冷却时间。

升级时自动移除已有任务保存的冷却时间和每日次数设置，历史操作记录仍然保留。已有任务继续按自己的 Cron 表达式或秒数间隔调度。

“立即检测”仅检测，不累计自动更换阈值、不换 IP。自动更换需要在任务中显式开启，升级不会替你启用已有任务。默认保留旧 EIP；勾选释放旧 EIP 才会在确认未绑定其他资源后释放，防止闲置地址持续积累。停用或删除任务会取消尚未提交的后续操作；已经提交给 AWS 的操作会完成。

### 可选：使用 Linux 系统 crontab

已附 `deploy/panel.crontab` 和单次工作器 `python -m app.cron_worker --once`。它们与页面后端使用同一执行流程、数据库租约和连续失败判断。

先按本机启动步骤安装依赖，并至少启动一次面板生成数据目录。以运行面板的同一个系统用户操作：

1. 将 Web 进程环境设为 `PANEL_SCHEDULER=external`，重启 Web 服务，让系统 cron 负责调度。
2. 修改 `deploy/panel.crontab` 中的 `/opt/ec2-panel` 为实际项目目录，然后用 `crontab -e` 加入其中的任务行（保留已有任务）。`flock` 防止上次工作器尚未完成时重复启动。
3. 若 Web 服务设置了 `PANEL_DATA_DIR` 或 `PANEL_ENCRYPTION_KEY`，cron 环境必须使用完全相同的值。不要把 AWS AK/SK 写入 crontab。

系统 cron 每分钟唤醒一次工作器；工作器按每个任务保存的表达式和时区领取到期任务。Windows / Docker 默认保持 `PANEL_SCHEDULER=internal` 即可，无需额外安装 cron。系统 cron 日志写入示例的 `data/cron.log`，需由部署者配置日志轮转。

## TCP 与 GFW 检测

这里的 TCPing 用 Python socket 建立真实 TCP 连接，与命令行 tcpping 的核心检测方式相同，不依赖额外二进制。延迟是 TCP 建连耗时，失败率是 TCP 样本失败比例，不是 ICMP 丢包率。

本机探测只能说明“后端所在网络到目标端口”的连通性。连接失败可能来自安全组、NACL、未监听端口、服务故障、路由或网络过滤，不能单独证明 GFW 屏蔽。

双探针结果解释：

| 观测 | 状态 |
|---|---|
| 缺少有效国内或境外结果 | 证据不足 |
| 国内失败、境外成功 | 疑似路径过滤，仍需排查其他原因 |
| 国内和境外均成功 | 双向可达 |
| 国内和境外均失败 | 双向不可达，无法据此认定 GFW |

探针地区是管理员配置的标签，程序不会推断实际地理位置。检测目标只从所选 AWS 账号的 EC2 实例获取，并限制为公网 IPv4。当前没有外部探针也能运行本机 TCP 检测。

## 可选：部署双探针

在你拥有的国内和境外服务器各放一份项目并安装依赖。分别设置随机、不同、至少 24 字符的 `PROBE_TOKEN`：

```bash
export PROBE_TOKEN='replace-with-your-own-long-random-token'
.venv/bin/python -m uvicorn app.probe_agent:app --host 127.0.0.1 --port 8091 --workers 1
```

用带有效 TLS 证书的反向代理将它暴露为 `https://probe.example.com/probe`。面板“探针设置”中填完整 `/probe` 地址、地区和对应 token。建议进一步在反向代理上只允许面板后端来源 IP。不要放到公开的无认证 TCP 探测服务上。

协议：`POST /probe`，`Authorization: Bearer <token>`，JSON 包含 `target_ip`、`port`、`timeout_seconds`（1–10）、`samples`（1–5）。探针有认证和 4 路并发限制，拒绝私网/回环/链路本地地址。远程调用强制 HTTPS、验证证书、拒绝重定向并固定经检查的 DNS 地址。

## 数据与权限

默认数据目录 `data/`；可通过 `PANEL_DATA_DIR` 指定。AK/SK 与探针 token 使用 Fernet 加密，密钥位于 `vault.key`（或由 `PANEL_ENCRYPTION_KEY` 提供）。备份时必须同时保存数据库与密钥。取得这两个文件的人仍可解密，所以主机文件访问权限也要保护好。

API 不返回原始 AK/SK，浏览器不将它们保存到 localStorage。操作日志不包含密码、密钥或脚本内容。检测保留最近 5,000 条，操作记录保留最近 2,000 条。

无需 `AdministratorAccess` 或 Organizations 权限。可参考 `iam-policy.example.json`：它只包含本面板使用的 EC2/STS 操作，但为了演示可移植性使用 Resource `*`，正式使用应进一步限制区域、实例和标签。AWS 的显式拒绝仍然优先。

## 演示、测试与来源

`http://127.0.0.1:8080/?demo=1` 为明确标识的只读演示，不发送 AWS 写入请求。正常入口默认为真实模式、空账号列表。

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

IP 类型与释放选项的浏览器回归检查（使用模拟 API，不连接 AWS）：

```bash
.venv/bin/python -m playwright install chromium
.venv/bin/python tests/browser_ip_labels.py
```

自动化测试用 Stubber / 假 AWS 客户端验证参数、状态、失败清理、加密、认证、动态 IP、后台调度和探针行为，不创建真实 EC2、不分配真实 EIP。真实 AWS 操作需你在面板中添加自己的密钥后验证。

本次交付验证（2026-10-13）：239 项 Python 测试全部通过（包含 Cron、自动换 IP、取消冷却和次数上限、旧配置迁移、重复任务、重启恢复、租约、ARM 镜像匹配、美国区域默认值、安全组创建和重试测试）。Chromium 浏览器检查通过桌面 / 390px 手机布局、导航与弹窗、首次设置与登录退出、脚本增删改和只读演示隔离；新增 Cron / 自动换 IP 表单、开关、规则提交、暂停解除及手机布局也通过隔离浏览器检查；ARM 镜像筛选、默认美国区域、安全组默认开放 / 自定义组提交、资源请求竞态与移动端布局通过隔离浏览器检查；无 JavaScript 页面错误。Linux cron 单次工作器已在空数据目录执行通过。JavaScript 语法、启动 shell 脚本和 IAM JSON 校验通过。测试环境为 Python 3.14；存在一条 Starlette 测试客户端的弃用提示，不影响测试结果。当前环境没有 Docker，Dockerfile / Compose 已提供但未实际构建容器；Windows 启动批处理和真实 AWS 操作尚未实机验证。

2026-10-14（v1.1.4）：239 项 Python 测试通过；新增可复跑的浏览器回归脚本，8 组场景覆盖 IP 类型未知 / 已知 EIP / 无公网 IP、释放选项提交、无额外查询、复检状态、手机布局及只读演示。浏览器请求全部模拟，未操作真实 AWS。

参考：[aws.sb 公开 API](https://api.aws.sb/)、[AWS 项目 SCP](https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html)、[EC2 User Data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html)、[Elastic IP](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html)。本项目为独立实现，与 aws.sb 无隶属关系。
