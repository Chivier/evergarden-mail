# 快速开始

本文在一台机器上安装 Evergarden，接入一个邮箱和一个 MCP 客户端，最后批准第一个操作。
全程约十五分钟，大部分时间花在首次构建镜像上。

所有服务都只监听 `127.0.0.1`。如果要从其他机器访问，请先完成本文，再按
[operations.md](../operations.md#reverse-proxy-and-https)（英文）配置反向代理。

英文版：[quickstart.md](../quickstart.md)。

## 准备

- 一台 Linux 主机，装有 Docker Engine 和 Docker Compose v2.24 或更新版本
  （`docker compose version`）。
- Python 3.10 或更新版本，用于运行初始化脚本（只用标准库）。
- Git。
- `127.0.0.1` 上空闲的 8788、8420、8421 端口（三个端口都可以改）。
- 一个可以用密码或应用专用密码登录 IMAP 和 SMTP 的邮箱。Gmail 和 iCloud 都可以；
  Microsoft 账户需要 OAuth，见 [providers.md](../providers.md)（英文）。

## 1. 克隆并运行 setup

```bash
git clone https://github.com/Chivier/evergarden-mail.git evergarden
cd evergarden
./deploy/setup
```

在终端里运行时，setup 会问两个问题，直接回车使用默认值即可（地址
`http://127.0.0.1:8788`，用户名 `admin`）。

setup 会创建 `.local/`（私钥、加密凭据库、归档目录）、`.local/run/runtime.env` 和 `.env`。
它先列出创建的文件，然后输出：

```text
Administrator login (shown only this once; store it in a password manager):
  username: admin
  password: <生成的密码>
```

请立即保存这个密码，它不会以明文保存在任何地方。忘记密码时见
[operations.md](../operations.md#reset-the-administrator-password)（英文）。

setup 还会列出后续步骤，并提示写入邮件服务商的功能处于关闭状态。重复运行 setup 是
安全的：它从不覆盖已有文件。

如需改用其他端口，在第一次运行时传入，例如
`./deploy/setup --http-port 38788 --mcp-port 38420 --approval-port 38421`。
它们会写入 `.env` 中的 `EVERGARDEN_HTTP_PORT`、`EVERGARDEN_MCP_PORT` 和
`EVERGARDEN_APPROVAL_PORT`。下文的 8788、8420 和 8421 请换成你的端口。

## 2. 启动

```bash
docker compose up -d --build
docker compose ps
```

首次构建需要几分钟。等到 `postgres`、`mcp`、`approval-ui`、`mail-ui`、`gateway`、
`scheduler` 都显示 `healthy`，并且 `migrate` 显示 `Exited (0)`。`migrate` 负责创建数据库
结构后退出，每次 `up` 都会运行。

## 3. 登录

打开 <http://127.0.0.1:8788>，用 `admin` 和刚才打印的密码登录。登录后进入邮件工作台，
在添加邮箱之前它是空的。侧边栏底部的 EN / 中文 切换界面语言。

## 4. 添加邮箱

1. 点侧边栏“邮箱”旁的 **+**（“管理邮箱”）。
2. 展开“添加邮箱”并填写表单。密码邮箱的示例：

   | 字段 | 示例 |
   |---|---|
   | 别名 | `personal`（小写，在命令和工具调用中使用） |
   | 认证邮箱地址 | `you@example.com` |
   | 认证 | “应用专用密码” |
   | 凭据记录 | `password:personal`，根据别名和认证方式自动填写。可以修改，任何稳定的标识都可以。 |
   | IMAP 主机 / 端口 | `imap.example.com` / `993` |
   | SMTP 主机 / 端口 / 加密 | `smtp.example.com` / `587` / STARTTLS（或 `465` / “隐式 TLS”） |
   | 归档文件夹、已发送文件夹、废纸篓文件夹 | 邮件服务商的实际文件夹名 |
   | 同步文件夹 | `INBOX, Archive` |
   | 允许移动到 | 必须包含归档文件夹；不能是废纸篓或垃圾邮件文件夹 |

   Gmail、iCloud 等服务商的取值见 [providers.md](../providers.md)（英文）。
3. 点“保存私有配置”。提示为“邮箱已写入本机私有配置；请完成凭据/OAuth 后重启服务。”

表单从不接收密码。请在命令行保存：

```bash
docker compose exec approval-ui evergarden-provider-credential set-password --account personal
```

在 `App password:` 提示后输入应用专用密码（不会回显）。命令输出
`{"account": "personal", "credential_version": 1, "stored": true}`。如需从密码管理器
通过管道输入，在 `exec` 后加 `-T`，并把密码从标准输入传入。

然后重启读取邮箱列表的服务。每次修改邮箱后都需要这一步：

```bash
docker compose restart mcp approval-ui mail-ui
```

## 5. 首次同步

刷新工作台，点“同步邮件”。同步是只读的，不会修改服务商上的任何内容。成功时按钮旁
显示“已同步 1 个邮箱”，邮件出现在“今日邮件”和“全部邮件”中。

失败时显示“同步未完成”，并弹出提示，逐个列出未能同步的邮箱和简短原因。例如 IMAP
主机写错时是这样：

```text
以下邮箱未能同步：
• personal 无法解析服务器地址。请检查 IMAP 主机。
  ▸ 技术细节
```

其他原因有“服务器拒绝连接”（主机或端口错误）、“认证失败”（重新运行 `set-password`，
或重新连接 OAuth）、“服务器响应超时”以及笼统的“同步失败”。“技术细节”中是服务商的原始
错误，例如 `gaierror: [Errno -2] Name or service not known`。提示会一直显示，直到你关闭它。网页可以添加和停用
邮箱，但不能编辑，所以主机或文件夹写错时，请用文本编辑器修改
`.local/run/mail-config/mail_accounts.json`。之后按上面的方法重启并再次同步。

此后 `scheduler` 服务每小时第 03 分钟自动同步所有邮箱。

## 6. 连接 MCP agent

1. 点侧边栏的“MCP 接入指南”。
2. 填写“名称”（例如 `laptop`），选择“权限档位”（“只读”、“读 + 草稿”或“完整”）和
   “有效期”，点“创建 API key”。
3. key 只显示这一次。下方的客户端配置片段已经填好了这把 key 和你的 MCP 地址，
   直接从对话框复制。

Claude Code 的片段：

```bash
umask 077
printf '%s' '<你的 API key>' > ~/.evergarden-mcp.token

TOKEN="$(tr -d '\n' < ~/.evergarden-mcp.token)"
claude mcp remove evergarden-mail -s user 2>/dev/null || true
claude mcp add --transport http evergarden-mail http://127.0.0.1:8788/mcp \
  --scope user \
  --header "Authorization: Bearer ${TOKEN}"
unset TOKEN

claude mcp list
```

Codex 的片段：

```bash
umask 077
printf 'EVERGARDEN_MCP_TOKEN=%s\n' '<你的 API key>' >> ~/.codex/.env
chmod 600 ~/.codex/.env

codex mcp remove evergarden-mail 2>/dev/null || true
codex mcp add evergarden-mail \
  --url http://127.0.0.1:8788/mcp \
  --bearer-token-env-var EVERGARDEN_MCP_TOKEN

codex mcp list
```

`claude mcp list` 应显示已连接；`codex mcp list` 应显示使用 bearer token。（Codex 片段会追加写入
`~/.codex/.env`；如果从未运行过 Codex，请先创建 `~/.codex` 目录。）其他客户端见
[mcp.md](../mcp.md)（英文）。

不用客户端也可以检查 key（这里读取的是 Claude Code 片段写入的 token 文件；如果只用
Codex，请先用同样的方式保存 key：
`umask 077; printf '%s' '<你的 API key>' > ~/.evergarden-mcp.token`）：

```bash
TOKEN="$(tr -d '\n' < ~/.evergarden-mcp.token)"
curl -sS -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  http://127.0.0.1:8788/mcp
```

返回的是 JSON-RPC 结果，列出这把 key 的 scope 允许的工具。不带该请求头的请求会得到
HTTP 401。

现在 agent 可以读信、搜索和起草。它准备的每一次发送、移动、标记或移入废纸篓，都会
在审批页等你处理。

## 7. 开启写入

新安装是只读的：你可以批准操作，但不会真的在服务商处发送或移动邮件。准备好之后，
编辑 `.local/run/runtime.env`：

```dotenv
EVERGARDEN_SIDE_EFFECTS_ENABLED=true
# 建议：即使没有客户端连接，也在后台执行你的批准
EVERGARDEN_APPROVAL_DISPATCH_ENABLED=true
```

然后应用：

```bash
docker compose up -d
curl -s http://127.0.0.1:8420/healthz
```

健康检查结果中会出现 `"mode":"production"`。每次写入仍然需要批准。移入废纸篓有单独的
开关 `EVERGARDEN_TRASH_ACTIONS_ENABLED`，可以保持关闭。

## 8. 批准第一个操作

1. 在工作台打开一封邮件，点“标记”，再点“标为已读”。“检查不可变操作”对话框会显示
   确切的修改内容。
2. 点“打开独立审批页”，它会在新标签页显示邮件和操作。点“批准”。
3. 开启后台执行时，页面提示“已批准，已加入执行队列，服务器会自动执行，关闭本页也会
   继续。”“执行记录”标签中可以看到该项从“执行中”变为“成功”。

   未开启后台执行时，回到工作台的对话框，点“检查审批状态”，再点“执行已批准操作”。

agent 的操作流程相同：它准备操作，你在审批页批准。审批队列、批量审批和撤销见
[使用手册](user-guide.md)。

## 停止、升级、备份

```bash
docker compose stop                # 停止，保留一切
docker compose up -d               # 再次启动
docker compose down                # 删除容器；数据保留在 .local/ 和 Postgres 卷中
```

`docker compose down -v` 还会删除 Postgres 卷，连同所有草稿、批准和审计记录。要保留的
部署请不要使用 `-v`。

升级：

```bash
git pull
docker compose up -d --build
```

`migrate` 服务会自动执行新的数据库迁移。请对照 `runtime.env.example` 检查
`.local/run/runtime.env` 是否有新设置。

备份 Postgres 数据库、`.local/` 和 `.env`，见
[operations.md](../operations.md#back-up-and-restore)（英文）。`.local/run/credential_store_key`
和 `EVERGARDEN_HOST_ID` 一起用于解密已保存的邮箱凭据；缺少它们，恢复后将无法读取密码和 token。
