# hark

[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的插件，把 [hark.com](https://hark.com) 的网页会话包装成一个 OpenAI 兼容接口。

一个 hark 账号就是浏览器里的一个登录会话。插件拿这个会话去 hark 发消息、取回复，再按 OpenAI 的 `/v1/chat/completions` 格式返回。支持多个账号，自动跳过过期的，并提供用量查看和批量导入。

## 它做什么

- 暴露一个模型 `claude-opus-5-5`，走标准的 chat completions 接口，流式输出也支持。
- 多账号。每个账号单独计用量、单独计到期，过期的自动移出轮询。
- 记忆跟着请求走，不跟着账号走。每轮都把客户端发来的完整对话发给 hark，所以一个账号额度用尽、自动切换到另一个账号时，上下文不会丢，也不会串到别的对话里。
- 用量页。每个账号一行，显示套餐、剩余天数、今日用量和本周期用量。
- 批量导入。一次粘贴任意多个会话 token，自动校验、自动去重、同邮箱覆盖。

## 它不做什么

hark 的会话没有刷新机制。到期就是到期，只能重新登录再导入一次，插件延长不了它。

## 环境要求

- CLIProxyAPI **v7.2.146**。插件按这一版的 ABI 编译，别的版本不保证能加载。
- 编译需要 Go 1.26 和 gcc，因为插件是 c-shared 的动态库。
- 管理面板要用跟 v7 配套的版本。v1.21.2 是已知可用的一个，[下载地址](https://github.com/router-for-me/Cli-Proxy-API-Management-Center/releases/tag/v1.21.2)。更新的面板只认 v8 的管理接口，配 v7 会在登录页报 404。

## 编译

```bash
cd hark-plugin
CGO_ENABLED=1 go build -buildmode=c-shared -o hark.so .
```

得到 `hark.so`。

## 安装到 CPA

1. 把 `hark.so` 放到 CPA 配置里 `plugins.dir` 指向的目录。
2. 配置里打开插件并声明 hark。参照 [config.yaml](config.yaml)：

```yaml
plugins:
  enabled: true
  dir: "/你的插件目录"
  configs:
    hark:
      enabled: true
      priority: 100
```

3. 启动 CPA。日志里出现 `plugin registered plugin_id=hark` 就是加载成功。
4. 打开 `http://<CPA 地址>:8317/management.html`，用 `remote-management.secret-key` 里设的管理密钥登录。

`config.yaml` 里的 `secret-key` 和 `api-keys` 是占位符，换成你自己的。CPA 第一次启动会把明文的管理密钥自动转成 bcrypt 哈希写回配置文件，这是正常行为。

## 导入账号

左侧栏底部出现一个 **hark** 分组，里面有「Hark 导入」和「Hark 用量」。

### 拿到 token

1. 浏览器登录 [hark.com/chat](https://hark.com/chat)。
2. 打开开发者工具，进 Application，再进 Cookies，选中 `https://hark.com`。
3. 找到 `__Secure-hark.session_token`，复制它的值。

这个值就是一个账号。它有到期时间，hark 到期后即失效。

### 批量导入

打开「Hark 导入」。

- **管理密钥**：填登录这个面板时用的那个密钥，也就是配置里 `remote-management.secret-key` 的明文。填一次就存在这台浏览器的 localStorage 里，之后不用再填。导入要往 CPA 写入凭据，那个接口受管理密钥保护，而导入页嵌在面板的 iframe 里，带不过登录状态，所以单独要一次。
- **文本框**：每行一个 token。逗号、分号、空格分隔都可以，把整段 cookie 原样粘进来也行，插件会自己抽出 token。

点导入。每个 token 会拿去 hark 校验，通过的写成账号，失败的标红并给出原因。同一个邮箱再次导入会覆盖旧的，不用重启 CPA。

## 接入客户端

任何支持 OpenAI 接口的客户端都能用。

| 项 | 值 |
|---|---|
| Base URL | `http://<CPA 地址>:8317/v1` |
| API Key | 配置里 `api-keys` 的任意一个 |
| 模型 | `claude-opus-5-5` |

上下文由客户端维护。插件每轮都把请求里的完整 `messages` 发给 hark，所以客户端只要照常带上历史，账号之间怎么切换都不影响记忆。反过来说，如果客户端每次只发当前一句、不带历史，插件也无从得知前面说过什么。Claude Code、Cline、Continue 这类客户端都会带历史。

## 用量

「Hark 用量」里每个账号一行：名字、邮箱、套餐、剩余天数、今日用量、本周期用量。

- 剩余天数不足 3 天标红。
- 用量超过 70% 进度条变橙，超过 90% 变红。
- 会话到期的账号显示「已到期」，同时不再参与请求轮询。

机器读取用 `GET /v0/resource/plugins/hark/quota?format=json`。

## 工作原理

hark 的网页没有公开 API。一次请求是这样处理的：

1. 把请求里的全部 `messages` 整理成一份带角色标记的记录。上下文放在请求里而不是 hark 上，因为 CPA 会在账号额度耗尽时把同一段对话的下一轮分给另一个账号，任何单个账号都不会持有完整历史。
2. `POST /api/conversations`，带 `title` 和 `autoTitle: false`，建一个临时对话。
3. `POST /api/messages/send`，把整份记录作为这一轮的消息发出去。
4. 轮询 `GET /api/messages/history`，直到出现由这次发送触发的助手回复。
5. `DELETE /api/conversations/<id>`，删掉这个临时对话。hark 没有清空对话的接口，只有删除，所以每轮各建各的，用完就删，不在账号里留下任何项目。

回复是整段返回的，插件按块切开发给客户端，所以流式输出是模拟的，不是 hark 原生的逐 token 流。

每轮重发完整历史会多消耗 hark 的 token 额度，换来的是账号切换时记忆不断、对话之间不串。历史相对额度上限很小。

账号凭据存在 CPA 的 auth 目录里，一个账号一个 JSON 文件，文件名是 `hark-<邮箱>.json`。
