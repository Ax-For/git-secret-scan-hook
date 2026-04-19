# git-secret-scan-hook

Git 的 `pre-push` 敏感信息扫描器。它只检查本次即将推送的提交增量，在内容到达远端前拦截高概率的敏感信息。

## 检查范围

- 私钥头
- GitHub、OpenAI、Anthropic、Tavily、Slack、Stripe token
- AWS Access Key ID
- 阿里云 AccessKey ID
- 带账号密码的数据库连接串
- 类似 `apiKey=...`、`token: ...`、`password=...` 的高熵敏感赋值

规则主要参考 GitHub Secret Scanning、gitleaks 和 detect-secrets 的常见模式。

## 安装

先把仓库 clone 到一个长期稳定的路径，再安装用户级 hook：

```bash
git clone <your-remote-or-local-path> ~/code/git-secret-scan-hook
cd ~/code/git-secret-scan-hook
./scripts/install-user-hook.sh
```

安装脚本会：

- 设置 `git config --global core.hooksPath ~/.config/git/hooks`
- 安装 `~/.config/git/hooks/pre-push`
- 备份已有的全局 `pre-push` hook，并在扫描通过后继续链式执行
- 如果存在旧的复制版 `~/.config/git/hooks/secret-scan.js`，会一并清理

## 更新

如果仓库路径不变，后续更新很简单：

```bash
cd ~/code/git-secret-scan-hook
git pull
```

正常更新不需要重新安装，因为用户目录下的 wrapper 会直接回指这个仓库里的脚本。

## 允许保留测试样例

如果某一行是故意保留的测试样例，可以在同一行加任一标记：

- `secret-scan: allow`
- `pragma: allowlist secret`
- `gitleaks:allow`

如果只想临时跳过一次扫描：

```bash
SKIP_SECRET_SCAN=1 git push
```
