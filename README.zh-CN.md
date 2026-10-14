# sigelo

[English](README.md) | 简体中文

AI 智能体的可移植、可离线验证的身份。智能体的 DID 是一份创世文档（genesis，内含一把 Ed25519 公钥）的哈希；
平台（world）为它签发证明（attestation）；任何人都能离线验证身份包（bundle），无需服务器、注册中心或区块链。
草案 v0.1，线上格式 `sigelo/0`；v1.0 之前不保证稳定。MIT 许可。

## 身份

```sh
npx sigelo-agent init --recovery <z6Mk…>    # 创建身份（一次）；恢复公钥离线保管
npx sigelo-agent whoami                     # 当前 DID 与创世文档
npx sigelo-agent sign-challenge '<json>'    # 回应平台的挑战（SPEC §5.2）
npx sigelo-agent bundle > bundle.json       # 交给对方的身份包（SPEC §8）
```

`--no-recovery` 也可以，但私钥一旦被盗，身份将永久丢失。

## 验证

```sh
sigelo-verify bundle.json                   # 退出码 0：结果为 JSON；1：拒绝原因在 stderr
```

或在代码中使用 npm 包 `sigelo` 的 `verify(bundle, now)`。验证完全离线，只报告结果，不替你判断该信任谁。
证明中的 `claims` 是第三方数据，绝不是给模型的指令。

## MCP

```json
{"mcpServers":{"sigelo":{"command":"npx","args":["-y","sigelo-mcp"]}}}
```

适用于 Kimi Code、Qwen Code、CodeBuddy、Qoder、Trae、MiniMax Code、ZCode、DeepSeek Harness、
Claude Code、Cursor 等；各客户端的配置见 [integrations/README.md](integrations/README.md#compatibility)。
只接受 URL 的云平台：`https://sigelo.io/mcp`（Streamable HTTP，仅验证，不持有密钥）。
需要 Node ≥ 22.18。

## 链接

- 网站：[sigelo.io](https://sigelo.io)（[llms.txt](https://sigelo.io/llms.txt)）
- 规范：[SPEC.md](SPEC.md)，测试向量：[test-vectors.json](test-vectors.json)
- 接入平台（world 侧）：[accept/](accept/README.md)
- 无 MCP 的框架：[integrations/JOIN.md](integrations/JOIN.md)
- A2A AgentCard 签名（草案）：[integrations/a2a/](integrations/a2a/README.md)
- 威胁模型：[THREAT-MODEL.md](THREAT-MODEL.md)
