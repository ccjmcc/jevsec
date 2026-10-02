# JevSec 使用指南

## 适用范围

JevSec v0.2 是本地运行的 Web 行为检测与分诊工具。它分析 Nginx/JSONL 事件，按来源 IP、会话和伪匿名用户聚合行为，用透明规则和 **Qwen3-4B（`llm-qwen3-4b`）** 产生 `BENIGN`、`REVIEW`、`HIGH_RISK` 或 `UNCERTAIN` 结果。模型只接收固定字段的聚合数值/布尔特征；原始路径、User-Agent、Referer、Cookie 和凭据不会发给模型。

它运行在 shadow mode，不会拦请求。生产部署应让 OWASP CRS 或其他 WAF 继续承担请求检查和阻断；参见[对比报告](../reports/WAF_COMPARISON.md)。

## 安装与启动

要求 Python 3.12、`uv`、Git。Apple Silicon 建议让 local-jev 在 macOS 主机本地运行，以使用 MPS；首次启动会下载 Qwen3-4B 模型权重。

```sh
git clone <repository-url>
cd jevsec
uv sync --all-extras --python 3.12
```

安装 local-jev（独立项目，不随 JevSec 发布）：

```sh
git clone https://github.com/amithgc/local-jev.git ../.local-jev
cd ../.local-jev
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e .
nohup .venv/bin/local-jev serve --model llm-qwen3-4b > /tmp/local-jev.log 2>&1 &
cd ../jevsec
```

启动产品并载入安全的示例日志：

```sh
./scripts/demo.sh
```

打开 <http://127.0.0.1:8000>。只看界面而不运行模型时，使用 `SDE_DECISION_PROVIDER=mock ./scripts/demo.sh`；Mock 结果不是模型跑分。

## 输入和运行模式

一次性导入 Nginx Combined Log Format：

```sh
uv run security-engine ingest /var/log/nginx/access.log --format nginx
```

持续 shadow 观察日志：

```sh
uv run security-engine shadow --nginx /var/log/nginx/access.log
```

支持追加、截断和替换式日志轮转。开始时应使用只读日志副本，并先在 staging 观察误报。也可用 `--mode rules_only` 或 `--mode jev_only` 做诊断；常规 triage 使用 Hybrid。

JSONL 导入采用字段白名单。用户或会话标识在写入时做单向哈希，查询字符串与片段被移除；来源 IP、规范化路径、状态码、时间戳和 User-Agent 仍可能保留在本机 SQLite，需按环境设置文件权限、保留期限和备份策略。

## 配置与安全部署

主要环境变量：

- `SDE_DATABASE`：SQLite 数据库路径。
- `SDE_DECISION_PROVIDER`：`local_jev` 或显式开发用 `mock`。
- `LOCAL_JEV_BASE_URL`：Jev 兼容推理端点；本机默认 `http://127.0.0.1:8765`。
- `LOCAL_JEV_MODEL`：唯一支持值为 `llm-qwen3-4b`；其他值会在启动时快速报错。
- `SDE_MODE`：`hybrid`、`rules_only`、`jev_only`。
- `SDE_ALERT_THRESHOLD`、`SDE_HIGH_RISK_THRESHOLD`、`SDE_LOW_CONFIDENCE_THRESHOLD`：triage 设置。

默认只绑定 loopback。非 loopback 监听必须设置 `SDE_AUTH_USERNAME` 与 `SDE_AUTH_PASSWORD`，并通过可信 TLS 反向代理提供外部访问。HTTP Basic 本身不加密。Docker Compose 发布端口也限制在主机 loopback，并要求本地 `.env` 中提供凭据：

```sh
cp .env.example .env
# 编辑 .env 中的随机长密码
docker compose up --build
```

Apple Silicon 的本机 MPS 不会透传给 Docker Linux 容器；在 macOS 上应将 local-jev 原生运行在宿主机。

## 基准、报告和复现

完整 Qwen3 基准会在 1%、5%、10% 合成攻击率各生成 20,000 个行为窗口，按来源实体隔离 60/20/20 的校准保留集、验证集、测试集。所有验证和测试窗口都会评分；阈值只使用验证集拟合。复现完整本地模型基准：

```sh
./scripts/run_public_benchmark.sh
```

`SDE_PUBLIC_WINDOWS=1000` 可用于较快的 smoke run，生成报告会保留实际测试样本数，不能将 smoke 指标当成完整跑分。运行失败后仅在数据指纹和模型均匹配时使用 `SDE_PUBLIC_RESUME=1` 续跑。

使用当前固定版本 OWASP CRS 跑请求级对比：

```sh
uv run python scripts/run_waf_comparison.py
```

此命令需 Docker Desktop/Engine 运行。它启动 loopback-only `owasp/modsecurity-crs:4.29.0-nginx-202609301109`，流量仅到本机临时 origin，完成后删除容器。行为样本采用安全路径与安全参数；另有少量常见 payload signature 正向控制，全部只发到这个本地 WAF。

报告位于：

- `reports/BENCHMARK_V2.md`：Qwen3、项目规则、Hybrid 的完整行为窗跑分和模型成本。
- `reports/WAF_COMPARISON.md`：同一留出行为窗上的 Qwen3 与 CRS 指标、CRS payload 正向控制及局限。
- `reports/FAILURE_ANALYSIS.md`：按标签和场景列出误报/漏报。
- `reports/waf_comparison/`：WAF 原始 JSON 和逐窗 CSV。

行为场景基准测的是 triage 能力和场景覆盖，不是生产流量估计，也不是 WAF 渗透测试或通用防护认证。请按真实环境流量构建独立、标注清楚的验收集，再选择阈值；不要仅凭合成跑分自动阻断流量。

## 常见诊断

```sh
uv run security-engine doctor
curl -fsS http://127.0.0.1:8765/healthz
docker compose ps
```

local-jev 未就绪时检查 `/tmp/local-jev.log`。若 Docker WAF 对比未就绪，脚本会输出容器日志并清理临时容器。若 dashboard 在非 loopback 绑定，应同时核对 TLS 代理、凭据和防火墙策略。
