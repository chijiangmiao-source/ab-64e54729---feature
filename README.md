# 辐照校准包 COSE_Sign1 复核服务

审查员在网页粘贴 Ed25519 公钥（十六进制）与 COSE_Sign1 校准包（十六进制），后端执行：

- **严格确定性 CBOR 解析**：拒绝不定长编码、非最短整数/长度、重复映射键、非规范键序、
  浮点/简单值与未声明的标签；
- **算法检查**：受保护头必须显式声明 `alg = EdDSA(-8)`，其余算法一律拒绝；
- **载荷检查**：载荷必须是 UTF-8 编码的 JSON 对象，并计算其原始字节 SHA-256 摘要；
- **原始字节验签**：以报文中的原始受保护头字节与原始载荷字节构造
  `Sig_structure = ["Signature1", protected, external_aad, payload]` 完成 Ed25519 验签，
  绝不由解析对象重新编码；
- **持久化**：通过与拒绝记录均落库（SQLite），返回复核编号，可按编号重新读取。

## 启动（Docker Compose）

```bash
docker compose up --build app          # 默认宿主端口 8000
HOST_PORT=9000 docker compose up app   # 宿主端口可配置
```

打开 `http://localhost:8000/`（或所配端口）。健康检查：`GET /api/health`。

## 验证（verify 服务）

```bash
docker compose up --build --exit-code-from verify verify
```

verify 服务依次执行：原始字节验签与非规范编码拒绝的单元测试 → 差分约束
审计引擎单元测试（有理数规范、负环、最少删除决胜）→ 构建检查
（字节码编译 + 应用导入）→ HTTP 冒烟（健康检查、提交/重读、拒绝记录
可观察、审计可行/矛盾/冻结读回/各类拒绝），
随后退出并打印 `VERIFY_EXIT_CODE`（0 通过 / 1 失败）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/reviews` | 提交复核，Body：`{"public_key_hex", "package_hex"}` |
| GET | `/api/reviews/{id}` | 按复核编号重新读取 |
| GET | `/api/reviews` | 最近记录摘要 |
| POST | `/api/audits` | 发起约束一致性审计，Body：`{"review_ids": [...]}` |
| GET | `/api/audits/{id}` | 按审计编号读回冻结结果 |
| GET | `/api/audits` | 最近审计摘要 |
| GET | `/api/health` | 健康检查 |

### 约束一致性审计

审查员在同一探测器的若干 **已通过** 复核编号上发起审计。服务只使用这些
已保存记录中的原始载荷（并再次验签确认），要求每份载荷均为 JSON 对象，
含相同的 `detector_id` 与 `constraints` 数组；数组项形如

```json
{"left": "p1", "right": "p2", "bound": "-7/3"}
```

声明上界 `p1 - p2 <= -7/3`，`bound` 必须是规范有理数字符串
（整数或已约分分数，禁止 `2/4`、`3/1`、`1.5`、前导零等）。

引擎以任意精度有理数（`Fraction`）建立差分约束图：

- **可行**：Bellman-Ford 给出按参数标识稳定排列的满足赋值，并对每条约束
  精确复算差值与松弛量；
- **不可行**：返回一个负环作为矛盾证据，并以分支定界精确裁决最少删除哪些
  带来源（复核编号 + 数组位置）的约束才能恢复可行；同尺寸删除集按
  来源编号、再按数组位置字典序稳定选择。

缺少字段、探测器不一致、重复引用、非法有理数、引用无通过记录（不存在或
验签失败）的编号一律以 400 拒绝，**不生成审计编号**。审计成功即冻结：
赋值、复算、负环、最小矛盾集连同来源编号一并落库，按审计编号读回结果
始终一致。

## 生成页面联调用样例

```bash
python verify/make_sample.py   # 输出 PUBLIC_KEY_HEX 与 PACKAGE_HEX
```

## 本地开发（无 Docker）

```bash
pip install -r requirements.txt
cd app && uvicorn main:app --port 8000
# 另一终端：
APP_BASE_URL=http://127.0.0.1:8000 python verify/verify.py
```
