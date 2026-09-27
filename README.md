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

verify 服务依次执行：原始字节验签与非规范编码拒绝的单元测试 → 构建检查
（字节码编译 + 应用导入）→ HTTP 冒烟（健康检查、提交/重读、拒绝记录可观察），
随后退出并打印 `VERIFY_EXIT_CODE`（0 通过 / 1 失败）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/reviews` | 提交复核，Body：`{"public_key_hex", "package_hex"}` |
| GET | `/api/reviews/{id}` | 按复核编号重新读取 |
| GET | `/api/reviews` | 最近记录摘要 |
| GET | `/api/health` | 健康检查 |

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
