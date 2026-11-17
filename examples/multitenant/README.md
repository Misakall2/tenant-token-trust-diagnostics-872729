# 多租户 JWT 信任接入诊断样例（joserfc）

本目录是一套**完全离线、可回放**的诊断样例，用于定位多租户身份认证接入
joserfc 后两类典型风险：

1. **“签名通过就放行”**——把 `jwt.decode` 的成功当作整体验证通过，跳过声明检查；
2. **轮换后偶发拒绝**——密钥缓存、租户隔离、刷新并发处理不当造成的间歇性失败。

样例不修改 joserfc 任何代码，只基于其公开接口（`jwt.encode/decode`、
`JWTClaimsRegistry`、`JWSRegistry`、`JWKRegistry/KeySet`）演示**接入方**应承担的职责。

## 直接运行

```bash
# 在仓库根目录
python examples/multitenant/demo_wrong_vs_correct.py   # 错误接法 vs 正确接法
python examples/multitenant/demo_rotation.py           # 可回放的密钥轮换全流程
python examples/multitenant/demo_diagnostic_matrix.py  # 全链路诊断矩阵 + 确定性并发
```

所有密钥在进程内临时生成、结束即销毁；`FakeKeySource` / `BlockingKeySource`
是内存假源，**不发起任何网络请求**。输出只含令牌的 SHA-256 短指纹、
失败阶段与原因码，不包含完整令牌、私钥或声明正文。

对应回归测试：

```bash
python -m pytest tests/tenant -q
```

## 包结构

```
tenant_auth/
  clock.py      可注入时钟（ControlledClock / SystemClock）
  errors.py     五阶段错误类型与稳定原因码（不含敏感数据）
  model.py      TenantPolicy（固定信任配置）、Diagnosis、脱敏指纹
  keystore.py   租户隔离缓存、单飞刷新、负缓存、TTL、假密钥源
  tokens.py     临时真实密钥签发令牌 + 伪造变体（篡改 / none / 越权算法）
  verifier.py   五阶段检查链的 MultiTenantVerifier
```

## 信任模型：五阶段检查链

任何请求都按固定顺序经过同一条链，失败即停在对应阶段；不存在
“只解析、不校验就返回声明”的旁路，`VerifiedClaims` 只在全链通过后构造。

```
TENANT_SELECTION -> KEY_REFRESH -> KEY_SELECTION -> SIGNATURE -> CLAIMS
```

| 阶段 | 职责 | 关键约束 |
| --- | --- | --- |
| 租户选择 | 租户 ID **只**来自可信调用上下文 | 令牌中的 iss/jku/jwk/alg 不能选择租户或改变配置 |
| 密钥刷新 | 按租户拉取 JWKS（样例为假源） | 未知编号每租户每快照世代只刷新一次；并发单飞合并 |
| 密钥选择 | 按 kid 在**本租户**快照内定位唯一钥匙 | 同 kid 跨租户不串用；用途不符/重复编号拒绝；不逐个试钥匙 |
| 签名验证 | joserfc 在固定算法白名单下验签 | 白名单永不包含 `none`；令牌 alg 不能扩大白名单 |
| 声明检查 | iss/aud/exp/nbf/iat + 必填声明 | 验签成功也必须通过；时间字段拒绝布尔值 |

## 库职责 vs 接入错误（根因说明）

这是本样例最重要的结论：以下行为**不是 joserfc 的漏洞**，而是接入方的策略缺失。

### 1. `jwt.decode` 只验签，不校验声明

joserfc 文档（`docs/guide/jwt.rst`）明确说明：

> The `jwt.decode` method will only verify if the payload is a JSON base64 string.

`decode` 返回的 `Token` 只代表“签名有效、载荷是合法 JSON 对象”。
`exp`/`nbf`/`iss`/`aud` 等是否满足业务要求，需要接入方再用
`JWTClaimsRegistry.validate()` 检查。**“签名通过就放行”是接入方漏调了声明检查，
不是库替你做了错误的信任决定。** 正确接法见 `verifier.py`：签名与声明两步都在
同一条链内，任一失败都拿不到 `VerifiedClaims`。

### 2. `alg=none` 是 RFC 7515 的中性能力

joserfc 可以在**显式**构造 `JWSRegistry(algorithms=["none"])` 时解析无签名令牌，
这是标准允许的能力。默认注册表只放行推荐算法（HS256/RS256/ES256），不含 `none`。
是否信任 `none` 完全取决于接入方的算法白名单。本样例的 `TenantPolicy` 在构造时
就拒绝包含 `none` 的白名单，并在验签前再次用固定白名单拦截。

### 3. 令牌自带的 iss / jku / jwk / alg 不是信任锚

库把头部字段当作可读数据，不会、也不应替接入方决定该信任谁。若接入方用
`token.claims["iss"]` 反查配置、或用头部 `jku` 去拉取钥匙，等于让不可信输入
驱动信任配置。正确接法是：租户由可信上下文选定后，issuer/audience/算法白名单/
密钥源全部从该租户的**固定策略**读取，令牌字段只能被校验、不能改写策略。

### 4. 轮换期偶发拒绝是缓存/并发策略问题

密钥缓存按租户隔离、TTL 到期、刷新失败处理、并发合并都是接入方逻辑。
本样例给出可回放的确定性实现（见下节），把“偶发”变成可稳定复现与断言的用例。

## 密钥刷新语义（可回放）

`TenantKeyStore` 的规则，全部有测试与演示覆盖：

- **租户隔离**：每个租户独立快照与锁；两个租户可以使用相同 `kid`，
  查找永远限定在本租户快照内，不会跨租户试钥匙。
- **单次刷新**：未知 `kid` 触发一次刷新；同一快照世代内对该 `kid` 做负缓存，
  之后直接 `unknown_key_id` 拒绝，不重复请求、不逐个试钥匙。
- **单飞合并**：并发请求由条件变量按“刷新世代”合并，只有一个线程访问密钥源，
  等待者收到与发起者**完全相同**的结果（成功共用快照，失败共用原因码）。
- **失败保留**：刷新失败不覆盖旧快照、不写负缓存（下次可重试）；
  但快照一旦按注入时钟到期，旧钥匙不再放行，到期 + 故障 = 拒绝。
- **快照校验**：空集合、缺 kid、同租户重复 kid、钥匙材料非法、用途（`use`）
  不符都在刷新/选择阶段拒绝。

## 时钟偏差与边界规则

`leeway` 按租户配置，时钟由 `ControlledClock` 注入，边界结论可精确断言
（来自 joserfc `JWTClaimsRegistry` 的真实实现）：

- `exp`：`now >= exp - leeway` 即过期（**含等号**）。故 `exp == now` 恰好到期即拒绝，
  过期恰等于 leeway 边界也拒绝；过期少于 leeway 才接受。
- `nbf`：`nbf > now + leeway` 才拒绝（**严格大于**）。故 `nbf == now` 即时生效，
  nbf 恰落在 leeway 边界接受，超过边界才拒绝。
- `iat`：与 nbf 同向，未来签发超过 leeway 拒绝。
- 时间字段若为布尔值（`true`/`false`，Python 中是 `int` 子类）会被
  NumericDate 校验显式拒绝，避免 `bool` 混入时间比较。

## 诊断输出脱敏

`Diagnosis` 只记录：阶段链、失败阶段、稳定原因码、kid/alg 等标识符、
令牌短指纹（SHA-256 前 12 位）。`redact_fingerprint` 不可逆，可用于日志关联，
完整令牌、私钥参数（如 RSA 的 `d`）、声明正文都不会进入诊断结果（有测试断言）。
