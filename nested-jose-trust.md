# 嵌套 JWE/JWS 与多签名对象的信任边界分析

> 分析对象：`github.com/go-jose/go-jose/v4`（本工作区快照，`go.mod` 声明 `go 1.24.0`）
> 关注入口：`jwt.ParseSignedAndEncrypted` / `NestedJSONWebToken.Decrypt`、`jose.JSONWebSignature.Verify` / `VerifyMulti`、`jose.JSONWebEncryption.Decrypt`、`jwt.Claims.Validate`
> 结论一句话：**解密成功只证明“持有解密密钥 + JWE 完整性标签有效”，某一签名验证成功只证明“该索引上的受保护头部与载荷被对应密钥签过”，受众校验是与前两者完全独立的第三道闸门。三道闸门分别由不同代码负责，任何一道被跳过或被错误地用另一道替代，都会产生认证绕过。**

---

## 1. 背景与分析对象

单点登录（SSO）/ OIDC 场景常见“先签名后加密”的嵌套令牌（RFC 7515 + RFC 7516）：

```
JWE_compact( JWS_compact( claims ) )
   外层：alg/dir + enc，提供机密性与 JWE 层完整性
   内层：JWS，对 protected_header.payload 签名，提供签发者身份认证
```

本库对应的构造与解析路径：

- 构造：`jwt.SignedAndEncrypted(signer, encrypter).Claims(...).Serialize()`
  （`jwt/builder.go:294` 的 `signAndEncrypt`：先 `sig.Sign`，再 `CompactSerialize`，最后 `enc.Encrypt`）。
- 解析：`jwt.ParseSignedAndEncrypted`（`jwt/jwt.go:173`）→ `NestedJSONWebToken.Decrypt`
  （`jwt/jwt.go:74`）→ 对解密出的字节再 `jwt.ParseSigned`（`jwt/jwt.go:80`）→ `JSONWebToken.Claims(key, &claims)`
  内部调用 `sig.Verify`（`jwt/jwt.go:43`、`jwt/jwt.go:105`）。

本文把“本地令牌”理解为**在本系统/本信任域内被生产与消费的嵌套令牌**：外层 JWE 常用 `dir` + 对称密钥（如 `A128GCM`），该密钥可能被多个组件共享；内层 JWS 才承载真正的签发者身份。

---

## 2. 三个责任边界的代码追踪

### 2.1 责任边界总表

| 闸门 | 负责的代码 | 成功后能得出的结论 | 明确**不能**得出的结论 |
|---|---|---|---|
| ① 外层 JWE 解密 | `JSONWebEncryption.Decrypt`（`crypter.go:462`） | 我持有正确的解密密钥；密文的 JWE 认证标签（AAD 覆盖 JWE protected header）有效；明文未被篡改 | 明文里的内层 JWS 是谁签的、claims 是否可信、令牌是否给本服务用 |
| ② 内层 JWS 签名验证 | `JSONWebSignature.Verify`（`signing.go:411`）/ `VerifyMulti`（`signing.go:490`），经 `tryJWKS`（`jwk.go:937`）选钥 | **被验证的那个签名索引**上的 protected header 与 payload，与验证密钥匹配 | 其它签名索引的元数据可信；merged/unprotected header 可信；aud/iss 等业务约束满足 |
| ③ Claims 受众/时间校验 | `Claims.ValidateWithLeeway`（`jwt/validation.go:79`） | 已验证载荷中的 `aud`（以及 iss/sub/jti/exp/nbf/iat）符合调用方期望 | 它本身不做任何密码学验证；传入未验证 claims 时结论无意义 |

### 2.2 闸门①：解密的责任边界

`crypter.go:462` 的 `Decrypt` 做的事：

1. `tryJWKS(decryptionKey, obj.Header)`（`crypter.go:474`）选解密密钥；
2. `decrypter.decryptKey(...)` 解出 CEK（`crypter.go:507`），失败统一归并为 `ErrCryptoFailure`；
3. `cipher.decrypt(cek, authData, parts)`（`crypter.go:517`）做 AEAD 解密并校验标签，`authData` 由 `computeAuthData`（`jwe.go:93`）生成，**只覆盖 JWE protected header（与可选 AAD）**；
4. `decompress` 解压后返回明文。

因此解密成功的语义被严格限定为：**密钥正确 + JWE 层完整性有效**。它对明文内容是“盲”的——明文可以是任意字节，包括一个由攻击者自行签名、结构合法的内层 JWS。`NestedJSONWebToken.Decrypt`（`jwt/jwt.go:74-86`）解密后仅调用 `ParseSigned`，而 `ParseSigned*` 的文档（`jws.go:91-92`、`jws.go:118-119`）明确写道：**解析阶段不验证签名，必须再调 `Verify()`**。

> 关键事实：`jwt.ParseSignedAndEncrypted` 在解析期还会强制外层 `cty=JWT`（`jwt/jwt.go:183-186`），但这只是结构类型提示，同样不构成身份保证。

### 2.3 闸门②：单签名与多签名验证的责任边界

**单签名 `Verify`（`signing.go:411`，经 `DetachedVerify` `signing.go:433`）**

- 显式拒绝多签名对象：`len(obj.Signatures) > 1` 直接报错（`signing.go:434-436`），不会“替你猜一个”。
- 选钥：`tryJWKS(verificationKey, signature.Header)`（`signing.go:440`）。注意传入的是 `signature.Header`，即 **merged header（protected + unprotected 合并）**，不是 `signature.Protected`。
- 真正被签名的输入由 `computeAuthData`（`jws.go:165`）计算：`base64(原始 protected header 字节) + "." + base64(payload)`。**unprotected header 从不参与签名输入**。
- 校验 `crit` 只能出现在 protected（`signing.go:449-466`），然后 `verifier.verifyPayload`（`signing.go:475`）。
- 成功后返回 `obj.payload`。`jwt.Claims`（`jwt/jwt.go:43-56`）在 `Verify` 成功后才把 payload 反序列化进目标结构。

**多签名 `VerifyMulti` / `DetachedVerifyMulti`（`signing.go:490`、`signing.go:510`）**

- 按索引顺序遍历 `obj.Signatures`，每个签名独立做 `crit` 检查、`tryJWKS` 选钥、`computeAuthData`、`verifyPayload`；任一环节失败就 `continue` 跳到下一个（`signing.go:518-553`）。
- **第一个验证通过的签名即返回 `(i, signature, nil)`**（`signing.go:555`）；全部失败才返回 `ErrCryptoFailure`（`signing.go:558`）。
- 文档（`jws.go:55-58`、`signing.go:483-486`）明确：返回索引与签名对象“to guarantee that callers are getting the verified value”。也就是说，**可信的元数据只有返回的那个 `Signature` 及其索引**，`JSONWebSignature.Signatures` 切片里的其它元素不能当作已验证。

`Signature` 三个头部字段的信任级别（定义见 `jws.go:62-83`，注释本身即安全说明）：

| 字段 | 内容 | 信任级别 |
|---|---|---|
| `Protected` | 受保护头部，参与签名输入 | 随签名验证成功而被认证 |
| `Unprotected` | 未保护头部（仅 JWS JSON 序列化可携带） | **未被签名，不可信** |
| `Header` | 上面两者的合并视图 | “may or may not have been signed … in general should not be trusted”（`jws.go:64-67`） |

### 2.4 闸门③：受众（aud）校验的责任边界

受众校验完全位于应用层，由 `Claims.ValidateWithLeeway`（`jwt/validation.go:79`）负责，与密码学代码无任何耦合：

- 仅当调用方在 `Expected.AnyAudience` 填入**非空**受众时才检查（`jwt/validation.go:92`）；为空则**整段跳过**。
- 检查规则是“非空交集”：`Expected.AnyAudience` 与令牌 `aud` 有任一相等即通过（`jwt/validation.go:93-104`），否则返回 `jwt.ErrInvalidAudience`（`jwt/errors.go:38`）。
- `aud` 的解析在 `Audience.UnmarshalJSON`（`jwt/claims.go:103`），同时接受字符串与字符串数组。

这意味着：**即使 JWE 解密、JWS 签名都成功，只要调用方不调用 `Validate`（或 `AnyAudience` 留空），一个签给其它服务的令牌在本服务也会被接受。** 库不会、也无法替调用方知道“本服务的标识符是什么”，所以这一步在设计上就被留给调用方。同理，`iss`/`sub`/`jti` 是精确匹配且零值跳过，`exp`/`nbf`/`iat` 带 1 分钟默认 leeway（`jwt/validation.go:24`、`jwt/validation.go:112-124`）。

---

## 3. 嵌套令牌的完整数据流与“外层有效但内层失效”的位置

```
输入字符串
  │ ParseSignedAndEncrypted（jwt/jwt.go:173）
  │   ├─ 算法白名单校验（alg/enc 非空且必须命中允许列表，jwe.go:289）
  │   └─ cty 必须为 JWT（jwt/jwt.go:183）           ← 仅结构提示
  ▼
NestedJSONWebToken
  │ Decrypt(encKey)（jwt/jwt.go:74）
  │   ├─ JWE.Decrypt（crypter.go:462）               ← 闸门①：机密性 + JWE 完整性
  │   └─ jose.ParseSigned（jwt/jwt.go:80）           ← 只解析，不验签
  ▼
*JSONWebToken（内层）
  │ Claims(sigKey, &claims)（jwt/jwt.go:43）
  │   └─ payload(sigKey) → sig.Verify（signing.go:411）  ← 闸门②：身份认证
  ▼
claims 结构体（此时才是“已认证的 claims”）
  │ claims.Validate(Expected{AnyAudience: ...})      ← 闸门③：受众/时间/签发者约束
  ▼
授权决策
```

“外层有效但内层签名不匹配”和“外层有效但受众不匹配”分别卡在闸门②和闸门③，二者都**不会**被闸门①的成功所覆盖。

---

## 4. 多签名对象：调用方如何只使用“已验证签名的索引 + 已认证头部/Claims”

### 4.1 正确用法（库已提供所需的全部绑定信息）

```go
idx, verifiedSig, payload, err := parsed.VerifyMulti(verificationKey)
if err != nil { /* 没有任何签名通过，拒绝 */ }

// 只使用：
//   idx                       —— 已验证签名的索引
//   verifiedSig.Protected     —— 随该签名被认证的头部（不要用 verifiedSig.Header / .Unprotected）
//   payload                   —— 与该签名绑定的、已验证的载荷
_ = idx
```

绑定关系由库保证：`DetachedVerifyMulti` 在 `verifyPayload` 成功的同一循环迭代里返回该迭代的 `i` 与 `signature`（`signing.go:543-555`），二者天然配对，不存在“索引是 A、签名对象是 B”的错配窗口。Claims 必须从返回的 `payload` 反序列化，而不是从 `UnsafePayloadWithoutVerification`（`signing.go:422`）或 `UnsafeClaimsWithoutVerification`（`jwt/jwt.go:61`）获取。

### 4.2 错误用法及后果

1. **按固定下标取元数据**：多签名对象中签名顺序由输入 JSON 决定，攻击者可构造。验证返回 `idx=1`，代码却去读 `Signatures[0].Header`（或验证前就缓存的 `JSONWebToken.Headers`，该切片在 `jwt/jwt.go:99-102` 由全部签名的 **merged** header 填充），拿到的是另一个未被当前密钥验证的签名者的 `kid`/自定义头。
2. **用 merged `Header` 而非 `Protected` 做安全判断**：`Header` 含未认证字段（见第 5.3 节）。
3. **把“某个签名验证成功”误读为“所有签名都有效”**：`VerifyMulti` 是“存在一个通过即返回”，不是“全部通过”。要求多签联名（m-of-n）的场景必须自行对期望的每个签发者分别验证并核对 `verifiedSig.Protected` 中的身份。
4. **对多签对象调用单签 `Verify`**：会直接得到 `too many signatures in payload; expecting only one`（`signing.go:435`），这是安全的失败方式，不应通过“先取 `Signatures[0]` 再绕过”来消除该错误。

---

## 5. 三类误用的具体影响

### 5.1 “解密即信任”——内层伪造令牌直通

外层 JWE 使用共享对称密钥（`dir`/`A128GCM` 等）时，任何持有该传输密钥的组件都能完成闸门①。若应用把 `Decrypt` 成功当作身份认证成功（或调用 `UnsafeClaimsWithoutVerification` 直接读 claims），攻击者可：用合法外层密钥解密 → 丢弃原内层 JWS → 用自己的 HMAC 私钥签一个 `sub=admin` 的新 JWS → 重新加密成结构完全合法的嵌套令牌。`cty=JWT`、算法白名单、JWE 标签全部正常，只有内层签名能识破，但该步被跳过。

影响：**认证绕过 / 权限提升**。按本仓库 `threat_model.md` 的评级口径（“Any authentication bypass … is a high+ severity”），属高危。

### 5.2 取错签名元数据——未认证 `kid` 驱动 JWKS 选钥 / 错索引错配

`tryJWKS`（`jwk.go:937-964`）的选钥逻辑：

```go
kid := header.KeyID                 // 来自调用方传入的 merged header
if kid == "" { return nil, ErrJWKSKidNotFound }
keys := jwks.Key(kid)
if len(keys) == 0 { return nil, ErrJWKSKidNotFound }
return keys[0].Key, nil             // 同 kid 多条目时，静默取第一个
```

两个可被利用的点：

- **kid 可来自未认证头部**：JWS JSON 通用序列化允许每个签名携带 `header`（unprotected）。`sanitized` 会把它与 protected 合并进 `Signature.Header`（`jws.go:354-360`），而 `DetachedVerifyMulti` 把 merged header 传给 `tryJWKS`（`signing.go:534`）。攻击者用自己控制的私钥签名，再在 unprotected header 里放入指向 JWKS 中“另一个合法条目”的 `kid`，验证就会用该条目的公钥完成——密码学上签名有效，但**签名者是攻击者借 JWKS 选钥流程“选”出来的，而非预期签发者**。
- **同 kid 多 JWK 时静默取 `keys[0]`**：`JSONWebKeySet.Key`（`jwk.go:405`）返回全部匹配，`tryJWKS` 只取第一个；kid 冲突/轮换残留时存在歧义，调用方无感知。

此外，多签场景取错索引（第 4.2 节）会把 A 签名者的元数据记到 B 的验证结论上，破坏审计与授权判断。

### 5.3 混用未认证头部——merged header 可在签名仍有效的情况下被篡改

JWS 的签名输入只含 protected header 与 payload（`jws.go:165-201`），unprotected header 不在其中。因此攻击者可以在不破坏签名的前提下任意改写 unprotected 字段，而 `Signature.Header`（merged）与 `Signature.Unprotected` 会如实反映被改写后的值。典型受害模式：把租户 ID、角色、路由提示等放进 unprotected/merged header 并据此授权。`jws.go:64-75` 的字段注释已明确警告该字段“in general should not be trusted”。

> 对照：JWE 侧 `mergedHeaders`（`jwe.go:80-90`）合并 protected + unprotected + per-recipient header，JWE 的 AEAD AAD 只认证 protected 部分；`Decrypt` 同样把 merged `obj.Header` 传给 `tryJWKS`（`crypter.go:474`）。在 JWE JSON 序列化下，unprotected `kid` 驱动解密选钥的问题同构存在（JWT 包的 compact 入口不暴露 unprotected header，但 `jose` 包的 JSON 入口暴露）。

---

## 6. 现有兼容行为下可复现的判定依据

以下结论均用独立 PoC 模块实测通过（未改动库源码）。PoC 位于仓库外的独立目录，通过 `replace` 指向本仓库：

- 代码：`/srv/fb2/mei8085/tasks/92/poc/main.go`
- 输出：`/srv/fb2/mei8085/tasks/92/poc/poc-output.txt`
- 复现命令：

```bash
cd /srv/fb2/mei8085/tasks/92/poc
GOTOOLCHAIN=local <go1.24+>/bin/go run .
```

| # | 判定点（可复现现象） | 实测结果 | 对应责任边界 |
|---|---|---|---|
| 1 | 外层 JWE 用合法 enc 密钥解密成功，但内层 JWS 用合法签名密钥 `Claims()` 验证 | 解密 `err == nil`；验签返回 `ErrCryptoFailure`；同一令牌 `UnsafeClaimsWithoutVerification` 仍能读出攻击者写入的 `sub="admin"` | ① 不覆盖 ② |
| 2 | 双签名 JWS 用 keyB 调 `VerifyMulti` | 返回 `idx=1` 且 `verifiedSig.Protected.KeyID="signer-b"`；另一索引 `Signatures[0]` 的 kid 为 `signer-a`；对该对象调 `Verify` 报 `too many signatures` | ② 仅绑定返回索引 |
| 3 | 签名 protected 中**无 kid**，仅在 unprotected header 放 `kid="attacker"`，对含两个条目的 JWKS 调 `VerifyMulti` | `Protected.KeyID=""`、`Unprotected.KeyID="attacker"`、merged `Header.KeyID="attacker"`；验证成功且 `idx=0`；改用固定签发者公钥则验签失败 | ② 的选钥受未认证输入影响（5.2） |
| 4 | 只篡改 unprotected 自定义头 `tenant`，protected 与签名字节不变 | 篡改前后 `VerifyMulti` 均成功，merged header 中 `tenant` 由 `tenant-A` 变为 `tenant-B` | merged/unprotected 未被认证（5.3） |
| 5 | 嵌套令牌外层解密、内层验签均成功，但 `aud=["billing.example"]`，本服务期望 `api.example` | `Claims.Validate(Expected{AnyAudience:["api.example"]})` 返回 `jwt.ErrInvalidAudience`；不调用 `Validate` 则该跨服务令牌会被接受 | ③ 独立且默认不强制 |
| 6 | 三道闸门全部正确执行（解密→固定密钥验签→`Validate` 带 iss/aud） | 输出 `ACCEPT: sub="alice" iss="https://idp.example" aud=[api.example]` | 正确组合范式 |

判定时可直接依据的库内“硬证据”：

- 解析不验签是文档化行为：`jws.go:91-92`。
- 签名输入不含 unprotected：`jws.go:165-201`。
- `VerifyMulti` 返回索引与签名配对、失败即 `continue`：`signing.go:510-558`。
- merged header 不可信的字段注释：`jws.go:62-75`。
- 受众零值跳过、交集语义：`jwt/validation.go:92-104`。
- `tryJWKS` 用 merged kid 选钥且取 `keys[0]`：`jwk.go:950-963`。

---

## 7. 改进方案

### 7.1 调用方（应用层，无需等库改 API，应立即落地）

1. **固定三段式判定，缺一不可**：
   `ParseSignedAndEncrypted`（显式算法白名单）→ `Decrypt(encKey)` → `inner.Claims(固定签发者密钥, &claims)` → `claims.Validate(Expected{Issuer, AnyAudience: 本服务标识, Time})`。任何一段报错即拒绝，禁止用 `UnsafeClaimsWithoutVerification` / `UnsafePayloadWithoutVerification` 的输出做安全决策。
2. **多签只用返回值**：以 `VerifyMulti` 返回的 `idx`/`Signature` 为唯一可信元数据源；安全相关头部只从 `verifiedSig.Protected` 读取；需要 m-of-n 联名时按期望签发者逐一并行验证，分别核对 protected 中的身份。
3. **不信任令牌自带的选钥提示**：优先直接传入固定签发者公钥/对称密钥，而非整个 JWKS；必须用 JWKS 时，要求 `kid` 出现在 **protected** header 并与预置期望值比对后再验签，且对 JWKS 中的 kid 唯一性做运维约束。
4. **受众显式化**：`Expected.AnyAudience` 永远显式传入本服务标识符，杜绝零值跳过；跨服务令牌按 `aud` 隔离，不共享接受逻辑。
5. **算法白名单最小化**：`ParseSignedAndEncrypted` 的三个算法列表按本协议实际需要收窄（库已在解析期强制 alg/enc 命中白名单，`jwe.go:289-299`、`jws.go:307`，可抵御 alg-confusion，但白名单本身仍需应用收紧）。

### 7.2 库层面（在兼容约束下可分阶段推进）

1. **文档强化**：在 `jwt` 包概览、`NestedJSONWebToken.Decrypt`、`JSONWebToken.Headers`、`tryJWKS` 的 godoc 中显式写明“解密不认证身份”“`Headers`/`Signature.Header` 含未认证字段、验签后只应使用返回的 `Signature.Protected`”“JWKS 模式下 kid 取自 merged header”。
2. **新增带绑定的高层 API**：例如 `JSONWebToken.ClaimsVerified(key, expected, dest...)`，在一次调用内完成验签 + `Validate`（含必填受众），从 API 形态上消除“验签后忘记 Validate”的整类漏洞；保留现有方法以兼容。
3. **多签辅助**：增加 `VerifyAll(keysByKid)` 或联名校验助手，返回每个期望签发者的验证结果与受保护头部，减少调用方自行拼装索引逻辑出错的概率。
4. **选钥硬化（可选/带开关）**：提供选项让 `tryJWKS` 仅接受 protected 中的 `kid`（而非 merged），并在同 kid 多 JWK 时返回歧义错误而非静默取 `keys[0]`；默认行为可保持不变以兼容，通过新选项/新函数迁移。
5. **`Header` 字段可发现性**：考虑在 `Signature.Header` 的 godoc 或静态检查层面进一步标注“非安全用途”，或提供 `Signature.AuthenticatedHeader()` 之类显式访问器，把 `Protected` 与 merged 视图在命名上彻底区分。
6. **嵌套令牌便捷构造/解析配对**：为 signed-then-encrypted 提供一个同时要求内层签名密钥与 `Expected` 的解析入口，使第 7.1 节的三段式成为默认路径而非需要开发者记忆的流程。

---

## 8. 一句话总结

> 在 go-jose v4 的现有兼容行为里，**JWE 解密、JWS 验签、Claims 受众校验是三道责任独立、先后衔接但互不替代的闸门**。解密成功后必须用固定签发者密钥完成内层验签，且只接受 `VerifyMulti` 返回索引所绑定的 `Signature.Protected` 与已验证 payload；随后必须由调用方显式完成以 `AnyAudience` 为核心的 `Validate`。把解密当认证、按错索引或 merged/unprotected 头部取签名元数据、跳过受众校验，分别对应内层伪造、选钥被未认证输入操纵、跨服务令牌误用三类可实测的认证绕过面。
