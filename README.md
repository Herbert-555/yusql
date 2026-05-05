# YuSQL - Burp Suite SQL Injection Assistant Plugin

基于 Burp Montoya API 开发的 SQL 注入辅助测试插件（中文界面）。

## 版本

**v2.1.0** | 2026-05-05

## 功能模块

| 模块 | 说明 |
|------|------|
| 布尔注入 | 引号奇偶性判别，3 步短路流程（R1→R3→R2），核心判定 R1≠R0 && R1==R3 && R2≠R1 |
| 报错注入 | 用户自定义 POC（默认 `\`），使用 SQL 报错正则匹配响应 |
| 追加参数测试 | 可分组追加参数，检测响应变化，支持重复 key 去重/溢出 |
| 排序注入 | 6 步流程检测 ORDER BY 注入（常规命中 / 逗号过滤兜底），响应体归一化对比 |

## 布尔注入流程

通过不同数量单引号（奇偶性）触发 SQL 语法差异来判定盲注：

```
          发送 R1(') ─── R1==R0(无变化) ──→ 跳过（不存在注入）
               │
          R1≠R0（有变化）
               │
               ▼
          发送 R3(''') ── R3≠R1 ──→ 跳过（奇偶不一致，非布尔注入）
               │
          R3==R1（同奇偶引号响应一致）
               │
               ▼
          发送 R2('') ── R2==R1 ──→ 跳过（偶数引号无差异，非布尔注入）
               │
          R2≠R1（偶数引号响应不同）
               │
               ▼
          ★ 布尔注入成立
```

### 判定原理

| 引号数量 | 拼接到 SQL 中的效果 | 预期 |
|---------|-------------------|------|
| `'` (1个，R1) | `WHERE id='1''` → 奇数引号，语法错误 | 与 R0 不同 |
| `'''` (3个，R3) | `WHERE id='1''''` → 奇数引号，语法错误 | 与 R1 相同 |
| `''` (2个，R2) | `WHERE id='1'''` → 偶数引号，语法闭合 | 与 R1/R3 不同 |

### 案例

```
GET /api/user?id=1

注入点：id 参数（数值型拼接到 SQL）

R0 (原始请求)： 200 OK  body="{"name":"admin"}"
R1 (id=1')：    500     body="You have an error in your SQL syntax near ''' ..."
  → R1≠R0，继续测试

R3 (id=1''')：  500     body="You have an error in your SQL syntax near ''''' ..."
  → R3==R1（同为奇数引号报错），继续测试

R2 (id=1'')：   200 OK  body="{"name":"admin"}"
  → R2≠R1（偶数引号闭合后恢复正常）
  → ★ 布尔注入成立！id 参数存在 SQL 注入
```

## 排序注入流程

向请求中追加排序参数，逐步替换参数值，通过响应体归一化对比检测 ORDER BY 注入点：

```
R0(原始请求)  vs  R1(追加基线)
       │               │
       └── R0==R1 ──→ 跳过
              │
         R0≠R1
              │
              ▼
R2(→1)  vs  R1 ── R2==R1 ──→ 跳过（1值不生效）
              │
         R2≠R1（排序生效）
              │
              ▼
R3(→1,aaa)  vs  R2 ── R3==R2 ──→ 跳过（逗号参数不生效）
              │
         R3≠R2（逗号生效）
              │
              ▼
R4(→1,CURRENT_TIMESTAMP)  vs  R2
       │                 │
       │    R4==R2 ─────→ ★ 常规命中
       │
  R4≠R2 ──→ 检查 R4 vs R3
              │
         R4≠R3 ──→ 跳过（均不相等，不存在注入）
         R4==R3 ──→ 疑似逗号过滤，进入兜底
              │
              ▼
         R5(→CURRENT_TIMESTAMP)  vs  R2
              │
         R5≠R2 ──→ 跳过
         R5==R2 ──→ 继续
              │
              ▼
         R6(→aaa)  vs  R2 且  vs  R5
              │
         R6≠R2 且 R6≠R5 ──→ ★ 逗号过滤兜底命中
         否则 ──→ 跳过（aaa 反证不通过）
```

### 各步骤含义

| 步骤 | 参数值 | 作用 |
|------|--------|------|
| R1 | 原始值（如 `price`） | 追加基线，确认参数生效 |
| R2 | `1` | 替换为数值 1，确认排序值变化会影响响应 |
| R3 | `1,aaa` | 含逗号的值，确认逗号未被过滤 |
| R4 | `1,CURRENT_TIMESTAMP` | 含时间函数，若响应同 R2 → 函数执行成功 |
| R5 | `CURRENT_TIMESTAMP` | 单值时间函数（逗号过滤兜底），若同 R2 → 函数值生效 |
| R6 | `aaa` | 反证：随机字符串，确保 R5 不是碰巧一致 |

### 案例

```
GET /shop/list?cat=1
追加参数：sort=price（归入排序测试）

R1 (sort=price)：              body="苹果,香蕉,橘子"        （按价格）
R2 (sort=1)：                  body="橘子,苹果,香蕉"        （按第1列，排序改变）
  → R2≠R1，排序值变化确实影响响应

R3 (sort=1,aaa)：              body="橘子,苹果,香蕉"
  → R3≠R2（1,aaa 可能是非法排序但仍按第1列），但差异存在说明逗号被接受

R4 (sort=1,CURRENT_TIMESTAMP)：body="橘子,苹果,香蕉"
  → R4==R2，CURRENT_TIMESTAMP 被解析为常量，与 1 同效
  → ★ 排序注入成立！（常规命中）
```

**逗号过滤兜底场景：**

```
R4 (sort=1,CURRENT_TIMESTAMP)：body="错误：非法排序参数"
  → R4≠R2，但 R4==R3（逗号被过滤，两个含逗号的值都报错）

R5 (sort=CURRENT_TIMESTAMP)：   body="橘子,苹果,香蕉"      （无逗号，正常）
  → R5==R2，函数值单独生效

R6 (sort=aaa)：                 body="错误：未知列名"
  → R6≠R2 且 R6≠R5，并非所有值都返回相同结果
  → ★ 排序注入成立！（逗号过滤兜底）
```

### 归一化说明

每一步对比前都会从响应体中移除参数名和参数值，再进行标准化（去除空白、时间戳等动态内容），确保判定不受参数值字面量影响。

## 参数支持

- GET 查询参数
- POST form 参数 (`application/x-www-form-urlencoded`)
- JSON body value
- GET/POST form 中参数值为 JSON (`JSON_IN_PARAM`)

## 构建

**前置要求：** JDK 17+

```bat
set JAVA_HOME=C:\Program Files\Java\jdk-17
mvn clean package
```

输出：`target/yusql-2.1.0.jar`

## Burp 加载

1. Burp Suite → Extensions → Add
2. Extension Type: Java
3. 选择 `yusql-2.1.0.jar`

## 配置目录

```
~/.yusql/
├── SQL_settings.ini              # 主配置
├── SQL_diy_error.ini             # SQL 报错正则（103 条默认规则）
├── SQL_append_params.ini         # 追加参数（113 条默认，含 JSON 值示例）
├── SQL_append_params_groups.ini  # 追加参数分组
├── SQL_order_injection_params.ini# 排序注入测试参数（默认全选）
├── SQL_error_pocs.ini            # 报错注入 POC
├── SQL_noise_regex.ini           # 响应去噪正则
├── SQL_param_blacklist.ini       # 参数黑名单
├── SQL_url_blacklist.ini         # URL 黑名单（123 条默认规则）
├── SQL_domain_blacklist.ini      # 域名黑名单
├── SQL_domain_whitelist.ini      # 域名白名单
└── SQL_param_whitelist.ini       # 参数白名单
```

## 使用方式

- **右键菜单**：发送到 YuSQL / 强制重新扫描
- **监控模式**：可开启 Proxy / Repeater 自动扫描
- **过滤规则**：域名黑名单 > 域名白名单 > URL 黑名单 > 参数黑名单 > 参数白名单

## 技术栈

- Java 17
- Burp Montoya API 2026.4
- Maven 3.9+