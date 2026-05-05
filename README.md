# YuSQL - Burp Suite SQL Injection Assistant Plugin

基于 Burp Montoya API 开发的 SQL 注入辅助测试插件（中文界面）。

## 版本

**v2.1.0** | 2026-05-05

## 功能模块

| 模块 | 说明 |
|------|------|
| 布尔注入 | 固定 payload（`'`, `''`, `'''`, `''''`），核心判定 R1==R3 && R1!=R2 |
| 报错注入 | 用户自定义 POC（默认 `\`），使用 SQL 报错正则匹配响应 |
| 追加参数测试 | 可分组追加参数，检测响应变化，支持重复 key 去重/溢出 |
| 排序注入 | 5 步流程检测 ORDER BY 注入（常规命中 / 逗号过滤兜底），响应体归一化对比 |

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

## 排序注入流程

```
R0(原始) vs R1(追加基线) → 归一化对比
R2(→1) vs R1 → 确认 1 值是否稳定
R3(→1,aaa) vs R2 → 确认逗号参数是否生效
R4(→1,CURRENT_TIMESTAMP) vs R2 → 常规命中判定
  如果 R4==R3 → 疑似逗号过滤 → 进入兜底
    R5(→CURRENT_TIMESTAMP) vs R2
    R6(→aaa) 反证测试
```

## 使用方式

- **右键菜单**：发送到 YuSQL / 强制重新扫描
- **监控模式**：可开启 Proxy / Repeater 自动扫描
- **过滤规则**：域名黑名单 > 域名白名单 > URL 黑名单 > 参数黑名单 > 参数白名单

## 技术栈

- Java 17
- Burp Montoya API 2026.4
- Maven 3.9+
