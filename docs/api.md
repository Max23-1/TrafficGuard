# 流量哨兵 · 本机 API 契约

控制台前端（`web/`）通过本机 HTTP 服务读取数据。服务只监听 `127.0.0.1`。

- 页面：`GET /`（服务端会把 HTML 中的 `__TG_TOKEN__` 替换成真实令牌）
- 静态资源：`GET /static/<file>`
- 写操作：`POST /api/**`，请求头必须带 `X-TG-Token: <token>`，`Content-Type: application/json`
- 读操作：`GET /api/**` 无需令牌

前端令牌获取方式：页面内有一段 `<script>window.__TG_TOKEN__="__TG_TOKEN__";</script>`，由服务端替换。

---

## GET /api/live

主轮询接口（建议 2 秒一次），一次性返回状态、流向、国家分布、进程排行。

```json
{
  "status": { ...见下... },
  "flows": { "flows": [ ... ], "total": 128, "lan_conns": 22 },
  "countries": [ ... ],
  "processes": [ ... ],
  "ts": 1792177116.0
}
```

## status 对象

```json
{
  "app": {
    "name": "流量哨兵", "version": "1.0.0", "uptime": 3600, "started_at": 1792177116.0,
    "admin": true, "firewall_ok": true, "simulate": false
  },
  "net": {
    "rx_rate": 102400.0, "tx_rate": 20480.0,
    "session_rx": 12345678, "session_tx": 2345678,
    "day_in": 123456789, "day_out": 23456789,
    "month_in": 1234567890, "month_out": 234567890,
    "interfaces": [{ "name": "WLAN 2", "desc": "Intel(R) Wi-Fi 6 AX101", "mac": "B0:DC:EF:D3:E7:58",
                     "speed": 1200000000, "rx": 269324063, "tx": 3892653945, "virtual": false }]
  },
  "policy": { "mode": "standard", "auto_block_enabled": true, "auto_block_threshold": 70,
              "alert_threshold": 40, "block_scope": "process", "alert_timeout_sec": 60 },
  "geo": { "available": true, "path": "data/GeoLite2-Country.mmdb", "error": null,
           "database_type": "GeoLite2-Country", "built_epoch": 1792177116, "loaded_at": 1792177116.0, "cached": 42 },
  "risk": {
    "score": 30, "level": "medium", "level_cn": "中危",
    "findings": [{ "kind": "vpn_adapter", "level": "medium", "score": 30,
                   "title": "存在已启用的虚拟专用网卡", "detail": "Radmin VPN（...）",
                   "advice": "虚拟网卡通常意味着流量隧道；请确认其用途与合规性。" }],
    "disclaimer": "本功能仅做技术层面的跨境流量识别与风险提示，不构成法律意见。"
  },
  "counts": { "flows": 36, "all_flows": 58, "overseas": 27, "hmt": 0, "unknown": 2,
              "lan": 22, "high_risk": 0, "blocked_rules": 0, "pending_alerts": 0,
              "events": 5, "suppressed": 0 },
  "kill_switch": false,
  "quota": { "enabled": false, "daily_gb": 0, "monthly_gb": 0, "warn_percent": 90,
             "day_used": 1234, "month_used": 4321, "day_percent": 0, "month_percent": 0 },
  "alerts": [ ...见 alert 对象... ],
  "blocked": [{ "name": "TG-BLK-xxxx", "ip": "1.2.3.4", "process": "C:\\x.exe",
                "process_name": "x.exe", "created": 1792177116.0, "score": 75 }],
  "tick": 512, "ts": 1792177116.0
}
```

## flow 对象（flows.flows[]）

```json
{
  "id": "TCP|10.0.0.2:50000|1.2.3.4:443|1234",
  "proto": "TCP", "local_ip": "10.0.0.2", "local_port": 50000,
  "remote_ip": "1.2.3.4", "remote_port": 443,
  "pid": 1234, "process": "chrome.exe", "state": "ESTABLISHED",
  "country": "美国", "country_cn": "美国", "iso": "US", "scope": "OVERSEAS",
  "score": 45, "level": "medium", "level_cn": "中危",
  "reasons": ["目的地为境外（美国）"], "tags": ["overseas"],
  "action": "alert", "rx": 12000.0, "tx": 34000.0, "rx_rate": 800.0, "tx_rate": 1200.0,
  "first_seen": 1792177116.0, "last_seen": 1792177200.0,
  "status": "normal", "conns": 2
}
```

- `scope` 取值：`DOMESTIC` 中国大陆 / `HMT` 中国港澳台 / `OVERSEAS` 境外 / `LAN` 局域网 / `UNKNOWN` 未知
- `level` 取值：`high` 高危 / `medium` 中危 / `low` 关注 / `info` 正常
- `status` 取值：`normal` / `pending`（待机主决定）/ `blocked`（已截流）/ `trusted`（已放行）

## countries[]

```json
{ "iso": "US", "country_cn": "美国", "scope": "OVERSEAS", "flows": 7,
  "rx": 1000.0, "tx": 2000.0, "risk_max": 45, "processes": ["OneDrive.exe"], "percent": 12.5 }
```

## processes[]

```json
{ "process": "chrome.exe", "pid": 1234, "flows": 8, "rx": 1000.0, "tx": 2000.0,
  "risk_max": 45, "countries": ["美国", "日本"] }
```

## events[]

```json
{ "id": "uuid", "ts": 1792177116.0, "kind": "flow", "level": "medium", "score": 45,
  "title": "chrome.exe → 1.2.3.4:443（美国）", "detail": "目的地为境外（美国）",
  "process": "chrome.exe", "pid": 1234, "ip": "1.2.3.4", "port": 443,
  "country_iso": "US", "country_cn": "美国", "action": "alert",
  "state": "open", "extra": {} }
```

`kind`：`flow` / `quota` / `control` / `proxy_listen` / `proxy_process` / `vpn_adapter` / `system_proxy`
`state`：`open` / `blocked` / `continued` / `timeout` / `done` / `failed` / `suppressed`

## alert 对象

```json
{ "id": "uuid", "created": 1792177116.0, "deadline": 1792177176.0, "status": "blocked",
  "risk": { "score": 75, "level": "high", "level_cn": "高危",
            "reasons": ["目的地为境外（美国）", "该连接由代理/翻墙类客户端发起（命中特征：clash）"],
            "action": "block", "tags": ["overseas", "proxy-process"] },
  "flow": { "process": "clash.exe", "pid": 4321, "remote_ip": "1.2.3.4", "remote_port": 443,
            "country_cn": "美国", "iso": "US", "scope": "OVERSEAS", "proto": "TCP" },
  "block": { "ok": true, "hint": null },
  "rule": "TG-BLK-xxxx" }
```

---

## 写操作

### POST /api/decide

```json
{ "id": "<alert id>", "decision": "continue" | "block" }
```
`continue` = 解除拦截并继续连接（该 IP/进程 30 分钟内不再提示）；`block` = 保持断开。
返回 `{ "ok": true, "decision": "continue" }`。

### POST /api/control

```json
{ "action": "kill_switch_on" | "kill_switch_off" | "clear_blocks" | "unblock" | "update_geoip" | "clear_events" | "shutdown",
  "name": "<规则名，unblock 时需要>" }
```
返回 `{ "ok": true, ... }`，失败时带 `hint`（多为「需要管理员权限」）。

### POST /api/config

```json
{ "patch": { "policy": { "mode": "strict" }, "quota": { "enabled": true, "daily_gb": 2 } } }
```
patch 会与现有配置深合并。返回 `{ "ok": true, "config": {...} }`。

### POST /api/whitelist

```json
{ "kind": "process" | "ip", "value": "chrome.exe" | "1.2.3.4", "action": "add" | "remove" }
```

### POST /api/geoip/update

无参数，重新下载 GeoLite2-Country 数据库。返回 `{ "ok": true, "size": 3408573 }`。

## GET 其它

- `GET /api/status`、`/api/flows?limit=300&sort=risk|traffic|country`、
  `/api/countries`、`/api/processes`、`/api/events?limit=120`、
  `/api/alerts`、`/api/config`、`/api/geoip`
