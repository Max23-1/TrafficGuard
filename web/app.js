/* ============================================================
 * 流量哨兵 · Web 控制台
 * 纯原生 JS（ES2018+），完全离线可用，无任何外部依赖。
 * 结构：state（状态）/ fmt（格式化）/ api（接口）/ render（渲染）/ tabs（导航）
 * ============================================================ */
(function () {
  'use strict';

  /* ============================ 常量 ============================ */
  var TABS = ['overview', 'flows', 'events', 'settings'];

  var LEVEL_CN = { high: '高危', medium: '中危', low: '关注', info: '正常' };
  var LEVEL_COLOR = { high: '#e5484d', medium: '#f5a524', low: '#3e8ef7', info: '#30a46c' };
  var SCOPE_CN = { DOMESTIC: '中国大陆', HMT: '中国港澳台', OVERSEAS: '境外', LAN: '局域网', UNKNOWN: '未知' };
  var SCOPE_RANK = { OVERSEAS: '0', HMT: '1', UNKNOWN: '2', DOMESTIC: '3', LAN: '4' };
  var STATUS_CN = { normal: '正常', pending: '待决定', blocked: '已截流', trusted: '已放行' };
  var STATE_CN = {
    open: '待处理', blocked: '已拦截', continued: '已继续',
    timeout: '超时', done: '已忽略', failed: '失败', suppressed: '已抑制'
  };
  var KIND_CN = {
    flow: '流量', quota: '配额', control: '控制', proxy_listen: '代理监听',
    proxy_process: '代理进程', vpn_adapter: '虚拟网卡', system_proxy: '系统代理'
  };
  var MODE_CN = { standard: '标准', strict: '严格', monitor: '监控' };
  var MODE_NOTE = {
    standard: '标准：风险分 ≥ 自动截流阈值时自动断流，达到告警阈值仅提醒机主。日常办公推荐。',
    strict: '严格：风险分 ≥ 告警阈值即可能自动断流，拦截更激进，误伤概率也更高。',
    monitor: '监控：只记录与提醒，从不自动断流，适合先观察一段时间再决定策略。'
  };

  var PRESET = {
    risk: { key: 'score', desc: true },
    traffic: { key: 'rate', desc: true },
    country: { key: 'country', desc: false }
  };

  var GAUGE_LEN = 2 * Math.PI * 62;   // 仪表环周长（r = 62）

  /* ============================ 状态 ============================ */
  var state = {
    tab: 'overview',
    online: null,        // null 未知 / true 在线 / false 断开
    live: null,          // /api/live 最近一次结果
    lastOk: 0,           // 最近一次成功时间（ms）
    timer: null,
    polling: false,
    config: null,
    configLoaded: false,
    configDirty: false,
    events: [],
    eventsAt: 0,
    spark: { rx: [], tx: [] },
    flow: { preset: 'risk', key: 'score', desc: true, search: '', lan: false },
    disclaimerOpen: false
  };

  /* ============================ 通用工具 ============================ */
  function $(id) { return document.getElementById(id); }

  function text(id, value) {
    var node = typeof id === 'string' ? document.getElementById(id) : id;
    if (!node) return;
    node.textContent = value == null ? '' : String(value);
  }

  function el(tag, className, value) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (value != null) node.textContent = String(value);
    return node;
  }

  function clear(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function emptyInto(node, message) {
    clear(node);
    node.appendChild(el('div', 'empty', message));
  }

  function pad2(n) { return n < 10 ? '0' + n : String(n); }

  function clampPercent(value) {
    var n = Number(value);
    if (!isFinite(n)) return 0;
    return Math.max(0, Math.min(100, n));
  }

  /** 按钮忙碌保护：同一按钮在请求返回前不再响应 */
  async function withBusy(btn, task) {
    if (!btn) return task();
    if (btn.classList.contains('is-busy')) return undefined;
    btn.classList.add('is-busy');
    try {
      return await task();
    } finally {
      btn.classList.remove('is-busy');
    }
  }

  /* ============================ 格式化 ============================ */
  var fmt = {
    /** 字节：1024 进制，B 取整，其余保留 1-2 位小数 */
    bytes: function (value) {
      var n = Number(value);
      if (!isFinite(n) || n <= 0) return '0 B';
      var units = ['B', 'KB', 'MB', 'GB', 'TB'];
      var i = 0;
      while (n >= 1024 && i < units.length - 1) { n = n / 1024; i += 1; }
      var digits = i === 0 ? 0 : (n < 10 ? 2 : 1);
      return n.toFixed(digits) + ' ' + units[i];
    },

    rate: function (value) {
      return fmt.bytes(value) + '/s';
    },

    /** HH:mm:ss（入参为秒级时间戳） */
    clock: function (ts) {
      var d = new Date((Number(ts) || 0) * 1000);
      if (!isFinite(d.getTime())) return '—';
      return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    },

    /** YYYY-MM-DD HH:mm:ss */
    full: function (ts) {
      var d = new Date((Number(ts) || 0) * 1000);
      if (!isFinite(d.getTime())) return '—';
      return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
        ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    },

    /** 刚刚 / 3 分钟前 / HH:mm:ss */
    ago: function (ts) {
      var t = Number(ts) || 0;
      if (!t) return '—';
      var diff = Math.max(0, Math.floor(Date.now() / 1000 - t));
      if (diff < 45) return '刚刚';
      if (diff < 3600) return Math.max(1, Math.floor(diff / 60)) + ' 分钟前';
      return fmt.clock(t);
    },

    /** IPv6 缩短：前 3 组 + … + 后 2 组；IPv4 与 IPv4-mapped 原样 */
    addr: function (ip) {
      var s = String(ip == null ? '' : ip);
      if (!s) return '—';
      if (s.indexOf(':') < 0) return s;
      if (s.length <= 24) return s;   // 短地址（如 fe80::1）无需压缩
      var mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
      if (mapped) return mapped[1];
      var base = s.split('%')[0];
      var groups;
      if (base.indexOf('::') >= 0) {
        var halves = base.split('::');
        var head = halves[0] ? halves[0].split(':') : [];
        var tail = halves[1] ? halves[1].split(':') : [];
        var fill = [];
        for (var i = 0; i < Math.max(1, 8 - head.length - tail.length); i += 1) fill.push('0');
        groups = head.concat(fill, tail);
      } else {
        groups = base.split(':');
      }
      if (groups.length <= 6) return s;
      return groups.slice(0, 3).join(':') + '…' + groups.slice(-2).join(':');
    },

    /** 地址 + 端口 */
    endpoint: function (ip, port) {
      var shortIp = fmt.addr(ip);
      if (port == null || port === '') return shortIp;
      return shortIp + ':' + port;
    },

    pct: function (value) {
      var n = Number(value);
      if (!isFinite(n) || n <= 0) return '0%';
      if (n >= 99.95) return '100%';
      return n.toFixed(1) + '%';
    }
  };

  /* ============================ 接口封装 ============================ */
  /**
   * 读取访问令牌。
   * 首选服务端注入的 window.__TG_TOKEN__；若服务端用的是全局字符串替换
   * （会把属性名也一起替换掉），再退回 <meta name="tg-token"> 的兜底来源。
   */
  function readToken() {
    var direct = window.__TG_TOKEN__;
    if (typeof direct === 'string' && direct && direct !== '__TG_TOKEN__') return direct;
    var meta = document.querySelector('meta[name="tg-token"]');
    var value = meta ? (meta.getAttribute('content') || '') : '';
    if (value && value !== '__TG_TOKEN__') return value;
    return '';
  }

  async function getJSON(path) {
    var res = await fetch(path, {
      cache: 'no-store',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin'
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }

  /** 统一写操作：自带令牌头 + JSON 请求体，失败抛出带后端提示的错误 */
  async function api(path, body) {
    var res = await fetch(path, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-TG-Token': readToken()
      },
      body: JSON.stringify(body || {})
    });
    var data = null;
    try { data = await res.json(); } catch (err) { data = null; }
    if (!res.ok || !data || data.ok === false) {
      var message = (data && (data.error || data.hint)) || ('请求失败（HTTP ' + res.status + '）');
      var error = new Error(message);
      error.status = res.status;
      error.data = data;
      throw error;
    }
    return data;
  }

  /* ============================ Toast ============================ */
  function toast(message, kind) {
    var box = $('toasts');
    if (!box) return;
    while (box.children.length >= 3) box.removeChild(box.firstChild);

    var item = el('div', 'toast toast-' + (kind || 'info'));
    var icon = el('span', 'toast-icon', kind === 'ok' ? '✓' : (kind === 'err' ? '!' : 'i'));
    var msg = el('span', 'toast-msg', message);
    item.appendChild(icon);
    item.appendChild(msg);
    box.appendChild(item);

    var timer = window.setTimeout(dismiss, 3000);

    function dismiss() {
      window.clearTimeout(timer);
      if (!item.parentNode) return;
      item.classList.add('is-out');
      window.setTimeout(function () {
        if (item.parentNode) item.parentNode.removeChild(item);
      }, 200);
    }

    item.addEventListener('click', dismiss);
  }

  /* ============================ 小标签 ============================ */
  function levelChip(level, label) {
    return el('span', 'chip lv-' + (level || 'info'), label || LEVEL_CN[level] || level || '—');
  }

  function scopeChip(scope) {
    var key = scope || 'UNKNOWN';
    return el('span', 'chip sc-' + String(key).toLowerCase(), SCOPE_CN[key] || key);
  }

  function statusChip(status) {
    var key = status || 'normal';
    return el('span', 'chip st-' + key, STATUS_CN[key] || key);
  }

  /* ============================ 渲染：状态条 ============================ */
  function renderStatusBar() {
    var st = state.live && state.live.status ? state.live.status : null;
    var app = (st && st.app) || {};

    var dot = $('st-dot');
    if (dot) {
      dot.className = 'dot ' + (state.online === true ? 'dot-ok' : (state.online === false ? 'dot-bad' : 'dot-idle'));
    }

    text('st-online', state.online === true ? '服务在线'
      : (state.online === false ? '与本地服务断开，正在重试' : '正在连接…'));

    var admin = $('st-admin');
    if (admin) {
      admin.textContent = app.admin === true ? '已获取' : (app.admin === false ? '未获取' : '—');
      admin.className = app.admin === false ? 'warn-text' : '';
    }

    var mode = st && st.policy ? st.policy.mode : '';
    text('st-mode', mode ? (MODE_CN[mode] || mode) : '—');

    var geo = st && st.geo ? st.geo : null;
    text('st-geo', !geo ? '—' : (geo.available ? '可用' : (geo.error ? '不可用' : '未加载')));

    text('st-updated', state.lastOk ? fmt.clock(state.lastOk / 1000) : '—');

    var kill = $('st-kill');
    if (kill) kill.hidden = !(st && st.kill_switch);

    var notes = [];
    if (app.simulate) notes.push('防火墙模拟模式');
    if (st && st.counts && st.counts.lan) notes.push('局域网连接 ' + st.counts.lan + ' 条');
    if (state.online === false && state.lastOk) notes.push('最后更新 ' + fmt.ago(state.lastOk / 1000));
    text('st-note', notes.join(' · '));

    text('ft-version', app.version ? 'v' + app.version : 'v—');
  }

  function renderOffline(offline) {
    var bar = $('offline-bar');
    if (bar) bar.hidden = !offline;
  }

  /* ============================ 渲染：Sparkline ============================ */
  function hexToRgba(hex, alpha) {
    var h = String(hex || '').replace('#', '');
    if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
    var num = parseInt(h, 16);
    if (!isFinite(num)) return 'rgba(62,142,247,' + alpha + ')';
    return 'rgba(' + ((num >> 16) & 255) + ',' + ((num >> 8) & 255) + ',' + (num & 255) + ',' + alpha + ')';
  }

  function drawSpark(canvas, series, color) {
    if (!canvas) return;
    var width = canvas.clientWidth;
    var height = canvas.clientHeight || 34;
    if (!width || !height) return;

    var dpr = window.devicePixelRatio || 1;
    var pxW = Math.round(width * dpr);
    var pxH = Math.round(height * dpr);
    if (canvas.width !== pxW) canvas.width = pxW;
    if (canvas.height !== pxH) canvas.height = pxH;

    var ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    // 基线
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, height - 1);
    ctx.lineTo(width, height - 1);
    ctx.stroke();

    var n = series ? series.length : 0;
    if (n < 2) return;

    var max = 0;
    var min = Infinity;
    for (var i = 0; i < n; i += 1) {
      if (series[i] > max) max = series[i];
      if (series[i] < min) min = series[i];
    }
    if (max <= 0) return;                       // 无流量：只保留基线

    var flat = (max - min) < 1e-9;              // 恒定速率：居中画一条平线
    var scaleMax = flat ? max * 2 : max * 1.06;

    var step = width / (n - 1);
    var padTop = 4;
    var usable = height - padTop - 2;

    function px(index) { return index * step; }
    function py(value) { return padTop + usable - (value / scaleMax) * usable; }

    if (!flat && n >= 6) {
      // 面积只在实际有波动时绘制，避免初始 1-2 个采样点看起来像色块
      ctx.beginPath();
      ctx.moveTo(px(0), height - 2);
      for (var a = 0; a < n; a += 1) ctx.lineTo(px(a), py(series[a]));
      ctx.lineTo(px(n - 1), height - 2);
      ctx.closePath();
      var grad = ctx.createLinearGradient(0, 0, 0, height);
      grad.addColorStop(0, hexToRgba(color, 0.22));
      grad.addColorStop(1, hexToRgba(color, 0));
      ctx.fillStyle = grad;
      ctx.fill();
    }

    // 折线
    ctx.beginPath();
    for (var b = 0; b < n; b += 1) {
      var x = px(b);
      var y = py(series[b]);
      if (b === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.stroke();

    // 末端点
    ctx.beginPath();
    ctx.arc(px(n - 1), py(series[n - 1]), 2.4, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
  }

  function drawSparks() {
    drawSpark($('spark-rx'), state.spark.rx, '#3e8ef7');
    drawSpark($('spark-tx'), state.spark.tx, '#30a46c');
  }

  function pushSpark(net) {
    if (!net) return;
    state.spark.rx.push(Number(net.rx_rate) || 0);
    state.spark.tx.push(Number(net.tx_rate) || 0);
    if (state.spark.rx.length > 60) state.spark.rx.splice(0, state.spark.rx.length - 60);
    if (state.spark.tx.length > 60) state.spark.tx.splice(0, state.spark.tx.length - 60);
  }

  /* ============================ 渲染：概览 ============================ */
  function renderOverview() {
    var st = state.live && state.live.status ? state.live.status : null;
    var net = (st && st.net) || {};
    var counts = (st && st.counts) || {};

    text('kpi-rx', st ? fmt.rate(net.rx_rate) : '—');
    text('kpi-tx', st ? fmt.rate(net.tx_rate) : '—');

    var dayIn = Number(net.day_in) || 0;
    var dayOut = Number(net.day_out) || 0;
    text('kpi-day', st ? fmt.bytes(dayIn + dayOut) : '—');
    text('kpi-day-sub', st ? '↓ ' + fmt.bytes(dayIn) + ' · ↑ ' + fmt.bytes(dayOut) : '等待数据…');

    var monIn = Number(net.month_in) || 0;
    var monOut = Number(net.month_out) || 0;
    text('kpi-month', st ? fmt.bytes(monIn + monOut) : '—');
    text('kpi-month-sub', st ? '↓ ' + fmt.bytes(monIn) + ' · ↑ ' + fmt.bytes(monOut) : '等待数据…');

    text('kpi-conns', st ? String(counts.flows || 0) : '—');
    text('kpi-conns-sub', st
      ? '境外 ' + (counts.overseas || 0) + ' · 跨境 ' + ((counts.overseas || 0) + (counts.hmt || 0)) +
        ' · 高危 ' + (counts.high_risk || 0)
      : '等待数据…');

    text('kpi-blocked', st ? String(counts.blocked_rules || 0) : '—');
    text('kpi-blocked-sub', st ? '待处理提醒 ' + (counts.pending_alerts || 0) : '等待数据…');

    drawSparks();
    renderRisk((st && st.risk) || null);
    renderCountries(state.live && state.live.countries);
    renderAlerts((st && st.alerts) || []);
    renderControl(st);
  }

  function renderRisk(risk) {
    var score = risk ? Math.max(0, Math.min(100, Number(risk.score) || 0)) : 0;
    var level = (risk && risk.level) || 'info';

    var ring = $('gauge-value');
    if (ring) {
      ring.style.strokeDasharray = GAUGE_LEN.toFixed(2);
      ring.style.strokeDashoffset = (GAUGE_LEN * (1 - score / 100)).toFixed(2);
      ring.style.stroke = LEVEL_COLOR[level] || LEVEL_COLOR.info;
    }

    text('risk-score', risk ? String(score) : '--');

    var chip = $('risk-level');
    if (chip) {
      chip.textContent = risk ? (risk.level_cn || LEVEL_CN[level] || level) : '等待数据';
      chip.className = 'chip lv-' + level;
    }

    var list = $('findings');
    if (list) {
      clear(list);
      var findings = (risk && risk.findings) || [];
      if (!findings.length) {
        list.appendChild(el('li', 'empty', risk ? '未发现明显的约谈风险项' : '等待数据…'));
      } else {
        findings.forEach(function (f) {
          var lv = f.level || 'info';
          var item = el('li', 'finding lv-' + lv);

          var head = el('div', 'finding-head');
          head.appendChild(el('span', 'finding-title', f.title || '风险项'));
          if (f.score) head.appendChild(el('span', 'finding-score mono', '+' + f.score));
          item.appendChild(head);

          if (f.detail) item.appendChild(el('p', 'finding-detail', f.detail));
          if (f.advice) item.appendChild(el('p', 'finding-advice', '建议：' + f.advice));
          list.appendChild(item);
        });
      }
    }

    var disclaimer = $('risk-disclaimer');
    if (disclaimer) {
      var word = (risk && risk.disclaimer) || '';
      disclaimer.textContent = word;
      disclaimer.title = word ? word + '（点击展开/收起）' : '';
      disclaimer.hidden = !word;
      disclaimer.classList.toggle('is-clamped', Boolean(word) && !state.disclaimerOpen);
    }
  }

  function renderCountries(countries) {
    var box = $('country-list');
    if (!box) return;
    clear(box);

    if (!countries || !countries.length) {
      emptyInto(box, state.live ? '暂无外联流量' : '等待数据…');
      text('countries-total', '');
      return;
    }

    var totalFlows = 0;
    countries.forEach(function (c) { totalFlows += Number(c.flows) || 0; });
    text('countries-total', countries.length + ' 个地区 · ' + totalFlows + ' 条连接');

    countries.slice(0, 14).forEach(function (c) {
      var row = el('div', 'country-row');
      var line = el('div', 'country-line');
      line.appendChild(el('span', 'country-name', c.country_cn || '未知'));
      line.appendChild(scopeChip(c.scope));

      var nums = el('span', 'country-nums');
      nums.appendChild(el('span', 'country-pct', fmt.pct(c.percent)));
      nums.appendChild(el('span', null, (c.flows || 0) + ' 连接'));
      nums.appendChild(el('span', null, '↓ ' + fmt.bytes(c.rx) + ' · ↑ ' + fmt.bytes(c.tx)));
      line.appendChild(nums);
      row.appendChild(line);

      var track = el('div', 'bar-track');
      var fill = el('div', 'bar-fill fill-' + String(c.scope || 'UNKNOWN').toLowerCase());
      fill.style.width = Math.max(1.5, clampPercent(c.percent)) + '%';
      track.appendChild(fill);
      row.appendChild(track);

      box.appendChild(row);
    });
  }

  function renderAlerts(alerts) {
    var box = $('alert-list');
    if (!box) return;
    clear(box);

    var badge = $('alerts-count');
    if (badge) {
      badge.textContent = String(alerts.length);
      badge.classList.toggle('is-on', alerts.length > 0);
    }

    if (!alerts.length) {
      box.appendChild(el('div', 'empty', state.live ? '暂无待处理提醒' : '等待数据…'));
      return;
    }

    var now = Date.now() / 1000;

    alerts.forEach(function (alert) {
      var flow = alert.flow || {};
      var risk = alert.risk || {};
      var level = risk.level || 'high';

      var card = el('div', 'alert-card');

      var head = el('div', 'alert-head');
      head.appendChild(el('span', 'alert-proc', flow.process || '未知进程'));
      head.appendChild(levelChip(level, risk.level_cn || LEVEL_CN[level] || level));
      if (risk.score != null) head.appendChild(el('span', 'chip lv-' + level, String(risk.score) + ' 分'));

      var deadline = Number(alert.deadline) || 0;
      if (deadline) {
        var left = Math.round(deadline - now);
        head.appendChild(el('span', 'alert-timer mono', left >= 0 ? '剩余 ' + left + ' 秒' : '已超时'));
      }
      card.appendChild(head);

      var meta = el('div', 'alert-meta');
      meta.appendChild(el('span', 'mono', fmt.endpoint(flow.remote_ip, flow.remote_port)));
      meta.appendChild(el('span', null, '归属地 ' + (flow.country_cn || '未知')));
      if (flow.scope) meta.appendChild(scopeChip(flow.scope));
      if (flow.proto) meta.appendChild(el('span', null, flow.proto));
      if (flow.pid) meta.appendChild(el('span', 'mono', 'PID ' + flow.pid));
      card.appendChild(meta);

      var reasons = risk.reasons || [];
      if (reasons.length) {
        var list = el('ul', 'alert-reasons');
        reasons.slice(0, 4).forEach(function (reason) {
          list.appendChild(el('li', null, reason));
        });
        card.appendChild(list);
      }

      var actions = el('div', 'alert-actions');
      var allow = el('button', 'btn btn-primary btn-sm', '继续连接（解除拦截）');
      allow.type = 'button';
      allow.setAttribute('data-decide', 'continue');
      allow.setAttribute('data-id', alert.id);

      var keep = el('button', 'btn btn-danger btn-sm', '保持断开');
      keep.type = 'button';
      keep.setAttribute('data-decide', 'block');
      keep.setAttribute('data-id', alert.id);

      actions.appendChild(allow);
      actions.appendChild(keep);
      card.appendChild(actions);

      box.appendChild(card);
    });
  }

  function renderControl(st) {
    var kill = Boolean(st && st.kill_switch);
    var chip = $('kill-state');
    if (chip) {
      chip.textContent = kill ? '全局断流已开启' : '断流未开启';
      chip.className = 'chip ' + (kill ? 'st-blocked' : 'st-normal');
    }

    var warn = $('admin-warning');
    if (warn) warn.hidden = !(st && st.app && st.app.admin === false);

    var actions = ['kill_switch_on', 'kill_switch_off', 'clear_blocks', 'update_geoip'];
    actions.forEach(function (action) {
      var btn = document.querySelector('.control-card [data-action="' + action + '"]');
      if (btn) btn.disabled = state.online !== true;
    });

    var hint = $('control-hint');
    if (hint) {
      if (!st) {
        hint.textContent = '等待数据…';
      } else {
        var parts = ['拦截规则 ' + ((st.counts && st.counts.blocked_rules) || 0) + ' 条'];
        if (st.app && st.app.simulate) parts.push('防火墙：模拟模式');
        else if (!st.app || st.app.admin === false) parts.push('防火墙：未提权');
        else parts.push(st.app.firewall_ok ? '防火墙就绪' : '防火墙异常');
        hint.textContent = parts.join(' · ');
      }
    }
  }

  /* ============================ 渲染：流量流向 ============================ */
  var SORT_GET = {
    process: function (f) { return String(f.process || '').toLowerCase(); },
    remote: function (f) { return String(f.remote_ip || ''); },
    proto: function (f) { return String(f.proto || ''); },
    country: function (f) { return (SCOPE_RANK[f.scope] || '9') + '|' + String(f.country_cn || ''); },
    score: function (f) { return Number(f.score) || 0; },
    conns: function (f) { return Number(f.conns) || 0; },
    rx: function (f) { return Number(f.rx) || 0; },
    tx: function (f) { return Number(f.tx) || 0; },
    rate: function (f) { return (Number(f.rx_rate) || 0) + (Number(f.tx_rate) || 0); },
    status: function (f) { return String(f.status || ''); }
  };

  function matchesFlow(flow, keyword) {
    var fields = [
      flow.process, flow.app, flow.app_company, flow.remote_ip, flow.country_cn,
      flow.country, flow.iso, flow.proto, flow.pid, flow.remote_port, flow.level_cn
    ];
    for (var i = 0; i < fields.length; i += 1) {
      var value = fields[i];
      if (value == null) continue;
      if (String(value).toLowerCase().indexOf(keyword) >= 0) return true;
    }
    return false;
  }

  function sortRows(rows) {
    var key = state.flow.key || 'score';
    var getter = SORT_GET[key] || SORT_GET.score;
    var dir = state.flow.desc ? -1 : 1;
    rows.sort(function (a, b) {
      var va = getter(a);
      var vb = getter(b);
      var result;
      if (typeof va === 'number' && typeof vb === 'number') {
        result = va - vb;
      } else {
        result = String(va).localeCompare(String(vb), 'zh-Hans-CN');
      }
      if (result === 0) {
        var ta = (Number(a.rx) || 0) + (Number(a.tx) || 0);
        var tb = (Number(b.rx) || 0) + (Number(b.tx) || 0);
        result = ta - tb;
      }
      return result * dir;
    });
    return rows;
  }

  function flowSummary(wrap, shown) {
    if (!state.live) return '等待数据…';
    var parts = ['显示 ' + shown + ' 条'];
    if (wrap) parts.push('聚合后 ' + (wrap.total || 0) + ' 条');
    if (state.flow.lan) {
      parts.push(wrap && wrap.lan_conns
        ? '局域网原始连接 ' + wrap.lan_conns + ' 条（后端默认不下发明细）'
        : '未发现局域网连接');
    }
    return parts.join(' · ');
  }

  function emptyFlowText() {
    if (!state.live) return '等待数据…';
    if (state.online === false) return '与本地服务断开，正在重试…';
    if (state.flow.search) return '没有匹配「' + state.flow.search + '」的连接';
    if (state.flow.lan) return '暂时没有可显示的连接';
    return '当前没有活跃的外联连接';
  }

  function buildFlowRow(f) {
    var level = f.level || 'info';
    var score = Math.max(0, Math.min(100, Number(f.score) || 0));
    var tr = document.createElement('tr');

    // 进程 + 所属应用 + PID
    var tdProc = document.createElement('td');
    var procName = f.process || ('PID ' + (f.pid || '?'));
    var proc = el('div', 'cell-main', procName);
    proc.title = [
      procName,
      f.app ? '应用：' + f.app : '',
      f.app_company ? '厂商：' + f.app_company : ''
    ].filter(Boolean).join('\n');
    tdProc.appendChild(proc);

    var subBits = [];
    if (f.app) subBits.push(f.app);
    subBits.push('PID ' + (f.pid == null ? '—' : f.pid));
    var sub = el('div', 'cell-sub', subBits.join(' · '));
    if (f.app) sub.classList.add('cell-app');
    tdProc.appendChild(sub);
    tr.appendChild(tdProc);

    // 远端地址
    var tdRemote = document.createElement('td');
    var ip = String(f.remote_ip || '');
    var port = f.remote_port == null ? '' : String(f.remote_port);
    var addr = el('span', 'mono addr', fmt.endpoint(ip, port || null));
    addr.title = ip ? (ip + (port ? ':' + port : '')) : '—';
    tdRemote.appendChild(addr);
    tr.appendChild(tdRemote);

    // 协议
    var tdProto = document.createElement('td');
    tdProto.appendChild(el('span', 'chip', f.proto || '—'));
    tr.appendChild(tdProto);

    // 归属地
    var tdCountry = document.createElement('td');
    var countryCell = el('div', 'country-cell');
    var countryName = el('span', 'cname', f.country_cn || '未知');
    if (f.iso) countryName.title = f.iso;
    countryCell.appendChild(countryName);
    countryCell.appendChild(scopeChip(f.scope));
    tdCountry.appendChild(countryCell);
    tr.appendChild(tdCountry);

    // 风险
    var tdRisk = document.createElement('td');
    var riskCell = el('div', 'risk-cell');
    var riskBar = el('div', 'risk-bar');
    var riskFill = el('div', 'risk-fill lv-' + level);
    riskFill.style.width = Math.max(1.5, score) + '%';
    riskBar.appendChild(riskFill);
    riskCell.appendChild(riskBar);
    var riskFoot = el('div', 'risk-num');
    riskFoot.appendChild(levelChip(level, (f.level_cn || LEVEL_CN[level] || level) + ' ' + score));
    riskCell.appendChild(riskFoot);
    tdRisk.appendChild(riskCell);
    tr.appendChild(tdRisk);

    // 连接数
    var tdConns = document.createElement('td');
    tdConns.className = 'mono';
    tdConns.textContent = String(f.conns == null ? 1 : f.conns);
    tr.appendChild(tdConns);

    // 下行 / 上行累计
    var tdRx = document.createElement('td');
    tdRx.className = 'mono';
    tdRx.textContent = fmt.bytes(f.rx);
    tr.appendChild(tdRx);

    var tdTx = document.createElement('td');
    tdTx.className = 'mono';
    tdTx.textContent = fmt.bytes(f.tx);
    tr.appendChild(tdTx);

    // 当前速率
    var tdRate = document.createElement('td');
    var rateCell = el('div', 'rate-cell');
    rateCell.appendChild(el('span', 'down mono', '↓ ' + fmt.rate(f.rx_rate)));
    rateCell.appendChild(el('span', 'up mono', '↑ ' + fmt.rate(f.tx_rate)));
    tdRate.appendChild(rateCell);
    tr.appendChild(tdRate);

    // 状态
    var tdStatus = document.createElement('td');
    tdStatus.appendChild(statusChip(f.status));
    tr.appendChild(tdStatus);

    // 操作
    var tdActions = document.createElement('td');
    tdActions.className = 'col-actions';
    var actions = el('div', 'actions');

    var trustProc = el('button', 'btn btn-ghost btn-xs', '信任此进程');
    trustProc.type = 'button';
    trustProc.setAttribute('data-trust', 'process');
    trustProc.setAttribute('data-value', f.process || '');
    trustProc.disabled = !f.process;

    var trustIp = el('button', 'btn btn-ghost btn-xs', '信任此 IP');
    trustIp.type = 'button';
    trustIp.setAttribute('data-trust', 'ip');
    trustIp.setAttribute('data-value', ip);
    trustIp.disabled = !ip || f.scope === 'LAN';

    actions.appendChild(trustProc);
    actions.appendChild(trustIp);
    tdActions.appendChild(actions);
    tr.appendChild(tdActions);

    return tr;
  }

  function renderFlows() {
    var body = $('flow-body');
    if (!body) return;

    var wrap = state.live && state.live.flows ? state.live.flows : null;
    var all = (wrap && wrap.flows) || [];
    var keyword = state.flow.search.trim().toLowerCase();
    var rows = [];

    for (var i = 0; i < all.length; i += 1) {
      var flow = all[i];
      if (!state.flow.lan && flow.scope === 'LAN') continue;
      if (keyword && !matchesFlow(flow, keyword)) continue;
      rows.push(flow);
    }

    sortRows(rows);
    clear(body);
    text('flow-summary', flowSummary(wrap, rows.length));

    if (!rows.length) {
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      td.colSpan = 11;
      td.appendChild(el('div', 'empty', emptyFlowText()));
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }

    var frag = document.createDocumentFragment();
    rows.forEach(function (flow) { frag.appendChild(buildFlowRow(flow)); });
    body.appendChild(frag);
  }

  function syncSortControls() {
    var segs = document.querySelectorAll('#flow-sorts .seg');
    Array.prototype.forEach.call(segs, function (seg) {
      seg.classList.toggle('is-active', seg.getAttribute('data-sort') === state.flow.preset);
    });
    var ths = document.querySelectorAll('#flow-table thead th[data-key]');
    Array.prototype.forEach.call(ths, function (th) {
      th.classList.remove('sorted-asc', 'sorted-desc');
      if (th.getAttribute('data-key') === state.flow.key) {
        th.classList.add(state.flow.desc ? 'sorted-desc' : 'sorted-asc');
      }
    });
  }

  /* ============================ 渲染：风险事件 ============================ */
  function renderEvents() {
    var list = state.events || [];
    var now = Date.now() / 1000;
    var high = 0;
    var medium = 0;
    var total = 0;
    var blocked = 0;

    list.forEach(function (ev) {
      if (ev.state === 'blocked') blocked += 1;
      if (now - (Number(ev.ts) || 0) <= 86400) {
        total += 1;
        if (ev.level === 'high') high += 1;
        else if (ev.level === 'medium') medium += 1;
      }
    });

    text('ev-high', high);
    text('ev-medium', medium);
    text('ev-total', total);
    text('ev-blocked', blocked);
    text('events-updated', state.eventsAt ? '更新于 ' + fmt.clock(state.eventsAt / 1000) : '—');

    var box = $('event-list');
    if (!box) return;
    clear(box);

    if (!list.length) {
      box.appendChild(el('li', 'empty', state.online === false
        ? '与本地服务断开，正在重试…'
        : '暂无风险事件'));
      return;
    }

    var frag = document.createDocumentFragment();
    list.forEach(function (ev) {
      var level = ev.level || 'info';
      var item = el('li', 'tl-item lv-' + level);
      item.appendChild(el('span', 'tl-dot'));

      var body = el('div', 'tl-body');

      var head = el('div', 'tl-head');
      var time = el('span', 'tl-time mono', fmt.clock(ev.ts));
      time.title = fmt.full(ev.ts);
      head.appendChild(time);
      head.appendChild(el('span', 'tl-title', ev.title || '风险事件'));
      var stateCn = STATE_CN[ev.state] || ev.state || '—';
      head.appendChild(el('span', 'chip ev-' + (ev.state || 'open'), stateCn));
      if (ev.kind) head.appendChild(el('span', 'chip', KIND_CN[ev.kind] || ev.kind));
      body.appendChild(head);

      if (ev.detail) body.appendChild(el('p', 'tl-detail', ev.detail));

      var meta = el('div', 'tl-meta');
      if (ev.process) {
        var procText = ev.process + (ev.app ? '（' + ev.app + '）' : '') + (ev.pid ? ' · PID ' + ev.pid : '');
        meta.appendChild(el('span', null, procText));
      }
      if (ev.ip) meta.appendChild(el('span', 'mono', fmt.endpoint(ev.ip, ev.port)));
      if (ev.country_cn) meta.appendChild(el('span', null, ev.country_cn));
      if (ev.score != null) meta.appendChild(el('span', 'mono', '风险分 ' + ev.score));
      body.appendChild(meta);

      item.appendChild(body);
      frag.appendChild(item);
    });
    box.appendChild(frag);
  }

  /* ============================ 渲染：设置 ============================ */
  function fillSettings(cfg) {
    if (!cfg) return;
    var policy = cfg.policy || {};
    var quota = cfg.quota || {};

    var mode = $('mode');
    if (mode) mode.value = policy.mode || 'standard';

    var autoBlock = $('auto-block-threshold');
    if (autoBlock) autoBlock.value = String(policy.auto_block_threshold == null ? 70 : policy.auto_block_threshold);

    var alert = $('alert-threshold');
    if (alert) alert.value = String(policy.alert_threshold == null ? 40 : policy.alert_threshold);

    var scope = $('block-scope');
    if (scope) scope.value = policy.block_scope || 'process';

    var timeout = $('alert-timeout');
    if (timeout) timeout.value = String(policy.alert_timeout_sec == null ? 60 : policy.alert_timeout_sec);

    var maxAlerts = $('max-alerts');
    if (maxAlerts) maxAlerts.value = String(policy.max_alerts_per_minute == null ? 6 : policy.max_alerts_per_minute);

    var quotaOn = $('quota-enabled');
    if (quotaOn) quotaOn.checked = Boolean(quota.enabled);

    var daily = $('quota-daily');
    if (daily) daily.value = String(quota.daily_gb == null ? 0 : quota.daily_gb);

    var monthly = $('quota-monthly');
    if (monthly) monthly.value = String(quota.monthly_gb == null ? 0 : quota.monthly_gb);

    var warn = $('quota-warn');
    if (warn) warn.value = String(quota.warn_percent == null ? 90 : quota.warn_percent);

    var quotaKill = $('quota-kill');
    if (quotaKill) quotaKill.checked = Boolean(policy.auto_kill_switch_on_quota);

    syncRangeOutputs();
    syncModeNote();
    renderWhitelist(cfg.whitelist || {});
    renderSettingsMeta();
    state.configDirty = false;
    text('settings-note', '修改后需保存才会生效');
  }

  function syncRangeOutputs() {
    var autoBlock = $('auto-block-threshold');
    var alert = $('alert-threshold');
    var warn = $('quota-warn');
    if (autoBlock) text('auto-block-out', autoBlock.value);
    if (alert) text('alert-out', alert.value);
    if (warn) text('quota-warn-out', warn.value);
  }

  function syncModeNote() {
    var mode = $('mode');
    text('mode-note', mode ? (MODE_NOTE[mode.value] || '') : '');
  }

  function renderWhitelist(whitelist) {
    fillWlList('wl-processes', whitelist.processes || [], 'process', '暂无信任进程');
    fillWlList('wl-ips', whitelist.ips || [], 'ip', '暂无信任 IP');
  }

  function fillWlList(id, items, kind, emptyText) {
    var box = $(id);
    if (!box) return;
    clear(box);
    if (!items.length) {
      box.appendChild(el('li', 'empty', emptyText));
      return;
    }
    items.forEach(function (value) {
      var li = el('li', 'wl-item');
      var label = el('span', 'wl-value mono', value);
      label.title = value;
      li.appendChild(label);

      var btn = el('button', 'btn btn-ghost btn-xs', '移除');
      btn.type = 'button';
      btn.setAttribute('data-wl-kind', kind);
      btn.setAttribute('data-wl-value', value);
      li.appendChild(btn);

      box.appendChild(li);
    });
  }

  function renderSettingsMeta() {
    var st = state.live && state.live.status ? state.live.status : null;
    var quota = st && st.quota ? st.quota : null;

    if (quota) {
      var dayLimit = Number(quota.daily_gb) || 0;
      var monthLimit = Number(quota.monthly_gb) || 0;

      var dayBar = $('quota-day-bar');
      if (dayBar) dayBar.style.width = (dayLimit > 0 ? clampPercent(quota.day_percent) : 0) + '%';
      var monthBar = $('quota-month-bar');
      if (monthBar) monthBar.style.width = (monthLimit > 0 ? clampPercent(quota.month_percent) : 0) + '%';

      text('quota-day-num', dayLimit > 0 ? fmt.pct(quota.day_percent) : '未设上限');
      text('quota-month-num', monthLimit > 0 ? fmt.pct(quota.month_percent) : '未设上限');
      text('quota-status', quota.enabled
        ? '今日 ' + fmt.bytes(quota.day_used) + ' · 本月 ' + fmt.bytes(quota.month_used)
        : '未启用');
    }

    renderGeo();
  }

  function renderGeo() {
    var geo = state.live && state.live.status ? state.live.status.geo : null;
    if (!geo) return;

    text('geo-state', geo.available ? '可用' : (geo.error ? '不可用' : '未加载'));
    text('geo-type', geo.database_type || '—');
    text('geo-built', geo.built_epoch ? fmt.full(geo.built_epoch) : '—');
    text('geo-cached', geo.cached == null ? '—' : geo.cached);
    text('geo-path', geo.path || '—');

    var err = $('geo-error');
    if (err) {
      err.textContent = geo.error ? '错误：' + geo.error : '';
      err.hidden = !geo.error;
    }
  }

  /* ============================ 数据加载 ============================ */
  async function loadConfig(force) {
    if (state.configLoaded && !force) return state.config;
    try {
      var data = await getJSON('/api/config');
      state.config = (data && data.config) || data || null;
      state.configLoaded = Boolean(state.config);
      return state.config;
    } catch (err) {
      if (force) toast('读取配置失败：' + err.message, 'err');
      return null;
    }
  }

  async function loadEvents(quiet) {
    try {
      var list = await getJSON('/api/events?limit=120');
      state.events = Array.isArray(list) ? list : [];
      state.eventsAt = Date.now();
      if (state.tab === 'events') renderEvents();
      return true;
    } catch (err) {
      if (!quiet) toast('读取事件失败：' + err.message, 'err');
      return false;
    }
  }

  async function ensureSettings() {
    if (!state.configDirty) await loadConfig(true);
    if (state.config && !state.configDirty) fillSettings(state.config);
    renderSettingsMeta();
  }

  /* ============================ 主轮询 ============================ */
  async function tick(force) {
    if (state.polling) return;
    if (document.hidden && !force) return;
    state.polling = true;
    try {
      var data = await getJSON('/api/live');
      state.live = data;
      state.online = true;
      state.lastOk = Date.now();
      pushSpark(data && data.status ? data.status.net : null);
      renderOffline(false);
      renderActive();

      if (state.tab === 'events' && (force || Date.now() - state.eventsAt > 4000)) {
        loadEvents(true);
      }
      if (state.tab === 'settings' && !state.config) loadConfig(true);
    } catch (err) {
      state.online = false;
      renderOffline(true);
      renderStatusBar();
    } finally {
      state.polling = false;
    }
  }

  function startPolling() {
    if (state.timer) return;
    state.timer = window.setInterval(function () { tick(false); }, 2000);
    tick(true);
  }

  function stopPolling() {
    if (state.timer) {
      window.clearInterval(state.timer);
      state.timer = null;
    }
  }

  /* ============================ 渲染入口 ============================ */
  function renderActive() {
    renderStatusBar();
    if (state.tab === 'overview') renderOverview();
    else if (state.tab === 'flows') renderFlows();
    else if (state.tab === 'events') renderEvents();
    else if (state.tab === 'settings') renderSettingsMeta();
  }

  function switchTab(name, silent) {
    if (TABS.indexOf(name) < 0) name = 'overview';
    state.tab = name;

    Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (btn) {
      var on = btn.getAttribute('data-tab') === name;
      btn.classList.toggle('is-active', on);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    Array.prototype.forEach.call(document.querySelectorAll('.view'), function (view) {
      view.classList.toggle('is-active', view.id === 'view-' + name);
    });

    if (!silent) {
      try {
        window.history.replaceState(null, '', '#' + name);
      } catch (err) {
        window.location.hash = name;
      }
    }

    if (name === 'events') loadEvents(true);
    if (name === 'settings') ensureSettings();
    renderActive();
  }

  /* ============================ 写操作 ============================ */
  async function decideAlert(alertId, decision) {
    try {
      await api('/api/decide', { id: alertId, decision: decision });
      toast(decision === 'continue' ? '已解除拦截，继续连接' : '已保持断开', 'ok');
      tick(true);
    } catch (err) {
      toast('处理失败：' + err.message, 'err');
    }
  }

  async function trust(kind, value) {
    if (!value) return;
    try {
      await api('/api/whitelist', { kind: kind, value: value, action: 'add' });
      toast('已加入信任列表：' + value, 'ok');
      if (state.tab === 'settings') {
        await loadConfig(true);
        if (state.config && !state.configDirty) fillSettings(state.config);
      }
      tick(true);
    } catch (err) {
      toast('加入信任失败：' + err.message, 'err');
    }
  }

  async function removeWhitelist(kind, value, btn) {
    await withBusy(btn, async function () {
      try {
        await api('/api/whitelist', { kind: kind, value: value, action: 'remove' });
        toast('已移除：' + value, 'ok');
        await loadConfig(true);
        if (state.config) fillSettings(state.config);
      } catch (err) {
        toast('移除失败：' + err.message, 'err');
      }
    });
  }

  var CONTROL_TOAST = {
    kill_switch_on: '已开启紧急断流',
    kill_switch_off: '已恢复网络',
    clear_blocks: '已清除全部拦截规则',
    update_geoip: 'IP 库已更新'
  };

  async function runControl(action, btn) {
    if (action === 'clear_blocks') {
      if (!window.confirm('确定清除全部拦截规则吗？这会立即解除当前所有截流。')) return;
    }
    await withBusy(btn, async function () {
      try {
        var result = await api('/api/control', { action: action });
        var message = CONTROL_TOAST[action] || '操作已完成';
        if (action === 'update_geoip' && result && result.size) {
          message += '（' + fmt.bytes(result.size) + '）';
        }
        toast(message, 'ok');
        tick(true);
      } catch (err) {
        toast('操作失败：' + err.message, 'err');
      }
    });
  }

  async function updateGeoip(btn) {
    await withBusy(btn, async function () {
      try {
        var result = await api('/api/geoip/update', {});
        toast('IP 库已更新' + (result && result.size ? '（' + fmt.bytes(result.size) + '）' : ''), 'ok');
        tick(true);
      } catch (err) {
        toast('更新 IP 库失败：' + err.message, 'err');
      }
    });
  }

  function collectPatch() {
    function val(id) { var n = $(id); return n ? n.value : ''; }
    function num(id) { var n = Number(val(id)); return isFinite(n) ? n : 0; }
    function checked(id) { var n = $(id); return Boolean(n && n.checked); }

    return {
      policy: {
        mode: val('mode') || 'standard',
        auto_block_threshold: Math.round(num('auto-block-threshold')),
        alert_threshold: Math.round(num('alert-threshold')),
        block_scope: val('block-scope') || 'process',
        alert_timeout_sec: Math.round(num('alert-timeout')),
        max_alerts_per_minute: Math.round(num('max-alerts')),
        auto_kill_switch_on_quota: checked('quota-kill')
      },
      quota: {
        enabled: checked('quota-enabled'),
        daily_gb: num('quota-daily'),
        monthly_gb: num('quota-monthly'),
        warn_percent: Math.round(num('quota-warn'))
      }
    };
  }

  async function saveSettings(event) {
    if (event) event.preventDefault();
    var btn = $('save-config');
    await withBusy(btn, async function () {
      try {
        var result = await api('/api/config', { patch: collectPatch() });
        if (result && result.config) state.config = result.config;
        state.configDirty = false;
        if (state.config) fillSettings(state.config);
        text('settings-note', '已保存 ' + fmt.full(Date.now() / 1000));
        toast('设置已保存', 'ok');
        tick(true);
      } catch (err) {
        toast('保存失败：' + err.message, 'err');
      }
    });
  }

  /* ============================ CSV 导出 ============================ */
  function csvCell(value) {
    var s = String(value == null ? '' : value);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  function exportCsv() {
    var rows = state.events || [];
    if (!rows.length) {
      toast('暂无可导出的事件', 'err');
      return;
    }

    var header = ['时间', '类型', '等级', '风险分', '标题', '详情', '进程', '应用', 'PID', '远端IP', '端口', '国家', '动作', '状态'];
    var lines = [header.join(',')];

    rows.forEach(function (ev) {
      lines.push([
        fmt.full(ev.ts),
        KIND_CN[ev.kind] || ev.kind || '',
        LEVEL_CN[ev.level] || ev.level || '',
        ev.score == null ? '' : ev.score,
        ev.title || '',
        ev.detail || '',
        ev.process || '',
        ev.app || '',
        ev.pid == null ? '' : ev.pid,
        ev.ip || '',
        ev.port == null ? '' : ev.port,
        ev.country_cn || '',
        ev.action || '',
        STATE_CN[ev.state] || ev.state || ''
      ].map(csvCell).join(','));
    });

    var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    var now = new Date();
    var name = 'traffic-guard-events-' + now.getFullYear() + pad2(now.getMonth() + 1) + pad2(now.getDate()) +
      '-' + pad2(now.getHours()) + pad2(now.getMinutes()) + pad2(now.getSeconds()) + '.csv';

    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);

    toast('已导出 ' + rows.length + ' 条事件', 'ok');
  }

  /* ============================ 事件绑定 ============================ */
  function bindTabs() {
    Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (btn) {
      btn.addEventListener('click', function () {
        switchTab(btn.getAttribute('data-tab'));
      });
    });
  }

  function bindToolbar() {
    var segs = document.querySelectorAll('#flow-sorts .seg');
    Array.prototype.forEach.call(segs, function (seg) {
      seg.addEventListener('click', function () {
        var preset = seg.getAttribute('data-sort');
        var config = PRESET[preset];
        if (!config) return;
        state.flow.preset = preset;
        state.flow.key = config.key;
        state.flow.desc = config.desc;
        syncSortControls();
        renderFlows();
      });
    });

    var search = $('flow-search');
    if (search) {
      search.addEventListener('input', function () {
        state.flow.search = search.value || '';
        renderFlows();
      });
    }

    var lan = $('show-lan');
    if (lan) {
      lan.addEventListener('change', function () {
        state.flow.lan = Boolean(lan.checked);
        renderFlows();
      });
    }
  }

  function bindTable() {
    Array.prototype.forEach.call(document.querySelectorAll('#flow-table thead th[data-key]'), function (th) {
      th.addEventListener('click', function () {
        var key = th.getAttribute('data-key');
        var textKeys = { process: 1, remote: 1, proto: 1, country: 1, status: 1 };
        if (state.flow.key === key && state.flow.preset === null) {
          state.flow.desc = !state.flow.desc;
        } else {
          state.flow.key = key;
          state.flow.desc = !textKeys[key];
        }
        state.flow.preset = null;
        syncSortControls();
        renderFlows();
      });
    });

    var body = $('flow-body');
    if (body) {
      body.addEventListener('click', function (event) {
        var btn = event.target.closest('button[data-trust]');
        if (!btn || btn.disabled) return;
        trust(btn.getAttribute('data-trust'), btn.getAttribute('data-value') || '');
      });
    }
  }

  function bindAlerts() {
    var list = $('alert-list');
    if (!list) return;
    list.addEventListener('click', function (event) {
      var btn = event.target.closest('button[data-decide]');
      if (!btn) return;
      var id = btn.getAttribute('data-id');
      if (!id) return;
      decideAlert(id, btn.getAttribute('data-decide'));
    });
  }

  function bindControl() {
    var card = document.querySelector('.control-card');
    if (card) {
      card.addEventListener('click', function (event) {
        var btn = event.target.closest('button[data-action]');
        if (!btn || btn.disabled) return;
        runControl(btn.getAttribute('data-action'), btn);
      });
    }

    var refresh = $('btn-refresh');
    if (refresh) {
      refresh.addEventListener('click', function () {
        tick(true);
        toast('已请求刷新', 'ok');
      });
    }
  }

  function bindEventsView() {
    var refresh = $('events-refresh');
    if (refresh) refresh.addEventListener('click', function () { loadEvents(false); });

    var exportBtn = $('events-export');
    if (exportBtn) exportBtn.addEventListener('click', exportCsv);
  }

  function bindSettings() {
    var form = $('settings-form');
    if (!form) return;

    form.addEventListener('submit', saveSettings);

    form.addEventListener('input', function (event) {
      syncRangeOutputs();
      if (event.target && event.target.id === 'mode') syncModeNote();
      state.configDirty = true;
      text('settings-note', '有未保存的修改');
    });

    form.addEventListener('change', function (event) {
      if (event.target && event.target.id === 'mode') syncModeNote();
      syncRangeOutputs();
      state.configDirty = true;
      text('settings-note', '有未保存的修改');
    });

    form.addEventListener('click', function (event) {
      var btn = event.target.closest('button[data-wl-kind]');
      if (!btn) return;
      removeWhitelist(btn.getAttribute('data-wl-kind'), btn.getAttribute('data-wl-value') || '', btn);
    });

    var geoBtn = $('geo-update');
    if (geoBtn) {
      geoBtn.addEventListener('click', function () { updateGeoip(geoBtn); });
    }
  }

  function bindMisc() {
    var disclaimer = $('risk-disclaimer');
    if (disclaimer) {
      disclaimer.addEventListener('click', function () {
        state.disclaimerOpen = !state.disclaimerOpen;
        disclaimer.classList.toggle('is-clamped', !state.disclaimerOpen);
      });
    }

    var resizeTimer = null;
    window.addEventListener('resize', function () {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(function () {
        if (state.tab === 'overview') drawSparks();
      }, 180);
    });

    document.addEventListener('visibilitychange', function () {
      if (document.hidden) stopPolling();
      else startPolling();
    });
  }

  /* ============================ 初始化 ============================ */
  function init() {
    bindTabs();
    bindToolbar();
    bindTable();
    bindAlerts();
    bindControl();
    bindEventsView();
    bindSettings();
    bindMisc();

    syncSortControls();
    syncModeNote();
    syncRangeOutputs();
    renderOffline(false);

    var initial = String(window.location.hash || '').replace('#', '');
    switchTab(TABS.indexOf(initial) >= 0 ? initial : 'overview', true);

    loadConfig(false).then(function (cfg) {
      if (state.tab === 'settings' && cfg && !state.configDirty) fillSettings(cfg);
    });

    startPolling();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
