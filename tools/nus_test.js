/* eslint-disable */
/**
 * NUS 二进制帧协议 自测
 * 1) CRC8(poly 0x07) 已知向量
 * 2) App 编码 -> 手工解析
 * 3) 固件编码(JS 复刻 main/ble_cli.c 的 nus_send_msg) -> App 解码 (nusFeed)
 * 4) 模拟小 MTU 切片 (帧跨多个 notify) -> App 解码
 *
 * 用法: node tools/nus_test.js
 */
const fs = require('fs');
const path = require('path');

/* 载入 app.js 中的真实 NUS 实现 */
const src = fs.readFileSync(path.join(__dirname, '..', 'app', 'app.js'), 'utf8');
const start = src.indexOf('const NUS_MAGIC');
const end = src.indexOf('const $ = id => document.getElementById(id);');
if (start < 0 || end < 0) { console.error('未找到 NUS 代码块边界'); process.exit(1); }
let block = src.slice(start, end);

globalThis.__rx = [];
globalThis.devMode = false;
globalThis.handshakeResolve = null;
globalThis.dlog = () => {};
globalThis.handleNotifyData = t => globalThis.__rx.push(t);
block += '\nglobalThis.__nus = { crc8, nusEncode, nusFeed, nusStat, NUS_HDR, NUS_MAX_PAYLOAD, NUS_T_DATA };\n';
eval(block);
const N = globalThis.__nus;

let pass = 0, fail = 0;
function check(name, ok, extra) {
    if (ok) { pass++; console.log('  PASS  ' + name); }
    else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

/* 固件侧算法复刻 (main/ble_cli.c) */
function fwCrc8(d) {
    let c = 0;
    for (let i = 0; i < d.length; i++) {
        c ^= d[i];
        for (let b = 0; b < 8; b++) c = (c & 0x80) ? (((c << 1) ^ 0x07) & 0xff) : ((c << 1) & 0xff);
    }
    return c;
}
function fwSendMessage(text, type, chunkMax) {
    chunkMax = chunkMax || 220;
    const data = new TextEncoder().encode(text);
    const out = [];
    let off = 0, seq = 0;
    while (off < data.length) {
        const chunk = Math.min(chunkMax, data.length - off);
        const frame = new Uint8Array(7 + chunk + 1);
        frame[0] = 0xA5;
        frame[1] = type;
        frame[2] = (off === 0 ? 0x01 : 0) | ((off + chunk >= data.length) ? 0x02 : 0);
        frame[3] = seq & 0xff; frame[4] = (seq >> 8) & 0xff;
        frame[5] = chunk & 0xff; frame[6] = (chunk >> 8) & 0xff;
        frame.set(data.subarray(off, off + chunk), 7);
        frame[7 + chunk] = fwCrc8(frame.subarray(1, 7 + chunk));
        out.push(frame);
        seq++; off += chunk;
    }
    return out;
}

console.log('=== NUS 帧协议自测 ===\n');

/* 1) CRC8 已知向量: CRC-8/ATM, poly 0x07 init 0x00, "123456789" -> 0xF4 */
console.log('[1] CRC8 向量');
const c1 = N.crc8(new TextEncoder().encode('123456789'));
check('crc8("123456789") == 0xF4', c1 === 0xF4, '0x' + c1.toString(16));
const c2 = N.crc8(new Uint8Array([0x00]));
check('crc8([0x00]) == 0x00', c2 === 0x00, '0x' + c2.toString(16));

/* 2) App 编码结构 */
console.log('\n[2] App 编码 (nusEncode)');
const fr = N.nusEncode('status');
check('单帧', fr.length === 1, 'frames=' + fr.length);
const f0 = fr[0];
const plen = f0[5] | (f0[6] << 8);
check('magic == 0xA5', f0[0] === 0xA5);
check('type == CMD(0x01)', f0[1] === 0x01);
check('flags == FIRST|LAST(0x03)', f0[2] === 0x03, '0x' + f0[2].toString(16));
const payload = new TextDecoder().decode(f0.subarray(N.NUS_HDR, N.NUS_HDR + plen));
check('payload == "status"', payload === 'status', JSON.stringify(payload));
check('len 字节数正确', f0.length === N.NUS_HDR + plen + 1, 'len=' + f0.length);
check('CRC8 覆盖 type..payload', N.crc8(f0.subarray(1, N.NUS_HDR + plen)) === f0[N.NUS_HDR + plen]);
/* nusWrite 会在命令后追加 \n (与固件 nus_deliver_msg 的去除逻辑对应) */
const frNl = N.nusEncode('status\n');
const plenNl = frNl[0][5] | (frNl[0][6] << 8);
check('带换行命令 payload == "status\\n"',
    new TextDecoder().decode(frNl[0].subarray(N.NUS_HDR, N.NUS_HDR + plenNl)) === 'status\n');

/* 3) 固件编码 -> App 解码 (整帧) */
console.log('\n[3] 固件编码 -> App 解码');
function decodeViaFeed(frames) {
    globalThis.__rx = [];
    for (const fr of frames) N.nusFeed(fr);
    return globalThis.__rx.join('');
}
const shortMsg = 'RFTOOL-C5 v1.0\r\n';
check('短消息往返', decodeViaFeed(fwSendMessage(shortMsg, 0x02)) === shortMsg);

const longMsg = 'META,WIFI,APS,count,3\n' + Array.from({ length: 12 }, (_, i) =>
    `AP,aa:bb:cc:dd:ee:${i.toString(16).padStart(2, '0')},TestSSID-${i},ch6,rssi-${40 + i},WPA2,0,1,x,x,Espressif`).join('\n') + '\n';
const lf = fwSendMessage(longMsg, 0x02);
check('长消息被分片 (>1 帧)', lf.length > 1, 'frames=' + lf.length);
check('长消息往返完整', decodeViaFeed(lf) === longMsg, 'len ' + longMsg.length);
check('每帧 payload <= NUS_MAX_PAYLOAD', lf.every(x => (x[5] | (x[6] << 8)) <= N.NUS_MAX_PAYLOAD));
check('首帧 FIRST / 末帧 LAST',
    (lf[0][2] & 0x01) === 0x01 && (lf[lf.length - 1][2] & 0x02) === 0x02);

/* 4) MTU 切片: 一帧被拆成多个 notify */
console.log('\n[4] MTU 切片重组 (帧跨多个 notify)');
function decodeViaFeedChunks(frames, sliceLen) {
    globalThis.__rx = [];
    for (const fr of frames) {
        for (let i = 0; i < fr.length; i += sliceLen) {
            N.nusFeed(fr.subarray(i, Math.min(i + sliceLen, fr.length)));
        }
    }
    return globalThis.__rx.join('');
}
check('切片 20B 往返', decodeViaFeedChunks(fwSendMessage(longMsg, 0x02), 20) === longMsg);
check('切片 7B (仅头部大小) 往返', decodeViaFeedChunks(fwSendMessage(longMsg, 0x02), 7) === longMsg);
check('切片 1B 往返', decodeViaFeedChunks(fwSendMessage(shortMsg, 0x02), 1) === shortMsg);

/* 5) 容错: 前导噪声 + 坏 CRC 帧 */
console.log('\n[5] 容错');
globalThis.__rx = [];
N.nusFeed(new Uint8Array([0x00, 0x11, 0x22]));           /* 噪声 */
for (const fr of fwSendMessage(shortMsg, 0x02)) N.nusFeed(fr);
check('前导噪声被跳过', globalThis.__rx.join('') === shortMsg);

const bad = fwSendMessage('should-be-dropped', 0x02);
bad[0][bad[0].length - 1] ^= 0xff;                        /* 破坏 CRC */
globalThis.__rx = [];
for (const fr of bad) N.nusFeed(fr);
check('坏 CRC 帧被丢弃', globalThis.__rx.length === 0 && N.nusStat.crcErr > 0);

/* 6) 空/边界 */
console.log('\n[6] 边界');
const exact = 'x'.repeat(N.NUS_MAX_PAYLOAD);
check('正好 NUS_MAX_PAYLOAD 单帧', N.nusEncode(exact).length === 1);
check('NUS_MAX_PAYLOAD+1 分两帧', N.nusEncode(exact + 'y').length === 2);
check('边界消息往返', decodeViaFeed(fwSendMessage(exact + 'y', 0x02)) === exact + 'y');

console.log('\n=== 结果: ' + pass + ' passed, ' + fail + ' failed ===');
process.exit(fail ? 1 : 0);
