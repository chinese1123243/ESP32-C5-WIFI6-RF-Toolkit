/* 离线验证 app.js 里真正的 buildWigleCsv 输出 WiGLE 格式正确 */
const APP_VERSION = '2.3.3';
function encToWigle(enc){
    switch(enc){
        case 'OPEN':   return '[OPEN]';
        case 'WEP':    return '[WEP]';
        case 'WPA':    return '[WPA-PSK]';
        case 'WPA2':   return '[WPA2-PSK]';
        case 'WPA3':   return '[WPA3-SAE]';
        case 'WPA/W2': return '[WPA-PSK]';
        default:       return '';
    }
}
function buildWigleCsv(){
    const lines = [];
    lines.push('WigleWifi-1.4,appRelease=' + APP_VERSION +
               ',model=rftool-c5,release=rftool,device=ESP32-C5,' +
               'display=RFTOOL-C5,brand=Espressif,board=esp32c5');
    lines.push('MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,' +
               'CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type');
    for (const pt of wardPts){
        const firstSeen = new Date(pt.ts).toISOString();
        const lat = pt.lat.toFixed(6);
        const lon = pt.lon.toFixed(6);
        const acc = Math.round(pt.acc || 0);
        for (const ap of pt.aps){
            /* CSV 字段内逗号要转义, SSID 里常见 */
            const ssid = '"' + String(ap.ssid || '').replace(/"/g, '""') + '"';
            lines.push([
                ap.bssid.toUpperCase(), ssid, encToWigle(ap.enc), firstSeen,
                ap.channel, ap.rssi, lat, lon, '', acc, 'WIFI'
            ].join(','));
        }
    }
    return lines.join('\n');
}

const wardPts = [
  { ts: Date.parse('2026-10-25T10:00:00Z'),
    lat: 39.9042, lon: 116.4074, acc: 12,
    aps: [ { bssid:'aa:bb:cc:dd:ee:ff', ssid:'Home,2.4G', channel:6, rssi:-45, enc:'WPA2' },
           { bssid:'11:22:33:44:55:66', ssid:'Guest', channel:6, rssi:-70, enc:'OPEN' } ] },
  { ts: Date.parse('2026-10-25T10:00:05Z'),
    lat: 39.9051, lon: 116.4080, acc: 8,
    aps: [ { bssid:'aa:bb:cc:dd:ee:ff', ssid:'Home,2.4G', channel:6, rssi:-50, enc:'WPA2' } ] },
];
const out = buildWigleCsv();
const lines = out.split('\n');
let pass = 0, fail = 0;
function check(name, ok, extra){
  if (ok){ pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + '  -> ' + extra); }
}
check('首行是 WigleWifi-1.4', lines[0].startsWith('WigleWifi-1.4,'), lines[0]);
check('第二行是表头', lines[1].startsWith('MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,'), lines[1]);
check('3 条 AP 记录', lines.length === 2 + 3, '共 ' + (lines.length - 2) + ' 条');
/* 简单的 CSV 行解析: 处理双引号包裹的字段, 不能直接 split(',') */
function parseCsv(line){
  const out = []; let cur = ''; let inQ = false;
  for (let i = 0; i < line.length; i++){
    const c = line[i];
    if (inQ){
      if (c === '"'){ if (line[i+1] === '"'){ cur += '"'; i++; } else inQ = false; }
      else cur += c;
    } else {
      if (c === '"') inQ = true;
      else if (c === ','){ out.push(cur); cur = ''; }
      else cur += c;
    }
  }
  out.push(cur);
  return out;
}
const r0 = parseCsv(lines[2]);
check('MAC 大写', r0[0] === 'AA:BB:CC:DD:EE:FF', r0[0]);
check('SSID 含逗号被引号包裹', r0[1] === 'Home,2.4G', r0[1]);
check('WPA2 -> [WPA2-PSK]', r0[2] === '[WPA2-PSK]', r0[2]);
check('FirstSeen 是 ISO 时间', /^2026-10-25T10:00:00/.test(r0[3]), r0[3]);
check('信道 6', r0[4] === '6', r0[4]);
check('RSSI -45', r0[5] === '-45', r0[5]);
check('纬度 39.904200', r0[6] === '39.904200', r0[6]);
check('经度 116.407400', r0[7] === '116.407400', r0[7]);
check('精度 12', r0[9] === '12', r0[9]);
check('类型 WIFI', r0[10] === 'WIFI', r0[10]);
const r2 = parseCsv(lines[3]);
check('OPEN -> [OPEN]', r2[2] === '[OPEN]', r2[2]);
console.log('\n=== 结果: ' + pass + ' passed, ' + fail + ' failed ===');
process.exit(fail ? 1 : 0);
