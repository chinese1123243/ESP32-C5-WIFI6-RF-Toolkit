/*
 * proto_test.js — App 侧 META 分发的回归测试
 *
 * 把 app.js 里的 parseOutputLine 连同它的等待器一起切出来, 灌进假 DOM 跑,
 * 断言"设备回了什么"和"界面最后停在哪". 覆盖的都是一类真实故障:
 * 固件回了明确的拒绝, App 没有分支, 计时器照样跑满, 最后报"设备无响应".
 *
 * 用例里的输入行按 main/*.c 的 printf 格式串逐字拼出, 不手抄字段名:
 * 少一个字段、错一位偏移, 断言当场就挂.
 *
 * 用法: node tools/proto_test.js
 */
const fs = require('fs');
const path = require('path');

const JS = process.env.PROTO_SRC || path.join(__dirname, '..', 'app', 'app.js');
const src = fs.readFileSync(JS, 'utf8');

/* 从 startMark 起做括号配平, 取到配平结尾 (跳过字符串与注释) */
function blockFrom(mark) {
    const i = src.indexOf(mark);
    if (i < 0) throw new Error('找不到标记: ' + mark);
    let depth = 0, started = false;
    for (let k = i; k < src.length; k++) {
        const c = src[k], n = src[k + 1];
        if (c === '/' && n === '*') { k = src.indexOf('*/', k + 2) + 1; continue; }
        if (c === '/' && n === '/') { k = src.indexOf('\n', k); continue; }
        if (c === "'" || c === '"' || c === '`') {
            for (k++; k < src.length; k++) {
                if (src[k] === '\\') { k++; continue; }
                if (src[k] === c) break;
            }
            continue;
        }
        if (c === '{') { depth++; started = true; }
        else if (c === '}') { depth--; if (started && depth === 0) return src.slice(i, k + 1); }
    }
    throw new Error('括号未配平: ' + mark);
}

const waiters = src.slice(src.indexOf('let pendingAction = null;'), src.indexOf('/* Deauth 的结果判定'));
const hsBlock = src.slice(src.indexOf('const HS_WAIT_MS'), src.indexOf('/* 批量设置同值元素 */'));
const fmt     = src.slice(src.indexOf('function kvOf'), src.indexOf('function parseOutputLine'));
const parser  = blockFrom('function parseOutputLine(line){');
if (!waiters || !hsBlock || !parser) { console.error('切片失败'); process.exit(1); }

const harness = `
let exportCap = null;
let deauthTarget = 'aa:bb:cc:dd:ee:ff';
let negotiatedMtu = 0, linkPhy = '--';
let hsSt = { seen: [0,0,0,0], total: 0, complete: 0, pmkid: 0 };
let hsList = [], hsGrab = null, hsWait = null;
let logs = [], toasts = [], stats = {};
function log(m, c){ logs.push((c || 'meta') + ' | ' + m); }
function toast(m, k){ toasts.push((k || 'ok') + ' | ' + m); }
function dlog(){}
function $(id){ return els[id] = els[id] || { id, textContent: '', innerHTML: '', value: '' }; }
function setStat(id, v){ stats[id] = String(v); }
function setText(ids, v){ for (const id of ids) stats[id] = String(v); }
function updateBand(){}
function setJobActive(){}
function bandOf(c){ return (+c) >= 36 ? '5G' : '2.4G'; }
function updateConnInfo(){}
function renderApList(){}
function renderGattTree(){}
function finishApScan(){}
function dumpAps(){}
function dumpClients(){}
function renderClientList(){}
function finishCliScan(){}
function renderPhishSta(){}
function renderCreds(){}
function updatePhishUI(){}
function radar(){}
function reportRefusal(){}
let phishOn = false, phishCredCount = 0, phishHtmlBytes = 0;
let phishCreds = [], phishCredCur = null, phishStas = [];
const apList = [], clientList = [];
let wardOn = false, wardCur = null, wardPts = [];
function updateWardUI(){}
let apExpect = -1, cliExpect = -1, apScanning = false, cliScanning = false;
const els = {};
const document = { getElementById: id => (els[id] = els[id] || { textContent: '' }) };
function fmtBytes(n){ return n + ' B'; }
${waiters}
${hsBlock}
${fmt}
${parser}
return {
  feed: l => parseOutputLine(l),
  expectConfirm, expectHandshake, clearPendingAction, clearHandshake,
  pending: () => pendingAction, hs: () => pendingHs,
  logs: () => logs, toasts: () => toasts, stats: () => stats, el: id => els[id],
  reset(){ logs.length = 0; toasts.length = 0; for (const k in stats) delete stats[k]; },
  setTarget(t){ deauthTarget = t; },
  phishCreds: () => phishCreds, phishStas: () => phishStas, phishCredCur: () => phishCredCur
};
`;

const M = new Function(harness)();

let pass = 0, fail = 0;
function check(name, ok, extra) {
    if (ok) { pass++; console.log('  PASS  ' + name); }
    else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

/* META,WIFI,PMF,BLOCKED,bssid,%s,reason,mfpr,advice,use --force / scenario pmf / downgrade / eviltwin */
console.log('[1] PMF 拦截不再沉默');
M.reset(); M.expectConfirm('Deauth', 8000);
M.feed('META,WIFI,PMF,BLOCKED,bssid,aa:bb:cc:dd:ee:ff,reason,mfpr,advice,use --force / scenario pmf / downgrade / eviltwin');
check('清掉等待回执', M.pending() === null);
check('提示 PMF 必需', /PMF/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));
check('保留固件给的替代路径', /scenario pmf/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

/* META,WIFI,PMF,UNKNOWN,bssid,%s,reason,not_in_db,advice,sniff first or add --force */
M.reset(); M.expectConfirm('Deauth', 8000);
M.feed('META,WIFI,PMF,UNKNOWN,bssid,aa:bb:cc:dd:ee:ff,reason,not_in_db,advice,sniff first or add --force');
check('目标不在库: 清等待', M.pending() === null);
check('目标不在库: 提示先扫描', /不在 AP 表/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));

/* META,CLI,ERR,cmd,%s,msg,need_confirm,detail,add --yes: %s %s --yes */
console.log('\n[2] 协议层错误直达界面');
M.reset(); M.expectConfirm('Beacon', 8000);
M.feed('META,CLI,ERR,cmd,beaconflood,msg,need_confirm,detail,add --yes: beaconflood -p <prefix> --yes');
check('need_confirm 清等待', M.pending() === null);
check('need_confirm 说明缺 --yes', /--yes/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));

M.reset(); M.expectConfirm('Deauth', 8000);
M.feed('META,CLI,ERR,cmd,deauth,msg,arg_parse_failed,detail,invalid option -- b');
check('arg_parse_failed 清等待', M.pending() === null);
check('arg_parse_failed 说参数不对', /参数/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));

M.reset(); M.expectConfirm('嗅探', 6000);
M.feed('META,WIFI,ERR,code,258,msg,deauth_start_failed');
check('WIFI,ERR 清等待', M.pending() === null);
check('WIFI,ERR 给出可读原因', /起不来/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));

/* META,CLI,END,stream,%u,cmd,%s,rc,%d — 没有 ERR 行, 只有 rc 非 0 */
M.reset(); M.expectConfirm('定位', 8000);
M.feed('META,CLI,END,stream,41,cmd,locate,rc,257');
check('END rc 非 0 清等待', M.pending() === null);
check('END rc 译成内存不足', /内存不足/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));

M.reset(); M.expectConfirm('定位', 8000);
M.feed('META,CLI,END,stream,42,cmd,locate,rc,0');
check('END rc=0 不动等待', M.pending() !== null);
M.clearPendingAction();

/* META,CLI,BEGIN,stream,%u,cmd,%s — 分帧标记, 每 3 秒随 status 一条 */
M.reset();
M.feed('META,CLI,BEGIN,stream,42,cmd,status');
check('BEGIN 不进日志', M.logs().length === 0, M.logs().join(' | '));

/* META,WIFI,INJECT,START,mode,%s,count,%lu,interval,%lu,channel,%u */
console.log('\n[3] 注入启动回执');
M.reset(); M.expectConfirm('Deauth', 8000);
M.feed('META,WIFI,INJECT,START,mode,deauth,count,10,interval,100,channel,6');
check('清等待', M.pending() === null);
check('模式解析正确', /deauth ch=6/.test(M.logs().join('\n')), M.logs().join(' | '));
check('间隔解析正确', /间隔 100ms/.test(M.logs().join('\n')), M.logs().join(' | '));

/* META,WIFI,INJECT,DONE,mode,%d,sent,%u,err,%u,ms,%u,stopped,%u */
console.log('\n[4] 发完帧不等于成功');
M.reset(); M.setTarget('AA:BB:CC:DD:EE:FF');
M.feed('META,WIFI,INJECT,DONE,mode,0,sent,10,err,0,ms,900,stopped,0');
check('sent 解析正确 (偏移未错位)', /10 帧/.test(M.logs().join('\n')), M.logs().join(' | '));
check('转入握手等待', M.hs() !== null && M.hs().bssid === 'aa:bb:cc:dd:ee:ff');

M.reset();
M.feed('META,HS,COMPLETE,pair,M1+M2,bssid,AA:BB:CC:DD:EE:FF,sta,11:22:33:44:55:66,chan,6,rssi,-52');
check('匹配目标的握手: 撤掉等待', M.hs() === null);
check('匹配目标的握手: 判 Deauth 生效', /生效/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));

M.reset(); M.feed('META,WIFI,INJECT,DONE,mode,0,sent,10,err,0,ms,900,stopped,1');
check('被中止不进入握手等待', M.hs() === null);
check('被中止写成中止', /中止/.test(M.logs().join('\n')), M.logs().join(' | '));

M.reset(); M.feed('META,WIFI,INJECT,DONE,mode,1,sent,500,err,0,ms,3000,stopped,0');
check('beacon 不进入握手等待', M.hs() === null);
check('beacon sent 解析正确', /sent=500/.test(M.logs().join('\n')), M.logs().join(' | '));

/* META,WIFI,SNIFF,PROGRESS,total,%u,channel,%u,aps,%d,clients,%d */
console.log('\n[5] 嗅探进度进状态栏');
M.reset();
M.feed('META,WIFI,SNIFF,PROGRESS,total,4096,channel,11,aps,7,clients,3');
check('total 进状态栏', M.stats().stSniff === '4096', JSON.stringify(M.stats()));
check('channel 进状态栏', M.stats().stCh === '11', JSON.stringify(M.stats()));
check('aps 进状态栏', M.stats().stAps === '7', JSON.stringify(M.stats()));
check('clients 进状态栏', M.stats().stCli === '3', JSON.stringify(M.stats()));

/* META,WIFI,AUTO,STATS,... 每 3s 随 status 一起来, 不能进日志 */
console.log('\n[6] 自适应统计不刷屏');
M.reset(); M.feed('META,WIFI,AUTO,STATS,round,12,total_hits,3400,dwell_now,220,base,200');
M.feed('META,WIFI,AUTO,CH,6,hits,900,dwell,220');
check('不产生日志', M.logs().length === 0, M.logs().join(' | '));

/* META,WIFI,DUMP,CLEARED,aps,0,clients,0,eapols,0 */
M.reset(); M.feed('META,WIFI,DUMP,CLEARED,aps,0,clients,0,eapols,0');
check('清库有回执', /清空/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));

/* 未知输出不能异常: else 分支兜住 */
console.log('\n[7] 未知行不抛异常');
M.reset();
let threw = '';
try {
    M.feed('META,WIFI,WHATEVER,x,1');
    M.feed('SO METHING,odd');
} catch (e) { threw = e.message; }
check('未知子类不抛异常', threw === '', threw);

/* META,EVILTWIN,ERR,msg,ap_not_found (先 scan/sniff 把它抓进库里) */
console.log('\n[8] 克隆与门户的拒绝');
M.reset(); M.expectConfirm('克隆', 12000);
M.feed('META,EVILTWIN,ERR,msg,ap_not_found (先 scan/sniff 把它抓进库里)');
check('克隆 ERR 清等待', M.pending() === null);
check('克隆 ERR 说清原因', /不在 AP 表/.test(JSON.stringify(M.toasts())), JSON.stringify(M.toasts()));

/* META,PHISH,ERR,msg,ap_start_failed,code,%d */
M.reset(); M.expectConfirm('门户', 12000);
M.feed('META,PHISH,ERR,msg,ap_start_failed,code,257');
check('门户 ERR 清等待', M.pending() === null);
check('门户 ERR 译出 code', /257/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

console.log('\n[9] 编排 / 定位 / OTA 的可读输出');
M.reset();
M.feed('META,SCENARIO,PMF,REPORT,bssid,aa:bb:cc:dd:ee:ff,channel,6,mfpr,1,mfpc,0,akm,0x08');
const pmfRep = M.el('scHint').textContent;
check('PMF 报告说必需', /必需/.test(pmfRep), pmfRep);
check('PMF 报告带信道', /CH 6/.test(pmfRep), pmfRep);

M.feed('META,SCENARIO,PMF,VERDICT,deauth_useless,1,next,downgrade (WPA3 transition) 或 eviltwin clone');
check('PMF 结论说 Deauth 无效', /无效/.test(M.el('scHint').textContent), M.el('scHint').textContent);

M.feed('META,SCENARIO,SURVEY,DONE,secs,30,aps,12,new_aps,3,clients,5,new_clients,1,eapols,2');
check('勘察结果带新旧数', /AP 12 \(新 3\)/.test(M.el('scHint').textContent), M.el('scHint').textContent);

M.feed('META,LOCATE,T,mac,aa:bb:cc:dd:ee:ff,rssi,-52,avg,-55,min,-60,max,-50,n,12,trend,rising');
const loc = M.el('locHint').textContent;
check('定位读数带 rssi', /-52/.test(loc), loc);
check('定位读数带样本数', /n 12/.test(loc), loc);

M.feed('META,OTA,STATUS,running,ota_0,boot,ota_1,state,VALID,version,2.3.1,project,rftool,rollback_enabled,1,slot_size,2621440,written,0,busy,0');
const ota = M.el('otaHint').textContent;
check('OTA 状态带槽名', /ota_0/.test(ota) && /ota_1/.test(ota), ota);
check('OTA 状态算对容量', /2\.5MB/.test(ota), ota);

M.feed('META,OTA,ERR,msg,rollback_disabled');
check('OTA 错误翻成人话', /没开回滚/.test(M.el('otaHint').textContent), M.el('otaHint').textContent);

M.reset(); M.expectConfirm('PMKID', 8000);
M.feed('META,PMKID,ACTIVE,ok,1,bssid,20:87:ec:0f:4e:82,ssid,iTV-82456,ch,6,m1,1,pmkid,0,ms,4159');
check('PMKID 回执清等待', M.pending() === null);
check('PMKID 结果进日志', /PMKID/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset(); M.expectConfirm('CSA', 8000);
M.feed('META,CSA,TX,ok,1,bssid,20:87:ec:0f:4e:82,from,6,to,1,sent,3,fail,0,cloned,1');
check('CSA 回执清等待', M.pending() === null);
check('CSA 结果进日志', /CSA/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset(); M.expectConfirm('Zbtx', 8000);
M.feed('META,ZB,TX,START,ch,15');
M.feed('META,ZB,TX,DONE,sub,beacon,ok,10,bad,0,cca_busy,3,lasterr,0');
check('zbtx 回执清等待', M.pending() === null);
check('CCA busy 提示 --noca', /--noca/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset(); M.expectConfirm('Zbtx', 8000);
M.feed('META,ZB,TX,DONE,sub,beaconreq,tx_ok,1,tx_bad,0,pans,2,dwell_ms,3000');
check('PAN 发现计数进日志', /2 个 PAN/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset();
M.feed('META,ZB,PAN,pan,0x1a2b,src,0x0,rssi,-70,lqi,80,ch,15');
check('PAN 行翻成可读', /0x1a2b/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset();
M.feed('META,ZB,TX,DRY,len,26,data,1a802a2b1a0000ffcf0000001205101112131415161700000000');
check('dry 只报组帧不报发送', /未发送/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset();
M.feed('META,ZB,TX,ERR,msg,bad_channel (11-26)');
check('zbtx 参数错误进日志', /bad_channel/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset(); M.expectConfirm('GATT', 30000);
M.feed('META,BTGATT,START,mac,e4:1b:43:2c:22:c4,timeout,25000');
M.feed('META,BTGATT,CONN,addr,e4:1b:43:2c:22:c4,rssi,-83');
M.feed('META,BTGATT,SVC,uuid,0x1800,hstart,5,hend,13');
M.feed('META,BTGATT,CHR,uuid,0x2a00,hstart,6,hend,7,val,7,props,R');
M.feed('META,BTGATT,DSC,uuid,0x2902,handle,4,chr,0');
M.feed('META,BTGATT,VAL,handle,7,len,22,hex,4d696a6961');
M.feed('META,BTGATT,DONE,svcs,4,chrs,16,dscs,3,reads,6,ms,14371,result,ok');
check('GATT 回执清等待', M.pending() === null);
check('GATT 汇总进日志', /服务 4/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset();
M.feed('META,BTGATT,ERR,msg,bad_mac');
check('GATT 参数错误进日志', /bad_mac/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

M.reset();
M.feed('META,BTGATT,DONE,svcs,1,chrs,2,dscs,0,reads,0,ms,3000,result,FAIL');
check('GATT 失败也报出来', /被跳过|有步骤/.test(JSON.stringify(M.logs())), JSON.stringify(M.logs()));

/* Flood 洪泛: auth 模式 (META,INJECT,START mode=auth) 必须被解析且不进握手等待 */
console.log('\n[10] Flood 洪泛回执');
M.reset(); M.expectConfirm('Flood', 8000);
M.feed('META,WIFI,INJECT,START,mode,auth,count,0,interval,0,channel,6');
check('auth 启动回执清等待', M.pending() === null);
check('auth 模式进日志', /\[Flood\] auth ch=6 已启动/.test(M.logs().join('\n')), M.logs().join(' | '));

M.reset(); M.setTarget('AA:BB:CC:DD:EE:FF');
M.feed('META,WIFI,INJECT,DONE,mode,auth,sent,1200,err,3,ms,5000,stopped,1');
check('auth DONE 不进握手等待 (不是 deauth)', M.hs() === null);
check('auth DONE 报已停止', /被中止/.test(M.logs().join('\n')), M.logs().join(' | '));
check('auth DONE 刷新 Flood 面板已发', M.el('floodSent') && String(M.el('floodSent').textContent) === '1200',
      'floodSent=' + (M.el('floodSent') && M.el('floodSent').textContent));
check('auth DONE 刷新 Flood 面板状态', M.el('floodRun') && M.el('floodRun').textContent === '已停止',
      'floodRun=' + (M.el('floodRun') && M.el('floodRun').textContent));

M.reset(); M.setTarget('AA:BB:CC:DD:EE:FF');
M.feed('META,WIFI,INJECT,DONE,mode,disassoc,sent,800,err,0,ms,4000,stopped,0');
check('disassoc DONE 不进握手等待', M.hs() === null);
check('disassoc DONE 报完成', /完成/.test(M.logs().join('\n')), M.logs().join(' | '));
check('disassoc DONE 刷新 Flood 面板已发', M.el('floodSent') && String(M.el('floodSent').textContent) === '800',
      'floodSent=' + (M.el('floodSent') && M.el('floodSent').textContent));

/* 钓鱼门户: META,PHISH,* 与 CRED,/PSTA, 行必须被解析, 不能静默丢弃 */
console.log('\n[11] 钓鱼门户回执');
M.reset(); M.expectConfirm('门户', 12000);
M.feed('META,PHISH,START,ssid,Free-WiFi,ip,192.168.71.1,dns,1,html_bytes,1234');
check('门户 START 清等待', M.pending() === null);
check('门户 START 进日志', /Free-WiFi/.test(M.logs().join('\n')), M.logs().join(' | '));

M.reset();
M.feed('META,PHISH,CRED,id,1,ip,192.168.71.5,fields,2');
M.feed('CRED,1,username,victim01');
M.feed('CRED,1,password,hunter2!');
check('凭据行不抛异常', true);
check('凭据对象进数组', M.phishCreds().length === 1, 'phishCreds.len=' + M.phishCreds().length);
check('字段解析进凭据对象', M.phishCredCur() && M.phishCredCur().fields.length === 2,
      'fields=' + (M.phishCredCur() ? M.phishCredCur().fields.length : 'null'));
check('用户名/密码解析正确', M.phishCredCur() &&
      M.phishCredCur().fields[0].k === 'username' && M.phishCredCur().fields[0].v === 'victim01' &&
      M.phishCredCur().fields[1].v === 'hunter2!',
      JSON.stringify(M.phishCredCur() && M.phishCredCur().fields));

M.reset();
M.feed('META,PHISH,STA,n,1,on,1');
M.feed('PSTA,de:ad:be:ef:00:01,rssi,-41');
check('客户端行不抛异常', true);
check('客户端进数组', M.phishStas().length === 1 && M.phishStas()[0].mac === 'de:ad:be:ef:00:01',
      JSON.stringify(M.phishStas()));

M.reset(); M.expectConfirm('门户', 12000);
M.feed('META,PHISH,STOP,ok,1');
check('门户 STOP 清等待', M.pending() === null);

console.log('\n=== 结果: ' + pass + ' passed, ' + fail + ' failed ===');
process.exit(fail ? 1 : 0);
