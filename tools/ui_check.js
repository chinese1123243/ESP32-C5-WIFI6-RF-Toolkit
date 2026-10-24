/*
 * ui_check.js — App 前端静态自检
 *
 * 用法: node tools/ui_check.js
 *
 * 检查项:
 *   1. app.js 语法 (等价 node --check)
 *   2. app.js 里所有 $('id') 引用的 id 是否都存在于 index.html
 *   3. 顶层 function / let / const 是否重复定义
 *   4. 解析器里新增的输出前缀是否都在 app.js 中有分支
 *
 * 退出码 0 = 全部通过.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const JS = path.join(ROOT, 'app', 'app.js');
const HTML = path.join(ROOT, 'app', 'index.html');

let fail = 0;
const bad = (msg) => { fail++; console.log('  FAIL ' + msg); };
const ok = (msg) => console.log('  ok   ' + msg);

const js = fs.readFileSync(JS, 'utf8');
const html = fs.readFileSync(HTML, 'utf8');

/* 1. 语法 */
console.log('[1] syntax');
try {
    new Function(js);
    ok('app.js parses');
} catch (e) {
    bad('app.js syntax: ' + e.message);
}

/* 2. $('id') 引用 */
console.log('[2] element ids');
const htmlIds = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
const refs = new Set([...js.matchAll(/\$\('([^']+)'\)/g)].map(m => m[1]));
const missing = [...refs].filter(r => !htmlIds.has(r));
if (missing.length) bad('$() ids not in index.html: ' + missing.join(', '));
else ok(refs.size + ' refs, all present in ' + htmlIds.size + ' html ids');

/* 3. 重复定义 */
console.log('[3] duplicate top-level definitions');
const defNames = [...js.matchAll(/^(?:function|let|const|var)\s+([A-Za-z_$][\w$]*)/gm)].map(m => m[1]);
const seen = new Set(), dup = new Set();
for (const n of defNames) { if (seen.has(n)) dup.add(n); seen.add(n); }
if (dup.size) bad('duplicate: ' + [...dup].join(', '));
else ok(defNames.length + ' definitions, no duplicates');

/* 4. 固件输出前缀覆盖 */
console.log('[4] output prefixes handled');
/* 只列需要 App 结构化解析的前缀. 纯文本 dump 的行走通用 log(),
 * 不在此列 (如 wifi_db 的 EAPOL,<a>,<b>,<type>,<step>). */
const FIRMWARE_PREFIXES = [
    'AP,', 'CLIENT,', 'META,WIFI,', 'META,CLI,', 'META,CAP,', 'META,HS,', 'META,PHISH,',
    'META,RAW,', 'META,KARMA,', 'META,BLESCAN,', 'META,EVILTWIN,', 'CRED,', 'PSTA,',
    'KARMA,', 'BLEDEV,', 'WPA*',
];
const unhandled = FIRMWARE_PREFIXES.filter(p => !js.includes("'" + p));
if (unhandled.length) bad('no branch for: ' + unhandled.join(', '));
else ok(FIRMWARE_PREFIXES.length + ' prefixes covered');

/* 5. id 重复 (搬动面板时最容易留重) */
console.log('[5] duplicate element ids');
const idList = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
const idSeen = new Set(), idDup = new Set();
for (const i of idList) { if (idSeen.has(i)) idDup.add(i); idSeen.add(i); }
if (idDup.size) bad('duplicate ids: ' + [...idDup].join(', '));
else ok(idList.length + ' ids, all unique');

/* 6. 面板数量 (每个 .tab 都要有对应的 #pan-*) */
console.log('[6] tabs vs panels');
const tabs = [...html.matchAll(/data-tab="([^"]+)"/g)].map(m => m[1]);
const panIds = new Set([...html.matchAll(/id="pan-([^"]+)"/g)].map(m => m[1]));
const noPanel = tabs.filter(t => !panIds.has(t));
if (noPanel.length) bad('tab without panel: ' + noPanel.join(', '));
else ok(tabs.length + ' tabs, all have panels');

/* 7. META,WIFI 子类覆盖
 * 固件新增一个 META,WIFI,<X>, App 的 else-if 链必须同步加分支. 漏了不会
 * 报错, 只是落进最后的 else 当普通日志, 调用方等不到回执, 表现成
 * "设备无响应". PMF,BLOCKED 就是这样漏掉的. */
console.log('[7] META,WIFI subkinds');
const fwFiles = ['cli.c', 'wifi_attack.c', 'wifi_db.c'];
const fwSrc = fwFiles.map(f => fs.readFileSync(path.join(ROOT, 'main', f), 'utf8')).join('\n');
const subkinds = new Set([...fwSrc.matchAll(/META,WIFI,([A-Z]+)/g)].map(m => m[1]));
const noBranch = [...subkinds].filter(k =>
    !js.includes("kind === '" + k + "'") && !js.includes('META,WIFI,' + k));
if (noBranch.length) bad('META,WIFI subkind without branch: ' + noBranch.join(', '));
else ok(subkinds.size + ' subkinds covered: ' + [...subkinds].join(' '));

console.log(fail ? ('\nFAILED (' + fail + ' check(s))') : '\nALL CHECKS PASSED');
process.exit(fail ? 1 : 0);
