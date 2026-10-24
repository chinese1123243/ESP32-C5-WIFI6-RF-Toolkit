#!/usr/bin/env python
"""AI 味扫描。代码只查注释，Markdown 查正文（跳过代码块与行内代码）。

用法: python scripts/check_slop.py [路径...]  默认扫 main app scripts docs README.md
命中只报告不修改。退出码 0。
"""

import re
import sys

# (标签, 正则)。正则同时用于注释文本与 Markdown 正文。
RULES = [
    ("装饰分隔线", r"^\s*(?://|/\*|#|;|--)\s*[=_*~^+.\-]{6,}"),
    ("装饰分隔线", r"^\s*(?://|/\*|#)\s*[-=_]{2,}\s*[^\-=_].*\s[-=_]{2,}\s*(?:\*/)?\s*$"),
    ("步骤旁白", r"(第[一二三四五六七八九十]+步|Step\s*[0-9]+)\s*[:：,，]"),
    ("步骤旁白", r"^\s*(首先|然后|接着|其次|最后)\s*[,，]"),
    ("步骤旁白", r"^\s*(First|Then|Next|Finally)\s*[,:]"),
    ("空标签", r"^\s*(核心逻辑|主逻辑|业务逻辑|主要逻辑|工具函数|入口函数|业务处理)\s*(?:\*/)?\s*$"),
    ("空标签", r"^\s*(helper|helpers|utils?|utilities)\s*(?:\*/)?\s*$"),
    ("空标签", r"^\s*(重要|注意|关键点)\s*[:：]?\s*(?:\*/)?\s*$"),
    ("changelog式", r"(更新为|改为使用|现在使用|新增了|已修改|已重构|从.{0,12}改为)"),
    ("changelog式", r"\b(Updated\s+to|Now\s+uses|Changed\s+to|Refactored\s+to)\b"),
    ("空泛TODO", r"(TODO|FIXME|XXX).{0,4}(优化|改进|完善|待优化|这里可以|后面再说)"),
    ("空泛TODO", r"(TODO|FIXME).{0,6}(fix this|improve this|make better|clean up)"),
    ("复述声明", r"^\s*(定义|声明|创建|初始化|设置|获取|返回|判断|处理)\s*[^。]{0,14}$"),
    ("夸大词", r"(极大地|显著(提升|提高|改善|降低|减少)|大幅(提升|提高|改善|降低|减少)|至关重要|里程碑|革命性|开创性|深远影响)"),
    ("吹捧词", r"(优雅|健壮|鲁棒|无缝|赋能|闭环|抓手|沉淀|拉通|保驾护航|坚实基础|一举多得)"),
    ("吹捧词", r"\b(robust|seamless|seamlessly|elegant|comprehensive|cutting-edge|groundbreaking|leverage|utilize|delve|pivotal|testament|showcase)\b"),
    ("元标签", r"(一句话总结|简而言之|总的来说|值得注意的是|不难发现|众所周知|综上所述|由此可见|关键在于|这里有个坑|划重点|接下来我们|让我们看看)"),
    ("否定平行", r"不是.{1,24}[，,]而是|不仅仅是.{1,24}[，,]更是|不只是.{1,20}[，,]这是"),
    ("否定平行", r"\bnot just\b.{0,30}\bbut also\b|\bisn't an?\b.{0,30}\bit's an?\b"),
    ("句尾伪分析", r"(充分体现了|显著提升了|为.{0,8}打下(坚实)?基础|反映了更广泛的趋势|提供了有力的支撑)"),
    ("句尾伪分析", r",\s*(highlighting|underscoring|ensuring|demonstrating|showcasing)\b"),
    ("假深刻收尾", r"(真正的挑战在于|未来取决于|尽管面临挑战)"),
    ("翻译腔", r"(基于(上述|以上)分析|为了进一步验证|通过这种方式|在.{0,12}的前提下|存在着|进行着|具备着)"),
    ("翻译腔硬接", r"^\s*(因此|从而|进而|与此同时|此外，|然而，)"),
    ("破折号", r"——"),
    ("客套", r"(希望(对你|这)有帮助|有问题随时(问|联系)|Happy coding|Great question|好的我来帮)"),
    # 装饰性 emoji 要禁。U+2630 是抽屉菜单按钮的真实字形, 文档引用它不算装饰,
    # 删了会丢信息, 故从区间里排除。
    ("emoji", r"[\U0001F300-\U0001FAFF\u2601-\u262F\u2631-\u27BF]"),
]

CODE_EXT = {".c", ".h", ".cc", ".cpp", ".js", ".jsx", ".ts", ".tsx", ".py", ".sh", ".sql"}
DOC_EXT = {".md"}

# C 风格块注释的续行（以 * 开头）要看上下文，这里用状态机处理
BLOCK_START = re.compile(r"/\*")
BLOCK_END = re.compile(r"\*/")


def comment_text(line, ext, in_block):
    """返回该行里的注释文本；不在注释里则返回 None。同时回传块注释状态。"""
    s = line.strip()
    if in_block:
        if BLOCK_END.search(s):
            return s, False
        return s, True
    if ext in (".py", ".sh"):
        if s.startswith("#"):
            return s, False
        return None, False
    if s.startswith("//"):
        return s, False
    if s.startswith("/*"):
        if BLOCK_END.search(s):
            return s, False
        return s, True
    if s.startswith("*"):          # 块注释续行（状态机漏掉时兜底）
        return s, True
    # 行尾注释
    m = re.search(r"(//|/\*)\s*(.*)$", s)
    if m:
        return m.group(2).strip(), ("/*" in m.group(1))
    return None, False


def is_prose(line, in_fence):
    """Markdown：跳过代码块与行内代码整行。"""
    s = line.strip()
    if s.startswith("```"):
        return False, not in_fence
    if in_fence:
        return False, True
    if not s:
        return False, False
    if s.startswith("|") or s.startswith(">"):
        return True, False
    if s.startswith(("`", "$", "<!--")):
        return False, False
    return True, False


def scan(path):
    ext = path[path.rfind("."):].lower()
    if ext in CODE_EXT:
        mode = "code"
    elif ext in DOC_EXT:
        mode = "doc"
    else:
        return []

    hits = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().split("\n")

    in_block = False
    in_fence = False
    for no, raw in enumerate(lines, 1):
        if mode == "code":
            text, in_block = comment_text(raw, ext, in_block)
        else:
            ok, in_fence = is_prose(raw, in_fence)
            text = raw.strip() if ok else None
        if not text:
            continue
        # 行内代码不参与判定
        probe = re.sub(r"`[^`]*`", "", text)
        for label, pat in RULES:
            if re.search(pat, probe, re.I):
                hits.append((no, label, text[:120]))
                break
    return hits


def main(argv):
    targets = argv[1:] or ["main", "app", "scripts", "tools", "docs", "README.md"]
    paths = []
    for t in targets:
        import os
        if os.path.isdir(t):
            for root, _, files in os.walk(t):
                if ".git" in root or "node_modules" in root:
                    continue
                for f in files:
                    if f[f.rfind("."):].lower() in (CODE_EXT | DOC_EXT):
                        paths.append(os.path.join(root, f))
        elif os.path.isfile(t):
            paths.append(t)

    total = 0
    for p in sorted(paths):
        hits = scan(p)
        if not hits:
            continue
        total += len(hits)
        print(f"\n== {p}  {len(hits)} 处 ==")
        for no, label, text in hits:
            print(f"{no:5d}  [{label}]  {text}")
    print(f"\n合计 {total} 处 / 扫了 {len(paths)} 个文件")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
