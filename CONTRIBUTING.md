# 贡献指南

## 提交前

```powershell
python scripts/selftest_b4.py COM4
python scripts/test_inject.py COM4
python scripts/test_sweep.py COM4
```

三条都要过。`test_sweep` 的用例带「预期」字段，加新命令时同步补用例，含至少一条 `reject`（喂非法参数，固件必须挡回）。

改了前端还要跑：

```powershell
cd app && npm run build:android
python scripts/verify_apk.py
```

## Issue

报告 bug 用模板，带上固件版本（`version` 命令输出）、板子型号、复现步骤、串口日志。

提功能先搜现有 issue。涉及发射、捕获、凭据相关的改动，描述里写清授权测试环境。

## PR

一个 PR 一件事。描述写三块：改了什么、为什么这么改、怎么验证的。

代码风格跟现有代码保持一致：

- 注释默认不写。只写 why、非显然的约束与坑、公开 API 契约。不写复述下一行的注释，不写装饰分隔线。
- 新增命令的 `META` 输出要跟现有字段命名一致，App 侧解析依赖这个约定。
- 不改与目标无关的格式、命名、注释。

## Commit

一句话说改了什么加为什么。正文只在 why 不明显时写。

```
wifi: 修正 AKM 套件只取前 2 字节的比较

AKM 是 4 字节（OUI 00-0F-AC + type），取前 2 字节当 uint16 比较时，
前两字节恒为 00 0F，比较永远失败。
```

## 安全

别在 issue 里公开漏洞细节。走 SECURITY.md 的私下报告流程。

## 许可证

GPL-3.0。贡献的代码默认按同一许可证授权。
