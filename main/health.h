#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* 整机自检. 只读状态, 不改任何模块.
 * --json 输出见实现; 字段名单在 scripts/test_sweep.py 的 REQUIRED_HEALTH 里,
 * 加字段要同步. */
int cmd_health(int argc, char **argv);

#ifdef __cplusplus
}
#endif
