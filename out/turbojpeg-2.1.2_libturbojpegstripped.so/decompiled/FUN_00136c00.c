1: 
2: void FUN_00136c00(code **param_1,int param_2,undefined8 param_3)
3: 
4: {
5: if (param_2 == 0xfe) {
6: *(undefined8 *)(param_1[0x49] + 0x28) = param_3;
7: return;
8: }
9: if (0xf < param_2 - 0xe0U) {
10: param_1 = (code **)*param_1;
11: *(undefined4 *)(param_1 + 5) = 0x44;
12: *(int *)((long)param_1 + 0x2c) = param_2;
13: /* WARNING: Could not recover jumptable at 0x00136c27. Too many branches */
14: /* WARNING: Treating indirect jump as call */
15: (**param_1)();
16: return;
17: }
18: *(undefined8 *)(param_1[0x49] + (long)(int)(param_2 - 0xe0U) * 8 + 0x30) = param_3;
19: return;
20: }
21: 
