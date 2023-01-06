1: 
2: void FUN_0012bdb0(code **param_1,int param_2,undefined8 param_3)
3: 
4: {
5: code *pcVar1;
6: 
7: if (param_2 == 0xfe) {
8: *(undefined8 *)(param_1[0x49] + 0x28) = param_3;
9: return;
10: }
11: if (param_2 - 0xe0U < 0x10) {
12: *(undefined8 *)(param_1[0x49] + (long)(int)(param_2 - 0xe0U) * 8 + 0x30) = param_3;
13: return;
14: }
15: pcVar1 = *param_1;
16: *(undefined4 *)(pcVar1 + 0x28) = 0x44;
17: *(int *)(pcVar1 + 0x2c) = param_2;
18: /* WARNING: Could not recover jumptable at 0x0012bdeb. Too many branches */
19: /* WARNING: Treating indirect jump as call */
20: (**(code **)*param_1)();
21: return;
22: }
23: 
