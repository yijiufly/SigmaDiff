1: 
2: long FUN_0013d920(long param_1,undefined8 param_2,long param_3,ulong param_4)
3: 
4: {
5: ulong uVar1;
6: 
7: uVar1 = *(ulong *)(*(long *)(param_1 + 8) + 0x58);
8: if (uVar1 != 0) {
9: param_3 = 0;
10: if (param_4 < uVar1) {
11: param_3 = uVar1 - param_4;
12: }
13: }
14: return param_3;
15: }
16: 
