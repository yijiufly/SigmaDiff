1: 
2: void FUN_001030e0(code **param_1,ulong param_2,ulong param_3)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: 
8: if ((*(int *)(param_1 + 0x26) != 0) || (2 < *(int *)((long)param_1 + 0x24) - 0x65U)) {
9: pcVar1 = *param_1;
10: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
11: ppcVar2 = (code **)*param_1;
12: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
13: (**ppcVar2)(param_1);
14: param_3 = param_3 & 0xffffffff;
15: param_2 = param_2 & 0xffffffff;
16: }
17: /* WARNING: Could not recover jumptable at 0x00103135. Too many branches */
18: /* WARNING: Treating indirect jump as call */
19: (**(code **)(param_1[0x3a] + 0x28))(param_1,param_2,param_3);
20: return;
21: }
22: 
