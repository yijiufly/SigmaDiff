1: 
2: void FUN_00102f30(code **param_1,undefined4 param_2,undefined4 param_3)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: 
8: iVar1 = *(int *)((long)param_1 + 0x24);
9: if ((*(int *)(param_1 + 0x26) != 0) || (2 < iVar1 - 0x65U)) {
10: ppcVar2 = (code **)*param_1;
11: *(undefined4 *)(ppcVar2 + 5) = 0x14;
12: *(int *)((long)ppcVar2 + 0x2c) = iVar1;
13: (**ppcVar2)(param_1);
14: }
15: /* WARNING: Could not recover jumptable at 0x00102f72. Too many branches */
16: /* WARNING: Treating indirect jump as call */
17: (**(code **)(param_1[0x3a] + 0x28))(param_1,param_2,param_3);
18: return;
19: }
20: 
