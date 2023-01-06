1: 
2: void FUN_00102fa0(code **param_1)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: 
8: iVar1 = *(int *)((long)param_1 + 0x24);
9: ppcVar2 = (code **)*param_1;
10: if (iVar1 != 100) {
11: *(undefined4 *)(ppcVar2 + 5) = 0x14;
12: *(int *)((long)ppcVar2 + 0x2c) = iVar1;
13: (**ppcVar2)();
14: ppcVar2 = (code **)*param_1;
15: }
16: (*ppcVar2[4])(param_1);
17: (**(code **)(param_1[5] + 0x10))(param_1);
18: FUN_0011e1b0(param_1);
19: (**(code **)(param_1[0x3a] + 0x20))(param_1);
20: /* WARNING: Could not recover jumptable at 0x00102fef. Too many branches */
21: /* WARNING: Treating indirect jump as call */
22: (**(code **)(param_1[5] + 0x20))(param_1);
23: return;
24: }
25: 
