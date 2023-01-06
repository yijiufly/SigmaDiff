1: 
2: void FUN_00103150(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: 
8: if (*(int *)((long)param_1 + 0x24) != 100) {
9: pcVar1 = *param_1;
10: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
11: ppcVar2 = (code **)*param_1;
12: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
13: (**ppcVar2)();
14: }
15: (**(code **)(*param_1 + 0x20))(param_1);
16: (**(code **)(param_1[5] + 0x10))(param_1);
17: FUN_00115260(param_1);
18: (**(code **)(param_1[0x3a] + 0x20))(param_1);
19: /* WARNING: Could not recover jumptable at 0x001031a2. Too many branches */
20: /* WARNING: Treating indirect jump as call */
21: (**(code **)(param_1[5] + 0x20))(param_1);
22: return;
23: }
24: 
