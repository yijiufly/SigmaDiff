1: 
2: void FUN_00103000(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: 
8: iVar1 = *(int *)((long)param_1 + 0x24);
9: if (iVar1 != 100) {
10: ppcVar2 = (code **)*param_1;
11: *(undefined4 *)(ppcVar2 + 5) = 0x14;
12: *(int *)((long)ppcVar2 + 0x2c) = iVar1;
13: (**ppcVar2)();
14: }
15: if (param_2 != 0) {
16: FUN_00102c80(param_1,0);
17: }
18: (**(code **)(*param_1 + 0x20))(param_1);
19: (**(code **)(param_1[5] + 0x10))(param_1);
20: FUN_0011c010(param_1);
21: (**(code **)param_1[0x36])(param_1);
22: *(undefined4 *)(param_1 + 0x26) = 0;
23: *(uint *)((long)param_1 + 0x24) = (*(int *)(param_1 + 0x20) != 0) + 0x65;
24: return;
25: }
26: 
