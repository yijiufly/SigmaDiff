1: 
2: undefined4 FUN_00126600(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: 
8: iVar2 = *(int *)((long)param_1 + 0x24);
9: if (iVar2 - 0xcdU < 2) {
10: if (*(int *)(param_1 + 0xb) != 0) {
11: (**(code **)(param_1[0x44] + 8))();
12: *(undefined4 *)((long)param_1 + 0x24) = 0xd0;
13: goto LAB_0012664f;
14: }
15: }
16: else {
17: if (iVar2 == 0xd0) goto LAB_0012664f;
18: }
19: ppcVar1 = (code **)*param_1;
20: *(undefined4 *)(ppcVar1 + 5) = 0x14;
21: *(int *)((long)ppcVar1 + 0x2c) = iVar2;
22: (**ppcVar1)(param_1);
23: LAB_0012664f:
24: while (*(int *)((long)param_1 + 0xac) == *(int *)((long)param_1 + 0xb4) ||
25: *(int *)((long)param_1 + 0xac) < *(int *)((long)param_1 + 0xb4)) {
26: if (*(int *)((long)param_1[0x48] + 0x24) != 0) break;
27: iVar2 = (**(code **)param_1[0x48])(param_1);
28: if (iVar2 == 0) {
29: return 0;
30: }
31: }
32: *(undefined4 *)((long)param_1 + 0x24) = 0xcf;
33: return 1;
34: }
35: 
