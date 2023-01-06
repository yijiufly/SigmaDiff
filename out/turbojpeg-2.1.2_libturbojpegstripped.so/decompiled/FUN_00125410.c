1: 
2: undefined4 FUN_00125410(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: 
8: iVar2 = *(int *)((long)param_1 + 0x24);
9: if (iVar2 - 0xcdU < 2) {
10: if (*(int *)(param_1 + 0xb) == 0) {
11: if (*(uint *)(param_1 + 0x15) < *(uint *)((long)param_1 + 0x8c)) {
12: ppcVar1 = (code **)*param_1;
13: *(undefined4 *)(ppcVar1 + 5) = 0x43;
14: (**ppcVar1)();
15: }
16: (**(code **)(param_1[0x44] + 8))(param_1);
17: *(undefined4 *)((long)param_1 + 0x24) = 0xd2;
18: goto LAB_00125459;
19: }
20: }
21: else {
22: if (iVar2 == 0xcf) {
23: *(undefined4 *)((long)param_1 + 0x24) = 0xd2;
24: goto LAB_00125459;
25: }
26: if (iVar2 == 0xd2) goto LAB_00125459;
27: }
28: ppcVar1 = (code **)*param_1;
29: *(undefined4 *)(ppcVar1 + 5) = 0x14;
30: *(int *)((long)ppcVar1 + 0x2c) = iVar2;
31: (**ppcVar1)(param_1);
32: LAB_00125459:
33: do {
34: if (*(int *)((long)param_1[0x48] + 0x24) != 0) {
35: (**(code **)(param_1[5] + 0x30))(param_1);
36: FUN_0011f490(param_1);
37: return 1;
38: }
39: iVar2 = (**(code **)param_1[0x48])(param_1);
40: } while (iVar2 != 0);
41: return 0;
42: }
43: 
