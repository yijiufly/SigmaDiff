1: 
2: undefined8 FUN_0011e580(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: int iVar3;
8: 
9: iVar3 = *(int *)((long)param_1 + 0x24);
10: if (iVar3 - 0xcdU < 2) {
11: if (*(int *)(param_1 + 0xb) != 0) {
12: (**(code **)(param_1[0x44] + 8))();
13: *(undefined4 *)((long)param_1 + 0x24) = 0xd0;
14: goto LAB_0011e5d7;
15: }
16: }
17: else {
18: if (iVar3 == 0xd0) goto LAB_0011e5d7;
19: }
20: pcVar1 = *param_1;
21: *(int *)(pcVar1 + 0x2c) = iVar3;
22: ppcVar2 = (code **)*param_1;
23: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
24: (**ppcVar2)(param_1);
25: if (*(int *)((long)param_1 + 0xac) == *(int *)((long)param_1 + 0xb4) ||
26: *(int *)((long)param_1 + 0xac) < *(int *)((long)param_1 + 0xb4)) {
27: do {
28: if (*(int *)((long)param_1[0x48] + 0x24) != 0) break;
29: iVar3 = (**(code **)param_1[0x48])(param_1);
30: if (iVar3 == 0) {
31: return 0;
32: }
33: LAB_0011e5d7:
34: } while (*(int *)((long)param_1 + 0xac) == *(int *)((long)param_1 + 0xb4) ||
35: *(int *)((long)param_1 + 0xac) < *(int *)((long)param_1 + 0xb4));
36: }
37: *(undefined4 *)((long)param_1 + 0x24) = 0xcf;
38: return 1;
39: }
40: 
