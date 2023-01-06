1: 
2: undefined8 FUN_0011d4d0(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: int iVar3;
8: 
9: iVar3 = *(int *)((long)param_1 + 0x24);
10: if (iVar3 - 0xcdU < 2) {
11: if (*(int *)(param_1 + 0xb) == 0) {
12: if (*(uint *)(param_1 + 0x15) < *(uint *)((long)param_1 + 0x8c)) {
13: ppcVar2 = (code **)*param_1;
14: *(undefined4 *)(ppcVar2 + 5) = 0x43;
15: (**ppcVar2)();
16: }
17: (**(code **)(param_1[0x44] + 8))(param_1);
18: *(undefined4 *)((long)param_1 + 0x24) = 0xd2;
19: goto LAB_0011d502;
20: }
21: }
22: else {
23: if (iVar3 == 0xcf) {
24: *(undefined4 *)((long)param_1 + 0x24) = 0xd2;
25: goto LAB_0011d502;
26: }
27: if (iVar3 == 0xd2) goto LAB_0011d502;
28: }
29: pcVar1 = *param_1;
30: *(int *)(pcVar1 + 0x2c) = iVar3;
31: ppcVar2 = (code **)*param_1;
32: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
33: (**ppcVar2)(param_1);
34: LAB_0011d502:
35: do {
36: if (*(int *)((long)param_1[0x48] + 0x24) != 0) {
37: (**(code **)(param_1[5] + 0x30))(param_1);
38: FUN_001166f0(param_1);
39: return 1;
40: }
41: iVar3 = (**(code **)param_1[0x48])(param_1);
42: } while (iVar3 != 0);
43: return 0;
44: }
45: 
