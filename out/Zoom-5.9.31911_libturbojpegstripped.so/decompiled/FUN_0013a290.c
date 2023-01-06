1: 
2: void FUN_0013a290(code **param_1,int param_2)
3: 
4: {
5: undefined8 *puVar1;
6: code *pcVar2;
7: long lVar3;
8: long lVar4;
9: code *pcVar5;
10: int iVar6;
11: long lVar7;
12: 
13: pcVar2 = param_1[0x4e];
14: lVar3 = *(long *)(pcVar2 + 0x30);
15: if (*(int *)(param_1 + 0xe) == 0) {
16: iVar6 = 0;
17: pcVar5 = FUN_0013b250;
18: if (param_2 == 0) {
19: LAB_0013a2c8:
20: *(code **)(pcVar2 + 8) = pcVar5;
21: *(code **)(pcVar2 + 0x10) = FUN_0013a270;
22: if (*(int *)((long)param_1 + 0x9c) < 1) {
23: pcVar5 = *param_1;
24: *(undefined4 *)(pcVar5 + 0x28) = 0x38;
25: *(undefined4 *)(pcVar5 + 0x2c) = 1;
26: (**(code **)*param_1)(param_1);
27: iVar6 = *(int *)(param_1 + 0xe);
28: }
29: else {
30: if (0x100 < *(int *)((long)param_1 + 0x9c)) {
31: pcVar5 = *param_1;
32: *(undefined4 *)(pcVar5 + 0x28) = 0x39;
33: *(undefined4 *)(pcVar5 + 0x2c) = 0x100;
34: (**(code **)*param_1)(param_1);
35: iVar6 = *(int *)(param_1 + 0xe);
36: }
37: }
38: if (iVar6 == 2) {
39: lVar7 = *(long *)(pcVar2 + 0x40);
40: lVar4 = (ulong)(*(int *)(param_1 + 0x11) + 2) * 6;
41: if (lVar7 == 0) {
42: lVar7 = (**(code **)(param_1[1] + 8))(param_1,1,lVar4);
43: *(long *)(pcVar2 + 0x40) = lVar7;
44: }
45: FUN_0013bed0(lVar7,lVar4);
46: if (*(long *)(pcVar2 + 0x50) == 0) {
47: FUN_0013a0a0(param_1);
48: }
49: *(undefined4 *)(pcVar2 + 0x48) = 0;
50: }
51: if (*(int *)(pcVar2 + 0x38) == 0) {
52: return;
53: }
54: goto LAB_0013a320;
55: }
56: }
57: else {
58: *(undefined4 *)(param_1 + 0xe) = 2;
59: if (param_2 == 0) {
60: iVar6 = 2;
61: pcVar5 = FUN_0013b390;
62: goto LAB_0013a2c8;
63: }
64: }
65: *(undefined4 *)(pcVar2 + 0x38) = 1;
66: *(code **)(pcVar2 + 8) = FUN_0013a010;
67: *(code **)(pcVar2 + 0x10) = FUN_0013b7e0;
68: LAB_0013a320:
69: lVar7 = 0;
70: do {
71: puVar1 = (undefined8 *)(lVar3 + lVar7);
72: lVar7 = lVar7 + 8;
73: FUN_0013bed0(*puVar1,0x1000);
74: } while (lVar7 != 0x100);
75: *(undefined4 *)(pcVar2 + 0x38) = 0;
76: return;
77: }
78: 
