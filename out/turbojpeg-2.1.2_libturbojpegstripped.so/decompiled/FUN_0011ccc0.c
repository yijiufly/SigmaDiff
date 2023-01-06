1: 
2: void FUN_0011ccc0(long *param_1)
3: 
4: {
5: bool bVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: undefined8 uVar5;
10: int iVar6;
11: int iVar7;
12: 
13: iVar7 = 0;
14: iVar2 = *(int *)((long)param_1 + 0x4c);
15: if (0 < iVar2) {
16: iVar6 = 0;
17: do {
18: iVar6 = iVar6 + 1;
19: iVar2 = FUN_0011ca80(param_1);
20: iVar7 = iVar7 + iVar2;
21: iVar2 = *(int *)((long)param_1 + 0x4c);
22: } while (iVar6 < iVar2);
23: }
24: iVar6 = *(int *)((long)param_1 + 0x134);
25: if (*(int *)((long)param_1 + 0x104) == 0) {
26: if (iVar6 != 0) {
27: LAB_0011cd12:
28: uVar5 = 0xc2;
29: goto LAB_0011cd17;
30: }
31: if (*(int *)(param_1 + 9) == 8) {
32: lVar4 = param_1[0xb];
33: if (iVar2 < 1) {
34: if (iVar7 == 0) {
35: LAB_0011cde6:
36: uVar5 = 0xc0;
37: goto LAB_0011cd17;
38: }
39: }
40: else {
41: bVar1 = true;
42: lVar3 = ((ulong)(iVar2 - 1) * 3 + 3) * 0x20 + lVar4;
43: do {
44: if (*(int *)(lVar4 + 0x14) < 2) {
45: if (1 < *(int *)(lVar4 + 0x18)) {
46: bVar1 = false;
47: }
48: }
49: else {
50: bVar1 = false;
51: }
52: lVar4 = lVar4 + 0x60;
53: } while (lVar3 != lVar4);
54: if ((iVar7 == 0) || (!bVar1)) {
55: if (bVar1) goto LAB_0011cde6;
56: goto LAB_0011cd86;
57: }
58: }
59: lVar4 = *param_1;
60: *(undefined4 *)(lVar4 + 0x28) = 0x4b;
61: (**(code **)(lVar4 + 8))(param_1,0);
62: if (*(int *)((long)param_1 + 0x104) != 0) {
63: iVar6 = *(int *)((long)param_1 + 0x134);
64: goto LAB_0011cd68;
65: }
66: if (*(int *)((long)param_1 + 0x134) != 0) goto LAB_0011cd12;
67: }
68: LAB_0011cd86:
69: uVar5 = 0xc1;
70: }
71: else {
72: LAB_0011cd68:
73: uVar5 = 0xca;
74: if (iVar6 == 0) {
75: uVar5 = 0xc9;
76: }
77: }
78: LAB_0011cd17:
79: FUN_0011c4e0(param_1,uVar5);
80: return;
81: }
82: 
