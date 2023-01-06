1: 
2: void FUN_001188c0(long param_1)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: long lVar3;
8: int iVar4;
9: long lVar5;
10: long lVar6;
11: undefined8 auStack72 [3];
12: 
13: lVar1 = *(long *)(param_1 + 0x1f0);
14: FUN_00118690();
15: iVar2 = *(int *)(param_1 + 0x144);
16: auStack72[0] = 0;
17: auStack72[1] = 0;
18: if (0 < iVar2) {
19: if (*(int *)(param_1 + 0x19c) == 0) {
20: if (*(int *)(param_1 + 0x1a4) == 0) {
21: lVar5 = (long)*(int *)(*(long *)(param_1 + 0x148) + 0x14);
22: if (*(int *)((long)auStack72 + lVar5 * 4) == 0) {
23: lVar6 = *(long *)(param_1 + (lVar5 + 0x10) * 8);
24: if (lVar6 == 0) {
25: lVar6 = FUN_00116780(param_1);
26: *(long *)(param_1 + (lVar5 + 0x10) * 8) = lVar6;
27: }
28: FUN_00111e20(param_1,lVar6,*(undefined8 *)(lVar1 + 0xa8 + lVar5 * 8));
29: *(undefined4 *)((long)auStack72 + lVar5 * 4) = 1;
30: iVar2 = *(int *)(param_1 + 0x144);
31: }
32: }
33: if (1 < iVar2) {
34: if ((*(int *)(param_1 + 0x1a4) == 0) &&
35: (lVar5 = (long)*(int *)(*(long *)(param_1 + 0x150) + 0x14),
36: *(int *)((long)auStack72 + lVar5 * 4) == 0)) {
37: lVar6 = *(long *)(param_1 + (lVar5 + 0x10) * 8);
38: if (lVar6 == 0) {
39: lVar6 = FUN_00116780(param_1);
40: *(long *)(param_1 + (lVar5 + 0x10) * 8) = lVar6;
41: }
42: FUN_00111e20(param_1,lVar6,*(undefined8 *)(lVar1 + 0xa8 + lVar5 * 8));
43: *(undefined4 *)((long)auStack72 + lVar5 * 4) = 1;
44: iVar2 = *(int *)(param_1 + 0x144);
45: }
46: if (2 < iVar2) {
47: if (*(int *)(param_1 + 0x1a4) == 0) {
48: lVar5 = (long)*(int *)(*(long *)(param_1 + 0x158) + 0x14);
49: if (*(int *)((long)auStack72 + lVar5 * 4) == 0) {
50: lVar6 = *(long *)(param_1 + (lVar5 + 0x10) * 8);
51: if (lVar6 == 0) {
52: lVar6 = FUN_00116780(param_1);
53: *(long *)(param_1 + (lVar5 + 0x10) * 8) = lVar6;
54: }
55: FUN_00111e20(param_1,lVar6,*(undefined8 *)(lVar1 + 0xa8 + lVar5 * 8));
56: *(undefined4 *)((long)auStack72 + lVar5 * 4) = 1;
57: iVar2 = *(int *)(param_1 + 0x144);
58: }
59: }
60: if (3 < iVar2) {
61: if ((*(int *)(param_1 + 0x1a4) == 0) &&
62: (lVar5 = (long)*(int *)(*(long *)(param_1 + 0x160) + 0x14),
63: *(int *)((long)auStack72 + lVar5 * 4) == 0)) {
64: lVar6 = *(long *)(param_1 + (lVar5 + 0x10) * 8);
65: if (lVar6 == 0) {
66: lVar6 = FUN_00116780(param_1);
67: *(long *)(param_1 + (lVar5 + 0x10) * 8) = lVar6;
68: }
69: FUN_00111e20(param_1,lVar6,*(undefined8 *)(lVar1 + 0xa8 + lVar5 * 8));
70: return;
71: }
72: }
73: }
74: }
75: }
76: else {
77: iVar4 = 0;
78: lVar5 = param_1;
79: do {
80: lVar6 = (long)*(int *)(*(long *)(lVar5 + 0x148) + 0x18);
81: if (*(int *)((long)auStack72 + lVar6 * 4) == 0) {
82: lVar3 = *(long *)(param_1 + (lVar6 + 0x14) * 8);
83: if (lVar3 == 0) {
84: lVar3 = FUN_00116780(param_1);
85: *(long *)(param_1 + (lVar6 + 0x14) * 8) = lVar3;
86: }
87: FUN_00111e20(param_1,lVar3,*(undefined8 *)(lVar1 + 0xa8 + lVar6 * 8));
88: iVar2 = *(int *)(param_1 + 0x144);
89: *(undefined4 *)((long)auStack72 + lVar6 * 4) = 1;
90: }
91: iVar4 = iVar4 + 1;
92: lVar5 = lVar5 + 8;
93: } while (iVar4 < iVar2);
94: }
95: }
96: return;
97: }
98: 
