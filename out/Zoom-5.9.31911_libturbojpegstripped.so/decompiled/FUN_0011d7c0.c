1: 
2: void FUN_0011d7c0(code **param_1,uint *param_2,uint *param_3)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: bool bVar5;
10: bool bVar6;
11: uint uVar7;
12: int iVar8;
13: long lVar9;
14: long lVar10;
15: int iVar11;
16: int iVar12;
17: uint uVar13;
18: code *pcVar14;
19: 
20: if ((*(int *)((long)param_1 + 0x24) != 0xcd) || (*(int *)(param_1 + 0x15) != 0)) {
21: pcVar3 = *param_1;
22: *(int *)(pcVar3 + 0x2c) = *(int *)((long)param_1 + 0x24);
23: ppcVar4 = (code **)*param_1;
24: *(undefined4 *)(pcVar3 + 0x28) = 0x14;
25: (**ppcVar4)();
26: }
27: if ((param_2 == (uint *)0x0) || (param_3 == (uint *)0x0)) {
28: ppcVar4 = (code **)*param_1;
29: *(undefined4 *)(ppcVar4 + 5) = 0x7c;
30: (**ppcVar4)();
31: }
32: uVar13 = *param_3;
33: if ((uVar13 == 0) || (*(uint *)(param_1 + 0x11) < *param_2 + uVar13)) {
34: ppcVar4 = (code **)*param_1;
35: *(undefined4 *)(ppcVar4 + 5) = 0x46;
36: (**ppcVar4)();
37: if (*param_3 == *(uint *)(param_1 + 0x11)) {
38: return;
39: }
40: }
41: else {
42: if (uVar13 == *(uint *)(param_1 + 0x11)) {
43: return;
44: }
45: }
46: if ((*(int *)(param_1 + 0x36) == 1) && (*(int *)(param_1 + 7) == 1)) {
47: uVar13 = *(uint *)(param_1 + 0x34);
48: }
49: else {
50: uVar13 = *(int *)(param_1 + 0x34) * *(int *)(param_1 + 0x33);
51: }
52: uVar1 = *param_2;
53: uVar7 = (uVar1 / uVar13) * uVar13;
54: *param_2 = uVar7;
55: uVar7 = (uVar1 + *param_3) - uVar7;
56: lVar9 = (long)(int)uVar13;
57: *param_3 = uVar7;
58: *(uint *)(param_1 + 0x11) = uVar7;
59: uVar13 = *param_2;
60: pcVar3 = param_1[0x44];
61: *(int *)(pcVar3 + 0x14) = (int)((long)(ulong)uVar13 / lVar9);
62: iVar8 = FUN_0013be20(uVar7 + *param_2,lVar9,(long)(ulong)uVar13 % lVar9);
63: pcVar14 = param_1[0x26];
64: *(int *)(pcVar3 + 0x18) = iVar8 + -1;
65: iVar8 = *(int *)(param_1 + 7);
66: if (0 < iVar8) {
67: iVar11 = 0;
68: bVar6 = false;
69: do {
70: if ((*(int *)(param_1 + 0x36) == 1) && (iVar8 == 1)) {
71: iVar8 = 1;
72: iVar12 = *(int *)(pcVar14 + 8);
73: }
74: else {
75: iVar8 = *(int *)(pcVar14 + 8);
76: iVar12 = iVar8;
77: }
78: iVar2 = *(int *)(pcVar14 + 0x28);
79: uVar13 = FUN_0013be20(iVar12 * *(int *)(param_1 + 0x11),(long)*(int *)(param_1 + 0x33));
80: *(uint *)(pcVar14 + 0x28) = uVar13;
81: bVar5 = bVar6;
82: if ((uVar13 < 2) && (bVar5 = true, iVar2 < 2)) {
83: bVar5 = bVar6;
84: }
85: pcVar3 = param_1[0x44];
86: lVar10 = (long)iVar11;
87: iVar11 = iVar11 + 1;
88: pcVar14 = pcVar14 + 0x60;
89: uVar13 = *param_2;
90: *(int *)(pcVar3 + lVar10 * 4 + 0x1c) = (int)((long)(ulong)(iVar8 * uVar13) / lVar9);
91: iVar8 = FUN_0013be20(iVar8 * (*param_2 + *(int *)(param_1 + 0x11)),lVar9,
92: (long)(ulong)(iVar8 * uVar13) % lVar9);
93: *(int *)(pcVar3 + lVar10 * 4 + 0x44) = iVar8 + -1;
94: iVar8 = *(int *)(param_1 + 7);
95: bVar6 = bVar5;
96: } while (iVar11 < iVar8);
97: if (bVar5) {
98: *(undefined4 *)(param_1[0x44] + 0x6c) = 1;
99: FUN_001327d0(param_1);
100: *(undefined4 *)(param_1[0x44] + 0x6c) = 0;
101: return;
102: }
103: }
104: return;
105: }
106: 
