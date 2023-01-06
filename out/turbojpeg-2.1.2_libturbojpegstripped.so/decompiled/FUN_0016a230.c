1: 
2: undefined8 FUN_0016a230(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: undefined8 uVar6;
11: long lVar7;
12: long lVar8;
13: undefined uVar9;
14: uint uVar10;
15: ulong uVar11;
16: long lVar12;
17: undefined *puVar13;
18: int iVar14;
19: undefined *puVar15;
20: 
21: uVar11 = (ulong)*(uint *)(param_1 + 0x3c);
22: iVar1 = *(int *)(param_2 + 0x50);
23: uVar6 = *(undefined8 *)(param_2 + 0x18);
24: iVar14 = *(int *)(param_1 + 0x30);
25: iVar2 = *(int *)(&DAT_00190860 + uVar11 * 4);
26: iVar3 = *(int *)(&DAT_00190800 + uVar11 * 4);
27: iVar4 = *(int *)(&DAT_001907a0 + uVar11 * 4);
28: iVar5 = *(int *)(&DAT_001906e0 + uVar11 * 4);
29: lVar12 = (long)*(int *)(&DAT_00190740 + uVar11 * 4);
30: lVar7 = **(long **)(param_2 + 0x20);
31: if (iVar1 == 0xff) {
32: if (iVar5 < 0) {
33: if (iVar14 != 0) {
34: puVar15 = (undefined *)(lVar7 + iVar4);
35: do {
36: uVar9 = FUN_00169820(param_1,uVar6,0xff);
37: puVar13 = puVar15 + -(long)iVar4;
38: *puVar15 = uVar9;
39: puVar15 = puVar15 + lVar12;
40: iVar14 = iVar14 + -1;
41: puVar13[iVar3] = uVar9;
42: puVar13[iVar2] = uVar9;
43: } while (iVar14 != 0);
44: }
45: }
46: else {
47: if (iVar14 != 0) {
48: puVar15 = (undefined *)(lVar7 + iVar4);
49: do {
50: uVar9 = FUN_00169820(param_1,uVar6,0xff);
51: puVar13 = puVar15 + -(long)iVar4;
52: *puVar15 = uVar9;
53: puVar15 = puVar15 + lVar12;
54: iVar14 = iVar14 + -1;
55: puVar13[iVar3] = uVar9;
56: puVar13[iVar2] = uVar9;
57: puVar13[iVar5] = 0xff;
58: } while (iVar14 != 0);
59: }
60: }
61: }
62: else {
63: lVar8 = *(long *)(param_2 + 0x48);
64: if (iVar5 < 0) {
65: if (iVar14 != 0) {
66: puVar15 = (undefined *)(lVar7 + iVar4);
67: do {
68: uVar10 = FUN_00169820(param_1,uVar6,iVar1);
69: puVar13 = puVar15 + -(long)iVar4;
70: uVar9 = *(undefined *)(lVar8 + (ulong)uVar10);
71: *puVar15 = uVar9;
72: puVar15 = puVar15 + lVar12;
73: iVar14 = iVar14 + -1;
74: puVar13[iVar3] = uVar9;
75: puVar13[iVar2] = uVar9;
76: } while (iVar14 != 0);
77: }
78: }
79: else {
80: if (iVar14 != 0) {
81: puVar15 = (undefined *)(lVar7 + iVar4);
82: do {
83: uVar10 = FUN_00169820(param_1,uVar6,iVar1);
84: uVar9 = *(undefined *)(lVar8 + (ulong)uVar10);
85: puVar13 = puVar15 + -(long)iVar4;
86: *puVar15 = uVar9;
87: puVar15 = puVar15 + lVar12;
88: iVar14 = iVar14 + -1;
89: puVar13[iVar3] = uVar9;
90: puVar13[iVar2] = uVar9;
91: puVar13[iVar5] = 0xff;
92: } while (iVar14 != 0);
93: }
94: }
95: }
96: return 1;
97: }
98: 
