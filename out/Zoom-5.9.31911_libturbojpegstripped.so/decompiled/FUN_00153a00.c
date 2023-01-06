1: 
2: undefined8 FUN_00153a00(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: undefined8 uVar7;
12: long lVar8;
13: long lVar9;
14: undefined uVar10;
15: uint uVar11;
16: ulong uVar12;
17: undefined *puVar13;
18: int iVar14;
19: undefined *puVar15;
20: 
21: uVar12 = (ulong)*(uint *)(param_1 + 0x3c);
22: iVar1 = *(int *)(param_2 + 0x50);
23: uVar7 = *(undefined8 *)(param_2 + 0x18);
24: lVar8 = *(long *)(param_2 + 0x48);
25: iVar14 = *(int *)(param_1 + 0x30);
26: iVar2 = *(int *)(&DAT_0018c4a0 + uVar12 * 4);
27: iVar3 = *(int *)(&DAT_0018c380 + uVar12 * 4);
28: iVar4 = *(int *)(&DAT_0018c440 + uVar12 * 4);
29: iVar5 = *(int *)(&DAT_0018c3e0 + uVar12 * 4);
30: iVar6 = *(int *)(&DAT_0018c320 + uVar12 * 4);
31: lVar9 = **(long **)(param_2 + 0x20);
32: if (iVar1 == 0xff) {
33: if (iVar6 < 0) {
34: if (iVar14 != 0) {
35: puVar15 = (undefined *)(lVar9 + iVar5);
36: do {
37: uVar10 = FUN_00152a10(param_1,uVar7,0xff);
38: puVar13 = puVar15 + -(long)iVar5;
39: *puVar15 = uVar10;
40: puVar15 = puVar15 + iVar3;
41: iVar14 = iVar14 + -1;
42: puVar13[iVar4] = uVar10;
43: puVar13[iVar2] = uVar10;
44: } while (iVar14 != 0);
45: }
46: }
47: else {
48: if (iVar14 != 0) {
49: puVar15 = (undefined *)(lVar9 + iVar5);
50: do {
51: uVar10 = FUN_00152a10(param_1,uVar7,0xff);
52: puVar13 = puVar15 + -(long)iVar5;
53: *puVar15 = uVar10;
54: puVar15 = puVar15 + iVar3;
55: iVar14 = iVar14 + -1;
56: puVar13[iVar4] = uVar10;
57: puVar13[iVar2] = uVar10;
58: puVar13[iVar6] = 0xff;
59: } while (iVar14 != 0);
60: }
61: }
62: }
63: else {
64: if (iVar6 < 0) {
65: if (iVar14 != 0) {
66: puVar15 = (undefined *)(lVar9 + iVar5);
67: do {
68: uVar11 = FUN_00152a10(param_1,uVar7,iVar1);
69: puVar13 = puVar15 + -(long)iVar5;
70: uVar10 = *(undefined *)(lVar8 + (ulong)uVar11);
71: *puVar15 = uVar10;
72: puVar13[iVar4] = uVar10;
73: puVar15 = puVar15 + iVar3;
74: iVar14 = iVar14 + -1;
75: puVar13[iVar2] = uVar10;
76: } while (iVar14 != 0);
77: }
78: }
79: else {
80: if (iVar14 != 0) {
81: puVar15 = (undefined *)(lVar9 + iVar5);
82: do {
83: uVar11 = FUN_00152a10(param_1,uVar7,iVar1);
84: uVar10 = *(undefined *)(lVar8 + (ulong)uVar11);
85: puVar13 = puVar15 + -(long)iVar5;
86: *puVar15 = uVar10;
87: puVar13[iVar4] = uVar10;
88: puVar15 = puVar15 + iVar3;
89: iVar14 = iVar14 + -1;
90: puVar13[iVar2] = uVar10;
91: puVar13[iVar6] = 0xff;
92: } while (iVar14 != 0);
93: }
94: }
95: }
96: return 1;
97: }
98: 
