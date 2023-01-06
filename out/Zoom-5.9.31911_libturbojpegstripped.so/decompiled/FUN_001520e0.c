1: 
2: undefined8 FUN_001520e0(code **param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: long lVar7;
12: code **ppcVar8;
13: long lVar9;
14: byte *pbVar10;
15: ulong uVar11;
16: size_t sVar12;
17: byte *pbVar13;
18: byte *pbVar14;
19: byte *pbVar15;
20: undefined *puVar16;
21: byte *pbVar17;
22: undefined *puVar18;
23: long lVar19;
24: 
25: uVar11 = (ulong)*(uint *)((long)param_1 + 0x3c);
26: lVar7 = *(long *)(param_2 + 0x48);
27: iVar1 = *(int *)(param_2 + 0x50);
28: lVar19 = (long)*(int *)(&DAT_0018c4a0 + uVar11 * 4);
29: iVar2 = *(int *)(&DAT_0018c440 + uVar11 * 4);
30: iVar3 = *(int *)(&DAT_0018c3e0 + uVar11 * 4);
31: iVar4 = *(int *)(&DAT_0018c320 + uVar11 * 4);
32: iVar5 = *(int *)(&DAT_0018c380 + uVar11 * 4);
33: sVar12 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18)
34: );
35: if (sVar12 != *(size_t *)(param_2 + 0x40)) {
36: ppcVar8 = (code **)*param_1;
37: *(undefined4 *)(ppcVar8 + 5) = 0x2b;
38: (**ppcVar8)(param_1);
39: }
40: iVar6 = *(int *)(param_1 + 6);
41: lVar9 = **(long **)(param_2 + 0x20);
42: pbVar10 = *(byte **)(param_2 + 0x30);
43: if (iVar1 == 0xff) {
44: if (iVar4 < 0) {
45: if (iVar6 != 0) {
46: pbVar13 = (byte *)(lVar9 + lVar19);
47: pbVar15 = pbVar10;
48: do {
49: pbVar14 = pbVar15 + 3;
50: *pbVar13 = *pbVar15;
51: pbVar17 = pbVar13 + -lVar19;
52: pbVar13 = pbVar13 + iVar5;
53: pbVar17[iVar2] = pbVar15[1];
54: pbVar17[iVar3] = pbVar15[2];
55: pbVar15 = pbVar14;
56: } while (pbVar14 != pbVar10 + (ulong)(iVar6 - 1) * 3 + 3);
57: }
58: }
59: else {
60: if (iVar6 != 0) {
61: pbVar13 = (byte *)(lVar9 + lVar19);
62: pbVar15 = pbVar10;
63: do {
64: pbVar14 = pbVar15 + 3;
65: *pbVar13 = *pbVar15;
66: pbVar17 = pbVar13 + -lVar19;
67: pbVar13 = pbVar13 + iVar5;
68: pbVar17[iVar2] = pbVar15[1];
69: pbVar17[iVar3] = pbVar15[2];
70: pbVar17[iVar4] = 0xff;
71: pbVar15 = pbVar14;
72: } while (pbVar14 != pbVar10 + (ulong)(iVar6 - 1) * 3 + 3);
73: }
74: }
75: }
76: else {
77: if (iVar4 < 0) {
78: if (iVar6 != 0) {
79: pbVar15 = pbVar10;
80: puVar18 = (undefined *)(lVar9 + lVar19);
81: do {
82: pbVar13 = pbVar15 + 3;
83: *puVar18 = *(undefined *)(lVar7 + (ulong)*pbVar15);
84: (puVar18 + -lVar19)[iVar2] = *(undefined *)(lVar7 + (ulong)pbVar15[1]);
85: (puVar18 + -lVar19)[iVar3] = *(undefined *)(lVar7 + (ulong)pbVar15[2]);
86: pbVar15 = pbVar13;
87: puVar18 = puVar18 + iVar5;
88: } while (pbVar10 + (ulong)(iVar6 - 1) * 3 + 3 != pbVar13);
89: }
90: }
91: else {
92: if (iVar6 != 0) {
93: pbVar15 = pbVar10;
94: puVar18 = (undefined *)(lVar9 + lVar19);
95: do {
96: pbVar13 = pbVar15 + 3;
97: *puVar18 = *(undefined *)(lVar7 + (ulong)*pbVar15);
98: puVar16 = puVar18 + -lVar19;
99: puVar16[iVar2] = *(undefined *)(lVar7 + (ulong)pbVar15[1]);
100: puVar16[iVar3] = *(undefined *)(lVar7 + (ulong)pbVar15[2]);
101: puVar16[iVar4] = 0xff;
102: pbVar15 = pbVar13;
103: puVar18 = puVar18 + iVar5;
104: } while (pbVar10 + (ulong)(iVar6 - 1) * 3 + 3 != pbVar13);
105: }
106: }
107: }
108: return 1;
109: }
110: 
