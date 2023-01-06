1: 
2: undefined8 FUN_00152650(code **param_1,long param_2)
3: 
4: {
5: undefined uVar1;
6: byte bVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: int iVar7;
12: int iVar8;
13: long lVar9;
14: code **ppcVar10;
15: long lVar11;
16: byte *pbVar12;
17: ulong uVar13;
18: size_t sVar14;
19: byte *pbVar15;
20: byte *pbVar16;
21: undefined *puVar17;
22: byte *pbVar18;
23: undefined *puVar19;
24: long lVar20;
25: 
26: uVar13 = (ulong)*(uint *)((long)param_1 + 0x3c);
27: lVar9 = *(long *)(param_2 + 0x48);
28: iVar3 = *(int *)(param_2 + 0x50);
29: lVar20 = (long)*(int *)(&DAT_0018c4a0 + uVar13 * 4);
30: iVar4 = *(int *)(&DAT_0018c440 + uVar13 * 4);
31: iVar5 = *(int *)(&DAT_0018c3e0 + uVar13 * 4);
32: iVar6 = *(int *)(&DAT_0018c320 + uVar13 * 4);
33: iVar7 = *(int *)(&DAT_0018c380 + uVar13 * 4);
34: sVar14 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18)
35: );
36: if (sVar14 != *(size_t *)(param_2 + 0x40)) {
37: ppcVar10 = (code **)*param_1;
38: *(undefined4 *)(ppcVar10 + 5) = 0x2b;
39: (**ppcVar10)(param_1);
40: }
41: iVar8 = *(int *)(param_1 + 6);
42: lVar11 = **(long **)(param_2 + 0x20);
43: pbVar12 = *(byte **)(param_2 + 0x30);
44: if (iVar3 == 0xff) {
45: if (iVar6 < 0) {
46: if (iVar8 != 0) {
47: pbVar15 = (byte *)(lVar11 + iVar5);
48: pbVar18 = pbVar12;
49: do {
50: pbVar16 = pbVar18 + 1;
51: bVar2 = *pbVar18;
52: pbVar18 = pbVar15 + -(long)iVar5;
53: *pbVar15 = bVar2;
54: pbVar15 = pbVar15 + iVar7;
55: pbVar18[iVar4] = bVar2;
56: pbVar18[lVar20] = bVar2;
57: pbVar18 = pbVar16;
58: } while (pbVar16 != pbVar12 + (ulong)(iVar8 - 1) + 1);
59: }
60: }
61: else {
62: if (iVar8 != 0) {
63: pbVar15 = (byte *)(lVar11 + iVar5);
64: pbVar18 = pbVar12;
65: do {
66: pbVar16 = pbVar18 + 1;
67: bVar2 = *pbVar18;
68: pbVar18 = pbVar15 + -(long)iVar5;
69: *pbVar15 = bVar2;
70: pbVar15 = pbVar15 + iVar7;
71: pbVar18[iVar4] = bVar2;
72: pbVar18[lVar20] = bVar2;
73: pbVar18[iVar6] = 0xff;
74: pbVar18 = pbVar16;
75: } while (pbVar16 != pbVar12 + (ulong)(iVar8 - 1) + 1);
76: }
77: }
78: }
79: else {
80: if (iVar6 < 0) {
81: if (iVar8 != 0) {
82: puVar19 = (undefined *)(lVar11 + iVar5);
83: pbVar18 = pbVar12;
84: do {
85: pbVar15 = pbVar18 + 1;
86: puVar17 = puVar19 + -(long)iVar5;
87: uVar1 = *(undefined *)(lVar9 + (ulong)*pbVar18);
88: *puVar19 = uVar1;
89: puVar19 = puVar19 + iVar7;
90: puVar17[iVar4] = uVar1;
91: puVar17[lVar20] = uVar1;
92: pbVar18 = pbVar15;
93: } while (pbVar15 != pbVar12 + (ulong)(iVar8 - 1) + 1);
94: }
95: }
96: else {
97: if (iVar8 != 0) {
98: puVar19 = (undefined *)(lVar11 + iVar5);
99: pbVar18 = pbVar12;
100: do {
101: pbVar15 = pbVar18 + 1;
102: uVar1 = *(undefined *)(lVar9 + (ulong)*pbVar18);
103: puVar17 = puVar19 + -(long)iVar5;
104: *puVar19 = uVar1;
105: puVar19 = puVar19 + iVar7;
106: puVar17[iVar4] = uVar1;
107: puVar17[lVar20] = uVar1;
108: puVar17[iVar6] = 0xff;
109: pbVar18 = pbVar15;
110: } while (pbVar15 != pbVar12 + (ulong)(iVar8 - 1) + 1);
111: }
112: }
113: }
114: return 1;
115: }
116: 
