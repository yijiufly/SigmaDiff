1: 
2: undefined8 FUN_00168b50(code **param_1,long param_2)
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
15: byte *pbVar11;
16: long lVar12;
17: ulong uVar13;
18: size_t sVar14;
19: undefined *puVar15;
20: undefined *puVar16;
21: byte *pbVar17;
22: byte *pbVar18;
23: byte *pbVar19;
24: long lVar20;
25: 
26: uVar13 = (ulong)*(uint *)((long)param_1 + 0x3c);
27: lVar9 = *(long *)(param_2 + 0x48);
28: iVar3 = *(int *)(param_2 + 0x50);
29: iVar4 = *(int *)(&DAT_00190860 + uVar13 * 4);
30: lVar20 = (long)*(int *)(&DAT_00190800 + uVar13 * 4);
31: iVar5 = *(int *)(&DAT_001907a0 + uVar13 * 4);
32: iVar6 = *(int *)(&DAT_001906e0 + uVar13 * 4);
33: iVar7 = *(int *)(&DAT_00190740 + uVar13 * 4);
34: sVar14 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18)
35: );
36: if (*(size_t *)(param_2 + 0x40) != sVar14) {
37: ppcVar10 = (code **)*param_1;
38: *(undefined4 *)(ppcVar10 + 5) = 0x2b;
39: (**ppcVar10)(param_1);
40: }
41: pbVar11 = *(byte **)(param_2 + 0x30);
42: iVar8 = *(int *)(param_1 + 6);
43: lVar12 = **(long **)(param_2 + 0x20);
44: if (iVar3 == 0xff) {
45: if (iVar6 < 0) {
46: if (iVar8 != 0) {
47: pbVar18 = (byte *)(lVar12 + iVar5);
48: pbVar17 = pbVar11;
49: do {
50: pbVar19 = pbVar17 + 1;
51: bVar2 = *pbVar17;
52: pbVar17 = pbVar18 + -(long)iVar5;
53: *pbVar18 = bVar2;
54: pbVar18 = pbVar18 + iVar7;
55: pbVar17[lVar20] = bVar2;
56: pbVar17[iVar4] = bVar2;
57: pbVar17 = pbVar19;
58: } while (pbVar11 + (ulong)(iVar8 - 1) + 1 != pbVar19);
59: }
60: }
61: else {
62: if (iVar8 != 0) {
63: pbVar18 = (byte *)(lVar12 + iVar5);
64: pbVar17 = pbVar11;
65: do {
66: pbVar19 = pbVar17 + 1;
67: bVar2 = *pbVar17;
68: pbVar17 = pbVar18 + -(long)iVar5;
69: *pbVar18 = bVar2;
70: pbVar18 = pbVar18 + iVar7;
71: pbVar17[lVar20] = bVar2;
72: pbVar17[iVar4] = bVar2;
73: pbVar17[iVar6] = 0xff;
74: pbVar17 = pbVar19;
75: } while (pbVar11 + (ulong)(iVar8 - 1) + 1 != pbVar19);
76: }
77: }
78: }
79: else {
80: if (iVar6 < 0) {
81: if (iVar8 != 0) {
82: puVar15 = (undefined *)(lVar12 + iVar5);
83: pbVar17 = pbVar11;
84: do {
85: pbVar18 = pbVar17 + 1;
86: puVar16 = puVar15 + -(long)iVar5;
87: uVar1 = *(undefined *)(lVar9 + (ulong)*pbVar17);
88: *puVar15 = uVar1;
89: puVar15 = puVar15 + iVar7;
90: puVar16[lVar20] = uVar1;
91: puVar16[iVar4] = uVar1;
92: pbVar17 = pbVar18;
93: } while (pbVar18 != pbVar11 + (ulong)(iVar8 - 1) + 1);
94: }
95: }
96: else {
97: if (iVar8 != 0) {
98: puVar15 = (undefined *)(lVar12 + iVar5);
99: pbVar17 = pbVar11;
100: do {
101: pbVar18 = pbVar17 + 1;
102: uVar1 = *(undefined *)(lVar9 + (ulong)*pbVar17);
103: puVar16 = puVar15 + -(long)iVar5;
104: *puVar15 = uVar1;
105: puVar15 = puVar15 + iVar7;
106: puVar16[lVar20] = uVar1;
107: puVar16[iVar4] = uVar1;
108: puVar16[iVar6] = 0xff;
109: pbVar17 = pbVar18;
110: } while (pbVar18 != pbVar11 + (ulong)(iVar8 - 1) + 1);
111: }
112: }
113: }
114: return 1;
115: }
116: 
