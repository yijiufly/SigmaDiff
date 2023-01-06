1: 
2: void FUN_001459b0(long param_1,long *param_2,char **param_3,int param_4)
3: 
4: {
5: uint uVar1;
6: byte bVar2;
7: byte bVar3;
8: int iVar4;
9: int iVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: int iVar10;
15: long lVar11;
16: int iVar12;
17: long lVar13;
18: int iVar14;
19: short sVar15;
20: char *pcVar17;
21: short *psVar18;
22: byte *pbVar19;
23: int iVar20;
24: int iVar21;
25: long lVar22;
26: short *psStack168;
27: char **ppcStack160;
28: long *plStack136;
29: int iVar16;
30: 
31: iVar4 = *(int *)(param_1 + 0x90);
32: iVar5 = *(int *)(param_1 + 0x88);
33: lVar6 = *(long *)(param_1 + 0x270);
34: lVar7 = *(long *)(param_1 + 0x1a8);
35: if (0 < param_4) {
36: uVar1 = iVar5 - 1;
37: ppcStack160 = param_3;
38: plStack136 = param_2;
39: do {
40: FUN_00148a80();
41: iVar10 = *(int *)(lVar6 + 0x90);
42: if (0 < iVar4) {
43: lVar22 = 0;
44: do {
45: psStack168 = *(short **)(lVar6 + 0x70 + lVar22 * 8);
46: pbVar19 = (byte *)(*plStack136 + lVar22);
47: pcVar17 = *ppcStack160;
48: if (iVar10 == 0) {
49: lVar13 = 2;
50: lVar11 = 1;
51: iVar14 = iVar4;
52: }
53: else {
54: pbVar19 = pbVar19 + iVar4 * uVar1;
55: lVar11 = -1;
56: pcVar17 = pcVar17 + uVar1;
57: psStack168 = psStack168 + (iVar5 + 1);
58: lVar13 = -2;
59: iVar14 = -iVar4;
60: }
61: lVar8 = *(long *)(*(long *)(lVar6 + 0x30) + lVar22 * 8);
62: lVar9 = *(long *)(*(long *)(lVar6 + 0x20) + lVar22 * 8);
63: if (iVar5 == 0) {
64: sVar15 = 0;
65: }
66: else {
67: iVar16 = 0;
68: iVar10 = 0;
69: psVar18 = psStack168;
70: iVar20 = iVar5;
71: iVar21 = 0;
72: do {
73: psVar18 = (short *)((long)psVar18 + lVar13);
74: bVar2 = *pbVar19;
75: pbVar19 = pbVar19 + iVar14;
76: bVar2 = *(byte *)(lVar7 + (int)((uint)bVar2 + (iVar10 + 8 + (int)*psVar18 >> 4)));
77: bVar3 = *(byte *)(lVar8 + (ulong)bVar2);
78: *pcVar17 = *pcVar17 + bVar3;
79: pcVar17 = pcVar17 + lVar11;
80: iVar12 = (uint)bVar2 - (uint)*(byte *)(lVar9 + (ulong)bVar3);
81: *(short *)((long)psVar18 - lVar13) = (short)iVar16 + (short)iVar12 * 3;
82: iVar16 = iVar12 * 5 + iVar21;
83: sVar15 = (short)iVar16;
84: iVar10 = iVar12 * 7;
85: iVar20 = iVar20 + -1;
86: iVar21 = iVar12;
87: } while (iVar20 != 0);
88: psStack168 = (short *)((long)psStack168 + lVar13 * ((ulong)uVar1 + 1));
89: iVar10 = *(int *)(lVar6 + 0x90);
90: }
91: lVar22 = lVar22 + 1;
92: *psStack168 = sVar15;
93: } while ((int)lVar22 < iVar4);
94: }
95: ppcStack160 = ppcStack160 + 1;
96: plStack136 = plStack136 + 1;
97: *(uint *)(lVar6 + 0x90) = (uint)(iVar10 == 0);
98: } while (param_3 + (ulong)(param_4 - 1) + 1 != ppcStack160);
99: }
100: return;
101: }
102: 
