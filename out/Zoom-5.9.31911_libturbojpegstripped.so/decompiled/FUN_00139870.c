1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_00139870(long param_1,long param_2,long param_3,int param_4)
5: 
6: {
7: byte bVar1;
8: byte bVar2;
9: int iVar3;
10: int iVar4;
11: int iVar5;
12: long lVar6;
13: long lVar7;
14: long lVar8;
15: long lVar9;
16: uint uVar10;
17: int iVar11;
18: int iVar12;
19: short *psVar13;
20: char *pcVar14;
21: long lVar15;
22: byte *pbVar16;
23: int iVar17;
24: short sVar18;
25: int iVar20;
26: long lStack176;
27: long lStack168;
28: short *psStack160;
29: long lStack136;
30: int iVar19;
31: 
32: lVar6 = *(long *)(param_1 + 0x270);
33: lVar7 = *(long *)(param_1 + 0x1a8);
34: iVar3 = *(int *)(param_1 + 0x90);
35: iVar4 = *(int *)(param_1 + 0x88);
36: if (0 < param_4) {
37: uVar10 = iVar4 - 1;
38: lStack136 = 0;
39: do {
40: FUN_0013bed0(*(undefined8 *)(param_3 + lStack136),iVar4);
41: iVar12 = *(int *)(lVar6 + 0x90);
42: if (0 < iVar3) {
43: lStack168 = 0;
44: do {
45: pbVar16 = (byte *)(lStack168 + *(long *)(param_2 + lStack136));
46: pcVar14 = *(char **)(param_3 + lStack136);
47: if (iVar12 == 0) {
48: lStack176 = 1;
49: psStack160 = *(short **)(lVar6 + 0x70 + lStack168 * 8);
50: lVar15 = 2;
51: iVar5 = iVar3;
52: }
53: else {
54: pbVar16 = pbVar16 + iVar3 * uVar10;
55: pcVar14 = pcVar14 + uVar10;
56: psStack160 = (short *)((ulong)(iVar4 + 1) * 2 + *(long *)(lVar6 + 0x70 + lStack168 * 8))
57: ;
58: lStack176 = -1;
59: lVar15 = -2;
60: iVar5 = -iVar3;
61: }
62: lVar8 = *(long *)(*(long *)(lVar6 + 0x30) + lStack168 * 8);
63: lVar9 = *(long *)(*(long *)(lVar6 + 0x20) + lStack168 * 8);
64: if (iVar4 == 0) {
65: sVar18 = 0;
66: }
67: else {
68: iVar19 = 0;
69: iVar12 = 0;
70: psVar13 = psStack160;
71: iVar17 = iVar4;
72: iVar20 = 0;
73: do {
74: psVar13 = (short *)((long)psVar13 + lVar15);
75: bVar1 = *pbVar16;
76: pbVar16 = pbVar16 + iVar5;
77: bVar1 = *(byte *)(lVar7 + (int)((iVar12 + 8 + (int)*psVar13 >> 4) + (uint)bVar1));
78: bVar2 = *(byte *)(lVar8 + (ulong)bVar1);
79: *pcVar14 = *pcVar14 + bVar2;
80: pcVar14 = pcVar14 + lStack176;
81: iVar11 = (uint)bVar1 - (uint)*(byte *)(lVar9 + (ulong)bVar2);
82: iVar12 = iVar11 * 7;
83: iVar17 = iVar17 + -1;
84: *(short *)((long)psVar13 - lVar15) = (short)iVar19 + (short)iVar11 * 3;
85: iVar19 = iVar20 + iVar11 * 5;
86: sVar18 = (short)iVar19;
87: iVar20 = iVar11;
88: } while (iVar17 != 0);
89: psStack160 = (short *)((long)psStack160 + lVar15 * ((ulong)uVar10 + 1));
90: iVar12 = *(int *)(lVar6 + 0x90);
91: }
92: lStack168 = lStack168 + 1;
93: *psStack160 = sVar18;
94: } while ((int)lStack168 < iVar3);
95: }
96: lStack136 = lStack136 + 8;
97: *(uint *)(lVar6 + 0x90) = (uint)(iVar12 == 0);
98: } while (lStack136 != (ulong)(param_4 - 1) * 8 + 8);
99: }
100: return;
101: }
102: 
