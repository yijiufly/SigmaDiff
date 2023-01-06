1: 
2: void FUN_0012d1c0(long param_1,long *param_2,uint param_3,ushort **param_4,int param_5)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: byte bVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: ushort *puVar9;
14: ushort **ppuVar10;
15: long lVar11;
16: ulong uVar12;
17: long lVar13;
18: byte *pbVar14;
19: byte *pbVar15;
20: long lVar16;
21: byte *pbVar17;
22: ushort *puStack112;
23: uint uStack76;
24: 
25: lVar4 = *(long *)(param_1 + 0x268);
26: uStack76 = *(uint *)(param_1 + 0x88);
27: lVar5 = *(long *)(param_1 + 0x1a8);
28: lVar6 = *(long *)(lVar4 + 0x10);
29: lVar7 = *(long *)(lVar4 + 0x20);
30: lVar8 = *(long *)(lVar4 + 0x28);
31: lVar4 = *(long *)(lVar4 + 0x18);
32: while (param_5 = param_5 + -1, -1 < param_5) {
33: uVar12 = (ulong)param_3;
34: ppuVar10 = param_4 + 1;
35: param_3 = param_3 + 1;
36: pbVar17 = *(byte **)(*param_2 + uVar12 * 8);
37: pbVar14 = *(byte **)(param_2[1] + uVar12 * 8);
38: pbVar15 = *(byte **)(param_2[2] + uVar12 * 8);
39: puVar9 = *param_4;
40: puStack112 = puVar9;
41: if (((ulong)puVar9 & 3) != 0) {
42: bVar1 = *pbVar15;
43: puStack112 = puVar9 + 1;
44: bVar2 = *pbVar17;
45: bVar3 = *pbVar14;
46: pbVar15 = pbVar15 + 1;
47: uStack76 = uStack76 - 1;
48: pbVar14 = pbVar14 + 1;
49: pbVar17 = pbVar17 + 1;
50: *puVar9 = (ushort)(*(byte *)(lVar5 + (int)(*(int *)(lVar4 + (ulong)bVar3 * 4) + (uint)bVar2))
51: >> 3) |
52: (ushort)((*(byte *)(lVar5 + (int)(*(int *)(lVar6 + (ulong)bVar1 * 4) + (uint)bVar2))
53: & 0xf8) << 8) |
54: (ushort)((*(byte *)(lVar5 + (int)((int)((ulong)(*(long *)(lVar7 + (ulong)bVar1 * 8)
55: + *(long *)(lVar8 + (ulong)bVar3 * 8)
56: ) >> 0x10) + (uint)bVar2)) & 0xfc) <<
57: 3);
58: }
59: if (uStack76 >> 1 != 0) {
60: lVar16 = 0;
61: lVar13 = (ulong)((uStack76 >> 1) - 1) + 1;
62: lVar11 = lVar13 * 2;
63: do {
64: bVar1 = pbVar17[lVar16 + 1];
65: bVar2 = pbVar17[lVar16];
66: *(uint *)(puStack112 + lVar16) =
67: ((uint)(*(byte *)(lVar5 + (int)(*(int *)(lVar4 + (ulong)pbVar14[lVar16 + 1] * 4) +
68: (uint)bVar1)) >> 3) |
69: (*(byte *)(lVar5 + (int)(*(int *)(lVar6 + (ulong)pbVar15[lVar16 + 1] * 4) +
70: (uint)bVar1)) & 0xf8) << 8 |
71: (*(byte *)(lVar5 + (int)((int)((ulong)(*(long *)(lVar7 + (ulong)pbVar15[lVar16 + 1] * 8
72: ) +
73: *(long *)(lVar8 + (ulong)pbVar14[lVar16 + 1] * 8)
74: ) >> 0x10) + (uint)bVar1)) & 0xfc) << 3) << 0x10
75: | (uint)(*(byte *)(lVar5 + (int)(*(int *)(lVar4 + (ulong)pbVar14[lVar16] * 4) +
76: (uint)bVar2)) >> 3) |
77: (*(byte *)(lVar5 + (int)(*(int *)(lVar6 + (ulong)pbVar15[lVar16] * 4) + (uint)bVar2))
78: & 0xf8) << 8 |
79: (*(byte *)(lVar5 + (int)((uint)bVar2 +
80: (int)((ulong)(*(long *)(lVar7 + (ulong)pbVar15[lVar16] * 8) +
81: *(long *)(lVar8 + (ulong)pbVar14[lVar16] * 8))
82: >> 0x10))) & 0xfc) << 3;
83: lVar16 = lVar16 + 2;
84: } while (lVar11 != lVar16);
85: pbVar17 = pbVar17 + lVar11;
86: pbVar14 = pbVar14 + lVar11;
87: pbVar15 = pbVar15 + lVar11;
88: puStack112 = puStack112 + lVar13 * 2;
89: }
90: param_4 = ppuVar10;
91: if ((uStack76 & 1) != 0) {
92: bVar1 = *pbVar17;
93: *puStack112 = (ushort)(*(byte *)(lVar5 + (int)(*(int *)(lVar4 + (ulong)*pbVar14 * 4) +
94: (uint)bVar1)) >> 3) |
95: (ushort)((*(byte *)(lVar5 + (int)(*(int *)(lVar6 + (ulong)*pbVar15 * 4) +
96: (uint)bVar1)) & 0xf8) << 8) |
97: (ushort)((*(byte *)(lVar5 + (int)((uint)bVar1 +
98: (int)((ulong)(*(long *)(lVar7 + (ulong)*pbVar15
99: * 8) +
100: *(long *)(lVar8 + (ulong)*pbVar14
101: * 8)) >> 0x10)))
102: & 0xfc) << 3);
103: }
104: }
105: return;
106: }
107: 
