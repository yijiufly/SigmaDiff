1: 
2: void FUN_0012d4c0(long param_1,long *param_2,uint param_3,uint **param_4,int param_5)
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
13: uint *puVar9;
14: uint **ppuVar10;
15: ulong uVar11;
16: ulong uVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: uint *puVar16;
21: uint *puVar17;
22: byte *pbVar18;
23: byte *pbVar19;
24: byte *pbVar20;
25: long lVar21;
26: ulong uVar22;
27: byte *pbStack112;
28: byte *pbStack104;
29: byte *pbStack96;
30: uint uStack76;
31: 
32: lVar4 = *(long *)(param_1 + 0x268);
33: uStack76 = *(uint *)(param_1 + 0x88);
34: lVar5 = *(long *)(param_1 + 0x1a8);
35: lVar6 = *(long *)(lVar4 + 0x10);
36: lVar7 = *(long *)(lVar4 + 0x28);
37: lVar8 = *(long *)(lVar4 + 0x18);
38: lVar4 = *(long *)(lVar4 + 0x20);
39: uVar22 = *(ulong *)(&DAT_0018cf00 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
40: while (param_5 = param_5 + -1, -1 < param_5) {
41: uVar11 = (ulong)param_3;
42: ppuVar10 = param_4 + 1;
43: param_3 = param_3 + 1;
44: pbStack112 = *(byte **)(*param_2 + uVar11 * 8);
45: pbStack104 = *(byte **)(param_2[1] + uVar11 * 8);
46: pbStack96 = *(byte **)(param_2[2] + uVar11 * 8);
47: puVar9 = *param_4;
48: puVar16 = puVar9;
49: if (((ulong)puVar9 & 3) != 0) {
50: bVar1 = *pbStack96;
51: bVar2 = *pbStack112;
52: bVar3 = *pbStack104;
53: lVar13 = (uVar22 & 0xff) + lVar5;
54: uStack76 = uStack76 - 1;
55: puVar16 = (uint *)((long)puVar9 + 2);
56: pbStack96 = pbStack96 + 1;
57: pbStack104 = pbStack104 + 1;
58: pbStack112 = pbStack112 + 1;
59: *(ushort *)puVar9 =
60: (ushort)((*(byte *)(lVar13 + (int)(*(int *)(lVar6 + (ulong)bVar1 * 4) + (uint)bVar2)) &
61: 0xf8) << 8) |
62: (ushort)(*(byte *)(lVar13 + (int)(*(int *)(lVar8 + (ulong)bVar3 * 4) + (uint)bVar2)) >> 3
63: ) |
64: (ushort)((*(byte *)((int)((uint)bVar2 +
65: (int)((ulong)(*(long *)(lVar4 + (ulong)bVar1 * 8) +
66: *(long *)(lVar7 + (ulong)bVar3 * 8)) >> 0x10)) +
67: lVar5 + (ulong)((uint)((long)uVar22 >> 1) & 0x7f)) & 0xfc) << 3);
68: }
69: if (uStack76 >> 1 != 0) {
70: lVar13 = (ulong)((uStack76 >> 1) - 1) + 1;
71: puVar9 = puVar16 + lVar13;
72: puVar17 = puVar16;
73: pbVar18 = pbStack112;
74: pbVar19 = pbStack104;
75: pbVar20 = pbStack96;
76: do {
77: bVar1 = *pbVar18;
78: lVar21 = (long)uVar22 >> 1;
79: uVar11 = (ulong)((uint)(uVar22 >> 8) & 0xffffff);
80: lVar14 = (uVar22 & 0xff) + lVar5;
81: uVar12 = uVar11 | (uVar22 & 0xff) << 0x18;
82: lVar15 = (uVar11 & 0xff) + lVar5;
83: uVar22 = (uVar11 & 0xff) << 0x18 | (long)uVar12 >> 8;
84: bVar2 = pbVar18[1];
85: puVar16 = puVar17 + 1;
86: *puVar17 = (uint)(*(byte *)(lVar14 + (int)(*(int *)(lVar8 + (ulong)*pbVar19 * 4) +
87: (uint)bVar1)) >> 3) |
88: (*(byte *)(lVar14 + (int)(*(int *)(lVar6 + (ulong)*pbVar20 * 4) + (uint)bVar1)) &
89: 0xf8) << 8 |
90: (*(byte *)((int)((uint)bVar1 +
91: (int)((ulong)(*(long *)(lVar4 + (ulong)*pbVar20 * 8) +
92: *(long *)(lVar7 + (ulong)*pbVar19 * 8)) >> 0x10)) +
93: lVar5 + (ulong)((uint)lVar21 & 0x7f)) & 0xfc) << 3 |
94: ((*(byte *)(lVar15 + (int)(*(int *)(lVar6 + (ulong)pbVar20[1] * 4) + (uint)bVar2)
95: ) & 0xf8) << 8 |
96: (uint)(*(byte *)(lVar15 + (int)(*(int *)(lVar8 + (ulong)pbVar19[1] * 4) +
97: (uint)bVar2)) >> 3) |
98: (*(byte *)((int)((int)((ulong)(*(long *)(lVar4 + (ulong)pbVar20[1] * 8) +
99: *(long *)(lVar7 + (ulong)pbVar19[1] * 8)) >> 0x10)
100: + (uint)bVar2) + lVar5 +
101: (ulong)((uint)((long)uVar12 >> 1) & 0x7f)) & 0xfc) << 3) << 0x10;
102: puVar17 = puVar16;
103: pbVar18 = pbVar18 + 2;
104: pbVar19 = pbVar19 + 2;
105: pbVar20 = pbVar20 + 2;
106: } while (puVar16 != puVar9);
107: lVar13 = lVar13 * 2;
108: pbStack112 = pbStack112 + lVar13;
109: pbStack104 = pbStack104 + lVar13;
110: pbStack96 = pbStack96 + lVar13;
111: }
112: param_4 = ppuVar10;
113: if ((uStack76 & 1) != 0) {
114: lVar13 = (uVar22 & 0xff) + lVar5;
115: bVar1 = *pbStack112;
116: *(ushort *)puVar16 =
117: (ushort)((*(byte *)(lVar13 + (int)(*(int *)(lVar6 + (ulong)*pbStack96 * 4) + (uint)bVar1)
118: ) & 0xf8) << 8) |
119: (ushort)(*(byte *)(lVar13 + (int)(*(int *)(lVar8 + (ulong)*pbStack104 * 4) + (uint)bVar1)
120: ) >> 3) |
121: (ushort)((*(byte *)((int)((uint)bVar1 +
122: (int)((ulong)(*(long *)(lVar4 + (ulong)*pbStack96 * 8) +
123: *(long *)(lVar7 + (ulong)*pbStack104 * 8)) >> 0x10)
124: ) + lVar5 + (ulong)((uint)((long)uVar22 >> 1) & 0x7f)) & 0xfc)
125: << 3);
126: }
127: }
128: return;
129: }
130: 
