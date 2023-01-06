1: 
2: void FUN_00122ca0(long param_1,long *param_2,uint param_3,uint **param_4,int param_5)
3: 
4: {
5: byte *pbVar1;
6: long lVar2;
7: byte bVar3;
8: byte bVar4;
9: byte bVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: uint *puVar11;
16: uint **ppuVar12;
17: ulong uVar13;
18: ulong uVar14;
19: byte *pbVar15;
20: byte *pbVar16;
21: long lVar17;
22: ulong uVar18;
23: byte *pbVar19;
24: ulong uVar20;
25: uint *puStack160;
26: uint *puStack120;
27: byte *pbStack112;
28: byte *pbStack104;
29: byte *pbStack96;
30: uint uStack84;
31: 
32: lVar6 = *(long *)(param_1 + 0x268);
33: lVar7 = *(long *)(param_1 + 0x1a8);
34: uStack84 = *(uint *)(param_1 + 0x88);
35: lVar8 = *(long *)(lVar6 + 0x10);
36: lVar9 = *(long *)(lVar6 + 0x18);
37: lVar10 = *(long *)(lVar6 + 0x20);
38: lVar6 = *(long *)(lVar6 + 0x28);
39: uVar20 = *(ulong *)(&DAT_001896c0 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
40: while (param_5 = param_5 + -1, -1 < param_5) {
41: uVar13 = (ulong)param_3;
42: ppuVar12 = param_4 + 1;
43: param_3 = param_3 + 1;
44: pbStack112 = *(byte **)(*param_2 + uVar13 * 8);
45: pbStack104 = *(byte **)(param_2[1] + uVar13 * 8);
46: pbStack96 = *(byte **)(param_2[2] + uVar13 * 8);
47: puVar11 = *param_4;
48: puStack120 = puVar11;
49: if (((ulong)puVar11 & 3) != 0) {
50: lVar2 = lVar7 + (uVar20 & 0xff);
51: uStack84 = uStack84 - 1;
52: bVar3 = *pbStack112;
53: puStack120 = (uint *)((long)puVar11 + 2);
54: *(ushort *)puVar11 =
55: (ushort)((*(byte *)(lVar2 + (int)(*(int *)(lVar8 + (ulong)*pbStack96 * 4) + (uint)bVar3))
56: & 0xf8) << 8) |
57: (ushort)(*(byte *)(lVar2 + (int)(*(int *)(lVar9 + (ulong)*pbStack104 * 4) + (uint)bVar3))
58: >> 3) |
59: (ushort)((*(byte *)((int)((uint)bVar3 +
60: (int)((ulong)(*(long *)(lVar6 + (ulong)*pbStack104 * 8) +
61: *(long *)(lVar10 + (ulong)*pbStack96 * 8)) >> 0x10)
62: ) + lVar7 + ((long)(uVar20 & 0xff) >> 1)) & 0xfc) << 3);
63: pbStack96 = pbStack96 + 1;
64: pbStack104 = pbStack104 + 1;
65: pbStack112 = pbStack112 + 1;
66: }
67: if (uStack84 >> 1 != 0) {
68: uVar13 = (ulong)((uStack84 >> 1) - 1);
69: puStack160 = puStack120;
70: pbVar15 = pbStack112;
71: pbVar16 = pbStack96;
72: pbVar19 = pbStack104;
73: do {
74: bVar3 = *pbVar16;
75: uVar14 = (ulong)((uint)(uVar20 >> 8) & 0xffffff);
76: pbVar1 = pbVar16 + 1;
77: uVar18 = uVar20 & 0xff;
78: bVar4 = *pbVar15;
79: uVar20 = (uVar14 & 0xff) << 0x18 | (long)(uVar14 | (uVar20 & 0xff) << 0x18) >> 8;
80: bVar5 = pbVar15[1];
81: lVar2 = lVar7 + uVar18;
82: lVar17 = lVar7 + (uVar14 & 0xff);
83: pbVar16 = pbVar16 + 2;
84: *puStack160 = (*(byte *)(lVar2 + (int)(*(int *)(lVar8 + (ulong)bVar3 * 4) + (uint)bVar4)) &
85: 0xf8) << 8 |
86: (uint)(*(byte *)(lVar2 + (int)(*(int *)(lVar9 + (ulong)*pbVar19 * 4) +
87: (uint)bVar4)) >> 3) |
88: (*(byte *)((int)((uint)bVar4 +
89: (int)((ulong)(*(long *)(lVar6 + (ulong)*pbVar19 * 8) +
90: *(long *)(lVar10 + (ulong)bVar3 * 8)) >> 0x10)) +
91: lVar7 + ((long)uVar18 >> 1)) & 0xfc) << 3 |
92: ((uint)(*(byte *)(lVar17 + (int)(*(int *)(lVar9 + (ulong)pbVar19[1] * 4) +
93: (uint)bVar5)) >> 3) |
94: (*(byte *)(lVar17 + (int)((uint)bVar5 + *(int *)(lVar8 + (ulong)*pbVar1 * 4))
95: ) & 0xf8) << 8 |
96: (*(byte *)((int)((uint)bVar5 +
97: (int)((ulong)(*(long *)(lVar6 + (ulong)pbVar19[1] * 8) +
98: *(long *)(lVar10 + (ulong)*pbVar1 * 8)) >> 0x10))
99: + lVar7 + ((long)(uVar14 & 0xff) >> 1)) & 0xfc) << 3) << 0x10;
100: puStack160 = puStack160 + 1;
101: pbVar15 = pbVar15 + 2;
102: pbVar19 = pbVar19 + 2;
103: } while (pbVar16 != pbStack96 + uVar13 * 2 + 2);
104: lVar17 = uVar13 + 1;
105: lVar2 = lVar17 * 2;
106: pbStack112 = pbStack112 + lVar2;
107: pbStack104 = pbStack104 + lVar2;
108: pbStack96 = pbStack96 + lVar2;
109: puStack120 = puStack120 + lVar17;
110: }
111: param_4 = ppuVar12;
112: if ((uStack84 & 1) != 0) {
113: lVar2 = lVar7 + (uVar20 & 0xff);
114: bVar3 = *pbStack112;
115: *(ushort *)puStack120 =
116: (ushort)((*(byte *)(lVar2 + (int)(*(int *)(lVar8 + (ulong)*pbStack96 * 4) + (uint)bVar3))
117: & 0xf8) << 8) |
118: (ushort)(*(byte *)(lVar2 + (int)(*(int *)(lVar9 + (ulong)*pbStack104 * 4) + (uint)bVar3))
119: >> 3) |
120: (ushort)((*(byte *)((int)((uint)bVar3 +
121: (int)((ulong)(*(long *)(lVar6 + (ulong)*pbStack104 * 8) +
122: *(long *)(lVar10 + (ulong)*pbStack96 * 8)) >> 0x10)
123: ) + lVar7 + ((long)(uVar20 & 0xff) >> 1)) & 0xfc) << 3);
124: }
125: }
126: return;
127: }
128: 
