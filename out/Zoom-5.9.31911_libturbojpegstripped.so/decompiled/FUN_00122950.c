1: 
2: void FUN_00122950(long param_1,long *param_2,uint param_3,ushort **param_4,int param_5)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: ushort *puVar8;
13: ushort **ppuVar9;
14: uint uVar10;
15: ulong uVar11;
16: byte *pbVar12;
17: long lVar13;
18: long lVar14;
19: byte *pbVar15;
20: byte *pbVar16;
21: ushort *puStack120;
22: byte *pbStack104;
23: byte *pbStack96;
24: byte *pbStack88;
25: uint uStack76;
26: 
27: lVar3 = *(long *)(param_1 + 0x268);
28: lVar4 = *(long *)(param_1 + 0x1a8);
29: uStack76 = *(uint *)(param_1 + 0x88);
30: lVar5 = *(long *)(lVar3 + 0x20);
31: lVar6 = *(long *)(lVar3 + 0x28);
32: lVar7 = *(long *)(lVar3 + 0x10);
33: lVar3 = *(long *)(lVar3 + 0x18);
34: while (param_5 = param_5 + -1, -1 < param_5) {
35: uVar11 = (ulong)param_3;
36: ppuVar9 = param_4 + 1;
37: param_3 = param_3 + 1;
38: pbStack104 = *(byte **)(*param_2 + uVar11 * 8);
39: pbStack96 = *(byte **)(param_2[1] + uVar11 * 8);
40: pbStack88 = *(byte **)(param_2[2] + uVar11 * 8);
41: puVar8 = *param_4;
42: puStack120 = puVar8;
43: if (((ulong)puVar8 & 3) != 0) {
44: uStack76 = uStack76 - 1;
45: bVar1 = *pbStack104;
46: puStack120 = puVar8 + 1;
47: *puVar8 = (ushort)((*(byte *)(lVar4 + (int)(*(int *)(lVar7 + (ulong)*pbStack88 * 4) +
48: (uint)bVar1)) & 0xf8) << 8) |
49: (ushort)(*(byte *)(lVar4 + (int)(*(int *)(lVar3 + (ulong)*pbStack96 * 4) +
50: (uint)bVar1)) >> 3) |
51: (ushort)((*(byte *)(lVar4 + (int)((uint)bVar1 +
52: (int)((ulong)(*(long *)(lVar6 + (ulong)*pbStack96 *
53: 8) +
54: *(long *)(lVar5 + (ulong)*pbStack88 *
55: 8)) >> 0x10))) &
56: 0xfc) << 3);
57: pbStack88 = pbStack88 + 1;
58: pbStack96 = pbStack96 + 1;
59: pbStack104 = pbStack104 + 1;
60: }
61: uVar10 = uStack76 >> 1;
62: if (uVar10 != 0) {
63: lVar13 = 0;
64: pbVar12 = pbStack104;
65: pbVar15 = pbStack96;
66: pbVar16 = pbStack88;
67: do {
68: bVar1 = *pbVar12;
69: bVar2 = pbVar12[1];
70: *(uint *)(puStack120 + lVar13 * 2) =
71: (*(byte *)(lVar4 + (int)(*(int *)(lVar7 + (ulong)*pbVar16 * 4) + (uint)bVar1)) & 0xf8)
72: << 8 | (uint)(*(byte *)(lVar4 + (int)(*(int *)(lVar3 + (ulong)*pbVar15 * 4) +
73: (uint)bVar1)) >> 3) |
74: (*(byte *)(lVar4 + (int)((uint)bVar1 +
75: (int)((ulong)(*(long *)(lVar6 + (ulong)*pbVar15 * 8) +
76: *(long *)(lVar5 + (ulong)*pbVar16 * 8)) >> 0x10)))
77: & 0xfc) << 3 |
78: ((*(byte *)(lVar4 + (int)(*(int *)(lVar7 + (ulong)pbVar16[1] * 4) + (uint)bVar2)) &
79: 0xf8) << 8 |
80: (uint)(*(byte *)(lVar4 + (int)(*(int *)(lVar3 + (ulong)pbVar15[1] * 4) + (uint)bVar2))
81: >> 3) |
82: (*(byte *)(lVar4 + (int)((uint)bVar2 +
83: (int)((ulong)(*(long *)(lVar6 + (ulong)pbVar15[1] * 8) +
84: *(long *)(lVar5 + (ulong)pbVar16[1] * 8)) >> 0x10)
85: )) & 0xfc) << 3) << 0x10;
86: lVar13 = lVar13 + 1;
87: pbVar12 = pbVar12 + 2;
88: pbVar15 = pbVar15 + 2;
89: pbVar16 = pbVar16 + 2;
90: } while ((uint)lVar13 < uVar10);
91: lVar14 = (ulong)(uVar10 - 1) + 1;
92: lVar13 = lVar14 * 2;
93: pbStack104 = pbStack104 + lVar13;
94: pbStack96 = pbStack96 + lVar13;
95: pbStack88 = pbStack88 + lVar13;
96: puStack120 = puStack120 + lVar14 * 2;
97: }
98: param_4 = ppuVar9;
99: if ((uStack76 & 1) != 0) {
100: bVar1 = *pbStack104;
101: *puStack120 = (ushort)((*(byte *)(lVar4 + (int)(*(int *)(lVar7 + (ulong)*pbStack88 * 4) +
102: (uint)bVar1)) & 0xf8) << 8) |
103: (ushort)(*(byte *)(lVar4 + (int)(*(int *)(lVar3 + (ulong)*pbStack96 * 4) +
104: (uint)bVar1)) >> 3) |
105: (ushort)((*(byte *)(lVar4 + (int)((uint)bVar1 +
106: (int)((ulong)(*(long *)(lVar6 + (ulong)*
107: pbStack96 * 8) +
108: *(long *)(lVar5 + (ulong)*pbStack88 * 8)) >> 0x10)
109: )) & 0xfc) << 3);
110: }
111: }
112: return;
113: }
114: 
