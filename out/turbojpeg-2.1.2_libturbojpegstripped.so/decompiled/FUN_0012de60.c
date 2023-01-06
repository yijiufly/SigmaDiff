1: 
2: void FUN_0012de60(long param_1,long *param_2,uint param_3,ushort **param_4,int param_5)
3: 
4: {
5: byte bVar1;
6: long lVar2;
7: byte *pbVar3;
8: byte *pbVar4;
9: ushort *puVar5;
10: ushort **ppuVar6;
11: ulong uVar7;
12: ulong uVar8;
13: long lVar9;
14: byte *pbVar10;
15: byte *pbVar11;
16: long lVar12;
17: ulong uVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: byte *pbVar17;
22: ushort *puVar18;
23: long lVar19;
24: uint uStack60;
25: 
26: uStack60 = *(uint *)(param_1 + 0x88);
27: lVar2 = *(long *)(param_1 + 0x1a8);
28: uVar13 = *(ulong *)(&DAT_0018cf00 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
29: while (param_5 = param_5 + -1, -1 < param_5) {
30: uVar7 = (ulong)param_3;
31: ppuVar6 = param_4 + 1;
32: pbVar3 = *(byte **)(*param_2 + uVar7 * 8);
33: param_3 = param_3 + 1;
34: pbVar11 = *(byte **)(param_2[1] + uVar7 * 8);
35: pbVar4 = *(byte **)(param_2[2] + uVar7 * 8);
36: puVar5 = *param_4;
37: pbVar10 = pbVar3;
38: pbVar17 = pbVar4;
39: puVar18 = puVar5;
40: if (((ulong)puVar5 & 3) != 0) {
41: bVar1 = *pbVar11;
42: lVar9 = (uVar13 & 0xff) + lVar2;
43: uStack60 = uStack60 - 1;
44: puVar18 = puVar5 + 1;
45: pbVar17 = pbVar4 + 1;
46: pbVar11 = pbVar11 + 1;
47: pbVar10 = pbVar3 + 1;
48: *puVar5 = (ushort)((*(byte *)(lVar9 + (ulong)*pbVar3) & 0xf8) << 8) |
49: (ushort)((*(byte *)((ulong)((uint)((long)uVar13 >> 1) & 0x7f) + lVar2 + (ulong)bVar1
50: ) & 0xfc) << 3) |
51: (ushort)(*(byte *)(lVar9 + (ulong)*pbVar4) >> 3);
52: }
53: if (uStack60 >> 1 != 0) {
54: lVar14 = 0;
55: lVar19 = (ulong)((uStack60 >> 1) - 1) + 1;
56: lVar9 = lVar19 * 2;
57: do {
58: lVar15 = (uVar13 & 0xff) + lVar2;
59: lVar12 = (long)uVar13 >> 1;
60: uVar7 = (ulong)((uint)(uVar13 >> 8) & 0xffffff);
61: uVar8 = uVar7 | (uVar13 & 0xff) << 0x18;
62: lVar16 = (uVar7 & 0xff) + lVar2;
63: uVar13 = (uVar7 & 0xff) << 0x18 | (long)uVar8 >> 8;
64: *(uint *)(puVar18 + lVar14) =
65: (*(byte *)((ulong)((uint)lVar12 & 0x7f) + lVar2 + (ulong)pbVar11[lVar14]) & 0xfc) << 3
66: | (*(byte *)(lVar15 + (ulong)pbVar10[lVar14]) & 0xf8) << 8 |
67: (uint)(*(byte *)(lVar15 + (ulong)pbVar17[lVar14]) >> 3) |
68: ((*(byte *)(lVar16 + (ulong)pbVar10[lVar14 + 1]) & 0xf8) << 8 |
69: (uint)(*(byte *)(lVar16 + (ulong)pbVar17[lVar14 + 1]) >> 3) |
70: (*(byte *)((ulong)((uint)((long)uVar8 >> 1) & 0x7f) + lVar2 +
71: (ulong)pbVar11[lVar14 + 1]) & 0xfc) << 3) << 0x10;
72: lVar14 = lVar14 + 2;
73: } while (lVar9 != lVar14);
74: puVar18 = puVar18 + lVar19 * 2;
75: pbVar10 = pbVar10 + lVar9;
76: pbVar11 = pbVar11 + lVar9;
77: pbVar17 = pbVar17 + lVar9;
78: }
79: param_4 = ppuVar6;
80: if ((uStack60 & 1) != 0) {
81: lVar9 = (uVar13 & 0xff) + lVar2;
82: *puVar18 = (ushort)((*(byte *)((ulong)((uint)((long)uVar13 >> 1) & 0x7f) + lVar2 +
83: (ulong)*pbVar11) & 0xfc) << 3) |
84: (ushort)((*(byte *)(lVar9 + (ulong)*pbVar10) & 0xf8) << 8) |
85: (ushort)(*(byte *)(lVar9 + (ulong)*pbVar17) >> 3);
86: }
87: }
88: return;
89: }
90: 
