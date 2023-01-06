1: 
2: void FUN_00123700(long param_1,long *param_2,uint param_3,ushort **param_4,int param_5)
3: 
4: {
5: long lVar1;
6: byte bVar2;
7: long lVar3;
8: ushort *puVar4;
9: ushort **ppuVar5;
10: ulong uVar6;
11: ulong uVar7;
12: long lVar8;
13: ushort *puVar9;
14: long lVar10;
15: byte *pbVar11;
16: byte *pbVar12;
17: byte *pbVar13;
18: ulong uVar14;
19: uint uVar15;
20: byte *pbVar16;
21: byte *pbStack88;
22: byte *pbStack80;
23: uint uStack68;
24: 
25: uStack68 = *(uint *)(param_1 + 0x88);
26: lVar3 = *(long *)(param_1 + 0x1a8);
27: uVar7 = *(ulong *)(&DAT_001896c0 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
28: while (param_5 = param_5 + -1, -1 < param_5) {
29: uVar6 = (ulong)param_3;
30: ppuVar5 = param_4 + 1;
31: param_3 = param_3 + 1;
32: pbVar16 = *(byte **)(*param_2 + uVar6 * 8);
33: pbStack88 = *(byte **)(param_2[1] + uVar6 * 8);
34: pbStack80 = *(byte **)(param_2[2] + uVar6 * 8);
35: puVar4 = *param_4;
36: puVar9 = puVar4;
37: if (((ulong)puVar4 & 3) != 0) {
38: bVar2 = *pbVar16;
39: lVar10 = lVar3 + (uVar7 & 0xff);
40: uStack68 = uStack68 - 1;
41: puVar9 = puVar4 + 1;
42: pbVar16 = pbVar16 + 1;
43: *puVar4 = (ushort)((*(byte *)(lVar10 + (ulong)bVar2) & 0xf8) << 8) |
44: (ushort)((*(byte *)((ulong)*pbStack88 + lVar3 + ((long)(uVar7 & 0xff) >> 1)) & 0xfc)
45: << 3) | (ushort)(*(byte *)(lVar10 + (ulong)*pbStack80) >> 3);
46: pbStack80 = pbStack80 + 1;
47: pbStack88 = pbStack88 + 1;
48: }
49: uVar15 = uStack68 >> 1;
50: if (uVar15 != 0) {
51: lVar10 = 0;
52: pbVar11 = pbVar16;
53: pbVar12 = pbStack88;
54: pbVar13 = pbStack80;
55: do {
56: uVar14 = uVar7 & 0xff;
57: uVar6 = (ulong)((uint)(uVar7 >> 8) & 0xffffff);
58: lVar8 = lVar3 + uVar14;
59: lVar1 = lVar3 + (uVar6 & 0xff);
60: uVar7 = (uVar6 & 0xff) << 0x18 | (long)(uVar6 | (uVar7 & 0xff) << 0x18) >> 8;
61: *(uint *)(puVar9 + lVar10 * 2) =
62: (*(byte *)(lVar8 + (ulong)*pbVar11) & 0xf8) << 8 |
63: (*(byte *)((ulong)*pbVar12 + lVar3 + ((long)uVar14 >> 1)) & 0xfc) << 3 |
64: (uint)(*(byte *)(lVar8 + (ulong)*pbVar13) >> 3) |
65: ((*(byte *)(lVar1 + (ulong)pbVar11[1]) & 0xf8) << 8 |
66: (*(byte *)((ulong)pbVar12[1] + lVar3 + ((long)(uVar6 & 0xff) >> 1)) & 0xfc) << 3 |
67: (uint)(*(byte *)(lVar1 + (ulong)pbVar13[1]) >> 3)) << 0x10;
68: lVar10 = lVar10 + 1;
69: pbVar11 = pbVar11 + 2;
70: pbVar12 = pbVar12 + 2;
71: pbVar13 = pbVar13 + 2;
72: } while ((uint)lVar10 < uVar15);
73: lVar8 = (ulong)(uVar15 - 1) + 1;
74: lVar10 = lVar8 * 2;
75: pbStack88 = pbStack88 + lVar10;
76: pbStack80 = pbStack80 + lVar10;
77: puVar9 = puVar9 + lVar8 * 2;
78: pbVar16 = pbVar16 + lVar10;
79: }
80: param_4 = ppuVar5;
81: if ((uStack68 & 1) != 0) {
82: lVar10 = lVar3 + (uVar7 & 0xff);
83: *puVar9 = (ushort)((*(byte *)(lVar10 + (ulong)*pbVar16) & 0xf8) << 8) |
84: (ushort)((*(byte *)((ulong)*pbStack88 + lVar3 + ((long)(uVar7 & 0xff) >> 1)) & 0xfc)
85: << 3) | (ushort)(*(byte *)(lVar10 + (ulong)*pbStack80) >> 3);
86: }
87: }
88: return;
89: }
90: 
