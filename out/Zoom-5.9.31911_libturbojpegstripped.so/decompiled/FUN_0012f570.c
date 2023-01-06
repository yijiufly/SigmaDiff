1: 
2: void FUN_0012f570(long param_1,long *param_2,uint param_3,ushort **param_4)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: byte bVar3;
8: byte bVar4;
9: byte bVar5;
10: byte bVar6;
11: uint uVar7;
12: int iVar8;
13: int iVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: int iVar15;
20: uint uVar16;
21: long lVar17;
22: ulong uVar18;
23: ulong uVar19;
24: byte *pbVar20;
25: byte *pbVar21;
26: ushort *puVar22;
27: byte *pbVar23;
28: byte *pbVar24;
29: ulong uVar25;
30: byte *pbStack96;
31: byte *pbStack88;
32: ushort *puStack80;
33: byte *pbStack72;
34: 
35: uVar18 = (ulong)param_3;
36: puStack80 = *param_4;
37: lVar10 = *(long *)(param_1 + 0x1a8);
38: lVar11 = *(long *)(param_1 + 0x260);
39: lVar12 = *(long *)(lVar11 + 0x20);
40: lVar13 = *(long *)(lVar11 + 0x28);
41: lVar14 = *(long *)(lVar11 + 0x30);
42: lVar11 = *(long *)(lVar11 + 0x38);
43: uVar19 = *(ulong *)(&DAT_00189cc0 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
44: pbStack88 = *(byte **)(*param_2 + uVar18 * 8);
45: pbStack96 = *(byte **)(param_2[1] + uVar18 * 8);
46: pbStack72 = *(byte **)(param_2[2] + uVar18 * 8);
47: uVar7 = *(uint *)(param_1 + 0x88);
48: uVar16 = uVar7 >> 1;
49: if (uVar16 != 0) {
50: lVar17 = (ulong)(uVar16 - 1) + 1;
51: pbVar20 = pbStack72;
52: pbVar21 = pbStack88;
53: puVar22 = puStack80;
54: pbVar23 = pbStack96;
55: do {
56: pbVar24 = pbVar23 + 1;
57: bVar3 = *pbVar21;
58: iVar8 = *(int *)(lVar12 + (ulong)*pbVar20 * 4);
59: iVar9 = *(int *)(lVar13 + (ulong)*pbVar23 * 4);
60: uVar25 = uVar19 & 0xff;
61: lVar1 = lVar10 + uVar25;
62: uVar18 = (ulong)((uint)(uVar19 >> 8) & 0xffffff);
63: bVar4 = pbVar21[1];
64: iVar15 = (int)((ulong)(*(long *)(lVar11 + (ulong)*pbVar23 * 8) +
65: *(long *)(lVar14 + (ulong)*pbVar20 * 8)) >> 0x10);
66: uVar19 = (uVar18 & 0xff) << 0x18 | (long)(uVar18 | (uVar19 & 0xff) << 0x18) >> 8;
67: lVar2 = lVar10 + (uVar18 & 0xff);
68: bVar5 = *(byte *)((int)(iVar15 + (uint)bVar4) + lVar10 + ((long)(uVar18 & 0xff) >> 1));
69: bVar6 = *(byte *)(lVar2 + (int)(iVar8 + (uint)bVar4));
70: bVar4 = *(byte *)(lVar2 + (int)((uint)bVar4 + iVar9));
71: *puVar22 = (ushort)((*(byte *)(lVar1 + (int)(iVar8 + (uint)bVar3)) & 0xf8) << 8) |
72: (ushort)((*(byte *)((int)((uint)bVar3 + iVar15) + lVar10 + ((long)uVar25 >> 1)) &
73: 0xfc) << 3) | (ushort)(*(byte *)(lVar1 + (int)((uint)bVar3 + iVar9)) >> 3)
74: ;
75: puVar22[1] = (ushort)((bVar6 & 0xf8) << 8) | (ushort)((bVar5 & 0xfc) << 3) |
76: (ushort)(bVar4 >> 3);
77: pbVar20 = pbVar20 + 1;
78: pbVar21 = pbVar21 + 2;
79: puVar22 = puVar22 + 2;
80: pbVar23 = pbVar24;
81: } while (pbVar24 != pbStack96 + lVar17);
82: pbStack72 = pbStack72 + lVar17;
83: pbStack88 = pbStack88 + lVar17 * 2;
84: puStack80 = puStack80 + lVar17 * 2;
85: pbStack96 = pbStack96 + lVar17;
86: }
87: if ((uVar7 & 1) != 0) {
88: lVar17 = lVar10 + (uVar19 & 0xff);
89: bVar3 = *pbStack88;
90: *puStack80 = (ushort)((*(byte *)(lVar17 + (int)(*(int *)(lVar12 + (ulong)*pbStack72 * 4) +
91: (uint)bVar3)) & 0xf8) << 8) |
92: (ushort)(*(byte *)(lVar17 + (int)(*(int *)(lVar13 + (ulong)*pbStack96 * 4) +
93: (uint)bVar3)) >> 3) |
94: (ushort)((*(byte *)(lVar10 + (int)((int)((ulong)(*(long *)(lVar11 + (ulong)*
95: pbStack96 * 8) +
96: *(long *)(lVar14 + (ulong)*pbStack72 * 8)) >> 0x10
97: ) + (uint)bVar3) + ((long)(uVar19 & 0xff) >> 1)) &
98: 0xfc) << 3);
99: }
100: return;
101: }
102: 
