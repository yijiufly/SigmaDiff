1: 
2: void FUN_0012f350(long param_1,long *param_2,uint param_3,ushort **param_4)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: byte bVar3;
8: byte bVar4;
9: uint uVar5;
10: int iVar6;
11: int iVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: int iVar13;
18: uint uVar14;
19: long lVar15;
20: ulong uVar16;
21: byte *pbVar17;
22: byte *pbVar18;
23: ushort *puVar19;
24: byte *pbVar20;
25: byte *pbStack96;
26: byte *pbStack88;
27: ushort *puStack80;
28: byte *pbStack72;
29: byte *pbVar21;
30: 
31: uVar16 = (ulong)param_3;
32: puStack80 = *param_4;
33: lVar8 = *(long *)(param_1 + 0x1a8);
34: lVar9 = *(long *)(param_1 + 0x260);
35: lVar10 = *(long *)(lVar9 + 0x30);
36: lVar11 = *(long *)(lVar9 + 0x20);
37: lVar12 = *(long *)(lVar9 + 0x28);
38: lVar9 = *(long *)(lVar9 + 0x38);
39: pbStack88 = *(byte **)(*param_2 + uVar16 * 8);
40: pbStack96 = *(byte **)(param_2[1] + uVar16 * 8);
41: pbStack72 = *(byte **)(param_2[2] + uVar16 * 8);
42: uVar5 = *(uint *)(param_1 + 0x88);
43: uVar14 = uVar5 >> 1;
44: if (uVar14 != 0) {
45: lVar15 = (ulong)(uVar14 - 1) + 1;
46: pbVar17 = pbStack72;
47: pbVar18 = pbStack88;
48: puVar19 = puStack80;
49: pbVar21 = pbStack96;
50: do {
51: pbVar20 = pbVar21 + 1;
52: bVar1 = *pbVar18;
53: iVar6 = *(int *)(lVar11 + (ulong)*pbVar17 * 4);
54: iVar7 = *(int *)(lVar12 + (ulong)*pbVar21 * 4);
55: bVar2 = pbVar18[1];
56: iVar13 = (int)((ulong)(*(long *)(lVar9 + (ulong)*pbVar21 * 8) +
57: *(long *)(lVar10 + (ulong)*pbVar17 * 8)) >> 0x10);
58: bVar3 = *(byte *)(lVar8 + (int)(iVar13 + (uint)bVar2));
59: bVar4 = *(byte *)(lVar8 + (int)(iVar6 + (uint)bVar2));
60: bVar2 = *(byte *)(lVar8 + (int)((uint)bVar2 + iVar7));
61: *puVar19 = (ushort)((*(byte *)(lVar8 + (int)(iVar6 + (uint)bVar1)) & 0xf8) << 8) |
62: (ushort)((*(byte *)(lVar8 + (int)((uint)bVar1 + iVar13)) & 0xfc) << 3) |
63: (ushort)(*(byte *)(lVar8 + (int)((uint)bVar1 + iVar7)) >> 3);
64: puVar19[1] = (ushort)((bVar4 & 0xf8) << 8) | (ushort)((bVar3 & 0xfc) << 3) |
65: (ushort)(bVar2 >> 3);
66: pbVar17 = pbVar17 + 1;
67: pbVar18 = pbVar18 + 2;
68: puVar19 = puVar19 + 2;
69: pbVar21 = pbVar20;
70: } while (pbVar20 != pbStack96 + lVar15);
71: pbStack72 = pbStack72 + lVar15;
72: pbStack88 = pbStack88 + lVar15 * 2;
73: puStack80 = puStack80 + lVar15 * 2;
74: pbStack96 = pbStack96 + lVar15;
75: }
76: if ((uVar5 & 1) != 0) {
77: bVar1 = *pbStack88;
78: *puStack80 = (ushort)((*(byte *)(lVar8 + (int)(*(int *)(lVar11 + (ulong)*pbStack72 * 4) +
79: (uint)bVar1)) & 0xf8) << 8) |
80: (ushort)(*(byte *)(lVar8 + (int)(*(int *)(lVar12 + (ulong)*pbStack96 * 4) +
81: (uint)bVar1)) >> 3) |
82: (ushort)((*(byte *)(lVar8 + (int)((int)((ulong)(*(long *)(lVar9 + (ulong)*pbStack96
83: * 8) +
84: *(long *)(lVar10 + (ulong)*pbStack72
85: * 8)) >> 0x10) +
86: (uint)bVar1)) & 0xfc) << 3);
87: }
88: return;
89: }
90: 
