1: 
2: void FUN_0013a2e0(long param_1,long *param_2,uint param_3,ushort **param_4)
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
20: byte *pbVar16;
21: ulong uVar17;
22: ulong uVar18;
23: long lVar19;
24: ulong uVar20;
25: byte *pbVar21;
26: long lVar23;
27: long lVar24;
28: byte *pbVar25;
29: ushort *puVar26;
30: byte *pbVar27;
31: byte *pbStack88;
32: ushort *puStack80;
33: byte *pbStack72;
34: byte *pbVar22;
35: 
36: uVar17 = (ulong)param_3;
37: lVar8 = *(long *)(param_1 + 0x260);
38: puStack80 = *param_4;
39: lVar9 = *(long *)(param_1 + 0x1a8);
40: lVar10 = *(long *)(lVar8 + 0x28);
41: lVar11 = *(long *)(lVar8 + 0x20);
42: lVar12 = *(long *)(lVar8 + 0x30);
43: lVar8 = *(long *)(lVar8 + 0x38);
44: uVar20 = *(ulong *)(&DAT_0018d900 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
45: pbStack88 = *(byte **)(*param_2 + uVar17 * 8);
46: pbStack72 = *(byte **)(param_2[1] + uVar17 * 8);
47: pbVar21 = *(byte **)(param_2[2] + uVar17 * 8);
48: uVar5 = *(uint *)(param_1 + 0x88);
49: uVar14 = uVar5 >> 1;
50: if (uVar14 != 0) {
51: lVar15 = (ulong)(uVar14 - 1) + 1;
52: pbVar16 = pbVar21 + lVar15;
53: pbVar22 = pbVar21;
54: pbVar25 = pbStack88;
55: puVar26 = puStack80;
56: pbVar27 = pbStack72;
57: do {
58: pbVar21 = pbVar22 + 1;
59: bVar1 = *pbVar25;
60: lVar24 = (uVar20 & 0xff) + lVar9;
61: iVar6 = *(int *)(lVar11 + (ulong)*pbVar22 * 4);
62: iVar7 = *(int *)(lVar10 + (ulong)*pbVar27 * 4);
63: iVar13 = (int)((ulong)(*(long *)(lVar12 + (ulong)*pbVar22 * 8) +
64: *(long *)(lVar8 + (ulong)*pbVar27 * 8)) >> 0x10);
65: lVar19 = (long)uVar20 >> 1;
66: uVar17 = (ulong)((uint)(uVar20 >> 8) & 0xffffff);
67: uVar18 = uVar17 | (uVar20 & 0xff) << 0x18;
68: bVar2 = pbVar25[1];
69: lVar23 = (uVar17 & 0xff) + lVar9;
70: uVar20 = (uVar17 & 0xff) << 0x18 | (long)uVar18 >> 8;
71: bVar3 = *(byte *)((ulong)((uint)((long)uVar18 >> 1) & 0x7f) + lVar9 +
72: (long)(int)(iVar13 + (uint)bVar2));
73: bVar4 = *(byte *)(lVar23 + (int)(iVar6 + (uint)bVar2));
74: bVar2 = *(byte *)(lVar23 + (int)(iVar7 + (uint)bVar2));
75: *puVar26 = (ushort)((*(byte *)(lVar24 + (int)(iVar6 + (uint)bVar1)) & 0xf8) << 8) |
76: (ushort)((*(byte *)((ulong)((uint)lVar19 & 0x7f) + lVar9 +
77: (long)(int)((uint)bVar1 + iVar13)) & 0xfc) << 3) |
78: (ushort)(*(byte *)(lVar24 + (int)((uint)bVar1 + iVar7)) >> 3);
79: puVar26[1] = (ushort)((bVar3 & 0xfc) << 3) | (ushort)((bVar4 & 0xf8) << 8) |
80: (ushort)(bVar2 >> 3);
81: pbVar22 = pbVar21;
82: pbVar25 = pbVar25 + 2;
83: puVar26 = puVar26 + 2;
84: pbVar27 = pbVar27 + 1;
85: } while (pbVar21 != pbVar16);
86: pbStack72 = pbStack72 + lVar15;
87: pbStack88 = pbStack88 + lVar15 * 2;
88: puStack80 = puStack80 + lVar15 * 2;
89: }
90: if ((uVar5 & 1) != 0) {
91: lVar15 = (uVar20 & 0xff) + lVar9;
92: bVar1 = *pbStack88;
93: *puStack80 = (ushort)((*(byte *)(lVar15 + (int)(*(int *)(lVar11 + (ulong)*pbVar21 * 4) +
94: (uint)bVar1)) & 0xf8) << 8) |
95: (ushort)(*(byte *)(lVar15 + (int)(*(int *)(lVar10 + (ulong)*pbStack72 * 4) +
96: (uint)bVar1)) >> 3) |
97: (ushort)((*(byte *)(lVar9 + (int)((uint)bVar1 +
98: (int)((ulong)(*(long *)(lVar12 + (ulong)*pbVar21 *
99: 8) +
100: *(long *)(lVar8 + (ulong)*pbStack72 *
101: 8)) >> 0x10)) +
102: (ulong)((uint)((long)uVar20 >> 1) & 0x7f)) & 0xfc) << 3);
103: }
104: return;
105: }
106: 
