1: 
2: void FUN_0013a570(long param_1,long *param_2,uint param_3,ushort **param_4)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: byte bVar3;
8: byte bVar4;
9: int iVar5;
10: int iVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: uint uVar12;
17: long lVar13;
18: byte *pbVar14;
19: int iVar15;
20: byte *pbVar16;
21: ushort *puVar17;
22: uint uVar18;
23: byte *pbVar19;
24: byte *pbVar20;
25: byte *pbVar21;
26: ushort *puVar22;
27: byte *pbVar23;
28: byte *pbStack104;
29: byte *pbStack96;
30: ushort *puStack88;
31: byte *pbStack80;
32: ushort *puStack72;
33: 
34: lVar7 = *(long *)(param_1 + 0x260);
35: puStack88 = *param_4;
36: puStack72 = param_4[1];
37: lVar8 = *(long *)(param_1 + 0x1a8);
38: lVar9 = *(long *)(lVar7 + 0x28);
39: lVar10 = *(long *)(lVar7 + 0x20);
40: lVar11 = *(long *)(lVar7 + 0x30);
41: lVar7 = *(long *)(lVar7 + 0x38);
42: pbStack96 = *(byte **)(*param_2 + (ulong)(param_3 * 2) * 8);
43: pbStack80 = *(byte **)(*param_2 + (ulong)(param_3 * 2 + 1) * 8);
44: pbVar20 = *(byte **)(param_2[1] + (ulong)param_3 * 8);
45: pbStack104 = *(byte **)(param_2[2] + (ulong)param_3 * 8);
46: uVar18 = *(uint *)(param_1 + 0x88);
47: uVar12 = uVar18 >> 1;
48: if (uVar12 != 0) {
49: lVar13 = (ulong)(uVar12 - 1) + 1;
50: pbVar14 = pbVar20 + lVar13;
51: pbVar16 = pbStack96;
52: puVar17 = puStack88;
53: pbVar19 = pbVar20;
54: pbVar21 = pbStack80;
55: puVar22 = puStack72;
56: pbVar23 = pbStack104;
57: do {
58: pbVar20 = pbVar19 + 1;
59: bVar1 = *pbVar16;
60: bVar2 = pbVar16[1];
61: iVar5 = *(int *)(lVar10 + (ulong)*pbVar23 * 4);
62: iVar6 = *(int *)(lVar9 + (ulong)*pbVar19 * 4);
63: bVar3 = *(byte *)(lVar8 + (int)(iVar5 + (uint)bVar2));
64: iVar15 = (int)((ulong)(*(long *)(lVar11 + (ulong)*pbVar23 * 8) +
65: *(long *)(lVar7 + (ulong)*pbVar19 * 8)) >> 0x10);
66: bVar4 = *(byte *)(lVar8 + (int)((uint)bVar2 + iVar15));
67: bVar2 = *(byte *)(lVar8 + (int)((uint)bVar2 + iVar6));
68: *puVar17 = (ushort)((*(byte *)(lVar8 + (int)((uint)bVar1 + iVar15)) & 0xfc) << 3) |
69: (ushort)((*(byte *)(lVar8 + (int)(iVar5 + (uint)bVar1)) & 0xf8) << 8) |
70: (ushort)(*(byte *)(lVar8 + (int)((uint)bVar1 + iVar6)) >> 3);
71: puVar17[1] = (ushort)((bVar4 & 0xfc) << 3) | (ushort)((bVar3 & 0xf8) << 8) |
72: (ushort)(bVar2 >> 3);
73: bVar1 = *pbVar21;
74: bVar2 = pbVar21[1];
75: bVar3 = *(byte *)(lVar8 + (int)(iVar5 + (uint)bVar2));
76: bVar4 = *(byte *)(lVar8 + (int)((uint)bVar2 + iVar15));
77: bVar2 = *(byte *)(lVar8 + (int)((uint)bVar2 + iVar6));
78: *puVar22 = (ushort)((*(byte *)(lVar8 + (int)(iVar5 + (uint)bVar1)) & 0xf8) << 8) |
79: (ushort)((*(byte *)(lVar8 + (int)(iVar15 + (uint)bVar1)) & 0xfc) << 3) |
80: (ushort)(*(byte *)(lVar8 + (int)(iVar6 + (uint)bVar1)) >> 3);
81: puVar22[1] = (ushort)(bVar2 >> 3) |
82: (ushort)((bVar4 & 0xfc) << 3) | (ushort)((bVar3 & 0xf8) << 8);
83: pbVar16 = pbVar16 + 2;
84: puVar17 = puVar17 + 2;
85: pbVar19 = pbVar20;
86: pbVar21 = pbVar21 + 2;
87: puVar22 = puVar22 + 2;
88: pbVar23 = pbVar23 + 1;
89: } while (pbVar20 != pbVar14);
90: pbStack104 = pbStack104 + lVar13;
91: pbStack96 = pbStack96 + lVar13 * 2;
92: puStack88 = puStack88 + lVar13 * 2;
93: pbStack80 = pbStack80 + lVar13 * 2;
94: puStack72 = puStack72 + lVar13 * 2;
95: }
96: if ((uVar18 & 1) != 0) {
97: iVar5 = *(int *)(lVar10 + (ulong)*pbStack104 * 4);
98: iVar6 = *(int *)(lVar9 + (ulong)*pbVar20 * 4);
99: uVar18 = (uint)*pbStack96;
100: iVar15 = (int)((ulong)(*(long *)(lVar11 + (ulong)*pbStack104 * 8) +
101: *(long *)(lVar7 + (ulong)*pbVar20 * 8)) >> 0x10);
102: *puStack88 = (ushort)((*(byte *)(lVar8 + (int)(iVar5 + uVar18)) & 0xf8) << 8) |
103: (ushort)(*(byte *)(lVar8 + (int)(iVar6 + uVar18)) >> 3) |
104: (ushort)((*(byte *)(lVar8 + (int)(uVar18 + iVar15)) & 0xfc) << 3);
105: bVar1 = *pbStack80;
106: *puStack72 = (ushort)((*(byte *)(lVar8 + (int)(iVar5 + (uint)bVar1)) & 0xf8) << 8) |
107: (ushort)(*(byte *)(lVar8 + (int)(iVar6 + (uint)bVar1)) >> 3) |
108: (ushort)((*(byte *)(lVar8 + (int)(iVar15 + (uint)bVar1)) & 0xfc) << 3);
109: }
110: return;
111: }
112: 
