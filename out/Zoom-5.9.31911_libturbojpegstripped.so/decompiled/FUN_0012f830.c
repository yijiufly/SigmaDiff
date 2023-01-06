1: 
2: void FUN_0012f830(long param_1,long *param_2,uint param_3,ushort **param_4)
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
18: uint uVar14;
19: int iVar15;
20: byte *pbVar16;
21: ushort *puVar17;
22: byte *pbVar18;
23: byte *pbVar19;
24: byte *pbVar20;
25: ushort *puVar21;
26: byte *pbVar22;
27: byte *pbStack112;
28: byte *pbStack104;
29: byte *pbStack96;
30: ushort *puStack88;
31: byte *pbStack80;
32: ushort *puStack72;
33: 
34: lVar7 = *(long *)(param_1 + 0x260);
35: lVar8 = *(long *)(param_1 + 0x1a8);
36: lVar9 = *(long *)(lVar7 + 0x28);
37: lVar10 = *(long *)(lVar7 + 0x20);
38: lVar11 = *(long *)(lVar7 + 0x30);
39: lVar7 = *(long *)(lVar7 + 0x38);
40: pbStack96 = *(byte **)(*param_2 + (ulong)(param_3 * 2) * 8);
41: pbStack80 = *(byte **)(*param_2 + (ulong)(param_3 * 2 + 1) * 8);
42: pbStack104 = *(byte **)(param_2[1] + (ulong)param_3 * 8);
43: pbStack112 = *(byte **)(param_2[2] + (ulong)param_3 * 8);
44: puStack88 = *param_4;
45: puStack72 = param_4[1];
46: uVar14 = *(uint *)(param_1 + 0x88);
47: uVar12 = uVar14 >> 1;
48: if (uVar12 != 0) {
49: lVar13 = (ulong)(uVar12 - 1) + 1;
50: pbVar16 = pbStack80;
51: puVar17 = puStack72;
52: pbVar18 = pbStack112;
53: pbVar20 = pbStack96;
54: puVar21 = puStack88;
55: pbVar22 = pbStack104;
56: do {
57: pbVar19 = pbVar18 + 1;
58: iVar5 = *(int *)(lVar10 + (ulong)*pbVar18 * 4);
59: bVar1 = *pbVar20;
60: bVar2 = pbVar20[1];
61: iVar6 = *(int *)(lVar9 + (ulong)*pbVar22 * 4);
62: iVar15 = (int)((ulong)(*(long *)(lVar7 + (ulong)*pbVar22 * 8) +
63: *(long *)(lVar11 + (ulong)*pbVar18 * 8)) >> 0x10);
64: bVar3 = *(byte *)(lVar8 + (int)((uint)bVar2 + iVar15));
65: bVar4 = *(byte *)(lVar8 + (int)((uint)bVar2 + iVar6));
66: bVar2 = *(byte *)(lVar8 + (int)(iVar5 + (uint)bVar2));
67: *puVar21 = (ushort)((*(byte *)(lVar8 + (int)(iVar5 + (uint)bVar1)) & 0xf8) << 8) |
68: (ushort)((*(byte *)(lVar8 + (int)((uint)bVar1 + iVar15)) & 0xfc) << 3) |
69: (ushort)(*(byte *)(lVar8 + (int)((uint)bVar1 + iVar6)) >> 3);
70: puVar21[1] = (ushort)((bVar2 & 0xf8) << 8) | (ushort)((bVar3 & 0xfc) << 3) |
71: (ushort)(bVar4 >> 3);
72: bVar1 = *pbVar16;
73: bVar2 = pbVar16[1];
74: bVar3 = *(byte *)(lVar8 + (int)(iVar5 + (uint)bVar2));
75: bVar4 = *(byte *)(lVar8 + (int)(iVar15 + (uint)bVar2));
76: bVar2 = *(byte *)(lVar8 + (int)((uint)bVar2 + iVar6));
77: *puVar17 = (ushort)((*(byte *)(lVar8 + (int)(iVar5 + (uint)bVar1)) & 0xf8) << 8) |
78: (ushort)((*(byte *)(lVar8 + (int)((uint)bVar1 + iVar15)) & 0xfc) << 3) |
79: (ushort)(*(byte *)(lVar8 + (int)((uint)bVar1 + iVar6)) >> 3);
80: puVar17[1] = (ushort)((bVar3 & 0xf8) << 8) | (ushort)((bVar4 & 0xfc) << 3) |
81: (ushort)(bVar2 >> 3);
82: pbVar16 = pbVar16 + 2;
83: puVar17 = puVar17 + 2;
84: pbVar18 = pbVar19;
85: pbVar20 = pbVar20 + 2;
86: puVar21 = puVar21 + 2;
87: pbVar22 = pbVar22 + 1;
88: } while (pbVar19 != pbStack112 + lVar13);
89: pbStack104 = pbStack104 + lVar13;
90: pbStack96 = pbStack96 + lVar13 * 2;
91: puStack88 = puStack88 + lVar13 * 2;
92: pbStack80 = pbStack80 + lVar13 * 2;
93: puStack72 = puStack72 + lVar13 * 2;
94: pbStack112 = pbStack112 + lVar13;
95: }
96: if ((uVar14 & 1) != 0) {
97: iVar5 = *(int *)(lVar10 + (ulong)*pbStack112 * 4);
98: iVar6 = *(int *)(lVar9 + (ulong)*pbStack104 * 4);
99: uVar14 = (uint)*pbStack96;
100: iVar15 = (int)((ulong)(*(long *)(lVar7 + (ulong)*pbStack104 * 8) +
101: *(long *)(lVar11 + (ulong)*pbStack112 * 8)) >> 0x10);
102: *puStack88 = (ushort)((*(byte *)(lVar8 + (int)(iVar5 + uVar14)) & 0xf8) << 8) |
103: (ushort)(*(byte *)(lVar8 + (int)(iVar6 + uVar14)) >> 3) |
104: (ushort)((*(byte *)(lVar8 + (int)(uVar14 + iVar15)) & 0xfc) << 3);
105: bVar1 = *pbStack80;
106: *puStack72 = (ushort)((*(byte *)(lVar8 + (int)(iVar5 + (uint)bVar1)) & 0xf8) << 8) |
107: (ushort)(*(byte *)(lVar8 + (int)(iVar6 + (uint)bVar1)) >> 3) |
108: (ushort)((*(byte *)(lVar8 + (int)(iVar15 + (uint)bVar1)) & 0xfc) << 3);
109: }
110: return;
111: }
112: 
