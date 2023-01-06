1: 
2: void FUN_0012fb70(long param_1,long *param_2,uint param_3,ushort **param_4)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: byte bVar3;
8: byte bVar4;
9: byte bVar5;
10: byte bVar6;
11: int iVar7;
12: int iVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: byte *pbVar14;
19: uint uVar15;
20: long lVar16;
21: ulong uVar17;
22: uint uVar18;
23: int iVar19;
24: byte *pbVar20;
25: ulong uVar21;
26: byte *pbVar22;
27: ulong uVar23;
28: ulong uVar24;
29: ulong uVar25;
30: byte *pbStack176;
31: byte *pbStack168;
32: ushort *puStack160;
33: ushort *puStack152;
34: byte *pbStack112;
35: byte *pbStack104;
36: byte *pbStack96;
37: ushort *puStack88;
38: byte *pbStack80;
39: ushort *puStack72;
40: 
41: lVar9 = *(long *)(param_1 + 0x260);
42: lVar10 = *(long *)(param_1 + 0x1a8);
43: lVar11 = *(long *)(lVar9 + 0x20);
44: lVar12 = *(long *)(lVar9 + 0x28);
45: lVar13 = *(long *)(lVar9 + 0x30);
46: lVar9 = *(long *)(lVar9 + 0x38);
47: uVar23 = *(ulong *)(&DAT_00189cc0 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
48: uVar21 = *(ulong *)(&DAT_00189cc0 + (ulong)(*(uint *)(param_1 + 0xa8) + 1 & 3) * 8);
49: pbStack96 = *(byte **)(*param_2 + (ulong)(param_3 * 2) * 8);
50: pbStack80 = *(byte **)(*param_2 + (ulong)(param_3 * 2 + 1) * 8);
51: pbStack112 = *(byte **)(param_2[1] + (ulong)param_3 * 8);
52: pbStack104 = *(byte **)(param_2[2] + (ulong)param_3 * 8);
53: puStack88 = *param_4;
54: puStack72 = param_4[1];
55: uVar18 = *(uint *)(param_1 + 0x88);
56: uVar15 = uVar18 >> 1;
57: if (uVar15 != 0) {
58: lVar16 = (ulong)(uVar15 - 1) + 1;
59: pbVar20 = pbStack96;
60: pbVar22 = pbStack80;
61: pbStack176 = pbStack112;
62: pbStack168 = pbStack104;
63: puStack160 = puStack88;
64: puStack152 = puStack72;
65: do {
66: pbVar14 = pbStack176 + 1;
67: uVar24 = uVar23 & 0xff;
68: bVar3 = *pbVar20;
69: iVar7 = *(int *)(lVar11 + (ulong)*pbStack168 * 4);
70: iVar8 = *(int *)(lVar12 + (ulong)*pbStack176 * 4);
71: uVar17 = (ulong)((uint)(uVar23 >> 8) & 0xffffff);
72: iVar19 = (int)((ulong)(*(long *)(lVar9 + (ulong)*pbStack176 * 8) +
73: *(long *)(lVar13 + (ulong)*pbStack168 * 8)) >> 0x10);
74: bVar4 = pbVar20[1];
75: lVar1 = lVar10 + uVar24;
76: uVar23 = (uVar17 & 0xff) << 0x18 | (long)(uVar17 | (uVar23 & 0xff) << 0x18) >> 8;
77: lVar2 = lVar10 + (uVar17 & 0xff);
78: bVar5 = *(byte *)(lVar2 + (int)((uint)bVar4 + iVar8));
79: bVar6 = *(byte *)(lVar2 + (int)(iVar7 + (uint)bVar4));
80: bVar4 = *(byte *)((int)((uint)bVar4 + iVar19) + lVar10 + ((long)(uVar17 & 0xff) >> 1));
81: uVar25 = uVar21 & 0xff;
82: lVar2 = lVar10 + uVar25;
83: *puStack160 = (ushort)((*(byte *)(lVar1 + (int)(iVar7 + (uint)bVar3)) & 0xf8) << 8) |
84: (ushort)((*(byte *)((int)((uint)bVar3 + iVar19) + lVar10 + ((long)uVar24 >> 1))
85: & 0xfc) << 3) |
86: (ushort)(*(byte *)(lVar1 + (int)((uint)bVar3 + iVar8)) >> 3);
87: puStack160[1] =
88: (ushort)((bVar6 & 0xf8) << 8) | (ushort)((bVar4 & 0xfc) << 3) | (ushort)(bVar5 >> 3);
89: bVar3 = *pbVar22;
90: uVar17 = (ulong)((uint)(uVar21 >> 8) & 0xffffff);
91: bVar4 = pbVar22[1];
92: uVar21 = (uVar17 & 0xff) << 0x18 | (long)(uVar17 | (uVar21 & 0xff) << 0x18) >> 8;
93: lVar1 = lVar10 + (uVar17 & 0xff);
94: bVar5 = *(byte *)((int)(iVar19 + (uint)bVar4) + lVar10 + ((long)(uVar17 & 0xff) >> 1));
95: bVar6 = *(byte *)(lVar1 + (int)(iVar7 + (uint)bVar4));
96: bVar4 = *(byte *)(lVar1 + (int)(iVar8 + (uint)bVar4));
97: *puStack152 = (ushort)((*(byte *)(lVar2 + (int)(iVar7 + (uint)bVar3)) & 0xf8) << 8) |
98: (ushort)((*(byte *)((int)((uint)bVar3 + iVar19) + lVar10 + ((long)uVar25 >> 1))
99: & 0xfc) << 3) |
100: (ushort)(*(byte *)(lVar2 + (int)((uint)bVar3 + iVar8)) >> 3);
101: puStack152[1] =
102: (ushort)((bVar6 & 0xf8) << 8) | (ushort)((bVar5 & 0xfc) << 3) | (ushort)(bVar4 >> 3);
103: pbVar20 = pbVar20 + 2;
104: pbVar22 = pbVar22 + 2;
105: pbStack176 = pbVar14;
106: pbStack168 = pbStack168 + 1;
107: puStack160 = puStack160 + 2;
108: puStack152 = puStack152 + 2;
109: } while (pbVar14 != pbStack112 + lVar16);
110: pbStack104 = pbStack104 + lVar16;
111: puStack88 = puStack88 + lVar16 * 2;
112: puStack72 = puStack72 + lVar16 * 2;
113: pbStack96 = pbStack96 + lVar16 * 2;
114: pbStack80 = pbStack80 + lVar16 * 2;
115: pbStack112 = pbStack112 + lVar16;
116: }
117: if ((uVar18 & 1) != 0) {
118: lVar16 = lVar10 + (uVar23 & 0xff);
119: iVar7 = *(int *)(lVar11 + (ulong)*pbStack104 * 4);
120: iVar8 = *(int *)(lVar12 + (ulong)*pbStack112 * 4);
121: uVar18 = (uint)*pbStack96;
122: iVar19 = (int)((ulong)(*(long *)(lVar9 + (ulong)*pbStack112 * 8) +
123: *(long *)(lVar13 + (ulong)*pbStack104 * 8)) >> 0x10);
124: lVar9 = lVar10 + (uVar21 & 0xff);
125: *puStack88 = (ushort)((*(byte *)(lVar16 + (int)(iVar7 + uVar18)) & 0xf8) << 8) |
126: (ushort)(*(byte *)(lVar16 + (int)(iVar8 + uVar18)) >> 3) |
127: (ushort)((*(byte *)((int)(uVar18 + iVar19) + lVar10 + ((long)(uVar23 & 0xff) >> 1))
128: & 0xfc) << 3);
129: bVar3 = *pbStack80;
130: *puStack72 = (ushort)((*(byte *)(lVar9 + (int)(iVar7 + (uint)bVar3)) & 0xf8) << 8) |
131: (ushort)(*(byte *)(lVar9 + (int)(iVar8 + (uint)bVar3)) >> 3) |
132: (ushort)((*(byte *)(lVar10 + (int)(iVar19 + (uint)bVar3) +
133: ((long)(uVar21 & 0xff) >> 1)) & 0xfc) << 3);
134: }
135: return;
136: }
137: 
