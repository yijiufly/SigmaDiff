1: 
2: void FUN_0013a890(long param_1,long *param_2,uint param_3,ushort **param_4)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: byte bVar3;
8: int iVar4;
9: int iVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: uint uVar10;
15: ulong uVar11;
16: ulong uVar12;
17: int iVar13;
18: uint uVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: ulong uVar18;
23: ulong uVar19;
24: uint uVar20;
25: uint uVar21;
26: long lVar22;
27: long lVar23;
28: ushort *puVar24;
29: byte *pbVar25;
30: byte *pbStack128;
31: byte *pbStack120;
32: byte *pbStack112;
33: ushort *puStack104;
34: 
35: lVar16 = *(long *)(param_1 + 0x260);
36: lVar6 = *(long *)(param_1 + 0x1a8);
37: lVar7 = *(long *)(lVar16 + 0x20);
38: lVar8 = *(long *)(lVar16 + 0x28);
39: lVar9 = *(long *)(lVar16 + 0x30);
40: lVar16 = *(long *)(lVar16 + 0x38);
41: puVar24 = *param_4;
42: uVar18 = *(ulong *)(&DAT_0018d900 + (ulong)(*(uint *)(param_1 + 0xa8) & 3) * 8);
43: uVar19 = *(ulong *)(&DAT_0018d900 + (ulong)(*(uint *)(param_1 + 0xa8) + 1 & 3) * 8);
44: pbVar25 = *(byte **)(*param_2 + (ulong)(param_3 * 2) * 8);
45: pbStack112 = *(byte **)(*param_2 + (ulong)(param_3 * 2 + 1) * 8);
46: pbStack120 = *(byte **)(param_2[1] + (ulong)param_3 * 8);
47: pbStack128 = *(byte **)(param_2[2] + (ulong)param_3 * 8);
48: puStack104 = param_4[1];
49: uVar14 = *(uint *)(param_1 + 0x88);
50: uVar10 = uVar14 >> 1;
51: if (uVar10 != 0) {
52: lVar15 = 0;
53: do {
54: uVar21 = (uint)pbVar25[lVar15 * 2];
55: lVar22 = (uVar18 & 0xff) + lVar6;
56: iVar4 = *(int *)(lVar7 + (ulong)pbStack128[lVar15] * 4);
57: iVar5 = *(int *)(lVar8 + (ulong)pbStack120[lVar15] * 4);
58: lVar17 = (long)uVar18 >> 1;
59: uVar11 = (ulong)((uint)(uVar18 >> 8) & 0xffffff);
60: uVar12 = uVar11 | (uVar18 & 0xff) << 0x18;
61: iVar13 = (int)((ulong)(*(long *)(lVar9 + (ulong)pbStack128[lVar15] * 8) +
62: *(long *)(lVar16 + (ulong)pbStack120[lVar15] * 8)) >> 0x10);
63: uVar20 = (uint)pbVar25[lVar15 * 2 + 1];
64: lVar23 = (uVar11 & 0xff) + lVar6;
65: uVar18 = (uVar11 & 0xff) << 0x18 | (long)uVar12 >> 8;
66: bVar1 = *(byte *)(lVar23 + (int)(iVar4 + uVar20));
67: bVar2 = *(byte *)(lVar23 + (int)(iVar5 + uVar20));
68: bVar3 = *(byte *)((ulong)((uint)((long)uVar12 >> 1) & 0x7f) + lVar6 +
69: (long)(int)(uVar20 + iVar13));
70: puVar24[lVar15 * 2] =
71: (ushort)(*(byte *)(lVar22 + (int)(iVar5 + uVar21)) >> 3) |
72: (ushort)((*(byte *)(lVar22 + (int)(iVar4 + uVar21)) & 0xf8) << 8) |
73: (ushort)((*(byte *)((ulong)((uint)lVar17 & 0x7f) + lVar6 + (long)(int)(uVar21 + iVar13))
74: & 0xfc) << 3);
75: puVar24[lVar15 * 2 + 1] =
76: (ushort)((bVar3 & 0xfc) << 3) | (ushort)((bVar1 & 0xf8) << 8) | (ushort)(bVar2 >> 3);
77: uVar21 = (uint)pbStack112[lVar15 * 2];
78: uVar11 = (ulong)((uint)(uVar19 >> 8) & 0xffffff);
79: uVar12 = uVar11 | (uVar19 & 0xff) << 0x18;
80: lVar22 = (long)uVar19 >> 1;
81: lVar23 = (uVar19 & 0xff) + lVar6;
82: bVar1 = pbStack112[lVar15 * 2 + 1];
83: lVar17 = (uVar11 & 0xff) + lVar6;
84: bVar2 = *(byte *)(lVar17 + (int)(iVar4 + (uint)bVar1));
85: bVar3 = *(byte *)(lVar17 + (int)(iVar5 + (uint)bVar1));
86: uVar19 = (uVar11 & 0xff) << 0x18 | (long)uVar12 >> 8;
87: bVar1 = *(byte *)((ulong)((uint)((long)uVar12 >> 1) & 0x7f) + lVar6 +
88: (long)(int)(iVar13 + (uint)bVar1));
89: puStack104[lVar15 * 2] =
90: (ushort)(*(byte *)(lVar23 + (int)(iVar5 + uVar21)) >> 3) |
91: (ushort)((*(byte *)(lVar23 + (int)(iVar4 + uVar21)) & 0xf8) << 8) |
92: (ushort)((*(byte *)((ulong)((uint)lVar22 & 0x7f) + lVar6 + (long)(int)(uVar21 + iVar13))
93: & 0xfc) << 3);
94: puStack104[lVar15 * 2 + 1] =
95: (ushort)((bVar1 & 0xfc) << 3) | (ushort)((bVar2 & 0xf8) << 8) | (ushort)(bVar3 >> 3);
96: lVar15 = lVar15 + 1;
97: } while (lVar15 != (ulong)(uVar10 - 1) + 1);
98: pbStack120 = pbStack120 + lVar15;
99: pbStack128 = pbStack128 + lVar15;
100: pbStack112 = pbStack112 + lVar15 * 2;
101: puStack104 = puStack104 + lVar15 * 2;
102: pbVar25 = pbVar25 + lVar15 * 2;
103: puVar24 = puVar24 + lVar15 * 2;
104: }
105: if ((uVar14 & 1) != 0) {
106: lVar15 = (uVar18 & 0xff) + lVar6;
107: iVar4 = *(int *)(lVar7 + (ulong)*pbStack128 * 4);
108: iVar5 = *(int *)(lVar8 + (ulong)*pbStack120 * 4);
109: uVar14 = (uint)*pbVar25;
110: iVar13 = (int)((ulong)(*(long *)(lVar9 + (ulong)*pbStack128 * 8) +
111: *(long *)(lVar16 + (ulong)*pbStack120 * 8)) >> 0x10);
112: *puVar24 = (ushort)((*(byte *)(lVar15 + (int)(iVar4 + uVar14)) & 0xf8) << 8) |
113: (ushort)(*(byte *)(lVar15 + (int)(iVar5 + uVar14)) >> 3) |
114: (ushort)((*(byte *)((ulong)((uint)((long)uVar18 >> 1) & 0x7f) + lVar6 +
115: (long)(int)(uVar14 + iVar13)) & 0xfc) << 3);
116: bVar1 = *pbStack112;
117: lVar16 = (uVar19 & 0xff) + lVar6;
118: *puStack104 = (ushort)((*(byte *)(lVar16 + (int)(iVar4 + (uint)bVar1)) & 0xf8) << 8) |
119: (ushort)(*(byte *)(lVar16 + (int)(iVar5 + (uint)bVar1)) >> 3) |
120: (ushort)((*(byte *)(lVar6 + (ulong)((uint)((long)uVar19 >> 1) & 0x7f) +
121: (long)(int)(iVar13 + (uint)bVar1)) & 0xfc) << 3);
122: }
123: return;
124: }
125: 
