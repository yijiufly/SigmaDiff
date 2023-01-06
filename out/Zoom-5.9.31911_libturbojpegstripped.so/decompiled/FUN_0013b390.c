1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_0013b390(long param_1,long param_2,long param_3,int param_4)
5: 
6: {
7: ushort *puVar1;
8: byte bVar2;
9: byte bVar3;
10: byte bVar4;
11: ushort uVar5;
12: int iVar6;
13: long lVar7;
14: long lVar8;
15: long *plVar9;
16: long lVar10;
17: long lVar11;
18: long lVar12;
19: long lVar13;
20: long lVar14;
21: int iVar15;
22: long lVar16;
23: short sVar17;
24: int iVar18;
25: int iVar19;
26: short *psVar20;
27: byte *pbVar21;
28: int iVar22;
29: int iVar23;
30: int iVar24;
31: int iVar25;
32: long lVar26;
33: bool bVar27;
34: int iStack268;
35: int iStack264;
36: int iStack260;
37: undefined *puStack256;
38: int iStack248;
39: int iStack244;
40: long lStack240;
41: long lStack232;
42: long lStack224;
43: long lStack216;
44: long lStack208;
45: int iStack176;
46: short *psStack152;
47: long lStack136;
48: 
49: lVar7 = *(long *)(param_1 + 0x270);
50: lVar8 = *(long *)(param_1 + 0x1a8);
51: iVar6 = *(int *)(param_1 + 0x88);
52: plVar9 = *(long **)(param_1 + 0xa0);
53: lVar10 = *(long *)(lVar7 + 0x30);
54: lVar11 = *(long *)(lVar7 + 0x50);
55: lVar12 = *plVar9;
56: lVar13 = plVar9[1];
57: lVar14 = plVar9[2];
58: if (0 < param_4) {
59: lStack136 = 0;
60: do {
61: pbVar21 = *(byte **)(param_2 + lStack136);
62: puStack256 = *(undefined **)(param_3 + lStack136);
63: bVar27 = *(int *)(lVar7 + 0x48) == 0;
64: if (bVar27) {
65: psStack152 = *(short **)(lVar7 + 0x40);
66: lStack208 = 1;
67: lStack216 = 10;
68: lStack224 = 8;
69: lStack240 = 6;
70: lStack232 = 3;
71: }
72: else {
73: pbVar21 = pbVar21 + (iVar6 * 3 - 3);
74: psStack152 = (short *)((ulong)(iVar6 * 3 + 3) * 2 + *(long *)(lVar7 + 0x40));
75: puStack256 = puStack256 + (iVar6 - 1);
76: lStack208 = -1;
77: lStack216 = -2;
78: lStack224 = -4;
79: lStack240 = -6;
80: lStack232 = -3;
81: }
82: *(uint *)(lVar7 + 0x48) = (uint)bVar27;
83: if (iVar6 == 0) {
84: sVar17 = 0;
85: iStack264._0_2_ = 0;
86: iStack268._0_2_ = 0;
87: }
88: else {
89: iStack260 = 0;
90: iVar18 = 0;
91: iStack264 = 0;
92: iStack268 = 0;
93: iVar19 = 0;
94: iStack244 = 0;
95: iStack248 = 0;
96: iVar15 = 0;
97: lVar26 = -lStack240;
98: psVar20 = psStack152;
99: iVar25 = 0;
100: iStack176 = iVar6;
101: do {
102: psVar20 = (short *)((long)psVar20 + lStack240);
103: bVar2 = *(byte *)(lVar8 + (int)((uint)*pbVar21 +
104: *(int *)(lVar11 + (long)(iVar15 + 8 + (int)*psVar20 >> 4) *
105: 4)));
106: bVar3 = *(byte *)(lVar8 + (int)((uint)pbVar21[1] +
107: *(int *)(lVar11 + (long)(iVar19 + 8 +
108: (int)*(short *)((long)(short *)((
109: long)psVar20 + lVar26) + lStack224) >> 4) * 4)));
110: bVar4 = *(byte *)(lVar8 + (int)((uint)pbVar21[2] +
111: *(int *)(lVar11 + (long)(iVar18 + 8 +
112: (int)*(short *)((long)(short *)((
113: long)psVar20 + lVar26) + lStack216) >> 4) * 4)));
114: puVar1 = (ushort *)
115: ((long)((int)(uint)bVar3 >> 2) * 0x40 +
116: *(long *)(lVar10 + (long)((int)(uint)bVar2 >> 3) * 8) +
117: (long)((int)(uint)bVar4 >> 3) * 2);
118: uVar5 = *puVar1;
119: if (uVar5 == 0) {
120: FUN_0013a910();
121: uVar5 = *puVar1;
122: }
123: pbVar21 = pbVar21 + lStack232;
124: *puStack256 = (char)(uVar5 - 1);
125: lVar16 = (long)(int)(uVar5 - 1);
126: iVar24 = (uint)bVar2 - (uint)*(byte *)(lVar12 + lVar16);
127: iVar22 = (uint)bVar4 - (uint)*(byte *)(lVar14 + lVar16);
128: iVar23 = (uint)bVar3 - (uint)*(byte *)(lVar13 + lVar16);
129: *(short *)((long)psVar20 + lVar26) = (short)iVar24 * 3 + (short)iStack268;
130: iStack268 = iVar24 * 5 + iStack248;
131: *(short *)((long)psVar20 + lVar26 + 4) = (short)iVar22 * 3 + (short)iStack260;
132: iStack260 = iVar22 * 5 + iStack244;
133: *(short *)((long)psVar20 + lVar26 + 2) = (short)iVar23 * 3 + (short)iStack264;
134: iStack264 = iVar23 * 5 + iVar25;
135: iVar15 = iVar24 * 7;
136: iVar19 = iVar23 * 7;
137: iVar18 = iVar22 * 7;
138: puStack256 = puStack256 + lStack208;
139: iStack176 = iStack176 + -1;
140: iVar25 = iVar23;
141: iStack248 = iVar24;
142: iStack244 = iVar22;
143: } while (iStack176 != 0);
144: sVar17 = (short)iStack260;
145: psStack152 = (short *)((long)psStack152 + lStack240 * ((ulong)(iVar6 - 1) + 1));
146: }
147: lStack136 = lStack136 + 8;
148: psStack152[1] = (short)iStack264;
149: *psStack152 = (short)iStack268;
150: psStack152[2] = sVar17;
151: } while (lStack136 != (ulong)(param_4 - 1) * 8 + 8);
152: }
153: return;
154: }
155: 
