1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_00147f30(long param_1,byte **param_2,long *param_3,int param_4)
5: 
6: {
7: short *psVar1;
8: byte bVar2;
9: byte bVar3;
10: byte bVar4;
11: ushort uVar5;
12: int iVar6;
13: long lVar7;
14: long lVar8;
15: long lVar9;
16: long lVar10;
17: long *plVar11;
18: long lVar12;
19: long lVar13;
20: long lVar14;
21: int iVar15;
22: long lVar16;
23: short sVar17;
24: int iVar18;
25: int iVar19;
26: int iVar20;
27: int iVar21;
28: short *psVar22;
29: long lVar23;
30: undefined *puVar24;
31: int iVar25;
32: byte *pbVar26;
33: ushort *puVar27;
34: bool bVar28;
35: int iStack260;
36: int iStack256;
37: int iStack252;
38: int iStack248;
39: int iStack244;
40: long lStack240;
41: long lStack232;
42: long lStack224;
43: long lStack216;
44: long lStack208;
45: int iStack200;
46: int iStack196;
47: short *psStack160;
48: byte **ppbStack152;
49: long *plStack104;
50: 
51: lVar7 = *(long *)(param_1 + 0x270);
52: lVar8 = *(long *)(param_1 + 0x1a8);
53: lVar9 = *(long *)(lVar7 + 0x30);
54: lVar10 = *(long *)(lVar7 + 0x50);
55: plVar11 = *(long **)(param_1 + 0xa0);
56: iVar6 = *(int *)(param_1 + 0x88);
57: lVar12 = *plVar11;
58: lVar13 = plVar11[1];
59: lVar14 = plVar11[2];
60: if (0 < param_4) {
61: ppbStack152 = param_2;
62: plStack104 = param_3;
63: do {
64: pbVar26 = *ppbStack152;
65: puVar24 = (undefined *)*plStack104;
66: psStack160 = *(short **)(lVar7 + 0x40);
67: bVar28 = *(int *)(lVar7 + 0x48) == 0;
68: if (bVar28) {
69: lStack208 = 1;
70: lStack216 = 10;
71: lStack224 = 8;
72: lStack240 = 6;
73: lStack232 = 3;
74: }
75: else {
76: pbVar26 = pbVar26 + (iVar6 * 3 - 3);
77: lStack208 = -1;
78: lStack216 = -2;
79: lStack224 = -4;
80: lStack240 = -6;
81: lStack232 = -3;
82: puVar24 = puVar24 + (iVar6 - 1U);
83: psStack160 = psStack160 + (iVar6 * 3 + 3);
84: }
85: *(uint *)(lVar7 + 0x48) = (uint)bVar28;
86: if (iVar6 == 0) {
87: sVar17 = 0;
88: iStack256._0_2_ = 0;
89: iStack260._0_2_ = 0;
90: }
91: else {
92: iVar18 = 0;
93: iStack252 = 0;
94: iVar19 = 0;
95: iStack256 = 0;
96: iStack260 = 0;
97: iVar15 = 0;
98: iStack200 = 0;
99: iStack244 = 0;
100: lVar23 = -lStack240;
101: iStack248 = 0;
102: psVar22 = psStack160;
103: iStack196 = iVar6;
104: do {
105: psVar1 = (short *)((long)psVar22 + lStack240);
106: bVar2 = *(byte *)(lVar8 + (int)((uint)*pbVar26 +
107: *(int *)(lVar10 + (long)(iVar15 + 8 + (int)*psVar1 >> 4) *
108: 4)));
109: bVar3 = *(byte *)(lVar8 + (int)((uint)pbVar26[1] +
110: *(int *)(lVar10 + (long)(iVar19 + 8 +
111: (int)*(short *)((long)psVar22 +
112: lStack224) >> 4) *
113: 4)));
114: bVar4 = *(byte *)(lVar8 + (int)((uint)pbVar26[2] +
115: *(int *)(lVar10 + (long)(iVar18 + 8 +
116: (int)*(short *)((long)psVar22 +
117: lStack216) >> 4) *
118: 4)));
119: puVar27 = (ushort *)
120: ((long)((int)(uint)bVar3 >> 2) * 0x40 + (long)((int)(uint)bVar4 >> 3) * 2 +
121: *(long *)(lVar9 + (long)((int)(uint)bVar2 >> 3) * 8));
122: uVar5 = *puVar27;
123: if (uVar5 == 0) {
124: FUN_001472b0();
125: uVar5 = *puVar27;
126: }
127: pbVar26 = pbVar26 + lStack232;
128: *puVar24 = (char)(uVar5 - 1);
129: lVar16 = (long)(int)(uVar5 - 1);
130: puVar24 = puVar24 + lStack208;
131: iVar25 = (uint)bVar2 - (uint)*(byte *)(lVar12 + lVar16);
132: iVar21 = (uint)bVar3 - (uint)*(byte *)(lVar13 + lVar16);
133: iVar20 = (uint)bVar4 - (uint)*(byte *)(lVar14 + lVar16);
134: *(short *)((long)psVar1 + lVar23 + 2) = (short)iVar21 * 3 + (short)iStack256;
135: iStack256 = iVar21 * 5 + iStack244;
136: *(short *)((long)psVar1 + lVar23) = (short)iVar25 * 3 + (short)iStack260;
137: iStack260 = iVar25 * 5 + iStack248;
138: *(short *)((long)psVar1 + lVar23 + 4) = (short)iVar20 * 3 + (short)iStack252;
139: iStack252 = iVar20 * 5 + iStack200;
140: iVar19 = iVar21 * 7;
141: iVar15 = iVar25 * 7;
142: iVar18 = iVar20 * 7;
143: iStack196 = iStack196 + -1;
144: psVar22 = psVar1;
145: iStack248 = iVar25;
146: iStack244 = iVar21;
147: iStack200 = iVar20;
148: } while (iStack196 != 0);
149: sVar17 = (short)iStack252;
150: psStack160 = (short *)((long)psStack160 + ((ulong)(iVar6 - 1U) + 1) * lStack240);
151: }
152: ppbStack152 = ppbStack152 + 1;
153: plStack104 = plStack104 + 1;
154: psStack160[1] = (short)iStack256;
155: *psStack160 = (short)iStack260;
156: psStack160[2] = sVar17;
157: } while (param_2 + (ulong)(param_4 - 1) + 1 != ppbStack152);
158: }
159: return;
160: }
161: 
