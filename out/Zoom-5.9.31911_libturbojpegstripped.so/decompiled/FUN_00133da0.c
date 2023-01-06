1: 
2: void FUN_00133da0(long param_1,long param_2,long param_3,long *param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: float *pfVar2;
7: float *pfVar3;
8: undefined *puVar4;
9: int iVar5;
10: int iVar6;
11: int iVar7;
12: int iVar8;
13: int iVar9;
14: int iVar10;
15: short sVar11;
16: float fVar12;
17: float fVar13;
18: float fVar14;
19: float fVar15;
20: float fVar16;
21: float fVar17;
22: float fVar18;
23: float fVar19;
24: float fVar20;
25: float fVar21;
26: float afStack312 [8];
27: float afStack280 [8];
28: float afStack248 [8];
29: float afStack216 [8];
30: float afStack184 [8];
31: float afStack152 [8];
32: float afStack120 [8];
33: float afStack88 [8];
34: float afStack56 [2];
35: 
36: param_3 = param_3 + 2;
37: iVar7 = 8;
38: lVar1 = *(long *)(param_1 + 0x1a8);
39: pfVar2 = afStack312;
40: pfVar3 = *(float **)(param_2 + 0x58);
41: do {
42: iVar10 = (int)*(short *)(param_3 + 0x1e);
43: if ((*(short *)(param_3 + 0xe) == 0) && (*(short *)(param_3 + 0x1e) == 0)) {
44: iVar5 = (int)*(short *)(param_3 + 0x2e);
45: iVar9 = (int)*(short *)(param_3 + 0x3e);
46: if (*(short *)(param_3 + 0x2e) != 0) {
47: iVar6 = (int)*(short *)(param_3 + 0x5e);
48: iVar8 = (int)*(short *)(param_3 + 0x4e);
49: iVar10 = 0;
50: sVar11 = *(short *)(param_3 + 0x6e);
51: goto LAB_00133e38;
52: }
53: if (*(short *)(param_3 + 0x3e) != 0) {
54: iVar6 = (int)*(short *)(param_3 + 0x5e);
55: iVar8 = (int)*(short *)(param_3 + 0x4e);
56: iVar5 = 0;
57: sVar11 = *(short *)(param_3 + 0x6e);
58: iVar10 = 0;
59: goto LAB_00133e38;
60: }
61: iVar8 = (int)*(short *)(param_3 + 0x4e);
62: iVar6 = (int)*(short *)(param_3 + 0x5e);
63: sVar11 = *(short *)(param_3 + 0x6e);
64: if (*(short *)(param_3 + 0x4e) != 0) {
65: LAB_001342a3:
66: iVar5 = 0;
67: iVar9 = 0;
68: iVar10 = 0;
69: goto LAB_00133e38;
70: }
71: if (*(short *)(param_3 + 0x5e) != 0) {
72: iVar8 = 0;
73: goto LAB_001342a3;
74: }
75: if (sVar11 != 0) {
76: iVar8 = 0;
77: iVar5 = 0;
78: iVar6 = 0;
79: iVar9 = 0;
80: iVar10 = 0;
81: goto LAB_00133e38;
82: }
83: fVar12 = (float)(int)*(short *)(param_3 + -2) * *pfVar3 * 0.125;
84: *pfVar2 = fVar12;
85: pfVar2[8] = fVar12;
86: pfVar2[0x10] = fVar12;
87: pfVar2[0x18] = fVar12;
88: pfVar2[0x20] = fVar12;
89: pfVar2[0x28] = fVar12;
90: pfVar2[0x30] = fVar12;
91: pfVar2[0x38] = fVar12;
92: }
93: else {
94: iVar9 = (int)*(short *)(param_3 + 0x3e);
95: iVar6 = (int)*(short *)(param_3 + 0x5e);
96: iVar5 = (int)*(short *)(param_3 + 0x2e);
97: iVar8 = (int)*(short *)(param_3 + 0x4e);
98: sVar11 = *(short *)(param_3 + 0x6e);
99: LAB_00133e38:
100: fVar17 = (float)(int)*(short *)(param_3 + -2) * *pfVar3 * 0.125;
101: fVar12 = (float)iVar10 * pfVar3[0x10] * 0.125;
102: fVar14 = (float)iVar9 * pfVar3[0x20] * 0.125;
103: fVar16 = fVar17 + fVar14;
104: fVar17 = fVar17 - fVar14;
105: fVar13 = (float)iVar6 * pfVar3[0x30] * 0.125;
106: fVar14 = fVar12 + fVar13;
107: fVar19 = fVar16 + fVar14;
108: fVar16 = fVar16 - fVar14;
109: fVar14 = (fVar12 - fVar13) * 1.414214 - fVar14;
110: fVar18 = fVar17 + fVar14;
111: fVar17 = fVar17 - fVar14;
112: fVar14 = (float)(int)*(short *)(param_3 + 0xe) * pfVar3[8] * 0.125;
113: fVar12 = (float)iVar5 * pfVar3[0x18] * 0.125;
114: fVar21 = (float)iVar8 * pfVar3[0x28] * 0.125;
115: fVar13 = fVar21 - fVar12;
116: fVar21 = fVar21 + fVar12;
117: fVar12 = (float)(int)sVar11 * pfVar3[0x38] * 0.125;
118: fVar20 = fVar14 - fVar12;
119: fVar14 = fVar14 + fVar12;
120: fVar12 = fVar14 + fVar21;
121: fVar15 = (fVar13 + fVar20) * 1.847759;
122: fVar13 = (fVar15 - fVar13 * 2.613126) - fVar12;
123: *pfVar2 = fVar19 + fVar12;
124: pfVar2[0x38] = fVar19 - fVar12;
125: fVar12 = (fVar14 - fVar21) * 1.414214 - fVar13;
126: fVar14 = (fVar15 - fVar20 * 1.082392) - fVar12;
127: pfVar2[8] = fVar18 + fVar13;
128: pfVar2[0x30] = fVar18 - fVar13;
129: pfVar2[0x10] = fVar17 + fVar12;
130: pfVar2[0x28] = fVar17 - fVar12;
131: pfVar2[0x18] = fVar16 + fVar14;
132: pfVar2[0x20] = fVar16 - fVar14;
133: }
134: pfVar2 = pfVar2 + 1;
135: param_3 = param_3 + 2;
136: iVar7 = iVar7 + -1;
137: pfVar3 = pfVar3 + 1;
138: if (iVar7 == 0) {
139: pfVar3 = afStack312;
140: do {
141: puVar4 = (undefined *)((ulong)param_5 + *param_4);
142: pfVar2 = pfVar3 + 8;
143: param_4 = param_4 + 1;
144: fVar16 = pfVar3[4] + *pfVar3 + 128.5;
145: fVar17 = (*pfVar3 + 128.5) - pfVar3[4];
146: fVar12 = pfVar3[2] + pfVar3[6];
147: fVar19 = fVar16 + fVar12;
148: fVar16 = fVar16 - fVar12;
149: fVar12 = (pfVar3[2] - pfVar3[6]) * 1.414214 - fVar12;
150: fVar18 = fVar17 + fVar12;
151: fVar17 = fVar17 - fVar12;
152: fVar14 = pfVar3[5] - pfVar3[3];
153: fVar21 = pfVar3[5] + pfVar3[3];
154: fVar20 = pfVar3[1] - pfVar3[7];
155: fVar12 = pfVar3[1] + pfVar3[7];
156: fVar15 = fVar12 + fVar21;
157: fVar13 = (fVar14 + fVar20) * 1.847759;
158: fVar14 = (fVar13 - fVar14 * 2.613126) - fVar15;
159: fVar12 = (fVar12 - fVar21) * 1.414214 - fVar14;
160: fVar13 = (fVar13 - fVar20 * 1.082392) - fVar12;
161: *puVar4 = *(undefined *)(lVar1 + (ulong)((int)(fVar19 + fVar15) & 0x3ff));
162: puVar4[7] = *(undefined *)(lVar1 + (ulong)((int)(fVar19 - fVar15) & 0x3ff));
163: puVar4[1] = *(undefined *)(lVar1 + (ulong)((int)(fVar18 + fVar14) & 0x3ff));
164: puVar4[6] = *(undefined *)(lVar1 + (ulong)((int)(fVar18 - fVar14) & 0x3ff));
165: puVar4[2] = *(undefined *)(lVar1 + (ulong)((int)(fVar17 + fVar12) & 0x3ff));
166: puVar4[5] = *(undefined *)(lVar1 + (ulong)((int)(fVar17 - fVar12) & 0x3ff));
167: puVar4[3] = *(undefined *)(lVar1 + (ulong)((int)(fVar16 + fVar13) & 0x3ff));
168: puVar4[4] = *(undefined *)(lVar1 + (ulong)((int)(fVar16 - fVar13) & 0x3ff));
169: pfVar3 = pfVar2;
170: } while (pfVar2 != afStack56);
171: return;
172: }
173: } while( true );
174: }
175: 
