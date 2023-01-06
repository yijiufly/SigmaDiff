1: 
2: void FUN_001342d0(long param_1,long param_2,long param_3,long param_4,uint param_5)
3: 
4: {
5: undefined uVar1;
6: short *psVar2;
7: int *piVar3;
8: int *piVar4;
9: long lVar5;
10: undefined *puVar6;
11: short sVar7;
12: short sVar8;
13: int iVar9;
14: short sVar10;
15: short sVar11;
16: long lVar12;
17: int iVar13;
18: short sVar14;
19: short sVar15;
20: short sVar16;
21: short sVar17;
22: int iVar18;
23: short sVar19;
24: short sVar20;
25: int iVar21;
26: int iVar22;
27: short sVar23;
28: int iVar24;
29: int aiStack312 [8];
30: int aiStack280 [8];
31: int aiStack248 [8];
32: int aiStack216 [8];
33: int aiStack184 [8];
34: int aiStack152 [8];
35: int aiStack120 [8];
36: int aiStack88 [10];
37: 
38: param_3 = param_3 + 2;
39: piVar4 = aiStack312;
40: iVar13 = 8;
41: lVar5 = *(long *)(param_1 + 0x1a8) + 0x80;
42: piVar3 = piVar4;
43: psVar2 = *(short **)(param_2 + 0x58);
44: do {
45: sVar7 = *(short *)(param_3 + 0x1e);
46: if ((*(short *)(param_3 + 0xe) == 0) && (sVar7 == 0)) {
47: sVar14 = *(short *)(param_3 + 0x2e);
48: sVar10 = *(short *)(param_3 + 0x3e);
49: if (sVar14 != 0) {
50: sVar20 = *(short *)(param_3 + 0x5e);
51: sVar19 = *(short *)(param_3 + 0x4e);
52: sVar7 = 0;
53: sVar16 = *(short *)(param_3 + 0x6e);
54: goto LAB_00134350;
55: }
56: if (sVar10 != 0) {
57: sVar20 = *(short *)(param_3 + 0x5e);
58: sVar19 = *(short *)(param_3 + 0x4e);
59: sVar14 = 0;
60: sVar16 = *(short *)(param_3 + 0x6e);
61: sVar7 = 0;
62: goto LAB_00134350;
63: }
64: sVar19 = *(short *)(param_3 + 0x4e);
65: sVar20 = *(short *)(param_3 + 0x5e);
66: sVar16 = *(short *)(param_3 + 0x6e);
67: if (sVar19 != 0) {
68: LAB_001347f3:
69: sVar14 = 0;
70: sVar10 = 0;
71: sVar7 = 0;
72: goto LAB_00134350;
73: }
74: if (sVar20 != 0) {
75: sVar19 = 0;
76: goto LAB_001347f3;
77: }
78: if (sVar16 != 0) {
79: sVar19 = 0;
80: sVar14 = 0;
81: sVar20 = 0;
82: sVar10 = 0;
83: sVar7 = 0;
84: goto LAB_00134350;
85: }
86: iVar9 = (int)*(short *)(param_3 + -2) * (int)*psVar2;
87: *piVar3 = iVar9;
88: piVar3[8] = iVar9;
89: piVar3[0x10] = iVar9;
90: piVar3[0x18] = iVar9;
91: piVar3[0x20] = iVar9;
92: piVar3[0x28] = iVar9;
93: piVar3[0x30] = iVar9;
94: piVar3[0x38] = iVar9;
95: }
96: else {
97: sVar10 = *(short *)(param_3 + 0x3e);
98: sVar20 = *(short *)(param_3 + 0x5e);
99: sVar14 = *(short *)(param_3 + 0x2e);
100: sVar19 = *(short *)(param_3 + 0x4e);
101: sVar16 = *(short *)(param_3 + 0x6e);
102: LAB_00134350:
103: sVar8 = *psVar2 * *(short *)(param_3 + -2);
104: sVar15 = *(short *)(param_3 + 0xe) * psVar2[8];
105: sVar17 = sVar10 * psVar2[0x20] + sVar8;
106: sVar8 = sVar8 - sVar10 * psVar2[0x20];
107: sVar11 = sVar20 * psVar2[0x30] + sVar7 * psVar2[0x10];
108: sVar23 = sVar19 * psVar2[0x28] + sVar14 * psVar2[0x18];
109: sVar19 = sVar19 * psVar2[0x28] - sVar14 * psVar2[0x18];
110: sVar14 = sVar16 * psVar2[0x38] + sVar15;
111: sVar15 = sVar15 - sVar16 * psVar2[0x38];
112: sVar10 = sVar14 + sVar23;
113: iVar24 = (int)(short)(sVar11 + sVar17);
114: iVar18 = (int)(short)(sVar17 - sVar11);
115: sVar11 = (short)((ulong)((long)((int)(short)(sVar7 * psVar2[0x10]) -
116: (int)(short)(sVar20 * psVar2[0x30])) * 0x16a) >> 8) - sVar11;
117: sVar20 = (short)((ulong)((long)((int)sVar15 + (int)sVar19) * 0x1d9) >> 8);
118: sVar7 = ((short)((ulong)((long)sVar19 * -0x29d) >> 8) - sVar10) + sVar20;
119: piVar3[0x38] = iVar24 - sVar10;
120: iVar21 = (int)(short)(sVar11 + sVar8);
121: iVar9 = (int)(short)(sVar8 - sVar11);
122: sVar14 = (short)((ulong)((long)((int)sVar14 - (int)sVar23) * 0x16a) >> 8) - sVar7;
123: *piVar3 = iVar24 + sVar10;
124: piVar3[8] = iVar21 + sVar7;
125: iVar24 = (int)(short)(sVar14 + ((short)((ulong)((long)sVar15 * 0x115) >> 8) - sVar20));
126: piVar3[0x30] = iVar21 - sVar7;
127: piVar3[0x10] = iVar9 + sVar14;
128: piVar3[0x28] = iVar9 - sVar14;
129: piVar3[0x18] = iVar18 - iVar24;
130: piVar3[0x20] = iVar18 + iVar24;
131: }
132: piVar3 = piVar3 + 1;
133: param_3 = param_3 + 2;
134: iVar13 = iVar13 + -1;
135: psVar2 = psVar2 + 1;
136: } while (iVar13 != 0);
137: lVar12 = 0;
138: do {
139: puVar6 = (undefined *)((ulong)param_5 + *(long *)(param_4 + lVar12));
140: if (piVar4[1] == 0) {
141: iVar13 = piVar4[2];
142: if (iVar13 != 0) {
143: iVar9 = piVar4[6];
144: iVar24 = piVar4[7];
145: iVar21 = piVar4[4];
146: iVar22 = piVar4[5];
147: iVar18 = piVar4[3];
148: goto LAB_0013450e;
149: }
150: iVar18 = piVar4[3];
151: iVar21 = piVar4[4];
152: if (iVar18 != 0) {
153: iVar9 = piVar4[6];
154: iVar24 = piVar4[7];
155: iVar22 = piVar4[5];
156: goto LAB_0013450e;
157: }
158: if (iVar21 != 0) {
159: iVar9 = piVar4[6];
160: iVar24 = piVar4[7];
161: iVar13 = iVar18;
162: iVar22 = piVar4[5];
163: goto LAB_0013450e;
164: }
165: iVar22 = piVar4[5];
166: iVar9 = piVar4[6];
167: iVar24 = piVar4[7];
168: iVar13 = iVar21;
169: iVar18 = iVar21;
170: if (((iVar22 != 0) || (iVar13 = iVar22, iVar21 = iVar22, iVar18 = iVar22, iVar9 != 0)) ||
171: (iVar13 = iVar9, iVar21 = iVar9, iVar22 = iVar9, iVar18 = iVar9, iVar24 != 0))
172: goto LAB_0013450e;
173: uVar1 = *(undefined *)(lVar5 + (ulong)(*piVar4 >> 5 & 0x3ff));
174: *puVar6 = uVar1;
175: puVar6[1] = uVar1;
176: puVar6[2] = uVar1;
177: puVar6[3] = uVar1;
178: puVar6[4] = uVar1;
179: puVar6[5] = uVar1;
180: puVar6[6] = uVar1;
181: puVar6[7] = uVar1;
182: }
183: else {
184: iVar9 = piVar4[6];
185: iVar24 = piVar4[7];
186: iVar13 = piVar4[2];
187: iVar21 = piVar4[4];
188: iVar22 = piVar4[5];
189: iVar18 = piVar4[3];
190: LAB_0013450e:
191: sVar10 = (short)iVar21 + (short)*piVar4;
192: sVar14 = (short)*piVar4 - (short)iVar21;
193: sVar7 = (short)iVar9 + (short)iVar13;
194: sVar11 = (short)iVar18 + (short)iVar22;
195: sVar15 = (short)iVar22 - (short)iVar18;
196: sVar8 = (short)piVar4[1];
197: sVar16 = (short)iVar24 + sVar8;
198: sVar8 = sVar8 - (short)iVar24;
199: sVar19 = sVar16 + sVar11;
200: iVar18 = (int)(short)(sVar7 + sVar10);
201: sVar20 = (short)((ulong)((long)((int)(short)iVar13 - (int)(short)iVar9) * 0x16a) >> 8) - sVar7
202: ;
203: *puVar6 = *(undefined *)(lVar5 + (ulong)(iVar18 + sVar19 >> 5 & 0x3ff));
204: iVar24 = (int)(short)(sVar14 - sVar20);
205: iVar13 = (int)(short)(sVar20 + sVar14);
206: sVar14 = (short)((ulong)((long)((int)sVar8 + (int)sVar15) * 0x1d9) >> 8);
207: sVar20 = ((short)((ulong)((long)sVar15 * -0x29d) >> 8) - sVar19) + sVar14;
208: sVar16 = (short)((ulong)((long)((int)sVar16 - (int)sVar11) * 0x16a) >> 8) - sVar20;
209: puVar6[7] = *(undefined *)(lVar5 + (ulong)(iVar18 - sVar19 >> 5 & 0x3ff));
210: puVar6[1] = *(undefined *)(lVar5 + (ulong)(iVar13 + sVar20 >> 5 & 0x3ff));
211: puVar6[6] = *(undefined *)(lVar5 + (ulong)(iVar13 - sVar20 >> 5 & 0x3ff));
212: iVar13 = (int)(short)(sVar10 - sVar7);
213: puVar6[2] = *(undefined *)(lVar5 + (ulong)(iVar24 + sVar16 >> 5 & 0x3ff));
214: iVar9 = (int)(short)(sVar16 + ((short)((ulong)((long)sVar8 * 0x115) >> 8) - sVar14));
215: puVar6[5] = *(undefined *)(lVar5 + (ulong)(iVar24 - sVar16 >> 5 & 0x3ff));
216: puVar6[4] = *(undefined *)(lVar5 + (ulong)(iVar13 + iVar9 >> 5 & 0x3ff));
217: puVar6[3] = *(undefined *)(lVar5 + (ulong)(iVar13 - iVar9 >> 5 & 0x3ff));
218: }
219: piVar4 = piVar4 + 8;
220: lVar12 = lVar12 + 8;
221: if (lVar12 == 0x40) {
222: return;
223: }
224: } while( true );
225: }
226: 
