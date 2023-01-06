1: 
2: void FUN_00107bd0(short *param_1,float *param_2,float *param_3)
3: 
4: {
5: undefined (*pauVar1) [16];
6: float *pfVar2;
7: int iVar3;
8: uint6 uVar4;
9: uint6 uVar5;
10: float fVar6;
11: float fVar7;
12: float fVar8;
13: float fVar9;
14: float fVar10;
15: float fVar11;
16: float fVar12;
17: float fVar13;
18: float *pfVar14;
19: uint uVar15;
20: uint uVar16;
21: int iVar17;
22: long lVar18;
23: ulong uVar19;
24: int iVar20;
25: undefined2 uVar21;
26: int iVar22;
27: int iVar23;
28: 
29: uVar15 = -(int)((ulong)param_3 >> 2) & 3;
30: if (uVar15 == 0) {
31: iVar20 = 0x40;
32: iVar17 = 0;
33: }
34: else {
35: *param_1 = (short)(int)(*param_3 * *param_2 + 16384.5) + -0x4000;
36: if (uVar15 == 1) {
37: iVar20 = 0x3f;
38: iVar17 = 1;
39: }
40: else {
41: param_1[1] = (short)(int)(param_3[1] * param_2[1] + 16384.5) + -0x4000;
42: if (uVar15 == 3) {
43: iVar20 = 0x3d;
44: iVar17 = 3;
45: param_1[2] = (short)(int)(param_2[2] * param_3[2] + 16384.5) + -0x4000;
46: }
47: else {
48: iVar20 = 0x3e;
49: iVar17 = 2;
50: }
51: }
52: }
53: uVar19 = (ulong)uVar15;
54: uVar15 = 0x40 - uVar15;
55: pauVar1 = (undefined (*) [16])(param_1 + uVar19);
56: pfVar2 = param_3 + uVar19;
57: pfVar14 = param_2 + uVar19;
58: iVar3 = (int)(pfVar14[1] * pfVar2[1] + 16384.5);
59: uVar21 = (undefined2)((uint)iVar3 >> 0x10);
60: iVar22 = (int)(pfVar14[2] * pfVar2[2] + 16384.5);
61: uVar4 = CONCAT24((short)((uint)iVar22 >> 0x10),CONCAT22((short)iVar22,uVar21));
62: iVar22 = (int)(pfVar14[4] * pfVar2[4] + 16384.5);
63: uVar5 = CONCAT24((short)(int)(pfVar14[5] * pfVar2[5] + 16384.5),
64: CONCAT22((short)iVar3,(short)((uint)iVar22 >> 0x10)));
65: fVar6 = pfVar14[0xc];
66: fVar7 = pfVar14[0xd];
67: fVar8 = pfVar14[0xe];
68: fVar9 = pfVar14[0xf];
69: fVar10 = pfVar2[0xc];
70: fVar11 = pfVar2[0xd];
71: fVar12 = pfVar2[0xe];
72: fVar13 = pfVar2[0xf];
73: *pauVar1 = CONCAT214((short)(int)(pfVar14[7] * pfVar2[7] + 16384.5) + -0x4000,
74: CONCAT212((short)(int)(pfVar14[6] * pfVar2[6] + 16384.5) + -0x4000,
75: CONCAT210(SUB142((ZEXT814(CONCAT26(uVar21,uVar5)) << 0x30) >> 0x50,
76: 0) + -0x4000,
77: CONCAT28((short)iVar22 + -0x4000,
78: CONCAT26(SUB142((ZEXT814(CONCAT26((short)(int)(
79: pfVar14[3] * pfVar2[3] + 16384.5),uVar4)) << 0x30)
80: >> 0x60,0) + -0x4000,
81: CONCAT24(SUB122((ZEXT612(uVar4) << 0x30) >> 0x40,0
82: ) + -0x4000,
83: CONCAT22(SUB122((ZEXT612(uVar5) << 0x30)
84: >> 0x40,0) + -0x4000,
85: (short)(int)(*pfVar14 * *pfVar2
86: + 16384.5) + -0x4000
87: )))))));
88: iVar23 = (int)(fVar6 * fVar10 + 16384.5);
89: iVar3 = (int)(pfVar14[9] * pfVar2[9] + 16384.5);
90: uVar21 = (undefined2)((uint)iVar3 >> 0x10);
91: iVar22 = (int)(pfVar14[10] * pfVar2[10] + 16384.5);
92: uVar4 = CONCAT24((short)((uint)iVar22 >> 0x10),CONCAT22((short)iVar22,uVar21));
93: uVar5 = CONCAT24((short)(int)(fVar7 * fVar11 + 16384.5),
94: CONCAT22((short)iVar3,(short)((uint)iVar23 >> 0x10)));
95: fVar6 = pfVar14[0x14];
96: fVar7 = pfVar14[0x15];
97: fVar10 = pfVar14[0x16];
98: fVar11 = pfVar14[0x17];
99: pauVar1[1] = CONCAT214((short)(int)(fVar9 * fVar13 + 16384.5) + -0x4000,
100: CONCAT212((short)(int)(fVar8 * fVar12 + 16384.5) + -0x4000,
101: CONCAT210(SUB142((ZEXT814(CONCAT26(uVar21,uVar5)) << 0x30) >>
102: 0x50,0) + -0x4000,
103: CONCAT28((short)iVar23 + -0x4000,
104: CONCAT26(SUB142((ZEXT814(CONCAT26((short)(int)
105: (pfVar14[0xb] * pfVar2[0xb] + 16384.5),uVar4)) <<
106: 0x30) >> 0x60,0) + -0x4000,
107: CONCAT24(SUB122((ZEXT612(uVar4) << 0x30) >> 0x40,0
108: ) + -0x4000,
109: CONCAT22(SUB122((ZEXT612(uVar5) << 0x30)
110: >> 0x40,0) + -0x4000,
111: (short)(int)(pfVar14[8] *
112: pfVar2[8] + 16384.5
113: ) + -0x4000)))))));
114: iVar23 = (int)(fVar6 * pfVar2[0x14] + 16384.5);
115: iVar3 = (int)(pfVar14[0x11] * pfVar2[0x11] + 16384.5);
116: uVar21 = (undefined2)((uint)iVar3 >> 0x10);
117: iVar22 = (int)(pfVar14[0x12] * pfVar2[0x12] + 16384.5);
118: uVar4 = CONCAT24((short)((uint)iVar22 >> 0x10),CONCAT22((short)iVar22,uVar21));
119: uVar5 = CONCAT24((short)(int)(fVar7 * pfVar2[0x15] + 16384.5),
120: CONCAT22((short)iVar3,(short)((uint)iVar23 >> 0x10)));
121: fVar6 = pfVar14[0x1c];
122: fVar7 = pfVar14[0x1d];
123: fVar8 = pfVar14[0x1e];
124: fVar9 = pfVar14[0x1f];
125: pauVar1[2] = CONCAT214((short)(int)(fVar11 * pfVar2[0x17] + 16384.5) + -0x4000,
126: CONCAT212((short)(int)(fVar10 * pfVar2[0x16] + 16384.5) + -0x4000,
127: CONCAT210(SUB142((ZEXT814(CONCAT26(uVar21,uVar5)) << 0x30) >>
128: 0x50,0) + -0x4000,
129: CONCAT28((short)iVar23 + -0x4000,
130: CONCAT26(SUB142((ZEXT814(CONCAT26((short)(int)
131: (pfVar14[0x13] * pfVar2[0x13] + 16384.5),uVar4))
132: << 0x30) >> 0x60,0) + -0x4000,
133: CONCAT24(SUB122((ZEXT612(uVar4) << 0x30) >> 0x40,0
134: ) + -0x4000,
135: CONCAT22(SUB122((ZEXT612(uVar5) << 0x30)
136: >> 0x40,0) + -0x4000,
137: (short)(int)(pfVar14[0x10] *
138: pfVar2[0x10] +
139: 16384.5) + -0x4000))
140: )))));
141: iVar23 = (int)(fVar6 * pfVar2[0x1c] + 16384.5);
142: iVar3 = (int)(pfVar14[0x19] * pfVar2[0x19] + 16384.5);
143: uVar21 = (undefined2)((uint)iVar3 >> 0x10);
144: iVar22 = (int)(pfVar14[0x1a] * pfVar2[0x1a] + 16384.5);
145: uVar4 = CONCAT24((short)((uint)iVar22 >> 0x10),CONCAT22((short)iVar22,uVar21));
146: uVar5 = CONCAT24((short)(int)(fVar7 * pfVar2[0x1d] + 16384.5),
147: CONCAT22((short)iVar3,(short)((uint)iVar23 >> 0x10)));
148: fVar6 = pfVar14[0x24];
149: fVar7 = pfVar14[0x25];
150: fVar10 = pfVar14[0x26];
151: fVar11 = pfVar14[0x27];
152: pauVar1[3] = CONCAT214((short)(int)(fVar9 * pfVar2[0x1f] + 16384.5) + -0x4000,
153: CONCAT212((short)(int)(fVar8 * pfVar2[0x1e] + 16384.5) + -0x4000,
154: CONCAT210(SUB142((ZEXT814(CONCAT26(uVar21,uVar5)) << 0x30) >>
155: 0x50,0) + -0x4000,
156: CONCAT28((short)iVar23 + -0x4000,
157: CONCAT26(SUB142((ZEXT814(CONCAT26((short)(int)
158: (pfVar14[0x1b] * pfVar2[0x1b] + 16384.5),uVar4))
159: << 0x30) >> 0x60,0) + -0x4000,
160: CONCAT24(SUB122((ZEXT612(uVar4) << 0x30) >> 0x40,0
161: ) + -0x4000,
162: CONCAT22(SUB122((ZEXT612(uVar5) << 0x30)
163: >> 0x40,0) + -0x4000,
164: (short)(int)(pfVar14[0x18] *
165: pfVar2[0x18] +
166: 16384.5) + -0x4000))
167: )))));
168: iVar23 = (int)(fVar6 * pfVar2[0x24] + 16384.5);
169: iVar3 = (int)(pfVar14[0x21] * pfVar2[0x21] + 16384.5);
170: uVar21 = (undefined2)((uint)iVar3 >> 0x10);
171: iVar22 = (int)(pfVar14[0x22] * pfVar2[0x22] + 16384.5);
172: uVar4 = CONCAT24((short)((uint)iVar22 >> 0x10),CONCAT22((short)iVar22,uVar21));
173: uVar5 = CONCAT24((short)(int)(fVar7 * pfVar2[0x25] + 16384.5),
174: CONCAT22((short)iVar3,(short)((uint)iVar23 >> 0x10)));
175: fVar6 = pfVar14[0x2c];
176: fVar7 = pfVar14[0x2d];
177: fVar8 = pfVar14[0x2e];
178: fVar9 = pfVar14[0x2f];
179: pauVar1[4] = CONCAT214((short)(int)(fVar11 * pfVar2[0x27] + 16384.5) + -0x4000,
180: CONCAT212((short)(int)(fVar10 * pfVar2[0x26] + 16384.5) + -0x4000,
181: CONCAT210(SUB142((ZEXT814(CONCAT26(uVar21,uVar5)) << 0x30) >>
182: 0x50,0) + -0x4000,
183: CONCAT28((short)iVar23 + -0x4000,
184: CONCAT26(SUB142((ZEXT814(CONCAT26((short)(int)
185: (pfVar14[0x23] * pfVar2[0x23] + 16384.5),uVar4))
186: << 0x30) >> 0x60,0) + -0x4000,
187: CONCAT24(SUB122((ZEXT612(uVar4) << 0x30) >> 0x40,0
188: ) + -0x4000,
189: CONCAT22(SUB122((ZEXT612(uVar5) << 0x30)
190: >> 0x40,0) + -0x4000,
191: (short)(int)(pfVar14[0x20] *
192: pfVar2[0x20] +
193: 16384.5) + -0x4000))
194: )))));
195: iVar23 = (int)(fVar6 * pfVar2[0x2c] + 16384.5);
196: iVar3 = (int)(pfVar14[0x29] * pfVar2[0x29] + 16384.5);
197: uVar21 = (undefined2)((uint)iVar3 >> 0x10);
198: iVar22 = (int)(pfVar14[0x2a] * pfVar2[0x2a] + 16384.5);
199: uVar4 = CONCAT24((short)((uint)iVar22 >> 0x10),CONCAT22((short)iVar22,uVar21));
200: uVar5 = CONCAT24((short)(int)(fVar7 * pfVar2[0x2d] + 16384.5),
201: CONCAT22((short)iVar3,(short)((uint)iVar23 >> 0x10)));
202: pauVar1[5] = CONCAT214((short)(int)(fVar9 * pfVar2[0x2f] + 16384.5) + -0x4000,
203: CONCAT212((short)(int)(fVar8 * pfVar2[0x2e] + 16384.5) + -0x4000,
204: CONCAT210(SUB142((ZEXT814(CONCAT26(uVar21,uVar5)) << 0x30) >>
205: 0x50,0) + -0x4000,
206: CONCAT28((short)iVar23 + -0x4000,
207: CONCAT26(SUB142((ZEXT814(CONCAT26((short)(int)
208: (pfVar14[0x2b] * pfVar2[0x2b] + 16384.5),uVar4))
209: << 0x30) >> 0x60,0) + -0x4000,
210: CONCAT24(SUB122((ZEXT612(uVar4) << 0x30) >> 0x40,0
211: ) + -0x4000,
212: CONCAT22(SUB122((ZEXT612(uVar5) << 0x30)
213: >> 0x40,0) + -0x4000,
214: (short)(int)(pfVar14[0x28] *
215: pfVar2[0x28] +
216: 16384.5) + -0x4000))
217: )))));
218: iVar3 = (int)(pfVar14[0x31] * pfVar2[0x31] + 16384.5);
219: uVar21 = (undefined2)((uint)iVar3 >> 0x10);
220: iVar22 = (int)(pfVar14[0x32] * pfVar2[0x32] + 16384.5);
221: uVar4 = CONCAT24((short)((uint)iVar22 >> 0x10),CONCAT22((short)iVar22,uVar21));
222: iVar22 = (int)(pfVar14[0x34] * pfVar2[0x34] + 16384.5);
223: uVar5 = CONCAT24((short)(int)(pfVar14[0x35] * pfVar2[0x35] + 16384.5),
224: CONCAT22((short)iVar3,(short)((uint)iVar22 >> 0x10)));
225: pauVar1[6] = CONCAT214((short)(int)(pfVar14[0x37] * pfVar2[0x37] + 16384.5) + -0x4000,
226: CONCAT212((short)(int)(pfVar14[0x36] * pfVar2[0x36] + 16384.5) + -0x4000,
227: CONCAT210(SUB142((ZEXT814(CONCAT26(uVar21,uVar5)) << 0x30) >>
228: 0x50,0) + -0x4000,
229: CONCAT28((short)iVar22 + -0x4000,
230: CONCAT26(SUB142((ZEXT814(CONCAT26((short)(int)
231: (pfVar14[0x33] * pfVar2[0x33] + 16384.5),uVar4))
232: << 0x30) >> 0x60,0) + -0x4000,
233: CONCAT24(SUB122((ZEXT612(uVar4) << 0x30) >> 0x40,0
234: ) + -0x4000,
235: CONCAT22(SUB122((ZEXT612(uVar5) << 0x30)
236: >> 0x40,0) + -0x4000,
237: (short)(int)(pfVar14[0x30] *
238: pfVar2[0x30] +
239: 16384.5) + -0x4000))
240: )))));
241: if (uVar15 >> 3 == 8) {
242: fVar6 = pfVar14[0x3b];
243: fVar7 = pfVar14[0x3e];
244: fVar8 = pfVar14[0x3f];
245: fVar9 = pfVar2[0x3b];
246: fVar10 = pfVar2[0x3e];
247: fVar11 = pfVar2[0x3f];
248: iVar3 = (int)(pfVar14[0x39] * pfVar2[0x39] + 16384.5);
249: uVar21 = (undefined2)((uint)iVar3 >> 0x10);
250: iVar22 = (int)(pfVar14[0x3a] * pfVar2[0x3a] + 16384.5);
251: uVar4 = CONCAT24((short)((uint)iVar22 >> 0x10),CONCAT22((short)iVar22,uVar21));
252: iVar22 = (int)(pfVar14[0x3c] * pfVar2[0x3c] + 16384.5);
253: uVar5 = CONCAT24((short)(int)(pfVar14[0x3d] * pfVar2[0x3d] + 16384.5),
254: CONCAT22((short)iVar3,(short)((uint)iVar22 >> 0x10)));
255: *(short *)pauVar1[7] = (short)(int)(pfVar14[0x38] * pfVar2[0x38] + 16384.5) + -0x4000;
256: *(short *)(pauVar1[7] + 2) = SUB122((ZEXT612(uVar5) << 0x30) >> 0x40,0) + -0x4000;
257: *(short *)(pauVar1[7] + 4) = SUB122((ZEXT612(uVar4) << 0x30) >> 0x40,0) + -0x4000;
258: *(short *)(pauVar1[7] + 6) =
259: SUB142((ZEXT814(CONCAT26((short)(int)(fVar6 * fVar9 + 16384.5),uVar4)) << 0x30) >> 0x60,0)
260: + -0x4000;
261: *(short *)(pauVar1[7] + 8) = (short)iVar22 + -0x4000;
262: *(short *)(pauVar1[7] + 10) =
263: SUB142((ZEXT814(CONCAT26(uVar21,uVar5)) << 0x30) >> 0x50,0) + -0x4000;
264: *(short *)(pauVar1[7] + 0xc) = (short)(int)(fVar7 * fVar10 + 16384.5) + -0x4000;
265: *(short *)(pauVar1[7] + 0xe) = (short)(int)(fVar8 * fVar11 + 16384.5) + -0x4000;
266: }
267: uVar16 = uVar15 & 0xfffffff8;
268: iVar20 = iVar20 - uVar16;
269: iVar17 = uVar16 + iVar17;
270: if (uVar15 != uVar16) {
271: lVar18 = (long)iVar17;
272: param_1[lVar18] = (short)(int)(param_3[lVar18] * param_2[lVar18] + 16384.5) + -0x4000;
273: if (iVar20 != 1) {
274: lVar18 = (long)(iVar17 + 1);
275: param_1[lVar18] = (short)(int)(param_3[lVar18] * param_2[lVar18] + 16384.5) + -0x4000;
276: if (iVar20 != 2) {
277: lVar18 = (long)(iVar17 + 2);
278: param_1[lVar18] = (short)(int)(param_3[lVar18] * param_2[lVar18] + 16384.5) + -0x4000;
279: if (iVar20 != 3) {
280: lVar18 = (long)(iVar17 + 3);
281: param_1[lVar18] = (short)(int)(param_3[lVar18] * param_2[lVar18] + 16384.5) + -0x4000;
282: if (iVar20 != 4) {
283: lVar18 = (long)(iVar17 + 4);
284: param_1[lVar18] = (short)(int)(param_3[lVar18] * param_2[lVar18] + 16384.5) + -0x4000;
285: if (iVar20 != 5) {
286: lVar18 = (long)(iVar17 + 5);
287: param_1[lVar18] = (short)(int)(param_3[lVar18] * param_2[lVar18] + 16384.5) + -0x4000;
288: if (iVar20 != 6) {
289: lVar18 = (long)(iVar17 + 6);
290: param_1[lVar18] =
291: (short)(int)(param_3[lVar18] * param_2[lVar18] + 16384.5) + -0x4000;
292: }
293: }
294: }
295: }
296: }
297: }
298: }
299: return;
300: }
301: 
