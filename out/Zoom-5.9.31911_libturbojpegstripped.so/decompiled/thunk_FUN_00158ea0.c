1: 
2: void thunk_FUN_00158ea0(long param_1,uint *param_2,uint param_3,ulong param_4,
3: undefined (*param_5) [16],ulong *param_6)
4: 
5: {
6: uint uVar1;
7: int iVar2;
8: ulong uVar3;
9: uint uVar4;
10: uint uVar5;
11: uint *puVar6;
12: uint uVar7;
13: ushort uVar8;
14: short sVar10;
15: short sVar12;
16: short sVar14;
17: short sVar16;
18: short sVar18;
19: short sVar20;
20: undefined auVar9 [16];
21: ushort uVar11;
22: ushort uVar13;
23: ushort uVar15;
24: ushort uVar17;
25: ushort uVar19;
26: ushort uVar21;
27: ushort uVar22;
28: undefined in_XMM0 [16];
29: ushort uVar23;
30: short sVar25;
31: short sVar27;
32: short sVar29;
33: short sVar31;
34: short sVar33;
35: short sVar35;
36: undefined auVar24 [16];
37: ushort uVar26;
38: ushort uVar28;
39: ushort uVar30;
40: ushort uVar32;
41: ushort uVar34;
42: ushort uVar36;
43: ushort uVar37;
44: undefined in_XMM1 [16];
45: short sVar38;
46: ushort uVar39;
47: short sVar40;
48: ushort uVar41;
49: short sVar42;
50: ushort uVar43;
51: short sVar44;
52: ushort uVar45;
53: short sVar46;
54: ushort uVar47;
55: short sVar48;
56: ushort uVar49;
57: short sVar50;
58: ushort uVar51;
59: ushort uVar52;
60: short sVar53;
61: ushort uVar54;
62: short sVar55;
63: ushort uVar56;
64: short sVar57;
65: ushort uVar58;
66: short sVar59;
67: ushort uVar60;
68: short sVar61;
69: ushort uVar62;
70: short sVar63;
71: ushort uVar64;
72: short sVar65;
73: ushort uVar66;
74: ushort uVar67;
75: ulong uVar68;
76: ulong uVar69;
77: undefined auVar71 [16];
78: undefined auVar72 [16];
79: ulong uVar70;
80: 
81: uVar7 = param_3 & 7;
82: uVar1 = param_3 >> 4;
83: uVar68 = param_4 & 0xffffffff;
84: uVar3 = param_4;
85: puVar6 = param_2;
86: uVar4 = param_3;
87: if (uVar1 != 0) {
88: do {
89: auVar9 = pinsrw(in_XMM0,*(undefined2 *)(param_1 + (ulong)*puVar6 * 2),0);
90: auVar24 = pinsrw(in_XMM1,*(undefined2 *)(param_1 + (ulong)puVar6[8] * 2),0);
91: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[1] * 2),1);
92: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)puVar6[9] * 2),1);
93: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[2] * 2),2);
94: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)puVar6[10] * 2),2);
95: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[3] * 2),3);
96: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)puVar6[0xb] * 2),3);
97: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[4] * 2),4);
98: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)puVar6[0xc] * 2),4);
99: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[5] * 2),5);
100: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)puVar6[0xd] * 2),5);
101: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[6] * 2),6);
102: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)puVar6[0xe] * 2),6);
103: uVar3 = (ulong)puVar6[7];
104: uVar4 = puVar6[0xf];
105: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + uVar3 * 2),7);
106: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),7);
107: sVar38 = -(ushort)(SUB162(auVar9,0) < 0);
108: sVar10 = SUB162(auVar9 >> 0x10,0);
109: sVar40 = -(ushort)(sVar10 < 0);
110: sVar12 = SUB162(auVar9 >> 0x20,0);
111: sVar42 = -(ushort)(sVar12 < 0);
112: sVar14 = SUB162(auVar9 >> 0x30,0);
113: sVar44 = -(ushort)(sVar14 < 0);
114: sVar16 = SUB162(auVar9 >> 0x40,0);
115: sVar46 = -(ushort)(sVar16 < 0);
116: sVar18 = SUB162(auVar9 >> 0x50,0);
117: sVar48 = -(ushort)(sVar18 < 0);
118: sVar20 = SUB162(auVar9 >> 0x60,0);
119: sVar50 = -(ushort)(sVar20 < 0);
120: auVar71 = CONCAT214(-(ushort)(auVar9 < (undefined  [16])0x0),
121: CONCAT212(sVar50,CONCAT210(sVar48,CONCAT28(sVar46,CONCAT26(sVar44,CONCAT24
122: (sVar42,CONCAT22(sVar40,sVar38)))))));
123: sVar53 = -(ushort)(SUB162(auVar24,0) < 0);
124: sVar25 = SUB162(auVar24 >> 0x10,0);
125: sVar55 = -(ushort)(sVar25 < 0);
126: sVar27 = SUB162(auVar24 >> 0x20,0);
127: sVar57 = -(ushort)(sVar27 < 0);
128: sVar29 = SUB162(auVar24 >> 0x30,0);
129: sVar59 = -(ushort)(sVar29 < 0);
130: sVar31 = SUB162(auVar24 >> 0x40,0);
131: sVar61 = -(ushort)(sVar31 < 0);
132: sVar33 = SUB162(auVar24 >> 0x50,0);
133: sVar63 = -(ushort)(sVar33 < 0);
134: sVar35 = SUB162(auVar24 >> 0x60,0);
135: sVar65 = -(ushort)(sVar35 < 0);
136: auVar72 = CONCAT214(-(ushort)(auVar24 < (undefined  [16])0x0),
137: CONCAT212(sVar65,CONCAT210(sVar63,CONCAT28(sVar61,CONCAT26(sVar59,CONCAT24
138: (sVar57,CONCAT22(sVar55,sVar53)))))));
139: auVar9 = CONCAT214(SUB162(auVar9 >> 0x70,0) + -(ushort)(auVar9 < (undefined  [16])0x0),
140: CONCAT212(sVar20 + sVar50,
141: CONCAT210(sVar18 + sVar48,
142: CONCAT28(sVar16 + sVar46,
143: CONCAT26(sVar14 + sVar44,
144: CONCAT24(sVar12 + sVar42,
145: CONCAT22(sVar10 + sVar40,
146: SUB162(auVar9,0) +
147: sVar38))))))) ^
148: auVar71;
149: auVar24 = CONCAT214(SUB162(auVar24 >> 0x70,0) + -(ushort)(auVar24 < (undefined  [16])0x0),
150: CONCAT212(sVar35 + sVar65,
151: CONCAT210(sVar33 + sVar63,
152: CONCAT28(sVar31 + sVar61,
153: CONCAT26(sVar29 + sVar59,
154: CONCAT24(sVar27 + sVar57,
155: CONCAT22(sVar25 + sVar55,
156: SUB162(auVar24,0)
157: + sVar53))))))) ^
158: auVar72;
159: uVar69 = param_4 & 0xffffffff;
160: uVar70 = param_4 & 0xffffffff;
161: in_XMM0 = CONCAT214(SUB162(auVar9 >> 0x70,0) >> uVar70,
162: CONCAT212(SUB162(auVar9 >> 0x60,0) >> uVar70,
163: CONCAT210(SUB162(auVar9 >> 0x50,0) >> uVar69,
164: CONCAT28(SUB162(auVar9 >> 0x40,0) >> uVar69,
165: CONCAT26(SUB162(auVar9 >> 0x30,0) >> uVar69,
166: CONCAT24(SUB162(auVar9 >> 0x20,0) >>
167: uVar69,CONCAT22(SUB162(
168: auVar9 >> 0x10,0) >> (param_4 & 0xffffffff),
169: SUB162(auVar9,0) >> (param_4 & 0xffffffff))))))));
170: in_XMM1 = CONCAT214(SUB162(auVar24 >> 0x70,0) >> uVar68,
171: CONCAT212(SUB162(auVar24 >> 0x60,0) >> uVar68,
172: CONCAT210(SUB162(auVar24 >> 0x50,0) >> uVar70,
173: CONCAT28(SUB162(auVar24 >> 0x40,0) >> uVar70,
174: CONCAT26(SUB162(auVar24 >> 0x30,0) >> uVar70,
175: CONCAT24(SUB162(auVar24 >> 0x20,0)
176: >> uVar70,
177: CONCAT22(SUB162(auVar24 >>
178: 0x10,0) >>
179: uVar70,SUB162(
180: auVar24,0) >> uVar70)))))));
181: *param_5 = in_XMM0;
182: param_5[1] = in_XMM1;
183: param_5[8] = auVar71 ^ in_XMM0;
184: param_5[9] = auVar72 ^ in_XMM1;
185: param_5 = param_5[2];
186: puVar6 = puVar6 + 0x10;
187: uVar1 = uVar1 - 1;
188: } while (uVar1 != 0);
189: if ((param_3 & 0xf) == 0) goto LAB_00159274;
190: }
191: param_4 = param_4 & 0xffffffff;
192: if ((param_3 & 8) == 0) {
193: uVar4 = *puVar6;
194: auVar9 = pinsrw((undefined  [16])0x0,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),0);
195: if (1 < uVar7) {
196: uVar4 = puVar6[1];
197: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),1);
198: if (2 < uVar7) {
199: uVar4 = puVar6[2];
200: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),2);
201: if (3 < uVar7) {
202: uVar4 = puVar6[3];
203: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),3);
204: if (4 < uVar7) {
205: uVar4 = puVar6[4];
206: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),4);
207: if (5 < uVar7) {
208: uVar4 = puVar6[5];
209: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),5);
210: if (6 < uVar7) {
211: uVar4 = puVar6[6];
212: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),6);
213: }
214: }
215: }
216: }
217: }
218: }
219: uVar23 = -(ushort)(SUB162(auVar9,0) < 0);
220: sVar10 = SUB162(auVar9 >> 0x10,0);
221: uVar26 = -(ushort)(sVar10 < 0);
222: sVar12 = SUB162(auVar9 >> 0x20,0);
223: uVar28 = -(ushort)(sVar12 < 0);
224: sVar14 = SUB162(auVar9 >> 0x30,0);
225: uVar30 = -(ushort)(sVar14 < 0);
226: sVar16 = SUB162(auVar9 >> 0x40,0);
227: uVar32 = -(ushort)(sVar16 < 0);
228: sVar18 = SUB162(auVar9 >> 0x50,0);
229: uVar34 = -(ushort)(sVar18 < 0);
230: sVar20 = SUB162(auVar9 >> 0x60,0);
231: uVar36 = -(ushort)(sVar20 < 0);
232: uVar37 = -(ushort)(auVar9 < (undefined  [16])0x0);
233: uVar8 = (ushort)(SUB162(auVar9,0) + uVar23 ^ uVar23) >> uVar68;
234: uVar11 = (ushort)(sVar10 + uVar26 ^ uVar26) >> uVar68;
235: uVar13 = (ushort)(sVar12 + uVar28 ^ uVar28) >> param_4;
236: uVar15 = (ushort)(sVar14 + uVar30 ^ uVar30) >> param_4;
237: uVar17 = (ushort)(sVar16 + uVar32 ^ uVar32) >> param_4;
238: uVar19 = (ushort)(sVar18 + uVar34 ^ uVar34) >> param_4;
239: uVar21 = (ushort)(sVar20 + uVar36 ^ uVar36) >> uVar68;
240: uVar22 = (ushort)(SUB162(auVar9 >> 0x70,0) + uVar37 ^ uVar37) >> uVar68;
241: *(ushort *)*param_5 = uVar8;
242: *(ushort *)(*param_5 + 2) = uVar11;
243: *(ushort *)(*param_5 + 4) = uVar13;
244: *(ushort *)(*param_5 + 6) = uVar15;
245: *(ushort *)(*param_5 + 8) = uVar17;
246: *(ushort *)(*param_5 + 10) = uVar19;
247: *(ushort *)(*param_5 + 0xc) = uVar21;
248: *(ushort *)(*param_5 + 0xe) = uVar22;
249: *(ushort *)param_5[8] = uVar23 ^ uVar8;
250: *(ushort *)(param_5[8] + 2) = uVar26 ^ uVar11;
251: *(ushort *)(param_5[8] + 4) = uVar28 ^ uVar13;
252: *(ushort *)(param_5[8] + 6) = uVar30 ^ uVar15;
253: *(ushort *)(param_5[8] + 8) = uVar32 ^ uVar17;
254: *(ushort *)(param_5[8] + 10) = uVar34 ^ uVar19;
255: *(ushort *)(param_5[8] + 0xc) = uVar36 ^ uVar21;
256: *(ushort *)(param_5[8] + 0xe) = uVar37 ^ uVar22;
257: param_5 = param_5[1];
258: }
259: else {
260: if ((param_3 & 7) == 0) {
261: auVar9 = pinsrw(in_XMM0,*(undefined2 *)(param_1 + (ulong)*puVar6 * 2),0);
262: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[1] * 2),1);
263: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[2] * 2),2);
264: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[3] * 2),3);
265: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[4] * 2),4);
266: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[5] * 2),5);
267: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[6] * 2),6);
268: uVar3 = (ulong)puVar6[7];
269: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + uVar3 * 2),7);
270: uVar23 = -(ushort)(SUB162(auVar9,0) < 0);
271: sVar10 = SUB162(auVar9 >> 0x10,0);
272: uVar26 = -(ushort)(sVar10 < 0);
273: sVar12 = SUB162(auVar9 >> 0x20,0);
274: uVar28 = -(ushort)(sVar12 < 0);
275: sVar14 = SUB162(auVar9 >> 0x30,0);
276: uVar30 = -(ushort)(sVar14 < 0);
277: sVar16 = SUB162(auVar9 >> 0x40,0);
278: uVar32 = -(ushort)(sVar16 < 0);
279: sVar18 = SUB162(auVar9 >> 0x50,0);
280: uVar34 = -(ushort)(sVar18 < 0);
281: sVar20 = SUB162(auVar9 >> 0x60,0);
282: uVar36 = -(ushort)(sVar20 < 0);
283: uVar37 = -(ushort)(auVar9 < (undefined  [16])0x0);
284: uVar8 = (ushort)(SUB162(auVar9,0) + uVar23 ^ uVar23) >> uVar68;
285: uVar11 = (ushort)(sVar10 + uVar26 ^ uVar26) >> uVar68;
286: uVar13 = (ushort)(sVar12 + uVar28 ^ uVar28) >> param_4;
287: uVar15 = (ushort)(sVar14 + uVar30 ^ uVar30) >> param_4;
288: uVar17 = (ushort)(sVar16 + uVar32 ^ uVar32) >> param_4;
289: uVar19 = (ushort)(sVar18 + uVar34 ^ uVar34) >> param_4;
290: uVar21 = (ushort)(sVar20 + uVar36 ^ uVar36) >> uVar68;
291: uVar22 = (ushort)(SUB162(auVar9 >> 0x70,0) + uVar37 ^ uVar37) >> uVar68;
292: *(ushort *)*param_5 = uVar8;
293: *(ushort *)(*param_5 + 2) = uVar11;
294: *(ushort *)(*param_5 + 4) = uVar13;
295: *(ushort *)(*param_5 + 6) = uVar15;
296: *(ushort *)(*param_5 + 8) = uVar17;
297: *(ushort *)(*param_5 + 10) = uVar19;
298: *(ushort *)(*param_5 + 0xc) = uVar21;
299: *(ushort *)(*param_5 + 0xe) = uVar22;
300: *(ushort *)param_5[8] = uVar23 ^ uVar8;
301: *(ushort *)(param_5[8] + 2) = uVar26 ^ uVar11;
302: *(ushort *)(param_5[8] + 4) = uVar28 ^ uVar13;
303: *(ushort *)(param_5[8] + 6) = uVar30 ^ uVar15;
304: *(ushort *)(param_5[8] + 8) = uVar32 ^ uVar17;
305: *(ushort *)(param_5[8] + 10) = uVar34 ^ uVar19;
306: *(ushort *)(param_5[8] + 0xc) = uVar36 ^ uVar21;
307: *(ushort *)(param_5[8] + 0xe) = uVar37 ^ uVar22;
308: param_5 = param_5[1];
309: }
310: else {
311: uVar4 = puVar6[8];
312: auVar9 = pinsrw(in_XMM0,*(undefined2 *)(param_1 + (ulong)*puVar6 * 2),0);
313: auVar24 = pinsrw((undefined  [16])0x0,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),0);
314: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[1] * 2),1);
315: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[2] * 2),2);
316: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[3] * 2),3);
317: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[4] * 2),4);
318: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[5] * 2),5);
319: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + (ulong)puVar6[6] * 2),6);
320: uVar3 = (ulong)puVar6[7];
321: auVar9 = pinsrw(auVar9,*(undefined2 *)(param_1 + uVar3 * 2),7);
322: if (1 < uVar7) {
323: uVar4 = puVar6[9];
324: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),1);
325: if (2 < uVar7) {
326: uVar4 = puVar6[10];
327: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),2);
328: if (3 < uVar7) {
329: uVar4 = puVar6[0xb];
330: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),3);
331: if (4 < uVar7) {
332: uVar4 = puVar6[0xc];
333: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),4);
334: if (5 < uVar7) {
335: uVar4 = puVar6[0xd];
336: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),5);
337: if (6 < uVar7) {
338: uVar4 = puVar6[0xe];
339: auVar24 = pinsrw(auVar24,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),6);
340: }
341: }
342: }
343: }
344: }
345: }
346: uVar39 = -(ushort)(SUB162(auVar9,0) < 0);
347: sVar10 = SUB162(auVar9 >> 0x10,0);
348: uVar41 = -(ushort)(sVar10 < 0);
349: sVar12 = SUB162(auVar9 >> 0x20,0);
350: uVar43 = -(ushort)(sVar12 < 0);
351: sVar14 = SUB162(auVar9 >> 0x30,0);
352: uVar45 = -(ushort)(sVar14 < 0);
353: sVar16 = SUB162(auVar9 >> 0x40,0);
354: uVar47 = -(ushort)(sVar16 < 0);
355: sVar18 = SUB162(auVar9 >> 0x50,0);
356: uVar49 = -(ushort)(sVar18 < 0);
357: sVar20 = SUB162(auVar9 >> 0x60,0);
358: uVar51 = -(ushort)(sVar20 < 0);
359: uVar52 = -(ushort)(auVar9 < (undefined  [16])0x0);
360: uVar54 = -(ushort)(SUB162(auVar24,0) < 0);
361: sVar25 = SUB162(auVar24 >> 0x10,0);
362: uVar56 = -(ushort)(sVar25 < 0);
363: sVar27 = SUB162(auVar24 >> 0x20,0);
364: uVar58 = -(ushort)(sVar27 < 0);
365: sVar29 = SUB162(auVar24 >> 0x30,0);
366: uVar60 = -(ushort)(sVar29 < 0);
367: sVar31 = SUB162(auVar24 >> 0x40,0);
368: uVar62 = -(ushort)(sVar31 < 0);
369: sVar33 = SUB162(auVar24 >> 0x50,0);
370: uVar64 = -(ushort)(sVar33 < 0);
371: sVar35 = SUB162(auVar24 >> 0x60,0);
372: uVar66 = -(ushort)(sVar35 < 0);
373: uVar67 = -(ushort)(auVar24 < (undefined  [16])0x0);
374: uVar8 = (ushort)(SUB162(auVar9,0) + uVar39 ^ uVar39) >> uVar68;
375: uVar11 = (ushort)(sVar10 + uVar41 ^ uVar41) >> uVar68;
376: uVar13 = (ushort)(sVar12 + uVar43 ^ uVar43) >> uVar68;
377: uVar15 = (ushort)(sVar14 + uVar45 ^ uVar45) >> uVar68;
378: uVar17 = (ushort)(sVar16 + uVar47 ^ uVar47) >> uVar68;
379: uVar19 = (ushort)(sVar18 + uVar49 ^ uVar49) >> uVar68;
380: uVar21 = (ushort)(sVar20 + uVar51 ^ uVar51) >> uVar68;
381: uVar22 = (ushort)(SUB162(auVar9 >> 0x70,0) + uVar52 ^ uVar52) >> uVar68;
382: uVar23 = (ushort)(SUB162(auVar24,0) + uVar54 ^ uVar54) >> uVar68;
383: uVar26 = (ushort)(sVar25 + uVar56 ^ uVar56) >> uVar68;
384: uVar28 = (ushort)(sVar27 + uVar58 ^ uVar58) >> uVar68;
385: uVar30 = (ushort)(sVar29 + uVar60 ^ uVar60) >> uVar68;
386: uVar32 = (ushort)(sVar31 + uVar62 ^ uVar62) >> uVar68;
387: uVar34 = (ushort)(sVar33 + uVar64 ^ uVar64) >> uVar68;
388: uVar36 = (ushort)(sVar35 + uVar66 ^ uVar66) >> uVar68;
389: uVar37 = (ushort)(SUB162(auVar24 >> 0x70,0) + uVar67 ^ uVar67) >> uVar68;
390: *(ushort *)*param_5 = uVar8;
391: *(ushort *)(*param_5 + 2) = uVar11;
392: *(ushort *)(*param_5 + 4) = uVar13;
393: *(ushort *)(*param_5 + 6) = uVar15;
394: *(ushort *)(*param_5 + 8) = uVar17;
395: *(ushort *)(*param_5 + 10) = uVar19;
396: *(ushort *)(*param_5 + 0xc) = uVar21;
397: *(ushort *)(*param_5 + 0xe) = uVar22;
398: *(ushort *)param_5[1] = uVar23;
399: *(ushort *)(param_5[1] + 2) = uVar26;
400: *(ushort *)(param_5[1] + 4) = uVar28;
401: *(ushort *)(param_5[1] + 6) = uVar30;
402: *(ushort *)(param_5[1] + 8) = uVar32;
403: *(ushort *)(param_5[1] + 10) = uVar34;
404: *(ushort *)(param_5[1] + 0xc) = uVar36;
405: *(ushort *)(param_5[1] + 0xe) = uVar37;
406: *(ushort *)param_5[8] = uVar39 ^ uVar8;
407: *(ushort *)(param_5[8] + 2) = uVar41 ^ uVar11;
408: *(ushort *)(param_5[8] + 4) = uVar43 ^ uVar13;
409: *(ushort *)(param_5[8] + 6) = uVar45 ^ uVar15;
410: *(ushort *)(param_5[8] + 8) = uVar47 ^ uVar17;
411: *(ushort *)(param_5[8] + 10) = uVar49 ^ uVar19;
412: *(ushort *)(param_5[8] + 0xc) = uVar51 ^ uVar21;
413: *(ushort *)(param_5[8] + 0xe) = uVar52 ^ uVar22;
414: *(ushort *)param_5[9] = uVar54 ^ uVar23;
415: *(ushort *)(param_5[9] + 2) = uVar56 ^ uVar26;
416: *(ushort *)(param_5[9] + 4) = uVar58 ^ uVar28;
417: *(ushort *)(param_5[9] + 6) = uVar60 ^ uVar30;
418: *(ushort *)(param_5[9] + 8) = uVar62 ^ uVar32;
419: *(ushort *)(param_5[9] + 10) = uVar64 ^ uVar34;
420: *(ushort *)(param_5[9] + 0xc) = uVar66 ^ uVar36;
421: *(ushort *)(param_5[9] + 0xe) = uVar67 ^ uVar37;
422: param_5 = param_5[2];
423: }
424: }
425: LAB_00159274:
426: iVar2 = (param_3 + 7 >> 3) - 8;
427: while (iVar2 != 0) {
428: *param_5 = (undefined  [16])0x0;
429: param_5 = param_5[1];
430: iVar2 = iVar2 + 1;
431: }
432: auVar9 = packsswb(CONCAT214(-(ushort)(*(short *)(param_5[-8] + 0xe) == 0),
433: CONCAT212(-(ushort)(*(short *)(param_5[-8] + 0xc) == 0),
434: CONCAT210(-(ushort)(*(short *)(param_5[-8] + 10) == 0),
435: CONCAT28(-(ushort)(*(short *)(param_5[-8] + 8) ==
436: 0),
437: CONCAT26(-(ushort)(*(short *)(param_5[-8]
438: + 6) == 0),
439: CONCAT24(-(ushort)(*(short *)(
440: param_5[-8] + 4) == 0),
441: CONCAT22(-(ushort)(*(short *)(param_5[-8] + 2) ==
442: 0),
443: -(ushort)(*(short *)param_5[-8] == 0)))))
444: ))),
445: CONCAT214(-(ushort)(*(short *)(param_5[-7] + 0xe) == 0),
446: CONCAT212(-(ushort)(*(short *)(param_5[-7] + 0xc) == 0),
447: CONCAT210(-(ushort)(*(short *)(param_5[-7] + 10) == 0),
448: CONCAT28(-(ushort)(*(short *)(param_5[-7] + 8) ==
449: 0),
450: CONCAT26(-(ushort)(*(short *)(param_5[-7]
451: + 6) == 0),
452: CONCAT24(-(ushort)(*(short *)(
453: param_5[-7] + 4) == 0),
454: CONCAT22(-(ushort)(*(short *)(param_5[-7] + 2) ==
455: 0),
456: -(ushort)(*(short *)param_5[-7] == 0)))))
457: ))));
458: auVar24 = packsswb(CONCAT214(-(ushort)(*(short *)(param_5[-6] + 0xe) == 0),
459: CONCAT212(-(ushort)(*(short *)(param_5[-6] + 0xc) == 0),
460: CONCAT210(-(ushort)(*(short *)(param_5[-6] + 10) == 0),
461: CONCAT28(-(ushort)(*(short *)(param_5[-6] + 8) ==
462: 0),
463: CONCAT26(-(ushort)(*(short *)(param_5[-6
464: ] + 6) == 0),
465: CONCAT24(-(ushort)(*(short *)(param_5[-6] + 4) ==
466: 0),
467: CONCAT22(-(ushort)(*(short *)(param_5[-6]
468: + 2) == 0),
469: -(ushort)(*(short *)param_5[-6]
470: == 0)))))))),
471: CONCAT214(-(ushort)(*(short *)(param_5[-5] + 0xe) == 0),
472: CONCAT212(-(ushort)(*(short *)(param_5[-5] + 0xc) == 0),
473: CONCAT210(-(ushort)(*(short *)(param_5[-5] + 10) == 0),
474: CONCAT28(-(ushort)(*(short *)(param_5[-5] + 8) ==
475: 0),
476: CONCAT26(-(ushort)(*(short *)(param_5[-5
477: ] + 6) == 0),
478: CONCAT24(-(ushort)(*(short *)(param_5[-5] + 4) ==
479: 0),
480: CONCAT22(-(ushort)(*(short *)(param_5[-5]
481: + 2) == 0),
482: -(ushort)(*(short *)param_5[-5]
483: == 0)))))))));
484: auVar71 = packsswb(CONCAT214(-(ushort)(*(short *)(param_5[-4] + 0xe) == 0),
485: CONCAT212(-(ushort)(*(short *)(param_5[-4] + 0xc) == 0),
486: CONCAT210(-(ushort)(*(short *)(param_5[-4] + 10) == 0),
487: CONCAT28(-(ushort)(*(short *)(param_5[-4] + 8) ==
488: 0),
489: CONCAT26(-(ushort)(*(short *)(param_5[-4
490: ] + 6) == 0),
491: CONCAT24(-(ushort)(*(short *)(param_5[-4] + 4) ==
492: 0),
493: CONCAT22(-(ushort)(*(short *)(param_5[-4]
494: + 2) == 0),
495: -(ushort)(*(short *)param_5[-4]
496: == 0)))))))),
497: CONCAT214(-(ushort)(*(short *)(param_5[-3] + 0xe) == 0),
498: CONCAT212(-(ushort)(*(short *)(param_5[-3] + 0xc) == 0),
499: CONCAT210(-(ushort)(*(short *)(param_5[-3] + 10) == 0),
500: CONCAT28(-(ushort)(*(short *)(param_5[-3] + 8) ==
501: 0),
502: CONCAT26(-(ushort)(*(short *)(param_5[-3
503: ] + 6) == 0),
504: CONCAT24(-(ushort)(*(short *)(param_5[-3] + 4) ==
505: 0),
506: CONCAT22(-(ushort)(*(short *)(param_5[-3]
507: + 2) == 0),
508: -(ushort)(*(short *)param_5[-3]
509: == 0)))))))));
510: auVar72 = packsswb(CONCAT214(-(ushort)(*(short *)(param_5[-2] + 0xe) == 0),
511: CONCAT212(-(ushort)(*(short *)(param_5[-2] + 0xc) == 0),
512: CONCAT210(-(ushort)(*(short *)(param_5[-2] + 10) == 0),
513: CONCAT28(-(ushort)(*(short *)(param_5[-2] + 8) ==
514: 0),
515: CONCAT26(-(ushort)(*(short *)(param_5[-2
516: ] + 6) == 0),
517: CONCAT24(-(ushort)(*(short *)(param_5[-2] + 4) ==
518: 0),
519: CONCAT22(-(ushort)(*(short *)(param_5[-2]
520: + 2) == 0),
521: -(ushort)(*(short *)param_5[-2]
522: == 0)))))))),
523: CONCAT214(-(ushort)(*(short *)(param_5[-1] + 0xe) == 0),
524: CONCAT212(-(ushort)(*(short *)(param_5[-1] + 0xc) == 0),
525: CONCAT210(-(ushort)(*(short *)(param_5[-1] + 10) == 0),
526: CONCAT28(-(ushort)(*(short *)(param_5[-1] + 8) ==
527: 0),
528: CONCAT26(-(ushort)(*(short *)(param_5[-1
529: ] + 6) == 0),
530: CONCAT24(-(ushort)(*(short *)(param_5[-1] + 4) ==
531: 0),
532: CONCAT22(-(ushort)(*(short *)(param_5[-1]
533: + 2) == 0),
534: -(ushort)(*(short *)param_5[-1]
535: == 0)))))))));
536: uVar1 = pmovmskb(0,auVar9);
537: uVar7 = pmovmskb((int)uVar3,auVar24);
538: uVar4 = pmovmskb(uVar4,auVar71);
539: uVar5 = pmovmskb((int)param_2,auVar72);
540: *param_6 = ~((ulong)uVar1 | (uVar3 & 0xffffffff00000000 | (ulong)uVar7) << 0x10 |
541: (ulong)uVar4 << 0x20 | (ulong)uVar5 << 0x30);
542: return;
543: }
544: 
