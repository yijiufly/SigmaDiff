1: 
2: int thunk_FUN_00159360(long param_1,uint *param_2,uint param_3,ulong param_4,ushort *param_5,
3: ulong *param_6)
4: 
5: {
6: uint uVar1;
7: uint uVar2;
8: ulong uVar3;
9: uint uVar4;
10: int iVar5;
11: ulong uVar6;
12: int iVar7;
13: int iVar8;
14: uint *puVar9;
15: uint uVar10;
16: undefined (*pauVar11) [16];
17: ushort uVar12;
18: short sVar14;
19: short sVar16;
20: short sVar18;
21: short sVar20;
22: short sVar22;
23: short sVar24;
24: undefined auVar13 [16];
25: ushort uVar15;
26: ushort uVar17;
27: ushort uVar19;
28: ushort uVar21;
29: ushort uVar23;
30: ushort uVar25;
31: ushort uVar26;
32: undefined in_XMM0 [16];
33: ushort uVar27;
34: ushort uVar29;
35: ushort uVar30;
36: ushort uVar31;
37: ushort uVar32;
38: ushort uVar33;
39: ushort uVar34;
40: undefined auVar28 [16];
41: ushort uVar35;
42: undefined in_XMM1 [16];
43: short sVar36;
44: short sVar37;
45: short sVar38;
46: short sVar39;
47: short sVar40;
48: short sVar41;
49: short sVar42;
50: short sVar43;
51: short sVar44;
52: short sVar45;
53: short sVar46;
54: short sVar47;
55: short sVar48;
56: short sVar49;
57: short sVar50;
58: short sVar51;
59: short sVar52;
60: short sVar53;
61: short sVar54;
62: short sVar55;
63: ulong uVar56;
64: undefined auVar57 [16];
65: undefined auVar58 [16];
66: 
67: uVar6 = 0;
68: iVar7 = 0;
69: iVar8 = 0;
70: uVar10 = param_3 & 7;
71: uVar1 = param_3 >> 4;
72: uVar56 = param_4 & 0xffffffff;
73: puVar9 = param_2;
74: uVar3 = param_4;
75: uVar2 = param_3;
76: while (uVar1 != 0) {
77: auVar13 = pinsrw(in_XMM0,*(undefined2 *)(param_1 + (ulong)*puVar9 * 2),0);
78: auVar28 = pinsrw(in_XMM1,*(undefined2 *)(param_1 + (ulong)puVar9[8] * 2),0);
79: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[1] * 2),1);
80: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)puVar9[9] * 2),1);
81: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[2] * 2),2);
82: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)puVar9[10] * 2),2);
83: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[3] * 2),3);
84: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)puVar9[0xb] * 2),3);
85: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[4] * 2),4);
86: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)puVar9[0xc] * 2),4);
87: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[5] * 2),5);
88: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)puVar9[0xd] * 2),5);
89: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[6] * 2),6);
90: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)puVar9[0xe] * 2),6);
91: uVar2 = puVar9[7];
92: uVar4 = puVar9[0xf];
93: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),7);
94: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)uVar4 * 2),7);
95: sVar36 = -(ushort)(SUB162(auVar13,0) < 0);
96: sVar14 = SUB162(auVar13 >> 0x10,0);
97: sVar38 = -(ushort)(sVar14 < 0);
98: sVar16 = SUB162(auVar13 >> 0x20,0);
99: sVar40 = -(ushort)(sVar16 < 0);
100: sVar18 = SUB162(auVar13 >> 0x30,0);
101: sVar42 = -(ushort)(sVar18 < 0);
102: sVar20 = SUB162(auVar13 >> 0x40,0);
103: sVar44 = -(ushort)(sVar20 < 0);
104: sVar22 = SUB162(auVar13 >> 0x50,0);
105: sVar46 = -(ushort)(sVar22 < 0);
106: sVar24 = SUB162(auVar13 >> 0x60,0);
107: sVar48 = -(ushort)(sVar24 < 0);
108: auVar57 = CONCAT214(-(ushort)(auVar13 < (undefined  [16])0x0),
109: CONCAT212(sVar48,CONCAT210(sVar46,CONCAT28(sVar44,CONCAT26(sVar42,CONCAT24(
110: sVar40,CONCAT22(sVar38,sVar36)))))));
111: sVar49 = -(ushort)(SUB162(auVar28,0) < 0);
112: sVar37 = SUB162(auVar28 >> 0x10,0);
113: sVar50 = -(ushort)(sVar37 < 0);
114: sVar39 = SUB162(auVar28 >> 0x20,0);
115: sVar51 = -(ushort)(sVar39 < 0);
116: sVar41 = SUB162(auVar28 >> 0x30,0);
117: sVar52 = -(ushort)(sVar41 < 0);
118: sVar43 = SUB162(auVar28 >> 0x40,0);
119: sVar53 = -(ushort)(sVar43 < 0);
120: sVar45 = SUB162(auVar28 >> 0x50,0);
121: sVar54 = -(ushort)(sVar45 < 0);
122: sVar47 = SUB162(auVar28 >> 0x60,0);
123: sVar55 = -(ushort)(sVar47 < 0);
124: auVar58 = CONCAT214(-(ushort)(auVar28 < (undefined  [16])0x0),
125: CONCAT212(sVar55,CONCAT210(sVar54,CONCAT28(sVar53,CONCAT26(sVar52,CONCAT24(
126: sVar51,CONCAT22(sVar50,sVar49)))))));
127: auVar13 = CONCAT214(SUB162(auVar13 >> 0x70,0) + -(ushort)(auVar13 < (undefined  [16])0x0),
128: CONCAT212(sVar24 + sVar48,
129: CONCAT210(sVar22 + sVar46,
130: CONCAT28(sVar20 + sVar44,
131: CONCAT26(sVar18 + sVar42,
132: CONCAT24(sVar16 + sVar40,
133: CONCAT22(sVar14 + sVar38,
134: SUB162(auVar13,0) +
135: sVar36))))))) ^
136: auVar57;
137: auVar28 = CONCAT214(SUB162(auVar28 >> 0x70,0) + -(ushort)(auVar28 < (undefined  [16])0x0),
138: CONCAT212(sVar47 + sVar55,
139: CONCAT210(sVar45 + sVar54,
140: CONCAT28(sVar43 + sVar53,
141: CONCAT26(sVar41 + sVar52,
142: CONCAT24(sVar39 + sVar51,
143: CONCAT22(sVar37 + sVar50,
144: SUB162(auVar28,0) +
145: sVar49))))))) ^
146: auVar58;
147: uVar12 = SUB162(auVar13,0) >> (param_4 & 0xffffffff);
148: uVar15 = SUB162(auVar13 >> 0x10,0) >> (param_4 & 0xffffffff);
149: uVar3 = param_4 & 0xffffffff;
150: uVar17 = SUB162(auVar13 >> 0x20,0) >> uVar3;
151: uVar19 = SUB162(auVar13 >> 0x30,0) >> uVar3;
152: uVar21 = SUB162(auVar13 >> 0x40,0) >> uVar3;
153: uVar23 = SUB162(auVar13 >> 0x50,0) >> uVar3;
154: uVar3 = param_4 & 0xffffffff;
155: uVar25 = SUB162(auVar13 >> 0x60,0) >> uVar3;
156: uVar26 = SUB162(auVar13 >> 0x70,0) >> uVar3;
157: uVar27 = SUB162(auVar28,0) >> uVar3;
158: uVar29 = SUB162(auVar28 >> 0x10,0) >> uVar3;
159: uVar30 = SUB162(auVar28 >> 0x20,0) >> uVar3;
160: uVar31 = SUB162(auVar28 >> 0x30,0) >> uVar3;
161: uVar32 = SUB162(auVar28 >> 0x40,0) >> uVar3;
162: uVar33 = SUB162(auVar28 >> 0x50,0) >> uVar3;
163: uVar34 = SUB162(auVar28 >> 0x60,0) >> uVar56;
164: uVar35 = SUB162(auVar28 >> 0x70,0) >> uVar56;
165: *param_5 = uVar12;
166: param_5[1] = uVar15;
167: param_5[2] = uVar17;
168: param_5[3] = uVar19;
169: param_5[4] = uVar21;
170: param_5[5] = uVar23;
171: param_5[6] = uVar25;
172: param_5[7] = uVar26;
173: param_5[8] = uVar27;
174: param_5[9] = uVar29;
175: param_5[10] = uVar30;
176: param_5[0xb] = uVar31;
177: param_5[0xc] = uVar32;
178: param_5[0xd] = uVar33;
179: param_5[0xe] = uVar34;
180: param_5[0xf] = uVar35;
181: in_XMM1 = CONCAT214(-(ushort)(uVar35 == 1),
182: CONCAT212(-(ushort)(uVar34 == 1),
183: CONCAT210(-(ushort)(uVar33 == 1),
184: CONCAT28(-(ushort)(uVar32 == 1),
185: CONCAT26(-(ushort)(uVar31 == 1),
186: CONCAT24(-(ushort)(uVar30 == 1),
187: CONCAT22(-(ushort)(uVar29 ==
188: 1),
189: -(ushort)(uVar27 ==
190: 1))))))));
191: auVar13 = packsswb(auVar57,auVar58);
192: in_XMM0 = packsswb(CONCAT214(-(ushort)(uVar26 == 1),
193: CONCAT212(-(ushort)(uVar25 == 1),
194: CONCAT210(-(ushort)(uVar23 == 1),
195: CONCAT28(-(ushort)(uVar21 == 1),
196: CONCAT26(-(ushort)(uVar19 == 1),
197: CONCAT24(-(ushort)(uVar17 ==
198: 1),
199: CONCAT22(-(ushort)(
200: uVar15 == 1),-(ushort)(uVar12 == 1)))))))),in_XMM1
201: );
202: uVar2 = pmovmskb(uVar2,auVar13);
203: uVar4 = pmovmskb(uVar4,in_XMM0);
204: uVar3 = (ulong)uVar2 << 0x30;
205: uVar6 = uVar6 >> 0x10 | uVar3;
206: uVar2 = 0x1f;
207: if (uVar4 != 0) {
208: while (uVar4 >> uVar2 == 0) {
209: uVar2 = uVar2 - 1;
210: }
211: }
212: if (uVar4 != 0) {
213: iVar7 = iVar8 + uVar2;
214: }
215: param_5 = param_5 + 0x10;
216: puVar9 = puVar9 + 0x10;
217: iVar8 = iVar8 + 0x10;
218: uVar1 = uVar1 - 1;
219: }
220: param_4 = param_4 & 0xffffffff;
221: if ((param_3 & 8) == 0) {
222: uVar2 = *puVar9;
223: auVar13 = pinsrw((undefined  [16])0x0,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),0);
224: if (1 < uVar10) {
225: uVar2 = puVar9[1];
226: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),1);
227: if (2 < uVar10) {
228: uVar2 = puVar9[2];
229: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),2);
230: if (3 < uVar10) {
231: uVar2 = puVar9[3];
232: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),3);
233: if (4 < uVar10) {
234: uVar2 = puVar9[4];
235: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),4);
236: if (5 < uVar10) {
237: uVar2 = puVar9[5];
238: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),5);
239: if (6 < uVar10) {
240: uVar2 = puVar9[6];
241: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),6);
242: }
243: }
244: }
245: }
246: }
247: }
248: sVar37 = -(ushort)(SUB162(auVar13,0) < 0);
249: sVar14 = SUB162(auVar13 >> 0x10,0);
250: sVar39 = -(ushort)(sVar14 < 0);
251: sVar16 = SUB162(auVar13 >> 0x20,0);
252: sVar41 = -(ushort)(sVar16 < 0);
253: sVar18 = SUB162(auVar13 >> 0x30,0);
254: sVar43 = -(ushort)(sVar18 < 0);
255: sVar20 = SUB162(auVar13 >> 0x40,0);
256: sVar45 = -(ushort)(sVar20 < 0);
257: sVar22 = SUB162(auVar13 >> 0x50,0);
258: sVar47 = -(ushort)(sVar22 < 0);
259: sVar24 = SUB162(auVar13 >> 0x60,0);
260: sVar36 = -(ushort)(sVar24 < 0);
261: auVar28 = CONCAT214(-(ushort)(auVar13 < (undefined  [16])0x0),
262: CONCAT212(sVar36,CONCAT210(sVar47,CONCAT28(sVar45,CONCAT26(sVar43,CONCAT24(
263: sVar41,CONCAT22(sVar39,sVar37)))))));
264: auVar13 = CONCAT214(SUB162(auVar13 >> 0x70,0) + -(ushort)(auVar13 < (undefined  [16])0x0),
265: CONCAT212(sVar24 + sVar36,
266: CONCAT210(sVar22 + sVar47,
267: CONCAT28(sVar20 + sVar45,
268: CONCAT26(sVar18 + sVar43,
269: CONCAT24(sVar16 + sVar41,
270: CONCAT22(sVar14 + sVar39,
271: SUB162(auVar13,0) +
272: sVar37))))))) ^
273: auVar28;
274: uVar12 = SUB162(auVar13,0) >> uVar56;
275: uVar15 = SUB162(auVar13 >> 0x10,0) >> uVar56;
276: uVar17 = SUB162(auVar13 >> 0x20,0) >> param_4;
277: uVar19 = SUB162(auVar13 >> 0x30,0) >> param_4;
278: uVar21 = SUB162(auVar13 >> 0x40,0) >> param_4;
279: uVar23 = SUB162(auVar13 >> 0x50,0) >> param_4;
280: uVar25 = SUB162(auVar13 >> 0x60,0) >> uVar56;
281: uVar26 = SUB162(auVar13 >> 0x70,0) >> uVar56;
282: *param_5 = uVar12;
283: param_5[1] = uVar15;
284: param_5[2] = uVar17;
285: param_5[3] = uVar19;
286: param_5[4] = uVar21;
287: param_5[5] = uVar23;
288: param_5[6] = uVar25;
289: param_5[7] = uVar26;
290: auVar28 = packsswb(auVar28,(undefined  [16])0x0);
291: auVar13 = packsswb(CONCAT214(-(ushort)(uVar26 == 1),
292: CONCAT212(-(ushort)(uVar25 == 1),
293: CONCAT210(-(ushort)(uVar23 == 1),
294: CONCAT28(-(ushort)(uVar21 == 1),
295: CONCAT26(-(ushort)(uVar19 == 1),
296: CONCAT24(-(ushort)(uVar17 ==
297: 1),
298: CONCAT22(-(ushort)(
299: uVar15 == 1),-(ushort)(uVar12 == 1)))))))),
300: (undefined  [16])0x0);
301: uVar1 = pmovmskb((int)uVar3,auVar28);
302: uVar2 = pmovmskb(uVar2,auVar13);
303: uVar6 = uVar6 >> 8 | (ulong)uVar1 << 0x38;
304: iVar5 = 0x1f;
305: if (uVar2 != 0) {
306: while (uVar2 >> iVar5 == 0) {
307: iVar5 = iVar5 + -1;
308: }
309: }
310: if (uVar2 != 0) {
311: iVar7 = iVar8 + iVar5;
312: }
313: pauVar11 = (undefined (*) [16])(param_5 + 8);
314: }
315: else {
316: if ((param_3 & 7) == 0) {
317: auVar13 = pinsrw(in_XMM0,*(undefined2 *)(param_1 + (ulong)*puVar9 * 2),0);
318: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[1] * 2),1);
319: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[2] * 2),2);
320: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[3] * 2),3);
321: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[4] * 2),4);
322: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[5] * 2),5);
323: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[6] * 2),6);
324: uVar1 = puVar9[7];
325: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar1 * 2),7);
326: sVar37 = -(ushort)(SUB162(auVar13,0) < 0);
327: sVar14 = SUB162(auVar13 >> 0x10,0);
328: sVar39 = -(ushort)(sVar14 < 0);
329: sVar16 = SUB162(auVar13 >> 0x20,0);
330: sVar41 = -(ushort)(sVar16 < 0);
331: sVar18 = SUB162(auVar13 >> 0x30,0);
332: sVar43 = -(ushort)(sVar18 < 0);
333: sVar20 = SUB162(auVar13 >> 0x40,0);
334: sVar45 = -(ushort)(sVar20 < 0);
335: sVar22 = SUB162(auVar13 >> 0x50,0);
336: sVar47 = -(ushort)(sVar22 < 0);
337: sVar24 = SUB162(auVar13 >> 0x60,0);
338: sVar36 = -(ushort)(sVar24 < 0);
339: auVar28 = CONCAT214(-(ushort)(auVar13 < (undefined  [16])0x0),
340: CONCAT212(sVar36,CONCAT210(sVar47,CONCAT28(sVar45,CONCAT26(sVar43,CONCAT24
341: (sVar41,CONCAT22(sVar39,sVar37)))))));
342: auVar13 = CONCAT214(SUB162(auVar13 >> 0x70,0) + -(ushort)(auVar13 < (undefined  [16])0x0),
343: CONCAT212(sVar24 + sVar36,
344: CONCAT210(sVar22 + sVar47,
345: CONCAT28(sVar20 + sVar45,
346: CONCAT26(sVar18 + sVar43,
347: CONCAT24(sVar16 + sVar41,
348: CONCAT22(sVar14 + sVar39,
349: SUB162(auVar13,0)
350: + sVar37))))))) ^
351: auVar28;
352: uVar12 = SUB162(auVar13,0) >> uVar56;
353: uVar15 = SUB162(auVar13 >> 0x10,0) >> uVar56;
354: uVar17 = SUB162(auVar13 >> 0x20,0) >> param_4;
355: uVar19 = SUB162(auVar13 >> 0x30,0) >> param_4;
356: uVar21 = SUB162(auVar13 >> 0x40,0) >> param_4;
357: uVar23 = SUB162(auVar13 >> 0x50,0) >> param_4;
358: uVar25 = SUB162(auVar13 >> 0x60,0) >> uVar56;
359: uVar26 = SUB162(auVar13 >> 0x70,0) >> uVar56;
360: *param_5 = uVar12;
361: param_5[1] = uVar15;
362: param_5[2] = uVar17;
363: param_5[3] = uVar19;
364: param_5[4] = uVar21;
365: param_5[5] = uVar23;
366: param_5[6] = uVar25;
367: param_5[7] = uVar26;
368: auVar28 = packsswb(auVar28,(undefined  [16])0x0);
369: auVar13 = packsswb(CONCAT214(-(ushort)(uVar26 == 1),
370: CONCAT212(-(ushort)(uVar25 == 1),
371: CONCAT210(-(ushort)(uVar23 == 1),
372: CONCAT28(-(ushort)(uVar21 == 1),
373: CONCAT26(-(ushort)(uVar19 == 1),
374: CONCAT24(-(ushort)(uVar17 
375: == 1),CONCAT22(-(ushort)(uVar15 == 1),
376: -(ushort)(uVar12 == 1)))))))),
377: (undefined  [16])0x0);
378: uVar1 = pmovmskb(uVar1,auVar28);
379: uVar2 = pmovmskb(uVar2,auVar13);
380: uVar6 = uVar6 >> 8 | (ulong)uVar1 << 0x38;
381: iVar5 = 0x1f;
382: if (uVar2 != 0) {
383: while (uVar2 >> iVar5 == 0) {
384: iVar5 = iVar5 + -1;
385: }
386: }
387: if (uVar2 != 0) {
388: iVar7 = iVar8 + iVar5;
389: }
390: pauVar11 = (undefined (*) [16])(param_5 + 8);
391: }
392: else {
393: uVar2 = puVar9[8];
394: auVar13 = pinsrw(in_XMM0,*(undefined2 *)(param_1 + (ulong)*puVar9 * 2),0);
395: auVar28 = pinsrw((undefined  [16])0x0,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),0);
396: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[1] * 2),1);
397: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[2] * 2),2);
398: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[3] * 2),3);
399: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[4] * 2),4);
400: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[5] * 2),5);
401: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)puVar9[6] * 2),6);
402: uVar1 = puVar9[7];
403: auVar13 = pinsrw(auVar13,*(undefined2 *)(param_1 + (ulong)uVar1 * 2),7);
404: if (1 < uVar10) {
405: uVar2 = puVar9[9];
406: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),1);
407: if (2 < uVar10) {
408: uVar2 = puVar9[10];
409: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),2);
410: if (3 < uVar10) {
411: uVar2 = puVar9[0xb];
412: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),3);
413: if (4 < uVar10) {
414: uVar2 = puVar9[0xc];
415: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),4);
416: if (5 < uVar10) {
417: uVar2 = puVar9[0xd];
418: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),5);
419: if (6 < uVar10) {
420: uVar2 = puVar9[0xe];
421: auVar28 = pinsrw(auVar28,*(undefined2 *)(param_1 + (ulong)uVar2 * 2),6);
422: }
423: }
424: }
425: }
426: }
427: }
428: sVar36 = -(ushort)(SUB162(auVar13,0) < 0);
429: sVar14 = SUB162(auVar13 >> 0x10,0);
430: sVar38 = -(ushort)(sVar14 < 0);
431: sVar16 = SUB162(auVar13 >> 0x20,0);
432: sVar40 = -(ushort)(sVar16 < 0);
433: sVar18 = SUB162(auVar13 >> 0x30,0);
434: sVar42 = -(ushort)(sVar18 < 0);
435: sVar20 = SUB162(auVar13 >> 0x40,0);
436: sVar44 = -(ushort)(sVar20 < 0);
437: sVar22 = SUB162(auVar13 >> 0x50,0);
438: sVar46 = -(ushort)(sVar22 < 0);
439: sVar24 = SUB162(auVar13 >> 0x60,0);
440: sVar48 = -(ushort)(sVar24 < 0);
441: auVar57 = CONCAT214(-(ushort)(auVar13 < (undefined  [16])0x0),
442: CONCAT212(sVar48,CONCAT210(sVar46,CONCAT28(sVar44,CONCAT26(sVar42,CONCAT24
443: (sVar40,CONCAT22(sVar38,sVar36)))))));
444: sVar49 = -(ushort)(SUB162(auVar28,0) < 0);
445: sVar37 = SUB162(auVar28 >> 0x10,0);
446: sVar50 = -(ushort)(sVar37 < 0);
447: sVar39 = SUB162(auVar28 >> 0x20,0);
448: sVar51 = -(ushort)(sVar39 < 0);
449: sVar41 = SUB162(auVar28 >> 0x30,0);
450: sVar52 = -(ushort)(sVar41 < 0);
451: sVar43 = SUB162(auVar28 >> 0x40,0);
452: sVar53 = -(ushort)(sVar43 < 0);
453: sVar45 = SUB162(auVar28 >> 0x50,0);
454: sVar54 = -(ushort)(sVar45 < 0);
455: sVar47 = SUB162(auVar28 >> 0x60,0);
456: sVar55 = -(ushort)(sVar47 < 0);
457: auVar58 = CONCAT214(-(ushort)(auVar28 < (undefined  [16])0x0),
458: CONCAT212(sVar55,CONCAT210(sVar54,CONCAT28(sVar53,CONCAT26(sVar52,CONCAT24
459: (sVar51,CONCAT22(sVar50,sVar49)))))));
460: auVar13 = CONCAT214(SUB162(auVar13 >> 0x70,0) + -(ushort)(auVar13 < (undefined  [16])0x0),
461: CONCAT212(sVar24 + sVar48,
462: CONCAT210(sVar22 + sVar46,
463: CONCAT28(sVar20 + sVar44,
464: CONCAT26(sVar18 + sVar42,
465: CONCAT24(sVar16 + sVar40,
466: CONCAT22(sVar14 + sVar38,
467: SUB162(auVar13,0)
468: + sVar36))))))) ^
469: auVar57;
470: auVar28 = CONCAT214(SUB162(auVar28 >> 0x70,0) + -(ushort)(auVar28 < (undefined  [16])0x0),
471: CONCAT212(sVar47 + sVar55,
472: CONCAT210(sVar45 + sVar54,
473: CONCAT28(sVar43 + sVar53,
474: CONCAT26(sVar41 + sVar52,
475: CONCAT24(sVar39 + sVar51,
476: CONCAT22(sVar37 + sVar50,
477: SUB162(auVar28,0)
478: + sVar49))))))) ^
479: auVar58;
480: uVar12 = SUB162(auVar13,0) >> uVar56;
481: uVar15 = SUB162(auVar13 >> 0x10,0) >> uVar56;
482: uVar17 = SUB162(auVar13 >> 0x20,0) >> uVar56;
483: uVar19 = SUB162(auVar13 >> 0x30,0) >> uVar56;
484: uVar21 = SUB162(auVar13 >> 0x40,0) >> uVar56;
485: uVar23 = SUB162(auVar13 >> 0x50,0) >> uVar56;
486: uVar25 = SUB162(auVar13 >> 0x60,0) >> uVar56;
487: uVar26 = SUB162(auVar13 >> 0x70,0) >> uVar56;
488: uVar27 = SUB162(auVar28,0) >> uVar56;
489: uVar29 = SUB162(auVar28 >> 0x10,0) >> uVar56;
490: uVar30 = SUB162(auVar28 >> 0x20,0) >> uVar56;
491: uVar31 = SUB162(auVar28 >> 0x30,0) >> uVar56;
492: uVar32 = SUB162(auVar28 >> 0x40,0) >> uVar56;
493: uVar33 = SUB162(auVar28 >> 0x50,0) >> uVar56;
494: uVar34 = SUB162(auVar28 >> 0x60,0) >> uVar56;
495: uVar35 = SUB162(auVar28 >> 0x70,0) >> uVar56;
496: *param_5 = uVar12;
497: param_5[1] = uVar15;
498: param_5[2] = uVar17;
499: param_5[3] = uVar19;
500: param_5[4] = uVar21;
501: param_5[5] = uVar23;
502: param_5[6] = uVar25;
503: param_5[7] = uVar26;
504: param_5[8] = uVar27;
505: param_5[9] = uVar29;
506: param_5[10] = uVar30;
507: param_5[0xb] = uVar31;
508: param_5[0xc] = uVar32;
509: param_5[0xd] = uVar33;
510: param_5[0xe] = uVar34;
511: param_5[0xf] = uVar35;
512: auVar28 = packsswb(auVar57,auVar58);
513: auVar13 = packsswb(CONCAT214(-(ushort)(uVar26 == 1),
514: CONCAT212(-(ushort)(uVar25 == 1),
515: CONCAT210(-(ushort)(uVar23 == 1),
516: CONCAT28(-(ushort)(uVar21 == 1),
517: CONCAT26(-(ushort)(uVar19 == 1),
518: CONCAT24(-(ushort)(uVar17 
519: == 1),CONCAT22(-(ushort)(uVar15 == 1),
520: -(ushort)(uVar12 == 1)))))))),
521: CONCAT214(-(ushort)(uVar35 == 1),
522: CONCAT212(-(ushort)(uVar34 == 1),
523: CONCAT210(-(ushort)(uVar33 == 1),
524: CONCAT28(-(ushort)(uVar32 == 1),
525: CONCAT26(-(ushort)(uVar31 == 1),
526: CONCAT24(-(ushort)(uVar30 
527: == 1),CONCAT22(-(ushort)(uVar29 == 1),
528: -(ushort)(uVar27 == 1)))))))));
529: uVar1 = pmovmskb(uVar1,auVar28);
530: uVar2 = pmovmskb(uVar2,auVar13);
531: uVar6 = uVar6 >> 0x10 | (ulong)uVar1 << 0x30;
532: iVar5 = 0x1f;
533: if (uVar2 != 0) {
534: while (uVar2 >> iVar5 == 0) {
535: iVar5 = iVar5 + -1;
536: }
537: }
538: if (uVar2 != 0) {
539: iVar7 = iVar8 + iVar5;
540: }
541: pauVar11 = (undefined (*) [16])(param_5 + 0x10);
542: }
543: }
544: iVar8 = (param_3 + 7 >> 3) - 8;
545: while (iVar8 != 0) {
546: *pauVar11 = (undefined  [16])0x0;
547: uVar6 = uVar6 >> 8;
548: pauVar11 = pauVar11[1];
549: iVar8 = iVar8 + 1;
550: }
551: param_6[1] = ~uVar6;
552: auVar13 = packsswb(CONCAT214(-(ushort)(*(short *)(pauVar11[-8] + 0xe) == 0),
553: CONCAT212(-(ushort)(*(short *)(pauVar11[-8] + 0xc) == 0),
554: CONCAT210(-(ushort)(*(short *)(pauVar11[-8] + 10) == 0),
555: CONCAT28(-(ushort)(*(short *)(pauVar11[-8] + 8)
556: == 0),
557: CONCAT26(-(ushort)(*(short *)(pauVar11[
558: -8] + 6) == 0),
559: CONCAT24(-(ushort)(*(short *)(pauVar11[-8] + 4) ==
560: 0),
561: CONCAT22(-(ushort)(*(short *)(pauVar11[-8
562: ] + 2) == 0),
563: -(ushort)(*(short *)pauVar11[-8] == 0)))))))),
564: CONCAT214(-(ushort)(*(short *)(pauVar11[-7] + 0xe) == 0),
565: CONCAT212(-(ushort)(*(short *)(pauVar11[-7] + 0xc) == 0),
566: CONCAT210(-(ushort)(*(short *)(pauVar11[-7] + 10) == 0),
567: CONCAT28(-(ushort)(*(short *)(pauVar11[-7] + 8)
568: == 0),
569: CONCAT26(-(ushort)(*(short *)(pauVar11[
570: -7] + 6) == 0),
571: CONCAT24(-(ushort)(*(short *)(pauVar11[-7] + 4) ==
572: 0),
573: CONCAT22(-(ushort)(*(short *)(pauVar11[-7
574: ] + 2) == 0),
575: -(ushort)(*(short *)pauVar11[-7] == 0)))))))));
576: auVar28 = packsswb(CONCAT214(-(ushort)(*(short *)(pauVar11[-6] + 0xe) == 0),
577: CONCAT212(-(ushort)(*(short *)(pauVar11[-6] + 0xc) == 0),
578: CONCAT210(-(ushort)(*(short *)(pauVar11[-6] + 10) == 0),
579: CONCAT28(-(ushort)(*(short *)(pauVar11[-6] + 8)
580: == 0),
581: CONCAT26(-(ushort)(*(short *)(pauVar11[
582: -6] + 6) == 0),
583: CONCAT24(-(ushort)(*(short *)(pauVar11[-6] + 4) ==
584: 0),
585: CONCAT22(-(ushort)(*(short *)(pauVar11[-6
586: ] + 2) == 0),
587: -(ushort)(*(short *)pauVar11[-6] == 0)))))))),
588: CONCAT214(-(ushort)(*(short *)(pauVar11[-5] + 0xe) == 0),
589: CONCAT212(-(ushort)(*(short *)(pauVar11[-5] + 0xc) == 0),
590: CONCAT210(-(ushort)(*(short *)(pauVar11[-5] + 10) == 0),
591: CONCAT28(-(ushort)(*(short *)(pauVar11[-5] + 8)
592: == 0),
593: CONCAT26(-(ushort)(*(short *)(pauVar11[
594: -5] + 6) == 0),
595: CONCAT24(-(ushort)(*(short *)(pauVar11[-5] + 4) ==
596: 0),
597: CONCAT22(-(ushort)(*(short *)(pauVar11[-5
598: ] + 2) == 0),
599: -(ushort)(*(short *)pauVar11[-5] == 0)))))))));
600: auVar57 = packsswb(CONCAT214(-(ushort)(*(short *)(pauVar11[-4] + 0xe) == 0),
601: CONCAT212(-(ushort)(*(short *)(pauVar11[-4] + 0xc) == 0),
602: CONCAT210(-(ushort)(*(short *)(pauVar11[-4] + 10) == 0),
603: CONCAT28(-(ushort)(*(short *)(pauVar11[-4] + 8)
604: == 0),
605: CONCAT26(-(ushort)(*(short *)(pauVar11[
606: -4] + 6) == 0),
607: CONCAT24(-(ushort)(*(short *)(pauVar11[-4] + 4) ==
608: 0),
609: CONCAT22(-(ushort)(*(short *)(pauVar11[-4
610: ] + 2) == 0),
611: -(ushort)(*(short *)pauVar11[-4] == 0)))))))),
612: CONCAT214(-(ushort)(*(short *)(pauVar11[-3] + 0xe) == 0),
613: CONCAT212(-(ushort)(*(short *)(pauVar11[-3] + 0xc) == 0),
614: CONCAT210(-(ushort)(*(short *)(pauVar11[-3] + 10) == 0),
615: CONCAT28(-(ushort)(*(short *)(pauVar11[-3] + 8)
616: == 0),
617: CONCAT26(-(ushort)(*(short *)(pauVar11[
618: -3] + 6) == 0),
619: CONCAT24(-(ushort)(*(short *)(pauVar11[-3] + 4) ==
620: 0),
621: CONCAT22(-(ushort)(*(short *)(pauVar11[-3
622: ] + 2) == 0),
623: -(ushort)(*(short *)pauVar11[-3] == 0)))))))));
624: auVar58 = packsswb(CONCAT214(-(ushort)(*(short *)(pauVar11[-2] + 0xe) == 0),
625: CONCAT212(-(ushort)(*(short *)(pauVar11[-2] + 0xc) == 0),
626: CONCAT210(-(ushort)(*(short *)(pauVar11[-2] + 10) == 0),
627: CONCAT28(-(ushort)(*(short *)(pauVar11[-2] + 8)
628: == 0),
629: CONCAT26(-(ushort)(*(short *)(pauVar11[
630: -2] + 6) == 0),
631: CONCAT24(-(ushort)(*(short *)(pauVar11[-2] + 4) ==
632: 0),
633: CONCAT22(-(ushort)(*(short *)(pauVar11[-2
634: ] + 2) == 0),
635: -(ushort)(*(short *)pauVar11[-2] == 0)))))))),
636: CONCAT214(-(ushort)(*(short *)(pauVar11[-1] + 0xe) == 0),
637: CONCAT212(-(ushort)(*(short *)(pauVar11[-1] + 0xc) == 0),
638: CONCAT210(-(ushort)(*(short *)(pauVar11[-1] + 10) == 0),
639: CONCAT28(-(ushort)(*(short *)(pauVar11[-1] + 8)
640: == 0),
641: CONCAT26(-(ushort)(*(short *)(pauVar11[
642: -1] + 6) == 0),
643: CONCAT24(-(ushort)(*(short *)(pauVar11[-1] + 4) ==
644: 0),
645: CONCAT22(-(ushort)(*(short *)(pauVar11[-1
646: ] + 2) == 0),
647: -(ushort)(*(short *)pauVar11[-1] == 0)))))))));
648: uVar2 = pmovmskb(0,auVar13);
649: uVar1 = pmovmskb(0,auVar28);
650: uVar10 = pmovmskb(iVar5,auVar57);
651: uVar4 = pmovmskb((int)param_2,auVar58);
652: *param_6 = ~((ulong)uVar2 | (ulong)uVar1 << 0x10 | (ulong)uVar10 << 0x20 | (ulong)uVar4 << 0x30);
653: return iVar7;
654: }
655: 
