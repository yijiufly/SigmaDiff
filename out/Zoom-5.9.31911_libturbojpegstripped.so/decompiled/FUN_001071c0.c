1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_001071c0(code **param_1)
5: 
6: {
7: code *pcVar1;
8: code *pcVar2;
9: code **ppcVar3;
10: ulong uVar4;
11: ulong uVar5;
12: undefined2 uVar6;
13: undefined2 uVar7;
14: undefined2 uVar8;
15: undefined2 uVar9;
16: unkbyte10 Var10;
17: short sVar11;
18: uint uVar12;
19: uint uVar13;
20: uint uVar14;
21: ulong uVar15;
22: undefined (*pauVar16) [16];
23: long lVar17;
24: int iVar18;
25: undefined (*pauVar19) [16];
26: ushort uVar20;
27: ulong uVar21;
28: int iVar22;
29: int iVar23;
30: code *pcVar24;
31: long lVar25;
32: undefined2 uVar27;
33: undefined2 uVar28;
34: undefined2 uVar29;
35: undefined2 uVar30;
36: undefined2 uVar31;
37: undefined2 uVar32;
38: undefined2 uVar33;
39: undefined2 uVar34;
40: undefined2 uVar35;
41: undefined2 uVar36;
42: undefined2 uVar37;
43: undefined2 uVar38;
44: undefined2 uVar39;
45: undefined auVar26 [16];
46: undefined2 uVar40;
47: undefined2 uVar41;
48: undefined8 uVar42;
49: undefined2 uVar43;
50: undefined2 uVar44;
51: undefined2 uVar45;
52: undefined2 uVar46;
53: uint6 uVar47;
54: undefined4 uVar48;
55: undefined2 uVar51;
56: undefined2 uVar52;
57: undefined2 uVar53;
58: undefined2 uVar54;
59: undefined auVar49 [12];
60: undefined auVar50 [16];
61: uint6 uVar55;
62: undefined2 uVar56;
63: ushort uVar57;
64: undefined2 uVar59;
65: ushort uVar60;
66: undefined2 uVar61;
67: undefined8 uVar58;
68: undefined2 uVar84;
69: float fVar85;
70: undefined2 uVar88;
71: undefined2 uVar89;
72: undefined2 uVar90;
73: undefined auVar62 [16];
74: undefined auVar63 [16];
75: undefined auVar64 [16];
76: undefined auVar65 [16];
77: float fVar86;
78: undefined auVar66 [16];
79: undefined auVar67 [16];
80: undefined auVar68 [16];
81: undefined auVar69 [16];
82: undefined auVar70 [16];
83: undefined auVar71 [16];
84: undefined auVar72 [16];
85: undefined auVar73 [16];
86: undefined auVar74 [16];
87: undefined auVar75 [16];
88: undefined auVar76 [16];
89: undefined auVar77 [16];
90: undefined auVar78 [16];
91: undefined auVar79 [16];
92: undefined auVar80 [16];
93: unkuint10 Var87;
94: undefined auVar81 [16];
95: undefined auVar82 [16];
96: undefined auVar83 [16];
97: double dVar91;
98: float fVar92;
99: ushort uVar93;
100: ushort uVar94;
101: undefined2 uVar95;
102: undefined2 uVar96;
103: undefined2 uVar97;
104: undefined2 uVar98;
105: float fVar99;
106: ushort uVar100;
107: ushort uVar102;
108: undefined8 uVar101;
109: undefined auVar103 [16];
110: undefined auVar104 [16];
111: float fVar108;
112: undefined auVar105 [16];
113: undefined auVar106 [16];
114: undefined auVar107 [16];
115: undefined auVar109 [16];
116: undefined2 uVar112;
117: uint6 uVar110;
118: ushort uVar113;
119: undefined2 uVar114;
120: undefined2 uVar115;
121: ushort uVar116;
122: undefined2 uVar118;
123: uint6 uVar117;
124: undefined2 uVar119;
125: undefined2 uVar120;
126: ushort uVar121;
127: ushort uVar122;
128: undefined auVar123 [16];
129: undefined auVar124 [16];
130: undefined8 uVar111;
131: 
132: iVar23 = 0;
133: pcVar1 = param_1[0x3d];
134: pcVar24 = param_1[0xb];
135: if (0 < *(int *)((long)param_1 + 0x4c)) {
136: do {
137: while( true ) {
138: uVar12 = *(uint *)(pcVar24 + 0x10);
139: lVar25 = (long)(int)uVar12;
140: if ((3 < uVar12) ||
141: (pauVar19 = (undefined (*) [16])param_1[lVar25 + 0xc],
142: pauVar19 == (undefined (*) [16])0x0)) break;
143: iVar22 = *(int *)((long)param_1 + 0x114);
144: if (iVar22 != 1) goto LAB_00107217;
145: LAB_00107d0b:
146: lVar17 = *(long *)(pcVar1 + lVar25 * 8 + 0x28);
147: if (lVar17 == 0) {
148: lVar17 = (**(code **)param_1[1])(param_1,1,0x200);
149: *(long *)(pcVar1 + lVar25 * 8 + 0x28) = lVar17;
150: }
151: lVar25 = 0;
152: do {
153: uVar21 = (long)((ulong)*(ushort *)(*pauVar19 + lVar25) *
154: (long)*(short *)(&DAT_00168e20 + lVar25) + 0x400) >> 0xb;
155: uVar20 = (ushort)uVar21;
156: if (uVar20 == 1) {
157: *(undefined2 *)(lVar17 + lVar25) = 1;
158: *(undefined2 *)(lVar17 + 0x80 + lVar25) = 0;
159: *(undefined2 *)(lVar17 + 0x100 + lVar25) = 1;
160: *(undefined2 *)(lVar17 + 0x180 + lVar25) = 0xfff0;
161: LAB_00108007:
162: if (*(code **)(pcVar1 + 0x20) == FUN_00168770) {
163: *(code **)(pcVar1 + 0x20) = FUN_00106b10;
164: }
165: }
166: else {
167: if (uVar20 == 0) {
168: uVar12 = 0x8000;
169: iVar22 = 0xf;
170: }
171: else {
172: uVar15 = uVar21 & 0xffffffff;
173: if ((uVar21 & 0xff00) == 0) {
174: uVar15 = (ulong)(uint)((int)uVar15 << 8);
175: iVar18 = 4;
176: iVar22 = 8;
177: }
178: else {
179: iVar18 = 0xc;
180: iVar22 = 0x10;
181: }
182: if ((uVar15 & 0xf000) == 0) {
183: uVar15 = (ulong)(uint)((int)uVar15 << 4);
184: iVar22 = iVar18;
185: }
186: sVar11 = (short)uVar15;
187: if ((uVar15 & 0xc000) == 0) {
188: iVar22 = iVar22 + -2;
189: sVar11 = (short)((int)uVar15 << 2);
190: }
191: if (sVar11 < 0) {
192: iVar22 = iVar22 + 0xf;
193: uVar12 = 1 << ((byte)iVar22 & 0x1f);
194: }
195: else {
196: iVar22 = iVar22 + 0xe;
197: uVar12 = 1 << ((byte)iVar22 & 0x1f);
198: }
199: }
200: uVar20 = uVar20 >> 1;
201: uVar13 = (uint)((ulong)uVar12 / (uVar21 & 0xffff));
202: uVar12 = (uint)((ulong)uVar12 % (uVar21 & 0xffff));
203: if (uVar12 == 0) {
204: uVar13 = uVar13 >> 1;
205: iVar22 = iVar22 + -1;
206: }
207: else {
208: if (uVar20 < uVar12) {
209: uVar13 = uVar13 + 1;
210: }
211: else {
212: uVar20 = uVar20 + 1;
213: }
214: }
215: *(short *)(lVar17 + lVar25) = (short)uVar13;
216: *(ushort *)(lVar17 + 0x80 + lVar25) = uVar20;
217: *(short *)(lVar17 + 0x100 + lVar25) = (short)(1 << (-(char)iVar22 & 0x1fU));
218: *(short *)(lVar17 + 0x180 + lVar25) = (short)iVar22 + -0x10;
219: if (iVar22 < 0x11) goto LAB_00108007;
220: }
221: lVar25 = lVar25 + 2;
222: } while (lVar25 != 0x80);
223: LAB_00107cbb:
224: iVar23 = iVar23 + 1;
225: pcVar24 = pcVar24 + 0x60;
226: if (*(int *)((long)param_1 + 0x4c) == iVar23 || *(int *)((long)param_1 + 0x4c) < iVar23) {
227: return;
228: }
229: }
230: pcVar2 = *param_1;
231: *(uint *)(pcVar2 + 0x2c) = uVar12;
232: ppcVar3 = (code **)*param_1;
233: *(undefined4 *)(pcVar2 + 0x28) = 0x34;
234: (**ppcVar3)(param_1);
235: iVar22 = *(int *)((long)param_1 + 0x114);
236: pauVar19 = (undefined (*) [16])param_1[lVar25 + 0xc];
237: if (iVar22 == 1) goto LAB_00107d0b;
238: LAB_00107217:
239: if (iVar22 == 0) {
240: lVar17 = *(long *)(pcVar1 + lVar25 * 8 + 0x28);
241: if (lVar17 == 0) {
242: lVar17 = (**(code **)param_1[1])(param_1,1,0x200);
243: *(long *)(pcVar1 + lVar25 * 8 + 0x28) = lVar17;
244: }
245: lVar25 = 0;
246: do {
247: uVar12 = (uint)*(ushort *)(*pauVar19 + lVar25) * 8;
248: if ((ushort)uVar12 == 0) {
249: uVar13 = 0x8000;
250: iVar22 = 0xf;
251: }
252: else {
253: if ((uVar12 & 0xff00) == 0) {
254: uVar21 = (ulong)*(ushort *)(*pauVar19 + lVar25) << 0xb;
255: iVar18 = 4;
256: iVar22 = 8;
257: }
258: else {
259: uVar21 = (ulong)uVar12;
260: iVar18 = 0xc;
261: iVar22 = 0x10;
262: }
263: if ((uVar21 & 0xf000) == 0) {
264: uVar21 = (ulong)(uint)((int)uVar21 << 4);
265: iVar22 = iVar18;
266: }
267: sVar11 = (short)uVar21;
268: if ((uVar21 & 0xc000) == 0) {
269: iVar22 = iVar22 + -2;
270: sVar11 = (short)((int)uVar21 << 2);
271: }
272: if (sVar11 < 0) {
273: iVar22 = iVar22 + 0xf;
274: uVar13 = 1 << ((byte)iVar22 & 0x1f);
275: }
276: else {
277: iVar22 = iVar22 + 0xe;
278: uVar13 = 1 << ((byte)iVar22 & 0x1f);
279: }
280: }
281: uVar20 = (ushort)uVar12 >> 1;
282: uVar14 = uVar13 / (uVar12 & 0xffff);
283: uVar13 = uVar13 % (uVar12 & 0xffff);
284: if (uVar13 == 0) {
285: uVar14 = uVar14 >> 1;
286: iVar22 = iVar22 + -1;
287: }
288: else {
289: if (uVar20 < uVar13) {
290: uVar14 = uVar14 + 1;
291: }
292: else {
293: uVar20 = uVar20 + 1;
294: }
295: }
296: *(short *)(lVar17 + lVar25) = (short)uVar14;
297: *(ushort *)(lVar17 + 0x80 + lVar25) = uVar20;
298: *(short *)(lVar17 + 0x100 + lVar25) = (short)(1 << (-(char)iVar22 & 0x1fU));
299: *(short *)(lVar17 + 0x180 + lVar25) = (short)iVar22 + -0x10;
300: if ((iVar22 < 0x11) && (*(code **)(pcVar1 + 0x20) == FUN_00168770)) {
301: *(code **)(pcVar1 + 0x20) = FUN_00106b10;
302: }
303: lVar25 = lVar25 + 2;
304: } while (lVar25 != 0x80);
305: goto LAB_00107cbb;
306: }
307: if (iVar22 == 2) {
308: pauVar16 = *(undefined (**) [16])(pcVar1 + lVar25 * 8 + 0x68);
309: if (pauVar16 == (undefined (*) [16])0x0) {
310: pauVar16 = (undefined (*) [16])(**(code **)param_1[1])(param_1,1,0x100);
311: *(undefined (**) [16])(pcVar1 + lVar25 * 8 + 0x68) = pauVar16;
312: }
313: if ((pauVar19 < pauVar16[0x10]) && (pauVar16 < pauVar19[8])) {
314: lVar25 = 0;
315: do {
316: dVar91 = *(double *)(&DAT_00168de0 + lVar25);
317: lVar25 = lVar25 + 8;
318: uVar20 = *(ushort *)(*pauVar19 + 2);
319: *(float *)*pauVar16 = (float)(1.0 / ((double)(uint)*(ushort *)*pauVar19 * dVar91 * 8.0))
320: ;
321: uVar57 = *(ushort *)(*pauVar19 + 4);
322: *(float *)(*pauVar16 + 4) =
323: (float)(1.0 / ((double)(uint)uVar20 * dVar91 * 1.387039845 * 8.0));
324: uVar20 = *(ushort *)(*pauVar19 + 6);
325: *(float *)(*pauVar16 + 8) =
326: (float)(1.0 / ((double)(uint)uVar57 * dVar91 * 1.306562965 * 8.0));
327: uVar57 = *(ushort *)(*pauVar19 + 8);
328: *(float *)(*pauVar16 + 0xc) =
329: (float)(1.0 / ((double)(uint)uVar20 * dVar91 * 1.175875602 * 8.0));
330: uVar20 = *(ushort *)(*pauVar19 + 10);
331: *(float *)pauVar16[1] = (float)(1.0 / ((double)(uint)uVar57 * dVar91 * 8.0));
332: uVar57 = *(ushort *)(*pauVar19 + 0xc);
333: *(float *)(pauVar16[1] + 4) =
334: (float)(1.0 / ((double)(uint)uVar20 * dVar91 * 0.785694958 * 8.0));
335: uVar20 = *(ushort *)(*pauVar19 + 0xe);
336: *(float *)(pauVar16[1] + 8) =
337: (float)(1.0 / ((double)(uint)uVar57 * dVar91 * 0.5411961 * 8.0));
338: *(float *)(pauVar16[1] + 0xc) =
339: (float)(1.0 / ((double)(uint)uVar20 * dVar91 * 0.275899379 * 8.0));
340: pauVar16 = pauVar16[2];
341: pauVar19 = pauVar19[1];
342: } while (lVar25 != 0x40);
343: }
344: else {
345: auVar26 = *pauVar19;
346: uVar28 = *(undefined2 *)pauVar19[1];
347: uVar30 = *(undefined2 *)(pauVar19[1] + 2);
348: uVar27 = *(undefined2 *)(pauVar19[1] + 4);
349: uVar29 = *(undefined2 *)(pauVar19[1] + 8);
350: uVar43 = *(undefined2 *)(pauVar19[1] + 0xc);
351: uVar6 = *(undefined2 *)(pauVar19[1] + 0xe);
352: auVar50 = pauVar19[2];
353: uVar119 = SUB162(auVar26 >> 0x30,0);
354: uVar118 = SUB162(auVar26 >> 0x20,0);
355: uVar110 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar19[1] + 6),
356: CONCAT212(uVar119,SUB1612(auVar26,0))) >> 0x60
357: ,0),CONCAT210(uVar27,SUB1610(auVar26,0))) >> 0x50,0);
358: auVar62 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar110,CONCAT28(uVar118,SUB168(auVar26,0)))
359: >> 0x40,0),uVar30)) << 0x30 &
360: (undefined  [16])0xffffffff00000000;
361: uVar31 = SUB162(auVar26 >> 0x40,0);
362: uVar34 = SUB162(auVar26 >> 0x50,0);
363: uVar37 = SUB162(auVar26 >> 0x70,0);
364: uVar44 = *(undefined2 *)pauVar19[3];
365: uVar35 = *(undefined2 *)(pauVar19[3] + 2);
366: uVar84 = *(undefined2 *)(pauVar19[3] + 4);
367: uVar96 = *(undefined2 *)(pauVar19[3] + 6);
368: uVar7 = *(undefined2 *)(pauVar19[3] + 8);
369: uVar112 = SUB162(auVar26 >> 0x10,0);
370: auVar76 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*
371: (undefined2 *)(pauVar19[1] + 6),
372: CONCAT212(uVar119,SUB1612(auVar26,0))) >> 0x60,0),
373: CONCAT210(uVar27,SUB1610(auVar26,0))) >> 0x50,0),
374: CONCAT28(uVar118,SUB168(auVar26,0))) >> 0x40,0),
375: uVar30),uVar112)) << 0x20;
376: auVar74 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
377: undefined2 *)(pauVar19[1] + 10),
378: CONCAT212(uVar30,SUB1612(auVar62,0))) >> 0x60,0),
379: CONCAT210(uVar34,SUB1610(auVar62,0))) >> 0x50,0),
380: CONCAT28(uVar112,SUB168(auVar62,0))) >> 0x40,0),
381: uVar29)) << 0x30 & (undefined  [16])0xffffffff00000000;
382: auVar62 = pauVar19[4];
383: uVar41 = SUB162(auVar50 >> 0x30,0);
384: uVar40 = SUB162(auVar50 >> 0x20,0);
385: uVar12 = SUB164(auVar50,0) & 0xffff;
386: auVar63 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar96,
387: CONCAT212(uVar41,SUB1612(auVar50,0))) >> 0x60,0),
388: CONCAT210(uVar84,SUB1610(auVar50,0))) >> 0x50,0),
389: CONCAT28(uVar40,SUB168(auVar50,0))) >> 0x40,0),
390: uVar35)) << 0x30 & (undefined  [16])0xffffffff00000000;
391: auVar68 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
392: undefined2 *)(pauVar19[1] + 10),
393: CONCAT212(SUB162(auVar76 >> 0x30,0),
394: SUB1612(auVar76,0))) >> 0x60,0),
395: CONCAT210(uVar34,SUB1610(auVar76,0))) >> 0x50,0),
396: CONCAT28(uVar112,SUB168(auVar76,0))) >> 0x40,0),
397: uVar29)) << 0x30;
398: uVar39 = SUB162(auVar50 >> 0x10,0);
399: auVar64 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
400: uVar96,CONCAT212(uVar41,SUB1612(auVar50,0))) >>
401: 0x60,0),CONCAT210(uVar84,SUB1610(auVar50,0))) >>
402: 0x50,0),CONCAT28(uVar40,SUB168(auVar50,0))) >>
403: 0x40,0),uVar35),uVar39)) << 0x20;
404: uVar32 = SUB162(auVar50 >> 0x40,0);
405: uVar33 = SUB162(auVar50 >> 0x50,0);
406: uVar36 = SUB162(auVar50 >> 0x60,0);
407: uVar38 = SUB162(auVar50 >> 0x70,0);
408: uVar30 = *(undefined2 *)pauVar19[5];
409: uVar34 = *(undefined2 *)(pauVar19[5] + 2);
410: uVar112 = *(undefined2 *)(pauVar19[5] + 4);
411: uVar8 = *(undefined2 *)(pauVar19[5] + 8);
412: uVar9 = *(undefined2 *)(pauVar19[5] + 0xc);
413: uVar111 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar43,CONCAT212(uVar29,
414: SUB1612(auVar74,0))) >> 0x60,0),
415: CONCAT210(uVar27,SUB1610(auVar74,0))) >> 0x50,0),
416: CONCAT28(uVar28,SUB168(auVar74,0))) >> 0x40,0);
417: uVar21 = (ulong)CONCAT24(uVar27,CONCAT22(SUB162(auVar26 >> 0x60,0),uVar118)) & 0xffff0000;
418: auVar65 = CONCAT88(uVar111,(uVar21 >> 0x10) << 0x30) & (undefined  [16])0xffff000000000000
419: ;
420: uVar114 = SUB162((auVar68 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
421: uVar115 = SUB162(auVar68 >> 0x60,0);
422: uVar46 = SUB162(auVar62 >> 0x30,0);
423: uVar45 = SUB162(auVar62 >> 0x20,0);
424: uVar47 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar19[5] + 6),
425: CONCAT212(uVar46,SUB1612(auVar62,0))) >> 0x60,0
426: ),CONCAT210(uVar112,SUB1610(auVar62,0))) >> 0x50,0);
427: uVar13 = SUB164(auVar62,0) & 0xffff;
428: auVar76 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar47,CONCAT28(uVar45,SUB168(auVar62,0))) >>
429: 0x40,0),uVar34)) << 0x30 &
430: (undefined  [16])0xffffffff00000000;
431: auVar50 = pauVar19[6];
432: auVar63 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
433: undefined2 *)(pauVar19[3] + 10),
434: CONCAT212(uVar35,SUB1612(auVar63,0))) >> 0x60,0),
435: CONCAT210(uVar33,SUB1610(auVar63,0))) >> 0x50,0),
436: CONCAT28(uVar39,SUB168(auVar63,0))) >> 0x40,0),
437: uVar7)) << 0x30 & (undefined  [16])0xffffffff00000000;
438: auVar64 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
439: undefined2 *)(pauVar19[3] + 10),
440: CONCAT212(SUB162(auVar64 >> 0x30,0),
441: SUB1612(auVar64,0))) >> 0x60,0),
442: CONCAT210(uVar33,SUB1610(auVar64,0))) >> 0x50,0),
443: CONCAT28(uVar39,SUB168(auVar64,0))) >> 0x40,0),
444: uVar7)) << 0x30;
445: uVar51 = SUB162(auVar62 >> 0x10,0);
446: auVar74 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*
447: (undefined2 *)(pauVar19[5] + 6),
448: CONCAT212(uVar46,SUB1612(auVar62,0))) >> 0x60,0),
449: CONCAT210(uVar112,SUB1610(auVar62,0))) >> 0x50,0),
450: CONCAT28(uVar45,SUB168(auVar62,0))) >> 0x40,0),
451: uVar34),uVar51)) << 0x20;
452: uVar42 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)
453: (pauVar19[3] + 0xc),
454: CONCAT212(uVar7,SUB1612(
455: auVar63,0))) >> 0x60,0),
456: CONCAT210(uVar84,SUB1610(auVar63,0))) >> 0x50,0),
457: CONCAT28(uVar44,SUB168(auVar63,0))) >> 0x40,0);
458: uVar33 = SUB162(auVar62 >> 0x40,0);
459: uVar35 = SUB162(auVar62 >> 0x50,0);
460: uVar39 = SUB162(auVar62 >> 0x70,0);
461: uVar88 = SUB162((auVar64 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
462: uVar89 = SUB162((auVar64 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
463: uVar90 = SUB162(auVar64 >> 0x70,0);
464: uVar56 = SUB162(auVar50 >> 0x40,0);
465: uVar59 = SUB162(auVar50 >> 0x60,0);
466: uVar61 = SUB162(auVar50 >> 0x70,0);
467: auVar63 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
468: undefined2 *)(pauVar19[5] + 10),
469: CONCAT212(uVar34,SUB1612(auVar76,0))) >> 0x60,0),
470: CONCAT210(uVar35,SUB1610(auVar76,0))) >> 0x50,0),
471: CONCAT28(uVar51,SUB168(auVar76,0))) >> 0x40,0),
472: uVar8)) << 0x30 & (undefined  [16])0xffffffff00000000;
473: auVar74 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
474: undefined2 *)(pauVar19[5] + 10),
475: CONCAT212(SUB162(auVar74 >> 0x30,0),
476: SUB1612(auVar74,0))) >> 0x60,0),
477: CONCAT210(uVar35,SUB1610(auVar74,0))) >> 0x50,0),
478: CONCAT28(uVar51,SUB168(auVar74,0))) >> 0x40,0),
479: uVar8)) << 0x30;
480: uVar52 = SUB162(auVar50 >> 0x30,0);
481: uVar51 = SUB162(auVar50 >> 0x20,0);
482: uVar34 = SUB162(auVar50 >> 0x10,0);
483: auVar76 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*
484: (undefined2 *)(pauVar19[7] + 6),
485: CONCAT212(uVar52,SUB1612(auVar50,0))) >> 0x60,0),
486: CONCAT210(*(undefined2 *)(pauVar19[7] + 4),
487: SUB1610(auVar50,0))) >> 0x50,0),
488: CONCAT28(uVar51,SUB168(auVar50,0))) >> 0x40,0),
489: *(undefined2 *)(pauVar19[7] + 2)),uVar34)) << 0x20;
490: uVar35 = SUB162(auVar50,0);
491: uVar15 = (ulong)CONCAT24(uVar112,CONCAT22(SUB162(auVar62 >> 0x60,0),uVar45)) & 0xffff0000;
492: auVar63 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar9,CONCAT212(
493: uVar8,SUB1612(auVar63,0))) >> 0x60,0),
494: CONCAT210(uVar112,SUB1610(auVar63,0))) >> 0x50,0),
495: CONCAT28(uVar30,SUB168(auVar63,0))) >> 0x40,0),
496: (uVar15 >> 0x10) << 0x30) & (undefined  [16])0xffff000000000000;
497: uVar93 = SUB162((auVar74 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
498: uVar95 = SUB162((auVar74 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
499: uVar97 = SUB162(auVar74 >> 0x60,0);
500: uVar98 = SUB162(auVar74 >> 0x70,0);
501: auVar76 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
502: undefined2 *)(pauVar19[7] + 10),
503: CONCAT212(SUB162(auVar76 >> 0x30,0),
504: SUB1612(auVar76,0))) >> 0x60,0),
505: CONCAT210(SUB162(auVar50 >> 0x50,0),
506: SUB1610(auVar76,0))) >> 0x50,0),
507: CONCAT28(uVar34,SUB168(auVar76,0))) >> 0x40,0),
508: *(undefined2 *)(pauVar19[7] + 8))) << 0x30;
509: uVar53 = SUB162((auVar76 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
510: uVar54 = SUB162((auVar76 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
511: uVar120 = (undefined2)(uVar21 >> 0x10);
512: auVar74 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
513: uVar36,CONCAT212(uVar120,SUB1612(auVar65,0))) >>
514: 0x60,0),CONCAT210(uVar32,SUB1610(auVar65,0))) >>
515: 0x50,0),CONCAT28(uVar31,SUB168(auVar65,0))) >>
516: 0x40,0),uVar40) &
517: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
518: uVar118)) << 0x20;
519: uVar55 = SUB166(CONCAT412(SUB164(CONCAT214(uVar36,CONCAT212(uVar120,SUB1612(auVar65,0)))
520: >> 0x60,0),CONCAT210(uVar32,SUB1610(auVar65,0))) >> 0x50,
521: 0);
522: auVar50 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar55,CONCAT28(uVar31,SUB168(auVar65,0))) >>
523: 0x40,0),uVar40) &
524: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
525: (undefined  [16])0xffffffff00000000;
526: auVar72 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar84,
527: CONCAT212(SUB162(auVar74 >> 0x30,0),
528: SUB1612(auVar74,0))) >> 0x60,0),
529: CONCAT210(uVar27,SUB1610(auVar74,0))) >> 0x50,0),
530: CONCAT28(uVar118,SUB168(auVar74,0))) >> 0x40,0),
531: uVar44)) << 0x30;
532: uVar34 = (undefined2)(uVar15 >> 0x10);
533: auVar74 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar84,
534: CONCAT212(uVar40,SUB1612(auVar50,0))) >> 0x60,0),
535: CONCAT210(uVar27,SUB1610(auVar50,0))) >> 0x50,0),
536: CONCAT28(uVar118,SUB168(auVar50,0))) >> 0x40,0),
537: uVar44)) << 0x30 & (undefined  [16])0xffffffff00000000;
538: auVar50 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
539: uVar59,CONCAT212(uVar34,SUB1612(auVar63,0))) >>
540: 0x60,0),CONCAT210(uVar56,SUB1610(auVar63,0))) >>
541: 0x50,0),CONCAT28(uVar33,SUB168(auVar63,0))) >>
542: 0x40,0),uVar51) &
543: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),uVar45
544: )) << 0x20;
545: uVar101 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar7,CONCAT212(uVar44,
546: SUB1612(auVar74,0))) >> 0x60,0),
547: CONCAT210(uVar32,SUB1610(auVar74,0))) >> 0x50,0),
548: CONCAT28((short)uVar12,SUB168(auVar74,0))) >> 0x40,0);
549: uVar21 = (ulong)CONCAT24(uVar32,CONCAT22(uVar29,uVar31)) & 0xffff0000;
550: auVar65 = CONCAT88(uVar101,(uVar21 >> 0x10) << 0x30) & (undefined  [16])0xffff000000000000
551: ;
552: uVar40 = SUB162((auVar72 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
553: uVar51 = SUB162(auVar72 >> 0x60,0);
554: Var10 = CONCAT28(uVar51,uVar111);
555: auVar63 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
556: undefined2 *)(pauVar19[7] + 4),
557: CONCAT212(SUB162(auVar50 >> 0x30,0),
558: SUB1612(auVar50,0))) >> 0x60,0),
559: CONCAT210(uVar112,SUB1610(auVar50,0))) >> 0x50,0),
560: CONCAT28(uVar45,SUB168(auVar50,0))) >> 0x40,0),
561: *(undefined2 *)pauVar19[7])) << 0x30;
562: uVar15 = (ulong)(uVar110 & 0xffff00000000 |
563: (uint6)CONCAT22(SUB162(auVar64 >> 0x60,0),uVar115));
564: uVar14 = CONCAT22(uVar38,uVar37);
565: auVar50 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar14,uVar89),
566: CONCAT22(uVar114,uVar37)) >> 0x10),uVar41)) <<
567: 0x30 & (undefined  [16])0xffffffff00000000;
568: auVar64 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar38,uVar37),
569: uVar89),
570: CONCAT22(uVar114,uVar37)) >> 0x10),
571: uVar41),uVar119)) << 0x20;
572: uVar20 = SUB162((auVar63 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
573: uVar4 = (ulong)CONCAT24(SUB162((auVar63 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
574: CONCAT22(uVar34,uVar20));
575: uVar29 = (undefined2)(uVar15 >> 0x20);
576: uVar27 = (undefined2)(uVar15 >> 0x10);
577: auVar69 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar96,
578: CONCAT212(SUB162(auVar64 >> 0x30,0),
579: SUB1612(auVar64,0))) >> 0x60,0),
580: CONCAT210(uVar29,SUB1610(auVar64,0))) >> 0x50,0),
581: CONCAT28(uVar119,SUB168(auVar64,0))) >> 0x40,0),
582: uVar27) & 0xffffffffffffffff) << 0x30;
583: auVar50 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
584: CONCAT214(uVar96,CONCAT212(uVar41,SUB1612(auVar50,
585: 0))) >> 0x60,0),
586: CONCAT210(uVar29,SUB1610(auVar50,0))) >> 0x50,0),
587: CONCAT28(uVar119,SUB168(auVar50,0))) >> 0x40,0),
588: uVar27)) << 0x30) >> 0x20,0) &
589: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
590: uVar5 = (ulong)(uVar47 & 0xffff00000000 |
591: (uint6)CONCAT22(SUB162(auVar76 >> 0x60,0),uVar97));
592: auVar74 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar61,uVar39),
593: uVar54),
594: CONCAT22(uVar95,uVar39)) >> 0x10),
595: uVar52),uVar46)) << 0x20;
596: uVar58 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar90,CONCAT212(uVar27,
597: SUB1612(auVar50,0))) >> 0x60,0),
598: CONCAT210(uVar89,SUB1610(auVar50,0))) >> 0x50,0),
599: CONCAT28(uVar88,SUB168(auVar50,0))) >> 0x40,0);
600: uVar15 = (ulong)CONCAT24(uVar89,CONCAT22(SUB162(auVar68 >> 0x70,0),uVar114)) & 0xffff0000;
601: auVar64 = CONCAT88(uVar58,(uVar15 >> 0x10) << 0x30) & (undefined  [16])0xffff000000000000;
602: uVar112 = SUB162((auVar69 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
603: uVar38 = SUB162(auVar69 >> 0x60,0);
604: uVar84 = (undefined2)(uVar5 >> 0x10);
605: auVar66 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
606: undefined2 *)(pauVar19[7] + 6),
607: CONCAT212(SUB162(auVar74 >> 0x30,0),
608: SUB1612(auVar74,0))) >> 0x60,0),
609: CONCAT210((short)(uVar5 >> 0x20),
610: SUB1610(auVar74,0))) >> 0x50,0),
611: CONCAT28(uVar46,SUB168(auVar74,0))) >> 0x40,0),
612: uVar84) & 0xffffffffffffffff) << 0x30;
613: uVar29 = (undefined2)(uVar21 >> 0x10);
614: auVar67 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
615: uVar8,CONCAT212(uVar29,SUB1612(auVar65,0))) >>
616: 0x60,0),CONCAT210(uVar30,SUB1610(auVar65,0))) >>
617: 0x50,0),CONCAT28(uVar28,SUB168(auVar65,0))) >>
618: 0x40,0),uVar33) &
619: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),uVar31
620: )) << 0x20;
621: auVar74 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar8,
622: CONCAT212(uVar29,SUB1612(auVar65,0))) >> 0x60,0),
623: CONCAT210(uVar30,SUB1610(auVar65,0))) >> 0x50,0),
624: CONCAT28(uVar28,SUB168(auVar65,0))) >> 0x40,0),
625: uVar33) &
626: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30;
627: auVar50 = auVar74 & (undefined  [16])0xffffffff00000000;
628: uVar94 = SUB162((auVar66 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
629: uVar96 = SUB162((auVar66 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
630: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar56,
631: CONCAT212(SUB162(auVar67 >> 0x30,0),
632: SUB1612(auVar67,0))) >> 0x60,0),
633: CONCAT210(uVar32,SUB1610(auVar67,0))) >> 0x50,0),
634: CONCAT28(uVar31,SUB168(auVar67,0))) >> 0x40,0),
635: uVar35) & 0xffffffffffffffff) << 0x30;
636: uVar12 = SUB164(auVar26,0) & 0xffff | uVar12 << 0x10;
637: auVar26 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
638: CONCAT214(uVar56,CONCAT212(uVar33,SUB1612(auVar50,
639: 0))) >> 0x60,0),
640: CONCAT210(uVar32,SUB1610(auVar50,0))) >> 0x50,0),
641: CONCAT28(uVar31,SUB168(auVar50,0))) >> 0x40,0),
642: uVar35)) << 0x30) >> 0x20,0) &
643: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0),uVar12);
644: auVar74 = auVar74 & (undefined  [16])0xffffffff00000000;
645: uVar28 = SUB162(auVar74 >> 0x50,0);
646: uVar34 = SUB162(auVar74 >> 0x70,0);
647: uVar30 = (undefined2)(uVar15 >> 0x10);
648: auVar50 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar98,
649: CONCAT212(uVar30,SUB1612(auVar64,0))) >> 0x60,0),
650: CONCAT210(uVar97,SUB1610(auVar64,0))) >> 0x50,0),
651: CONCAT28(uVar115,SUB168(auVar64,0))) >> 0x40,0),
652: uVar95) &
653: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30;
654: auVar67 = auVar50 & (undefined  [16])0xffffffff00000000;
655: auVar65 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(
656: SUB164(CONCAT214(*(undefined2 *)pauVar19[7],
657: CONCAT212(uVar35,SUB1612(auVar26,
658: 0))) >> 0x60,0),
659: CONCAT210(uVar28,SUB1610(auVar26,0))) >> 0x50,0),
660: CONCAT28((short)uVar13,SUB168(auVar26,0))) >> 0x40
661: ,0),(((ulong)CONCAT24(uVar28,SUB144(CONCAT122(
662: SUB1612(auVar74 >> 0x20,0),uVar44),0) << 0x10) &
663: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0) &
664: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,
665: 0),(SUB166(auVar26,0) >> 0x10) << 0x20) >>
666: 0x20,0),uVar12) & (undefined  [16])0xffffffff0000ffff;
667: uVar100 = SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
668: uVar47 = CONCAT24(SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
669: CONCAT22(SUB162(auVar74 >> 0x60,0),uVar100));
670: uVar102 = SUB162(auVar70 >> 0x60,0);
671: auVar26 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
672: uVar98,CONCAT212(uVar30,SUB1612(auVar64,0))) >>
673: 0x60,0),CONCAT210(uVar97,SUB1610(auVar64,0))) >>
674: 0x50,0),CONCAT28(uVar115,SUB168(auVar64,0))) >>
675: 0x40,0),uVar95) &
676: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
677: uVar114)) << 0x20;
678: uVar28 = (undefined2)(uVar4 >> 0x20);
679: uVar44 = (undefined2)(uVar4 >> 0x10);
680: auVar64 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
681: CONCAT214(uVar9,CONCAT212(uVar43,CONCAT210(uVar36,
682: Var10))) >> 0x60,0),CONCAT210(uVar28,Var10)) >>
683: 0x50,0),CONCAT28(uVar40,uVar111)) >> 0x40,0),
684: uVar44) & 0xffffffffffffffff) << 0x30) >> 0x20,0)
685: & SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
686: auVar50 = auVar50 & (undefined  [16])0xffffffff00000000;
687: uVar30 = SUB162(auVar50 >> 0x50,0);
688: uVar35 = SUB162(auVar50 >> 0x70,0);
689: uVar21 = (ulong)(uVar55 & 0xffff00000000 |
690: (uint6)CONCAT22(SUB162(auVar63 >> 0x60,0),uVar51));
691: uVar48 = CONCAT22(uVar88,SUB162((auVar68 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
692: );
693: auVar67 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
694: CONCAT214(uVar54,CONCAT212(uVar95,SUB1612(auVar67,
695: 0))) >> 0x60,0),
696: CONCAT210(uVar89,SUB1610(auVar67,0))) >> 0x50,0),
697: CONCAT28(uVar114,SUB168(auVar67,0))) >> 0x40,0),
698: uVar53)) << 0x30) >> 0x20,0),uVar48);
699: auVar74 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar54,
700: CONCAT212(SUB162(auVar26 >> 0x30,0),
701: SUB1612(auVar26,0))) >> 0x60,0),
702: CONCAT210(uVar89,SUB1610(auVar26,0))) >> 0x50,0),
703: CONCAT28(uVar114,SUB168(auVar26,0))) >> 0x40,0),
704: uVar53)) << 0x30;
705: auVar71 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
706: uVar9,CONCAT212(uVar43,CONCAT210(uVar36,Var10)))
707: >> 0x60,0),CONCAT210(uVar28,Var10)) >> 0x50,0),
708: CONCAT28(uVar40,uVar111)) >> 0x40,0),uVar44),
709: uVar120) & (undefined  [12])0xffffffffffffffff) << 0x20;
710: auVar26 = auVar64 & (undefined  [16])0xffffffffffff0000;
711: uVar29 = SUB162(auVar26 >> 0x50,0);
712: uVar43 = SUB162(auVar26 >> 0x70,0);
713: auVar68 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(
714: SUB164(CONCAT214(uVar84,CONCAT212(uVar53,SUB1612(
715: auVar67,0))) >> 0x60,0),
716: CONCAT210(uVar30,SUB1610(auVar67,0))) >> 0x50,0),
717: CONCAT28(uVar93,SUB168(auVar67,0))) >> 0x40,0),
718: (((ulong)CONCAT24(uVar30,SUB144(CONCAT122(SUB1612(
719: auVar50 >> 0x20,0),uVar27),0) << 0x10) &
720: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
721: (SUB166(auVar67,0) >> 0x10) << 0x20) >> 0x20,0),
722: uVar48) & (undefined  [16])0xffffffff0000ffff;
723: uVar57 = SUB162((auVar74 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
724: uVar55 = CONCAT24(SUB162((auVar74 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
725: CONCAT22(SUB162(auVar50 >> 0x60,0),uVar57));
726: uVar60 = SUB162(auVar74 >> 0x60,0);
727: uVar30 = (undefined2)(uVar21 >> 0x20);
728: uVar28 = (undefined2)(uVar21 >> 0x10);
729: uVar48 = CONCAT22(uVar51,SUB162((auVar72 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
730: );
731: auVar67 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
732: CONCAT214(uVar59,CONCAT212(uVar44,SUB1612(auVar64,
733: 0))) >> 0x60,0),
734: CONCAT210(uVar30,SUB1610(auVar64,0))) >> 0x50,0),
735: CONCAT28(uVar120,SUB168(auVar64,0))) >> 0x40,0),
736: uVar28)) << 0x30) >> 0x20,0) &
737: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0),uVar48);
738: auVar77 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar59,
739: CONCAT212(SUB162(auVar71 >> 0x30,0),
740: SUB1612(auVar71,0))) >> 0x60,0),
741: CONCAT210(uVar30,SUB1610(auVar71,0))) >> 0x50,0),
742: CONCAT28(uVar120,SUB168(auVar71,0))) >> 0x40,0),
743: uVar28) & 0xffffffffffffffff) << 0x30;
744: uVar21 = (ulong)(((uint6)uVar14 & 0xffff0000) << 0x10 |
745: (uint6)CONCAT22(SUB162(auVar66 >> 0x60,0),uVar38));
746: auVar50 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(*(undefined2 *)
747: (pauVar19[5] + 0xe),uVar6),
748: uVar96),CONCAT22(uVar112,uVar6)) >>
749: 0x10),uVar39)) << 0x30;
750: auVar64 = auVar50 & (undefined  [16])0xffffffff00000000;
751: auVar71 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(*(undefined2 *)
752: (pauVar19[5] +
753: 0xe),uVar6),
754: uVar96),
755: CONCAT22(uVar112,uVar6)) >> 0x10),
756: uVar39),uVar37)) << 0x20;
757: auVar67 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(
758: SUB164(CONCAT214(SUB162(auVar63 >> 0x70,0),
759: CONCAT212(uVar28,SUB1612(auVar67,
760: 0))) >> 0x60,0),
761: CONCAT210(uVar29,SUB1610(auVar67,0))) >> 0x50,0),
762: CONCAT28(uVar20,SUB168(auVar67,0))) >> 0x40,0),
763: (((ulong)CONCAT24(uVar29,SUB144(CONCAT122(SUB1612(
764: auVar26 >> 0x20,0),SUB162(auVar72 >> 0x70,0)),0)
765: << 0x10) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0
766: ),(SUB166(auVar67,0) >> 0x10) << 0x20) >> 0x20,0),
767: uVar48) & (undefined  [16])0xffffffff0000ffff;
768: uVar121 = SUB162((auVar77 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
769: uVar117 = CONCAT24(SUB162((auVar77 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
770: CONCAT22(SUB162(auVar26 >> 0x60,0),uVar121));
771: uVar122 = SUB162(auVar77 >> 0x60,0);
772: uVar30 = (undefined2)(uVar21 >> 0x20);
773: uVar28 = (undefined2)(uVar21 >> 0x10);
774: auVar81 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar61,
775: CONCAT212(SUB162(auVar71 >> 0x30,0),
776: SUB1612(auVar71,0))) >> 0x60,0),
777: CONCAT210(uVar30,SUB1610(auVar71,0))) >> 0x50,0),
778: CONCAT28(uVar37,SUB168(auVar71,0))) >> 0x40,0),
779: uVar28) & 0xffffffffffffffff) << 0x30;
780: auVar50 = auVar50 & (undefined  [16])0xffffffff00000000;
781: uVar27 = SUB162(auVar50 >> 0x50,0);
782: uVar29 = SUB162(auVar50 >> 0x70,0);
783: uVar48 = CONCAT22(uVar38,SUB162((auVar69 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
784: );
785: auVar26 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
786: CONCAT214(uVar61,CONCAT212(uVar39,SUB1612(auVar64,
787: 0))) >> 0x60,0),
788: CONCAT210(uVar30,SUB1610(auVar64,0))) >> 0x50,0),
789: CONCAT28(uVar37,SUB168(auVar64,0))) >> 0x40,0),
790: uVar28)) << 0x30) >> 0x20,0) &
791: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0),uVar48);
792: auVar49 = ZEXT1012(CONCAT28(SUB162(auVar65 >> 0x60,0),
793: (ulong)(CONCAT24(SUB162(auVar65 >> 0x50,0),SUB164(auVar62,0))
794: & 0xffff0000ffff)));
795: uVar113 = SUB162((auVar81 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
796: uVar30 = SUB162((auVar81 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
797: uVar110 = CONCAT24(uVar30,CONCAT22(SUB162(auVar50 >> 0x60,0),uVar113));
798: uVar111 = CONCAT26(*(undefined2 *)(pauVar19[3] + 0xe),uVar110);
799: uVar116 = SUB162(auVar81 >> 0x60,0);
800: auVar26 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(
801: SUB164(CONCAT214(SUB162(auVar66 >> 0x70,0),
802: CONCAT212(uVar28,SUB1612(auVar26,
803: 0))) >> 0x60,0),
804: CONCAT210(uVar27,SUB1610(auVar26,0))) >> 0x50,0),
805: CONCAT28(uVar94,SUB168(auVar26,0))) >> 0x40,0),
806: (((ulong)CONCAT24(uVar27,SUB144(CONCAT122(SUB1612(
807: auVar50 >> 0x20,0),SUB162(auVar69 >> 0x70,0)),0)
808: << 0x10) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0
809: ),(SUB166(auVar26,0) >> 0x10) << 0x20) >> 0x20,0),
810: uVar48) & (undefined  [16])0xffffffff0000ffff;
811: auVar109 = divpd(_DAT_00168ed0,
812: CONCAT88((double)(int)((ulong)(double)SUB164(auVar65,0) >> 0x20) *
813: 1.387039845 * 8.0,(double)SUB164(auVar65,0) * 1.0 * 8.0));
814: dVar91 = (double)(int)((unkuint10)
815: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar65 >>
816: 0x30,0),
817: SUB1612(auVar65,0
818: )) >> 0x50
819: ,0),
820: CONCAT28(SUB162(auVar65 >> 0x20,0)
821: ,SUB168(auVar65,0))) >>
822: 0x40,0),SUB168(auVar65,0)) >> 0x30,0) >>
823: 0x10);
824: auVar105 = divpd(_DAT_00168ed0,
825: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 1.175875602 * 8.0,
826: dVar91 * 1.306562965 * 8.0));
827: dVar91 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar65 >> 0x70,0),auVar49)) >> 0x40,0);
828: auVar106 = divpd(_DAT_00168ed0,
829: CONCAT88((double)SUB124(auVar49 >> 0x20,0) * 0.785694958 * 8.0,
830: (double)uVar13 * 1.0 * 8.0));
831: auVar103 = divpd(_DAT_00168ed0,
832: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 0.275899379 * 8.0,
833: dVar91 * 0.5411961 * 8.0));
834: fVar92 = (float)SUB168(auVar106 >> 0x40,0);
835: fVar85 = (float)SUB168(auVar103 >> 0x40,0);
836: auVar49 = ZEXT1012(CONCAT28(SUB162(auVar68 >> 0x60,0),
837: (ulong)CONCAT24(SUB162(auVar68 >> 0x50,0),(uint)uVar93)));
838: auVar107 = divpd(_DAT_00168ed0,
839: CONCAT88((double)(int)((ulong)(double)SUB164(auVar68,0) >> 0x20) *
840: 1.387039845 * 1.387039845 * 8.0,
841: (double)SUB164(auVar68,0) * 1.0 * 1.387039845 * 8.0));
842: dVar91 = (double)(int)((unkuint10)
843: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar68 >>
844: 0x30,0),
845: SUB1612(auVar68,0
846: )) >> 0x50
847: ,0),
848: CONCAT28(SUB162(auVar68 >> 0x20,0)
849: ,SUB168(auVar68,0))) >>
850: 0x40,0),SUB168(auVar68,0)) >> 0x30,0) >>
851: 0x10);
852: fVar108 = (float)SUB168(auVar107 >> 0x40,0);
853: auVar123 = divpd(_DAT_00168ed0,
854: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 1.175875602 * 1.387039845
855: * 8.0,dVar91 * 1.306562965 * 1.387039845 * 8.0));
856: dVar91 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar68 >> 0x70,0),auVar49)) >> 0x40,0);
857: auVar124 = divpd(_DAT_00168ed0,
858: CONCAT88((double)SUB124(auVar49 >> 0x20,0) * 0.785694958 * 1.387039845 *
859: 8.0,(double)(uint)uVar93 * 1.0 * 1.387039845 * 8.0));
860: auVar104 = divpd(_DAT_00168ed0,
861: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 0.275899379 * 1.387039845
862: * 8.0,dVar91 * 0.5411961 * 1.387039845 * 8.0));
863: auVar49 = ZEXT1012(CONCAT28(SUB162(auVar67 >> 0x60,0),
864: (ulong)CONCAT24(SUB162(auVar67 >> 0x50,0),(uint)uVar20)));
865: dVar91 = (double)((uint)((unkuint10)
866: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar67 
867: >> 0x30,0),SUB1612(auVar67,0)) >> 0x50,0),
868: CONCAT28(SUB162(auVar67 >> 0x20,0),
869: SUB168(auVar67,0))) >> 0x40,0),
870: SUB168(auVar67,0)) >> 0x30,0) >> 0x10) & 0xffff);
871: auVar62 = divpd(_DAT_00168ed0,
872: CONCAT88((double)(int)((ulong)(double)SUB164(auVar67,0) >> 0x20) *
873: 1.387039845 * 1.306562965 * 8.0,
874: (double)SUB164(auVar67,0) * 1.0 * 1.306562965 * 8.0));
875: auVar63 = divpd(_DAT_00168ed0,
876: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 1.175875602 * 1.306562965
877: * 8.0,dVar91 * 1.306562965 * 1.306562965 * 8.0));
878: dVar91 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar67 >> 0x70,0),auVar49)) >> 0x40,0);
879: auVar64 = divpd(_DAT_00168ed0,
880: CONCAT88((double)SUB124(auVar49 >> 0x20,0) * 0.785694958 * 1.306562965 *
881: 8.0,(double)(uint)uVar20 * 1.0 * 1.306562965 * 8.0));
882: auVar65 = divpd(_DAT_00168ed0,
883: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 0.275899379 * 1.306562965
884: * 8.0,dVar91 * 0.5411961 * 1.306562965 * 8.0));
885: fVar86 = (float)SUB168(auVar64 >> 0x40,0);
886: fVar99 = (float)SUB168(auVar65 >> 0x40,0);
887: auVar49 = ZEXT1012(CONCAT28(SUB162(auVar26 >> 0x60,0),
888: (ulong)CONCAT24(SUB162(auVar26 >> 0x50,0),(uint)uVar94)));
889: dVar91 = (double)((uint)((unkuint10)
890: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar26 
891: >> 0x30,0),SUB1612(auVar26,0)) >> 0x50,0),
892: CONCAT28(SUB162(auVar26 >> 0x20,0),
893: SUB168(auVar26,0))) >> 0x40,0),
894: SUB168(auVar26,0)) >> 0x30,0) >> 0x10) & 0xffff);
895: auVar66 = divpd(_DAT_00168ed0,
896: CONCAT88((double)(int)((ulong)(double)SUB164(auVar26,0) >> 0x20) *
897: 1.387039845 * 1.175875602 * 8.0,
898: (double)SUB164(auVar26,0) * 1.0 * 1.175875602 * 8.0));
899: auVar67 = divpd(_DAT_00168ed0,
900: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 1.175875602 * 1.175875602
901: * 8.0,dVar91 * 1.306562965 * 1.175875602 * 8.0));
902: dVar91 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar26 >> 0x70,0),auVar49)) >> 0x40,0);
903: auVar68 = divpd(_DAT_00168ed0,
904: CONCAT88((double)SUB124(auVar49 >> 0x20,0) * 0.785694958 * 1.175875602 *
905: 8.0,(double)(uint)uVar94 * 1.0 * 1.175875602 * 8.0));
906: auVar69 = divpd(_DAT_00168ed0,
907: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 0.275899379 * 1.175875602
908: * 8.0,dVar91 * 0.5411961 * 1.175875602 * 8.0));
909: auVar49 = ZEXT1012(CONCAT28(SUB162(auVar70 >> 0x70,0),
910: (ulong)CONCAT24(uVar34,(uint)uVar102)));
911: auVar70 = divpd(_DAT_00168ed0,
912: CONCAT88((double)SUB164(CONCAT106((unkuint10)
913: (SUB148(CONCAT68(SUB146(CONCAT410(SUB144
914: (CONCAT212(uVar7,CONCAT210(uVar34,CONCAT28(uVar102
915: ,uVar101))) >> 0x50,0),
916: CONCAT28((short)((ulong)uVar47 >> 0x20),uVar101))
917: >> 0x40,0),uVar101) >> 0x30,0) & 0xffff) &
918: SUB1610((undefined  [16])0xffffffffffffffff >>
919: 0x30,0) &
920: SUB1610((undefined  [16])0xffffffffffffffff >>
921: 0x30,0),(uVar47 >> 0x10) << 0x20) >> 0x20,
922: 0) * 1.387039845 * 8.0,
923: (double)(uint)uVar100 * 1.0 * 8.0));
924: auVar71 = divpd(_DAT_00168ed0,ZEXT816(0) << 0x40);
925: dVar91 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar19[7] + 8),auVar49)) >>
926: 0x40,0);
927: auVar72 = divpd(_DAT_00168ed0,
928: CONCAT88((double)SUB124(auVar49 >> 0x20,0) * 0.785694958 * 8.0,
929: (double)(uint)uVar102 * 1.0 * 8.0));
930: auVar73 = divpd(_DAT_00168ed0,
931: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 0.275899379 * 8.0,
932: dVar91 * 0.5411961 * 8.0));
933: auVar49 = ZEXT1012(CONCAT28(SUB162(auVar74 >> 0x70,0),(ulong)CONCAT24(uVar35,(uint)uVar60)
934: ));
935: auVar74 = divpd(_DAT_00168ed0,
936: CONCAT88((double)SUB164(CONCAT106((unkuint10)
937: (SUB148(CONCAT68(SUB146(CONCAT410(SUB144
938: (CONCAT212(uVar90,CONCAT210(uVar35,CONCAT28(uVar60
939: ,uVar58))) >> 0x50,0),
940: CONCAT28((short)((ulong)uVar55 >> 0x20),uVar58))
941: >> 0x40,0),uVar58) >> 0x30,0) & 0xffff) &
942: SUB1610((undefined  [16])0xffffffffffffffff >>
943: 0x30,0) &
944: SUB1610((undefined  [16])0xffffffffffffffff >>
945: 0x30,0),(uVar55 >> 0x10) << 0x20) >> 0x20,
946: 0) * 1.387039845 * 0.785694958 * 8.0,
947: (double)(uint)uVar57 * 1.0 * 0.785694958 * 8.0));
948: auVar75 = divpd(_DAT_00168ed0,ZEXT816(0) << 0x40);
949: dVar91 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar76 >> 0x70,0),auVar49)) >> 0x40,0);
950: auVar76 = divpd(_DAT_00168ed0,
951: CONCAT88((double)SUB124(auVar49 >> 0x20,0) * 0.785694958 * 0.785694958 *
952: 8.0,(double)(uint)uVar60 * 1.0 * 0.785694958 * 8.0));
953: auVar50 = divpd(_DAT_00168ed0,
954: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 0.275899379 * 0.785694958
955: * 8.0,dVar91 * 0.5411961 * 0.785694958 * 8.0));
956: auVar49 = ZEXT1012(CONCAT28(SUB162(auVar77 >> 0x70,0),
957: (ulong)CONCAT24(uVar43,(uint)uVar122)));
958: auVar77 = divpd(_DAT_00168ed0,
959: CONCAT88((double)SUB164(CONCAT106((unkuint10)
960: (SUB148(CONCAT68(SUB146(CONCAT410(SUB144
961: (CONCAT212(*(undefined2 *)(pauVar19[3] + 0xc),
962: CONCAT210(uVar43,CONCAT28(uVar122,
963: uVar42))) >> 0x50,0),
964: CONCAT28((short)((ulong)uVar117 >> 0x20),uVar42))
965: >> 0x40,0),uVar42) >> 0x30,0) & 0xffff) &
966: SUB1610((undefined  [16])0xffffffffffffffff >>
967: 0x30,0) &
968: SUB1610((undefined  [16])0xffffffffffffffff >>
969: 0x30,0),(uVar117 >> 0x10) << 0x20) >> 0x20
970: ,0) * 1.387039845 * 0.5411961 * 8.0,
971: (double)(uint)uVar121 * 1.0 * 0.5411961 * 8.0));
972: auVar78 = divpd(_DAT_00168ed0,ZEXT816(0) << 0x40);
973: dVar91 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar19[7] + 0xc),auVar49)) >>
974: 0x40,0);
975: auVar79 = divpd(_DAT_00168ed0,
976: CONCAT88((double)SUB124(auVar49 >> 0x20,0) * 0.785694958 * 0.5411961 * 8.0
977: ,(double)(uint)uVar122 * 1.0 * 0.5411961 * 8.0));
978: auVar80 = divpd(_DAT_00168ed0,
979: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 0.275899379 * 0.5411961 *
980: 8.0,dVar91 * 0.5411961 * 0.5411961 * 8.0));
981: auVar49 = ZEXT1012(CONCAT28(SUB162(auVar81 >> 0x70,0),
982: (ulong)CONCAT24(uVar29,(uint)uVar116)));
983: Var87 = (unkuint10)
984: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(*(undefined2 *)
985: (pauVar19[3] + 0xe),
986: CONCAT210(uVar29,CONCAT28(
987: uVar116,uVar111))) >> 0x50,0),
988: CONCAT28(uVar30,uVar111)) >> 0x40,0),uVar111) >>
989: 0x30,0) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
990: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
991: dVar91 = (double)((uint)(Var87 >> 0x10) & 0xffff);
992: auVar81 = divpd(_DAT_00168ed0,
993: CONCAT88((double)SUB164(CONCAT106(Var87,(uVar110 >> 0x10) << 0x20) >> 0x20
994: ,0) * 1.387039845 * 0.275899379 * 8.0,
995: (double)(uint)uVar113 * 1.0 * 0.275899379 * 8.0));
996: auVar82 = divpd(_DAT_00168ed0,
997: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 1.175875602 * 0.275899379
998: * 8.0,dVar91 * 1.306562965 * 0.275899379 * 8.0));
999: dVar91 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar19[7] + 0xe),auVar49)) >>
1000: 0x40,0);
1001: auVar83 = divpd(_DAT_00168ed0,
1002: CONCAT88((double)SUB124(auVar49 >> 0x20,0) * 0.785694958 * 0.275899379 *
1003: 8.0,(double)(uint)uVar116 * 1.0 * 0.275899379 * 8.0));
1004: auVar26 = divpd(_DAT_00168ed0,
1005: CONCAT88((double)(int)((ulong)dVar91 >> 0x20) * 0.275899379 * 0.275899379
1006: * 8.0,dVar91 * 0.5411961 * 0.275899379 * 8.0));
1007: uVar42 = CONCAT44((float)SUB168(auVar74,0),(float)SUB168(auVar70,0));
1008: *(undefined8 *)pauVar16[1] = uVar42;
1009: *(ulong *)*pauVar16 = CONCAT44((float)SUB168(auVar107,0),(float)SUB168(auVar109,0));
1010: *(long *)(*pauVar16 + 8) =
1011: SUB168(CONCAT412((float)SUB168(auVar66,0),
1012: CONCAT48((float)SUB168(auVar62,0),
1013: CONCAT44((float)SUB168(auVar62,0),(float)SUB168(auVar109,0)
1014: ))) >> 0x40,0);
1015: uVar21 = SUB168(CONCAT412((float)SUB168(auVar74 >> 0x40,0),
1016: CONCAT48(fVar108,CONCAT44(fVar108,(float)SUB168(auVar107,0))))
1017: >> 0x40,0) & 0xffffffff00000000 |
1018: (ulong)(uint)(float)SUB168(auVar70 >> 0x40,0);
1019: *(long *)(pauVar16[1] + 8) =
1020: SUB168(CONCAT412((float)SUB168(auVar81,0),CONCAT48((float)SUB168(auVar77,0),uVar42))
1021: >> 0x40,0);
1022: *(ulong *)pauVar16[2] = CONCAT44(fVar108,(float)SUB168(auVar109 >> 0x40,0));
1023: *(float *)pauVar16[3] = (float)SUB168(auVar62 >> 0x40,0);
1024: *(float *)(pauVar16[3] + 4) = (float)SUB168(auVar66 >> 0x40,0);
1025: *(ulong *)pauVar16[3] = uVar21;
1026: *(long *)(pauVar16[3] + 8) =
1027: SUB168(CONCAT412((float)SUB168(auVar81 >> 0x40,0),
1028: CONCAT48((float)SUB168(auVar77 >> 0x40,0),uVar21)) >> 0x40,0);
1029: *(ulong *)pauVar16[4] = CONCAT44((float)SUB168(auVar123,0),(float)SUB168(auVar105,0));
1030: *(long *)(pauVar16[4] + 8) =
1031: SUB168(CONCAT412((float)SUB168(auVar67,0),
1032: CONCAT48((float)SUB168(auVar63,0),
1033: CONCAT44((float)SUB168(auVar63,0),(float)SUB168(auVar105,0)
1034: ))) >> 0x40,0);
1035: *(float *)pauVar16[5] = (float)SUB168(auVar71,0);
1036: *(float *)(pauVar16[5] + 4) = (float)SUB168(auVar75,0);
1037: *(float *)pauVar16[6] = (float)SUB168(auVar78,0);
1038: *(float *)(pauVar16[6] + 4) = (float)SUB168(auVar82,0);
1039: uVar42 = CONCAT44((float)SUB168(auVar75 >> 0x40,0),(float)SUB168(auVar71 >> 0x40,0));
1040: *(ulong *)pauVar16[6] =
1041: CONCAT44((float)SUB168(auVar123 >> 0x40,0),(float)SUB168(auVar105 >> 0x40,0));
1042: *(float *)pauVar16[7] = (float)SUB168(auVar63 >> 0x40,0);
1043: *(float *)(pauVar16[7] + 4) = (float)SUB168(auVar67 >> 0x40,0);
1044: *(undefined8 *)pauVar16[7] = uVar42;
1045: *(long *)(pauVar16[7] + 8) =
1046: SUB168(CONCAT412((float)SUB168(auVar82 >> 0x40,0),
1047: CONCAT48((float)SUB168(auVar78 >> 0x40,0),uVar42)) >> 0x40,0);
1048: uVar42 = CONCAT44((float)SUB168(auVar76,0),(float)SUB168(auVar72,0));
1049: *(undefined8 *)pauVar16[9] = uVar42;
1050: *(long *)(pauVar16[9] + 8) =
1051: SUB168(CONCAT412((float)SUB168(auVar83,0),CONCAT48((float)SUB168(auVar79,0),uVar42))
1052: >> 0x40,0);
1053: *(ulong *)pauVar16[8] = CONCAT44((float)SUB168(auVar124,0),(float)SUB168(auVar106,0));
1054: *(long *)(pauVar16[8] + 8) =
1055: SUB168(CONCAT412((float)SUB168(auVar68,0),
1056: CONCAT48((float)SUB168(auVar64,0),
1057: CONCAT44(fVar86,(float)SUB168(auVar64,0)) << 0x20)) >> 0x40
1058: ,0);
1059: *(float *)pauVar16[0xb] = (float)SUB168(auVar72 >> 0x40,0);
1060: *(float *)(pauVar16[0xb] + 4) = (float)SUB168(auVar76 >> 0x40,0);
1061: *(float *)pauVar16[0xc] = (float)SUB168(auVar79 >> 0x40,0);
1062: *(float *)(pauVar16[0xc] + 4) = (float)SUB168(auVar83 >> 0x40,0);
1063: *(ulong *)pauVar16[10] = CONCAT44((float)SUB168(auVar124 >> 0x40,0),fVar92);
1064: *(long *)(pauVar16[10] + 8) =
1065: SUB168(CONCAT412((float)SUB168(auVar68 >> 0x40,0),
1066: CONCAT48(fVar86,CONCAT44(fVar86,fVar92))) >> 0x40,0);
1067: *(float *)pauVar16[0xd] = (float)SUB168(auVar73,0);
1068: *(float *)(pauVar16[0xd] + 4) = (float)SUB168(auVar50,0);
1069: *(float *)pauVar16[0xe] = (float)SUB168(auVar80,0);
1070: *(float *)(pauVar16[0xe] + 4) = (float)SUB168(auVar26,0);
1071: uVar42 = CONCAT44((float)SUB168(auVar50 >> 0x40,0),(float)SUB168(auVar73 >> 0x40,0));
1072: *(ulong *)pauVar16[0xc] = CONCAT44((float)SUB168(auVar104,0),(float)SUB168(auVar103,0));
1073: *(long *)(pauVar16[0xc] + 8) =
1074: SUB128(CONCAT48((float)SUB168(auVar69,0),
1075: CONCAT44((float)SUB168(auVar65,0),(float)SUB168(auVar65,0))) >> 0x20,
1076: 0);
1077: *(undefined8 *)pauVar16[0xf] = uVar42;
1078: *(ulong *)pauVar16[0xe] = CONCAT44((float)SUB168(auVar104 >> 0x40,0),fVar85);
1079: *(long *)(pauVar16[0xe] + 8) =
1080: SUB168(CONCAT412((float)SUB168(auVar69 >> 0x40,0),
1081: CONCAT48(fVar99,CONCAT44(fVar99,fVar85))) >> 0x40,0);
1082: *(long *)(pauVar16[0xf] + 8) =
1083: SUB168(CONCAT412((float)SUB168(auVar26 >> 0x40,0),
1084: CONCAT48((float)SUB168(auVar80 >> 0x40,0),uVar42)) >> 0x40,0);
1085: }
1086: goto LAB_00107cbb;
1087: }
1088: ppcVar3 = (code **)*param_1;
1089: iVar23 = iVar23 + 1;
1090: pcVar24 = pcVar24 + 0x60;
1091: *(undefined4 *)(ppcVar3 + 5) = 0x30;
1092: (**ppcVar3)(param_1);
1093: } while (*(int *)((long)param_1 + 0x4c) != iVar23 && iVar23 <= *(int *)((long)param_1 + 0x4c));
1094: }
1095: /* WARNING: Read-only address (ram,0x00168ed0) is written */
1096: return;
1097: }
1098: 
