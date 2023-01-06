1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00124560(code **param_1)
5: 
6: {
7: code *pcVar1;
8: code *pcVar2;
9: code **ppcVar3;
10: uint uVar4;
11: ulong uVar5;
12: ulong uVar6;
13: ulong uVar7;
14: uint6 uVar8;
15: undefined2 uVar9;
16: undefined2 uVar10;
17: undefined2 uVar11;
18: undefined2 uVar12;
19: undefined2 uVar13;
20: undefined4 uVar14;
21: undefined4 uVar15;
22: float fVar16;
23: float fVar17;
24: float fVar18;
25: float fVar19;
26: float fVar20;
27: float fVar21;
28: float fVar22;
29: float fVar23;
30: float fVar24;
31: float fVar25;
32: float fVar26;
33: float fVar27;
34: float fVar28;
35: float fVar29;
36: float fVar30;
37: unkbyte10 Var31;
38: uint uVar32;
39: int iVar33;
40: long lVar34;
41: long lVar35;
42: undefined (*pauVar36) [16];
43: long lVar37;
44: code *pcVar38;
45: undefined (*pauVar39) [16];
46: int iVar40;
47: code *pcVar41;
48: undefined2 uVar43;
49: undefined2 uVar44;
50: undefined2 uVar45;
51: undefined2 uVar46;
52: undefined8 uVar42;
53: undefined2 uVar47;
54: undefined2 uVar48;
55: undefined2 uVar49;
56: undefined2 uVar50;
57: undefined2 uVar51;
58: undefined2 uVar52;
59: undefined2 uVar53;
60: undefined2 uVar54;
61: undefined2 uVar55;
62: uint6 uVar56;
63: ulong uVar57;
64: undefined auVar58 [12];
65: ushort uVar64;
66: undefined2 uVar66;
67: ushort uVar68;
68: undefined auVar59 [16];
69: undefined auVar60 [16];
70: undefined2 uVar65;
71: undefined auVar61 [16];
72: undefined2 uVar67;
73: undefined auVar62 [16];
74: double dVar69;
75: double dVar70;
76: undefined auVar71 [12];
77: undefined2 uVar75;
78: ushort uVar78;
79: undefined auVar72 [16];
80: undefined auVar73 [16];
81: unkuint10 Var77;
82: uint6 uVar79;
83: double dVar80;
84: double dVar81;
85: ushort uVar85;
86: ushort uVar87;
87: undefined auVar82 [16];
88: undefined8 uVar86;
89: undefined2 uVar89;
90: undefined2 uVar90;
91: undefined auVar88 [12];
92: undefined2 uVar93;
93: undefined2 uVar95;
94: undefined2 uVar97;
95: undefined2 uVar98;
96: undefined8 uVar96;
97: undefined auVar91 [16];
98: undefined auVar92 [16];
99: undefined4 uVar99;
100: undefined2 uVar105;
101: undefined auVar100 [12];
102: undefined2 uVar102;
103: undefined2 uVar103;
104: undefined2 uVar104;
105: undefined auVar101 [16];
106: ushort uVar106;
107: uint uVar107;
108: undefined2 uVar110;
109: undefined2 uVar111;
110: undefined2 uVar112;
111: undefined auVar108 [16];
112: ushort uVar113;
113: float fVar114;
114: float fVar115;
115: double dVar116;
116: double dVar117;
117: ushort uVar119;
118: ushort uVar120;
119: undefined2 uVar121;
120: undefined2 uVar122;
121: undefined2 uVar123;
122: undefined2 uVar124;
123: undefined auVar118 [16];
124: ushort uVar125;
125: ushort uVar127;
126: undefined auVar126 [16];
127: ushort uVar128;
128: uint6 uVar129;
129: double dVar130;
130: undefined auVar131 [12];
131: ushort uVar133;
132: ushort uVar134;
133: undefined auVar132 [16];
134: float fVar135;
135: double dVar136;
136: float fVar137;
137: double dVar138;
138: double dVar139;
139: double dVar140;
140: double dVar141;
141: unkuint10 Var142;
142: unkuint10 Var143;
143: undefined2 uVar63;
144: undefined2 uVar74;
145: undefined2 uVar76;
146: undefined2 uVar83;
147: undefined2 uVar84;
148: undefined2 uVar94;
149: undefined auVar109 [16];
150: 
151: pcVar41 = (code *)0x0;
152: iVar40 = 0;
153: lVar37 = 0;
154: pcVar1 = param_1[0x4b];
155: pcVar38 = param_1[0x26];
156: if (0 < *(int *)(param_1 + 7)) {
157: do {
158: switch(*(undefined4 *)(pcVar38 + 0x24)) {
159: default:
160: pcVar2 = *param_1;
161: *(undefined4 *)(pcVar2 + 0x2c) = *(undefined4 *)(pcVar38 + 0x24);
162: ppcVar3 = (code **)*param_1;
163: *(undefined4 *)(pcVar2 + 0x28) = 7;
164: (**ppcVar3)(param_1);
165: break;
166: case 1:
167: pcVar41 = FUN_00139130;
168: iVar40 = 0;
169: break;
170: case 2:
171: iVar40 = FUN_001687a0();
172: if (iVar40 == 0) {
173: pcVar41 = FUN_00138dc0;
174: iVar40 = 0;
175: }
176: else {
177: pcVar41 = FUN_00168820;
178: iVar40 = 0;
179: }
180: break;
181: case 3:
182: pcVar41 = FUN_001356e0;
183: iVar40 = 0;
184: break;
185: case 4:
186: iVar40 = FUN_001687e0();
187: if (iVar40 == 0) {
188: pcVar41 = FUN_00138990;
189: iVar40 = 0;
190: }
191: else {
192: pcVar41 = FUN_00168840;
193: iVar40 = 0;
194: }
195: break;
196: case 5:
197: pcVar41 = FUN_001354d0;
198: iVar40 = 0;
199: break;
200: case 6:
201: pcVar41 = FUN_00135250;
202: iVar40 = 0;
203: break;
204: case 7:
205: pcVar41 = FUN_00134eb0;
206: iVar40 = 0;
207: break;
208: case 8:
209: iVar33 = *(int *)(param_1 + 0xc);
210: if (iVar33 == 1) {
211: iVar40 = FUN_001688c0();
212: if (iVar40 == 0) {
213: pcVar41 = FUN_001342d0;
214: iVar40 = 1;
215: }
216: else {
217: pcVar41 = FUN_00168970;
218: iVar40 = 1;
219: }
220: }
221: else {
222: if (iVar33 == 0) {
223: iVar40 = FUN_00168860();
224: if (iVar40 == 0) {
225: pcVar41 = FUN_00134850;
226: iVar40 = 0;
227: }
228: else {
229: pcVar41 = FUN_00168940;
230: iVar40 = 0;
231: }
232: }
233: else {
234: if (iVar33 == 2) {
235: iVar40 = FUN_00168900();
236: if (iVar40 == 0) {
237: pcVar41 = FUN_00133da0;
238: iVar40 = 2;
239: }
240: else {
241: pcVar41 = FUN_00168990;
242: iVar40 = 2;
243: }
244: }
245: else {
246: ppcVar3 = (code **)*param_1;
247: *(undefined4 *)(ppcVar3 + 5) = 0x30;
248: (**ppcVar3)(param_1);
249: }
250: }
251: }
252: break;
253: case 9:
254: pcVar41 = FUN_001359a0;
255: iVar40 = 0;
256: break;
257: case 10:
258: pcVar41 = FUN_00135df0;
259: iVar40 = 0;
260: break;
261: case 0xb:
262: pcVar41 = FUN_001362a0;
263: iVar40 = 0;
264: break;
265: case 0xc:
266: pcVar41 = FUN_00136860;
267: iVar40 = 0;
268: break;
269: case 0xd:
270: pcVar41 = FUN_00136df0;
271: iVar40 = 0;
272: break;
273: case 0xe:
274: pcVar41 = FUN_001374c0;
275: iVar40 = 0;
276: break;
277: case 0xf:
278: pcVar41 = FUN_00137b60;
279: iVar40 = 0;
280: break;
281: case 0x10:
282: pcVar41 = FUN_00138210;
283: iVar40 = 0;
284: }
285: iVar33 = *(int *)(pcVar38 + 0x30);
286: *(code **)(pcVar1 + lVar37 * 8 + 8) = pcVar41;
287: if (((iVar33 != 0) && (*(int *)(pcVar1 + lVar37 * 4 + 0x58) != iVar40)) &&
288: (pauVar39 = *(undefined (**) [16])(pcVar38 + 0x50), pauVar39 != (undefined (*) [16])0x0)) {
289: *(int *)(pcVar1 + lVar37 * 4 + 0x58) = iVar40;
290: if (iVar40 == 1) {
291: lVar35 = *(long *)(pcVar38 + 0x58);
292: lVar34 = 0;
293: do {
294: *(short *)(lVar35 + lVar34) =
295: (short)((long)((ulong)*(ushort *)(*pauVar39 + lVar34) *
296: (long)*(short *)(&DAT_00189920 + lVar34) + 0x800) >> 0xc);
297: lVar34 = lVar34 + 2;
298: } while (lVar34 != 0x80);
299: }
300: else {
301: if (iVar40 == 2) {
302: pauVar36 = *(undefined (**) [16])(pcVar38 + 0x58);
303: if ((pauVar36 < pauVar39[8]) && (pauVar39 < pauVar36[0x10])) {
304: lVar35 = 0;
305: do {
306: dVar116 = *(double *)(&DAT_001898e0 + lVar35);
307: lVar35 = lVar35 + 8;
308: uVar64 = *(ushort *)(*pauVar39 + 2);
309: *(float *)*pauVar36 = (float)((double)(uint)*(ushort *)*pauVar39 * dVar116);
310: uVar68 = *(ushort *)(*pauVar39 + 4);
311: *(float *)(*pauVar36 + 4) = (float)((double)(uint)uVar64 * dVar116 * 1.387039845);
312: uVar64 = *(ushort *)(*pauVar39 + 6);
313: *(float *)(*pauVar36 + 8) = (float)((double)(uint)uVar68 * dVar116 * 1.306562965);
314: uVar68 = *(ushort *)(*pauVar39 + 8);
315: *(float *)(*pauVar36 + 0xc) = (float)((double)(uint)uVar64 * dVar116 * 1.175875602);
316: uVar64 = *(ushort *)(*pauVar39 + 10);
317: *(float *)pauVar36[1] = (float)((double)(uint)uVar68 * dVar116);
318: uVar68 = *(ushort *)(*pauVar39 + 0xc);
319: *(float *)(pauVar36[1] + 4) = (float)((double)(uint)uVar64 * dVar116 * 0.785694958);
320: uVar64 = *(ushort *)(*pauVar39 + 0xe);
321: *(float *)(pauVar36[1] + 8) = (float)((double)(uint)uVar68 * dVar116 * 0.5411961);
322: *(float *)(pauVar36[1] + 0xc) =
323: (float)((double)(uint)uVar64 * dVar116 * 0.275899379);
324: pauVar36 = pauVar36[2];
325: pauVar39 = pauVar39[1];
326: } while (lVar35 != 0x40);
327: }
328: else {
329: auVar62 = *pauVar39;
330: uVar44 = *(undefined2 *)pauVar39[1];
331: uVar45 = *(undefined2 *)(pauVar39[1] + 2);
332: uVar43 = *(undefined2 *)(pauVar39[1] + 4);
333: uVar46 = *(undefined2 *)(pauVar39[1] + 8);
334: uVar9 = *(undefined2 *)(pauVar39[1] + 0xc);
335: uVar10 = *(undefined2 *)(pauVar39[1] + 0xe);
336: auVar61 = pauVar39[2];
337: uVar76 = SUB162(auVar62 >> 0x30,0);
338: uVar74 = SUB162(auVar62 >> 0x20,0);
339: uVar56 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar39[1] + 6),
340: CONCAT212(uVar76,SUB1612(auVar62,0))) >>
341: 0x60,0),CONCAT210(uVar43,SUB1610(auVar62,0))) >> 0x50
342: ,0);
343: auVar72 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar56,CONCAT28(uVar74,SUB168(auVar62,0))
344: ) >> 0x40,0),uVar45)) << 0x30 &
345: (undefined  [16])0xffffffff00000000;
346: uVar47 = SUB162(auVar62 >> 0x40,0);
347: uVar50 = SUB162(auVar62 >> 0x50,0);
348: uVar53 = SUB162(auVar62 >> 0x70,0);
349: uVar75 = *(undefined2 *)pauVar39[3];
350: uVar67 = *(undefined2 *)(pauVar39[3] + 4);
351: uVar94 = *(undefined2 *)(pauVar39[3] + 6);
352: uVar11 = *(undefined2 *)(pauVar39[3] + 8);
353: uVar63 = SUB162(auVar62 >> 0x10,0);
354: auVar59 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
355: CONCAT214(*(undefined2 *)(pauVar39[1] + 6),
356: CONCAT212(uVar76,SUB1612(auVar62,0))) >>
357: 0x60,0),CONCAT210(uVar43,SUB1610(auVar62,0))) >>
358: 0x50,0),CONCAT28(uVar74,SUB168(auVar62,0))) >>
359: 0x40,0),uVar45),uVar63)) << 0x20;
360: auVar73 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
361: undefined2 *)(pauVar39[1] + 10),
362: CONCAT212(uVar45,SUB1612(auVar72,0))) >> 0x60,0),
363: CONCAT210(uVar50,SUB1610(auVar72,0))) >> 0x50,0),
364: CONCAT28(uVar63,SUB168(auVar72,0))) >> 0x40,0),
365: uVar46)) << 0x30 & (undefined  [16])0xffffffff00000000;
366: auVar72 = pauVar39[4];
367: uVar90 = SUB162(auVar61 >> 0x30,0);
368: uVar89 = SUB162(auVar61 >> 0x20,0);
369: uVar107 = SUB164(auVar61,0) & 0xffff;
370: auVar60 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
371: undefined2 *)(pauVar39[1] + 10),
372: CONCAT212(SUB162(auVar59 >> 0x30,0),
373: SUB1612(auVar59,0))) >> 0x60,0),
374: CONCAT210(uVar50,SUB1610(auVar59,0))) >> 0x50,0),
375: CONCAT28(uVar63,SUB168(auVar59,0))) >> 0x40,0),
376: uVar46)) << 0x30;
377: uVar49 = SUB162(auVar61 >> 0x10,0);
378: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
379: CONCAT214(uVar94,CONCAT212(uVar90,SUB1612(auVar61,
380: 0))) >> 0x60,0),
381: CONCAT210(uVar67,SUB1610(auVar61,0))) >> 0x50,0),
382: CONCAT28(uVar89,SUB168(auVar61,0))) >> 0x40,0),
383: *(undefined2 *)(pauVar39[3] + 2)),uVar49)) << 0x20
384: ;
385: uVar48 = SUB162(auVar61 >> 0x40,0);
386: uVar52 = SUB162(auVar61 >> 0x60,0);
387: uVar54 = SUB162(auVar61 >> 0x70,0);
388: uVar45 = *(undefined2 *)pauVar39[5];
389: uVar50 = *(undefined2 *)(pauVar39[5] + 2);
390: uVar63 = *(undefined2 *)(pauVar39[5] + 4);
391: uVar122 = *(undefined2 *)(pauVar39[5] + 8);
392: uVar12 = *(undefined2 *)(pauVar39[5] + 0xc);
393: uVar13 = *(undefined2 *)(pauVar39[5] + 0xe);
394: uVar42 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar9,CONCAT212(uVar46,
395: SUB1612(auVar73,0))) >> 0x60,0),
396: CONCAT210(uVar43,SUB1610(auVar73,0))) >> 0x50,0),
397: CONCAT28(uVar44,SUB168(auVar73,0))) >> 0x40,0);
398: uVar57 = (ulong)CONCAT24(uVar43,CONCAT22(SUB162(auVar62 >> 0x60,0),uVar74)) &
399: 0xffff0000;
400: auVar73 = CONCAT88(uVar42,(uVar57 >> 0x10) << 0x30) &
401: (undefined  [16])0xffff000000000000;
402: uVar65 = SUB162((auVar60 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
403: uVar66 = SUB162(auVar60 >> 0x60,0);
404: uVar84 = SUB162(auVar72 >> 0x30,0);
405: uVar83 = SUB162(auVar72 >> 0x20,0);
406: uVar79 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar39[5] + 6),
407: CONCAT212(uVar84,SUB1612(auVar72,0))) >>
408: 0x60,0),CONCAT210(uVar63,SUB1610(auVar72,0))) >> 0x50
409: ,0);
410: uVar4 = SUB164(auVar72,0) & 0xffff;
411: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar79,CONCAT28(uVar83,SUB168(auVar72,0))
412: ) >> 0x40,0),uVar50)) << 0x30 &
413: (undefined  [16])0xffffffff00000000;
414: auVar59 = pauVar39[6];
415: auVar91 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
416: undefined2 *)(pauVar39[3] + 10),
417: CONCAT212(SUB162(auVar92 >> 0x30,0),
418: SUB1612(auVar92,0))) >> 0x60,0),
419: CONCAT210(SUB162(auVar61 >> 0x50,0),
420: SUB1610(auVar92,0))) >> 0x50,0),
421: CONCAT28(uVar49,SUB168(auVar92,0))) >> 0x40,0),
422: uVar11)) << 0x30;
423: uVar93 = SUB162(auVar72 >> 0x10,0);
424: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
425: CONCAT214(*(undefined2 *)(pauVar39[5] + 6),
426: CONCAT212(uVar84,SUB1612(auVar72,0))) >>
427: 0x60,0),CONCAT210(uVar63,SUB1610(auVar72,0))) >>
428: 0x50,0),CONCAT28(uVar83,SUB168(auVar72,0))) >>
429: 0x40,0),uVar50),uVar93)) << 0x20;
430: uVar49 = SUB162(auVar72 >> 0x40,0);
431: uVar51 = SUB162(auVar72 >> 0x50,0);
432: uVar55 = SUB162(auVar72 >> 0x70,0);
433: uVar110 = SUB162((auVar91 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
434: uVar111 = SUB162((auVar91 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
435: uVar112 = SUB162(auVar91 >> 0x70,0);
436: uVar95 = SUB162(auVar59 >> 0x40,0);
437: uVar97 = SUB162(auVar59 >> 0x60,0);
438: uVar98 = SUB162(auVar59 >> 0x70,0);
439: auVar61 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
440: undefined2 *)(pauVar39[5] + 10),
441: CONCAT212(uVar50,SUB1612(auVar82,0))) >> 0x60,0),
442: CONCAT210(uVar51,SUB1610(auVar82,0))) >> 0x50,0),
443: CONCAT28(uVar93,SUB168(auVar82,0))) >> 0x40,0),
444: uVar122)) << 0x30 & (undefined  [16])0xffffffff00000000;
445: auVar101 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
446: undefined2 *)(pauVar39[5] + 10),
447: CONCAT212(SUB162(auVar92 >> 0x30,0),
448: SUB1612(auVar92,0))) >> 0x60,0),
449: CONCAT210(uVar51,SUB1610(auVar92,0))) >> 0x50,0),
450: CONCAT28(uVar93,SUB168(auVar92,0))) >> 0x40,0),
451: uVar122)) << 0x30;
452: uVar103 = SUB162(auVar59 >> 0x30,0);
453: uVar102 = SUB162(auVar59 >> 0x20,0);
454: uVar51 = SUB162(auVar59 >> 0x10,0);
455: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
456: CONCAT214(*(undefined2 *)(pauVar39[7] + 6),
457: CONCAT212(uVar103,SUB1612(auVar59,0)))
458: >> 0x60,0),
459: CONCAT210(*(undefined2 *)(pauVar39[7] + 4),
460: SUB1610(auVar59,0))) >> 0x50,0),
461: CONCAT28(uVar102,SUB168(auVar59,0))) >> 0x40,0),
462: *(undefined2 *)(pauVar39[7] + 2)),uVar51)) << 0x20
463: ;
464: uVar5 = (ulong)CONCAT24(uVar63,CONCAT22(SUB162(auVar72 >> 0x60,0),uVar83)) &
465: 0xffff0000;
466: auVar82 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar12,CONCAT212
467: (uVar122,SUB1612(auVar61,0))) >> 0x60,0),
468: CONCAT210(uVar63,SUB1610(auVar61,0))) >> 0x50,0),
469: CONCAT28(uVar45,SUB168(auVar61,0))) >> 0x40,0),
470: (uVar5 >> 0x10) << 0x30) & (undefined  [16])0xffff000000000000;
471: uVar50 = SUB162(auVar59,0);
472: uVar119 = SUB162((auVar101 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
473: uVar121 = SUB162((auVar101 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
474: uVar123 = SUB162(auVar101 >> 0x60,0);
475: uVar124 = SUB162(auVar101 >> 0x70,0);
476: auVar101 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
477: undefined2 *)(pauVar39[7] + 10),
478: CONCAT212(SUB162(auVar92 >> 0x30,0),
479: SUB1612(auVar92,0))) >> 0x60,0),
480: CONCAT210(SUB162(auVar59 >> 0x50,0),
481: SUB1610(auVar92,0))) >> 0x50,0),
482: CONCAT28(uVar51,SUB168(auVar92,0))) >> 0x40,0),
483: *(undefined2 *)(pauVar39[7] + 8))) << 0x30;
484: uVar93 = (undefined2)(uVar57 >> 0x10);
485: uVar8 = SUB166(CONCAT412(SUB164(CONCAT214(uVar52,CONCAT212(uVar93,SUB1612(auVar73,0)))
486: >> 0x60,0),CONCAT210(uVar48,SUB1610(auVar73,0))) >>
487: 0x50,0);
488: auVar59 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar8,CONCAT28(uVar47,SUB168(auVar73,0)))
489: >> 0x40,0),uVar89) &
490: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
491: (undefined  [16])0xffffffff00000000;
492: auVar61 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
493: CONCAT214(uVar52,CONCAT212(uVar93,SUB1612(auVar73,
494: 0))) >> 0x60,0),
495: CONCAT210(uVar48,SUB1610(auVar73,0))) >> 0x50,0),
496: CONCAT28(uVar47,SUB168(auVar73,0))) >> 0x40,0),
497: uVar89) &
498: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
499: uVar74)) << 0x20;
500: uVar104 = SUB162((auVar101 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
501: uVar105 = SUB162((auVar101 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
502: auVar73 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar67,
503: CONCAT212(SUB162(auVar61 >> 0x30,0),
504: SUB1612(auVar61,0))) >> 0x60,0),
505: CONCAT210(uVar43,SUB1610(auVar61,0))) >> 0x50,0),
506: CONCAT28(uVar74,SUB168(auVar61,0))) >> 0x40,0),
507: uVar75)) << 0x30;
508: auVar61 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar67,
509: CONCAT212(uVar89,SUB1612(auVar59,0))) >> 0x60,0),
510: CONCAT210(uVar43,SUB1610(auVar59,0))) >> 0x50,0),
511: CONCAT28(uVar74,SUB168(auVar59,0))) >> 0x40,0),
512: uVar75)) << 0x30 & (undefined  [16])0xffffffff00000000;
513: uVar74 = (undefined2)(uVar5 >> 0x10);
514: uVar78 = SUB162((auVar73 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
515: uVar6 = (ulong)CONCAT24(SUB162((auVar73 & (undefined  [16])0xffffffff00000000) >> 0x50
516: ,0),CONCAT22(uVar93,uVar78));
517: uVar51 = SUB162(auVar73 >> 0x60,0);
518: Var31 = CONCAT28(uVar51,uVar42);
519: uVar96 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar11,CONCAT212(uVar75,
520: SUB1612(auVar61,0))) >> 0x60,0),
521: CONCAT210(uVar48,SUB1610(auVar61,0))) >> 0x50,0),
522: CONCAT28((short)uVar107,SUB168(auVar61,0))) >> 0x40,0);
523: uVar57 = (ulong)CONCAT24(uVar48,CONCAT22(uVar46,uVar47)) & 0xffff0000;
524: auVar92 = CONCAT88(uVar96,(uVar57 >> 0x10) << 0x30) &
525: (undefined  [16])0xffff000000000000;
526: auVar59 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
527: CONCAT214(uVar97,CONCAT212(uVar74,SUB1612(auVar82,
528: 0))) >> 0x60,0),
529: CONCAT210(uVar95,SUB1610(auVar82,0))) >> 0x50,0),
530: CONCAT28(uVar49,SUB168(auVar82,0))) >> 0x40,0),
531: uVar102) &
532: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
533: uVar83)) << 0x20;
534: uVar5 = (ulong)(uVar56 & 0xffff00000000 |
535: (uint6)CONCAT22(SUB162(auVar91 >> 0x60,0),uVar66));
536: uVar32 = CONCAT22(uVar54,uVar53);
537: auVar82 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar32,uVar111),
538: CONCAT22(uVar65,uVar53)) >> 0x10),uVar90))
539: << 0x30 & (undefined  [16])0xffffffff00000000;
540: auVar61 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar54,uVar53)
541: ,uVar111),
542: CONCAT22(uVar65,uVar53)) >> 0x10
543: ),uVar90),uVar76)) << 0x20;
544: auVar126 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
545: undefined2 *)(pauVar39[7] + 4),
546: CONCAT212(SUB162(auVar59 >> 0x30,0),
547: SUB1612(auVar59,0))) >> 0x60,0),
548: CONCAT210(uVar63,SUB1610(auVar59,0))) >> 0x50,0),
549: CONCAT28(uVar83,SUB168(auVar59,0))) >> 0x40,0),
550: *(undefined2 *)pauVar39[7])) << 0x30;
551: uVar46 = (undefined2)(uVar5 >> 0x20);
552: uVar43 = (undefined2)(uVar5 >> 0x10);
553: auVar59 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar94,
554: CONCAT212(SUB162(auVar61 >> 0x30,0),
555: SUB1612(auVar61,0))) >> 0x60,0),
556: CONCAT210(uVar46,SUB1610(auVar61,0))) >> 0x50,0),
557: CONCAT28(uVar76,SUB168(auVar61,0))) >> 0x40,0),
558: uVar43) & 0xffffffffffffffff) << 0x30;
559: auVar61 = auVar59 & (undefined  [16])0xffffffff00000000;
560: auVar82 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
561: (CONCAT214(uVar94,CONCAT212(uVar90,SUB1612(auVar82
562: ,0))) >> 0x60,0),
563: CONCAT210(uVar46,SUB1610(auVar82,0))) >> 0x50,0),
564: CONCAT28(uVar76,SUB168(auVar82,0))) >> 0x40,0),
565: uVar43)) << 0x30) >> 0x20,0) &
566: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
567: uVar7 = (ulong)(uVar79 & 0xffff00000000 |
568: (uint6)CONCAT22(SUB162(auVar101 >> 0x60,0),uVar123));
569: auVar91 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar98,uVar55)
570: ,uVar105),
571: CONCAT22(uVar121,uVar55)) >>
572: 0x10),uVar103),uVar84)) << 0x20;
573: uVar86 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar112,CONCAT212(uVar43,
574: SUB1612(auVar82,0))) >> 0x60,0),
575: CONCAT210(uVar111,SUB1610(auVar82,0))) >> 0x50,0),
576: CONCAT28(uVar110,SUB168(auVar82,0))) >> 0x40,0);
577: uVar5 = (ulong)CONCAT24(uVar111,CONCAT22(SUB162(auVar60 >> 0x70,0),uVar65)) &
578: 0xffff0000;
579: auVar82 = CONCAT88(uVar86,(uVar5 >> 0x10) << 0x30) &
580: (undefined  [16])0xffff000000000000;
581: uVar46 = SUB162(auVar61 >> 0x50,0);
582: uVar67 = SUB162(auVar59 >> 0x60,0);
583: uVar63 = (undefined2)(uVar7 >> 0x10);
584: auVar118 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
585: undefined2 *)(pauVar39[7] + 6),
586: CONCAT212(SUB162(auVar91 >> 0x30,0),
587: SUB1612(auVar91,0))) >> 0x60,0),
588: CONCAT210((short)(uVar7 >> 0x20),
589: SUB1610(auVar91,0))) >> 0x50,0),
590: CONCAT28(uVar84,SUB168(auVar91,0))) >> 0x40,0),
591: uVar63) & 0xffffffffffffffff) << 0x30;
592: uVar94 = (undefined2)(uVar57 >> 0x10);
593: auVar91 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
594: CONCAT214(uVar122,CONCAT212(uVar94,SUB1612(auVar92
595: ,0))) >> 0x60,0),
596: CONCAT210(uVar45,SUB1610(auVar92,0))) >> 0x50,0),
597: CONCAT28(uVar44,SUB168(auVar92,0))) >> 0x40,0),
598: uVar49) &
599: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
600: uVar47)) << 0x20;
601: auVar108 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
602: uVar122,CONCAT212(uVar94,SUB1612(auVar92,0))) >>
603: 0x60,0),CONCAT210(uVar45,SUB1610(auVar92,0))) >>
604: 0x50,0),CONCAT28(uVar44,SUB168(auVar92,0))) >>
605: 0x40,0),uVar49) &
606: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30;
607: auVar92 = auVar108 & (undefined  [16])0xffffffff00000000;
608: uVar127 = SUB162((auVar126 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
609: uVar57 = (ulong)CONCAT24(SUB162((auVar126 & (undefined  [16])0xffffffff00000000) >>
610: 0x50,0),CONCAT22(uVar74,uVar127));
611: uVar128 = SUB162(auVar126 >> 0x70,0);
612: uVar120 = SUB162((auVar118 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
613: uVar122 = SUB162((auVar118 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
614: uVar125 = SUB162(auVar118 >> 0x70,0);
615: auVar108 = auVar108 & (undefined  [16])0xffffffff00000000;
616: uVar45 = SUB162(auVar108 >> 0x50,0);
617: uVar54 = SUB162(auVar108 >> 0x70,0);
618: uVar107 = SUB164(auVar62,0) & 0xffff | uVar107 << 0x10;
619: auVar109 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
620: SUB164(CONCAT214(uVar95,CONCAT212(uVar49,SUB1612(
621: auVar92,0))) >> 0x60,0),
622: CONCAT210(uVar48,SUB1610(auVar92,0))) >> 0x50,0),
623: CONCAT28(uVar47,SUB168(auVar92,0))) >> 0x40,0),
624: uVar50)) << 0x30) >> 0x20,0) &
625: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0),uVar107);
626: auVar132 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar95
627: ,CONCAT212(SUB162(auVar91 >> 0x30,0),
628: SUB1612(auVar91,0))) >> 0x60,0),
629: CONCAT210(uVar48,SUB1610(auVar91,0))) >> 0x50,0),
630: CONCAT28(uVar47,SUB168(auVar91,0))) >> 0x40,0),
631: uVar50) & 0xffffffffffffffff) << 0x30;
632: uVar44 = (undefined2)(uVar5 >> 0x10);
633: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar124
634: ,CONCAT212(uVar44,SUB1612(auVar82,0))) >> 0x60,0),
635: CONCAT210(uVar123,SUB1610(auVar82,0))) >> 0x50,0),
636: CONCAT28(uVar66,SUB168(auVar82,0))) >> 0x40,0),
637: uVar121) &
638: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30;
639: auVar91 = auVar92 & (undefined  [16])0xffffffff00000000;
640: auVar62 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
641: CONCAT214(uVar124,CONCAT212(uVar44,SUB1612(auVar82
642: ,0))) >> 0x60,0),
643: CONCAT210(uVar123,SUB1610(auVar82,0))) >> 0x50,0),
644: CONCAT28(uVar66,SUB168(auVar82,0))) >> 0x40,0),
645: uVar121) &
646: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
647: uVar65)) << 0x20;
648: auVar109 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(
649: CONCAT412(SUB164(CONCAT214(*(undefined2 *)
650: pauVar39[7],
651: CONCAT212(uVar50,
652: SUB1612(auVar109,0))) >> 0x60,0),
653: CONCAT210(uVar45,SUB1610(auVar109,0))) >> 0x50,0),
654: CONCAT28((short)uVar4,SUB168(auVar109,0))) >> 0x40
655: ,0),(((ulong)CONCAT24(uVar45,SUB144(CONCAT122(
656: SUB1612(auVar108 >> 0x20,0),uVar75),0) << 0x10) &
657: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0) &
658: SUB1610((undefined  [16])0xffffffffffffffff >>
659: 0x30,0),
660: (SUB166(auVar109,0) >> 0x10) << 0x20) >> 0x20,0),
661: uVar107) & (undefined  [16])0xffffffff0000ffff;
662: uVar99 = CONCAT22(uVar110,SUB162((auVar60 & (undefined  [16])0xffffffff00000000) >>
663: 0x40,0));
664: auVar60 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(
665: SUB164(CONCAT214(uVar105,CONCAT212(uVar121,SUB1612
666: (auVar91,0))) >> 0x60,0),
667: CONCAT210(uVar111,SUB1610(auVar91,0))) >> 0x50,0),
668: CONCAT28(uVar65,SUB168(auVar91,0))) >> 0x40,0),
669: uVar104)) << 0x30) >> 0x20,0),uVar99);
670: auVar82 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar105
671: ,CONCAT212(SUB162(auVar62 >> 0x30,0),
672: SUB1612(auVar62,0))) >> 0x60,0),
673: CONCAT210(uVar111,SUB1610(auVar62,0))) >> 0x50,0),
674: CONCAT28(uVar65,SUB168(auVar62,0))) >> 0x40,0),
675: uVar104)) << 0x30;
676: auVar92 = auVar92 & (undefined  [16])0xffffffff00000000;
677: uVar44 = SUB162(auVar92 >> 0x50,0);
678: uVar94 = SUB162(auVar92 >> 0x70,0);
679: uVar5 = (ulong)(uVar8 & 0xffff00000000 |
680: (uint6)CONCAT22(SUB162(auVar126 >> 0x60,0),uVar51));
681: uVar133 = SUB162((auVar132 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
682: uVar129 = CONCAT24(SUB162((auVar132 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
683: CONCAT22(SUB162(auVar108 >> 0x60,0),uVar133));
684: uVar134 = SUB162(auVar132 >> 0x60,0);
685: auVar91 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(
686: CONCAT412(SUB164(CONCAT214(uVar63,CONCAT212(
687: uVar104,SUB1612(auVar60,0))) >> 0x60,0),
688: CONCAT210(uVar44,SUB1610(auVar60,0))) >> 0x50,0),
689: CONCAT28(uVar119,SUB168(auVar60,0))) >> 0x40,0),
690: (((ulong)CONCAT24(uVar44,SUB144(CONCAT122(SUB1612(
691: auVar92 >> 0x20,0),uVar43),0) << 0x10) &
692: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
693: (SUB166(auVar60,0) >> 0x10) << 0x20) >> 0x20,0),
694: uVar99) & (undefined  [16])0xffffffff0000ffff;
695: uVar85 = SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
696: uVar79 = CONCAT24(SUB162((auVar82 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
697: CONCAT22(SUB162(auVar92 >> 0x60,0),uVar85));
698: uVar87 = SUB162(auVar82 >> 0x60,0);
699: uVar63 = (undefined2)(uVar57 >> 0x20);
700: uVar75 = (undefined2)(uVar6 >> 0x20);
701: uVar50 = (undefined2)(uVar57 >> 0x10);
702: uVar43 = (undefined2)(uVar6 >> 0x10);
703: auVar62 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
704: CONCAT214(uVar12,CONCAT212(uVar9,CONCAT210(uVar52,
705: Var31))) >> 0x60,0),CONCAT210(uVar63,Var31)) >>
706: 0x50,0),CONCAT28(uVar75,uVar42)) >> 0x40,0),uVar50
707: ),uVar43) & (undefined  [12])0xffffffffffffffff)
708: << 0x20;
709: uVar8 = SUB166(CONCAT412(SUB164(CONCAT214(uVar12,CONCAT212(uVar9,CONCAT210(uVar52,
710: Var31))) >> 0x60,0),CONCAT210(uVar63,Var31)) >>
711: 0x50,0);
712: auVar92 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar8,CONCAT28(uVar75,
713: uVar42)) >> 0x40,0),uVar50) & 0xffffffffffffffff)
714: << 0x30) >> 0x20,0) &
715: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
716: uVar45 = (undefined2)(uVar5 >> 0x20);
717: uVar44 = (undefined2)(uVar5 >> 0x10);
718: auVar60 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar97,
719: CONCAT212(SUB162(auVar62 >> 0x30,0),
720: SUB1612(auVar62,0))) >> 0x60,0),
721: CONCAT210(uVar45,SUB1610(auVar62,0))) >> 0x50,0),
722: CONCAT28(uVar43,SUB168(auVar62,0))) >> 0x40,0),
723: uVar44) & 0xffffffffffffffff) << 0x30;
724: auVar62 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
725: (CONCAT214(uVar97,CONCAT212(uVar50,SUB1612(auVar92
726: ,0))) >> 0x60,0),
727: CONCAT210(uVar45,SUB1610(auVar92,0))) >> 0x50,0),
728: CONCAT28(uVar93,SUB168(auVar92,0))) >> 0x40,0),
729: uVar44)) << 0x30) >> 0x20,0) &
730: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
731: uVar57 = (ulong)CONCAT24(uVar63,CONCAT22(SUB162(auVar73 >> 0x70,0),uVar75)) &
732: 0xffff0000;
733: auVar92 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
734: CONCAT214(uVar128,CONCAT212(uVar44,SUB1612(auVar62
735: ,0))) >> 0x60,0),
736: CONCAT210(uVar63,SUB1610(auVar62,0))) >> 0x50,0),
737: CONCAT28(uVar127,SUB168(auVar62,0))) >> 0x40,0),
738: (uVar57 >> 0x10) << 0x30) >> 0x20,0) &
739: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
740: CONCAT22(uVar75,uVar78));
741: uVar5 = (ulong)(((uint6)uVar32 & 0xffff0000) << 0x10 |
742: (uint6)CONCAT22(SUB162(auVar118 >> 0x60,0),uVar67));
743: auVar73 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar13,uVar10),uVar122),
744: CONCAT22(uVar46,uVar10)) >> 0x10),uVar55))
745: << 0x30 & (undefined  [16])0xffffffff00000000;
746: auVar62 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar13,uVar10)
747: ,uVar122),
748: CONCAT22(uVar46,uVar10)) >> 0x10
749: ),uVar55),uVar53)) << 0x20;
750: uVar43 = (undefined2)(uVar5 >> 0x20);
751: uVar45 = (undefined2)(uVar5 >> 0x10);
752: auVar62 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar98,
753: CONCAT212(SUB162(auVar62 >> 0x30,0),
754: SUB1612(auVar62,0))) >> 0x60,0),
755: CONCAT210(uVar43,SUB1610(auVar62,0))) >> 0x50,0),
756: CONCAT28(uVar53,SUB168(auVar62,0))) >> 0x40,0),
757: uVar45) & 0xffffffffffffffff) << 0x30;
758: auVar73 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164
759: (CONCAT214(uVar98,CONCAT212(uVar55,SUB1612(auVar73
760: ,0))) >> 0x60,0),
761: CONCAT210(uVar43,SUB1610(auVar73,0))) >> 0x50,0),
762: CONCAT28(uVar53,SUB168(auVar73,0))) >> 0x40,0),
763: uVar45)) << 0x30) >> 0x20,0) &
764: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
765: uVar64 = SUB162((auVar62 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
766: uVar43 = SUB162((auVar62 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
767: uVar56 = CONCAT24(uVar43,CONCAT22(uVar10,uVar64));
768: uVar42 = CONCAT26(*(undefined2 *)(pauVar39[3] + 0xe),uVar56);
769: uVar68 = SUB162(auVar62 >> 0x60,0);
770: uVar5 = (ulong)CONCAT24(uVar122,CONCAT22(SUB162(auVar59 >> 0x70,0),uVar46)) &
771: 0xffff0000;
772: auVar59 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
773: CONCAT214(uVar125,CONCAT212(uVar45,SUB1612(auVar73
774: ,0))) >> 0x60,0),
775: CONCAT210(uVar122,SUB1610(auVar73,0))) >> 0x50,0),
776: CONCAT28(uVar120,SUB168(auVar73,0))) >> 0x40,0),
777: (uVar5 >> 0x10) << 0x30) >> 0x20,0) &
778: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
779: SUB164(auVar61 >> 0x40,0));
780: auVar71 = ZEXT1012(CONCAT28(SUB162(auVar109 >> 0x60,0),
781: (ulong)(CONCAT24(SUB162(auVar109 >> 0x50,0),
782: SUB164(auVar72,0)) & 0xffff0000ffff)));
783: uVar113 = SUB162(auVar109 >> 0x70,0);
784: fVar17 = (float)uVar4 * 1.0;
785: fVar18 = (float)SUB124(auVar71 >> 0x20,0) * 0.785695;
786: dVar116 = (double)((uint)((unkuint10)
787: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(
788: auVar109 >> 0x30,0),SUB1612(auVar109,0)) >> 0x50,0
789: ),CONCAT28(SUB162(auVar109 >> 0x20,0),
790: SUB168(auVar109,0))) >> 0x40,0),
791: SUB168(auVar109,0)) >> 0x30,0) >> 0x10) & 0xffff);
792: fVar16 = (float)(int)((ulong)dVar116 >> 0x20) * 1.175876;
793: fVar137 = (float)((double)SUB164(auVar109,0) * 1.0);
794: auVar100 = ZEXT1012(CONCAT28(SUB162(auVar91 >> 0x60,0),
795: (ulong)CONCAT24(SUB162(auVar91 >> 0x50,0),(uint)uVar119))
796: );
797: uVar106 = SUB162(auVar91 >> 0x70,0);
798: Var142 = (unkuint10)
799: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212((short)(uVar57 >> 0x10),
800: SUB1612(auVar92,0)) >> 0x50
801: ,0),
802: CONCAT28(uVar51,SUB168(auVar92,0))) >> 0x40,
803: 0),SUB168(auVar92,0)) >> 0x30,0) &
804: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
805: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
806: auVar58 = ZEXT1012(CONCAT28(uVar44,(ulong)CONCAT24(uVar63,(uint)uVar127)));
807: fVar114 = (float)(dVar116 * 1.306562965);
808: fVar19 = (float)SUB164(ZEXT1416(CONCAT212(uVar113,auVar71)) >> 0x40,0) * 0.541196;
809: fVar20 = (float)(uint)uVar113 * 0.2758994;
810: fVar22 = (float)(uint)uVar119 * 1.0 * 1.38704;
811: fVar23 = (float)SUB124(auVar100 >> 0x20,0) * 0.785695 * 1.38704;
812: dVar117 = (double)((uint)((unkuint10)
813: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(
814: auVar91 >> 0x30,0),SUB1612(auVar91,0)) >> 0x50,0),
815: CONCAT28(SUB162(auVar91 >> 0x20,0),
816: SUB168(auVar91,0))) >> 0x40,0),
817: SUB168(auVar91,0)) >> 0x30,0) >> 0x10) & 0xffff);
818: fVar21 = (float)(int)((ulong)(double)SUB164(auVar91,0) >> 0x20) * 1.38704 * 1.38704;
819: fVar135 = (float)((double)SUB164(auVar91,0) * 1.0 * 1.387039845);
820: fVar24 = (float)(uint)uVar78 * 1.0 * 1.306563;
821: fVar26 = (float)(uint)uVar127 * 1.0 * 1.306563;
822: fVar27 = (float)SUB124(auVar58 >> 0x20,0) * 0.785695 * 1.306563;
823: auVar88 = ZEXT1012(CONCAT28(uVar45,(ulong)CONCAT24(uVar122,(uint)uVar120)));
824: Var143 = (unkuint10)
825: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212((short)(uVar5 >> 0x10),
826: SUB1612(auVar59,0)) >> 0x50
827: ,0),
828: CONCAT28(uVar67,SUB168(auVar59,0))) >> 0x40,
829: 0),SUB168(auVar59,0)) >> 0x30,0) &
830: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
831: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
832: dVar116 = (double)(int)(Var142 >> 0x10);
833: fVar25 = (float)(int)((ulong)dVar116 >> 0x20) * 1.175876 * 1.306563;
834: fVar115 = (float)(dVar116 * 1.306562965 * 1.306562965);
835: fVar28 = (float)SUB164(ZEXT1416(CONCAT212(uVar128,auVar58)) >> 0x40,0) * 0.541196 *
836: 1.306563;
837: fVar29 = (float)(uint)uVar128 * 0.2758994 * 1.306563;
838: dVar136 = (double)((uint)(Var143 >> 0x10) & 0xffff);
839: auVar131 = ZEXT1012(CONCAT28(SUB162(auVar132 >> 0x70,0),
840: (ulong)CONCAT24(uVar54,(uint)uVar134)));
841: auVar72 = ZEXT1416(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(uVar11,CONCAT210(uVar54,
842: CONCAT28(uVar134,uVar96))) >> 0x50,0),
843: CONCAT28((short)((ulong)uVar129 >> 0x20),uVar96))
844: >> 0x40,0),uVar96) &
845: (undefined  [14])0xffffffffffffffff) &
846: (undefined  [16])0xffffffffffffffff;
847: dVar138 = (double)SUB164(auVar72 >> 0x40,0);
848: dVar130 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar39[7] + 8),auVar131)
849: ) >> 0x40,0);
850: auVar58 = ZEXT1012(CONCAT28(SUB162(auVar82 >> 0x70,0),
851: (ulong)CONCAT24(uVar94,(uint)uVar87)));
852: dVar80 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar101 >> 0x70,0),auVar58)) >>
853: 0x40,0);
854: fVar30 = (float)SUB124(auVar58 >> 0x20,0) * 0.785695 * 0.785695;
855: auVar71 = ZEXT1012(CONCAT28(SUB162(auVar60 >> 0x70,0),(ulong)(uVar8 & 0xffff00000000))
856: );
857: dVar81 = (double)(uint)SUB162((auVar60 & (undefined  [16])0xffffffff00000000) >> 0x40,
858: 0);
859: dVar141 = (double)(uint)SUB162((auVar60 & (undefined  [16])0xffffffff00000000) >> 0x50
860: ,0);
861: dVar69 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar39[7] + 0xc),auVar71)
862: ) >> 0x40,0);
863: dVar139 = SUB168(_DAT_00168f30,0);
864: dVar140 = SUB168(_DAT_00168f30 >> 0x40,0);
865: auVar58 = ZEXT1012(CONCAT28(SUB162(auVar62 >> 0x70,0),
866: (ulong)(((uint6)CONCAT22(uVar13,uVar10) & 0xffff0000) <<
867: 0x10)));
868: Var77 = (unkuint10)
869: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(*(undefined2 *)
870: (pauVar39[3] + 0xe),
871: CONCAT210(uVar13,CONCAT28(
872: uVar68,uVar42))) >> 0x50,0),
873: CONCAT28(uVar43,uVar42)) >> 0x40,0),uVar42) >>
874: 0x30,0) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
875: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
876: dVar70 = (double)(int)(Var77 >> 0x10);
877: dVar116 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar39[7] + 0xe),auVar58
878: )) >> 0x40,0);
879: uVar42 = CONCAT44((float)(uint)uVar85 * 1.0 * 0.785695,(float)(uint)uVar133 * 1.0);
880: *(undefined8 *)pauVar36[1] = uVar42;
881: *(long *)(pauVar36[1] + 8) =
882: SUB168(CONCAT412((float)((double)(uint)uVar64 * 1.0 * dVar139),
883: CONCAT48((float)(dVar81 * 1.0 * 0.5411961),uVar42)) >> 0x40,0);
884: uVar57 = SUB168(CONCAT412((float)SUB164(CONCAT106((unkuint10)
885: (SUB148(CONCAT68(SUB146(CONCAT410(
886: SUB144(CONCAT212(uVar112,CONCAT210(uVar94,CONCAT28
887: (uVar87,uVar86))) >> 0x50,0),
888: CONCAT28((short)((ulong)uVar79 >> 0x20),uVar86))
889: >> 0x40,0),uVar86) >> 0x30,0) & 0xffff) &
890: SUB1610((undefined  [16])0xffffffffffffffff >>
891: 0x30,0) &
892: SUB1610((undefined  [16])0xffffffffffffffff >>
893: 0x30,0),(uVar79 >> 0x10) << 0x20) >> 0x20,
894: 0) * 1.38704 * 0.785695,
895: CONCAT48(fVar21,CONCAT44(fVar21,fVar135))) >> 0x40,0) &
896: 0xffffffff00000000 |
897: (ulong)(uint)((float)SUB164(CONCAT106(SUB1610(auVar72 >> 0x30,0),
898: (uVar129 >> 0x10) << 0x20) >> 0x20,0) *
899: 1.38704);
900: *(ulong *)*pauVar36 = CONCAT44(fVar135,fVar137);
901: *(long *)(*pauVar36 + 8) =
902: SUB168(CONCAT412((float)(uint)SUB162(auVar61 >> 0x40,0) * 1.0 * 1.175876,
903: CONCAT48(fVar24,CONCAT44(fVar24,fVar137))) >> 0x40,0);
904: *(ulong *)pauVar36[3] = uVar57;
905: *(ulong *)pauVar36[2] =
906: CONCAT44(fVar21,(float)(int)((ulong)(double)SUB164(auVar109,0) >> 0x20) * 1.38704
907: );
908: *(float *)pauVar36[3] =
909: (float)SUB164(CONCAT106(Var142,(SUB166(auVar92,0) >> 0x10) << 0x20) >> 0x20,0) *
910: 1.38704 * 1.306563;
911: *(float *)(pauVar36[3] + 4) =
912: (float)SUB164(CONCAT106(Var143,(SUB166(auVar59,0) >> 0x10) << 0x20) >> 0x20,0) *
913: 1.38704 * 1.175876;
914: *(long *)(pauVar36[3] + 8) =
915: SUB168(CONCAT412((float)((double)SUB164(CONCAT106(Var77,(uVar56 >> 0x10) << 0x20)
916: >> 0x20,0) * 1.387039845 * dVar140),
917: CONCAT48((float)(int)((ulong)dVar81 >> 0x20) * 1.38704 *
918: 0.541196,uVar57)) >> 0x40,0);
919: *(ulong *)pauVar36[4] = CONCAT44((float)(dVar117 * 1.306562965 * 1.387039845),fVar114)
920: ;
921: *(long *)(pauVar36[4] + 8) =
922: SUB168(CONCAT412((float)(dVar136 * 1.306562965 * 1.175875602),
923: CONCAT48(fVar115,CONCAT44(fVar115,fVar114))) >> 0x40,0);
924: *(float *)pauVar36[5] = (float)(dVar138 * 1.306562965);
925: *(undefined4 *)(pauVar36[5] + 4) = 0;
926: *(float *)pauVar36[6] = (float)(dVar141 * 1.306562965 * 0.5411961);
927: *(float *)(pauVar36[6] + 4) = (float)(dVar70 * 1.306562965 * dVar139);
928: *(float *)pauVar36[7] = (float)(int)((ulong)dVar138 >> 0x20) * 1.175876;
929: *(undefined4 *)(pauVar36[7] + 4) = 0;
930: *(ulong *)pauVar36[6] =
931: CONCAT44((float)(int)((ulong)dVar117 >> 0x20) * 1.175876 * 1.38704,fVar16);
932: *(long *)(pauVar36[6] + 8) =
933: SUB168(CONCAT412((float)(int)((ulong)dVar136 >> 0x20) * 1.175876 * 1.175876,
934: CONCAT48(fVar25,CONCAT44(fVar25,fVar16))) >> 0x40,0);
935: *(float *)pauVar36[8] = (float)(int)((ulong)dVar141 >> 0x20) * 1.175876 * 0.541196;
936: *(float *)(pauVar36[8] + 4) =
937: (float)((double)(int)((ulong)dVar70 >> 0x20) * 1.175875602 * dVar140);
938: uVar57 = CONCAT44(fVar30,(float)(uint)uVar87 * 1.0 * 0.785695) << 0x20 |
939: (ulong)(uint)((float)(uint)uVar134 * 1.0);
940: *(ulong *)pauVar36[9] = uVar57;
941: *(ulong *)pauVar36[8] = CONCAT44(fVar22,fVar17);
942: *(long *)(pauVar36[8] + 8) =
943: SUB168(CONCAT412((float)(uint)uVar120 * 1.0 * 1.175876,
944: CONCAT48(fVar26,CONCAT44(fVar26,fVar17))) >> 0x40,0);
945: *(long *)(pauVar36[9] + 8) =
946: SUB168(CONCAT412((float)((double)(uint)uVar68 * 1.0 * dVar139),
947: CONCAT48((float)(uint)SUB162(auVar60 >> 0x60,0) * 1.0 * 0.541196
948: ,uVar57)) >> 0x40,0);
949: uVar57 = SUB168(CONCAT412(fVar30,CONCAT48(fVar23,CONCAT44(fVar23,fVar22))) >> 0x40,0)
950: & 0xffffffff00000000 |
951: (ulong)(uint)((float)SUB124(auVar131 >> 0x20,0) * 0.785695);
952: *(ulong *)pauVar36[0xb] = uVar57;
953: *(long *)(pauVar36[0xb] + 8) =
954: SUB168(CONCAT412((float)((double)SUB124(auVar58 >> 0x20,0) * 0.785694958 *
955: dVar140),
956: CONCAT48((float)SUB124(auVar71 >> 0x20,0) * 0.785695 * 0.541196,
957: uVar57)) >> 0x40,0);
958: *(ulong *)pauVar36[10] = CONCAT44(fVar23,fVar18);
959: *(long *)(pauVar36[10] + 8) =
960: SUB168(CONCAT412((float)SUB124(auVar88 >> 0x20,0) * 0.785695 * 1.175876,
961: CONCAT48(fVar27,CONCAT44(fVar27,fVar18))) >> 0x40,0);
962: *(float *)pauVar36[0xd] = (float)(dVar130 * 0.5411961);
963: *(float *)(pauVar36[0xd] + 4) = (float)(dVar80 * 0.5411961 * 0.785694958);
964: *(float *)pauVar36[0xe] = (float)(dVar69 * 0.5411961 * 0.5411961);
965: *(float *)(pauVar36[0xe] + 4) = (float)(dVar116 * 0.5411961 * dVar139);
966: uVar42 = CONCAT44((float)(int)((ulong)dVar80 >> 0x20) * 0.2758994 * 0.785695,
967: (float)(int)((ulong)dVar130 >> 0x20) * 0.2758994);
968: *(ulong *)pauVar36[0xc] =
969: CONCAT44((float)SUB164(ZEXT1416(CONCAT212(uVar106,auVar100)) >> 0x40,0) *
970: 0.541196 * 1.38704,fVar19);
971: *(long *)(pauVar36[0xc] + 8) =
972: SUB168(CONCAT412((float)SUB164(ZEXT1416(CONCAT212(uVar125,auVar88)) >> 0x40,0) *
973: 0.541196 * 1.175876,CONCAT48(fVar28,CONCAT44(fVar28,fVar19))) >>
974: 0x40,0);
975: *(undefined8 *)pauVar36[0xf] = uVar42;
976: *(ulong *)pauVar36[0xe] = CONCAT44((float)(uint)uVar106 * 0.2758994 * 1.38704,fVar20);
977: *(long *)(pauVar36[0xe] + 8) =
978: SUB168(CONCAT412((float)(uint)uVar125 * 0.2758994 * 1.175876,
979: CONCAT48(fVar29,CONCAT44(fVar29,fVar20))) >> 0x40,0);
980: *(long *)(pauVar36[0xf] + 8) =
981: SUB168(CONCAT412((float)((double)(int)((ulong)dVar116 >> 0x20) * 0.275899379 *
982: dVar140),
983: CONCAT48((float)(int)((ulong)dVar69 >> 0x20) * 0.2758994 *
984: 0.541196,uVar42)) >> 0x40,0);
985: }
986: }
987: else {
988: if (iVar40 == 0) {
989: pauVar36 = *(undefined (**) [16])(pcVar38 + 0x58);
990: if ((pauVar36 < pauVar39[1]) && (pauVar39 < pauVar36[1])) {
991: lVar35 = 0;
992: do {
993: *(undefined2 *)(*pauVar36 + lVar35) = *(undefined2 *)(*pauVar39 + lVar35);
994: lVar35 = lVar35 + 2;
995: } while (lVar35 != 0x80);
996: }
997: else {
998: uVar99 = *(undefined4 *)(*pauVar39 + 4);
999: uVar14 = *(undefined4 *)(*pauVar39 + 8);
1000: uVar15 = *(undefined4 *)(*pauVar39 + 0xc);
1001: *(undefined4 *)*pauVar36 = *(undefined4 *)*pauVar39;
1002: *(undefined4 *)(*pauVar36 + 4) = uVar99;
1003: *(undefined4 *)(*pauVar36 + 8) = uVar14;
1004: *(undefined4 *)(*pauVar36 + 0xc) = uVar15;
1005: uVar99 = *(undefined4 *)(pauVar39[1] + 4);
1006: uVar14 = *(undefined4 *)(pauVar39[1] + 8);
1007: uVar15 = *(undefined4 *)(pauVar39[1] + 0xc);
1008: *(undefined4 *)pauVar36[1] = *(undefined4 *)pauVar39[1];
1009: *(undefined4 *)(pauVar36[1] + 4) = uVar99;
1010: *(undefined4 *)(pauVar36[1] + 8) = uVar14;
1011: *(undefined4 *)(pauVar36[1] + 0xc) = uVar15;
1012: uVar99 = *(undefined4 *)(pauVar39[2] + 4);
1013: uVar14 = *(undefined4 *)(pauVar39[2] + 8);
1014: uVar15 = *(undefined4 *)(pauVar39[2] + 0xc);
1015: *(undefined4 *)pauVar36[2] = *(undefined4 *)pauVar39[2];
1016: *(undefined4 *)(pauVar36[2] + 4) = uVar99;
1017: *(undefined4 *)(pauVar36[2] + 8) = uVar14;
1018: *(undefined4 *)(pauVar36[2] + 0xc) = uVar15;
1019: uVar99 = *(undefined4 *)(pauVar39[3] + 4);
1020: uVar14 = *(undefined4 *)(pauVar39[3] + 8);
1021: uVar15 = *(undefined4 *)(pauVar39[3] + 0xc);
1022: *(undefined4 *)pauVar36[3] = *(undefined4 *)pauVar39[3];
1023: *(undefined4 *)(pauVar36[3] + 4) = uVar99;
1024: *(undefined4 *)(pauVar36[3] + 8) = uVar14;
1025: *(undefined4 *)(pauVar36[3] + 0xc) = uVar15;
1026: uVar99 = *(undefined4 *)(pauVar39[4] + 4);
1027: uVar14 = *(undefined4 *)(pauVar39[4] + 8);
1028: uVar15 = *(undefined4 *)(pauVar39[4] + 0xc);
1029: *(undefined4 *)pauVar36[4] = *(undefined4 *)pauVar39[4];
1030: *(undefined4 *)(pauVar36[4] + 4) = uVar99;
1031: *(undefined4 *)(pauVar36[4] + 8) = uVar14;
1032: *(undefined4 *)(pauVar36[4] + 0xc) = uVar15;
1033: uVar99 = *(undefined4 *)(pauVar39[5] + 4);
1034: uVar14 = *(undefined4 *)(pauVar39[5] + 8);
1035: uVar15 = *(undefined4 *)(pauVar39[5] + 0xc);
1036: *(undefined4 *)pauVar36[5] = *(undefined4 *)pauVar39[5];
1037: *(undefined4 *)(pauVar36[5] + 4) = uVar99;
1038: *(undefined4 *)(pauVar36[5] + 8) = uVar14;
1039: *(undefined4 *)(pauVar36[5] + 0xc) = uVar15;
1040: uVar99 = *(undefined4 *)(pauVar39[6] + 4);
1041: uVar14 = *(undefined4 *)(pauVar39[6] + 8);
1042: uVar15 = *(undefined4 *)(pauVar39[6] + 0xc);
1043: *(undefined4 *)pauVar36[6] = *(undefined4 *)pauVar39[6];
1044: *(undefined4 *)(pauVar36[6] + 4) = uVar99;
1045: *(undefined4 *)(pauVar36[6] + 8) = uVar14;
1046: *(undefined4 *)(pauVar36[6] + 0xc) = uVar15;
1047: pauVar36[7] = pauVar39[7];
1048: }
1049: }
1050: else {
1051: ppcVar3 = (code **)*param_1;
1052: *(undefined4 *)(ppcVar3 + 5) = 0x30;
1053: (**ppcVar3)(param_1);
1054: }
1055: }
1056: }
1057: }
1058: iVar33 = (int)lVar37 + 1;
1059: pcVar38 = pcVar38 + 0x60;
1060: lVar37 = lVar37 + 1;
1061: } while (*(int *)(param_1 + 7) != iVar33 && iVar33 <= *(int *)(param_1 + 7));
1062: }
1063: return;
1064: }
1065: 
