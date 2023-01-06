1: 
2: void FUN_0012ece0(code **param_1)
3: 
4: {
5: undefined auVar1 [16];
6: undefined auVar2 [16];
7: code *pcVar3;
8: undefined (*pauVar4) [16];
9: code **ppcVar5;
10: undefined8 *puVar6;
11: undefined (*pauVar7) [16];
12: undefined (*pauVar8) [16];
13: ulong uVar9;
14: ulong uVar10;
15: ulong uVar11;
16: uint6 uVar12;
17: undefined2 uVar13;
18: undefined2 uVar14;
19: undefined2 uVar15;
20: undefined2 uVar16;
21: undefined4 uVar17;
22: undefined4 uVar18;
23: float fVar19;
24: float fVar20;
25: float fVar21;
26: float fVar22;
27: float fVar23;
28: float fVar24;
29: float fVar25;
30: float fVar26;
31: float fVar27;
32: float fVar28;
33: unkbyte10 Var29;
34: uint uVar30;
35: uint6 uVar31;
36: undefined4 *puVar32;
37: undefined (*pauVar33) [16];
38: long lVar34;
39: uint uVar35;
40: code *pcVar36;
41: long lVar37;
42: int iVar38;
43: long lVar39;
44: int iVar40;
45: int iVar41;
46: int iVar42;
47: int iVar43;
48: code *pcVar44;
49: uint6 uVar45;
50: ushort uVar53;
51: undefined2 uVar56;
52: undefined auVar47 [12];
53: ushort uVar52;
54: undefined2 uVar57;
55: ushort uVar59;
56: undefined auVar48 [16];
57: undefined2 uVar54;
58: undefined auVar49 [16];
59: undefined2 uVar55;
60: undefined2 uVar58;
61: undefined auVar50 [16];
62: double dVar60;
63: double dVar61;
64: undefined2 uVar71;
65: undefined auVar62 [12];
66: undefined2 uVar65;
67: undefined2 uVar66;
68: ushort uVar73;
69: uint6 uVar72;
70: undefined auVar63 [16];
71: undefined2 uVar67;
72: undefined2 uVar70;
73: undefined auVar64 [16];
74: unkuint10 Var68;
75: undefined2 uVar76;
76: undefined2 uVar77;
77: ushort uVar78;
78: ushort uVar79;
79: undefined2 uVar80;
80: undefined2 uVar81;
81: undefined2 uVar82;
82: undefined2 uVar83;
83: undefined auVar75 [16];
84: undefined2 uVar85;
85: undefined2 uVar86;
86: undefined2 uVar87;
87: undefined2 uVar88;
88: undefined2 uVar90;
89: undefined auVar84 [16];
90: ulong uVar89;
91: undefined auVar91 [12];
92: undefined2 uVar94;
93: undefined2 uVar95;
94: undefined2 uVar96;
95: undefined2 uVar97;
96: undefined auVar92 [16];
97: float fVar98;
98: double dVar99;
99: double dVar100;
100: undefined auVar101 [12];
101: undefined2 uVar103;
102: undefined2 uVar104;
103: undefined2 uVar105;
104: undefined2 uVar106;
105: undefined2 uVar107;
106: undefined2 uVar108;
107: undefined auVar102 [16];
108: float fVar109;
109: double dVar110;
110: undefined auVar111 [12];
111: undefined2 uVar113;
112: undefined2 uVar114;
113: undefined2 uVar115;
114: undefined2 uVar116;
115: undefined2 uVar117;
116: undefined auVar112 [16];
117: double dVar118;
118: double dVar119;
119: undefined auVar120 [12];
120: undefined2 uVar122;
121: undefined2 uVar123;
122: undefined2 uVar124;
123: undefined auVar121 [16];
124: uint6 uVar125;
125: double dVar126;
126: undefined auVar127 [12];
127: ushort uVar129;
128: ushort uVar131;
129: undefined8 uVar130;
130: undefined auVar128 [16];
131: uint6 uVar132;
132: double dVar133;
133: undefined auVar134 [12];
134: ushort uVar137;
135: ushort uVar139;
136: undefined auVar135 [16];
137: undefined auVar136 [16];
138: double dVar140;
139: double dVar141;
140: ushort uVar142;
141: undefined2 uVar143;
142: uint6 uVar144;
143: undefined8 uVar46;
144: undefined2 uVar51;
145: undefined8 uVar69;
146: undefined4 uVar74;
147: undefined auVar93 [16];
148: undefined8 uVar138;
149: 
150: pcVar3 = param_1[0x4b];
151: pcVar36 = param_1[0x26];
152: if (0 < *(int *)(param_1 + 7)) {
153: lVar37 = 1;
154: pcVar44 = (code *)0x0;
155: iVar43 = 0;
156: do {
157: uVar74 = *(undefined4 *)(pcVar36 + 0x24);
158: switch(uVar74) {
159: default:
160: ppcVar5 = (code **)*param_1;
161: *(undefined4 *)(ppcVar5 + 5) = 7;
162: *(undefined4 *)((long)ppcVar5 + 0x2c) = uVar74;
163: (**ppcVar5)(param_1);
164: break;
165: case 1:
166: pcVar44 = FUN_00144f30;
167: iVar43 = 0;
168: break;
169: case 2:
170: iVar43 = FUN_0016c190();
171: if (iVar43 == 0) {
172: pcVar44 = FUN_00144c40;
173: }
174: else {
175: pcVar44 = FUN_0016c1d0;
176: iVar43 = 0;
177: }
178: break;
179: case 3:
180: pcVar44 = FUN_001414e0;
181: iVar43 = 0;
182: break;
183: case 4:
184: iVar43 = FUN_0016c1a0();
185: if (iVar43 == 0) {
186: pcVar44 = FUN_001448c0;
187: }
188: else {
189: pcVar44 = FUN_0016c1e0;
190: iVar43 = 0;
191: }
192: break;
193: case 5:
194: pcVar44 = FUN_00140b60;
195: iVar43 = 0;
196: break;
197: case 6:
198: pcVar44 = FUN_001408c0;
199: iVar43 = 0;
200: break;
201: case 7:
202: pcVar44 = FUN_001404f0;
203: iVar43 = 0;
204: break;
205: case 8:
206: iVar38 = *(int *)(param_1 + 0xc);
207: if (iVar38 == 1) {
208: iVar43 = FUN_0016c220();
209: if (iVar43 == 0) {
210: pcVar44 = FUN_0013fad0;
211: iVar43 = 1;
212: }
213: else {
214: pcVar44 = FUN_0016c250;
215: iVar43 = 1;
216: }
217: }
218: else {
219: if (iVar38 == 0) {
220: iVar43 = FUN_0016c210();
221: if (iVar43 == 0) {
222: pcVar44 = FUN_0013ff70;
223: }
224: else {
225: pcVar44 = FUN_0016c240;
226: iVar43 = 0;
227: }
228: }
229: else {
230: if (iVar38 == 2) {
231: iVar43 = FUN_0016c230();
232: if (iVar43 == 0) {
233: pcVar44 = FUN_0013f5d0;
234: iVar43 = 2;
235: }
236: else {
237: pcVar44 = FUN_0016c260;
238: iVar43 = 2;
239: }
240: }
241: else {
242: ppcVar5 = (code **)*param_1;
243: *(undefined4 *)(ppcVar5 + 5) = 0x30;
244: (**ppcVar5)(param_1);
245: }
246: }
247: }
248: break;
249: case 9:
250: pcVar44 = FUN_001417e0;
251: iVar43 = 0;
252: break;
253: case 10:
254: pcVar44 = FUN_00141c40;
255: iVar43 = 0;
256: break;
257: case 0xb:
258: pcVar44 = FUN_00142100;
259: iVar43 = 0;
260: break;
261: case 0xc:
262: pcVar44 = FUN_001426f0;
263: iVar43 = 0;
264: break;
265: case 0xd:
266: pcVar44 = FUN_00142ca0;
267: iVar43 = 0;
268: break;
269: case 0xe:
270: pcVar44 = FUN_00143380;
271: iVar43 = 0;
272: break;
273: case 0xf:
274: pcVar44 = FUN_00143a20;
275: iVar43 = 0;
276: break;
277: case 0x10:
278: pcVar44 = FUN_00144110;
279: iVar43 = 0;
280: }
281: iVar38 = *(int *)(pcVar36 + 0x30);
282: *(code **)(pcVar3 + lVar37 * 8) = pcVar44;
283: if (((iVar38 != 0) && (*(int *)(pcVar3 + lVar37 * 4 + 0x54) != iVar43)) &&
284: (pauVar4 = *(undefined (**) [16])(pcVar36 + 0x50), pauVar4 != (undefined (*) [16])0x0)) {
285: *(int *)(pcVar3 + lVar37 * 4 + 0x54) = iVar43;
286: if (iVar43 == 1) {
287: lVar34 = *(long *)(pcVar36 + 0x58);
288: lVar39 = 0;
289: do {
290: *(short *)(lVar34 + lVar39) =
291: (short)((long)((long)*(short *)(&DAT_0018d160 + lVar39) *
292: (ulong)*(ushort *)(*pauVar4 + lVar39) + 0x800) >> 0xc);
293: lVar39 = lVar39 + 2;
294: } while (lVar39 != 0x80);
295: }
296: else {
297: if (iVar43 == 2) {
298: auVar1 = *pauVar4;
299: puVar6 = *(undefined8 **)(pcVar36 + 0x58);
300: uVar56 = *(undefined2 *)pauVar4[1];
301: uVar13 = *(undefined2 *)(pauVar4[1] + 2);
302: uVar55 = *(undefined2 *)(pauVar4[1] + 4);
303: uVar58 = *(undefined2 *)(pauVar4[1] + 8);
304: uVar71 = *(undefined2 *)(pauVar4[1] + 0xc);
305: uVar143 = *(undefined2 *)(pauVar4[1] + 0xe);
306: uVar66 = SUB162(auVar1 >> 0x30,0);
307: uVar65 = SUB162(auVar1 >> 0x20,0);
308: uVar72 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar4[1] + 6),
309: CONCAT212(uVar66,SUB1612(auVar1,0))) >> 0x60,
310: 0),CONCAT210(uVar55,SUB1610(auVar1,0))) >> 0x50,0);
311: auVar49 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar72,CONCAT28(uVar65,SUB168(auVar1,0)))
312: >> 0x40,0),uVar13)) << 0x30 &
313: (undefined  [16])0xffffffff00000000;
314: auVar2 = pauVar4[2];
315: uVar107 = SUB162(auVar1 >> 0x40,0);
316: uVar106 = SUB162(auVar1 >> 0x50,0);
317: uVar108 = SUB162(auVar1 >> 0x70,0);
318: uVar51 = SUB162(auVar1 >> 0x10,0);
319: auVar48 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
320: (*(undefined2 *)(pauVar4[1] + 6),
321: CONCAT212(uVar66,SUB1612(auVar1,0))) >> 0x60,0),
322: CONCAT210(uVar55,SUB1610(auVar1,0))) >> 0x50,0),
323: CONCAT28(uVar65,SUB168(auVar1,0))) >> 0x40,0),
324: uVar13),uVar51)) << 0x20;
325: uVar85 = *(undefined2 *)pauVar4[3];
326: uVar70 = *(undefined2 *)(pauVar4[3] + 4);
327: uVar81 = *(undefined2 *)(pauVar4[3] + 6);
328: uVar14 = *(undefined2 *)(pauVar4[3] + 0xc);
329: auVar49 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
330: undefined2 *)(pauVar4[1] + 10),
331: CONCAT212(uVar13,SUB1612(auVar49,0))) >> 0x60,0),
332: CONCAT210(uVar106,SUB1610(auVar49,0))) >> 0x50,0),
333: CONCAT28(uVar51,SUB168(auVar49,0))) >> 0x40,0),
334: uVar58)) << 0x30 & (undefined  [16])0xffffffff00000000;
335: auVar50 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
336: undefined2 *)(pauVar4[1] + 10),
337: CONCAT212(SUB162(auVar48 >> 0x30,0),
338: SUB1612(auVar48,0))) >> 0x60,0),
339: CONCAT210(uVar106,SUB1610(auVar48,0))) >> 0x50,0),
340: CONCAT28(uVar51,SUB168(auVar48,0))) >> 0x40,0),
341: uVar58)) << 0x30;
342: uVar113 = SUB162(auVar2 >> 0x40,0);
343: uVar115 = SUB162(auVar2 >> 0x60,0);
344: uVar116 = SUB162(auVar2 >> 0x70,0);
345: uVar104 = SUB162(auVar2 >> 0x30,0);
346: uVar103 = SUB162(auVar2 >> 0x20,0);
347: auVar48 = pauVar4[4];
348: uVar94 = SUB162(auVar2 >> 0x10,0);
349: auVar64 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
350: (uVar81,CONCAT212(uVar104,SUB1612(auVar2,0))) >>
351: 0x60,0),CONCAT210(uVar70,SUB1610(auVar2,0))) >>
352: 0x50,0),CONCAT28(uVar103,SUB168(auVar2,0))) >>
353: 0x40,0),*(undefined2 *)(pauVar4[3] + 2)),uVar94))
354: << 0x20;
355: uVar74 = SUB164(CONCAT214(uVar71,CONCAT212(uVar58,SUB1612(auVar49,0))) >> 0x60,0);
356: uVar69 = SUB168(CONCAT610(SUB166(CONCAT412(uVar74,CONCAT210(uVar55,SUB1610(auVar49,0)))
357: >> 0x50,0),CONCAT28(uVar56,SUB168(auVar49,0))) >> 0x40,
358: 0);
359: uVar89 = (ulong)CONCAT24(uVar55,CONCAT22(SUB162(auVar1 >> 0x60,0),uVar65)) & 0xffff0000;
360: auVar63 = CONCAT88(uVar69,(uVar89 >> 0x10) << 0x30) &
361: (undefined  [16])0xffff000000000000;
362: uVar13 = *(undefined2 *)pauVar4[5];
363: uVar51 = *(undefined2 *)(pauVar4[5] + 2);
364: uVar106 = *(undefined2 *)(pauVar4[5] + 4);
365: uVar15 = *(undefined2 *)(pauVar4[5] + 8);
366: uVar16 = *(undefined2 *)(pauVar4[5] + 0xc);
367: uVar52 = SUB162((auVar50 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
368: uVar54 = SUB162((auVar50 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
369: uVar57 = SUB162(auVar50 >> 0x60,0);
370: auVar92 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
371: undefined2 *)(pauVar4[3] + 10),
372: CONCAT212(SUB162(auVar64 >> 0x30,0),
373: SUB1612(auVar64,0))) >> 0x60,0),
374: CONCAT210(SUB162(auVar2 >> 0x50,0),
375: SUB1610(auVar64,0))) >> 0x50,0),
376: CONCAT28(uVar94,SUB168(auVar64,0))) >> 0x40,0),
377: *(undefined2 *)(pauVar4[3] + 8))) << 0x30;
378: auVar49 = pauVar4[6];
379: uVar114 = SUB162(auVar48 >> 0x40,0);
380: uVar80 = SUB162(auVar48 >> 0x50,0);
381: uVar117 = SUB162(auVar48 >> 0x70,0);
382: uVar94 = *(undefined2 *)pauVar4[7];
383: uVar95 = SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
384: uVar96 = SUB162((auVar92 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
385: uVar97 = SUB162(auVar92 >> 0x70,0);
386: uVar77 = SUB162(auVar48 >> 0x30,0);
387: uVar76 = SUB162(auVar48 >> 0x20,0);
388: uVar67 = SUB162(auVar48 >> 0x10,0);
389: auVar64 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
390: (*(undefined2 *)(pauVar4[5] + 6),
391: CONCAT212(uVar77,SUB1612(auVar48,0))) >> 0x60,0),
392: CONCAT210(uVar106,SUB1610(auVar48,0))) >> 0x50,0),
393: CONCAT28(uVar76,SUB168(auVar48,0))) >> 0x40,0),
394: uVar51),uVar67)) << 0x20;
395: uVar144 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar4[5] + 6),
396: CONCAT212(uVar77,SUB1612(auVar48,0))) >>
397: 0x60,0),CONCAT210(uVar106,SUB1610(auVar48,0))) >> 0x50
398: ,0);
399: uVar35 = SUB164(auVar48,0) & 0xffff;
400: auVar75 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar144,CONCAT28(uVar76,SUB168(auVar48,0)))
401: >> 0x40,0),uVar51)) << 0x30 &
402: (undefined  [16])0xffffffff00000000;
403: auVar64 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
404: undefined2 *)(pauVar4[5] + 10),
405: CONCAT212(SUB162(auVar64 >> 0x30,0),
406: SUB1612(auVar64,0))) >> 0x60,0),
407: CONCAT210(uVar80,SUB1610(auVar64,0))) >> 0x50,0),
408: CONCAT28(uVar67,SUB168(auVar64,0))) >> 0x40,0),
409: uVar15)) << 0x30;
410: uVar122 = SUB162(auVar49 >> 0x40,0);
411: uVar123 = SUB162(auVar49 >> 0x60,0);
412: uVar124 = SUB162(auVar49 >> 0x70,0);
413: auVar84 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
414: undefined2 *)(pauVar4[5] + 10),
415: CONCAT212(uVar51,SUB1612(auVar75,0))) >> 0x60,0),
416: CONCAT210(uVar80,SUB1610(auVar75,0))) >> 0x50,0),
417: CONCAT28(uVar67,SUB168(auVar75,0))) >> 0x40,0),
418: uVar15)) << 0x30 & (undefined  [16])0xffffffff00000000;
419: uVar87 = SUB162(auVar49 >> 0x30,0);
420: uVar86 = SUB162(auVar49 >> 0x20,0);
421: uVar67 = SUB162(auVar49 >> 0x10,0);
422: auVar75 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
423: (*(undefined2 *)(pauVar4[7] + 6),
424: CONCAT212(uVar87,SUB1612(auVar49,0))) >> 0x60,0),
425: CONCAT210(*(undefined2 *)(pauVar4[7] + 4),
426: SUB1610(auVar49,0))) >> 0x50,0),
427: CONCAT28(uVar86,SUB168(auVar49,0))) >> 0x40,0),
428: *(undefined2 *)(pauVar4[7] + 2)),uVar67)) << 0x20;
429: uVar51 = SUB162(auVar49,0);
430: uVar9 = (ulong)CONCAT24(uVar106,CONCAT22(SUB162(auVar48 >> 0x60,0),uVar76)) & 0xffff0000
431: ;
432: auVar93 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar16,CONCAT212(
433: uVar15,SUB1612(auVar84,0))) >> 0x60,0),
434: CONCAT210(uVar106,SUB1610(auVar84,0))) >> 0x50,0),
435: CONCAT28(uVar13,SUB168(auVar84,0))) >> 0x40,0),
436: (uVar9 >> 0x10) << 0x30) & (undefined  [16])0xffff000000000000;
437: uVar78 = SUB162((auVar64 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
438: uVar80 = SUB162((auVar64 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
439: uVar82 = SUB162(auVar64 >> 0x60,0);
440: uVar83 = SUB162(auVar64 >> 0x70,0);
441: auVar84 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
442: undefined2 *)(pauVar4[7] + 10),
443: CONCAT212(SUB162(auVar75 >> 0x30,0),
444: SUB1612(auVar75,0))) >> 0x60,0),
445: CONCAT210(SUB162(auVar49 >> 0x50,0),
446: SUB1610(auVar75,0))) >> 0x50,0),
447: CONCAT28(uVar67,SUB168(auVar75,0))) >> 0x40,0),
448: *(undefined2 *)(pauVar4[7] + 8))) << 0x30;
449: uVar88 = SUB162((auVar84 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
450: uVar90 = SUB162((auVar84 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
451: uVar67 = (undefined2)(uVar89 >> 0x10);
452: auVar49 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
453: (uVar115,CONCAT212(uVar67,SUB1612(auVar63,0))) >>
454: 0x60,0),CONCAT210(uVar113,SUB1610(auVar63,0))) >>
455: 0x50,0),CONCAT28(uVar107,SUB168(auVar63,0))) >>
456: 0x40,0),uVar103) &
457: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
458: uVar65)) << 0x20;
459: uVar12 = SUB166(CONCAT412(SUB164(CONCAT214(uVar115,CONCAT212(uVar67,SUB1612(auVar63,0)))
460: >> 0x60,0),CONCAT210(uVar113,SUB1610(auVar63,0))) >>
461: 0x50,0);
462: auVar64 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar12,CONCAT28(uVar107,SUB168(auVar63,0)))
463: >> 0x40,0),uVar103) &
464: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
465: (undefined  [16])0xffffffff00000000;
466: auVar63 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar70,
467: CONCAT212(SUB162(auVar49 >> 0x30,0),
468: SUB1612(auVar49,0))) >> 0x60,0),
469: CONCAT210(uVar55,SUB1610(auVar49,0))) >> 0x50,0),
470: CONCAT28(uVar65,SUB168(auVar49,0))) >> 0x40,0),
471: uVar85)) << 0x30;
472: uVar105 = (undefined2)(uVar9 >> 0x10);
473: auVar49 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar70,
474: CONCAT212(uVar103,SUB1612(auVar64,0))) >> 0x60,0),
475: CONCAT210(uVar55,SUB1610(auVar64,0))) >> 0x50,0),
476: CONCAT28(uVar65,SUB168(auVar64,0))) >> 0x40,0),
477: uVar85)) << 0x30 & (undefined  [16])0xffffffff00000000;
478: auVar64 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
479: (uVar123,CONCAT212(uVar105,SUB1612(auVar93,0))) >>
480: 0x60,0),CONCAT210(uVar122,SUB1610(auVar93,0))) >>
481: 0x50,0),CONCAT28(uVar114,SUB168(auVar93,0))) >>
482: 0x40,0),uVar86) &
483: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
484: uVar76)) << 0x20;
485: auVar135 = CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar4[3] + 8),
486: CONCAT212(uVar85,SUB1612(auVar49,
487: 0))) >> 0x60,0),
488: CONCAT210(uVar113,SUB1610(auVar49,0))) >> 0x50,0),
489: CONCAT28(SUB162(auVar2,0),SUB168(auVar49,0))) &
490: (undefined  [16])0xffffffffffffffff;
491: uVar138 = SUB168(auVar135 >> 0x40,0);
492: uVar89 = (ulong)CONCAT24(uVar113,CONCAT22(uVar58,uVar107)) & 0xffff0000;
493: auVar93 = CONCAT88(uVar138,(uVar89 >> 0x10) << 0x30) &
494: (undefined  [16])0xffff000000000000;
495: uVar70 = SUB162((auVar63 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
496: uVar65 = SUB162(auVar63 >> 0x60,0);
497: Var29 = CONCAT28(uVar65,uVar69);
498: auVar112 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
499: undefined2 *)(pauVar4[7] + 4),
500: CONCAT212(SUB162(auVar64 >> 0x30,0),
501: SUB1612(auVar64,0))) >> 0x60,0),
502: CONCAT210(uVar106,SUB1610(auVar64,0))) >> 0x50,0),
503: CONCAT28(uVar76,SUB168(auVar64,0))) >> 0x40,0),
504: uVar94)) << 0x30;
505: uVar9 = (ulong)(uVar72 & 0xffff00000000 |
506: (uint6)CONCAT22(SUB162(auVar92 >> 0x60,0),uVar57));
507: uVar142 = SUB162((auVar112 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
508: uVar10 = (ulong)CONCAT24(SUB162((auVar112 & (undefined  [16])0xffffffff00000000) >> 0x50
509: ,0),CONCAT22(uVar105,uVar142));
510: uVar86 = SUB162(auVar112 >> 0x70,0);
511: auVar49 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar116,uVar108)
512: ,uVar96),
513: CONCAT22(uVar54,uVar108)) >> 0x10)
514: ,uVar104),uVar66)) << 0x20;
515: uVar30 = CONCAT22(uVar116,uVar108);
516: auVar64 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar30,uVar96),
517: CONCAT22(uVar54,uVar108)) >> 0x10),uVar104))
518: << 0x30 & (undefined  [16])0xffffffff00000000;
519: uVar55 = (undefined2)(uVar9 >> 0x20);
520: uVar76 = (undefined2)(uVar9 >> 0x10);
521: auVar49 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar81,
522: CONCAT212(SUB162(auVar49 >> 0x30,0),
523: SUB1612(auVar49,0))) >> 0x60,0),
524: CONCAT210(uVar55,SUB1610(auVar49,0))) >> 0x50,0),
525: CONCAT28(uVar66,SUB168(auVar49,0))) >> 0x40,0),
526: uVar76) & 0xffffffffffffffff) << 0x30;
527: auVar75 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
528: CONCAT214(uVar81,CONCAT212(uVar104,SUB1612(auVar64
529: ,0))) >> 0x60,0),
530: CONCAT210(uVar55,SUB1610(auVar64,0))) >> 0x50,0),
531: CONCAT28(uVar66,SUB168(auVar64,0))) >> 0x40,0),
532: uVar76)) << 0x30) >> 0x20,0) &
533: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
534: auVar64 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar124,uVar117)
535: ,uVar90),
536: CONCAT22(uVar80,uVar117)) >> 0x10)
537: ,uVar87),uVar77)) << 0x20;
538: uVar11 = (ulong)(uVar144 & 0xffff00000000 |
539: (uint6)CONCAT22(SUB162(auVar84 >> 0x60,0),uVar82));
540: uVar130 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar97,CONCAT212(uVar76,
541: SUB1612(auVar75,0))) >> 0x60,0),
542: CONCAT210(uVar96,SUB1610(auVar75,0))) >> 0x50,0),
543: CONCAT28(uVar95,SUB168(auVar75,0))) >> 0x40,0);
544: uVar9 = (ulong)CONCAT24(uVar96,CONCAT22(SUB162(auVar50 >> 0x70,0),uVar54)) & 0xffff0000;
545: auVar92 = CONCAT88(uVar130,(uVar9 >> 0x10) << 0x30) &
546: (undefined  [16])0xffff000000000000;
547: uVar55 = SUB162((auVar49 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
548: uVar58 = SUB162(auVar49 >> 0x60,0);
549: uVar66 = (undefined2)(uVar11 >> 0x10);
550: auVar75 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
551: undefined2 *)(pauVar4[7] + 6),
552: CONCAT212(SUB162(auVar64 >> 0x30,0),
553: SUB1612(auVar64,0))) >> 0x60,0),
554: CONCAT210((short)(uVar11 >> 0x20),
555: SUB1610(auVar64,0))) >> 0x50,0),
556: CONCAT28(uVar77,SUB168(auVar64,0))) >> 0x40,0),
557: uVar66) & 0xffffffffffffffff) << 0x30;
558: uVar79 = SUB162((auVar75 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
559: uVar81 = SUB162((auVar75 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
560: uVar77 = (undefined2)(uVar89 >> 0x10);
561: auVar50 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
562: (uVar15,CONCAT212(uVar77,SUB1612(auVar93,0))) >>
563: 0x60,0),CONCAT210(uVar13,SUB1610(auVar93,0))) >>
564: 0x50,0),CONCAT28(uVar56,SUB168(auVar93,0))) >>
565: 0x40,0),uVar114) &
566: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
567: uVar107)) << 0x20;
568: uVar72 = SUB166(CONCAT412(SUB164(CONCAT214(uVar15,CONCAT212(uVar77,SUB1612(auVar93,0)))
569: >> 0x60,0),CONCAT210(uVar13,SUB1610(auVar93,0))) >>
570: 0x50,0);
571: auVar64 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar72,CONCAT28(uVar56,SUB168(auVar93,0)))
572: >> 0x40,0),uVar114) &
573: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
574: (undefined  [16])0xffffffff00000000;
575: auVar136 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar122,
576: CONCAT212(SUB162(auVar50 >> 0x30,0),
577: SUB1612(auVar50,0))) >> 0x60,0),
578: CONCAT210(uVar113,SUB1610(auVar50,0))) >> 0x50,0),
579: CONCAT28(uVar107,SUB168(auVar50,0))) >> 0x40,0),
580: uVar51) & 0xffffffffffffffff) << 0x30;
581: uVar106 = (undefined2)(uVar9 >> 0x10);
582: uVar144 = SUB166(CONCAT412(SUB164(CONCAT214(uVar83,CONCAT212(uVar106,SUB1612(auVar92,0))
583: ) >> 0x60,0),
584: CONCAT210(uVar82,SUB1610(auVar92,0))) >> 0x50,0);
585: auVar50 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar144,CONCAT28(uVar57,SUB168(auVar92,0)))
586: >> 0x40,0),uVar80) &
587: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
588: (undefined  [16])0xffffffff00000000;
589: auVar64 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
590: CONCAT214(uVar122,CONCAT212(uVar114,SUB1612(
591: auVar64,0))) >> 0x60,0),
592: CONCAT210(uVar113,SUB1610(auVar64,0))) >> 0x50,0),
593: CONCAT28(uVar107,SUB168(auVar64,0))) >> 0x40,0),
594: uVar51)) << 0x30) >> 0x20,0) &
595: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
596: auVar92 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
597: (uVar83,CONCAT212(uVar106,SUB1612(auVar92,0))) >>
598: 0x60,0),CONCAT210(uVar82,SUB1610(auVar92,0))) >>
599: 0x50,0),CONCAT28(uVar57,SUB168(auVar92,0))) >>
600: 0x40,0),uVar80) &
601: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
602: uVar54)) << 0x20;
603: uVar89 = (ulong)CONCAT24(uVar13,CONCAT22(uVar85,uVar56)) & 0xffff0000;
604: auVar121 = ZEXT1416(CONCAT122(SUB1612((ZEXT1016(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166
605: (CONCAT412(SUB164(CONCAT214(uVar94,CONCAT212(
606: uVar51,SUB1612(auVar64,0))) >> 0x60,0),
607: CONCAT210(uVar13,SUB1610(auVar64,0))) >> 0x50,0),
608: CONCAT28((short)uVar35,SUB168(auVar64,0))) >> 0x40
609: ,0),(uVar89 >> 0x10) << 0x30) >> 0x30,0) &
610: SUB1610((undefined  [16])0xffffffffffffffff >>
611: 0x30,0)) << 0x30) >> 0x20,0),uVar56)) <<
612: 0x10;
613: uVar137 = SUB162((auVar136 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
614: uVar132 = CONCAT24(SUB162((auVar136 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
615: CONCAT22(uVar77,uVar137));
616: uVar139 = SUB162(auVar136 >> 0x60,0);
617: auVar128 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar90,
618: CONCAT212(SUB162(auVar92 >> 0x30,0),
619: SUB1612(auVar92,0))) >> 0x60,0),
620: CONCAT210(uVar96,SUB1610(auVar92,0))) >> 0x50,0),
621: CONCAT28(uVar54,SUB168(auVar92,0))) >> 0x40,0),
622: uVar88)) << 0x30;
623: auVar50 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar90,
624: CONCAT212(uVar80,SUB1612(auVar50,0))) >> 0x60,0),
625: CONCAT210(uVar96,SUB1610(auVar50,0))) >> 0x50,0),
626: CONCAT28(uVar54,SUB168(auVar50,0))) >> 0x40,0),
627: uVar88)) << 0x30 & (undefined  [16])0xffffffff00000000;
628: uVar129 = SUB162((auVar128 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
629: uVar125 = CONCAT24(SUB162((auVar128 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
630: CONCAT22(uVar106,uVar129));
631: uVar131 = SUB162(auVar128 >> 0x60,0);
632: uVar9 = (ulong)CONCAT24(uVar82,CONCAT22(uVar76,uVar57)) & 0xffff0000;
633: auVar102 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
634: (uVar66,CONCAT212(uVar88,SUB1612(auVar50,0))) >>
635: 0x60,0),CONCAT210(uVar82,SUB1610(auVar50,0))) >>
636: 0x50,0),CONCAT28(uVar78,SUB168(auVar50,0))) >>
637: 0x40,0),(uVar9 >> 0x10) << 0x30) >> 0x20,0) &
638: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
639: CONCAT22(uVar57,uVar52));
640: uVar11 = (ulong)(uVar12 & 0xffff00000000 |
641: (uint6)CONCAT22(SUB162(auVar112 >> 0x60,0),uVar65));
642: uVar54 = (undefined2)(uVar10 >> 0x20);
643: uVar12 = SUB166(CONCAT412(SUB164(CONCAT214(uVar16,CONCAT212(uVar71,CONCAT210(uVar115,
644: Var29))) >> 0x60,0),CONCAT210(uVar54,Var29)) >>
645: 0x50,0);
646: uVar106 = (undefined2)(uVar10 >> 0x10);
647: auVar92 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar12,CONCAT28(uVar70,
648: uVar69)) >> 0x40,0),uVar106) & 0xffffffffffffffff)
649: << 0x30) >> 0x20,0) &
650: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
651: auVar50 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
652: (uVar16,CONCAT212(uVar71,CONCAT210(uVar115,Var29))
653: ) >> 0x60,0),CONCAT210(uVar54,Var29)) >> 0x50,0),
654: CONCAT28(uVar70,uVar69)) >> 0x40,0),uVar106),
655: uVar67) & (undefined  [12])0xffffffffffffffff) << 0x20;
656: uVar56 = (undefined2)(uVar11 >> 0x20);
657: uVar85 = (undefined2)(uVar11 >> 0x10);
658: auVar64 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar123,
659: CONCAT212(SUB162(auVar50 >> 0x30,0),
660: SUB1612(auVar50,0))) >> 0x60,0),
661: CONCAT210(uVar56,SUB1610(auVar50,0))) >> 0x50,0),
662: CONCAT28(uVar67,SUB168(auVar50,0))) >> 0x40,0),
663: uVar85) & 0xffffffffffffffff) << 0x30;
664: auVar50 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
665: CONCAT214(uVar123,CONCAT212(uVar106,SUB1612(
666: auVar92,0))) >> 0x60,0),
667: CONCAT210(uVar56,SUB1610(auVar92,0))) >> 0x50,0),
668: CONCAT28(uVar67,SUB168(auVar92,0))) >> 0x40,0),
669: uVar85)) << 0x30) >> 0x20,0) &
670: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
671: uVar71 = SUB162((auVar64 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
672: uVar31 = CONCAT24(uVar71,uVar74);
673: uVar69 = CONCAT26(uVar14,uVar31);
674: uVar73 = SUB162(auVar64 >> 0x60,0);
675: uVar10 = (ulong)CONCAT24(uVar54,CONCAT22(SUB162(auVar63 >> 0x70,0),uVar70)) & 0xffff0000
676: ;
677: auVar112 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
678: CONCAT214(uVar86,CONCAT212(uVar85,SUB1612(auVar50,
679: 0))) >> 0x60,0),
680: CONCAT210(uVar54,SUB1610(auVar50,0))) >> 0x50,0),
681: CONCAT28(uVar142,SUB168(auVar50,0))) >> 0x40,0),
682: (uVar10 >> 0x10) << 0x30) >> 0x20,0) &
683: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
684: uVar70)) << 0x10;
685: uVar11 = (ulong)(((uint6)uVar30 & 0xffff0000) << 0x10 |
686: (uint6)CONCAT22(SUB162(auVar75 >> 0x60,0),uVar58));
687: auVar93 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(*(undefined2 *)
688: (pauVar4[5] + 0xe),
689: uVar143),uVar81),
690: CONCAT22(uVar55,uVar143)) >> 0x10),uVar117))
691: << 0x30;
692: auVar92 = auVar93 & (undefined  [16])0xffffffff00000000;
693: auVar50 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(*(undefined2 *)
694: (pauVar4[5] +
695: 0xe),uVar143),
696: uVar81),
697: CONCAT22(uVar55,uVar143)) >> 0x10)
698: ,uVar117),uVar108)) << 0x20;
699: uVar56 = (undefined2)(uVar11 >> 0x20);
700: uVar55 = (undefined2)(uVar11 >> 0x10);
701: auVar50 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar124,
702: CONCAT212(SUB162(auVar50 >> 0x30,0),
703: SUB1612(auVar50,0))) >> 0x60,0),
704: CONCAT210(uVar56,SUB1610(auVar50,0))) >> 0x50,0),
705: CONCAT28(uVar108,SUB168(auVar50,0))) >> 0x40,0),
706: uVar55) & 0xffffffffffffffff) << 0x30;
707: auVar93 = auVar93 & (undefined  [16])0xffffffff00000000;
708: uVar143 = SUB162(auVar93 >> 0x50,0);
709: uVar70 = SUB162(auVar93 >> 0x70,0);
710: uVar74 = CONCAT22(uVar58,SUB162((auVar49 & (undefined  [16])0xffffffff00000000) >> 0x40,
711: 0));
712: auVar92 = CONCAT124(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
713: CONCAT214(uVar124,CONCAT212(uVar117,SUB1612(
714: auVar92,0))) >> 0x60,0),
715: CONCAT210(uVar56,SUB1610(auVar92,0))) >> 0x50,0),
716: CONCAT28(uVar108,SUB168(auVar92,0))) >> 0x40,0),
717: uVar55)) << 0x30) >> 0x20,0) &
718: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0),uVar74);
719: uVar53 = SUB162((auVar50 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
720: uVar56 = SUB162((auVar50 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
721: uVar45 = CONCAT24(uVar56,CONCAT22(SUB162(auVar93 >> 0x60,0),uVar53));
722: uVar46 = CONCAT26(*(undefined2 *)(pauVar4[3] + 0xe),uVar45);
723: uVar59 = SUB162(auVar50 >> 0x60,0);
724: auVar49 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412
725: (SUB164(CONCAT214(SUB162(auVar75 >> 0x70,0),
726: CONCAT212(uVar55,SUB1612(auVar92
727: ,0))) >> 0x60,0),
728: CONCAT210(uVar143,SUB1610(auVar92,0))) >> 0x50,0),
729: CONCAT28(uVar79,SUB168(auVar92,0))) >> 0x40,0),
730: (((ulong)CONCAT24(uVar143,SUB144(CONCAT122(SUB1612
731: (auVar93 >> 0x20,0),SUB162(auVar49 >> 0x70,0)),0)
732: << 0x10) & 0xffff0000) >> 0x10) << 0x30) >> 0x30,0
733: ),(SUB166(auVar92,0) >> 0x10) << 0x20) >> 0x20,0),
734: uVar74) & (undefined  [16])0xffffffff0000ffff;
735: auVar120 = ZEXT1012(CONCAT28(uVar51,(ulong)(CONCAT24(uVar13,SUB164(auVar48,0)) &
736: 0xffff0000ffff)) & 0xffffffffffffffff);
737: fVar19 = (float)(SUB164(auVar1,0) & 0xffff) * 1.0;
738: fVar20 = (float)SUB164(CONCAT106((unkuint10)
739: (SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212((
740: short)(uVar89 >> 0x10),SUB1612(auVar121,0)) >>
741: 0x50,0),CONCAT28(SUB162(auVar2,0),
742: SUB168(auVar121,0))) >> 0x40,0),
743: SUB168(auVar121,0)) >> 0x30,0) & 0xffff) &
744: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)
745: & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0
746: ),(SUB166(auVar121,0) >> 0x10) << 0x20) >>
747: 0x20,0) * 1.38704;
748: dVar118 = (double)SUB164(ZEXT1416(CONCAT212(uVar94,auVar120)) >> 0x40,0);
749: fVar21 = (float)(int)((ulong)dVar118 >> 0x20) * 0.2758994;
750: auVar101 = ZEXT1012(CONCAT28(uVar88,(ulong)CONCAT24(uVar82,(uint)uVar78)));
751: Var68 = (unkuint10)
752: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212((short)(uVar9 >> 0x10),
753: SUB1612(auVar102,0)) >> 0x50,0
754: ),CONCAT28(uVar95,SUB168(auVar102,0))) >>
755: 0x40,0),SUB168(auVar102,0)) >> 0x30,0) &
756: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
757: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
758: dVar119 = (double)(int)(Var68 >> 0x10);
759: fVar22 = (float)(uint)uVar52 * 1.0 * 1.38704;
760: fVar23 = (float)SUB164(CONCAT106(Var68,(SUB166(auVar102,0) >> 0x10) << 0x20) >> 0x20,0)
761: * 1.38704 * 1.38704;
762: dVar99 = (double)SUB164(ZEXT1416(CONCAT212(uVar66,auVar101)) >> 0x40,0);
763: auVar111 = ZEXT1012(CONCAT28(uVar85,(ulong)CONCAT24(uVar54,(uint)uVar142)));
764: Var68 = (unkuint10)
765: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212((short)(uVar10 >> 0x10),
766: SUB1612(auVar112,0)) >> 0x50,0
767: ),CONCAT28(uVar65,SUB168(auVar112,0))) >>
768: 0x40,0),SUB168(auVar112,0)) >> 0x30,0) &
769: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
770: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
771: dVar100 = (double)(int)(Var68 >> 0x10);
772: fVar24 = (float)(uint)SUB162((auVar63 & (undefined  [16])0xffffffff00000000) >> 0x40,0)
773: * 1.0 * 1.306563;
774: fVar25 = (float)SUB164(CONCAT106(Var68,(SUB166(auVar112,0) >> 0x10) << 0x20) >> 0x20,0)
775: * 1.38704 * 1.306563;
776: fVar98 = (float)(dVar100 * 1.306562965 * 1.306562965);
777: dVar110 = (double)SUB164(ZEXT1416(CONCAT212(uVar86,auVar111)) >> 0x40,0);
778: fVar26 = (float)(uint)uVar142 * 1.0 * 1.306563;
779: fVar27 = (float)(int)((ulong)dVar110 >> 0x20) * 0.2758994 * 1.306563;
780: fVar109 = (float)(dVar110 * 0.5411961 * 1.306562965);
781: auVar91 = ZEXT1012(CONCAT28(SUB162(auVar49 >> 0x60,0),
782: (ulong)CONCAT24(SUB162(auVar49 >> 0x50,0),(uint)uVar79)));
783: dVar140 = (double)((uint)((unkuint10)
784: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(
785: auVar49 >> 0x30,0),SUB1612(auVar49,0)) >> 0x50,0),
786: CONCAT28(SUB162(auVar49 >> 0x20,0),
787: SUB168(auVar49,0))) >> 0x40,0),
788: SUB168(auVar49,0)) >> 0x30,0) >> 0x10) & 0xffff);
789: dVar141 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar49 >> 0x70,0),auVar91)) >> 0x40,
790: 0);
791: auVar134 = ZEXT1012(CONCAT28(SUB162(auVar136 >> 0x70,0),(ulong)(uVar72 & 0xffff00000000)
792: ));
793: fVar28 = (float)SUB164(CONCAT106((unkuint10)
794: (SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(
795: SUB162(auVar135 >> 0x70,0),
796: CONCAT210(uVar15,CONCAT28(uVar139,uVar138))) >>
797: 0x50,0),CONCAT28((short)((ulong)uVar132 >> 0x20),
798: uVar138)) >> 0x40,0),uVar138) >>
799: 0x30,0) & 0xffff) &
800: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)
801: & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0
802: ),(uVar132 >> 0x10) << 0x20) >> 0x20,0) *
803: 1.38704;
804: dVar133 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar4[7] + 8),auVar134))
805: >> 0x40,0);
806: auVar127 = ZEXT1012(CONCAT28(SUB162(auVar128 >> 0x70,0),
807: (ulong)(uVar144 & 0xffff00000000)));
808: dVar126 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar84 >> 0x70,0),auVar127)) >> 0x40
809: ,0);
810: auVar62 = ZEXT1012(CONCAT28(SUB162(auVar64 >> 0x70,0),(ulong)(uVar12 & 0xffff00000000)))
811: ;
812: dVar60 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar4[7] + 0xc),auVar62))
813: >> 0x40,0);
814: auVar47 = ZEXT1012(CONCAT28(SUB162(auVar50 >> 0x70,0),
815: (ulong)CONCAT24(uVar70,(uint)uVar59)));
816: Var68 = (unkuint10)
817: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(*(undefined2 *)
818: (pauVar4[3] + 0xe),
819: CONCAT210(uVar70,CONCAT28(
820: uVar59,uVar46))) >> 0x50,0),
821: CONCAT28(uVar56,uVar46)) >> 0x40,0),uVar46) >>
822: 0x30,0) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
823: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
824: dVar61 = (double)(int)(Var68 >> 0x10);
825: dVar110 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar4[7] + 0xe),auVar47))
826: >> 0x40,0);
827: uVar89 = SUB168(CONCAT412((float)SUB164(CONCAT106((unkuint10)
828: (SUB148(CONCAT68(SUB146(CONCAT410(
829: SUB144(CONCAT212(uVar97,CONCAT210(uVar83,CONCAT28(
830: uVar131,uVar130))) >> 0x50,0),
831: CONCAT28((short)((ulong)uVar125 >> 0x20),uVar130))
832: >> 0x40,0),uVar130) >> 0x30,0) & 0xffff) &
833: SUB1610((undefined  [16])0xffffffffffffffff >>
834: 0x30,0) &
835: SUB1610((undefined  [16])0xffffffffffffffff >>
836: 0x30,0),(uVar125 >> 0x10) << 0x20) >> 0x20
837: ,0) * 1.38704 * 0.785695,
838: CONCAT48(fVar23,CONCAT44(fVar23,fVar22))) >> 0x40,0);
839: *(undefined (*) [16])(puVar6 + 2) =
840: CONCAT412((float)(uint)uVar53 * 1.0 * 0.2758994,
841: CONCAT48((float)(uint)SUB162((auVar64 &
842: (undefined  [16])0xffffffff00000000) >> 0x40
843: ,0) * 1.0 * 0.541196,
844: CONCAT44((float)(uint)uVar129 * 1.0 * 0.785695,
845: (float)(uint)uVar137 * 1.0)));
846: *puVar6 = CONCAT44(fVar22,fVar19);
847: puVar6[1] = SUB168(CONCAT412((float)((double)SUB164(auVar49,0) * 1.0 * 1.175875602),
848: CONCAT48(fVar24,CONCAT44(fVar24,fVar19))) >> 0x40,0);
849: *(undefined (*) [16])(puVar6 + 6) =
850: CONCAT412((float)SUB164(CONCAT106(Var68,(uVar45 >> 0x10) << 0x20) >> 0x20,0) *
851: 1.38704 * 0.2758994,
852: CONCAT48((float)SUB164(CONCAT106((unkuint10)
853: (SUB148(CONCAT68(SUB146(CONCAT410(SUB144
854: (CONCAT212(uVar14,CONCAT210(uVar16,CONCAT28(uVar73
855: ,uVar69))) >> 0x50,0),CONCAT28(uVar71,uVar69)) >>
856: 0x40,0),uVar69) >> 0x30,0) & 0xffff) &
857: SUB1610((undefined  [16])0xffffffffffffffff >>
858: 0x30,0) &
859: SUB1610((undefined  [16])0xffffffffffffffff >>
860: 0x30,0),(uVar31 >> 0x10) << 0x20) >> 0x20,
861: 0) * 1.38704 * 0.541196,
862: uVar89 & 0xffffffff00000000 | (ulong)(uint)fVar28));
863: puVar6[4] = SUB168(CONCAT412(fVar28,CONCAT48(fVar20,CONCAT44(fVar20,fVar19))) >> 0x40,0)
864: & 0xffffffff | uVar89 << 0x20;
865: puVar6[5] = SUB128(CONCAT48((float)(int)((ulong)(double)SUB164(auVar49,0) >> 0x20) *
866: 1.38704 * 1.175876,CONCAT44(fVar25,fVar25)) >> 0x20,0);
867: puVar6[8] = (ulong)(uint)(float)(dVar119 * 1.306562965 * 1.387039845) << 0x20;
868: puVar6[9] = SUB128(CONCAT48((float)(dVar140 * 1.306562965 * 1.175875602),
869: CONCAT44(fVar98,fVar98)) >> 0x20,0);
870: *(undefined (*) [16])(puVar6 + 10) =
871: CONCAT412((float)(dVar61 * 1.306562965 * 0.275899379),ZEXT412(0) << 0x20);
872: *(undefined4 *)(puVar6 + 0xe) = 0;
873: *(undefined4 *)((long)puVar6 + 0x74) = 0;
874: *(undefined4 *)(puVar6 + 0xf) = 0;
875: *(float *)((long)puVar6 + 0x7c) =
876: (float)(int)((ulong)dVar61 >> 0x20) * 1.175876 * 0.2758994;
877: puVar6[0xc] = (ulong)(uint)((float)(int)((ulong)dVar119 >> 0x20) * 1.175876 * 1.38704)
878: << 0x20;
879: *(float *)(puVar6 + 0xe) = (float)(int)((ulong)dVar100 >> 0x20) * 1.175876 * 1.306563;
880: *(float *)((long)puVar6 + 0x74) =
881: (float)(int)((ulong)dVar140 >> 0x20) * 1.175876 * 1.175876;
882: *(undefined (*) [16])(puVar6 + 0x12) =
883: CONCAT412((float)(uint)uVar59 * 1.0 * 0.2758994,
884: CONCAT48((float)(uint)uVar73 * 1.0 * 0.541196,
885: CONCAT44((float)(uint)uVar131 * 1.0 * 0.785695,
886: (float)(uint)uVar139 * 1.0)));
887: puVar6[0x10] = CONCAT44((float)(uint)uVar78 * 1.0 * 1.38704,(float)uVar35 * 1.0);
888: puVar6[0x11] = SUB128(CONCAT48((float)(uint)uVar79 * 1.0 * 1.175876,
889: CONCAT44(fVar26,fVar26)) >> 0x20,0);
890: puVar6[0x14] = CONCAT44((float)SUB124(auVar101 >> 0x20,0) * 0.785695 * 1.38704,
891: (float)SUB124(auVar120 >> 0x20,0) * 0.785695);
892: *(float *)(puVar6 + 0x16) = (float)SUB124(auVar111 >> 0x20,0) * 0.785695 * 1.306563;
893: *(float *)((long)puVar6 + 0xb4) = (float)SUB124(auVar91 >> 0x20,0) * 0.785695 * 1.175876
894: ;
895: puVar6[0x18] = CONCAT44((float)(dVar99 * 0.5411961 * 1.387039845),
896: (float)(dVar118 * 0.5411961));
897: puVar6[0x19] = SUB128(CONCAT48((float)(dVar141 * 0.5411961 * 1.175875602),
898: CONCAT44(fVar109,fVar109)) >> 0x20,0);
899: *(float *)(puVar6 + 0x16) = (float)SUB124(auVar134 >> 0x20,0) * 0.785695;
900: *(float *)((long)puVar6 + 0xb4) =
901: (float)SUB124(auVar127 >> 0x20,0) * 0.785695 * 0.785695;
902: *(float *)(puVar6 + 0x17) = (float)SUB124(auVar62 >> 0x20,0) * 0.785695 * 0.541196;
903: *(float *)((long)puVar6 + 0xbc) =
904: (float)SUB124(auVar47 >> 0x20,0) * 0.785695 * 0.2758994;
905: *(float *)(puVar6 + 0x1a) = (float)(dVar133 * 0.5411961);
906: *(float *)((long)puVar6 + 0xd4) = (float)(dVar126 * 0.5411961 * 0.785694958);
907: *(float *)(puVar6 + 0x1b) = (float)(dVar60 * 0.5411961 * 0.5411961);
908: *(float *)((long)puVar6 + 0xdc) = (float)(dVar110 * 0.5411961 * 0.275899379);
909: *(undefined (*) [16])(puVar6 + 0x1c) =
910: CONCAT88(SUB168(CONCAT412((float)(int)((ulong)dVar141 >> 0x20) * 0.2758994 *
911: 1.175876,CONCAT48(fVar27,CONCAT44(fVar27,fVar21))) >>
912: 0x40,0),
913: CONCAT44((float)(int)((ulong)dVar99 >> 0x20) * 0.2758994 * 1.38704,fVar21)
914: ) & (undefined  [16])0xffffffffffffffff;
915: *(float *)(puVar6 + 0x1e) = (float)(int)((ulong)dVar133 >> 0x20) * 0.2758994;
916: *(float *)((long)puVar6 + 0xf4) =
917: (float)(int)((ulong)dVar126 >> 0x20) * 0.2758994 * 0.785695;
918: *(float *)(puVar6 + 0x1f) = (float)(int)((ulong)dVar60 >> 0x20) * 0.2758994 * 0.541196;
919: *(float *)((long)puVar6 + 0xfc) =
920: (float)(int)((ulong)dVar110 >> 0x20) * 0.2758994 * 0.2758994;
921: }
922: else {
923: if (iVar43 == 0) {
924: pauVar7 = *(undefined (**) [16])(pcVar36 + 0x58);
925: pauVar33 = pauVar7[1];
926: if ((pauVar4 < pauVar33) && (pauVar7 < pauVar4[1])) {
927: lVar34 = 0;
928: do {
929: *(undefined2 *)(*pauVar7 + lVar34) = *(undefined2 *)(*pauVar4 + lVar34);
930: lVar34 = lVar34 + 2;
931: } while (lVar34 != 0x80);
932: }
933: else {
934: uVar35 = -(int)((ulong)pauVar4 >> 1) & 7;
935: if (uVar35 == 0) {
936: uVar74 = *(undefined4 *)(*pauVar4 + 4);
937: uVar17 = *(undefined4 *)(*pauVar4 + 8);
938: uVar18 = *(undefined4 *)(*pauVar4 + 0xc);
939: iVar38 = 0;
940: iVar40 = 0x40;
941: iVar41 = 0x40;
942: *(undefined4 *)*pauVar7 = *(undefined4 *)*pauVar4;
943: *(undefined4 *)(*pauVar7 + 4) = uVar74;
944: *(undefined4 *)(*pauVar7 + 8) = uVar17;
945: *(undefined4 *)(*pauVar7 + 0xc) = uVar18;
946: iVar42 = 8;
947: pauVar8 = pauVar4;
948: }
949: else {
950: *(undefined2 *)*pauVar7 = *(undefined2 *)*pauVar4;
951: if (uVar35 == 1) {
952: iVar40 = 0x3f;
953: iVar38 = 1;
954: }
955: else {
956: *(undefined2 *)(*pauVar7 + 2) = *(undefined2 *)(*pauVar4 + 2);
957: if (uVar35 == 2) {
958: iVar40 = 0x3e;
959: iVar38 = 2;
960: }
961: else {
962: *(undefined2 *)(*pauVar7 + 4) = *(undefined2 *)(*pauVar4 + 4);
963: if (uVar35 == 3) {
964: iVar40 = 0x3d;
965: iVar38 = 3;
966: }
967: else {
968: *(undefined2 *)(*pauVar7 + 6) = *(undefined2 *)(*pauVar4 + 6);
969: if (uVar35 == 4) {
970: iVar40 = 0x3c;
971: iVar38 = 4;
972: }
973: else {
974: *(undefined2 *)(*pauVar7 + 8) = *(undefined2 *)(*pauVar4 + 8);
975: if (uVar35 == 5) {
976: iVar40 = 0x3b;
977: iVar38 = 5;
978: }
979: else {
980: *(undefined2 *)(*pauVar7 + 10) = *(undefined2 *)(*pauVar4 + 10);
981: if (uVar35 == 7) {
982: iVar40 = 0x39;
983: iVar38 = 7;
984: *(undefined2 *)(*pauVar7 + 0xc) = *(undefined2 *)(*pauVar4 + 0xc);
985: }
986: else {
987: iVar40 = 0x3a;
988: iVar38 = 6;
989: }
990: }
991: }
992: }
993: }
994: }
995: iVar42 = 7;
996: iVar41 = 0x40 - uVar35;
997: pauVar8 = (undefined (*) [16])(*pauVar4 + (ulong)uVar35 * 2);
998: puVar32 = (undefined4 *)(*pauVar7 + (ulong)uVar35 * 2);
999: pauVar33 = (undefined (*) [16])(puVar32 + 4);
1000: uVar74 = *(undefined4 *)(*pauVar8 + 4);
1001: uVar17 = *(undefined4 *)(*pauVar8 + 8);
1002: uVar18 = *(undefined4 *)(*pauVar8 + 0xc);
1003: *puVar32 = *(undefined4 *)*pauVar8;
1004: puVar32[1] = uVar74;
1005: puVar32[2] = uVar17;
1006: puVar32[3] = uVar18;
1007: }
1008: uVar74 = *(undefined4 *)(pauVar8[1] + 4);
1009: uVar17 = *(undefined4 *)(pauVar8[1] + 8);
1010: uVar18 = *(undefined4 *)(pauVar8[1] + 0xc);
1011: *(undefined4 *)*pauVar33 = *(undefined4 *)pauVar8[1];
1012: *(undefined4 *)(*pauVar33 + 4) = uVar74;
1013: *(undefined4 *)(*pauVar33 + 8) = uVar17;
1014: *(undefined4 *)(*pauVar33 + 0xc) = uVar18;
1015: uVar74 = *(undefined4 *)(pauVar8[2] + 4);
1016: uVar17 = *(undefined4 *)(pauVar8[2] + 8);
1017: uVar18 = *(undefined4 *)(pauVar8[2] + 0xc);
1018: *(undefined4 *)pauVar33[1] = *(undefined4 *)pauVar8[2];
1019: *(undefined4 *)(pauVar33[1] + 4) = uVar74;
1020: *(undefined4 *)(pauVar33[1] + 8) = uVar17;
1021: *(undefined4 *)(pauVar33[1] + 0xc) = uVar18;
1022: uVar74 = *(undefined4 *)(pauVar8[3] + 4);
1023: uVar17 = *(undefined4 *)(pauVar8[3] + 8);
1024: uVar18 = *(undefined4 *)(pauVar8[3] + 0xc);
1025: *(undefined4 *)pauVar33[2] = *(undefined4 *)pauVar8[3];
1026: *(undefined4 *)(pauVar33[2] + 4) = uVar74;
1027: *(undefined4 *)(pauVar33[2] + 8) = uVar17;
1028: *(undefined4 *)(pauVar33[2] + 0xc) = uVar18;
1029: uVar74 = *(undefined4 *)(pauVar8[4] + 4);
1030: uVar17 = *(undefined4 *)(pauVar8[4] + 8);
1031: uVar18 = *(undefined4 *)(pauVar8[4] + 0xc);
1032: *(undefined4 *)pauVar33[3] = *(undefined4 *)pauVar8[4];
1033: *(undefined4 *)(pauVar33[3] + 4) = uVar74;
1034: *(undefined4 *)(pauVar33[3] + 8) = uVar17;
1035: *(undefined4 *)(pauVar33[3] + 0xc) = uVar18;
1036: uVar74 = *(undefined4 *)(pauVar8[5] + 4);
1037: uVar17 = *(undefined4 *)(pauVar8[5] + 8);
1038: uVar18 = *(undefined4 *)(pauVar8[5] + 0xc);
1039: *(undefined4 *)pauVar33[4] = *(undefined4 *)pauVar8[5];
1040: *(undefined4 *)(pauVar33[4] + 4) = uVar74;
1041: *(undefined4 *)(pauVar33[4] + 8) = uVar17;
1042: *(undefined4 *)(pauVar33[4] + 0xc) = uVar18;
1043: uVar74 = *(undefined4 *)(pauVar8[6] + 4);
1044: uVar17 = *(undefined4 *)(pauVar8[6] + 8);
1045: uVar18 = *(undefined4 *)(pauVar8[6] + 0xc);
1046: *(undefined4 *)pauVar33[5] = *(undefined4 *)pauVar8[6];
1047: *(undefined4 *)(pauVar33[5] + 4) = uVar74;
1048: *(undefined4 *)(pauVar33[5] + 8) = uVar17;
1049: *(undefined4 *)(pauVar33[5] + 0xc) = uVar18;
1050: if (iVar42 == 8) {
1051: iVar38 = iVar38 + 0x40;
1052: iVar40 = iVar40 + -0x40;
1053: uVar74 = *(undefined4 *)(pauVar8[7] + 4);
1054: uVar17 = *(undefined4 *)(pauVar8[7] + 8);
1055: uVar18 = *(undefined4 *)(pauVar8[7] + 0xc);
1056: *(undefined4 *)pauVar33[6] = *(undefined4 *)pauVar8[7];
1057: *(undefined4 *)(pauVar33[6] + 4) = uVar74;
1058: *(undefined4 *)(pauVar33[6] + 8) = uVar17;
1059: *(undefined4 *)(pauVar33[6] + 0xc) = uVar18;
1060: if (iVar41 == 0x40) goto LAB_0012ed90;
1061: }
1062: else {
1063: iVar38 = iVar38 + 0x38;
1064: iVar40 = iVar40 + -0x38;
1065: }
1066: *(undefined2 *)(*pauVar7 + (long)iVar38 * 2) =
1067: *(undefined2 *)(*pauVar4 + (long)iVar38 * 2);
1068: if (iVar40 != 1) {
1069: *(undefined2 *)(*pauVar7 + (long)(iVar38 + 1) * 2) =
1070: *(undefined2 *)(*pauVar4 + (long)(iVar38 + 1) * 2);
1071: if (iVar40 != 2) {
1072: *(undefined2 *)(*pauVar7 + (long)(iVar38 + 2) * 2) =
1073: *(undefined2 *)(*pauVar4 + (long)(iVar38 + 2) * 2);
1074: if (iVar40 != 3) {
1075: *(undefined2 *)(*pauVar7 + (long)(iVar38 + 3) * 2) =
1076: *(undefined2 *)(*pauVar4 + (long)(iVar38 + 3) * 2);
1077: if (iVar40 != 4) {
1078: *(undefined2 *)(*pauVar7 + (long)(iVar38 + 4) * 2) =
1079: *(undefined2 *)(*pauVar4 + (long)(iVar38 + 4) * 2);
1080: if (iVar40 != 5) {
1081: *(undefined2 *)(*pauVar7 + (long)(iVar38 + 5) * 2) =
1082: *(undefined2 *)(*pauVar4 + (long)(iVar38 + 5) * 2);
1083: if (iVar40 != 6) {
1084: *(undefined2 *)(*pauVar7 + (long)(iVar38 + 6) * 2) =
1085: *(undefined2 *)(*pauVar4 + (long)(iVar38 + 6) * 2);
1086: }
1087: }
1088: }
1089: }
1090: }
1091: }
1092: }
1093: }
1094: else {
1095: ppcVar5 = (code **)*param_1;
1096: *(undefined4 *)(ppcVar5 + 5) = 0x30;
1097: (**ppcVar5)(param_1);
1098: }
1099: }
1100: }
1101: }
1102: LAB_0012ed90:
1103: iVar38 = (int)lVar37;
1104: pcVar36 = pcVar36 + 0x60;
1105: lVar37 = lVar37 + 1;
1106: } while (*(int *)(param_1 + 7) != iVar38 && iVar38 <= *(int *)(param_1 + 7));
1107: }
1108: return;
1109: }
1110: 
