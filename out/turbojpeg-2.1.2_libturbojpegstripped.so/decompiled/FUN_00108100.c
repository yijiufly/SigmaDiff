1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00108100(code **param_1)
5: 
6: {
7: undefined (*pauVar1) [16];
8: code *pcVar2;
9: code **ppcVar3;
10: ulong uVar4;
11: ulong uVar5;
12: uint6 uVar6;
13: undefined2 uVar7;
14: undefined2 uVar8;
15: undefined2 uVar9;
16: undefined2 uVar10;
17: undefined2 uVar11;
18: unkbyte10 Var12;
19: uint6 uVar13;
20: short sVar14;
21: int iVar15;
22: uint uVar16;
23: uint uVar17;
24: undefined8 *puVar18;
25: long lVar19;
26: short *psVar20;
27: byte bVar21;
28: ulong uVar22;
29: undefined (*pauVar23) [16];
30: uint uVar24;
31: code *pcVar25;
32: ushort uVar26;
33: ulong uVar27;
34: int iVar28;
35: long lVar29;
36: undefined2 uVar33;
37: undefined2 uVar34;
38: uint6 uVar30;
39: undefined2 uVar35;
40: ushort uVar36;
41: undefined2 uVar37;
42: undefined2 uVar38;
43: undefined2 uVar39;
44: undefined auVar32 [12];
45: undefined2 uVar40;
46: undefined2 uVar41;
47: ushort uVar42;
48: undefined2 uVar44;
49: ushort uVar45;
50: ushort uVar46;
51: undefined2 uVar47;
52: undefined2 uVar48;
53: undefined2 uVar49;
54: undefined2 uVar50;
55: undefined auVar43 [16];
56: undefined2 uVar56;
57: undefined2 uVar58;
58: uint6 uVar57;
59: undefined8 uVar55;
60: ushort uVar59;
61: undefined auVar51 [16];
62: undefined auVar52 [16];
63: undefined auVar53 [16];
64: unkuint10 Var54;
65: undefined2 uVar61;
66: undefined2 uVar62;
67: undefined2 uVar63;
68: undefined2 uVar64;
69: undefined2 uVar65;
70: float fVar66;
71: undefined2 uVar67;
72: undefined2 uVar68;
73: undefined2 uVar69;
74: undefined2 uVar71;
75: undefined2 uVar72;
76: undefined2 uVar73;
77: undefined2 uVar74;
78: undefined2 uVar75;
79: undefined auVar70 [16];
80: undefined2 uVar77;
81: undefined2 uVar80;
82: double dVar76;
83: float fVar78;
84: float fVar79;
85: undefined2 uVar81;
86: undefined2 uVar82;
87: undefined2 uVar83;
88: undefined2 uVar84;
89: undefined2 uVar85;
90: undefined2 uVar86;
91: undefined2 uVar87;
92: ushort uVar88;
93: uint6 uVar89;
94: uint6 uVar90;
95: undefined2 uVar91;
96: ushort uVar92;
97: undefined2 uVar94;
98: ushort uVar95;
99: undefined2 uVar96;
100: undefined8 uVar93;
101: uint6 uVar97;
102: undefined2 uVar98;
103: ushort uVar99;
104: ushort uVar101;
105: undefined8 uVar100;
106: undefined auVar102 [16];
107: float fVar106;
108: undefined auVar103 [16];
109: undefined auVar104 [16];
110: undefined auVar105 [16];
111: undefined auVar107 [16];
112: undefined auVar108 [16];
113: undefined auVar109 [16];
114: undefined auVar110 [16];
115: undefined auVar111 [16];
116: undefined auVar112 [16];
117: undefined auVar113 [16];
118: undefined auVar114 [16];
119: undefined auVar115 [16];
120: undefined auVar116 [16];
121: undefined auVar117 [16];
122: undefined auVar118 [16];
123: undefined auVar119 [16];
124: undefined auVar120 [16];
125: undefined auVar121 [16];
126: undefined auVar122 [16];
127: undefined auVar123 [16];
128: undefined auVar124 [16];
129: undefined auVar125 [16];
130: undefined auVar126 [16];
131: undefined auVar127 [16];
132: undefined auVar128 [16];
133: undefined auVar129 [16];
134: int iStack160;
135: int iStack140;
136: undefined8 uVar31;
137: undefined4 uVar60;
138: 
139: pcVar2 = param_1[0x3d];
140: pcVar25 = param_1[0xb];
141: if (0 < *(int *)((long)param_1 + 0x4c)) {
142: iStack140 = 0;
143: do {
144: uVar24 = *(uint *)(pcVar25 + 0x10);
145: lVar29 = (long)(int)uVar24;
146: if ((3 < uVar24) ||
147: (pauVar23 = (undefined (*) [16])param_1[lVar29 + 0xc], pauVar23 == (undefined (*) [16])0x0)
148: ) {
149: ppcVar3 = (code **)*param_1;
150: *(undefined4 *)(ppcVar3 + 5) = 0x34;
151: *(uint *)((long)ppcVar3 + 0x2c) = uVar24;
152: (**ppcVar3)();
153: pauVar23 = (undefined (*) [16])param_1[lVar29 + 0xc];
154: }
155: iVar28 = *(int *)((long)param_1 + 0x114);
156: if (iVar28 == 1) {
157: lVar19 = *(long *)(pcVar2 + lVar29 * 8 + 0x28);
158: if (lVar19 == 0) {
159: lVar19 = (**(code **)param_1[1])(param_1,1,0x200);
160: *(long *)(pcVar2 + lVar29 * 8 + 0x28) = lVar19;
161: }
162: lVar29 = 0;
163: do {
164: while( true ) {
165: uVar27 = (long)((ulong)*(ushort *)(*pauVar23 + lVar29) *
166: (long)*(short *)(&DAT_0016c660 + lVar29) + 0x400) >> 0xb;
167: uVar26 = (ushort)uVar27;
168: if (uVar26 == 1) break;
169: if (uVar26 == 0) {
170: uVar24 = 0x8000;
171: iVar28 = 0xf;
172: }
173: else {
174: uVar22 = uVar27 & 0xffffffff;
175: if ((uVar27 & 0xff00) == 0) {
176: uVar22 = (ulong)(uint)((int)uVar22 << 8);
177: iVar28 = 4;
178: iVar15 = 8;
179: }
180: else {
181: iVar28 = 0xc;
182: iVar15 = 0x10;
183: }
184: if ((uVar22 & 0xf000) == 0) {
185: uVar22 = (ulong)(uint)((int)uVar22 << 4);
186: iVar15 = iVar28;
187: }
188: sVar14 = (short)uVar22;
189: if ((uVar22 & 0xc000) == 0) {
190: iVar15 = iVar15 + -2;
191: sVar14 = (short)((int)uVar22 << 2);
192: }
193: iVar28 = iVar15 + 0xe;
194: uVar24 = 1 << ((byte)iVar28 & 0x1f);
195: if (sVar14 < 0) {
196: iVar28 = iVar15 + 0xf;
197: uVar24 = 1 << ((byte)iVar28 & 0x1f);
198: }
199: }
200: uVar16 = (uint)((ulong)uVar24 / (uVar27 & 0xffff));
201: uVar26 = uVar26 >> 1;
202: uVar24 = (uint)((ulong)uVar24 % (uVar27 & 0xffff));
203: if (uVar24 == 0) {
204: uVar16 = uVar16 >> 1;
205: iVar28 = iVar28 + -1;
206: }
207: else {
208: if (uVar26 < uVar24) {
209: uVar16 = uVar16 + 1;
210: }
211: else {
212: uVar26 = uVar26 + 1;
213: }
214: }
215: *(short *)(lVar19 + lVar29) = (short)uVar16;
216: *(ushort *)(lVar19 + 0x80 + lVar29) = uVar26;
217: *(short *)(lVar19 + 0x100 + lVar29) = (short)(1 << (-(char)iVar28 & 0x1fU));
218: *(short *)(lVar19 + 0x180 + lVar29) = (short)iVar28 + -0x10;
219: if (iVar28 < 0x11) goto LAB_00108d61;
220: LAB_00108c7f:
221: lVar29 = lVar29 + 2;
222: if (lVar29 == 0x80) goto LAB_00108b8c;
223: }
224: *(undefined2 *)(lVar19 + lVar29) = 1;
225: *(undefined2 *)(lVar19 + 0x80 + lVar29) = 0;
226: *(undefined2 *)(lVar19 + 0x100 + lVar29) = 1;
227: *(undefined2 *)(lVar19 + 0x180 + lVar29) = 0xfff0;
228: LAB_00108d61:
229: if (*(code **)(pcVar2 + 0x20) != FUN_0016c170) goto LAB_00108c7f;
230: lVar29 = lVar29 + 2;
231: *(code **)(pcVar2 + 0x20) = FUN_00107510;
232: } while (lVar29 != 0x80);
233: }
234: else {
235: if (iVar28 == 0) {
236: psVar20 = *(short **)(pcVar2 + lVar29 * 8 + 0x28);
237: if (psVar20 == (short *)0x0) {
238: psVar20 = (short *)(**(code **)param_1[1])(param_1,1,0x200);
239: *(short **)(pcVar2 + lVar29 * 8 + 0x28) = psVar20;
240: }
241: pauVar1 = pauVar23[8];
242: do {
243: uVar24 = (uint)*(ushort *)*pauVar23 * 8;
244: uVar26 = (ushort)uVar24;
245: if (uVar26 == 0) {
246: uVar16 = (uint)(0x8000 / (ulong)(uVar24 & 0xffff));
247: iVar15 = 0xf;
248: uVar17 = (uint)(0x8000 % (ulong)(uVar24 & 0xffff));
249: if (uVar17 == 0) goto LAB_00108ec2;
250: LAB_00108f34:
251: uVar26 = uVar26 >> 1;
252: sVar14 = (short)uVar16;
253: if (uVar26 < uVar17) {
254: sVar14 = sVar14 + 1;
255: }
256: else {
257: uVar26 = uVar26 + 1;
258: }
259: }
260: else {
261: if ((uVar24 & 0xff00) == 0) {
262: iVar15 = 4;
263: iVar28 = 8;
264: uVar16 = (uint)*(ushort *)*pauVar23 << 0xb;
265: }
266: else {
267: iVar15 = 0xc;
268: iVar28 = 0x10;
269: uVar16 = uVar24;
270: }
271: if ((uVar16 & 0xf000) == 0) {
272: uVar16 = uVar16 << 4;
273: iVar28 = iVar15;
274: }
275: sVar14 = (short)uVar16;
276: if ((uVar16 & 0xc000) == 0) {
277: iVar28 = iVar28 + -2;
278: sVar14 = (short)(uVar16 << 2);
279: }
280: iVar15 = iVar28 + 0xe;
281: bVar21 = (byte)iVar15;
282: if (sVar14 < 0) {
283: iVar15 = iVar28 + 0xf;
284: bVar21 = (byte)iVar15;
285: }
286: uVar17 = 1 << (bVar21 & 0x1f);
287: uVar16 = uVar17 / (uVar24 & 0xffff);
288: uVar17 = uVar17 % (uVar24 & 0xffff);
289: if (uVar17 != 0) goto LAB_00108f34;
290: LAB_00108ec2:
291: uVar26 = uVar26 >> 1;
292: sVar14 = (short)(uVar16 >> 1);
293: iVar15 = iVar15 + -1;
294: }
295: *psVar20 = sVar14;
296: psVar20[0x40] = uVar26;
297: psVar20[0x80] = (short)(1 << (-(char)iVar15 & 0x1fU));
298: psVar20[0xc0] = (short)iVar15 + -0x10;
299: if ((iVar15 < 0x11) && (*(code **)(pcVar2 + 0x20) == FUN_0016c170)) {
300: *(code **)(pcVar2 + 0x20) = FUN_00107510;
301: }
302: pauVar23 = (undefined (*) [16])(*pauVar23 + 2);
303: psVar20 = psVar20 + 1;
304: } while (pauVar1 != pauVar23);
305: }
306: else {
307: if (iVar28 == 2) {
308: puVar18 = *(undefined8 **)(pcVar2 + lVar29 * 8 + 0x68);
309: if (puVar18 == (undefined8 *)0x0) {
310: puVar18 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x100);
311: *(undefined8 **)(pcVar2 + lVar29 * 8 + 0x68) = puVar18;
312: }
313: auVar43 = *pauVar23;
314: uVar39 = *(undefined2 *)pauVar23[1];
315: uVar7 = *(undefined2 *)(pauVar23[1] + 2);
316: uVar38 = *(undefined2 *)(pauVar23[1] + 4);
317: uVar41 = *(undefined2 *)(pauVar23[1] + 8);
318: uVar56 = *(undefined2 *)(pauVar23[1] + 0xc);
319: uVar8 = *(undefined2 *)(pauVar23[1] + 0xe);
320: uVar35 = SUB162(auVar43 >> 0x30,0);
321: uVar34 = SUB162(auVar43 >> 0x20,0);
322: uVar33 = SUB162(auVar43 >> 0x10,0);
323: auVar52 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
324: (*(undefined2 *)(pauVar23[1] + 6),
325: CONCAT212(uVar35,SUB1612(auVar43,0))) >> 0x60,0),
326: CONCAT210(uVar38,SUB1610(auVar43,0))) >> 0x50,0),
327: CONCAT28(uVar34,SUB168(auVar43,0))) >> 0x40,0),
328: uVar7),uVar33)) << 0x20;
329: uVar57 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar23[1] + 6),
330: CONCAT212(uVar35,SUB1612(auVar43,0))) >> 0x60
331: ,0),CONCAT210(uVar38,SUB1610(auVar43,0))) >> 0x50,0);
332: auVar53 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar57,CONCAT28(uVar34,SUB168(auVar43,0)))
333: >> 0x40,0),uVar7)) << 0x30 &
334: (undefined  [16])0xffffffff00000000;
335: auVar51 = pauVar23[2];
336: uVar74 = SUB162(auVar43 >> 0x40,0);
337: uVar62 = SUB162(auVar43 >> 0x50,0);
338: uVar75 = SUB162(auVar43 >> 0x70,0);
339: uVar61 = *(undefined2 *)pauVar23[3];
340: uVar47 = *(undefined2 *)(pauVar23[3] + 4);
341: uVar50 = *(undefined2 *)(pauVar23[3] + 6);
342: auVar127 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
343: undefined2 *)(pauVar23[1] + 10),
344: CONCAT212(SUB162(auVar52 >> 0x30,0),
345: SUB1612(auVar52,0))) >> 0x60,0),
346: CONCAT210(uVar62,SUB1610(auVar52,0))) >> 0x50,0),
347: CONCAT28(uVar33,SUB168(auVar52,0))) >> 0x40,0),
348: uVar41)) << 0x30;
349: auVar52 = pauVar23[4];
350: auVar53 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
351: undefined2 *)(pauVar23[1] + 10),
352: CONCAT212(uVar7,SUB1612(auVar53,0))) >> 0x60,0),
353: CONCAT210(uVar62,SUB1610(auVar53,0))) >> 0x50,0),
354: CONCAT28(uVar33,SUB168(auVar53,0))) >> 0x40,0),
355: uVar41)) << 0x30 & (undefined  [16])0xffffffff00000000;
356: uVar81 = SUB162(auVar51 >> 0x40,0);
357: uVar83 = SUB162(auVar51 >> 0x60,0);
358: uVar84 = SUB162(auVar51 >> 0x70,0);
359: uVar72 = SUB162(auVar51 >> 0x30,0);
360: uVar71 = SUB162(auVar51 >> 0x20,0);
361: uVar7 = *(undefined2 *)pauVar23[5];
362: uVar33 = *(undefined2 *)(pauVar23[5] + 2);
363: uVar62 = *(undefined2 *)(pauVar23[5] + 4);
364: uVar9 = *(undefined2 *)(pauVar23[5] + 8);
365: uVar10 = *(undefined2 *)(pauVar23[5] + 0xc);
366: uVar11 = *(undefined2 *)(pauVar23[5] + 0xe);
367: uVar65 = SUB162(auVar51 >> 0x10,0);
368: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
369: (uVar50,CONCAT212(uVar72,SUB1612(auVar51,0))) >>
370: 0x60,0),CONCAT210(uVar47,SUB1610(auVar51,0))) >>
371: 0x50,0),CONCAT28(uVar71,SUB168(auVar51,0))) >>
372: 0x40,0),*(undefined2 *)(pauVar23[3] + 2)),uVar65))
373: << 0x20;
374: uVar60 = SUB164(CONCAT214(uVar56,CONCAT212(uVar41,SUB1612(auVar53,0))) >> 0x60,0);
375: uVar55 = SUB168(CONCAT610(SUB166(CONCAT412(uVar60,CONCAT210(uVar38,SUB1610(auVar53,0)))
376: >> 0x50,0),CONCAT28(uVar39,SUB168(auVar53,0))) >> 0x40,
377: 0);
378: uVar27 = (ulong)CONCAT24(uVar38,CONCAT22(SUB162(auVar43 >> 0x60,0),uVar34)) & 0xffff0000
379: ;
380: auVar126 = CONCAT88(uVar55,(uVar27 >> 0x10) << 0x30) &
381: (undefined  [16])0xffff000000000000;
382: uVar26 = SUB162((auVar127 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
383: uVar37 = SUB162((auVar127 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
384: uVar40 = SUB162(auVar127 >> 0x60,0);
385: uVar87 = SUB162(auVar52 >> 0x30,0);
386: uVar86 = SUB162(auVar52 >> 0x20,0);
387: uVar89 = SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar23[5] + 6),
388: CONCAT212(uVar87,SUB1612(auVar52,0))) >> 0x60
389: ,0),CONCAT210(uVar62,SUB1610(auVar52,0))) >> 0x50,0);
390: uVar24 = SUB164(auVar52,0) & 0xffff;
391: auVar102 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar89,CONCAT28(uVar86,SUB168(auVar52,0)))
392: >> 0x40,0),uVar33)) << 0x30 &
393: (undefined  [16])0xffffffff00000000;
394: auVar53 = pauVar23[6];
395: auVar103 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
396: undefined2 *)(pauVar23[3] + 10),
397: CONCAT212(SUB162(auVar70 >> 0x30,0),
398: SUB1612(auVar70,0))) >> 0x60,0),
399: CONCAT210(SUB162(auVar51 >> 0x50,0),
400: SUB1610(auVar70,0))) >> 0x50,0),
401: CONCAT28(uVar65,SUB168(auVar70,0))) >> 0x40,0),
402: *(undefined2 *)(pauVar23[3] + 8))) << 0x30;
403: uVar44 = SUB162(auVar52 >> 0x10,0);
404: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
405: (*(undefined2 *)(pauVar23[5] + 6),
406: CONCAT212(uVar87,SUB1612(auVar52,0))) >> 0x60,0),
407: CONCAT210(uVar62,SUB1610(auVar52,0))) >> 0x50,0),
408: CONCAT28(uVar86,SUB168(auVar52,0))) >> 0x40,0),
409: uVar33),uVar44)) << 0x20;
410: uVar82 = SUB162(auVar52 >> 0x40,0);
411: uVar48 = SUB162(auVar52 >> 0x50,0);
412: uVar85 = SUB162(auVar52 >> 0x70,0);
413: uVar65 = *(undefined2 *)pauVar23[7];
414: uVar67 = SUB162((auVar103 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
415: uVar68 = SUB162((auVar103 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
416: uVar69 = SUB162(auVar103 >> 0x70,0);
417: auVar102 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
418: undefined2 *)(pauVar23[5] + 10),
419: CONCAT212(uVar33,SUB1612(auVar102,0))) >> 0x60,0),
420: CONCAT210(uVar48,SUB1610(auVar102,0))) >> 0x50,0),
421: CONCAT28(uVar44,SUB168(auVar102,0))) >> 0x40,0),
422: uVar9)) << 0x30 & (undefined  [16])0xffffffff00000000;
423: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
424: undefined2 *)(pauVar23[5] + 10),
425: CONCAT212(SUB162(auVar70 >> 0x30,0),
426: SUB1612(auVar70,0))) >> 0x60,0),
427: CONCAT210(uVar48,SUB1610(auVar70,0))) >> 0x50,0),
428: CONCAT28(uVar44,SUB168(auVar70,0))) >> 0x40,0),
429: uVar9)) << 0x30;
430: uVar91 = SUB162(auVar53 >> 0x40,0);
431: uVar94 = SUB162(auVar53 >> 0x60,0);
432: uVar96 = SUB162(auVar53 >> 0x70,0);
433: uVar80 = SUB162(auVar53 >> 0x30,0);
434: uVar77 = SUB162(auVar53 >> 0x20,0);
435: uVar33 = SUB162(auVar53,0);
436: uVar22 = (ulong)CONCAT24(uVar62,CONCAT22(SUB162(auVar52 >> 0x60,0),uVar86)) & 0xffff0000
437: ;
438: auVar104 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar10,CONCAT212(
439: uVar9,SUB1612(auVar102,0))) >> 0x60,0),
440: CONCAT210(uVar62,SUB1610(auVar102,0))) >> 0x50,0),
441: CONCAT28(uVar7,SUB168(auVar102,0))) >> 0x40,0),
442: (uVar22 >> 0x10) << 0x30) & (undefined  [16])0xffff000000000000;
443: uVar45 = SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
444: uVar44 = SUB162((auVar70 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
445: uVar48 = SUB162(auVar70 >> 0x60,0);
446: uVar49 = SUB162(auVar70 >> 0x70,0);
447: uVar58 = SUB162(auVar53 >> 0x10,0);
448: auVar70 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
449: (*(undefined2 *)(pauVar23[7] + 6),
450: CONCAT212(uVar80,SUB1612(auVar53,0))) >> 0x60,0),
451: CONCAT210(*(undefined2 *)(pauVar23[7] + 4),
452: SUB1610(auVar53,0))) >> 0x50,0),
453: CONCAT28(uVar77,SUB168(auVar53,0))) >> 0x40,0),
454: *(undefined2 *)(pauVar23[7] + 2)),uVar58)) << 0x20
455: ;
456: uVar98 = (undefined2)(uVar27 >> 0x10);
457: uVar6 = SUB166(CONCAT412(SUB164(CONCAT214(uVar83,CONCAT212(uVar98,SUB1612(auVar126,0)))
458: >> 0x60,0),CONCAT210(uVar81,SUB1610(auVar126,0))) >>
459: 0x50,0);
460: auVar102 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar6,CONCAT28(uVar74,SUB168(auVar126,0)))
461: >> 0x40,0),uVar71) &
462: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
463: (undefined  [16])0xffffffff00000000;
464: auVar125 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
465: undefined2 *)(pauVar23[7] + 10),
466: CONCAT212(SUB162(auVar70 >> 0x30,0),
467: SUB1612(auVar70,0))) >> 0x60,0),
468: CONCAT210(SUB162(auVar53 >> 0x50,0),
469: SUB1610(auVar70,0))) >> 0x50,0),
470: CONCAT28(uVar58,SUB168(auVar70,0))) >> 0x40,0),
471: *(undefined2 *)(pauVar23[7] + 8))) << 0x30;
472: auVar53 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
473: (uVar83,CONCAT212(uVar98,SUB1612(auVar126,0))) >>
474: 0x60,0),CONCAT210(uVar81,SUB1610(auVar126,0))) >>
475: 0x50,0),CONCAT28(uVar74,SUB168(auVar126,0))) >>
476: 0x40,0),uVar71) &
477: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
478: uVar34)) << 0x20;
479: uVar63 = SUB162((auVar125 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
480: uVar64 = SUB162((auVar125 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
481: uVar73 = (undefined2)(uVar22 >> 0x10);
482: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar47,
483: CONCAT212(uVar71,SUB1612(auVar102,0))) >> 0x60,0),
484: CONCAT210(uVar38,SUB1610(auVar102,0))) >> 0x50,0),
485: CONCAT28(uVar34,SUB168(auVar102,0))) >> 0x40,0),
486: uVar61)) << 0x30 & (undefined  [16])0xffffffff00000000;
487: auVar102 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar47,
488: CONCAT212(SUB162(auVar53 >> 0x30,0),
489: SUB1612(auVar53,0))) >> 0x60,0),
490: CONCAT210(uVar38,SUB1610(auVar53,0))) >> 0x50,0),
491: CONCAT28(uVar34,SUB168(auVar53,0))) >> 0x40,0),
492: uVar61)) << 0x30;
493: auVar53 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
494: (uVar94,CONCAT212(uVar73,SUB1612(auVar104,0))) >>
495: 0x60,0),CONCAT210(uVar91,SUB1610(auVar104,0))) >>
496: 0x50,0),CONCAT28(uVar82,SUB168(auVar104,0))) >>
497: 0x40,0),uVar77) &
498: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
499: uVar86)) << 0x20;
500: auVar119 = CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(undefined2 *)(pauVar23[3] + 8),
501: CONCAT212(uVar61,SUB1612(auVar70,
502: 0))) >> 0x60,0),
503: CONCAT210(uVar81,SUB1610(auVar70,0))) >> 0x50,0),
504: CONCAT28(SUB162(auVar51,0),SUB168(auVar70,0))) &
505: (undefined  [16])0xffffffffffffffff;
506: uVar100 = SUB168(auVar119 >> 0x40,0);
507: uVar27 = (ulong)CONCAT24(uVar81,CONCAT22(uVar41,uVar74)) & 0xffff0000;
508: auVar105 = CONCAT88(uVar100,(uVar27 >> 0x10) << 0x30) &
509: (undefined  [16])0xffff000000000000;
510: uVar34 = SUB162((auVar102 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
511: uVar58 = SUB162(auVar102 >> 0x60,0);
512: Var12 = CONCAT28(uVar58,uVar55);
513: auVar115 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
514: undefined2 *)(pauVar23[7] + 4),
515: CONCAT212(SUB162(auVar53 >> 0x30,0),
516: SUB1612(auVar53,0))) >> 0x60,0),
517: CONCAT210(uVar62,SUB1610(auVar53,0))) >> 0x50,0),
518: CONCAT28(uVar86,SUB168(auVar53,0))) >> 0x40,0),
519: uVar65)) << 0x30;
520: uVar22 = (ulong)(uVar57 & 0xffff00000000 |
521: (uint6)CONCAT22(SUB162(auVar103 >> 0x60,0),uVar40));
522: uVar16 = CONCAT22(uVar84,uVar75);
523: auVar70 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(uVar16,uVar68),
524: CONCAT22(uVar37,uVar75)) >> 0x10),uVar72))
525: << 0x30 & (undefined  [16])0xffffffff00000000;
526: auVar53 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar84,uVar75),
527: uVar68),
528: CONCAT22(uVar37,uVar75)) >> 0x10),
529: uVar72),uVar35)) << 0x20;
530: uVar88 = SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
531: uVar4 = (ulong)CONCAT24(SUB162((auVar115 & (undefined  [16])0xffffffff00000000) >> 0x50,
532: 0),CONCAT22(uVar73,uVar88));
533: uVar77 = SUB162(auVar115 >> 0x70,0);
534: uVar38 = (undefined2)(uVar22 >> 0x20);
535: uVar71 = (undefined2)(uVar22 >> 0x10);
536: auVar103 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
537: CONCAT214(uVar50,CONCAT212(uVar72,SUB1612(auVar70,
538: 0))) >> 0x60,0),
539: CONCAT210(uVar38,SUB1610(auVar70,0))) >> 0x50,0),
540: CONCAT28(uVar35,SUB168(auVar70,0))) >> 0x40,0),
541: uVar71)) << 0x30) >> 0x20,0) &
542: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
543: auVar70 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar50,
544: CONCAT212(SUB162(auVar53 >> 0x30,0),
545: SUB1612(auVar53,0))) >> 0x60,0),
546: CONCAT210(uVar38,SUB1610(auVar53,0))) >> 0x50,0),
547: CONCAT28(uVar35,SUB168(auVar53,0))) >> 0x40,0),
548: uVar71) & 0xffffffffffffffff) << 0x30;
549: auVar53 = auVar70 & (undefined  [16])0xffffffff00000000;
550: auVar126 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar96,uVar85),
551: uVar64),
552: CONCAT22(uVar44,uVar85)) >> 0x10)
553: ,uVar80),uVar87)) << 0x20;
554: uVar5 = (ulong)(uVar89 & 0xffff00000000 |
555: (uint6)CONCAT22(SUB162(auVar125 >> 0x60,0),uVar48));
556: uVar93 = SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar69,CONCAT212(uVar71,
557: SUB1612(auVar103,0))) >> 0x60,0),
558: CONCAT210(uVar68,SUB1610(auVar103,0))) >> 0x50,0),
559: CONCAT28(uVar67,SUB168(auVar103,0))) >> 0x40,0);
560: uVar22 = (ulong)CONCAT24(uVar68,CONCAT22(SUB162(auVar127 >> 0x70,0),uVar37)) &
561: 0xffff0000;
562: auVar104 = CONCAT88(uVar93,(uVar22 >> 0x10) << 0x30) &
563: (undefined  [16])0xffff000000000000;
564: uVar38 = SUB162(auVar53 >> 0x50,0);
565: uVar41 = SUB162(auVar70 >> 0x60,0);
566: uVar35 = (undefined2)(uVar5 >> 0x10);
567: auVar127 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(*(
568: undefined2 *)(pauVar23[7] + 6),
569: CONCAT212(SUB162(auVar126 >> 0x30,0),
570: SUB1612(auVar126,0))) >> 0x60,0),
571: CONCAT210((short)(uVar5 >> 0x20),
572: SUB1610(auVar126,0))) >> 0x50,0),
573: CONCAT28(uVar87,SUB168(auVar126,0))) >> 0x40,0),
574: uVar35) & 0xffffffffffffffff) << 0x30;
575: uVar72 = (undefined2)(uVar27 >> 0x10);
576: uVar57 = SUB166(CONCAT412(SUB164(CONCAT214(uVar9,CONCAT212(uVar72,SUB1612(auVar105,0)))
577: >> 0x60,0),CONCAT210(uVar7,SUB1610(auVar105,0))) >>
578: 0x50,0);
579: auVar103 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar57,CONCAT28(uVar39,SUB168(auVar105,0))
580: ) >> 0x40,0),uVar82) &
581: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
582: (undefined  [16])0xffffffff00000000;
583: auVar105 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
584: CONCAT214(uVar9,CONCAT212(uVar72,SUB1612(auVar105,
585: 0))) >> 0x60,0),
586: CONCAT210(uVar7,SUB1610(auVar105,0))) >> 0x50,0),
587: CONCAT28(uVar39,SUB168(auVar105,0))) >> 0x40,0),
588: uVar82) &
589: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
590: uVar74)) << 0x20;
591: uVar46 = SUB162((auVar127 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
592: uVar47 = SUB162((auVar127 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
593: uVar50 = SUB162(auVar127 >> 0x70,0);
594: uVar62 = (undefined2)(uVar22 >> 0x10);
595: uVar89 = SUB166(CONCAT412(SUB164(CONCAT214(uVar49,CONCAT212(uVar62,SUB1612(auVar104,0)))
596: >> 0x60,0),CONCAT210(uVar48,SUB1610(auVar104,0))) >>
597: 0x50,0);
598: auVar126 = ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar89,CONCAT28(uVar40,SUB168(auVar104,0))
599: ) >> 0x40,0),uVar44) &
600: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0)) << 0x30 &
601: (undefined  [16])0xffffffff00000000;
602: auVar103 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
603: CONCAT214(uVar91,CONCAT212(uVar82,SUB1612(auVar103
604: ,0))) >> 0x60,0),
605: CONCAT210(uVar81,SUB1610(auVar103,0))) >> 0x50,0),
606: CONCAT28(uVar74,SUB168(auVar103,0))) >> 0x40,0),
607: uVar33)) << 0x30) >> 0x20,0) &
608: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
609: auVar124 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar91,
610: CONCAT212(SUB162(auVar105 >> 0x30,0),
611: SUB1612(auVar105,0))) >> 0x60,0),
612: CONCAT210(uVar81,SUB1610(auVar105,0))) >> 0x50,0),
613: CONCAT28(uVar74,SUB168(auVar105,0))) >> 0x40,0),
614: uVar33) & 0xffffffffffffffff) << 0x30;
615: auVar123 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
616: CONCAT214(uVar49,CONCAT212(uVar62,SUB1612(auVar104
617: ,0))) >> 0x60,0),
618: CONCAT210(uVar48,SUB1610(auVar104,0))) >> 0x50,0),
619: CONCAT28(uVar40,SUB168(auVar104,0))) >> 0x40,0),
620: uVar44) &
621: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
622: uVar37)) << 0x20;
623: uVar27 = (ulong)CONCAT24(uVar7,CONCAT22(uVar61,uVar39)) & 0xffff0000;
624: auVar105 = ZEXT1416(CONCAT122(SUB1612((ZEXT1016(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166
625: (CONCAT412(SUB164(CONCAT214(uVar65,CONCAT212(
626: uVar33,SUB1612(auVar103,0))) >> 0x60,0),
627: CONCAT210(uVar7,SUB1610(auVar103,0))) >> 0x50,0),
628: CONCAT28((short)uVar24,SUB168(auVar103,0))) >>
629: 0x40,0),(uVar27 >> 0x10) << 0x30) >> 0x30,0) &
630: SUB1610((undefined  [16])0xffffffffffffffff >>
631: 0x30,0)) << 0x30) >> 0x20,0),uVar39)) <<
632: 0x10;
633: uVar99 = SUB162((auVar124 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
634: uVar97 = CONCAT24(SUB162((auVar124 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
635: CONCAT22(uVar72,uVar99));
636: uVar101 = SUB162(auVar124 >> 0x60,0);
637: uVar73 = (undefined2)(uVar4 >> 0x20);
638: uVar13 = SUB166(CONCAT412(SUB164(CONCAT214(uVar10,CONCAT212(uVar56,CONCAT210(uVar83,
639: Var12))) >> 0x60,0),CONCAT210(uVar73,Var12)) >>
640: 0x50,0);
641: uVar72 = (undefined2)(uVar4 >> 0x10);
642: auVar103 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(uVar13,CONCAT28(uVar34,
643: uVar55)) >> 0x40,0),uVar72) & 0xffffffffffffffff)
644: << 0x30) >> 0x20,0) &
645: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
646: auVar104 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar64,
647: CONCAT212(uVar44,SUB1612(auVar126,0))) >> 0x60,0),
648: CONCAT210(uVar68,SUB1610(auVar126,0))) >> 0x50,0),
649: CONCAT28(uVar37,SUB168(auVar126,0))) >> 0x40,0),
650: uVar63)) << 0x30 & (undefined  [16])0xffffffff00000000;
651: auVar123 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar64,
652: CONCAT212(SUB162(auVar123 >> 0x30,0),
653: SUB1612(auVar123,0))) >> 0x60,0),
654: CONCAT210(uVar68,SUB1610(auVar123,0))) >> 0x50,0),
655: CONCAT28(uVar37,SUB168(auVar123,0))) >> 0x40,0),
656: uVar63)) << 0x30;
657: auVar126 = ZEXT1216(CONCAT102(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
658: CONCAT214(uVar10,CONCAT212(uVar56,CONCAT210(uVar83
659: ,Var12))) >> 0x60,0),CONCAT210(uVar73,Var12)) >>
660: 0x50,0),CONCAT28(uVar34,uVar55)) >> 0x40,0),uVar72
661: ),uVar98) & (undefined  [12])0xffffffffffffffff)
662: << 0x20;
663: uVar4 = (ulong)(uVar6 & 0xffff00000000 |
664: (uint6)CONCAT22(SUB162(auVar115 >> 0x60,0),uVar58));
665: uVar22 = (ulong)CONCAT24(uVar48,CONCAT22(uVar71,uVar40)) & 0xffff0000;
666: auVar104 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
667: (uVar35,CONCAT212(uVar63,SUB1612(auVar104,0))) >>
668: 0x60,0),CONCAT210(uVar48,SUB1610(auVar104,0))) >>
669: 0x50,0),CONCAT28(uVar45,SUB168(auVar104,0))) >>
670: 0x40,0),(uVar22 >> 0x10) << 0x30) >> 0x20,0) &
671: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
672: CONCAT22(uVar40,uVar26));
673: uVar92 = SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
674: uVar90 = CONCAT24(SUB162((auVar123 & (undefined  [16])0xffffffff00000000) >> 0x50,0),
675: CONCAT22(uVar62,uVar92));
676: uVar95 = SUB162(auVar123 >> 0x60,0);
677: uVar39 = (undefined2)(uVar4 >> 0x20);
678: uVar61 = (undefined2)(uVar4 >> 0x10);
679: auVar126 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar94,
680: CONCAT212(SUB162(auVar126 >> 0x30,0),
681: SUB1612(auVar126,0))) >> 0x60,0),
682: CONCAT210(uVar39,SUB1610(auVar126,0))) >> 0x50,0),
683: CONCAT28(uVar98,SUB168(auVar126,0))) >> 0x40,0),
684: uVar61) & 0xffffffffffffffff) << 0x30;
685: auVar103 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
686: CONCAT214(uVar94,CONCAT212(uVar72,SUB1612(auVar103
687: ,0))) >> 0x60,0),
688: CONCAT210(uVar39,SUB1610(auVar103,0))) >> 0x50,0),
689: CONCAT28(uVar98,SUB168(auVar103,0))) >> 0x40,0),
690: uVar61)) << 0x30) >> 0x20,0) &
691: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
692: uVar56 = SUB162((auVar126 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
693: uVar6 = CONCAT24(uVar56,uVar60);
694: uVar55 = CONCAT26(*(undefined2 *)(pauVar23[3] + 0xc),uVar6);
695: uVar59 = SUB162(auVar126 >> 0x60,0);
696: uVar4 = (ulong)CONCAT24(uVar73,CONCAT22(SUB162(auVar102 >> 0x70,0),uVar34)) & 0xffff0000
697: ;
698: auVar103 = ZEXT1416(CONCAT122(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
699: CONCAT214(uVar77,CONCAT212(uVar61,SUB1612(auVar103
700: ,0))) >> 0x60,0),
701: CONCAT210(uVar73,SUB1610(auVar103,0))) >> 0x50,0),
702: CONCAT28(uVar88,SUB168(auVar103,0))) >> 0x40,0),
703: (uVar4 >> 0x10) << 0x30) >> 0x20,0) &
704: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
705: uVar34)) << 0x10;
706: uVar5 = (ulong)(((uint6)uVar16 & 0xffff0000) << 0x10 |
707: (uint6)CONCAT22(SUB162(auVar127 >> 0x60,0),uVar41));
708: auVar115 = ZEXT1016(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar11,uVar8),uVar47),
709: CONCAT22(uVar38,uVar8)) >> 0x10),uVar85))
710: << 0x30 & (undefined  [16])0xffffffff00000000;
711: auVar127 = ZEXT1216(CONCAT102(CONCAT82((long)(CONCAT64(CONCAT42(CONCAT22(uVar11,uVar8),
712: uVar47),
713: CONCAT22(uVar38,uVar8)) >> 0x10),
714: uVar85),uVar75)) << 0x20;
715: uVar39 = (undefined2)(uVar5 >> 0x20);
716: uVar62 = (undefined2)(uVar5 >> 0x10);
717: auVar127 = ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(uVar96,
718: CONCAT212(SUB162(auVar127 >> 0x30,0),
719: SUB1612(auVar127,0))) >> 0x60,0),
720: CONCAT210(uVar39,SUB1610(auVar127,0))) >> 0x50,0),
721: CONCAT28(uVar75,SUB168(auVar127,0))) >> 0x40,0),
722: uVar62) & 0xffffffffffffffff) << 0x30;
723: auVar115 = ZEXT1216(SUB1612((ZEXT1016(CONCAT82(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(
724: CONCAT214(uVar96,CONCAT212(uVar85,SUB1612(auVar115
725: ,0))) >> 0x60,0),
726: CONCAT210(uVar39,SUB1610(auVar115,0))) >> 0x50,0),
727: CONCAT28(uVar75,SUB168(auVar115,0))) >> 0x40,0),
728: uVar62)) << 0x30) >> 0x20,0) &
729: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0)) << 0x20;
730: uVar36 = SUB162((auVar127 & (undefined  [16])0xffffffff00000000) >> 0x40,0);
731: uVar39 = SUB162((auVar127 & (undefined  [16])0xffffffff00000000) >> 0x50,0);
732: uVar30 = CONCAT24(uVar39,CONCAT22(uVar8,uVar36));
733: uVar31 = CONCAT26(*(undefined2 *)(pauVar23[3] + 0xe),uVar30);
734: uVar42 = SUB162(auVar127 >> 0x60,0);
735: uVar5 = (ulong)CONCAT24(uVar47,CONCAT22(SUB162(auVar70 >> 0x70,0),uVar38)) & 0xffff0000;
736: auVar115 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214
737: (uVar50,CONCAT212(uVar62,SUB1612(auVar115,0))) >>
738: 0x60,0),CONCAT210(uVar47,SUB1610(auVar115,0))) >>
739: 0x50,0),CONCAT28(uVar46,SUB168(auVar115,0))) >>
740: 0x40,0),(uVar5 >> 0x10) << 0x30) >> 0x20,0) &
741: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
742: SUB164(auVar53 >> 0x40,0));
743: auVar32 = ZEXT1012(CONCAT28(uVar33,(ulong)(CONCAT24(uVar7,SUB164(auVar52,0)) &
744: 0xffff0000ffff)) & 0xffffffffffffffff);
745: auVar120 = divpd(_DAT_0016c720,
746: CONCAT88((double)SUB164(CONCAT106((unkuint10)
747: (SUB148(CONCAT68(SUB146(CONCAT410(
748: SUB144(CONCAT212((short)(uVar27 >> 0x10),
749: SUB1612(auVar105,0)) >> 0x50,0),
750: CONCAT28(SUB162(auVar51,0),SUB168(auVar105,0))) >>
751: 0x40,0),SUB168(auVar105,0)) >> 0x30,0) & 0xffff) &
752: SUB1610((undefined  [16])0xffffffffffffffff >>
753: 0x30,0) &
754: SUB1610((undefined  [16])0xffffffffffffffff >>
755: 0x30,0),
756: (SUB166(auVar105,0) >> 0x10) << 0x20) >> 0x20,0) *
757: 1.387039845 * 8.0,
758: (double)(SUB164(auVar43,0) & 0xffff) * 1.0 * 8.0));
759: auVar107 = divpd(_DAT_0016c720,ZEXT816(0) << 0x40);
760: dVar76 = (double)SUB164(ZEXT1416(CONCAT212(uVar65,auVar32)) >> 0x40,0);
761: auVar121 = divpd(_DAT_0016c720,
762: CONCAT88((double)SUB124(auVar32 >> 0x20,0) * 0.785694958 * 8.0,
763: (double)uVar24 * 1.0 * 8.0));
764: auVar108 = divpd(_DAT_0016c720,
765: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 0.275899379 * 8.0,
766: dVar76 * 0.5411961 * 8.0));
767: fVar78 = (float)SUB168(auVar108 >> 0x40,0);
768: auVar32 = ZEXT1012(CONCAT28(uVar63,(ulong)CONCAT24(uVar48,(uint)uVar45)));
769: Var54 = (unkuint10)
770: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212((short)(uVar22 >> 0x10),
771: SUB1612(auVar104,0)) >> 0x50,0
772: ),CONCAT28(uVar67,SUB168(auVar104,0))) >>
773: 0x40,0),SUB168(auVar104,0)) >> 0x30,0) &
774: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
775: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
776: dVar76 = (double)(int)(Var54 >> 0x10);
777: auVar122 = divpd(_DAT_0016c720,
778: CONCAT88((double)SUB164(CONCAT106(Var54,(SUB166(auVar104,0) >> 0x10) <<
779: 0x20) >> 0x20,0) * 1.387039845
780: * 1.387039845 * 8.0,
781: (double)(uint)uVar26 * 1.0 * 1.387039845 * 8.0));
782: auVar109 = divpd(_DAT_0016c720,
783: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 1.175875602 *
784: 1.387039845 * 8.0,dVar76 * 1.306562965 * 1.387039845 * 8.0));
785: fVar106 = (float)SUB168(auVar122 >> 0x40,0);
786: dVar76 = (double)SUB164(ZEXT1416(CONCAT212(uVar35,auVar32)) >> 0x40,0);
787: auVar110 = divpd(_DAT_0016c720,
788: CONCAT88((double)SUB124(auVar32 >> 0x20,0) * 0.785694958 * 1.387039845
789: * 8.0,(double)(uint)uVar45 * 1.0 * 1.387039845 * 8.0));
790: fVar79 = (float)SUB168(auVar110 >> 0x40,0);
791: auVar111 = divpd(_DAT_0016c720,
792: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 0.275899379 *
793: 1.387039845 * 8.0,dVar76 * 0.5411961 * 1.387039845 * 8.0));
794: auVar32 = ZEXT1012(CONCAT28(uVar61,(ulong)CONCAT24(uVar73,(uint)uVar88)));
795: Var54 = (unkuint10)
796: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212((short)(uVar4 >> 0x10),
797: SUB1612(auVar103,0)) >> 0x50,0
798: ),CONCAT28(uVar58,SUB168(auVar103,0))) >>
799: 0x40,0),SUB168(auVar103,0)) >> 0x30,0) &
800: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
801: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
802: dVar76 = (double)((uint)(Var54 >> 0x10) & 0xffff);
803: auVar112 = divpd(_DAT_0016c720,
804: CONCAT88((double)SUB164(CONCAT106(Var54,(SUB166(auVar103,0) >> 0x10) <<
805: 0x20) >> 0x20,0) * 1.387039845
806: * 1.306562965 * 8.0,
807: (double)(uint)SUB162((auVar102 &
808: (undefined  [16])0xffffffff00000000) >>
809: 0x40,0) * 1.0 * 1.306562965 * 8.0));
810: auVar113 = divpd(_DAT_0016c720,
811: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 1.175875602 *
812: 1.306562965 * 8.0,dVar76 * 1.306562965 * 1.306562965 * 8.0));
813: dVar76 = (double)SUB164(ZEXT1416(CONCAT212(uVar77,auVar32)) >> 0x40,0);
814: auVar114 = divpd(_DAT_0016c720,
815: CONCAT88((double)SUB124(auVar32 >> 0x20,0) * 0.785694958 * 1.306562965
816: * 8.0,(double)(uint)uVar88 * 1.0 * 1.306562965 * 8.0));
817: auVar70 = divpd(_DAT_0016c720,
818: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 0.275899379 *
819: 1.306562965 * 8.0,dVar76 * 0.5411961 * 1.306562965 * 8.0));
820: fVar66 = (float)SUB168(auVar70 >> 0x40,0);
821: auVar32 = ZEXT1012(CONCAT28(uVar62,(ulong)CONCAT24(uVar47,(uint)uVar46)));
822: Var54 = (unkuint10)
823: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212((short)(uVar5 >> 0x10),
824: SUB1612(auVar115,0)) >> 0x50,0
825: ),CONCAT28(uVar41,SUB168(auVar115,0))) >>
826: 0x40,0),SUB168(auVar115,0)) >> 0x30,0) &
827: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
828: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
829: dVar76 = (double)(int)(Var54 >> 0x10);
830: auVar115 = divpd(_DAT_0016c720,
831: CONCAT88((double)SUB164(CONCAT106(Var54,(SUB166(auVar115,0) >> 0x10) <<
832: 0x20) >> 0x20,0) * 1.387039845
833: * 1.175875602 * 8.0,
834: (double)(uint)SUB162(auVar53 >> 0x40,0) * 1.0 * 1.175875602 *
835: 8.0));
836: auVar116 = divpd(_DAT_0016c720,
837: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 1.175875602 *
838: 1.175875602 * 8.0,dVar76 * 1.306562965 * 1.175875602 * 8.0));
839: dVar76 = (double)SUB164(ZEXT1416(CONCAT212(uVar50,auVar32)) >> 0x40,0);
840: auVar117 = divpd(_DAT_0016c720,
841: CONCAT88((double)SUB124(auVar32 >> 0x20,0) * 0.785694958 * 1.175875602
842: * 8.0,(double)(uint)uVar46 * 1.0 * 1.175875602 * 8.0));
843: auVar118 = divpd(_DAT_0016c720,
844: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 0.275899379 *
845: 1.175875602 * 8.0,dVar76 * 0.5411961 * 1.175875602 * 8.0));
846: auVar32 = ZEXT1012(CONCAT28(SUB162(auVar124 >> 0x70,0),(ulong)(uVar57 & 0xffff00000000))
847: );
848: auVar119 = divpd(_DAT_0016c720,
849: CONCAT88((double)SUB164(CONCAT106((unkuint10)
850: (SUB148(CONCAT68(SUB146(CONCAT410(
851: SUB144(CONCAT212(SUB162(auVar119 >> 0x70,0),
852: CONCAT210(uVar9,CONCAT28(uVar101,
853: uVar100))) >> 0x50,0),
854: CONCAT28((short)((ulong)uVar97 >> 0x20),uVar100))
855: >> 0x40,0),uVar100) >> 0x30,0) & 0xffff) &
856: SUB1610((undefined  [16])0xffffffffffffffff >>
857: 0x30,0) &
858: SUB1610((undefined  [16])0xffffffffffffffff >>
859: 0x30,0),(uVar97 >> 0x10) << 0x20) >> 0x20,
860: 0) * 1.387039845 * 8.0,
861: (double)(uint)uVar99 * 1.0 * 8.0));
862: auVar103 = divpd(_DAT_0016c720,ZEXT816(0) << 0x40);
863: dVar76 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar23[7] + 8),auVar32)) >>
864: 0x40,0);
865: auVar104 = divpd(_DAT_0016c720,
866: CONCAT88((double)SUB124(auVar32 >> 0x20,0) * 0.785694958 * 8.0,
867: (double)(uint)uVar101 * 1.0 * 8.0));
868: auVar105 = divpd(_DAT_0016c720,
869: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 0.275899379 * 8.0,
870: dVar76 * 0.5411961 * 8.0));
871: auVar32 = ZEXT1012(CONCAT28(SUB162(auVar123 >> 0x70,0),(ulong)(uVar89 & 0xffff00000000))
872: );
873: auVar123 = divpd(_DAT_0016c720,
874: CONCAT88((double)SUB164(CONCAT106((unkuint10)
875: (SUB148(CONCAT68(SUB146(CONCAT410(
876: SUB144(CONCAT212(uVar69,CONCAT210(uVar49,CONCAT28(
877: uVar95,uVar93))) >> 0x50,0),
878: CONCAT28((short)((ulong)uVar90 >> 0x20),uVar93))
879: >> 0x40,0),uVar93) >> 0x30,0) & 0xffff) &
880: SUB1610((undefined  [16])0xffffffffffffffff >>
881: 0x30,0) &
882: SUB1610((undefined  [16])0xffffffffffffffff >>
883: 0x30,0),(uVar90 >> 0x10) << 0x20) >> 0x20,
884: 0) * 1.387039845 * 0.785694958 * 8.0,
885: (double)(uint)uVar92 * 1.0 * 0.785694958 * 8.0));
886: auVar124 = divpd(_DAT_0016c720,ZEXT816(0) << 0x40);
887: dVar76 = (double)SUB164(ZEXT1416(CONCAT212(SUB162(auVar125 >> 0x70,0),auVar32)) >> 0x40,
888: 0);
889: auVar125 = divpd(_DAT_0016c720,
890: CONCAT88((double)SUB124(auVar32 >> 0x20,0) * 0.785694958 * 0.785694958
891: * 8.0,(double)(uint)uVar95 * 1.0 * 0.785694958 * 8.0));
892: auVar102 = divpd(_DAT_0016c720,
893: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 0.275899379 *
894: 0.785694958 * 8.0,dVar76 * 0.5411961 * 0.785694958 * 8.0));
895: auVar32 = ZEXT1012(CONCAT28(SUB162(auVar126 >> 0x70,0),(ulong)(uVar13 & 0xffff00000000))
896: );
897: auVar51 = divpd(_DAT_0016c720,
898: CONCAT88((double)SUB164(CONCAT106((unkuint10)
899: (SUB148(CONCAT68(SUB146(CONCAT410(
900: SUB144(CONCAT212(*(undefined2 *)
901: (pauVar23[3] + 0xc),
902: CONCAT210(uVar10,CONCAT28(uVar59,
903: uVar55))) >> 0x50,0),CONCAT28(uVar56,uVar55)) >>
904: 0x40,0),uVar55) >> 0x30,0) & 0xffff) &
905: SUB1610((undefined  [16])0xffffffffffffffff >>
906: 0x30,0) &
907: SUB1610((undefined  [16])0xffffffffffffffff >>
908: 0x30,0),(uVar6 >> 0x10) << 0x20) >> 0x20,0
909: ) * 1.387039845 * 0.5411961 * 8.0,
910: (double)(uint)SUB162((auVar126 &
911: (undefined  [16])0xffffffff00000000) >>
912: 0x40,0) * 1.0 * 0.5411961 * 8.0));
913: auVar52 = divpd(_DAT_0016c720,ZEXT816(0) << 0x40);
914: auVar53 = divpd(_DAT_0016c720,
915: CONCAT88((double)SUB124(auVar32 >> 0x20,0) * 0.785694958 * 0.5411961 *
916: 8.0,(double)(uint)uVar59 * 1.0 * 0.5411961 * 8.0));
917: iStack160 = SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar23[7] + 0xc),auVar32)) >>
918: 0x40,0);
919: auVar126 = divpd(_DAT_0016c720,
920: CONCAT88((double)(int)((ulong)(double)iStack160 >> 0x20) * 0.275899379
921: * 0.5411961 * 8.0,
922: (double)iStack160 * 0.5411961 * 0.5411961 * 8.0));
923: auVar32 = ZEXT1012(CONCAT28(SUB162(auVar127 >> 0x70,0),
924: (ulong)(((uint6)CONCAT22(uVar11,uVar8) & 0xffff0000) << 0x10
925: )));
926: Var54 = (unkuint10)
927: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(*(undefined2 *)
928: (pauVar23[3] + 0xe),
929: CONCAT210(uVar11,CONCAT28(
930: uVar42,uVar31))) >> 0x50,0),
931: CONCAT28(uVar39,uVar31)) >> 0x40,0),uVar31) >>
932: 0x30,0) & SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
933: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
934: dVar76 = (double)(int)(Var54 >> 0x10);
935: auVar127 = divpd(_DAT_0016c720,
936: CONCAT88((double)SUB164(CONCAT106(Var54,(uVar30 >> 0x10) << 0x20) >>
937: 0x20,0) * 1.387039845 * 0.275899379 * 8.0,
938: (double)(uint)uVar36 * 1.0 * 0.275899379 * 8.0));
939: auVar128 = divpd(_DAT_0016c720,
940: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 1.175875602 *
941: 0.275899379 * 8.0,dVar76 * 1.306562965 * 0.275899379 * 8.0));
942: dVar76 = (double)SUB164(ZEXT1416(CONCAT212(*(undefined2 *)(pauVar23[7] + 0xe),auVar32))
943: >> 0x40,0);
944: auVar129 = divpd(_DAT_0016c720,
945: CONCAT88((double)SUB124(auVar32 >> 0x20,0) * 0.785694958 * 0.275899379
946: * 8.0,(double)(uint)uVar42 * 1.0 * 0.275899379 * 8.0));
947: auVar43 = divpd(_DAT_0016c720,
948: CONCAT88((double)(int)((ulong)dVar76 >> 0x20) * 0.275899379 *
949: 0.275899379 * 8.0,dVar76 * 0.5411961 * 0.275899379 * 8.0));
950: *(undefined (*) [16])(puVar18 + 2) =
951: CONCAT412((float)SUB168(auVar127,0),
952: CONCAT48((float)SUB168(auVar51,0),
953: CONCAT44((float)SUB168(auVar123,0),(float)SUB168(auVar119,0))));
954: puVar18[4] = CONCAT44(fVar106,(float)SUB168(auVar120 >> 0x40,0));
955: *(float *)(puVar18 + 6) = (float)SUB168(auVar112 >> 0x40,0);
956: *(float *)((long)puVar18 + 0x34) = (float)SUB168(auVar115 >> 0x40,0);
957: *(undefined (*) [16])(puVar18 + 6) =
958: CONCAT412((float)SUB168(auVar127 >> 0x40,0),
959: CONCAT48((float)SUB168(auVar51 >> 0x40,0),
960: SUB168(CONCAT412((float)SUB168(auVar123 >> 0x40,0),
961: CONCAT48(fVar106,CONCAT44(fVar106,(float)SUB168
962: (auVar122,0)))) >> 0x40,0) & 0xffffffff00000000 |
963: (ulong)(uint)(float)SUB168(auVar119 >> 0x40,0)));
964: *puVar18 = CONCAT44((float)SUB168(auVar122,0),(float)SUB168(auVar120,0));
965: puVar18[1] = SUB128(CONCAT48((float)SUB168(auVar115,0),
966: CONCAT44((float)SUB168(auVar112,0),
967: (float)SUB168(auVar112,0))) >> 0x20,0);
968: puVar18[8] = CONCAT44((float)SUB168(auVar109,0),(float)SUB168(auVar107,0));
969: puVar18[9] = SUB128(CONCAT48((float)SUB168(auVar116,0),
970: CONCAT44((float)SUB168(auVar113,0),
971: (float)SUB168(auVar113,0))) >> 0x20,0);
972: puVar18[0xc] = CONCAT44((float)SUB168(auVar109 >> 0x40,0),
973: (float)SUB168(auVar107 >> 0x40,0));
974: *(float *)(puVar18 + 0xe) = (float)SUB168(auVar113 >> 0x40,0);
975: *(float *)((long)puVar18 + 0x74) = (float)SUB168(auVar116 >> 0x40,0);
976: *(float *)(puVar18 + 0xe) = (float)SUB168(auVar103 >> 0x40,0);
977: *(float *)((long)puVar18 + 0x74) = (float)SUB168(auVar124 >> 0x40,0);
978: *(float *)(puVar18 + 0xf) = (float)SUB168(auVar52 >> 0x40,0);
979: *(float *)((long)puVar18 + 0x7c) = (float)SUB168(auVar128 >> 0x40,0);
980: *(undefined (*) [16])(puVar18 + 10) =
981: CONCAT412((float)SUB168(auVar128,0),
982: CONCAT48((float)SUB168(auVar52,0),
983: CONCAT44((float)SUB168(auVar124,0),(float)SUB168(auVar103,0))));
984: puVar18[0x10] = CONCAT44((float)SUB168(auVar110,0),(float)SUB168(auVar121,0));
985: puVar18[0x11] =
986: SUB128(CONCAT48((float)SUB168(auVar117,0),
987: CONCAT44((float)SUB168(auVar114,0),(float)SUB168(auVar114,0))) >>
988: 0x20,0);
989: *(undefined (*) [16])(puVar18 + 0x12) =
990: CONCAT412((float)SUB168(auVar129,0),
991: CONCAT48((float)SUB168(auVar53,0),
992: CONCAT44((float)SUB168(auVar125,0),(float)SUB168(auVar104,0))));
993: puVar18[0x14] = CONCAT44(fVar79,(float)SUB168(auVar121 >> 0x40,0));
994: *(float *)(puVar18 + 0x16) = (float)SUB168(auVar114 >> 0x40,0);
995: *(float *)((long)puVar18 + 0xb4) = (float)SUB168(auVar117 >> 0x40,0);
996: *(undefined (*) [16])(puVar18 + 0x16) =
997: CONCAT412((float)SUB168(auVar129 >> 0x40,0),
998: CONCAT48((float)SUB168(auVar53 >> 0x40,0),
999: SUB168(CONCAT412((float)SUB168(auVar125 >> 0x40,0),
1000: CONCAT48(fVar79,CONCAT44(fVar79,(float)SUB168(
1001: auVar110,0)))) >> 0x40,0) & 0xffffffff00000000 |
1002: (ulong)(uint)(float)SUB168(auVar104 >> 0x40,0)));
1003: puVar18[0x18] = CONCAT44((float)SUB168(auVar111,0),(float)SUB168(auVar108,0));
1004: puVar18[0x19] =
1005: SUB128(CONCAT48((float)SUB168(auVar118,0),
1006: CONCAT44((float)SUB168(auVar70,0),(float)SUB168(auVar70,0))) >>
1007: 0x20,0);
1008: *(float *)(puVar18 + 0x1a) = (float)SUB168(auVar105,0);
1009: *(float *)((long)puVar18 + 0xd4) = (float)SUB168(auVar102,0);
1010: *(float *)(puVar18 + 0x1b) = (float)SUB168(auVar126,0);
1011: *(float *)((long)puVar18 + 0xdc) = (float)SUB168(auVar43,0);
1012: *(undefined (*) [16])(puVar18 + 0x1c) =
1013: CONCAT88(SUB168(CONCAT412((float)SUB168(auVar118 >> 0x40,0),
1014: CONCAT48(fVar66,CONCAT44(fVar66,fVar78))) >> 0x40,0),
1015: CONCAT44((float)SUB168(auVar111 >> 0x40,0),fVar78)) &
1016: (undefined  [16])0xffffffffffffffff;
1017: *(float *)(puVar18 + 0x1e) = (float)SUB168(auVar105 >> 0x40,0);
1018: *(float *)((long)puVar18 + 0xf4) = (float)SUB168(auVar102 >> 0x40,0);
1019: *(float *)(puVar18 + 0x1f) = (float)SUB168(auVar126 >> 0x40,0);
1020: *(float *)((long)puVar18 + 0xfc) = (float)SUB168(auVar43 >> 0x40,0);
1021: }
1022: else {
1023: ppcVar3 = (code **)*param_1;
1024: *(undefined4 *)(ppcVar3 + 5) = 0x30;
1025: (**ppcVar3)();
1026: }
1027: }
1028: }
1029: LAB_00108b8c:
1030: pcVar25 = pcVar25 + 0x60;
1031: iStack140 = iStack140 + 1;
1032: } while (*(int *)((long)param_1 + 0x4c) != iStack140 &&
1033: iStack140 <= *(int *)((long)param_1 + 0x4c));
1034: }
1035: return;
1036: }
1037: 
