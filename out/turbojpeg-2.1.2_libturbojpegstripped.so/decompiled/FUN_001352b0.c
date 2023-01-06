1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined8 FUN_001352b0(code **param_1)
5: 
6: {
7: long lVar1;
8: byte bVar2;
9: uint uVar3;
10: undefined4 uVar4;
11: byte **ppbVar5;
12: code **ppcVar6;
13: uint *puVar7;
14: byte bVar8;
15: int iVar9;
16: int iVar10;
17: byte *pbVar11;
18: byte *pbVar12;
19: code *pcVar13;
20: undefined8 uVar14;
21: ushort uVar15;
22: uint uVar16;
23: long lVar17;
24: uint uVar18;
25: int *piVar19;
26: ushort *puVar20;
27: byte *pbVar21;
28: uint *puVar22;
29: ushort *puStack96;
30: byte *pbStack88;
31: byte *pbStack80;
32: 
33: uVar16 = *(uint *)((long)param_1 + 0x21c);
34: if (uVar16 == 0) {
35: pcVar13 = param_1[0x49];
36: goto LAB_0013548e;
37: }
38: do {
39: if ((int)uVar16 < 0xd0) {
40: if ((int)uVar16 < 0xcd) {
41: if (uVar16 == 0xc4) {
42: iVar9 = FUN_00134bf0(param_1);
43: }
44: else {
45: if ((int)uVar16 < 0xc5) {
46: if ((int)uVar16 < 0xc2) {
47: if (0xbf < (int)uVar16) {
48: uVar14 = 0;
49: goto LAB_0013564a;
50: }
51: if (uVar16 == 1) goto LAB_001355e9;
52: }
53: else {
54: if (uVar16 == 0xc2) goto LAB_00135467;
55: if (uVar16 == 0xc3) goto LAB_00135626;
56: }
57: LAB_00135668:
58: ppcVar6 = (code **)*param_1;
59: *(undefined4 *)(ppcVar6 + 5) = 0x44;
60: *(uint *)((long)ppcVar6 + 0x2c) = uVar16;
61: (**ppcVar6)(param_1);
62: goto LAB_0013547c;
63: }
64: if (uVar16 != 0xc9) {
65: if (((int)uVar16 < 0xc9) || (uVar16 == 0xcb)) goto LAB_00135626;
66: if (0xcb < (int)uVar16) {
67: ppbVar5 = (byte **)param_1[5];
68: pbVar11 = ppbVar5[1];
69: if (pbVar11 == (byte *)0x0) {
70: iVar9 = (*(code *)ppbVar5[3])(param_1);
71: if (iVar9 == 0) {
72: return 0;
73: }
74: pbVar12 = *ppbVar5;
75: pbVar11 = ppbVar5[1];
76: }
77: else {
78: pbVar12 = *ppbVar5;
79: }
80: pbVar11 = pbVar11 + -1;
81: bVar8 = *pbVar12;
82: if (pbVar11 == (byte *)0x0) {
83: iVar9 = (*(code *)ppbVar5[3])(param_1);
84: if (iVar9 == 0) {
85: return 0;
86: }
87: pbVar12 = *ppbVar5;
88: pbVar11 = ppbVar5[1];
89: }
90: else {
91: pbVar12 = pbVar12 + 1;
92: }
93: pbVar21 = pbVar12 + 1;
94: pbVar11 = pbVar11 + -1;
95: lVar17 = (ulong)*pbVar12 + (ulong)bVar8 * 0x100;
96: puStack96 = (ushort *)(lVar17 + -2);
97: if (0 < (long)puStack96) {
98: do {
99: if (pbVar11 == (byte *)0x0) {
100: iVar9 = (*(code *)ppbVar5[3])(param_1);
101: if (iVar9 == 0) {
102: return 0;
103: }
104: pbVar21 = *ppbVar5;
105: pbVar11 = ppbVar5[1];
106: }
107: bVar8 = *pbVar21;
108: pbVar11 = pbVar11 + -1;
109: pbVar21 = pbVar21 + 1;
110: if (pbVar11 == (byte *)0x0) {
111: iVar9 = (*(code *)ppbVar5[3])(param_1);
112: if (iVar9 == 0) {
113: return 0;
114: }
115: pbVar21 = *ppbVar5;
116: pbVar11 = ppbVar5[1];
117: }
118: bVar2 = *pbVar21;
119: pbVar21 = pbVar21 + 1;
120: pcVar13 = *param_1;
121: puStack96 = (ushort *)((long)puStack96 + -2);
122: pbVar11 = pbVar11 + -1;
123: *(undefined4 *)(pcVar13 + 0x28) = 0x4f;
124: uVar16 = (uint)bVar8;
125: *(uint *)(pcVar13 + 0x2c) = uVar16;
126: *(uint *)(pcVar13 + 0x30) = (uint)bVar2;
127: (**(code **)(pcVar13 + 8))(param_1);
128: if (0x1f < bVar8) {
129: ppcVar6 = (code **)*param_1;
130: *(undefined4 *)(ppcVar6 + 5) = 0x1c;
131: *(uint *)((long)ppcVar6 + 0x2c) = uVar16;
132: (**ppcVar6)(param_1);
133: }
134: if (uVar16 < 0x10) {
135: pbStack80._0_4_ = (uint)bVar2;
136: *(byte *)((long)param_1 + (long)(int)uVar16 + 0x140) = bVar2 & 0xf;
137: bVar8 = (byte)((int)(uint)pbStack80 >> 4);
138: *(byte *)((long)param_1 + (long)(int)uVar16 + 0x150) = bVar8;
139: if (bVar8 < (bVar2 & 0xf)) {
140: ppcVar6 = (code **)*param_1;
141: *(undefined4 *)(ppcVar6 + 5) = 0x1d;
142: *(uint *)((long)ppcVar6 + 0x2c) = (uint)pbStack80;
143: (**ppcVar6)(param_1);
144: }
145: }
146: else {
147: *(byte *)((long)param_1 + (long)(int)(uVar16 - 0x10) + 0x160) = bVar2;
148: }
149: } while (puStack96 != (ushort *)((lVar17 + -4) - (lVar17 - 3U & 0xfffffffffffffffe))
150: );
151: }
152: if (puStack96 != (ushort *)0x0) {
153: ppcVar6 = (code **)*param_1;
154: *(undefined4 *)(ppcVar6 + 5) = 0xb;
155: (**ppcVar6)(param_1);
156: }
157: *ppbVar5 = pbVar21;
158: ppbVar5[1] = pbVar11;
159: pcVar13 = param_1[0x49];
160: goto LAB_00135483;
161: }
162: LAB_00135467:
163: iVar9 = FUN_00134370(param_1);
164: goto joined_r0x00135992;
165: }
166: uVar14 = 1;
167: LAB_0013564a:
168: iVar9 = FUN_00134370(param_1,0,uVar14);
169: }
170: if (iVar9 == 0) {
171: return 0;
172: }
173: LAB_0013547c:
174: pcVar13 = param_1[0x49];
175: }
176: else {
177: LAB_00135626:
178: ppcVar6 = (code **)*param_1;
179: *(undefined4 *)(ppcVar6 + 5) = 0x3c;
180: *(uint *)((long)ppcVar6 + 0x2c) = uVar16;
181: (**ppcVar6)(param_1);
182: pcVar13 = param_1[0x49];
183: }
184: }
185: else {
186: if (uVar16 == 0xdb) {
187: ppbVar5 = (byte **)param_1[5];
188: pbVar11 = ppbVar5[1];
189: if (pbVar11 == (byte *)0x0) {
190: iVar9 = (*(code *)ppbVar5[3])(param_1);
191: if (iVar9 == 0) {
192: return 0;
193: }
194: pbVar12 = *ppbVar5;
195: pbVar11 = ppbVar5[1];
196: }
197: else {
198: pbVar12 = *ppbVar5;
199: }
200: pbVar11 = pbVar11 + -1;
201: bVar8 = *pbVar12;
202: if (pbVar11 == (byte *)0x0) {
203: iVar9 = (*(code *)ppbVar5[3])(param_1);
204: if (iVar9 == 0) {
205: return 0;
206: }
207: pbVar12 = *ppbVar5;
208: pbVar11 = ppbVar5[1];
209: }
210: else {
211: pbVar12 = pbVar12 + 1;
212: }
213: pbVar21 = pbVar12 + 1;
214: pbVar11 = pbVar11 + -1;
215: lVar17 = (ulong)bVar8 * 0x100 + -2 + (ulong)*pbVar12;
216: while (0 < lVar17) {
217: if (pbVar11 == (byte *)0x0) {
218: iVar9 = (*(code *)ppbVar5[3])(param_1);
219: if (iVar9 == 0) {
220: return 0;
221: }
222: pbVar21 = *ppbVar5;
223: pbVar11 = ppbVar5[1];
224: }
225: bVar8 = *pbVar21;
226: pcVar13 = *param_1;
227: pbVar21 = pbVar21 + 1;
228: pbVar11 = pbVar11 + -1;
229: *(undefined4 *)(pcVar13 + 0x28) = 0x51;
230: iVar9 = (int)(uint)bVar8 >> 4;
231: uVar16 = bVar8 & 0xf;
232: *(int *)(pcVar13 + 0x30) = iVar9;
233: *(uint *)(pcVar13 + 0x2c) = uVar16;
234: (**(code **)(pcVar13 + 8))(param_1);
235: if (3 < (byte)uVar16) {
236: ppcVar6 = (code **)*param_1;
237: *(undefined4 *)(ppcVar6 + 5) = 0x1f;
238: *(uint *)((long)ppcVar6 + 0x2c) = uVar16;
239: (**ppcVar6)(param_1);
240: }
241: puStack96 = (ushort *)(param_1 + uVar16)[0x19];
242: if (puStack96 == (ushort *)0x0) {
243: puStack96 = (ushort *)FUN_0011f510(param_1);
244: (param_1 + uVar16)[0x19] = (code *)puStack96;
245: }
246: piVar19 = (int *)&DAT_0018f100;
247: do {
248: if (iVar9 == 0) {
249: if (pbVar11 == (byte *)0x0) {
250: iVar10 = (*(code *)ppbVar5[3])(param_1);
251: if (iVar10 == 0) {
252: return 0;
253: }
254: pbVar21 = *ppbVar5;
255: pbVar11 = ppbVar5[1];
256: }
257: uVar15 = (ushort)*pbVar21;
258: }
259: else {
260: if (pbVar11 == (byte *)0x0) {
261: iVar10 = (*(code *)ppbVar5[3])(param_1);
262: if (iVar10 == 0) {
263: return 0;
264: }
265: pbVar21 = *ppbVar5;
266: pbVar11 = ppbVar5[1];
267: }
268: bVar8 = *pbVar21;
269: pbVar21 = pbVar21 + 1;
270: pbVar11 = pbVar11 + -1;
271: if (pbVar11 == (byte *)0x0) {
272: iVar10 = (*(code *)ppbVar5[3])(param_1);
273: if (iVar10 == 0) {
274: return 0;
275: }
276: pbVar21 = *ppbVar5;
277: pbVar11 = ppbVar5[1];
278: }
279: uVar15 = (ushort)bVar8 * 0x100 + (ushort)*pbVar21;
280: }
281: pbVar11 = pbVar11 + -1;
282: pbVar21 = pbVar21 + 1;
283: iVar10 = *piVar19;
284: piVar19 = piVar19 + 1;
285: puStack96[iVar10] = uVar15;
286: } while (piVar19 != (int *)&UNK_0018f200);
287: pcVar13 = *param_1;
288: if (1 < *(int *)(pcVar13 + 0x7c)) {
289: puVar20 = puStack96;
290: while( true ) {
291: *(uint *)(pcVar13 + 0x2c) = (uint)*puVar20;
292: *(uint *)(pcVar13 + 0x30) = (uint)puVar20[1];
293: *(uint *)(pcVar13 + 0x34) = (uint)puVar20[2];
294: *(uint *)(pcVar13 + 0x38) = (uint)puVar20[3];
295: *(uint *)(pcVar13 + 0x3c) = (uint)puVar20[4];
296: *(uint *)(pcVar13 + 0x40) = (uint)puVar20[5];
297: *(uint *)(pcVar13 + 0x44) = (uint)puVar20[6];
298: uVar15 = puVar20[7];
299: *(undefined4 *)(pcVar13 + 0x28) = 0x5d;
300: *(uint *)(pcVar13 + 0x48) = (uint)uVar15;
301: (**(code **)(pcVar13 + 8))(param_1);
302: if (puVar20 + 8 == puStack96 + 0x40) break;
303: pcVar13 = *param_1;
304: puVar20 = puVar20 + 8;
305: }
306: }
307: lVar1 = lVar17 + -0x81;
308: lVar17 = lVar17 + -0x41;
309: if (iVar9 != 0) {
310: lVar17 = lVar1;
311: }
312: }
313: if (lVar17 != 0) {
314: ppcVar6 = (code **)*param_1;
315: *(undefined4 *)(ppcVar6 + 5) = 0xb;
316: (**ppcVar6)(param_1);
317: }
318: *ppbVar5 = pbVar21;
319: ppbVar5[1] = pbVar11;
320: pcVar13 = param_1[0x49];
321: }
322: else {
323: if (0xdb < (int)uVar16) {
324: if ((int)uVar16 < 0xf0) {
325: if ((int)uVar16 < 0xe0) {
326: if (uVar16 != 0xdc) {
327: if (uVar16 == 0xdd) {
328: ppbVar5 = (byte **)param_1[5];
329: pbVar11 = ppbVar5[1];
330: if (pbVar11 == (byte *)0x0) {
331: iVar9 = (*(code *)ppbVar5[3])(param_1);
332: if (iVar9 == 0) {
333: return 0;
334: }
335: pbVar12 = *ppbVar5;
336: pbVar11 = ppbVar5[1];
337: }
338: else {
339: pbVar12 = *ppbVar5;
340: }
341: pbVar11 = pbVar11 + -1;
342: bVar8 = *pbVar12;
343: pbVar12 = pbVar12 + 1;
344: if (pbVar11 == (byte *)0x0) {
345: iVar9 = (*(code *)ppbVar5[3])(param_1);
346: if (iVar9 == 0) {
347: return 0;
348: }
349: pbVar12 = *ppbVar5;
350: pbVar11 = ppbVar5[1];
351: }
352: pbVar11 = pbVar11 + -1;
353: if ((uint)bVar8 * 0x100 + (uint)*pbVar12 != 4) {
354: ppcVar6 = (code **)*param_1;
355: *(undefined4 *)(ppcVar6 + 5) = 0xb;
356: (**ppcVar6)(param_1);
357: }
358: pbVar12 = pbVar12 + 1;
359: if (pbVar11 == (byte *)0x0) {
360: iVar9 = (*(code *)ppbVar5[3])(param_1);
361: if (iVar9 == 0) {
362: return 0;
363: }
364: pbVar12 = *ppbVar5;
365: pbVar11 = ppbVar5[1];
366: }
367: bVar8 = *pbVar12;
368: pbVar12 = pbVar12 + 1;
369: pbVar11 = pbVar11 + -1;
370: if (pbVar11 == (byte *)0x0) {
371: iVar9 = (*(code *)ppbVar5[3])(param_1);
372: if (iVar9 == 0) {
373: return 0;
374: }
375: pbVar12 = *ppbVar5;
376: pbVar11 = ppbVar5[1];
377: }
378: bVar2 = *pbVar12;
379: pcVar13 = *param_1;
380: *(undefined4 *)(pcVar13 + 0x28) = 0x52;
381: *(uint *)(pcVar13 + 0x2c) = (uint)CONCAT11(bVar8,bVar2);
382: (**(code **)(pcVar13 + 8))(param_1);
383: *(uint *)(param_1 + 0x2e) = (uint)CONCAT11(bVar8,bVar2);
384: pcVar13 = param_1[0x49];
385: ppbVar5[1] = pbVar11 + -1;
386: *ppbVar5 = pbVar12 + 1;
387: goto LAB_00135483;
388: }
389: goto LAB_00135668;
390: }
391: iVar9 = FUN_00134990(param_1);
392: }
393: else {
394: iVar9 = (**(code **)(param_1[0x49] + (long)(int)(uVar16 - 0xe0) * 8 + 0x30))(param_1);
395: }
396: }
397: else {
398: if (uVar16 != 0xfe) goto LAB_00135668;
399: iVar9 = (**(code **)(param_1[0x49] + 0x28))(param_1);
400: }
401: joined_r0x00135992:
402: if (iVar9 == 0) {
403: return 0;
404: }
405: goto LAB_0013547c;
406: }
407: if (uVar16 == 0xd8) {
408: pcVar13 = *param_1;
409: *(undefined4 *)(pcVar13 + 0x28) = 0x66;
410: (**(code **)(pcVar13 + 8))(param_1);
411: pcVar13 = param_1[0x49];
412: if (*(int *)(pcVar13 + 0x18) != 0) {
413: ppcVar6 = (code **)*param_1;
414: *(undefined4 *)(ppcVar6 + 5) = 0x3d;
415: (**ppcVar6)(param_1);
416: pcVar13 = param_1[0x49];
417: }
418: *(undefined4 *)(param_1 + 0x2e) = 0;
419: *(undefined4 *)((long)param_1 + 0x3c) = 0;
420: *(undefined4 *)(param_1 + 0x31) = 0;
421: *(undefined4 *)((long)param_1 + 0x174) = 0;
422: *(undefined *)(param_1 + 0x2f) = 1;
423: *(undefined *)((long)param_1 + 0x179) = 1;
424: *(undefined (*) [16])(param_1 + 0x28) = (undefined  [16])0x0;
425: *(undefined *)((long)param_1 + 0x17a) = 0;
426: *(undefined8 *)((long)param_1 + 0x17c) = 0x10001;
427: *(undefined *)((long)param_1 + 0x184) = 0;
428: *(undefined4 *)(param_1 + 0x2a) = 0x1010101;
429: *(undefined4 *)((long)param_1 + 0x154) = 0x1010101;
430: *(undefined4 *)(param_1 + 0x2b) = 0x1010101;
431: *(undefined4 *)((long)param_1 + 0x15c) = 0x1010101;
432: *(undefined4 *)(param_1 + 0x2c) = 0x5050505;
433: *(undefined4 *)((long)param_1 + 0x164) = 0x5050505;
434: *(undefined4 *)(param_1 + 0x2d) = 0x5050505;
435: *(undefined4 *)((long)param_1 + 0x16c) = 0x5050505;
436: *(undefined4 *)(pcVar13 + 0x18) = 1;
437: }
438: else {
439: if (0xd7 < (int)uVar16) {
440: if (uVar16 == 0xd9) {
441: pcVar13 = *param_1;
442: *(undefined4 *)(pcVar13 + 0x28) = 0x55;
443: (**(code **)(pcVar13 + 8))(param_1,1);
444: *(undefined4 *)((long)param_1 + 0x21c) = 0;
445: return 2;
446: }
447: if (uVar16 != 0xda) goto LAB_00135668;
448: ppbVar5 = (byte **)param_1[5];
449: pbVar11 = *ppbVar5;
450: pbStack88 = ppbVar5[1];
451: if (*(int *)(param_1[0x49] + 0x1c) == 0) {
452: ppcVar6 = (code **)*param_1;
453: *(undefined4 *)(ppcVar6 + 5) = 0x3e;
454: (**ppcVar6)(param_1);
455: }
456: if (pbStack88 == (byte *)0x0) {
457: iVar9 = (*(code *)ppbVar5[3])(param_1);
458: if (iVar9 == 0) {
459: return 0;
460: }
461: pbVar11 = *ppbVar5;
462: pbStack88 = ppbVar5[1];
463: }
464: pbStack88 = pbStack88 + -1;
465: bVar8 = *pbVar11;
466: if (pbStack88 == (byte *)0x0) {
467: iVar9 = (*(code *)ppbVar5[3])(param_1);
468: if (iVar9 == 0) {
469: return 0;
470: }
471: pbVar11 = *ppbVar5;
472: pbStack88 = ppbVar5[1];
473: }
474: else {
475: pbVar11 = pbVar11 + 1;
476: }
477: bVar2 = *pbVar11;
478: pbStack88 = pbStack88 + -1;
479: if (pbStack88 == (byte *)0x0) {
480: iVar9 = (*(code *)ppbVar5[3])(param_1);
481: if (iVar9 == 0) {
482: return 0;
483: }
484: pbVar11 = *ppbVar5;
485: pbStack88 = ppbVar5[1];
486: }
487: else {
488: pbVar11 = pbVar11 + 1;
489: }
490: pbStack88 = pbStack88 + -1;
491: pbStack80 = pbVar11 + 1;
492: uVar16 = (uint)*pbVar11;
493: pcVar13 = *param_1;
494: *(undefined4 *)(pcVar13 + 0x28) = 0x67;
495: *(uint *)(pcVar13 + 0x2c) = uVar16;
496: (**(code **)(pcVar13 + 8))(param_1);
497: if (((uint)bVar8 * 0x100 + (uint)bVar2 != uVar16 * 2 + 6) || (3 < uVar16 - 1)) {
498: ppcVar6 = (code **)*param_1;
499: *(undefined4 *)(ppcVar6 + 5) = 0xb;
500: (**ppcVar6)(param_1);
501: }
502: param_1[0x37] = (code *)0x0;
503: param_1[0x38] = (code *)0x0;
504: param_1[0x39] = (code *)0x0;
505: param_1[0x3a] = (code *)0x0;
506: *(uint *)(param_1 + 0x36) = uVar16;
507: if (uVar16 == 0) goto LAB_00135dea;
508: puStack96 = (ushort *)0x0;
509: break;
510: }
511: LAB_001355e9:
512: pcVar13 = *param_1;
513: *(undefined4 *)(pcVar13 + 0x28) = 0x5c;
514: *(uint *)(pcVar13 + 0x2c) = uVar16;
515: (**(code **)(pcVar13 + 8))(param_1);
516: pcVar13 = param_1[0x49];
517: }
518: }
519: }
520: LAB_00135483:
521: *(undefined4 *)((long)param_1 + 0x21c) = 0;
522: LAB_0013548e:
523: if (*(int *)(pcVar13 + 0x18) == 0) {
524: ppbVar5 = (byte **)param_1[5];
525: if (ppbVar5[1] == (byte *)0x0) {
526: iVar9 = (*(code *)ppbVar5[3])(param_1);
527: if (iVar9 == 0) {
528: return 0;
529: }
530: pbVar11 = *ppbVar5;
531: pbVar12 = ppbVar5[1] + -1;
532: bVar8 = *pbVar11;
533: if (pbVar12 != (byte *)0x0) goto LAB_00135f19;
534: LAB_001354cd:
535: iVar9 = (*(code *)ppbVar5[3])(param_1);
536: if (iVar9 == 0) {
537: return 0;
538: }
539: pbVar11 = *ppbVar5;
540: pbVar12 = ppbVar5[1];
541: }
542: else {
543: pbVar11 = *ppbVar5;
544: pbVar12 = ppbVar5[1] + -1;
545: bVar8 = *pbVar11;
546: if (pbVar12 == (byte *)0x0) goto LAB_001354cd;
547: LAB_00135f19:
548: pbVar11 = pbVar11 + 1;
549: }
550: uVar16 = (uint)*pbVar11;
551: if ((bVar8 != 0xff) || (uVar16 != 0xd8)) {
552: ppcVar6 = (code **)*param_1;
553: *(undefined4 *)(ppcVar6 + 5) = 0x35;
554: *(uint *)((long)ppcVar6 + 0x2c) = (uint)bVar8;
555: *(uint *)(ppcVar6 + 6) = uVar16;
556: (**ppcVar6)(param_1);
557: }
558: *(uint *)((long)param_1 + 0x21c) = uVar16;
559: *ppbVar5 = pbVar11 + 1;
560: ppbVar5[1] = pbVar12 + -1;
561: }
562: else {
563: iVar9 = FUN_00134a80(param_1);
564: if (iVar9 == 0) {
565: return 0;
566: }
567: uVar16 = *(uint *)((long)param_1 + 0x21c);
568: }
569: } while( true );
570: LAB_00135c60:
571: if (pbStack88 == (byte *)0x0) {
572: iVar9 = (*(code *)ppbVar5[3])(param_1);
573: if (iVar9 == 0) {
574: return 0;
575: }
576: pbStack80 = *ppbVar5;
577: pbStack88 = ppbVar5[1];
578: }
579: pbStack88 = pbStack88 + -1;
580: bVar8 = *pbStack80;
581: if (pbStack88 == (byte *)0x0) {
582: iVar9 = (*(code *)ppbVar5[3])(param_1);
583: if (iVar9 == 0) {
584: return 0;
585: }
586: pbVar11 = *ppbVar5;
587: pbStack88 = ppbVar5[1];
588: }
589: else {
590: pbVar11 = pbStack80 + 1;
591: }
592: pbStack80 = pbVar11 + 1;
593: iVar9 = *(int *)(param_1 + 7);
594: bVar2 = *pbVar11;
595: pbStack88 = pbStack88 + -1;
596: puVar7 = (uint *)param_1[0x26];
597: uVar18 = (uint)bVar8;
598: puVar22 = puVar7;
599: if (iVar9 < 1) {
600: LAB_00135d4b:
601: ppcVar6 = (code **)*param_1;
602: *(undefined4 *)(ppcVar6 + 5) = 5;
603: *(uint *)((long)ppcVar6 + 0x2c) = uVar18;
604: (**ppcVar6)(param_1);
605: }
606: else {
607: if (((uint)bVar8 != *puVar7) || (param_1[0x37] != (code *)0x0)) {
608: puVar22 = puVar7 + 0x18;
609: if (iVar9 != 1) {
610: if ((puVar7[0x18] == (uint)bVar8) && (param_1[0x38] == (code *)0x0)) goto LAB_00135d5d;
611: puVar22 = puVar7 + 0x30;
612: if (iVar9 != 2) {
613: if ((uVar18 == puVar7[0x30]) && (param_1[0x39] == (code *)0x0)) goto LAB_00135d5d;
614: puVar22 = puVar7 + 0x48;
615: if (iVar9 != 3) {
616: if ((uVar18 == puVar7[0x48]) && (param_1[0x3a] == (code *)0x0)) goto LAB_00135d5d;
617: puVar22 = puVar7 + 0x60;
618: }
619: }
620: }
621: goto LAB_00135d4b;
622: }
623: }
624: LAB_00135d5d:
625: param_1[(long)puStack96 + 0x37] = (code *)puVar22;
626: puVar22[6] = bVar2 & 0xf;
627: pcVar13 = *param_1;
628: puVar22[5] = (int)(uint)bVar2 >> 4;
629: *(uint *)(pcVar13 + 0x2c) = uVar18;
630: *(uint *)(pcVar13 + 0x30) = puVar22[5];
631: uVar3 = puVar22[6];
632: *(undefined4 *)(pcVar13 + 0x28) = 0x68;
633: *(uint *)(pcVar13 + 0x34) = uVar3;
634: (**(code **)(pcVar13 + 8))(param_1);
635: if ((int)puStack96 != 0) {
636: lVar17 = 0;
637: do {
638: if (puVar22 == (uint *)param_1[lVar17 + 0x37]) {
639: ppcVar6 = (code **)*param_1;
640: *(undefined4 *)(ppcVar6 + 5) = 5;
641: *(uint *)((long)ppcVar6 + 0x2c) = uVar18;
642: (**ppcVar6)(param_1);
643: }
644: lVar17 = lVar17 + 1;
645: } while ((int)lVar17 < (int)puStack96);
646: }
647: puStack96 = (ushort *)((long)puStack96 + 1);
648: if ((int)uVar16 <= (int)puStack96) {
649: LAB_00135dea:
650: if (pbStack88 == (byte *)0x0) {
651: iVar9 = (*(code *)ppbVar5[3])(param_1);
652: if (iVar9 == 0) {
653: return 0;
654: }
655: pbStack80 = *ppbVar5;
656: pbStack88 = ppbVar5[1];
657: }
658: pbStack88 = pbStack88 + -1;
659: *(uint *)((long)param_1 + 0x20c) = (uint)*pbStack80;
660: if (pbStack88 == (byte *)0x0) {
661: iVar9 = (*(code *)ppbVar5[3])(param_1);
662: if (iVar9 == 0) {
663: return 0;
664: }
665: pbStack80 = *ppbVar5;
666: pbStack88 = ppbVar5[1];
667: }
668: else {
669: pbStack80 = pbStack80 + 1;
670: }
671: pbStack88 = pbStack88 + -1;
672: *(uint *)(param_1 + 0x42) = (uint)*pbStack80;
673: if (pbStack88 == (byte *)0x0) {
674: iVar9 = (*(code *)ppbVar5[3])(param_1);
675: if (iVar9 == 0) {
676: return 0;
677: }
678: pbStack80 = *ppbVar5;
679: pbStack88 = ppbVar5[1];
680: }
681: else {
682: pbStack80 = pbStack80 + 1;
683: }
684: bVar8 = *pbStack80;
685: *(int *)((long)param_1 + 0x214) = (int)(uint)bVar8 >> 4;
686: *(uint *)(param_1 + 0x43) = bVar8 & 0xf;
687: pcVar13 = *param_1;
688: *(undefined4 *)(pcVar13 + 0x2c) = *(undefined4 *)((long)param_1 + 0x20c);
689: *(undefined4 *)(pcVar13 + 0x30) = *(undefined4 *)(param_1 + 0x42);
690: *(undefined4 *)(pcVar13 + 0x34) = *(undefined4 *)((long)param_1 + 0x214);
691: uVar4 = *(undefined4 *)(param_1 + 0x43);
692: *(undefined4 *)(pcVar13 + 0x28) = 0x69;
693: *(undefined4 *)(pcVar13 + 0x38) = uVar4;
694: (**(code **)(pcVar13 + 8))(param_1,1);
695: *(undefined4 *)(param_1[0x49] + 0x20) = 0;
696: *(int *)((long)param_1 + 0xac) = *(int *)((long)param_1 + 0xac) + 1;
697: *ppbVar5 = pbStack80 + 1;
698: ppbVar5[1] = pbStack88 + -1;
699: *(undefined4 *)((long)param_1 + 0x21c) = 0;
700: return 1;
701: }
702: goto LAB_00135c60;
703: }
704: 
