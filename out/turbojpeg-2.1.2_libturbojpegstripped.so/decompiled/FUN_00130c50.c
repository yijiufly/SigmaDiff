1: 
2: undefined8 FUN_00130c50(long param_1,long param_2)
3: 
4: {
5: int *piVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: byte bVar5;
10: undefined8 uVar6;
11: byte *pbVar7;
12: byte *pbVar8;
13: byte *pbVar9;
14: byte bVar10;
15: sbyte sVar11;
16: long lVar12;
17: byte *pbVar13;
18: int iVar14;
19: int iVar15;
20: byte *pbVar16;
21: ulong uVar17;
22: ulong uVar18;
23: ulong uVar19;
24: uint uVar20;
25: uint uVar21;
26: byte **ppbVar22;
27: long lVar23;
28: int iVar24;
29: int iVar25;
30: ulong uVar26;
31: int iVar27;
32: long lVar28;
33: undefined2 *puVar29;
34: long in_FS_OFFSET;
35: long lStack208;
36: int iStack184;
37: byte *pbStack168;
38: byte *pbStack136;
39: byte *pbStack128;
40: ulong uStack120;
41: int iStack112;
42: long lStack104;
43: int aiStack88 [6];
44: long lStack64;
45: 
46: lVar3 = *(long *)(param_1 + 0x250);
47: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
48: iVar24 = *(int *)(param_1 + 0x170);
49: if (iVar24 == 0) {
50: iStack184 = 1;
51: LAB_00130cad:
52: ppbVar22 = *(byte ***)(param_1 + 0x28);
53: iVar25 = *(int *)(param_1 + 0x1e0);
54: pbStack168 = ppbVar22[1];
55: iVar14 = *(int *)(lVar3 + 0x10);
56: if ((pbStack168 < (byte *)((long)iVar25 << 9)) || (*(int *)(param_1 + 0x21c) != 0)) {
57: LAB_00130dc8:
58: if (iVar14 == 0) goto LAB_00130dd0;
59: }
60: else {
61: if (iVar14 == 0) {
62: uVar18 = *(ulong *)(lVar3 + 0x18);
63: iVar14 = *(int *)(lVar3 + 0x20);
64: lStack208 = lVar3;
65: if (iStack184 == 0) goto LAB_00130de3;
66: pbVar9 = *ppbVar22;
67: aiStack88[0] = *(int *)(lVar3 + 0x28);
68: aiStack88[1] = *(undefined4 *)(lVar3 + 0x2c);
69: aiStack88[2] = *(undefined4 *)(lVar3 + 0x30);
70: aiStack88[3] = *(undefined4 *)(lVar3 + 0x34);
71: if (0 < iVar25) {
72: lVar28 = 1;
73: pbVar7 = pbVar9;
74: do {
75: puVar29 = (undefined2 *)0x0;
76: if (param_2 != 0) {
77: puVar29 = *(undefined2 **)(param_2 + -8 + lVar28 * 8);
78: }
79: lVar12 = *(long *)(lVar3 + 0x78 + lVar28 * 8);
80: lVar4 = *(long *)(lVar3 + 200 + lVar28 * 8);
81: if (iVar14 < 0x11) {
82: bVar10 = pbVar7[1];
83: uVar17 = uVar18 << 8 | (ulong)*pbVar7;
84: pbVar13 = pbVar7 + 2;
85: pbVar8 = pbVar7 + 1;
86: if (*pbVar7 == 0xff) {
87: if (bVar10 == 0) {
88: bVar10 = pbVar7[2];
89: pbVar13 = pbVar7 + 3;
90: pbVar8 = pbVar7 + 2;
91: }
92: else {
93: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
94: uVar17 = uVar18 << 8;
95: bVar10 = *pbVar7;
96: pbVar13 = pbVar7 + 1;
97: pbVar8 = pbVar7;
98: }
99: }
100: bVar5 = pbVar8[1];
101: uVar18 = uVar17 << 8 | (ulong)bVar10;
102: if (bVar10 == 0xff) {
103: if (bVar5 == 0) {
104: bVar5 = pbVar8[2];
105: pbVar7 = pbVar8 + 3;
106: pbVar8 = pbVar8 + 2;
107: }
108: else {
109: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
110: uVar18 = uVar17 << 8;
111: bVar5 = *pbVar8;
112: pbVar7 = pbVar13;
113: }
114: }
115: else {
116: pbVar7 = pbVar13 + 1;
117: pbVar8 = pbVar13;
118: }
119: bVar10 = pbVar8[1];
120: uVar17 = uVar18 << 8 | (ulong)bVar5;
121: pbVar13 = pbVar7;
122: pbVar16 = pbVar7 + 1;
123: if (bVar5 == 0xff) {
124: if (bVar10 == 0) {
125: bVar10 = pbVar8[2];
126: pbVar13 = pbVar8 + 2;
127: pbVar16 = pbVar8 + 3;
128: }
129: else {
130: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
131: uVar17 = uVar18 << 8;
132: bVar10 = *pbVar8;
133: pbVar13 = pbVar8;
134: pbVar16 = pbVar7;
135: }
136: }
137: bVar5 = pbVar13[1];
138: uVar18 = uVar17 << 8 | (ulong)bVar10;
139: if (bVar10 == 0xff) {
140: if (bVar5 == 0) {
141: bVar5 = pbVar13[2];
142: pbVar8 = pbVar13 + 3;
143: pbVar13 = pbVar13 + 2;
144: }
145: else {
146: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
147: uVar18 = uVar17 << 8;
148: bVar5 = *pbVar13;
149: pbVar8 = pbVar16;
150: }
151: }
152: else {
153: pbVar8 = pbVar16 + 1;
154: pbVar13 = pbVar16;
155: }
156: bVar10 = pbVar13[1];
157: uVar17 = uVar18 << 8 | (ulong)bVar5;
158: if (bVar5 == 0xff) {
159: if (bVar10 == 0) {
160: bVar10 = pbVar13[2];
161: pbVar7 = pbVar13 + 3;
162: pbVar13 = pbVar13 + 2;
163: }
164: else {
165: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
166: uVar17 = uVar18 << 8;
167: bVar10 = *pbVar13;
168: pbVar7 = pbVar8;
169: }
170: }
171: else {
172: pbVar7 = pbVar8 + 1;
173: pbVar13 = pbVar8;
174: }
175: iVar14 = iVar14 + 0x30;
176: uVar18 = uVar17 << 8 | (ulong)bVar10;
177: if (bVar10 == 0xff) {
178: if (pbVar13[1] == 0) {
179: pbVar7 = pbVar13 + 2;
180: }
181: else {
182: *(uint *)(param_1 + 0x21c) = (uint)pbVar13[1];
183: uVar18 = uVar17 << 8;
184: pbVar7 = pbVar13;
185: }
186: }
187: }
188: uVar21 = *(uint *)(lVar12 + 0x128 + (uVar18 >> ((char)iVar14 - 8U & 0x3f) & 0xff) * 4);
189: uVar20 = uVar21 & 0xff;
190: iVar15 = (int)uVar21 >> 8;
191: iVar14 = iVar14 - iVar15;
192: if (iVar15 < 9) {
193: LAB_00131383:
194: if (uVar20 != 0) {
195: if (iVar14 < 0x11) {
196: pbVar8 = pbVar7 + 1;
197: bVar10 = pbVar7[1];
198: uVar17 = (ulong)bVar10;
199: uVar19 = uVar18 << 8 | (ulong)*pbVar7;
200: if (*pbVar7 == 0xff) {
201: if (bVar10 == 0) {
202: pbVar13 = pbVar7 + 2;
203: pbVar8 = pbVar7 + 3;
204: uVar17 = (ulong)pbVar7[2];
205: }
206: else {
207: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
208: uVar19 = uVar18 << 8;
209: uVar17 = (ulong)*pbVar7;
210: pbVar13 = pbVar7;
211: }
212: }
213: else {
214: pbVar13 = pbVar8;
215: pbVar8 = pbVar7 + 2;
216: }
217: bVar10 = pbVar13[1];
218: uVar18 = uVar17 | uVar19 << 8;
219: if ((char)uVar17 == -1) {
220: if (bVar10 == 0) {
221: pbVar8 = pbVar13 + 2;
222: pbVar7 = pbVar13 + 3;
223: bVar10 = pbVar13[2];
224: }
225: else {
226: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
227: uVar18 = uVar19 << 8;
228: bVar10 = *pbVar13;
229: pbVar7 = pbVar8;
230: pbVar8 = pbVar13;
231: }
232: }
233: else {
234: pbVar7 = pbVar8 + 1;
235: }
236: bVar5 = pbVar8[1];
237: uVar19 = (ulong)bVar5;
238: uVar17 = uVar18 << 8 | (ulong)bVar10;
239: if (bVar10 == 0xff) {
240: if (bVar5 == 0) {
241: pbVar13 = pbVar8 + 2;
242: pbVar7 = pbVar8 + 3;
243: uVar19 = (ulong)pbVar8[2];
244: }
245: else {
246: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
247: uVar17 = uVar18 << 8;
248: uVar19 = (ulong)*pbVar8;
249: pbVar13 = pbVar8;
250: }
251: }
252: else {
253: pbVar13 = pbVar7;
254: pbVar7 = pbVar7 + 1;
255: }
256: bVar10 = pbVar13[1];
257: uVar26 = (ulong)bVar10;
258: uVar18 = uVar17 << 8 | uVar19;
259: pbVar8 = pbVar7;
260: pbVar16 = pbVar7 + 1;
261: if ((char)uVar19 == -1) {
262: if (bVar10 == 0) {
263: pbVar8 = pbVar13 + 2;
264: pbVar16 = pbVar13 + 3;
265: uVar26 = (ulong)pbVar13[2];
266: }
267: else {
268: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
269: uVar18 = uVar17 << 8;
270: uVar26 = (ulong)*pbVar13;
271: pbVar8 = pbVar13;
272: pbVar16 = pbVar7;
273: }
274: }
275: bVar10 = pbVar8[1];
276: uVar17 = uVar26 | uVar18 << 8;
277: pbVar7 = pbVar16 + 1;
278: if ((char)uVar26 == -1) {
279: if (bVar10 == 0) {
280: pbVar16 = pbVar8 + 2;
281: pbVar7 = pbVar8 + 3;
282: bVar10 = pbVar8[2];
283: }
284: else {
285: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
286: uVar17 = uVar18 << 8;
287: bVar10 = *pbVar8;
288: pbVar7 = pbVar16;
289: pbVar16 = pbVar8;
290: }
291: }
292: iVar14 = iVar14 + 0x30;
293: uVar18 = uVar17 << 8 | (ulong)bVar10;
294: if (bVar10 == 0xff) {
295: if (pbVar16[1] == 0) {
296: pbVar7 = pbVar16 + 2;
297: }
298: else {
299: *(uint *)(param_1 + 0x21c) = (uint)pbVar16[1];
300: uVar18 = uVar17 << 8;
301: pbVar7 = pbVar16;
302: }
303: }
304: }
305: iVar14 = iVar14 - uVar20;
306: bVar10 = (byte)uVar20;
307: uVar20 = (1 << (bVar10 & 0x1f)) - 1U & (uint)(uVar18 >> ((byte)iVar14 & 0x3f));
308: uVar20 = ((int)(uVar20 - (1 << (bVar10 - 1 & 0x1f))) >> 0x1f &
309: (-1 << (bVar10 & 0x1f)) + 1U) + uVar20;
310: }
311: }
312: else {
313: uVar21 = (uint)(uVar18 >> ((byte)iVar14 & 0x3f)) &
314: (1 << ((byte)(uVar21 >> 8) & 0x1f)) - 1U;
315: if (*(long *)(lVar12 + (long)iVar15 * 8) < (long)(int)uVar21) {
316: lVar23 = (long)(iVar15 + 1);
317: do {
318: iVar14 = iVar14 + -1;
319: uVar21 = uVar21 * 2 | (uint)(uVar18 >> ((byte)iVar14 & 0x3f)) & 1;
320: iVar15 = (int)lVar23;
321: lVar23 = lVar23 + 1;
322: } while (*(long *)(lVar12 + -8 + lVar23 * 8) < (long)(int)uVar21);
323: }
324: uVar20 = 0;
325: if (iVar15 < 0x11) {
326: uVar20 = (uint)*(byte *)(*(long *)(lVar12 + 0x120) + 0x11 +
327: (ulong)(uVar21 + *(int *)(lVar12 + 0x90 + (long)iVar15 * 8)
328: & 0xff));
329: goto LAB_00131383;
330: }
331: }
332: iVar15 = iStack184;
333: if (*(int *)(lVar3 + 0x11c + lVar28 * 4) == 0) {
334: if ((*(int *)(lVar3 + 0x144 + lVar28 * 4) == 0) || (puVar29 == (undefined2 *)0x0))
335: goto LAB_001318d9;
336: LAB_001314eb:
337: do {
338: while( true ) {
339: if (iVar14 < 0x11) {
340: bVar10 = pbVar7[1];
341: uVar17 = uVar18 << 8 | (ulong)*pbVar7;
342: pbVar13 = pbVar7 + 2;
343: pbVar8 = pbVar7 + 1;
344: if (*pbVar7 == 0xff) {
345: if (bVar10 == 0) {
346: bVar10 = pbVar7[2];
347: pbVar13 = pbVar7 + 3;
348: pbVar8 = pbVar7 + 2;
349: }
350: else {
351: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
352: uVar17 = uVar18 << 8;
353: bVar10 = *pbVar7;
354: pbVar13 = pbVar7 + 1;
355: pbVar8 = pbVar7;
356: }
357: }
358: bVar5 = pbVar8[1];
359: uVar18 = uVar17 << 8 | (ulong)bVar10;
360: if (bVar10 == 0xff) {
361: if (bVar5 == 0) {
362: bVar5 = pbVar8[2];
363: pbVar7 = pbVar8 + 3;
364: pbVar8 = pbVar8 + 2;
365: }
366: else {
367: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
368: uVar18 = uVar17 << 8;
369: bVar5 = *pbVar8;
370: pbVar7 = pbVar13;
371: }
372: }
373: else {
374: pbVar7 = pbVar13 + 1;
375: pbVar8 = pbVar13;
376: }
377: bVar10 = pbVar8[1];
378: uVar19 = (ulong)bVar10;
379: uVar17 = uVar18 << 8 | (ulong)bVar5;
380: pbVar13 = pbVar7;
381: pbVar16 = pbVar7 + 1;
382: if (bVar5 == 0xff) {
383: if (bVar10 == 0) {
384: uVar19 = (ulong)pbVar8[2];
385: pbVar13 = pbVar8 + 2;
386: pbVar16 = pbVar8 + 3;
387: }
388: else {
389: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
390: uVar17 = uVar18 << 8;
391: uVar19 = (ulong)*pbVar8;
392: pbVar13 = pbVar8;
393: pbVar16 = pbVar7;
394: }
395: }
396: bVar10 = pbVar13[1];
397: uVar18 = uVar17 << 8 | uVar19;
398: if ((char)uVar19 == -1) {
399: if (bVar10 == 0) {
400: bVar10 = pbVar13[2];
401: pbVar8 = pbVar13 + 3;
402: pbVar13 = pbVar13 + 2;
403: }
404: else {
405: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
406: uVar18 = uVar17 << 8;
407: bVar10 = *pbVar13;
408: pbVar8 = pbVar16;
409: }
410: }
411: else {
412: pbVar8 = pbVar16 + 1;
413: pbVar13 = pbVar16;
414: }
415: bVar5 = pbVar13[1];
416: uVar17 = (ulong)bVar10 | uVar18 << 8;
417: if (bVar10 == 0xff) {
418: if (bVar5 == 0) {
419: bVar5 = pbVar13[2];
420: pbVar7 = pbVar13 + 3;
421: pbVar13 = pbVar13 + 2;
422: }
423: else {
424: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
425: uVar17 = uVar18 << 8;
426: bVar5 = *pbVar13;
427: pbVar7 = pbVar8;
428: }
429: }
430: else {
431: pbVar7 = pbVar8 + 1;
432: pbVar13 = pbVar8;
433: }
434: iVar14 = iVar14 + 0x30;
435: uVar18 = uVar17 << 8 | (ulong)bVar5;
436: if (bVar5 == 0xff) {
437: if (pbVar13[1] == 0) {
438: pbVar7 = pbVar13 + 2;
439: }
440: else {
441: *(uint *)(param_1 + 0x21c) = (uint)pbVar13[1];
442: uVar18 = uVar17 << 8;
443: pbVar7 = pbVar13;
444: }
445: }
446: }
447: uVar20 = *(uint *)(lVar4 + 0x128 +
448: (uVar18 >> ((char)iVar14 - 8U & 0x3f) & 0xff) * 4);
449: uVar21 = uVar20 & 0xff;
450: iVar27 = (int)uVar20 >> 8;
451: iVar14 = iVar14 - iVar27;
452: if (8 < iVar27) {
453: uVar20 = (uint)(uVar18 >> ((byte)iVar14 & 0x3f)) &
454: (1 << ((byte)(uVar20 >> 8) & 0x1f)) - 1U;
455: if (*(long *)(lVar4 + (long)iVar27 * 8) < (long)(int)uVar20) {
456: lVar12 = (long)(iVar27 + 1);
457: do {
458: iVar14 = iVar14 + -1;
459: uVar20 = uVar20 * 2 | (uint)(uVar18 >> ((byte)iVar14 & 0x3f)) & 1;
460: iVar27 = (int)lVar12;
461: lVar12 = lVar12 + 1;
462: } while (*(long *)(lVar4 + -8 + lVar12 * 8) < (long)(int)uVar20);
463: }
464: if (0x10 < iVar27) goto LAB_001316fd;
465: uVar21 = (uint)*(byte *)(*(long *)(lVar4 + 0x120) + 0x11 +
466: (ulong)(uVar20 + *(int *)(lVar4 + 0x90 +
467: (long)iVar27 * 8) & 0xff));
468: }
469: uVar20 = uVar21 & 0xf;
470: if (uVar20 != 0) break;
471: if (((int)uVar21 >> 4 != 0xf) || (iVar15 = iVar15 + 0x10, 0x3f < iVar15))
472: goto LAB_001316fd;
473: }
474: iVar27 = iVar15 + ((int)uVar21 >> 4);
475: if (iVar14 < 0x11) {
476: bVar10 = pbVar7[1];
477: uVar17 = uVar18 << 8 | (ulong)*pbVar7;
478: pbVar13 = pbVar7 + 2;
479: pbVar8 = pbVar7 + 1;
480: if (*pbVar7 == 0xff) {
481: if (bVar10 == 0) {
482: bVar10 = pbVar7[2];
483: pbVar13 = pbVar7 + 3;
484: pbVar8 = pbVar7 + 2;
485: }
486: else {
487: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
488: uVar17 = uVar18 << 8;
489: bVar10 = *pbVar7;
490: pbVar13 = pbVar7 + 1;
491: pbVar8 = pbVar7;
492: }
493: }
494: bVar5 = pbVar8[1];
495: uVar18 = uVar17 << 8 | (ulong)bVar10;
496: if (bVar10 == 0xff) {
497: if (bVar5 == 0) {
498: bVar5 = pbVar8[2];
499: pbVar7 = pbVar8 + 3;
500: pbVar8 = pbVar8 + 2;
501: }
502: else {
503: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
504: uVar18 = uVar17 << 8;
505: bVar5 = *pbVar8;
506: pbVar7 = pbVar13;
507: }
508: }
509: else {
510: pbVar7 = pbVar13 + 1;
511: pbVar8 = pbVar13;
512: }
513: bVar10 = pbVar8[1];
514: uVar17 = uVar18 << 8 | (ulong)bVar5;
515: pbVar13 = pbVar7;
516: pbVar16 = pbVar7 + 1;
517: if (bVar5 == 0xff) {
518: if (bVar10 == 0) {
519: bVar10 = pbVar8[2];
520: pbVar13 = pbVar8 + 2;
521: pbVar16 = pbVar8 + 3;
522: }
523: else {
524: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
525: uVar17 = uVar18 << 8;
526: bVar10 = *pbVar8;
527: pbVar13 = pbVar8;
528: pbVar16 = pbVar7;
529: }
530: }
531: bVar5 = pbVar13[1];
532: uVar18 = uVar17 << 8 | (ulong)bVar10;
533: if (bVar10 == 0xff) {
534: if (bVar5 == 0) {
535: bVar5 = pbVar13[2];
536: pbVar8 = pbVar13 + 3;
537: pbVar13 = pbVar13 + 2;
538: }
539: else {
540: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
541: uVar18 = uVar17 << 8;
542: bVar5 = *pbVar13;
543: pbVar8 = pbVar16;
544: }
545: }
546: else {
547: pbVar8 = pbVar16 + 1;
548: pbVar13 = pbVar16;
549: }
550: bVar10 = pbVar13[1];
551: uVar17 = uVar18 << 8 | (ulong)bVar5;
552: if (bVar5 == 0xff) {
553: if (bVar10 == 0) {
554: bVar10 = pbVar13[2];
555: pbVar7 = pbVar13 + 3;
556: pbVar13 = pbVar13 + 2;
557: }
558: else {
559: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
560: uVar17 = uVar18 << 8;
561: bVar10 = *pbVar13;
562: pbVar7 = pbVar8;
563: }
564: }
565: else {
566: pbVar7 = pbVar8 + 1;
567: pbVar13 = pbVar8;
568: }
569: iVar14 = iVar14 + 0x30;
570: uVar18 = uVar17 << 8 | (ulong)bVar10;
571: if (bVar10 == 0xff) {
572: if (pbVar13[1] == 0) {
573: pbVar7 = pbVar13 + 2;
574: }
575: else {
576: *(uint *)(param_1 + 0x21c) = (uint)pbVar13[1];
577: uVar18 = uVar17 << 8;
578: pbVar7 = pbVar13;
579: }
580: }
581: }
582: iVar14 = iVar14 - uVar20;
583: sVar11 = (sbyte)uVar20;
584: uVar20 = (uint)(uVar18 >> ((byte)iVar14 & 0x3f)) & (1 << sVar11) - 1U;
585: iVar15 = iVar27 + 1;
586: puVar29[*(int *)(&DAT_0018f100 + (long)iVar27 * 4)] =
587: ((ushort)((int)(uVar20 - (1 << (sVar11 - 1U & 0x1f))) >> 0x1f) &
588: (short)(-1 << sVar11) + 1U) + (short)uVar20;
589: } while (iVar15 < 0x40);
590: }
591: else {
592: lVar12 = (long)*(int *)(param_1 + 0x1e0 + lVar28 * 4);
593: iVar27 = aiStack88[lVar12];
594: aiStack88[lVar12] = uVar20 + iVar27;
595: if ((puVar29 != (undefined2 *)0x0) &&
596: (iVar2 = *(int *)(lVar3 + 0x144 + lVar28 * 4), *puVar29 = (short)(uVar20 + iVar27),
597: iVar2 != 0)) goto LAB_001314eb;
598: LAB_001318d9:
599: do {
600: if (iVar14 < 0x11) {
601: bVar10 = pbVar7[1];
602: uVar17 = (ulong)*pbVar7 | uVar18 << 8;
603: pbVar13 = pbVar7 + 2;
604: pbVar8 = pbVar7 + 1;
605: if (*pbVar7 == 0xff) {
606: if (bVar10 == 0) {
607: bVar10 = pbVar7[2];
608: pbVar13 = pbVar7 + 3;
609: pbVar8 = pbVar7 + 2;
610: }
611: else {
612: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
613: uVar17 = uVar18 << 8;
614: bVar10 = *pbVar7;
615: pbVar13 = pbVar7 + 1;
616: pbVar8 = pbVar7;
617: }
618: }
619: bVar5 = pbVar8[1];
620: uVar19 = (ulong)bVar5;
621: uVar18 = (ulong)bVar10 | uVar17 << 8;
622: if (bVar10 == 0xff) {
623: if (bVar5 == 0) {
624: uVar19 = (ulong)pbVar8[2];
625: pbVar7 = pbVar8 + 3;
626: pbVar8 = pbVar8 + 2;
627: }
628: else {
629: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
630: uVar18 = uVar17 << 8;
631: uVar19 = (ulong)*pbVar8;
632: pbVar7 = pbVar13;
633: }
634: }
635: else {
636: pbVar7 = pbVar13 + 1;
637: pbVar8 = pbVar13;
638: }
639: bVar10 = pbVar8[1];
640: uVar26 = (ulong)bVar10;
641: uVar17 = uVar19 | uVar18 << 8;
642: if ((char)uVar19 == -1) {
643: if (bVar10 == 0) {
644: pbVar7 = pbVar8 + 3;
645: uVar26 = (ulong)pbVar8[2];
646: pbVar8 = pbVar8 + 2;
647: }
648: else {
649: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
650: uVar17 = uVar18 << 8;
651: uVar26 = (ulong)*pbVar8;
652: }
653: }
654: else {
655: pbVar8 = pbVar7;
656: pbVar7 = pbVar7 + 1;
657: }
658: bVar10 = pbVar8[1];
659: uVar18 = uVar26 | uVar17 << 8;
660: if ((char)uVar26 == -1) {
661: if (bVar10 == 0) {
662: bVar10 = pbVar8[2];
663: pbVar13 = pbVar8 + 3;
664: pbVar8 = pbVar8 + 2;
665: }
666: else {
667: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
668: uVar18 = uVar17 << 8;
669: bVar10 = *pbVar8;
670: pbVar13 = pbVar7;
671: }
672: }
673: else {
674: pbVar13 = pbVar7 + 1;
675: pbVar8 = pbVar7;
676: }
677: bVar5 = pbVar8[1];
678: uVar17 = (ulong)bVar10 | uVar18 << 8;
679: pbVar7 = pbVar13 + 1;
680: if (bVar10 == 0xff) {
681: if (bVar5 == 0) {
682: bVar5 = pbVar8[2];
683: pbVar7 = pbVar8 + 3;
684: pbVar13 = pbVar8 + 2;
685: }
686: else {
687: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
688: uVar17 = uVar18 << 8;
689: bVar5 = *pbVar8;
690: pbVar7 = pbVar13;
691: pbVar13 = pbVar8;
692: }
693: }
694: iVar14 = iVar14 + 0x30;
695: uVar18 = uVar17 << 8 | (ulong)bVar5;
696: if (bVar5 == 0xff) {
697: if (pbVar13[1] == 0) {
698: pbVar7 = pbVar13 + 2;
699: }
700: else {
701: *(uint *)(param_1 + 0x21c) = (uint)pbVar13[1];
702: uVar18 = uVar17 << 8;
703: pbVar7 = pbVar13;
704: }
705: }
706: }
707: uVar20 = *(uint *)(lVar4 + 0x128 + (uVar18 >> ((char)iVar14 - 8U & 0x3f) & 0xff) * 4
708: );
709: uVar21 = uVar20 & 0xff;
710: iVar27 = (int)uVar20 >> 8;
711: iVar14 = iVar14 - iVar27;
712: if (8 < iVar27) {
713: uVar20 = (uint)(uVar18 >> ((byte)iVar14 & 0x3f)) &
714: (1 << ((byte)(uVar20 >> 8) & 0x1f)) - 1U;
715: if (*(long *)(lVar4 + (long)iVar27 * 8) < (long)(int)uVar20) {
716: lVar12 = (long)(iVar27 + 1);
717: do {
718: iVar14 = iVar14 + -1;
719: uVar20 = uVar20 * 2 | (uint)(uVar18 >> ((byte)iVar14 & 0x3f)) & 1;
720: iVar27 = (int)lVar12;
721: lVar12 = lVar12 + 1;
722: } while (*(long *)(lVar4 + -8 + lVar12 * 8) < (long)(int)uVar20);
723: }
724: if (0x10 < iVar27) break;
725: uVar21 = (uint)*(byte *)(*(long *)(lVar4 + 0x120) + 0x11 +
726: (ulong)(uVar20 + *(int *)(lVar4 + 0x90 + (long)iVar27 * 8)
727: & 0xff));
728: }
729: uVar20 = uVar21 & 0xf;
730: if (uVar20 == 0) {
731: if ((int)uVar21 >> 4 != 0xf) break;
732: iVar27 = iVar15 + 0xf;
733: }
734: else {
735: iVar27 = iVar15 + ((int)uVar21 >> 4);
736: pbVar8 = pbVar7;
737: if (iVar14 < 0x11) {
738: bVar10 = pbVar7[1];
739: uVar19 = (ulong)bVar10;
740: uVar17 = uVar18 << 8 | (ulong)*pbVar7;
741: pbVar8 = pbVar7 + 2;
742: pbVar13 = pbVar7 + 1;
743: if (*pbVar7 == 0xff) {
744: if (bVar10 == 0) {
745: uVar19 = (ulong)pbVar7[2];
746: pbVar8 = pbVar7 + 3;
747: pbVar13 = pbVar7 + 2;
748: }
749: else {
750: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
751: uVar17 = uVar18 << 8;
752: uVar19 = (ulong)*pbVar7;
753: pbVar8 = pbVar7 + 1;
754: pbVar13 = pbVar7;
755: }
756: }
757: bVar10 = pbVar13[1];
758: uVar18 = uVar17 << 8 | uVar19;
759: if ((char)uVar19 == -1) {
760: if (bVar10 == 0) {
761: pbVar8 = pbVar13 + 3;
762: bVar10 = pbVar13[2];
763: pbVar13 = pbVar13 + 2;
764: }
765: else {
766: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
767: uVar18 = uVar17 << 8;
768: bVar10 = *pbVar13;
769: }
770: }
771: else {
772: pbVar13 = pbVar8;
773: pbVar8 = pbVar8 + 1;
774: }
775: bVar5 = pbVar13[1];
776: uVar19 = (ulong)bVar5;
777: uVar17 = uVar18 << 8 | (ulong)bVar10;
778: pbVar16 = pbVar8 + 1;
779: pbVar7 = pbVar8;
780: if (bVar10 == 0xff) {
781: if (bVar5 == 0) {
782: uVar19 = (ulong)pbVar13[2];
783: pbVar16 = pbVar13 + 3;
784: pbVar7 = pbVar13 + 2;
785: }
786: else {
787: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
788: uVar17 = uVar18 << 8;
789: uVar19 = (ulong)*pbVar13;
790: pbVar16 = pbVar8;
791: pbVar7 = pbVar13;
792: }
793: }
794: bVar10 = pbVar7[1];
795: uVar18 = uVar17 << 8 | uVar19;
796: if ((char)uVar19 == -1) {
797: if (bVar10 == 0) {
798: pbVar16 = pbVar7 + 3;
799: bVar10 = pbVar7[2];
800: pbVar7 = pbVar7 + 2;
801: }
802: else {
803: *(uint *)(param_1 + 0x21c) = (uint)bVar10;
804: uVar18 = uVar17 << 8;
805: bVar10 = *pbVar7;
806: }
807: }
808: else {
809: pbVar7 = pbVar16;
810: pbVar16 = pbVar16 + 1;
811: }
812: bVar5 = pbVar7[1];
813: uVar19 = (ulong)bVar5;
814: uVar17 = (ulong)bVar10 | uVar18 << 8;
815: if (bVar10 == 0xff) {
816: if (bVar5 == 0) {
817: uVar19 = (ulong)pbVar7[2];
818: pbVar8 = pbVar7 + 3;
819: pbVar7 = pbVar7 + 2;
820: }
821: else {
822: *(uint *)(param_1 + 0x21c) = (uint)bVar5;
823: uVar17 = uVar18 << 8;
824: uVar19 = (ulong)*pbVar7;
825: pbVar8 = pbVar16;
826: }
827: }
828: else {
829: pbVar8 = pbVar16 + 1;
830: pbVar7 = pbVar16;
831: }
832: iVar14 = iVar14 + 0x30;
833: uVar18 = uVar17 << 8 | uVar19;
834: if ((char)uVar19 == -1) {
835: if (pbVar7[1] == 0) {
836: pbVar7 = pbVar7 + 2;
837: iVar14 = iVar14 - uVar20;
838: }
839: else {
840: *(uint *)(param_1 + 0x21c) = (uint)pbVar7[1];
841: uVar18 = uVar17 << 8;
842: iVar14 = iVar14 - uVar20;
843: }
844: goto LAB_001318cd;
845: }
846: }
847: pbVar7 = pbVar8;
848: iVar14 = iVar14 - uVar20;
849: }
850: LAB_001318cd:
851: iVar15 = iVar27 + 1;
852: } while (iVar27 + 1 < 0x40);
853: }
854: LAB_001316fd:
855: iVar15 = (int)lVar28;
856: lVar28 = lVar28 + 1;
857: } while (iVar15 < iVar25);
858: if (*(int *)(param_1 + 0x21c) != 0) {
859: pbStack168 = ppbVar22[1];
860: *(undefined4 *)(param_1 + 0x21c) = 0;
861: uVar18 = *(ulong *)(lVar3 + 0x18);
862: iVar14 = *(int *)(lVar3 + 0x20);
863: goto LAB_00130de3;
864: }
865: pbStack168 = pbStack168 + -(long)(pbVar7 + -(long)pbVar9);
866: pbVar9 = pbVar7;
867: }
868: *ppbVar22 = pbVar9;
869: ppbVar22[1] = pbStack168;
870: *(int *)(lVar3 + 0x20) = iVar14;
871: *(ulong *)(lVar3 + 0x18) = uVar18;
872: *(int *)(lVar3 + 0x28) = aiStack88[0];
873: *(int *)(lVar3 + 0x2c) = aiStack88[1];
874: *(int *)(lVar3 + 0x30) = aiStack88[2];
875: *(int *)(lVar3 + 0x34) = aiStack88[3];
876: }
877: }
878: }
879: else {
880: iStack184 = 0;
881: if (*(int *)(lVar3 + 0x38) != 0) goto LAB_00130cad;
882: lVar28 = *(long *)(param_1 + 0x248);
883: iVar24 = *(int *)(lVar3 + 0x20);
884: iVar25 = iVar24 + 7;
885: if (-1 < iVar24) {
886: iVar25 = iVar24;
887: }
888: piVar1 = (int *)(lVar28 + 0x24);
889: *piVar1 = *piVar1 + (iVar25 >> 3);
890: *(undefined4 *)(lVar3 + 0x20) = 0;
891: uVar6 = (**(code **)(lVar28 + 0x10))();
892: if ((int)uVar6 == 0) goto LAB_00130d11;
893: if (0 < *(int *)(param_1 + 0x1b0)) {
894: memset((void *)(lVar3 + 0x28),0,(ulong)(*(int *)(param_1 + 0x1b0) - 1) * 4 + 4);
895: }
896: iVar24 = *(int *)(param_1 + 0x170);
897: ppbVar22 = *(byte ***)(param_1 + 0x28);
898: iVar25 = *(int *)(param_1 + 0x1e0);
899: *(int *)(lVar3 + 0x38) = iVar24;
900: pbStack168 = ppbVar22[1];
901: if (*(int *)(param_1 + 0x21c) != 0) {
902: iVar14 = *(int *)(lVar3 + 0x10);
903: goto LAB_00130dc8;
904: }
905: *(undefined4 *)(lVar3 + 0x10) = 0;
906: LAB_00130dd0:
907: lStack208 = *(long *)(param_1 + 0x250);
908: uVar18 = *(ulong *)(lStack208 + 0x18);
909: iVar14 = *(int *)(lStack208 + 0x20);
910: LAB_00130de3:
911: pbStack136 = *ppbVar22;
912: pbStack128 = pbStack168;
913: aiStack88[0] = *(int *)(lStack208 + 0x28);
914: aiStack88[1] = *(undefined4 *)(lStack208 + 0x2c);
915: aiStack88[2] = *(undefined4 *)(lStack208 + 0x30);
916: aiStack88[3] = *(undefined4 *)(lStack208 + 0x34);
917: lStack104 = param_1;
918: if (0 < iVar25) {
919: lVar28 = 1;
920: do {
921: puVar29 = (undefined2 *)0x0;
922: if (param_2 != 0) {
923: puVar29 = *(undefined2 **)(param_2 + -8 + lVar28 * 8);
924: }
925: lVar12 = *(long *)(lStack208 + 0x78 + lVar28 * 8);
926: lVar4 = *(long *)(lStack208 + 200 + lVar28 * 8);
927: if (iVar14 < 8) {
928: iVar24 = FUN_00130960(&pbStack136);
929: if (iVar24 != 0) {
930: uVar18 = uStack120;
931: iVar14 = iStack112;
932: if (7 < iStack112) goto LAB_00130e51;
933: goto LAB_0013120e;
934: }
935: LAB_00131230:
936: uVar6 = 0;
937: goto LAB_00130d11;
938: }
939: LAB_00130e51:
940: uVar20 = *(uint *)(lVar12 + 0x128 + (uVar18 >> ((char)iVar14 - 8U & 0x3f) & 0xff) * 4);
941: iVar24 = (int)uVar20 >> 8;
942: if (iVar24 < 9) {
943: uVar20 = uVar20 & 0xff;
944: iVar14 = iVar14 - iVar24;
945: }
946: else {
947: LAB_0013120e:
948: uVar20 = FUN_00130b10(&pbStack136);
949: uVar18 = uStack120;
950: iVar14 = iStack112;
951: if ((int)uVar20 < 0) goto LAB_00131230;
952: }
953: if (uVar20 != 0) {
954: if ((iVar14 < (int)uVar20) &&
955: (iVar24 = FUN_00130960(&pbStack136), uVar18 = uStack120, iVar14 = iStack112,
956: iVar24 == 0)) goto LAB_00131230;
957: iVar14 = iVar14 - uVar20;
958: bVar10 = (byte)uVar20;
959: uVar20 = (1 << (bVar10 & 0x1f)) - 1U & (uint)(uVar18 >> ((byte)iVar14 & 0x3f));
960: uVar20 = ((int)(uVar20 - (1 << (bVar10 - 1 & 0x1f))) >> 0x1f &
961: (-1 << (bVar10 & 0x1f)) + 1U) + uVar20;
962: }
963: if (*(int *)(lStack208 + 0x11c + lVar28 * 4) == 0) {
964: if ((*(int *)(lStack208 + 0x144 + lVar28 * 4) != 0) && (puVar29 != (undefined2 *)0x0))
965: goto LAB_00130f21;
966: LAB_00131095:
967: iVar24 = 1;
968: do {
969: if (iVar14 < 8) {
970: iVar25 = FUN_00130960(&pbStack136);
971: if (iVar25 == 0) goto LAB_00131230;
972: uVar18 = uStack120;
973: iVar14 = iStack112;
974: if (7 < iStack112) goto LAB_001310c2;
975: LAB_0013112e:
976: uVar20 = FUN_00130b10(&pbStack136);
977: uVar18 = uStack120;
978: iVar14 = iStack112;
979: if ((int)uVar20 < 0) goto LAB_00131230;
980: }
981: else {
982: LAB_001310c2:
983: uVar20 = *(uint *)(lVar4 + 0x128 + (uVar18 >> ((char)iVar14 - 8U & 0x3f) & 0xff) * 4);
984: iVar25 = (int)uVar20 >> 8;
985: if (8 < iVar25) goto LAB_0013112e;
986: uVar20 = uVar20 & 0xff;
987: iVar14 = iVar14 - iVar25;
988: }
989: uVar21 = uVar20 & 0xf;
990: if (uVar21 == 0) {
991: if ((int)uVar20 >> 4 != 0xf) break;
992: iVar24 = iVar24 + 0xf;
993: }
994: else {
995: iVar24 = iVar24 + ((int)uVar20 >> 4);
996: if ((iVar14 < (int)uVar21) &&
997: (iVar25 = FUN_00130960(&pbStack136), uVar18 = uStack120, iVar14 = iStack112,
998: iVar25 == 0)) goto LAB_00131230;
999: iVar14 = iVar14 - uVar21;
1000: }
1001: iVar24 = iVar24 + 1;
1002: } while (iVar24 < 0x40);
1003: }
1004: else {
1005: lVar12 = (long)*(int *)(param_1 + 0x1e0 + lVar28 * 4);
1006: iVar24 = aiStack88[lVar12];
1007: aiStack88[lVar12] = uVar20 + iVar24;
1008: if ((puVar29 == (undefined2 *)0x0) ||
1009: (iVar25 = *(int *)(lStack208 + 0x144 + lVar28 * 4), *puVar29 = (short)(uVar20 + iVar24)
1010: , iVar25 == 0)) goto LAB_00131095;
1011: LAB_00130f21:
1012: iVar24 = 1;
1013: do {
1014: if (iVar14 < 8) {
1015: iVar25 = FUN_00130960(&pbStack136);
1016: if (iVar25 == 0) goto LAB_00131230;
1017: uVar18 = uStack120;
1018: iVar14 = iStack112;
1019: if (7 < iStack112) goto LAB_00130fb5;
1020: LAB_0013117a:
1021: uVar20 = FUN_00130b10(&pbStack136);
1022: uVar18 = uStack120;
1023: iVar14 = iStack112;
1024: if ((int)uVar20 < 0) goto LAB_00131230;
1025: }
1026: else {
1027: LAB_00130fb5:
1028: uVar20 = *(uint *)(lVar4 + 0x128 + (uVar18 >> ((char)iVar14 - 8U & 0x3f) & 0xff) * 4);
1029: iVar25 = (int)uVar20 >> 8;
1030: if (8 < iVar25) goto LAB_0013117a;
1031: uVar20 = uVar20 & 0xff;
1032: iVar14 = iVar14 - iVar25;
1033: }
1034: uVar21 = uVar20 & 0xf;
1035: if (uVar21 == 0) {
1036: if ((int)uVar20 >> 4 != 0xf) break;
1037: iVar24 = iVar24 + 0x10;
1038: }
1039: else {
1040: iVar25 = iVar24 + ((int)uVar20 >> 4);
1041: if ((iVar14 < (int)uVar21) &&
1042: (iVar24 = FUN_00130960(&pbStack136), uVar18 = uStack120, iVar14 = iStack112,
1043: iVar24 == 0)) goto LAB_00131230;
1044: iVar14 = iVar14 - uVar21;
1045: sVar11 = (sbyte)uVar21;
1046: uVar20 = (uint)(uVar18 >> ((byte)iVar14 & 0x3f)) & (1 << sVar11) - 1U;
1047: iVar24 = iVar25 + 1;
1048: puVar29[*(int *)(&DAT_0018f100 + (long)iVar25 * 4)] =
1049: ((ushort)((int)(uVar20 - (1 << (sVar11 - 1U & 0x1f))) >> 0x1f) &
1050: (short)(-1 << sVar11) + 1U) + (short)uVar20;
1051: }
1052: } while (iVar24 < 0x40);
1053: }
1054: iVar24 = (int)lVar28;
1055: lVar28 = lVar28 + 1;
1056: } while (iVar24 < *(int *)(param_1 + 0x1e0));
1057: ppbVar22 = *(byte ***)(param_1 + 0x28);
1058: iVar24 = *(int *)(param_1 + 0x170);
1059: }
1060: *ppbVar22 = pbStack136;
1061: ppbVar22[1] = pbStack128;
1062: *(ulong *)(lStack208 + 0x18) = uVar18;
1063: *(int *)(lStack208 + 0x20) = iVar14;
1064: *(int *)(lStack208 + 0x28) = aiStack88[0];
1065: *(int *)(lStack208 + 0x2c) = aiStack88[1];
1066: *(int *)(lStack208 + 0x30) = aiStack88[2];
1067: *(int *)(lStack208 + 0x34) = aiStack88[3];
1068: }
1069: uVar6 = 1;
1070: if (iVar24 != 0) {
1071: uVar6 = 1;
1072: *(int *)(lVar3 + 0x38) = *(int *)(lVar3 + 0x38) + -1;
1073: }
1074: LAB_00130d11:
1075: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
1076: return uVar6;
1077: }
1078: /* WARNING: Subroutine does not return */
1079: __stack_chk_fail();
1080: }
1081: 
