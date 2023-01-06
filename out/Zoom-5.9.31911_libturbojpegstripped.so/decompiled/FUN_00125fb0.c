1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined8 FUN_00125fb0(long param_1,long param_2)
5: 
6: {
7: int *piVar1;
8: long lVar2;
9: byte *pbVar3;
10: long lVar4;
11: bool bVar5;
12: uint uVar6;
13: byte *pbVar7;
14: long lVar8;
15: byte bVar9;
16: sbyte sVar10;
17: byte bVar11;
18: byte **ppbVar12;
19: long lVar13;
20: long lVar14;
21: byte *pbVar15;
22: byte *pbVar16;
23: byte *pbVar17;
24: byte *pbVar18;
25: int iVar19;
26: uint uVar20;
27: ulong uVar21;
28: ulong uVar22;
29: byte *pbVar23;
30: int iVar24;
31: int iVar25;
32: int iVar26;
33: ulong uVar27;
34: ulong uVar28;
35: undefined2 *puVar29;
36: long lVar30;
37: long lStack192;
38: long lStack184;
39: long lStack160;
40: long lStack152;
41: byte *apbStack120 [2];
42: byte *pbStack104;
43: byte *pbStack96;
44: ulong uStack88;
45: int iStack80;
46: long lStack72;
47: 
48: lVar2 = *(long *)(param_1 + 0x250);
49: if (*(int *)(param_1 + 0x170) == 0) {
50: iVar19 = *(int *)(lVar2 + 0x10);
51: bVar5 = true;
52: }
53: else {
54: if (*(int *)(lVar2 + 0x38) == 0) {
55: lVar8 = *(long *)(param_1 + 0x248);
56: iVar19 = *(int *)(lVar2 + 0x20);
57: if (iVar19 < 0) {
58: iVar19 = iVar19 + 7;
59: }
60: piVar1 = (int *)(lVar8 + 0x24);
61: *piVar1 = *piVar1 + (iVar19 >> 3);
62: *(undefined4 *)(lVar2 + 0x20) = 0;
63: iVar19 = (**(code **)(lVar8 + 0x10))();
64: if (iVar19 == 0) {
65: return 0;
66: }
67: if (0 < *(int *)(param_1 + 0x1b0)) {
68: memset((void *)(lVar2 + 0x28),0,(long)*(int *)(param_1 + 0x1b0) * 4);
69: }
70: iVar19 = *(int *)(param_1 + 0x21c);
71: *(undefined4 *)(lVar2 + 0x38) = *(undefined4 *)(param_1 + 0x170);
72: if (iVar19 == 0) {
73: *(undefined4 *)(lVar2 + 0x10) = 0;
74: iVar19 = 0;
75: bVar5 = false;
76: goto LAB_00126002;
77: }
78: }
79: iVar19 = *(int *)(lVar2 + 0x10);
80: bVar5 = false;
81: }
82: LAB_00126002:
83: ppbVar12 = *(byte ***)(param_1 + 0x28);
84: pbVar7 = ppbVar12[1];
85: iVar24 = *(int *)(param_1 + 0x1e0);
86: if ((pbVar7 < (byte *)((long)iVar24 << 9)) || (*(int *)(param_1 + 0x21c) != 0)) {
87: if (iVar19 != 0) goto LAB_001262dd;
88: LAB_00126044:
89: lStack160 = *(long *)(param_1 + 0x250);
90: LAB_00126058:
91: lStack72 = param_1;
92: iVar19 = *(int *)(lStack160 + 0x20);
93: pbStack104 = *ppbVar12;
94: pbStack96 = pbVar7;
95: apbStack120[0] = *(byte **)(lStack160 + 0x28);
96: uVar21 = *(ulong *)(lStack160 + 0x18);
97: apbStack120[1] = (byte *)*(undefined8 *)(lStack160 + 0x30);
98: if (0 < iVar24) {
99: lStack184 = 0;
100: lStack192 = lStack160;
101: lStack152 = lStack160;
102: do {
103: if (param_2 == 0) {
104: puVar29 = (undefined2 *)0x0;
105: }
106: else {
107: puVar29 = *(undefined2 **)(param_2 + lStack184 * 8);
108: }
109: lVar8 = *(long *)(lStack152 + 0x80);
110: lVar30 = *(long *)(lStack152 + 0xd0);
111: if (iVar19 < 8) {
112: iVar19 = FUN_00125d30();
113: if (iVar19 == 0) {
114: return 0;
115: }
116: uVar21 = uStack88;
117: iVar19 = iStack80;
118: if (7 < iStack80) goto LAB_001260eb;
119: LAB_00127306:
120: uVar20 = FUN_00125ea0();
121: uVar21 = uStack88;
122: iVar19 = iStack80;
123: if ((int)uVar20 < 0) {
124: return 0;
125: }
126: }
127: else {
128: LAB_001260eb:
129: uVar20 = *(uint *)(lVar8 + 0x128 + (uVar21 >> ((char)iVar19 - 8U & 0x3f) & 0xff) * 4);
130: iVar24 = (int)uVar20 >> 8;
131: if (8 < iVar24) goto LAB_00127306;
132: uVar20 = uVar20 & 0xff;
133: iVar19 = iVar19 - iVar24;
134: }
135: if (uVar20 != 0) {
136: if ((iVar19 < (int)uVar20) &&
137: (iVar24 = FUN_00125d30(apbStack120 + 2), uVar21 = uStack88, iVar19 = iStack80,
138: iVar24 == 0)) {
139: return 0;
140: }
141: iVar19 = iVar19 - uVar20;
142: bVar9 = (byte)uVar20;
143: uVar20 = (1 << (bVar9 & 0x1f)) - 1U & (uint)(uVar21 >> ((byte)iVar19 & 0x3f));
144: uVar20 = ((int)(uVar20 - (1 << (bVar9 - 1 & 0x1f))) >> 0x1f & (-1 << (bVar9 & 0x1f)) + 1U)
145: + uVar20;
146: }
147: if (*(int *)(lStack192 + 0x120) == 0) {
148: if ((*(int *)(lStack192 + 0x148) == 0) || (puVar29 == (undefined2 *)0x0))
149: goto LAB_00127170;
150: }
151: else {
152: lVar8 = (long)*(int *)(param_1 + 0x1e4 + lStack184 * 4);
153: iVar24 = uVar20 + *(int *)((long)apbStack120 + lVar8 * 4);
154: *(int *)((long)apbStack120 + lVar8 * 4) = iVar24;
155: if ((puVar29 == (undefined2 *)0x0) ||
156: (*puVar29 = (short)iVar24, *(int *)(lStack192 + 0x148) == 0)) {
157: LAB_00127170:
158: iVar24 = 1;
159: if (iVar19 < 8) goto LAB_001271d3;
160: LAB_00127180:
161: uVar20 = *(uint *)(lVar30 + 0x128 + (uVar21 >> ((char)iVar19 - 8U & 0x3f) & 0xff) * 4);
162: if (8 < (int)uVar20 >> 8) goto LAB_001271fe;
163: iVar19 = iVar19 - ((int)uVar20 >> 8);
164: iVar25 = (int)(uVar20 & 0xff) >> 4;
165: uVar20 = uVar20 & 0xf;
166: if (uVar20 == 0) goto LAB_00127226;
167: do {
168: iVar24 = iVar24 + iVar25;
169: if ((iVar19 < (int)uVar20) &&
170: (iVar25 = FUN_00125d30(), uVar21 = uStack88, iVar19 = iStack80, iVar25 == 0)) {
171: return 0;
172: }
173: iVar19 = iVar19 - uVar20;
174: while( true ) {
175: iVar24 = iVar24 + 1;
176: if (0x3f < iVar24) goto LAB_00126280;
177: if (7 < iVar19) goto LAB_00127180;
178: LAB_001271d3:
179: iVar19 = FUN_00125d30();
180: if (iVar19 == 0) {
181: return 0;
182: }
183: uVar21 = uStack88;
184: iVar19 = iStack80;
185: if (7 < iStack80) goto LAB_00127180;
186: LAB_001271fe:
187: uVar20 = FUN_00125ea0();
188: if ((int)uVar20 < 0) {
189: return 0;
190: }
191: iVar25 = (int)uVar20 >> 4;
192: uVar20 = uVar20 & 0xf;
193: uVar21 = uStack88;
194: iVar19 = iStack80;
195: if (uVar20 != 0) break;
196: LAB_00127226:
197: if (iVar25 != 0xf) goto LAB_00126280;
198: iVar24 = iVar24 + 0xf;
199: }
200: } while( true );
201: }
202: }
203: iVar24 = 1;
204: do {
205: if (iVar19 < 8) {
206: iVar19 = FUN_00125d30();
207: if (iVar19 == 0) {
208: return 0;
209: }
210: uVar21 = uStack88;
211: iVar19 = iStack80;
212: if (7 < iStack80) goto LAB_00126230;
213: LAB_0012728f:
214: uVar20 = FUN_00125ea0();
215: uVar21 = uStack88;
216: iVar19 = iStack80;
217: if ((int)uVar20 < 0) {
218: return 0;
219: }
220: }
221: else {
222: LAB_00126230:
223: uVar20 = *(uint *)(lVar30 + 0x128 + (uVar21 >> ((char)iVar19 - 8U & 0x3f) & 0xff) * 4);
224: iVar25 = (int)uVar20 >> 8;
225: if (8 < iVar25) goto LAB_0012728f;
226: uVar20 = uVar20 & 0xff;
227: iVar19 = iVar19 - iVar25;
228: }
229: uVar6 = uVar20 & 0xf;
230: if (uVar6 == 0) {
231: if ((int)uVar20 >> 4 != 0xf) break;
232: iVar24 = iVar24 + 0x10;
233: }
234: else {
235: iVar25 = iVar24 + ((int)uVar20 >> 4);
236: if ((iVar19 < (int)uVar6) &&
237: (iVar24 = FUN_00125d30(), uVar21 = uStack88, iVar19 = iStack80, iVar24 == 0)) {
238: return 0;
239: }
240: iVar19 = iVar19 - uVar6;
241: sVar10 = (sbyte)uVar6;
242: uVar20 = (1 << sVar10) - 1U & (uint)(uVar21 >> ((byte)iVar19 & 0x3f));
243: iVar24 = iVar25 + 1;
244: puVar29[*(int *)(&DAT_0018b460 + (long)iVar25 * 4)] =
245: (short)uVar20 +
246: ((ushort)((int)(uVar20 - (1 << (sVar10 - 1U & 0x1f))) >> 0x1f) &
247: (short)(-1 << sVar10) + 1U);
248: }
249: } while (iVar24 < 0x40);
250: LAB_00126280:
251: lStack184 = lStack184 + 1;
252: lStack192 = lStack192 + 4;
253: lStack152 = lStack152 + 8;
254: } while ((int)lStack184 + 1 < *(int *)(param_1 + 0x1e0));
255: ppbVar12 = *(byte ***)(param_1 + 0x28);
256: }
257: ppbVar12[1] = pbStack96;
258: *ppbVar12 = pbStack104;
259: *(int *)(lStack160 + 0x20) = iVar19;
260: *(ulong *)(lStack160 + 0x18) = uVar21;
261: *(byte **)(lStack160 + 0x28) = apbStack120[0];
262: *(byte **)(lStack160 + 0x30) = apbStack120[1];
263: }
264: else {
265: if (iVar19 != 0) goto LAB_001262dd;
266: if (!bVar5) goto LAB_00126044;
267: lStack160 = *(long *)(param_1 + 0x250);
268: uVar21 = *(ulong *)(lStack160 + 0x18);
269: pbVar3 = *ppbVar12;
270: iVar19 = *(int *)(lStack160 + 0x20);
271: pbStack104 = (byte *)*(undefined8 *)(lStack160 + 0x28);
272: pbStack96 = (byte *)*(undefined8 *)(lStack160 + 0x30);
273: pbVar16 = pbVar3;
274: if (0 < iVar24) {
275: lVar30 = 0;
276: lVar8 = lStack160;
277: lStack184 = lStack160;
278: do {
279: if (param_2 == 0) {
280: puVar29 = (undefined2 *)0x0;
281: }
282: else {
283: puVar29 = *(undefined2 **)(param_2 + lVar30 * 8);
284: }
285: lVar14 = *(long *)(lStack184 + 0x80);
286: lVar4 = *(long *)(lStack184 + 0xd0);
287: if (iVar19 < 0x11) {
288: bVar9 = pbVar16[1];
289: uVar27 = (ulong)*pbVar16 | uVar21 << 8;
290: if (*pbVar16 == 0xff) {
291: if (bVar9 == 0) {
292: pbVar17 = pbVar16 + 2;
293: bVar9 = pbVar16[2];
294: pbVar15 = pbVar16 + 3;
295: }
296: else {
297: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
298: uVar27 = uVar21 << 8;
299: bVar9 = *pbVar16;
300: pbVar15 = pbVar16 + 1;
301: pbVar17 = pbVar16;
302: }
303: }
304: else {
305: pbVar15 = pbVar16 + 2;
306: pbVar17 = pbVar16 + 1;
307: }
308: bVar11 = pbVar17[1];
309: uVar21 = (ulong)bVar9 | uVar27 << 8;
310: pbVar16 = pbVar15;
311: pbVar18 = pbVar15 + 1;
312: if (bVar9 == 0xff) {
313: if (bVar11 == 0) {
314: pbVar16 = pbVar17 + 2;
315: bVar11 = pbVar17[2];
316: pbVar18 = pbVar17 + 3;
317: }
318: else {
319: *(uint *)(param_1 + 0x21c) = (uint)bVar11;
320: uVar21 = uVar27 << 8;
321: bVar11 = *pbVar17;
322: pbVar16 = pbVar17;
323: pbVar18 = pbVar15;
324: }
325: }
326: bVar9 = pbVar16[1];
327: uVar28 = (ulong)bVar9;
328: uVar27 = (ulong)bVar11 | uVar21 << 8;
329: if (bVar11 == 0xff) {
330: if (bVar9 == 0) {
331: pbVar18 = pbVar16 + 2;
332: uVar28 = (ulong)pbVar16[2];
333: pbVar17 = pbVar16 + 3;
334: }
335: else {
336: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
337: uVar27 = uVar21 << 8;
338: uVar28 = (ulong)*pbVar16;
339: pbVar17 = pbVar18;
340: pbVar18 = pbVar16;
341: }
342: }
343: else {
344: pbVar17 = pbVar18 + 1;
345: }
346: bVar9 = pbVar18[1];
347: uVar22 = (ulong)bVar9;
348: uVar21 = uVar28 | uVar27 << 8;
349: pbVar15 = pbVar17;
350: pbVar23 = pbVar17 + 1;
351: if ((char)uVar28 == -1) {
352: if (bVar9 == 0) {
353: pbVar15 = pbVar18 + 2;
354: uVar22 = (ulong)pbVar18[2];
355: pbVar23 = pbVar18 + 3;
356: }
357: else {
358: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
359: uVar21 = uVar27 << 8;
360: uVar22 = (ulong)*pbVar18;
361: pbVar15 = pbVar18;
362: pbVar23 = pbVar17;
363: }
364: }
365: bVar9 = pbVar15[1];
366: uVar28 = (ulong)bVar9;
367: uVar27 = uVar22 | uVar21 << 8;
368: pbVar17 = pbVar23;
369: pbVar16 = pbVar23 + 1;
370: if ((char)uVar22 == -1) {
371: if (bVar9 == 0) {
372: pbVar17 = pbVar15 + 2;
373: uVar28 = (ulong)pbVar15[2];
374: pbVar16 = pbVar15 + 3;
375: }
376: else {
377: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
378: uVar27 = uVar21 << 8;
379: uVar28 = (ulong)*pbVar15;
380: pbVar17 = pbVar15;
381: pbVar16 = pbVar23;
382: }
383: }
384: iVar19 = iVar19 + 0x30;
385: uVar21 = uVar28 | uVar27 << 8;
386: if (((char)uVar28 == -1) && (pbVar16 = pbVar17 + 2, pbVar17[1] != 0)) {
387: *(uint *)(param_1 + 0x21c) = (uint)pbVar17[1];
388: uVar21 = uVar27 << 8;
389: pbVar16 = pbVar17;
390: }
391: }
392: uVar6 = *(uint *)(lVar14 + 0x128 + (uVar21 >> ((char)iVar19 - 8U & 0x3f) & 0xff) * 4);
393: uVar20 = uVar6 & 0xff;
394: iVar25 = (int)uVar6 >> 8;
395: iVar19 = iVar19 - iVar25;
396: if (8 < iVar25) {
397: lVar13 = (long)iVar25;
398: uVar20 = (1 << ((byte)(uVar6 >> 8) & 0x1f)) - 1U & (uint)(uVar21 >> ((byte)iVar19 & 0x3f))
399: ;
400: if (*(long *)(lVar14 + lVar13 * 8) < (long)(int)uVar20) {
401: do {
402: iVar19 = iVar19 + -1;
403: iVar25 = iVar25 + 1;
404: uVar20 = (uint)(uVar21 >> ((byte)iVar19 & 0x3f)) & 1 | uVar20 * 2;
405: lVar13 = (long)iVar25;
406: } while (*(long *)(lVar14 + lVar13 * 8) < (long)(int)uVar20);
407: }
408: uVar20 = (uint)*(byte *)(*(long *)(lVar14 + 0x120) + 0x11 +
409: (ulong)(uVar20 + *(int *)(lVar14 + 0x90 + lVar13 * 8) & 0xff));
410: }
411: if (uVar20 != 0) {
412: if (iVar19 < 0x11) {
413: bVar9 = pbVar16[1];
414: uVar28 = (ulong)bVar9;
415: uVar27 = (ulong)*pbVar16 | uVar21 << 8;
416: pbVar17 = pbVar16 + 1;
417: pbVar15 = pbVar16 + 2;
418: if (*pbVar16 == 0xff) {
419: if (bVar9 == 0) {
420: uVar28 = (ulong)pbVar16[2];
421: pbVar17 = pbVar16 + 2;
422: pbVar15 = pbVar16 + 3;
423: }
424: else {
425: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
426: uVar27 = uVar21 << 8;
427: uVar28 = (ulong)*pbVar16;
428: pbVar17 = pbVar16;
429: pbVar15 = pbVar16 + 1;
430: }
431: }
432: bVar9 = pbVar17[1];
433: uVar21 = uVar28 | uVar27 << 8;
434: pbVar16 = pbVar15;
435: pbVar18 = pbVar15 + 1;
436: if ((char)uVar28 == -1) {
437: if (bVar9 == 0) {
438: bVar9 = pbVar17[2];
439: pbVar16 = pbVar17 + 2;
440: pbVar18 = pbVar17 + 3;
441: }
442: else {
443: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
444: uVar21 = uVar27 << 8;
445: bVar9 = *pbVar17;
446: pbVar16 = pbVar17;
447: pbVar18 = pbVar15;
448: }
449: }
450: bVar11 = pbVar16[1];
451: uVar27 = (ulong)bVar9 | uVar21 << 8;
452: pbVar17 = pbVar18 + 1;
453: if (bVar9 == 0xff) {
454: if (bVar11 == 0) {
455: bVar11 = pbVar16[2];
456: pbVar17 = pbVar16 + 3;
457: pbVar18 = pbVar16 + 2;
458: }
459: else {
460: *(uint *)(param_1 + 0x21c) = (uint)bVar11;
461: uVar27 = uVar21 << 8;
462: bVar11 = *pbVar16;
463: pbVar17 = pbVar18;
464: pbVar18 = pbVar16;
465: }
466: }
467: bVar9 = pbVar18[1];
468: uVar21 = (ulong)bVar11 | uVar27 << 8;
469: if (bVar11 == 0xff) {
470: if (bVar9 == 0) {
471: bVar9 = pbVar18[2];
472: pbVar15 = pbVar18 + 3;
473: pbVar18 = pbVar18 + 2;
474: }
475: else {
476: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
477: uVar21 = uVar27 << 8;
478: bVar9 = *pbVar18;
479: pbVar15 = pbVar17;
480: }
481: }
482: else {
483: pbVar15 = pbVar17 + 1;
484: pbVar18 = pbVar17;
485: }
486: bVar11 = pbVar18[1];
487: uVar27 = (ulong)bVar11;
488: uVar28 = (ulong)bVar9 | uVar21 << 8;
489: pbVar17 = pbVar15;
490: pbVar16 = pbVar15 + 1;
491: if (bVar9 == 0xff) {
492: if (bVar11 == 0) {
493: uVar27 = (ulong)pbVar18[2];
494: pbVar17 = pbVar18 + 2;
495: pbVar16 = pbVar18 + 3;
496: }
497: else {
498: *(uint *)(param_1 + 0x21c) = (uint)bVar11;
499: uVar28 = uVar21 << 8;
500: uVar27 = (ulong)*pbVar18;
501: pbVar17 = pbVar18;
502: pbVar16 = pbVar15;
503: }
504: }
505: iVar19 = iVar19 + 0x30;
506: uVar21 = uVar27 | uVar28 << 8;
507: if (((char)uVar27 == -1) && (pbVar16 = pbVar17 + 2, pbVar17[1] != 0)) {
508: *(uint *)(param_1 + 0x21c) = (uint)pbVar17[1];
509: uVar21 = uVar28 << 8;
510: pbVar16 = pbVar17;
511: }
512: }
513: iVar19 = iVar19 - uVar20;
514: bVar9 = (byte)uVar20;
515: uVar20 = (1 << (bVar9 & 0x1f)) - 1U & (uint)(uVar21 >> ((byte)iVar19 & 0x3f));
516: uVar20 = ((int)(uVar20 - (1 << (bVar9 - 1 & 0x1f))) >> 0x1f & (-1 << (bVar9 & 0x1f)) + 1U)
517: + uVar20;
518: }
519: if (*(int *)(lVar8 + 0x120) == 0) {
520: if ((*(int *)(lVar8 + 0x148) == 0) || (puVar29 == (undefined2 *)0x0)) goto LAB_00126990;
521: LAB_0012662b:
522: iVar25 = 1;
523: do {
524: if (iVar19 < 0x11) {
525: pbVar17 = pbVar16 + 1;
526: bVar9 = pbVar16[1];
527: uVar28 = (ulong)bVar9;
528: uVar27 = (ulong)*pbVar16 | uVar21 << 8;
529: if (*pbVar16 == 0xff) {
530: if (bVar9 == 0) {
531: uVar28 = (ulong)pbVar16[2];
532: pbVar17 = pbVar16 + 3;
533: pbVar16 = pbVar16 + 2;
534: }
535: else {
536: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
537: uVar27 = uVar21 << 8;
538: uVar28 = (ulong)*pbVar16;
539: }
540: }
541: else {
542: pbVar15 = pbVar16 + 2;
543: pbVar16 = pbVar17;
544: pbVar17 = pbVar15;
545: }
546: bVar9 = pbVar16[1];
547: uVar21 = uVar28 | uVar27 << 8;
548: if ((char)uVar28 == -1) {
549: if (bVar9 == 0) {
550: bVar9 = pbVar16[2];
551: pbVar15 = pbVar16 + 3;
552: pbVar16 = pbVar16 + 2;
553: }
554: else {
555: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
556: uVar21 = uVar27 << 8;
557: bVar9 = *pbVar16;
558: pbVar15 = pbVar17;
559: }
560: }
561: else {
562: pbVar15 = pbVar17 + 1;
563: pbVar16 = pbVar17;
564: }
565: bVar11 = pbVar16[1];
566: uVar28 = (ulong)bVar11;
567: uVar27 = (ulong)bVar9 | uVar21 << 8;
568: if (bVar9 == 0xff) {
569: if (bVar11 == 0) {
570: uVar28 = (ulong)pbVar16[2];
571: pbVar17 = pbVar16 + 3;
572: pbVar16 = pbVar16 + 2;
573: }
574: else {
575: *(uint *)(param_1 + 0x21c) = (uint)bVar11;
576: uVar27 = uVar21 << 8;
577: uVar28 = (ulong)*pbVar16;
578: pbVar17 = pbVar15;
579: }
580: }
581: else {
582: pbVar17 = pbVar15 + 1;
583: pbVar16 = pbVar15;
584: }
585: bVar9 = pbVar16[1];
586: uVar22 = (ulong)bVar9;
587: uVar21 = uVar28 | uVar27 << 8;
588: pbVar15 = pbVar17;
589: pbVar18 = pbVar17 + 1;
590: if ((char)uVar28 == -1) {
591: if (bVar9 == 0) {
592: uVar22 = (ulong)pbVar16[2];
593: pbVar15 = pbVar16 + 2;
594: pbVar18 = pbVar16 + 3;
595: }
596: else {
597: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
598: uVar21 = uVar27 << 8;
599: uVar22 = (ulong)*pbVar16;
600: pbVar15 = pbVar16;
601: pbVar18 = pbVar17;
602: }
603: }
604: bVar9 = pbVar15[1];
605: uVar28 = (ulong)bVar9;
606: uVar27 = uVar22 | uVar21 << 8;
607: if ((char)uVar22 == -1) {
608: if (bVar9 == 0) {
609: uVar28 = (ulong)pbVar15[2];
610: pbVar16 = pbVar15 + 3;
611: pbVar15 = pbVar15 + 2;
612: }
613: else {
614: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
615: uVar27 = uVar21 << 8;
616: uVar28 = (ulong)*pbVar15;
617: pbVar16 = pbVar18;
618: }
619: }
620: else {
621: pbVar16 = pbVar18 + 1;
622: pbVar15 = pbVar18;
623: }
624: iVar19 = iVar19 + 0x30;
625: uVar21 = uVar28 | uVar27 << 8;
626: if (((char)uVar28 == -1) && (pbVar16 = pbVar15 + 2, pbVar15[1] != 0)) {
627: *(uint *)(param_1 + 0x21c) = (uint)pbVar15[1];
628: uVar21 = uVar27 << 8;
629: pbVar16 = pbVar15;
630: }
631: }
632: uVar20 = *(uint *)(lVar4 + 0x128 + (uVar21 >> ((char)iVar19 - 8U & 0x3f) & 0xff) * 4);
633: uVar6 = uVar20 & 0xff;
634: iVar26 = (int)uVar20 >> 8;
635: iVar19 = iVar19 - iVar26;
636: if (8 < iVar26) {
637: lVar14 = (long)iVar26;
638: uVar20 = (1 << ((byte)(uVar20 >> 8) & 0x1f)) - 1U &
639: (uint)(uVar21 >> ((byte)iVar19 & 0x3f));
640: if (*(long *)(lVar4 + lVar14 * 8) < (long)(int)uVar20) {
641: do {
642: iVar19 = iVar19 + -1;
643: iVar26 = iVar26 + 1;
644: uVar20 = (uint)(uVar21 >> ((byte)iVar19 & 0x3f)) & 1 | uVar20 * 2;
645: lVar14 = (long)iVar26;
646: } while (*(long *)(lVar4 + lVar14 * 8) < (long)(int)uVar20);
647: }
648: uVar6 = (uint)*(byte *)(*(long *)(lVar4 + 0x120) + 0x11 +
649: (ulong)(uVar20 + *(int *)(lVar4 + 0x90 + lVar14 * 8) & 0xff));
650: }
651: uVar20 = uVar6 & 0xf;
652: if (uVar20 == 0) {
653: if ((int)uVar6 >> 4 != 0xf) break;
654: iVar25 = iVar25 + 0xf;
655: }
656: else {
657: iVar25 = iVar25 + ((int)uVar6 >> 4);
658: if (iVar19 < 0x11) {
659: pbVar17 = pbVar16 + 1;
660: bVar9 = pbVar16[1];
661: uVar28 = (ulong)bVar9;
662: uVar27 = (ulong)*pbVar16 | uVar21 << 8;
663: if (*pbVar16 == 0xff) {
664: if (bVar9 == 0) {
665: uVar28 = (ulong)pbVar16[2];
666: pbVar17 = pbVar16 + 3;
667: pbVar16 = pbVar16 + 2;
668: }
669: else {
670: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
671: uVar27 = uVar21 << 8;
672: uVar28 = (ulong)*pbVar16;
673: }
674: }
675: else {
676: pbVar15 = pbVar16 + 2;
677: pbVar16 = pbVar17;
678: pbVar17 = pbVar15;
679: }
680: bVar9 = pbVar16[1];
681: uVar22 = (ulong)bVar9;
682: uVar21 = uVar28 | uVar27 << 8;
683: if ((char)uVar28 == -1) {
684: if (bVar9 == 0) {
685: uVar22 = (ulong)pbVar16[2];
686: pbVar15 = pbVar16 + 3;
687: pbVar16 = pbVar16 + 2;
688: }
689: else {
690: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
691: uVar21 = uVar27 << 8;
692: uVar22 = (ulong)*pbVar16;
693: pbVar15 = pbVar17;
694: }
695: }
696: else {
697: pbVar15 = pbVar17 + 1;
698: pbVar16 = pbVar17;
699: }
700: bVar9 = pbVar16[1];
701: uVar28 = (ulong)bVar9;
702: uVar27 = uVar22 | uVar21 << 8;
703: pbVar17 = pbVar15 + 1;
704: if ((char)uVar22 == -1) {
705: if (bVar9 == 0) {
706: uVar28 = (ulong)pbVar16[2];
707: pbVar17 = pbVar16 + 3;
708: pbVar15 = pbVar16 + 2;
709: }
710: else {
711: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
712: uVar27 = uVar21 << 8;
713: uVar28 = (ulong)*pbVar16;
714: pbVar17 = pbVar15;
715: pbVar15 = pbVar16;
716: }
717: }
718: bVar9 = pbVar15[1];
719: uVar22 = (ulong)bVar9;
720: uVar21 = uVar28 | uVar27 << 8;
721: pbVar18 = pbVar17;
722: pbVar23 = pbVar17 + 1;
723: if ((char)uVar28 == -1) {
724: if (bVar9 == 0) {
725: uVar22 = (ulong)pbVar15[2];
726: pbVar18 = pbVar15 + 2;
727: pbVar23 = pbVar15 + 3;
728: }
729: else {
730: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
731: uVar21 = uVar27 << 8;
732: uVar22 = (ulong)*pbVar15;
733: pbVar18 = pbVar15;
734: pbVar23 = pbVar17;
735: }
736: }
737: bVar9 = pbVar18[1];
738: uVar28 = (ulong)bVar9;
739: uVar27 = uVar22 | uVar21 << 8;
740: pbVar16 = pbVar23 + 1;
741: if ((char)uVar22 == -1) {
742: if (bVar9 == 0) {
743: uVar28 = (ulong)pbVar18[2];
744: pbVar16 = pbVar18 + 3;
745: pbVar23 = pbVar18 + 2;
746: }
747: else {
748: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
749: uVar27 = uVar21 << 8;
750: uVar28 = (ulong)*pbVar18;
751: pbVar16 = pbVar23;
752: pbVar23 = pbVar18;
753: }
754: }
755: iVar19 = iVar19 + 0x30;
756: uVar21 = uVar28 | uVar27 << 8;
757: if (((char)uVar28 == -1) && (pbVar16 = pbVar23 + 2, pbVar23[1] != 0)) {
758: *(uint *)(param_1 + 0x21c) = (uint)pbVar23[1];
759: uVar21 = uVar27 << 8;
760: pbVar16 = pbVar23;
761: }
762: }
763: iVar19 = iVar19 - uVar20;
764: sVar10 = (sbyte)uVar20;
765: uVar20 = (1 << sVar10) - 1U & (uint)(uVar21 >> ((byte)iVar19 & 0x3f));
766: puVar29[*(int *)(&DAT_0018b460 + (long)iVar25 * 4)] =
767: (short)uVar20 +
768: ((ushort)((int)(uVar20 - (1 << (sVar10 - 1U & 0x1f))) >> 0x1f) &
769: (short)(-1 << sVar10) + 1U);
770: }
771: iVar25 = iVar25 + 1;
772: } while (iVar25 < 0x40);
773: }
774: else {
775: lVar14 = (long)*(int *)(param_1 + 0x1e4 + lVar30 * 4);
776: iVar25 = uVar20 + *(int *)((long)apbStack120 + lVar14 * 4 + 0x10);
777: *(int *)((long)apbStack120 + lVar14 * 4 + 0x10) = iVar25;
778: if ((puVar29 != (undefined2 *)0x0) &&
779: (iVar26 = *(int *)(lVar8 + 0x148), *puVar29 = (short)iVar25, iVar26 != 0))
780: goto LAB_0012662b;
781: LAB_00126990:
782: iVar25 = 1;
783: do {
784: if (iVar19 < 0x11) {
785: pbVar17 = pbVar16 + 1;
786: bVar9 = pbVar16[1];
787: uVar28 = (ulong)bVar9;
788: uVar27 = (ulong)*pbVar16 | uVar21 << 8;
789: if (*pbVar16 == 0xff) {
790: if (bVar9 == 0) {
791: uVar28 = (ulong)pbVar16[2];
792: pbVar17 = pbVar16 + 3;
793: pbVar16 = pbVar16 + 2;
794: }
795: else {
796: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
797: uVar27 = uVar21 << 8;
798: uVar28 = (ulong)*pbVar16;
799: }
800: }
801: else {
802: pbVar15 = pbVar16 + 2;
803: pbVar16 = pbVar17;
804: pbVar17 = pbVar15;
805: }
806: bVar9 = pbVar16[1];
807: uVar21 = uVar28 | uVar27 << 8;
808: if ((char)uVar28 == -1) {
809: if (bVar9 == 0) {
810: bVar9 = pbVar16[2];
811: pbVar15 = pbVar16 + 3;
812: pbVar16 = pbVar16 + 2;
813: }
814: else {
815: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
816: uVar21 = uVar27 << 8;
817: bVar9 = *pbVar16;
818: pbVar15 = pbVar17;
819: }
820: }
821: else {
822: pbVar15 = pbVar17 + 1;
823: pbVar16 = pbVar17;
824: }
825: bVar11 = pbVar16[1];
826: uVar28 = (ulong)bVar11;
827: uVar27 = (ulong)bVar9 | uVar21 << 8;
828: if (bVar9 == 0xff) {
829: if (bVar11 == 0) {
830: uVar28 = (ulong)pbVar16[2];
831: pbVar17 = pbVar16 + 3;
832: pbVar16 = pbVar16 + 2;
833: }
834: else {
835: *(uint *)(param_1 + 0x21c) = (uint)bVar11;
836: uVar27 = uVar21 << 8;
837: uVar28 = (ulong)*pbVar16;
838: pbVar17 = pbVar15;
839: }
840: }
841: else {
842: pbVar17 = pbVar15 + 1;
843: pbVar16 = pbVar15;
844: }
845: bVar9 = pbVar16[1];
846: uVar22 = (ulong)bVar9;
847: uVar21 = uVar28 | uVar27 << 8;
848: pbVar15 = pbVar17;
849: pbVar18 = pbVar17 + 1;
850: if ((char)uVar28 == -1) {
851: if (bVar9 == 0) {
852: uVar22 = (ulong)pbVar16[2];
853: pbVar15 = pbVar16 + 2;
854: pbVar18 = pbVar16 + 3;
855: }
856: else {
857: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
858: uVar21 = uVar27 << 8;
859: uVar22 = (ulong)*pbVar16;
860: pbVar15 = pbVar16;
861: pbVar18 = pbVar17;
862: }
863: }
864: bVar9 = pbVar15[1];
865: uVar28 = (ulong)bVar9;
866: uVar27 = uVar22 | uVar21 << 8;
867: if ((char)uVar22 == -1) {
868: if (bVar9 == 0) {
869: uVar28 = (ulong)pbVar15[2];
870: pbVar16 = pbVar15 + 3;
871: pbVar15 = pbVar15 + 2;
872: }
873: else {
874: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
875: uVar27 = uVar21 << 8;
876: uVar28 = (ulong)*pbVar15;
877: pbVar16 = pbVar18;
878: }
879: }
880: else {
881: pbVar16 = pbVar18 + 1;
882: pbVar15 = pbVar18;
883: }
884: iVar19 = iVar19 + 0x30;
885: uVar21 = uVar28 | uVar27 << 8;
886: if (((char)uVar28 == -1) && (pbVar16 = pbVar15 + 2, pbVar15[1] != 0)) {
887: *(uint *)(param_1 + 0x21c) = (uint)pbVar15[1];
888: uVar21 = uVar27 << 8;
889: pbVar16 = pbVar15;
890: }
891: }
892: uVar20 = *(uint *)(lVar4 + 0x128 + (uVar21 >> ((char)iVar19 - 8U & 0x3f) & 0xff) * 4);
893: uVar6 = uVar20 & 0xff;
894: iVar26 = (int)uVar20 >> 8;
895: iVar19 = iVar19 - iVar26;
896: if (8 < iVar26) {
897: lVar14 = (long)iVar26;
898: uVar20 = (1 << ((byte)(uVar20 >> 8) & 0x1f)) - 1U &
899: (uint)(uVar21 >> ((byte)iVar19 & 0x3f));
900: if (*(long *)(lVar4 + lVar14 * 8) < (long)(int)uVar20) {
901: do {
902: iVar19 = iVar19 + -1;
903: iVar26 = iVar26 + 1;
904: uVar20 = (uint)(uVar21 >> ((byte)iVar19 & 0x3f)) & 1 | uVar20 * 2;
905: lVar14 = (long)iVar26;
906: } while (*(long *)(lVar4 + lVar14 * 8) < (long)(int)uVar20);
907: }
908: uVar6 = (uint)*(byte *)(*(long *)(lVar4 + 0x120) + 0x11 +
909: (ulong)(uVar20 + *(int *)(lVar4 + 0x90 + lVar14 * 8) & 0xff));
910: }
911: if ((uVar6 & 0xf) == 0) {
912: if ((int)uVar6 >> 4 != 0xf) break;
913: iVar25 = iVar25 + 0xf;
914: }
915: else {
916: iVar25 = iVar25 + ((int)uVar6 >> 4);
917: if (iVar19 < 0x11) {
918: pbVar17 = pbVar16 + 1;
919: bVar9 = pbVar16[1];
920: uVar28 = (ulong)bVar9;
921: uVar27 = (ulong)*pbVar16 | uVar21 << 8;
922: if (*pbVar16 == 0xff) {
923: if (bVar9 == 0) {
924: uVar28 = (ulong)pbVar16[2];
925: pbVar17 = pbVar16 + 3;
926: pbVar16 = pbVar16 + 2;
927: }
928: else {
929: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
930: uVar27 = uVar21 << 8;
931: uVar28 = (ulong)*pbVar16;
932: }
933: }
934: else {
935: pbVar15 = pbVar16 + 2;
936: pbVar16 = pbVar17;
937: pbVar17 = pbVar15;
938: }
939: bVar9 = pbVar16[1];
940: uVar22 = (ulong)bVar9;
941: uVar21 = uVar28 | uVar27 << 8;
942: if ((char)uVar28 == -1) {
943: if (bVar9 == 0) {
944: uVar22 = (ulong)pbVar16[2];
945: pbVar15 = pbVar16 + 3;
946: pbVar16 = pbVar16 + 2;
947: }
948: else {
949: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
950: uVar21 = uVar27 << 8;
951: uVar22 = (ulong)*pbVar16;
952: pbVar15 = pbVar17;
953: }
954: }
955: else {
956: pbVar15 = pbVar17 + 1;
957: pbVar16 = pbVar17;
958: }
959: bVar9 = pbVar16[1];
960: uVar28 = (ulong)bVar9;
961: uVar27 = uVar22 | uVar21 << 8;
962: if ((char)uVar22 == -1) {
963: if (bVar9 == 0) {
964: uVar28 = (ulong)pbVar16[2];
965: pbVar17 = pbVar16 + 3;
966: pbVar16 = pbVar16 + 2;
967: }
968: else {
969: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
970: uVar27 = uVar21 << 8;
971: uVar28 = (ulong)*pbVar16;
972: pbVar17 = pbVar15;
973: }
974: }
975: else {
976: pbVar17 = pbVar15 + 1;
977: pbVar16 = pbVar15;
978: }
979: bVar9 = pbVar16[1];
980: uVar22 = (ulong)bVar9;
981: uVar21 = uVar28 | uVar27 << 8;
982: pbVar15 = pbVar17;
983: pbVar18 = pbVar17 + 1;
984: if ((char)uVar28 == -1) {
985: if (bVar9 == 0) {
986: uVar22 = (ulong)pbVar16[2];
987: pbVar15 = pbVar16 + 2;
988: pbVar18 = pbVar16 + 3;
989: }
990: else {
991: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
992: uVar21 = uVar27 << 8;
993: uVar22 = (ulong)*pbVar16;
994: pbVar15 = pbVar16;
995: pbVar18 = pbVar17;
996: }
997: }
998: bVar9 = pbVar15[1];
999: uVar28 = (ulong)bVar9;
1000: uVar27 = uVar22 | uVar21 << 8;
1001: pbVar16 = pbVar18 + 1;
1002: if ((char)uVar22 == -1) {
1003: if (bVar9 == 0) {
1004: uVar28 = (ulong)pbVar15[2];
1005: pbVar16 = pbVar15 + 3;
1006: pbVar18 = pbVar15 + 2;
1007: }
1008: else {
1009: *(uint *)(param_1 + 0x21c) = (uint)bVar9;
1010: uVar27 = uVar21 << 8;
1011: uVar28 = (ulong)*pbVar15;
1012: pbVar16 = pbVar18;
1013: pbVar18 = pbVar15;
1014: }
1015: }
1016: iVar19 = iVar19 + 0x30;
1017: uVar21 = uVar28 | uVar27 << 8;
1018: if (((char)uVar28 == -1) && (pbVar16 = pbVar18 + 2, pbVar18[1] != 0)) {
1019: *(uint *)(param_1 + 0x21c) = (uint)pbVar18[1];
1020: uVar21 = uVar27 << 8;
1021: pbVar16 = pbVar18;
1022: }
1023: }
1024: iVar19 = iVar19 - (uVar6 & 0xf);
1025: }
1026: iVar25 = iVar25 + 1;
1027: } while (iVar25 < 0x40);
1028: }
1029: iVar25 = (int)lVar30;
1030: lVar8 = lVar8 + 4;
1031: lVar30 = lVar30 + 1;
1032: lStack184 = lStack184 + 8;
1033: } while (iVar25 + 1 < *(int *)(param_1 + 0x1e0));
1034: if (*(int *)(param_1 + 0x21c) != 0) {
1035: *(undefined4 *)(param_1 + 0x21c) = 0;
1036: pbVar7 = ppbVar12[1];
1037: goto LAB_00126058;
1038: }
1039: }
1040: *ppbVar12 = pbVar16;
1041: ppbVar12[1] = pbVar3 + -(long)pbVar16 + (long)pbVar7;
1042: *(int *)(lStack160 + 0x20) = iVar19;
1043: *(ulong *)(lStack160 + 0x18) = uVar21;
1044: *(byte **)(lStack160 + 0x28) = pbStack104;
1045: *(byte **)(lStack160 + 0x30) = pbStack96;
1046: }
1047: LAB_001262dd:
1048: *(int *)(lVar2 + 0x38) = *(int *)(lVar2 + 0x38) + -1;
1049: return 1;
1050: }
1051: 
