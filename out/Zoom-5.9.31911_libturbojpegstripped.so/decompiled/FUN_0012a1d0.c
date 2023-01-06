1: 
2: undefined8 FUN_0012a1d0(code **param_1)
3: 
4: {
5: long lVar1;
6: ushort uVar2;
7: uint uVar3;
8: undefined4 uVar4;
9: byte **ppbVar5;
10: code **ppcVar6;
11: uint *puVar7;
12: code *pcVar8;
13: int iVar9;
14: uint uVar10;
15: code *pcVar11;
16: ushort *puVar12;
17: byte *pbVar13;
18: undefined8 uVar14;
19: ulong uVar15;
20: long lVar16;
21: byte bVar17;
22: int iVar18;
23: uint *puVar19;
24: int *piVar20;
25: byte bVar21;
26: byte *pbVar22;
27: uint uVar23;
28: byte *pbVar24;
29: byte *pbStack80;
30: 
31: uVar10 = *(uint *)((long)param_1 + 0x21c);
32: if (uVar10 != 0) goto LAB_0012a25a;
33: if (*(int *)(param_1[0x49] + 0x18) != 0) goto LAB_0012a3a7;
34: LAB_0012a200:
35: ppbVar5 = (byte **)param_1[5];
36: pbVar22 = ppbVar5[1];
37: pbVar13 = *ppbVar5;
38: if (pbVar22 == (byte *)0x0) {
39: iVar9 = (*(code *)ppbVar5[3])();
40: if (iVar9 == 0) {
41: return 0;
42: }
43: pbVar22 = ppbVar5[1];
44: pbVar13 = *ppbVar5;
45: bVar21 = *pbVar13;
46: }
47: else {
48: bVar21 = *pbVar13;
49: }
50: pbVar22 = pbVar22 + -1;
51: if (pbVar22 == (byte *)0x0) {
52: iVar9 = (*(code *)ppbVar5[3])();
53: if (iVar9 == 0) {
54: return 0;
55: }
56: pbVar13 = *ppbVar5;
57: pbVar22 = ppbVar5[1];
58: }
59: else {
60: pbVar13 = pbVar13 + 1;
61: }
62: bVar17 = *pbVar13;
63: if ((bVar17 != 0xd8) || (bVar21 != 0xff)) {
64: pcVar11 = *param_1;
65: *(uint *)(pcVar11 + 0x2c) = (uint)bVar21;
66: *(undefined4 *)(pcVar11 + 0x28) = 0x35;
67: *(uint *)(*param_1 + 0x30) = (uint)bVar17;
68: (**(code **)*param_1)();
69: }
70: uVar10 = (uint)bVar17;
71: *(uint *)((long)param_1 + 0x21c) = uVar10;
72: *ppbVar5 = pbVar13 + 1;
73: ppbVar5[1] = pbVar22 + -1;
74: LAB_0012a25a:
75: do {
76: if ((int)uVar10 < 0xd0) {
77: if ((int)uVar10 < 0xcd) {
78: if (uVar10 == 0xc4) {
79: iVar9 = FUN_00129cc0();
80: goto joined_r0x0012a382;
81: }
82: if ((int)uVar10 < 0xc5) {
83: if ((int)uVar10 < 0xc2) {
84: if (0xbf < (int)uVar10) {
85: uVar14 = 0;
86: goto LAB_0012a77a;
87: }
88: if (uVar10 == 1) goto LAB_0012a6eb;
89: }
90: else {
91: uVar14 = 0;
92: if (uVar10 == 0xc2) goto LAB_0012a373;
93: if (uVar10 == 0xc3) goto LAB_0012a724;
94: }
95: goto LAB_0012a798;
96: }
97: if (uVar10 == 0xc9) {
98: uVar14 = 1;
99: LAB_0012a77a:
100: iVar9 = FUN_001293b0(param_1,0,uVar14);
101: goto joined_r0x0012a786;
102: }
103: if (((int)uVar10 < 0xc9) || (uVar10 == 0xcb)) goto LAB_0012a724;
104: if (0xcb < (int)uVar10) {
105: ppbVar5 = (byte **)param_1[5];
106: pbVar13 = ppbVar5[1];
107: pbVar22 = *ppbVar5;
108: if (pbVar13 == (byte *)0x0) {
109: iVar9 = (*(code *)ppbVar5[3])();
110: if (iVar9 == 0) {
111: return 0;
112: }
113: pbVar22 = *ppbVar5;
114: pbVar13 = ppbVar5[1];
115: }
116: bVar21 = *pbVar22;
117: pbVar13 = pbVar13 + -1;
118: if (pbVar13 == (byte *)0x0) {
119: iVar9 = (*(code *)ppbVar5[3])();
120: if (iVar9 == 0) {
121: return 0;
122: }
123: pbVar22 = *ppbVar5;
124: pbVar13 = ppbVar5[1];
125: }
126: else {
127: pbVar22 = pbVar22 + 1;
128: }
129: pbVar13 = pbVar13 + -1;
130: pbVar24 = pbVar22 + 1;
131: lVar16 = (ulong)bVar21 * 0x100 + -2 + (ulong)*pbVar22;
132: while (0 < lVar16) {
133: while( true ) {
134: if (pbVar13 == (byte *)0x0) {
135: iVar9 = (*(code *)ppbVar5[3])(param_1);
136: if (iVar9 == 0) {
137: return 0;
138: }
139: pbVar24 = *ppbVar5;
140: pbVar13 = ppbVar5[1];
141: }
142: bVar21 = *pbVar24;
143: pbVar13 = pbVar13 + -1;
144: if (pbVar13 == (byte *)0x0) {
145: iVar9 = (*(code *)ppbVar5[3])(param_1);
146: if (iVar9 == 0) {
147: return 0;
148: }
149: pbVar22 = *ppbVar5;
150: pbVar13 = ppbVar5[1];
151: }
152: else {
153: pbVar22 = pbVar24 + 1;
154: }
155: pcVar11 = *param_1;
156: pbVar24 = pbVar22 + 1;
157: bVar17 = *pbVar22;
158: pbVar13 = pbVar13 + -1;
159: lVar16 = lVar16 + -2;
160: *(uint *)(pcVar11 + 0x2c) = (uint)bVar21;
161: *(undefined4 *)(pcVar11 + 0x28) = 0x4f;
162: uVar10 = (uint)bVar17;
163: *(uint *)(*param_1 + 0x30) = uVar10;
164: (**(code **)(*param_1 + 8))();
165: if (0x1f < bVar21) {
166: pcVar11 = *param_1;
167: *(undefined4 *)(pcVar11 + 0x28) = 0x1c;
168: *(uint *)(pcVar11 + 0x2c) = (uint)bVar21;
169: (**(code **)*param_1)();
170: }
171: uVar23 = (uint)bVar21;
172: if (uVar23 < 0x10) break;
173: *(byte *)((long)param_1 + (long)(int)(bVar21 - 0x10) + 0x160) = bVar17;
174: if (lVar16 < 1) goto LAB_0012adfb;
175: }
176: *(byte *)((long)param_1 + (long)(int)uVar23 + 0x140) = bVar17 & 0xf;
177: bVar21 = (byte)((int)uVar10 >> 4);
178: *(byte *)((long)param_1 + (long)(int)uVar23 + 0x150) = bVar21;
179: if (bVar21 < (bVar17 & 0xf)) {
180: pcVar11 = *param_1;
181: *(uint *)(pcVar11 + 0x2c) = uVar10;
182: *(undefined4 *)(pcVar11 + 0x28) = 0x1d;
183: (**(code **)*param_1)();
184: }
185: }
186: LAB_0012adfb:
187: if (lVar16 != 0) {
188: ppcVar6 = (code **)*param_1;
189: *(undefined4 *)(ppcVar6 + 5) = 0xb;
190: (**ppcVar6)();
191: }
192: *ppbVar5 = pbVar24;
193: ppbVar5[1] = pbVar13;
194: goto LAB_0012a388;
195: }
196: uVar14 = 1;
197: LAB_0012a373:
198: iVar9 = FUN_001293b0(param_1,1,uVar14);
199: joined_r0x0012a382:
200: if (iVar9 == 0) {
201: return 0;
202: }
203: }
204: else {
205: LAB_0012a724:
206: pcVar11 = *param_1;
207: *(uint *)(pcVar11 + 0x2c) = uVar10;
208: ppcVar6 = (code **)*param_1;
209: *(undefined4 *)(pcVar11 + 0x28) = 0x3c;
210: (**ppcVar6)();
211: }
212: }
213: else {
214: if (uVar10 == 0xdb) {
215: ppbVar5 = (byte **)param_1[5];
216: pbVar13 = ppbVar5[1];
217: pbVar22 = *ppbVar5;
218: if (pbVar13 == (byte *)0x0) {
219: iVar9 = (*(code *)ppbVar5[3])(param_1);
220: if (iVar9 == 0) {
221: return 0;
222: }
223: pbVar22 = *ppbVar5;
224: pbVar13 = ppbVar5[1];
225: }
226: bVar21 = *pbVar22;
227: pbVar13 = pbVar13 + -1;
228: if (pbVar13 == (byte *)0x0) {
229: iVar9 = (*(code *)ppbVar5[3])(param_1);
230: if (iVar9 == 0) {
231: return 0;
232: }
233: pbVar22 = *ppbVar5;
234: pbVar13 = ppbVar5[1];
235: }
236: else {
237: pbVar22 = pbVar22 + 1;
238: }
239: pbVar13 = pbVar13 + -1;
240: pbVar24 = pbVar22 + 1;
241: lVar16 = (ulong)bVar21 * 0x100 + -2 + (ulong)*pbVar22;
242: while (0 < lVar16) {
243: if (pbVar13 == (byte *)0x0) {
244: iVar9 = (*(code *)ppbVar5[3])(param_1);
245: if (iVar9 == 0) {
246: return 0;
247: }
248: pbVar24 = *ppbVar5;
249: pbVar13 = ppbVar5[1];
250: }
251: bVar21 = *pbVar24;
252: pbVar24 = pbVar24 + 1;
253: pbVar13 = pbVar13 + -1;
254: bVar17 = bVar21 & 0xf;
255: pcVar11 = *param_1;
256: iVar9 = (int)(uint)bVar21 >> 4;
257: *(uint *)(pcVar11 + 0x2c) = (uint)bVar17;
258: *(undefined4 *)(pcVar11 + 0x28) = 0x51;
259: *(int *)(*param_1 + 0x30) = iVar9;
260: (**(code **)(*param_1 + 8))();
261: if (3 < bVar17) {
262: pcVar11 = *param_1;
263: *(uint *)(pcVar11 + 0x2c) = (uint)bVar17;
264: *(undefined4 *)(pcVar11 + 0x28) = 0x1f;
265: (**(code **)*param_1)();
266: }
267: puVar12 = (ushort *)(param_1 + bVar17)[0x19];
268: if (puVar12 == (ushort *)0x0) {
269: puVar12 = (ushort *)FUN_00116760();
270: (param_1 + bVar17)[0x19] = (code *)puVar12;
271: }
272: piVar20 = (int *)&DAT_0018b460;
273: if (iVar9 != 0) {
274: if (pbVar13 == (byte *)0x0) goto LAB_0012aa30;
275: LAB_0012a9f5:
276: uVar15 = (ulong)*pbVar24 << 8;
277: uVar10 = (uint)uVar15;
278: pbVar13 = pbVar13 + -1;
279: if (pbVar13 == (byte *)0x0) goto LAB_0012aa53;
280: do {
281: pbVar22 = pbVar24 + 1;
282: while( true ) {
283: pbVar24 = pbVar22 + 1;
284: iVar18 = *piVar20;
285: pbVar13 = pbVar13 + -1;
286: piVar20 = piVar20 + 1;
287: puVar12[iVar18] = (short)uVar15 + (ushort)*pbVar22;
288: if (piVar20 == (int *)&UNK_0018b560) goto LAB_0012a939;
289: if (pbVar13 != (byte *)0x0) goto LAB_0012a9f5;
290: LAB_0012aa30:
291: iVar18 = (*(code *)ppbVar5[3])();
292: if (iVar18 == 0) {
293: return 0;
294: }
295: pbVar24 = *ppbVar5;
296: uVar15 = (ulong)*pbVar24 << 8;
297: uVar10 = (uint)uVar15;
298: pbVar13 = ppbVar5[1] + -1;
299: if (pbVar13 != (byte *)0x0) break;
300: LAB_0012aa53:
301: iVar18 = (*(code *)ppbVar5[3])();
302: if (iVar18 == 0) {
303: return 0;
304: }
305: pbVar22 = *ppbVar5;
306: pbVar13 = ppbVar5[1];
307: uVar15 = (ulong)uVar10;
308: }
309: } while( true );
310: }
311: do {
312: if (pbVar13 == (byte *)0x0) {
313: iVar18 = (*(code *)ppbVar5[3])();
314: if (iVar18 == 0) {
315: return 0;
316: }
317: pbVar24 = *ppbVar5;
318: pbVar13 = ppbVar5[1];
319: }
320: bVar21 = *pbVar24;
321: iVar18 = *piVar20;
322: pbVar13 = pbVar13 + -1;
323: pbVar24 = pbVar24 + 1;
324: piVar20 = piVar20 + 1;
325: puVar12[iVar18] = (ushort)bVar21;
326: } while (piVar20 != (int *)&UNK_0018b560);
327: LAB_0012a939:
328: pcVar11 = *param_1;
329: iVar18 = 8;
330: if (1 < *(int *)(pcVar11 + 0x7c)) {
331: while( true ) {
332: *(uint *)(pcVar11 + 0x2c) = (uint)*puVar12;
333: *(uint *)(pcVar11 + 0x30) = (uint)puVar12[1];
334: *(uint *)(pcVar11 + 0x34) = (uint)puVar12[2];
335: *(uint *)(pcVar11 + 0x38) = (uint)puVar12[3];
336: *(uint *)(pcVar11 + 0x3c) = (uint)puVar12[4];
337: *(uint *)(pcVar11 + 0x40) = (uint)puVar12[5];
338: *(uint *)(pcVar11 + 0x44) = (uint)puVar12[6];
339: uVar2 = puVar12[7];
340: *(undefined4 *)(pcVar11 + 0x28) = 0x5d;
341: *(uint *)(pcVar11 + 0x48) = (uint)uVar2;
342: (**(code **)(pcVar11 + 8))();
343: iVar18 = iVar18 + -1;
344: if (iVar18 == 0) break;
345: pcVar11 = *param_1;
346: puVar12 = puVar12 + 8;
347: }
348: }
349: lVar1 = lVar16 + -0x81;
350: lVar16 = lVar16 + -0x41;
351: if (iVar9 != 0) {
352: lVar16 = lVar1;
353: }
354: }
355: if (lVar16 != 0) {
356: ppcVar6 = (code **)*param_1;
357: *(undefined4 *)(ppcVar6 + 5) = 0xb;
358: (**ppcVar6)();
359: }
360: *ppbVar5 = pbVar24;
361: ppbVar5[1] = pbVar13;
362: }
363: else {
364: if ((int)uVar10 < 0xdc) {
365: if (uVar10 == 0xd8) {
366: pcVar11 = *param_1;
367: *(undefined4 *)(pcVar11 + 0x28) = 0x66;
368: (**(code **)(pcVar11 + 8))();
369: pcVar11 = param_1[0x49];
370: if (*(int *)(pcVar11 + 0x18) != 0) {
371: ppcVar6 = (code **)*param_1;
372: *(undefined4 *)(ppcVar6 + 5) = 0x3d;
373: (**ppcVar6)();
374: pcVar11 = param_1[0x49];
375: }
376: *(undefined *)(param_1 + 0x28) = 0;
377: *(undefined *)(param_1 + 0x2a) = 1;
378: *(undefined *)(param_1 + 0x2c) = 5;
379: *(undefined *)((long)param_1 + 0x141) = 0;
380: *(undefined *)((long)param_1 + 0x151) = 1;
381: *(undefined *)((long)param_1 + 0x161) = 5;
382: *(undefined *)((long)param_1 + 0x142) = 0;
383: *(undefined *)((long)param_1 + 0x152) = 1;
384: *(undefined *)((long)param_1 + 0x162) = 5;
385: *(undefined *)((long)param_1 + 0x143) = 0;
386: *(undefined *)((long)param_1 + 0x153) = 1;
387: *(undefined *)((long)param_1 + 0x163) = 5;
388: *(undefined *)((long)param_1 + 0x144) = 0;
389: *(undefined *)((long)param_1 + 0x154) = 1;
390: *(undefined *)((long)param_1 + 0x164) = 5;
391: *(undefined *)((long)param_1 + 0x145) = 0;
392: *(undefined *)((long)param_1 + 0x155) = 1;
393: *(undefined *)((long)param_1 + 0x165) = 5;
394: *(undefined *)((long)param_1 + 0x146) = 0;
395: *(undefined *)((long)param_1 + 0x156) = 1;
396: *(undefined *)((long)param_1 + 0x166) = 5;
397: *(undefined *)((long)param_1 + 0x147) = 0;
398: *(undefined *)((long)param_1 + 0x157) = 1;
399: *(undefined *)((long)param_1 + 0x167) = 5;
400: *(undefined *)(param_1 + 0x29) = 0;
401: *(undefined *)(param_1 + 0x2b) = 1;
402: *(undefined *)(param_1 + 0x2d) = 5;
403: *(undefined *)((long)param_1 + 0x149) = 0;
404: *(undefined *)((long)param_1 + 0x159) = 1;
405: *(undefined *)((long)param_1 + 0x169) = 5;
406: *(undefined *)((long)param_1 + 0x14a) = 0;
407: *(undefined *)((long)param_1 + 0x15a) = 1;
408: *(undefined *)((long)param_1 + 0x16a) = 5;
409: *(undefined *)((long)param_1 + 0x14b) = 0;
410: *(undefined *)((long)param_1 + 0x15b) = 1;
411: *(undefined *)((long)param_1 + 0x16b) = 5;
412: *(undefined *)((long)param_1 + 0x14c) = 0;
413: *(undefined *)((long)param_1 + 0x15c) = 1;
414: *(undefined *)((long)param_1 + 0x16c) = 5;
415: *(undefined *)((long)param_1 + 0x14d) = 0;
416: *(undefined *)((long)param_1 + 0x15d) = 1;
417: *(undefined *)((long)param_1 + 0x16d) = 5;
418: *(undefined *)((long)param_1 + 0x14e) = 0;
419: *(undefined *)((long)param_1 + 0x15e) = 1;
420: *(undefined *)((long)param_1 + 0x16e) = 5;
421: *(undefined *)((long)param_1 + 0x14f) = 0;
422: *(undefined *)((long)param_1 + 0x15f) = 1;
423: *(undefined *)((long)param_1 + 0x16f) = 5;
424: *(undefined4 *)(param_1 + 0x2e) = 0;
425: *(undefined4 *)((long)param_1 + 0x3c) = 0;
426: *(undefined4 *)(param_1 + 0x31) = 0;
427: *(undefined4 *)((long)param_1 + 0x174) = 0;
428: *(undefined *)(param_1 + 0x2f) = 1;
429: *(undefined *)((long)param_1 + 0x179) = 1;
430: *(undefined *)((long)param_1 + 0x17a) = 0;
431: *(undefined2 *)((long)param_1 + 0x17c) = 1;
432: *(undefined2 *)((long)param_1 + 0x17e) = 1;
433: *(undefined4 *)(param_1 + 0x30) = 0;
434: *(undefined *)((long)param_1 + 0x184) = 0;
435: *(undefined4 *)(pcVar11 + 0x18) = 1;
436: }
437: else {
438: if (0xd7 < (int)uVar10) {
439: if (uVar10 == 0xd9) {
440: pcVar11 = *param_1;
441: *(undefined4 *)(pcVar11 + 0x28) = 0x55;
442: (**(code **)(pcVar11 + 8))(param_1,1);
443: *(undefined4 *)((long)param_1 + 0x21c) = 0;
444: return 2;
445: }
446: if (uVar10 != 0xda) goto LAB_0012a798;
447: ppbVar5 = (byte **)param_1[5];
448: pbVar13 = *ppbVar5;
449: pbStack80 = ppbVar5[1];
450: if (*(int *)(param_1[0x49] + 0x1c) == 0) {
451: ppcVar6 = (code **)*param_1;
452: *(undefined4 *)(ppcVar6 + 5) = 0x3e;
453: (**ppcVar6)(param_1);
454: }
455: if (pbStack80 == (byte *)0x0) {
456: iVar9 = (*(code *)ppbVar5[3])(param_1);
457: if (iVar9 == 0) {
458: return 0;
459: }
460: pbVar13 = *ppbVar5;
461: pbStack80 = ppbVar5[1];
462: }
463: bVar21 = *pbVar13;
464: pbStack80 = pbStack80 + -1;
465: if (pbStack80 == (byte *)0x0) {
466: iVar9 = (*(code *)ppbVar5[3])(param_1);
467: if (iVar9 == 0) {
468: return 0;
469: }
470: pbVar13 = *ppbVar5;
471: pbStack80 = ppbVar5[1];
472: }
473: else {
474: pbVar13 = pbVar13 + 1;
475: }
476: bVar17 = *pbVar13;
477: pbStack80 = pbStack80 + -1;
478: if (pbStack80 == (byte *)0x0) {
479: iVar9 = (*(code *)ppbVar5[3])(param_1);
480: if (iVar9 == 0) {
481: return 0;
482: }
483: pbVar13 = *ppbVar5;
484: pbStack80 = ppbVar5[1];
485: }
486: else {
487: pbVar13 = pbVar13 + 1;
488: }
489: pbStack80 = pbStack80 + -1;
490: pbVar22 = pbVar13 + 1;
491: uVar10 = (uint)*pbVar13;
492: pcVar11 = *param_1;
493: *(undefined4 *)(pcVar11 + 0x28) = 0x67;
494: *(uint *)(pcVar11 + 0x2c) = uVar10;
495: (**(code **)(*param_1 + 8))(param_1);
496: if (((ulong)bVar17 + (ulong)bVar21 * 0x100 != (long)(int)(uVar10 * 2 + 6)) ||
497: (3 < uVar10 - 1)) {
498: ppcVar6 = (code **)*param_1;
499: *(undefined4 *)(ppcVar6 + 5) = 0xb;
500: (**ppcVar6)(param_1);
501: }
502: param_1[0x37] = (code *)0x0;
503: param_1[0x38] = (code *)0x0;
504: param_1[0x39] = (code *)0x0;
505: param_1[0x3a] = (code *)0x0;
506: *(uint *)(param_1 + 0x36) = uVar10;
507: if (uVar10 == 0) goto LAB_0012b010;
508: lVar16 = 0;
509: break;
510: }
511: LAB_0012a6eb:
512: pcVar11 = *param_1;
513: *(uint *)(pcVar11 + 0x2c) = uVar10;
514: pcVar8 = *param_1;
515: *(undefined4 *)(pcVar11 + 0x28) = 0x5c;
516: (**(code **)(pcVar8 + 8))();
517: }
518: }
519: else {
520: if ((int)uVar10 < 0xf0) {
521: if (0xdf < (int)uVar10) {
522: iVar9 = (**(code **)(param_1[0x49] + (long)(int)(uVar10 - 0xe0) * 8 + 0x30))();
523: joined_r0x0012a786:
524: if (iVar9 == 0) {
525: return 0;
526: }
527: goto LAB_0012a388;
528: }
529: if (uVar10 == 0xdc) {
530: iVar9 = FUN_00129a10();
531: goto joined_r0x0012a382;
532: }
533: if (uVar10 == 0xdd) {
534: ppbVar5 = (byte **)param_1[5];
535: pbVar13 = ppbVar5[1];
536: pbVar22 = *ppbVar5;
537: if (pbVar13 == (byte *)0x0) {
538: iVar9 = (*(code *)ppbVar5[3])(param_1);
539: if (iVar9 == 0) {
540: return 0;
541: }
542: pbVar22 = *ppbVar5;
543: pbVar13 = ppbVar5[1];
544: }
545: bVar21 = *pbVar22;
546: pbVar13 = pbVar13 + -1;
547: if (pbVar13 == (byte *)0x0) {
548: iVar9 = (*(code *)ppbVar5[3])(param_1);
549: if (iVar9 == 0) {
550: return 0;
551: }
552: pbVar22 = *ppbVar5;
553: pbVar13 = ppbVar5[1];
554: }
555: else {
556: pbVar22 = pbVar22 + 1;
557: }
558: pbVar13 = pbVar13 + -1;
559: if ((ulong)*pbVar22 + (ulong)bVar21 * 0x100 != 4) {
560: ppcVar6 = (code **)*param_1;
561: *(undefined4 *)(ppcVar6 + 5) = 0xb;
562: (**ppcVar6)(param_1);
563: }
564: pbVar22 = pbVar22 + 1;
565: if (pbVar13 == (byte *)0x0) {
566: iVar9 = (*(code *)ppbVar5[3])(param_1);
567: if (iVar9 == 0) {
568: return 0;
569: }
570: pbVar22 = *ppbVar5;
571: pbVar13 = ppbVar5[1];
572: }
573: bVar21 = *pbVar22;
574: pbVar13 = pbVar13 + -1;
575: if (pbVar13 == (byte *)0x0) {
576: iVar9 = (*(code *)ppbVar5[3])(param_1);
577: if (iVar9 == 0) {
578: return 0;
579: }
580: pbVar22 = *ppbVar5;
581: pbVar13 = ppbVar5[1];
582: }
583: else {
584: pbVar22 = pbVar22 + 1;
585: }
586: iVar9 = (uint)bVar21 * 0x100 + (uint)*pbVar22;
587: pcVar11 = *param_1;
588: *(undefined4 *)(pcVar11 + 0x28) = 0x52;
589: *(int *)(pcVar11 + 0x2c) = iVar9;
590: (**(code **)(*param_1 + 8))();
591: *(int *)(param_1 + 0x2e) = iVar9;
592: ppbVar5[1] = pbVar13 + -1;
593: *ppbVar5 = pbVar22 + 1;
594: goto LAB_0012a388;
595: }
596: }
597: else {
598: if (uVar10 == 0xfe) {
599: iVar9 = (**(code **)(param_1[0x49] + 0x28))();
600: goto joined_r0x0012a382;
601: }
602: }
603: LAB_0012a798:
604: pcVar11 = *param_1;
605: *(uint *)(pcVar11 + 0x2c) = uVar10;
606: ppcVar6 = (code **)*param_1;
607: *(undefined4 *)(pcVar11 + 0x28) = 0x44;
608: (**ppcVar6)();
609: }
610: }
611: }
612: LAB_0012a388:
613: *(undefined4 *)((long)param_1 + 0x21c) = 0;
614: if (*(int *)(param_1[0x49] + 0x18) == 0) goto LAB_0012a200;
615: LAB_0012a3a7:
616: iVar9 = FUN_00129b00();
617: if (iVar9 == 0) {
618: return 0;
619: }
620: uVar10 = *(uint *)((long)param_1 + 0x21c);
621: } while( true );
622: LAB_0012a66e:
623: if (pbStack80 == (byte *)0x0) {
624: iVar9 = (*(code *)ppbVar5[3])(param_1);
625: if (iVar9 == 0) {
626: return 0;
627: }
628: pbVar22 = *ppbVar5;
629: uVar23 = (uint)*pbVar22;
630: pbStack80 = ppbVar5[1] + -1;
631: if (pbStack80 != (byte *)0x0) goto LAB_0012a524;
632: LAB_0012a6ae:
633: iVar9 = (*(code *)ppbVar5[3])(param_1);
634: if (iVar9 == 0) {
635: return 0;
636: }
637: pbVar22 = *ppbVar5;
638: pbStack80 = ppbVar5[1];
639: }
640: else {
641: uVar23 = (uint)*pbVar22;
642: pbStack80 = pbStack80 + -1;
643: if (pbStack80 == (byte *)0x0) goto LAB_0012a6ae;
644: LAB_0012a524:
645: pbVar22 = pbVar22 + 1;
646: }
647: bVar21 = *pbVar22;
648: iVar9 = *(int *)(param_1 + 7);
649: pbStack80 = pbStack80 + -1;
650: pbVar22 = pbVar22 + 1;
651: puVar7 = (uint *)param_1[0x26];
652: puVar19 = puVar7;
653: if (iVar9 < 1) {
654: LAB_0012a5af:
655: pcVar11 = *param_1;
656: *(undefined4 *)(pcVar11 + 0x28) = 5;
657: *(uint *)(pcVar11 + 0x2c) = uVar23;
658: (**(code **)*param_1)(param_1);
659: }
660: else {
661: if (uVar23 == *puVar7) {
662: if (param_1[0x37] == (code *)0x0) goto LAB_0012a5d1;
663: puVar19 = puVar7 + 0x18;
664: if (iVar9 != 1) goto LAB_0012a564;
665: goto LAB_0012a5af;
666: }
667: puVar19 = puVar7 + 0x18;
668: if (iVar9 == 1) goto LAB_0012a5af;
669: LAB_0012a564:
670: puVar19 = puVar7 + 0x18;
671: if ((uVar23 != *puVar19) || (param_1[0x38] != (code *)0x0)) {
672: puVar19 = puVar7 + 0x30;
673: if (iVar9 != 2) {
674: if ((uVar23 == puVar7[0x30]) && (param_1[0x39] == (code *)0x0)) goto LAB_0012a5d1;
675: puVar19 = puVar7 + 0x48;
676: if (iVar9 != 3) {
677: if ((uVar23 == puVar7[0x48]) && (param_1[0x3a] == (code *)0x0)) goto LAB_0012a5d1;
678: puVar19 = puVar7 + 0x60;
679: }
680: }
681: goto LAB_0012a5af;
682: }
683: }
684: LAB_0012a5d1:
685: param_1[lVar16 + 0x37] = (code *)puVar19;
686: puVar19[6] = bVar21 & 0xf;
687: pcVar11 = *param_1;
688: puVar19[5] = (int)(uint)bVar21 >> 4;
689: iVar9 = (int)lVar16;
690: *(uint *)(pcVar11 + 0x2c) = uVar23;
691: *(uint *)(pcVar11 + 0x30) = puVar19[5];
692: uVar3 = puVar19[6];
693: *(undefined4 *)(pcVar11 + 0x28) = 0x68;
694: *(uint *)(pcVar11 + 0x34) = uVar3;
695: (**(code **)(pcVar11 + 8))(param_1);
696: if (iVar9 != 0) {
697: if (puVar19 == (uint *)param_1[0x37]) {
698: pcVar11 = *param_1;
699: *(uint *)(pcVar11 + 0x2c) = uVar23;
700: *(undefined4 *)(pcVar11 + 0x28) = 5;
701: (**(code **)*param_1)(param_1);
702: }
703: if (iVar9 != 1) {
704: if (puVar19 == (uint *)param_1[0x38]) {
705: pcVar11 = *param_1;
706: *(uint *)(pcVar11 + 0x2c) = uVar23;
707: *(undefined4 *)(pcVar11 + 0x28) = 5;
708: (**(code **)*param_1)(param_1);
709: }
710: if (iVar9 != 2) {
711: if (puVar19 == (uint *)param_1[0x39]) {
712: pcVar11 = *param_1;
713: *(uint *)(pcVar11 + 0x2c) = uVar23;
714: *(undefined4 *)(pcVar11 + 0x28) = 5;
715: (**(code **)*param_1)(param_1);
716: }
717: if ((iVar9 == 4) && (puVar19 == (uint *)param_1[0x3a])) {
718: pcVar11 = *param_1;
719: *(undefined4 *)(pcVar11 + 0x28) = 5;
720: *(uint *)(pcVar11 + 0x2c) = uVar23;
721: (**(code **)*param_1)(param_1);
722: }
723: }
724: }
725: }
726: lVar16 = lVar16 + 1;
727: if ((int)uVar10 <= iVar9 + 1) {
728: LAB_0012b010:
729: if (pbStack80 == (byte *)0x0) {
730: iVar9 = (*(code *)ppbVar5[3])(param_1);
731: if (iVar9 == 0) {
732: return 0;
733: }
734: pbStack80 = ppbVar5[1];
735: pbVar22 = *ppbVar5;
736: }
737: pbStack80 = pbStack80 + -1;
738: *(uint *)((long)param_1 + 0x20c) = (uint)*pbVar22;
739: if (pbStack80 == (byte *)0x0) {
740: iVar9 = (*(code *)ppbVar5[3])(param_1);
741: if (iVar9 == 0) {
742: return 0;
743: }
744: pbVar22 = *ppbVar5;
745: pbStack80 = ppbVar5[1];
746: }
747: else {
748: pbVar22 = pbVar22 + 1;
749: }
750: pbStack80 = pbStack80 + -1;
751: *(uint *)(param_1 + 0x42) = (uint)*pbVar22;
752: if (pbStack80 == (byte *)0x0) {
753: iVar9 = (*(code *)ppbVar5[3])(param_1);
754: if (iVar9 == 0) {
755: return 0;
756: }
757: pbVar22 = *ppbVar5;
758: pbStack80 = ppbVar5[1];
759: }
760: else {
761: pbVar22 = pbVar22 + 1;
762: }
763: bVar21 = *pbVar22;
764: *(uint *)(param_1 + 0x43) = bVar21 & 0xf;
765: *(int *)((long)param_1 + 0x214) = (int)(uint)bVar21 >> 4;
766: pcVar11 = *param_1;
767: *(undefined4 *)(pcVar11 + 0x2c) = *(undefined4 *)((long)param_1 + 0x20c);
768: *(undefined4 *)(pcVar11 + 0x30) = *(undefined4 *)(param_1 + 0x42);
769: *(undefined4 *)(pcVar11 + 0x34) = *(undefined4 *)((long)param_1 + 0x214);
770: uVar4 = *(undefined4 *)(param_1 + 0x43);
771: *(undefined4 *)(pcVar11 + 0x28) = 0x69;
772: *(undefined4 *)(pcVar11 + 0x38) = uVar4;
773: (**(code **)(pcVar11 + 8))(param_1,1);
774: *(undefined4 *)(param_1[0x49] + 0x20) = 0;
775: *(int *)((long)param_1 + 0xac) = *(int *)((long)param_1 + 0xac) + 1;
776: *ppbVar5 = pbVar22 + 1;
777: ppbVar5[1] = pbStack80 + -1;
778: *(undefined4 *)((long)param_1 + 0x21c) = 0;
779: return 1;
780: }
781: goto LAB_0012a66e;
782: }
783: 
