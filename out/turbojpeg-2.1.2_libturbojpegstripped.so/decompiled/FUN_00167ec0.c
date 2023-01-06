1: 
2: void FUN_00167ec0(code **param_1,long param_2)
3: 
4: {
5: int *piVar1;
6: uint uVar2;
7: long *plVar3;
8: bool bVar4;
9: undefined4 uVar5;
10: size_t sVar6;
11: long lVar7;
12: undefined8 uVar8;
13: uint uVar9;
14: int iVar10;
15: int iVar11;
16: int iVar12;
17: code **ppcVar13;
18: int iVar14;
19: uint uVar15;
20: int iVar16;
21: long lVar17;
22: short sVar18;
23: long in_FS_OFFSET;
24: int iStack180;
25: int iStack176;
26: int iStack172;
27: byte bStack150;
28: byte bStack149;
29: byte bStack140;
30: byte bStack139;
31: byte bStack138;
32: byte bStack137;
33: byte bStack136;
34: byte bStack135;
35: byte bStack134;
36: byte bStack133;
37: byte bStack132;
38: byte bStack131;
39: byte bStack130;
40: byte bStack129;
41: byte bStack128;
42: byte bStack127;
43: byte bStack126;
44: byte bStack125;
45: byte bStack124;
46: byte bStack123;
47: byte bStack122;
48: byte bStack121;
49: byte bStack120;
50: byte bStack119;
51: byte bStack118;
52: byte bStack117;
53: byte bStack112;
54: byte bStack111;
55: byte bStack110;
56: byte bStack109;
57: byte bStack108;
58: byte bStack107;
59: byte bStack106;
60: byte bStack105;
61: byte bStack104;
62: byte bStack103;
63: byte bStack102;
64: byte bStack101;
65: long lStack64;
66: 
67: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
68: sVar6 = fread(&bStack150,1,0xe,*(FILE **)(param_2 + 0x18));
69: if (sVar6 != 0xe) {
70: ppcVar13 = (code **)*param_1;
71: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
72: (**ppcVar13)(param_1);
73: }
74: if ((uint)bStack149 * 0x100 + (uint)bStack150 != 0x4d42) {
75: ppcVar13 = (code **)*param_1;
76: *(undefined4 *)(ppcVar13 + 5) = 0x3f0;
77: (**ppcVar13)(param_1);
78: }
79: iVar16 = (uint)bStack140 + (uint)bStack138 * 0x10000 + (uint)bStack139 * 0x100 +
80: (uint)bStack137 * 0x1000000;
81: sVar6 = fread(&bStack136,1,4,*(FILE **)(param_2 + 0x18));
82: if (sVar6 != 4) {
83: ppcVar13 = (code **)*param_1;
84: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
85: (**ppcVar13)(param_1);
86: }
87: iVar14 = (uint)bStack133 * 0x1000000 +
88: (uint)bStack136 + (uint)bStack134 * 0x10000 + (uint)bStack135 * 0x100;
89: if ((0x34 < iVar14 - 0xcU) || (iVar16 <= iVar14 + 0xd)) {
90: ppcVar13 = (code **)*param_1;
91: *(undefined4 *)(ppcVar13 + 5) = 0x3eb;
92: (**ppcVar13)(param_1);
93: }
94: lVar7 = __fread_chk(&bStack132,0x3c,1);
95: if (iVar14 + -4 != lVar7) {
96: ppcVar13 = (code **)*param_1;
97: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
98: (**ppcVar13)();
99: }
100: ppcVar13 = (code **)*param_1;
101: if ((iVar14 == 0x28) || (iVar14 == 0x40)) {
102: uVar15 = (uint)bStack129 * 0x1000000 +
103: (uint)bStack132 + (uint)bStack130 * 0x10000 + (uint)bStack131 * 0x100;
104: iStack176 = (uint)bStack126 * 0x10000 + (uint)bStack127 * 0x100 + (uint)bStack128 +
105: (uint)bStack125 * 0x1000000;
106: sVar18 = (ushort)bStack123 * 0x100 + (ushort)bStack124;
107: iVar10 = (uint)bStack121 * 0x100 + (uint)bStack122;
108: *(int *)(param_2 + 0x50) = iVar10;
109: iVar11 = (uint)bStack109 * 0x1000000 +
110: (uint)bStack110 * 0x10000 + (uint)bStack111 * 0x100 + (uint)bStack112;
111: iVar12 = (uint)bStack105 * 0x1000000 +
112: (uint)bStack106 * 0x10000 + (uint)bStack107 * 0x100 + (uint)bStack108;
113: iStack180 = (uint)bStack101 * 0x1000000 +
114: (uint)bStack102 * 0x10000 + (uint)bStack103 * 0x100 + (uint)bStack104;
115: if ((iVar10 == 0x18) || (iVar10 == 0x20)) {
116: *(uint *)((long)ppcVar13 + 0x2c) = uVar15;
117: *(int *)(ppcVar13 + 6) = iStack176;
118: uVar5 = *(undefined4 *)(param_2 + 0x50);
119: *(undefined4 *)(ppcVar13 + 5) = 0x3f2;
120: *(undefined4 *)((long)ppcVar13 + 0x34) = uVar5;
121: (*ppcVar13[1])();
122: iStack172 = 0;
123: }
124: else {
125: if (iVar10 == 8) {
126: *(int *)(ppcVar13 + 6) = iStack176;
127: *(undefined4 *)(ppcVar13 + 5) = 0x3f3;
128: *(uint *)((long)ppcVar13 + 0x2c) = uVar15;
129: (*ppcVar13[1])();
130: iStack172 = 4;
131: }
132: else {
133: *(undefined4 *)(ppcVar13 + 5) = 0x3ea;
134: (**ppcVar13)();
135: iStack172 = 0;
136: }
137: }
138: if ((uint)bStack117 * 0x1000000 +
139: (uint)bStack118 * 0x10000 + (uint)bStack119 * 0x100 + (uint)bStack120 != 0) {
140: ppcVar13 = (code **)*param_1;
141: *(undefined4 *)(ppcVar13 + 5) = 0x3ee;
142: (**ppcVar13)();
143: }
144: if ((0 < iVar11) && (0 < iVar12)) {
145: *(undefined *)((long)param_1 + 0x126) = 2;
146: *(short *)(param_1 + 0x25) = (short)(iVar11 / 100);
147: *(short *)((long)param_1 + 0x12a) = (short)(iVar12 / 100);
148: }
149: }
150: else {
151: if (iVar14 != 0xc) {
152: *(undefined4 *)(ppcVar13 + 5) = 0x3eb;
153: (**ppcVar13)(param_1);
154: goto LAB_00168048;
155: }
156: uVar15 = (uint)bStack131 * 0x100 + (uint)bStack132;
157: iStack176 = (uint)bStack129 * 0x100 + (uint)bStack130;
158: sVar18 = (ushort)bStack127 * 0x100 + (ushort)bStack128;
159: iVar10 = (uint)bStack125 * 0x100 + (uint)bStack126;
160: *(int *)(param_2 + 0x50) = iVar10;
161: if ((iVar10 == 0x18) || (iVar10 == 0x20)) {
162: *(int *)(ppcVar13 + 6) = iStack176;
163: *(uint *)((long)ppcVar13 + 0x2c) = uVar15;
164: uVar5 = *(undefined4 *)(param_2 + 0x50);
165: *(undefined4 *)(ppcVar13 + 5) = 0x3f4;
166: *(undefined4 *)((long)ppcVar13 + 0x34) = uVar5;
167: (*ppcVar13[1])();
168: iStack172 = 0;
169: iStack180 = 0;
170: }
171: else {
172: if (iVar10 == 8) {
173: *(int *)(ppcVar13 + 6) = iStack176;
174: *(undefined4 *)(ppcVar13 + 5) = 0x3f5;
175: *(uint *)((long)ppcVar13 + 0x2c) = uVar15;
176: (*ppcVar13[1])();
177: iStack172 = 3;
178: iStack180 = 0;
179: }
180: else {
181: *(undefined4 *)(ppcVar13 + 5) = 0x3ea;
182: (**ppcVar13)();
183: iStack172 = 0;
184: iStack180 = 0;
185: }
186: }
187: }
188: if (((int)uVar15 < 1) || (iStack176 < 1)) {
189: ppcVar13 = (code **)*param_1;
190: *(undefined4 *)(ppcVar13 + 5) = 0x3ef;
191: (**ppcVar13)(param_1);
192: }
193: if (sVar18 != 1) {
194: ppcVar13 = (code **)*param_1;
195: *(undefined4 *)(ppcVar13 + 5) = 0x3ec;
196: (**ppcVar13)(param_1);
197: }
198: iVar16 = iVar16 - (iVar14 + 0xe);
199: if (iStack172 != 0) {
200: if (iStack180 < 1) {
201: iStack180 = 0x100;
202: }
203: else {
204: if (0x100 < iStack180) {
205: ppcVar13 = (code **)*param_1;
206: *(undefined4 *)(ppcVar13 + 5) = 0x3e9;
207: (**ppcVar13)(param_1);
208: }
209: }
210: uVar8 = (**(code **)(param_1[1] + 0x10))(param_1,1,iStack180);
211: *(undefined8 *)(param_2 + 0x38) = uVar8;
212: *(int *)(param_2 + 0x54) = iStack180;
213: if (iStack172 == 3) {
214: lVar7 = 0;
215: bVar4 = true;
216: do {
217: iVar14 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
218: if (iVar14 == -1) {
219: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
220: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
221: (**ppcVar13)();
222: }
223: *(char *)(*(long *)(*(long *)(param_2 + 0x38) + 0x10) + lVar7) = (char)iVar14;
224: iVar14 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
225: if (iVar14 == -1) {
226: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
227: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
228: (**ppcVar13)();
229: }
230: *(char *)(*(long *)(*(long *)(param_2 + 0x38) + 8) + lVar7) = (char)iVar14;
231: iVar14 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
232: if (iVar14 == -1) {
233: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
234: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
235: (**ppcVar13)();
236: }
237: *(char *)(**(long **)(param_2 + 0x38) + lVar7) = (char)iVar14;
238: plVar3 = *(long **)(param_2 + 0x38);
239: if (*(char *)(plVar3[2] + lVar7) == *(char *)(plVar3[1] + lVar7)) {
240: if (*(char *)(plVar3[2] + lVar7) != *(char *)(*plVar3 + lVar7)) {
241: bVar4 = false;
242: }
243: }
244: else {
245: bVar4 = false;
246: }
247: lVar7 = lVar7 + 1;
248: } while (lVar7 != (ulong)(iStack180 - 1) + 1);
249: LAB_00168480:
250: ppcVar13 = *(code ***)(param_2 + 0x30);
251: if (*(int *)((long)ppcVar13 + 0x3c) == 0) {
252: if (bVar4) goto LAB_0016878f;
253: }
254: else {
255: if ((!bVar4) && (*(int *)((long)ppcVar13 + 0x3c) == 1)) {
256: ppcVar13 = (code **)*ppcVar13;
257: *(undefined4 *)(ppcVar13 + 5) = 9;
258: (**ppcVar13)();
259: }
260: }
261: }
262: else {
263: if (iStack172 == 4) {
264: lVar17 = 0;
265: bVar4 = true;
266: lVar7 = (ulong)(iStack180 - 1) + 1;
267: do {
268: while( true ) {
269: iVar14 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
270: if (iVar14 == -1) {
271: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
272: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
273: (**ppcVar13)();
274: }
275: *(char *)(*(long *)(*(long *)(param_2 + 0x38) + 0x10) + lVar17) = (char)iVar14;
276: iVar14 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
277: if (iVar14 == -1) {
278: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
279: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
280: (**ppcVar13)();
281: }
282: *(char *)(*(long *)(*(long *)(param_2 + 0x38) + 8) + lVar17) = (char)iVar14;
283: iVar14 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
284: if (iVar14 == -1) {
285: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
286: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
287: (**ppcVar13)();
288: }
289: *(char *)(**(long **)(param_2 + 0x38) + lVar17) = (char)iVar14;
290: iVar14 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
291: if (iVar14 == -1) {
292: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
293: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
294: (**ppcVar13)();
295: }
296: plVar3 = *(long **)(param_2 + 0x38);
297: if (*(char *)(plVar3[2] + lVar17) != *(char *)(plVar3[1] + lVar17)) break;
298: if (*(char *)(plVar3[2] + lVar17) != *(char *)(*plVar3 + lVar17)) {
299: bVar4 = false;
300: }
301: lVar17 = lVar17 + 1;
302: if (lVar7 == lVar17) goto LAB_00168480;
303: }
304: bVar4 = false;
305: lVar17 = lVar17 + 1;
306: } while (lVar7 != lVar17);
307: goto LAB_00168480;
308: }
309: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
310: *(undefined4 *)(ppcVar13 + 5) = 0x3e9;
311: (**ppcVar13)();
312: ppcVar13 = *(code ***)(param_2 + 0x30);
313: if (*(int *)((long)ppcVar13 + 0x3c) == 0) {
314: LAB_0016878f:
315: *(undefined4 *)((long)ppcVar13 + 0x3c) = 1;
316: }
317: }
318: iVar16 = iVar16 - iStack180 * iStack172;
319: }
320: if (iVar16 < 0) {
321: ppcVar13 = (code **)*param_1;
322: *(undefined4 *)(ppcVar13 + 5) = 0x3eb;
323: (**ppcVar13)(param_1);
324: }
325: while (iVar16 = iVar16 + -1, -1 < iVar16) {
326: while (iVar14 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18)), iVar14 == -1) {
327: ppcVar13 = (code **)**(code ***)(param_2 + 0x30);
328: *(undefined4 *)(ppcVar13 + 5) = 0x2b;
329: (**ppcVar13)();
330: iVar16 = iVar16 + -1;
331: if (iVar16 < 0) goto LAB_001684f1;
332: }
333: }
334: LAB_001684f1:
335: iVar16 = *(int *)(param_2 + 0x50);
336: lVar7 = (long)(int)uVar15;
337: if (iVar16 == 0x18) {
338: uVar9 = *(uint *)((long)param_1 + 0x3c);
339: if (uVar9 == 0) {
340: *(undefined4 *)((long)param_1 + 0x3c) = 8;
341: uVar5 = 3;
342: LAB_00168717:
343: *(undefined4 *)(param_1 + 7) = uVar5;
344: }
345: else {
346: if ((uVar9 - 6 < 10) || (uVar9 == 2)) {
347: uVar5 = *(undefined4 *)(&DAT_00190560 + (ulong)uVar9 * 4);
348: goto LAB_00168717;
349: }
350: if (uVar9 == 4) {
351: *(undefined4 *)(param_1 + 7) = 4;
352: }
353: else {
354: ppcVar13 = (code **)*param_1;
355: *(undefined4 *)(ppcVar13 + 5) = 9;
356: (**ppcVar13)(param_1);
357: }
358: }
359: if (0xffffffff < (ulong)(lVar7 * 3)) {
360: ppcVar13 = (code **)*param_1;
361: *(undefined4 *)(ppcVar13 + 5) = 0x46;
362: (**ppcVar13)(param_1);
363: }
364: uVar9 = uVar15 * 3;
365: LAB_001686a3:
366: while ((uVar9 & 3) != 0) {
367: uVar9 = uVar9 + 1;
368: }
369: }
370: else {
371: if (iVar16 == 0x20) {
372: uVar9 = *(uint *)((long)param_1 + 0x3c);
373: if (uVar9 == 0) {
374: *(undefined4 *)((long)param_1 + 0x3c) = 0xd;
375: uVar5 = 4;
376: LAB_001686c7:
377: *(undefined4 *)(param_1 + 7) = uVar5;
378: }
379: else {
380: if ((uVar9 - 6 < 10) || (uVar9 == 2)) {
381: uVar5 = *(undefined4 *)(&DAT_00190560 + (ulong)uVar9 * 4);
382: goto LAB_001686c7;
383: }
384: if (uVar9 == 4) {
385: *(undefined4 *)(param_1 + 7) = 4;
386: }
387: else {
388: ppcVar13 = (code **)*param_1;
389: *(undefined4 *)(ppcVar13 + 5) = 9;
390: (**ppcVar13)(param_1);
391: }
392: }
393: if (0xffffffff < (ulong)(lVar7 * 4)) {
394: ppcVar13 = (code **)*param_1;
395: *(undefined4 *)(ppcVar13 + 5) = 0x46;
396: (**ppcVar13)(param_1);
397: }
398: uVar9 = uVar15 * 4;
399: goto LAB_001686a3;
400: }
401: if (iVar16 == 8) {
402: uVar2 = *(uint *)((long)param_1 + 0x3c);
403: uVar9 = uVar15;
404: if (uVar2 == 0) {
405: *(undefined4 *)((long)param_1 + 0x3c) = 6;
406: uVar5 = 3;
407: LAB_0016868f:
408: *(undefined4 *)(param_1 + 7) = uVar5;
409: }
410: else {
411: if ((uVar2 - 6 < 10) || (uVar2 == 2)) {
412: uVar5 = *(undefined4 *)(&DAT_00190560 + (ulong)uVar2 * 4);
413: goto LAB_0016868f;
414: }
415: if (uVar2 == 1) {
416: *(undefined4 *)(param_1 + 7) = 1;
417: }
418: else {
419: if (uVar2 == 4) {
420: *(undefined4 *)(param_1 + 7) = 4;
421: }
422: else {
423: ppcVar13 = (code **)*param_1;
424: *(undefined4 *)(ppcVar13 + 5) = 9;
425: (**ppcVar13)(param_1);
426: }
427: }
428: }
429: goto LAB_001686a3;
430: }
431: ppcVar13 = (code **)*param_1;
432: *(undefined4 *)(ppcVar13 + 5) = 0x3ea;
433: (**ppcVar13)(param_1);
434: uVar9 = 0;
435: }
436: *(uint *)(param_2 + 0x4c) = uVar9;
437: if (*(int *)(param_2 + 0x58) == 0) {
438: uVar8 = (**(code **)param_1[1])(param_1,1,uVar9);
439: *(undefined8 *)(param_2 + 0x60) = uVar8;
440: iVar16 = *(int *)(param_2 + 0x50);
441: if (iVar16 == 0x18) {
442: *(code **)(param_2 + 8) = FUN_00167770;
443: }
444: else {
445: if (iVar16 == 0x20) {
446: *(code **)(param_2 + 8) = FUN_00167a80;
447: }
448: else {
449: if (iVar16 == 8) {
450: *(code **)(param_2 + 8) = FUN_00167340;
451: }
452: else {
453: ppcVar13 = (code **)*param_1;
454: *(undefined4 *)(ppcVar13 + 5) = 0x3ea;
455: (**ppcVar13)(param_1);
456: }
457: }
458: }
459: }
460: else {
461: uVar8 = (**(code **)((long)param_1[1] + 0x20))(param_1,1,0,uVar9,iStack176,1);
462: *(undefined8 *)(param_2 + 0x40) = uVar8;
463: *(code **)(param_2 + 8) = FUN_00167d90;
464: if (param_1[2] != (code *)0x0) {
465: piVar1 = (int *)(param_1[2] + 0x24);
466: *piVar1 = *piVar1 + 1;
467: }
468: }
469: iVar16 = *(int *)(param_1 + 7);
470: if (0xffffffff < (ulong)(lVar7 * iVar16)) {
471: ppcVar13 = (code **)*param_1;
472: *(undefined4 *)(ppcVar13 + 5) = 0x46;
473: (**ppcVar13)(param_1);
474: iVar16 = *(int *)(param_1 + 7);
475: }
476: uVar8 = (**(code **)(param_1[1] + 0x10))(param_1,1,iVar16 * uVar15,1);
477: *(undefined8 *)(param_2 + 0x20) = uVar8;
478: *(undefined4 *)(param_2 + 0x28) = 1;
479: *(undefined4 *)(param_1 + 9) = 8;
480: *(uint *)(param_1 + 6) = uVar15;
481: *(int *)((long)param_1 + 0x34) = iStack176;
482: LAB_00168048:
483: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
484: /* WARNING: Subroutine does not return */
485: __stack_chk_fail();
486: }
487: return;
488: }
489: 
