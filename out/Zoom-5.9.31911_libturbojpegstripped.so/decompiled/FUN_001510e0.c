1: 
2: void FUN_001510e0(code **param_1,long param_2)
3: 
4: {
5: int *piVar1;
6: int iVar2;
7: code *pcVar3;
8: long *plVar4;
9: bool bVar5;
10: int iVar6;
11: int iVar7;
12: uint uVar8;
13: uint uVar9;
14: size_t sVar10;
15: long lVar11;
16: undefined8 uVar12;
17: int iVar13;
18: long lVar14;
19: code **ppcVar15;
20: short sVar16;
21: long in_FS_OFFSET;
22: uint uStack192;
23: int iStack188;
24: uint uStack184;
25: int iStack180;
26: byte bStack152;
27: byte bStack151;
28: byte bStack142;
29: byte bStack141;
30: byte bStack140;
31: byte bStack139;
32: byte bStack136;
33: byte bStack135;
34: byte bStack134;
35: byte bStack133;
36: byte bStack132;
37: byte bStack131;
38: byte bStack130;
39: byte bStack129;
40: byte bStack128;
41: byte bStack127;
42: byte bStack126;
43: byte bStack125;
44: byte bStack124;
45: byte bStack123;
46: byte bStack122;
47: byte bStack121;
48: byte bStack120;
49: byte bStack119;
50: byte bStack118;
51: byte bStack117;
52: byte bStack112;
53: byte bStack111;
54: byte bStack110;
55: byte bStack109;
56: byte bStack108;
57: byte bStack107;
58: byte bStack106;
59: byte bStack105;
60: byte bStack104;
61: byte bStack103;
62: byte bStack102;
63: byte bStack101;
64: long lStack64;
65: 
66: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
67: sVar10 = fread(&bStack152,1,0xe,*(FILE **)(param_2 + 0x18));
68: if (sVar10 != 0xe) {
69: ppcVar15 = (code **)*param_1;
70: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
71: (**ppcVar15)(param_1);
72: }
73: if ((uint)bStack151 * 0x100 + (uint)bStack152 != 0x4d42) {
74: ppcVar15 = (code **)*param_1;
75: *(undefined4 *)(ppcVar15 + 5) = 0x3f0;
76: (**ppcVar15)(param_1);
77: }
78: sVar10 = fread(&bStack136,1,4,*(FILE **)(param_2 + 0x18));
79: if (sVar10 != 4) {
80: ppcVar15 = (code **)*param_1;
81: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
82: (**ppcVar15)(param_1);
83: }
84: iVar13 = (uint)bStack135 * 0x100 + (uint)bStack134 * 0x10000 + (uint)bStack136 +
85: (uint)bStack133 * 0x1000000;
86: if (0x34 < iVar13 - 0xcU) {
87: ppcVar15 = (code **)*param_1;
88: *(undefined4 *)(ppcVar15 + 5) = 0x3eb;
89: (**ppcVar15)(param_1);
90: }
91: sVar10 = fread(&bStack132,1,(ulong)(iVar13 - 4),*(FILE **)(param_2 + 0x18));
92: if (iVar13 - 4 != sVar10) {
93: ppcVar15 = (code **)*param_1;
94: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
95: (**ppcVar15)(param_1);
96: }
97: if ((iVar13 == 0x28) || (iVar13 == 0x40)) {
98: uStack192 = (uint)bStack129 * 0x1000000 +
99: (uint)bStack131 * 0x100 + (uint)bStack130 * 0x10000 + (uint)bStack132;
100: iStack188 = (uint)bStack125 * 0x1000000 +
101: (uint)bStack127 * 0x100 + (uint)bStack126 * 0x10000 + (uint)bStack128;
102: sVar16 = (ushort)bStack124 + (ushort)bStack123 * 0x100;
103: iVar7 = (uint)bStack121 * 0x100 + (uint)bStack122;
104: *(int *)(param_2 + 0x50) = iVar7;
105: iVar6 = (uint)bStack111 * 0x100 + (uint)bStack110 * 0x10000 + (uint)bStack112 +
106: (uint)bStack109 * 0x1000000;
107: iVar2 = (uint)bStack107 * 0x100 + (uint)bStack106 * 0x10000 + (uint)bStack108 +
108: (uint)bStack105 * 0x1000000;
109: uStack184 = (uint)bStack103 * 0x100 + (uint)bStack102 * 0x10000 + (uint)bStack104 +
110: (uint)bStack101 * 0x1000000;
111: if ((iVar7 == 0x18) || (iVar7 == 0x20)) {
112: pcVar3 = *param_1;
113: *(uint *)(pcVar3 + 0x2c) = uStack192;
114: *(undefined4 *)(pcVar3 + 0x28) = 0x3f2;
115: *(int *)(*param_1 + 0x30) = iStack188;
116: (**(code **)(*param_1 + 8))();
117: iStack180 = 0;
118: }
119: else {
120: ppcVar15 = (code **)*param_1;
121: if (iVar7 == 8) {
122: *(undefined4 *)(ppcVar15 + 5) = 0x3f3;
123: *(uint *)((long)ppcVar15 + 0x2c) = uStack192;
124: *(int *)(*param_1 + 0x30) = iStack188;
125: (**(code **)(*param_1 + 8))();
126: iStack180 = 4;
127: }
128: else {
129: *(undefined4 *)(ppcVar15 + 5) = 0x3ea;
130: (**ppcVar15)();
131: iStack180 = 0;
132: }
133: }
134: if ((uint)bStack119 * 0x100 + (uint)bStack118 * 0x10000 + (uint)bStack120 +
135: (uint)bStack117 * 0x1000000 != 0) {
136: ppcVar15 = (code **)*param_1;
137: *(undefined4 *)(ppcVar15 + 5) = 0x3ee;
138: (**ppcVar15)();
139: }
140: if ((0 < iVar2) && (0 < iVar6)) {
141: *(undefined *)((long)param_1 + 0x126) = 2;
142: *(short *)(param_1 + 0x25) = (short)(iVar6 / 100);
143: *(short *)((long)param_1 + 0x12a) = (short)(iVar2 / 100);
144: }
145: goto LAB_001514c5;
146: }
147: if (iVar13 != 0xc) {
148: ppcVar15 = (code **)*param_1;
149: *(undefined4 *)(ppcVar15 + 5) = 0x3eb;
150: (**ppcVar15)(param_1);
151: goto LAB_00151231;
152: }
153: uStack192 = (uint)bStack131 * 0x100 + (uint)bStack132;
154: iStack188 = (uint)bStack129 * 0x100 + (uint)bStack130;
155: sVar16 = (ushort)bStack128 + (ushort)bStack127 * 0x100;
156: iVar6 = (uint)bStack125 * 0x100 + (uint)bStack126;
157: *(int *)(param_2 + 0x50) = iVar6;
158: if (iVar6 == 8) {
159: pcVar3 = *param_1;
160: *(uint *)(pcVar3 + 0x2c) = uStack192;
161: *(undefined4 *)(pcVar3 + 0x28) = 0x3f5;
162: *(int *)(*param_1 + 0x30) = iStack188;
163: (**(code **)(*param_1 + 8))();
164: iStack180 = 3;
165: uStack184 = 0;
166: LAB_001514c5:
167: if (iStack188 < 1) goto LAB_00151308;
168: LAB_001514d3:
169: if ((int)uStack192 < 1) goto LAB_00151308;
170: }
171: else {
172: if (iVar6 != 0x18) {
173: ppcVar15 = (code **)*param_1;
174: *(undefined4 *)(ppcVar15 + 5) = 0x3ea;
175: (**ppcVar15)();
176: iStack180 = 0;
177: uStack184 = 0;
178: goto LAB_001514c5;
179: }
180: pcVar3 = *param_1;
181: *(uint *)(pcVar3 + 0x2c) = uStack192;
182: *(undefined4 *)(pcVar3 + 0x28) = 0x3f4;
183: *(int *)(*param_1 + 0x30) = iStack188;
184: (**(code **)(*param_1 + 8))();
185: iStack180 = 0;
186: uStack184 = 0;
187: if (iStack188 != 0) goto LAB_001514d3;
188: LAB_00151308:
189: ppcVar15 = (code **)*param_1;
190: *(undefined4 *)(ppcVar15 + 5) = 0x3ef;
191: (**ppcVar15)(param_1);
192: }
193: if (sVar16 != 1) {
194: ppcVar15 = (code **)*param_1;
195: *(undefined4 *)(ppcVar15 + 5) = 0x3ec;
196: (**ppcVar15)(param_1);
197: }
198: iVar13 = ((uint)bStack140 * 0x10000 + (bStack142 - 0xe) + (uint)bStack141 * 0x100 +
199: (uint)bStack139 * 0x1000000) - iVar13;
200: if (iStack180 != 0) {
201: if (uStack184 == 0) {
202: uStack184 = 0x100;
203: }
204: else {
205: if (0x100 < uStack184) {
206: ppcVar15 = (code **)*param_1;
207: *(undefined4 *)(ppcVar15 + 5) = 0x3e9;
208: (**ppcVar15)(param_1);
209: }
210: }
211: lVar11 = (**(code **)(param_1[1] + 0x10))(param_1,1,uStack184);
212: *(long *)(param_2 + 0x38) = lVar11;
213: *(uint *)(param_2 + 0x54) = uStack184;
214: if (iStack180 == 3) {
215: if (0 < (int)uStack184) {
216: lVar11 = *(long *)(lVar11 + 0x10);
217: lVar14 = 0;
218: bVar5 = true;
219: do {
220: iVar6 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
221: if (iVar6 == -1) {
222: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
223: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
224: (**ppcVar15)();
225: }
226: *(char *)(lVar11 + lVar14) = (char)iVar6;
227: lVar11 = *(long *)(*(long *)(param_2 + 0x38) + 8);
228: iVar6 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
229: if (iVar6 == -1) {
230: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
231: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
232: (**ppcVar15)();
233: }
234: *(char *)(lVar14 + lVar11) = (char)iVar6;
235: lVar11 = **(long **)(param_2 + 0x38);
236: iVar6 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
237: if (iVar6 == -1) {
238: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
239: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
240: (**ppcVar15)();
241: }
242: *(char *)(lVar14 + lVar11) = (char)iVar6;
243: plVar4 = *(long **)(param_2 + 0x38);
244: lVar11 = plVar4[2];
245: if (*(char *)(lVar11 + lVar14) == *(char *)(plVar4[1] + lVar14)) {
246: if (*(char *)(lVar11 + lVar14) != *(char *)(*plVar4 + lVar14)) {
247: bVar5 = false;
248: }
249: }
250: else {
251: bVar5 = false;
252: }
253: lVar14 = lVar14 + 1;
254: } while ((int)lVar14 < (int)uStack184);
255: goto LAB_00151658;
256: }
257: LAB_0015187e:
258: ppcVar15 = *(code ***)(param_2 + 0x30);
259: bVar5 = true;
260: iVar6 = *(int *)((long)ppcVar15 + 0x3c);
261: if (iVar6 != 0) goto LAB_00151898;
262: LAB_00151675:
263: *(undefined4 *)((long)ppcVar15 + 0x3c) = 1;
264: }
265: else {
266: if (iStack180 == 4) {
267: if ((int)uStack184 < 1) goto LAB_0015187e;
268: lVar11 = *(long *)(lVar11 + 0x10);
269: lVar14 = 0;
270: bVar5 = true;
271: do {
272: while( true ) {
273: iVar6 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
274: if (iVar6 == -1) {
275: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
276: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
277: (**ppcVar15)();
278: }
279: *(char *)(lVar11 + lVar14) = (char)iVar6;
280: lVar11 = *(long *)(*(long *)(param_2 + 0x38) + 8);
281: iVar6 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
282: if (iVar6 == -1) {
283: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
284: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
285: (**ppcVar15)();
286: }
287: *(char *)(lVar14 + lVar11) = (char)iVar6;
288: lVar11 = **(long **)(param_2 + 0x38);
289: iVar6 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
290: if (iVar6 == -1) {
291: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
292: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
293: (**ppcVar15)();
294: }
295: *(char *)(lVar14 + lVar11) = (char)iVar6;
296: iVar6 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
297: if (iVar6 == -1) {
298: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
299: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
300: (**ppcVar15)();
301: }
302: plVar4 = *(long **)(param_2 + 0x38);
303: lVar11 = plVar4[2];
304: if (*(char *)(lVar11 + lVar14) != *(char *)(plVar4[1] + lVar14)) break;
305: if (*(char *)(lVar11 + lVar14) != *(char *)(*plVar4 + lVar14)) {
306: bVar5 = false;
307: }
308: lVar14 = lVar14 + 1;
309: if ((int)uStack184 <= (int)lVar14) goto LAB_00151658;
310: }
311: lVar14 = lVar14 + 1;
312: bVar5 = false;
313: } while ((int)lVar14 < (int)uStack184);
314: LAB_00151658:
315: ppcVar15 = *(code ***)(param_2 + 0x30);
316: iVar6 = *(int *)((long)ppcVar15 + 0x3c);
317: if (iVar6 == 0) {
318: if (bVar5) goto LAB_00151675;
319: }
320: else {
321: LAB_00151898:
322: if ((iVar6 == 1) && (!bVar5)) {
323: ppcVar15 = (code **)*ppcVar15;
324: *(undefined4 *)(ppcVar15 + 5) = 9;
325: (**ppcVar15)();
326: }
327: }
328: }
329: else {
330: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
331: *(undefined4 *)(ppcVar15 + 5) = 0x3e9;
332: (**ppcVar15)();
333: ppcVar15 = *(code ***)(param_2 + 0x30);
334: if (*(int *)((long)ppcVar15 + 0x3c) == 0) goto LAB_00151675;
335: }
336: }
337: iVar13 = iVar13 - uStack184 * iStack180;
338: }
339: if (iVar13 < 0) {
340: ppcVar15 = (code **)*param_1;
341: *(undefined4 *)(ppcVar15 + 5) = 0x3eb;
342: (**ppcVar15)(param_1);
343: }
344: while (iVar13 = iVar13 + -1, -1 < iVar13) {
345: while (iVar6 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18)), iVar6 == -1) {
346: ppcVar15 = (code **)**(code ***)(param_2 + 0x30);
347: *(undefined4 *)(ppcVar15 + 5) = 0x2b;
348: (**ppcVar15)();
349: iVar13 = iVar13 + -1;
350: if (iVar13 < 0) goto LAB_001516c8;
351: }
352: }
353: LAB_001516c8:
354: iVar13 = *(int *)(param_2 + 0x50);
355: if (iVar13 == 0x18) {
356: uVar8 = *(uint *)((long)param_1 + 0x3c);
357: if (uVar8 == 0) {
358: *(undefined4 *)((long)param_1 + 0x3c) = 8;
359: uVar8 = 8;
360: LAB_00151974:
361: *(undefined4 *)(param_1 + 7) = *(undefined4 *)(&DAT_0018c1a0 + (ulong)uVar8 * 4);
362: }
363: else {
364: if ((uVar8 - 6 < 10) || (uVar8 == 2)) goto LAB_00151974;
365: if (uVar8 == 4) {
366: *(undefined4 *)(param_1 + 7) = 4;
367: }
368: else {
369: ppcVar15 = (code **)*param_1;
370: *(undefined4 *)(ppcVar15 + 5) = 9;
371: (**ppcVar15)(param_1);
372: }
373: }
374: uVar8 = uStack192 * 3;
375: LAB_00151993:
376: while ((uVar8 & 3) != 0) {
377: uVar8 = uVar8 + 1;
378: }
379: }
380: else {
381: if (iVar13 == 0x20) {
382: uVar8 = *(uint *)((long)param_1 + 0x3c);
383: if (uVar8 == 0) {
384: *(undefined4 *)((long)param_1 + 0x3c) = 0xd;
385: uVar8 = 0xd;
386: LAB_001519e4:
387: *(undefined4 *)(param_1 + 7) = *(undefined4 *)(&DAT_0018c1a0 + (ulong)uVar8 * 4);
388: }
389: else {
390: if ((uVar8 - 6 < 10) || (uVar8 == 2)) goto LAB_001519e4;
391: if (uVar8 == 4) {
392: *(undefined4 *)(param_1 + 7) = 4;
393: }
394: else {
395: ppcVar15 = (code **)*param_1;
396: *(undefined4 *)(ppcVar15 + 5) = 9;
397: (**ppcVar15)(param_1);
398: }
399: }
400: uVar8 = uStack192 * 4;
401: goto LAB_00151993;
402: }
403: if (iVar13 == 8) {
404: uVar9 = *(uint *)((long)param_1 + 0x3c);
405: uVar8 = uStack192;
406: if (uVar9 == 0) {
407: *(undefined4 *)((long)param_1 + 0x3c) = 6;
408: uVar9 = 6;
409: LAB_001519b4:
410: *(undefined4 *)(param_1 + 7) = *(undefined4 *)(&DAT_0018c1a0 + (ulong)uVar9 * 4);
411: }
412: else {
413: if ((uVar9 - 6 < 10) || (uVar9 == 2)) goto LAB_001519b4;
414: if (uVar9 == 1) {
415: *(undefined4 *)(param_1 + 7) = 1;
416: }
417: else {
418: if (uVar9 == 4) {
419: *(undefined4 *)(param_1 + 7) = 4;
420: }
421: else {
422: ppcVar15 = (code **)*param_1;
423: *(undefined4 *)(ppcVar15 + 5) = 9;
424: (**ppcVar15)(param_1);
425: }
426: }
427: }
428: goto LAB_00151993;
429: }
430: ppcVar15 = (code **)*param_1;
431: *(undefined4 *)(ppcVar15 + 5) = 0x3ea;
432: (**ppcVar15)(param_1);
433: uVar8 = 0;
434: }
435: *(uint *)(param_2 + 0x4c) = uVar8;
436: if (*(int *)(param_2 + 0x58) == 0) {
437: uVar12 = (**(code **)param_1[1])(param_1,1,uVar8);
438: *(undefined8 *)(param_2 + 0x60) = uVar12;
439: iVar13 = *(int *)(param_2 + 0x50);
440: if (iVar13 == 0x18) {
441: *(code **)(param_2 + 8) = FUN_00150c00;
442: }
443: else {
444: if (iVar13 == 0x20) {
445: *(code **)(param_2 + 8) = FUN_00150900;
446: }
447: else {
448: if (iVar13 == 8) {
449: *(code **)(param_2 + 8) = FUN_00150460;
450: }
451: else {
452: ppcVar15 = (code **)*param_1;
453: *(undefined4 *)(ppcVar15 + 5) = 0x3ea;
454: (**ppcVar15)(param_1);
455: }
456: }
457: }
458: }
459: else {
460: uVar12 = (**(code **)((long)param_1[1] + 0x20))(param_1,1,0,uVar8,iStack188,1);
461: *(undefined8 *)(param_2 + 0x40) = uVar12;
462: *(code **)(param_2 + 8) = FUN_00150f10;
463: if (param_1[2] != (code *)0x0) {
464: piVar1 = (int *)(param_1[2] + 0x24);
465: *piVar1 = *piVar1 + 1;
466: }
467: }
468: iVar13 = *(int *)(param_1 + 7);
469: if (0xffffffff < (ulong)((long)(int)uStack192 * (long)iVar13)) {
470: ppcVar15 = (code **)*param_1;
471: *(undefined4 *)(ppcVar15 + 5) = 0x46;
472: (**ppcVar15)(param_1);
473: iVar13 = *(int *)(param_1 + 7);
474: }
475: uVar12 = (**(code **)(param_1[1] + 0x10))(param_1,1,iVar13 * uStack192,1);
476: *(undefined8 *)(param_2 + 0x20) = uVar12;
477: *(undefined4 *)(param_2 + 0x28) = 1;
478: *(undefined4 *)(param_1 + 9) = 8;
479: *(uint *)(param_1 + 6) = uStack192;
480: *(int *)((long)param_1 + 0x34) = iStack188;
481: LAB_00151231:
482: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
483: /* WARNING: Subroutine does not return */
484: __stack_chk_fail();
485: }
486: return;
487: }
488: 
