1: 
2: ulong FUN_00127b40(long param_1)
3: 
4: {
5: long lVar1;
6: short *psVar2;
7: undefined8 uVar3;
8: code *pcVar4;
9: ushort *puVar5;
10: bool bVar6;
11: int iVar7;
12: short sVar8;
13: uint uVar9;
14: int iVar10;
15: ulong uVar11;
16: long lVar12;
17: uint uVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: long lVar18;
23: long lVar19;
24: uint uVar20;
25: int iVar21;
26: int iVar22;
27: long lVar23;
28: long lVar24;
29: long lVar25;
30: long lVar26;
31: long lVar27;
32: long lVar28;
33: long lVar29;
34: long lVar30;
35: long lVar31;
36: long lVar32;
37: long lVar33;
38: int iVar34;
39: int iVar35;
40: int iVar36;
41: long lVar37;
42: ulong uVar38;
43: long lVar39;
44: long lVar40;
45: short *psVar41;
46: int iVar42;
47: long lVar43;
48: int iVar44;
49: int iVar45;
50: uint uVar46;
51: int iVar47;
52: long lVar48;
53: uint uVar49;
54: int iVar50;
55: int iVar51;
56: uint uVar52;
57: long lVar53;
58: long lStack504;
59: int iStack480;
60: int iStack476;
61: int iStack472;
62: int iStack468;
63: short *psStack464;
64: int iStack456;
65: int iStack452;
66: short *psStack448;
67: int iStack440;
68: int iStack436;
69: int iStack424;
70: int iStack420;
71: int iStack416;
72: int iStack412;
73: int iStack408;
74: int iStack392;
75: int iStack388;
76: int iStack384;
77: int iStack380;
78: long lStack376;
79: short *psStack360;
80: long *plStack336;
81: short *psStack328;
82: short *psStack304;
83: long *plStack296;
84: short *psStack288;
85: uint uStack200;
86: int iStack124;
87: long lStack120;
88: ulong uStack104;
89: ulong uStack96;
90: ulong uStack88;
91: ulong uStack80;
92: 
93: lVar1 = *(long *)(param_1 + 0x230);
94: iVar21 = *(int *)(param_1 + 0x1a4);
95: psVar2 = *(short **)(lVar1 + 0x88);
96: while( true ) {
97: if ((*(int *)(param_1 + 0xb4) < *(int *)(param_1 + 0xac)) ||
98: (*(int *)((long)*(code ***)(param_1 + 0x240) + 0x24) != 0)) break;
99: if ((*(int *)(param_1 + 0xac) == *(int *)(param_1 + 0xb4)) &&
100: (uVar49 = *(uint *)(param_1 + 0xb8),
101: uVar9 = uVar49 + (uint)(*(int *)(param_1 + 0x20c) == 0) * 2,
102: uVar9 <= *(uint *)(param_1 + 0xb0) && *(uint *)(param_1 + 0xb0) != uVar9)) goto LAB_00127be0;
103: uVar11 = (***(code ***)(param_1 + 0x240))();
104: if ((int)uVar11 == 0) {
105: return uVar11;
106: }
107: }
108: uVar49 = *(uint *)(param_1 + 0xb8);
109: LAB_00127be0:
110: lStack504 = *(long *)(param_1 + 0x130);
111: iVar45 = *(int *)(param_1 + 0x38);
112: if (0 < iVar45) {
113: uVar9 = iVar21 - 1;
114: uVar20 = iVar21 - 2;
115: lStack120 = 0;
116: uStack80 = 0;
117: uStack88 = 0;
118: uStack96 = 0;
119: uStack104 = 0;
120: iStack124 = 0;
121: do {
122: if (*(int *)(lStack504 + 0x30) != 0) {
123: uVar52 = *(uint *)(lStack504 + 0xc);
124: uStack200 = uVar52;
125: if (uVar49 < uVar20) {
126: uVar11 = (ulong)(uVar52 * 3);
127: }
128: else {
129: if (uVar49 < uVar9) {
130: uVar11 = (ulong)(uVar52 * 2);
131: }
132: else {
133: uVar11 = (ulong)*(uint *)(lStack504 + 0x20) % (ulong)uVar52;
134: uStack200 = (uint)uVar11;
135: if (uStack200 == 0) {
136: uVar11 = (ulong)uVar52;
137: uStack200 = uVar52;
138: }
139: }
140: }
141: uVar3 = *(undefined8 *)(lVar1 + 0x90 + lStack120);
142: pcVar4 = *(code **)(*(long *)(param_1 + 8) + 0x40);
143: if (uVar49 < 2) {
144: if (uVar49 == 0) {
145: plStack296 = (long *)(*pcVar4)(param_1,uVar3,0,uVar11);
146: }
147: else {
148: lVar12 = (*pcVar4)(param_1,uVar3,0,uVar11);
149: plStack296 = (long *)(lVar12 + (long)*(int *)(lStack504 + 0xc) * 8);
150: }
151: }
152: else {
153: lVar12 = (*pcVar4)(param_1,uVar3,(uVar49 - 2) * uVar52,(int)uVar11 + uVar52 * 2);
154: plStack296 = (long *)(lVar12 + (long)(*(int *)(lStack504 + 0xc) * 2) * 8);
155: }
156: lVar12 = *(long *)(param_1 + 0x220);
157: uVar49 = *(uint *)(param_1 + 0xb8);
158: if (uVar49 < *(uint *)(lVar12 + 0x70) || uVar49 == *(uint *)(lVar12 + 0x70)) {
159: lVar53 = lStack120 * 5;
160: }
161: else {
162: lVar53 = (long)((iStack124 + *(int *)(param_1 + 0x38)) * 10) * 4;
163: }
164: lVar53 = *(long *)(lVar1 + 0xe0) + lVar53;
165: bVar6 = false;
166: puVar5 = *(ushort **)(lStack504 + 0x50);
167: uVar11 = (ulong)*puVar5;
168: if ((((((*(int *)(lVar53 + 4) == -1) && (*(int *)(lVar53 + 8) == -1)) &&
169: (*(int *)(lVar53 + 0xc) == -1)) &&
170: ((*(int *)(lVar53 + 0x10) == -1 && (*(int *)(lVar53 + 0x14) == -1)))) &&
171: ((*(int *)(lVar53 + 0x18) == -1 &&
172: ((*(int *)(lVar53 + 0x1c) == -1 && (*(int *)(lVar53 + 0x20) == -1)))))) &&
173: (*(int *)(lVar53 + 0x24) == -1)) {
174: uStack104 = (ulong)puVar5[3];
175: bVar6 = true;
176: uStack96 = (ulong)puVar5[10];
177: uStack88 = (ulong)puVar5[0x11];
178: uStack80 = (ulong)puVar5[0x18];
179: }
180: lVar23 = (long)iStack124;
181: pcVar4 = *(code **)(*(long *)(param_1 + 600) + 8 + lVar23 * 8);
182: if ((int)uStack200 < 1) {
183: iVar45 = *(int *)(param_1 + 0x38);
184: }
185: else {
186: lVar43 = (ulong)puVar5[1] << 8;
187: lVar24 = (ulong)puVar5[1] * 0x80;
188: lVar40 = (ulong)puVar5[8] << 8;
189: lVar25 = (ulong)puVar5[8] * 0x80;
190: lVar37 = (ulong)puVar5[0x10] << 8;
191: lVar26 = (ulong)puVar5[0x10] * 0x80;
192: lVar14 = (ulong)puVar5[9] << 8;
193: lVar27 = (ulong)puVar5[9] * 0x80;
194: lVar48 = (ulong)puVar5[2] << 8;
195: lVar28 = (ulong)puVar5[2] * 0x80;
196: lVar29 = uStack104 << 8;
197: lVar15 = uStack104 * 0x80;
198: lVar30 = uStack96 << 8;
199: lVar16 = uStack96 * 0x80;
200: lVar31 = uStack88 << 8;
201: lVar17 = uStack88 * 0x80;
202: lVar32 = uStack80 << 8;
203: lVar18 = uStack80 * 0x80;
204: lVar33 = uVar11 << 8;
205: lVar19 = uVar11 * 0x80;
206: iVar21 = uStack200 - 2;
207: uVar52 = *(uint *)(lVar12 + 0x1c + lVar23 * 4);
208: uVar38 = (ulong)uVar52;
209: uVar13 = *(uint *)(lVar12 + 0x44 + lVar23 * 4);
210: lVar39 = uVar38 * 0x80;
211: psStack448 = (short *)(*plStack296 + lVar39);
212: plStack336 = (long *)psStack448;
213: if ((uVar49 == 0) || (plStack336 = (long *)(plStack296[-1] + lVar39), uVar49 < 2)) {
214: psStack360 = (short *)plStack336;
215: if (uStack200 == 1) goto LAB_00129508;
216: LAB_00127f68:
217: psStack328 = (short *)(plStack296[1] + lVar39);
218: if (0 < iVar21) goto LAB_00127f8e;
219: LAB_00129531:
220: psStack304 = psStack328;
221: if (uVar49 < uVar20) goto LAB_00127f8e;
222: }
223: else {
224: psStack360 = (short *)(plStack296[-2] + lVar39);
225: if (uStack200 != 1) goto LAB_00127f68;
226: LAB_00129508:
227: if (uVar49 < uVar9) goto LAB_00127f68;
228: psStack328 = psStack448;
229: if (iVar21 < 1) goto LAB_00129531;
230: LAB_00127f8e:
231: psStack304 = (short *)(lVar39 + plStack296[2]);
232: }
233: iStack456 = (int)*psStack360;
234: iStack472 = (int)*psStack304;
235: iStack408 = (int)*(short *)plStack336;
236: uVar49 = *(int *)(lStack504 + 0x1c) - 1;
237: iStack424 = (int)*psStack448;
238: iStack412 = (int)*psStack328;
239: if (uVar52 <= uVar13) {
240: lStack376 = 0x80;
241: iVar44 = iStack412;
242: iVar50 = iStack408;
243: iVar35 = iStack424;
244: iVar22 = iStack412;
245: iStack476 = iStack408;
246: iStack468 = iStack424;
247: iStack452 = iStack456;
248: iStack420 = iStack456;
249: iStack416 = iStack472;
250: iStack392 = iStack424;
251: iStack388 = iStack456;
252: iStack384 = iStack472;
253: iStack380 = iStack408;
254: iVar42 = iStack412;
255: iVar45 = iStack472;
256: do {
257: iStack480 = iVar22;
258: iVar34 = iVar35;
259: iVar51 = iVar50;
260: iVar22 = iVar44;
261: iVar7 = iStack472;
262: FUN_00148a60(psStack448,psVar2,1);
263: uVar52 = (uint)uVar38;
264: if ((*(uint *)(*(long *)(param_1 + 0x220) + 0xc + (lVar23 + 4) * 4) == uVar52) &&
265: (uVar52 < uVar49)) {
266: iStack440 = (int)*(short *)((long)psStack360 + lStack376);
267: iVar50 = (int)*(short *)((long)plStack336 + lStack376);
268: iVar47 = (int)psStack448[0x40];
269: iVar44 = (int)*(short *)((long)psStack328 + lStack376);
270: iStack436 = (int)*(short *)((long)psStack304 + lStack376);
271: }
272: else {
273: iStack436 = iStack416;
274: iStack440 = iStack420;
275: iVar44 = iStack412;
276: iVar47 = iStack424;
277: iVar50 = iStack408;
278: }
279: uVar52 = uVar52 + 1;
280: uVar38 = (ulong)uVar52;
281: if (uVar52 < uVar49) {
282: iStack420 = (int)*(short *)((long)psStack360 + lStack376 + 0x80);
283: iStack408 = (int)*(short *)((long)plStack336 + lStack376 + 0x80);
284: iStack424 = (int)psStack448[0x80];
285: iStack412 = (int)*(short *)((long)psStack328 + lStack376 + 0x80);
286: iStack416 = (int)*(short *)((long)psStack304 + lStack376 + 0x80);
287: }
288: iVar35 = *(int *)(lVar53 + 4);
289: if ((iVar35 != 0) && (psVar2[1] == 0)) {
290: if (bVar6) {
291: lVar12 = (long)((((((iStack440 - iStack388) - iStack452) + iStack420 +
292: iStack380 * -3 + iStack476 * 0xd + iVar50 * -0xd +
293: iStack408 * 3 + iStack392 * -3 + iVar34 * 0x26 + iVar47 * -0x26
294: + iStack424 * 3 + iVar42 * -3 + iStack480 * 0xd + iVar44 * -0xd
295: + iStack412 * 3) - iStack384) - iVar45) + iStack436 + iStack416)
296: * uVar11;
297: if (-1 < lVar12) goto LAB_00128338;
298: LAB_0012974d:
299: iVar36 = (int)((lVar24 - lVar12) / lVar43);
300: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
301: iVar36 = iVar35 + -1;
302: }
303: sVar8 = -(short)iVar36;
304: }
305: else {
306: lVar12 = (long)(iStack424 * 7 + iVar47 * -0x32 + iStack392 * -7 + iVar34 * 0x32) *
307: uVar11;
308: if (lVar12 < 0) goto LAB_0012974d;
309: LAB_00128338:
310: lVar12 = (lVar12 + lVar24) / lVar43;
311: sVar8 = (short)lVar12;
312: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12))
313: {
314: sVar8 = (short)iVar35 + -1;
315: }
316: }
317: psVar2[1] = sVar8;
318: }
319: iVar35 = *(int *)(lVar53 + 8);
320: if ((iVar35 != 0) && (psVar2[8] == 0)) {
321: if (bVar6) {
322: lVar12 = (long)(((((((iStack452 * -3 - iStack388) + iStack456 * -3 +
323: iStack440 * -3) - iStack420) - iStack380) + iStack476 * 0xd +
324: iVar51 * 0x26 + iVar50 * 0xd) - iStack408) + iVar42 +
325: iStack480 * -0xd + iVar22 * -0x26 + iVar44 * -0xd + iStack412 +
326: iStack384 + iVar45 * 3 + iStack472 * 3 + iStack436 * 3 + iStack416
327: ) * uVar11;
328: if (-1 < lVar12) goto LAB_00128439;
329: LAB_0012999a:
330: iVar36 = (int)((lVar25 - lVar12) / lVar40);
331: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
332: iVar36 = iVar35 + -1;
333: }
334: sVar8 = -(short)iVar36;
335: }
336: else {
337: lVar12 = (long)(iStack472 * 7 + iVar22 * -0x32 + iStack456 * -7 + iVar51 * 0x32) *
338: uVar11;
339: if (lVar12 < 0) goto LAB_0012999a;
340: LAB_00128439:
341: lVar12 = (lVar12 + lVar25) / lVar40;
342: sVar8 = (short)lVar12;
343: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12))
344: {
345: sVar8 = (short)iVar35 + -1;
346: }
347: }
348: psVar2[8] = sVar8;
349: }
350: iVar35 = *(int *)(lVar53 + 0xc);
351: if ((iVar35 != 0) && (psVar2[0x10] == 0)) {
352: if (bVar6) {
353: lVar12 = (long)(iVar22 * 7 +
354: iStack456 + iStack476 * 2 + iVar51 * 7 + iVar50 * 2 + iVar34 * -5
355: + iStack468 * -0xe + iVar47 * -5 + iStack480 * 2 + iVar44 * 2 +
356: iStack472) * uVar11;
357: if (-1 < lVar12) goto LAB_001284ee;
358: LAB_00129929:
359: iVar36 = (int)((lVar26 - lVar12) / lVar37);
360: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
361: iVar36 = iVar35 + -1;
362: }
363: sVar8 = -(short)iVar36;
364: }
365: else {
366: lVar12 = (long)(((iVar51 * 0xd - iStack456) + iStack468 * -0x18 + iVar22 * 0xd) -
367: iStack472) * uVar11;
368: if (lVar12 < 0) goto LAB_00129929;
369: LAB_001284ee:
370: lVar12 = (lVar12 + lVar26) / lVar37;
371: sVar8 = (short)lVar12;
372: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12))
373: {
374: sVar8 = (short)iVar35 + -1;
375: }
376: }
377: psVar2[0x10] = sVar8;
378: }
379: iVar35 = *(int *)(lVar53 + 0x10);
380: if ((iVar35 != 0) && (psVar2[9] == 0)) {
381: if (bVar6) {
382: lVar12 = (long)(((iStack420 - iStack388) + iStack476 * 9 + iVar50 * -9 +
383: iStack480 * -9 + iVar44 * 9 + iStack384) - iStack416) * uVar11;
384: if (-1 < lVar12) goto LAB_00128581;
385: LAB_00129a9f:
386: iVar36 = (int)((lVar27 - lVar12) / lVar14);
387: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
388: iVar36 = iVar35 + -1;
389: }
390: sVar8 = -(short)iVar36;
391: }
392: else {
393: lVar12 = (long)((((((((iStack408 + iVar42 + iStack480 * -10 + iVar44 * 10) -
394: iStack452) - iStack412) + iVar45) - iStack436) + iStack440) -
395: iStack380) + iStack476 * 10 + iVar50 * -10) * uVar11;
396: if (lVar12 < 0) goto LAB_00129a9f;
397: LAB_00128581:
398: lVar12 = (lVar12 + lVar27) / lVar14;
399: sVar8 = (short)lVar12;
400: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12))
401: {
402: sVar8 = (short)iVar35 + -1;
403: }
404: }
405: psVar2[9] = sVar8;
406: }
407: iVar35 = *(int *)(lVar53 + 0x14);
408: if ((iVar35 != 0) && (psVar2[2] == 0)) {
409: if (bVar6) {
410: lVar12 = (long)(iVar47 * 7 +
411: iVar34 * 7 + iVar51 * -5 + iStack476 * 2 + iVar50 * 2 + iStack392
412: + iStack468 * -0xe + iStack424 + iStack480 * 2 + iVar22 * -5 +
413: iVar44 * 2) * uVar11;
414: if (-1 < lVar12) goto LAB_0012863b;
415: LAB_00129a0e:
416: iVar36 = (int)((lVar28 - lVar12) / lVar48);
417: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
418: iVar36 = iVar35 + -1;
419: }
420: sVar8 = -(short)iVar36;
421: }
422: else {
423: lVar12 = (long)(((iVar34 * 0xd - iStack392) + iStack468 * -0x18 + iVar47 * 0xd) -
424: iStack424) * uVar11;
425: if (lVar12 < 0) goto LAB_00129a0e;
426: LAB_0012863b:
427: lVar12 = (lVar12 + lVar28) / lVar48;
428: sVar8 = (short)lVar12;
429: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12))
430: {
431: sVar8 = (short)iVar35 + -1;
432: }
433: }
434: psVar2[2] = sVar8;
435: }
436: if (bVar6) {
437: iVar35 = *(int *)(lVar53 + 0x18);
438: if ((iVar35 != 0) && (psVar2[3] == 0)) {
439: lVar12 = (long)(((iStack476 - iVar50) + iVar34 * 2 + iVar47 * -2 + iStack480) -
440: iVar44) * uVar11;
441: if (lVar12 < 0) {
442: iVar36 = (int)((lVar15 - lVar12) / lVar29);
443: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
444: iVar36 = iVar35 + -1;
445: }
446: sVar8 = -(short)iVar36;
447: }
448: else {
449: lVar12 = (lVar12 + lVar15) / lVar29;
450: sVar8 = (short)lVar12;
451: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12)
452: ) {
453: sVar8 = (short)iVar35 + -1;
454: }
455: }
456: psVar2[3] = sVar8;
457: }
458: iVar35 = *(int *)(lVar53 + 0x1c);
459: if ((iVar35 != 0) && (psVar2[10] == 0)) {
460: lVar12 = (long)((((iStack476 + iVar51 * -3 + iVar50) - iStack480) + iVar22 * 3) -
461: iVar44) * uVar11;
462: if (lVar12 < 0) {
463: iVar36 = (int)((lVar16 - lVar12) / lVar30);
464: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
465: iVar36 = iVar35 + -1;
466: }
467: sVar8 = -(short)iVar36;
468: }
469: else {
470: lVar12 = (lVar12 + lVar16) / lVar30;
471: sVar8 = (short)lVar12;
472: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12)
473: ) {
474: sVar8 = (short)iVar35 + -1;
475: }
476: }
477: psVar2[10] = sVar8;
478: }
479: iVar35 = *(int *)(lVar53 + 0x20);
480: if ((iVar35 != 0) && (psVar2[0x11] == 0)) {
481: lVar12 = (long)(((iStack476 - iVar50) + iVar34 * -3 + iVar47 * 3 + iStack480) -
482: iVar44) * uVar11;
483: if (lVar12 < 0) {
484: iVar36 = (int)((lVar17 - lVar12) / lVar31);
485: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
486: iVar36 = iVar35 + -1;
487: }
488: sVar8 = -(short)iVar36;
489: }
490: else {
491: lVar12 = (lVar12 + lVar17) / lVar31;
492: sVar8 = (short)lVar12;
493: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12)
494: ) {
495: sVar8 = (short)iVar35 + -1;
496: }
497: }
498: psVar2[0x11] = sVar8;
499: }
500: iVar35 = *(int *)(lVar53 + 0x24);
501: if ((iVar35 != 0) && (psVar2[0x18] == 0)) {
502: lVar12 = (long)((((iStack476 + iVar51 * 2 + iVar50) - iStack480) + iVar22 * -2) -
503: iVar44) * uVar11;
504: if (lVar12 < 0) {
505: iVar36 = (int)((lVar18 - lVar12) / lVar32);
506: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= iVar36)) {
507: iVar36 = iVar35 + -1;
508: }
509: sVar8 = -(short)iVar36;
510: }
511: else {
512: lVar12 = (lVar12 + lVar18) / lVar32;
513: sVar8 = (short)lVar12;
514: if ((0 < iVar35) && (iVar35 = 1 << ((byte)iVar35 & 0x1f), iVar35 <= (int)lVar12)
515: ) {
516: sVar8 = (short)iVar35 + -1;
517: }
518: }
519: psVar2[0x18] = sVar8;
520: }
521: lVar12 = (long)(((((((iStack440 * -3 - (iStack452 * 3 + iStack388 + iStack456 * 4))
522: - iStack420) + iStack380 * -3 + iStack476 * 3 + iVar51 * 0x15 +
523: iVar50 * 3 + iStack408 * -3 + iStack392 * -4 + iVar34 * 0x15 +
524: iStack468 * 0x4c + iVar47 * 0x15 + iStack424 * -4 + iVar42 * -3
525: + iStack480 * 3 + iVar22 * 0x15 + iVar44 * 3 + iStack412 * -3) -
526: iStack384) + iVar45 * -3 + iStack472 * -4 + iStack436 * -3) -
527: iStack416) * 2) * uVar11;
528: if (lVar12 < 0) {
529: sVar8 = -(short)((lVar19 - lVar12) / lVar33);
530: }
531: else {
532: sVar8 = (short)((lVar12 + lVar19) / lVar33);
533: }
534: *psVar2 = sVar8;
535: }
536: (*pcVar4)(param_1,lStack504,psVar2);
537: psStack448 = psStack448 + 0x40;
538: lVar12 = *(long *)(param_1 + 0x220);
539: lStack376 = lStack376 + 0x80;
540: uVar13 = *(uint *)(lVar12 + 0x44 + lVar23 * 4);
541: iStack388 = iStack452;
542: iStack452 = iStack456;
543: iStack456 = iStack440;
544: iStack380 = iStack476;
545: iStack472 = iStack436;
546: iVar35 = iStack468;
547: iStack476 = iVar51;
548: iStack468 = iVar47;
549: iStack392 = iVar34;
550: iStack384 = iVar45;
551: iVar42 = iStack480;
552: iVar45 = iVar7;
553: } while (uVar52 <= uVar13);
554: }
555: uVar49 = 1;
556: if (uStack200 != 1) {
557: do {
558: plStack336 = plStack296 + 1;
559: uVar52 = *(uint *)(lVar12 + 0xc + (lVar23 + 4) * 4);
560: uVar38 = (ulong)uVar52;
561: lVar39 = uVar38 * 0x80;
562: psStack464 = (short *)(*plStack336 + lVar39);
563: psVar41 = (short *)(*plStack296 + lVar39);
564: if ((uVar49 != 1) || (psStack288 = psVar41, 1 < *(uint *)(param_1 + 0xb8))) {
565: psStack288 = (short *)(plStack296[-1] + lVar39);
566: }
567: if (((int)uVar49 < (int)(uStack200 - 1)) ||
568: (*(uint *)(param_1 + 0xb8) <= uVar9 && uVar9 != *(uint *)(param_1 + 0xb8))) {
569: psStack328 = (short *)(plStack296[2] + lVar39);
570: if (iVar21 <= (int)uVar49) goto LAB_00129e25;
571: LAB_00128a5e:
572: psStack304 = (short *)(lVar39 + plStack296[3]);
573: }
574: else {
575: psStack328 = psStack464;
576: if ((int)uVar49 < iVar21) goto LAB_00128a5e;
577: LAB_00129e25:
578: psStack304 = psStack328;
579: if (*(uint *)(param_1 + 0xb8) <= uVar20 && uVar20 != *(uint *)(param_1 + 0xb8))
580: goto LAB_00128a5e;
581: }
582: iStack472 = (int)*psStack288;
583: iStack468 = (int)*psStack304;
584: iStack412 = (int)*psVar41;
585: iStack424 = (int)*psStack464;
586: uVar46 = *(int *)(lStack504 + 0x1c) - 1;
587: iStack408 = (int)*psStack328;
588: if (uVar52 <= uVar13) {
589: lStack376 = 0x80;
590: iVar45 = iStack408;
591: iVar50 = iStack412;
592: iVar35 = iStack424;
593: iVar22 = iStack408;
594: iStack476 = iStack412;
595: iStack456 = iStack424;
596: iStack452 = iStack472;
597: iStack420 = iStack472;
598: iStack416 = iStack468;
599: iStack392 = iStack424;
600: iStack388 = iStack468;
601: iStack384 = iStack472;
602: iStack380 = iStack412;
603: iVar42 = iStack408;
604: iVar44 = iStack468;
605: do {
606: iStack480 = iVar22;
607: iVar34 = iVar35;
608: iVar51 = iVar50;
609: iVar22 = iVar45;
610: iVar35 = iStack452;
611: iVar7 = iStack468;
612: FUN_00148a60(psStack464,psVar2,1);
613: uVar52 = (uint)uVar38;
614: if ((*(uint *)(*(long *)(param_1 + 0x220) + 0xc + (lVar23 + 4) * 4) == uVar52) &&
615: (uVar52 < uVar46)) {
616: iStack436 = (int)*(short *)((long)psStack288 + lStack376);
617: iVar50 = (int)*(short *)((long)psVar41 + lStack376);
618: iVar47 = (int)psStack464[0x40];
619: iVar45 = (int)*(short *)((long)psStack328 + lStack376);
620: iStack440 = (int)*(short *)((long)psStack304 + lStack376);
621: }
622: else {
623: iStack440 = iStack416;
624: iStack436 = iStack420;
625: iVar47 = iStack424;
626: iVar50 = iStack412;
627: iVar45 = iStack408;
628: }
629: uVar52 = uVar52 + 1;
630: uVar38 = (ulong)uVar52;
631: if (uVar52 < uVar46) {
632: iStack420 = (int)*(short *)((long)psStack288 + lStack376 + 0x80);
633: iStack412 = (int)*(short *)((long)psVar41 + lStack376 + 0x80);
634: iStack424 = (int)psStack464[0x80];
635: iStack408 = (int)*(short *)((long)psStack328 + lStack376 + 0x80);
636: iStack416 = (int)*(short *)((long)psStack304 + lStack376 + 0x80);
637: }
638: iVar36 = *(int *)(lVar53 + 4);
639: if ((iVar36 != 0) && (psVar2[1] == 0)) {
640: if (bVar6) {
641: lVar12 = (long)((((((iStack436 - iStack384) - iStack452) + iStack420 +
642: iStack380 * -3 + iStack476 * 0xd + iVar50 * -0xd +
643: iStack412 * 3 + iStack392 * -3 + iVar34 * 0x26 +
644: iVar47 * -0x26 + iStack424 * 3 + iVar42 * -3 +
645: iStack480 * 0xd + iVar45 * -0xd + iStack408 * 3) -
646: iStack388) - iVar44) + iStack440 + iStack416) * uVar11;
647: if (-1 < lVar12) goto LAB_00128df8;
648: LAB_001297c5:
649: iVar10 = (int)((lVar24 - lVar12) / lVar43);
650: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10)) {
651: iVar10 = iVar36 + -1;
652: }
653: sVar8 = -(short)iVar10;
654: }
655: else {
656: lVar12 = (long)(iStack424 * 7 +
657: iVar47 * -0x32 + iStack392 * -7 + iVar34 * 0x32) * uVar11;
658: if (lVar12 < 0) goto LAB_001297c5;
659: LAB_00128df8:
660: lVar12 = (lVar12 + lVar24) / lVar43;
661: sVar8 = (short)lVar12;
662: if ((0 < iVar36) &&
663: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
664: sVar8 = (short)iVar36 + -1;
665: }
666: }
667: psVar2[1] = sVar8;
668: }
669: iVar36 = *(int *)(lVar53 + 8);
670: if ((iVar36 != 0) && (psVar2[8] == 0)) {
671: if (bVar6) {
672: lVar12 = (long)(((((((iStack452 * -3 - iStack384) + iStack472 * -3 +
673: iStack436 * -3) - iStack420) - iStack380) +
674: iStack476 * 0xd + iVar51 * 0x26 + iVar50 * 0xd) - iStack412)
675: + iVar42 + iStack480 * -0xd + iVar22 * -0x26 + iVar45 * -0xd +
676: iStack408 + iStack388 + iVar44 * 3 + iStack468 * 3 +
677: iStack440 * 3 + iStack416) * uVar11;
678: if (-1 < lVar12) goto LAB_00128ef9;
679: LAB_001298b2:
680: iVar10 = (int)((lVar25 - lVar12) / lVar40);
681: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10)) {
682: iVar10 = iVar36 + -1;
683: }
684: sVar8 = -(short)iVar10;
685: }
686: else {
687: lVar12 = (long)(iStack468 * 7 +
688: iVar22 * -0x32 + iStack472 * -7 + iVar51 * 0x32) * uVar11;
689: if (lVar12 < 0) goto LAB_001298b2;
690: LAB_00128ef9:
691: lVar12 = (lVar12 + lVar25) / lVar40;
692: sVar8 = (short)lVar12;
693: if ((0 < iVar36) &&
694: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
695: sVar8 = (short)iVar36 + -1;
696: }
697: }
698: psVar2[8] = sVar8;
699: }
700: iVar36 = *(int *)(lVar53 + 0xc);
701: if ((iVar36 != 0) && (psVar2[0x10] == 0)) {
702: if (bVar6) {
703: lVar12 = (long)(iVar22 * 7 +
704: iStack472 + iStack476 * 2 + iVar51 * 7 + iVar50 * 2 +
705: iVar34 * -5 + iStack456 * -0xe + iVar47 * -5 + iStack480 * 2 +
706: iVar45 * 2 + iStack468) * uVar11;
707: if (-1 < lVar12) goto LAB_00128fae;
708: LAB_0012983b:
709: iVar10 = (int)((lVar26 - lVar12) / lVar37);
710: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10)) {
711: iVar10 = iVar36 + -1;
712: }
713: sVar8 = -(short)iVar10;
714: }
715: else {
716: lVar12 = (long)(((iVar51 * 0xd - iStack472) + iStack456 * -0x18 + iVar22 * 0xd
717: ) - iStack468) * uVar11;
718: if (lVar12 < 0) goto LAB_0012983b;
719: LAB_00128fae:
720: lVar12 = (lVar12 + lVar26) / lVar37;
721: sVar8 = (short)lVar12;
722: if ((0 < iVar36) &&
723: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
724: sVar8 = (short)iVar36 + -1;
725: }
726: }
727: psVar2[0x10] = sVar8;
728: }
729: iVar36 = *(int *)(lVar53 + 0x10);
730: if ((iVar36 != 0) && (psVar2[9] == 0)) {
731: if (bVar6) {
732: lVar12 = (long)(((iStack420 - iStack384) + iStack476 * 9 + iVar50 * -9 +
733: iStack480 * -9 + iVar45 * 9 + iStack388) - iStack416) *
734: uVar11;
735: if (-1 < lVar12) goto LAB_00129041;
736: LAB_001296d7:
737: iVar10 = (int)((lVar27 - lVar12) / lVar14);
738: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10)) {
739: iVar10 = iVar36 + -1;
740: }
741: sVar8 = -(short)iVar10;
742: }
743: else {
744: lVar12 = (long)((((((((iStack412 + iVar42 + iStack480 * -10 + iVar45 * 10) -
745: iStack452) - iStack408) + iVar44) - iStack440) +
746: iStack436) - iStack380) + iStack476 * 10 + iVar50 * -10) *
747: uVar11;
748: if (lVar12 < 0) goto LAB_001296d7;
749: LAB_00129041:
750: lVar12 = (lVar12 + lVar27) / lVar14;
751: sVar8 = (short)lVar12;
752: if ((0 < iVar36) &&
753: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
754: sVar8 = (short)iVar36 + -1;
755: }
756: }
757: psVar2[9] = sVar8;
758: }
759: iVar36 = *(int *)(lVar53 + 0x14);
760: if ((iVar36 != 0) && (psVar2[2] == 0)) {
761: if (bVar6) {
762: lVar12 = (long)(iVar47 * 7 +
763: iVar34 * 7 +
764: iVar51 * -5 + iStack476 * 2 + iVar50 * 2 + iStack392 +
765: iStack456 * -0xe + iStack424 + iStack480 * 2 + iVar22 * -5 +
766: iVar45 * 2) * uVar11;
767: if (-1 < lVar12) goto LAB_001290fc;
768: LAB_00129646:
769: iVar10 = (int)((lVar28 - lVar12) / lVar48);
770: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10)) {
771: iVar10 = iVar36 + -1;
772: }
773: sVar8 = -(short)iVar10;
774: }
775: else {
776: lVar12 = (long)(((iVar34 * 0xd - iStack392) + iStack456 * -0x18 + iVar47 * 0xd
777: ) - iStack424) * uVar11;
778: if (lVar12 < 0) goto LAB_00129646;
779: LAB_001290fc:
780: lVar12 = (lVar12 + lVar28) / lVar48;
781: sVar8 = (short)lVar12;
782: if ((0 < iVar36) &&
783: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
784: sVar8 = (short)iVar36 + -1;
785: }
786: }
787: psVar2[2] = sVar8;
788: }
789: if (bVar6) {
790: iVar36 = *(int *)(lVar53 + 0x18);
791: if ((iVar36 != 0) && (psVar2[3] == 0)) {
792: lVar12 = (long)(((iStack476 - iVar50) + iVar34 * 2 + iVar47 * -2 + iStack480)
793: - iVar45) * uVar11;
794: if (lVar12 < 0) {
795: iVar10 = (int)((lVar15 - lVar12) / lVar29);
796: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10))
797: {
798: iVar10 = iVar36 + -1;
799: }
800: sVar8 = -(short)iVar10;
801: }
802: else {
803: lVar12 = (lVar12 + lVar15) / lVar29;
804: sVar8 = (short)lVar12;
805: if ((0 < iVar36) &&
806: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
807: sVar8 = (short)iVar36 + -1;
808: }
809: }
810: psVar2[3] = sVar8;
811: }
812: iVar36 = *(int *)(lVar53 + 0x1c);
813: if ((iVar36 != 0) && (psVar2[10] == 0)) {
814: lVar12 = (long)((((iStack476 + iVar51 * -3 + iVar50) - iStack480) + iVar22 * 3
815: ) - iVar45) * uVar11;
816: if (lVar12 < 0) {
817: iVar10 = (int)((lVar16 - lVar12) / lVar30);
818: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10))
819: {
820: iVar10 = iVar36 + -1;
821: }
822: sVar8 = -(short)iVar10;
823: }
824: else {
825: lVar12 = (lVar12 + lVar16) / lVar30;
826: sVar8 = (short)lVar12;
827: if ((0 < iVar36) &&
828: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
829: sVar8 = (short)iVar36 + -1;
830: }
831: }
832: psVar2[10] = sVar8;
833: }
834: iVar36 = *(int *)(lVar53 + 0x20);
835: if ((iVar36 != 0) && (psVar2[0x11] == 0)) {
836: lVar12 = (long)(((iStack476 - iVar50) + iVar34 * -3 + iVar47 * 3 + iStack480)
837: - iVar45) * uVar11;
838: if (lVar12 < 0) {
839: iVar10 = (int)((lVar17 - lVar12) / lVar31);
840: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10))
841: {
842: iVar10 = iVar36 + -1;
843: }
844: sVar8 = -(short)iVar10;
845: }
846: else {
847: lVar12 = (lVar12 + lVar17) / lVar31;
848: sVar8 = (short)lVar12;
849: if ((0 < iVar36) &&
850: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
851: sVar8 = (short)iVar36 + -1;
852: }
853: }
854: psVar2[0x11] = sVar8;
855: }
856: iVar36 = *(int *)(lVar53 + 0x24);
857: if ((iVar36 != 0) && (psVar2[0x18] == 0)) {
858: lVar12 = (long)((((iStack476 + iVar51 * 2 + iVar50) - iStack480) + iVar22 * -2
859: ) - iVar45) * uVar11;
860: if (lVar12 < 0) {
861: iVar10 = (int)((lVar18 - lVar12) / lVar32);
862: if ((0 < iVar36) && (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= iVar10))
863: {
864: iVar10 = iVar36 + -1;
865: }
866: sVar8 = -(short)iVar10;
867: }
868: else {
869: lVar12 = (lVar12 + lVar18) / lVar32;
870: sVar8 = (short)lVar12;
871: if ((0 < iVar36) &&
872: (iVar36 = 1 << ((byte)iVar36 & 0x1f), iVar36 <= (int)lVar12)) {
873: sVar8 = (short)iVar36 + -1;
874: }
875: }
876: psVar2[0x18] = sVar8;
877: }
878: lVar12 = (long)(((((((iStack436 * -3 -
879: (iStack452 * 3 + iStack384 + iStack472 * 4)) - iStack420) +
880: iStack380 * -3 + iStack476 * 3 + iVar51 * 0x15 + iVar50 * 3
881: + iStack412 * -3 + iStack392 * -4 + iVar34 * 0x15 +
882: iStack456 * 0x4c + iVar47 * 0x15 + iStack424 * -4 +
883: iVar42 * -3 + iStack480 * 3 + iVar22 * 0x15 + iVar45 * 3 +
884: iStack408 * -3) - iStack388) + iVar44 * -3 + iStack468 * -4 +
885: iStack440 * -3) - iStack416) * 2) * uVar11;
886: if (lVar12 < 0) {
887: sVar8 = -(short)((lVar19 - lVar12) / lVar33);
888: }
889: else {
890: sVar8 = (short)((lVar12 + lVar19) / lVar33);
891: }
892: *psVar2 = sVar8;
893: }
894: (*pcVar4)(param_1,lStack504,psVar2);
895: lVar12 = *(long *)(param_1 + 0x220);
896: psStack464 = psStack464 + 0x40;
897: uVar13 = *(uint *)(lVar12 + 0x44 + lVar23 * 4);
898: iStack452 = iStack472;
899: iStack384 = iVar35;
900: lStack376 = lStack376 + 0x80;
901: iStack472 = iStack436;
902: iStack380 = iStack476;
903: iStack468 = iStack440;
904: iVar35 = iStack456;
905: iStack476 = iVar51;
906: iStack456 = iVar47;
907: iStack392 = iVar34;
908: iStack388 = iVar44;
909: iVar42 = iStack480;
910: iVar44 = iVar7;
911: } while (uVar52 <= uVar13);
912: }
913: uVar49 = uVar49 + 1;
914: plStack296 = plStack336;
915: } while (uStack200 != uVar49);
916: }
917: iVar45 = *(int *)(param_1 + 0x38);
918: uVar49 = *(uint *)(param_1 + 0xb8);
919: }
920: }
921: iStack124 = iStack124 + 1;
922: lStack504 = lStack504 + 0x60;
923: lStack120 = lStack120 + 8;
924: } while (iStack124 < iVar45);
925: }
926: *(uint *)(param_1 + 0xb8) = uVar49 + 1;
927: return (ulong)((*(uint *)(param_1 + 0x1a4) <= uVar49 + 1) + 3);
928: }
929: 
