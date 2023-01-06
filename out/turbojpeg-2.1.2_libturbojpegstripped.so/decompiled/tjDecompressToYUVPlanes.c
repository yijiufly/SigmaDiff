1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined4
5: tjDecompressToYUVPlanes
6: (long param_1,long param_2,long param_3,long *param_4,int param_5,long param_6,int param_7
7: ,uint param_8)
8: 
9: {
10: long *plVar1;
11: undefined8 uVar2;
12: int iVar3;
13: int iVar4;
14: int iVar5;
15: undefined4 uVar6;
16: int iVar7;
17: undefined4 *puVar8;
18: undefined8 *puVar9;
19: long *plVar10;
20: void **ppvVar11;
21: char *pcVar12;
22: int iVar13;
23: int iVar14;
24: void *pvVar15;
25: int iVar16;
26: long lVar17;
27: ulong uVar18;
28: long lVar19;
29: char *pcVar20;
30: int iVar21;
31: uint uVar22;
32: uint uVar23;
33: int iVar24;
34: int iVar25;
35: void **ppvVar26;
36: int iVar27;
37: uint uVar28;
38: int iVar29;
39: int iVar30;
40: void **ppvVar31;
41: long lVar32;
42: void *pvVar33;
43: long in_FS_OFFSET;
44: byte bVar34;
45: void *pvVar35;
46: void *pvVar36;
47: void *pvStack1160;
48: undefined4 uStack1136;
49: int iStack1008;
50: int iStack996;
51: int iStack980;
52: code *pcStack600;
53: undefined auStack592 [16];
54: undefined8 uStack576;
55: long lStack568;
56: int aiStack556 [12];
57: int aiStack508 [13];
58: int aiStack456 [11];
59: int aiStack412 [12];
60: int aiStack364 [5];
61: int iStack344;
62: int iStack340;
63: int iStack336;
64: int iStack332;
65: int iStack328;
66: int iStack324;
67: long lStack320;
68: undefined auStack312 [16];
69: undefined auStack296 [16];
70: undefined auStack280 [16];
71: undefined auStack264 [16];
72: undefined auStack248 [8];
73: void *pvStack240;
74: undefined auStack232 [16];
75: undefined auStack216 [16];
76: undefined auStack200 [16];
77: undefined auStack184 [16];
78: undefined auStack168 [16];
79: long lStack152;
80: long lStack144;
81: long lStack136;
82: long lStack128;
83: long lStack120;
84: long lStack112;
85: long lStack104;
86: long lStack96;
87: long lStack88;
88: long lStack80;
89: long lStack64;
90: 
91: bVar34 = 0;
92: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
93: if (param_1 == 0) {
94: puVar9 = (undefined8 *)__tls_get_addr(&PTR_00398fc0,0);
95: *puVar9 = 0x2064696c61766e49;
96: *(undefined4 *)(puVar9 + 1) = 0x646e6168;
97: *(undefined2 *)((long)puVar9 + 0xc) = 0x656c;
98: *(undefined *)((long)puVar9 + 0xe) = 0;
99: uVar6 = 0xffffffff;
100: goto LAB_00155ee3;
101: }
102: lVar17 = param_1 + 0x208;
103: *(undefined4 *)(param_1 + 0x5f8) = 0;
104: *(undefined4 *)(param_1 + 0x6d0) = 0;
105: auStack232 = (undefined  [16])0x0;
106: *(uint *)(param_1 + 0x5fc) = (int)param_8 >> 0xd & 1;
107: auStack216 = (undefined  [16])0x0;
108: auStack200 = (undefined  [16])0x0;
109: auStack184 = (undefined  [16])0x0;
110: auStack168 = (undefined  [16])0x0;
111: auStack312 = (undefined  [16])0x0;
112: auStack296 = (undefined  [16])0x0;
113: auStack280 = (undefined  [16])0x0;
114: auStack264 = (undefined  [16])0x0;
115: _auStack248 = (undefined  [16])0x0;
116: if ((*(byte *)(param_1 + 0x600) & 2) == 0) {
117: *(undefined8 *)(param_1 + 0x648) = 0x72706d6f63656420;
118: *(undefined4 *)(param_1 + 0x650) = 0x69737365;
119: *(undefined2 *)(param_1 + 0x654) = 0x6e6f;
120: *(undefined *)(param_1 + 0x656) = 0;
121: *(undefined4 *)(param_1 + 0x6d0) = 1;
122: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
123: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
124: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
125: *(undefined8 *)(param_1 + 0x620) = 0x6174736e49203a29;
126: *(undefined8 *)(param_1 + 0x628) = 0x207361682065636e;
127: *(undefined8 *)(param_1 + 0x630) = 0x6e65656220746f6e;
128: *(undefined8 *)(param_1 + 0x638) = 0x6c616974696e6920;
129: *(undefined8 *)(param_1 + 0x640) = 0x726f662064657a69;
130: puVar8 = (undefined4 *)
131: __tls_get_addr(0x6c616974696e6920,0x207361682065636e,0x2873656e616c5056,
132: 0x706d6f6365446a74,&PTR_00398fc0,0);
133: *(undefined8 *)(puVar8 + 0x10) = 0x72706d6f63656420;
134: puVar8[0x12] = 0x69737365;
135: *(undefined2 *)(puVar8 + 0x13) = 0x6e6f;
136: *(undefined *)((long)puVar8 + 0x4e) = 0;
137: pvStack1160 = (void *)0x0;
138: uStack1136 = 0xffffffff;
139: *puVar8 = 0x65446a74;
140: puVar8[1] = 0x706d6f63;
141: puVar8[2] = 0x73736572;
142: puVar8[3] = 0x55596f54;
143: puVar8[4] = 0x616c5056;
144: puVar8[5] = 0x2873656e;
145: puVar8[6] = 0x49203a29;
146: puVar8[7] = 0x6174736e;
147: puVar8[8] = 0x2065636e;
148: puVar8[9] = 0x20736168;
149: puVar8[10] = 0x20746f6e;
150: puVar8[0xb] = 0x6e656562;
151: puVar8[0xc] = 0x696e6920;
152: puVar8[0xd] = 0x6c616974;
153: puVar8[0xe] = 0x64657a69;
154: puVar8[0xf] = 0x726f6620;
155: }
156: else {
157: if ((((param_3 == 0 || param_4 == (long *)0x0) || (param_2 == 0)) || (*param_4 == 0)) ||
158: ((param_5 < 0 || (param_7 < 0)))) {
159: *(undefined8 *)(param_1 + 0x628) = 0x6d75677261206469;
160: *(undefined4 *)(param_1 + 0x630) = 0x746e65;
161: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
162: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
163: *(undefined4 *)(param_1 + 0x6d0) = 1;
164: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
165: *(undefined8 *)(param_1 + 0x620) = 0x6c61766e49203a29;
166: puVar8 = (undefined4 *)__tls_get_addr(0x2873656e616c5056,0x706d6f6365446a74,&PTR_00398fc0);
167: *(undefined8 *)(puVar8 + 8) = 0x6d75677261206469;
168: puVar8[10] = 0x746e65;
169: pvStack1160 = (void *)0x0;
170: uStack1136 = 0xffffffff;
171: *puVar8 = 0x65446a74;
172: puVar8[1] = 0x706d6f63;
173: puVar8[2] = 0x73736572;
174: puVar8[3] = 0x55596f54;
175: puVar8[4] = 0x616c5056;
176: puVar8[5] = 0x2873656e;
177: puVar8[6] = 0x49203a29;
178: puVar8[7] = 0x6c61766e;
179: }
180: else {
181: if ((param_8 & 8) == 0) {
182: if ((param_8 & 0x10) == 0) {
183: if ((param_8 & 0x20) != 0) {
184: putenv("JSIMD_FORCESSE2=1");
185: }
186: }
187: else {
188: putenv("JSIMD_FORCESSE=1");
189: }
190: }
191: else {
192: putenv("JSIMD_FORCEMMX=1");
193: }
194: if ((param_8 & 0x8000) == 0) {
195: *(undefined8 *)(param_1 + 0x218) = 0;
196: }
197: else {
198: uStack576 = 0;
199: pcStack600 = FUN_0014eb60;
200: auStack592 = (undefined  [16])0x0;
201: *(code ***)(param_1 + 0x218) = &pcStack600;
202: lStack568 = param_1;
203: }
204: pvStack1160 = (void *)0x0;
205: iStack1008 = 0;
206: iStack996 = 0;
207: uStack1136 = 0;
208: iVar4 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
209: if (iVar4 == 0) {
210: if (*(int *)(param_1 + 0x604) == 0) {
211: FUN_00167270(lVar17,param_2,param_3);
212: FUN_00125330(lVar17,1);
213: }
214: *(undefined4 *)(param_1 + 0x604) = 0;
215: if (*(long *)(param_1 + 0x240) == 0x100000001) {
216: iStack980 = 3;
217: LAB_00155960:
218: iVar5 = *(int *)(param_1 + 0x238);
219: iVar16 = *(int *)(param_1 + 0x23c);
220: if (param_5 == 0) {
221: param_5 = iVar5;
222: }
223: iVar7 = iVar16;
224: if (param_7 != 0) {
225: iVar7 = param_7;
226: }
227: if ((param_5 < iVar5 * 2) || (iVar7 < iVar16 * 2)) {
228: iVar13 = iVar5 * 0xf + 7;
229: if (iVar13 < 0) {
230: iVar13 = iVar5 * 0xf + 0xe;
231: }
232: iVar14 = iVar16 * 0xf + 7;
233: if (iVar14 < 0) {
234: iVar14 = iVar16 * 0xf + 0xe;
235: }
236: if ((param_5 < iVar13 >> 3) || (iVar7 < iVar14 >> 3)) {
237: iVar13 = iVar5 * 7;
238: iVar14 = iVar13 + 6;
239: if (-1 < iVar13 + 3) {
240: iVar14 = iVar13 + 3;
241: }
242: iVar25 = iVar16 * 7;
243: iVar21 = iVar25 + 6;
244: if (-1 < iVar25 + 3) {
245: iVar21 = iVar25 + 3;
246: }
247: if ((param_5 < iVar14 >> 2) || (iVar7 < iVar21 >> 2)) {
248: iVar21 = iVar5 * 0xd + 7;
249: iVar14 = iVar5 * 0xd + 0xe;
250: if (-1 < iVar21) {
251: iVar14 = iVar21;
252: }
253: iVar21 = iVar16 * 0xd + 7;
254: if (iVar21 < 0) {
255: iVar21 = iVar16 * 0xd + 0xe;
256: }
257: if ((param_5 < iVar14 >> 3) || (iVar7 < iVar21 >> 3)) {
258: iVar21 = iVar5 * 3;
259: iVar14 = iVar16 * 3;
260: if ((param_5 < (iVar21 + 1) / 2) || (iVar7 < (iVar14 + 1) / 2)) {
261: iVar27 = iVar5 * 0xb + 7;
262: iVar24 = iVar5 * 0xb + 0xe;
263: if (-1 < iVar27) {
264: iVar24 = iVar27;
265: }
266: iVar27 = iVar16 * 0xb + 7;
267: if (iVar27 < 0) {
268: iVar27 = iVar16 * 0xb + 0xe;
269: }
270: if ((param_5 < iVar24 >> 3) || (iVar7 < iVar27 >> 3)) {
271: iVar24 = iVar5 * 5;
272: iVar27 = iVar24 + 6;
273: if (-1 < iVar24 + 3) {
274: iVar27 = iVar24 + 3;
275: }
276: iVar3 = iVar16 * 5;
277: iVar29 = iVar3 + 6;
278: if (-1 < iVar3 + 3) {
279: iVar29 = iVar3 + 3;
280: }
281: if ((param_5 < iVar27 >> 2) || (iVar7 < iVar29 >> 2)) {
282: iVar27 = iVar5 * 9 + 7;
283: if (iVar27 < 0) {
284: iVar27 = iVar5 * 9 + 0xe;
285: }
286: iVar30 = iVar16 * 9 + 7;
287: iVar29 = iVar16 * 9 + 0xe;
288: if (-1 < iVar30) {
289: iVar29 = iVar30;
290: }
291: if ((param_5 < iVar27 >> 3) || (iVar7 < iVar29 >> 3)) {
292: if ((param_5 < iVar5) || (iVar7 < iVar16)) {
293: iVar27 = iVar13 + 7;
294: if (iVar13 + 7 < 0) {
295: iVar27 = iVar13 + 0xe;
296: }
297: iVar13 = iVar25 + 7;
298: if (iVar25 + 7 < 0) {
299: iVar13 = iVar25 + 0xe;
300: }
301: if ((param_5 < iVar27 >> 3) || (iVar7 < iVar13 >> 3)) {
302: iVar13 = iVar21 + 6;
303: if (-1 < iVar21 + 3) {
304: iVar13 = iVar21 + 3;
305: }
306: iVar25 = iVar14 + 6;
307: if (-1 < iVar14 + 3) {
308: iVar25 = iVar14 + 3;
309: }
310: if ((param_5 < iVar13 >> 2) || (iVar7 < iVar25 >> 2)) {
311: iVar13 = iVar24 + 7;
312: if (iVar24 + 7 < 0) {
313: iVar13 = iVar24 + 0xe;
314: }
315: iVar25 = iVar3 + 7;
316: if (iVar3 + 7 < 0) {
317: iVar25 = iVar3 + 0xe;
318: }
319: if ((param_5 < iVar13 >> 3) || (iVar7 < iVar25 >> 3)) {
320: if ((param_5 < (iVar5 + 1) / 2) || (iVar7 < (iVar16 + 1) / 2)) {
321: iVar13 = iVar21 + 7;
322: if (iVar21 + 7 < 0) {
323: iVar13 = iVar21 + 0xe;
324: }
325: iVar25 = iVar14 + 7;
326: if (iVar14 + 7 < 0) {
327: iVar25 = iVar14 + 0xe;
328: }
329: if ((param_5 < iVar13 >> 3) || (iVar7 < iVar25 >> 3)) {
330: iVar13 = iVar5 + 6;
331: if (-1 < iVar5 + 3) {
332: iVar13 = iVar5 + 3;
333: }
334: iVar14 = iVar16 + 6;
335: if (-1 < iVar16 + 3) {
336: iVar14 = iVar16 + 3;
337: }
338: if ((param_5 < iVar13 >> 2) || (iVar7 < iVar14 >> 2)) {
339: iVar13 = iVar5 + 7;
340: if (iVar5 + 7 < 0) {
341: iVar13 = iVar5 + 0xe;
342: }
343: iVar5 = iVar16 + 7;
344: if (iVar16 + 7 < 0) {
345: iVar5 = iVar16 + 0xe;
346: }
347: if ((param_5 < iVar13 >> 3) || (iVar7 < iVar5 >> 3)) {
348: *(undefined8 *)(param_1 + 0x648) = 0x69736e656d696420;
349: *(undefined4 *)(param_1 + 0x650) = 0x736e6f;
350: *(undefined4 *)(param_1 + 0x6d0) = 1;
351: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
352: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
353: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
354: *(undefined8 *)(param_1 + 0x620) = 0x646c756f43203a29;
355: *(undefined8 *)(param_1 + 0x628) = 0x61637320746f6e20;
356: *(undefined8 *)(param_1 + 0x630) = 0x206e776f6420656c;
357: *(undefined8 *)(param_1 + 0x638) = 0x7269736564206f74;
358: *(undefined8 *)(param_1 + 0x640) = 0x6567616d69206465;
359: puVar8 = (undefined4 *)
360: __tls_get_addr(0x7269736564206f74,
361: 0x61637320746f6e20,
362: 0x2873656e616c5056,
363: 0x706d6f6365446a74,&PTR_00398fc0);
364: *(undefined8 *)(puVar8 + 0x10) = 0x69736e656d696420;
365: puVar8[0x12] = 0x736e6f;
366: uStack1136 = 0xffffffff;
367: *puVar8 = 0x65446a74;
368: puVar8[1] = 0x706d6f63;
369: puVar8[2] = 0x73736572;
370: puVar8[3] = 0x55596f54;
371: puVar8[4] = 0x616c5056;
372: puVar8[5] = 0x2873656e;
373: puVar8[6] = 0x43203a29;
374: puVar8[7] = 0x646c756f;
375: puVar8[8] = 0x746f6e20;
376: puVar8[9] = 0x61637320;
377: puVar8[10] = 0x6420656c;
378: puVar8[0xb] = 0x206e776f;
379: puVar8[0xc] = 0x64206f74;
380: puVar8[0xd] = 0x72697365;
381: puVar8[0xe] = 0x69206465;
382: puVar8[0xf] = 0x6567616d;
383: goto LAB_00155e72;
384: }
385: iVar7 = 8;
386: iVar16 = 1;
387: iVar5 = 0xf;
388: }
389: else {
390: iVar7 = 4;
391: iVar16 = 1;
392: iVar5 = 0xe;
393: }
394: }
395: else {
396: iVar7 = 8;
397: iVar16 = 3;
398: iVar5 = 0xd;
399: }
400: }
401: else {
402: iVar7 = 2;
403: iVar16 = 1;
404: iVar5 = 0xc;
405: }
406: }
407: else {
408: iVar7 = 8;
409: iVar16 = 5;
410: iVar5 = 0xb;
411: }
412: }
413: else {
414: iVar7 = 4;
415: iVar16 = 3;
416: iVar5 = 10;
417: }
418: }
419: else {
420: iVar7 = 8;
421: iVar16 = 7;
422: iVar5 = 9;
423: }
424: }
425: else {
426: iVar7 = 1;
427: iVar16 = 1;
428: iVar5 = 8;
429: }
430: }
431: else {
432: iVar7 = 8;
433: iVar16 = 9;
434: iVar5 = 7;
435: }
436: }
437: else {
438: iVar7 = 4;
439: iVar16 = 5;
440: iVar5 = 6;
441: }
442: }
443: else {
444: iVar7 = 8;
445: iVar16 = 0xb;
446: iVar5 = 5;
447: }
448: }
449: else {
450: iVar7 = 2;
451: iVar16 = 3;
452: iVar5 = 4;
453: }
454: }
455: else {
456: iVar7 = 8;
457: iVar16 = 0xd;
458: iVar5 = 3;
459: }
460: }
461: else {
462: iVar7 = 4;
463: iVar16 = 7;
464: iVar5 = 2;
465: }
466: }
467: else {
468: iVar7 = 8;
469: iVar16 = 0xf;
470: iVar5 = 1;
471: }
472: }
473: else {
474: iVar7 = 1;
475: iVar16 = 2;
476: iVar5 = iVar4;
477: }
478: if (*(int *)(param_1 + 0x240) < 4) {
479: *(int *)(param_1 + 0x24c) = iVar16;
480: *(int *)(param_1 + 0x250) = iVar7;
481: FUN_00136eb0(lVar17);
482: iVar13 = *(int *)(param_1 + 0x240);
483: iVar16 = (int)((ulong)(uint)(iVar16 * 8) / (ulong)(long)iVar7);
484: if (0 < iVar13) {
485: uVar18 = 0;
486: do {
487: uVar6 = *(undefined4 *)(param_1 + 0x290);
488: lVar32 = *(long *)(param_1 + 0x338) + uVar18 * 0x60;
489: iVar7 = *(int *)(lVar32 + 0x20);
490: iVar25 = *(int *)(lVar32 + 0x1c) * iVar16;
491: aiStack456[uVar18] = iVar25;
492: iVar13 = tjPlaneWidth(uVar18 & 0xffffffff,uVar6,iStack980);
493: uVar6 = *(undefined4 *)(param_1 + 0x294);
494: aiStack556[uVar18 + 1] = iVar13;
495: iVar14 = tjPlaneHeight(uVar18 & 0xffffffff,uVar6,iStack980);
496: aiStack508[uVar18 + 1] = iVar14;
497: if ((iVar7 * iVar16 != iVar14) || (iVar25 != iVar13)) {
498: iStack1008 = 1;
499: }
500: iVar7 = iVar16 * *(int *)(lVar32 + 0xc);
501: aiStack412[uVar18 + 1] = iVar7;
502: iStack996 = iStack996 + iVar25 * iVar7;
503: plVar10 = (long *)malloc((long)iVar14 << 3);
504: *(long **)(auStack312 + uVar18 * 8) = plVar10;
505: if (plVar10 == (long *)0x0) {
506: *(undefined4 *)(param_1 + 0x638) = 0x6572756c;
507: *(undefined *)(param_1 + 0x63c) = 0;
508: *(undefined4 *)(param_1 + 0x6d0) = 1;
509: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
510: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
511: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
512: *(undefined8 *)(param_1 + 0x620) = 0x726f6d654d203a29;
513: *(undefined8 *)(param_1 + 0x628) = 0x61636f6c6c612079;
514: *(undefined8 *)(param_1 + 0x630) = 0x696166206e6f6974;
515: puVar8 = (undefined4 *)
516: __tls_get_addr(0x61636f6c6c612079,0x2873656e616c5056,0x706d6f6365446a74,
517: &PTR_00398fc0);
518: puVar8[0xc] = 0x6572756c;
519: *(undefined *)(puVar8 + 0xd) = 0;
520: uStack1136 = 0xffffffff;
521: *puVar8 = 0x65446a74;
522: puVar8[1] = 0x706d6f63;
523: puVar8[2] = 0x73736572;
524: puVar8[3] = 0x55596f54;
525: puVar8[4] = 0x616c5056;
526: puVar8[5] = 0x2873656e;
527: puVar8[6] = 0x4d203a29;
528: puVar8[7] = 0x726f6d65;
529: puVar8[8] = 0x6c612079;
530: puVar8[9] = 0x61636f6c;
531: puVar8[10] = 0x6e6f6974;
532: puVar8[0xb] = 0x69616620;
533: goto LAB_00155e72;
534: }
535: lVar32 = param_4[uVar18];
536: if (0 < iVar14) {
537: if (param_6 == 0) {
538: plVar1 = plVar10 + (ulong)(iVar14 - 1) + 1;
539: do {
540: *plVar10 = lVar32;
541: plVar10 = plVar10 + 1;
542: lVar32 = lVar32 + iVar13;
543: } while (plVar1 != plVar10);
544: }
545: else {
546: iVar7 = *(int *)(param_6 + uVar18 * 4);
547: plVar1 = plVar10 + (ulong)(iVar14 - 1) + 1;
548: lVar19 = (long)iVar13;
549: if (iVar7 != 0) {
550: lVar19 = (long)iVar7;
551: }
552: do {
553: *plVar10 = lVar32;
554: plVar10 = plVar10 + 1;
555: lVar32 = lVar32 + lVar19;
556: } while (plVar1 != plVar10);
557: }
558: }
559: iVar13 = *(int *)(param_1 + 0x240);
560: iVar7 = (int)uVar18;
561: uVar18 = uVar18 + 1;
562: } while (iVar7 + 1 < iVar13);
563: }
564: if (iStack1008 != 0) {
565: pvStack1160 = malloc((long)iStack996);
566: if (pvStack1160 == (void *)0x0) {
567: lVar32 = 0x35;
568: pcVar20 = "tjDecompressToYUVPlanes(): Memory allocation failure";
569: pcVar12 = (char *)(param_1 + 0x608);
570: while (lVar32 != 0) {
571: lVar32 = lVar32 + -1;
572: *pcVar12 = *pcVar20;
573: pcVar20 = pcVar20 + (ulong)bVar34 * -2 + 1;
574: pcVar12 = pcVar12 + (ulong)bVar34 * -2 + 1;
575: }
576: *(undefined4 *)(param_1 + 0x6d0) = 1;
577: pcVar12 = (char *)__tls_get_addr(&PTR_00398fc0);
578: lVar32 = 0x35;
579: uStack1136 = 0xffffffff;
580: pcVar20 = "tjDecompressToYUVPlanes(): Memory allocation failure";
581: while (lVar32 != 0) {
582: lVar32 = lVar32 + -1;
583: *pcVar12 = *pcVar20;
584: pcVar20 = pcVar20 + (ulong)bVar34 * -2 + 1;
585: pcVar12 = pcVar12 + (ulong)bVar34 * -2 + 1;
586: }
587: goto LAB_00155e72;
588: }
589: if (0 < iVar13) {
590: lVar32 = 0;
591: pvVar33 = pvStack1160;
592: do {
593: iVar7 = *(int *)((long)aiStack412 + lVar32 + 4);
594: ppvVar11 = (void **)malloc((long)iVar7 << 3);
595: *(void ***)(auStack232 + lVar32 * 2) = ppvVar11;
596: if (ppvVar11 == (void **)0x0) {
597: *(undefined4 *)(param_1 + 0x638) = 0x6572756c;
598: *(undefined *)(param_1 + 0x63c) = 0;
599: *(undefined4 *)(param_1 + 0x6d0) = 1;
600: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
601: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
602: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
603: *(undefined8 *)(param_1 + 0x620) = 0x726f6d654d203a29;
604: *(undefined8 *)(param_1 + 0x628) = 0x61636f6c6c612079;
605: *(undefined8 *)(param_1 + 0x630) = 0x696166206e6f6974;
606: puVar8 = (undefined4 *)
607: __tls_get_addr(0x61636f6c6c612079,0x2873656e616c5056,0x706d6f6365446a74
608: ,&PTR_00398fc0);
609: puVar8[0xc] = 0x6572756c;
610: *(undefined *)(puVar8 + 0xd) = 0;
611: uStack1136 = 0xffffffff;
612: *puVar8 = 0x65446a74;
613: puVar8[1] = 0x706d6f63;
614: puVar8[2] = 0x73736572;
615: puVar8[3] = 0x55596f54;
616: puVar8[4] = 0x616c5056;
617: puVar8[5] = 0x2873656e;
618: puVar8[6] = 0x4d203a29;
619: puVar8[7] = 0x726f6d65;
620: puVar8[8] = 0x6c612079;
621: puVar8[9] = 0x61636f6c;
622: puVar8[10] = 0x6e6f6974;
623: puVar8[0xb] = 0x69616620;
624: goto LAB_00155e72;
625: }
626: if (0 < iVar7) {
627: lVar19 = (long)*(int *)((long)aiStack456 + lVar32);
628: uVar22 = (uint)((ulong)ppvVar11 >> 3) & 1;
629: pvVar15 = pvVar33;
630: iVar14 = iVar4;
631: if (iVar7 - 1U < 9) {
632: LAB_00157342:
633: ppvVar11[iVar14] = pvVar15;
634: if (iVar14 + 1 < iVar7) {
635: ppvVar11[iVar14 + 1] = (void *)((long)pvVar15 + lVar19);
636: pvVar15 = (void *)((long)(void *)((long)pvVar15 + lVar19) + lVar19);
637: if (iVar14 + 2 < iVar7) {
638: ppvVar11[iVar14 + 2] = pvVar15;
639: pvVar15 = (void *)((long)pvVar15 + lVar19);
640: if (iVar14 + 3 < iVar7) {
641: ppvVar11[iVar14 + 3] = pvVar15;
642: pvVar15 = (void *)((long)pvVar15 + lVar19);
643: if (iVar14 + 4 < iVar7) {
644: ppvVar11[iVar14 + 4] = pvVar15;
645: pvVar15 = (void *)((long)pvVar15 + lVar19);
646: if (iVar14 + 5 < iVar7) {
647: ppvVar11[iVar14 + 5] = pvVar15;
648: pvVar15 = (void *)((long)pvVar15 + lVar19);
649: if (iVar14 + 6 < iVar7) {
650: ppvVar11[iVar14 + 6] = pvVar15;
651: pvVar15 = (void *)((long)pvVar15 + lVar19);
652: if (iVar14 + 7 < iVar7) {
653: ppvVar11[iVar14 + 7] = pvVar15;
654: if (iVar14 + 8 < iVar7) {
655: ppvVar11[iVar14 + 8] = (void *)((long)pvVar15 + lVar19);
656: }
657: }
658: }
659: }
660: }
661: }
662: }
663: }
664: }
665: else {
666: if (((ulong)ppvVar11 >> 3 & 1) != 0) {
667: *ppvVar11 = pvVar33;
668: pvVar15 = (void *)((long)pvVar33 + lVar19);
669: iVar14 = iStack1008;
670: }
671: pvVar36 = (void *)(lVar19 + (long)pvVar15);
672: uVar28 = iVar7 - uVar22;
673: uVar23 = 0;
674: ppvVar26 = ppvVar11 + uVar22;
675: pvVar35 = pvVar15;
676: do {
677: uVar23 = uVar23 + 1;
678: *ppvVar26 = pvVar35;
679: ppvVar26[1] = pvVar36;
680: pvVar35 = (void *)((long)pvVar35 + lVar19 * 2);
681: pvVar36 = (void *)((long)pvVar36 + lVar19 * 2);
682: ppvVar26 = ppvVar26 + 2;
683: } while (uVar23 < uVar28 >> 1);
684: uVar22 = uVar28 & 0xfffffffe;
685: pvVar15 = (void *)((long)pvVar15 + (ulong)uVar22 * lVar19);
686: iVar14 = iVar14 + uVar22;
687: if (uVar22 != uVar28) goto LAB_00157342;
688: }
689: pvVar33 = (void *)((long)pvVar33 + lVar19 * ((ulong)(iVar7 - 1U) + 1));
690: }
691: lVar32 = lVar32 + 4;
692: } while ((ulong)(iVar13 - 1) * 4 + 4 != lVar32);
693: }
694: }
695: iVar4 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
696: if (iVar4 != 0) goto LAB_00156032;
697: if ((param_8 & 0x100) != 0) {
698: *(undefined4 *)(param_1 + 0x26c) = 0;
699: }
700: if ((param_8 & 0x800) != 0) {
701: *(undefined4 *)(param_1 + 0x268) = 1;
702: }
703: *(undefined4 *)(param_1 + 0x264) = 1;
704: FUN_00125640();
705: if (0 < *(int *)(param_1 + 0x294)) {
706: iVar7 = *(int *)(param_1 + 0x3a4);
707: iVar13 = *(int *)(param_1 + 0x3a8);
708: do {
709: iVar14 = *(int *)(param_1 + 0x240);
710: if (0 < iVar14) {
711: lVar32 = *(long *)(param_1 + 0x338);
712: if (iStack980 == 2) {
713: iVar25 = *(int *)(&UNK_0018fcc4 + (long)iVar5 * 8);
714: if (iStack1008 == 0) {
715: iVar21 = *(int *)(&DAT_0018fcc0 + (long)iVar5 * 8);
716: iVar24 = *(int *)(&DAT_0018fdd0 + (long)iStack980 * 4);
717: *(int *)(lVar32 + 0x24) = iVar16;
718: iVar25 = (iVar24 * iVar21) / iVar25;
719: *(int *)(lVar32 + 0x40) = (*(int *)(lVar32 + 0xc) * iVar25) / iVar7;
720: lVar19 = *(long *)(param_1 + 0x460);
721: uVar2 = *(undefined8 *)(lVar19 + 8);
722: aiStack364[1] = (*(int *)(lVar32 + 0xc) * iVar4) / iVar7;
723: lStack152 = auStack312._0_8_ + (long)aiStack364[1] * 8;
724: if (iVar14 != 1) {
725: iVar21 = *(int *)(lVar32 + 0x6c);
726: *(int *)(lVar32 + 0x84) = iVar16;
727: *(int *)(lVar32 + 0xa0) = (iVar25 * iVar21) / iVar7;
728: *(undefined8 *)(lVar19 + 0x10) = uVar2;
729: aiStack364[2] = (iVar21 * iVar4) / iVar7;
730: lStack144 = auStack312._8_8_ + (long)aiStack364[2] * 8;
731: if (iVar14 != 2) {
732: iVar21 = *(int *)(lVar32 + 0xcc);
733: *(int *)(lVar32 + 0xe4) = iVar16;
734: *(int *)(lVar32 + 0x100) = (iVar25 * iVar21) / iVar7;
735: *(undefined8 *)(lVar19 + 0x18) = uVar2;
736: aiStack364[3] = (iVar21 * iVar4) / iVar7;
737: lStack136 = auStack296._0_8_ + (long)aiStack364[3] * 8;
738: if (iVar14 != 3) {
739: iVar21 = *(int *)(lVar32 + 300);
740: *(int *)(lVar32 + 0x144) = iVar16;
741: *(int *)(lVar32 + 0x160) = (iVar25 * iVar21) / iVar7;
742: *(undefined8 *)(lVar19 + 0x20) = uVar2;
743: aiStack364[4] = (iVar21 * iVar4) / iVar7;
744: lStack128 = auStack296._8_8_ + (long)aiStack364[4] * 8;
745: if (iVar14 != 4) {
746: iVar21 = *(int *)(lVar32 + 0x18c);
747: *(int *)(lVar32 + 0x1a4) = iVar16;
748: *(int *)(lVar32 + 0x1c0) = (iVar25 * iVar21) / iVar7;
749: *(undefined8 *)(lVar19 + 0x28) = uVar2;
750: iStack344 = (iVar21 * iVar4) / iVar7;
751: lStack120 = auStack280._0_8_ + (long)iStack344 * 8;
752: if (iVar14 != 5) {
753: iVar21 = *(int *)(lVar32 + 0x1ec);
754: *(int *)(lVar32 + 0x204) = iVar16;
755: *(int *)(lVar32 + 0x220) = (iVar25 * iVar21) / iVar7;
756: *(undefined8 *)(lVar19 + 0x30) = uVar2;
757: iStack340 = (iVar21 * iVar4) / iVar7;
758: lStack112 = auStack280._8_8_ + (long)iStack340 * 8;
759: if (iVar14 != 6) {
760: iVar21 = *(int *)(lVar32 + 0x24c);
761: *(int *)(lVar32 + 0x264) = iVar16;
762: *(int *)(lVar32 + 0x280) = (iVar25 * iVar21) / iVar7;
763: *(undefined8 *)(lVar19 + 0x38) = uVar2;
764: iStack336 = (iVar21 * iVar4) / iVar7;
765: lStack104 = auStack264._0_8_ + (long)iStack336 * 8;
766: if (iVar14 != 7) {
767: iVar21 = *(int *)(lVar32 + 0x2ac);
768: *(int *)(lVar32 + 0x2c4) = iVar16;
769: *(int *)(lVar32 + 0x2e0) = (iVar25 * iVar21) / iVar7;
770: *(undefined8 *)(lVar19 + 0x40) = uVar2;
771: iStack332 = (iVar21 * iVar4) / iVar7;
772: lStack96 = auStack264._8_8_ + (long)iStack332 * 8;
773: if (iVar14 != 8) {
774: iVar21 = *(int *)(lVar32 + 0x30c);
775: *(int *)(lVar32 + 0x324) = iVar16;
776: *(int *)(lVar32 + 0x340) = (iVar25 * iVar21) / iVar7;
777: *(undefined8 *)(lVar19 + 0x48) = uVar2;
778: iStack328 = (iVar21 * iVar4) / iVar7;
779: lStack88 = auStack248 + (long)iStack328 * 8;
780: if (iVar14 != 9) {
781: iVar14 = *(int *)(lVar32 + 0x36c);
782: *(int *)(lVar32 + 900) = iVar16;
783: *(int *)(lVar32 + 0x3a0) = (iVar25 * iVar14) / iVar7;
784: *(undefined8 *)(lVar19 + 0x50) = uVar2;
785: goto LAB_001568ac;
786: }
787: }
788: }
789: }
790: }
791: }
792: }
793: }
794: }
795: }
796: else {
797: iVar21 = *(int *)(&DAT_0018fcc0 + (long)iVar5 * 8);
798: iVar24 = *(int *)(&DAT_0018fdd0 + (long)iStack980 * 4);
799: *(int *)(lVar32 + 0x24) = iVar16;
800: iVar25 = (iVar21 * iVar24) / iVar25;
801: *(int *)(lVar32 + 0x40) = (*(int *)(lVar32 + 0xc) * iVar25) / iVar7;
802: lVar19 = *(long *)(param_1 + 0x460);
803: uVar2 = *(undefined8 *)(lVar19 + 8);
804: aiStack364[1] = (*(int *)(lVar32 + 0xc) * iVar4) / iVar7;
805: lStack152 = auStack232._0_8_;
806: if (iVar14 != 1) {
807: iVar21 = *(int *)(lVar32 + 0x6c);
808: *(int *)(lVar32 + 0x84) = iVar16;
809: *(int *)(lVar32 + 0xa0) = (iVar25 * iVar21) / iVar7;
810: *(undefined8 *)(lVar19 + 0x10) = uVar2;
811: aiStack364[2] = (iVar21 * iVar4) / iVar7;
812: lStack144 = auStack232._8_8_;
813: if (iVar14 != 2) {
814: iVar21 = *(int *)(lVar32 + 0xcc);
815: *(int *)(lVar32 + 0xe4) = iVar16;
816: *(int *)(lVar32 + 0x100) = (iVar25 * iVar21) / iVar7;
817: *(undefined8 *)(lVar19 + 0x18) = uVar2;
818: aiStack364[3] = (iVar21 * iVar4) / iVar7;
819: lStack136 = auStack216._0_8_;
820: if (iVar14 != 3) {
821: iVar21 = *(int *)(lVar32 + 300);
822: *(int *)(lVar32 + 0x144) = iVar16;
823: *(int *)(lVar32 + 0x160) = (iVar25 * iVar21) / iVar7;
824: *(undefined8 *)(lVar19 + 0x20) = uVar2;
825: aiStack364[4] = (iVar21 * iVar4) / iVar7;
826: lStack128 = auStack216._8_8_;
827: if (iVar14 != 4) {
828: iVar21 = *(int *)(lVar32 + 0x18c);
829: *(int *)(lVar32 + 0x1a4) = iVar16;
830: *(int *)(lVar32 + 0x1c0) = (iVar25 * iVar21) / iVar7;
831: *(undefined8 *)(lVar19 + 0x28) = uVar2;
832: iStack344 = (iVar21 * iVar4) / iVar7;
833: lStack120 = auStack200._0_8_;
834: if (iVar14 != 5) {
835: iVar21 = *(int *)(lVar32 + 0x1ec);
836: *(int *)(lVar32 + 0x204) = iVar16;
837: *(int *)(lVar32 + 0x220) = (iVar25 * iVar21) / iVar7;
838: *(undefined8 *)(lVar19 + 0x30) = uVar2;
839: iStack340 = (iVar21 * iVar4) / iVar7;
840: lStack112 = auStack200._8_8_;
841: if (iVar14 != 6) {
842: iVar21 = *(int *)(lVar32 + 0x24c);
843: *(int *)(lVar32 + 0x264) = iVar16;
844: *(int *)(lVar32 + 0x280) = (iVar25 * iVar21) / iVar7;
845: *(undefined8 *)(lVar19 + 0x38) = uVar2;
846: iStack336 = (iVar21 * iVar4) / iVar7;
847: lStack104 = auStack184._0_8_;
848: if (iVar14 != 7) {
849: iVar21 = *(int *)(lVar32 + 0x2ac);
850: *(int *)(lVar32 + 0x2c4) = iVar16;
851: *(int *)(lVar32 + 0x2e0) = (iVar25 * iVar21) / iVar7;
852: *(undefined8 *)(lVar19 + 0x40) = uVar2;
853: iStack332 = (iVar21 * iVar4) / iVar7;
854: lStack96 = auStack184._8_8_;
855: if (iVar14 != 8) {
856: iVar21 = *(int *)(lVar32 + 0x30c);
857: *(int *)(lVar32 + 0x324) = iVar16;
858: *(int *)(lVar32 + 0x340) = (iVar25 * iVar21) / iVar7;
859: *(undefined8 *)(lVar19 + 0x48) = uVar2;
860: iStack328 = (iVar21 * iVar4) / iVar7;
861: lStack88 = auStack168._0_8_;
862: if (iVar14 != 9) {
863: iVar14 = *(int *)(lVar32 + 0x36c);
864: *(int *)(lVar32 + 900) = iVar16;
865: *(int *)(lVar32 + 0x3a0) = (iVar25 * iVar14) / iVar7;
866: *(undefined8 *)(lVar19 + 0x50) = uVar2;
867: goto LAB_00156b3b;
868: }
869: }
870: }
871: }
872: }
873: }
874: }
875: }
876: }
877: }
878: }
879: else {
880: aiStack364[1] = (*(int *)(lVar32 + 0xc) * iVar4) / iVar7;
881: if (iStack1008 == 0) {
882: lStack152 = auStack312._0_8_ + (long)aiStack364[1] * 8;
883: if (iVar14 != 1) {
884: aiStack364[2] = (*(int *)(lVar32 + 0x6c) * iVar4) / iVar7;
885: lStack144 = auStack312._8_8_ + (long)aiStack364[2] * 8;
886: if (iVar14 != 2) {
887: aiStack364[3] = (*(int *)(lVar32 + 0xcc) * iVar4) / iVar7;
888: lStack136 = auStack296._0_8_ + (long)aiStack364[3] * 8;
889: if (iVar14 != 3) {
890: aiStack364[4] = (*(int *)(lVar32 + 300) * iVar4) / iVar7;
891: lStack128 = auStack296._8_8_ + (long)aiStack364[4] * 8;
892: if (iVar14 != 4) {
893: iStack344 = (*(int *)(lVar32 + 0x18c) * iVar4) / iVar7;
894: lStack120 = auStack280._0_8_ + (long)iStack344 * 8;
895: if (iVar14 != 5) {
896: iStack340 = (*(int *)(lVar32 + 0x1ec) * iVar4) / iVar7;
897: lStack112 = auStack280._8_8_ + (long)iStack340 * 8;
898: if (iVar14 != 6) {
899: iStack336 = (*(int *)(lVar32 + 0x24c) * iVar4) / iVar7;
900: lStack104 = auStack264._0_8_ + (long)iStack336 * 8;
901: if (iVar14 != 7) {
902: iStack332 = (*(int *)(lVar32 + 0x2ac) * iVar4) / iVar7;
903: lStack96 = auStack264._8_8_ + (long)iStack332 * 8;
904: if (iVar14 != 8) {
905: iStack328 = (*(int *)(lVar32 + 0x30c) * iVar4) / iVar7;
906: lStack88 = auStack248 + (long)iStack328 * 8;
907: if (iVar14 != 9) {
908: iVar14 = *(int *)(lVar32 + 0x36c);
909: LAB_001568ac:
910: iStack324 = (iVar14 * iVar4) / iVar7;
911: lStack80 = (long)pvStack240 + (long)iStack324 * 8;
912: }
913: }
914: }
915: }
916: }
917: }
918: }
919: }
920: }
921: }
922: else {
923: lStack152 = auStack232._0_8_;
924: if (iVar14 != 1) {
925: aiStack364[2] = (*(int *)(lVar32 + 0x6c) * iVar4) / iVar7;
926: lStack144 = auStack232._8_8_;
927: if (iVar14 != 2) {
928: aiStack364[3] = (*(int *)(lVar32 + 0xcc) * iVar4) / iVar7;
929: lStack136 = auStack216._0_8_;
930: if (iVar14 != 3) {
931: aiStack364[4] = (*(int *)(lVar32 + 300) * iVar4) / iVar7;
932: lStack128 = auStack216._8_8_;
933: if (iVar14 != 4) {
934: iStack344 = (*(int *)(lVar32 + 0x18c) * iVar4) / iVar7;
935: lStack120 = auStack200._0_8_;
936: if (iVar14 != 5) {
937: iStack340 = (*(int *)(lVar32 + 0x1ec) * iVar4) / iVar7;
938: lStack112 = auStack200._8_8_;
939: if (iVar14 != 6) {
940: iStack336 = (*(int *)(lVar32 + 0x24c) * iVar4) / iVar7;
941: lStack104 = auStack184._0_8_;
942: if (iVar14 != 7) {
943: iStack332 = (*(int *)(lVar32 + 0x2ac) * iVar4) / iVar7;
944: lStack96 = auStack184._8_8_;
945: if (iVar14 != 8) {
946: iStack328 = (*(int *)(lVar32 + 0x30c) * iVar4) / iVar7;
947: lStack88 = auStack168._0_8_;
948: if (iVar14 != 9) {
949: iVar14 = *(int *)(lVar32 + 0x36c);
950: LAB_00156b3b:
951: lStack88 = auStack168._0_8_;
952: lStack96 = auStack184._8_8_;
953: lStack104 = auStack184._0_8_;
954: lStack112 = auStack200._8_8_;
955: lStack120 = auStack200._0_8_;
956: lStack128 = auStack216._8_8_;
957: lStack136 = auStack216._0_8_;
958: lStack144 = auStack232._8_8_;
959: lStack152 = auStack232._0_8_;
960: iStack324 = (iVar14 * iVar4) / iVar7;
961: lStack80 = auStack168._8_8_;
962: }
963: }
964: }
965: }
966: }
967: }
968: }
969: }
970: }
971: }
972: }
973: }
974: FUN_001264c0(lVar17,&lStack152,iVar7 * iVar13);
975: if (iStack1008 != 0) {
976: lVar32 = 1;
977: iVar7 = *(int *)(param_1 + 0x240);
978: if (0 < iVar7) {
979: do {
980: iVar13 = aiStack508[lVar32] - aiStack364[lVar32];
981: if (aiStack412[lVar32] < iVar13) {
982: iVar13 = aiStack412[lVar32];
983: }
984: if (0 < iVar13) {
985: ppvVar31 = *(void ***)(auStack248 + lVar32 * 8 + 8);
986: iVar7 = aiStack556[lVar32];
987: ppvVar11 = (void **)((&lStack320)[lVar32] + (long)aiStack364[lVar32] * 8);
988: ppvVar26 = ppvVar31 + (ulong)(iVar13 - 1) + 1;
989: do {
990: pvVar33 = *ppvVar11;
991: pvVar15 = *ppvVar31;
992: ppvVar31 = ppvVar31 + 1;
993: ppvVar11 = ppvVar11 + 1;
994: memcpy(pvVar33,pvVar15,(long)iVar7);
995: } while (ppvVar26 != ppvVar31);
996: iVar7 = *(int *)(param_1 + 0x240);
997: }
998: iVar13 = (int)lVar32;
999: lVar32 = lVar32 + 1;
1000: } while (iVar13 < iVar7);
1001: }
1002: }
1003: iVar7 = *(int *)(param_1 + 0x3a4);
1004: iVar13 = *(int *)(param_1 + 0x3a8);
1005: iVar4 = iVar4 + iVar7 * iVar13;
1006: } while (*(int *)(param_1 + 0x294) != iVar4 && iVar4 <= *(int *)(param_1 + 0x294));
1007: }
1008: FUN_00125410(lVar17);
1009: }
1010: else {
1011: *(undefined4 *)(param_1 + 0x648) = 0x746e656e;
1012: *(undefined2 *)(param_1 + 0x64c) = 0x73;
1013: *(undefined4 *)(param_1 + 0x6d0) = 1;
1014: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
1015: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
1016: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
1017: *(undefined8 *)(param_1 + 0x620) = 0x204745504a203a29;
1018: *(undefined8 *)(param_1 + 0x628) = 0x756d206567616d69;
1019: *(undefined8 *)(param_1 + 0x630) = 0x2065766168207473;
1020: *(undefined8 *)(param_1 + 0x638) = 0x77656620726f2033;
1021: *(undefined8 *)(param_1 + 0x640) = 0x6f706d6f63207265;
1022: puVar8 = (undefined4 *)
1023: __tls_get_addr(0x77656620726f2033,0x756d206567616d69,0x2873656e616c5056,
1024: 0x706d6f6365446a74,&PTR_00398fc0);
1025: puVar8[0x10] = 0x746e656e;
1026: *(undefined2 *)(puVar8 + 0x11) = 0x73;
1027: uStack1136 = 0xffffffff;
1028: *puVar8 = 0x65446a74;
1029: puVar8[1] = 0x706d6f63;
1030: puVar8[2] = 0x73736572;
1031: puVar8[3] = 0x55596f54;
1032: puVar8[4] = 0x616c5056;
1033: puVar8[5] = 0x2873656e;
1034: puVar8[6] = 0x4a203a29;
1035: puVar8[7] = 0x20474550;
1036: puVar8[8] = 0x67616d69;
1037: puVar8[9] = 0x756d2065;
1038: puVar8[10] = 0x68207473;
1039: puVar8[0xb] = 0x20657661;
1040: puVar8[0xc] = 0x726f2033;
1041: puVar8[0xd] = 0x77656620;
1042: puVar8[0xe] = 0x63207265;
1043: puVar8[0xf] = 0x6f706d6f;
1044: }
1045: }
1046: else {
1047: iStack980 = FUN_0014e860();
1048: if (iStack980 < 0) {
1049: *(undefined8 *)(param_1 + 0x648) = 0x4745504a20726f66;
1050: *(undefined4 *)(param_1 + 0x650) = 0x616d6920;
1051: *(undefined2 *)(param_1 + 0x654) = 0x6567;
1052: *(undefined *)(param_1 + 0x656) = 0;
1053: *(undefined4 *)(param_1 + 0x6d0) = 1;
1054: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
1055: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
1056: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
1057: *(undefined8 *)(param_1 + 0x620) = 0x646c756f43203a29;
1058: *(undefined8 *)(param_1 + 0x628) = 0x74656420746f6e20;
1059: *(undefined8 *)(param_1 + 0x630) = 0x7320656e696d7265;
1060: *(undefined8 *)(param_1 + 0x638) = 0x696c706d61736275;
1061: *(undefined8 *)(param_1 + 0x640) = 0x206570797420676e;
1062: puVar8 = (undefined4 *)
1063: __tls_get_addr(0x696c706d61736275,0x74656420746f6e20,0x2873656e616c5056,
1064: 0x706d6f6365446a74,&PTR_00398fc0);
1065: *(undefined8 *)(puVar8 + 0x10) = 0x4745504a20726f66;
1066: puVar8[0x12] = 0x616d6920;
1067: *(undefined2 *)(puVar8 + 0x13) = 0x6567;
1068: *(undefined *)((long)puVar8 + 0x4e) = 0;
1069: uStack1136 = 0xffffffff;
1070: *puVar8 = 0x65446a74;
1071: puVar8[1] = 0x706d6f63;
1072: puVar8[2] = 0x73736572;
1073: puVar8[3] = 0x55596f54;
1074: puVar8[4] = 0x616c5056;
1075: puVar8[5] = 0x2873656e;
1076: puVar8[6] = 0x43203a29;
1077: puVar8[7] = 0x646c756f;
1078: puVar8[8] = 0x746f6e20;
1079: puVar8[9] = 0x74656420;
1080: puVar8[10] = 0x696d7265;
1081: puVar8[0xb] = 0x7320656e;
1082: puVar8[0xc] = 0x61736275;
1083: puVar8[0xd] = 0x696c706d;
1084: puVar8[0xe] = 0x7420676e;
1085: puVar8[0xf] = 0x20657079;
1086: }
1087: else {
1088: if ((iStack980 == 3) || ((param_4[1] != 0 && (param_4[2] != 0)))) goto LAB_00155960;
1089: *(undefined8 *)(param_1 + 0x628) = 0x6d75677261206469;
1090: *(undefined4 *)(param_1 + 0x630) = 0x746e65;
1091: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
1092: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
1093: *(undefined4 *)(param_1 + 0x6d0) = 1;
1094: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
1095: *(undefined8 *)(param_1 + 0x620) = 0x6c61766e49203a29;
1096: puVar8 = (undefined4 *)
1097: __tls_get_addr(0x2873656e616c5056,0x706d6f6365446a74,&PTR_00398fc0);
1098: *(undefined8 *)(puVar8 + 8) = 0x6d75677261206469;
1099: puVar8[10] = 0x746e65;
1100: uStack1136 = 0xffffffff;
1101: *puVar8 = 0x65446a74;
1102: puVar8[1] = 0x706d6f63;
1103: puVar8[2] = 0x73736572;
1104: puVar8[3] = 0x55596f54;
1105: puVar8[4] = 0x616c5056;
1106: puVar8[5] = 0x2873656e;
1107: puVar8[6] = 0x49203a29;
1108: puVar8[7] = 0x6c61766e;
1109: }
1110: }
1111: }
1112: else {
1113: LAB_00156032:
1114: uStack1136 = 0xffffffff;
1115: }
1116: }
1117: }
1118: LAB_00155e72:
1119: if (200 < *(int *)(param_1 + 0x22c)) {
1120: thunk_FUN_0011f490(lVar17);
1121: }
1122: lVar17 = 0;
1123: do {
1124: free(*(void **)(auStack232 + lVar17));
1125: ppvVar11 = (void **)(auStack312 + lVar17);
1126: lVar17 = lVar17 + 8;
1127: free(*ppvVar11);
1128: } while (lVar17 != 0x50);
1129: free(pvStack1160);
1130: *(undefined4 *)(param_1 + 0x5fc) = 0;
1131: uVar6 = 0xffffffff;
1132: if (*(int *)(param_1 + 0x5f8) == 0) {
1133: uVar6 = uStack1136;
1134: }
1135: LAB_00155ee3:
1136: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
1137: /* WARNING: Subroutine does not return */
1138: __stack_chk_fail();
1139: }
1140: return uVar6;
1141: }
1142: 
