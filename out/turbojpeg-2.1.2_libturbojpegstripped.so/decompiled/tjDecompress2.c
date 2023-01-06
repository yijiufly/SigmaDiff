1: 
2: undefined4
3: tjDecompress2(long param_1,long param_2,long param_3,long param_4,int param_5,int param_6,
4: int param_7,uint param_8,uint param_9)
5: 
6: {
7: long lVar1;
8: bool bVar2;
9: int iVar3;
10: int iVar4;
11: uint uVar5;
12: undefined4 uVar6;
13: undefined4 *puVar7;
14: undefined8 *puVar8;
15: long *plVar9;
16: long lVar10;
17: int iVar11;
18: uint uVar12;
19: undefined4 uVar13;
20: int iVar14;
21: int iVar15;
22: int iVar16;
23: uint uVar17;
24: ulong uVar18;
25: int iVar19;
26: int iVar20;
27: uint uVar21;
28: uint uVar22;
29: long in_FS_OFFSET;
30: undefined auVar23 [16];
31: int iVar24;
32: int iVar25;
33: int iVar26;
34: uint uVar27;
35: ulong uVar28;
36: ulong uVar29;
37: uint uVar30;
38: uint uVar31;
39: uint uVar32;
40: long *plStack344;
41: undefined4 uStack320;
42: int iStack136;
43: code *pcStack72;
44: undefined auStack64 [16];
45: undefined8 uStack48;
46: long lStack40;
47: long lStack32;
48: 
49: lStack32 = *(long *)(in_FS_OFFSET + 0x28);
50: if (param_1 == 0) {
51: puVar8 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
52: *puVar8 = 0x2064696c61766e49;
53: *(undefined4 *)(puVar8 + 1) = 0x646e6168;
54: *(undefined2 *)((long)puVar8 + 0xc) = 0x656c;
55: *(undefined *)((long)puVar8 + 0xe) = 0;
56: uVar6 = 0xffffffff;
57: goto LAB_0015323c;
58: }
59: lVar1 = param_1 + 0x208;
60: *(undefined4 *)(param_1 + 0x5f8) = 0;
61: *(undefined4 *)(param_1 + 0x6d0) = 0;
62: *(uint *)(param_1 + 0x5fc) = (int)param_9 >> 0xd & 1;
63: if ((*(byte *)(param_1 + 0x600) & 2) == 0) {
64: *(undefined4 *)(param_1 + 0x648) = 0x6e6f6973;
65: *(undefined *)(param_1 + 0x64c) = 0;
66: *(undefined4 *)(param_1 + 0x6d0) = 1;
67: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
68: *(undefined8 *)(param_1 + 0x610) = 0x3a29283273736572;
69: *(undefined8 *)(param_1 + 0x618) = 0x636e6174736e4920;
70: *(undefined8 *)(param_1 + 0x620) = 0x6f6e207361682065;
71: *(undefined8 *)(param_1 + 0x628) = 0x69206e6565622074;
72: *(undefined8 *)(param_1 + 0x630) = 0x7a696c616974696e;
73: *(undefined8 *)(param_1 + 0x638) = 0x6420726f66206465;
74: *(undefined8 *)(param_1 + 0x640) = 0x736572706d6f6365;
75: puVar7 = (undefined4 *)
76: __tls_get_addr(0x6420726f66206465,0x69206e6565622074,0x636e6174736e4920,
77: 0x706d6f6365446a74,&PTR_00398fc0);
78: puVar7[0x10] = 0x6e6f6973;
79: *(undefined *)(puVar7 + 0x11) = 0;
80: uStack320 = 0xffffffff;
81: plStack344 = (long *)0x0;
82: *puVar7 = 0x65446a74;
83: puVar7[1] = 0x706d6f63;
84: puVar7[2] = 0x73736572;
85: puVar7[3] = 0x3a292832;
86: puVar7[4] = 0x736e4920;
87: puVar7[5] = 0x636e6174;
88: puVar7[6] = 0x61682065;
89: puVar7[7] = 0x6f6e2073;
90: puVar7[8] = 0x65622074;
91: puVar7[9] = 0x69206e65;
92: puVar7[10] = 0x6974696e;
93: puVar7[0xb] = 0x7a696c61;
94: puVar7[0xc] = 0x66206465;
95: puVar7[0xd] = 0x6420726f;
96: puVar7[0xe] = 0x6d6f6365;
97: puVar7[0xf] = 0x73657270;
98: iVar4 = *(int *)(param_1 + 0x22c);
99: }
100: else {
101: if (((((param_2 == 0) || (param_3 == 0)) || (param_4 == 0)) || ((param_5 < 0 || (param_6 < 0))))
102: || ((param_7 < 0 || (0xb < param_8)))) {
103: *(undefined2 *)(param_1 + 0x628) = 0x74;
104: *(undefined4 *)(param_1 + 0x6d0) = 1;
105: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
106: *(undefined8 *)(param_1 + 0x610) = 0x3a29283273736572;
107: *(undefined8 *)(param_1 + 0x618) = 0x64696c61766e4920;
108: *(undefined8 *)(param_1 + 0x620) = 0x6e656d7567726120;
109: puVar7 = (undefined4 *)__tls_get_addr(0x64696c61766e4920,0x706d6f6365446a74,&PTR_00398fc0);
110: *(undefined2 *)(puVar7 + 8) = 0x74;
111: uStack320 = 0xffffffff;
112: plStack344 = (long *)0x0;
113: *puVar7 = 0x65446a74;
114: puVar7[1] = 0x706d6f63;
115: puVar7[2] = 0x73736572;
116: puVar7[3] = 0x3a292832;
117: puVar7[4] = 0x766e4920;
118: puVar7[5] = 0x64696c61;
119: puVar7[6] = 0x67726120;
120: puVar7[7] = 0x6e656d75;
121: }
122: else {
123: if ((param_9 & 8) == 0) {
124: if ((param_9 & 0x10) == 0) {
125: if ((param_9 & 0x20) != 0) {
126: putenv("JSIMD_FORCESSE2=1");
127: }
128: }
129: else {
130: putenv("JSIMD_FORCESSE=1");
131: }
132: }
133: else {
134: putenv("JSIMD_FORCEMMX=1");
135: }
136: if ((param_9 & 0x8000) == 0) {
137: *(undefined8 *)(param_1 + 0x218) = 0;
138: }
139: else {
140: uStack48 = 0;
141: pcStack72 = FUN_0014eb60;
142: auStack64 = (undefined  [16])0x0;
143: *(code ***)(param_1 + 0x218) = &pcStack72;
144: lStack40 = param_1;
145: }
146: uStack320 = 0;
147: plStack344 = (long *)0x0;
148: iVar4 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
149: if (iVar4 == 0) {
150: FUN_00167270(lVar1,param_2,param_3);
151: FUN_00125330();
152: *(undefined4 *)(param_1 + 0x248) = *(undefined4 *)(&DAT_0018fc80 + (long)(int)param_8 * 4);
153: if ((param_9 & 0x800) != 0) {
154: *(undefined4 *)(param_1 + 0x268) = 1;
155: }
156: if ((param_9 & 0x100) != 0) {
157: *(undefined4 *)(param_1 + 0x26c) = 0;
158: }
159: iVar4 = *(int *)(param_1 + 0x238);
160: iVar24 = *(int *)(param_1 + 0x23c);
161: if (param_5 == 0) {
162: param_5 = iVar4;
163: }
164: iVar25 = iVar24;
165: if (param_7 != 0) {
166: iVar25 = param_7;
167: }
168: if ((param_5 < iVar4 * 2) || (iVar25 < iVar24 * 2)) {
169: iVar11 = iVar4 * 0xf + 7;
170: iVar26 = iVar4 * 0xf + 0xe;
171: if (-1 < iVar11) {
172: iVar26 = iVar11;
173: }
174: iVar11 = iVar24 * 0xf + 7;
175: if (iVar11 < 0) {
176: iVar11 = iVar24 * 0xf + 0xe;
177: }
178: if ((param_5 < iVar26 >> 3) || (iVar25 < iVar11 >> 3)) {
179: iVar11 = iVar4 * 7;
180: iVar26 = iVar11 + 6;
181: if (-1 < iVar11 + 3) {
182: iVar26 = iVar11 + 3;
183: }
184: iVar16 = iVar24 * 7;
185: iVar19 = iVar16 + 6;
186: if (-1 < iVar16 + 3) {
187: iVar19 = iVar16 + 3;
188: }
189: if ((param_5 < iVar26 >> 2) || (iVar25 < iVar19 >> 2)) {
190: iVar19 = iVar4 * 0xd + 7;
191: iVar26 = iVar4 * 0xd + 0xe;
192: if (-1 < iVar19) {
193: iVar26 = iVar19;
194: }
195: iVar19 = iVar24 * 0xd + 7;
196: if (iVar19 < 0) {
197: iVar19 = iVar24 * 0xd + 0xe;
198: }
199: if ((param_5 < iVar26 >> 3) || (iVar25 < iVar19 >> 3)) {
200: iVar26 = iVar4 * 3;
201: iVar19 = iVar24 * 3;
202: if ((param_5 < (iVar26 + 1) / 2) || (iVar25 < (iVar19 + 1) / 2)) {
203: iVar20 = iVar4 * 0xb + 7;
204: iVar15 = iVar4 * 0xb + 0xe;
205: if (-1 < iVar20) {
206: iVar15 = iVar20;
207: }
208: iVar20 = iVar24 * 0xb + 7;
209: if (iVar20 < 0) {
210: iVar20 = iVar24 * 0xb + 0xe;
211: }
212: if ((param_5 < iVar15 >> 3) || (iVar25 < iVar20 >> 3)) {
213: iVar20 = iVar4 * 5;
214: iVar15 = iVar20 + 6;
215: if (-1 < iVar20 + 3) {
216: iVar15 = iVar20 + 3;
217: }
218: iVar3 = iVar24 * 5;
219: iVar14 = iVar3 + 6;
220: if (-1 < iVar3 + 3) {
221: iVar14 = iVar3 + 3;
222: }
223: if ((param_5 < iVar15 >> 2) || (iVar25 < iVar14 >> 2)) {
224: iVar14 = iVar4 * 9 + 7;
225: iVar15 = iVar4 * 9 + 0xe;
226: if (-1 < iVar14) {
227: iVar15 = iVar14;
228: }
229: iVar14 = iVar24 * 9 + 7;
230: if (iVar14 < 0) {
231: iVar14 = iVar24 * 9 + 0xe;
232: }
233: if ((param_5 < iVar15 >> 3) || (iVar25 < iVar14 >> 3)) {
234: if ((param_5 < iVar4) || (iVar25 < iVar24)) {
235: iVar15 = iVar11 + 7;
236: if (iVar11 + 7 < 0) {
237: iVar15 = iVar11 + 0xe;
238: }
239: iVar11 = iVar16 + 7;
240: if (iVar16 + 7 < 0) {
241: iVar11 = iVar16 + 0xe;
242: }
243: if ((param_5 < iVar15 >> 3) || (iVar25 < iVar11 >> 3)) {
244: iVar11 = iVar26 + 6;
245: if (-1 < iVar26 + 3) {
246: iVar11 = iVar26 + 3;
247: }
248: iVar16 = iVar19 + 6;
249: if (-1 < iVar19 + 3) {
250: iVar16 = iVar19 + 3;
251: }
252: if ((param_5 < iVar11 >> 2) || (iVar25 < iVar16 >> 2)) {
253: iVar11 = iVar20 + 7;
254: if (iVar20 + 7 < 0) {
255: iVar11 = iVar20 + 0xe;
256: }
257: iVar16 = iVar3 + 7;
258: if (iVar3 + 7 < 0) {
259: iVar16 = iVar3 + 0xe;
260: }
261: if ((param_5 < iVar11 >> 3) || (iVar25 < iVar16 >> 3)) {
262: if ((param_5 < (iVar4 + 1) / 2) || (iVar25 < (iVar24 + 1) / 2)) {
263: iVar11 = iVar26 + 7;
264: if (iVar26 + 7 < 0) {
265: iVar11 = iVar26 + 0xe;
266: }
267: iVar26 = iVar19 + 7;
268: if (iVar19 + 7 < 0) {
269: iVar26 = iVar19 + 0xe;
270: }
271: if ((param_5 < iVar11 >> 3) || (iVar25 < iVar26 >> 3)) {
272: iVar26 = iVar4 + 6;
273: if (-1 < iVar4 + 3) {
274: iVar26 = iVar4 + 3;
275: }
276: iVar11 = iVar24 + 6;
277: if (-1 < iVar24 + 3) {
278: iVar11 = iVar24 + 3;
279: }
280: if ((param_5 < iVar26 >> 2) || (iVar25 < iVar11 >> 2)) {
281: iVar26 = iVar4 + 7;
282: if (iVar4 + 7 < 0) {
283: iVar26 = iVar4 + 0xe;
284: }
285: iVar4 = iVar24 + 7;
286: if (iVar24 + 7 < 0) {
287: iVar4 = iVar24 + 0xe;
288: }
289: if ((param_5 < iVar26 >> 3) || (iVar25 < iVar4 >> 3)) {
290: *(undefined2 *)(param_1 + 0x648) = 0x73;
291: *(undefined4 *)(param_1 + 0x6d0) = 1;
292: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
293: *(undefined8 *)(param_1 + 0x610) = 0x3a29283273736572;
294: *(undefined8 *)(param_1 + 0x618) = 0x6e20646c756f4320;
295: *(undefined8 *)(param_1 + 0x620) = 0x656c61637320746f;
296: *(undefined8 *)(param_1 + 0x628) = 0x6f74206e776f6420;
297: *(undefined8 *)(param_1 + 0x630) = 0x6465726973656420;
298: *(undefined8 *)(param_1 + 0x638) = 0x64206567616d6920;
299: *(undefined8 *)(param_1 + 0x640) = 0x6e6f69736e656d69;
300: puVar7 = (undefined4 *)
301: __tls_get_addr(0x64206567616d6920,
302: 0x6f74206e776f6420,
303: 0x6e20646c756f4320,
304: 0x706d6f6365446a74,&PTR_00398fc0);
305: *(undefined2 *)(puVar7 + 0x10) = 0x73;
306: uStack320 = 0xffffffff;
307: *puVar7 = 0x65446a74;
308: puVar7[1] = 0x706d6f63;
309: puVar7[2] = 0x73736572;
310: puVar7[3] = 0x3a292832;
311: puVar7[4] = 0x756f4320;
312: puVar7[5] = 0x6e20646c;
313: puVar7[6] = 0x7320746f;
314: puVar7[7] = 0x656c6163;
315: puVar7[8] = 0x776f6420;
316: puVar7[9] = 0x6f74206e;
317: puVar7[10] = 0x73656420;
318: puVar7[0xb] = 0x64657269;
319: puVar7[0xc] = 0x616d6920;
320: puVar7[0xd] = 0x64206567;
321: puVar7[0xe] = 0x6e656d69;
322: puVar7[0xf] = 0x6e6f6973;
323: goto LAB_001531fd;
324: }
325: uVar6 = 8;
326: uVar13 = 1;
327: }
328: else {
329: uVar6 = 4;
330: uVar13 = 1;
331: }
332: }
333: else {
334: uVar6 = 8;
335: uVar13 = 3;
336: }
337: }
338: else {
339: uVar6 = 2;
340: uVar13 = 1;
341: }
342: }
343: else {
344: uVar6 = 8;
345: uVar13 = 5;
346: }
347: }
348: else {
349: uVar6 = 4;
350: uVar13 = 3;
351: }
352: }
353: else {
354: uVar6 = 8;
355: uVar13 = 7;
356: }
357: }
358: else {
359: uVar6 = 1;
360: uVar13 = 1;
361: }
362: }
363: else {
364: uVar6 = 8;
365: uVar13 = 9;
366: }
367: }
368: else {
369: uVar6 = 4;
370: uVar13 = 5;
371: }
372: }
373: else {
374: uVar6 = 8;
375: uVar13 = 0xb;
376: }
377: }
378: else {
379: uVar6 = 2;
380: uVar13 = 3;
381: }
382: }
383: else {
384: uVar6 = 8;
385: uVar13 = 0xd;
386: }
387: }
388: else {
389: uVar6 = 4;
390: uVar13 = 7;
391: }
392: }
393: else {
394: uVar6 = 8;
395: uVar13 = 0xf;
396: }
397: }
398: else {
399: uVar6 = 1;
400: uVar13 = 2;
401: }
402: *(undefined4 *)(param_1 + 0x24c) = uVar13;
403: *(undefined4 *)(param_1 + 0x250) = uVar6;
404: FUN_00125640();
405: iStack136 = param_6;
406: if (param_6 == 0) {
407: iStack136 = *(int *)(param_1 + 0x290) * *(int *)(&DAT_0018fd80 + (long)(int)param_8 * 4);
408: }
409: plStack344 = (long *)malloc((ulong)*(uint *)(param_1 + 0x294) << 3);
410: if (plStack344 == (long *)0x0) {
411: *(undefined8 *)(param_1 + 0x628) = 0x756c696166206e6f;
412: *(undefined2 *)(param_1 + 0x630) = 0x6572;
413: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
414: *(undefined8 *)(param_1 + 0x610) = 0x3a29283273736572;
415: *(undefined *)(param_1 + 0x632) = 0;
416: *(undefined4 *)(param_1 + 0x6d0) = 1;
417: *(undefined8 *)(param_1 + 0x618) = 0x2079726f6d654d20;
418: *(undefined8 *)(param_1 + 0x620) = 0x697461636f6c6c61;
419: puVar7 = (undefined4 *)__tls_get_addr(0x2079726f6d654d20,0x706d6f6365446a74,&PTR_00398fc0)
420: ;
421: *(undefined8 *)(puVar7 + 8) = 0x756c696166206e6f;
422: *(undefined2 *)(puVar7 + 10) = 0x6572;
423: *(undefined *)((long)puVar7 + 0x2a) = 0;
424: uStack320 = 0xffffffff;
425: *puVar7 = 0x65446a74;
426: puVar7[1] = 0x706d6f63;
427: puVar7[2] = 0x73736572;
428: puVar7[3] = 0x3a292832;
429: puVar7[4] = 0x6d654d20;
430: puVar7[5] = 0x2079726f;
431: puVar7[6] = 0x6f6c6c61;
432: puVar7[7] = 0x69746163;
433: }
434: else {
435: iVar4 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
436: if (iVar4 != 0) goto LAB_00153159;
437: uVar12 = *(uint *)(param_1 + 0x294);
438: if (0 < (int)uVar12) {
439: uVar18 = SEXT48(iStack136);
440: param_9 = param_9 & 2;
441: uVar27 = iStack136 >> 0x1f;
442: if (param_9 == 0) {
443: uVar5 = (uint)((ulong)plStack344 >> 3) & 1;
444: if (4 < uVar12 - 1) {
445: if (((ulong)plStack344 >> 3 & 1) != 0) {
446: *plStack344 = param_4;
447: param_9 = 1;
448: }
449: uVar21 = uVar12 - uVar5;
450: uVar17 = 0;
451: auVar23 = CONCAT412(param_9 + 3,CONCAT48(param_9 + 2,CONCAT44(param_9 + 1,param_9)))
452: ;
453: plVar9 = plStack344 + uVar5;
454: do {
455: uVar17 = uVar17 + 1;
456: iVar4 = SUB164(auVar23 >> 0x20,0);
457: uVar5 = SUB164(auVar23 >> 0x40,0);
458: iVar24 = SUB164(auVar23 >> 0x60,0);
459: bVar2 = auVar23 < (undefined  [16])0x0;
460: uVar28 = SUB168(CONCAT412(-(uint)(iVar4 < 0),CONCAT48(iVar4,SUB168(auVar23,0))) >>
461: 0x40,0);
462: uVar29 = SUB168(auVar23,0) & 0xffffffff;
463: *plVar9 = ((ulong)-(uint)(SUB164(auVar23,0) < 0) * (uVar18 & 0xffffffff) +
464: uVar29 * uVar27 << 0x20) + uVar29 * (uVar18 & 0xffffffff) + param_4;
465: plVar9[1] = ((uVar28 >> 0x20) * (uVar18 & 0xffffffff) +
466: (uVar28 & 0xffffffff) * (ulong)uVar27 << 0x20) +
467: (uVar28 & 0xffffffff) * (uVar18 & 0xffffffff) + param_4;
468: auVar23 = CONCAT412(iVar24 + 4,
469: CONCAT48(uVar5 + 4,CONCAT44(iVar4 + 4,SUB164(auVar23,0) + 4)))
470: ;
471: uVar29 = SUB168(CONCAT412(-(uint)bVar2,
472: CONCAT48(iVar24,CONCAT44(-(uint)((int)uVar5 < 0),uVar5))
473: ) >> 0x40,0);
474: plVar9[2] = ((ulong)-(uint)((int)uVar5 < 0) * (uVar18 & 0xffffffff) +
475: (ulong)uVar5 * (ulong)uVar27 << 0x20) +
476: (ulong)uVar5 * (uVar18 & 0xffffffff) + param_4;
477: plVar9[3] = ((uVar29 >> 0x20) * (uVar18 & 0xffffffff) +
478: (uVar29 & 0xffffffff) * (ulong)uVar27 << 0x20) +
479: (uVar29 & 0xffffffff) * (uVar18 & 0xffffffff) + param_4;
480: plVar9 = plVar9 + 4;
481: } while (uVar17 < uVar21 >> 2);
482: param_9 = param_9 + (uVar21 & 0xfffffffc);
483: if ((uVar21 & 0xfffffffc) == uVar21) goto LAB_00153ba5;
484: }
485: lVar10 = uVar18 * (long)(int)param_9;
486: plStack344[(int)param_9] = param_4 + lVar10;
487: if ((int)(param_9 + 1) < (int)uVar12) {
488: lVar10 = lVar10 + uVar18;
489: plStack344[(int)(param_9 + 1)] = param_4 + lVar10;
490: if ((int)(param_9 + 2) < (int)uVar12) {
491: lVar10 = lVar10 + uVar18;
492: plStack344[(int)(param_9 + 2)] = param_4 + lVar10;
493: if ((int)(param_9 + 3) < (int)uVar12) {
494: lVar10 = lVar10 + uVar18;
495: iVar4 = param_9 + 4;
496: plStack344[(int)(param_9 + 3)] = param_4 + lVar10;
497: if (iVar4 < (int)uVar12) {
498: lVar10 = lVar10 + uVar18;
499: goto LAB_00153b74;
500: }
501: }
502: }
503: }
504: }
505: else {
506: uVar17 = uVar12 - 1;
507: uVar5 = (uint)((ulong)plStack344 >> 3) & 1;
508: if (3 < uVar17) {
509: if (((ulong)plStack344 >> 3 & 1) != 0) {
510: *plStack344 = uVar17 * uVar18 + param_4;
511: iVar4 = 1;
512: }
513: uVar22 = uVar12 - uVar5;
514: uVar21 = 0;
515: iVar25 = iVar4 + 1;
516: iVar26 = iVar4 + 2;
517: iVar11 = iVar4 + 3;
518: plVar9 = plStack344 + uVar5;
519: iVar24 = iVar4;
520: do {
521: uVar21 = uVar21 + 1;
522: uVar5 = uVar17 - iVar24;
523: uVar30 = uVar17 - iVar25;
524: uVar31 = uVar17 - iVar26;
525: uVar32 = uVar17 - iVar11;
526: iVar24 = iVar24 + 4;
527: iVar25 = iVar25 + 4;
528: iVar26 = iVar26 + 4;
529: iVar11 = iVar11 + 4;
530: *plVar9 = ((ulong)uVar5 * (ulong)uVar27 << 0x20) +
531: (ulong)uVar5 * (uVar18 & 0xffffffff) + param_4;
532: plVar9[1] = ((ulong)uVar30 * (ulong)uVar27 << 0x20) +
533: (ulong)uVar30 * (uVar18 & 0xffffffff) + param_4;
534: plVar9[2] = ((ulong)uVar31 * (ulong)uVar27 << 0x20) +
535: (ulong)uVar31 * (uVar18 & 0xffffffff) + param_4;
536: plVar9[3] = ((ulong)uVar32 * (ulong)uVar27 << 0x20) +
537: (ulong)uVar32 * (uVar18 & 0xffffffff) + param_4;
538: plVar9 = plVar9 + 4;
539: } while (uVar21 < uVar22 >> 2);
540: iVar4 = iVar4 + (uVar22 & 0xfffffffc);
541: if (uVar22 == (uVar22 & 0xfffffffc)) goto LAB_00153ba5;
542: }
543: plStack344[iVar4] = (uVar17 - iVar4) * uVar18 + param_4;
544: iVar24 = iVar4 + 1;
545: if (iVar24 < (int)uVar12) {
546: plStack344[iVar24] = (uVar17 - iVar24) * uVar18 + param_4;
547: iVar24 = iVar4 + 2;
548: if (iVar24 < (int)uVar12) {
549: iVar4 = iVar4 + 3;
550: plStack344[iVar24] = (uVar17 - iVar24) * uVar18 + param_4;
551: if (iVar4 < (int)uVar12) {
552: lVar10 = (uVar17 - iVar4) * uVar18;
553: LAB_00153b74:
554: plStack344[iVar4] = lVar10 + param_4;
555: }
556: }
557: }
558: }
559: }
560: LAB_00153ba5:
561: while( true ) {
562: uVar27 = *(uint *)(param_1 + 0x2b0);
563: if (uVar12 <= uVar27) break;
564: FUN_00125990(lVar1,plStack344 + uVar27,uVar12 - uVar27);
565: uVar12 = *(uint *)(param_1 + 0x294);
566: }
567: FUN_00125410(lVar1);
568: }
569: }
570: else {
571: LAB_00153159:
572: uStack320 = 0xffffffff;
573: }
574: }
575: LAB_001531fd:
576: iVar4 = *(int *)(param_1 + 0x22c);
577: }
578: if (200 < iVar4) {
579: thunk_FUN_0011f490(lVar1);
580: }
581: free(plStack344);
582: *(undefined4 *)(param_1 + 0x5fc) = 0;
583: uVar6 = 0xffffffff;
584: if (*(int *)(param_1 + 0x5f8) == 0) {
585: uVar6 = uStack320;
586: }
587: LAB_0015323c:
588: if (lStack32 == *(long *)(in_FS_OFFSET + 0x28)) {
589: return uVar6;
590: }
591: /* WARNING: Subroutine does not return */
592: __stack_chk_fail();
593: }
594: 
