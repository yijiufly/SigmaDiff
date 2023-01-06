1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8
5: tjDecodeYUVPlanes(long param_1,long *param_2,long param_3,uint param_4,long param_5,int param_6,
6: int param_7,uint param_8,uint param_9,uint param_10)
7: 
8: {
9: int *piVar1;
10: byte bVar2;
11: code **ppcVar3;
12: code *pcVar4;
13: code *pcVar5;
14: int iVar6;
15: undefined8 uVar7;
16: undefined4 *puVar8;
17: ulong uVar9;
18: long *plVar10;
19: long *plVar11;
20: void *pvVar12;
21: void *pvVar13;
22: uint uVar14;
23: long lVar15;
24: uint uVar16;
25: uint uVar17;
26: int iVar18;
27: long lVar19;
28: uint uVar20;
29: long lVar21;
30: undefined8 uVar22;
31: long lVar23;
32: uint uVar24;
33: void **ppvVar25;
34: uint uVar26;
35: int iVar27;
36: uint uVar29;
37: undefined auVar28 [16];
38: ulong uVar30;
39: int iVar31;
40: int iVar32;
41: int iVar33;
42: ulong uVar34;
43: int iVar35;
44: int iVar36;
45: int iVar37;
46: int iVar38;
47: int iVar39;
48: long *plStack496;
49: undefined4 auStack376 [4];
50: undefined4 uStack360;
51: int aiStack344 [12];
52: void *apvStack296 [10];
53: void *apvStack216 [10];
54: void *apvStack136 [11];
55: 
56: if (param_1 == 0) {
57: ram0x003a6008 = ram0x003a6008 & 0xff00000000000000 | 0x656c646e6168;
58: s_No_error_003a6000._0_8_ = 0x2064696c61766e49;
59: return 0xffffffff;
60: }
61: lVar21 = param_1 + 0x208;
62: *(undefined4 *)(param_1 + 0x5f8) = 0;
63: *(undefined4 *)(param_1 + 0x6d0) = 0;
64: lVar15 = 10;
65: *(uint *)(param_1 + 0x5fc) = param_10 >> 0xd & 1;
66: ppvVar25 = apvStack216;
67: while (lVar15 != 0) {
68: lVar15 = lVar15 + -1;
69: *ppvVar25 = (void *)0x0;
70: ppvVar25 = ppvVar25 + 1;
71: }
72: bVar2 = *(byte *)(param_1 + 0x600);
73: lVar15 = 10;
74: ppvVar25 = apvStack296;
75: while (lVar15 != 0) {
76: lVar15 = lVar15 + -1;
77: *ppvVar25 = (void *)0x0;
78: ppvVar25 = ppvVar25 + 1;
79: }
80: lVar15 = 10;
81: ppvVar25 = apvStack136;
82: while (lVar15 != 0) {
83: lVar15 = lVar15 + -1;
84: *ppvVar25 = (void *)0x0;
85: ppvVar25 = ppvVar25 + 1;
86: }
87: if ((bVar2 & 2) == 0) {
88: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
89: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
90: *(undefined8 *)(param_1 + 0x618) = 0x736e49203a292873;
91: *(undefined8 *)(param_1 + 0x620) = 0x61682065636e6174;
92: *(undefined8 *)(param_1 + 0x628) = 0x656220746f6e2073;
93: *(undefined8 *)(param_1 + 0x630) = 0x6974696e69206e65;
94: *(undefined8 *)(param_1 + 0x640) = 0x6d6f63656420726f;
95: *(undefined8 *)(param_1 + 0x648) = 0x6e6f697373657270;
96: *(undefined8 *)(param_1 + 0x638) = 0x662064657a696c61;
97: *(undefined *)(param_1 + 0x650) = 0;
98: uVar22 = 0xffffffff;
99: *(undefined4 *)(param_1 + 0x6d0) = 1;
100: s_No_error_003a6000._0_8_ = 0x65646f6365446a74;
101: ram0x003a6008 = 0x656e616c50565559;
102: _DAT_003a6010 = 0x736e49203a292873;
103: _DAT_003a6018 = 0x61682065636e6174;
104: _DAT_003a6020 = 0x656220746f6e2073;
105: _DAT_003a6028 = 0x6974696e69206e65;
106: _DAT_003a6030 = 0x662064657a696c61;
107: _DAT_003a6038 = 0x6d6f63656420726f;
108: _DAT_003a6040 = 0x6e6f697373657270;
109: DAT_003a6048 = 0;
110: plStack496 = (long *)0x0;
111: goto LAB_00146ea5;
112: }
113: if ((((((param_2 == (long *)0x0) || (*param_2 == 0)) || (5 < param_4)) ||
114: ((param_5 == 0 || (param_6 < 1)))) ||
115: ((param_7 < 0 || (((int)param_8 < 1 || (0xb < param_9)))))) ||
116: ((param_4 != 3 && ((param_2[1] == 0 || (param_2[2] == 0)))))) {
117: s_No_error_003a6000._0_8_ = 0x65646f6365446a74;
118: ram0x003a6008 = 0x656e616c50565559;
119: *(undefined2 *)(param_1 + 0x62c) = 0x74;
120: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
121: uVar22 = 0xffffffff;
122: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
123: *(undefined8 *)(param_1 + 0x618) = 0x766e49203a292873;
124: *(undefined8 *)(param_1 + 0x620) = 0x6772612064696c61;
125: *(undefined4 *)(param_1 + 0x628) = 0x6e656d75;
126: *(undefined4 *)(param_1 + 0x6d0) = 1;
127: _DAT_003a6010 = 0x766e49203a292873;
128: _DAT_003a6018 = 0x6772612064696c61;
129: _DAT_003a6020 = CONCAT26(_DAT_003a6026,0x746e656d75);
130: plStack496 = (long *)0x0;
131: goto LAB_00146ea5;
132: }
133: iVar6 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
134: uVar22 = 0xffffffff;
135: plStack496 = (long *)0x0;
136: if (iVar6 != 0) goto LAB_00146ea5;
137: if (param_9 == 0xb) {
138: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
139: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
140: *(undefined8 *)(param_1 + 0x618) = 0x6e6143203a292873;
141: *(undefined8 *)(param_1 + 0x620) = 0x6f63656420746f6e;
142: *(undefined8 *)(param_1 + 0x628) = 0x6920565559206564;
143: *(undefined8 *)(param_1 + 0x630) = 0x6e6920736567616d;
144: *(undefined8 *)(param_1 + 0x638) = 0x204b594d43206f74;
145: *(undefined8 *)(param_1 + 0x640) = 0x2e736c65786970;
146: *(undefined4 *)(param_1 + 0x6d0) = 1;
147: s_No_error_003a6000._0_8_ = 0x65646f6365446a74;
148: ram0x003a6008 = 0x656e616c50565559;
149: _DAT_003a6010 = 0x6e6143203a292873;
150: _DAT_003a6018 = 0x6f63656420746f6e;
151: _DAT_003a6020 = 0x6920565559206564;
152: _DAT_003a6028 = 0x6e6920736567616d;
153: _DAT_003a6030 = 0x204b594d43206f74;
154: _DAT_003a6038 = 0x2e736c65786970;
155: goto LAB_00146ea5;
156: }
157: if (param_7 == 0) {
158: param_7 = param_6 * *(int *)(&DAT_0018bc40 + (long)(int)param_9 * 4);
159: }
160: *(int *)(param_1 + 0x238) = param_6;
161: *(uint *)(param_1 + 0x23c) = param_8;
162: if ((param_10 & 8) == 0) {
163: if ((param_10 & 0x10) == 0) {
164: if ((param_10 & 0x20) != 0) {
165: putenv("JSIMD_FORCESSE2=1");
166: }
167: }
168: else {
169: putenv("JSIMD_FORCESSE=1");
170: }
171: }
172: else {
173: putenv("JSIMD_FORCEMMX=1");
174: }
175: *(undefined4 *)(*(long *)(param_1 + 0x448) + 0x20) = 0;
176: *(undefined4 *)(param_1 + 0x340) = 0;
177: *(undefined4 *)(param_1 + 0x420) = 0;
178: *(undefined4 *)(param_1 + 0x41c) = 0;
179: *(undefined4 *)(param_1 + 0x414) = 0;
180: *(undefined4 *)(param_1 + 0x418) = 0x3f;
181: *(undefined4 *)(param_1 + 0x250) = 1;
182: *(undefined4 *)(param_1 + 0x24c) = 1;
183: if (param_4 == 3) {
184: *(undefined4 *)(param_1 + 0x3b8) = 1;
185: *(undefined4 *)(param_1 + 0x240) = 1;
186: *(undefined4 *)(param_1 + 0x244) = 1;
187: uVar22 = 0x60;
188: }
189: else {
190: *(undefined4 *)(param_1 + 0x3b8) = 3;
191: *(undefined4 *)(param_1 + 0x240) = 3;
192: *(undefined4 *)(param_1 + 0x244) = 3;
193: uVar22 = 0x120;
194: }
195: puVar8 = (undefined4 *)(***(code ***)(param_1 + 0x210))(lVar21,1,uVar22);
196: iVar6 = *(int *)(param_1 + 0x240);
197: *(undefined4 **)(param_1 + 0x338) = puVar8;
198: if (0 < iVar6) {
199: puVar8[1] = 0;
200: *puVar8 = 1;
201: puVar8[6] = 0;
202: puVar8[5] = 0;
203: puVar8[4] = 0;
204: iVar27 = *(int *)(&DAT_0018bc70 + (long)(int)param_4 * 4);
205: if (iVar27 < 0) {
206: iVar27 = iVar27 + 7;
207: }
208: iVar18 = *(int *)(&DAT_0018bc90 + (long)(int)param_4 * 4);
209: puVar8[3] = iVar27 >> 3;
210: if (iVar18 < 0) {
211: iVar18 = iVar18 + 7;
212: }
213: puVar8[2] = iVar18 >> 3;
214: *(undefined4 **)(param_1 + 0x3c0) = puVar8;
215: if (1 < iVar6) {
216: puVar8[0x1a] = 1;
217: puVar8[0x1b] = 1;
218: puVar8[0x19] = 1;
219: puVar8[0x18] = 2;
220: puVar8[0x1e] = 1;
221: puVar8[0x1d] = 1;
222: puVar8[0x1c] = 1;
223: *(undefined4 **)(param_1 + 0x3c8) = puVar8 + 0x18;
224: if (2 < iVar6) {
225: puVar8[0x32] = 1;
226: puVar8[0x33] = 1;
227: puVar8[0x31] = 2;
228: puVar8[0x30] = 3;
229: puVar8[0x36] = 1;
230: puVar8[0x35] = 1;
231: puVar8[0x34] = 1;
232: *(undefined4 **)(param_1 + 0x3d0) = puVar8 + 0x30;
233: if (3 < iVar6) {
234: puVar8[0x4a] = 1;
235: puVar8[0x4b] = 1;
236: puVar8[0x49] = 3;
237: puVar8[0x48] = 4;
238: puVar8[0x4e] = 1;
239: puVar8[0x4d] = 1;
240: puVar8[0x4c] = 1;
241: *(undefined4 **)(param_1 + 0x3d8) = puVar8 + 0x48;
242: }
243: }
244: }
245: }
246: *(undefined4 *)(param_1 + 0x330) = 8;
247: if (*(long *)(param_1 + 0x2d0) == 0) {
248: uVar22 = FUN_00116760(lVar21);
249: *(undefined8 *)(param_1 + 0x2d0) = uVar22;
250: }
251: if (*(long *)(param_1 + 0x2d8) == 0) {
252: uVar22 = FUN_00116760(lVar21);
253: *(undefined8 *)(param_1 + 0x2d8) = uVar22;
254: }
255: ppcVar3 = *(code ***)(param_1 + 0x450);
256: pcVar4 = ppcVar3[1];
257: ppcVar3[1] = FUN_00141a40;
258: pcVar5 = *ppcVar3;
259: *ppcVar3 = FUN_00141a50;
260: FUN_0011d3f0(lVar21);
261: ppcVar3 = *(code ***)(param_1 + 0x450);
262: ppcVar3[1] = pcVar4;
263: *ppcVar3 = pcVar5;
264: *(undefined4 *)(param_1 + 0x248) = *(undefined4 *)(&DAT_0018bb40 + (long)(int)param_9 * 4);
265: if ((param_10 & 0x800) != 0) {
266: *(undefined4 *)(param_1 + 0x268) = 1;
267: }
268: *(undefined4 *)(param_1 + 0x26c) = 0;
269: *(undefined4 *)(param_1 + 0x418) = 0x3f;
270: FUN_0012c8f0(lVar21);
271: (***(code ***)(param_1 + 0x468))(lVar21);
272: iVar6 = *(int *)(param_1 + 0x3a0);
273: iVar27 = *(int *)(param_1 + 0x3a4);
274: uVar16 = iVar27 + -1 + param_8 & -iVar27;
275: if (param_7 == 0) {
276: param_7 = *(int *)(&DAT_0018bc40 + (long)(int)param_9 * 4) * *(int *)(param_1 + 0x290);
277: }
278: plStack496 = (long *)malloc((long)(int)uVar16 << 3);
279: if (plStack496 == (long *)0x0) {
280: LAB_00147c5e:
281: s_No_error_003a6000._0_8_ = 0x65646f6365446a74;
282: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
283: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
284: uVar22 = 0xffffffff;
285: *(undefined8 *)(param_1 + 0x618) = 0x6d654d203a292873;
286: *(undefined8 *)(param_1 + 0x620) = 0x6f6c6c612079726f;
287: *(undefined8 *)(param_1 + 0x628) = 0x66206e6f69746163;
288: *(undefined4 *)(param_1 + 0x630) = 0x756c6961;
289: *(undefined2 *)(param_1 + 0x634) = 0x6572;
290: *(undefined *)(param_1 + 0x636) = 0;
291: *(undefined4 *)(param_1 + 0x6d0) = 1;
292: ram0x003a6008 = 0x656e616c50565559;
293: _DAT_003a6010 = 0x6d654d203a292873;
294: _DAT_003a6018 = 0x6f6c6c612079726f;
295: _DAT_003a6020 = 0x66206e6f69746163;
296: _DAT_003a6028 = CONCAT17(DAT_003a6028_7,0x6572756c6961);
297: goto LAB_00146ea5;
298: }
299: uVar9 = SEXT48(param_7);
300: uVar20 = (uint)((ulong)((long)plStack496 << 0x3c) >> 0x20);
301: uVar14 = param_7 >> 0x1f;
302: if ((param_10 & 2) == 0) {
303: uVar17 = uVar20 >> 0x1f;
304: if (param_8 <= (uint)-((int)uVar20 >> 0x1f)) {
305: uVar17 = param_8;
306: }
307: uVar20 = param_8;
308: if ((param_8 < 7) || (uVar20 = uVar17, uVar17 != 0)) {
309: *plStack496 = param_5;
310: if (uVar20 < 2) {
311: iVar18 = 1;
312: }
313: else {
314: plStack496[1] = param_5 + uVar9;
315: if (uVar20 < 3) {
316: iVar18 = 2;
317: }
318: else {
319: lVar15 = param_5 + uVar9 * 2;
320: plStack496[2] = lVar15;
321: if (uVar20 < 4) {
322: iVar18 = 3;
323: }
324: else {
325: lVar15 = lVar15 + uVar9;
326: plStack496[3] = lVar15;
327: if (uVar20 < 5) {
328: iVar18 = 4;
329: }
330: else {
331: lVar15 = lVar15 + uVar9;
332: plStack496[4] = lVar15;
333: if (uVar20 < 6) {
334: iVar18 = 5;
335: }
336: else {
337: plStack496[5] = lVar15 + uVar9;
338: iVar18 = 6;
339: }
340: }
341: }
342: }
343: }
344: if (param_8 == uVar20) goto LAB_0014775e;
345: }
346: else {
347: uVar20 = 0;
348: iVar18 = 0;
349: }
350: uVar26 = param_8 - uVar20;
351: uVar17 = uVar26 & 0xfffffffc;
352: if (uVar17 != 0) {
353: uVar24 = 0;
354: plVar10 = plStack496 + uVar20;
355: auVar28 = CONCAT88(CONCAT44(iVar18 + 3,iVar18 + 2),CONCAT44(iVar18 + 1,iVar18));
356: do {
357: uVar24 = uVar24 + 1;
358: iVar37 = SUB164(auVar28 >> 0x20,0);
359: uVar20 = SUB164(auVar28 >> 0x40,0);
360: iVar38 = SUB164(auVar28 >> 0x60,0);
361: uVar34 = SUB168(CONCAT412(-(uint)(iVar37 < 0),CONCAT48(iVar37,SUB168(auVar28,0))) >> 0x40,0)
362: ;
363: uVar30 = SUB168(auVar28,0) & 0xffffffff;
364: *plVar10 = uVar30 * (uVar9 & 0xffffffff) +
365: ((ulong)-(uint)(SUB164(auVar28,0) < 0) * (uVar9 & 0xffffffff) + uVar30 * uVar14
366: << 0x20) + param_5;
367: plVar10[1] = (uVar34 & 0xffffffff) * (uVar9 & 0xffffffff) +
368: ((uVar34 >> 0x20) * (uVar9 & 0xffffffff) +
369: (uVar34 & 0xffffffff) * (ulong)uVar14 << 0x20) + param_5;
370: uVar30 = SUB168(CONCAT412(-(uint)(auVar28 < (undefined  [16])0x0),
371: CONCAT48(iVar38,CONCAT44(-(uint)((int)uVar20 < 0),uVar20))) >>
372: 0x40,0);
373: plVar10[2] = (ulong)uVar20 * (uVar9 & 0xffffffff) +
374: ((ulong)-(uint)((int)uVar20 < 0) * (uVar9 & 0xffffffff) +
375: (ulong)uVar20 * (ulong)uVar14 << 0x20) + param_5;
376: plVar10[3] = (uVar30 & 0xffffffff) * (uVar9 & 0xffffffff) +
377: ((uVar30 >> 0x20) * (uVar9 & 0xffffffff) +
378: (uVar30 & 0xffffffff) * (ulong)uVar14 << 0x20) + param_5;
379: plVar10 = plVar10 + 4;
380: auVar28 = CONCAT412(iVar38 + 4,
381: CONCAT48(uVar20 + 4,CONCAT44(iVar37 + 4,SUB164(auVar28,0) + 4)));
382: } while (uVar24 < uVar26 >> 2);
383: iVar18 = iVar18 + uVar17;
384: if (uVar17 == uVar26) goto LAB_0014775e;
385: }
386: plStack496[iVar18] = (long)iVar18 * uVar9 + param_5;
387: iVar37 = iVar18 + 1;
388: if (iVar37 < (int)param_8) {
389: iVar18 = iVar18 + 2;
390: plStack496[iVar37] = (long)iVar37 * uVar9 + param_5;
391: if (iVar18 < (int)param_8) {
392: plStack496[iVar18] = uVar9 * (long)iVar18 + param_5;
393: }
394: }
395: }
396: else {
397: uVar17 = uVar20 >> 0x1f;
398: if (param_8 < (uint)-((int)uVar20 >> 0x1f)) {
399: uVar17 = param_8;
400: }
401: uVar20 = param_8;
402: if ((param_8 < 7) || (uVar20 = uVar17, uVar17 != 0)) {
403: *plStack496 = (long)(int)(param_8 - 1) * uVar9 + param_5;
404: if (uVar20 < 2) {
405: iVar18 = 1;
406: }
407: else {
408: lVar15 = (long)(int)(param_8 - 2) * uVar9;
409: plStack496[1] = param_5 + lVar15;
410: if (uVar20 < 3) {
411: iVar18 = 2;
412: }
413: else {
414: lVar15 = lVar15 - uVar9;
415: plStack496[2] = param_5 + lVar15;
416: if (uVar20 < 4) {
417: iVar18 = 3;
418: }
419: else {
420: lVar15 = lVar15 - uVar9;
421: plStack496[3] = param_5 + lVar15;
422: if (uVar20 < 5) {
423: iVar18 = 4;
424: }
425: else {
426: lVar15 = lVar15 - uVar9;
427: plStack496[4] = param_5 + lVar15;
428: if (uVar20 < 6) {
429: iVar18 = 5;
430: }
431: else {
432: plStack496[5] = (lVar15 - uVar9) + param_5;
433: iVar18 = 6;
434: }
435: }
436: }
437: }
438: }
439: if (param_8 == uVar20) goto LAB_0014775e;
440: }
441: else {
442: uVar20 = 0;
443: iVar18 = 0;
444: }
445: uVar26 = param_8 - uVar20;
446: uVar17 = uVar26 & 0xfffffffc;
447: if (uVar17 != 0) {
448: iVar37 = iVar18 + 1;
449: iVar38 = iVar18 + 2;
450: iVar39 = iVar18 + 3;
451: uVar24 = 0;
452: plVar10 = plStack496 + uVar20;
453: iVar36 = iVar18;
454: do {
455: uVar24 = uVar24 + 1;
456: iVar31 = param_8 - iVar36;
457: iVar32 = param_8 - iVar37;
458: iVar33 = param_8 - iVar38;
459: iVar35 = param_8 - iVar39;
460: iVar36 = iVar36 + 4;
461: iVar37 = iVar37 + 4;
462: iVar38 = iVar38 + 4;
463: iVar39 = iVar39 + 4;
464: uVar20 = iVar31 - 1;
465: iVar32 = iVar32 + -1;
466: uVar29 = iVar33 - 1;
467: iVar35 = iVar35 + -1;
468: uVar30 = SUB168(CONCAT412(-(uint)(iVar32 < 0),CONCAT48(iVar32,CONCAT44(iVar32,uVar20))) >>
469: 0x40,0);
470: *plVar10 = (ulong)uVar20 * (uVar9 & 0xffffffff) +
471: ((ulong)-(uint)((int)uVar20 < 0) * (uVar9 & 0xffffffff) +
472: (ulong)uVar20 * (ulong)uVar14 << 0x20) + param_5;
473: plVar10[1] = (uVar30 & 0xffffffff) * (uVar9 & 0xffffffff) +
474: ((uVar30 >> 0x20) * (uVar9 & 0xffffffff) +
475: (uVar30 & 0xffffffff) * (ulong)uVar14 << 0x20) + param_5;
476: uVar30 = SUB168(CONCAT412(-(uint)(iVar35 < 0),
477: CONCAT48(iVar35,CONCAT44(-(uint)((int)uVar29 < 0),uVar29))) >>
478: 0x40,0);
479: plVar10[2] = (ulong)uVar29 * (uVar9 & 0xffffffff) +
480: ((ulong)-(uint)((int)uVar29 < 0) * (uVar9 & 0xffffffff) +
481: (ulong)uVar29 * (ulong)uVar14 << 0x20) + param_5;
482: plVar10[3] = (uVar30 & 0xffffffff) * (uVar9 & 0xffffffff) +
483: ((uVar30 >> 0x20) * (uVar9 & 0xffffffff) +
484: (uVar30 & 0xffffffff) * (ulong)uVar14 << 0x20) + param_5;
485: plVar10 = plVar10 + 4;
486: } while (uVar24 < uVar26 >> 2);
487: iVar18 = iVar18 + uVar17;
488: if (uVar17 == uVar26) goto LAB_0014775e;
489: }
490: plStack496[iVar18] = (long)(int)((param_8 - iVar18) + -1) * uVar9 + param_5;
491: iVar37 = iVar18 + 1;
492: if (iVar37 < (int)param_8) {
493: iVar18 = iVar18 + 2;
494: plStack496[iVar37] = (long)(int)((param_8 - iVar37) + -1) * uVar9 + param_5;
495: if (iVar18 < (int)param_8) {
496: plStack496[iVar18] = (long)(int)((param_8 - iVar18) + -1) * uVar9 + param_5;
497: }
498: }
499: }
500: LAB_0014775e:
501: if ((int)param_8 < (int)uVar16) {
502: lVar15 = (long)(int)param_8;
503: plVar10 = plStack496 + lVar15;
504: do {
505: plVar11 = plVar10 + 1;
506: *plVar10 = plStack496[lVar15 + -1];
507: plVar10 = plVar11;
508: } while (plVar11 != plStack496 + lVar15 + (ulong)(~param_8 + uVar16) + 1);
509: }
510: lVar15 = 0;
511: iVar18 = *(int *)(param_1 + 0x240);
512: if (0 < iVar18) {
513: do {
514: lVar23 = lVar15 * 0x60 + *(long *)(param_1 + 0x338);
515: iVar37 = *(int *)(lVar23 + 0xc);
516: uVar20 = *(int *)(lVar23 + 0x1c) * 8 + 0x1fU & 0xffffffe0;
517: pvVar12 = malloc((ulong)(uVar20 * iVar37 + 0x20));
518: apvStack296[lVar15] = pvVar12;
519: if (pvVar12 == (void *)0x0) goto LAB_00147c5e;
520: pvVar13 = malloc((long)iVar37 << 3);
521: apvStack216[lVar15] = pvVar13;
522: if (pvVar13 == (void *)0x0) goto LAB_00147c5e;
523: if (0 < iVar37) {
524: uVar14 = 0;
525: lVar19 = 0;
526: while( true ) {
527: uVar9 = (ulong)uVar14;
528: uVar14 = uVar14 + uVar20;
529: *(ulong *)((long)pvVar13 + lVar19) = uVar9 + ((long)pvVar12 + 0x1fU & 0xffffffffffffffe0);
530: lVar19 = lVar19 + 8;
531: if (lVar19 == (ulong)(iVar37 - 1) * 8 + 8) break;
532: pvVar13 = apvStack216[lVar15];
533: }
534: }
535: iVar38 = (*(int *)(lVar23 + 8) * (iVar6 + -1 + param_6 & -iVar6)) / iVar6;
536: aiStack344[lVar15] = iVar38;
537: iVar37 = (int)(uVar16 * iVar37) / iVar27;
538: pvVar12 = malloc((long)iVar37 << 3);
539: apvStack136[lVar15] = pvVar12;
540: if (pvVar12 == (void *)0x0) goto LAB_00147c5e;
541: lVar23 = param_2[lVar15];
542: if (0 < iVar37) {
543: if (param_3 == 0) {
544: lVar19 = 0;
545: do {
546: *(long *)((long)pvVar12 + lVar19 * 8) = lVar23;
547: lVar19 = lVar19 + 1;
548: lVar23 = lVar23 + iVar38;
549: } while ((int)lVar19 < iVar37);
550: }
551: else {
552: iVar39 = *(int *)(param_3 + lVar15 * 4);
553: lVar19 = 0;
554: do {
555: *(long *)((long)pvVar12 + lVar19 * 8) = lVar23;
556: iVar36 = iVar38;
557: if (iVar39 != 0) {
558: iVar36 = iVar39;
559: }
560: lVar19 = lVar19 + 1;
561: lVar23 = lVar23 + iVar36;
562: } while ((int)lVar19 < iVar37);
563: }
564: }
565: lVar15 = lVar15 + 1;
566: } while ((int)lVar15 < iVar18);
567: }
568: iVar6 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
569: uVar22 = 0xffffffff;
570: if (iVar6 == 0) {
571: if (0 < (int)uVar16) {
572: iVar27 = 0;
573: iVar6 = *(int *)(param_1 + 0x3a4);
574: do {
575: auStack376[0] = 0;
576: uStack360 = 0;
577: lVar15 = *(long *)(param_1 + 0x338);
578: if (0 < *(int *)(param_1 + 0x240)) {
579: lVar23 = 0;
580: do {
581: piVar1 = (int *)(lVar15 + 0xc);
582: lVar15 = lVar15 + 0x60;
583: FUN_0013be50(apvStack136[lVar23],(long)(*piVar1 * iVar27) / (long)iVar6 & 0xffffffff,
584: apvStack216[lVar23],0,*piVar1,aiStack344[lVar23]);
585: iVar18 = (int)lVar23 + 1;
586: lVar23 = lVar23 + 1;
587: iVar6 = *(int *)(param_1 + 0x3a4);
588: } while (*(int *)(param_1 + 0x240) != iVar18 && iVar18 <= *(int *)(param_1 + 0x240));
589: }
590: (**(code **)(*(long *)(param_1 + 0x468) + 8))(lVar21,apvStack216,auStack376);
591: iVar6 = *(int *)(param_1 + 0x3a4);
592: iVar27 = iVar27 + iVar6;
593: } while (iVar27 < (int)uVar16);
594: }
595: uVar22 = 0;
596: thunk_FUN_001166f0(lVar21);
597: }
598: LAB_00146ea5:
599: if (200 < *(int *)(param_1 + 0x22c)) {
600: thunk_FUN_001166f0(lVar21);
601: }
602: if (plStack496 != (long *)0x0) {
603: free(plStack496);
604: }
605: lVar21 = 0;
606: do {
607: if (*(void **)((long)apvStack216 + lVar21) != (void *)0x0) {
608: free(*(void **)((long)apvStack216 + lVar21));
609: }
610: if (*(void **)((long)apvStack296 + lVar21) != (void *)0x0) {
611: free(*(void **)((long)apvStack296 + lVar21));
612: }
613: if (*(void **)((long)apvStack136 + lVar21) != (void *)0x0) {
614: free(*(void **)((long)apvStack136 + lVar21));
615: }
616: lVar21 = lVar21 + 8;
617: } while (lVar21 != 0x50);
618: *(undefined4 *)(param_1 + 0x5fc) = 0;
619: uVar7 = 0xffffffff;
620: if (*(int *)(param_1 + 0x5f8) == 0) {
621: uVar7 = uVar22;
622: }
623: return uVar7;
624: }
625: 
