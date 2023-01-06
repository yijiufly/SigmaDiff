1: 
2: undefined4
3: tjCompressFromYUVPlanes
4: (long param_1,long *param_2,int param_3,long param_4,int param_5,uint param_6,long param_7
5: ,undefined8 *param_8,uint param_9,uint param_10)
6: 
7: {
8: int iVar1;
9: long *plVar2;
10: int iVar3;
11: int iVar4;
12: int iVar5;
13: undefined4 uVar6;
14: int iVar7;
15: uint uVar8;
16: undefined4 *puVar9;
17: undefined8 uVar10;
18: long *plVar11;
19: long lVar12;
20: size_t sVar13;
21: undefined8 *puVar14;
22: void **ppvVar15;
23: char *pcVar16;
24: void *pvVar17;
25: long lVar18;
26: size_t __n;
27: void **ppvVar19;
28: int iVar20;
29: char *pcVar21;
30: long lVar22;
31: uint uVar23;
32: uint uVar24;
33: int iVar25;
34: uint uVar26;
35: void *pvVar27;
36: void **ppvVar28;
37: int *piVar29;
38: long in_FS_OFFSET;
39: byte bVar30;
40: void *pvVar31;
41: void *pvVar32;
42: undefined4 uStack876;
43: void *pvStack872;
44: uint uStack696;
45: int iStack692;
46: int iStack680;
47: int iStack668;
48: uint auStack504 [12];
49: uint auStack456 [12];
50: int aiStack408 [12];
51: int aiStack360 [12];
52: undefined auStack312 [16];
53: undefined auStack296 [16];
54: undefined auStack280 [16];
55: undefined auStack264 [16];
56: undefined auStack248 [16];
57: undefined auStack232 [16];
58: undefined auStack216 [16];
59: undefined auStack200 [16];
60: undefined auStack184 [16];
61: undefined auStack168 [16];
62: void *apvStack152 [11];
63: long lStack64;
64: 
65: bVar30 = 0;
66: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
67: if (param_1 == 0) {
68: puVar14 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
69: *puVar14 = 0x2064696c61766e49;
70: *(undefined4 *)(puVar14 + 1) = 0x646e6168;
71: *(undefined2 *)((long)puVar14 + 0xc) = 0x656c;
72: *(undefined *)((long)puVar14 + 0xe) = 0;
73: uVar6 = 0xffffffff;
74: goto LAB_00151a12;
75: }
76: *(undefined4 *)(param_1 + 0x5f8) = 0;
77: *(undefined4 *)(param_1 + 0x6d0) = 0;
78: *(uint *)(param_1 + 0x5fc) = (int)param_10 >> 0xd & 1;
79: auStack232 = (undefined  [16])0x0;
80: auStack216 = (undefined  [16])0x0;
81: auStack200 = (undefined  [16])0x0;
82: auStack184 = (undefined  [16])0x0;
83: auStack168 = (undefined  [16])0x0;
84: auStack312 = (undefined  [16])0x0;
85: auStack296 = (undefined  [16])0x0;
86: auStack280 = (undefined  [16])0x0;
87: auStack264 = (undefined  [16])0x0;
88: auStack248 = (undefined  [16])0x0;
89: uStack696 = *(uint *)(param_1 + 0x600) & 1;
90: if (uStack696 == 0) {
91: *(undefined8 *)(param_1 + 0x648) = 0x736572706d6f6320;
92: *(undefined4 *)(param_1 + 0x650) = 0x6e6f6973;
93: *(undefined *)(param_1 + 0x654) = 0;
94: *(undefined4 *)(param_1 + 0x6d0) = 1;
95: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
96: *(undefined8 *)(param_1 + 0x610) = 0x55596d6f72467373;
97: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
98: *(undefined8 *)(param_1 + 0x620) = 0x6174736e49203a29;
99: *(undefined8 *)(param_1 + 0x628) = 0x207361682065636e;
100: *(undefined8 *)(param_1 + 0x630) = 0x6e65656220746f6e;
101: *(undefined8 *)(param_1 + 0x638) = 0x6c616974696e6920;
102: *(undefined8 *)(param_1 + 0x640) = 0x726f662064657a69;
103: puVar9 = (undefined4 *)
104: __tls_get_addr(0x6c616974696e6920,0x207361682065636e,0x2873656e616c5056,
105: 0x6572706d6f436a74,&PTR_00398fc0);
106: *(undefined8 *)(puVar9 + 0x10) = 0x736572706d6f6320;
107: puVar9[0x12] = 0x6e6f6973;
108: *(undefined *)(puVar9 + 0x13) = 0;
109: *puVar9 = 0x6f436a74;
110: puVar9[1] = 0x6572706d;
111: puVar9[2] = 0x72467373;
112: puVar9[3] = 0x55596d6f;
113: puVar9[4] = 0x616c5056;
114: puVar9[5] = 0x2873656e;
115: puVar9[6] = 0x49203a29;
116: puVar9[7] = 0x6174736e;
117: puVar9[8] = 0x2065636e;
118: puVar9[9] = 0x20736168;
119: puVar9[10] = 0x20746f6e;
120: puVar9[0xb] = 0x6e656562;
121: puVar9[0xc] = 0x696e6920;
122: puVar9[0xd] = 0x6c616974;
123: puVar9[0xe] = 0x64657a69;
124: puVar9[0xf] = 0x726f6620;
125: LAB_00151998:
126: pvStack872 = (void *)0x0;
127: uStack876 = 0xffffffff;
128: if (100 < *(int *)(param_1 + 0x24)) {
129: LAB_00151aa0:
130: (**(code **)(*(long *)(param_1 + 0x28) + 0x20))(param_1);
131: LAB_00151aaa:
132: thunk_FUN_0011f490(param_1);
133: }
134: }
135: else {
136: if ((((((param_2 == (long *)0x0) || (*param_2 == 0)) || (param_3 < 1)) ||
137: ((param_5 < 1 || (5 < param_6)))) ||
138: ((param_7 == 0 || ((param_8 == (undefined8 *)0x0 || (100 < param_9)))))) ||
139: ((param_6 != 3 && ((param_2[1] == 0 || (param_2[2] == 0)))))) {
140: *(undefined8 *)(param_1 + 0x628) = 0x6d75677261206469;
141: *(undefined4 *)(param_1 + 0x630) = 0x746e65;
142: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
143: *(undefined8 *)(param_1 + 0x610) = 0x55596d6f72467373;
144: *(undefined4 *)(param_1 + 0x6d0) = 1;
145: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
146: *(undefined8 *)(param_1 + 0x620) = 0x6c61766e49203a29;
147: puVar9 = (undefined4 *)__tls_get_addr(0x2873656e616c5056,0x6572706d6f436a74,&PTR_00398fc0);
148: *(undefined8 *)(puVar9 + 8) = 0x6d75677261206469;
149: puVar9[10] = 0x746e65;
150: *puVar9 = 0x6f436a74;
151: puVar9[1] = 0x6572706d;
152: puVar9[2] = 0x72467373;
153: puVar9[3] = 0x55596d6f;
154: puVar9[4] = 0x616c5056;
155: puVar9[5] = 0x2873656e;
156: puVar9[6] = 0x49203a29;
157: puVar9[7] = 0x6c61766e;
158: goto LAB_00151998;
159: }
160: pvStack872 = (void *)0x0;
161: iStack692 = 0;
162: iStack668 = 0;
163: uStack876 = 0;
164: iVar7 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
165: if (iVar7 == 0) {
166: *(int *)(param_1 + 0x30) = param_3;
167: *(int *)(param_1 + 0x34) = param_5;
168: if ((param_10 & 8) == 0) {
169: if ((param_10 & 0x10) == 0) {
170: if ((param_10 & 0x20) != 0) {
171: putenv("JSIMD_FORCESSE2=1");
172: }
173: }
174: else {
175: putenv("JSIMD_FORCESSE=1");
176: }
177: }
178: else {
179: putenv("JSIMD_FORCEMMX=1");
180: }
181: if ((param_10 & 0x400) != 0) {
182: uStack696 = 0;
183: uVar10 = tjBufSize(param_3,param_5,param_6);
184: *param_8 = uVar10;
185: }
186: FUN_00166fe0(param_1,param_7,param_8);
187: FUN_0014e450(param_1,0,param_6);
188: *(undefined4 *)(param_1 + 0x100) = 1;
189: FUN_00103000();
190: iVar3 = *(int *)(param_1 + 0x4c);
191: if (0 < iVar3) {
192: uVar23 = *(uint *)(param_1 + 0x138);
193: iVar4 = *(int *)(param_1 + 0x30);
194: uVar24 = *(uint *)(param_1 + 0x13c);
195: iVar20 = *(int *)(param_1 + 0x34);
196: lVar18 = 0;
197: piVar29 = (int *)(*(long *)(param_1 + 0x58) + 8);
198: do {
199: iVar25 = piVar29[1];
200: iVar1 = piVar29[5] * 8;
201: iVar5 = piVar29[6];
202: *(int *)((long)aiStack408 + lVar18) = iVar1;
203: uVar26 = (((uVar23 - 1) + iVar4 & -uVar23) * *piVar29) / uVar23;
204: *(uint *)((long)auStack504 + lVar18) = uVar26;
205: uVar8 = (((uVar24 - 1) + iVar20 & -uVar24) * iVar25) / uVar24;
206: *(uint *)((long)auStack456 + lVar18) = uVar8;
207: if ((uVar8 != iVar5 * 8) || (iVar1 - uVar26 != 0)) {
208: iStack692 = 1;
209: }
210: iVar25 = iVar25 * 8;
211: *(int *)((long)aiStack360 + lVar18) = iVar25;
212: iStack668 = iStack668 + iVar25 * iVar1;
213: plVar11 = (long *)malloc((long)(int)uVar8 << 3);
214: *(long **)(auStack312 + lVar18 * 2) = plVar11;
215: if (plVar11 == (long *)0x0) {
216: *(undefined4 *)(param_1 + 0x638) = 0x6572756c;
217: *(undefined *)(param_1 + 0x63c) = 0;
218: *(undefined4 *)(param_1 + 0x6d0) = 1;
219: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
220: *(undefined8 *)(param_1 + 0x610) = 0x55596d6f72467373;
221: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
222: *(undefined8 *)(param_1 + 0x620) = 0x726f6d654d203a29;
223: *(undefined8 *)(param_1 + 0x628) = 0x61636f6c6c612079;
224: *(undefined8 *)(param_1 + 0x630) = 0x696166206e6f6974;
225: puVar9 = (undefined4 *)
226: __tls_get_addr(0x61636f6c6c612079,0x2873656e616c5056,0x6572706d6f436a74,
227: &PTR_00398fc0);
228: puVar9[0xc] = 0x6572756c;
229: *(undefined *)(puVar9 + 0xd) = 0;
230: uStack876 = 0xffffffff;
231: *puVar9 = 0x6f436a74;
232: puVar9[1] = 0x6572706d;
233: puVar9[2] = 0x72467373;
234: puVar9[3] = 0x55596d6f;
235: puVar9[4] = 0x616c5056;
236: puVar9[5] = 0x2873656e;
237: puVar9[6] = 0x4d203a29;
238: puVar9[7] = 0x726f6d65;
239: puVar9[8] = 0x6c612079;
240: puVar9[9] = 0x61636f6c;
241: puVar9[10] = 0x6e6f6974;
242: puVar9[0xb] = 0x69616620;
243: goto LAB_00151a81;
244: }
245: lVar22 = *(long *)((long)param_2 + lVar18 * 2);
246: if (0 < (int)uVar8) {
247: if (param_4 == 0) {
248: plVar2 = plVar11 + (ulong)(uVar8 - 1) + 1;
249: do {
250: *plVar11 = lVar22;
251: plVar11 = plVar11 + 1;
252: lVar22 = lVar22 + (int)uVar26;
253: } while (plVar11 != plVar2);
254: }
255: else {
256: plVar2 = plVar11 + (ulong)(uVar8 - 1) + 1;
257: lVar12 = (long)*(int *)(param_4 + lVar18);
258: if (*(int *)(param_4 + lVar18) == 0) {
259: lVar12 = (long)(int)uVar26;
260: }
261: do {
262: *plVar11 = lVar22;
263: plVar11 = plVar11 + 1;
264: lVar22 = lVar22 + lVar12;
265: } while (plVar11 != plVar2);
266: }
267: }
268: piVar29 = piVar29 + 0x18;
269: lVar18 = lVar18 + 4;
270: } while (lVar18 != (ulong)(iVar3 - 1) * 4 + 4);
271: }
272: if (iStack692 == 0) {
273: LAB_00151e76:
274: iStack680 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
275: if (iStack680 != 0) goto LAB_0015209b;
276: if (0 < *(int *)(param_1 + 0x34)) {
277: iVar7 = *(int *)(param_1 + 0x13c);
278: do {
279: lVar18 = 0;
280: if (0 < *(int *)(param_1 + 0x4c)) {
281: do {
282: iVar3 = (iStack680 * *(int *)(lVar18 * 0x60 + *(long *)(param_1 + 0x58) + 0xc)) /
283: iVar7;
284: if (iStack692 == 0) {
285: apvStack152[lVar18] =
286: (void *)(*(long *)(auStack312 + lVar18 * 8) + (long)iVar3 * 8);
287: }
288: else {
289: iVar7 = aiStack360[lVar18];
290: iVar20 = auStack456[lVar18] - iVar3;
291: iVar4 = iVar7;
292: if (iVar20 <= iVar7) {
293: iVar4 = iVar20;
294: }
295: ppvVar15 = *(void ***)(auStack232 + lVar18 * 8);
296: if (0 < iVar4) {
297: uVar23 = auStack504[lVar18];
298: __n = SEXT48((int)uVar23);
299: ppvVar19 = (void **)(*(long *)(auStack312 + lVar18 * 8) + (long)iVar3 * 8);
300: ppvVar28 = ppvVar15;
301: do {
302: memcpy(*ppvVar28,*ppvVar19,__n);
303: iVar3 = aiStack408[lVar18];
304: if ((int)uVar23 < iVar3) {
305: sVar13 = __n;
306: do {
307: *(undefined *)((long)*ppvVar28 + sVar13) =
308: *(undefined *)((long)*ppvVar28 + (__n - 1));
309: sVar13 = sVar13 + 1;
310: } while ((ulong)((iVar3 + -1) - uVar23) + __n + 1 != sVar13);
311: }
312: ppvVar19 = ppvVar19 + 1;
313: ppvVar28 = ppvVar28 + 1;
314: } while (ppvVar28 != ppvVar15 + (ulong)(iVar4 - 1) + 1);
315: }
316: if (iVar20 < iVar7) {
317: lVar22 = (long)iVar20;
318: iVar3 = aiStack408[lVar18];
319: ppvVar19 = ppvVar15 + lVar22;
320: do {
321: pvVar27 = *ppvVar19;
322: ppvVar19 = ppvVar19 + 1;
323: memcpy(pvVar27,ppvVar15[lVar22 + -1],(long)iVar3);
324: } while (ppvVar19 !=
325: ppvVar15 + (ulong)(uint)((iVar7 + -1) - iVar20) + lVar22 + 1);
326: }
327: apvStack152[lVar18] = ppvVar15;
328: iVar7 = *(int *)(param_1 + 0x13c);
329: }
330: iVar3 = (int)lVar18;
331: lVar18 = lVar18 + 1;
332: } while (iVar3 + 1 < *(int *)(param_1 + 0x4c));
333: }
334: FUN_00103180(param_1,apvStack152,iVar7 * 8);
335: iVar7 = *(int *)(param_1 + 0x13c);
336: iStack680 = iStack680 + iVar7 * 8;
337: } while (*(int *)(param_1 + 0x34) != iStack680 && iStack680 <= *(int *)(param_1 + 0x34));
338: }
339: FUN_00102d50(param_1);
340: }
341: else {
342: pvStack872 = malloc((long)iStack668);
343: if (pvStack872 != (void *)0x0) {
344: if (0 < iVar3) {
345: lVar18 = 0;
346: pvVar27 = pvStack872;
347: do {
348: iVar4 = *(int *)((long)aiStack360 + lVar18);
349: ppvVar15 = (void **)malloc((long)iVar4 << 3);
350: *(void ***)(auStack232 + lVar18 * 2) = ppvVar15;
351: if (ppvVar15 == (void **)0x0) {
352: *(undefined4 *)(param_1 + 0x638) = 0x6572756c;
353: *(undefined *)(param_1 + 0x63c) = 0;
354: *(undefined4 *)(param_1 + 0x6d0) = 1;
355: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
356: *(undefined8 *)(param_1 + 0x610) = 0x55596d6f72467373;
357: *(undefined8 *)(param_1 + 0x618) = 0x2873656e616c5056;
358: *(undefined8 *)(param_1 + 0x620) = 0x726f6d654d203a29;
359: *(undefined8 *)(param_1 + 0x628) = 0x61636f6c6c612079;
360: *(undefined8 *)(param_1 + 0x630) = 0x696166206e6f6974;
361: puVar9 = (undefined4 *)
362: __tls_get_addr(0x61636f6c6c612079,0x2873656e616c5056,0x6572706d6f436a74,
363: &PTR_00398fc0);
364: puVar9[0xc] = 0x6572756c;
365: *(undefined *)(puVar9 + 0xd) = 0;
366: uStack876 = 0xffffffff;
367: *puVar9 = 0x6f436a74;
368: puVar9[1] = 0x6572706d;
369: puVar9[2] = 0x72467373;
370: puVar9[3] = 0x55596d6f;
371: puVar9[4] = 0x616c5056;
372: puVar9[5] = 0x2873656e;
373: puVar9[6] = 0x4d203a29;
374: puVar9[7] = 0x726f6d65;
375: puVar9[8] = 0x6c612079;
376: puVar9[9] = 0x61636f6c;
377: puVar9[10] = 0x6e6f6974;
378: puVar9[0xb] = 0x69616620;
379: goto LAB_00151a81;
380: }
381: if (0 < iVar4) {
382: lVar22 = (long)*(int *)((long)aiStack408 + lVar18);
383: uVar23 = (uint)((ulong)ppvVar15 >> 3) & 1;
384: pvVar17 = pvVar27;
385: iVar20 = iVar7;
386: if (iVar4 - 1U < 9) {
387: LAB_00152318:
388: ppvVar15[iVar20] = pvVar17;
389: if (iVar20 + 1 < iVar4) {
390: ppvVar15[iVar20 + 1] = (void *)((long)pvVar17 + lVar22);
391: pvVar17 = (void *)((long)(void *)((long)pvVar17 + lVar22) + lVar22);
392: if (iVar20 + 2 < iVar4) {
393: ppvVar15[iVar20 + 2] = pvVar17;
394: pvVar17 = (void *)((long)pvVar17 + lVar22);
395: if (iVar20 + 3 < iVar4) {
396: ppvVar15[iVar20 + 3] = pvVar17;
397: pvVar17 = (void *)((long)pvVar17 + lVar22);
398: if (iVar20 + 4 < iVar4) {
399: ppvVar15[iVar20 + 4] = pvVar17;
400: pvVar17 = (void *)((long)pvVar17 + lVar22);
401: if (iVar20 + 5 < iVar4) {
402: ppvVar15[iVar20 + 5] = pvVar17;
403: pvVar17 = (void *)((long)pvVar17 + lVar22);
404: if (iVar20 + 6 < iVar4) {
405: ppvVar15[iVar20 + 6] = pvVar17;
406: pvVar17 = (void *)((long)pvVar17 + lVar22);
407: if (iVar20 + 7 < iVar4) {
408: ppvVar15[iVar20 + 7] = pvVar17;
409: if (iVar20 + 8 < iVar4) {
410: ppvVar15[iVar20 + 8] = (void *)((long)pvVar17 + lVar22);
411: }
412: }
413: }
414: }
415: }
416: }
417: }
418: }
419: }
420: else {
421: if (((ulong)ppvVar15 >> 3 & 1) != 0) {
422: *ppvVar15 = pvVar27;
423: pvVar17 = (void *)((long)pvVar27 + lVar22);
424: iVar20 = iStack692;
425: }
426: pvVar32 = (void *)(lVar22 + (long)pvVar17);
427: uVar26 = iVar4 - uVar23;
428: uVar24 = 0;
429: ppvVar19 = ppvVar15 + uVar23;
430: pvVar31 = pvVar17;
431: do {
432: uVar24 = uVar24 + 1;
433: *ppvVar19 = pvVar31;
434: ppvVar19[1] = pvVar32;
435: pvVar31 = (void *)((long)pvVar31 + lVar22 * 2);
436: pvVar32 = (void *)((long)pvVar32 + lVar22 * 2);
437: ppvVar19 = ppvVar19 + 2;
438: } while (uVar24 < uVar26 >> 1);
439: uVar23 = uVar26 & 0xfffffffe;
440: pvVar17 = (void *)((long)pvVar17 + (ulong)uVar23 * lVar22);
441: iVar20 = iVar20 + uVar23;
442: if (uVar23 != uVar26) goto LAB_00152318;
443: }
444: pvVar27 = (void *)((long)pvVar27 + lVar22 * ((ulong)(iVar4 - 1U) + 1));
445: }
446: lVar18 = lVar18 + 4;
447: } while (lVar18 != (ulong)(iVar3 - 1) * 4 + 4);
448: }
449: goto LAB_00151e76;
450: }
451: lVar18 = 0x35;
452: pcVar21 = "tjCompressFromYUVPlanes(): Memory allocation failure";
453: pcVar16 = (char *)(param_1 + 0x608);
454: while (lVar18 != 0) {
455: lVar18 = lVar18 + -1;
456: *pcVar16 = *pcVar21;
457: pcVar21 = pcVar21 + (ulong)bVar30 * -2 + 1;
458: pcVar16 = pcVar16 + (ulong)bVar30 * -2 + 1;
459: }
460: *(undefined4 *)(param_1 + 0x6d0) = 1;
461: pcVar16 = (char *)__tls_get_addr(&PTR_00398fc0);
462: lVar18 = 0x35;
463: uStack876 = 0xffffffff;
464: pcVar21 = "tjCompressFromYUVPlanes(): Memory allocation failure";
465: while (lVar18 != 0) {
466: lVar18 = lVar18 + -1;
467: *pcVar16 = *pcVar21;
468: pcVar21 = pcVar21 + (ulong)bVar30 * -2 + 1;
469: pcVar16 = pcVar16 + (ulong)bVar30 * -2 + 1;
470: }
471: }
472: }
473: else {
474: LAB_0015209b:
475: uStack876 = 0xffffffff;
476: }
477: LAB_00151a81:
478: if (100 < *(int *)(param_1 + 0x24)) {
479: if (uStack696 != 0) goto LAB_00151aa0;
480: goto LAB_00151aaa;
481: }
482: }
483: lVar18 = 0;
484: do {
485: free(*(void **)(auStack232 + lVar18));
486: ppvVar15 = (void **)(auStack312 + lVar18);
487: lVar18 = lVar18 + 8;
488: free(*ppvVar15);
489: } while (lVar18 != 0x50);
490: free(pvStack872);
491: *(undefined4 *)(param_1 + 0x5fc) = 0;
492: uVar6 = 0xffffffff;
493: if (*(int *)(param_1 + 0x5f8) == 0) {
494: uVar6 = uStack876;
495: }
496: LAB_00151a12:
497: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
498: /* WARNING: Subroutine does not return */
499: __stack_chk_fail();
500: }
501: return uVar6;
502: }
503: 
