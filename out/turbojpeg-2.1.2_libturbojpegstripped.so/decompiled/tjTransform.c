1: 
2: int tjTransform(long param_1,long param_2,long param_3,int param_4,long param_5,undefined8 *param_6,
3: undefined4 *param_7,uint param_8)
4: 
5: {
6: long lVar1;
7: undefined4 uVar2;
8: undefined4 uVar3;
9: int iVar4;
10: uint uVar5;
11: int iVar6;
12: uint uVar7;
13: int iVar8;
14: int iVar9;
15: undefined4 *puVar10;
16: undefined4 *puVar11;
17: undefined8 *puVar12;
18: undefined8 uVar13;
19: long lVar14;
20: int *piVar15;
21: long lVar16;
22: uint uVar17;
23: long lVar18;
24: long lVar19;
25: long in_FS_OFFSET;
26: undefined8 uVar20;
27: int iStack572;
28: void *pvStack568;
29: int iStack392;
30: int iStack384;
31: int iStack324;
32: ulong uStack320;
33: long lStack296;
34: undefined4 *puStack288;
35: long lStack280;
36: undefined8 *puStack272;
37: uint uStack264;
38: code *pcStack104;
39: undefined auStack96 [16];
40: undefined8 uStack80;
41: long lStack72;
42: long lStack64;
43: 
44: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
45: if (param_1 == 0) {
46: puVar12 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
47: *puVar12 = 0x2064696c61766e49;
48: *(undefined4 *)(puVar12 + 1) = 0x646e6168;
49: *(undefined2 *)((long)puVar12 + 0xc) = 0x656c;
50: *(undefined *)((long)puVar12 + 0xe) = 0;
51: iVar6 = -1;
52: goto LAB_001583a5;
53: }
54: lVar1 = param_1 + 0x208;
55: *(undefined4 *)(param_1 + 0x5f8) = 0;
56: *(undefined4 *)(param_1 + 0x6d0) = 0;
57: *(uint *)(param_1 + 0x5fc) = (int)param_8 >> 0xd & 1;
58: if ((*(uint *)(param_1 + 0x600) & 3) == 3) {
59: if (((((param_2 == 0) || (param_3 == 0)) || (param_4 < 1)) ||
60: ((param_5 == 0 || (param_6 == (undefined8 *)0x0 || param_7 == (undefined4 *)0x0)))) ||
61: ((int)param_8 < 0)) {
62: *(undefined4 *)(param_1 + 0x6d0) = 1;
63: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
64: *(undefined8 *)(param_1 + 0x610) = 0x49203a29286d726f;
65: *(undefined8 *)(param_1 + 0x618) = 0x612064696c61766e;
66: *(undefined8 *)(param_1 + 0x620) = 0x746e656d756772;
67: puVar11 = (undefined4 *)__tls_get_addr(0x612064696c61766e,0x66736e6172546a74,&PTR_00398fc0);
68: *puVar11 = 0x72546a74;
69: puVar11[1] = 0x66736e61;
70: puVar11[2] = 0x286d726f;
71: puVar11[3] = 0x49203a29;
72: puVar11[4] = 0x6c61766e;
73: puVar11[5] = 0x61206469;
74: puVar11[6] = 0x6d756772;
75: puVar11[7] = 0x746e65;
76: goto LAB_0015834c;
77: }
78: if ((param_8 & 8) == 0) {
79: if ((param_8 & 0x10) == 0) {
80: if ((param_8 & 0x20) != 0) {
81: putenv("JSIMD_FORCESSE2=1");
82: }
83: }
84: else {
85: putenv("JSIMD_FORCESSE=1");
86: }
87: }
88: else {
89: putenv("JSIMD_FORCEMMX=1");
90: }
91: if ((param_8 & 0x8000) == 0) {
92: *(undefined8 *)(param_1 + 0x218) = 0;
93: }
94: else {
95: uStack80 = 0;
96: auStack96 = (undefined  [16])0x0;
97: pcStack104 = FUN_0014eb60;
98: *(code ***)(param_1 + 0x218) = &pcStack104;
99: lStack72 = param_1;
100: }
101: pvStack568 = calloc((long)param_4 * 0x78,1);
102: if (pvStack568 == (void *)0x0) {
103: *(undefined8 *)(param_1 + 0x628) = 0x6572756c69616620;
104: *(undefined *)(param_1 + 0x630) = 0;
105: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
106: *(undefined8 *)(param_1 + 0x610) = 0x4d203a29286d726f;
107: *(undefined4 *)(param_1 + 0x6d0) = 1;
108: *(undefined8 *)(param_1 + 0x618) = 0x6c612079726f6d65;
109: *(undefined8 *)(param_1 + 0x620) = 0x6e6f697461636f6c;
110: puVar11 = (undefined4 *)__tls_get_addr(0x6c612079726f6d65,0x66736e6172546a74,&PTR_00398fc0);
111: *(undefined8 *)(puVar11 + 8) = 0x6572756c69616620;
112: *(undefined *)(puVar11 + 10) = 0;
113: *puVar11 = 0x72546a74;
114: puVar11[1] = 0x66736e61;
115: puVar11[2] = 0x286d726f;
116: puVar11[3] = 0x4d203a29;
117: puVar11[4] = 0x726f6d65;
118: puVar11[5] = 0x6c612079;
119: puVar11[6] = 0x61636f6c;
120: puVar11[7] = 0x6e6f6974;
121: goto LAB_0015834c;
122: }
123: iStack384 = 0;
124: iStack392 = 1;
125: iStack572 = 0;
126: uVar5 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
127: if (uVar5 == 0) {
128: FUN_00167270(lVar1,param_2,param_3);
129: if (0 < param_4) {
130: lVar18 = 0;
131: puVar11 = param_7;
132: do {
133: while( true ) {
134: iVar6 = puVar11[4];
135: puVar10 = (undefined4 *)((long)pvStack568 + lVar18);
136: *puVar10 = *(undefined4 *)(&DAT_0018fd40 + (long)iVar6 * 4);
137: uVar7 = puVar11[5];
138: puVar10[1] = uVar7 & 1;
139: puVar10[2] = (int)uVar7 >> 1 & 1;
140: puVar10[3] = (int)uVar7 >> 3 & 1;
141: uVar17 = (int)uVar7 >> 2 & 1;
142: puVar10[4] = uVar17;
143: puVar10[5] = (uint)(param_4 != 1 && iVar6 == 1);
144: if (uVar17 != 0) {
145: uVar2 = *puVar11;
146: iVar6 = puVar11[2];
147: puVar10[0xb] = 1;
148: puVar10[0xd] = 1;
149: puVar10[10] = uVar2;
150: puVar10[0xc] = puVar11[1];
151: iVar9 = 0;
152: if (iVar6 != 0) {
153: puVar10[7] = 1;
154: iVar9 = iVar6;
155: }
156: puVar10[6] = iVar9;
157: if (puVar11[3] == 0) {
158: puVar10[8] = 0;
159: }
160: else {
161: puVar10[8] = puVar11[3];
162: puVar10[9] = 1;
163: }
164: }
165: puVar11 = puVar11 + 10;
166: lVar18 = lVar18 + 0x78;
167: if ((uVar7 & 0x40) != 0) break;
168: if (puVar11 == param_7 + (ulong)(param_4 - 1) * 10 + 10) {
169: iStack384 = 2;
170: goto LAB_001586b2;
171: }
172: iStack384 = 1;
173: }
174: } while (param_7 + (ulong)(param_4 - 1) * 10 + 10 != puVar11);
175: }
176: iStack384 = iStack384 * 2;
177: LAB_001586b2:
178: FUN_00166c90(lVar1,iStack384);
179: FUN_00125330(lVar1,1);
180: if (*(long *)(param_1 + 0x240) == 0x100000001) {
181: iStack324 = 3;
182: }
183: else {
184: iStack324 = FUN_0014e860(lVar1);
185: if (iStack324 < 0) {
186: *(undefined2 *)(param_1 + 0x648) = 0x6567;
187: *(undefined *)(param_1 + 0x64a) = 0;
188: *(undefined4 *)(param_1 + 0x6d0) = 1;
189: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
190: *(undefined8 *)(param_1 + 0x610) = 0x43203a29286d726f;
191: *(undefined8 *)(param_1 + 0x618) = 0x746f6e20646c756f;
192: *(undefined8 *)(param_1 + 0x620) = 0x696d726574656420;
193: *(undefined8 *)(param_1 + 0x628) = 0x617362757320656e;
194: *(undefined8 *)(param_1 + 0x630) = 0x7420676e696c706d;
195: *(undefined8 *)(param_1 + 0x638) = 0x20726f6620657079;
196: *(undefined8 *)(param_1 + 0x640) = 0x616d69204745504a;
197: puVar11 = (undefined4 *)
198: __tls_get_addr(0x20726f6620657079,0x617362757320656e,0x746f6e20646c756f,
199: 0x66736e6172546a74,&PTR_00398fc0);
200: *(undefined2 *)(puVar11 + 0x10) = 0x6567;
201: *(undefined *)((long)puVar11 + 0x42) = 0;
202: iStack572 = -1;
203: *puVar11 = 0x72546a74;
204: puVar11[1] = 0x66736e61;
205: puVar11[2] = 0x286d726f;
206: puVar11[3] = 0x43203a29;
207: puVar11[4] = 0x646c756f;
208: puVar11[5] = 0x746f6e20;
209: puVar11[6] = 0x74656420;
210: puVar11[7] = 0x696d7265;
211: puVar11[8] = 0x7320656e;
212: puVar11[9] = 0x61736275;
213: puVar11[10] = 0x696c706d;
214: puVar11[0xb] = 0x7420676e;
215: puVar11[0xc] = 0x20657079;
216: puVar11[0xd] = 0x20726f66;
217: puVar11[0xe] = 0x4745504a;
218: puVar11[0xf] = 0x616d6920;
219: goto LAB_0015827d;
220: }
221: }
222: if (0 < param_4) {
223: lVar18 = 0;
224: piVar15 = param_7 + 1;
225: do {
226: uVar20 = 0x1587b3;
227: iVar6 = FUN_00166290(lVar1);
228: if (iVar6 == 0) {
229: *(undefined8 *)(param_1 + 0x628) = 0x74636566726570;
230: *(undefined4 *)(param_1 + 0x6d0) = 1;
231: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
232: *(undefined8 *)(param_1 + 0x610) = 0x54203a29286d726f;
233: *(undefined8 *)(param_1 + 0x618) = 0x6d726f66736e6172;
234: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20736920;
235: puVar11 = (undefined4 *)
236: __tls_get_addr(0x6d726f66736e6172,0x66736e6172546a74,&PTR_00398fc0);
237: *(undefined8 *)(puVar11 + 8) = 0x74636566726570;
238: iStack572 = -1;
239: *puVar11 = 0x72546a74;
240: puVar11[1] = 0x66736e61;
241: puVar11[2] = 0x286d726f;
242: puVar11[3] = 0x54203a29;
243: puVar11[4] = 0x736e6172;
244: puVar11[5] = 0x6d726f66;
245: puVar11[6] = 0x20736920;
246: puVar11[7] = 0x20746f6e;
247: goto LAB_0015827d;
248: }
249: if (*(int *)((long)pvStack568 + lVar18 + 0x10) != 0) {
250: if ((piVar15[-1] % *(int *)(&DAT_0018fdd0 + (long)iStack324 * 4) != 0) ||
251: (*piVar15 % *(int *)(&DAT_0018fdb0 + (long)iStack324 * 4) != 0)) {
252: __snprintf_chk(param_1 + 0x608,200,1,200,
253: 
254: "To crop this JPEG image, x must be a multiple of %d\nand y must be a multiple of %d.\n"
255: ,*(int *)(&DAT_0018fdd0 + (long)iStack324 * 4),
256: *(int *)(&DAT_0018fdb0 + (long)iStack324 * 4),uVar20);
257: *(undefined4 *)(param_1 + 0x6d0) = 1;
258: iStack572 = -1;
259: goto LAB_0015827d;
260: }
261: }
262: lVar18 = lVar18 + 0x78;
263: piVar15 = piVar15 + 10;
264: } while (((ulong)(param_4 - 1) + 1) * 0x78 != lVar18);
265: }
266: uVar20 = FUN_0013dd20(lVar1);
267: if (0 < param_4) {
268: lStack280 = 0;
269: uStack320 = 0;
270: puStack288 = param_7;
271: puStack272 = param_6;
272: do {
273: lVar18 = (long)pvStack568 + lStack280;
274: if (*(int *)(lVar18 + 0x10) == 0) {
275: uVar2 = *(undefined4 *)(param_1 + 0x238);
276: uVar3 = *(undefined4 *)(param_1 + 0x23c);
277: }
278: else {
279: uVar2 = *(undefined4 *)(lVar18 + 0x18);
280: uVar3 = *(undefined4 *)(lVar18 + 0x20);
281: }
282: if ((param_8 & 0x400) != 0) {
283: iStack392 = 0;
284: uVar13 = tjBufSize(uVar2,uVar3,iStack324);
285: *puStack272 = uVar13;
286: }
287: if ((*(byte *)(puStack288 + 5) & 0x10) == 0) {
288: FUN_00166fe0(param_1,param_5 + uStack320 * 8,puStack272,iStack392);
289: }
290: FUN_00124be0(lVar1,param_1);
291: lVar18 = FUN_00159be0(lVar1,param_1,uVar20,lVar18);
292: if (((param_8 & 0x4000) != 0) || (uVar7 = puStack288[5], (uVar7 & 0x20) != 0)) {
293: FUN_0011ffa0(param_1);
294: uVar7 = puStack288[5];
295: }
296: if ((uVar7 & 0x10) == 0) {
297: FUN_001249b0(param_1,lVar18);
298: FUN_00166e30(lVar1,param_1,((*(byte *)(puStack288 + 5) & 0x40) == 0) * '\x02');
299: }
300: else {
301: FUN_0011f0b0(param_1,1);
302: }
303: FUN_0015a610(lVar1,param_1,uVar20);
304: if ((*(long *)(puStack288 + 8) != 0) && (0 < *(int *)(param_1 + 0x4c))) {
305: lStack296 = 0;
306: do {
307: iVar9 = (int)lStack296;
308: lVar16 = lStack296 * 0x60 + *(long *)(param_1 + 0x58);
309: iVar6 = *(int *)(lVar16 + 0x20);
310: uVar7 = *(int *)(lVar16 + 0x1c) * 8;
311: if (iVar6 != 0) {
312: iVar8 = *(int *)(lVar16 + 0xc);
313: uStack264 = 0;
314: uVar17 = uVar5;
315: do {
316: lVar14 = (**(code **)(*(long *)(param_1 + 0x210) + 0x40))
317: (lVar1,*(undefined8 *)(lVar18 + lStack296 * 8),uStack264,iVar8,
318: 1);
319: iVar8 = *(int *)(lVar16 + 0xc);
320: if (0 < iVar8) {
321: lVar19 = 1;
322: do {
323: iVar8 = (**(code **)(puStack288 + 8))
324: (*(undefined8 *)(lVar14 + -8 + lVar19 * 8),
325: (ulong)uVar17 << 0x20,(ulong)uVar7 | 0x800000000,0,
326: CONCAT44(iVar6 * 8,uVar7),iVar9,uStack320 & 0xffffffff);
327: if (iVar8 == -1) {
328: *(undefined4 *)(param_1 + 0x628) = 0x65746c69;
329: *(undefined2 *)(param_1 + 0x62c) = 0x72;
330: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
331: *(undefined8 *)(param_1 + 0x610) = 0x45203a29286d726f;
332: *(undefined4 *)(param_1 + 0x6d0) = 1;
333: *(undefined8 *)(param_1 + 0x618) = 0x206e6920726f7272;
334: *(undefined8 *)(param_1 + 0x620) = 0x66206d6f74737563;
335: puVar11 = (undefined4 *)
336: __tls_get_addr(0x206e6920726f7272,0x66736e6172546a74,&PTR_00398fc0
337: );
338: puVar11[8] = 0x65746c69;
339: *(undefined2 *)(puVar11 + 9) = 0x72;
340: *puVar11 = 0x72546a74;
341: puVar11[1] = 0x66736e61;
342: puVar11[2] = 0x286d726f;
343: puVar11[3] = 0x45203a29;
344: puVar11[4] = 0x726f7272;
345: puVar11[5] = 0x206e6920;
346: puVar11[6] = 0x74737563;
347: puVar11[7] = 0x66206d6f;
348: iStack572 = iVar8;
349: goto LAB_0015827d;
350: }
351: iVar8 = *(int *)(lVar16 + 0xc);
352: iVar4 = (int)lVar19;
353: uVar17 = uVar17 + 8;
354: lVar19 = lVar19 + 1;
355: } while (iVar4 < iVar8);
356: }
357: uStack264 = uStack264 + iVar8;
358: } while (uStack264 <= *(uint *)(lVar16 + 0x20) &&
359: *(uint *)(lVar16 + 0x20) != uStack264);
360: }
361: lStack296 = lStack296 + 1;
362: iVar9 = iVar9 + 1;
363: } while (*(int *)(param_1 + 0x4c) != iVar9 && iVar9 <= *(int *)(param_1 + 0x4c));
364: }
365: if ((*(byte *)(puStack288 + 5) & 0x10) == 0) {
366: FUN_00102d50();
367: }
368: uStack320 = uStack320 + 1;
369: lStack280 = lStack280 + 0x78;
370: puStack288 = puStack288 + 10;
371: puStack272 = puStack272 + 1;
372: } while ((ulong)(param_4 - 1) + 1 != uStack320);
373: }
374: FUN_00125410(lVar1);
375: }
376: else {
377: iStack572 = -1;
378: }
379: LAB_0015827d:
380: if (*(int *)(param_1 + 0x24) < 0x65) goto LAB_00158367;
381: if (iStack392 != 0) goto LAB_001582a0;
382: LAB_001582aa:
383: thunk_FUN_0011f490(param_1);
384: iVar6 = *(int *)(param_1 + 0x22c);
385: }
386: else {
387: *(undefined4 *)(param_1 + 0x648) = 0x6e6f69;
388: *(undefined4 *)(param_1 + 0x6d0) = 1;
389: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
390: *(undefined8 *)(param_1 + 0x610) = 0x49203a29286d726f;
391: *(undefined8 *)(param_1 + 0x618) = 0x2065636e6174736e;
392: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20736168;
393: *(undefined8 *)(param_1 + 0x628) = 0x696e69206e656562;
394: *(undefined8 *)(param_1 + 0x630) = 0x64657a696c616974;
395: *(undefined8 *)(param_1 + 0x638) = 0x61727420726f6620;
396: *(undefined8 *)(param_1 + 0x640) = 0x74616d726f66736e;
397: puVar11 = (undefined4 *)
398: __tls_get_addr(0x61727420726f6620,0x696e69206e656562,0x2065636e6174736e,
399: 0x66736e6172546a74,&PTR_00398fc0);
400: puVar11[0x10] = 0x6e6f69;
401: *puVar11 = 0x72546a74;
402: puVar11[1] = 0x66736e61;
403: puVar11[2] = 0x286d726f;
404: puVar11[3] = 0x49203a29;
405: puVar11[4] = 0x6174736e;
406: puVar11[5] = 0x2065636e;
407: puVar11[6] = 0x20736168;
408: puVar11[7] = 0x20746f6e;
409: puVar11[8] = 0x6e656562;
410: puVar11[9] = 0x696e6920;
411: puVar11[10] = 0x6c616974;
412: puVar11[0xb] = 0x64657a69;
413: puVar11[0xc] = 0x726f6620;
414: puVar11[0xd] = 0x61727420;
415: puVar11[0xe] = 0x6f66736e;
416: puVar11[0xf] = 0x74616d72;
417: LAB_0015834c:
418: iStack572 = -1;
419: pvStack568 = (void *)0x0;
420: if (100 < *(int *)(param_1 + 0x24)) {
421: LAB_001582a0:
422: (**(code **)(*(long *)(param_1 + 0x28) + 0x20))(param_1);
423: goto LAB_001582aa;
424: }
425: LAB_00158367:
426: iVar6 = *(int *)(param_1 + 0x22c);
427: }
428: if (200 < iVar6) {
429: thunk_FUN_0011f490(lVar1);
430: }
431: free(pvStack568);
432: *(undefined4 *)(param_1 + 0x5fc) = 0;
433: iVar6 = -1;
434: if (*(int *)(param_1 + 0x5f8) == 0) {
435: iVar6 = iStack572;
436: }
437: LAB_001583a5:
438: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
439: return iVar6;
440: }
441: /* WARNING: Subroutine does not return */
442: __stack_chk_fail();
443: }
444: 
