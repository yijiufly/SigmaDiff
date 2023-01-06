1: 
2: undefined4
3: tjEncodeYUVPlanes(long *param_1,long param_2,int param_3,int param_4,uint param_5,uint param_6,
4: long *param_7,long param_8,uint param_9,uint param_10)
5: 
6: {
7: int *piVar1;
8: void **ppvVar2;
9: int iVar3;
10: int iVar4;
11: bool bVar5;
12: int iVar6;
13: undefined4 uVar7;
14: int iVar8;
15: void *pvVar9;
16: ulong *puVar10;
17: long *plVar11;
18: long lVar12;
19: undefined8 *puVar13;
20: undefined4 *puVar14;
21: long *plVar15;
22: long *plVar16;
23: uint uVar17;
24: uint uVar18;
25: long lVar19;
26: uint uVar20;
27: uint uVar21;
28: uint uVar22;
29: uint uVar23;
30: long lVar24;
31: ulong *puVar25;
32: ulong uVar26;
33: uint uVar27;
34: uint uVar28;
35: uint *puVar29;
36: long in_FS_OFFSET;
37: ulong uVar30;
38: undefined auVar31 [16];
39: int iVar32;
40: int iVar33;
41: int iVar34;
42: ulong uVar35;
43: int iVar36;
44: int iVar37;
45: undefined4 uStack1100;
46: long *plStack1096;
47: int iStack1044;
48: int iStack936;
49: int iStack932;
50: int aiStack520 [12];
51: undefined auStack472 [16];
52: undefined auStack456 [16];
53: undefined auStack440 [16];
54: undefined auStack424 [16];
55: undefined auStack408 [16];
56: undefined auStack392 [16];
57: undefined auStack376 [16];
58: undefined auStack360 [16];
59: undefined auStack344 [16];
60: undefined auStack328 [16];
61: undefined auStack312 [16];
62: undefined auStack296 [16];
63: undefined auStack280 [16];
64: undefined auStack264 [16];
65: undefined auStack248 [16];
66: undefined auStack232 [16];
67: undefined auStack216 [16];
68: undefined auStack200 [16];
69: undefined auStack184 [16];
70: undefined auStack168 [16];
71: undefined auStack152 [16];
72: undefined auStack136 [16];
73: undefined auStack120 [16];
74: undefined auStack104 [16];
75: undefined auStack88 [16];
76: long lStack64;
77: 
78: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
79: if (param_1 == (long *)0x0) {
80: puVar13 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
81: *puVar13 = 0x2064696c61766e49;
82: *(undefined4 *)(puVar13 + 1) = 0x646e6168;
83: *(undefined2 *)((long)puVar13 + 0xc) = 0x656c;
84: *(undefined *)((long)puVar13 + 0xe) = 0;
85: uVar7 = 0xffffffff;
86: goto LAB_001508ff;
87: }
88: *(undefined4 *)(param_1 + 0xbf) = 0;
89: *(undefined4 *)(param_1 + 0xda) = 0;
90: *(uint *)((long)param_1 + 0x5fc) = (int)param_10 >> 0xd & 1;
91: auStack312 = (undefined  [16])0x0;
92: auStack296 = (undefined  [16])0x0;
93: auStack280 = (undefined  [16])0x0;
94: auStack264 = (undefined  [16])0x0;
95: auStack248 = (undefined  [16])0x0;
96: auStack472 = (undefined  [16])0x0;
97: auStack456 = (undefined  [16])0x0;
98: auStack440 = (undefined  [16])0x0;
99: auStack424 = (undefined  [16])0x0;
100: auStack408 = (undefined  [16])0x0;
101: auStack232 = (undefined  [16])0x0;
102: auStack216 = (undefined  [16])0x0;
103: auStack200 = (undefined  [16])0x0;
104: auStack184 = (undefined  [16])0x0;
105: auStack168 = (undefined  [16])0x0;
106: auStack392 = (undefined  [16])0x0;
107: auStack376 = (undefined  [16])0x0;
108: auStack360 = (undefined  [16])0x0;
109: auStack344 = (undefined  [16])0x0;
110: auStack328 = (undefined  [16])0x0;
111: auStack152 = (undefined  [16])0x0;
112: auStack136 = (undefined  [16])0x0;
113: auStack120 = (undefined  [16])0x0;
114: auStack104 = (undefined  [16])0x0;
115: auStack88 = (undefined  [16])0x0;
116: if ((*(byte *)(param_1 + 0xc0) & 1) == 0) {
117: *(undefined4 *)(param_1 + 0xc9) = 0x69737365;
118: *(undefined2 *)((long)param_1 + 0x64c) = 0x6e6f;
119: *(undefined *)((long)param_1 + 0x64e) = 0;
120: *(undefined4 *)(param_1 + 0xda) = 1;
121: param_1[0xc1] = 0x65646f636e456a74;
122: param_1[0xc2] = 0x656e616c50565559;
123: param_1[0xc3] = 0x736e49203a292873;
124: param_1[0xc4] = 0x61682065636e6174;
125: param_1[0xc5] = 0x656220746f6e2073;
126: param_1[0xc6] = 0x6974696e69206e65;
127: param_1[199] = 0x662064657a696c61;
128: param_1[200] = 0x72706d6f6320726f;
129: puVar14 = (undefined4 *)
130: __tls_get_addr(0x662064657a696c61,0x656220746f6e2073,0x736e49203a292873,
131: 0x65646f636e456a74,&PTR_00398fc0);
132: puVar14[0x10] = 0x69737365;
133: *(undefined2 *)(puVar14 + 0x11) = 0x6e6f;
134: *(undefined *)((long)puVar14 + 0x46) = 0;
135: uStack1100 = 0xffffffff;
136: plStack1096 = (long *)0x0;
137: *puVar14 = 0x6e456a74;
138: puVar14[1] = 0x65646f63;
139: puVar14[2] = 0x50565559;
140: puVar14[3] = 0x656e616c;
141: puVar14[4] = 0x3a292873;
142: puVar14[5] = 0x736e4920;
143: puVar14[6] = 0x636e6174;
144: puVar14[7] = 0x61682065;
145: puVar14[8] = 0x6f6e2073;
146: puVar14[9] = 0x65622074;
147: puVar14[10] = 0x69206e65;
148: puVar14[0xb] = 0x6974696e;
149: puVar14[0xc] = 0x7a696c61;
150: puVar14[0xd] = 0x66206465;
151: puVar14[0xe] = 0x6320726f;
152: puVar14[0xf] = 0x72706d6f;
153: iVar6 = *(int *)((long)param_1 + 0x24);
154: }
155: else {
156: if ((((((param_2 == 0) || (param_3 < 1)) || (param_4 < 0)) ||
157: (((int)param_5 < 1 || (0xb < param_6)))) ||
158: ((param_7 == (long *)0x0 || ((*param_7 == 0 || (5 < param_9)))))) ||
159: ((param_9 != 3 && ((param_7[1] == 0 || (param_7[2] == 0)))))) {
160: *(undefined4 *)(param_1 + 0xc5) = 0x6e656d75;
161: *(undefined2 *)((long)param_1 + 0x62c) = 0x74;
162: param_1[0xc1] = 0x65646f636e456a74;
163: param_1[0xc2] = 0x656e616c50565559;
164: *(undefined4 *)(param_1 + 0xda) = 1;
165: param_1[0xc3] = 0x766e49203a292873;
166: param_1[0xc4] = 0x6772612064696c61;
167: puVar14 = (undefined4 *)__tls_get_addr(0x766e49203a292873,0x65646f636e456a74,&PTR_00398fc0);
168: puVar14[8] = 0x6e656d75;
169: *(undefined2 *)(puVar14 + 9) = 0x74;
170: uStack1100 = 0xffffffff;
171: plStack1096 = (long *)0x0;
172: *puVar14 = 0x6e456a74;
173: puVar14[1] = 0x65646f63;
174: puVar14[2] = 0x50565559;
175: puVar14[3] = 0x656e616c;
176: puVar14[4] = 0x3a292873;
177: puVar14[5] = 0x766e4920;
178: puVar14[6] = 0x64696c61;
179: puVar14[7] = 0x67726120;
180: }
181: else {
182: if (param_6 == 0xb) {
183: *(undefined *)(param_1 + 0xc9) = 0;
184: *(undefined4 *)(param_1 + 0xda) = 1;
185: param_1[0xc1] = 0x65646f636e456a74;
186: param_1[0xc2] = 0x656e616c50565559;
187: param_1[0xc3] = 0x6e6143203a292873;
188: param_1[0xc4] = 0x656e656720746f6e;
189: param_1[0xc5] = 0x5655592065746172;
190: param_1[0xc6] = 0x20736567616d6920;
191: param_1[199] = 0x594d43206d6f7266;
192: param_1[200] = 0x736c65786970204b;
193: puVar14 = (undefined4 *)
194: __tls_get_addr(0x594d43206d6f7266,0x5655592065746172,0x6e6143203a292873,
195: 0x65646f636e456a74,&PTR_00398fc0);
196: *(undefined *)(puVar14 + 0x10) = 0;
197: uStack1100 = 0xffffffff;
198: plStack1096 = (long *)0x0;
199: *puVar14 = 0x6e456a74;
200: puVar14[1] = 0x65646f63;
201: puVar14[2] = 0x50565559;
202: puVar14[3] = 0x656e616c;
203: puVar14[4] = 0x3a292873;
204: puVar14[5] = 0x6e614320;
205: puVar14[6] = 0x20746f6e;
206: puVar14[7] = 0x656e6567;
207: puVar14[8] = 0x65746172;
208: puVar14[9] = 0x56555920;
209: puVar14[10] = 0x616d6920;
210: puVar14[0xb] = 0x20736567;
211: puVar14[0xc] = 0x6d6f7266;
212: puVar14[0xd] = 0x594d4320;
213: puVar14[0xe] = 0x6970204b;
214: puVar14[0xf] = 0x736c6578;
215: }
216: else {
217: iStack1044 = param_4;
218: if (param_4 == 0) {
219: iStack1044 = param_3 * *(int *)(&DAT_0018fd80 + (long)(int)param_6 * 4);
220: }
221: uStack1100 = 0;
222: plStack1096 = (long *)0x0;
223: iVar6 = _setjmp((__jmp_buf_tag *)(param_1 + 0xa5));
224: if (iVar6 == 0) {
225: *(int *)(param_1 + 6) = param_3;
226: *(uint *)((long)param_1 + 0x34) = param_5;
227: if ((param_10 & 8) == 0) {
228: if ((param_10 & 0x10) == 0) {
229: if ((param_10 & 0x20) != 0) {
230: putenv("JSIMD_FORCESSE2=1");
231: }
232: }
233: else {
234: putenv("JSIMD_FORCESSE=1");
235: }
236: }
237: else {
238: putenv("JSIMD_FORCEMMX=1");
239: }
240: FUN_0014e450(param_1,param_6,param_9);
241: if (*(int *)((long)param_1 + 0x24) == 100) {
242: (**(code **)(*param_1 + 0x20))(param_1);
243: FUN_0011f0b0(param_1);
244: FUN_00106ef0(param_1);
245: FUN_00123d50(param_1);
246: (**(code **)param_1[0x3b])(param_1);
247: iVar3 = *(int *)(param_1 + 0x27);
248: iVar4 = *(int *)((long)param_1 + 0x13c);
249: uVar20 = iVar4 + -1 + param_5 & -iVar4;
250: plStack1096 = (long *)malloc((long)(int)uVar20 << 3);
251: if (plStack1096 == (long *)0x0) {
252: param_1[0xc5] = 0x66206e6f69746163;
253: *(undefined4 *)(param_1 + 0xc6) = 0x756c6961;
254: param_1[0xc1] = 0x65646f636e456a74;
255: param_1[0xc2] = 0x656e616c50565559;
256: *(undefined2 *)((long)param_1 + 0x634) = 0x6572;
257: *(undefined *)((long)param_1 + 0x636) = 0;
258: param_1[0xc3] = 0x6d654d203a292873;
259: param_1[0xc4] = 0x6f6c6c612079726f;
260: *(undefined4 *)(param_1 + 0xda) = 1;
261: puVar14 = (undefined4 *)
262: __tls_get_addr(0x6d654d203a292873,0x65646f636e456a74,&PTR_00398fc0);
263: *puVar14 = 0x6e456a74;
264: puVar14[1] = 0x65646f63;
265: puVar14[2] = 0x50565559;
266: puVar14[3] = 0x656e616c;
267: LAB_00150e80:
268: *(undefined8 *)(puVar14 + 8) = 0x66206e6f69746163;
269: puVar14[10] = 0x756c6961;
270: puVar14[4] = 0x3a292873;
271: puVar14[5] = 0x6d654d20;
272: puVar14[6] = 0x2079726f;
273: puVar14[7] = 0x6f6c6c61;
274: *(undefined2 *)(puVar14 + 0xb) = 0x6572;
275: *(undefined *)((long)puVar14 + 0x2e) = 0;
276: uStack1100 = 0xffffffff;
277: }
278: else {
279: if (0 < (int)param_5) {
280: uVar26 = SEXT48(iStack1044);
281: param_10 = param_10 & 2;
282: uVar22 = iStack1044 >> 0x1f;
283: if (param_10 == 0) {
284: uVar21 = (uint)((ulong)plStack1096 >> 3) & 1;
285: if (4 < param_5 - 1) {
286: if (((ulong)plStack1096 >> 3 & 1) != 0) {
287: *plStack1096 = param_2;
288: param_10 = 1;
289: }
290: uVar27 = 0;
291: uVar17 = param_5 - uVar21;
292: auVar31 = CONCAT412(param_10 + 3,
293: CONCAT48(param_10 + 2,CONCAT44(param_10 + 1,param_10)));
294: plVar11 = plStack1096 + uVar21;
295: do {
296: uVar27 = uVar27 + 1;
297: iVar8 = SUB164(auVar31 >> 0x20,0);
298: uVar21 = SUB164(auVar31 >> 0x40,0);
299: iVar32 = SUB164(auVar31 >> 0x60,0);
300: bVar5 = auVar31 < (undefined  [16])0x0;
301: uVar35 = SUB168(CONCAT412(-(uint)(iVar8 < 0),CONCAT48(iVar8,SUB168(auVar31,0))
302: ) >> 0x40,0);
303: uVar30 = SUB168(auVar31,0) & 0xffffffff;
304: *plVar11 = ((ulong)-(uint)(SUB164(auVar31,0) < 0) * (uVar26 & 0xffffffff) +
305: uVar30 * uVar22 << 0x20) + uVar30 * (uVar26 & 0xffffffff) +
306: param_2;
307: plVar11[1] = ((uVar35 >> 0x20) * (uVar26 & 0xffffffff) +
308: (uVar35 & 0xffffffff) * (ulong)uVar22 << 0x20) +
309: (uVar35 & 0xffffffff) * (uVar26 & 0xffffffff) + param_2;
310: auVar31 = CONCAT412(iVar32 + 4,
311: CONCAT48(uVar21 + 4,
312: CONCAT44(iVar8 + 4,SUB164(auVar31,0) + 4)));
313: uVar30 = SUB168(CONCAT412(-(uint)bVar5,
314: CONCAT48(iVar32,CONCAT44(-(uint)((int)uVar21 < 0),
315: uVar21))) >> 0x40,0);
316: plVar11[2] = ((ulong)-(uint)((int)uVar21 < 0) * (uVar26 & 0xffffffff) +
317: (ulong)uVar21 * (ulong)uVar22 << 0x20) +
318: (ulong)uVar21 * (uVar26 & 0xffffffff) + param_2;
319: plVar11[3] = ((uVar30 >> 0x20) * (uVar26 & 0xffffffff) +
320: (uVar30 & 0xffffffff) * (ulong)uVar22 << 0x20) +
321: (uVar30 & 0xffffffff) * (uVar26 & 0xffffffff) + param_2;
322: plVar11 = plVar11 + 4;
323: } while (uVar27 < uVar17 >> 2);
324: param_10 = param_10 + (uVar17 & 0xfffffffc);
325: if (uVar17 == (uVar17 & 0xfffffffc)) goto LAB_00150122;
326: }
327: lVar24 = (long)(int)param_10 * uVar26;
328: plStack1096[(int)param_10] = param_2 + lVar24;
329: if ((int)(param_10 + 1) < (int)param_5) {
330: lVar24 = lVar24 + uVar26;
331: plStack1096[(int)(param_10 + 1)] = param_2 + lVar24;
332: if ((int)(param_10 + 2) < (int)param_5) {
333: lVar24 = lVar24 + uVar26;
334: plStack1096[(int)(param_10 + 2)] = param_2 + lVar24;
335: if ((int)(param_10 + 3) < (int)param_5) {
336: lVar24 = lVar24 + uVar26;
337: plStack1096[(int)(param_10 + 3)] = param_2 + lVar24;
338: if ((int)(param_10 + 4) < (int)param_5) {
339: plStack1096[(int)(param_10 + 4)] = lVar24 + uVar26 + param_2;
340: }
341: }
342: }
343: }
344: }
345: else {
346: uVar21 = (uint)((ulong)plStack1096 >> 3) & 1;
347: iVar8 = iVar6;
348: if (4 < param_5 - 1) {
349: if (((ulong)plStack1096 >> 3 & 1) != 0) {
350: *plStack1096 = (long)(int)(param_5 - 1) * uVar26 + param_2;
351: iVar8 = 1;
352: }
353: uVar27 = param_5 - uVar21;
354: auVar31 = CONCAT412(iVar8 + 3,CONCAT48(iVar8 + 2,CONCAT44(iVar8 + 1,iVar8)));
355: uVar17 = 0;
356: plVar11 = plStack1096 + uVar21;
357: do {
358: uVar17 = uVar17 + 1;
359: iVar32 = SUB164(auVar31 >> 0x20,0);
360: iVar33 = SUB164(auVar31 >> 0x40,0);
361: iVar34 = SUB164(auVar31 >> 0x60,0);
362: uVar21 = (param_5 - SUB164(auVar31,0)) - 1;
363: iVar36 = (param_5 - iVar32) + -1;
364: uVar23 = (param_5 - iVar33) - 1;
365: iVar37 = (param_5 - iVar34) + -1;
366: auVar31 = CONCAT412(iVar34 + 4,
367: CONCAT48(iVar33 + 4,
368: CONCAT44(iVar32 + 4,SUB164(auVar31,0) + 4)));
369: uVar30 = SUB168(CONCAT412(-(uint)(iVar36 < 0),
370: CONCAT48(iVar36,CONCAT44(iVar36,uVar21))) >> 0x40,0)
371: ;
372: *plVar11 = ((ulong)-(uint)((int)uVar21 < 0) * (uVar26 & 0xffffffff) +
373: (ulong)uVar21 * (ulong)uVar22 << 0x20) +
374: (ulong)uVar21 * (uVar26 & 0xffffffff) + param_2;
375: plVar11[1] = ((uVar30 >> 0x20) * (uVar26 & 0xffffffff) +
376: (uVar30 & 0xffffffff) * (ulong)uVar22 << 0x20) +
377: (uVar30 & 0xffffffff) * (uVar26 & 0xffffffff) + param_2;
378: uVar30 = SUB168(CONCAT412(-(uint)(iVar37 < 0),
379: CONCAT48(iVar37,CONCAT44(-(uint)((int)uVar23 < 0),
380: uVar23))) >> 0x40,0);
381: plVar11[2] = ((ulong)-(uint)((int)uVar23 < 0) * (uVar26 & 0xffffffff) +
382: (ulong)uVar23 * (ulong)uVar22 << 0x20) +
383: (ulong)uVar23 * (uVar26 & 0xffffffff) + param_2;
384: plVar11[3] = ((uVar30 >> 0x20) * (uVar26 & 0xffffffff) +
385: (uVar30 & 0xffffffff) * (ulong)uVar22 << 0x20) +
386: (uVar30 & 0xffffffff) * (uVar26 & 0xffffffff) + param_2;
387: plVar11 = plVar11 + 4;
388: } while (uVar17 < uVar27 >> 2);
389: iVar8 = iVar8 + (uVar27 & 0xfffffffc);
390: if (uVar27 == (uVar27 & 0xfffffffc)) goto LAB_00150122;
391: }
392: plStack1096[iVar8] = (long)(int)((param_5 - iVar8) + -1) * uVar26 + param_2;
393: iVar32 = iVar8 + 1;
394: if (iVar32 < (int)param_5) {
395: plStack1096[iVar32] = (long)(int)((param_5 - iVar32) + -1) * uVar26 + param_2;
396: iVar32 = iVar8 + 2;
397: if (iVar32 < (int)param_5) {
398: plStack1096[iVar32] = (long)(int)((param_5 - iVar32) + -1) * uVar26 + param_2;
399: iVar32 = iVar8 + 3;
400: if (iVar32 < (int)param_5) {
401: iVar8 = iVar8 + 4;
402: plStack1096[iVar32] =
403: (long)(int)((param_5 - iVar32) + -1) * uVar26 + param_2;
404: if (iVar8 < (int)param_5) {
405: plStack1096[iVar8] =
406: (long)(int)((param_5 - iVar8) + -1) * uVar26 + param_2;
407: }
408: }
409: }
410: }
411: }
412: }
413: LAB_00150122:
414: if ((int)param_5 < (int)uVar20) {
415: lVar24 = (long)(int)param_5;
416: plVar11 = plStack1096 + lVar24 + -1;
417: if (uVar20 - param_5 < 0x19) {
418: plVar15 = plStack1096 + lVar24;
419: do {
420: plVar16 = plVar15 + 1;
421: *plVar15 = *plVar11;
422: plVar15 = plVar16;
423: } while (plVar16 != plStack1096 + (ulong)(~param_5 + uVar20) + lVar24 + 1);
424: }
425: else {
426: uVar26 = (ulong)(plStack1096 + lVar24) >> 3;
427: uVar21 = (uint)uVar26 & 1;
428: uVar22 = param_5;
429: if (2 - ((uVar26 & 1) == 0) <= ~param_5 + uVar20) {
430: if ((uVar26 & 1) != 0) {
431: plStack1096[lVar24] = *plVar11;
432: uVar22 = param_5 + 1;
433: }
434: uVar27 = (uVar20 - param_5) - uVar21;
435: lVar19 = *plVar11;
436: uVar17 = 0;
437: plVar15 = plStack1096 + (ulong)uVar21 + lVar24;
438: do {
439: uVar17 = uVar17 + 1;
440: *plVar15 = lVar19;
441: plVar15[1] = lVar19;
442: plVar15 = plVar15 + 2;
443: } while (uVar17 < uVar27 >> 1);
444: uVar22 = (uVar27 & 0xfffffffe) + uVar22;
445: if (uVar27 == (uVar27 & 0xfffffffe)) goto LAB_001501f1;
446: }
447: plStack1096[(int)uVar22] = *plVar11;
448: if ((int)(uVar22 + 1) < (int)uVar20) {
449: plStack1096[(int)(uVar22 + 1)] = *plVar11;
450: }
451: }
452: }
453: LAB_001501f1:
454: iVar8 = *(int *)((long)param_1 + 0x4c);
455: if (0 < iVar8) {
456: lVar24 = 0;
457: puVar29 = (uint *)(param_1[0xb] + 8);
458: do {
459: uVar22 = puVar29[5];
460: uVar21 = *puVar29;
461: uVar17 = (iVar3 * 8 * uVar22) / uVar21 + 0x1f;
462: uVar27 = uVar17 & 0xffffffe0;
463: pvVar9 = malloc((ulong)(iVar4 * uVar27 + 0x20));
464: *(void **)(auStack472 + lVar24 * 2) = pvVar9;
465: if (pvVar9 == (void *)0x0) {
466: param_1[0xc5] = 0x66206e6f69746163;
467: *(undefined4 *)(param_1 + 0xc6) = 0x756c6961;
468: param_1[0xc1] = 0x65646f636e456a74;
469: param_1[0xc2] = 0x656e616c50565559;
470: *(undefined2 *)((long)param_1 + 0x634) = 0x6572;
471: *(undefined *)((long)param_1 + 0x636) = 0;
472: param_1[0xc3] = 0x6d654d203a292873;
473: param_1[0xc4] = 0x6f6c6c612079726f;
474: *(undefined4 *)(param_1 + 0xda) = 1;
475: puVar14 = (undefined4 *)
476: __tls_get_addr(0x6d654d203a292873,0x65646f636e456a74,&PTR_00398fc0);
477: *puVar14 = 0x6e456a74;
478: puVar14[1] = 0x65646f63;
479: puVar14[2] = 0x50565559;
480: puVar14[3] = 0x656e616c;
481: goto LAB_00150e80;
482: }
483: puVar10 = (ulong *)malloc((long)iVar4 << 3);
484: *(ulong **)(auStack312 + lVar24 * 2) = puVar10;
485: if (puVar10 == (ulong *)0x0) {
486: param_1[0xc5] = 0x66206e6f69746163;
487: *(undefined4 *)(param_1 + 0xc6) = 0x756c6961;
488: param_1[0xc1] = 0x65646f636e456a74;
489: param_1[0xc2] = 0x656e616c50565559;
490: *(undefined2 *)((long)param_1 + 0x634) = 0x6572;
491: *(undefined *)((long)param_1 + 0x636) = 0;
492: param_1[0xc3] = 0x6d654d203a292873;
493: param_1[0xc4] = 0x6f6c6c612079726f;
494: *(undefined4 *)(param_1 + 0xda) = 1;
495: puVar14 = (undefined4 *)
496: __tls_get_addr(0x6d654d203a292873,0x65646f636e456a74,&PTR_00398fc0);
497: *puVar14 = 0x6e456a74;
498: puVar14[1] = 0x65646f63;
499: puVar14[2] = 0x50565559;
500: puVar14[3] = 0x656e616c;
501: goto LAB_00150e80;
502: }
503: if (0 < iVar4) {
504: uVar26 = (long)pvVar9 + 0x1fU & 0xffffffffffffffe0;
505: uVar23 = (uint)((ulong)puVar10 >> 3) & 1;
506: iVar32 = iVar6;
507: if (3 < iVar4 - 1U) {
508: iStack932 = iVar6;
509: if (((ulong)puVar10 >> 3 & 1) != 0) {
510: *puVar10 = uVar26;
511: iStack932 = 1;
512: }
513: uVar18 = 0;
514: uVar28 = iVar4 - uVar23;
515: puVar25 = puVar10 + uVar23;
516: auVar31 = CONCAT412(iStack932 + 3,
517: CONCAT48(iStack932 + 2,CONCAT44(iStack932 + 1,iStack932)))
518: ;
519: do {
520: uVar18 = uVar18 + 1;
521: uVar30 = SUB168(auVar31 >> 0x40,0);
522: puVar25[2] = ((uVar30 & 0xffffffff) * (ulong)uVar27 & 0xffffffff) + uVar26;
523: puVar25[3] = ((uVar30 >> 0x20) *
524: SUB168(CONCAT412(uVar17,CONCAT48(uVar17,CONCAT44(uVar17,uVar17
525: ))) >> 0x60,0)
526: & 0xffffffff) + uVar26;
527: *puVar25 = ((ulong)SUB164(auVar31,0) * (ulong)uVar27 & 0xffffffff) + uVar26;
528: puVar25[1] = ((SUB168(auVar31,0) >> 0x20) * (ulong)uVar27 & 0xffffffff) +
529: uVar26;
530: puVar25 = puVar25 + 4;
531: auVar31 = CONCAT412(SUB164(auVar31 >> 0x60,0) + 4,
532: CONCAT48(SUB164(auVar31 >> 0x40,0) + 4,
533: CONCAT44(SUB164(auVar31 >> 0x20,0) + 4,
534: SUB164(auVar31,0) + 4)));
535: } while (uVar18 < uVar28 >> 2);
536: iVar32 = iStack932 + (uVar28 & 0xfffffffc);
537: if ((uVar28 & 0xfffffffc) == uVar28) goto LAB_00150457;
538: }
539: puVar10[iVar32] = iVar32 * uVar27 + uVar26;
540: if (iVar32 + 1 < iVar4) {
541: uVar17 = iVar32 * uVar27 + uVar27;
542: puVar10[iVar32 + 1] = uVar17 + uVar26;
543: if (iVar32 + 2 < iVar4) {
544: uVar17 = uVar17 + uVar27;
545: puVar10[iVar32 + 2] = uVar17 + uVar26;
546: if (iVar32 + 3 < iVar4) {
547: puVar10[iVar32 + 3] = (uVar27 + uVar17) + uVar26;
548: }
549: }
550: }
551: }
552: LAB_00150457:
553: uVar22 = uVar22 * 8 + 0x1f;
554: uVar27 = uVar22 & 0xffffffe0;
555: uVar17 = puVar29[1];
556: pvVar9 = malloc((ulong)(uVar27 * uVar17 + 0x20));
557: *(void **)(auStack392 + lVar24 * 2) = pvVar9;
558: if (pvVar9 == (void *)0x0) {
559: param_1[0xc5] = 0x66206e6f69746163;
560: *(undefined4 *)(param_1 + 0xc6) = 0x756c6961;
561: param_1[0xc1] = 0x65646f636e456a74;
562: param_1[0xc2] = 0x656e616c50565559;
563: *(undefined2 *)((long)param_1 + 0x634) = 0x6572;
564: *(undefined *)((long)param_1 + 0x636) = 0;
565: param_1[0xc3] = 0x6d654d203a292873;
566: param_1[0xc4] = 0x6f6c6c612079726f;
567: *(undefined4 *)(param_1 + 0xda) = 1;
568: puVar14 = (undefined4 *)
569: __tls_get_addr(0x6d654d203a292873,0x65646f636e456a74,&PTR_00398fc0);
570: *puVar14 = 0x6e456a74;
571: puVar14[1] = 0x65646f63;
572: puVar14[2] = 0x50565559;
573: puVar14[3] = 0x656e616c;
574: goto LAB_00150e80;
575: }
576: puVar10 = (ulong *)malloc((long)(int)uVar17 << 3);
577: *(ulong **)(auStack232 + lVar24 * 2) = puVar10;
578: if (puVar10 == (ulong *)0x0) {
579: param_1[0xc5] = 0x66206e6f69746163;
580: *(undefined4 *)(param_1 + 0xc6) = 0x756c6961;
581: param_1[0xc1] = 0x65646f636e456a74;
582: param_1[0xc2] = 0x656e616c50565559;
583: *(undefined2 *)((long)param_1 + 0x634) = 0x6572;
584: *(undefined *)((long)param_1 + 0x636) = 0;
585: param_1[0xc3] = 0x6d654d203a292873;
586: param_1[0xc4] = 0x6f6c6c612079726f;
587: *(undefined4 *)(param_1 + 0xda) = 1;
588: puVar14 = (undefined4 *)
589: __tls_get_addr(0x6d654d203a292873,0x65646f636e456a74,&PTR_00398fc0);
590: *puVar14 = 0x6e456a74;
591: puVar14[1] = 0x65646f63;
592: puVar14[2] = 0x50565559;
593: puVar14[3] = 0x656e616c;
594: goto LAB_00150e80;
595: }
596: if (0 < (int)uVar17) {
597: uVar26 = (long)pvVar9 + 0x1fU & 0xffffffffffffffe0;
598: uVar23 = (uint)((ulong)puVar10 >> 3) & 1;
599: iVar32 = iVar6;
600: if (3 < uVar17 - 1) {
601: iStack936 = iVar6;
602: if (((ulong)puVar10 >> 3 & 1) != 0) {
603: *puVar10 = uVar26;
604: iStack936 = 1;
605: }
606: uVar28 = uVar17 - uVar23;
607: uVar18 = 0;
608: puVar25 = puVar10 + uVar23;
609: auVar31 = CONCAT412(iStack936 + 3,
610: CONCAT48(iStack936 + 2,CONCAT44(iStack936 + 1,iStack936)))
611: ;
612: do {
613: uVar18 = uVar18 + 1;
614: uVar30 = SUB168(auVar31 >> 0x40,0);
615: puVar25[2] = ((uVar30 & 0xffffffff) * (ulong)uVar27 & 0xffffffff) + uVar26;
616: puVar25[3] = ((uVar30 >> 0x20) *
617: SUB168(CONCAT412(uVar22,CONCAT48(uVar22,CONCAT44(uVar22,uVar22
618: ))) >> 0x60,0)
619: & 0xffffffff) + uVar26;
620: *puVar25 = ((ulong)SUB164(auVar31,0) * (ulong)uVar27 & 0xffffffff) + uVar26;
621: puVar25[1] = ((SUB168(auVar31,0) >> 0x20) * (ulong)uVar27 & 0xffffffff) +
622: uVar26;
623: puVar25 = puVar25 + 4;
624: auVar31 = CONCAT412(SUB164(auVar31 >> 0x60,0) + 4,
625: CONCAT48(SUB164(auVar31 >> 0x40,0) + 4,
626: CONCAT44(SUB164(auVar31 >> 0x20,0) + 4,
627: SUB164(auVar31,0) + 4)));
628: } while (uVar18 < uVar28 >> 2);
629: iVar32 = iStack936 + (uVar28 & 0xfffffffc);
630: if ((uVar28 & 0xfffffffc) == uVar28) goto LAB_00150619;
631: }
632: puVar10[iVar32] = iVar32 * uVar27 + uVar26;
633: if (iVar32 + 1 < (int)uVar17) {
634: uVar22 = iVar32 * uVar27 + uVar27;
635: puVar10[iVar32 + 1] = uVar22 + uVar26;
636: if (iVar32 + 2 < (int)uVar17) {
637: uVar22 = uVar22 + uVar27;
638: puVar10[iVar32 + 2] = uVar22 + uVar26;
639: if (iVar32 + 3 < (int)uVar17) {
640: puVar10[iVar32 + 3] = (uVar22 + uVar27) + uVar26;
641: }
642: }
643: }
644: }
645: LAB_00150619:
646: iVar32 = (int)(uVar21 * (iVar3 + -1 + param_3 & -iVar3)) / iVar3;
647: *(int *)((long)aiStack520 + lVar24) = iVar32;
648: iVar33 = (int)(uVar20 * uVar17) / iVar4;
649: plVar11 = (long *)malloc((long)iVar33 << 3);
650: *(long **)(auStack152 + lVar24 * 2) = plVar11;
651: if (plVar11 == (long *)0x0) {
652: param_1[0xc5] = 0x66206e6f69746163;
653: *(undefined4 *)(param_1 + 0xc6) = 0x756c6961;
654: param_1[0xc1] = 0x65646f636e456a74;
655: param_1[0xc2] = 0x656e616c50565559;
656: *(undefined2 *)((long)param_1 + 0x634) = 0x6572;
657: *(undefined *)((long)param_1 + 0x636) = 0;
658: param_1[0xc3] = 0x6d654d203a292873;
659: param_1[0xc4] = 0x6f6c6c612079726f;
660: *(undefined4 *)(param_1 + 0xda) = 1;
661: puVar14 = (undefined4 *)
662: __tls_get_addr(0x6d654d203a292873,0x65646f636e456a74,&PTR_00398fc0);
663: *puVar14 = 0x6e456a74;
664: puVar14[1] = 0x65646f63;
665: puVar14[2] = 0x50565559;
666: puVar14[3] = 0x656e616c;
667: goto LAB_00150e80;
668: }
669: lVar19 = *(long *)((long)param_7 + lVar24 * 2);
670: if (0 < iVar33) {
671: if (param_8 == 0) {
672: plVar15 = plVar11 + (ulong)(iVar33 - 1) + 1;
673: do {
674: *plVar11 = lVar19;
675: plVar11 = plVar11 + 1;
676: lVar19 = lVar19 + iVar32;
677: } while (plVar15 != plVar11);
678: }
679: else {
680: plVar15 = plVar11 + (ulong)(iVar33 - 1) + 1;
681: lVar12 = (long)*(int *)(param_8 + lVar24);
682: if (*(int *)(param_8 + lVar24) == 0) {
683: lVar12 = (long)iVar32;
684: }
685: do {
686: *plVar11 = lVar19;
687: plVar11 = plVar11 + 1;
688: lVar19 = lVar19 + lVar12;
689: } while (plVar11 != plVar15);
690: }
691: }
692: puVar29 = puVar29 + 0x18;
693: lVar24 = lVar24 + 4;
694: } while (lVar24 != (ulong)(iVar8 - 1) * 4 + 4);
695: }
696: iVar6 = _setjmp((__jmp_buf_tag *)(param_1 + 0xa5));
697: if (iVar6 != 0) goto LAB_00150a40;
698: if (0 < (int)uVar20) {
699: do {
700: (**(code **)(param_1[0x3b] + 8))(param_1,plStack1096 + iVar6,auStack312,0);
701: (**(code **)(param_1[0x3c] + 8))(param_1,auStack312,0);
702: lVar24 = param_1[0xb];
703: if (0 < *(int *)((long)param_1 + 0x4c)) {
704: lVar19 = 1;
705: do {
706: piVar1 = (int *)(lVar24 + 0xc);
707: lVar24 = lVar24 + 0x60;
708: FUN_00148a00(*(undefined8 *)(auStack248 + lVar19 * 8 + 8),0,
709: *(undefined8 *)(auStack168 + lVar19 * 8 + 8),
710: (long)(*piVar1 * iVar6) / (long)*(int *)((long)param_1 + 0x13c) &
711: 0xffffffff,*piVar1,aiStack520[lVar19 + -1]);
712: iVar3 = (int)lVar19;
713: lVar19 = lVar19 + 1;
714: } while (*(int *)((long)param_1 + 0x4c) != iVar3 &&
715: iVar3 <= *(int *)((long)param_1 + 0x4c));
716: }
717: iVar6 = iVar6 + *(int *)((long)param_1 + 0x13c);
718: } while (iVar6 < (int)uVar20);
719: }
720: *(uint *)(param_1 + 0x26) = *(int *)(param_1 + 0x26) + param_5;
721: thunk_FUN_0011f490(param_1);
722: }
723: }
724: else {
725: *(undefined4 *)(param_1 + 199) = 0x61747320;
726: *(undefined2 *)((long)param_1 + 0x63c) = 0x6574;
727: *(undefined *)((long)param_1 + 0x63e) = 0;
728: *(undefined4 *)(param_1 + 0xda) = 1;
729: param_1[0xc1] = 0x65646f636e456a74;
730: param_1[0xc2] = 0x656e616c50565559;
731: param_1[0xc3] = 0x62696c203a292873;
732: param_1[0xc4] = 0x495041206765706a;
733: param_1[0xc5] = 0x74206e6920736920;
734: param_1[0xc6] = 0x676e6f7277206568;
735: puVar14 = (undefined4 *)
736: __tls_get_addr(0x74206e6920736920,0x62696c203a292873,0x65646f636e456a74,
737: &PTR_00398fc0);
738: puVar14[0xc] = 0x61747320;
739: *(undefined2 *)(puVar14 + 0xd) = 0x6574;
740: *(undefined *)((long)puVar14 + 0x36) = 0;
741: uStack1100 = 0xffffffff;
742: *puVar14 = 0x6e456a74;
743: puVar14[1] = 0x65646f63;
744: puVar14[2] = 0x50565559;
745: puVar14[3] = 0x656e616c;
746: puVar14[4] = 0x3a292873;
747: puVar14[5] = 0x62696c20;
748: puVar14[6] = 0x6765706a;
749: puVar14[7] = 0x49504120;
750: puVar14[8] = 0x20736920;
751: puVar14[9] = 0x74206e69;
752: puVar14[10] = 0x77206568;
753: puVar14[0xb] = 0x676e6f72;
754: }
755: }
756: else {
757: LAB_00150a40:
758: uStack1100 = 0xffffffff;
759: }
760: }
761: }
762: iVar6 = *(int *)((long)param_1 + 0x24);
763: }
764: if (100 < iVar6) {
765: thunk_FUN_0011f490(param_1);
766: }
767: lVar24 = 0;
768: free(plStack1096);
769: do {
770: free(*(void **)(auStack312 + lVar24));
771: free(*(void **)(auStack472 + lVar24));
772: free(*(void **)(auStack232 + lVar24));
773: free(*(void **)(auStack392 + lVar24));
774: ppvVar2 = (void **)(auStack152 + lVar24);
775: lVar24 = lVar24 + 8;
776: free(*ppvVar2);
777: } while (lVar24 != 0x50);
778: *(undefined4 *)((long)param_1 + 0x5fc) = 0;
779: uVar7 = 0xffffffff;
780: if (*(int *)(param_1 + 0xbf) == 0) {
781: uVar7 = uStack1100;
782: }
783: LAB_001508ff:
784: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
785: return uVar7;
786: }
787: /* WARNING: Subroutine does not return */
788: __stack_chk_fail();
789: }
790: 
