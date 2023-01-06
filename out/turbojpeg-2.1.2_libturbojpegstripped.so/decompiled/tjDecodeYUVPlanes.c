1: 
2: undefined4
3: tjDecodeYUVPlanes(long param_1,long *param_2,long param_3,uint param_4,long param_5,int param_6,
4: int param_7,uint param_8,uint param_9,uint param_10)
5: 
6: {
7: void **ppvVar1;
8: int iVar2;
9: int iVar3;
10: code **ppcVar4;
11: code *pcVar5;
12: code *pcVar6;
13: bool bVar7;
14: undefined4 uVar8;
15: int iVar9;
16: int iVar10;
17: undefined4 *puVar11;
18: undefined8 *puVar12;
19: void *pvVar13;
20: ulong *puVar14;
21: long *plVar15;
22: uint uVar16;
23: long *plVar17;
24: uint uVar18;
25: uint uVar19;
26: undefined8 uVar20;
27: long lVar21;
28: ulong *puVar22;
29: long lVar23;
30: long *plVar24;
31: long lVar25;
32: int *piVar26;
33: ulong uVar27;
34: long lVar28;
35: uint uVar29;
36: uint uVar30;
37: uint uVar31;
38: long in_FS_OFFSET;
39: ulong uVar32;
40: undefined auVar33 [16];
41: int iVar34;
42: int iVar35;
43: int iVar36;
44: int iVar37;
45: ulong uVar38;
46: int iVar39;
47: int iVar40;
48: undefined4 uStack892;
49: long *plStack888;
50: undefined4 uStack368;
51: int aiStack364 [13];
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
62: undefined auStack152 [16];
63: undefined auStack136 [16];
64: undefined auStack120 [16];
65: undefined auStack104 [16];
66: undefined auStack88 [16];
67: long lStack64;
68: 
69: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
70: if (param_1 == 0) {
71: puVar12 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
72: *puVar12 = 0x2064696c61766e49;
73: *(undefined4 *)(puVar12 + 1) = 0x646e6168;
74: *(undefined2 *)((long)puVar12 + 0xc) = 0x656c;
75: *(undefined *)((long)puVar12 + 0xe) = 0;
76: uVar8 = 0xffffffff;
77: goto LAB_001541b5;
78: }
79: lVar25 = param_1 + 0x208;
80: *(undefined4 *)(param_1 + 0x5f8) = 0;
81: *(undefined4 *)(param_1 + 0x6d0) = 0;
82: auStack232 = (undefined  [16])0x0;
83: *(uint *)(param_1 + 0x5fc) = (int)param_10 >> 0xd & 1;
84: auStack216 = (undefined  [16])0x0;
85: auStack200 = (undefined  [16])0x0;
86: auStack184 = (undefined  [16])0x0;
87: auStack168 = (undefined  [16])0x0;
88: auStack312 = (undefined  [16])0x0;
89: auStack296 = (undefined  [16])0x0;
90: auStack280 = (undefined  [16])0x0;
91: auStack264 = (undefined  [16])0x0;
92: auStack248 = (undefined  [16])0x0;
93: auStack152 = (undefined  [16])0x0;
94: auStack136 = (undefined  [16])0x0;
95: auStack120 = (undefined  [16])0x0;
96: auStack104 = (undefined  [16])0x0;
97: auStack88 = (undefined  [16])0x0;
98: if ((*(byte *)(param_1 + 0x600) & 2) == 0) {
99: *(undefined8 *)(param_1 + 0x648) = 0x6e6f697373657270;
100: *(undefined *)(param_1 + 0x650) = 0;
101: *(undefined4 *)(param_1 + 0x6d0) = 1;
102: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
103: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
104: *(undefined8 *)(param_1 + 0x618) = 0x736e49203a292873;
105: *(undefined8 *)(param_1 + 0x620) = 0x61682065636e6174;
106: *(undefined8 *)(param_1 + 0x628) = 0x656220746f6e2073;
107: *(undefined8 *)(param_1 + 0x630) = 0x6974696e69206e65;
108: *(undefined8 *)(param_1 + 0x638) = 0x662064657a696c61;
109: *(undefined8 *)(param_1 + 0x640) = 0x6d6f63656420726f;
110: puVar11 = (undefined4 *)
111: __tls_get_addr(0x662064657a696c61,0x656220746f6e2073,0x736e49203a292873,
112: 0x65646f6365446a74,&PTR_00398fc0);
113: *(undefined8 *)(puVar11 + 0x10) = 0x6e6f697373657270;
114: *(undefined *)(puVar11 + 0x12) = 0;
115: uStack892 = 0xffffffff;
116: plStack888 = (long *)0x0;
117: *puVar11 = 0x65446a74;
118: puVar11[1] = 0x65646f63;
119: puVar11[2] = 0x50565559;
120: puVar11[3] = 0x656e616c;
121: puVar11[4] = 0x3a292873;
122: puVar11[5] = 0x736e4920;
123: puVar11[6] = 0x636e6174;
124: puVar11[7] = 0x61682065;
125: puVar11[8] = 0x6f6e2073;
126: puVar11[9] = 0x65622074;
127: puVar11[10] = 0x69206e65;
128: puVar11[0xb] = 0x6974696e;
129: puVar11[0xc] = 0x7a696c61;
130: puVar11[0xd] = 0x66206465;
131: puVar11[0xe] = 0x6420726f;
132: puVar11[0xf] = 0x6d6f6365;
133: iVar9 = *(int *)(param_1 + 0x22c);
134: }
135: else {
136: if ((((((param_2 == (long *)0x0) || (*param_2 == 0)) || (5 < param_4)) ||
137: ((param_5 == 0 || (param_6 < 1)))) ||
138: ((param_7 < 0 || (((int)param_8 < 1 || (0xb < param_9)))))) ||
139: ((param_4 != 3 && ((param_2[1] == 0 || (param_2[2] == 0)))))) {
140: *(undefined4 *)(param_1 + 0x628) = 0x6e656d75;
141: *(undefined2 *)(param_1 + 0x62c) = 0x74;
142: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
143: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
144: *(undefined4 *)(param_1 + 0x6d0) = 1;
145: *(undefined8 *)(param_1 + 0x618) = 0x766e49203a292873;
146: *(undefined8 *)(param_1 + 0x620) = 0x6772612064696c61;
147: puVar11 = (undefined4 *)__tls_get_addr(0x766e49203a292873,0x65646f6365446a74,&PTR_00398fc0);
148: puVar11[8] = 0x6e656d75;
149: *(undefined2 *)(puVar11 + 9) = 0x74;
150: uStack892 = 0xffffffff;
151: plStack888 = (long *)0x0;
152: *puVar11 = 0x65446a74;
153: puVar11[1] = 0x65646f63;
154: puVar11[2] = 0x50565559;
155: puVar11[3] = 0x656e616c;
156: puVar11[4] = 0x3a292873;
157: puVar11[5] = 0x766e4920;
158: puVar11[6] = 0x64696c61;
159: puVar11[7] = 0x67726120;
160: }
161: else {
162: uStack892 = 0;
163: plStack888 = (long *)0x0;
164: iVar9 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
165: if (iVar9 == 0) {
166: if (param_9 == 0xb) {
167: *(undefined4 *)(param_1 + 0x6d0) = 1;
168: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
169: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
170: *(undefined8 *)(param_1 + 0x618) = 0x6e6143203a292873;
171: *(undefined8 *)(param_1 + 0x620) = 0x6f63656420746f6e;
172: *(undefined8 *)(param_1 + 0x628) = 0x6920565559206564;
173: *(undefined8 *)(param_1 + 0x630) = 0x6e6920736567616d;
174: *(undefined8 *)(param_1 + 0x638) = 0x204b594d43206f74;
175: *(undefined8 *)(param_1 + 0x640) = 0x2e736c65786970;
176: puVar11 = (undefined4 *)
177: __tls_get_addr(0x204b594d43206f74,0x6920565559206564,0x6e6143203a292873,
178: 0x65646f6365446a74,&PTR_00398fc0);
179: uStack892 = 0xffffffff;
180: *puVar11 = 0x65446a74;
181: puVar11[1] = 0x65646f63;
182: puVar11[2] = 0x50565559;
183: puVar11[3] = 0x656e616c;
184: puVar11[4] = 0x3a292873;
185: puVar11[5] = 0x6e614320;
186: puVar11[6] = 0x20746f6e;
187: puVar11[7] = 0x6f636564;
188: puVar11[8] = 0x59206564;
189: puVar11[9] = 0x69205655;
190: puVar11[10] = 0x6567616d;
191: puVar11[0xb] = 0x6e692073;
192: puVar11[0xc] = 0x43206f74;
193: puVar11[0xd] = 0x204b594d;
194: puVar11[0xe] = 0x65786970;
195: puVar11[0xf] = 0x2e736c;
196: }
197: else {
198: if (param_7 == 0) {
199: param_7 = param_6 * *(int *)(&DAT_0018fd80 + (long)(int)param_9 * 4);
200: }
201: *(int *)(param_1 + 0x238) = param_6;
202: *(uint *)(param_1 + 0x23c) = param_8;
203: if ((param_10 & 8) == 0) {
204: if ((param_10 & 0x10) == 0) {
205: if ((param_10 & 0x20) != 0) {
206: putenv("JSIMD_FORCESSE2=1");
207: }
208: }
209: else {
210: putenv("JSIMD_FORCESSE=1");
211: }
212: }
213: else {
214: putenv("JSIMD_FORCEMMX=1");
215: }
216: *(undefined4 *)(*(long *)(param_1 + 0x448) + 0x20) = 0;
217: *(undefined4 *)(param_1 + 0x340) = 0;
218: *(undefined8 *)(param_1 + 0x414) = 0x3f00000000;
219: *(undefined8 *)(param_1 + 0x41c) = 0;
220: *(undefined8 *)(param_1 + 0x24c) = 0x100000001;
221: if (param_4 == 3) {
222: *(undefined4 *)(param_1 + 0x3b8) = 1;
223: *(undefined4 *)(param_1 + 0x240) = 1;
224: uVar20 = 0x60;
225: *(undefined4 *)(param_1 + 0x244) = 1;
226: }
227: else {
228: uVar20 = 0x120;
229: *(undefined4 *)(param_1 + 0x3b8) = 3;
230: *(undefined4 *)(param_1 + 0x240) = 3;
231: *(undefined4 *)(param_1 + 0x244) = 3;
232: }
233: puVar12 = (undefined8 *)(***(code ***)(param_1 + 0x210))(0x3f00000000,lVar25,1,uVar20);
234: iVar2 = *(int *)(param_1 + 0x240);
235: *(undefined8 **)(param_1 + 0x338) = puVar12;
236: if (0 < iVar2) {
237: *puVar12 = 1;
238: puVar12[2] = 0;
239: *(undefined4 *)(puVar12 + 3) = 0;
240: iVar3 = *(int *)(&DAT_0018fdd0 + (long)(int)param_4 * 4);
241: iVar10 = iVar3 + 7;
242: if (-1 < iVar3) {
243: iVar10 = iVar3;
244: }
245: *(int *)(puVar12 + 1) = iVar10 >> 3;
246: iVar3 = *(int *)(&DAT_0018fdb0 + (long)(int)param_4 * 4);
247: iVar10 = iVar3 + 7;
248: if (-1 < iVar3) {
249: iVar10 = iVar3;
250: }
251: *(int *)((long)puVar12 + 0xc) = iVar10 >> 3;
252: *(undefined8 **)(param_1 + 0x3c0) = puVar12;
253: if (iVar2 != 1) {
254: puVar12[0xc] = 0x100000002;
255: puVar12[0xd] = 0x100000001;
256: puVar12[0xe] = 0x100000001;
257: *(undefined4 *)(puVar12 + 0xf) = 1;
258: *(undefined8 **)(param_1 + 0x3c8) = puVar12 + 0xc;
259: if (iVar2 != 2) {
260: puVar12[0x19] = 0x100000001;
261: puVar12[0x18] = 0x200000003;
262: puVar12[0x1a] = 0x100000001;
263: *(undefined4 *)(puVar12 + 0x1b) = 1;
264: *(undefined8 **)(param_1 + 0x3d0) = puVar12 + 0x18;
265: if (iVar2 != 3) {
266: puVar12[0x25] = 0x100000001;
267: puVar12[0x26] = 0x100000001;
268: puVar12[0x24] = 0x300000004;
269: *(undefined4 *)(puVar12 + 0x27) = 1;
270: *(undefined8 **)(param_1 + 0x3d8) = puVar12 + 0x24;
271: }
272: }
273: }
274: }
275: *(undefined4 *)(param_1 + 0x330) = 8;
276: if (*(long *)(param_1 + 0x2d0) == 0) {
277: uVar20 = FUN_0011f510(lVar25);
278: *(undefined8 *)(param_1 + 0x2d0) = uVar20;
279: }
280: if (*(long *)(param_1 + 0x2d8) == 0) {
281: uVar20 = FUN_0011f510(lVar25);
282: *(undefined8 *)(param_1 + 0x2d8) = uVar20;
283: }
284: ppcVar4 = *(code ***)(param_1 + 0x450);
285: pcVar5 = ppcVar4[1];
286: pcVar6 = *ppcVar4;
287: ppcVar4[1] = FUN_0014e2b0;
288: *ppcVar4 = FUN_0014e2c0;
289: FUN_00125330(lVar25);
290: ppcVar4 = *(code ***)(param_1 + 0x450);
291: ppcVar4[1] = pcVar5;
292: *ppcVar4 = pcVar6;
293: *(undefined4 *)(param_1 + 0x248) = *(undefined4 *)(&DAT_0018fc80 + (long)(int)param_9 * 4)
294: ;
295: if ((param_10 & 0x800) != 0) {
296: *(undefined4 *)(param_1 + 0x268) = 1;
297: }
298: *(undefined4 *)(param_1 + 0x26c) = 0;
299: *(undefined4 *)(param_1 + 0x418) = 0x3f;
300: FUN_00137680(lVar25);
301: (***(code ***)(param_1 + 0x468))(lVar25);
302: iVar2 = *(int *)(param_1 + 0x3a0);
303: iVar3 = *(int *)(param_1 + 0x3a4);
304: uVar18 = iVar3 + -1 + param_8 & -iVar3;
305: if (param_7 == 0) {
306: param_7 = *(int *)(param_1 + 0x290) * *(int *)(&DAT_0018fd80 + (long)(int)param_9 * 4);
307: }
308: plStack888 = (long *)malloc((long)(int)uVar18 << 3);
309: if (plStack888 == (long *)0x0) {
310: *(undefined8 *)(param_1 + 0x628) = 0x66206e6f69746163;
311: *(undefined4 *)(param_1 + 0x630) = 0x756c6961;
312: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
313: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
314: *(undefined2 *)(param_1 + 0x634) = 0x6572;
315: *(undefined *)(param_1 + 0x636) = 0;
316: *(undefined8 *)(param_1 + 0x618) = 0x6d654d203a292873;
317: *(undefined8 *)(param_1 + 0x620) = 0x6f6c6c612079726f;
318: *(undefined4 *)(param_1 + 0x6d0) = 1;
319: puVar11 = (undefined4 *)
320: __tls_get_addr(0x6d654d203a292873,0x65646f6365446a74,&PTR_00398fc0);
321: *puVar11 = 0x65446a74;
322: puVar11[1] = 0x65646f63;
323: puVar11[2] = 0x50565559;
324: puVar11[3] = 0x656e616c;
325: LAB_00155095:
326: *(undefined8 *)(puVar11 + 8) = 0x66206e6f69746163;
327: puVar11[10] = 0x756c6961;
328: puVar11[4] = 0x3a292873;
329: puVar11[5] = 0x6d654d20;
330: puVar11[6] = 0x2079726f;
331: puVar11[7] = 0x6f6c6c61;
332: *(undefined2 *)(puVar11 + 0xb) = 0x6572;
333: *(undefined *)((long)puVar11 + 0x2e) = 0;
334: uStack892 = 0xffffffff;
335: }
336: else {
337: if (0 < (int)param_8) {
338: uVar27 = SEXT48(param_7);
339: param_10 = param_10 & 2;
340: uVar30 = param_7 >> 0x1f;
341: if (param_10 == 0) {
342: uVar19 = (uint)((ulong)plStack888 >> 3) & 1;
343: if (4 < param_8 - 1) {
344: if (((ulong)plStack888 >> 3 & 1) != 0) {
345: *plStack888 = param_5;
346: param_10 = 1;
347: }
348: uVar29 = 0;
349: uVar16 = param_8 - uVar19;
350: auVar33 = CONCAT412(param_10 + 3,
351: CONCAT48(param_10 + 2,CONCAT44(param_10 + 1,param_10)));
352: plVar15 = plStack888 + uVar19;
353: do {
354: uVar29 = uVar29 + 1;
355: iVar10 = SUB164(auVar33 >> 0x20,0);
356: uVar19 = SUB164(auVar33 >> 0x40,0);
357: iVar34 = SUB164(auVar33 >> 0x60,0);
358: bVar7 = auVar33 < (undefined  [16])0x0;
359: uVar38 = SUB168(CONCAT412(-(uint)(iVar10 < 0),CONCAT48(iVar10,SUB168(auVar33,0))
360: ) >> 0x40,0);
361: uVar32 = SUB168(auVar33,0) & 0xffffffff;
362: *plVar15 = ((ulong)-(uint)(SUB164(auVar33,0) < 0) * (uVar27 & 0xffffffff) +
363: uVar32 * uVar30 << 0x20) + uVar32 * (uVar27 & 0xffffffff) + param_5;
364: plVar15[1] = ((uVar38 >> 0x20) * (uVar27 & 0xffffffff) +
365: (uVar38 & 0xffffffff) * (ulong)uVar30 << 0x20) +
366: (uVar38 & 0xffffffff) * (uVar27 & 0xffffffff) + param_5;
367: auVar33 = CONCAT412(iVar34 + 4,
368: CONCAT48(uVar19 + 4,
369: CONCAT44(iVar10 + 4,SUB164(auVar33,0) + 4)));
370: uVar32 = SUB168(CONCAT412(-(uint)bVar7,
371: CONCAT48(iVar34,CONCAT44(-(uint)((int)uVar19 < 0),
372: uVar19))) >> 0x40,0);
373: plVar15[2] = ((ulong)-(uint)((int)uVar19 < 0) * (uVar27 & 0xffffffff) +
374: (ulong)uVar19 * (ulong)uVar30 << 0x20) +
375: (ulong)uVar19 * (uVar27 & 0xffffffff) + param_5;
376: plVar15[3] = ((uVar32 >> 0x20) * (uVar27 & 0xffffffff) +
377: (uVar32 & 0xffffffff) * (ulong)uVar30 << 0x20) +
378: (uVar32 & 0xffffffff) * (uVar27 & 0xffffffff) + param_5;
379: plVar15 = plVar15 + 4;
380: } while (uVar29 < uVar16 >> 2);
381: param_10 = param_10 + (uVar16 & 0xfffffffc);
382: if (uVar16 == (uVar16 & 0xfffffffc)) goto LAB_0015489a;
383: }
384: lVar21 = (long)(int)param_10 * uVar27;
385: plStack888[(int)param_10] = param_5 + lVar21;
386: if ((int)(param_10 + 1) < (int)param_8) {
387: lVar21 = lVar21 + uVar27;
388: plStack888[(int)(param_10 + 1)] = param_5 + lVar21;
389: if ((int)(param_10 + 2) < (int)param_8) {
390: lVar21 = lVar21 + uVar27;
391: plStack888[(int)(param_10 + 2)] = param_5 + lVar21;
392: if ((int)(param_10 + 3) < (int)param_8) {
393: lVar21 = lVar21 + uVar27;
394: plStack888[(int)(param_10 + 3)] = param_5 + lVar21;
395: if ((int)(param_10 + 4) < (int)param_8) {
396: plStack888[(int)(param_10 + 4)] = lVar21 + uVar27 + param_5;
397: }
398: }
399: }
400: }
401: }
402: else {
403: uVar19 = (uint)((ulong)plStack888 >> 3) & 1;
404: iVar10 = iVar9;
405: if (4 < param_8 - 1) {
406: if (((ulong)plStack888 >> 3 & 1) != 0) {
407: *plStack888 = (long)(int)(param_8 - 1) * uVar27 + param_5;
408: iVar10 = 1;
409: }
410: uVar29 = param_8 - uVar19;
411: uVar16 = 0;
412: iVar35 = iVar10 + 1;
413: iVar36 = iVar10 + 2;
414: iVar37 = iVar10 + 3;
415: plVar15 = plStack888 + uVar19;
416: iVar34 = iVar10;
417: do {
418: uVar16 = uVar16 + 1;
419: uVar19 = (param_8 - iVar34) - 1;
420: iVar39 = (param_8 - iVar35) + -1;
421: uVar31 = (param_8 - iVar36) - 1;
422: iVar40 = (param_8 - iVar37) + -1;
423: iVar34 = iVar34 + 4;
424: iVar35 = iVar35 + 4;
425: iVar36 = iVar36 + 4;
426: iVar37 = iVar37 + 4;
427: uVar32 = SUB168(CONCAT412(-(uint)(iVar39 < 0),
428: CONCAT48(iVar39,CONCAT44(iVar39,uVar19))) >> 0x40,0);
429: *plVar15 = ((ulong)-(uint)((int)uVar19 < 0) * (uVar27 & 0xffffffff) +
430: (ulong)uVar19 * (ulong)uVar30 << 0x20) +
431: (ulong)uVar19 * (uVar27 & 0xffffffff) + param_5;
432: plVar15[1] = ((uVar32 >> 0x20) * (uVar27 & 0xffffffff) +
433: (uVar32 & 0xffffffff) * (ulong)uVar30 << 0x20) +
434: (uVar32 & 0xffffffff) * (uVar27 & 0xffffffff) + param_5;
435: uVar32 = SUB168(CONCAT412(-(uint)(iVar40 < 0),
436: CONCAT48(iVar40,CONCAT44(-(uint)((int)uVar31 < 0),
437: uVar31))) >> 0x40,0);
438: plVar15[2] = ((ulong)-(uint)((int)uVar31 < 0) * (uVar27 & 0xffffffff) +
439: (ulong)uVar31 * (ulong)uVar30 << 0x20) +
440: (ulong)uVar31 * (uVar27 & 0xffffffff) + param_5;
441: plVar15[3] = ((uVar32 >> 0x20) * (uVar27 & 0xffffffff) +
442: (uVar32 & 0xffffffff) * (ulong)uVar30 << 0x20) +
443: (uVar32 & 0xffffffff) * (uVar27 & 0xffffffff) + param_5;
444: plVar15 = plVar15 + 4;
445: } while (uVar16 < uVar29 >> 2);
446: iVar10 = iVar10 + (uVar29 & 0xfffffffc);
447: if (uVar29 == (uVar29 & 0xfffffffc)) goto LAB_0015489a;
448: }
449: plStack888[iVar10] = (long)(int)((param_8 - iVar10) + -1) * uVar27 + param_5;
450: iVar34 = iVar10 + 1;
451: if (iVar34 < (int)param_8) {
452: plStack888[iVar34] = (long)(int)((param_8 - iVar34) + -1) * uVar27 + param_5;
453: iVar34 = iVar10 + 2;
454: if (iVar34 < (int)param_8) {
455: plStack888[iVar34] = (long)(int)((param_8 - iVar34) + -1) * uVar27 + param_5;
456: iVar34 = iVar10 + 3;
457: if (iVar34 < (int)param_8) {
458: iVar10 = iVar10 + 4;
459: plStack888[iVar34] = (long)(int)((param_8 - iVar34) + -1) * uVar27 + param_5;
460: if (iVar10 < (int)param_8) {
461: plStack888[iVar10] = (long)(int)((param_8 - iVar10) + -1) * uVar27 + param_5
462: ;
463: }
464: }
465: }
466: }
467: }
468: }
469: LAB_0015489a:
470: if ((int)param_8 < (int)uVar18) {
471: lVar21 = (long)(int)param_8;
472: uVar30 = uVar18 - param_8;
473: plVar15 = plStack888 + lVar21 + -1;
474: if (uVar30 < 0x19) {
475: plVar17 = plStack888 + lVar21;
476: do {
477: plVar24 = plVar17 + 1;
478: *plVar17 = *plVar15;
479: plVar17 = plVar24;
480: } while (plVar24 != plStack888 + (ulong)(~param_8 + uVar18) + lVar21 + 1);
481: }
482: else {
483: uVar27 = (ulong)(plStack888 + lVar21) >> 3;
484: uVar19 = (uint)uVar27 & 1;
485: if (2 - ((uVar27 & 1) == 0) <= ~param_8 + uVar18) {
486: if ((uVar27 & 1) != 0) {
487: param_8 = param_8 + 1;
488: plStack888[lVar21] = *plVar15;
489: }
490: uVar30 = uVar30 - uVar19;
491: lVar23 = *plVar15;
492: uVar16 = 0;
493: plVar17 = plStack888 + (ulong)uVar19 + lVar21;
494: do {
495: uVar16 = uVar16 + 1;
496: *plVar17 = lVar23;
497: plVar17[1] = lVar23;
498: plVar17 = plVar17 + 2;
499: } while (uVar16 < uVar30 >> 1);
500: param_8 = param_8 + (uVar30 & 0xfffffffe);
501: if (uVar30 == (uVar30 & 0xfffffffe)) goto LAB_00154975;
502: }
503: plStack888[(int)param_8] = *plVar15;
504: if ((int)(param_8 + 1) < (int)uVar18) {
505: plStack888[(int)(param_8 + 1)] = *plVar15;
506: }
507: }
508: }
509: LAB_00154975:
510: iVar10 = *(int *)(param_1 + 0x240);
511: if (0 < iVar10) {
512: lVar21 = 0;
513: piVar26 = (int *)(*(long *)(param_1 + 0x338) + 8);
514: do {
515: iVar34 = piVar26[1];
516: uVar30 = piVar26[5] * 8 + 0x1f;
517: uVar19 = uVar30 & 0xffffffe0;
518: pvVar13 = malloc((ulong)(uVar19 * iVar34 + 0x20));
519: *(void **)(auStack312 + lVar21 * 2) = pvVar13;
520: if (pvVar13 == (void *)0x0) {
521: *(undefined8 *)(param_1 + 0x628) = 0x66206e6f69746163;
522: *(undefined4 *)(param_1 + 0x630) = 0x756c6961;
523: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
524: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
525: *(undefined2 *)(param_1 + 0x634) = 0x6572;
526: *(undefined *)(param_1 + 0x636) = 0;
527: *(undefined8 *)(param_1 + 0x618) = 0x6d654d203a292873;
528: *(undefined8 *)(param_1 + 0x620) = 0x6f6c6c612079726f;
529: *(undefined4 *)(param_1 + 0x6d0) = 1;
530: puVar11 = (undefined4 *)
531: __tls_get_addr(0x6d654d203a292873,0x65646f6365446a74,&PTR_00398fc0);
532: *puVar11 = 0x65446a74;
533: puVar11[1] = 0x65646f63;
534: puVar11[2] = 0x50565559;
535: puVar11[3] = 0x656e616c;
536: goto LAB_00155095;
537: }
538: puVar14 = (ulong *)malloc((long)iVar34 << 3);
539: *(ulong **)(auStack232 + lVar21 * 2) = puVar14;
540: if (puVar14 == (ulong *)0x0) {
541: *(undefined8 *)(param_1 + 0x628) = 0x66206e6f69746163;
542: *(undefined4 *)(param_1 + 0x630) = 0x756c6961;
543: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
544: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
545: *(undefined2 *)(param_1 + 0x634) = 0x6572;
546: *(undefined *)(param_1 + 0x636) = 0;
547: *(undefined8 *)(param_1 + 0x618) = 0x6d654d203a292873;
548: *(undefined8 *)(param_1 + 0x620) = 0x6f6c6c612079726f;
549: *(undefined4 *)(param_1 + 0x6d0) = 1;
550: puVar11 = (undefined4 *)
551: __tls_get_addr(0x6d654d203a292873,0x65646f6365446a74,&PTR_00398fc0);
552: *puVar11 = 0x65446a74;
553: puVar11[1] = 0x65646f63;
554: puVar11[2] = 0x50565559;
555: puVar11[3] = 0x656e616c;
556: goto LAB_00155095;
557: }
558: if (0 < iVar34) {
559: uVar27 = (long)pvVar13 + 0x1fU & 0xffffffffffffffe0;
560: uVar16 = (uint)((ulong)puVar14 >> 3) & 1;
561: iVar35 = iVar9;
562: if (3 < iVar34 - 1U) {
563: if (((ulong)puVar14 >> 3 & 1) != 0) {
564: *puVar14 = uVar27;
565: iVar35 = 1;
566: }
567: uVar31 = iVar34 - uVar16;
568: uVar29 = 0;
569: puVar22 = puVar14 + uVar16;
570: auVar33 = CONCAT412(iVar35 + 3,CONCAT48(iVar35 + 2,CONCAT44(iVar35 + 1,iVar35)))
571: ;
572: do {
573: uVar29 = uVar29 + 1;
574: iVar36 = SUB164(auVar33 >> 0x60,0);
575: puVar22[2] = ((SUB168(auVar33 >> 0x40,0) & 0xffffffff) * (ulong)uVar19 &
576: 0xffffffff) + uVar27;
577: puVar22[3] = iVar36 * uVar30 + uVar27;
578: *puVar22 = ((ulong)SUB164(auVar33,0) * (ulong)uVar19 & 0xffffffff) + uVar27;
579: puVar22[1] = ((SUB168(auVar33,0) >> 0x20) * (ulong)uVar19 & 0xffffffff) +
580: uVar27;
581: puVar22 = puVar22 + 4;
582: auVar33 = CONCAT412(iVar36 + 4,
583: CONCAT48(SUB164(auVar33 >> 0x40,0) + 4,
584: CONCAT44(SUB164(auVar33 >> 0x20,0) + 4,
585: SUB164(auVar33,0) + 4)));
586: } while (uVar29 < uVar31 >> 2);
587: iVar35 = (uVar31 & 0xfffffffc) + iVar35;
588: if ((uVar31 & 0xfffffffc) == uVar31) goto LAB_00154bc1;
589: }
590: puVar14[iVar35] = iVar35 * uVar19 + uVar27;
591: if (iVar35 + 1 < iVar34) {
592: uVar30 = iVar35 * uVar19 + uVar19;
593: puVar14[iVar35 + 1] = uVar30 + uVar27;
594: if (iVar35 + 2 < iVar34) {
595: uVar30 = uVar30 + uVar19;
596: puVar14[iVar35 + 2] = uVar30 + uVar27;
597: if (iVar35 + 3 < iVar34) {
598: puVar14[iVar35 + 3] = (uVar30 + uVar19) + uVar27;
599: }
600: }
601: }
602: }
603: LAB_00154bc1:
604: iVar35 = ((iVar2 + -1 + param_6 & -iVar2) * *piVar26) / iVar2;
605: *(int *)((long)aiStack364 + lVar21 + 4) = iVar35;
606: iVar34 = (int)(uVar18 * iVar34) / iVar3;
607: plVar15 = (long *)malloc((long)iVar34 << 3);
608: *(long **)(auStack152 + lVar21 * 2) = plVar15;
609: if (plVar15 == (long *)0x0) {
610: *(undefined8 *)(param_1 + 0x628) = 0x66206e6f69746163;
611: *(undefined4 *)(param_1 + 0x630) = 0x756c6961;
612: *(undefined8 *)(param_1 + 0x608) = 0x65646f6365446a74;
613: *(undefined8 *)(param_1 + 0x610) = 0x656e616c50565559;
614: *(undefined2 *)(param_1 + 0x634) = 0x6572;
615: *(undefined *)(param_1 + 0x636) = 0;
616: *(undefined8 *)(param_1 + 0x618) = 0x6d654d203a292873;
617: *(undefined8 *)(param_1 + 0x620) = 0x6f6c6c612079726f;
618: *(undefined4 *)(param_1 + 0x6d0) = 1;
619: puVar11 = (undefined4 *)
620: __tls_get_addr(0x6d654d203a292873,0x65646f6365446a74,&PTR_00398fc0);
621: *(undefined8 *)(puVar11 + 8) = 0x66206e6f69746163;
622: puVar11[10] = 0x756c6961;
623: *(undefined2 *)(puVar11 + 0xb) = 0x6572;
624: *(undefined *)((long)puVar11 + 0x2e) = 0;
625: *puVar11 = 0x65446a74;
626: puVar11[1] = 0x65646f63;
627: puVar11[2] = 0x50565559;
628: puVar11[3] = 0x656e616c;
629: puVar11[4] = 0x3a292873;
630: puVar11[5] = 0x6d654d20;
631: puVar11[6] = 0x2079726f;
632: puVar11[7] = 0x6f6c6c61;
633: goto LAB_00154e5e;
634: }
635: lVar23 = *(long *)((long)param_2 + lVar21 * 2);
636: if (0 < iVar34) {
637: if (param_3 == 0) {
638: plVar17 = plVar15 + (ulong)(iVar34 - 1) + 1;
639: do {
640: *plVar15 = lVar23;
641: plVar15 = plVar15 + 1;
642: lVar23 = lVar23 + iVar35;
643: } while (plVar15 != plVar17);
644: }
645: else {
646: plVar17 = plVar15 + (ulong)(iVar34 - 1) + 1;
647: lVar28 = (long)iVar35;
648: if (*(int *)(param_3 + lVar21) != 0) {
649: lVar28 = (long)*(int *)(param_3 + lVar21);
650: }
651: do {
652: *plVar15 = lVar23;
653: plVar15 = plVar15 + 1;
654: lVar23 = lVar23 + lVar28;
655: } while (plVar15 != plVar17);
656: }
657: }
658: piVar26 = piVar26 + 0x18;
659: lVar21 = lVar21 + 4;
660: } while (lVar21 != (ulong)(iVar10 - 1) * 4 + 4);
661: }
662: iVar9 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
663: if (iVar9 != 0) goto LAB_00154e5e;
664: if (0 < (int)uVar18) {
665: iVar2 = *(int *)(param_1 + 0x3a4);
666: do {
667: uStack368 = 0;
668: aiStack364[0] = 0;
669: lVar21 = *(long *)(param_1 + 0x338);
670: if (0 < *(int *)(param_1 + 0x240)) {
671: lVar23 = 1;
672: do {
673: piVar26 = (int *)(lVar21 + 0xc);
674: lVar21 = lVar21 + 0x60;
675: FUN_00148a00(*(undefined8 *)(auStack168 + lVar23 * 8 + 8),
676: (long)(*piVar26 * iVar9) / (long)iVar2 & 0xffffffff,
677: *(undefined8 *)(auStack248 + lVar23 * 8 + 8),0,*piVar26,
678: aiStack364[lVar23]);
679: iVar3 = (int)lVar23;
680: lVar23 = lVar23 + 1;
681: iVar2 = *(int *)(param_1 + 0x3a4);
682: } while (*(int *)(param_1 + 0x240) != iVar3 && iVar3 <= *(int *)(param_1 + 0x240))
683: ;
684: }
685: (**(code **)(*(long *)(param_1 + 0x468) + 8))(lVar25,auStack232,&uStack368);
686: iVar2 = *(int *)(param_1 + 0x3a4);
687: iVar9 = iVar9 + iVar2;
688: } while (iVar9 < (int)uVar18);
689: }
690: thunk_FUN_0011f490(lVar25);
691: }
692: }
693: }
694: else {
695: LAB_00154e5e:
696: uStack892 = 0xffffffff;
697: }
698: }
699: iVar9 = *(int *)(param_1 + 0x22c);
700: }
701: if (200 < iVar9) {
702: thunk_FUN_0011f490(lVar25);
703: }
704: lVar25 = 0;
705: free(plStack888);
706: do {
707: free(*(void **)(auStack232 + lVar25));
708: free(*(void **)(auStack312 + lVar25));
709: ppvVar1 = (void **)(auStack152 + lVar25);
710: lVar25 = lVar25 + 8;
711: free(*ppvVar1);
712: } while (lVar25 != 0x50);
713: *(undefined4 *)(param_1 + 0x5fc) = 0;
714: uVar8 = 0xffffffff;
715: if (*(int *)(param_1 + 0x5f8) == 0) {
716: uVar8 = uStack892;
717: }
718: LAB_001541b5:
719: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
720: return uVar8;
721: }
722: /* WARNING: Subroutine does not return */
723: __stack_chk_fail();
724: }
725: 
