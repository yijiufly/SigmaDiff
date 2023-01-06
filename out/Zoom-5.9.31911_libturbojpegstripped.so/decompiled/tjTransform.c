1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: int tjTransform(long param_1,long param_2,long param_3,int param_4,long param_5,undefined8 *param_6,
5: int *param_7,uint param_8)
6: 
7: {
8: long lVar1;
9: undefined4 uVar2;
10: undefined4 uVar3;
11: int iVar4;
12: int iVar5;
13: uint uVar6;
14: int iVar7;
15: undefined8 uVar8;
16: long lVar9;
17: long lVar10;
18: undefined4 *puVar11;
19: undefined8 uVar12;
20: int *piVar13;
21: uint uVar14;
22: int iVar15;
23: long lVar16;
24: int iVar17;
25: long lVar18;
26: bool bVar19;
27: undefined4 *puStack248;
28: int iStack160;
29: int iStack156;
30: long lStack136;
31: uint uStack128;
32: int iStack124;
33: undefined4 *puStack104;
34: int *piStack96;
35: undefined8 *puStack80;
36: long lStack72;
37: 
38: if (param_1 == 0) {
39: ram0x003a6008 = ram0x003a6008 & 0xff00000000000000 | 0x656c646e6168;
40: s_No_error_003a6000._0_8_ = 0x2064696c61766e49;
41: return -1;
42: }
43: lVar1 = param_1 + 0x208;
44: *(undefined4 *)(param_1 + 0x5f8) = 0;
45: *(undefined4 *)(param_1 + 0x6d0) = 0;
46: *(uint *)(param_1 + 0x5fc) = param_8 >> 0xd & 1;
47: if ((*(uint *)(param_1 + 0x600) & 3) == 3) {
48: if (((((param_2 == 0) || (param_3 == 0)) || (param_4 < 1)) ||
49: ((param_5 == 0 || (param_6 == (undefined8 *)0x0)))) ||
50: ((param_7 == (int *)0x0 || ((int)param_8 < 0)))) {
51: ram0x003a6008 = 0x49203a29286d726f;
52: _DAT_003a6010 = 0x612064696c61766e;
53: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
54: *(undefined8 *)(param_1 + 0x610) = 0x49203a29286d726f;
55: *(undefined8 *)(param_1 + 0x618) = 0x612064696c61766e;
56: *(undefined8 *)(param_1 + 0x620) = 0x746e656d756772;
57: _DAT_003a6018 = 0x746e656d756772;
58: iVar5 = *(int *)(param_1 + 0x24);
59: *(undefined4 *)(param_1 + 0x6d0) = 1;
60: s_No_error_003a6000._0_8_ = 0x66736e6172546a74;
61: iVar15 = -1;
62: puStack248 = (undefined4 *)0x0;
63: goto joined_r0x0014a19e;
64: }
65: if ((param_8 & 8) == 0) {
66: if ((param_8 & 0x10) == 0) {
67: if ((param_8 & 0x20) != 0) {
68: putenv("JSIMD_FORCESSE2=1");
69: }
70: }
71: else {
72: putenv("JSIMD_FORCESSE=1");
73: }
74: }
75: else {
76: putenv("JSIMD_FORCEMMX=1");
77: }
78: puStack248 = (undefined4 *)malloc((long)param_4 * 0x60);
79: if (puStack248 == (undefined4 *)0x0) {
80: s_No_error_003a6000._0_8_ = 0x66736e6172546a74;
81: ram0x003a6008 = 0x4d203a29286d726f;
82: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
83: *(undefined8 *)(param_1 + 0x610) = 0x4d203a29286d726f;
84: *(undefined8 *)(param_1 + 0x618) = 0x6c612079726f6d65;
85: *(undefined8 *)(param_1 + 0x620) = 0x6e6f697461636f6c;
86: *(undefined8 *)(param_1 + 0x628) = 0x6572756c69616620;
87: *(undefined *)(param_1 + 0x630) = 0;
88: *(undefined4 *)(param_1 + 0x6d0) = 1;
89: _DAT_003a6010 = 0x6c612079726f6d65;
90: iVar15 = -1;
91: _DAT_003a6018 = 0x6e6f697461636f6c;
92: _DAT_003a6020 = 0x6572756c69616620;
93: _DAT_003a6028 = _DAT_003a6028 & 0xffffffffffffff00;
94: }
95: else {
96: memset(puStack248,0,(long)param_4 * 0x60);
97: iVar5 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
98: iVar15 = -1;
99: if (iVar5 == 0) {
100: FUN_00150390(lVar1,param_2,param_3);
101: if (param_4 == 1) {
102: bVar19 = false;
103: puVar11 = puStack248;
104: piVar13 = param_7;
105: do {
106: *puVar11 = *(undefined4 *)(&DAT_0018bc00 + (long)piVar13[4] * 4);
107: uVar6 = piVar13[5];
108: puVar11[5] = 0;
109: puVar11[1] = uVar6 & 1;
110: puVar11[2] = uVar6 >> 1 & 1;
111: puVar11[3] = uVar6 >> 3 & 1;
112: uVar14 = uVar6 >> 2 & 1;
113: puVar11[4] = uVar14;
114: if (uVar14 != 0) {
115: iVar15 = *piVar13;
116: puVar11[0xb] = 1;
117: puVar11[10] = iVar15;
118: iVar15 = piVar13[1];
119: puVar11[0xd] = 1;
120: puVar11[0xc] = iVar15;
121: iVar15 = piVar13[2];
122: if (iVar15 != 0) {
123: puVar11[7] = 1;
124: }
125: puVar11[6] = iVar15;
126: if (piVar13[3] == 0) {
127: puVar11[8] = 0;
128: }
129: else {
130: puVar11[8] = piVar13[3];
131: puVar11[9] = 1;
132: }
133: }
134: if ((uVar6 & 0x40) == 0) {
135: bVar19 = true;
136: }
137: piVar13 = piVar13 + 10;
138: puVar11 = puVar11 + 0x18;
139: } while (piVar13 != param_7 + 10);
140: }
141: else {
142: bVar19 = false;
143: iVar15 = 0;
144: puVar11 = puStack248;
145: piVar13 = param_7;
146: do {
147: iVar5 = piVar13[4];
148: *puVar11 = *(undefined4 *)(&DAT_0018bc00 + (long)iVar5 * 4);
149: uVar6 = piVar13[5];
150: puVar11[1] = uVar6 & 1;
151: puVar11[2] = uVar6 >> 1 & 1;
152: puVar11[3] = uVar6 >> 3 & 1;
153: uVar14 = uVar6 >> 2 & 1;
154: puVar11[4] = uVar14;
155: puVar11[5] = (uint)(iVar5 == 1);
156: if (uVar14 != 0) {
157: iVar5 = *piVar13;
158: iVar7 = piVar13[2];
159: puVar11[0xb] = 1;
160: puVar11[10] = iVar5;
161: iVar5 = piVar13[1];
162: puVar11[0xd] = 1;
163: puVar11[0xc] = iVar5;
164: iVar5 = 0;
165: if (iVar7 != 0) {
166: puVar11[7] = 1;
167: iVar5 = iVar7;
168: }
169: puVar11[6] = iVar5;
170: if (piVar13[3] == 0) {
171: puVar11[8] = 0;
172: }
173: else {
174: puVar11[8] = piVar13[3];
175: puVar11[9] = 1;
176: }
177: }
178: if ((uVar6 & 0x40) == 0) {
179: bVar19 = true;
180: }
181: iVar15 = iVar15 + 1;
182: piVar13 = piVar13 + 10;
183: puVar11 = puVar11 + 0x18;
184: } while (iVar15 < param_4);
185: }
186: FUN_0014fde0(lVar1,~-!bVar19 & 2);
187: FUN_0011d3f0(lVar1,1);
188: if (*(long *)(param_1 + 0x240) == 0x100000001) {
189: iStack124 = 3;
190: }
191: else {
192: iStack124 = FUN_00141f70(lVar1);
193: if (iStack124 < 0) {
194: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
195: *(undefined8 *)(param_1 + 0x610) = 0x43203a29286d726f;
196: *(undefined8 *)(param_1 + 0x618) = 0x746f6e20646c756f;
197: *(undefined8 *)(param_1 + 0x620) = 0x696d726574656420;
198: *(undefined8 *)(param_1 + 0x628) = 0x617362757320656e;
199: *(undefined8 *)(param_1 + 0x630) = 0x7420676e696c706d;
200: *(undefined8 *)(param_1 + 0x638) = 0x20726f6620657079;
201: *(undefined8 *)(param_1 + 0x640) = 0x616d69204745504a;
202: *(undefined2 *)(param_1 + 0x648) = 0x6567;
203: *(undefined *)(param_1 + 0x64a) = 0;
204: *(undefined4 *)(param_1 + 0x6d0) = 1;
205: iVar15 = -1;
206: s_No_error_003a6000._0_8_ = 0x66736e6172546a74;
207: ram0x003a6008 = 0x43203a29286d726f;
208: _DAT_003a6010 = 0x746f6e20646c756f;
209: _DAT_003a6018 = 0x696d726574656420;
210: _DAT_003a6020 = 0x617362757320656e;
211: _DAT_003a6028 = 0x7420676e696c706d;
212: _DAT_003a6030 = 0x20726f6620657079;
213: _DAT_003a6038 = 0x616d69204745504a;
214: _DAT_003a6040 = CONCAT13(DAT_003a6040_3,0x6567);
215: goto LAB_00149ed0;
216: }
217: }
218: iVar15 = 0;
219: puVar11 = puStack248;
220: piVar13 = param_7;
221: do {
222: iVar5 = FUN_0014f760(lVar1,puVar11);
223: if (iVar5 == 0) {
224: s_No_error_003a6000._0_8_ = 0x66736e6172546a74;
225: ram0x003a6008 = 0x54203a29286d726f;
226: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
227: *(undefined8 *)(param_1 + 0x610) = 0x54203a29286d726f;
228: *(undefined8 *)(param_1 + 0x618) = 0x6d726f66736e6172;
229: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20736920;
230: *(undefined8 *)(param_1 + 0x628) = 0x74636566726570;
231: *(undefined4 *)(param_1 + 0x6d0) = 1;
232: iVar15 = -1;
233: _DAT_003a6010 = 0x6d726f66736e6172;
234: _DAT_003a6018 = 0x20746f6e20736920;
235: _DAT_003a6020 = 0x74636566726570;
236: goto LAB_00149ed0;
237: }
238: if ((puVar11[4] != 0) &&
239: ((*piVar13 % (int)puVar11[0x16] != 0 || (piVar13[1] % (int)puVar11[0x17] != 0)))) {
240: snprintf((char *)(param_1 + 0x608),200,
241: 
242: "To crop this JPEG image, x must be a multiple of %d\nand y must be a multiple of %d.\n"
243: );
244: *(undefined4 *)(param_1 + 0x6d0) = 1;
245: iVar15 = -1;
246: goto LAB_00149ed0;
247: }
248: iVar15 = iVar15 + 1;
249: puVar11 = puVar11 + 0x18;
250: piVar13 = piVar13 + 10;
251: } while (iVar15 < param_4);
252: uVar8 = FUN_00132b50(lVar1);
253: iStack156 = 0;
254: piStack96 = param_7;
255: puStack104 = puStack248;
256: puStack80 = param_6;
257: lStack72 = param_5;
258: do {
259: if (puStack104[4] == 0) {
260: uVar2 = *(undefined4 *)(param_1 + 0x238);
261: uVar3 = *(undefined4 *)(param_1 + 0x23c);
262: }
263: else {
264: uVar2 = puStack104[6];
265: uVar3 = puStack104[8];
266: }
267: bVar19 = (param_8 & 0x400) != 0;
268: if (bVar19) {
269: uVar12 = tjBufSize(uVar2,uVar3,iStack124,1);
270: *puStack80 = uVar12;
271: }
272: if ((*(byte *)(piStack96 + 5) & 0x10) == 0) {
273: FUN_00150120(param_1,lStack72,puStack80,!bVar19);
274: }
275: FUN_0011c430(lVar1,param_1);
276: lVar9 = FUN_0014b730(lVar1,param_1,uVar8,puStack104);
277: if (((param_8 & 0x4000) != 0) || (uVar6 = piStack96[5], (uVar6 & 0x20) != 0)) {
278: FUN_00117620(param_1);
279: uVar6 = piStack96[5];
280: }
281: if ((uVar6 & 0x10) == 0) {
282: FUN_0011c1b0(param_1,lVar9);
283: FUN_0014ff50(lVar1,param_1,-((piStack96[5] & 0x40U) == 0) & 2);
284: }
285: else {
286: FUN_00116330(param_1,1);
287: }
288: FUN_0014bde0(lVar1,param_1,uVar8);
289: if ((*(long *)(piStack96 + 8) != 0) && (0 < *(int *)(param_1 + 0x4c))) {
290: lStack136 = 0;
291: do {
292: iVar7 = (int)lStack136;
293: lVar18 = lStack136 * 0x60 + *(long *)(param_1 + 0x58);
294: uVar6 = *(int *)(lVar18 + 0x1c) * 8;
295: iVar5 = *(int *)(lVar18 + 0x20);
296: if (iVar5 != 0) {
297: iVar15 = *(int *)(lVar18 + 0xc);
298: iStack160 = 0;
299: uStack128 = 0;
300: do {
301: lVar10 = (**(code **)(*(long *)(param_1 + 0x210) + 0x40))
302: (lVar1,*(undefined8 *)(lVar9 + lStack136 * 8),uStack128,iVar15,
303: 1);
304: iVar15 = *(int *)(lVar18 + 0xc);
305: iVar17 = iStack160;
306: if (0 < iVar15) {
307: lVar16 = 0;
308: do {
309: iVar4 = (int)lVar16;
310: iVar17 = iVar4 * 8;
311: iVar15 = (**(code **)(piStack96 + 8))
312: (*(undefined8 *)(lVar10 + lVar16 * 8),
313: (ulong)(uint)(iVar17 + iStack160) << 0x20,
314: (ulong)uVar6 | 0x800000000,0,CONCAT44(iVar5 * 8,uVar6),
315: iVar7,iStack156,piStack96);
316: if (iVar15 == -1) {
317: s_No_error_003a6000._0_8_ = 0x66736e6172546a74;
318: ram0x003a6008 = 0x45203a29286d726f;
319: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
320: *(undefined8 *)(param_1 + 0x610) = 0x45203a29286d726f;
321: *(undefined8 *)(param_1 + 0x618) = 0x206e6920726f7272;
322: _DAT_003a6010 = 0x206e6920726f7272;
323: *(undefined8 *)(param_1 + 0x620) = 0x66206d6f74737563;
324: *(undefined4 *)(param_1 + 0x628) = 0x65746c69;
325: *(undefined2 *)(param_1 + 0x62c) = 0x72;
326: _DAT_003a6018 = 0x66206d6f74737563;
327: *(undefined4 *)(param_1 + 0x6d0) = 1;
328: _DAT_003a6020 = CONCAT26(_DAT_003a6026,0x7265746c69);
329: goto LAB_00149ed0;
330: }
331: iVar15 = *(int *)(lVar18 + 0xc);
332: lVar16 = lVar16 + 1;
333: iVar17 = iStack160 + 8 + iVar17;
334: } while (iVar4 + 1 < iVar15);
335: }
336: uStack128 = uStack128 + iVar15;
337: iStack160 = iVar17;
338: } while (uStack128 <= *(uint *)(lVar18 + 0x20) &&
339: *(uint *)(lVar18 + 0x20) != uStack128);
340: }
341: lStack136 = lStack136 + 1;
342: iVar7 = iVar7 + 1;
343: } while (*(int *)(param_1 + 0x4c) != iVar7 && iVar7 <= *(int *)(param_1 + 0x4c));
344: }
345: if ((*(byte *)(piStack96 + 5) & 0x10) == 0) {
346: FUN_00102f10();
347: }
348: iStack156 = iStack156 + 1;
349: puStack104 = puStack104 + 0x18;
350: piStack96 = piStack96 + 10;
351: lStack72 = lStack72 + 8;
352: puStack80 = puStack80 + 1;
353: } while (iStack156 < param_4);
354: iVar15 = 0;
355: FUN_0011d4d0(lVar1);
356: }
357: }
358: }
359: else {
360: *(undefined8 *)(param_1 + 0x608) = 0x66736e6172546a74;
361: *(undefined8 *)(param_1 + 0x610) = 0x49203a29286d726f;
362: *(undefined8 *)(param_1 + 0x618) = 0x2065636e6174736e;
363: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20736168;
364: *(undefined8 *)(param_1 + 0x628) = 0x696e69206e656562;
365: *(undefined8 *)(param_1 + 0x630) = 0x64657a696c616974;
366: *(undefined8 *)(param_1 + 0x638) = 0x61727420726f6620;
367: *(undefined8 *)(param_1 + 0x640) = 0x74616d726f66736e;
368: *(undefined4 *)(param_1 + 0x648) = 0x6e6f69;
369: *(undefined4 *)(param_1 + 0x6d0) = 1;
370: iVar15 = -1;
371: s_No_error_003a6000._0_8_ = 0x66736e6172546a74;
372: ram0x003a6008 = 0x49203a29286d726f;
373: _DAT_003a6010 = 0x2065636e6174736e;
374: _DAT_003a6018 = 0x20746f6e20736168;
375: _DAT_003a6020 = 0x696e69206e656562;
376: _DAT_003a6028 = 0x64657a696c616974;
377: _DAT_003a6030 = 0x61727420726f6620;
378: _DAT_003a6038 = 0x74616d726f66736e;
379: _DAT_003a6040 = 0x6e6f69;
380: puStack248 = (undefined4 *)0x0;
381: }
382: LAB_00149ed0:
383: iVar5 = *(int *)(param_1 + 0x24);
384: joined_r0x0014a19e:
385: if (iVar5 < 0x65) {
386: iVar5 = *(int *)(param_1 + 0x22c);
387: }
388: else {
389: thunk_FUN_001166f0(param_1);
390: iVar5 = *(int *)(param_1 + 0x22c);
391: }
392: if (200 < iVar5) {
393: thunk_FUN_001166f0(lVar1);
394: }
395: if (puStack248 != (undefined4 *)0x0) {
396: free(puStack248);
397: }
398: *(undefined4 *)(param_1 + 0x5fc) = 0;
399: iVar5 = -1;
400: if (*(int *)(param_1 + 0x5f8) == 0) {
401: iVar5 = iVar15;
402: }
403: return iVar5;
404: }
405: 
