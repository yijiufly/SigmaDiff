1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8
5: tjDecompress2(long param_1,long param_2,long param_3,long param_4,int param_5,int param_6,
6: int param_7,uint param_8,uint param_9)
7: 
8: {
9: long lVar1;
10: int iVar2;
11: undefined8 uVar3;
12: ulong uVar4;
13: int *piVar5;
14: long lVar6;
15: uint uVar7;
16: undefined8 uVar8;
17: uint uVar9;
18: uint uVar10;
19: long *plVar11;
20: uint uVar12;
21: uint uVar13;
22: undefined auVar14 [16];
23: ulong uVar15;
24: int iVar16;
25: int iVar17;
26: int iVar18;
27: ulong uVar19;
28: uint uVar20;
29: int iVar21;
30: int iVar22;
31: int iVar23;
32: int iVar24;
33: long *plStack120;
34: int iStack64;
35: 
36: if (param_1 == 0) {
37: ram0x003a6008 = ram0x003a6008 & 0xff00000000000000 | 0x656c646e6168;
38: s_No_error_003a6000._0_8_ = 0x2064696c61766e49;
39: return 0xffffffff;
40: }
41: lVar1 = param_1 + 0x208;
42: *(undefined4 *)(param_1 + 0x5f8) = 0;
43: *(undefined4 *)(param_1 + 0x6d0) = 0;
44: *(uint *)(param_1 + 0x5fc) = param_9 >> 0xd & 1;
45: if ((*(byte *)(param_1 + 0x600) & 2) == 0) {
46: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
47: *(undefined8 *)(param_1 + 0x610) = 0x3a29283273736572;
48: *(undefined8 *)(param_1 + 0x618) = 0x636e6174736e4920;
49: *(undefined8 *)(param_1 + 0x620) = 0x6f6e207361682065;
50: *(undefined8 *)(param_1 + 0x628) = 0x69206e6565622074;
51: *(undefined8 *)(param_1 + 0x630) = 0x7a696c616974696e;
52: *(undefined8 *)(param_1 + 0x638) = 0x6420726f66206465;
53: *(undefined8 *)(param_1 + 0x640) = 0x736572706d6f6365;
54: *(undefined4 *)(param_1 + 0x648) = 0x6e6f6973;
55: *(undefined *)(param_1 + 0x64c) = 0;
56: *(undefined4 *)(param_1 + 0x6d0) = 1;
57: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
58: uVar8 = 0xffffffff;
59: ram0x003a6008 = 0x3a29283273736572;
60: _DAT_003a6010 = 0x636e6174736e4920;
61: _DAT_003a6018 = 0x6f6e207361682065;
62: _DAT_003a6020 = 0x69206e6565622074;
63: _DAT_003a6028 = 0x7a696c616974696e;
64: _DAT_003a6030 = 0x6420726f66206465;
65: _DAT_003a6038 = 0x736572706d6f6365;
66: _DAT_003a6040 = 0x6e6f6973;
67: DAT_003a6044 = 0;
68: plStack120 = (long *)0x0;
69: }
70: else {
71: if (((((param_2 == 0) || (param_3 == 0)) || (param_4 == 0)) || ((param_5 < 0 || (param_6 < 0))))
72: || ((param_7 < 0 || (0xb < param_8)))) {
73: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
74: ram0x003a6008 = 0x3a29283273736572;
75: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
76: *(undefined8 *)(param_1 + 0x610) = 0x3a29283273736572;
77: *(undefined8 *)(param_1 + 0x618) = 0x64696c61766e4920;
78: *(undefined8 *)(param_1 + 0x620) = 0x6e656d7567726120;
79: *(undefined2 *)(param_1 + 0x628) = 0x74;
80: *(undefined4 *)(param_1 + 0x6d0) = 1;
81: uVar8 = 0xffffffff;
82: _DAT_003a6010 = 0x64696c61766e4920;
83: _DAT_003a6018 = 0x6e656d7567726120;
84: _DAT_003a6020 = CONCAT62(_DAT_003a6022,0x74);
85: plStack120 = (long *)0x0;
86: }
87: else {
88: if ((param_9 & 8) == 0) {
89: if ((param_9 & 0x10) == 0) {
90: if ((param_9 & 0x20) != 0) {
91: putenv("JSIMD_FORCESSE2=1");
92: }
93: }
94: else {
95: putenv("JSIMD_FORCESSE=1");
96: }
97: }
98: else {
99: putenv("JSIMD_FORCEMMX=1");
100: }
101: iVar2 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
102: uVar8 = 0xffffffff;
103: plStack120 = (long *)0x0;
104: if (iVar2 == 0) {
105: FUN_00150390(lVar1,param_2,param_3);
106: FUN_0011d3f0(lVar1,1);
107: *(undefined4 *)(param_1 + 0x248) = *(undefined4 *)(&DAT_0018bb40 + (long)(int)param_8 * 4);
108: if ((param_9 & 0x800) != 0) {
109: *(undefined4 *)(param_1 + 0x268) = 1;
110: }
111: if ((param_9 & 0x100) != 0) {
112: *(undefined4 *)(param_1 + 0x26c) = 0;
113: }
114: piVar5 = (int *)&DAT_0018bb80;
115: if (param_5 == 0) {
116: param_5 = *(int *)(param_1 + 0x238);
117: }
118: iVar2 = *(int *)(param_1 + 0x23c);
119: if (param_7 != 0) {
120: iVar2 = param_7;
121: }
122: do {
123: iVar22 = *piVar5;
124: iVar23 = piVar5[1];
125: if (((iVar23 + -1 + *(int *)(param_1 + 0x23c) * iVar22) / iVar23 <= iVar2) &&
126: ((iVar23 + -1 + iVar22 * *(int *)(param_1 + 0x238)) / iVar23 <= param_5)) {
127: *(int *)(param_1 + 0x24c) = iVar22;
128: *(int *)(param_1 + 0x250) = iVar23;
129: FUN_0011d6c0();
130: iStack64 = param_6;
131: if (param_6 == 0) {
132: iStack64 = *(int *)(&DAT_0018bc40 + (long)(int)param_8 * 4) *
133: *(int *)(param_1 + 0x290);
134: }
135: plStack120 = (long *)malloc((ulong)*(uint *)(param_1 + 0x294) << 3);
136: if (plStack120 == (long *)0x0) {
137: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
138: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
139: *(undefined8 *)(param_1 + 0x610) = 0x3a29283273736572;
140: *(undefined8 *)(param_1 + 0x618) = 0x2079726f6d654d20;
141: *(undefined8 *)(param_1 + 0x620) = 0x697461636f6c6c61;
142: *(undefined8 *)(param_1 + 0x628) = 0x756c696166206e6f;
143: *(undefined2 *)(param_1 + 0x630) = 0x6572;
144: *(undefined *)(param_1 + 0x632) = 0;
145: *(undefined4 *)(param_1 + 0x6d0) = 1;
146: uVar8 = 0xffffffff;
147: ram0x003a6008 = 0x3a29283273736572;
148: _DAT_003a6010 = 0x2079726f6d654d20;
149: _DAT_003a6018 = 0x697461636f6c6c61;
150: _DAT_003a6020 = 0x756c696166206e6f;
151: _DAT_003a6028 = CONCAT53(DAT_003a6028_3,0x6572);
152: goto LAB_00146224;
153: }
154: iVar2 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
155: uVar8 = 0xffffffff;
156: if (iVar2 != 0) goto LAB_00146224;
157: uVar7 = *(uint *)(param_1 + 0x294);
158: if ((int)uVar7 < 1) goto LAB_0014691d;
159: uVar4 = SEXT48(iStack64);
160: uVar9 = (uint)((ulong)((long)plStack120 << 0x3c) >> 0x20);
161: uVar20 = iStack64 >> 0x1f;
162: if ((param_9 & 2) == 0) {
163: uVar13 = uVar9 >> 0x1f;
164: if (uVar7 < (uint)-((int)uVar9 >> 0x1f)) {
165: uVar13 = uVar7;
166: }
167: uVar9 = uVar7;
168: if (uVar7 < 7) {
169: LAB_001466f0:
170: *plStack120 = param_4;
171: if (uVar9 < 2) {
172: iVar2 = 1;
173: }
174: else {
175: plStack120[1] = param_4 + uVar4;
176: if (uVar9 < 3) {
177: iVar2 = 2;
178: }
179: else {
180: lVar6 = param_4 + uVar4 * 2;
181: plStack120[2] = lVar6;
182: if (uVar9 < 4) {
183: iVar2 = 3;
184: }
185: else {
186: lVar6 = lVar6 + uVar4;
187: plStack120[3] = lVar6;
188: if (uVar9 < 5) {
189: iVar2 = 4;
190: }
191: else {
192: lVar6 = lVar6 + uVar4;
193: plStack120[4] = lVar6;
194: if (uVar9 < 6) {
195: iVar2 = 5;
196: }
197: else {
198: plStack120[5] = lVar6 + uVar4;
199: iVar2 = 6;
200: }
201: }
202: }
203: }
204: }
205: uVar10 = uVar9;
206: if (uVar7 == uVar9) goto LAB_0014691d;
207: }
208: else {
209: uVar10 = 0;
210: iVar2 = 0;
211: uVar9 = uVar13;
212: if (uVar13 != 0) goto LAB_001466f0;
213: }
214: uVar13 = uVar7 - uVar10;
215: uVar9 = uVar13 & 0xfffffffc;
216: if (uVar9 == 0) goto LAB_00146c49;
217: uVar12 = 0;
218: plVar11 = plStack120 + uVar10;
219: auVar14 = CONCAT88(CONCAT44(iVar2 + 3,iVar2 + 2),CONCAT44(iVar2 + 1,iVar2));
220: do {
221: uVar12 = uVar12 + 1;
222: iVar22 = SUB164(auVar14 >> 0x20,0);
223: uVar10 = SUB164(auVar14 >> 0x40,0);
224: iVar23 = SUB164(auVar14 >> 0x60,0);
225: uVar19 = SUB168(CONCAT412(-(uint)(iVar22 < 0),CONCAT48(iVar22,SUB168(auVar14,0))) >>
226: 0x40,0);
227: uVar15 = SUB168(auVar14,0) & 0xffffffff;
228: *plVar11 = uVar15 * (uVar4 & 0xffffffff) +
229: ((ulong)-(uint)(SUB164(auVar14,0) < 0) * (uVar4 & 0xffffffff) +
230: uVar15 * uVar20 << 0x20) + param_4;
231: plVar11[1] = (uVar19 & 0xffffffff) * (uVar4 & 0xffffffff) +
232: ((uVar19 >> 0x20) * (uVar4 & 0xffffffff) +
233: (uVar19 & 0xffffffff) * (ulong)uVar20 << 0x20) + param_4;
234: uVar15 = SUB168(CONCAT412(-(uint)(auVar14 < (undefined  [16])0x0),
235: CONCAT48(iVar23,CONCAT44(-(uint)((int)uVar10 < 0),uVar10))
236: ) >> 0x40,0);
237: plVar11[2] = (ulong)uVar10 * (uVar4 & 0xffffffff) +
238: ((ulong)-(uint)((int)uVar10 < 0) * (uVar4 & 0xffffffff) +
239: (ulong)uVar10 * (ulong)uVar20 << 0x20) + param_4;
240: plVar11[3] = (uVar15 & 0xffffffff) * (uVar4 & 0xffffffff) +
241: ((uVar15 >> 0x20) * (uVar4 & 0xffffffff) +
242: (uVar15 & 0xffffffff) * (ulong)uVar20 << 0x20) + param_4;
243: plVar11 = plVar11 + 4;
244: auVar14 = CONCAT412(iVar23 + 4,
245: CONCAT48(uVar10 + 4,CONCAT44(iVar22 + 4,SUB164(auVar14,0) + 4)))
246: ;
247: } while (uVar12 < uVar13 >> 2);
248: iVar2 = iVar2 + uVar9;
249: if (uVar9 != uVar13) {
250: LAB_00146c49:
251: plStack120[iVar2] = (long)iVar2 * uVar4 + param_4;
252: iVar22 = iVar2 + 1;
253: if (iVar22 < (int)uVar7) {
254: iVar2 = iVar2 + 2;
255: plStack120[iVar22] = (long)iVar22 * uVar4 + param_4;
256: if (iVar2 < (int)uVar7) {
257: plStack120[iVar2] = uVar4 * (long)iVar2 + param_4;
258: }
259: }
260: }
261: }
262: else {
263: uVar13 = uVar9 >> 0x1f;
264: if (uVar7 <= (uint)-((int)uVar9 >> 0x1f)) {
265: uVar13 = uVar7;
266: }
267: uVar9 = uVar7;
268: if (uVar7 < 6) {
269: LAB_001469b7:
270: *plStack120 = (uVar7 - 1) * uVar4 + param_4;
271: if (uVar9 < 2) {
272: iVar2 = 1;
273: }
274: else {
275: plStack120[1] = (uVar7 - 2) * uVar4 + param_4;
276: if (uVar9 < 3) {
277: iVar2 = 2;
278: }
279: else {
280: plStack120[2] = (uVar7 - 3) * uVar4 + param_4;
281: if (uVar9 < 4) {
282: iVar2 = 3;
283: }
284: else {
285: plStack120[3] = (uVar7 - 4) * uVar4 + param_4;
286: if (uVar9 < 5) {
287: iVar2 = 4;
288: }
289: else {
290: plStack120[4] = (uVar7 - 5) * uVar4 + param_4;
291: iVar2 = 5;
292: }
293: }
294: }
295: }
296: uVar10 = uVar9;
297: if (uVar7 == uVar9) goto LAB_0014691d;
298: }
299: else {
300: uVar10 = 0;
301: iVar2 = 0;
302: uVar9 = uVar13;
303: if (uVar13 != 0) goto LAB_001469b7;
304: }
305: uVar13 = uVar7 - uVar10;
306: uVar9 = uVar13 & 0xfffffffc;
307: if (uVar9 == 0) goto LAB_001468c0;
308: iVar22 = iVar2 + 1;
309: iVar23 = iVar2 + 2;
310: iVar24 = iVar2 + 3;
311: uVar12 = 0;
312: plVar11 = plStack120 + uVar10;
313: iVar21 = iVar2;
314: do {
315: uVar12 = uVar12 + 1;
316: iVar16 = -1 - iVar21;
317: iVar17 = -1 - iVar22;
318: iVar18 = -1 - iVar24;
319: uVar10 = (-1 - iVar23) + uVar7;
320: iVar21 = iVar21 + 4;
321: iVar22 = iVar22 + 4;
322: iVar23 = iVar23 + 4;
323: iVar24 = iVar24 + 4;
324: uVar19 = (ulong)(iVar17 + uVar7);
325: uVar15 = (ulong)(iVar16 + uVar7);
326: *plVar11 = uVar15 * (uVar4 & 0xffffffff) + (uVar15 * uVar20 << 0x20) + param_4;
327: plVar11[1] = uVar19 * (uVar4 & 0xffffffff) + (uVar19 * uVar20 << 0x20) + param_4;
328: uVar15 = (ulong)(iVar18 + uVar7);
329: plVar11[2] = (ulong)uVar10 * (uVar4 & 0xffffffff) +
330: ((ulong)uVar10 * (ulong)uVar20 << 0x20) + param_4;
331: plVar11[3] = uVar15 * (uVar4 & 0xffffffff) + (uVar15 * uVar20 << 0x20) + param_4;
332: plVar11 = plVar11 + 4;
333: } while (uVar12 < uVar13 >> 2);
334: iVar2 = iVar2 + uVar9;
335: if (uVar13 != uVar9) {
336: LAB_001468c0:
337: iVar23 = uVar7 - 1;
338: plStack120[iVar2] = (uint)(iVar23 - iVar2) * uVar4 + param_4;
339: iVar22 = iVar2 + 1;
340: if (iVar22 < (int)uVar7) {
341: iVar2 = iVar2 + 2;
342: plStack120[iVar22] = (uint)(iVar23 - iVar22) * uVar4 + param_4;
343: if (iVar2 < (int)uVar7) {
344: plStack120[iVar2] = (uint)(iVar23 - iVar2) * uVar4 + param_4;
345: }
346: }
347: }
348: }
349: LAB_0014691d:
350: uVar9 = *(uint *)(param_1 + 0x2b0);
351: if (uVar9 < uVar7) {
352: do {
353: FUN_0011da40(lVar1,plStack120 + uVar9,uVar7 - uVar9);
354: uVar9 = *(uint *)(param_1 + 0x2b0);
355: uVar7 = *(uint *)(param_1 + 0x294);
356: } while (uVar9 < uVar7);
357: }
358: uVar8 = 0;
359: FUN_0011d4d0(lVar1);
360: goto LAB_00146224;
361: }
362: piVar5 = piVar5 + 2;
363: } while (piVar5 != (int *)&DAT_0018bc00);
364: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
365: *(undefined8 *)(param_1 + 0x610) = 0x3a29283273736572;
366: *(undefined8 *)(param_1 + 0x618) = 0x6e20646c756f4320;
367: *(undefined8 *)(param_1 + 0x620) = 0x656c61637320746f;
368: *(undefined8 *)(param_1 + 0x628) = 0x6f74206e776f6420;
369: *(undefined8 *)(param_1 + 0x630) = 0x6465726973656420;
370: *(undefined8 *)(param_1 + 0x638) = 0x64206567616d6920;
371: *(undefined8 *)(param_1 + 0x640) = 0x6e6f69736e656d69;
372: *(undefined2 *)(param_1 + 0x648) = 0x73;
373: *(undefined4 *)(param_1 + 0x6d0) = 1;
374: uVar8 = 0xffffffff;
375: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
376: ram0x003a6008 = 0x3a29283273736572;
377: _DAT_003a6010 = 0x6e20646c756f4320;
378: _DAT_003a6018 = 0x656c61637320746f;
379: _DAT_003a6020 = 0x6f74206e776f6420;
380: _DAT_003a6028 = 0x6465726973656420;
381: _DAT_003a6030 = 0x64206567616d6920;
382: _DAT_003a6038 = 0x6e6f69736e656d69;
383: _DAT_003a6040 = CONCAT22(_DAT_003a6042,0x73);
384: plStack120 = (long *)0x0;
385: }
386: }
387: }
388: LAB_00146224:
389: if (200 < *(int *)(param_1 + 0x22c)) {
390: thunk_FUN_001166f0(lVar1);
391: }
392: if (plStack120 != (long *)0x0) {
393: free(plStack120);
394: }
395: *(undefined4 *)(param_1 + 0x5fc) = 0;
396: uVar3 = 0xffffffff;
397: if (*(int *)(param_1 + 0x5f8) == 0) {
398: uVar3 = uVar8;
399: }
400: return uVar3;
401: }
402: 
