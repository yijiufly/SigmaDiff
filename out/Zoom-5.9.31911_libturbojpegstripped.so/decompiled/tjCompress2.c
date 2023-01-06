1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: ulong tjCompress2(long param_1,long param_2,int param_3,int param_4,uint param_5,uint param_6,
5: long param_7,undefined8 *param_8,uint param_9,uint param_10,uint param_11)
6: 
7: {
8: uint uVar1;
9: int iVar2;
10: ulong uVar3;
11: undefined8 uVar4;
12: int iVar5;
13: long *plVar6;
14: uint uVar7;
15: uint uVar8;
16: long lVar9;
17: uint uVar10;
18: bool bVar11;
19: uint uVar12;
20: uint uVar13;
21: ulong uVar14;
22: undefined auVar15 [16];
23: int iVar16;
24: int iVar17;
25: int iVar18;
26: ulong uVar19;
27: int iVar20;
28: int iVar21;
29: int iVar22;
30: int iVar23;
31: long *plStack96;
32: int iStack80;
33: 
34: if (param_1 == 0) {
35: ram0x003a6008 = ram0x003a6008 & 0xff00000000000000 | 0x656c646e6168;
36: s_No_error_003a6000._0_8_ = 0x2064696c61766e49;
37: return 0xffffffff;
38: }
39: *(undefined4 *)(param_1 + 0x5f8) = 0;
40: *(undefined4 *)(param_1 + 0x6d0) = 0;
41: *(uint *)(param_1 + 0x5fc) = param_11 >> 0xd & 1;
42: if ((*(byte *)(param_1 + 0x600) & 1) == 0) {
43: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
44: *(undefined8 *)(param_1 + 0x610) = 0x49203a2928327373;
45: *(undefined8 *)(param_1 + 0x618) = 0x2065636e6174736e;
46: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20736168;
47: *(undefined8 *)(param_1 + 0x628) = 0x696e69206e656562;
48: *(undefined8 *)(param_1 + 0x630) = 0x64657a696c616974;
49: *(undefined8 *)(param_1 + 0x638) = 0x6d6f6320726f6620;
50: *(undefined8 *)(param_1 + 0x640) = 0x6e6f697373657270;
51: *(undefined *)(param_1 + 0x648) = 0;
52: s_No_error_003a6000._0_8_ = 0x6572706d6f436a74;
53: ram0x003a6008 = 0x49203a2928327373;
54: _DAT_003a6010 = 0x2065636e6174736e;
55: _DAT_003a6018 = 0x20746f6e20736168;
56: _DAT_003a6020 = 0x696e69206e656562;
57: _DAT_003a6028 = 0x64657a696c616974;
58: _DAT_003a6030 = 0x6d6f6320726f6620;
59: _DAT_003a6038 = 0x6e6f697373657270;
60: DAT_003a6040 = 0;
61: iVar2 = *(int *)(param_1 + 0x24);
62: *(undefined4 *)(param_1 + 0x6d0) = 1;
63: uVar7 = 0xffffffff;
64: plStack96 = (long *)0x0;
65: goto joined_r0x0014302e;
66: }
67: if ((((((param_2 == 0) || (param_3 < 1)) || (param_4 < 0)) ||
68: (((int)param_5 < 1 || (0xb < param_6)))) ||
69: ((param_7 == 0 || ((param_8 == (undefined8 *)0x0 || (5 < param_9)))))) || (100 < param_10)) {
70: s_No_error_003a6000._0_8_ = 0x6572706d6f436a74;
71: ram0x003a6008 = 0x49203a2928327373;
72: _DAT_003a6010 = 0x612064696c61766e;
73: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
74: *(undefined8 *)(param_1 + 0x610) = 0x49203a2928327373;
75: *(undefined8 *)(param_1 + 0x618) = 0x612064696c61766e;
76: *(undefined8 *)(param_1 + 0x620) = 0x746e656d756772;
77: *(undefined4 *)(param_1 + 0x6d0) = 1;
78: _DAT_003a6018 = 0x746e656d756772;
79: uVar7 = 0xffffffff;
80: plStack96 = (long *)0x0;
81: }
82: else {
83: iStack80 = param_4;
84: if (param_4 == 0) {
85: iStack80 = param_3 * *(int *)(&DAT_0018bc40 + (long)(int)param_6 * 4);
86: }
87: plStack96 = (long *)malloc((long)(int)param_5 << 3);
88: if (plStack96 == (long *)0x0) {
89: s_No_error_003a6000._0_8_ = 0x6572706d6f436a74;
90: ram0x003a6008 = 0x4d203a2928327373;
91: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
92: *(undefined8 *)(param_1 + 0x610) = 0x4d203a2928327373;
93: *(undefined8 *)(param_1 + 0x618) = 0x6c612079726f6d65;
94: *(undefined8 *)(param_1 + 0x620) = 0x6e6f697461636f6c;
95: *(undefined8 *)(param_1 + 0x628) = 0x6572756c69616620;
96: *(undefined *)(param_1 + 0x630) = 0;
97: *(undefined4 *)(param_1 + 0x6d0) = 1;
98: _DAT_003a6010 = 0x6c612079726f6d65;
99: uVar7 = 0xffffffff;
100: _DAT_003a6018 = 0x6e6f697461636f6c;
101: _DAT_003a6020 = 0x6572756c69616620;
102: _DAT_003a6028 = _DAT_003a6028 & 0xffffffffffffff00;
103: }
104: else {
105: iVar2 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
106: if (iVar2 == 0) {
107: *(int *)(param_1 + 0x30) = param_3;
108: *(uint *)(param_1 + 0x34) = param_5;
109: if ((param_11 & 8) == 0) {
110: if ((param_11 & 0x10) == 0) {
111: if ((param_11 & 0x20) != 0) {
112: putenv("JSIMD_FORCESSE2=1");
113: }
114: }
115: else {
116: putenv("JSIMD_FORCESSE=1");
117: }
118: }
119: else {
120: putenv("JSIMD_FORCEMMX=1");
121: }
122: bVar11 = (param_11 & 0x400) != 0;
123: if (bVar11) {
124: uVar4 = tjBufSize(param_3,param_5,param_9,1);
125: *param_8 = uVar4;
126: }
127: FUN_00150120(param_1,param_7,param_8,!bVar11);
128: uVar3 = FUN_00141bd0(param_1,param_6,param_9,param_10);
129: if ((int)uVar3 == -1) {
130: return uVar3;
131: }
132: FUN_001031b0();
133: uVar3 = SEXT48(iStack80);
134: uVar7 = 1;
135: if (0 < (int)param_5) {
136: uVar7 = param_5;
137: }
138: uVar8 = (uint)((ulong)((long)plStack96 << 0x3c) >> 0x20);
139: uVar1 = uVar8 >> 0x1f;
140: if (uVar7 < (uint)-((int)uVar8 >> 0x1f)) {
141: uVar1 = uVar7;
142: }
143: uVar8 = iStack80 >> 0x1f;
144: if ((param_11 & 2) == 0) {
145: uVar10 = uVar7;
146: if (uVar7 < 7) {
147: LAB_00142cf7:
148: uVar12 = uVar10;
149: *plStack96 = param_2;
150: if (uVar12 < 2) {
151: iVar2 = 1;
152: }
153: else {
154: plStack96[1] = param_2 + uVar3;
155: if (uVar12 < 3) {
156: iVar2 = 2;
157: }
158: else {
159: lVar9 = param_2 + uVar3 * 2;
160: plStack96[2] = lVar9;
161: if (uVar12 < 4) {
162: iVar2 = 3;
163: }
164: else {
165: lVar9 = lVar9 + uVar3;
166: plStack96[3] = lVar9;
167: if (uVar12 < 5) {
168: iVar2 = 4;
169: }
170: else {
171: lVar9 = lVar9 + uVar3;
172: plStack96[4] = lVar9;
173: if (uVar12 < 6) {
174: iVar2 = 5;
175: }
176: else {
177: plStack96[5] = lVar9 + uVar3;
178: iVar2 = 6;
179: }
180: }
181: }
182: }
183: }
184: if (uVar7 == uVar12) goto LAB_00142ee6;
185: }
186: else {
187: uVar12 = 0;
188: iVar2 = 0;
189: uVar10 = uVar1;
190: if (uVar1 != 0) goto LAB_00142cf7;
191: }
192: uVar7 = uVar7 - uVar12;
193: uVar1 = uVar7 & 0xfffffffc;
194: if (uVar1 != 0) {
195: uVar10 = 0;
196: plVar6 = plStack96 + uVar12;
197: auVar15 = CONCAT88(CONCAT44(iVar2 + 3,iVar2 + 2),CONCAT44(iVar2 + 1,iVar2));
198: do {
199: uVar10 = uVar10 + 1;
200: iVar22 = SUB164(auVar15 >> 0x20,0);
201: uVar12 = SUB164(auVar15 >> 0x40,0);
202: iVar23 = SUB164(auVar15 >> 0x60,0);
203: uVar19 = SUB168(CONCAT412(-(uint)(iVar22 < 0),CONCAT48(iVar22,SUB168(auVar15,0))) >>
204: 0x40,0);
205: uVar14 = SUB168(auVar15,0) & 0xffffffff;
206: *plVar6 = uVar14 * (uVar3 & 0xffffffff) +
207: ((ulong)-(uint)(SUB164(auVar15,0) < 0) * (uVar3 & 0xffffffff) +
208: uVar14 * uVar8 << 0x20) + param_2;
209: plVar6[1] = (uVar19 & 0xffffffff) * (uVar3 & 0xffffffff) +
210: ((uVar19 >> 0x20) * (uVar3 & 0xffffffff) +
211: (uVar19 & 0xffffffff) * (ulong)uVar8 << 0x20) + param_2;
212: uVar14 = SUB168(CONCAT412(-(uint)(auVar15 < (undefined  [16])0x0),
213: CONCAT48(iVar23,CONCAT44(-(uint)((int)uVar12 < 0),uVar12)))
214: >> 0x40,0);
215: plVar6[2] = (ulong)uVar12 * (uVar3 & 0xffffffff) +
216: ((ulong)-(uint)((int)uVar12 < 0) * (uVar3 & 0xffffffff) +
217: (ulong)uVar12 * (ulong)uVar8 << 0x20) + param_2;
218: plVar6[3] = (uVar14 & 0xffffffff) * (uVar3 & 0xffffffff) +
219: ((uVar14 >> 0x20) * (uVar3 & 0xffffffff) +
220: (uVar14 & 0xffffffff) * (ulong)uVar8 << 0x20) + param_2;
221: plVar6 = plVar6 + 4;
222: auVar15 = CONCAT412(iVar23 + 4,
223: CONCAT48(uVar12 + 4,CONCAT44(iVar22 + 4,SUB164(auVar15,0) + 4)));
224: } while (uVar10 < uVar7 >> 2);
225: iVar2 = iVar2 + uVar1;
226: if (uVar7 == uVar1) goto LAB_00142ee6;
227: }
228: plStack96[iVar2] = (long)iVar2 * uVar3 + param_2;
229: iVar22 = iVar2 + 1;
230: if (iVar22 < (int)param_5) {
231: iVar2 = iVar2 + 2;
232: plStack96[iVar22] = (long)iVar22 * uVar3 + param_2;
233: if (iVar2 < (int)param_5) {
234: plStack96[iVar2] = uVar3 * (long)iVar2 + param_2;
235: }
236: }
237: }
238: else {
239: uVar10 = uVar7;
240: if (uVar7 < 7) {
241: LAB_00143056:
242: uVar12 = uVar10;
243: *plStack96 = (long)(int)(param_5 - 1) * uVar3 + param_2;
244: if (uVar12 < 2) {
245: iVar2 = 1;
246: }
247: else {
248: lVar9 = (long)(int)(param_5 - 2) * uVar3;
249: plStack96[1] = param_2 + lVar9;
250: if (uVar12 < 3) {
251: iVar2 = 2;
252: }
253: else {
254: lVar9 = lVar9 - uVar3;
255: plStack96[2] = param_2 + lVar9;
256: if (uVar12 < 4) {
257: iVar2 = 3;
258: }
259: else {
260: lVar9 = lVar9 - uVar3;
261: plStack96[3] = param_2 + lVar9;
262: if (uVar12 < 5) {
263: iVar2 = 4;
264: }
265: else {
266: lVar9 = lVar9 - uVar3;
267: plStack96[4] = param_2 + lVar9;
268: if (uVar12 < 6) {
269: iVar2 = 5;
270: }
271: else {
272: plStack96[5] = (lVar9 - uVar3) + param_2;
273: iVar2 = 6;
274: }
275: }
276: }
277: }
278: }
279: if (uVar7 != uVar12) goto LAB_001430fa;
280: }
281: else {
282: uVar12 = 0;
283: iVar2 = 0;
284: uVar10 = uVar1;
285: if (uVar1 != 0) goto LAB_00143056;
286: LAB_001430fa:
287: uVar7 = uVar7 - uVar12;
288: uVar1 = uVar7 & 0xfffffffc;
289: if (uVar1 != 0) {
290: iVar5 = iVar2 + 1;
291: iVar22 = iVar2 + 2;
292: iVar23 = iVar2 + 3;
293: uVar10 = 0;
294: plVar6 = plStack96 + uVar12;
295: iVar21 = iVar2;
296: do {
297: uVar10 = uVar10 + 1;
298: iVar16 = param_5 - iVar21;
299: iVar17 = param_5 - iVar5;
300: iVar18 = param_5 - iVar22;
301: iVar20 = param_5 - iVar23;
302: iVar21 = iVar21 + 4;
303: iVar5 = iVar5 + 4;
304: iVar22 = iVar22 + 4;
305: iVar23 = iVar23 + 4;
306: uVar12 = iVar16 - 1;
307: iVar17 = iVar17 + -1;
308: uVar13 = iVar18 - 1;
309: iVar20 = iVar20 + -1;
310: uVar14 = SUB168(CONCAT412(-(uint)(iVar17 < 0),
311: CONCAT48(iVar17,CONCAT44(iVar17,uVar12))) >> 0x40,0);
312: *plVar6 = (ulong)uVar12 * (uVar3 & 0xffffffff) +
313: ((ulong)-(uint)((int)uVar12 < 0) * (uVar3 & 0xffffffff) +
314: (ulong)uVar12 * (ulong)uVar8 << 0x20) + param_2;
315: plVar6[1] = (uVar14 & 0xffffffff) * (uVar3 & 0xffffffff) +
316: ((uVar14 >> 0x20) * (uVar3 & 0xffffffff) +
317: (uVar14 & 0xffffffff) * (ulong)uVar8 << 0x20) + param_2;
318: uVar14 = SUB168(CONCAT412(-(uint)(iVar20 < 0),
319: CONCAT48(iVar20,CONCAT44(-(uint)((int)uVar13 < 0),uVar13))
320: ) >> 0x40,0);
321: plVar6[2] = (ulong)uVar13 * (uVar3 & 0xffffffff) +
322: ((ulong)-(uint)((int)uVar13 < 0) * (uVar3 & 0xffffffff) +
323: (ulong)uVar13 * (ulong)uVar8 << 0x20) + param_2;
324: plVar6[3] = (uVar14 & 0xffffffff) * (uVar3 & 0xffffffff) +
325: ((uVar14 >> 0x20) * (uVar3 & 0xffffffff) +
326: (uVar14 & 0xffffffff) * (ulong)uVar8 << 0x20) + param_2;
327: plVar6 = plVar6 + 4;
328: } while (uVar10 < uVar7 >> 2);
329: iVar2 = iVar2 + uVar1;
330: if (uVar7 == uVar1) goto LAB_00142ee6;
331: }
332: plStack96[iVar2] = (long)(int)((param_5 - iVar2) + -1) * uVar3 + param_2;
333: iVar22 = iVar2 + 1;
334: if (iVar22 < (int)param_5) {
335: iVar2 = iVar2 + 2;
336: plStack96[iVar22] = (long)(int)((param_5 - iVar22) + -1) * uVar3 + param_2;
337: if (iVar2 < (int)param_5) {
338: plStack96[iVar2] = (long)(int)((param_5 - iVar2) + -1) * uVar3 + param_2;
339: }
340: }
341: }
342: }
343: LAB_00142ee6:
344: uVar7 = *(uint *)(param_1 + 0x130);
345: uVar8 = *(uint *)(param_1 + 0x34);
346: if (uVar7 < uVar8) {
347: do {
348: FUN_00103230(param_1,plStack96 + uVar7,uVar8 - uVar7);
349: uVar7 = *(uint *)(param_1 + 0x130);
350: uVar8 = *(uint *)(param_1 + 0x34);
351: } while (uVar7 < uVar8);
352: }
353: uVar7 = 0;
354: FUN_00102f10(param_1);
355: }
356: else {
357: uVar7 = 0xffffffff;
358: }
359: }
360: }
361: iVar2 = *(int *)(param_1 + 0x24);
362: joined_r0x0014302e:
363: if (100 < iVar2) {
364: thunk_FUN_001166f0(param_1);
365: }
366: if (plStack96 != (long *)0x0) {
367: free(plStack96);
368: }
369: *(undefined4 *)(param_1 + 0x5fc) = 0;
370: uVar3 = 0xffffffff;
371: if (*(int *)(param_1 + 0x5f8) == 0) {
372: uVar3 = (ulong)uVar7;
373: }
374: return uVar3;
375: }
376: 
