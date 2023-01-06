1: 
2: void FUN_0012fb00(code **param_1,int param_2,uint param_3,long *param_4)
3: 
4: {
5: code cVar1;
6: code **ppcVar2;
7: uint uVar3;
8: uint uVar4;
9: long lVar5;
10: long lVar6;
11: byte bVar7;
12: long lVar8;
13: ulong uVar9;
14: undefined4 *puVar10;
15: uint *puVar11;
16: code *pcVar12;
17: uint uVar13;
18: uint uVar14;
19: long *plVar15;
20: uint uVar16;
21: uint uVar17;
22: long lVar18;
23: int iVar19;
24: ulong uVar20;
25: int iVar21;
26: int iVar22;
27: long lVar23;
28: int iVar24;
29: long in_FS_OFFSET;
30: long lStack1416;
31: code *pcStack1400;
32: int iStack1392;
33: uint auStack1372 [259];
34: undefined8 uStack336;
35: undefined8 uStack328;
36: undefined auStack320 [256];
37: long lStack64;
38: 
39: bVar7 = 0;
40: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
41: if (3 < param_3) {
42: ppcVar2 = (code **)*param_1;
43: *(undefined4 *)(ppcVar2 + 5) = 0x32;
44: *(uint *)((long)ppcVar2 + 0x2c) = param_3;
45: (**ppcVar2)();
46: }
47: if (param_2 == 0) {
48: pcStack1400 = param_1[(long)(int)param_3 + 0x21];
49: }
50: else {
51: pcStack1400 = param_1[(long)(int)param_3 + 0x1d];
52: }
53: if (pcStack1400 == (code *)0x0) {
54: ppcVar2 = (code **)*param_1;
55: *(undefined4 *)(ppcVar2 + 5) = 0x32;
56: *(uint *)((long)ppcVar2 + 0x2c) = param_3;
57: (**ppcVar2)();
58: }
59: lVar5 = *param_4;
60: if (lVar5 == 0) {
61: lVar5 = (**(code **)param_1[1])(param_1,1,0x528);
62: *param_4 = lVar5;
63: }
64: uVar20 = 1;
65: *(code **)(lVar5 + 0x120) = pcStack1400;
66: iVar24 = 0;
67: do {
68: cVar1 = pcStack1400[uVar20];
69: uVar13 = (uint)(byte)cVar1;
70: if (0x100 < (int)(uVar13 + iVar24)) {
71: ppcVar2 = (code **)*param_1;
72: *(undefined4 *)(ppcVar2 + 5) = 8;
73: (**ppcVar2)();
74: }
75: if (cVar1 != (code)0x0) {
76: lVar8 = (long)iVar24;
77: lVar6 = (uVar20 & 0xff) * 0x101010101010101;
78: plVar15 = (long *)(auStack320 + lVar8 + -8);
79: if (uVar13 < 8) {
80: if (((byte)cVar1 & 4) == 0) {
81: if ((uVar13 != 0) && (*(char *)plVar15 = (char)lVar6, ((byte)cVar1 & 2) != 0)) {
82: *(short *)((long)&uStack336 + (ulong)uVar13 + lVar8 + 6) = (short)lVar6;
83: }
84: }
85: else {
86: *(int *)plVar15 = (int)lVar6;
87: *(int *)((long)&uStack336 + (ulong)uVar13 + lVar8 + 4) = (int)lVar6;
88: }
89: }
90: else {
91: *plVar15 = lVar6;
92: *(long *)((long)&uStack336 + (ulong)uVar13 + lVar8) = lVar6;
93: uVar9 = (ulong)(((int)plVar15 -
94: (int)(long *)((ulong)(auStack320 + lVar8) & 0xfffffffffffffff8)) + uVar13 >>
95: 3);
96: plVar15 = (long *)((ulong)(auStack320 + lVar8) & 0xfffffffffffffff8);
97: while (uVar9 != 0) {
98: uVar9 = uVar9 - 1;
99: *plVar15 = lVar6;
100: plVar15 = plVar15 + (ulong)bVar7 * -2 + 1;
101: }
102: }
103: iVar24 = iVar24 + uVar13;
104: }
105: uVar20 = uVar20 + 1;
106: } while (uVar20 != 0x11);
107: uVar13 = 0;
108: lVar6 = 0;
109: auStack320[(long)iVar24 + -8] = 0;
110: iVar21 = (int)(char)uStack328;
111: iVar22 = iVar21;
112: iVar19 = iVar21;
113: while ((char)uStack328 != '\0') {
114: while (iVar21 != iVar22) {
115: if (1 << ((byte)iVar21 & 0x3f) <= (long)(ulong)uVar13) goto LAB_0012fd03;
116: uVar13 = uVar13 * 2;
117: iVar21 = iVar21 + 1;
118: }
119: lVar8 = (long)((int)lVar6 + 1);
120: lVar23 = lVar6 - lVar8;
121: do {
122: iVar22 = (int)(char)auStack320[lVar8 + -8];
123: auStack1372[lVar23 + lVar8 + 1] = uVar13;
124: lVar6 = (long)(int)lVar8;
125: uVar13 = uVar13 + 1;
126: lVar8 = lVar8 + 1;
127: } while (iVar22 == iVar21);
128: iVar19 = iVar22;
129: if (1 << ((byte)iVar21 & 0x3f) <= (long)(ulong)uVar13) {
130: LAB_0012fd03:
131: ppcVar2 = (code **)*param_1;
132: *(undefined4 *)(ppcVar2 + 5) = 8;
133: (**ppcVar2)();
134: }
135: uVar13 = uVar13 * 2;
136: iVar21 = iVar21 + 1;
137: uStack328._0_1_ = (char)iVar19;
138: }
139: uVar20 = 0xffffffffffffffff;
140: cVar1 = pcStack1400[1];
141: uVar13 = 0;
142: if (cVar1 != (code)0x0) {
143: *(ulong *)(lVar5 + 0x98) = -(ulong)auStack1372[1];
144: uVar13 = (uint)(byte)cVar1;
145: uVar20 = (ulong)auStack1372[(long)(int)((byte)cVar1 - 1) + 1];
146: }
147: *(ulong *)(lVar5 + 8) = uVar20;
148: uVar20 = 0xffffffffffffffff;
149: if (pcStack1400[2] != (code)0x0) {
150: lVar6 = (long)(int)uVar13;
151: uVar13 = uVar13 + (byte)pcStack1400[2];
152: *(ulong *)(lVar5 + 0xa0) = lVar6 - (ulong)auStack1372[lVar6 + 1];
153: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
154: }
155: *(ulong *)(lVar5 + 0x10) = uVar20;
156: uVar20 = 0xffffffffffffffff;
157: if (pcStack1400[3] != (code)0x0) {
158: lVar6 = (long)(int)uVar13;
159: uVar13 = uVar13 + (byte)pcStack1400[3];
160: *(ulong *)(lVar5 + 0xa8) = lVar6 - (ulong)auStack1372[lVar6 + 1];
161: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
162: }
163: *(ulong *)(lVar5 + 0x18) = uVar20;
164: uVar20 = 0xffffffffffffffff;
165: if (pcStack1400[4] != (code)0x0) {
166: lVar6 = (long)(int)uVar13;
167: uVar13 = uVar13 + (byte)pcStack1400[4];
168: *(ulong *)(lVar5 + 0xb0) = lVar6 - (ulong)auStack1372[lVar6 + 1];
169: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
170: }
171: *(ulong *)(lVar5 + 0x20) = uVar20;
172: uVar20 = 0xffffffffffffffff;
173: if (pcStack1400[5] != (code)0x0) {
174: lVar6 = (long)(int)uVar13;
175: uVar13 = uVar13 + (byte)pcStack1400[5];
176: *(ulong *)(lVar5 + 0xb8) = lVar6 - (ulong)auStack1372[lVar6 + 1];
177: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
178: }
179: *(ulong *)(lVar5 + 0x28) = uVar20;
180: uVar20 = 0xffffffffffffffff;
181: if (pcStack1400[6] != (code)0x0) {
182: lVar6 = (long)(int)uVar13;
183: uVar13 = uVar13 + (byte)pcStack1400[6];
184: *(ulong *)(lVar5 + 0xc0) = lVar6 - (ulong)auStack1372[lVar6 + 1];
185: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
186: }
187: *(ulong *)(lVar5 + 0x30) = uVar20;
188: uVar20 = 0xffffffffffffffff;
189: if (pcStack1400[7] != (code)0x0) {
190: lVar6 = (long)(int)uVar13;
191: uVar13 = uVar13 + (byte)pcStack1400[7];
192: *(ulong *)(lVar5 + 200) = lVar6 - (ulong)auStack1372[lVar6 + 1];
193: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
194: }
195: *(ulong *)(lVar5 + 0x38) = uVar20;
196: uVar20 = 0xffffffffffffffff;
197: if (pcStack1400[8] != (code)0x0) {
198: lVar6 = (long)(int)uVar13;
199: uVar13 = uVar13 + (byte)pcStack1400[8];
200: *(ulong *)(lVar5 + 0xd0) = lVar6 - (ulong)auStack1372[lVar6 + 1];
201: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
202: }
203: *(ulong *)(lVar5 + 0x40) = uVar20;
204: uVar20 = 0xffffffffffffffff;
205: if (pcStack1400[9] != (code)0x0) {
206: lVar6 = (long)(int)uVar13;
207: uVar13 = uVar13 + (byte)pcStack1400[9];
208: *(ulong *)(lVar5 + 0xd8) = lVar6 - (ulong)auStack1372[lVar6 + 1];
209: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
210: }
211: *(ulong *)(lVar5 + 0x48) = uVar20;
212: uVar20 = 0xffffffffffffffff;
213: if (pcStack1400[10] != (code)0x0) {
214: lVar6 = (long)(int)uVar13;
215: uVar13 = uVar13 + (byte)pcStack1400[10];
216: *(ulong *)(lVar5 + 0xe0) = lVar6 - (ulong)auStack1372[lVar6 + 1];
217: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
218: }
219: *(ulong *)(lVar5 + 0x50) = uVar20;
220: uVar20 = 0xffffffffffffffff;
221: if (pcStack1400[0xb] != (code)0x0) {
222: lVar6 = (long)(int)uVar13;
223: uVar13 = uVar13 + (byte)pcStack1400[0xb];
224: *(ulong *)(lVar5 + 0xe8) = lVar6 - (ulong)auStack1372[lVar6 + 1];
225: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
226: }
227: *(ulong *)(lVar5 + 0x58) = uVar20;
228: uVar20 = 0xffffffffffffffff;
229: if (pcStack1400[0xc] != (code)0x0) {
230: lVar6 = (long)(int)uVar13;
231: uVar13 = uVar13 + (byte)pcStack1400[0xc];
232: *(ulong *)(lVar5 + 0xf0) = lVar6 - (ulong)auStack1372[lVar6 + 1];
233: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
234: }
235: *(ulong *)(lVar5 + 0x60) = uVar20;
236: uVar20 = 0xffffffffffffffff;
237: if (pcStack1400[0xd] != (code)0x0) {
238: lVar6 = (long)(int)uVar13;
239: uVar13 = uVar13 + (byte)pcStack1400[0xd];
240: *(ulong *)(lVar5 + 0xf8) = lVar6 - (ulong)auStack1372[lVar6 + 1];
241: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
242: }
243: *(ulong *)(lVar5 + 0x68) = uVar20;
244: uVar20 = 0xffffffffffffffff;
245: if (pcStack1400[0xe] != (code)0x0) {
246: lVar6 = (long)(int)uVar13;
247: uVar13 = uVar13 + (byte)pcStack1400[0xe];
248: *(ulong *)(lVar5 + 0x100) = lVar6 - (ulong)auStack1372[lVar6 + 1];
249: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
250: }
251: *(ulong *)(lVar5 + 0x70) = uVar20;
252: uVar20 = 0xffffffffffffffff;
253: if (pcStack1400[0xf] != (code)0x0) {
254: lVar6 = (long)(int)uVar13;
255: uVar13 = uVar13 + (byte)pcStack1400[0xf];
256: *(ulong *)(lVar5 + 0x108) = lVar6 - (ulong)auStack1372[lVar6 + 1];
257: uVar20 = (ulong)auStack1372[(long)(int)(uVar13 - 1) + 1];
258: }
259: *(ulong *)(lVar5 + 0x78) = uVar20;
260: cVar1 = pcStack1400[0x10];
261: uVar20 = 0xffffffffffffffff;
262: if (cVar1 != (code)0x0) {
263: *(ulong *)(lVar5 + 0x110) = (long)(int)uVar13 - (ulong)auStack1372[(long)(int)uVar13 + 1];
264: uVar20 = (ulong)auStack1372[(long)(int)((uVar13 - 1) + (uint)(byte)cVar1) + 1];
265: }
266: *(ulong *)(lVar5 + 0x80) = uVar20;
267: *(undefined8 *)(lVar5 + 0x118) = 0;
268: *(undefined8 *)(lVar5 + 0x88) = 0xfffff;
269: uVar13 = -(int)(lVar5 + 0x128U >> 2) & 3;
270: if (uVar13 == 0) {
271: iVar22 = 0x100;
272: iVar21 = 0;
273: }
274: else {
275: *(undefined4 *)(lVar5 + 0x128) = 0x900;
276: if (uVar13 == 1) {
277: iVar22 = 0xff;
278: iVar21 = 1;
279: }
280: else {
281: *(undefined4 *)(lVar5 + 300) = 0x900;
282: if (uVar13 == 3) {
283: *(undefined4 *)(lVar5 + 0x130) = 0x900;
284: iVar22 = 0xfd;
285: iVar21 = 3;
286: }
287: else {
288: iVar22 = 0xfe;
289: iVar21 = 2;
290: }
291: }
292: }
293: uVar14 = 0x100 - uVar13;
294: uVar3 = 0;
295: puVar10 = (undefined4 *)(lVar5 + 0x128 + (ulong)uVar13 * 4);
296: do {
297: uVar3 = uVar3 + 1;
298: *puVar10 = 0x900;
299: puVar10[1] = 0x900;
300: puVar10[2] = 0x900;
301: puVar10[3] = 0x900;
302: puVar10 = puVar10 + 4;
303: } while (uVar3 < uVar14 >> 2);
304: uVar13 = uVar14 & 0xfffffffc;
305: iVar21 = uVar13 + iVar21;
306: if (uVar14 != uVar13) {
307: *(undefined4 *)(lVar5 + 0x128 + (long)iVar21 * 4) = 0x900;
308: if (iVar22 - uVar13 != 1) {
309: *(undefined4 *)(lVar5 + 0x128 + (long)(iVar21 + 1) * 4) = 0x900;
310: if (iVar22 - uVar13 != 2) {
311: *(undefined4 *)(lVar5 + 0x128 + (long)(iVar21 + 2) * 4) = 0x900;
312: }
313: }
314: }
315: lStack1416 = 1;
316: iStack1392 = 0;
317: LAB_00130130:
318: cVar1 = pcStack1400[lStack1416];
319: if (cVar1 != (code)0x0) {
320: bVar7 = 8 - (char)lStack1416;
321: uVar13 = 1 << (bVar7 & 0x1f);
322: lVar6 = (long)iStack1392 + 1;
323: lVar8 = (long)iStack1392;
324: lVar23 = lVar6;
325: do {
326: iVar21 = auStack1372[lVar8 + 1] << (bVar7 & 0x1f);
327: lVar18 = (long)iVar21;
328: uVar14 = (uint)(byte)pcStack1400[lVar8 + 0x11] | (int)lStack1416 << 8;
329: uVar3 = -(int)((ulong)(lVar5 + (lVar18 + 0x4a) * 4) >> 2) & 3;
330: uVar16 = uVar3 + 3;
331: if (uVar16 < 5) {
332: uVar16 = 5;
333: }
334: uVar4 = uVar13;
335: if (uVar13 - 1 < uVar16) {
336: LAB_00130264:
337: *(uint *)(lVar5 + 0x128 + lVar18 * 4) = uVar14;
338: if (uVar4 != 1) {
339: *(uint *)(lVar5 + 0x128 + (long)(iVar21 + 1) * 4) = uVar14;
340: if (uVar4 != 2) {
341: *(uint *)(lVar5 + 0x128 + (long)(iVar21 + 2) * 4) = uVar14;
342: if (uVar4 != 3) {
343: *(uint *)(lVar5 + 0x128 + (long)(iVar21 + 3) * 4) = uVar14;
344: if (uVar4 != 4) {
345: *(uint *)(lVar5 + 0x128 + (long)(iVar21 + 4) * 4) = uVar14;
346: if (uVar4 != 5) {
347: *(uint *)(lVar5 + 0x128 + (long)(iVar21 + 5) * 4) = uVar14;
348: }
349: }
350: }
351: }
352: }
353: }
354: else {
355: uVar16 = uVar13;
356: iVar22 = iVar21;
357: if (uVar3 != 0) {
358: *(uint *)(lVar5 + 0x128 + lVar18 * 4) = uVar14;
359: uVar16 = uVar13 - 1;
360: iVar22 = iVar21 + 1;
361: if (uVar3 != 1) {
362: *(uint *)(lVar5 + 0x128 + (long)(iVar21 + 1) * 4) = uVar14;
363: uVar16 = uVar13 - 2;
364: iVar22 = iVar21 + 2;
365: if (uVar3 == 3) {
366: *(uint *)(lVar5 + 0x128 + (long)(iVar21 + 2) * 4) = uVar14;
367: uVar16 = uVar13 - 3;
368: iVar22 = iVar21 + 3;
369: }
370: }
371: }
372: uVar17 = uVar13 - uVar3;
373: uVar4 = 0;
374: puVar11 = (uint *)(lVar5 + ((ulong)uVar3 + lVar18 + 0x4a) * 4);
375: do {
376: uVar4 = uVar4 + 1;
377: *puVar11 = uVar14;
378: puVar11[1] = uVar14;
379: puVar11[2] = uVar14;
380: puVar11[3] = uVar14;
381: puVar11 = puVar11 + 4;
382: } while (uVar4 < uVar17 >> 2);
383: uVar3 = uVar17 & 0xfffffffc;
384: iVar21 = uVar3 + iVar22;
385: if (uVar3 != uVar17) {
386: lVar18 = (long)iVar21;
387: uVar4 = uVar16 - uVar3;
388: goto LAB_00130264;
389: }
390: }
391: if (lVar6 + (ulong)((byte)cVar1 - 1) == lVar23) goto LAB_00130340;
392: lVar8 = lVar23;
393: lVar23 = lVar23 + 1;
394: } while( true );
395: }
396: goto LAB_00130348;
397: LAB_00130340:
398: iStack1392 = iStack1392 + (uint)(byte)cVar1;
399: LAB_00130348:
400: lStack1416 = lStack1416 + 1;
401: if (lStack1416 == 9) {
402: if ((param_2 != 0) && (iVar24 != 0)) {
403: pcVar12 = pcStack1400 + 0x11;
404: do {
405: if (0xf < (byte)*pcVar12) {
406: ppcVar2 = (code **)*param_1;
407: *(undefined4 *)(ppcVar2 + 5) = 8;
408: (**ppcVar2)(param_1);
409: }
410: pcVar12 = pcVar12 + 1;
411: } while (pcVar12 != pcStack1400 + (ulong)(iVar24 - 1) + 0x12);
412: }
413: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
414: return;
415: }
416: /* WARNING: Subroutine does not return */
417: __stack_chk_fail();
418: }
419: goto LAB_00130130;
420: }
421: 
