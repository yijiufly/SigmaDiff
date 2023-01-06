1: 
2: long FUN_00159be0(long param_1,code **param_2,long param_3,uint *param_4)
3: 
4: {
5: char *pcVar1;
6: long *plVar2;
7: undefined2 uVar3;
8: uint uVar4;
9: undefined4 uVar5;
10: undefined4 uVar6;
11: undefined2 *puVar7;
12: char *pcVar8;
13: long lVar9;
14: long lVar10;
15: undefined8 uVar11;
16: code *pcVar12;
17: bool bVar13;
18: short sVar14;
19: uint uVar15;
20: undefined4 *puVar16;
21: undefined4 *puVar17;
22: undefined2 *puVar18;
23: long *plVar19;
24: short sVar20;
25: long lVar21;
26: short sVar22;
27: undefined2 *puVar23;
28: ulong uVar24;
29: int iVar25;
30: long lVar26;
31: long lVar27;
32: int iVar28;
33: code **ppcVar29;
34: long lVar30;
35: char cVar31;
36: uint uVar32;
37: long lVar33;
38: long lVar34;
39: long lStack120;
40: 
41: if (param_4[3] == 0) {
42: if (param_4[0x12] == 1) {
43: *(undefined8 *)(param_2[0xb] + 8) = 0x100000001;
44: }
45: }
46: else {
47: if (*(int *)(param_2 + 10) == 3) {
48: if (*(int *)((long)param_2 + 0x4c) == 3) goto LAB_00159ce6;
49: }
50: else {
51: if ((*(int *)(param_2 + 10) == 1) && (*(int *)((long)param_2 + 0x4c) == 1)) {
52: LAB_00159ce6:
53: if (*(long *)(*(long *)(param_1 + 0x130) + 8) == *(long *)(param_1 + 0x198)) {
54: uVar5 = *(undefined4 *)(param_2[0xb] + 0x10);
55: FUN_0011f6f0();
56: *(undefined4 *)(param_2[0xb] + 0x10) = uVar5;
57: goto LAB_00159c37;
58: }
59: }
60: }
61: ppcVar29 = (code **)*param_2;
62: *(undefined4 *)(ppcVar29 + 5) = 0x1b;
63: (**ppcVar29)();
64: }
65: LAB_00159c37:
66: uVar4 = *param_4;
67: if (uVar4 == 7) {
68: LAB_00159d38:
69: uVar4 = param_4[0x17];
70: *(uint *)(param_2 + 6) = param_4[0x16];
71: iVar28 = *(int *)((long)param_2 + 0x4c);
72: *(uint *)((long)param_2 + 0x34) = uVar4;
73: if (0 < iVar28) {
74: pcVar12 = param_2[0xb];
75: puVar16 = (undefined4 *)(pcVar12 + 8);
76: do {
77: uVar5 = *puVar16;
78: puVar17 = puVar16 + 0x18;
79: *puVar16 = puVar16[1];
80: puVar16[1] = uVar5;
81: puVar16 = puVar17;
82: } while ((undefined4 *)(pcVar12 + (ulong)(iVar28 - 1) * 0x60 + 0x68) != puVar17);
83: }
84: ppcVar29 = param_2 + 0xc;
85: do {
86: puVar7 = (undefined2 *)*ppcVar29;
87: if (puVar7 != (undefined2 *)0x0) {
88: lVar21 = 0;
89: puVar18 = puVar7;
90: puVar23 = puVar7;
91: do {
92: if (lVar21 != 0) {
93: uVar3 = *puVar23;
94: iVar28 = (int)lVar21;
95: *puVar23 = *puVar18;
96: *puVar18 = uVar3;
97: if (iVar28 != 1) {
98: uVar3 = puVar23[1];
99: puVar23[1] = puVar18[8];
100: puVar18[8] = uVar3;
101: if (iVar28 != 2) {
102: uVar3 = puVar23[2];
103: puVar23[2] = puVar18[0x10];
104: puVar18[0x10] = uVar3;
105: if (iVar28 != 3) {
106: uVar3 = puVar23[3];
107: puVar23[3] = puVar18[0x18];
108: puVar18[0x18] = uVar3;
109: if (iVar28 != 4) {
110: uVar3 = puVar23[4];
111: puVar23[4] = puVar18[0x20];
112: puVar18[0x20] = uVar3;
113: if (iVar28 != 5) {
114: uVar3 = puVar23[5];
115: puVar23[5] = puVar18[0x28];
116: puVar18[0x28] = uVar3;
117: if (iVar28 == 7) {
118: uVar3 = puVar7[0x37];
119: puVar7[0x37] = puVar7[0x3e];
120: puVar7[0x3e] = uVar3;
121: break;
122: }
123: if (iVar28 == 7) break;
124: }
125: }
126: }
127: }
128: }
129: }
130: lVar21 = lVar21 + 1;
131: puVar23 = puVar23 + 8;
132: puVar18 = puVar18 + 1;
133: } while( true );
134: }
135: ppcVar29 = ppcVar29 + 1;
136: } while (param_2 + 0x10 != ppcVar29);
137: }
138: else {
139: if (uVar4 < 8) {
140: if (uVar4 - 3 < 3) goto LAB_00159d38;
141: }
142: else {
143: if (uVar4 == 9) {
144: if ((param_4[0x1a] != 0) && (param_4[0x1b] != 0)) {
145: uVar4 = param_4[2];
146: lVar21 = *(long *)(param_4 + 0x10);
147: lVar9 = *(long *)(param_4 + 0xe);
148: if ((0 < *(int *)((long)param_2 + 0x4c)) && (0 < *(int *)(lVar9 + 0x38))) {
149: lStack120 = 0;
150: LAB_0015a021:
151: lVar27 = 0;
152: lVar33 = *(long *)(param_1 + 0x130) + lStack120 * 0x60;
153: lVar30 = lStack120 * 0x60 + *(long *)(lVar9 + 0x130);
154: lVar10 = *(long *)(lVar33 + 0x50);
155: lVar34 = *(long *)(lVar30 + 0x50);
156: do {
157: if (*(short *)(lVar10 + lVar27) != *(short *)(lVar34 + lVar27)) {
158: if (uVar4 == 0) {
159: lVar27 = 0;
160: pcVar12 = param_2[(long)*(int *)(lVar33 + 0x10) + 0xc];
161: goto LAB_0015a1e5;
162: }
163: uVar11 = *(undefined8 *)(lVar21 + lStack120 * 8);
164: if (*(int *)(lVar30 + 0x20) != 0) {
165: uVar15 = 0;
166: do {
167: plVar19 = (long *)(**(code **)(*(long *)(lVar9 + 8) + 0x40))
168: (lVar9,uVar11,uVar15);
169: iVar28 = *(int *)(lVar30 + 0xc);
170: if ((0 < iVar28) && (iVar25 = *(int *)(lVar30 + 0x1c), iVar25 != 0)) {
171: plVar2 = plVar19 + (ulong)(iVar28 - 1) + 1;
172: do {
173: lVar33 = *plVar19;
174: lVar27 = (ulong)(iVar25 - 1) * 0x80 + 0x80 + lVar33;
175: do {
176: lVar26 = 0;
177: do {
178: sVar20 = *(short *)(lVar10 + lVar26);
179: if (*(short *)(lVar34 + lVar26) != sVar20) {
180: sVar14 = *(short *)(lVar34 + lVar26) * *(short *)(lVar33 + lVar26);
181: if (sVar14 < 0) {
182: sVar14 = (sVar20 >> 1) - sVar14;
183: sVar22 = 0;
184: if (sVar20 <= sVar14) {
185: sVar22 = -(sVar14 / sVar20);
186: }
187: }
188: else {
189: sVar14 = sVar14 + (sVar20 >> 1);
190: sVar22 = 0;
191: if (sVar20 <= sVar14) {
192: sVar22 = sVar14 / sVar20;
193: }
194: }
195: *(short *)(lVar33 + lVar26) = sVar22;
196: }
197: lVar26 = lVar26 + 2;
198: } while (lVar26 != 0x80);
199: lVar33 = lVar33 + 0x80;
200: } while (lVar27 != lVar33);
201: plVar19 = plVar19 + 1;
202: } while (plVar2 != plVar19);
203: }
204: uVar15 = uVar15 + iVar28;
205: } while (uVar15 < *(uint *)(lVar30 + 0x20));
206: }
207: break;
208: }
209: lVar27 = lVar27 + 2;
210: } while (lVar27 != 0x80);
211: goto LAB_0015a183;
212: }
213: }
214: goto LAB_00159c66;
215: }
216: }
217: *(uint *)(param_2 + 6) = param_4[0x16];
218: *(uint *)((long)param_2 + 0x34) = param_4[0x17];
219: }
220: LAB_00159c66:
221: lVar21 = *(long *)(param_1 + 400);
222: if ((((((lVar21 != 0) && (*(char *)(lVar21 + 8) == -0x1f)) &&
223: (uVar4 = *(uint *)(lVar21 + 0x10), 5 < uVar4)) &&
224: ((pcVar8 = *(char **)(lVar21 + 0x18), *pcVar8 == 'E' && (pcVar8[1] == 'x')))) &&
225: (pcVar8[2] == 'i')) &&
226: (((pcVar8[3] == 'f' && (pcVar8[4] == '\0')) &&
227: ((pcVar8[5] == '\0' &&
228: (*(undefined4 *)(param_2 + 0x24) = 0, param_2[6] != *(code **)(param_1 + 0x30))))))) {
229: uVar5 = *(undefined4 *)((long)param_2 + 0x34);
230: pcVar1 = pcVar8 + 6;
231: uVar6 = *(undefined4 *)(param_2 + 6);
232: if (0xb < uVar4 - 6) {
233: if (pcVar8[6] == 'I') {
234: if ((((pcVar8[7] != 'I') || (pcVar8[9] != '\0')) || (pcVar8[8] != '*')) ||
235: (((pcVar8[0xd] != '\0' || (pcVar8[0xc] != '\0')) ||
236: (uVar15 = (uint)(byte)pcVar8[0xb] * 0x100 + (uint)(byte)pcVar8[10], uVar4 - 8 < uVar15))
237: )) goto LAB_00159c81;
238: bVar13 = false;
239: iVar28 = (uint)(byte)pcVar8[(ulong)uVar15 + 6] +
240: (uint)(byte)pcVar8[(ulong)(uVar15 + 1) + 6] * 0x100;
241: }
242: else {
243: if ((((pcVar8[6] != 'M') || (pcVar8[7] != 'M')) ||
244: ((pcVar8[8] != '\0' ||
245: (((pcVar8[9] != '*' || (pcVar8[10] != '\0')) || (pcVar8[0xb] != '\0')))))) ||
246: (uVar15 = (uint)(byte)pcVar8[0xc] * 0x100 + (uint)(byte)pcVar8[0xd], uVar4 - 8 < uVar15))
247: goto LAB_00159c81;
248: bVar13 = true;
249: iVar28 = (uint)(byte)pcVar8[(ulong)(uVar15 + 1) + 6] +
250: (uint)(byte)pcVar8[(ulong)uVar15 + 6] * 0x100;
251: }
252: if (iVar28 != 0) {
253: uVar15 = uVar15 + 2;
254: while (uVar15 <= uVar4 - 0x12) {
255: if (bVar13) {
256: iVar25 = (uint)(byte)pcVar1[uVar15 + 1] + (uint)(byte)pcVar1[uVar15] * 0x100;
257: }
258: else {
259: iVar25 = (uint)(byte)pcVar1[uVar15 + 1] * 0x100 + (uint)(byte)pcVar1[uVar15];
260: }
261: if (iVar25 == 0x8769) {
262: if (bVar13) {
263: if (((pcVar8[(ulong)(uVar15 + 8) + 6] != '\0') ||
264: (pcVar8[(ulong)(uVar15 + 9) + 6] != '\0')) ||
265: (uVar15 = (uint)(byte)pcVar8[(ulong)(uVar15 + 0xb) + 6] +
266: (uint)(byte)pcVar8[(ulong)(uVar15 + 10) + 6] * 0x100, uVar4 - 8 < uVar15)
267: ) break;
268: uVar32 = (uint)(byte)pcVar8[(ulong)(uVar15 + 1) + 6] +
269: (uint)(byte)pcVar8[(ulong)uVar15 + 6] * 0x100;
270: }
271: else {
272: if (((pcVar8[(ulong)(uVar15 + 0xb) + 6] != '\0') ||
273: (pcVar8[(ulong)(uVar15 + 10) + 6] != '\0')) ||
274: (uVar15 = (uint)(byte)pcVar8[(ulong)(uVar15 + 8) + 6] +
275: (uint)(byte)pcVar8[(ulong)(uVar15 + 9) + 6] * 0x100, uVar4 - 8 < uVar15))
276: break;
277: uVar32 = (uint)(byte)pcVar8[(ulong)uVar15 + 6] +
278: (uint)(byte)pcVar8[(ulong)(uVar15 + 1) + 6] * 0x100;
279: }
280: if (1 < uVar32) {
281: uVar15 = uVar15 + 2;
282: goto LAB_0015a438;
283: }
284: break;
285: }
286: iVar28 = iVar28 + -1;
287: if (iVar28 == 0) break;
288: uVar15 = uVar15 + 0xc;
289: }
290: }
291: }
292: }
293: LAB_00159c81:
294: lVar21 = *(long *)(param_4 + 0x14);
295: if (*(long *)(param_4 + 0x14) == 0) {
296: lVar21 = param_3;
297: }
298: return lVar21;
299: while (lVar27 = lVar27 + 2, lVar27 != 0x80) {
300: LAB_0015a1e5:
301: sVar20 = *(short *)(lVar34 + lVar27);
302: if (*(short *)(lVar10 + lVar27) != sVar20) {
303: uVar24 = (long)(int)*(short *)(lVar10 + lVar27) % (long)(int)sVar20 & 0xffffffff;
304: sVar14 = (short)uVar24;
305: while (sVar14 != 0) {
306: iVar28 = (int)sVar20;
307: sVar20 = (short)uVar24;
308: uVar24 = (ulong)(uint)(iVar28 % (int)sVar20);
309: sVar14 = (short)(iVar28 % (int)sVar20);
310: }
311: *(short *)(pcVar12 + lVar27) = sVar20;
312: lVar27 = lVar27 + 2;
313: if (lVar27 == 0x80) break;
314: goto LAB_0015a1e5;
315: }
316: }
317: uVar11 = *(undefined8 *)(param_3 + lStack120 * 8);
318: if (*(int *)(lVar33 + 0x20) != 0) {
319: uVar15 = 0;
320: do {
321: plVar19 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))(param_1,uVar11,uVar15);
322: iVar28 = *(int *)(lVar33 + 0xc);
323: if ((0 < iVar28) && (iVar25 = *(int *)(lVar33 + 0x1c), iVar25 != 0)) {
324: plVar2 = plVar19 + (ulong)(iVar28 - 1) + 1;
325: do {
326: lVar27 = *plVar19;
327: lVar34 = (ulong)(iVar25 - 1) * 0x80 + 0x80 + lVar27;
328: do {
329: lVar26 = 0;
330: do {
331: if (*(ushort *)(lVar10 + lVar26) != *(ushort *)(pcVar12 + lVar26)) {
332: *(ushort *)(lVar27 + lVar26) =
333: (*(ushort *)(lVar10 + lVar26) / *(ushort *)(pcVar12 + lVar26)) *
334: *(short *)(lVar27 + lVar26);
335: }
336: lVar26 = lVar26 + 2;
337: } while (lVar26 != 0x80);
338: lVar27 = lVar27 + 0x80;
339: } while (lVar34 != lVar27);
340: plVar19 = plVar19 + 1;
341: } while (plVar2 != plVar19);
342: }
343: uVar15 = uVar15 + iVar28;
344: } while (uVar15 < *(uint *)(lVar33 + 0x20));
345: lVar34 = *(long *)(lVar30 + 0x50);
346: }
347: uVar11 = *(undefined8 *)(lVar21 + lStack120 * 8);
348: if (*(int *)(lVar30 + 0x20) != 0) {
349: uVar15 = 0;
350: do {
351: plVar19 = (long *)(**(code **)(*(long *)(lVar9 + 8) + 0x40))(lVar9,uVar11,uVar15);
352: iVar28 = *(int *)(lVar30 + 0xc);
353: if ((0 < iVar28) && (iVar25 = *(int *)(lVar30 + 0x1c), iVar25 != 0)) {
354: plVar2 = plVar19 + (ulong)(iVar28 - 1) + 1;
355: do {
356: lVar27 = *plVar19;
357: lVar10 = (ulong)(iVar25 - 1) * 0x80 + 0x80 + lVar27;
358: do {
359: lVar33 = 0;
360: do {
361: if (*(ushort *)(lVar34 + lVar33) != *(ushort *)(pcVar12 + lVar33)) {
362: *(ushort *)(lVar27 + lVar33) =
363: (*(ushort *)(lVar34 + lVar33) / *(ushort *)(pcVar12 + lVar33)) *
364: *(short *)(lVar27 + lVar33);
365: }
366: lVar33 = lVar33 + 2;
367: } while (lVar33 != 0x80);
368: lVar27 = lVar27 + 0x80;
369: } while (lVar10 != lVar27);
370: plVar19 = plVar19 + 1;
371: } while (plVar2 != plVar19);
372: }
373: uVar15 = uVar15 + iVar28;
374: } while (uVar15 < *(uint *)(lVar30 + 0x20));
375: }
376: LAB_0015a183:
377: iVar28 = (int)lStack120 + 1;
378: if ((*(int *)((long)param_2 + 0x4c) == iVar28 || *(int *)((long)param_2 + 0x4c) < iVar28) ||
379: (lStack120 = lStack120 + 1, *(int *)(lVar9 + 0x38) == iVar28 || *(int *)(lVar9 + 0x38) < iVar28
380: )) goto LAB_00159c66;
381: goto LAB_0015a021;
382: while( true ) {
383: if (bVar13) {
384: iVar28 = (uint)(byte)pcVar1[uVar15 + 1] + (uint)(byte)pcVar1[uVar15] * 0x100;
385: }
386: else {
387: iVar28 = (uint)(byte)pcVar1[uVar15 + 1] * 0x100 + (uint)(byte)pcVar1[uVar15];
388: }
389: if (iVar28 - 0xa002U < 2) {
390: uVar3 = (short)uVar6;
391: if (iVar28 != 0xa002) {
392: uVar3 = (undefined2)uVar5;
393: }
394: cVar31 = (char)((ushort)uVar3 >> 8);
395: if (bVar13) {
396: pcVar1[uVar15 + 2] = '\0';
397: pcVar1[uVar15 + 3] = '\x04';
398: pcVar1[uVar15 + 4] = '\0';
399: pcVar1[uVar15 + 5] = '\0';
400: pcVar1[uVar15 + 6] = '\0';
401: pcVar1[uVar15 + 7] = '\x01';
402: pcVar1[uVar15 + 8] = '\0';
403: pcVar1[uVar15 + 9] = '\0';
404: pcVar1[uVar15 + 10] = cVar31;
405: pcVar1[uVar15 + 0xb] = (char)uVar3;
406: }
407: else {
408: pcVar1[uVar15 + 2] = '\x04';
409: pcVar1[uVar15 + 3] = '\0';
410: pcVar1[uVar15 + 4] = '\x01';
411: pcVar1[uVar15 + 5] = '\0';
412: pcVar1[uVar15 + 6] = '\0';
413: pcVar1[uVar15 + 7] = '\0';
414: pcVar1[uVar15 + 8] = (char)uVar3;
415: pcVar1[uVar15 + 9] = cVar31;
416: pcVar1[uVar15 + 10] = '\0';
417: pcVar1[uVar15 + 0xb] = '\0';
418: }
419: }
420: uVar15 = uVar15 + 0xc;
421: uVar32 = uVar32 - 1;
422: if (uVar32 == 0) break;
423: LAB_0015a438:
424: if (uVar4 - 0x12 < uVar15) break;
425: }
426: goto LAB_00159c81;
427: }
428: 
