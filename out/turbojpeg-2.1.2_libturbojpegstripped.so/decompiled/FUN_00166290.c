1: 
2: undefined  [16] FUN_00166290(code **param_1,uint *param_2)
3: 
4: {
5: uint uVar1;
6: uint uVar2;
7: code **ppcVar3;
8: bool bVar4;
9: int iVar5;
10: int iVar6;
11: uint uVar7;
12: long lVar8;
13: undefined8 uVar9;
14: int iVar10;
15: uint uVar11;
16: ulong extraout_RDX;
17: undefined *puVar12;
18: ulong extraout_RDX_00;
19: ulong extraout_RDX_01;
20: ulong uVar13;
21: code *pcVar14;
22: uint uVar15;
23: uint uVar16;
24: uint uVar17;
25: int iVar18;
26: int iVar19;
27: uint uVar20;
28: uint uVar21;
29: ulong uVar22;
30: long lVar23;
31: 
32: if ((param_2[3] == 0) || (param_1[7] != (code *)0x300000003)) {
33: uVar21 = param_2[1];
34: uVar7 = *(uint *)(param_1 + 7);
35: uVar15 = *(uint *)(param_1 + 6);
36: uVar11 = *(uint *)((long)param_1 + 0x34);
37: uVar16 = *param_2;
38: uVar20 = *(uint *)(param_1 + 0x34);
39: puVar12 = (undefined *)(ulong)uVar20;
40: param_2[0x12] = uVar7;
41: *(uint *)(param_1 + 0x11) = uVar15;
42: *(uint *)((long)param_1 + 0x8c) = uVar11;
43: if (uVar21 != 0) {
44: if (uVar7 == 1) goto LAB_00166508;
45: iVar5 = FUN_00166220(uVar15,uVar11,uVar20 * *(int *)(param_1 + 0x33));
46: uVar13 = extraout_RDX;
47: goto joined_r0x00166511;
48: }
49: }
50: else {
51: uVar21 = param_2[1];
52: uVar15 = *(uint *)(param_1 + 6);
53: uVar11 = *(uint *)((long)param_1 + 0x34);
54: param_2[0x12] = 1;
55: uVar16 = *param_2;
56: puVar12 = (undefined *)(ulong)*(uint *)(param_1 + 0x34);
57: *(uint *)(param_1 + 0x11) = uVar15;
58: *(uint *)((long)param_1 + 0x8c) = uVar11;
59: if (uVar21 == 0) {
60: uVar7 = 1;
61: }
62: else {
63: LAB_00166508:
64: iVar5 = FUN_00166220();
65: uVar13 = extraout_RDX_00;
66: joined_r0x00166511:
67: if (iVar5 == 0) {
68: return ZEXT816(uVar13) << 0x40;
69: }
70: uVar16 = *param_2;
71: uVar11 = *(uint *)((long)param_1 + 0x8c);
72: uVar15 = *(uint *)(param_1 + 0x11);
73: uVar7 = param_2[0x12];
74: puVar12 = (undefined *)(ulong)*(uint *)(param_1 + 0x34);
75: }
76: }
77: uVar21 = (uint)puVar12;
78: if ((uVar16 < 8) && ((1 << ((byte)uVar16 & 0x3f) & 0xb8U) != 0)) {
79: param_2[0x16] = uVar11;
80: param_2[0x17] = uVar15;
81: uVar15 = uVar11;
82: if (uVar7 == 1) {
83: param_2[0x1c] = uVar21;
84: param_2[0x1d] = uVar21;
85: goto LAB_001663c5;
86: }
87: iVar5 = *(int *)(param_1 + 0x33);
88: puVar12 = (undefined *)(ulong)(uVar21 * iVar5);
89: param_2[0x1c] = *(int *)((long)param_1 + 0x19c) * uVar21;
90: param_2[0x1d] = uVar21 * iVar5;
91: if (param_2[4] != 0) goto LAB_001663cc;
92: LAB_00166370:
93: *(undefined8 *)(param_2 + 0x18) = 0;
94: uVar20 = 0;
95: uVar7 = 0;
96: }
97: else {
98: param_2[0x16] = uVar15;
99: param_2[0x17] = uVar11;
100: if (uVar7 == 1) {
101: param_2[0x1c] = uVar21;
102: param_2[0x1d] = uVar21;
103: }
104: else {
105: uVar7 = uVar21 * *(int *)((long)param_1 + 0x19c);
106: puVar12 = (undefined *)(ulong)uVar7;
107: param_2[0x1c] = *(int *)(param_1 + 0x33) * uVar21;
108: param_2[0x1d] = uVar7;
109: }
110: LAB_001663c5:
111: if (param_2[4] == 0) goto LAB_00166370;
112: LAB_001663cc:
113: if (param_2[0xb] == 0) {
114: param_2[10] = 0;
115: }
116: if (param_2[0xd] == 0) {
117: param_2[0xc] = 0;
118: }
119: if (param_2[7] == 0) {
120: uVar21 = param_2[10];
121: if (uVar15 <= uVar21) {
122: ppcVar3 = (code **)*param_1;
123: *(undefined4 *)(ppcVar3 + 5) = 0x7c;
124: (**ppcVar3)();
125: uVar15 = param_2[0x16];
126: uVar21 = param_2[10];
127: }
128: uVar7 = param_2[0x17];
129: param_2[6] = uVar15 - uVar21;
130: if (param_2[9] != 0) goto LAB_001666d2;
131: LAB_0016642b:
132: uVar11 = param_2[0xc];
133: if (uVar7 <= uVar11) {
134: ppcVar3 = (code **)*param_1;
135: *(undefined4 *)(ppcVar3 + 5) = 0x7c;
136: (**ppcVar3)();
137: uVar7 = param_2[0x17];
138: uVar11 = param_2[0xc];
139: }
140: uVar16 = *param_2;
141: param_2[8] = uVar7 - uVar11;
142: LAB_00166454:
143: uVar20 = param_2[0xb];
144: uVar21 = param_2[6];
145: uVar7 = param_2[10];
146: }
147: else {
148: uVar21 = param_2[6];
149: if (uVar15 < uVar21) {
150: if (((uVar16 != 0) || (uVar21 <= param_2[10])) || (uVar21 - uVar15 < param_2[10])) {
151: LAB_0016640b:
152: ppcVar3 = (code **)*param_1;
153: *(undefined4 *)(ppcVar3 + 5) = 0x7c;
154: (**ppcVar3)();
155: }
156: }
157: else {
158: if (((uVar15 <= param_2[10]) || (uVar21 == 0)) || (uVar15 - uVar21 < param_2[10]))
159: goto LAB_0016640b;
160: }
161: uVar7 = param_2[0x17];
162: if (param_2[9] == 0) goto LAB_0016642b;
163: LAB_001666d2:
164: uVar21 = param_2[8];
165: if (uVar7 < uVar21) {
166: uVar16 = *param_2;
167: if (((uVar16 != 0) || (uVar11 = param_2[0xc], uVar21 <= uVar11)) ||
168: (uVar21 - uVar7 < uVar11)) goto LAB_001666e9;
169: goto LAB_00166454;
170: }
171: uVar11 = param_2[0xc];
172: if (((uVar21 == 0) || (uVar7 <= uVar11)) || (uVar7 - uVar21 < uVar11)) {
173: LAB_001666e9:
174: ppcVar3 = (code **)*param_1;
175: *(undefined4 *)(ppcVar3 + 5) = 0x7c;
176: (**ppcVar3)();
177: uVar11 = param_2[0xc];
178: }
179: uVar20 = param_2[0xb];
180: uVar16 = *param_2;
181: uVar21 = param_2[6];
182: uVar7 = param_2[10];
183: }
184: if (uVar20 == 2) {
185: uVar20 = param_2[0x16];
186: if (uVar20 < uVar21) {
187: uVar7 = (uVar21 - uVar20) - uVar7;
188: }
189: else {
190: uVar7 = (uVar20 - uVar21) - uVar7;
191: }
192: }
193: if (param_2[0xd] == 2) {
194: uVar20 = param_2[8];
195: uVar15 = param_2[0x17];
196: if (uVar15 < uVar20) {
197: uVar11 = (uVar20 - uVar15) - uVar11;
198: }
199: else {
200: uVar11 = (uVar15 - uVar20) - uVar11;
201: }
202: }
203: uVar20 = param_2[0x1c];
204: uVar13 = (ulong)uVar20;
205: if (uVar16 == 8) {
206: uVar21 = FUN_001489d0(uVar7 % uVar20 + uVar21,(long)(int)uVar20);
207: param_2[0x1a] = uVar21;
208: uVar21 = FUN_001489d0();
209: uVar13 = (ulong)param_2[0x1c];
210: param_2[0x1b] = uVar21;
211: uVar21 = param_2[0x1d];
212: uVar16 = *param_2;
213: }
214: else {
215: if (uVar16 == 9) {
216: uVar15 = (uVar20 - 1) - (uVar7 + (uVar20 - 1)) % uVar20;
217: if (uVar15 < uVar21) {
218: if (uVar7 + uVar21 == param_2[0x16]) {
219: uVar21 = (((uVar21 - 1) + uVar20) - uVar15) / uVar20;
220: param_2[0x1a] = uVar21;
221: }
222: else {
223: uVar21 = (uVar21 - uVar15) / uVar20;
224: param_2[0x1a] = uVar21;
225: }
226: }
227: else {
228: param_2[0x1a] = 0;
229: uVar21 = 0;
230: }
231: uVar16 = param_2[0x1d];
232: uVar2 = param_2[8];
233: uVar17 = (uVar16 - 1) - (uVar11 + (uVar16 - 1)) % uVar16;
234: uVar1 = uVar11 + uVar17;
235: if (uVar17 < uVar2) {
236: if (uVar11 + uVar2 == param_2[0x17]) {
237: uVar11 = (((uVar16 - 1) + uVar2) - uVar17) / uVar16;
238: param_2[0x1b] = uVar11;
239: }
240: else {
241: uVar11 = (uVar2 - uVar17) / uVar16;
242: param_2[0x1b] = uVar11;
243: }
244: if (((uVar21 != 0) && (uVar11 != 0)) && (0 < (int)param_2[0x12])) {
245: lVar8 = *(long *)(param_2 + 0xe);
246: lVar23 = 0;
247: uVar21 = 0;
248: if (0 < *(int *)(lVar8 + 0x38)) {
249: do {
250: iVar5 = *(int *)(param_1 + 0x33);
251: iVar6 = *(int *)(*(long *)(lVar8 + 0x130) + 8 + lVar23);
252: pcVar14 = param_1[0x26] + lVar23;
253: iVar19 = *(int *)(pcVar14 + 8);
254: if (iVar6 * iVar5 != iVar19 * *(int *)(lVar8 + 0x198)) {
255: ppcVar3 = (code **)*param_1;
256: *(int *)((long)ppcVar3 + 0x34) = *(int *)(lVar8 + 0x198);
257: *(undefined4 *)(ppcVar3 + 5) = 0x80;
258: *(uint *)((long)ppcVar3 + 0x2c) = uVar21;
259: *(int *)(ppcVar3 + 6) = iVar6;
260: *(int *)(ppcVar3 + 7) = iVar19;
261: *(int *)((long)ppcVar3 + 0x3c) = iVar5;
262: *(undefined4 *)(ppcVar3 + 8) = 0x68;
263: (**ppcVar3)();
264: lVar8 = *(long *)(param_2 + 0xe);
265: pcVar14 = param_1[0x26] + lVar23;
266: }
267: iVar5 = *(int *)(pcVar14 + 0xc);
268: iVar6 = *(int *)(lVar8 + 0x19c);
269: iVar19 = *(int *)(*(long *)(lVar8 + 0x130) + 0xc + lVar23);
270: iVar10 = *(int *)((long)param_1 + 0x19c);
271: if (iVar19 * iVar10 != iVar5 * iVar6) {
272: ppcVar3 = (code **)*param_1;
273: *(int *)(ppcVar3 + 6) = iVar19;
274: *(undefined4 *)(ppcVar3 + 5) = 0x80;
275: *(uint *)((long)ppcVar3 + 0x2c) = uVar21;
276: *(int *)((long)ppcVar3 + 0x34) = iVar6;
277: *(int *)(ppcVar3 + 7) = iVar5;
278: *(int *)((long)ppcVar3 + 0x3c) = iVar10;
279: *(undefined4 *)(ppcVar3 + 8) = 0x76;
280: (**ppcVar3)();
281: }
282: uVar21 = uVar21 + 1;
283: if (param_2[0x12] == uVar21 || (int)param_2[0x12] < (int)uVar21) break;
284: lVar8 = *(long *)(param_2 + 0xe);
285: lVar23 = lVar23 + 0x60;
286: } while (*(uint *)(lVar8 + 0x38) != uVar21 &&
287: (int)uVar21 <= (int)*(uint *)(lVar8 + 0x38));
288: uVar13 = (ulong)param_2[0x1c];
289: uVar21 = param_2[0x1d];
290: uVar16 = *param_2;
291: uVar11 = uVar1;
292: uVar7 = uVar7 + uVar15;
293: goto LAB_0016695a;
294: }
295: }
296: }
297: else {
298: param_2[0x1b] = 0;
299: }
300: param_2[0x18] = (uVar7 + uVar15) / uVar20;
301: puVar12 = (undefined *)((ulong)uVar1 % (ulong)uVar16);
302: param_2[0x19] = uVar1 / uVar16;
303: goto LAB_001664e7;
304: }
305: if ((param_2[7] != 3) && (uVar21 <= param_2[0x16])) {
306: uVar21 = uVar21 + uVar7 % uVar20;
307: }
308: param_2[0x16] = uVar21;
309: uVar20 = param_2[8];
310: uVar21 = param_2[0x1d];
311: if ((param_2[9] == 3) || (param_2[0x17] < uVar20)) {
312: param_2[0x17] = uVar20;
313: }
314: else {
315: param_2[0x17] = uVar11 % uVar21 + uVar20;
316: }
317: }
318: LAB_0016695a:
319: uVar7 = (uint)(uVar7 / uVar13);
320: param_2[0x18] = uVar7;
321: uVar20 = uVar11 / uVar21;
322: puVar12 = (undefined *)((ulong)uVar11 % (ulong)uVar21);
323: param_2[0x19] = uVar20;
324: }
325: if (7 < uVar16) {
326: LAB_001664e7:
327: *(undefined8 *)(param_2 + 0x14) = 0;
328: return CONCAT88(puVar12,1);
329: }
330: puVar12 = &DAT_001904c8;
331: switch(uVar16) {
332: case 0:
333: if ((*(long *)(param_2 + 0x18) == 0) &&
334: ((param_2[0x16] < *(uint *)(param_1 + 0x11) || param_2[0x16] == *(uint *)(param_1 + 0x11) &&
335: (param_2[0x17] < *(uint *)((long)param_1 + 0x8c) ||
336: param_2[0x17] == *(uint *)((long)param_1 + 0x8c))))) goto LAB_001664e7;
337: break;
338: case 1:
339: if (param_2[2] != 0) {
340: uVar21 = param_2[0x1c];
341: uVar11 = param_2[0x16] / uVar21;
342: puVar12 = (undefined *)((ulong)param_2[0x16] % (ulong)uVar21);
343: if ((uVar11 != 0) &&
344: (puVar12 = (undefined *)((ulong)*(uint *)(param_1 + 0x11) % (ulong)uVar21),
345: uVar7 + uVar11 == *(uint *)(param_1 + 0x11) / uVar21)) {
346: param_2[0x16] = uVar21 * uVar11;
347: }
348: }
349: if ((uVar20 == 0) && (param_2[5] == 0)) goto LAB_001664e7;
350: break;
351: case 2:
352: if (param_2[2] != 0) {
353: code_r0x00166848:
354: uVar21 = param_2[0x1d];
355: uVar7 = param_2[0x17] / uVar21;
356: if ((uVar7 != 0) && (uVar20 + uVar7 == *(uint *)((long)param_1 + 0x8c) / uVar21)) {
357: param_2[0x17] = uVar21 * uVar7;
358: }
359: }
360: break;
361: case 3:
362: goto code_r0x00166540;
363: case 4:
364: if (param_2[2] != 0) {
365: uVar21 = param_2[0x1c];
366: uVar11 = param_2[0x16] / uVar21;
367: if ((uVar11 != 0) && (uVar7 + uVar11 == *(uint *)((long)param_1 + 0x8c) / uVar21)) {
368: param_2[0x16] = uVar21 * uVar11;
369: }
370: code_r0x001667cb:
371: uVar21 = param_2[0x1d];
372: uVar7 = param_2[0x17] / uVar21;
373: if ((uVar7 != 0) && (uVar20 + uVar7 == *(uint *)(param_1 + 0x11) / uVar21)) {
374: bVar4 = true;
375: param_2[0x17] = uVar21 * uVar7;
376: goto code_r0x00166546;
377: }
378: }
379: goto code_r0x00166540;
380: case 5:
381: if (param_2[2] != 0) {
382: uVar21 = param_2[0x1c];
383: uVar11 = param_2[0x16] / uVar21;
384: if ((uVar11 != 0) && (uVar7 + uVar11 == *(uint *)((long)param_1 + 0x8c) / uVar21)) {
385: bVar4 = true;
386: param_2[0x16] = uVar21 * uVar11;
387: goto code_r0x00166546;
388: }
389: }
390: goto code_r0x00166540;
391: case 6:
392: if (param_2[2] != 0) {
393: uVar21 = param_2[0x1c];
394: uVar11 = param_2[0x16] / uVar21;
395: if ((uVar11 != 0) && (uVar7 + uVar11 == *(uint *)(param_1 + 0x11) / uVar21)) {
396: param_2[0x16] = uVar21 * uVar11;
397: }
398: goto code_r0x00166848;
399: }
400: break;
401: case 7:
402: if (param_2[2] != 0) goto code_r0x001667cb;
403: code_r0x00166540:
404: bVar4 = true;
405: goto code_r0x00166546;
406: }
407: bVar4 = false;
408: code_r0x00166546:
409: lVar8 = (**(code **)param_1[1])(param_1,1,(long)(int)param_2[0x12] << 3);
410: iVar5 = FUN_001489d0(param_2[0x16],(long)(int)param_2[0x1c]);
411: iVar6 = FUN_001489d0(param_2[0x17],(long)(int)param_2[0x1d]);
412: uVar21 = param_2[0x12];
413: uVar13 = extraout_RDX_01;
414: if (0 < (int)uVar21) {
415: uVar22 = 1;
416: if (bVar4) {
417: do {
418: if (uVar21 == 1) {
419: pcVar14 = param_1[1];
420: iVar19 = 1;
421: iVar10 = iVar5;
422: iVar18 = iVar6;
423: }
424: else {
425: iVar19 = *(int *)(param_1[0x26] + uVar22 * 0x60 + -0x60 + 8);
426: pcVar14 = param_1[1];
427: iVar10 = *(int *)(param_1[0x26] + uVar22 * 0x60 + -0x60 + 0xc) * iVar5;
428: iVar18 = iVar19 * iVar6;
429: }
430: uVar9 = (**(code **)(pcVar14 + 0x28))(param_1,1,0,iVar10,iVar18,iVar19);
431: *(undefined8 *)(lVar8 + -8 + uVar22 * 8) = uVar9;
432: uVar21 = param_2[0x12];
433: uVar13 = uVar22 & 0xffffffff;
434: uVar22 = uVar22 + 1;
435: } while ((int)uVar13 < (int)uVar21);
436: }
437: else {
438: do {
439: if (uVar21 == 1) {
440: pcVar14 = param_1[1];
441: iVar19 = 1;
442: iVar10 = iVar5;
443: iVar18 = iVar6;
444: }
445: else {
446: iVar19 = *(int *)(param_1[0x26] + uVar22 * 0x60 + -0x60 + 0xc);
447: pcVar14 = param_1[1];
448: iVar10 = *(int *)(param_1[0x26] + uVar22 * 0x60 + -0x60 + 8) * iVar5;
449: iVar18 = iVar19 * iVar6;
450: }
451: uVar9 = (**(code **)(pcVar14 + 0x28))(param_1,1,0,iVar10,iVar18,iVar19);
452: *(undefined8 *)(lVar8 + -8 + uVar22 * 8) = uVar9;
453: uVar21 = param_2[0x12];
454: uVar13 = uVar22 & 0xffffffff;
455: uVar22 = uVar22 + 1;
456: } while ((int)uVar13 < (int)uVar21);
457: }
458: }
459: *(long *)(param_2 + 0x14) = lVar8;
460: return CONCAT88(uVar13,1);
461: }
462: 
