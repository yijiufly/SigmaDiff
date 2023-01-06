1: 
2: /* WARNING: Removing unreachable block (ram,0x00115369) */
3: /* WARNING: Removing unreachable block (ram,0x00115347) */
4: /* WARNING: Type propagation algorithm not settling */
5: /* WARNING: Could not reconcile some variable overlaps */
6: 
7: void FUN_001152d0(code **param_1)
8: 
9: {
10: int iVar1;
11: uint uVar2;
12: uint uVar3;
13: uint uVar4;
14: code *pcVar5;
15: code **ppcVar6;
16: uint uVar7;
17: long lVar8;
18: undefined8 *puVar9;
19: uint *puVar10;
20: int iVar11;
21: int iVar12;
22: int iVar13;
23: undefined8 *puVar14;
24: int *piVar15;
25: uint uVar16;
26: byte bVar17;
27: int *piStack2704;
28: long lStack2696;
29: int aiStack2664 [4];
30: int iStack2648;
31: int iStack2644;
32: int iStack2640;
33: int iStack2636;
34: int iStack2632;
35: int iStack2628;
36: undefined8 auStack2616 [32];
37: int iStack2360;
38: int iStack2104;
39: int iStack1848;
40: int iStack1592;
41: int iStack1336;
42: int iStack1080;
43: int iStack824;
44: int iStack568;
45: int iStack312;
46: 
47: bVar17 = 0;
48: if (*(int *)(param_1 + 0x1e) < 1) {
49: pcVar5 = *param_1;
50: *(undefined4 *)(pcVar5 + 0x28) = 0x13;
51: *(undefined4 *)(pcVar5 + 0x2c) = 0;
52: (**(code **)*param_1)();
53: }
54: piStack2704 = (int *)param_1[0x1f];
55: if ((piStack2704[5] == 0) && (piStack2704[6] == 0x3f)) {
56: iVar11 = *(int *)((long)param_1 + 0x4c);
57: *(undefined4 *)((long)param_1 + 0x134) = 0;
58: if (iVar11 < 1) {
59: iVar13 = 0;
60: }
61: else {
62: memset(aiStack2664,0,(long)iVar11 << 2);
63: iVar13 = 0;
64: }
65: }
66: else {
67: iVar11 = *(int *)((long)param_1 + 0x4c);
68: *(undefined4 *)((long)param_1 + 0x134) = 1;
69: if (0 < iVar11) {
70: iVar13 = 0;
71: puVar9 = auStack2616;
72: do {
73: lVar8 = 0x20;
74: puVar14 = puVar9;
75: while (lVar8 != 0) {
76: lVar8 = lVar8 + -1;
77: *puVar14 = 0xffffffffffffffff;
78: puVar14 = puVar14 + (ulong)bVar17 * -2 + 1;
79: }
80: iVar13 = iVar13 + 1;
81: puVar9 = puVar9 + 0x20;
82: } while (iVar13 != iVar11);
83: }
84: iVar13 = 1;
85: }
86: iVar12 = 1;
87: if (0 < *(int *)(param_1 + 0x1e)) {
88: do {
89: iVar11 = *piStack2704;
90: if (iVar11 - 1U < 4) {
91: LAB_001153b6:
92: iVar13 = 0;
93: piVar15 = piStack2704;
94: do {
95: while( true ) {
96: iVar1 = piVar15[1];
97: if ((iVar1 < 0) || (*(int *)((long)param_1 + 0x4c) <= iVar1)) {
98: pcVar5 = *param_1;
99: *(undefined4 *)(pcVar5 + 0x28) = 0x13;
100: *(int *)(pcVar5 + 0x2c) = iVar12;
101: (**(code **)*param_1)();
102: }
103: if ((iVar13 == 0) || (*piVar15 < iVar1)) break;
104: pcVar5 = *param_1;
105: iVar13 = iVar13 + 1;
106: piVar15 = piVar15 + 1;
107: *(undefined4 *)(pcVar5 + 0x28) = 0x13;
108: *(int *)(pcVar5 + 0x2c) = iVar12;
109: (**(code **)*param_1)();
110: if (iVar13 == iVar11) goto LAB_0011541c;
111: }
112: iVar13 = iVar13 + 1;
113: piVar15 = piVar15 + 1;
114: } while (iVar13 != iVar11);
115: }
116: else {
117: pcVar5 = *param_1;
118: *(int *)(pcVar5 + 0x2c) = iVar11;
119: *(undefined4 *)(pcVar5 + 0x28) = 0x1a;
120: *(undefined4 *)(*param_1 + 0x30) = 4;
121: (**(code **)*param_1)();
122: if (0 < iVar11) goto LAB_001153b6;
123: }
124: LAB_0011541c:
125: uVar2 = piStack2704[5];
126: iVar13 = piStack2704[6];
127: uVar3 = piStack2704[8];
128: uVar4 = piStack2704[7];
129: if (*(int *)((long)param_1 + 0x134) == 0) {
130: if (((uVar2 != 0) || (iVar13 != 0x3f)) || ((uVar4 | uVar3) != 0)) {
131: pcVar5 = *param_1;
132: *(undefined4 *)(pcVar5 + 0x28) = 0x11;
133: *(int *)(pcVar5 + 0x2c) = iVar12;
134: (**(code **)*param_1)();
135: }
136: if (0 < iVar11) {
137: iVar13 = piStack2704[1];
138: if (aiStack2664[iVar13] != 0) {
139: pcVar5 = *param_1;
140: *(int *)(pcVar5 + 0x2c) = iVar12;
141: *(undefined4 *)(pcVar5 + 0x28) = 0x13;
142: (**(code **)*param_1)();
143: }
144: aiStack2664[iVar13] = 1;
145: if (iVar11 != 1) {
146: iVar13 = piStack2704[2];
147: if (aiStack2664[iVar13] != 0) {
148: pcVar5 = *param_1;
149: *(int *)(pcVar5 + 0x2c) = iVar12;
150: *(undefined4 *)(pcVar5 + 0x28) = 0x13;
151: (**(code **)*param_1)();
152: }
153: aiStack2664[iVar13] = 1;
154: if (iVar11 != 2) {
155: iVar13 = piStack2704[3];
156: if (aiStack2664[iVar13] != 0) {
157: pcVar5 = *param_1;
158: *(int *)(pcVar5 + 0x2c) = iVar12;
159: *(undefined4 *)(pcVar5 + 0x28) = 0x13;
160: (**(code **)*param_1)();
161: }
162: aiStack2664[iVar13] = 1;
163: if (iVar11 != 3) {
164: iVar11 = piStack2704[4];
165: if (aiStack2664[iVar11] != 0) {
166: pcVar5 = *param_1;
167: *(int *)(pcVar5 + 0x2c) = iVar12;
168: *(undefined4 *)(pcVar5 + 0x28) = 0x13;
169: (**(code **)*param_1)();
170: }
171: aiStack2664[iVar11] = 1;
172: }
173: }
174: }
175: }
176: }
177: else {
178: if (((uVar2 < 0x40) && ((int)uVar2 <= iVar13)) &&
179: ((iVar13 < 0x40 && ((uVar4 < 0xb && (uVar3 < 0xb)))))) {
180: if (uVar2 != 0) goto LAB_00115679;
181: LAB_00115488:
182: if (iVar13 != 0) goto LAB_00115683;
183: LAB_00115490:
184: if (iVar11 < 1) goto LAB_00115558;
185: }
186: else {
187: pcVar5 = *param_1;
188: *(undefined4 *)(pcVar5 + 0x28) = 0x11;
189: *(int *)(pcVar5 + 0x2c) = iVar12;
190: (**(code **)*param_1)();
191: if (uVar2 == 0) goto LAB_00115488;
192: LAB_00115679:
193: if (iVar11 != 1) {
194: LAB_00115683:
195: pcVar5 = *param_1;
196: *(int *)(pcVar5 + 0x2c) = iVar12;
197: *(undefined4 *)(pcVar5 + 0x28) = 0x11;
198: (**(code **)*param_1)();
199: goto LAB_00115490;
200: }
201: }
202: lStack2696 = 0;
203: uVar7 = uVar4 - 1;
204: do {
205: while( true ) {
206: piVar15 = (int *)((long)auStack2616 + (long)piStack2704[lStack2696 + 1] * 0x40 * 4);
207: uVar16 = 0;
208: if ((uVar2 != 0) &&
209: (uVar16 = uVar2,
210: *(int *)((long)auStack2616 + (long)piStack2704[lStack2696 + 1] * 0x40 * 4) < 0)) {
211: pcVar5 = *param_1;
212: *(undefined4 *)(pcVar5 + 0x28) = 0x11;
213: *(int *)(pcVar5 + 0x2c) = iVar12;
214: (**(code **)*param_1)();
215: }
216: if ((int)uVar16 <= iVar13) break;
217: joined_r0x001156f1:
218: iVar1 = (int)lStack2696;
219: lStack2696 = lStack2696 + 1;
220: if (iVar11 <= iVar1 + 1) goto LAB_00115558;
221: }
222: lVar8 = (long)(int)uVar16;
223: if (uVar7 == uVar3) {
224: puVar10 = (uint *)(piVar15 + lVar8);
225: if (uVar4 == 0) {
226: do {
227: if ((-1 < (int)*puVar10) && (*puVar10 != 0)) {
228: pcVar5 = *param_1;
229: *(undefined4 *)(pcVar5 + 0x28) = 0x11;
230: *(int *)(pcVar5 + 0x2c) = iVar12;
231: (**(code **)*param_1)();
232: }
233: uVar16 = uVar16 + 1;
234: *puVar10 = uVar7;
235: puVar10 = puVar10 + 1;
236: } while ((int)uVar16 <= iVar13);
237: }
238: else {
239: do {
240: if (((int)*puVar10 < 0) || (uVar4 != *puVar10)) {
241: pcVar5 = *param_1;
242: *(undefined4 *)(pcVar5 + 0x28) = 0x11;
243: *(int *)(pcVar5 + 0x2c) = iVar12;
244: (**(code **)*param_1)();
245: }
246: uVar16 = uVar16 + 1;
247: *puVar10 = uVar7;
248: puVar10 = puVar10 + 1;
249: } while ((int)uVar16 <= iVar13);
250: }
251: goto joined_r0x001156f1;
252: }
253: if (uVar4 == 0) {
254: puVar10 = (uint *)(piVar15 + lVar8);
255: do {
256: if (-1 < (int)*puVar10) {
257: pcVar5 = *param_1;
258: *(undefined4 *)(pcVar5 + 0x28) = 0x11;
259: *(int *)(pcVar5 + 0x2c) = iVar12;
260: (**(code **)*param_1)();
261: }
262: uVar16 = uVar16 + 1;
263: *puVar10 = uVar3;
264: puVar10 = puVar10 + 1;
265: } while ((int)uVar16 <= iVar13);
266: goto joined_r0x001156f1;
267: }
268: puVar10 = (uint *)(piVar15 + lVar8);
269: do {
270: pcVar5 = *param_1;
271: uVar16 = uVar16 + 1;
272: *(undefined4 *)(pcVar5 + 0x28) = 0x11;
273: *(int *)(pcVar5 + 0x2c) = iVar12;
274: (**(code **)*param_1)();
275: *puVar10 = uVar3;
276: puVar10 = puVar10 + 1;
277: } while ((int)uVar16 <= iVar13);
278: lStack2696 = lStack2696 + 1;
279: } while ((int)lStack2696 < iVar11);
280: }
281: LAB_00115558:
282: piStack2704 = piStack2704 + 9;
283: iVar12 = iVar12 + 1;
284: } while (iVar12 <= *(int *)(param_1 + 0x1e));
285: iVar11 = *(int *)((long)param_1 + 0x4c);
286: iVar13 = *(int *)((long)param_1 + 0x134);
287: }
288: if (iVar13 == 0) {
289: if (0 < iVar11) {
290: if (aiStack2664[0] == 0) {
291: ppcVar6 = (code **)*param_1;
292: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
293: (**ppcVar6)();
294: iVar11 = *(int *)((long)param_1 + 0x4c);
295: }
296: if (1 < iVar11) {
297: if (aiStack2664[1] == 0) {
298: ppcVar6 = (code **)*param_1;
299: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
300: (**ppcVar6)();
301: iVar11 = *(int *)((long)param_1 + 0x4c);
302: }
303: if (2 < iVar11) {
304: if (aiStack2664[2] == 0) {
305: ppcVar6 = (code **)*param_1;
306: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
307: (**ppcVar6)();
308: iVar11 = *(int *)((long)param_1 + 0x4c);
309: }
310: if (3 < iVar11) {
311: if (aiStack2664[3] == 0) {
312: ppcVar6 = (code **)*param_1;
313: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
314: (**ppcVar6)();
315: iVar11 = *(int *)((long)param_1 + 0x4c);
316: }
317: if (4 < iVar11) {
318: if (iStack2648 == 0) {
319: ppcVar6 = (code **)*param_1;
320: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
321: (**ppcVar6)();
322: iVar11 = *(int *)((long)param_1 + 0x4c);
323: }
324: if (5 < iVar11) {
325: if (iStack2644 == 0) {
326: ppcVar6 = (code **)*param_1;
327: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
328: (**ppcVar6)(param_1);
329: iVar11 = *(int *)((long)param_1 + 0x4c);
330: }
331: if (6 < iVar11) {
332: if (iStack2640 == 0) {
333: ppcVar6 = (code **)*param_1;
334: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
335: (**ppcVar6)(param_1);
336: iVar11 = *(int *)((long)param_1 + 0x4c);
337: }
338: if (7 < iVar11) {
339: if (iStack2636 == 0) {
340: ppcVar6 = (code **)*param_1;
341: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
342: (**ppcVar6)(param_1);
343: iVar11 = *(int *)((long)param_1 + 0x4c);
344: }
345: if (8 < iVar11) {
346: if (iStack2632 == 0) {
347: ppcVar6 = (code **)*param_1;
348: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
349: (**ppcVar6)(param_1);
350: iVar11 = *(int *)((long)param_1 + 0x4c);
351: }
352: if ((9 < iVar11) && (iStack2628 == 0)) {
353: LAB_00115a4c:
354: ppcVar6 = (code **)*param_1;
355: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
356: /* WARNING: Could not recover jumptable at 0x00115a6d. Too many branches */
357: /* WARNING: Treating indirect jump as call */
358: (**ppcVar6)(param_1);
359: return;
360: }
361: }
362: }
363: }
364: }
365: }
366: }
367: }
368: }
369: }
370: }
371: else {
372: if (0 < iVar11) {
373: if ((int)auStack2616[0] < 0) {
374: ppcVar6 = (code **)*param_1;
375: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
376: (**ppcVar6)(param_1);
377: iVar11 = *(int *)((long)param_1 + 0x4c);
378: }
379: if (1 < iVar11) {
380: if (iStack2360 < 0) {
381: ppcVar6 = (code **)*param_1;
382: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
383: (**ppcVar6)(param_1);
384: iVar11 = *(int *)((long)param_1 + 0x4c);
385: }
386: if (2 < iVar11) {
387: if (iStack2104 < 0) {
388: ppcVar6 = (code **)*param_1;
389: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
390: (**ppcVar6)(param_1);
391: iVar11 = *(int *)((long)param_1 + 0x4c);
392: }
393: if (3 < iVar11) {
394: if (iStack1848 < 0) {
395: ppcVar6 = (code **)*param_1;
396: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
397: (**ppcVar6)(param_1);
398: iVar11 = *(int *)((long)param_1 + 0x4c);
399: }
400: if (4 < iVar11) {
401: if (iStack1592 < 0) {
402: ppcVar6 = (code **)*param_1;
403: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
404: (**ppcVar6)(param_1);
405: iVar11 = *(int *)((long)param_1 + 0x4c);
406: }
407: if (5 < iVar11) {
408: if (iStack1336 < 0) {
409: ppcVar6 = (code **)*param_1;
410: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
411: (**ppcVar6)(param_1);
412: iVar11 = *(int *)((long)param_1 + 0x4c);
413: }
414: if (6 < iVar11) {
415: if (iStack1080 < 0) {
416: ppcVar6 = (code **)*param_1;
417: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
418: (**ppcVar6)(param_1);
419: iVar11 = *(int *)((long)param_1 + 0x4c);
420: }
421: if (7 < iVar11) {
422: if (iStack824 < 0) {
423: ppcVar6 = (code **)*param_1;
424: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
425: (**ppcVar6)(param_1);
426: iVar11 = *(int *)((long)param_1 + 0x4c);
427: }
428: if (8 < iVar11) {
429: if (iStack568 < 0) {
430: ppcVar6 = (code **)*param_1;
431: *(undefined4 *)(ppcVar6 + 5) = 0x2d;
432: (**ppcVar6)(param_1);
433: iVar11 = *(int *)((long)param_1 + 0x4c);
434: }
435: if ((9 < iVar11) && (iStack312 < 0)) goto LAB_00115a4c;
436: }
437: }
438: }
439: }
440: }
441: }
442: }
443: }
444: }
445: }
446: return;
447: }
448: 
