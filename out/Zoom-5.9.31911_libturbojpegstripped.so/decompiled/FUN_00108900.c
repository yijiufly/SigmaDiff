1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined8 FUN_00108900(long param_1,long param_2)
5: 
6: {
7: byte bVar1;
8: byte bVar2;
9: byte bVar3;
10: short sVar4;
11: int iVar5;
12: undefined4 uVar6;
13: long lVar7;
14: int *piVar8;
15: short *psVar9;
16: undefined8 uVar10;
17: undefined8 uVar11;
18: char **ppcVar12;
19: int iVar13;
20: long lVar14;
21: char *pcVar15;
22: undefined8 uVar16;
23: int iVar17;
24: long lVar18;
25: char *pcVar19;
26: uint uVar20;
27: int iVar21;
28: char cVar22;
29: char cVar23;
30: char *pcVar24;
31: uint uVar25;
32: uint uVar26;
33: ulong uVar27;
34: int iVar28;
35: ulong uVar29;
36: uint uVar30;
37: long lVar31;
38: long in_FS_OFFSET;
39: long lStack680;
40: char *pcStack648;
41: char *pcStack640;
42: ulong uStack632;
43: undefined8 uStack624;
44: undefined8 uStack616;
45: undefined8 uStack608;
46: long lStack600;
47: char acStack584 [520];
48: long lStack64;
49: 
50: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
51: lVar7 = *(long *)(param_1 + 0x1f0);
52: pcStack648 = **(char ***)(param_1 + 0x28);
53: pcVar19 = (*(char ***)(param_1 + 0x28))[1];
54: uStack632 = *(ulong *)(lVar7 + 0x18);
55: uStack624 = *(ulong *)(lVar7 + 0x20);
56: uStack616 = *(undefined8 *)(lVar7 + 0x28);
57: lStack600 = param_1;
58: uStack608 = *(undefined8 *)(lVar7 + 0x30);
59: pcStack640 = pcVar19;
60: if ((*(int *)(param_1 + 0x118) != 0) && (*(int *)(lVar7 + 0x38) == 0)) {
61: uVar6 = *(undefined4 *)(lVar7 + 0x3c);
62: iVar13 = FUN_00108780();
63: if (iVar13 == 0) {
64: LAB_001105b0:
65: uVar16 = 0;
66: goto LAB_001105b2;
67: }
68: pcVar19 = pcStack648 + 1;
69: *pcStack648 = -1;
70: pcStack640 = pcStack640 + -1;
71: if (pcStack640 == (char *)0x0) {
72: ppcVar12 = *(char ***)(lStack600 + 0x28);
73: pcStack648 = pcVar19;
74: iVar13 = (*(code *)ppcVar12[3])();
75: if (iVar13 == 0) goto LAB_001105b0;
76: pcStack640 = ppcVar12[1];
77: pcVar19 = *ppcVar12;
78: }
79: pcStack648 = pcVar19 + 1;
80: *pcVar19 = (char)uVar6 + -0x30;
81: pcVar19 = pcStack640 + -1;
82: if (pcVar19 == (char *)0x0) {
83: ppcVar12 = *(char ***)(lStack600 + 0x28);
84: pcStack640 = pcVar19;
85: iVar13 = (*(code *)ppcVar12[3])();
86: if (iVar13 == 0) goto LAB_001105b0;
87: pcStack648 = *ppcVar12;
88: pcVar19 = ppcVar12[1];
89: }
90: pcStack640 = pcVar19;
91: if (0 < *(int *)(lStack600 + 0x144)) {
92: memset((void *)((long)&uStack624 + 4),0,(long)*(int *)(lStack600 + 0x144) * 4);
93: }
94: }
95: if (*(int *)(lVar7 + 0xc0) == 0) {
96: lStack680 = 0;
97: if (0 < *(int *)(param_1 + 0x170)) {
98: do {
99: lVar14 = (long)*(int *)(param_1 + 0x174 + lStack680 * 4);
100: lVar18 = *(long *)(param_1 + 0x148 + lVar14 * 8);
101: piVar8 = *(int **)(lVar7 + 0x60 + (long)*(int *)(lVar18 + 0x18) * 8);
102: lVar18 = *(long *)(lVar7 + 0x40 + (long)*(int *)(lVar18 + 0x14) * 8);
103: bVar1 = *(byte *)(piVar8 + 0x13c);
104: iVar21 = (int)(char)bVar1;
105: psVar9 = *(short **)(param_2 + lStack680 * 8);
106: iVar13 = piVar8[0xf0];
107: pcVar24 = pcStack648;
108: if (pcVar19 < (char *)0x200) {
109: pcVar24 = acStack584;
110: }
111: uVar20 = (int)*psVar9 - *(int *)((long)&uStack624 + lVar14 * 4 + 4);
112: uVar26 = (int)uVar20 >> 0x1f;
113: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
114: iVar17 = *(int *)(lVar18 + (long)(int)(uint)bVar2 * 4);
115: bVar3 = *(byte *)(lVar18 + 0x400 + (long)(int)(uint)bVar2);
116: if (0x2f < (int)uStack624) {
117: cVar23 = (char)uStack624;
118: pcVar15 = pcVar24 + 1;
119: cVar22 = (char)(uStack632 >> (cVar23 - 8U & 0x3f));
120: *pcVar24 = cVar22;
121: if (cVar22 == -1) {
122: pcVar15 = pcVar24 + 2;
123: pcVar24[1] = '\0';
124: }
125: cVar22 = (char)(uStack632 >> (cVar23 - 0x10U & 0x3f));
126: *pcVar15 = cVar22;
127: pcVar24 = pcVar15 + 1;
128: if (cVar22 == -1) {
129: pcVar24 = pcVar15 + 2;
130: pcVar15[1] = '\0';
131: }
132: pcVar15 = pcVar24 + 1;
133: cVar22 = (char)(uStack632 >> (cVar23 - 0x18U & 0x3f));
134: *pcVar24 = cVar22;
135: if (cVar22 == -1) {
136: pcVar15 = pcVar24 + 2;
137: pcVar24[1] = '\0';
138: }
139: cVar22 = (char)(uStack632 >> (cVar23 - 0x20U & 0x3f));
140: *pcVar15 = cVar22;
141: pcVar24 = pcVar15 + 1;
142: if (cVar22 == -1) {
143: pcVar24 = pcVar15 + 2;
144: pcVar15[1] = '\0';
145: }
146: pcVar15 = pcVar24 + 1;
147: cVar23 = (char)(uStack632 >> (cVar23 - 0x28U & 0x3f));
148: *pcVar24 = cVar23;
149: if (cVar23 == -1) {
150: pcVar15 = pcVar24 + 2;
151: pcVar24[1] = '\0';
152: }
153: uStack624._0_4_ = (int)uStack624 + -0x30;
154: cVar23 = (char)(uStack632 >> ((byte)(int)uStack624 & 0x3f));
155: *pcVar15 = cVar23;
156: pcVar24 = pcVar15 + 1;
157: if (cVar23 == -1) {
158: pcVar24 = pcVar15 + 2;
159: pcVar15[1] = '\0';
160: }
161: }
162: uStack624._0_4_ = (int)uStack624 + (char)bVar3;
163: uVar29 = (long)iVar17 | uStack632 << (bVar3 & 0x3f);
164: if (0x2f < (int)uStack624) {
165: cVar23 = (char)(int)uStack624;
166: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
167: *pcVar24 = cVar22;
168: pcVar15 = pcVar24 + 1;
169: if (cVar22 == -1) {
170: pcVar15 = pcVar24 + 2;
171: pcVar24[1] = '\0';
172: }
173: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
174: *pcVar15 = cVar22;
175: pcVar24 = pcVar15 + 1;
176: if (cVar22 == -1) {
177: pcVar24 = pcVar15 + 2;
178: pcVar15[1] = '\0';
179: }
180: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
181: *pcVar24 = cVar22;
182: pcVar15 = pcVar24 + 1;
183: if (cVar22 == -1) {
184: pcVar15 = pcVar24 + 2;
185: pcVar24[1] = '\0';
186: }
187: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
188: *pcVar15 = cVar22;
189: pcVar24 = pcVar15 + 1;
190: if (cVar22 == -1) {
191: pcVar24 = pcVar15 + 2;
192: pcVar15[1] = '\0';
193: }
194: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
195: *pcVar24 = cVar23;
196: pcVar15 = pcVar24 + 1;
197: if (cVar23 == -1) {
198: pcVar15 = pcVar24 + 2;
199: pcVar24[1] = '\0';
200: }
201: uStack624._0_4_ = (int)uStack624 + -0x30;
202: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
203: *pcVar15 = cVar23;
204: pcVar24 = pcVar15 + 1;
205: if (cVar23 == -1) {
206: pcVar24 = pcVar15 + 2;
207: pcVar15[1] = '\0';
208: }
209: }
210: uVar30 = SEXT24(psVar9[1]);
211: uStack624._0_4_ = (int)uStack624 + (uint)bVar2;
212: uVar29 = (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26) |
213: uVar29 << (bVar2 & 0x3f);
214: if (psVar9[1] == 0) {
215: iVar28 = 0x10;
216: iVar17 = 2;
217: }
218: else {
219: uVar20 = (int)uVar30 >> 0x1f;
220: bVar2 = (&DAT_00168f80)[(int)((uVar20 ^ uVar30) - uVar20)];
221: iVar28 = piVar8[(int)(uint)bVar2];
222: bVar3 = *(byte *)((long)piVar8 + (long)(int)(uint)bVar2 + 0x400);
223: if (0x1f < (int)uStack624) {
224: cVar23 = (char)(int)uStack624;
225: pcVar15 = pcVar24 + 1;
226: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
227: *pcVar24 = cVar22;
228: if (cVar22 == -1) {
229: pcVar15 = pcVar24 + 2;
230: pcVar24[1] = '\0';
231: }
232: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
233: *pcVar15 = cVar22;
234: pcVar24 = pcVar15 + 1;
235: if (cVar22 == -1) {
236: pcVar24 = pcVar15 + 2;
237: pcVar15[1] = '\0';
238: }
239: pcVar15 = pcVar24 + 1;
240: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
241: *pcVar24 = cVar23;
242: if (cVar23 == -1) {
243: pcVar15 = pcVar24 + 2;
244: pcVar24[1] = '\0';
245: }
246: uStack624._0_4_ = (int)uStack624 + -0x20;
247: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
248: *pcVar15 = cVar23;
249: pcVar24 = pcVar15 + 1;
250: if (cVar23 == -1) {
251: pcVar24 = pcVar15 + 2;
252: pcVar15[1] = '\0';
253: }
254: }
255: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
256: iVar17 = 1;
257: uVar29 = (uVar29 << (bVar3 & 0x3f) | (long)iVar28) << (bVar2 & 0x3f) |
258: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar20);
259: iVar28 = 0;
260: }
261: uVar20 = SEXT24(psVar9[8]);
262: if (psVar9[8] != 0) {
263: uVar26 = (int)uVar20 >> 0x1f;
264: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
265: iVar5 = piVar8[(int)(iVar28 + (uint)bVar2)];
266: bVar3 = *(byte *)((long)piVar8 + (long)(int)(iVar28 + (uint)bVar2) + 0x400);
267: if (0x1f < (int)uStack624) {
268: cVar23 = (char)(int)uStack624;
269: pcVar15 = pcVar24 + 1;
270: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
271: *pcVar24 = cVar22;
272: if (cVar22 == -1) {
273: pcVar15 = pcVar24 + 2;
274: pcVar24[1] = '\0';
275: }
276: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
277: *pcVar15 = cVar22;
278: pcVar24 = pcVar15 + 1;
279: if (cVar22 == -1) {
280: pcVar24 = pcVar15 + 2;
281: pcVar15[1] = '\0';
282: }
283: pcVar15 = pcVar24 + 1;
284: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
285: *pcVar24 = cVar23;
286: if (cVar23 == -1) {
287: pcVar15 = pcVar24 + 2;
288: pcVar24[1] = '\0';
289: }
290: uStack624._0_4_ = (int)uStack624 + -0x20;
291: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
292: *pcVar15 = cVar23;
293: pcVar24 = pcVar15 + 1;
294: if (cVar23 == -1) {
295: pcVar24 = pcVar15 + 2;
296: pcVar15[1] = '\0';
297: }
298: }
299: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
300: iVar17 = 0;
301: uVar29 = ((long)iVar5 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
302: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
303: }
304: uVar20 = SEXT24(psVar9[0x10]);
305: iVar28 = iVar17 + 1;
306: if (psVar9[0x10] != 0) {
307: uVar26 = (int)uVar20 >> 0x1f;
308: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
309: lVar18 = (long)(int)(iVar17 * 0x10 + (uint)bVar2);
310: iVar17 = piVar8[lVar18];
311: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
312: if (0x1f < (int)uStack624) {
313: cVar23 = (char)(int)uStack624;
314: pcVar15 = pcVar24 + 1;
315: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
316: *pcVar24 = cVar22;
317: if (cVar22 == -1) {
318: pcVar15 = pcVar24 + 2;
319: pcVar24[1] = '\0';
320: }
321: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
322: *pcVar15 = cVar22;
323: pcVar24 = pcVar15 + 1;
324: if (cVar22 == -1) {
325: pcVar24 = pcVar15 + 2;
326: pcVar15[1] = '\0';
327: }
328: pcVar15 = pcVar24 + 1;
329: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
330: *pcVar24 = cVar23;
331: if (cVar23 == -1) {
332: pcVar15 = pcVar24 + 2;
333: pcVar24[1] = '\0';
334: }
335: uStack624._0_4_ = (int)uStack624 + -0x20;
336: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
337: *pcVar15 = cVar23;
338: pcVar24 = pcVar15 + 1;
339: if (cVar23 == -1) {
340: pcVar24 = pcVar15 + 2;
341: pcVar15[1] = '\0';
342: }
343: }
344: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
345: iVar28 = 0;
346: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
347: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
348: }
349: uVar20 = SEXT24(psVar9[9]);
350: if (psVar9[9] == 0) {
351: iVar28 = iVar28 + 1;
352: }
353: else {
354: uVar26 = (int)uVar20 >> 0x1f;
355: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
356: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
357: iVar17 = piVar8[lVar18];
358: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
359: if (0x1f < (int)uStack624) {
360: cVar23 = (char)(int)uStack624;
361: pcVar15 = pcVar24 + 1;
362: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
363: *pcVar24 = cVar22;
364: if (cVar22 == -1) {
365: pcVar15 = pcVar24 + 2;
366: pcVar24[1] = '\0';
367: }
368: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
369: *pcVar15 = cVar22;
370: pcVar24 = pcVar15 + 1;
371: if (cVar22 == -1) {
372: pcVar24 = pcVar15 + 2;
373: pcVar15[1] = '\0';
374: }
375: pcVar15 = pcVar24 + 1;
376: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
377: *pcVar24 = cVar23;
378: if (cVar23 == -1) {
379: pcVar15 = pcVar24 + 2;
380: pcVar24[1] = '\0';
381: }
382: uStack624._0_4_ = (int)uStack624 + -0x20;
383: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
384: *pcVar15 = cVar23;
385: pcVar24 = pcVar15 + 1;
386: if (cVar23 == -1) {
387: pcVar24 = pcVar15 + 2;
388: pcVar15[1] = '\0';
389: }
390: }
391: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
392: iVar28 = 0;
393: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
394: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
395: }
396: uVar20 = SEXT24(psVar9[2]);
397: if (psVar9[2] == 0) {
398: iVar28 = iVar28 + 1;
399: }
400: else {
401: uVar26 = (int)uVar20 >> 0x1f;
402: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
403: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
404: iVar17 = piVar8[lVar18];
405: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
406: if (0x1f < (int)uStack624) {
407: cVar23 = (char)(int)uStack624;
408: pcVar15 = pcVar24 + 1;
409: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
410: *pcVar24 = cVar22;
411: if (cVar22 == -1) {
412: pcVar15 = pcVar24 + 2;
413: pcVar24[1] = '\0';
414: }
415: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
416: *pcVar15 = cVar22;
417: pcVar24 = pcVar15 + 1;
418: if (cVar22 == -1) {
419: pcVar24 = pcVar15 + 2;
420: pcVar15[1] = '\0';
421: }
422: pcVar15 = pcVar24 + 1;
423: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
424: *pcVar24 = cVar23;
425: if (cVar23 == -1) {
426: pcVar15 = pcVar24 + 2;
427: pcVar24[1] = '\0';
428: }
429: uStack624._0_4_ = (int)uStack624 + -0x20;
430: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
431: *pcVar15 = cVar23;
432: pcVar24 = pcVar15 + 1;
433: if (cVar23 == -1) {
434: pcVar24 = pcVar15 + 2;
435: pcVar15[1] = '\0';
436: }
437: }
438: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
439: iVar28 = 0;
440: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
441: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
442: }
443: uVar20 = SEXT24(psVar9[3]);
444: if (psVar9[3] == 0) {
445: iVar28 = iVar28 + 1;
446: }
447: else {
448: uVar26 = (int)uVar20 >> 0x1f;
449: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
450: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
451: iVar17 = piVar8[lVar18];
452: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
453: if (0x1f < (int)uStack624) {
454: cVar23 = (char)(int)uStack624;
455: pcVar15 = pcVar24 + 1;
456: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
457: *pcVar24 = cVar22;
458: if (cVar22 == -1) {
459: pcVar15 = pcVar24 + 2;
460: pcVar24[1] = '\0';
461: }
462: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
463: *pcVar15 = cVar22;
464: pcVar24 = pcVar15 + 1;
465: if (cVar22 == -1) {
466: pcVar24 = pcVar15 + 2;
467: pcVar15[1] = '\0';
468: }
469: pcVar15 = pcVar24 + 1;
470: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
471: *pcVar24 = cVar23;
472: if (cVar23 == -1) {
473: pcVar15 = pcVar24 + 2;
474: pcVar24[1] = '\0';
475: }
476: uStack624._0_4_ = (int)uStack624 + -0x20;
477: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
478: *pcVar15 = cVar23;
479: pcVar24 = pcVar15 + 1;
480: if (cVar23 == -1) {
481: pcVar24 = pcVar15 + 2;
482: pcVar15[1] = '\0';
483: }
484: }
485: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
486: iVar28 = 0;
487: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
488: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
489: }
490: uVar20 = SEXT24(psVar9[10]);
491: if (psVar9[10] == 0) {
492: iVar28 = iVar28 + 1;
493: }
494: else {
495: uVar26 = (int)uVar20 >> 0x1f;
496: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
497: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
498: iVar17 = piVar8[lVar18];
499: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
500: if (0x1f < (int)uStack624) {
501: cVar23 = (char)(int)uStack624;
502: pcVar15 = pcVar24 + 1;
503: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
504: *pcVar24 = cVar22;
505: if (cVar22 == -1) {
506: pcVar15 = pcVar24 + 2;
507: pcVar24[1] = '\0';
508: }
509: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
510: *pcVar15 = cVar22;
511: pcVar24 = pcVar15 + 1;
512: if (cVar22 == -1) {
513: pcVar24 = pcVar15 + 2;
514: pcVar15[1] = '\0';
515: }
516: pcVar15 = pcVar24 + 1;
517: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
518: *pcVar24 = cVar23;
519: if (cVar23 == -1) {
520: pcVar15 = pcVar24 + 2;
521: pcVar24[1] = '\0';
522: }
523: uStack624._0_4_ = (int)uStack624 + -0x20;
524: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
525: *pcVar15 = cVar23;
526: pcVar24 = pcVar15 + 1;
527: if (cVar23 == -1) {
528: pcVar24 = pcVar15 + 2;
529: pcVar15[1] = '\0';
530: }
531: }
532: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
533: iVar28 = 0;
534: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
535: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
536: }
537: uVar20 = SEXT24(psVar9[0x11]);
538: if (psVar9[0x11] == 0) {
539: iVar28 = iVar28 + 1;
540: }
541: else {
542: uVar26 = (int)uVar20 >> 0x1f;
543: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
544: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
545: iVar17 = piVar8[lVar18];
546: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
547: if (0x1f < (int)uStack624) {
548: cVar23 = (char)(int)uStack624;
549: pcVar15 = pcVar24 + 1;
550: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
551: *pcVar24 = cVar22;
552: if (cVar22 == -1) {
553: pcVar15 = pcVar24 + 2;
554: pcVar24[1] = '\0';
555: }
556: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
557: *pcVar15 = cVar22;
558: pcVar24 = pcVar15 + 1;
559: if (cVar22 == -1) {
560: pcVar24 = pcVar15 + 2;
561: pcVar15[1] = '\0';
562: }
563: pcVar15 = pcVar24 + 1;
564: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
565: *pcVar24 = cVar23;
566: if (cVar23 == -1) {
567: pcVar15 = pcVar24 + 2;
568: pcVar24[1] = '\0';
569: }
570: uStack624._0_4_ = (int)uStack624 + -0x20;
571: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
572: *pcVar15 = cVar23;
573: pcVar24 = pcVar15 + 1;
574: if (cVar23 == -1) {
575: pcVar24 = pcVar15 + 2;
576: pcVar15[1] = '\0';
577: }
578: }
579: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
580: iVar28 = 0;
581: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
582: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
583: }
584: uVar20 = SEXT24(psVar9[0x18]);
585: if (psVar9[0x18] == 0) {
586: iVar28 = iVar28 + 1;
587: }
588: else {
589: uVar26 = (int)uVar20 >> 0x1f;
590: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
591: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
592: iVar17 = piVar8[lVar18];
593: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
594: if (0x1f < (int)uStack624) {
595: cVar23 = (char)(int)uStack624;
596: pcVar15 = pcVar24 + 1;
597: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
598: *pcVar24 = cVar22;
599: if (cVar22 == -1) {
600: pcVar15 = pcVar24 + 2;
601: pcVar24[1] = '\0';
602: }
603: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
604: *pcVar15 = cVar22;
605: pcVar24 = pcVar15 + 1;
606: if (cVar22 == -1) {
607: pcVar24 = pcVar15 + 2;
608: pcVar15[1] = '\0';
609: }
610: pcVar15 = pcVar24 + 1;
611: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
612: *pcVar24 = cVar23;
613: if (cVar23 == -1) {
614: pcVar15 = pcVar24 + 2;
615: pcVar24[1] = '\0';
616: }
617: uStack624._0_4_ = (int)uStack624 + -0x20;
618: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
619: *pcVar15 = cVar23;
620: pcVar24 = pcVar15 + 1;
621: if (cVar23 == -1) {
622: pcVar24 = pcVar15 + 2;
623: pcVar15[1] = '\0';
624: }
625: }
626: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
627: iVar28 = 0;
628: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
629: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
630: }
631: uVar20 = SEXT24(psVar9[0x20]);
632: if (psVar9[0x20] == 0) {
633: iVar28 = iVar28 + 1;
634: }
635: else {
636: uVar26 = (int)uVar20 >> 0x1f;
637: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
638: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
639: iVar17 = piVar8[lVar18];
640: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
641: if (0x1f < (int)uStack624) {
642: cVar23 = (char)(int)uStack624;
643: pcVar15 = pcVar24 + 1;
644: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
645: *pcVar24 = cVar22;
646: if (cVar22 == -1) {
647: pcVar15 = pcVar24 + 2;
648: pcVar24[1] = '\0';
649: }
650: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
651: *pcVar15 = cVar22;
652: pcVar24 = pcVar15 + 1;
653: if (cVar22 == -1) {
654: pcVar24 = pcVar15 + 2;
655: pcVar15[1] = '\0';
656: }
657: pcVar15 = pcVar24 + 1;
658: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
659: *pcVar24 = cVar23;
660: if (cVar23 == -1) {
661: pcVar15 = pcVar24 + 2;
662: pcVar24[1] = '\0';
663: }
664: uStack624._0_4_ = (int)uStack624 + -0x20;
665: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
666: *pcVar15 = cVar23;
667: pcVar24 = pcVar15 + 1;
668: if (cVar23 == -1) {
669: pcVar24 = pcVar15 + 2;
670: pcVar15[1] = '\0';
671: }
672: }
673: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
674: iVar28 = 0;
675: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
676: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
677: }
678: uVar20 = SEXT24(psVar9[0x19]);
679: if (psVar9[0x19] == 0) {
680: iVar28 = iVar28 + 1;
681: }
682: else {
683: uVar26 = (int)uVar20 >> 0x1f;
684: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
685: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
686: iVar17 = piVar8[lVar18];
687: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
688: if (0x1f < (int)uStack624) {
689: cVar23 = (char)(int)uStack624;
690: pcVar15 = pcVar24 + 1;
691: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
692: *pcVar24 = cVar22;
693: if (cVar22 == -1) {
694: pcVar15 = pcVar24 + 2;
695: pcVar24[1] = '\0';
696: }
697: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
698: *pcVar15 = cVar22;
699: pcVar24 = pcVar15 + 1;
700: if (cVar22 == -1) {
701: pcVar24 = pcVar15 + 2;
702: pcVar15[1] = '\0';
703: }
704: pcVar15 = pcVar24 + 1;
705: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
706: *pcVar24 = cVar23;
707: if (cVar23 == -1) {
708: pcVar15 = pcVar24 + 2;
709: pcVar24[1] = '\0';
710: }
711: uStack624._0_4_ = (int)uStack624 + -0x20;
712: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
713: *pcVar15 = cVar23;
714: pcVar24 = pcVar15 + 1;
715: if (cVar23 == -1) {
716: pcVar24 = pcVar15 + 2;
717: pcVar15[1] = '\0';
718: }
719: }
720: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
721: iVar28 = 0;
722: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
723: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
724: }
725: uVar20 = SEXT24(psVar9[0x12]);
726: if (psVar9[0x12] == 0) {
727: iVar28 = iVar28 + 1;
728: }
729: else {
730: uVar26 = (int)uVar20 >> 0x1f;
731: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
732: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
733: iVar17 = piVar8[lVar18];
734: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
735: if (0x1f < (int)uStack624) {
736: cVar23 = (char)(int)uStack624;
737: pcVar15 = pcVar24 + 1;
738: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
739: *pcVar24 = cVar22;
740: if (cVar22 == -1) {
741: pcVar15 = pcVar24 + 2;
742: pcVar24[1] = '\0';
743: }
744: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
745: *pcVar15 = cVar22;
746: pcVar24 = pcVar15 + 1;
747: if (cVar22 == -1) {
748: pcVar24 = pcVar15 + 2;
749: pcVar15[1] = '\0';
750: }
751: pcVar15 = pcVar24 + 1;
752: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
753: *pcVar24 = cVar23;
754: if (cVar23 == -1) {
755: pcVar15 = pcVar24 + 2;
756: pcVar24[1] = '\0';
757: }
758: uStack624._0_4_ = (int)uStack624 + -0x20;
759: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
760: *pcVar15 = cVar23;
761: pcVar24 = pcVar15 + 1;
762: if (cVar23 == -1) {
763: pcVar24 = pcVar15 + 2;
764: pcVar15[1] = '\0';
765: }
766: }
767: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
768: iVar28 = 0;
769: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
770: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
771: }
772: uVar20 = SEXT24(psVar9[0xb]);
773: if (psVar9[0xb] == 0) {
774: iVar28 = iVar28 + 1;
775: }
776: else {
777: uVar26 = (int)uVar20 >> 0x1f;
778: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
779: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
780: iVar17 = piVar8[lVar18];
781: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
782: if (0x1f < (int)uStack624) {
783: cVar23 = (char)(int)uStack624;
784: pcVar15 = pcVar24 + 1;
785: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
786: *pcVar24 = cVar22;
787: if (cVar22 == -1) {
788: pcVar15 = pcVar24 + 2;
789: pcVar24[1] = '\0';
790: }
791: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
792: *pcVar15 = cVar22;
793: pcVar24 = pcVar15 + 1;
794: if (cVar22 == -1) {
795: pcVar24 = pcVar15 + 2;
796: pcVar15[1] = '\0';
797: }
798: pcVar15 = pcVar24 + 1;
799: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
800: *pcVar24 = cVar23;
801: if (cVar23 == -1) {
802: pcVar15 = pcVar24 + 2;
803: pcVar24[1] = '\0';
804: }
805: uStack624._0_4_ = (int)uStack624 + -0x20;
806: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
807: *pcVar15 = cVar23;
808: pcVar24 = pcVar15 + 1;
809: if (cVar23 == -1) {
810: pcVar24 = pcVar15 + 2;
811: pcVar15[1] = '\0';
812: }
813: }
814: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
815: iVar28 = 0;
816: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
817: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
818: }
819: uVar20 = SEXT24(psVar9[4]);
820: if (psVar9[4] == 0) {
821: sVar4 = psVar9[5];
822: iVar28 = iVar28 + 1;
823: if (sVar4 == 0) goto LAB_00108f86;
824: LAB_0010bc19:
825: uVar26 = SEXT24(sVar4);
826: uVar20 = (int)uVar26 >> 0x1f;
827: bVar2 = (&DAT_00168f80)[(int)((uVar20 ^ uVar26) - uVar20)];
828: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
829: iVar17 = piVar8[lVar18];
830: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
831: if (0x1f < (int)uStack624) {
832: cVar23 = (char)(int)uStack624;
833: pcVar15 = pcVar24 + 1;
834: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
835: *pcVar24 = cVar22;
836: if (cVar22 == -1) {
837: pcVar15 = pcVar24 + 2;
838: pcVar24[1] = '\0';
839: }
840: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
841: *pcVar15 = cVar22;
842: pcVar24 = pcVar15 + 1;
843: if (cVar22 == -1) {
844: pcVar24 = pcVar15 + 2;
845: pcVar15[1] = '\0';
846: }
847: pcVar15 = pcVar24 + 1;
848: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
849: *pcVar24 = cVar23;
850: if (cVar23 == -1) {
851: pcVar15 = pcVar24 + 2;
852: pcVar24[1] = '\0';
853: }
854: uStack624._0_4_ = (int)uStack624 + -0x20;
855: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
856: *pcVar15 = cVar23;
857: pcVar24 = pcVar15 + 1;
858: if (cVar23 == -1) {
859: pcVar24 = pcVar15 + 2;
860: pcVar15[1] = '\0';
861: }
862: }
863: sVar4 = psVar9[0xc];
864: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
865: iVar28 = 0;
866: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
867: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar20);
868: if (sVar4 != 0) goto LAB_0010bd02;
869: LAB_00108f98:
870: sVar4 = psVar9[0x13];
871: iVar28 = iVar28 + 1;
872: if (sVar4 == 0) goto LAB_00108faa;
873: LAB_0010bdeb:
874: uVar30 = SEXT24(sVar4);
875: uVar26 = (int)uVar30 >> 0x1f;
876: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
877: if (iVar28 == 0x10) {
878: if (0x2f < (int)uStack624) {
879: cVar23 = (char)(int)uStack624;
880: pcVar15 = pcVar24 + 1;
881: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
882: *pcVar24 = cVar22;
883: if (cVar22 == -1) {
884: pcVar15 = pcVar24 + 2;
885: pcVar24[1] = '\0';
886: }
887: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
888: *pcVar15 = cVar22;
889: pcVar24 = pcVar15 + 1;
890: if (cVar22 == -1) {
891: pcVar24 = pcVar15 + 2;
892: pcVar15[1] = '\0';
893: }
894: pcVar15 = pcVar24 + 1;
895: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
896: *pcVar24 = cVar22;
897: if (cVar22 == -1) {
898: pcVar15 = pcVar24 + 2;
899: pcVar24[1] = '\0';
900: }
901: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
902: *pcVar15 = cVar22;
903: pcVar24 = pcVar15 + 1;
904: if (cVar22 == -1) {
905: pcVar24 = pcVar15 + 2;
906: pcVar15[1] = '\0';
907: }
908: pcVar15 = pcVar24 + 1;
909: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
910: *pcVar24 = cVar23;
911: if (cVar23 == -1) {
912: pcVar15 = pcVar24 + 2;
913: pcVar24[1] = '\0';
914: }
915: uStack624._0_4_ = (int)uStack624 + -0x30;
916: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
917: *pcVar15 = cVar23;
918: pcVar24 = pcVar15 + 1;
919: if (cVar23 == -1) {
920: pcVar24 = pcVar15 + 2;
921: pcVar15[1] = '\0';
922: }
923: }
924: uStack624._0_4_ = (int)uStack624 + iVar21;
925: iVar28 = 0;
926: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
927: }
928: else {
929: iVar28 = iVar28 << 4;
930: }
931: iVar17 = piVar8[(int)(iVar28 + (uint)bVar2)];
932: bVar3 = *(byte *)((long)piVar8 + (long)(int)(iVar28 + (uint)bVar2) + 0x400);
933: if (0x1f < (int)uStack624) {
934: cVar23 = (char)(int)uStack624;
935: pcVar15 = pcVar24 + 1;
936: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
937: *pcVar24 = cVar22;
938: if (cVar22 == -1) {
939: pcVar15 = pcVar24 + 2;
940: pcVar24[1] = '\0';
941: }
942: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
943: *pcVar15 = cVar22;
944: pcVar24 = pcVar15 + 1;
945: if (cVar22 == -1) {
946: pcVar24 = pcVar15 + 2;
947: pcVar15[1] = '\0';
948: }
949: pcVar15 = pcVar24 + 1;
950: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
951: *pcVar24 = cVar23;
952: if (cVar23 == -1) {
953: pcVar15 = pcVar24 + 2;
954: pcVar24[1] = '\0';
955: }
956: uStack624._0_4_ = (int)uStack624 + -0x20;
957: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
958: *pcVar15 = cVar23;
959: pcVar24 = pcVar15 + 1;
960: if (cVar23 == -1) {
961: pcVar24 = pcVar15 + 2;
962: pcVar15[1] = '\0';
963: }
964: }
965: sVar4 = psVar9[0x1a];
966: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
967: uVar20 = 0;
968: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
969: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
970: if (sVar4 != 0) goto LAB_0010bf97;
971: LAB_00108fbc:
972: sVar4 = psVar9[0x21];
973: uVar20 = uVar20 + 1;
974: if (sVar4 == 0) goto LAB_00108fce;
975: LAB_0010c148:
976: uVar30 = SEXT24(sVar4);
977: uVar26 = (int)uVar30 >> 0x1f;
978: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
979: if (0xf < uVar20) {
980: if (0x2f < (int)uStack624) {
981: cVar23 = (char)(int)uStack624;
982: pcVar15 = pcVar24 + 1;
983: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
984: *pcVar24 = cVar22;
985: if (cVar22 == -1) {
986: pcVar15 = pcVar24 + 2;
987: pcVar24[1] = '\0';
988: }
989: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
990: *pcVar15 = cVar22;
991: pcVar24 = pcVar15 + 1;
992: if (cVar22 == -1) {
993: pcVar24 = pcVar15 + 2;
994: pcVar15[1] = '\0';
995: }
996: pcVar15 = pcVar24 + 1;
997: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
998: *pcVar24 = cVar22;
999: if (cVar22 == -1) {
1000: pcVar15 = pcVar24 + 2;
1001: pcVar24[1] = '\0';
1002: }
1003: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1004: *pcVar15 = cVar22;
1005: pcVar24 = pcVar15 + 1;
1006: if (cVar22 == -1) {
1007: pcVar24 = pcVar15 + 2;
1008: pcVar15[1] = '\0';
1009: }
1010: pcVar15 = pcVar24 + 1;
1011: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1012: *pcVar24 = cVar23;
1013: if (cVar23 == -1) {
1014: pcVar15 = pcVar24 + 2;
1015: pcVar24[1] = '\0';
1016: }
1017: uStack624._0_4_ = (int)uStack624 + -0x30;
1018: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1019: *pcVar15 = cVar23;
1020: pcVar24 = pcVar15 + 1;
1021: if (cVar23 == -1) {
1022: pcVar24 = pcVar15 + 2;
1023: pcVar15[1] = '\0';
1024: }
1025: }
1026: uStack624._0_4_ = (int)uStack624 + iVar21;
1027: uVar20 = uVar20 - 0x10;
1028: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1029: }
1030: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1031: iVar17 = piVar8[lVar18];
1032: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1033: if (0x1f < (int)uStack624) {
1034: cVar23 = (char)(int)uStack624;
1035: pcVar15 = pcVar24 + 1;
1036: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1037: *pcVar24 = cVar22;
1038: if (cVar22 == -1) {
1039: pcVar15 = pcVar24 + 2;
1040: pcVar24[1] = '\0';
1041: }
1042: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1043: *pcVar15 = cVar22;
1044: pcVar24 = pcVar15 + 1;
1045: if (cVar22 == -1) {
1046: pcVar24 = pcVar15 + 2;
1047: pcVar15[1] = '\0';
1048: }
1049: pcVar15 = pcVar24 + 1;
1050: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1051: *pcVar24 = cVar23;
1052: if (cVar23 == -1) {
1053: pcVar15 = pcVar24 + 2;
1054: pcVar24[1] = '\0';
1055: }
1056: uStack624._0_4_ = (int)uStack624 + -0x20;
1057: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1058: *pcVar15 = cVar23;
1059: pcVar24 = pcVar15 + 1;
1060: if (cVar23 == -1) {
1061: pcVar24 = pcVar15 + 2;
1062: pcVar15[1] = '\0';
1063: }
1064: }
1065: sVar4 = psVar9[0x28];
1066: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1067: uVar20 = 0;
1068: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1069: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1070: if (sVar4 != 0) goto LAB_0010c2f9;
1071: LAB_00108fe0:
1072: sVar4 = psVar9[0x30];
1073: uVar20 = uVar20 + 1;
1074: if (sVar4 == 0) goto LAB_00108ff2;
1075: LAB_0010c4aa:
1076: uVar30 = SEXT24(sVar4);
1077: uVar26 = (int)uVar30 >> 0x1f;
1078: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1079: if (0xf < uVar20) {
1080: if (0x2f < (int)uStack624) {
1081: cVar23 = (char)(int)uStack624;
1082: pcVar15 = pcVar24 + 1;
1083: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1084: *pcVar24 = cVar22;
1085: if (cVar22 == -1) {
1086: pcVar15 = pcVar24 + 2;
1087: pcVar24[1] = '\0';
1088: }
1089: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1090: *pcVar15 = cVar22;
1091: pcVar24 = pcVar15 + 1;
1092: if (cVar22 == -1) {
1093: pcVar24 = pcVar15 + 2;
1094: pcVar15[1] = '\0';
1095: }
1096: pcVar15 = pcVar24 + 1;
1097: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1098: *pcVar24 = cVar22;
1099: if (cVar22 == -1) {
1100: pcVar15 = pcVar24 + 2;
1101: pcVar24[1] = '\0';
1102: }
1103: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1104: *pcVar15 = cVar22;
1105: pcVar24 = pcVar15 + 1;
1106: if (cVar22 == -1) {
1107: pcVar24 = pcVar15 + 2;
1108: pcVar15[1] = '\0';
1109: }
1110: pcVar15 = pcVar24 + 1;
1111: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1112: *pcVar24 = cVar23;
1113: if (cVar23 == -1) {
1114: pcVar15 = pcVar24 + 2;
1115: pcVar24[1] = '\0';
1116: }
1117: uStack624._0_4_ = (int)uStack624 + -0x30;
1118: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1119: *pcVar15 = cVar23;
1120: pcVar24 = pcVar15 + 1;
1121: if (cVar23 == -1) {
1122: pcVar24 = pcVar15 + 2;
1123: pcVar15[1] = '\0';
1124: }
1125: }
1126: uStack624._0_4_ = (int)uStack624 + iVar21;
1127: uVar20 = uVar20 - 0x10;
1128: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1129: }
1130: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1131: iVar17 = piVar8[lVar18];
1132: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1133: if (0x1f < (int)uStack624) {
1134: cVar23 = (char)(int)uStack624;
1135: pcVar15 = pcVar24 + 1;
1136: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1137: *pcVar24 = cVar22;
1138: if (cVar22 == -1) {
1139: pcVar15 = pcVar24 + 2;
1140: pcVar24[1] = '\0';
1141: }
1142: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1143: *pcVar15 = cVar22;
1144: pcVar24 = pcVar15 + 1;
1145: if (cVar22 == -1) {
1146: pcVar24 = pcVar15 + 2;
1147: pcVar15[1] = '\0';
1148: }
1149: pcVar15 = pcVar24 + 1;
1150: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1151: *pcVar24 = cVar23;
1152: if (cVar23 == -1) {
1153: pcVar15 = pcVar24 + 2;
1154: pcVar24[1] = '\0';
1155: }
1156: uStack624._0_4_ = (int)uStack624 + -0x20;
1157: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1158: *pcVar15 = cVar23;
1159: pcVar24 = pcVar15 + 1;
1160: if (cVar23 == -1) {
1161: pcVar24 = pcVar15 + 2;
1162: pcVar15[1] = '\0';
1163: }
1164: }
1165: sVar4 = psVar9[0x29];
1166: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1167: uVar20 = 0;
1168: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1169: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1170: if (sVar4 != 0) goto LAB_0010c65b;
1171: LAB_00109004:
1172: sVar4 = psVar9[0x22];
1173: uVar20 = uVar20 + 1;
1174: if (sVar4 == 0) goto LAB_00109016;
1175: LAB_0010c80c:
1176: uVar30 = SEXT24(sVar4);
1177: uVar26 = (int)uVar30 >> 0x1f;
1178: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1179: if (0xf < uVar20) {
1180: if (0x2f < (int)uStack624) {
1181: cVar23 = (char)(int)uStack624;
1182: pcVar15 = pcVar24 + 1;
1183: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1184: *pcVar24 = cVar22;
1185: if (cVar22 == -1) {
1186: pcVar15 = pcVar24 + 2;
1187: pcVar24[1] = '\0';
1188: }
1189: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1190: *pcVar15 = cVar22;
1191: pcVar24 = pcVar15 + 1;
1192: if (cVar22 == -1) {
1193: pcVar24 = pcVar15 + 2;
1194: pcVar15[1] = '\0';
1195: }
1196: pcVar15 = pcVar24 + 1;
1197: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1198: *pcVar24 = cVar22;
1199: if (cVar22 == -1) {
1200: pcVar15 = pcVar24 + 2;
1201: pcVar24[1] = '\0';
1202: }
1203: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1204: *pcVar15 = cVar22;
1205: pcVar24 = pcVar15 + 1;
1206: if (cVar22 == -1) {
1207: pcVar24 = pcVar15 + 2;
1208: pcVar15[1] = '\0';
1209: }
1210: pcVar15 = pcVar24 + 1;
1211: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1212: *pcVar24 = cVar23;
1213: if (cVar23 == -1) {
1214: pcVar15 = pcVar24 + 2;
1215: pcVar24[1] = '\0';
1216: }
1217: uStack624._0_4_ = (int)uStack624 + -0x30;
1218: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1219: *pcVar15 = cVar23;
1220: pcVar24 = pcVar15 + 1;
1221: if (cVar23 == -1) {
1222: pcVar24 = pcVar15 + 2;
1223: pcVar15[1] = '\0';
1224: }
1225: }
1226: uStack624._0_4_ = (int)uStack624 + iVar21;
1227: uVar20 = uVar20 - 0x10;
1228: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1229: }
1230: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1231: iVar17 = piVar8[lVar18];
1232: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1233: if (0x1f < (int)uStack624) {
1234: cVar23 = (char)(int)uStack624;
1235: pcVar15 = pcVar24 + 1;
1236: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1237: *pcVar24 = cVar22;
1238: if (cVar22 == -1) {
1239: pcVar15 = pcVar24 + 2;
1240: pcVar24[1] = '\0';
1241: }
1242: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1243: *pcVar15 = cVar22;
1244: pcVar24 = pcVar15 + 1;
1245: if (cVar22 == -1) {
1246: pcVar24 = pcVar15 + 2;
1247: pcVar15[1] = '\0';
1248: }
1249: pcVar15 = pcVar24 + 1;
1250: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1251: *pcVar24 = cVar23;
1252: if (cVar23 == -1) {
1253: pcVar15 = pcVar24 + 2;
1254: pcVar24[1] = '\0';
1255: }
1256: uStack624._0_4_ = (int)uStack624 + -0x20;
1257: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1258: *pcVar15 = cVar23;
1259: pcVar24 = pcVar15 + 1;
1260: if (cVar23 == -1) {
1261: pcVar24 = pcVar15 + 2;
1262: pcVar15[1] = '\0';
1263: }
1264: }
1265: sVar4 = psVar9[0x1b];
1266: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1267: uVar20 = 0;
1268: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1269: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1270: if (sVar4 != 0) goto LAB_0010c9bd;
1271: LAB_00109028:
1272: sVar4 = psVar9[0x14];
1273: uVar20 = uVar20 + 1;
1274: if (sVar4 == 0) goto LAB_0010903a;
1275: LAB_0010cb6e:
1276: uVar30 = SEXT24(sVar4);
1277: uVar26 = (int)uVar30 >> 0x1f;
1278: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1279: if (0xf < uVar20) {
1280: if (0x2f < (int)uStack624) {
1281: cVar23 = (char)(int)uStack624;
1282: pcVar15 = pcVar24 + 1;
1283: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1284: *pcVar24 = cVar22;
1285: if (cVar22 == -1) {
1286: pcVar15 = pcVar24 + 2;
1287: pcVar24[1] = '\0';
1288: }
1289: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1290: *pcVar15 = cVar22;
1291: pcVar24 = pcVar15 + 1;
1292: if (cVar22 == -1) {
1293: pcVar24 = pcVar15 + 2;
1294: pcVar15[1] = '\0';
1295: }
1296: pcVar15 = pcVar24 + 1;
1297: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1298: *pcVar24 = cVar22;
1299: if (cVar22 == -1) {
1300: pcVar15 = pcVar24 + 2;
1301: pcVar24[1] = '\0';
1302: }
1303: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1304: *pcVar15 = cVar22;
1305: pcVar24 = pcVar15 + 1;
1306: if (cVar22 == -1) {
1307: pcVar24 = pcVar15 + 2;
1308: pcVar15[1] = '\0';
1309: }
1310: pcVar15 = pcVar24 + 1;
1311: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1312: *pcVar24 = cVar23;
1313: if (cVar23 == -1) {
1314: pcVar15 = pcVar24 + 2;
1315: pcVar24[1] = '\0';
1316: }
1317: uStack624._0_4_ = (int)uStack624 + -0x30;
1318: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1319: *pcVar15 = cVar23;
1320: pcVar24 = pcVar15 + 1;
1321: if (cVar23 == -1) {
1322: pcVar24 = pcVar15 + 2;
1323: pcVar15[1] = '\0';
1324: }
1325: }
1326: uStack624._0_4_ = (int)uStack624 + iVar21;
1327: uVar20 = uVar20 - 0x10;
1328: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1329: }
1330: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1331: iVar17 = piVar8[lVar18];
1332: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1333: if (0x1f < (int)uStack624) {
1334: cVar23 = (char)(int)uStack624;
1335: pcVar15 = pcVar24 + 1;
1336: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1337: *pcVar24 = cVar22;
1338: if (cVar22 == -1) {
1339: pcVar15 = pcVar24 + 2;
1340: pcVar24[1] = '\0';
1341: }
1342: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1343: *pcVar15 = cVar22;
1344: pcVar24 = pcVar15 + 1;
1345: if (cVar22 == -1) {
1346: pcVar24 = pcVar15 + 2;
1347: pcVar15[1] = '\0';
1348: }
1349: pcVar15 = pcVar24 + 1;
1350: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1351: *pcVar24 = cVar23;
1352: if (cVar23 == -1) {
1353: pcVar15 = pcVar24 + 2;
1354: pcVar24[1] = '\0';
1355: }
1356: uStack624._0_4_ = (int)uStack624 + -0x20;
1357: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1358: *pcVar15 = cVar23;
1359: pcVar24 = pcVar15 + 1;
1360: if (cVar23 == -1) {
1361: pcVar24 = pcVar15 + 2;
1362: pcVar15[1] = '\0';
1363: }
1364: }
1365: sVar4 = psVar9[0xd];
1366: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1367: uVar20 = 0;
1368: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1369: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1370: if (sVar4 != 0) goto LAB_0010cd1f;
1371: LAB_0010904c:
1372: sVar4 = psVar9[6];
1373: uVar20 = uVar20 + 1;
1374: if (sVar4 == 0) goto LAB_0010905e;
1375: LAB_0010ced0:
1376: uVar30 = SEXT24(sVar4);
1377: uVar26 = (int)uVar30 >> 0x1f;
1378: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1379: if (0xf < uVar20) {
1380: if (0x2f < (int)uStack624) {
1381: cVar23 = (char)(int)uStack624;
1382: pcVar15 = pcVar24 + 1;
1383: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1384: *pcVar24 = cVar22;
1385: if (cVar22 == -1) {
1386: pcVar15 = pcVar24 + 2;
1387: pcVar24[1] = '\0';
1388: }
1389: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1390: *pcVar15 = cVar22;
1391: pcVar24 = pcVar15 + 1;
1392: if (cVar22 == -1) {
1393: pcVar24 = pcVar15 + 2;
1394: pcVar15[1] = '\0';
1395: }
1396: pcVar15 = pcVar24 + 1;
1397: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1398: *pcVar24 = cVar22;
1399: if (cVar22 == -1) {
1400: pcVar15 = pcVar24 + 2;
1401: pcVar24[1] = '\0';
1402: }
1403: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1404: *pcVar15 = cVar22;
1405: pcVar24 = pcVar15 + 1;
1406: if (cVar22 == -1) {
1407: pcVar24 = pcVar15 + 2;
1408: pcVar15[1] = '\0';
1409: }
1410: pcVar15 = pcVar24 + 1;
1411: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1412: *pcVar24 = cVar23;
1413: if (cVar23 == -1) {
1414: pcVar15 = pcVar24 + 2;
1415: pcVar24[1] = '\0';
1416: }
1417: uStack624._0_4_ = (int)uStack624 + -0x30;
1418: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1419: *pcVar15 = cVar23;
1420: pcVar24 = pcVar15 + 1;
1421: if (cVar23 == -1) {
1422: pcVar24 = pcVar15 + 2;
1423: pcVar15[1] = '\0';
1424: }
1425: }
1426: uStack624._0_4_ = (int)uStack624 + iVar21;
1427: uVar20 = uVar20 - 0x10;
1428: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1429: }
1430: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1431: iVar17 = piVar8[lVar18];
1432: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1433: if (0x1f < (int)uStack624) {
1434: cVar23 = (char)(int)uStack624;
1435: pcVar15 = pcVar24 + 1;
1436: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1437: *pcVar24 = cVar22;
1438: if (cVar22 == -1) {
1439: pcVar15 = pcVar24 + 2;
1440: pcVar24[1] = '\0';
1441: }
1442: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1443: *pcVar15 = cVar22;
1444: pcVar24 = pcVar15 + 1;
1445: if (cVar22 == -1) {
1446: pcVar24 = pcVar15 + 2;
1447: pcVar15[1] = '\0';
1448: }
1449: pcVar15 = pcVar24 + 1;
1450: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1451: *pcVar24 = cVar23;
1452: if (cVar23 == -1) {
1453: pcVar15 = pcVar24 + 2;
1454: pcVar24[1] = '\0';
1455: }
1456: uStack624._0_4_ = (int)uStack624 + -0x20;
1457: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1458: *pcVar15 = cVar23;
1459: pcVar24 = pcVar15 + 1;
1460: if (cVar23 == -1) {
1461: pcVar24 = pcVar15 + 2;
1462: pcVar15[1] = '\0';
1463: }
1464: }
1465: sVar4 = psVar9[7];
1466: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1467: uVar20 = 0;
1468: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1469: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1470: if (sVar4 != 0) goto LAB_0010d081;
1471: LAB_00109070:
1472: sVar4 = psVar9[0xe];
1473: uVar20 = uVar20 + 1;
1474: if (sVar4 == 0) goto LAB_00109082;
1475: LAB_0010d232:
1476: uVar30 = SEXT24(sVar4);
1477: uVar26 = (int)uVar30 >> 0x1f;
1478: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1479: if (0xf < uVar20) {
1480: if (0x2f < (int)uStack624) {
1481: cVar23 = (char)(int)uStack624;
1482: pcVar15 = pcVar24 + 1;
1483: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1484: *pcVar24 = cVar22;
1485: if (cVar22 == -1) {
1486: pcVar15 = pcVar24 + 2;
1487: pcVar24[1] = '\0';
1488: }
1489: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1490: *pcVar15 = cVar22;
1491: pcVar24 = pcVar15 + 1;
1492: if (cVar22 == -1) {
1493: pcVar24 = pcVar15 + 2;
1494: pcVar15[1] = '\0';
1495: }
1496: pcVar15 = pcVar24 + 1;
1497: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1498: *pcVar24 = cVar22;
1499: if (cVar22 == -1) {
1500: pcVar15 = pcVar24 + 2;
1501: pcVar24[1] = '\0';
1502: }
1503: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1504: *pcVar15 = cVar22;
1505: pcVar24 = pcVar15 + 1;
1506: if (cVar22 == -1) {
1507: pcVar24 = pcVar15 + 2;
1508: pcVar15[1] = '\0';
1509: }
1510: pcVar15 = pcVar24 + 1;
1511: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1512: *pcVar24 = cVar23;
1513: if (cVar23 == -1) {
1514: pcVar15 = pcVar24 + 2;
1515: pcVar24[1] = '\0';
1516: }
1517: uStack624._0_4_ = (int)uStack624 + -0x30;
1518: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1519: *pcVar15 = cVar23;
1520: pcVar24 = pcVar15 + 1;
1521: if (cVar23 == -1) {
1522: pcVar24 = pcVar15 + 2;
1523: pcVar15[1] = '\0';
1524: }
1525: }
1526: uStack624._0_4_ = (int)uStack624 + iVar21;
1527: uVar20 = uVar20 - 0x10;
1528: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1529: }
1530: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1531: iVar17 = piVar8[lVar18];
1532: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1533: if (0x1f < (int)uStack624) {
1534: cVar23 = (char)(int)uStack624;
1535: pcVar15 = pcVar24 + 1;
1536: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1537: *pcVar24 = cVar22;
1538: if (cVar22 == -1) {
1539: pcVar15 = pcVar24 + 2;
1540: pcVar24[1] = '\0';
1541: }
1542: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1543: *pcVar15 = cVar22;
1544: pcVar24 = pcVar15 + 1;
1545: if (cVar22 == -1) {
1546: pcVar24 = pcVar15 + 2;
1547: pcVar15[1] = '\0';
1548: }
1549: pcVar15 = pcVar24 + 1;
1550: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1551: *pcVar24 = cVar23;
1552: if (cVar23 == -1) {
1553: pcVar15 = pcVar24 + 2;
1554: pcVar24[1] = '\0';
1555: }
1556: uStack624._0_4_ = (int)uStack624 + -0x20;
1557: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1558: *pcVar15 = cVar23;
1559: pcVar24 = pcVar15 + 1;
1560: if (cVar23 == -1) {
1561: pcVar24 = pcVar15 + 2;
1562: pcVar15[1] = '\0';
1563: }
1564: }
1565: sVar4 = psVar9[0x15];
1566: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1567: uVar20 = 0;
1568: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1569: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1570: if (sVar4 != 0) goto LAB_0010d3e3;
1571: LAB_00109094:
1572: sVar4 = psVar9[0x1c];
1573: uVar20 = uVar20 + 1;
1574: if (sVar4 == 0) goto LAB_001090a6;
1575: LAB_0010d594:
1576: uVar30 = SEXT24(sVar4);
1577: uVar26 = (int)uVar30 >> 0x1f;
1578: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1579: if (0xf < uVar20) {
1580: if (0x2f < (int)uStack624) {
1581: cVar23 = (char)(int)uStack624;
1582: pcVar15 = pcVar24 + 1;
1583: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1584: *pcVar24 = cVar22;
1585: if (cVar22 == -1) {
1586: pcVar15 = pcVar24 + 2;
1587: pcVar24[1] = '\0';
1588: }
1589: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1590: *pcVar15 = cVar22;
1591: pcVar24 = pcVar15 + 1;
1592: if (cVar22 == -1) {
1593: pcVar24 = pcVar15 + 2;
1594: pcVar15[1] = '\0';
1595: }
1596: pcVar15 = pcVar24 + 1;
1597: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1598: *pcVar24 = cVar22;
1599: if (cVar22 == -1) {
1600: pcVar15 = pcVar24 + 2;
1601: pcVar24[1] = '\0';
1602: }
1603: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1604: *pcVar15 = cVar22;
1605: pcVar24 = pcVar15 + 1;
1606: if (cVar22 == -1) {
1607: pcVar24 = pcVar15 + 2;
1608: pcVar15[1] = '\0';
1609: }
1610: pcVar15 = pcVar24 + 1;
1611: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1612: *pcVar24 = cVar23;
1613: if (cVar23 == -1) {
1614: pcVar15 = pcVar24 + 2;
1615: pcVar24[1] = '\0';
1616: }
1617: uStack624._0_4_ = (int)uStack624 + -0x30;
1618: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1619: *pcVar15 = cVar23;
1620: pcVar24 = pcVar15 + 1;
1621: if (cVar23 == -1) {
1622: pcVar24 = pcVar15 + 2;
1623: pcVar15[1] = '\0';
1624: }
1625: }
1626: uStack624._0_4_ = (int)uStack624 + iVar21;
1627: uVar20 = uVar20 - 0x10;
1628: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1629: }
1630: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1631: iVar17 = piVar8[lVar18];
1632: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1633: if (0x1f < (int)uStack624) {
1634: cVar23 = (char)(int)uStack624;
1635: pcVar15 = pcVar24 + 1;
1636: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1637: *pcVar24 = cVar22;
1638: if (cVar22 == -1) {
1639: pcVar15 = pcVar24 + 2;
1640: pcVar24[1] = '\0';
1641: }
1642: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1643: *pcVar15 = cVar22;
1644: pcVar24 = pcVar15 + 1;
1645: if (cVar22 == -1) {
1646: pcVar24 = pcVar15 + 2;
1647: pcVar15[1] = '\0';
1648: }
1649: pcVar15 = pcVar24 + 1;
1650: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1651: *pcVar24 = cVar23;
1652: if (cVar23 == -1) {
1653: pcVar15 = pcVar24 + 2;
1654: pcVar24[1] = '\0';
1655: }
1656: uStack624._0_4_ = (int)uStack624 + -0x20;
1657: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1658: *pcVar15 = cVar23;
1659: pcVar24 = pcVar15 + 1;
1660: if (cVar23 == -1) {
1661: pcVar24 = pcVar15 + 2;
1662: pcVar15[1] = '\0';
1663: }
1664: }
1665: sVar4 = psVar9[0x23];
1666: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1667: uVar20 = 0;
1668: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1669: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1670: if (sVar4 != 0) goto LAB_0010d745;
1671: LAB_001090b8:
1672: sVar4 = psVar9[0x2a];
1673: uVar20 = uVar20 + 1;
1674: if (sVar4 == 0) goto LAB_001090ca;
1675: LAB_0010d8f6:
1676: uVar30 = SEXT24(sVar4);
1677: uVar27 = (ulong)uVar20;
1678: uVar26 = (int)uVar30 >> 0x1f;
1679: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1680: if (0xf < (int)uVar20) {
1681: while( true ) {
1682: if (0x2f < (int)uStack624) {
1683: cVar23 = (char)(int)uStack624;
1684: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1685: *pcVar24 = cVar22;
1686: pcVar15 = pcVar24 + 1;
1687: if (cVar22 == -1) {
1688: pcVar15 = pcVar24 + 2;
1689: pcVar24[1] = '\0';
1690: }
1691: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1692: *pcVar15 = cVar22;
1693: pcVar24 = pcVar15 + 1;
1694: if (cVar22 == -1) {
1695: pcVar24 = pcVar15 + 2;
1696: pcVar15[1] = '\0';
1697: }
1698: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1699: *pcVar24 = cVar22;
1700: pcVar15 = pcVar24 + 1;
1701: if (cVar22 == -1) {
1702: pcVar15 = pcVar24 + 2;
1703: pcVar24[1] = '\0';
1704: }
1705: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1706: *pcVar15 = cVar22;
1707: pcVar24 = pcVar15 + 1;
1708: if (cVar22 == -1) {
1709: pcVar24 = pcVar15 + 2;
1710: pcVar15[1] = '\0';
1711: }
1712: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1713: *pcVar24 = cVar23;
1714: pcVar15 = pcVar24 + 1;
1715: if (cVar23 == -1) {
1716: pcVar15 = pcVar24 + 2;
1717: pcVar24[1] = '\0';
1718: }
1719: uStack624._0_4_ = (int)uStack624 + -0x30;
1720: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1721: *pcVar15 = cVar23;
1722: pcVar24 = pcVar15 + 1;
1723: if (cVar23 == -1) {
1724: pcVar24 = pcVar15 + 2;
1725: pcVar15[1] = '\0';
1726: }
1727: }
1728: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1729: uStack624._0_4_ = (int)uStack624 + iVar21;
1730: if ((int)uVar27 != 0x20) break;
1731: uVar27 = CONCAT71((int7)(uVar27 >> 8),0x10);
1732: }
1733: uVar20 = uVar20 & 0xf;
1734: }
1735: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1736: iVar17 = piVar8[lVar18];
1737: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1738: if (0x1f < (int)uStack624) {
1739: cVar23 = (char)(int)uStack624;
1740: pcVar15 = pcVar24 + 1;
1741: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1742: *pcVar24 = cVar22;
1743: if (cVar22 == -1) {
1744: pcVar15 = pcVar24 + 2;
1745: pcVar24[1] = '\0';
1746: }
1747: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1748: *pcVar15 = cVar22;
1749: pcVar24 = pcVar15 + 1;
1750: if (cVar22 == -1) {
1751: pcVar24 = pcVar15 + 2;
1752: pcVar15[1] = '\0';
1753: }
1754: pcVar15 = pcVar24 + 1;
1755: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1756: *pcVar24 = cVar23;
1757: if (cVar23 == -1) {
1758: pcVar15 = pcVar24 + 2;
1759: pcVar24[1] = '\0';
1760: }
1761: uStack624._0_4_ = (int)uStack624 + -0x20;
1762: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1763: *pcVar15 = cVar23;
1764: pcVar24 = pcVar15 + 1;
1765: if (cVar23 == -1) {
1766: pcVar24 = pcVar15 + 2;
1767: pcVar15[1] = '\0';
1768: }
1769: }
1770: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1771: uVar20 = 0;
1772: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1773: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1774: }
1775: else {
1776: uVar26 = (int)uVar20 >> 0x1f;
1777: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar20) - uVar26)];
1778: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
1779: iVar17 = piVar8[lVar18];
1780: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1781: if (0x1f < (int)uStack624) {
1782: cVar23 = (char)(int)uStack624;
1783: pcVar15 = pcVar24 + 1;
1784: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1785: *pcVar24 = cVar22;
1786: if (cVar22 == -1) {
1787: pcVar15 = pcVar24 + 2;
1788: pcVar24[1] = '\0';
1789: }
1790: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1791: *pcVar15 = cVar22;
1792: pcVar24 = pcVar15 + 1;
1793: if (cVar22 == -1) {
1794: pcVar24 = pcVar15 + 2;
1795: pcVar15[1] = '\0';
1796: }
1797: pcVar15 = pcVar24 + 1;
1798: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1799: *pcVar24 = cVar23;
1800: if (cVar23 == -1) {
1801: pcVar15 = pcVar24 + 2;
1802: pcVar24[1] = '\0';
1803: }
1804: uStack624._0_4_ = (int)uStack624 + -0x20;
1805: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1806: *pcVar15 = cVar23;
1807: pcVar24 = pcVar15 + 1;
1808: if (cVar23 == -1) {
1809: pcVar24 = pcVar15 + 2;
1810: pcVar15[1] = '\0';
1811: }
1812: }
1813: sVar4 = psVar9[5];
1814: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1815: iVar28 = 0;
1816: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1817: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar20 + uVar26);
1818: if (sVar4 != 0) goto LAB_0010bc19;
1819: LAB_00108f86:
1820: sVar4 = psVar9[0xc];
1821: iVar28 = iVar28 + 1;
1822: if (sVar4 == 0) goto LAB_00108f98;
1823: LAB_0010bd02:
1824: uVar26 = SEXT24(sVar4);
1825: uVar20 = (int)uVar26 >> 0x1f;
1826: bVar2 = (&DAT_00168f80)[(int)((uVar20 ^ uVar26) - uVar20)];
1827: lVar18 = (long)(int)(iVar28 * 0x10 + (uint)bVar2);
1828: iVar17 = piVar8[lVar18];
1829: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1830: if (0x1f < (int)uStack624) {
1831: cVar23 = (char)(int)uStack624;
1832: pcVar15 = pcVar24 + 1;
1833: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1834: *pcVar24 = cVar22;
1835: if (cVar22 == -1) {
1836: pcVar15 = pcVar24 + 2;
1837: pcVar24[1] = '\0';
1838: }
1839: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1840: *pcVar15 = cVar22;
1841: pcVar24 = pcVar15 + 1;
1842: if (cVar22 == -1) {
1843: pcVar24 = pcVar15 + 2;
1844: pcVar15[1] = '\0';
1845: }
1846: pcVar15 = pcVar24 + 1;
1847: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1848: *pcVar24 = cVar23;
1849: if (cVar23 == -1) {
1850: pcVar15 = pcVar24 + 2;
1851: pcVar24[1] = '\0';
1852: }
1853: uStack624._0_4_ = (int)uStack624 + -0x20;
1854: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1855: *pcVar15 = cVar23;
1856: pcVar24 = pcVar15 + 1;
1857: if (cVar23 == -1) {
1858: pcVar24 = pcVar15 + 2;
1859: pcVar15[1] = '\0';
1860: }
1861: }
1862: sVar4 = psVar9[0x13];
1863: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1864: iVar28 = 0;
1865: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1866: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar20);
1867: if (sVar4 != 0) goto LAB_0010bdeb;
1868: LAB_00108faa:
1869: sVar4 = psVar9[0x1a];
1870: uVar20 = iVar28 + 1;
1871: if (sVar4 == 0) goto LAB_00108fbc;
1872: LAB_0010bf97:
1873: uVar30 = SEXT24(sVar4);
1874: uVar26 = (int)uVar30 >> 0x1f;
1875: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1876: if (0xf < uVar20) {
1877: if (0x2f < (int)uStack624) {
1878: cVar23 = (char)(int)uStack624;
1879: pcVar15 = pcVar24 + 1;
1880: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1881: *pcVar24 = cVar22;
1882: if (cVar22 == -1) {
1883: pcVar15 = pcVar24 + 2;
1884: pcVar24[1] = '\0';
1885: }
1886: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1887: *pcVar15 = cVar22;
1888: pcVar24 = pcVar15 + 1;
1889: if (cVar22 == -1) {
1890: pcVar24 = pcVar15 + 2;
1891: pcVar15[1] = '\0';
1892: }
1893: pcVar15 = pcVar24 + 1;
1894: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1895: *pcVar24 = cVar22;
1896: if (cVar22 == -1) {
1897: pcVar15 = pcVar24 + 2;
1898: pcVar24[1] = '\0';
1899: }
1900: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
1901: *pcVar15 = cVar22;
1902: pcVar24 = pcVar15 + 1;
1903: if (cVar22 == -1) {
1904: pcVar24 = pcVar15 + 2;
1905: pcVar15[1] = '\0';
1906: }
1907: pcVar15 = pcVar24 + 1;
1908: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
1909: *pcVar24 = cVar23;
1910: if (cVar23 == -1) {
1911: pcVar15 = pcVar24 + 2;
1912: pcVar24[1] = '\0';
1913: }
1914: uStack624._0_4_ = (int)uStack624 + -0x30;
1915: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1916: *pcVar15 = cVar23;
1917: pcVar24 = pcVar15 + 1;
1918: if (cVar23 == -1) {
1919: pcVar24 = pcVar15 + 2;
1920: pcVar15[1] = '\0';
1921: }
1922: }
1923: uStack624._0_4_ = (int)uStack624 + iVar21;
1924: uVar20 = uVar20 - 0x10;
1925: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
1926: }
1927: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
1928: iVar17 = piVar8[lVar18];
1929: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
1930: if (0x1f < (int)uStack624) {
1931: cVar23 = (char)(int)uStack624;
1932: pcVar15 = pcVar24 + 1;
1933: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1934: *pcVar24 = cVar22;
1935: if (cVar22 == -1) {
1936: pcVar15 = pcVar24 + 2;
1937: pcVar24[1] = '\0';
1938: }
1939: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1940: *pcVar15 = cVar22;
1941: pcVar24 = pcVar15 + 1;
1942: if (cVar22 == -1) {
1943: pcVar24 = pcVar15 + 2;
1944: pcVar15[1] = '\0';
1945: }
1946: pcVar15 = pcVar24 + 1;
1947: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1948: *pcVar24 = cVar23;
1949: if (cVar23 == -1) {
1950: pcVar15 = pcVar24 + 2;
1951: pcVar24[1] = '\0';
1952: }
1953: uStack624._0_4_ = (int)uStack624 + -0x20;
1954: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
1955: *pcVar15 = cVar23;
1956: pcVar24 = pcVar15 + 1;
1957: if (cVar23 == -1) {
1958: pcVar24 = pcVar15 + 2;
1959: pcVar15[1] = '\0';
1960: }
1961: }
1962: sVar4 = psVar9[0x21];
1963: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
1964: uVar20 = 0;
1965: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
1966: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
1967: if (sVar4 != 0) goto LAB_0010c148;
1968: LAB_00108fce:
1969: sVar4 = psVar9[0x28];
1970: uVar20 = uVar20 + 1;
1971: if (sVar4 == 0) goto LAB_00108fe0;
1972: LAB_0010c2f9:
1973: uVar30 = SEXT24(sVar4);
1974: uVar26 = (int)uVar30 >> 0x1f;
1975: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
1976: if (0xf < uVar20) {
1977: if (0x2f < (int)uStack624) {
1978: cVar23 = (char)(int)uStack624;
1979: pcVar15 = pcVar24 + 1;
1980: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
1981: *pcVar24 = cVar22;
1982: if (cVar22 == -1) {
1983: pcVar15 = pcVar24 + 2;
1984: pcVar24[1] = '\0';
1985: }
1986: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
1987: *pcVar15 = cVar22;
1988: pcVar24 = pcVar15 + 1;
1989: if (cVar22 == -1) {
1990: pcVar24 = pcVar15 + 2;
1991: pcVar15[1] = '\0';
1992: }
1993: pcVar15 = pcVar24 + 1;
1994: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
1995: *pcVar24 = cVar22;
1996: if (cVar22 == -1) {
1997: pcVar15 = pcVar24 + 2;
1998: pcVar24[1] = '\0';
1999: }
2000: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2001: *pcVar15 = cVar22;
2002: pcVar24 = pcVar15 + 1;
2003: if (cVar22 == -1) {
2004: pcVar24 = pcVar15 + 2;
2005: pcVar15[1] = '\0';
2006: }
2007: pcVar15 = pcVar24 + 1;
2008: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2009: *pcVar24 = cVar23;
2010: if (cVar23 == -1) {
2011: pcVar15 = pcVar24 + 2;
2012: pcVar24[1] = '\0';
2013: }
2014: uStack624._0_4_ = (int)uStack624 + -0x30;
2015: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2016: *pcVar15 = cVar23;
2017: pcVar24 = pcVar15 + 1;
2018: if (cVar23 == -1) {
2019: pcVar24 = pcVar15 + 2;
2020: pcVar15[1] = '\0';
2021: }
2022: }
2023: uStack624._0_4_ = (int)uStack624 + iVar21;
2024: uVar20 = uVar20 - 0x10;
2025: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2026: }
2027: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2028: iVar17 = piVar8[lVar18];
2029: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2030: if (0x1f < (int)uStack624) {
2031: cVar23 = (char)(int)uStack624;
2032: pcVar15 = pcVar24 + 1;
2033: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2034: *pcVar24 = cVar22;
2035: if (cVar22 == -1) {
2036: pcVar15 = pcVar24 + 2;
2037: pcVar24[1] = '\0';
2038: }
2039: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2040: *pcVar15 = cVar22;
2041: pcVar24 = pcVar15 + 1;
2042: if (cVar22 == -1) {
2043: pcVar24 = pcVar15 + 2;
2044: pcVar15[1] = '\0';
2045: }
2046: pcVar15 = pcVar24 + 1;
2047: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2048: *pcVar24 = cVar23;
2049: if (cVar23 == -1) {
2050: pcVar15 = pcVar24 + 2;
2051: pcVar24[1] = '\0';
2052: }
2053: uStack624._0_4_ = (int)uStack624 + -0x20;
2054: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2055: *pcVar15 = cVar23;
2056: pcVar24 = pcVar15 + 1;
2057: if (cVar23 == -1) {
2058: pcVar24 = pcVar15 + 2;
2059: pcVar15[1] = '\0';
2060: }
2061: }
2062: sVar4 = psVar9[0x30];
2063: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2064: uVar20 = 0;
2065: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2066: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
2067: if (sVar4 != 0) goto LAB_0010c4aa;
2068: LAB_00108ff2:
2069: sVar4 = psVar9[0x29];
2070: uVar20 = uVar20 + 1;
2071: if (sVar4 == 0) goto LAB_00109004;
2072: LAB_0010c65b:
2073: uVar30 = SEXT24(sVar4);
2074: uVar26 = (int)uVar30 >> 0x1f;
2075: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
2076: if (0xf < uVar20) {
2077: if (0x2f < (int)uStack624) {
2078: cVar23 = (char)(int)uStack624;
2079: pcVar15 = pcVar24 + 1;
2080: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2081: *pcVar24 = cVar22;
2082: if (cVar22 == -1) {
2083: pcVar15 = pcVar24 + 2;
2084: pcVar24[1] = '\0';
2085: }
2086: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2087: *pcVar15 = cVar22;
2088: pcVar24 = pcVar15 + 1;
2089: if (cVar22 == -1) {
2090: pcVar24 = pcVar15 + 2;
2091: pcVar15[1] = '\0';
2092: }
2093: pcVar15 = pcVar24 + 1;
2094: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2095: *pcVar24 = cVar22;
2096: if (cVar22 == -1) {
2097: pcVar15 = pcVar24 + 2;
2098: pcVar24[1] = '\0';
2099: }
2100: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2101: *pcVar15 = cVar22;
2102: pcVar24 = pcVar15 + 1;
2103: if (cVar22 == -1) {
2104: pcVar24 = pcVar15 + 2;
2105: pcVar15[1] = '\0';
2106: }
2107: pcVar15 = pcVar24 + 1;
2108: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2109: *pcVar24 = cVar23;
2110: if (cVar23 == -1) {
2111: pcVar15 = pcVar24 + 2;
2112: pcVar24[1] = '\0';
2113: }
2114: uStack624._0_4_ = (int)uStack624 + -0x30;
2115: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2116: *pcVar15 = cVar23;
2117: pcVar24 = pcVar15 + 1;
2118: if (cVar23 == -1) {
2119: pcVar24 = pcVar15 + 2;
2120: pcVar15[1] = '\0';
2121: }
2122: }
2123: uStack624._0_4_ = (int)uStack624 + iVar21;
2124: uVar20 = uVar20 - 0x10;
2125: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2126: }
2127: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2128: iVar17 = piVar8[lVar18];
2129: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2130: if (0x1f < (int)uStack624) {
2131: cVar23 = (char)(int)uStack624;
2132: pcVar15 = pcVar24 + 1;
2133: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2134: *pcVar24 = cVar22;
2135: if (cVar22 == -1) {
2136: pcVar15 = pcVar24 + 2;
2137: pcVar24[1] = '\0';
2138: }
2139: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2140: *pcVar15 = cVar22;
2141: pcVar24 = pcVar15 + 1;
2142: if (cVar22 == -1) {
2143: pcVar24 = pcVar15 + 2;
2144: pcVar15[1] = '\0';
2145: }
2146: pcVar15 = pcVar24 + 1;
2147: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2148: *pcVar24 = cVar23;
2149: if (cVar23 == -1) {
2150: pcVar15 = pcVar24 + 2;
2151: pcVar24[1] = '\0';
2152: }
2153: uStack624._0_4_ = (int)uStack624 + -0x20;
2154: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2155: *pcVar15 = cVar23;
2156: pcVar24 = pcVar15 + 1;
2157: if (cVar23 == -1) {
2158: pcVar24 = pcVar15 + 2;
2159: pcVar15[1] = '\0';
2160: }
2161: }
2162: sVar4 = psVar9[0x22];
2163: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2164: uVar20 = 0;
2165: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2166: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
2167: if (sVar4 != 0) goto LAB_0010c80c;
2168: LAB_00109016:
2169: sVar4 = psVar9[0x1b];
2170: uVar20 = uVar20 + 1;
2171: if (sVar4 == 0) goto LAB_00109028;
2172: LAB_0010c9bd:
2173: uVar30 = SEXT24(sVar4);
2174: uVar26 = (int)uVar30 >> 0x1f;
2175: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
2176: if (0xf < uVar20) {
2177: if (0x2f < (int)uStack624) {
2178: cVar23 = (char)(int)uStack624;
2179: pcVar15 = pcVar24 + 1;
2180: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2181: *pcVar24 = cVar22;
2182: if (cVar22 == -1) {
2183: pcVar15 = pcVar24 + 2;
2184: pcVar24[1] = '\0';
2185: }
2186: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2187: *pcVar15 = cVar22;
2188: pcVar24 = pcVar15 + 1;
2189: if (cVar22 == -1) {
2190: pcVar24 = pcVar15 + 2;
2191: pcVar15[1] = '\0';
2192: }
2193: pcVar15 = pcVar24 + 1;
2194: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2195: *pcVar24 = cVar22;
2196: if (cVar22 == -1) {
2197: pcVar15 = pcVar24 + 2;
2198: pcVar24[1] = '\0';
2199: }
2200: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2201: *pcVar15 = cVar22;
2202: pcVar24 = pcVar15 + 1;
2203: if (cVar22 == -1) {
2204: pcVar24 = pcVar15 + 2;
2205: pcVar15[1] = '\0';
2206: }
2207: pcVar15 = pcVar24 + 1;
2208: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2209: *pcVar24 = cVar23;
2210: if (cVar23 == -1) {
2211: pcVar15 = pcVar24 + 2;
2212: pcVar24[1] = '\0';
2213: }
2214: uStack624._0_4_ = (int)uStack624 + -0x30;
2215: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2216: *pcVar15 = cVar23;
2217: pcVar24 = pcVar15 + 1;
2218: if (cVar23 == -1) {
2219: pcVar24 = pcVar15 + 2;
2220: pcVar15[1] = '\0';
2221: }
2222: }
2223: uStack624._0_4_ = (int)uStack624 + iVar21;
2224: uVar20 = uVar20 - 0x10;
2225: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2226: }
2227: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2228: iVar17 = piVar8[lVar18];
2229: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2230: if (0x1f < (int)uStack624) {
2231: cVar23 = (char)(int)uStack624;
2232: pcVar15 = pcVar24 + 1;
2233: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2234: *pcVar24 = cVar22;
2235: if (cVar22 == -1) {
2236: pcVar15 = pcVar24 + 2;
2237: pcVar24[1] = '\0';
2238: }
2239: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2240: *pcVar15 = cVar22;
2241: pcVar24 = pcVar15 + 1;
2242: if (cVar22 == -1) {
2243: pcVar24 = pcVar15 + 2;
2244: pcVar15[1] = '\0';
2245: }
2246: pcVar15 = pcVar24 + 1;
2247: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2248: *pcVar24 = cVar23;
2249: if (cVar23 == -1) {
2250: pcVar15 = pcVar24 + 2;
2251: pcVar24[1] = '\0';
2252: }
2253: uStack624._0_4_ = (int)uStack624 + -0x20;
2254: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2255: *pcVar15 = cVar23;
2256: pcVar24 = pcVar15 + 1;
2257: if (cVar23 == -1) {
2258: pcVar24 = pcVar15 + 2;
2259: pcVar15[1] = '\0';
2260: }
2261: }
2262: sVar4 = psVar9[0x14];
2263: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2264: uVar20 = 0;
2265: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2266: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
2267: if (sVar4 != 0) goto LAB_0010cb6e;
2268: LAB_0010903a:
2269: sVar4 = psVar9[0xd];
2270: uVar20 = uVar20 + 1;
2271: if (sVar4 == 0) goto LAB_0010904c;
2272: LAB_0010cd1f:
2273: uVar30 = SEXT24(sVar4);
2274: uVar26 = (int)uVar30 >> 0x1f;
2275: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
2276: if (0xf < uVar20) {
2277: if (0x2f < (int)uStack624) {
2278: cVar23 = (char)(int)uStack624;
2279: pcVar15 = pcVar24 + 1;
2280: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2281: *pcVar24 = cVar22;
2282: if (cVar22 == -1) {
2283: pcVar15 = pcVar24 + 2;
2284: pcVar24[1] = '\0';
2285: }
2286: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2287: *pcVar15 = cVar22;
2288: pcVar24 = pcVar15 + 1;
2289: if (cVar22 == -1) {
2290: pcVar24 = pcVar15 + 2;
2291: pcVar15[1] = '\0';
2292: }
2293: pcVar15 = pcVar24 + 1;
2294: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2295: *pcVar24 = cVar22;
2296: if (cVar22 == -1) {
2297: pcVar15 = pcVar24 + 2;
2298: pcVar24[1] = '\0';
2299: }
2300: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2301: *pcVar15 = cVar22;
2302: pcVar24 = pcVar15 + 1;
2303: if (cVar22 == -1) {
2304: pcVar24 = pcVar15 + 2;
2305: pcVar15[1] = '\0';
2306: }
2307: pcVar15 = pcVar24 + 1;
2308: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2309: *pcVar24 = cVar23;
2310: if (cVar23 == -1) {
2311: pcVar15 = pcVar24 + 2;
2312: pcVar24[1] = '\0';
2313: }
2314: uStack624._0_4_ = (int)uStack624 + -0x30;
2315: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2316: *pcVar15 = cVar23;
2317: pcVar24 = pcVar15 + 1;
2318: if (cVar23 == -1) {
2319: pcVar24 = pcVar15 + 2;
2320: pcVar15[1] = '\0';
2321: }
2322: }
2323: uStack624._0_4_ = (int)uStack624 + iVar21;
2324: uVar20 = uVar20 - 0x10;
2325: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2326: }
2327: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2328: iVar17 = piVar8[lVar18];
2329: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2330: if (0x1f < (int)uStack624) {
2331: cVar23 = (char)(int)uStack624;
2332: pcVar15 = pcVar24 + 1;
2333: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2334: *pcVar24 = cVar22;
2335: if (cVar22 == -1) {
2336: pcVar15 = pcVar24 + 2;
2337: pcVar24[1] = '\0';
2338: }
2339: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2340: *pcVar15 = cVar22;
2341: pcVar24 = pcVar15 + 1;
2342: if (cVar22 == -1) {
2343: pcVar24 = pcVar15 + 2;
2344: pcVar15[1] = '\0';
2345: }
2346: pcVar15 = pcVar24 + 1;
2347: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2348: *pcVar24 = cVar23;
2349: if (cVar23 == -1) {
2350: pcVar15 = pcVar24 + 2;
2351: pcVar24[1] = '\0';
2352: }
2353: uStack624._0_4_ = (int)uStack624 + -0x20;
2354: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2355: *pcVar15 = cVar23;
2356: pcVar24 = pcVar15 + 1;
2357: if (cVar23 == -1) {
2358: pcVar24 = pcVar15 + 2;
2359: pcVar15[1] = '\0';
2360: }
2361: }
2362: sVar4 = psVar9[6];
2363: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2364: uVar20 = 0;
2365: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2366: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
2367: if (sVar4 != 0) goto LAB_0010ced0;
2368: LAB_0010905e:
2369: sVar4 = psVar9[7];
2370: uVar20 = uVar20 + 1;
2371: if (sVar4 == 0) goto LAB_00109070;
2372: LAB_0010d081:
2373: uVar30 = SEXT24(sVar4);
2374: uVar26 = (int)uVar30 >> 0x1f;
2375: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
2376: if (0xf < uVar20) {
2377: if (0x2f < (int)uStack624) {
2378: cVar23 = (char)(int)uStack624;
2379: pcVar15 = pcVar24 + 1;
2380: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2381: *pcVar24 = cVar22;
2382: if (cVar22 == -1) {
2383: pcVar15 = pcVar24 + 2;
2384: pcVar24[1] = '\0';
2385: }
2386: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2387: *pcVar15 = cVar22;
2388: pcVar24 = pcVar15 + 1;
2389: if (cVar22 == -1) {
2390: pcVar24 = pcVar15 + 2;
2391: pcVar15[1] = '\0';
2392: }
2393: pcVar15 = pcVar24 + 1;
2394: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2395: *pcVar24 = cVar22;
2396: if (cVar22 == -1) {
2397: pcVar15 = pcVar24 + 2;
2398: pcVar24[1] = '\0';
2399: }
2400: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2401: *pcVar15 = cVar22;
2402: pcVar24 = pcVar15 + 1;
2403: if (cVar22 == -1) {
2404: pcVar24 = pcVar15 + 2;
2405: pcVar15[1] = '\0';
2406: }
2407: pcVar15 = pcVar24 + 1;
2408: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2409: *pcVar24 = cVar23;
2410: if (cVar23 == -1) {
2411: pcVar15 = pcVar24 + 2;
2412: pcVar24[1] = '\0';
2413: }
2414: uStack624._0_4_ = (int)uStack624 + -0x30;
2415: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2416: *pcVar15 = cVar23;
2417: pcVar24 = pcVar15 + 1;
2418: if (cVar23 == -1) {
2419: pcVar24 = pcVar15 + 2;
2420: pcVar15[1] = '\0';
2421: }
2422: }
2423: uStack624._0_4_ = (int)uStack624 + iVar21;
2424: uVar20 = uVar20 - 0x10;
2425: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2426: }
2427: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2428: iVar17 = piVar8[lVar18];
2429: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2430: if (0x1f < (int)uStack624) {
2431: cVar23 = (char)(int)uStack624;
2432: pcVar15 = pcVar24 + 1;
2433: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2434: *pcVar24 = cVar22;
2435: if (cVar22 == -1) {
2436: pcVar15 = pcVar24 + 2;
2437: pcVar24[1] = '\0';
2438: }
2439: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2440: *pcVar15 = cVar22;
2441: pcVar24 = pcVar15 + 1;
2442: if (cVar22 == -1) {
2443: pcVar24 = pcVar15 + 2;
2444: pcVar15[1] = '\0';
2445: }
2446: pcVar15 = pcVar24 + 1;
2447: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2448: *pcVar24 = cVar23;
2449: if (cVar23 == -1) {
2450: pcVar15 = pcVar24 + 2;
2451: pcVar24[1] = '\0';
2452: }
2453: uStack624._0_4_ = (int)uStack624 + -0x20;
2454: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2455: *pcVar15 = cVar23;
2456: pcVar24 = pcVar15 + 1;
2457: if (cVar23 == -1) {
2458: pcVar24 = pcVar15 + 2;
2459: pcVar15[1] = '\0';
2460: }
2461: }
2462: sVar4 = psVar9[0xe];
2463: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2464: uVar20 = 0;
2465: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2466: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
2467: if (sVar4 != 0) goto LAB_0010d232;
2468: LAB_00109082:
2469: sVar4 = psVar9[0x15];
2470: uVar20 = uVar20 + 1;
2471: if (sVar4 == 0) goto LAB_00109094;
2472: LAB_0010d3e3:
2473: uVar30 = SEXT24(sVar4);
2474: uVar26 = (int)uVar30 >> 0x1f;
2475: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
2476: if (0xf < uVar20) {
2477: if (0x2f < (int)uStack624) {
2478: cVar23 = (char)(int)uStack624;
2479: pcVar15 = pcVar24 + 1;
2480: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2481: *pcVar24 = cVar22;
2482: if (cVar22 == -1) {
2483: pcVar15 = pcVar24 + 2;
2484: pcVar24[1] = '\0';
2485: }
2486: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2487: *pcVar15 = cVar22;
2488: pcVar24 = pcVar15 + 1;
2489: if (cVar22 == -1) {
2490: pcVar24 = pcVar15 + 2;
2491: pcVar15[1] = '\0';
2492: }
2493: pcVar15 = pcVar24 + 1;
2494: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2495: *pcVar24 = cVar22;
2496: if (cVar22 == -1) {
2497: pcVar15 = pcVar24 + 2;
2498: pcVar24[1] = '\0';
2499: }
2500: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2501: *pcVar15 = cVar22;
2502: pcVar24 = pcVar15 + 1;
2503: if (cVar22 == -1) {
2504: pcVar24 = pcVar15 + 2;
2505: pcVar15[1] = '\0';
2506: }
2507: pcVar15 = pcVar24 + 1;
2508: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2509: *pcVar24 = cVar23;
2510: if (cVar23 == -1) {
2511: pcVar15 = pcVar24 + 2;
2512: pcVar24[1] = '\0';
2513: }
2514: uStack624._0_4_ = (int)uStack624 + -0x30;
2515: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2516: *pcVar15 = cVar23;
2517: pcVar24 = pcVar15 + 1;
2518: if (cVar23 == -1) {
2519: pcVar24 = pcVar15 + 2;
2520: pcVar15[1] = '\0';
2521: }
2522: }
2523: uStack624._0_4_ = (int)uStack624 + iVar21;
2524: uVar20 = uVar20 - 0x10;
2525: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2526: }
2527: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2528: iVar17 = piVar8[lVar18];
2529: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2530: if (0x1f < (int)uStack624) {
2531: cVar23 = (char)(int)uStack624;
2532: pcVar15 = pcVar24 + 1;
2533: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2534: *pcVar24 = cVar22;
2535: if (cVar22 == -1) {
2536: pcVar15 = pcVar24 + 2;
2537: pcVar24[1] = '\0';
2538: }
2539: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2540: *pcVar15 = cVar22;
2541: pcVar24 = pcVar15 + 1;
2542: if (cVar22 == -1) {
2543: pcVar24 = pcVar15 + 2;
2544: pcVar15[1] = '\0';
2545: }
2546: pcVar15 = pcVar24 + 1;
2547: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2548: *pcVar24 = cVar23;
2549: if (cVar23 == -1) {
2550: pcVar15 = pcVar24 + 2;
2551: pcVar24[1] = '\0';
2552: }
2553: uStack624._0_4_ = (int)uStack624 + -0x20;
2554: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2555: *pcVar15 = cVar23;
2556: pcVar24 = pcVar15 + 1;
2557: if (cVar23 == -1) {
2558: pcVar24 = pcVar15 + 2;
2559: pcVar15[1] = '\0';
2560: }
2561: }
2562: sVar4 = psVar9[0x1c];
2563: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2564: uVar20 = 0;
2565: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2566: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
2567: if (sVar4 != 0) goto LAB_0010d594;
2568: LAB_001090a6:
2569: sVar4 = psVar9[0x23];
2570: uVar20 = uVar20 + 1;
2571: if (sVar4 == 0) goto LAB_001090b8;
2572: LAB_0010d745:
2573: uVar30 = SEXT24(sVar4);
2574: uVar26 = (int)uVar30 >> 0x1f;
2575: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
2576: if (0xf < uVar20) {
2577: if (0x2f < (int)uStack624) {
2578: cVar23 = (char)(int)uStack624;
2579: pcVar15 = pcVar24 + 1;
2580: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2581: *pcVar24 = cVar22;
2582: if (cVar22 == -1) {
2583: pcVar15 = pcVar24 + 2;
2584: pcVar24[1] = '\0';
2585: }
2586: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2587: *pcVar15 = cVar22;
2588: pcVar24 = pcVar15 + 1;
2589: if (cVar22 == -1) {
2590: pcVar24 = pcVar15 + 2;
2591: pcVar15[1] = '\0';
2592: }
2593: pcVar15 = pcVar24 + 1;
2594: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2595: *pcVar24 = cVar22;
2596: if (cVar22 == -1) {
2597: pcVar15 = pcVar24 + 2;
2598: pcVar24[1] = '\0';
2599: }
2600: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2601: *pcVar15 = cVar22;
2602: pcVar24 = pcVar15 + 1;
2603: if (cVar22 == -1) {
2604: pcVar24 = pcVar15 + 2;
2605: pcVar15[1] = '\0';
2606: }
2607: pcVar15 = pcVar24 + 1;
2608: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2609: *pcVar24 = cVar23;
2610: if (cVar23 == -1) {
2611: pcVar15 = pcVar24 + 2;
2612: pcVar24[1] = '\0';
2613: }
2614: uStack624._0_4_ = (int)uStack624 + -0x30;
2615: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2616: *pcVar15 = cVar23;
2617: pcVar24 = pcVar15 + 1;
2618: if (cVar23 == -1) {
2619: pcVar24 = pcVar15 + 2;
2620: pcVar15[1] = '\0';
2621: }
2622: }
2623: uStack624._0_4_ = (int)uStack624 + iVar21;
2624: uVar20 = uVar20 - 0x10;
2625: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2626: }
2627: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2628: iVar17 = piVar8[lVar18];
2629: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2630: if (0x1f < (int)uStack624) {
2631: cVar23 = (char)(int)uStack624;
2632: pcVar15 = pcVar24 + 1;
2633: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2634: *pcVar24 = cVar22;
2635: if (cVar22 == -1) {
2636: pcVar15 = pcVar24 + 2;
2637: pcVar24[1] = '\0';
2638: }
2639: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2640: *pcVar15 = cVar22;
2641: pcVar24 = pcVar15 + 1;
2642: if (cVar22 == -1) {
2643: pcVar24 = pcVar15 + 2;
2644: pcVar15[1] = '\0';
2645: }
2646: pcVar15 = pcVar24 + 1;
2647: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2648: *pcVar24 = cVar23;
2649: if (cVar23 == -1) {
2650: pcVar15 = pcVar24 + 2;
2651: pcVar24[1] = '\0';
2652: }
2653: uStack624._0_4_ = (int)uStack624 + -0x20;
2654: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2655: *pcVar15 = cVar23;
2656: pcVar24 = pcVar15 + 1;
2657: if (cVar23 == -1) {
2658: pcVar24 = pcVar15 + 2;
2659: pcVar15[1] = '\0';
2660: }
2661: }
2662: sVar4 = psVar9[0x2a];
2663: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2664: uVar20 = 0;
2665: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2666: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
2667: if (sVar4 != 0) goto LAB_0010d8f6;
2668: LAB_001090ca:
2669: uVar20 = uVar20 + 1;
2670: }
2671: uVar26 = SEXT24(psVar9[0x31]);
2672: if (psVar9[0x31] == 0) {
2673: uVar20 = uVar20 + 1;
2674: }
2675: else {
2676: uVar30 = (int)uVar26 >> 0x1f;
2677: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
2678: if (0xf < (int)uVar20) {
2679: uVar25 = uVar20;
2680: do {
2681: if (0x2f < (int)uStack624) {
2682: cVar23 = (char)(int)uStack624;
2683: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2684: *pcVar24 = cVar22;
2685: pcVar15 = pcVar24 + 1;
2686: if (cVar22 == -1) {
2687: pcVar15 = pcVar24 + 2;
2688: pcVar24[1] = '\0';
2689: }
2690: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2691: *pcVar15 = cVar22;
2692: pcVar24 = pcVar15 + 1;
2693: if (cVar22 == -1) {
2694: pcVar24 = pcVar15 + 2;
2695: pcVar15[1] = '\0';
2696: }
2697: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2698: *pcVar24 = cVar22;
2699: pcVar15 = pcVar24 + 1;
2700: if (cVar22 == -1) {
2701: pcVar15 = pcVar24 + 2;
2702: pcVar24[1] = '\0';
2703: }
2704: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2705: *pcVar15 = cVar22;
2706: pcVar24 = pcVar15 + 1;
2707: if (cVar22 == -1) {
2708: pcVar24 = pcVar15 + 2;
2709: pcVar15[1] = '\0';
2710: }
2711: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2712: *pcVar24 = cVar23;
2713: pcVar15 = pcVar24 + 1;
2714: if (cVar23 == -1) {
2715: pcVar15 = pcVar24 + 2;
2716: pcVar24[1] = '\0';
2717: }
2718: uStack624._0_4_ = (int)uStack624 + -0x30;
2719: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2720: *pcVar15 = cVar23;
2721: pcVar24 = pcVar15 + 1;
2722: if (cVar23 == -1) {
2723: pcVar24 = pcVar15 + 2;
2724: pcVar15[1] = '\0';
2725: }
2726: }
2727: uVar25 = uVar25 - 0x10;
2728: uStack624._0_4_ = (int)uStack624 + iVar21;
2729: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2730: } while (0xf < (int)uVar25);
2731: uVar20 = uVar20 & 0xf;
2732: }
2733: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2734: iVar17 = piVar8[lVar18];
2735: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2736: if (0x1f < (int)uStack624) {
2737: cVar23 = (char)(int)uStack624;
2738: pcVar15 = pcVar24 + 1;
2739: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2740: *pcVar24 = cVar22;
2741: if (cVar22 == -1) {
2742: pcVar15 = pcVar24 + 2;
2743: pcVar24[1] = '\0';
2744: }
2745: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2746: *pcVar15 = cVar22;
2747: pcVar24 = pcVar15 + 1;
2748: if (cVar22 == -1) {
2749: pcVar24 = pcVar15 + 2;
2750: pcVar15[1] = '\0';
2751: }
2752: pcVar15 = pcVar24 + 1;
2753: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2754: *pcVar24 = cVar23;
2755: if (cVar23 == -1) {
2756: pcVar15 = pcVar24 + 2;
2757: pcVar24[1] = '\0';
2758: }
2759: uStack624._0_4_ = (int)uStack624 + -0x20;
2760: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2761: *pcVar15 = cVar23;
2762: pcVar24 = pcVar15 + 1;
2763: if (cVar23 == -1) {
2764: pcVar24 = pcVar15 + 2;
2765: pcVar15[1] = '\0';
2766: }
2767: }
2768: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2769: uVar20 = 0;
2770: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2771: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
2772: }
2773: uVar26 = SEXT24(psVar9[0x38]);
2774: if (psVar9[0x38] == 0) {
2775: uVar20 = uVar20 + 1;
2776: }
2777: else {
2778: uVar30 = (int)uVar26 >> 0x1f;
2779: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
2780: if (0xf < (int)uVar20) {
2781: uVar25 = uVar20;
2782: do {
2783: if (0x2f < (int)uStack624) {
2784: cVar23 = (char)(int)uStack624;
2785: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2786: *pcVar24 = cVar22;
2787: pcVar15 = pcVar24 + 1;
2788: if (cVar22 == -1) {
2789: pcVar15 = pcVar24 + 2;
2790: pcVar24[1] = '\0';
2791: }
2792: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2793: *pcVar15 = cVar22;
2794: pcVar24 = pcVar15 + 1;
2795: if (cVar22 == -1) {
2796: pcVar24 = pcVar15 + 2;
2797: pcVar15[1] = '\0';
2798: }
2799: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2800: *pcVar24 = cVar22;
2801: pcVar15 = pcVar24 + 1;
2802: if (cVar22 == -1) {
2803: pcVar15 = pcVar24 + 2;
2804: pcVar24[1] = '\0';
2805: }
2806: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2807: *pcVar15 = cVar22;
2808: pcVar24 = pcVar15 + 1;
2809: if (cVar22 == -1) {
2810: pcVar24 = pcVar15 + 2;
2811: pcVar15[1] = '\0';
2812: }
2813: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2814: *pcVar24 = cVar23;
2815: pcVar15 = pcVar24 + 1;
2816: if (cVar23 == -1) {
2817: pcVar15 = pcVar24 + 2;
2818: pcVar24[1] = '\0';
2819: }
2820: uStack624._0_4_ = (int)uStack624 + -0x30;
2821: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2822: *pcVar15 = cVar23;
2823: pcVar24 = pcVar15 + 1;
2824: if (cVar23 == -1) {
2825: pcVar24 = pcVar15 + 2;
2826: pcVar15[1] = '\0';
2827: }
2828: }
2829: uVar25 = uVar25 - 0x10;
2830: uStack624._0_4_ = (int)uStack624 + iVar21;
2831: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2832: } while (0xf < (int)uVar25);
2833: uVar20 = uVar20 & 0xf;
2834: }
2835: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2836: iVar17 = piVar8[lVar18];
2837: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2838: if (0x1f < (int)uStack624) {
2839: cVar23 = (char)(int)uStack624;
2840: pcVar15 = pcVar24 + 1;
2841: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2842: *pcVar24 = cVar22;
2843: if (cVar22 == -1) {
2844: pcVar15 = pcVar24 + 2;
2845: pcVar24[1] = '\0';
2846: }
2847: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2848: *pcVar15 = cVar22;
2849: pcVar24 = pcVar15 + 1;
2850: if (cVar22 == -1) {
2851: pcVar24 = pcVar15 + 2;
2852: pcVar15[1] = '\0';
2853: }
2854: pcVar15 = pcVar24 + 1;
2855: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2856: *pcVar24 = cVar23;
2857: if (cVar23 == -1) {
2858: pcVar15 = pcVar24 + 2;
2859: pcVar24[1] = '\0';
2860: }
2861: uStack624._0_4_ = (int)uStack624 + -0x20;
2862: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2863: *pcVar15 = cVar23;
2864: pcVar24 = pcVar15 + 1;
2865: if (cVar23 == -1) {
2866: pcVar24 = pcVar15 + 2;
2867: pcVar15[1] = '\0';
2868: }
2869: }
2870: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2871: uVar20 = 0;
2872: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2873: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
2874: }
2875: uVar26 = SEXT24(psVar9[0x39]);
2876: if (psVar9[0x39] == 0) {
2877: uVar20 = uVar20 + 1;
2878: }
2879: else {
2880: uVar30 = (int)uVar26 >> 0x1f;
2881: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
2882: if (0xf < (int)uVar20) {
2883: uVar25 = uVar20;
2884: do {
2885: if (0x2f < (int)uStack624) {
2886: cVar23 = (char)(int)uStack624;
2887: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2888: *pcVar24 = cVar22;
2889: pcVar15 = pcVar24 + 1;
2890: if (cVar22 == -1) {
2891: pcVar15 = pcVar24 + 2;
2892: pcVar24[1] = '\0';
2893: }
2894: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2895: *pcVar15 = cVar22;
2896: pcVar24 = pcVar15 + 1;
2897: if (cVar22 == -1) {
2898: pcVar24 = pcVar15 + 2;
2899: pcVar15[1] = '\0';
2900: }
2901: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2902: *pcVar24 = cVar22;
2903: pcVar15 = pcVar24 + 1;
2904: if (cVar22 == -1) {
2905: pcVar15 = pcVar24 + 2;
2906: pcVar24[1] = '\0';
2907: }
2908: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
2909: *pcVar15 = cVar22;
2910: pcVar24 = pcVar15 + 1;
2911: if (cVar22 == -1) {
2912: pcVar24 = pcVar15 + 2;
2913: pcVar15[1] = '\0';
2914: }
2915: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
2916: *pcVar24 = cVar23;
2917: pcVar15 = pcVar24 + 1;
2918: if (cVar23 == -1) {
2919: pcVar15 = pcVar24 + 2;
2920: pcVar24[1] = '\0';
2921: }
2922: uStack624._0_4_ = (int)uStack624 + -0x30;
2923: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2924: *pcVar15 = cVar23;
2925: pcVar24 = pcVar15 + 1;
2926: if (cVar23 == -1) {
2927: pcVar24 = pcVar15 + 2;
2928: pcVar15[1] = '\0';
2929: }
2930: }
2931: uVar25 = uVar25 - 0x10;
2932: uStack624._0_4_ = (int)uStack624 + iVar21;
2933: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
2934: } while (0xf < (int)uVar25);
2935: uVar20 = uVar20 & 0xf;
2936: }
2937: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
2938: iVar17 = piVar8[lVar18];
2939: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
2940: if (0x1f < (int)uStack624) {
2941: cVar23 = (char)(int)uStack624;
2942: pcVar15 = pcVar24 + 1;
2943: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2944: *pcVar24 = cVar22;
2945: if (cVar22 == -1) {
2946: pcVar15 = pcVar24 + 2;
2947: pcVar24[1] = '\0';
2948: }
2949: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2950: *pcVar15 = cVar22;
2951: pcVar24 = pcVar15 + 1;
2952: if (cVar22 == -1) {
2953: pcVar24 = pcVar15 + 2;
2954: pcVar15[1] = '\0';
2955: }
2956: pcVar15 = pcVar24 + 1;
2957: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
2958: *pcVar24 = cVar23;
2959: if (cVar23 == -1) {
2960: pcVar15 = pcVar24 + 2;
2961: pcVar24[1] = '\0';
2962: }
2963: uStack624._0_4_ = (int)uStack624 + -0x20;
2964: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
2965: *pcVar15 = cVar23;
2966: pcVar24 = pcVar15 + 1;
2967: if (cVar23 == -1) {
2968: pcVar24 = pcVar15 + 2;
2969: pcVar15[1] = '\0';
2970: }
2971: }
2972: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
2973: uVar20 = 0;
2974: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
2975: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
2976: }
2977: uVar26 = SEXT24(psVar9[0x32]);
2978: if (psVar9[0x32] == 0) {
2979: uVar20 = uVar20 + 1;
2980: }
2981: else {
2982: uVar30 = (int)uVar26 >> 0x1f;
2983: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
2984: if (0xf < (int)uVar20) {
2985: uVar25 = uVar20;
2986: do {
2987: if (0x2f < (int)uStack624) {
2988: cVar23 = (char)(int)uStack624;
2989: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
2990: *pcVar24 = cVar22;
2991: pcVar15 = pcVar24 + 1;
2992: if (cVar22 == -1) {
2993: pcVar15 = pcVar24 + 2;
2994: pcVar24[1] = '\0';
2995: }
2996: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
2997: *pcVar15 = cVar22;
2998: pcVar24 = pcVar15 + 1;
2999: if (cVar22 == -1) {
3000: pcVar24 = pcVar15 + 2;
3001: pcVar15[1] = '\0';
3002: }
3003: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3004: *pcVar24 = cVar22;
3005: pcVar15 = pcVar24 + 1;
3006: if (cVar22 == -1) {
3007: pcVar15 = pcVar24 + 2;
3008: pcVar24[1] = '\0';
3009: }
3010: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3011: *pcVar15 = cVar22;
3012: pcVar24 = pcVar15 + 1;
3013: if (cVar22 == -1) {
3014: pcVar24 = pcVar15 + 2;
3015: pcVar15[1] = '\0';
3016: }
3017: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3018: *pcVar24 = cVar23;
3019: pcVar15 = pcVar24 + 1;
3020: if (cVar23 == -1) {
3021: pcVar15 = pcVar24 + 2;
3022: pcVar24[1] = '\0';
3023: }
3024: uStack624._0_4_ = (int)uStack624 + -0x30;
3025: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3026: *pcVar15 = cVar23;
3027: pcVar24 = pcVar15 + 1;
3028: if (cVar23 == -1) {
3029: pcVar24 = pcVar15 + 2;
3030: pcVar15[1] = '\0';
3031: }
3032: }
3033: uVar25 = uVar25 - 0x10;
3034: uStack624._0_4_ = (int)uStack624 + iVar21;
3035: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3036: } while (0xf < (int)uVar25);
3037: uVar20 = uVar20 & 0xf;
3038: }
3039: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3040: iVar17 = piVar8[lVar18];
3041: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3042: if (0x1f < (int)uStack624) {
3043: cVar23 = (char)(int)uStack624;
3044: pcVar15 = pcVar24 + 1;
3045: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3046: *pcVar24 = cVar22;
3047: if (cVar22 == -1) {
3048: pcVar15 = pcVar24 + 2;
3049: pcVar24[1] = '\0';
3050: }
3051: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3052: *pcVar15 = cVar22;
3053: pcVar24 = pcVar15 + 1;
3054: if (cVar22 == -1) {
3055: pcVar24 = pcVar15 + 2;
3056: pcVar15[1] = '\0';
3057: }
3058: pcVar15 = pcVar24 + 1;
3059: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3060: *pcVar24 = cVar23;
3061: if (cVar23 == -1) {
3062: pcVar15 = pcVar24 + 2;
3063: pcVar24[1] = '\0';
3064: }
3065: uStack624._0_4_ = (int)uStack624 + -0x20;
3066: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3067: *pcVar15 = cVar23;
3068: pcVar24 = pcVar15 + 1;
3069: if (cVar23 == -1) {
3070: pcVar24 = pcVar15 + 2;
3071: pcVar15[1] = '\0';
3072: }
3073: }
3074: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3075: uVar20 = 0;
3076: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3077: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3078: }
3079: uVar26 = SEXT24(psVar9[0x2b]);
3080: if (psVar9[0x2b] == 0) {
3081: uVar20 = uVar20 + 1;
3082: }
3083: else {
3084: uVar30 = (int)uVar26 >> 0x1f;
3085: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3086: if (0xf < (int)uVar20) {
3087: uVar25 = uVar20;
3088: do {
3089: if (0x2f < (int)uStack624) {
3090: cVar23 = (char)(int)uStack624;
3091: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3092: *pcVar24 = cVar22;
3093: pcVar15 = pcVar24 + 1;
3094: if (cVar22 == -1) {
3095: pcVar15 = pcVar24 + 2;
3096: pcVar24[1] = '\0';
3097: }
3098: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3099: *pcVar15 = cVar22;
3100: pcVar24 = pcVar15 + 1;
3101: if (cVar22 == -1) {
3102: pcVar24 = pcVar15 + 2;
3103: pcVar15[1] = '\0';
3104: }
3105: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3106: *pcVar24 = cVar22;
3107: pcVar15 = pcVar24 + 1;
3108: if (cVar22 == -1) {
3109: pcVar15 = pcVar24 + 2;
3110: pcVar24[1] = '\0';
3111: }
3112: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3113: *pcVar15 = cVar22;
3114: pcVar24 = pcVar15 + 1;
3115: if (cVar22 == -1) {
3116: pcVar24 = pcVar15 + 2;
3117: pcVar15[1] = '\0';
3118: }
3119: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3120: *pcVar24 = cVar23;
3121: pcVar15 = pcVar24 + 1;
3122: if (cVar23 == -1) {
3123: pcVar15 = pcVar24 + 2;
3124: pcVar24[1] = '\0';
3125: }
3126: uStack624._0_4_ = (int)uStack624 + -0x30;
3127: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3128: *pcVar15 = cVar23;
3129: pcVar24 = pcVar15 + 1;
3130: if (cVar23 == -1) {
3131: pcVar24 = pcVar15 + 2;
3132: pcVar15[1] = '\0';
3133: }
3134: }
3135: uVar25 = uVar25 - 0x10;
3136: uStack624._0_4_ = (int)uStack624 + iVar21;
3137: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3138: } while (0xf < (int)uVar25);
3139: uVar20 = uVar20 & 0xf;
3140: }
3141: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3142: iVar17 = piVar8[lVar18];
3143: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3144: if (0x1f < (int)uStack624) {
3145: cVar23 = (char)(int)uStack624;
3146: pcVar15 = pcVar24 + 1;
3147: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3148: *pcVar24 = cVar22;
3149: if (cVar22 == -1) {
3150: pcVar15 = pcVar24 + 2;
3151: pcVar24[1] = '\0';
3152: }
3153: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3154: *pcVar15 = cVar22;
3155: pcVar24 = pcVar15 + 1;
3156: if (cVar22 == -1) {
3157: pcVar24 = pcVar15 + 2;
3158: pcVar15[1] = '\0';
3159: }
3160: pcVar15 = pcVar24 + 1;
3161: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3162: *pcVar24 = cVar23;
3163: if (cVar23 == -1) {
3164: pcVar15 = pcVar24 + 2;
3165: pcVar24[1] = '\0';
3166: }
3167: uStack624._0_4_ = (int)uStack624 + -0x20;
3168: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3169: *pcVar15 = cVar23;
3170: pcVar24 = pcVar15 + 1;
3171: if (cVar23 == -1) {
3172: pcVar24 = pcVar15 + 2;
3173: pcVar15[1] = '\0';
3174: }
3175: }
3176: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3177: uVar20 = 0;
3178: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3179: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3180: }
3181: uVar26 = SEXT24(psVar9[0x24]);
3182: if (psVar9[0x24] == 0) {
3183: uVar20 = uVar20 + 1;
3184: }
3185: else {
3186: uVar30 = (int)uVar26 >> 0x1f;
3187: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3188: if (0xf < (int)uVar20) {
3189: uVar25 = uVar20;
3190: do {
3191: if (0x2f < (int)uStack624) {
3192: cVar23 = (char)(int)uStack624;
3193: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3194: *pcVar24 = cVar22;
3195: pcVar15 = pcVar24 + 1;
3196: if (cVar22 == -1) {
3197: pcVar15 = pcVar24 + 2;
3198: pcVar24[1] = '\0';
3199: }
3200: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3201: *pcVar15 = cVar22;
3202: pcVar24 = pcVar15 + 1;
3203: if (cVar22 == -1) {
3204: pcVar24 = pcVar15 + 2;
3205: pcVar15[1] = '\0';
3206: }
3207: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3208: *pcVar24 = cVar22;
3209: pcVar15 = pcVar24 + 1;
3210: if (cVar22 == -1) {
3211: pcVar15 = pcVar24 + 2;
3212: pcVar24[1] = '\0';
3213: }
3214: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3215: *pcVar15 = cVar22;
3216: pcVar24 = pcVar15 + 1;
3217: if (cVar22 == -1) {
3218: pcVar24 = pcVar15 + 2;
3219: pcVar15[1] = '\0';
3220: }
3221: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3222: *pcVar24 = cVar23;
3223: pcVar15 = pcVar24 + 1;
3224: if (cVar23 == -1) {
3225: pcVar15 = pcVar24 + 2;
3226: pcVar24[1] = '\0';
3227: }
3228: uStack624._0_4_ = (int)uStack624 + -0x30;
3229: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3230: *pcVar15 = cVar23;
3231: pcVar24 = pcVar15 + 1;
3232: if (cVar23 == -1) {
3233: pcVar24 = pcVar15 + 2;
3234: pcVar15[1] = '\0';
3235: }
3236: }
3237: uVar25 = uVar25 - 0x10;
3238: uStack624._0_4_ = (int)uStack624 + iVar21;
3239: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3240: } while (0xf < (int)uVar25);
3241: uVar20 = uVar20 & 0xf;
3242: }
3243: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3244: iVar17 = piVar8[lVar18];
3245: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3246: if (0x1f < (int)uStack624) {
3247: cVar23 = (char)(int)uStack624;
3248: pcVar15 = pcVar24 + 1;
3249: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3250: *pcVar24 = cVar22;
3251: if (cVar22 == -1) {
3252: pcVar15 = pcVar24 + 2;
3253: pcVar24[1] = '\0';
3254: }
3255: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3256: *pcVar15 = cVar22;
3257: pcVar24 = pcVar15 + 1;
3258: if (cVar22 == -1) {
3259: pcVar24 = pcVar15 + 2;
3260: pcVar15[1] = '\0';
3261: }
3262: pcVar15 = pcVar24 + 1;
3263: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3264: *pcVar24 = cVar23;
3265: if (cVar23 == -1) {
3266: pcVar15 = pcVar24 + 2;
3267: pcVar24[1] = '\0';
3268: }
3269: uStack624._0_4_ = (int)uStack624 + -0x20;
3270: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3271: *pcVar15 = cVar23;
3272: pcVar24 = pcVar15 + 1;
3273: if (cVar23 == -1) {
3274: pcVar24 = pcVar15 + 2;
3275: pcVar15[1] = '\0';
3276: }
3277: }
3278: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3279: uVar20 = 0;
3280: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3281: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3282: }
3283: uVar26 = SEXT24(psVar9[0x1d]);
3284: if (psVar9[0x1d] == 0) {
3285: uVar20 = uVar20 + 1;
3286: }
3287: else {
3288: uVar30 = (int)uVar26 >> 0x1f;
3289: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3290: if (0xf < (int)uVar20) {
3291: uVar25 = uVar20;
3292: do {
3293: if (0x2f < (int)uStack624) {
3294: cVar23 = (char)(int)uStack624;
3295: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3296: *pcVar24 = cVar22;
3297: pcVar15 = pcVar24 + 1;
3298: if (cVar22 == -1) {
3299: pcVar15 = pcVar24 + 2;
3300: pcVar24[1] = '\0';
3301: }
3302: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3303: *pcVar15 = cVar22;
3304: pcVar24 = pcVar15 + 1;
3305: if (cVar22 == -1) {
3306: pcVar24 = pcVar15 + 2;
3307: pcVar15[1] = '\0';
3308: }
3309: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3310: *pcVar24 = cVar22;
3311: pcVar15 = pcVar24 + 1;
3312: if (cVar22 == -1) {
3313: pcVar15 = pcVar24 + 2;
3314: pcVar24[1] = '\0';
3315: }
3316: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3317: *pcVar15 = cVar22;
3318: pcVar24 = pcVar15 + 1;
3319: if (cVar22 == -1) {
3320: pcVar24 = pcVar15 + 2;
3321: pcVar15[1] = '\0';
3322: }
3323: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3324: *pcVar24 = cVar23;
3325: pcVar15 = pcVar24 + 1;
3326: if (cVar23 == -1) {
3327: pcVar15 = pcVar24 + 2;
3328: pcVar24[1] = '\0';
3329: }
3330: uStack624._0_4_ = (int)uStack624 + -0x30;
3331: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3332: *pcVar15 = cVar23;
3333: pcVar24 = pcVar15 + 1;
3334: if (cVar23 == -1) {
3335: pcVar24 = pcVar15 + 2;
3336: pcVar15[1] = '\0';
3337: }
3338: }
3339: uVar25 = uVar25 - 0x10;
3340: uStack624._0_4_ = (int)uStack624 + iVar21;
3341: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3342: } while (0xf < (int)uVar25);
3343: uVar20 = uVar20 & 0xf;
3344: }
3345: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3346: iVar17 = piVar8[lVar18];
3347: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3348: if (0x1f < (int)uStack624) {
3349: cVar23 = (char)(int)uStack624;
3350: pcVar15 = pcVar24 + 1;
3351: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3352: *pcVar24 = cVar22;
3353: if (cVar22 == -1) {
3354: pcVar15 = pcVar24 + 2;
3355: pcVar24[1] = '\0';
3356: }
3357: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3358: *pcVar15 = cVar22;
3359: pcVar24 = pcVar15 + 1;
3360: if (cVar22 == -1) {
3361: pcVar24 = pcVar15 + 2;
3362: pcVar15[1] = '\0';
3363: }
3364: pcVar15 = pcVar24 + 1;
3365: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3366: *pcVar24 = cVar23;
3367: if (cVar23 == -1) {
3368: pcVar15 = pcVar24 + 2;
3369: pcVar24[1] = '\0';
3370: }
3371: uStack624._0_4_ = (int)uStack624 + -0x20;
3372: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3373: *pcVar15 = cVar23;
3374: pcVar24 = pcVar15 + 1;
3375: if (cVar23 == -1) {
3376: pcVar24 = pcVar15 + 2;
3377: pcVar15[1] = '\0';
3378: }
3379: }
3380: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3381: uVar20 = 0;
3382: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3383: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3384: }
3385: uVar26 = SEXT24(psVar9[0x16]);
3386: if (psVar9[0x16] == 0) {
3387: uVar20 = uVar20 + 1;
3388: }
3389: else {
3390: uVar30 = (int)uVar26 >> 0x1f;
3391: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3392: if (0xf < (int)uVar20) {
3393: uVar25 = uVar20;
3394: do {
3395: if (0x2f < (int)uStack624) {
3396: cVar23 = (char)(int)uStack624;
3397: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3398: *pcVar24 = cVar22;
3399: pcVar15 = pcVar24 + 1;
3400: if (cVar22 == -1) {
3401: pcVar15 = pcVar24 + 2;
3402: pcVar24[1] = '\0';
3403: }
3404: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3405: *pcVar15 = cVar22;
3406: pcVar24 = pcVar15 + 1;
3407: if (cVar22 == -1) {
3408: pcVar24 = pcVar15 + 2;
3409: pcVar15[1] = '\0';
3410: }
3411: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3412: *pcVar24 = cVar22;
3413: pcVar15 = pcVar24 + 1;
3414: if (cVar22 == -1) {
3415: pcVar15 = pcVar24 + 2;
3416: pcVar24[1] = '\0';
3417: }
3418: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3419: *pcVar15 = cVar22;
3420: pcVar24 = pcVar15 + 1;
3421: if (cVar22 == -1) {
3422: pcVar24 = pcVar15 + 2;
3423: pcVar15[1] = '\0';
3424: }
3425: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3426: *pcVar24 = cVar23;
3427: pcVar15 = pcVar24 + 1;
3428: if (cVar23 == -1) {
3429: pcVar15 = pcVar24 + 2;
3430: pcVar24[1] = '\0';
3431: }
3432: uStack624._0_4_ = (int)uStack624 + -0x30;
3433: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3434: *pcVar15 = cVar23;
3435: pcVar24 = pcVar15 + 1;
3436: if (cVar23 == -1) {
3437: pcVar24 = pcVar15 + 2;
3438: pcVar15[1] = '\0';
3439: }
3440: }
3441: uVar25 = uVar25 - 0x10;
3442: uStack624._0_4_ = (int)uStack624 + iVar21;
3443: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3444: } while (0xf < (int)uVar25);
3445: uVar20 = uVar20 & 0xf;
3446: }
3447: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3448: iVar17 = piVar8[lVar18];
3449: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3450: if (0x1f < (int)uStack624) {
3451: cVar23 = (char)(int)uStack624;
3452: pcVar15 = pcVar24 + 1;
3453: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3454: *pcVar24 = cVar22;
3455: if (cVar22 == -1) {
3456: pcVar15 = pcVar24 + 2;
3457: pcVar24[1] = '\0';
3458: }
3459: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3460: *pcVar15 = cVar22;
3461: pcVar24 = pcVar15 + 1;
3462: if (cVar22 == -1) {
3463: pcVar24 = pcVar15 + 2;
3464: pcVar15[1] = '\0';
3465: }
3466: pcVar15 = pcVar24 + 1;
3467: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3468: *pcVar24 = cVar23;
3469: if (cVar23 == -1) {
3470: pcVar15 = pcVar24 + 2;
3471: pcVar24[1] = '\0';
3472: }
3473: uStack624._0_4_ = (int)uStack624 + -0x20;
3474: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3475: *pcVar15 = cVar23;
3476: pcVar24 = pcVar15 + 1;
3477: if (cVar23 == -1) {
3478: pcVar24 = pcVar15 + 2;
3479: pcVar15[1] = '\0';
3480: }
3481: }
3482: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3483: uVar20 = 0;
3484: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3485: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3486: }
3487: uVar26 = SEXT24(psVar9[0xf]);
3488: if (psVar9[0xf] == 0) {
3489: uVar20 = uVar20 + 1;
3490: }
3491: else {
3492: uVar30 = (int)uVar26 >> 0x1f;
3493: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3494: if (0xf < (int)uVar20) {
3495: uVar25 = uVar20;
3496: do {
3497: if (0x2f < (int)uStack624) {
3498: cVar23 = (char)(int)uStack624;
3499: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3500: *pcVar24 = cVar22;
3501: pcVar15 = pcVar24 + 1;
3502: if (cVar22 == -1) {
3503: pcVar15 = pcVar24 + 2;
3504: pcVar24[1] = '\0';
3505: }
3506: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3507: *pcVar15 = cVar22;
3508: pcVar24 = pcVar15 + 1;
3509: if (cVar22 == -1) {
3510: pcVar24 = pcVar15 + 2;
3511: pcVar15[1] = '\0';
3512: }
3513: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3514: *pcVar24 = cVar22;
3515: pcVar15 = pcVar24 + 1;
3516: if (cVar22 == -1) {
3517: pcVar15 = pcVar24 + 2;
3518: pcVar24[1] = '\0';
3519: }
3520: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3521: *pcVar15 = cVar22;
3522: pcVar24 = pcVar15 + 1;
3523: if (cVar22 == -1) {
3524: pcVar24 = pcVar15 + 2;
3525: pcVar15[1] = '\0';
3526: }
3527: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3528: *pcVar24 = cVar23;
3529: pcVar15 = pcVar24 + 1;
3530: if (cVar23 == -1) {
3531: pcVar15 = pcVar24 + 2;
3532: pcVar24[1] = '\0';
3533: }
3534: uStack624._0_4_ = (int)uStack624 + -0x30;
3535: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3536: *pcVar15 = cVar23;
3537: pcVar24 = pcVar15 + 1;
3538: if (cVar23 == -1) {
3539: pcVar24 = pcVar15 + 2;
3540: pcVar15[1] = '\0';
3541: }
3542: }
3543: uVar25 = uVar25 - 0x10;
3544: uStack624._0_4_ = (int)uStack624 + iVar21;
3545: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3546: } while (0xf < (int)uVar25);
3547: uVar20 = uVar20 & 0xf;
3548: }
3549: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3550: iVar17 = piVar8[lVar18];
3551: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3552: if (0x1f < (int)uStack624) {
3553: cVar23 = (char)(int)uStack624;
3554: pcVar15 = pcVar24 + 1;
3555: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3556: *pcVar24 = cVar22;
3557: if (cVar22 == -1) {
3558: pcVar15 = pcVar24 + 2;
3559: pcVar24[1] = '\0';
3560: }
3561: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3562: *pcVar15 = cVar22;
3563: pcVar24 = pcVar15 + 1;
3564: if (cVar22 == -1) {
3565: pcVar24 = pcVar15 + 2;
3566: pcVar15[1] = '\0';
3567: }
3568: pcVar15 = pcVar24 + 1;
3569: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3570: *pcVar24 = cVar23;
3571: if (cVar23 == -1) {
3572: pcVar15 = pcVar24 + 2;
3573: pcVar24[1] = '\0';
3574: }
3575: uStack624._0_4_ = (int)uStack624 + -0x20;
3576: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3577: *pcVar15 = cVar23;
3578: pcVar24 = pcVar15 + 1;
3579: if (cVar23 == -1) {
3580: pcVar24 = pcVar15 + 2;
3581: pcVar15[1] = '\0';
3582: }
3583: }
3584: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3585: uVar20 = 0;
3586: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3587: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3588: }
3589: uVar26 = SEXT24(psVar9[0x17]);
3590: if (psVar9[0x17] == 0) {
3591: uVar20 = uVar20 + 1;
3592: }
3593: else {
3594: uVar30 = (int)uVar26 >> 0x1f;
3595: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3596: if (0xf < (int)uVar20) {
3597: uVar25 = uVar20;
3598: do {
3599: if (0x2f < (int)uStack624) {
3600: cVar23 = (char)(int)uStack624;
3601: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3602: *pcVar24 = cVar22;
3603: pcVar15 = pcVar24 + 1;
3604: if (cVar22 == -1) {
3605: pcVar15 = pcVar24 + 2;
3606: pcVar24[1] = '\0';
3607: }
3608: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3609: *pcVar15 = cVar22;
3610: pcVar24 = pcVar15 + 1;
3611: if (cVar22 == -1) {
3612: pcVar24 = pcVar15 + 2;
3613: pcVar15[1] = '\0';
3614: }
3615: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3616: *pcVar24 = cVar22;
3617: pcVar15 = pcVar24 + 1;
3618: if (cVar22 == -1) {
3619: pcVar15 = pcVar24 + 2;
3620: pcVar24[1] = '\0';
3621: }
3622: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3623: *pcVar15 = cVar22;
3624: pcVar24 = pcVar15 + 1;
3625: if (cVar22 == -1) {
3626: pcVar24 = pcVar15 + 2;
3627: pcVar15[1] = '\0';
3628: }
3629: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3630: *pcVar24 = cVar23;
3631: pcVar15 = pcVar24 + 1;
3632: if (cVar23 == -1) {
3633: pcVar15 = pcVar24 + 2;
3634: pcVar24[1] = '\0';
3635: }
3636: uStack624._0_4_ = (int)uStack624 + -0x30;
3637: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3638: *pcVar15 = cVar23;
3639: pcVar24 = pcVar15 + 1;
3640: if (cVar23 == -1) {
3641: pcVar24 = pcVar15 + 2;
3642: pcVar15[1] = '\0';
3643: }
3644: }
3645: uVar25 = uVar25 - 0x10;
3646: uStack624._0_4_ = (int)uStack624 + iVar21;
3647: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3648: } while (0xf < (int)uVar25);
3649: uVar20 = uVar20 & 0xf;
3650: }
3651: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3652: iVar17 = piVar8[lVar18];
3653: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3654: if (0x1f < (int)uStack624) {
3655: cVar23 = (char)(int)uStack624;
3656: pcVar15 = pcVar24 + 1;
3657: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3658: *pcVar24 = cVar22;
3659: if (cVar22 == -1) {
3660: pcVar15 = pcVar24 + 2;
3661: pcVar24[1] = '\0';
3662: }
3663: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3664: *pcVar15 = cVar22;
3665: pcVar24 = pcVar15 + 1;
3666: if (cVar22 == -1) {
3667: pcVar24 = pcVar15 + 2;
3668: pcVar15[1] = '\0';
3669: }
3670: pcVar15 = pcVar24 + 1;
3671: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3672: *pcVar24 = cVar23;
3673: if (cVar23 == -1) {
3674: pcVar15 = pcVar24 + 2;
3675: pcVar24[1] = '\0';
3676: }
3677: uStack624._0_4_ = (int)uStack624 + -0x20;
3678: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3679: *pcVar15 = cVar23;
3680: pcVar24 = pcVar15 + 1;
3681: if (cVar23 == -1) {
3682: pcVar24 = pcVar15 + 2;
3683: pcVar15[1] = '\0';
3684: }
3685: }
3686: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3687: uVar20 = 0;
3688: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3689: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3690: }
3691: uVar26 = SEXT24(psVar9[0x1e]);
3692: if (psVar9[0x1e] == 0) {
3693: uVar20 = uVar20 + 1;
3694: }
3695: else {
3696: uVar30 = (int)uVar26 >> 0x1f;
3697: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3698: if (0xf < (int)uVar20) {
3699: uVar25 = uVar20;
3700: do {
3701: if (0x2f < (int)uStack624) {
3702: cVar23 = (char)(int)uStack624;
3703: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3704: *pcVar24 = cVar22;
3705: pcVar15 = pcVar24 + 1;
3706: if (cVar22 == -1) {
3707: pcVar15 = pcVar24 + 2;
3708: pcVar24[1] = '\0';
3709: }
3710: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3711: *pcVar15 = cVar22;
3712: pcVar24 = pcVar15 + 1;
3713: if (cVar22 == -1) {
3714: pcVar24 = pcVar15 + 2;
3715: pcVar15[1] = '\0';
3716: }
3717: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3718: *pcVar24 = cVar22;
3719: pcVar15 = pcVar24 + 1;
3720: if (cVar22 == -1) {
3721: pcVar15 = pcVar24 + 2;
3722: pcVar24[1] = '\0';
3723: }
3724: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3725: *pcVar15 = cVar22;
3726: pcVar24 = pcVar15 + 1;
3727: if (cVar22 == -1) {
3728: pcVar24 = pcVar15 + 2;
3729: pcVar15[1] = '\0';
3730: }
3731: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3732: *pcVar24 = cVar23;
3733: pcVar15 = pcVar24 + 1;
3734: if (cVar23 == -1) {
3735: pcVar15 = pcVar24 + 2;
3736: pcVar24[1] = '\0';
3737: }
3738: uStack624._0_4_ = (int)uStack624 + -0x30;
3739: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3740: *pcVar15 = cVar23;
3741: pcVar24 = pcVar15 + 1;
3742: if (cVar23 == -1) {
3743: pcVar24 = pcVar15 + 2;
3744: pcVar15[1] = '\0';
3745: }
3746: }
3747: uVar25 = uVar25 - 0x10;
3748: uStack624._0_4_ = (int)uStack624 + iVar21;
3749: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3750: } while (0xf < (int)uVar25);
3751: uVar20 = uVar20 & 0xf;
3752: }
3753: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3754: iVar17 = piVar8[lVar18];
3755: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3756: if (0x1f < (int)uStack624) {
3757: cVar23 = (char)(int)uStack624;
3758: pcVar15 = pcVar24 + 1;
3759: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3760: *pcVar24 = cVar22;
3761: if (cVar22 == -1) {
3762: pcVar15 = pcVar24 + 2;
3763: pcVar24[1] = '\0';
3764: }
3765: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3766: *pcVar15 = cVar22;
3767: pcVar24 = pcVar15 + 1;
3768: if (cVar22 == -1) {
3769: pcVar24 = pcVar15 + 2;
3770: pcVar15[1] = '\0';
3771: }
3772: pcVar15 = pcVar24 + 1;
3773: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3774: *pcVar24 = cVar23;
3775: if (cVar23 == -1) {
3776: pcVar15 = pcVar24 + 2;
3777: pcVar24[1] = '\0';
3778: }
3779: uStack624._0_4_ = (int)uStack624 + -0x20;
3780: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3781: *pcVar15 = cVar23;
3782: pcVar24 = pcVar15 + 1;
3783: if (cVar23 == -1) {
3784: pcVar24 = pcVar15 + 2;
3785: pcVar15[1] = '\0';
3786: }
3787: }
3788: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3789: uVar20 = 0;
3790: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3791: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3792: }
3793: uVar26 = SEXT24(psVar9[0x25]);
3794: if (psVar9[0x25] == 0) {
3795: uVar20 = uVar20 + 1;
3796: }
3797: else {
3798: uVar30 = (int)uVar26 >> 0x1f;
3799: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3800: if (0xf < (int)uVar20) {
3801: uVar25 = uVar20;
3802: do {
3803: if (0x2f < (int)uStack624) {
3804: cVar23 = (char)(int)uStack624;
3805: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3806: *pcVar24 = cVar22;
3807: pcVar15 = pcVar24 + 1;
3808: if (cVar22 == -1) {
3809: pcVar15 = pcVar24 + 2;
3810: pcVar24[1] = '\0';
3811: }
3812: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3813: *pcVar15 = cVar22;
3814: pcVar24 = pcVar15 + 1;
3815: if (cVar22 == -1) {
3816: pcVar24 = pcVar15 + 2;
3817: pcVar15[1] = '\0';
3818: }
3819: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3820: *pcVar24 = cVar22;
3821: pcVar15 = pcVar24 + 1;
3822: if (cVar22 == -1) {
3823: pcVar15 = pcVar24 + 2;
3824: pcVar24[1] = '\0';
3825: }
3826: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3827: *pcVar15 = cVar22;
3828: pcVar24 = pcVar15 + 1;
3829: if (cVar22 == -1) {
3830: pcVar24 = pcVar15 + 2;
3831: pcVar15[1] = '\0';
3832: }
3833: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3834: *pcVar24 = cVar23;
3835: pcVar15 = pcVar24 + 1;
3836: if (cVar23 == -1) {
3837: pcVar15 = pcVar24 + 2;
3838: pcVar24[1] = '\0';
3839: }
3840: uStack624._0_4_ = (int)uStack624 + -0x30;
3841: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3842: *pcVar15 = cVar23;
3843: pcVar24 = pcVar15 + 1;
3844: if (cVar23 == -1) {
3845: pcVar24 = pcVar15 + 2;
3846: pcVar15[1] = '\0';
3847: }
3848: }
3849: uVar25 = uVar25 - 0x10;
3850: uStack624._0_4_ = (int)uStack624 + iVar21;
3851: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3852: } while (0xf < (int)uVar25);
3853: uVar20 = uVar20 & 0xf;
3854: }
3855: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3856: iVar17 = piVar8[lVar18];
3857: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3858: if (0x1f < (int)uStack624) {
3859: cVar23 = (char)(int)uStack624;
3860: pcVar15 = pcVar24 + 1;
3861: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3862: *pcVar24 = cVar22;
3863: if (cVar22 == -1) {
3864: pcVar15 = pcVar24 + 2;
3865: pcVar24[1] = '\0';
3866: }
3867: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3868: *pcVar15 = cVar22;
3869: pcVar24 = pcVar15 + 1;
3870: if (cVar22 == -1) {
3871: pcVar24 = pcVar15 + 2;
3872: pcVar15[1] = '\0';
3873: }
3874: pcVar15 = pcVar24 + 1;
3875: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3876: *pcVar24 = cVar23;
3877: if (cVar23 == -1) {
3878: pcVar15 = pcVar24 + 2;
3879: pcVar24[1] = '\0';
3880: }
3881: uStack624._0_4_ = (int)uStack624 + -0x20;
3882: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3883: *pcVar15 = cVar23;
3884: pcVar24 = pcVar15 + 1;
3885: if (cVar23 == -1) {
3886: pcVar24 = pcVar15 + 2;
3887: pcVar15[1] = '\0';
3888: }
3889: }
3890: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3891: uVar20 = 0;
3892: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3893: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3894: }
3895: uVar26 = SEXT24(psVar9[0x2c]);
3896: if (psVar9[0x2c] == 0) {
3897: uVar20 = uVar20 + 1;
3898: }
3899: else {
3900: uVar30 = (int)uVar26 >> 0x1f;
3901: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
3902: if (0xf < (int)uVar20) {
3903: uVar25 = uVar20;
3904: do {
3905: if (0x2f < (int)uStack624) {
3906: cVar23 = (char)(int)uStack624;
3907: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3908: *pcVar24 = cVar22;
3909: pcVar15 = pcVar24 + 1;
3910: if (cVar22 == -1) {
3911: pcVar15 = pcVar24 + 2;
3912: pcVar24[1] = '\0';
3913: }
3914: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3915: *pcVar15 = cVar22;
3916: pcVar24 = pcVar15 + 1;
3917: if (cVar22 == -1) {
3918: pcVar24 = pcVar15 + 2;
3919: pcVar15[1] = '\0';
3920: }
3921: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3922: *pcVar24 = cVar22;
3923: pcVar15 = pcVar24 + 1;
3924: if (cVar22 == -1) {
3925: pcVar15 = pcVar24 + 2;
3926: pcVar24[1] = '\0';
3927: }
3928: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
3929: *pcVar15 = cVar22;
3930: pcVar24 = pcVar15 + 1;
3931: if (cVar22 == -1) {
3932: pcVar24 = pcVar15 + 2;
3933: pcVar15[1] = '\0';
3934: }
3935: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
3936: *pcVar24 = cVar23;
3937: pcVar15 = pcVar24 + 1;
3938: if (cVar23 == -1) {
3939: pcVar15 = pcVar24 + 2;
3940: pcVar24[1] = '\0';
3941: }
3942: uStack624._0_4_ = (int)uStack624 + -0x30;
3943: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3944: *pcVar15 = cVar23;
3945: pcVar24 = pcVar15 + 1;
3946: if (cVar23 == -1) {
3947: pcVar24 = pcVar15 + 2;
3948: pcVar15[1] = '\0';
3949: }
3950: }
3951: uVar25 = uVar25 - 0x10;
3952: uStack624._0_4_ = (int)uStack624 + iVar21;
3953: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
3954: } while (0xf < (int)uVar25);
3955: uVar20 = uVar20 & 0xf;
3956: }
3957: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
3958: iVar17 = piVar8[lVar18];
3959: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
3960: if (0x1f < (int)uStack624) {
3961: cVar23 = (char)(int)uStack624;
3962: pcVar15 = pcVar24 + 1;
3963: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
3964: *pcVar24 = cVar22;
3965: if (cVar22 == -1) {
3966: pcVar15 = pcVar24 + 2;
3967: pcVar24[1] = '\0';
3968: }
3969: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
3970: *pcVar15 = cVar22;
3971: pcVar24 = pcVar15 + 1;
3972: if (cVar22 == -1) {
3973: pcVar24 = pcVar15 + 2;
3974: pcVar15[1] = '\0';
3975: }
3976: pcVar15 = pcVar24 + 1;
3977: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
3978: *pcVar24 = cVar23;
3979: if (cVar23 == -1) {
3980: pcVar15 = pcVar24 + 2;
3981: pcVar24[1] = '\0';
3982: }
3983: uStack624._0_4_ = (int)uStack624 + -0x20;
3984: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
3985: *pcVar15 = cVar23;
3986: pcVar24 = pcVar15 + 1;
3987: if (cVar23 == -1) {
3988: pcVar24 = pcVar15 + 2;
3989: pcVar15[1] = '\0';
3990: }
3991: }
3992: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
3993: uVar20 = 0;
3994: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
3995: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
3996: }
3997: uVar26 = SEXT24(psVar9[0x33]);
3998: if (psVar9[0x33] == 0) {
3999: uVar20 = uVar20 + 1;
4000: }
4001: else {
4002: uVar30 = (int)uVar26 >> 0x1f;
4003: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4004: if (0xf < (int)uVar20) {
4005: uVar25 = uVar20;
4006: do {
4007: if (0x2f < (int)uStack624) {
4008: cVar23 = (char)(int)uStack624;
4009: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4010: *pcVar24 = cVar22;
4011: pcVar15 = pcVar24 + 1;
4012: if (cVar22 == -1) {
4013: pcVar15 = pcVar24 + 2;
4014: pcVar24[1] = '\0';
4015: }
4016: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4017: *pcVar15 = cVar22;
4018: pcVar24 = pcVar15 + 1;
4019: if (cVar22 == -1) {
4020: pcVar24 = pcVar15 + 2;
4021: pcVar15[1] = '\0';
4022: }
4023: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4024: *pcVar24 = cVar22;
4025: pcVar15 = pcVar24 + 1;
4026: if (cVar22 == -1) {
4027: pcVar15 = pcVar24 + 2;
4028: pcVar24[1] = '\0';
4029: }
4030: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4031: *pcVar15 = cVar22;
4032: pcVar24 = pcVar15 + 1;
4033: if (cVar22 == -1) {
4034: pcVar24 = pcVar15 + 2;
4035: pcVar15[1] = '\0';
4036: }
4037: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4038: *pcVar24 = cVar23;
4039: pcVar15 = pcVar24 + 1;
4040: if (cVar23 == -1) {
4041: pcVar15 = pcVar24 + 2;
4042: pcVar24[1] = '\0';
4043: }
4044: uStack624._0_4_ = (int)uStack624 + -0x30;
4045: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4046: *pcVar15 = cVar23;
4047: pcVar24 = pcVar15 + 1;
4048: if (cVar23 == -1) {
4049: pcVar24 = pcVar15 + 2;
4050: pcVar15[1] = '\0';
4051: }
4052: }
4053: uVar25 = uVar25 - 0x10;
4054: uStack624._0_4_ = (int)uStack624 + iVar21;
4055: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4056: } while (0xf < (int)uVar25);
4057: uVar20 = uVar20 & 0xf;
4058: }
4059: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4060: iVar17 = piVar8[lVar18];
4061: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4062: if (0x1f < (int)uStack624) {
4063: cVar23 = (char)(int)uStack624;
4064: pcVar15 = pcVar24 + 1;
4065: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4066: *pcVar24 = cVar22;
4067: if (cVar22 == -1) {
4068: pcVar15 = pcVar24 + 2;
4069: pcVar24[1] = '\0';
4070: }
4071: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4072: *pcVar15 = cVar22;
4073: pcVar24 = pcVar15 + 1;
4074: if (cVar22 == -1) {
4075: pcVar24 = pcVar15 + 2;
4076: pcVar15[1] = '\0';
4077: }
4078: pcVar15 = pcVar24 + 1;
4079: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4080: *pcVar24 = cVar23;
4081: if (cVar23 == -1) {
4082: pcVar15 = pcVar24 + 2;
4083: pcVar24[1] = '\0';
4084: }
4085: uStack624._0_4_ = (int)uStack624 + -0x20;
4086: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4087: *pcVar15 = cVar23;
4088: pcVar24 = pcVar15 + 1;
4089: if (cVar23 == -1) {
4090: pcVar24 = pcVar15 + 2;
4091: pcVar15[1] = '\0';
4092: }
4093: }
4094: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4095: uVar20 = 0;
4096: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4097: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
4098: }
4099: uVar26 = SEXT24(psVar9[0x3a]);
4100: if (psVar9[0x3a] == 0) {
4101: uVar20 = uVar20 + 1;
4102: }
4103: else {
4104: uVar30 = (int)uVar26 >> 0x1f;
4105: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4106: if (0xf < (int)uVar20) {
4107: uVar25 = uVar20;
4108: do {
4109: if (0x2f < (int)uStack624) {
4110: cVar23 = (char)(int)uStack624;
4111: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4112: *pcVar24 = cVar22;
4113: pcVar15 = pcVar24 + 1;
4114: if (cVar22 == -1) {
4115: pcVar15 = pcVar24 + 2;
4116: pcVar24[1] = '\0';
4117: }
4118: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4119: *pcVar15 = cVar22;
4120: pcVar24 = pcVar15 + 1;
4121: if (cVar22 == -1) {
4122: pcVar24 = pcVar15 + 2;
4123: pcVar15[1] = '\0';
4124: }
4125: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4126: *pcVar24 = cVar22;
4127: pcVar15 = pcVar24 + 1;
4128: if (cVar22 == -1) {
4129: pcVar15 = pcVar24 + 2;
4130: pcVar24[1] = '\0';
4131: }
4132: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4133: *pcVar15 = cVar22;
4134: pcVar24 = pcVar15 + 1;
4135: if (cVar22 == -1) {
4136: pcVar24 = pcVar15 + 2;
4137: pcVar15[1] = '\0';
4138: }
4139: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4140: *pcVar24 = cVar23;
4141: pcVar15 = pcVar24 + 1;
4142: if (cVar23 == -1) {
4143: pcVar15 = pcVar24 + 2;
4144: pcVar24[1] = '\0';
4145: }
4146: uStack624._0_4_ = (int)uStack624 + -0x30;
4147: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4148: *pcVar15 = cVar23;
4149: pcVar24 = pcVar15 + 1;
4150: if (cVar23 == -1) {
4151: pcVar24 = pcVar15 + 2;
4152: pcVar15[1] = '\0';
4153: }
4154: }
4155: uVar25 = uVar25 - 0x10;
4156: uStack624._0_4_ = (int)uStack624 + iVar21;
4157: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4158: } while (0xf < (int)uVar25);
4159: uVar20 = uVar20 & 0xf;
4160: }
4161: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4162: iVar17 = piVar8[lVar18];
4163: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4164: if (0x1f < (int)uStack624) {
4165: cVar23 = (char)(int)uStack624;
4166: pcVar15 = pcVar24 + 1;
4167: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4168: *pcVar24 = cVar22;
4169: if (cVar22 == -1) {
4170: pcVar15 = pcVar24 + 2;
4171: pcVar24[1] = '\0';
4172: }
4173: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4174: *pcVar15 = cVar22;
4175: pcVar24 = pcVar15 + 1;
4176: if (cVar22 == -1) {
4177: pcVar24 = pcVar15 + 2;
4178: pcVar15[1] = '\0';
4179: }
4180: pcVar15 = pcVar24 + 1;
4181: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4182: *pcVar24 = cVar23;
4183: if (cVar23 == -1) {
4184: pcVar15 = pcVar24 + 2;
4185: pcVar24[1] = '\0';
4186: }
4187: uStack624._0_4_ = (int)uStack624 + -0x20;
4188: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4189: *pcVar15 = cVar23;
4190: pcVar24 = pcVar15 + 1;
4191: if (cVar23 == -1) {
4192: pcVar24 = pcVar15 + 2;
4193: pcVar15[1] = '\0';
4194: }
4195: }
4196: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4197: uVar20 = 0;
4198: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4199: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
4200: }
4201: uVar26 = SEXT24(psVar9[0x3b]);
4202: if (psVar9[0x3b] == 0) {
4203: uVar20 = uVar20 + 1;
4204: }
4205: else {
4206: uVar30 = (int)uVar26 >> 0x1f;
4207: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4208: if (0xf < (int)uVar20) {
4209: uVar25 = uVar20;
4210: do {
4211: if (0x2f < (int)uStack624) {
4212: cVar23 = (char)(int)uStack624;
4213: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4214: *pcVar24 = cVar22;
4215: pcVar15 = pcVar24 + 1;
4216: if (cVar22 == -1) {
4217: pcVar15 = pcVar24 + 2;
4218: pcVar24[1] = '\0';
4219: }
4220: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4221: *pcVar15 = cVar22;
4222: pcVar24 = pcVar15 + 1;
4223: if (cVar22 == -1) {
4224: pcVar24 = pcVar15 + 2;
4225: pcVar15[1] = '\0';
4226: }
4227: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4228: *pcVar24 = cVar22;
4229: pcVar15 = pcVar24 + 1;
4230: if (cVar22 == -1) {
4231: pcVar15 = pcVar24 + 2;
4232: pcVar24[1] = '\0';
4233: }
4234: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4235: *pcVar15 = cVar22;
4236: pcVar24 = pcVar15 + 1;
4237: if (cVar22 == -1) {
4238: pcVar24 = pcVar15 + 2;
4239: pcVar15[1] = '\0';
4240: }
4241: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4242: *pcVar24 = cVar23;
4243: pcVar15 = pcVar24 + 1;
4244: if (cVar23 == -1) {
4245: pcVar15 = pcVar24 + 2;
4246: pcVar24[1] = '\0';
4247: }
4248: uStack624._0_4_ = (int)uStack624 + -0x30;
4249: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4250: *pcVar15 = cVar23;
4251: pcVar24 = pcVar15 + 1;
4252: if (cVar23 == -1) {
4253: pcVar24 = pcVar15 + 2;
4254: pcVar15[1] = '\0';
4255: }
4256: }
4257: uVar25 = uVar25 - 0x10;
4258: uStack624._0_4_ = (int)uStack624 + iVar21;
4259: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4260: } while (0xf < (int)uVar25);
4261: uVar20 = uVar20 & 0xf;
4262: }
4263: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4264: iVar17 = piVar8[lVar18];
4265: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4266: if (0x1f < (int)uStack624) {
4267: cVar23 = (char)(int)uStack624;
4268: pcVar15 = pcVar24 + 1;
4269: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4270: *pcVar24 = cVar22;
4271: if (cVar22 == -1) {
4272: pcVar15 = pcVar24 + 2;
4273: pcVar24[1] = '\0';
4274: }
4275: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4276: *pcVar15 = cVar22;
4277: pcVar24 = pcVar15 + 1;
4278: if (cVar22 == -1) {
4279: pcVar24 = pcVar15 + 2;
4280: pcVar15[1] = '\0';
4281: }
4282: pcVar15 = pcVar24 + 1;
4283: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4284: *pcVar24 = cVar23;
4285: if (cVar23 == -1) {
4286: pcVar15 = pcVar24 + 2;
4287: pcVar24[1] = '\0';
4288: }
4289: uStack624._0_4_ = (int)uStack624 + -0x20;
4290: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4291: *pcVar15 = cVar23;
4292: pcVar24 = pcVar15 + 1;
4293: if (cVar23 == -1) {
4294: pcVar24 = pcVar15 + 2;
4295: pcVar15[1] = '\0';
4296: }
4297: }
4298: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4299: uVar20 = 0;
4300: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4301: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
4302: }
4303: uVar26 = SEXT24(psVar9[0x34]);
4304: if (psVar9[0x34] == 0) {
4305: sVar4 = psVar9[0x2d];
4306: uVar20 = uVar20 + 1;
4307: }
4308: else {
4309: uVar30 = (int)uVar26 >> 0x1f;
4310: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4311: if (0xf < (int)uVar20) {
4312: uVar25 = uVar20;
4313: do {
4314: if (0x2f < (int)uStack624) {
4315: cVar23 = (char)(int)uStack624;
4316: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4317: *pcVar24 = cVar22;
4318: pcVar15 = pcVar24 + 1;
4319: if (cVar22 == -1) {
4320: pcVar15 = pcVar24 + 2;
4321: pcVar24[1] = '\0';
4322: }
4323: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4324: *pcVar15 = cVar22;
4325: pcVar24 = pcVar15 + 1;
4326: if (cVar22 == -1) {
4327: pcVar24 = pcVar15 + 2;
4328: pcVar15[1] = '\0';
4329: }
4330: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4331: *pcVar24 = cVar22;
4332: pcVar15 = pcVar24 + 1;
4333: if (cVar22 == -1) {
4334: pcVar15 = pcVar24 + 2;
4335: pcVar24[1] = '\0';
4336: }
4337: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4338: *pcVar15 = cVar22;
4339: pcVar24 = pcVar15 + 1;
4340: if (cVar22 == -1) {
4341: pcVar24 = pcVar15 + 2;
4342: pcVar15[1] = '\0';
4343: }
4344: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4345: *pcVar24 = cVar23;
4346: pcVar15 = pcVar24 + 1;
4347: if (cVar23 == -1) {
4348: pcVar15 = pcVar24 + 2;
4349: pcVar24[1] = '\0';
4350: }
4351: uStack624._0_4_ = (int)uStack624 + -0x30;
4352: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4353: *pcVar15 = cVar23;
4354: pcVar24 = pcVar15 + 1;
4355: if (cVar23 == -1) {
4356: pcVar24 = pcVar15 + 2;
4357: pcVar15[1] = '\0';
4358: }
4359: }
4360: uVar25 = uVar25 - 0x10;
4361: uStack624._0_4_ = (int)uStack624 + iVar21;
4362: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4363: } while (0xf < (int)uVar25);
4364: uVar20 = uVar20 & 0xf;
4365: }
4366: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4367: iVar17 = piVar8[lVar18];
4368: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4369: if (0x1f < (int)uStack624) {
4370: cVar23 = (char)(int)uStack624;
4371: pcVar15 = pcVar24 + 1;
4372: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4373: *pcVar24 = cVar22;
4374: if (cVar22 == -1) {
4375: pcVar15 = pcVar24 + 2;
4376: pcVar24[1] = '\0';
4377: }
4378: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4379: *pcVar15 = cVar22;
4380: pcVar24 = pcVar15 + 1;
4381: if (cVar22 == -1) {
4382: pcVar24 = pcVar15 + 2;
4383: pcVar15[1] = '\0';
4384: }
4385: pcVar15 = pcVar24 + 1;
4386: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4387: *pcVar24 = cVar23;
4388: if (cVar23 == -1) {
4389: pcVar15 = pcVar24 + 2;
4390: pcVar24[1] = '\0';
4391: }
4392: uStack624._0_4_ = (int)uStack624 + -0x20;
4393: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4394: *pcVar15 = cVar23;
4395: pcVar24 = pcVar15 + 1;
4396: if (cVar23 == -1) {
4397: pcVar24 = pcVar15 + 2;
4398: pcVar15[1] = '\0';
4399: }
4400: }
4401: sVar4 = psVar9[0x2d];
4402: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4403: uVar20 = 0;
4404: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4405: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
4406: }
4407: if (sVar4 == 0) {
4408: uVar20 = uVar20 + 1;
4409: }
4410: else {
4411: uVar30 = SEXT24(sVar4);
4412: uVar26 = (int)uVar30 >> 0x1f;
4413: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
4414: if (0xf < (int)uVar20) {
4415: uVar25 = uVar20;
4416: do {
4417: if (0x2f < (int)uStack624) {
4418: cVar23 = (char)(int)uStack624;
4419: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4420: *pcVar24 = cVar22;
4421: pcVar15 = pcVar24 + 1;
4422: if (cVar22 == -1) {
4423: pcVar15 = pcVar24 + 2;
4424: pcVar24[1] = '\0';
4425: }
4426: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4427: *pcVar15 = cVar22;
4428: pcVar24 = pcVar15 + 1;
4429: if (cVar22 == -1) {
4430: pcVar24 = pcVar15 + 2;
4431: pcVar15[1] = '\0';
4432: }
4433: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4434: *pcVar24 = cVar22;
4435: pcVar15 = pcVar24 + 1;
4436: if (cVar22 == -1) {
4437: pcVar15 = pcVar24 + 2;
4438: pcVar24[1] = '\0';
4439: }
4440: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4441: *pcVar15 = cVar22;
4442: pcVar24 = pcVar15 + 1;
4443: if (cVar22 == -1) {
4444: pcVar24 = pcVar15 + 2;
4445: pcVar15[1] = '\0';
4446: }
4447: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4448: *pcVar24 = cVar23;
4449: pcVar15 = pcVar24 + 1;
4450: if (cVar23 == -1) {
4451: pcVar15 = pcVar24 + 2;
4452: pcVar24[1] = '\0';
4453: }
4454: uStack624._0_4_ = (int)uStack624 + -0x30;
4455: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4456: *pcVar15 = cVar23;
4457: pcVar24 = pcVar15 + 1;
4458: if (cVar23 == -1) {
4459: pcVar24 = pcVar15 + 2;
4460: pcVar15[1] = '\0';
4461: }
4462: }
4463: uVar25 = uVar25 - 0x10;
4464: uStack624._0_4_ = (int)uStack624 + iVar21;
4465: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4466: } while (0xf < (int)uVar25);
4467: uVar20 = uVar20 & 0xf;
4468: }
4469: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4470: iVar17 = piVar8[lVar18];
4471: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4472: if (0x1f < (int)uStack624) {
4473: cVar23 = (char)(int)uStack624;
4474: pcVar15 = pcVar24 + 1;
4475: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4476: *pcVar24 = cVar22;
4477: if (cVar22 == -1) {
4478: pcVar15 = pcVar24 + 2;
4479: pcVar24[1] = '\0';
4480: }
4481: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4482: *pcVar15 = cVar22;
4483: pcVar24 = pcVar15 + 1;
4484: if (cVar22 == -1) {
4485: pcVar24 = pcVar15 + 2;
4486: pcVar15[1] = '\0';
4487: }
4488: pcVar15 = pcVar24 + 1;
4489: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4490: *pcVar24 = cVar23;
4491: if (cVar23 == -1) {
4492: pcVar15 = pcVar24 + 2;
4493: pcVar24[1] = '\0';
4494: }
4495: uStack624._0_4_ = (int)uStack624 + -0x20;
4496: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4497: *pcVar15 = cVar23;
4498: pcVar24 = pcVar15 + 1;
4499: if (cVar23 == -1) {
4500: pcVar24 = pcVar15 + 2;
4501: pcVar15[1] = '\0';
4502: }
4503: }
4504: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4505: uVar20 = 0;
4506: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4507: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
4508: }
4509: uVar26 = SEXT24(psVar9[0x26]);
4510: if (psVar9[0x26] == 0) {
4511: uVar20 = uVar20 + 1;
4512: }
4513: else {
4514: uVar30 = (int)uVar26 >> 0x1f;
4515: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4516: if (0xf < (int)uVar20) {
4517: uVar25 = uVar20;
4518: do {
4519: if (0x2f < (int)uStack624) {
4520: cVar23 = (char)(int)uStack624;
4521: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4522: *pcVar24 = cVar22;
4523: pcVar15 = pcVar24 + 1;
4524: if (cVar22 == -1) {
4525: pcVar15 = pcVar24 + 2;
4526: pcVar24[1] = '\0';
4527: }
4528: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4529: *pcVar15 = cVar22;
4530: pcVar24 = pcVar15 + 1;
4531: if (cVar22 == -1) {
4532: pcVar24 = pcVar15 + 2;
4533: pcVar15[1] = '\0';
4534: }
4535: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4536: *pcVar24 = cVar22;
4537: pcVar15 = pcVar24 + 1;
4538: if (cVar22 == -1) {
4539: pcVar15 = pcVar24 + 2;
4540: pcVar24[1] = '\0';
4541: }
4542: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4543: *pcVar15 = cVar22;
4544: pcVar24 = pcVar15 + 1;
4545: if (cVar22 == -1) {
4546: pcVar24 = pcVar15 + 2;
4547: pcVar15[1] = '\0';
4548: }
4549: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4550: *pcVar24 = cVar23;
4551: pcVar15 = pcVar24 + 1;
4552: if (cVar23 == -1) {
4553: pcVar15 = pcVar24 + 2;
4554: pcVar24[1] = '\0';
4555: }
4556: uStack624._0_4_ = (int)uStack624 + -0x30;
4557: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4558: *pcVar15 = cVar23;
4559: pcVar24 = pcVar15 + 1;
4560: if (cVar23 == -1) {
4561: pcVar24 = pcVar15 + 2;
4562: pcVar15[1] = '\0';
4563: }
4564: }
4565: uVar25 = uVar25 - 0x10;
4566: uStack624._0_4_ = (int)uStack624 + iVar21;
4567: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4568: } while (0xf < (int)uVar25);
4569: uVar20 = uVar20 & 0xf;
4570: }
4571: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4572: iVar17 = piVar8[lVar18];
4573: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4574: if (0x1f < (int)uStack624) {
4575: cVar23 = (char)(int)uStack624;
4576: pcVar15 = pcVar24 + 1;
4577: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4578: *pcVar24 = cVar22;
4579: if (cVar22 == -1) {
4580: pcVar15 = pcVar24 + 2;
4581: pcVar24[1] = '\0';
4582: }
4583: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4584: *pcVar15 = cVar22;
4585: pcVar24 = pcVar15 + 1;
4586: if (cVar22 == -1) {
4587: pcVar24 = pcVar15 + 2;
4588: pcVar15[1] = '\0';
4589: }
4590: pcVar15 = pcVar24 + 1;
4591: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4592: *pcVar24 = cVar23;
4593: if (cVar23 == -1) {
4594: pcVar15 = pcVar24 + 2;
4595: pcVar24[1] = '\0';
4596: }
4597: uStack624._0_4_ = (int)uStack624 + -0x20;
4598: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4599: *pcVar15 = cVar23;
4600: pcVar24 = pcVar15 + 1;
4601: if (cVar23 == -1) {
4602: pcVar24 = pcVar15 + 2;
4603: pcVar15[1] = '\0';
4604: }
4605: }
4606: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4607: uVar20 = 0;
4608: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4609: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
4610: }
4611: uVar26 = SEXT24(psVar9[0x1f]);
4612: if (psVar9[0x1f] == 0) {
4613: uVar20 = uVar20 + 1;
4614: }
4615: else {
4616: uVar30 = (int)uVar26 >> 0x1f;
4617: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4618: if (0xf < (int)uVar20) {
4619: uVar25 = uVar20;
4620: do {
4621: if (0x2f < (int)uStack624) {
4622: cVar23 = (char)(int)uStack624;
4623: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4624: *pcVar24 = cVar22;
4625: pcVar15 = pcVar24 + 1;
4626: if (cVar22 == -1) {
4627: pcVar15 = pcVar24 + 2;
4628: pcVar24[1] = '\0';
4629: }
4630: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4631: *pcVar15 = cVar22;
4632: pcVar24 = pcVar15 + 1;
4633: if (cVar22 == -1) {
4634: pcVar24 = pcVar15 + 2;
4635: pcVar15[1] = '\0';
4636: }
4637: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4638: *pcVar24 = cVar22;
4639: pcVar15 = pcVar24 + 1;
4640: if (cVar22 == -1) {
4641: pcVar15 = pcVar24 + 2;
4642: pcVar24[1] = '\0';
4643: }
4644: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4645: *pcVar15 = cVar22;
4646: pcVar24 = pcVar15 + 1;
4647: if (cVar22 == -1) {
4648: pcVar24 = pcVar15 + 2;
4649: pcVar15[1] = '\0';
4650: }
4651: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4652: *pcVar24 = cVar23;
4653: pcVar15 = pcVar24 + 1;
4654: if (cVar23 == -1) {
4655: pcVar15 = pcVar24 + 2;
4656: pcVar24[1] = '\0';
4657: }
4658: uStack624._0_4_ = (int)uStack624 + -0x30;
4659: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4660: *pcVar15 = cVar23;
4661: pcVar24 = pcVar15 + 1;
4662: if (cVar23 == -1) {
4663: pcVar24 = pcVar15 + 2;
4664: pcVar15[1] = '\0';
4665: }
4666: }
4667: uVar25 = uVar25 - 0x10;
4668: uStack624._0_4_ = (int)uStack624 + iVar21;
4669: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4670: } while (0xf < (int)uVar25);
4671: uVar20 = uVar20 & 0xf;
4672: }
4673: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4674: iVar17 = piVar8[lVar18];
4675: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4676: if (0x1f < (int)uStack624) {
4677: cVar23 = (char)(int)uStack624;
4678: pcVar15 = pcVar24 + 1;
4679: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4680: *pcVar24 = cVar22;
4681: if (cVar22 == -1) {
4682: pcVar15 = pcVar24 + 2;
4683: pcVar24[1] = '\0';
4684: }
4685: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4686: *pcVar15 = cVar22;
4687: pcVar24 = pcVar15 + 1;
4688: if (cVar22 == -1) {
4689: pcVar24 = pcVar15 + 2;
4690: pcVar15[1] = '\0';
4691: }
4692: pcVar15 = pcVar24 + 1;
4693: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4694: *pcVar24 = cVar23;
4695: if (cVar23 == -1) {
4696: pcVar15 = pcVar24 + 2;
4697: pcVar24[1] = '\0';
4698: }
4699: uStack624._0_4_ = (int)uStack624 + -0x20;
4700: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4701: *pcVar15 = cVar23;
4702: pcVar24 = pcVar15 + 1;
4703: if (cVar23 == -1) {
4704: pcVar24 = pcVar15 + 2;
4705: pcVar15[1] = '\0';
4706: }
4707: }
4708: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4709: uVar20 = 0;
4710: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4711: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
4712: }
4713: uVar26 = SEXT24(psVar9[0x27]);
4714: if (psVar9[0x27] == 0) {
4715: uVar20 = uVar20 + 1;
4716: }
4717: else {
4718: uVar30 = (int)uVar26 >> 0x1f;
4719: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4720: if (0xf < (int)uVar20) {
4721: uVar25 = uVar20;
4722: do {
4723: if (0x2f < (int)uStack624) {
4724: cVar23 = (char)(int)uStack624;
4725: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4726: *pcVar24 = cVar22;
4727: pcVar15 = pcVar24 + 1;
4728: if (cVar22 == -1) {
4729: pcVar15 = pcVar24 + 2;
4730: pcVar24[1] = '\0';
4731: }
4732: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4733: *pcVar15 = cVar22;
4734: pcVar24 = pcVar15 + 1;
4735: if (cVar22 == -1) {
4736: pcVar24 = pcVar15 + 2;
4737: pcVar15[1] = '\0';
4738: }
4739: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4740: *pcVar24 = cVar22;
4741: pcVar15 = pcVar24 + 1;
4742: if (cVar22 == -1) {
4743: pcVar15 = pcVar24 + 2;
4744: pcVar24[1] = '\0';
4745: }
4746: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4747: *pcVar15 = cVar22;
4748: pcVar24 = pcVar15 + 1;
4749: if (cVar22 == -1) {
4750: pcVar24 = pcVar15 + 2;
4751: pcVar15[1] = '\0';
4752: }
4753: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4754: *pcVar24 = cVar23;
4755: pcVar15 = pcVar24 + 1;
4756: if (cVar23 == -1) {
4757: pcVar15 = pcVar24 + 2;
4758: pcVar24[1] = '\0';
4759: }
4760: uStack624._0_4_ = (int)uStack624 + -0x30;
4761: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4762: *pcVar15 = cVar23;
4763: pcVar24 = pcVar15 + 1;
4764: if (cVar23 == -1) {
4765: pcVar24 = pcVar15 + 2;
4766: pcVar15[1] = '\0';
4767: }
4768: }
4769: uVar25 = uVar25 - 0x10;
4770: uStack624._0_4_ = (int)uStack624 + iVar21;
4771: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4772: } while (0xf < (int)uVar25);
4773: uVar20 = uVar20 & 0xf;
4774: }
4775: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4776: iVar17 = piVar8[lVar18];
4777: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4778: if (0x1f < (int)uStack624) {
4779: cVar23 = (char)(int)uStack624;
4780: pcVar15 = pcVar24 + 1;
4781: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4782: *pcVar24 = cVar22;
4783: if (cVar22 == -1) {
4784: pcVar15 = pcVar24 + 2;
4785: pcVar24[1] = '\0';
4786: }
4787: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4788: *pcVar15 = cVar22;
4789: pcVar24 = pcVar15 + 1;
4790: if (cVar22 == -1) {
4791: pcVar24 = pcVar15 + 2;
4792: pcVar15[1] = '\0';
4793: }
4794: pcVar15 = pcVar24 + 1;
4795: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4796: *pcVar24 = cVar23;
4797: if (cVar23 == -1) {
4798: pcVar15 = pcVar24 + 2;
4799: pcVar24[1] = '\0';
4800: }
4801: uStack624._0_4_ = (int)uStack624 + -0x20;
4802: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4803: *pcVar15 = cVar23;
4804: pcVar24 = pcVar15 + 1;
4805: if (cVar23 == -1) {
4806: pcVar24 = pcVar15 + 2;
4807: pcVar15[1] = '\0';
4808: }
4809: }
4810: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4811: uVar20 = 0;
4812: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4813: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
4814: }
4815: uVar26 = SEXT24(psVar9[0x2e]);
4816: if (psVar9[0x2e] == 0) {
4817: uVar20 = uVar20 + 1;
4818: }
4819: else {
4820: uVar30 = (int)uVar26 >> 0x1f;
4821: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4822: if (0xf < (int)uVar20) {
4823: uVar25 = uVar20;
4824: do {
4825: if (0x2f < (int)uStack624) {
4826: cVar23 = (char)(int)uStack624;
4827: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4828: *pcVar24 = cVar22;
4829: pcVar15 = pcVar24 + 1;
4830: if (cVar22 == -1) {
4831: pcVar15 = pcVar24 + 2;
4832: pcVar24[1] = '\0';
4833: }
4834: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4835: *pcVar15 = cVar22;
4836: pcVar24 = pcVar15 + 1;
4837: if (cVar22 == -1) {
4838: pcVar24 = pcVar15 + 2;
4839: pcVar15[1] = '\0';
4840: }
4841: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4842: *pcVar24 = cVar22;
4843: pcVar15 = pcVar24 + 1;
4844: if (cVar22 == -1) {
4845: pcVar15 = pcVar24 + 2;
4846: pcVar24[1] = '\0';
4847: }
4848: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4849: *pcVar15 = cVar22;
4850: pcVar24 = pcVar15 + 1;
4851: if (cVar22 == -1) {
4852: pcVar24 = pcVar15 + 2;
4853: pcVar15[1] = '\0';
4854: }
4855: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4856: *pcVar24 = cVar23;
4857: pcVar15 = pcVar24 + 1;
4858: if (cVar23 == -1) {
4859: pcVar15 = pcVar24 + 2;
4860: pcVar24[1] = '\0';
4861: }
4862: uStack624._0_4_ = (int)uStack624 + -0x30;
4863: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4864: *pcVar15 = cVar23;
4865: pcVar24 = pcVar15 + 1;
4866: if (cVar23 == -1) {
4867: pcVar24 = pcVar15 + 2;
4868: pcVar15[1] = '\0';
4869: }
4870: }
4871: uVar25 = uVar25 - 0x10;
4872: uStack624._0_4_ = (int)uStack624 + iVar21;
4873: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4874: } while (0xf < (int)uVar25);
4875: uVar20 = uVar20 & 0xf;
4876: }
4877: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4878: iVar17 = piVar8[lVar18];
4879: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4880: if (0x1f < (int)uStack624) {
4881: cVar23 = (char)(int)uStack624;
4882: pcVar15 = pcVar24 + 1;
4883: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4884: *pcVar24 = cVar22;
4885: if (cVar22 == -1) {
4886: pcVar15 = pcVar24 + 2;
4887: pcVar24[1] = '\0';
4888: }
4889: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4890: *pcVar15 = cVar22;
4891: pcVar24 = pcVar15 + 1;
4892: if (cVar22 == -1) {
4893: pcVar24 = pcVar15 + 2;
4894: pcVar15[1] = '\0';
4895: }
4896: pcVar15 = pcVar24 + 1;
4897: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4898: *pcVar24 = cVar23;
4899: if (cVar23 == -1) {
4900: pcVar15 = pcVar24 + 2;
4901: pcVar24[1] = '\0';
4902: }
4903: uStack624._0_4_ = (int)uStack624 + -0x20;
4904: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4905: *pcVar15 = cVar23;
4906: pcVar24 = pcVar15 + 1;
4907: if (cVar23 == -1) {
4908: pcVar24 = pcVar15 + 2;
4909: pcVar15[1] = '\0';
4910: }
4911: }
4912: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
4913: uVar20 = 0;
4914: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
4915: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
4916: }
4917: uVar26 = SEXT24(psVar9[0x35]);
4918: if (psVar9[0x35] == 0) {
4919: uVar20 = uVar20 + 1;
4920: }
4921: else {
4922: uVar30 = (int)uVar26 >> 0x1f;
4923: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
4924: if (0xf < (int)uVar20) {
4925: uVar25 = uVar20;
4926: do {
4927: if (0x2f < (int)uStack624) {
4928: cVar23 = (char)(int)uStack624;
4929: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4930: *pcVar24 = cVar22;
4931: pcVar15 = pcVar24 + 1;
4932: if (cVar22 == -1) {
4933: pcVar15 = pcVar24 + 2;
4934: pcVar24[1] = '\0';
4935: }
4936: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4937: *pcVar15 = cVar22;
4938: pcVar24 = pcVar15 + 1;
4939: if (cVar22 == -1) {
4940: pcVar24 = pcVar15 + 2;
4941: pcVar15[1] = '\0';
4942: }
4943: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
4944: *pcVar24 = cVar22;
4945: pcVar15 = pcVar24 + 1;
4946: if (cVar22 == -1) {
4947: pcVar15 = pcVar24 + 2;
4948: pcVar24[1] = '\0';
4949: }
4950: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
4951: *pcVar15 = cVar22;
4952: pcVar24 = pcVar15 + 1;
4953: if (cVar22 == -1) {
4954: pcVar24 = pcVar15 + 2;
4955: pcVar15[1] = '\0';
4956: }
4957: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
4958: *pcVar24 = cVar23;
4959: pcVar15 = pcVar24 + 1;
4960: if (cVar23 == -1) {
4961: pcVar15 = pcVar24 + 2;
4962: pcVar24[1] = '\0';
4963: }
4964: uStack624._0_4_ = (int)uStack624 + -0x30;
4965: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
4966: *pcVar15 = cVar23;
4967: pcVar24 = pcVar15 + 1;
4968: if (cVar23 == -1) {
4969: pcVar24 = pcVar15 + 2;
4970: pcVar15[1] = '\0';
4971: }
4972: }
4973: uVar25 = uVar25 - 0x10;
4974: uStack624._0_4_ = (int)uStack624 + iVar21;
4975: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
4976: } while (0xf < (int)uVar25);
4977: uVar20 = uVar20 & 0xf;
4978: }
4979: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
4980: iVar17 = piVar8[lVar18];
4981: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
4982: if (0x1f < (int)uStack624) {
4983: cVar23 = (char)(int)uStack624;
4984: pcVar15 = pcVar24 + 1;
4985: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
4986: *pcVar24 = cVar22;
4987: if (cVar22 == -1) {
4988: pcVar15 = pcVar24 + 2;
4989: pcVar24[1] = '\0';
4990: }
4991: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
4992: *pcVar15 = cVar22;
4993: pcVar24 = pcVar15 + 1;
4994: if (cVar22 == -1) {
4995: pcVar24 = pcVar15 + 2;
4996: pcVar15[1] = '\0';
4997: }
4998: pcVar15 = pcVar24 + 1;
4999: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5000: *pcVar24 = cVar23;
5001: if (cVar23 == -1) {
5002: pcVar15 = pcVar24 + 2;
5003: pcVar24[1] = '\0';
5004: }
5005: uStack624._0_4_ = (int)uStack624 + -0x20;
5006: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5007: *pcVar15 = cVar23;
5008: pcVar24 = pcVar15 + 1;
5009: if (cVar23 == -1) {
5010: pcVar24 = pcVar15 + 2;
5011: pcVar15[1] = '\0';
5012: }
5013: }
5014: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
5015: uVar20 = 0;
5016: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
5017: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
5018: }
5019: uVar26 = SEXT24(psVar9[0x3c]);
5020: if (psVar9[0x3c] == 0) {
5021: uVar20 = uVar20 + 1;
5022: }
5023: else {
5024: uVar30 = (int)uVar26 >> 0x1f;
5025: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
5026: if (0xf < (int)uVar20) {
5027: uVar25 = uVar20;
5028: do {
5029: if (0x2f < (int)uStack624) {
5030: cVar23 = (char)(int)uStack624;
5031: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5032: *pcVar24 = cVar22;
5033: pcVar15 = pcVar24 + 1;
5034: if (cVar22 == -1) {
5035: pcVar15 = pcVar24 + 2;
5036: pcVar24[1] = '\0';
5037: }
5038: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5039: *pcVar15 = cVar22;
5040: pcVar24 = pcVar15 + 1;
5041: if (cVar22 == -1) {
5042: pcVar24 = pcVar15 + 2;
5043: pcVar15[1] = '\0';
5044: }
5045: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5046: *pcVar24 = cVar22;
5047: pcVar15 = pcVar24 + 1;
5048: if (cVar22 == -1) {
5049: pcVar15 = pcVar24 + 2;
5050: pcVar24[1] = '\0';
5051: }
5052: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
5053: *pcVar15 = cVar22;
5054: pcVar24 = pcVar15 + 1;
5055: if (cVar22 == -1) {
5056: pcVar24 = pcVar15 + 2;
5057: pcVar15[1] = '\0';
5058: }
5059: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
5060: *pcVar24 = cVar23;
5061: pcVar15 = pcVar24 + 1;
5062: if (cVar23 == -1) {
5063: pcVar15 = pcVar24 + 2;
5064: pcVar24[1] = '\0';
5065: }
5066: uStack624._0_4_ = (int)uStack624 + -0x30;
5067: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5068: *pcVar15 = cVar23;
5069: pcVar24 = pcVar15 + 1;
5070: if (cVar23 == -1) {
5071: pcVar24 = pcVar15 + 2;
5072: pcVar15[1] = '\0';
5073: }
5074: }
5075: uVar25 = uVar25 - 0x10;
5076: uStack624._0_4_ = (int)uStack624 + iVar21;
5077: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
5078: } while (0xf < (int)uVar25);
5079: uVar20 = uVar20 & 0xf;
5080: }
5081: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
5082: iVar17 = piVar8[lVar18];
5083: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
5084: if (0x1f < (int)uStack624) {
5085: cVar23 = (char)(int)uStack624;
5086: pcVar15 = pcVar24 + 1;
5087: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5088: *pcVar24 = cVar22;
5089: if (cVar22 == -1) {
5090: pcVar15 = pcVar24 + 2;
5091: pcVar24[1] = '\0';
5092: }
5093: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5094: *pcVar15 = cVar22;
5095: pcVar24 = pcVar15 + 1;
5096: if (cVar22 == -1) {
5097: pcVar24 = pcVar15 + 2;
5098: pcVar15[1] = '\0';
5099: }
5100: pcVar15 = pcVar24 + 1;
5101: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5102: *pcVar24 = cVar23;
5103: if (cVar23 == -1) {
5104: pcVar15 = pcVar24 + 2;
5105: pcVar24[1] = '\0';
5106: }
5107: uStack624._0_4_ = (int)uStack624 + -0x20;
5108: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5109: *pcVar15 = cVar23;
5110: pcVar24 = pcVar15 + 1;
5111: if (cVar23 == -1) {
5112: pcVar24 = pcVar15 + 2;
5113: pcVar15[1] = '\0';
5114: }
5115: }
5116: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
5117: uVar20 = 0;
5118: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
5119: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
5120: }
5121: uVar26 = SEXT24(psVar9[0x3d]);
5122: if (psVar9[0x3d] == 0) {
5123: sVar4 = psVar9[0x36];
5124: uVar20 = uVar20 + 1;
5125: }
5126: else {
5127: uVar30 = (int)uVar26 >> 0x1f;
5128: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
5129: if (0xf < (int)uVar20) {
5130: uVar25 = uVar20;
5131: do {
5132: if (0x2f < (int)uStack624) {
5133: cVar23 = (char)(int)uStack624;
5134: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5135: *pcVar24 = cVar22;
5136: pcVar15 = pcVar24 + 1;
5137: if (cVar22 == -1) {
5138: pcVar15 = pcVar24 + 2;
5139: pcVar24[1] = '\0';
5140: }
5141: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5142: *pcVar15 = cVar22;
5143: pcVar24 = pcVar15 + 1;
5144: if (cVar22 == -1) {
5145: pcVar24 = pcVar15 + 2;
5146: pcVar15[1] = '\0';
5147: }
5148: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5149: *pcVar24 = cVar22;
5150: pcVar15 = pcVar24 + 1;
5151: if (cVar22 == -1) {
5152: pcVar15 = pcVar24 + 2;
5153: pcVar24[1] = '\0';
5154: }
5155: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
5156: *pcVar15 = cVar22;
5157: pcVar24 = pcVar15 + 1;
5158: if (cVar22 == -1) {
5159: pcVar24 = pcVar15 + 2;
5160: pcVar15[1] = '\0';
5161: }
5162: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
5163: *pcVar24 = cVar23;
5164: pcVar15 = pcVar24 + 1;
5165: if (cVar23 == -1) {
5166: pcVar15 = pcVar24 + 2;
5167: pcVar24[1] = '\0';
5168: }
5169: uStack624._0_4_ = (int)uStack624 + -0x30;
5170: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5171: *pcVar15 = cVar23;
5172: pcVar24 = pcVar15 + 1;
5173: if (cVar23 == -1) {
5174: pcVar24 = pcVar15 + 2;
5175: pcVar15[1] = '\0';
5176: }
5177: }
5178: uVar25 = uVar25 - 0x10;
5179: uStack624._0_4_ = (int)uStack624 + iVar21;
5180: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
5181: } while (0xf < (int)uVar25);
5182: uVar20 = uVar20 & 0xf;
5183: }
5184: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
5185: iVar17 = piVar8[lVar18];
5186: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
5187: if (0x1f < (int)uStack624) {
5188: cVar23 = (char)(int)uStack624;
5189: pcVar15 = pcVar24 + 1;
5190: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5191: *pcVar24 = cVar22;
5192: if (cVar22 == -1) {
5193: pcVar15 = pcVar24 + 2;
5194: pcVar24[1] = '\0';
5195: }
5196: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5197: *pcVar15 = cVar22;
5198: pcVar24 = pcVar15 + 1;
5199: if (cVar22 == -1) {
5200: pcVar24 = pcVar15 + 2;
5201: pcVar15[1] = '\0';
5202: }
5203: pcVar15 = pcVar24 + 1;
5204: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5205: *pcVar24 = cVar23;
5206: if (cVar23 == -1) {
5207: pcVar15 = pcVar24 + 2;
5208: pcVar24[1] = '\0';
5209: }
5210: uStack624._0_4_ = (int)uStack624 + -0x20;
5211: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5212: *pcVar15 = cVar23;
5213: pcVar24 = pcVar15 + 1;
5214: if (cVar23 == -1) {
5215: pcVar24 = pcVar15 + 2;
5216: pcVar15[1] = '\0';
5217: }
5218: }
5219: sVar4 = psVar9[0x36];
5220: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
5221: uVar20 = 0;
5222: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
5223: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
5224: }
5225: if (sVar4 == 0) {
5226: uVar20 = uVar20 + 1;
5227: }
5228: else {
5229: uVar30 = SEXT24(sVar4);
5230: uVar26 = (int)uVar30 >> 0x1f;
5231: bVar2 = (&DAT_00168f80)[(int)((uVar26 ^ uVar30) - uVar26)];
5232: if (0xf < (int)uVar20) {
5233: uVar25 = uVar20;
5234: do {
5235: if (0x2f < (int)uStack624) {
5236: cVar23 = (char)(int)uStack624;
5237: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5238: *pcVar24 = cVar22;
5239: pcVar15 = pcVar24 + 1;
5240: if (cVar22 == -1) {
5241: pcVar15 = pcVar24 + 2;
5242: pcVar24[1] = '\0';
5243: }
5244: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5245: *pcVar15 = cVar22;
5246: pcVar24 = pcVar15 + 1;
5247: if (cVar22 == -1) {
5248: pcVar24 = pcVar15 + 2;
5249: pcVar15[1] = '\0';
5250: }
5251: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5252: *pcVar24 = cVar22;
5253: pcVar15 = pcVar24 + 1;
5254: if (cVar22 == -1) {
5255: pcVar15 = pcVar24 + 2;
5256: pcVar24[1] = '\0';
5257: }
5258: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
5259: *pcVar15 = cVar22;
5260: pcVar24 = pcVar15 + 1;
5261: if (cVar22 == -1) {
5262: pcVar24 = pcVar15 + 2;
5263: pcVar15[1] = '\0';
5264: }
5265: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
5266: *pcVar24 = cVar23;
5267: pcVar15 = pcVar24 + 1;
5268: if (cVar23 == -1) {
5269: pcVar15 = pcVar24 + 2;
5270: pcVar24[1] = '\0';
5271: }
5272: uStack624._0_4_ = (int)uStack624 + -0x30;
5273: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5274: *pcVar15 = cVar23;
5275: pcVar24 = pcVar15 + 1;
5276: if (cVar23 == -1) {
5277: pcVar24 = pcVar15 + 2;
5278: pcVar15[1] = '\0';
5279: }
5280: }
5281: uVar25 = uVar25 - 0x10;
5282: uStack624._0_4_ = (int)uStack624 + iVar21;
5283: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
5284: } while (0xf < (int)uVar25);
5285: uVar20 = uVar20 & 0xf;
5286: }
5287: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
5288: iVar17 = piVar8[lVar18];
5289: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
5290: if (0x1f < (int)uStack624) {
5291: cVar23 = (char)(int)uStack624;
5292: pcVar15 = pcVar24 + 1;
5293: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5294: *pcVar24 = cVar22;
5295: if (cVar22 == -1) {
5296: pcVar15 = pcVar24 + 2;
5297: pcVar24[1] = '\0';
5298: }
5299: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5300: *pcVar15 = cVar22;
5301: pcVar24 = pcVar15 + 1;
5302: if (cVar22 == -1) {
5303: pcVar24 = pcVar15 + 2;
5304: pcVar15[1] = '\0';
5305: }
5306: pcVar15 = pcVar24 + 1;
5307: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5308: *pcVar24 = cVar23;
5309: if (cVar23 == -1) {
5310: pcVar15 = pcVar24 + 2;
5311: pcVar24[1] = '\0';
5312: }
5313: uStack624._0_4_ = (int)uStack624 + -0x20;
5314: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5315: *pcVar15 = cVar23;
5316: pcVar24 = pcVar15 + 1;
5317: if (cVar23 == -1) {
5318: pcVar24 = pcVar15 + 2;
5319: pcVar15[1] = '\0';
5320: }
5321: }
5322: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
5323: uVar20 = 0;
5324: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
5325: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar30 + uVar26);
5326: }
5327: uVar26 = SEXT24(psVar9[0x2f]);
5328: if (psVar9[0x2f] == 0) {
5329: uVar20 = uVar20 + 1;
5330: }
5331: else {
5332: uVar30 = (int)uVar26 >> 0x1f;
5333: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
5334: if (0xf < (int)uVar20) {
5335: uVar25 = uVar20;
5336: do {
5337: if (0x2f < (int)uStack624) {
5338: cVar23 = (char)(int)uStack624;
5339: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5340: *pcVar24 = cVar22;
5341: pcVar15 = pcVar24 + 1;
5342: if (cVar22 == -1) {
5343: pcVar15 = pcVar24 + 2;
5344: pcVar24[1] = '\0';
5345: }
5346: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5347: *pcVar15 = cVar22;
5348: pcVar24 = pcVar15 + 1;
5349: if (cVar22 == -1) {
5350: pcVar24 = pcVar15 + 2;
5351: pcVar15[1] = '\0';
5352: }
5353: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5354: *pcVar24 = cVar22;
5355: pcVar15 = pcVar24 + 1;
5356: if (cVar22 == -1) {
5357: pcVar15 = pcVar24 + 2;
5358: pcVar24[1] = '\0';
5359: }
5360: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
5361: *pcVar15 = cVar22;
5362: pcVar24 = pcVar15 + 1;
5363: if (cVar22 == -1) {
5364: pcVar24 = pcVar15 + 2;
5365: pcVar15[1] = '\0';
5366: }
5367: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
5368: *pcVar24 = cVar23;
5369: pcVar15 = pcVar24 + 1;
5370: if (cVar23 == -1) {
5371: pcVar15 = pcVar24 + 2;
5372: pcVar24[1] = '\0';
5373: }
5374: uStack624._0_4_ = (int)uStack624 + -0x30;
5375: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5376: *pcVar15 = cVar23;
5377: pcVar24 = pcVar15 + 1;
5378: if (cVar23 == -1) {
5379: pcVar24 = pcVar15 + 2;
5380: pcVar15[1] = '\0';
5381: }
5382: }
5383: uVar25 = uVar25 - 0x10;
5384: uStack624._0_4_ = (int)uStack624 + iVar21;
5385: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
5386: } while (0xf < (int)uVar25);
5387: uVar20 = uVar20 & 0xf;
5388: }
5389: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
5390: iVar17 = piVar8[lVar18];
5391: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
5392: if (0x1f < (int)uStack624) {
5393: cVar23 = (char)(int)uStack624;
5394: pcVar15 = pcVar24 + 1;
5395: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5396: *pcVar24 = cVar22;
5397: if (cVar22 == -1) {
5398: pcVar15 = pcVar24 + 2;
5399: pcVar24[1] = '\0';
5400: }
5401: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5402: *pcVar15 = cVar22;
5403: pcVar24 = pcVar15 + 1;
5404: if (cVar22 == -1) {
5405: pcVar24 = pcVar15 + 2;
5406: pcVar15[1] = '\0';
5407: }
5408: pcVar15 = pcVar24 + 1;
5409: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5410: *pcVar24 = cVar23;
5411: if (cVar23 == -1) {
5412: pcVar15 = pcVar24 + 2;
5413: pcVar24[1] = '\0';
5414: }
5415: uStack624._0_4_ = (int)uStack624 + -0x20;
5416: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5417: *pcVar15 = cVar23;
5418: pcVar24 = pcVar15 + 1;
5419: if (cVar23 == -1) {
5420: pcVar24 = pcVar15 + 2;
5421: pcVar15[1] = '\0';
5422: }
5423: }
5424: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
5425: uVar20 = 0;
5426: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
5427: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
5428: }
5429: uVar26 = SEXT24(psVar9[0x37]);
5430: if (psVar9[0x37] == 0) {
5431: uVar20 = uVar20 + 1;
5432: }
5433: else {
5434: uVar30 = (int)uVar26 >> 0x1f;
5435: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
5436: if (0xf < (int)uVar20) {
5437: uVar25 = uVar20;
5438: do {
5439: if (0x2f < (int)uStack624) {
5440: cVar23 = (char)(int)uStack624;
5441: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5442: *pcVar24 = cVar22;
5443: pcVar15 = pcVar24 + 1;
5444: if (cVar22 == -1) {
5445: pcVar15 = pcVar24 + 2;
5446: pcVar24[1] = '\0';
5447: }
5448: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5449: *pcVar15 = cVar22;
5450: pcVar24 = pcVar15 + 1;
5451: if (cVar22 == -1) {
5452: pcVar24 = pcVar15 + 2;
5453: pcVar15[1] = '\0';
5454: }
5455: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5456: *pcVar24 = cVar22;
5457: pcVar15 = pcVar24 + 1;
5458: if (cVar22 == -1) {
5459: pcVar15 = pcVar24 + 2;
5460: pcVar24[1] = '\0';
5461: }
5462: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
5463: *pcVar15 = cVar22;
5464: pcVar24 = pcVar15 + 1;
5465: if (cVar22 == -1) {
5466: pcVar24 = pcVar15 + 2;
5467: pcVar15[1] = '\0';
5468: }
5469: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
5470: *pcVar24 = cVar23;
5471: pcVar15 = pcVar24 + 1;
5472: if (cVar23 == -1) {
5473: pcVar15 = pcVar24 + 2;
5474: pcVar24[1] = '\0';
5475: }
5476: uStack624._0_4_ = (int)uStack624 + -0x30;
5477: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5478: *pcVar15 = cVar23;
5479: pcVar24 = pcVar15 + 1;
5480: if (cVar23 == -1) {
5481: pcVar24 = pcVar15 + 2;
5482: pcVar15[1] = '\0';
5483: }
5484: }
5485: uVar25 = uVar25 - 0x10;
5486: uStack624._0_4_ = (int)uStack624 + iVar21;
5487: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
5488: } while (0xf < (int)uVar25);
5489: uVar20 = uVar20 & 0xf;
5490: }
5491: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
5492: iVar17 = piVar8[lVar18];
5493: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
5494: if (0x1f < (int)uStack624) {
5495: cVar23 = (char)(int)uStack624;
5496: pcVar15 = pcVar24 + 1;
5497: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5498: *pcVar24 = cVar22;
5499: if (cVar22 == -1) {
5500: pcVar15 = pcVar24 + 2;
5501: pcVar24[1] = '\0';
5502: }
5503: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5504: *pcVar15 = cVar22;
5505: pcVar24 = pcVar15 + 1;
5506: if (cVar22 == -1) {
5507: pcVar24 = pcVar15 + 2;
5508: pcVar15[1] = '\0';
5509: }
5510: pcVar15 = pcVar24 + 1;
5511: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5512: *pcVar24 = cVar23;
5513: if (cVar23 == -1) {
5514: pcVar15 = pcVar24 + 2;
5515: pcVar24[1] = '\0';
5516: }
5517: uStack624._0_4_ = (int)uStack624 + -0x20;
5518: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5519: *pcVar15 = cVar23;
5520: pcVar24 = pcVar15 + 1;
5521: if (cVar23 == -1) {
5522: pcVar24 = pcVar15 + 2;
5523: pcVar15[1] = '\0';
5524: }
5525: }
5526: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
5527: uVar20 = 0;
5528: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
5529: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
5530: }
5531: uVar26 = SEXT24(psVar9[0x3e]);
5532: if (psVar9[0x3e] == 0) {
5533: uVar20 = uVar20 + 1;
5534: }
5535: else {
5536: uVar30 = (int)uVar26 >> 0x1f;
5537: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
5538: if (0xf < (int)uVar20) {
5539: uVar25 = uVar20;
5540: do {
5541: if (0x2f < (int)uStack624) {
5542: cVar23 = (char)(int)uStack624;
5543: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5544: *pcVar24 = cVar22;
5545: pcVar15 = pcVar24 + 1;
5546: if (cVar22 == -1) {
5547: pcVar15 = pcVar24 + 2;
5548: pcVar24[1] = '\0';
5549: }
5550: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5551: *pcVar15 = cVar22;
5552: pcVar24 = pcVar15 + 1;
5553: if (cVar22 == -1) {
5554: pcVar24 = pcVar15 + 2;
5555: pcVar15[1] = '\0';
5556: }
5557: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5558: *pcVar24 = cVar22;
5559: pcVar15 = pcVar24 + 1;
5560: if (cVar22 == -1) {
5561: pcVar15 = pcVar24 + 2;
5562: pcVar24[1] = '\0';
5563: }
5564: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
5565: *pcVar15 = cVar22;
5566: pcVar24 = pcVar15 + 1;
5567: if (cVar22 == -1) {
5568: pcVar24 = pcVar15 + 2;
5569: pcVar15[1] = '\0';
5570: }
5571: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
5572: *pcVar24 = cVar23;
5573: pcVar15 = pcVar24 + 1;
5574: if (cVar23 == -1) {
5575: pcVar15 = pcVar24 + 2;
5576: pcVar24[1] = '\0';
5577: }
5578: uStack624._0_4_ = (int)uStack624 + -0x30;
5579: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5580: *pcVar15 = cVar23;
5581: pcVar24 = pcVar15 + 1;
5582: if (cVar23 == -1) {
5583: pcVar24 = pcVar15 + 2;
5584: pcVar15[1] = '\0';
5585: }
5586: }
5587: uVar25 = uVar25 - 0x10;
5588: uStack624._0_4_ = (int)uStack624 + iVar21;
5589: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
5590: } while (0xf < (int)uVar25);
5591: uVar20 = uVar20 & 0xf;
5592: }
5593: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
5594: iVar17 = piVar8[lVar18];
5595: bVar3 = *(byte *)((long)piVar8 + lVar18 + 0x400);
5596: if (0x1f < (int)uStack624) {
5597: cVar23 = (char)(int)uStack624;
5598: pcVar15 = pcVar24 + 1;
5599: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5600: *pcVar24 = cVar22;
5601: if (cVar22 == -1) {
5602: pcVar15 = pcVar24 + 2;
5603: pcVar24[1] = '\0';
5604: }
5605: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5606: *pcVar15 = cVar22;
5607: pcVar24 = pcVar15 + 1;
5608: if (cVar22 == -1) {
5609: pcVar24 = pcVar15 + 2;
5610: pcVar15[1] = '\0';
5611: }
5612: pcVar15 = pcVar24 + 1;
5613: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5614: *pcVar24 = cVar23;
5615: if (cVar23 == -1) {
5616: pcVar15 = pcVar24 + 2;
5617: pcVar24[1] = '\0';
5618: }
5619: uStack624._0_4_ = (int)uStack624 + -0x20;
5620: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5621: *pcVar15 = cVar23;
5622: pcVar24 = pcVar15 + 1;
5623: if (cVar23 == -1) {
5624: pcVar24 = pcVar15 + 2;
5625: pcVar15[1] = '\0';
5626: }
5627: }
5628: uStack624._0_4_ = (int)uStack624 + (char)bVar3 + (uint)bVar2;
5629: uVar20 = 0;
5630: uVar29 = ((long)iVar17 | uVar29 << (bVar3 & 0x3f)) << (bVar2 & 0x3f) |
5631: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
5632: }
5633: uVar26 = SEXT24(psVar9[0x3f]);
5634: if (psVar9[0x3f] == 0) {
5635: iVar13 = *piVar8;
5636: bVar1 = *(byte *)(piVar8 + 0x100);
5637: if (0x2f < (int)uStack624) {
5638: cVar23 = (char)(int)uStack624;
5639: pcVar15 = pcVar24 + 1;
5640: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5641: *pcVar24 = cVar22;
5642: if (cVar22 == -1) {
5643: pcVar15 = pcVar24 + 2;
5644: pcVar24[1] = '\0';
5645: }
5646: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5647: *pcVar15 = cVar22;
5648: pcVar24 = pcVar15 + 1;
5649: if (cVar22 == -1) {
5650: pcVar24 = pcVar15 + 2;
5651: pcVar15[1] = '\0';
5652: }
5653: pcVar15 = pcVar24 + 1;
5654: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5655: *pcVar24 = cVar22;
5656: if (cVar22 == -1) {
5657: pcVar15 = pcVar24 + 2;
5658: pcVar24[1] = '\0';
5659: }
5660: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
5661: *pcVar15 = cVar22;
5662: pcVar24 = pcVar15 + 1;
5663: if (cVar22 == -1) {
5664: pcVar24 = pcVar15 + 2;
5665: pcVar15[1] = '\0';
5666: }
5667: pcVar15 = pcVar24 + 1;
5668: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
5669: *pcVar24 = cVar23;
5670: if (cVar23 == -1) {
5671: pcVar15 = pcVar24 + 2;
5672: pcVar24[1] = '\0';
5673: }
5674: uStack624._0_4_ = (int)uStack624 + -0x30;
5675: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5676: *pcVar15 = cVar23;
5677: pcVar24 = pcVar15 + 1;
5678: if (cVar23 == -1) {
5679: pcVar24 = pcVar15 + 2;
5680: pcVar15[1] = '\0';
5681: }
5682: }
5683: uVar20 = (int)uStack624 + (char)bVar1;
5684: uStack632 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
5685: }
5686: else {
5687: uVar30 = (int)uVar26 >> 0x1f;
5688: bVar2 = (&DAT_00168f80)[(int)((uVar30 ^ uVar26) - uVar30)];
5689: if (0xf < (int)uVar20) {
5690: uVar25 = uVar20;
5691: do {
5692: if (0x2f < (int)uStack624) {
5693: cVar23 = (char)(int)uStack624;
5694: pcVar15 = pcVar24 + 1;
5695: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5696: *pcVar24 = cVar22;
5697: if (cVar22 == -1) {
5698: pcVar15 = pcVar24 + 2;
5699: pcVar24[1] = '\0';
5700: }
5701: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5702: *pcVar15 = cVar22;
5703: pcVar24 = pcVar15 + 1;
5704: if (cVar22 == -1) {
5705: pcVar24 = pcVar15 + 2;
5706: pcVar15[1] = '\0';
5707: }
5708: pcVar15 = pcVar24 + 1;
5709: cVar22 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5710: *pcVar24 = cVar22;
5711: if (cVar22 == -1) {
5712: pcVar15 = pcVar24 + 2;
5713: pcVar24[1] = '\0';
5714: }
5715: cVar22 = (char)(uVar29 >> (cVar23 - 0x20U & 0x3f));
5716: *pcVar15 = cVar22;
5717: pcVar24 = pcVar15 + 1;
5718: if (cVar22 == -1) {
5719: pcVar24 = pcVar15 + 2;
5720: pcVar15[1] = '\0';
5721: }
5722: pcVar15 = pcVar24 + 1;
5723: cVar23 = (char)(uVar29 >> (cVar23 - 0x28U & 0x3f));
5724: *pcVar24 = cVar23;
5725: if (cVar23 == -1) {
5726: pcVar15 = pcVar24 + 2;
5727: pcVar24[1] = '\0';
5728: }
5729: uStack624._0_4_ = (int)uStack624 + -0x30;
5730: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5731: *pcVar15 = cVar23;
5732: pcVar24 = pcVar15 + 1;
5733: if (cVar23 == -1) {
5734: pcVar24 = pcVar15 + 2;
5735: pcVar15[1] = '\0';
5736: }
5737: }
5738: uVar25 = uVar25 - 0x10;
5739: uStack624._0_4_ = (int)uStack624 + iVar21;
5740: uVar29 = uVar29 << (bVar1 & 0x3f) | (long)iVar13;
5741: } while (0xf < (int)uVar25);
5742: uVar20 = uVar20 & 0xf;
5743: }
5744: lVar18 = (long)(int)(uVar20 * 0x10 + (uint)bVar2);
5745: iVar13 = piVar8[lVar18];
5746: bVar1 = *(byte *)((long)piVar8 + lVar18 + 0x400);
5747: if (0x1f < (int)uStack624) {
5748: cVar23 = (char)(int)uStack624;
5749: pcVar15 = pcVar24 + 1;
5750: cVar22 = (char)(uVar29 >> (cVar23 - 8U & 0x3f));
5751: *pcVar24 = cVar22;
5752: if (cVar22 == -1) {
5753: pcVar15 = pcVar24 + 2;
5754: pcVar24[1] = '\0';
5755: }
5756: cVar22 = (char)(uVar29 >> (cVar23 - 0x10U & 0x3f));
5757: *pcVar15 = cVar22;
5758: pcVar24 = pcVar15 + 1;
5759: if (cVar22 == -1) {
5760: pcVar24 = pcVar15 + 2;
5761: pcVar15[1] = '\0';
5762: }
5763: pcVar15 = pcVar24 + 1;
5764: cVar23 = (char)(uVar29 >> (cVar23 - 0x18U & 0x3f));
5765: *pcVar24 = cVar23;
5766: if (cVar23 == -1) {
5767: pcVar15 = pcVar24 + 2;
5768: pcVar24[1] = '\0';
5769: }
5770: uStack624._0_4_ = (int)uStack624 + -0x20;
5771: cVar23 = (char)(uVar29 >> ((byte)(int)uStack624 & 0x3f));
5772: *pcVar15 = cVar23;
5773: pcVar24 = pcVar15 + 1;
5774: if (cVar23 == -1) {
5775: pcVar24 = pcVar15 + 2;
5776: pcVar15[1] = '\0';
5777: }
5778: }
5779: uVar20 = (int)uStack624 + (char)bVar1 + (uint)bVar2;
5780: uStack632 = ((long)iVar13 | uVar29 << (bVar1 & 0x3f)) << (bVar2 & 0x3f) |
5781: (long)(int)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar26 + uVar30);
5782: }
5783: uStack624 = uStack624 & 0xffffffff00000000 | (ulong)uVar20;
5784: if (pcVar19 < (char *)0x200) {
5785: pcVar24 = pcVar24 + -(long)acStack584;
5786: pcVar19 = acStack584;
5787: while (pcVar24 != (char *)0x0) {
5788: while( true ) {
5789: pcVar15 = pcStack640;
5790: if (pcVar24 < pcStack640) {
5791: pcVar15 = pcVar24;
5792: }
5793: memcpy(pcStack648,pcVar19,(size_t)pcVar15);
5794: pcStack648 = pcVar15 + (long)pcStack648;
5795: pcStack640 = pcStack640 + -(long)pcVar15;
5796: if (pcStack640 != (char *)0x0) break;
5797: ppcVar12 = *(char ***)(lStack600 + 0x28);
5798: iVar13 = (*(code *)ppcVar12[3])();
5799: if (iVar13 == 0) goto LAB_001105b0;
5800: pcStack648 = *ppcVar12;
5801: pcStack640 = ppcVar12[1];
5802: pcVar24 = pcVar24 + -(long)pcVar15;
5803: pcVar19 = pcVar19 + (long)pcVar15;
5804: if (pcVar24 == (char *)0x0) goto LAB_00109710;
5805: }
5806: pcVar24 = pcVar24 + -(long)pcVar15;
5807: pcVar19 = pcVar19 + (long)pcVar15;
5808: }
5809: }
5810: else {
5811: pcStack640 = pcStack648 + -(long)pcVar24 + (long)pcStack640;
5812: pcStack648 = pcVar24;
5813: }
5814: LAB_00109710:
5815: *(int *)((long)&uStack624 + lVar14 * 4 + 4) = (int)**(short **)(param_2 + lStack680 * 8);
5816: iVar13 = (int)lStack680 + 1;
5817: pcVar19 = pcStack640;
5818: lStack680 = lStack680 + 1;
5819: } while (*(int *)(param_1 + 0x170) != iVar13 && iVar13 <= *(int *)(param_1 + 0x170));
5820: }
5821: }
5822: else {
5823: if (0 < *(int *)(param_1 + 0x170)) {
5824: lVar18 = 0;
5825: do {
5826: lVar31 = (long)*(int *)(param_1 + 0x174 + lVar18 * 4);
5827: lVar14 = *(long *)(param_1 + 0x148 + lVar31 * 8);
5828: uVar16 = *(undefined8 *)(lVar7 + 0x60 + (long)*(int *)(lVar14 + 0x18) * 8);
5829: uVar10 = *(undefined8 *)(lVar7 + 0x40 + (long)*(int *)(lVar14 + 0x14) * 8);
5830: uVar6 = *(undefined4 *)((long)&uStack624 + lVar31 * 4 + 4);
5831: uVar11 = *(undefined8 *)(param_2 + lVar18 * 8);
5832: if (pcVar19 < (char *)0x200) {
5833: lVar14 = thunk_FUN_001585e0(&pcStack648,acStack584,uVar11,uVar6,uVar10,uVar16);
5834: pcVar24 = (char *)(lVar14 - (long)acStack584);
5835: pcVar19 = acStack584;
5836: while (pcVar24 != (char *)0x0) {
5837: pcVar15 = pcStack640;
5838: if (pcVar24 < pcStack640) {
5839: pcVar15 = pcVar24;
5840: }
5841: memcpy(pcStack648,pcVar19,(size_t)pcVar15);
5842: pcStack648 = pcVar15 + (long)pcStack648;
5843: pcVar19 = pcVar19 + (long)pcVar15;
5844: pcStack640 = pcStack640 + -(long)pcVar15;
5845: if (pcStack640 == (char *)0x0) {
5846: ppcVar12 = *(char ***)(lStack600 + 0x28);
5847: iVar13 = (*(code *)ppcVar12[3])();
5848: if (iVar13 == 0) goto LAB_001105b0;
5849: pcStack648 = *ppcVar12;
5850: pcStack640 = ppcVar12[1];
5851: }
5852: pcVar24 = pcVar24 + -(long)pcVar15;
5853: }
5854: }
5855: else {
5856: pcVar19 = (char *)thunk_FUN_001585e0(&pcStack648,pcStack648,uVar11,uVar6,uVar10,uVar16);
5857: pcStack640 = pcStack648 + -(long)pcVar19 + (long)pcStack640;
5858: pcStack648 = pcVar19;
5859: }
5860: *(int *)((long)&uStack624 + lVar31 * 4 + 4) = (int)**(short **)(param_2 + lVar18 * 8);
5861: iVar13 = (int)lVar18 + 1;
5862: lVar18 = lVar18 + 1;
5863: pcVar19 = pcStack640;
5864: } while (*(int *)(param_1 + 0x170) != iVar13 && iVar13 <= *(int *)(param_1 + 0x170));
5865: }
5866: }
5867: ppcVar12 = *(char ***)(param_1 + 0x28);
5868: *ppcVar12 = pcStack648;
5869: ppcVar12[1] = pcVar19;
5870: iVar13 = *(int *)(param_1 + 0x118);
5871: *(ulong *)(lVar7 + 0x18) = uStack632;
5872: *(ulong *)(lVar7 + 0x20) = uStack624;
5873: *(undefined8 *)(lVar7 + 0x28) = uStack616;
5874: *(undefined8 *)(lVar7 + 0x30) = uStack608;
5875: uVar16 = 1;
5876: if (iVar13 != 0) {
5877: iVar21 = *(int *)(lVar7 + 0x38);
5878: if (*(int *)(lVar7 + 0x38) == 0) {
5879: *(uint *)(lVar7 + 0x3c) = *(int *)(lVar7 + 0x3c) + 1U & 7;
5880: iVar21 = iVar13;
5881: }
5882: *(int *)(lVar7 + 0x38) = iVar21 + -1;
5883: uVar16 = 1;
5884: }
5885: LAB_001105b2:
5886: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
5887: return uVar16;
5888: }
5889: /* WARNING: Subroutine does not return */
5890: __stack_chk_fail();
5891: }
5892: 
