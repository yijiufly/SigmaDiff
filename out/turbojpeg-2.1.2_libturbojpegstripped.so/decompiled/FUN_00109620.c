1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined8 FUN_00109620(long param_1,long param_2)
5: 
6: {
7: short sVar1;
8: undefined4 uVar2;
9: long lVar3;
10: uint *puVar4;
11: short *psVar5;
12: char **ppcVar6;
13: undefined8 uVar7;
14: undefined8 uVar8;
15: byte bVar9;
16: char cVar10;
17: ulong uVar11;
18: undefined8 uVar12;
19: long lVar13;
20: ulong uVar14;
21: byte bVar15;
22: uint uVar16;
23: int iVar17;
24: int iVar18;
25: uint uVar19;
26: char cVar20;
27: char *pcVar26;
28: char *pcVar27;
29: char *pcVar28;
30: int iVar29;
31: long lVar30;
32: uint uVar31;
33: int iVar32;
34: char cVar33;
35: long lVar34;
36: uint uVar35;
37: long in_FS_OFFSET;
38: long lStack680;
39: char *pcStack648;
40: char *pcStack640;
41: undefined8 uStack632;
42: int iStack624;
43: int iStack620;
44: undefined8 uStack616;
45: undefined8 uStack608;
46: long lStack600;
47: int iStack592;
48: char acStack584 [520];
49: long lStack64;
50: char cVar21;
51: char cVar22;
52: char cVar23;
53: char cVar24;
54: char cVar25;
55: 
56: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
57: lVar3 = *(long *)(param_1 + 0x1f0);
58: pcStack648 = **(char ***)(param_1 + 0x28);
59: pcStack640 = (*(char ***)(param_1 + 0x28))[1];
60: uStack632 = *(ulong *)(lVar3 + 0x18);
61: iStack624 = *(int *)(lVar3 + 0x20);
62: iVar17 = *(int *)(lVar3 + 0xc0);
63: iStack620 = *(int *)(lVar3 + 0x24);
64: lStack600 = param_1;
65: iStack592 = iVar17;
66: uStack616 = *(undefined8 *)(lVar3 + 0x28);
67: uStack608 = *(undefined8 *)(lVar3 + 0x30);
68: if ((*(int *)(param_1 + 0x118) != 0) && (*(int *)(lVar3 + 0x38) == 0)) {
69: uVar2 = *(undefined4 *)(lVar3 + 0x3c);
70: uVar12 = FUN_00109470(*(undefined8 *)(lVar3 + 0x28));
71: if ((int)uVar12 == 0) goto LAB_0010b2e8;
72: pcVar28 = pcStack648 + 1;
73: *pcStack648 = -1;
74: pcStack640 = pcStack640 + -1;
75: pcStack648 = pcVar28;
76: if (pcStack640 == (char *)0x0) {
77: ppcVar6 = *(char ***)(lStack600 + 0x28);
78: uVar12 = (*(code *)ppcVar6[3])();
79: if ((int)uVar12 == 0) goto LAB_0010b2e8;
80: pcStack648 = *ppcVar6;
81: pcStack640 = ppcVar6[1];
82: }
83: pcVar28 = pcStack648 + 1;
84: *pcStack648 = (char)uVar2 + -0x30;
85: pcStack640 = pcStack640 + -1;
86: pcStack648 = pcVar28;
87: if (pcStack640 == (char *)0x0) {
88: ppcVar6 = *(char ***)(lStack600 + 0x28);
89: uVar12 = (*(code *)ppcVar6[3])();
90: if ((int)uVar12 == 0) goto LAB_0010b2e8;
91: pcStack648 = *ppcVar6;
92: pcStack640 = ppcVar6[1];
93: }
94: if (0 < *(int *)(lStack600 + 0x144)) {
95: memset(&iStack620,0,(ulong)(*(int *)(lStack600 + 0x144) - 1) * 4 + 4);
96: }
97: iVar17 = *(int *)(lVar3 + 0xc0);
98: }
99: if (iVar17 == 0) {
100: lStack680 = 1;
101: if (0 < *(int *)(param_1 + 0x170)) {
102: do {
103: lVar30 = (long)*(int *)(param_1 + 0x170 + lStack680 * 4);
104: lVar34 = *(long *)(param_1 + 0x148 + lVar30 * 8);
105: lVar13 = *(long *)(lVar3 + 0x40 + (long)*(int *)(lVar34 + 0x14) * 8);
106: puVar4 = *(uint **)(lVar3 + 0x60 + (long)*(int *)(lVar34 + 0x18) * 8);
107: psVar5 = *(short **)(param_2 + -8 + lStack680 * 8);
108: pcVar28 = pcStack648;
109: if (pcStack640 < (char *)0x200) {
110: pcVar28 = acStack584;
111: }
112: uVar16 = (int)*psVar5 - (&iStack620)[lVar30] >> 0x1f;
113: uVar31 = ((int)*psVar5 - (&iStack620)[lVar30]) + uVar16;
114: bVar15 = (&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
115: uVar31 = *(int *)(lVar13 + (long)(int)(uint)bVar15 * 4) << (bVar15 & 0x1f) |
116: (int)(1 << (bVar15 & 0x3f)) - 1U & uVar31;
117: iVar17 = (int)*(char *)(lVar13 + 0x400 + (long)(int)(uint)bVar15) + (uint)bVar15;
118: iVar29 = iStack624 - iVar17;
119: if (iVar29 < 0) {
120: uVar11 = uStack632 << ((byte)iStack624 & 0x3f) |
121: (long)((int)uVar31 >> (-(char)iVar29 & 0x1fU));
122: cVar33 = (char)uVar11;
123: cVar20 = (char)(uVar11 >> 8);
124: cVar21 = (char)(uVar11 >> 0x10);
125: cVar22 = (char)(uVar11 >> 0x18);
126: cVar23 = (char)(uVar11 >> 0x20);
127: cVar24 = (char)(uVar11 >> 0x28);
128: cVar25 = (char)(uVar11 >> 0x30);
129: cVar10 = (char)(uVar11 >> 0x38);
130: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
131: pcVar28[7] = cVar33;
132: pcVar26 = pcVar28 + 8;
133: *pcVar28 = cVar10;
134: pcVar28[1] = cVar25;
135: pcVar28[2] = cVar24;
136: pcVar28[3] = cVar23;
137: pcVar28[4] = cVar22;
138: pcVar28[5] = cVar21;
139: pcVar28[6] = cVar20;
140: }
141: else {
142: pcVar28[1] = '\0';
143: *pcVar28 = cVar10;
144: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
145: *pcVar28 = cVar25;
146: pcVar28[1] = '\0';
147: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
148: *pcVar28 = cVar24;
149: pcVar28[1] = '\0';
150: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
151: *pcVar28 = cVar23;
152: pcVar28[1] = '\0';
153: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
154: *pcVar28 = cVar22;
155: pcVar28[1] = '\0';
156: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
157: *pcVar28 = cVar21;
158: pcVar28[1] = '\0';
159: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
160: *pcVar28 = cVar20;
161: pcVar28[1] = '\0';
162: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
163: pcVar26 = pcVar28 + (ulong)(cVar33 == -1) + 1;
164: *pcVar28 = cVar33;
165: pcVar28[1] = '\0';
166: }
167: iVar29 = iVar29 + 0x40;
168: uVar11 = SEXT48((int)uVar31);
169: }
170: else {
171: uVar11 = (long)(int)uVar31 | uStack632 << ((byte)iVar17 & 0x3f);
172: pcVar26 = pcVar28;
173: }
174: sVar1 = psVar5[1];
175: iVar18 = 0x10;
176: pcVar28 = pcVar26;
177: iVar17 = iVar29;
178: if (sVar1 != 0) {
179: uVar16 = (int)sVar1 >> 0x1f;
180: uVar31 = (int)sVar1 + uVar16;
181: bVar15 = (&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
182: uVar31 = uVar31 & (int)(1 << (bVar15 & 0x3f)) - 1U |
183: puVar4[(int)(uint)bVar15] << (bVar15 & 0x1f);
184: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(uint)bVar15 + 0x400) + (uint)bVar15;
185: iVar17 = iVar29 - iVar18;
186: if (iVar17 < 0) {
187: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
188: uVar11 << ((byte)iVar29 & 0x3f);
189: cVar10 = (char)uVar11;
190: cVar24 = (char)(uVar11 >> 8);
191: cVar23 = (char)(uVar11 >> 0x10);
192: cVar22 = (char)(uVar11 >> 0x18);
193: cVar33 = (char)(uVar11 >> 0x20);
194: cVar20 = (char)(uVar11 >> 0x28);
195: cVar21 = (char)(uVar11 >> 0x30);
196: cVar25 = (char)(uVar11 >> 0x38);
197: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
198: pcVar26[7] = cVar10;
199: pcVar28 = pcVar26 + 8;
200: *pcVar26 = cVar25;
201: pcVar26[1] = cVar21;
202: pcVar26[2] = cVar20;
203: pcVar26[3] = cVar33;
204: pcVar26[4] = cVar22;
205: pcVar26[5] = cVar23;
206: pcVar26[6] = cVar24;
207: }
208: else {
209: pcVar26[1] = '\0';
210: *pcVar26 = cVar25;
211: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
212: *pcVar26 = cVar21;
213: pcVar26[1] = '\0';
214: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
215: *pcVar26 = cVar20;
216: pcVar26[1] = '\0';
217: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
218: *pcVar26 = cVar33;
219: pcVar26[1] = '\0';
220: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
221: *pcVar26 = cVar22;
222: pcVar26[1] = '\0';
223: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
224: *pcVar26 = cVar23;
225: pcVar26[1] = '\0';
226: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
227: *pcVar26 = cVar24;
228: pcVar26[1] = '\0';
229: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
230: *pcVar26 = cVar10;
231: pcVar26[1] = '\0';
232: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
233: }
234: uVar11 = SEXT48((int)uVar31);
235: iVar17 = iVar17 + 0x40;
236: iVar18 = 0;
237: }
238: else {
239: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar31;
240: iVar18 = 0;
241: }
242: }
243: sVar1 = psVar5[8];
244: if (sVar1 == 0) {
245: iVar18 = iVar18 + 0x10;
246: pcVar26 = pcVar28;
247: LAB_00109841:
248: sVar1 = psVar5[0x10];
249: pcVar28 = pcVar26;
250: iVar29 = iVar17;
251: iVar17 = iVar18;
252: if (sVar1 != 0) goto LAB_0010c82d;
253: LAB_0010984f:
254: iVar18 = iVar18 + 0x10;
255: pcVar26 = pcVar28;
256: iVar17 = iVar29;
257: }
258: else {
259: uVar31 = (int)sVar1 >> 0x1f;
260: uVar16 = (int)sVar1 + uVar31;
261: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
262: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
263: puVar4[(int)(iVar18 + (uint)bVar15)] << (bVar15 & 0x1f);
264: iVar32 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + (uint)bVar15) + 0x400) +
265: (uint)bVar15;
266: iVar29 = iVar17 - iVar32;
267: if (iVar29 < 0) {
268: uVar11 = (long)((int)uVar31 >> (-(char)iVar29 & 0x1fU)) |
269: uVar11 << ((byte)iVar17 & 0x3f);
270: cVar10 = (char)uVar11;
271: cVar33 = (char)(uVar11 >> 8);
272: cVar20 = (char)(uVar11 >> 0x10);
273: cVar21 = (char)(uVar11 >> 0x18);
274: cVar22 = (char)(uVar11 >> 0x20);
275: cVar23 = (char)(uVar11 >> 0x28);
276: cVar24 = (char)(uVar11 >> 0x30);
277: cVar25 = (char)(uVar11 >> 0x38);
278: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
279: pcVar28[7] = cVar10;
280: pcVar26 = pcVar28 + 8;
281: *pcVar28 = cVar25;
282: pcVar28[1] = cVar24;
283: pcVar28[2] = cVar23;
284: pcVar28[3] = cVar22;
285: pcVar28[4] = cVar21;
286: pcVar28[5] = cVar20;
287: pcVar28[6] = cVar33;
288: }
289: else {
290: pcVar28[1] = '\0';
291: *pcVar28 = cVar25;
292: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
293: *pcVar28 = cVar24;
294: pcVar28[1] = '\0';
295: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
296: *pcVar28 = cVar23;
297: pcVar28[1] = '\0';
298: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
299: *pcVar28 = cVar22;
300: pcVar28[1] = '\0';
301: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
302: *pcVar28 = cVar21;
303: pcVar28[1] = '\0';
304: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
305: *pcVar28 = cVar20;
306: pcVar28[1] = '\0';
307: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
308: *pcVar28 = cVar33;
309: pcVar28[1] = '\0';
310: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
311: *pcVar28 = cVar10;
312: pcVar28[1] = '\0';
313: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
314: }
315: iVar17 = iVar29 + 0x40;
316: uVar11 = SEXT48((int)uVar31);
317: iVar18 = 0;
318: goto LAB_00109841;
319: }
320: iVar18 = 0;
321: iVar17 = 0;
322: uVar11 = uVar11 << ((byte)iVar32 & 0x3f) | (long)(int)uVar31;
323: sVar1 = psVar5[0x10];
324: if (sVar1 == 0) goto LAB_0010984f;
325: LAB_0010c82d:
326: uVar31 = (int)sVar1 >> 0x1f;
327: uVar16 = (int)sVar1 + uVar31;
328: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
329: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
330: puVar4[(int)(iVar17 + (uint)bVar15)] << (bVar15 & 0x1f);
331: iVar32 = (int)*(char *)((long)puVar4 + (long)(int)(iVar17 + (uint)bVar15) + 0x400) +
332: (uint)bVar15;
333: iVar17 = iVar29 - iVar32;
334: if (iVar17 < 0) {
335: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
336: uVar11 << ((byte)iVar29 & 0x3f);
337: cVar10 = (char)uVar11;
338: cVar21 = (char)(uVar11 >> 8);
339: cVar20 = (char)(uVar11 >> 0x10);
340: cVar33 = (char)(uVar11 >> 0x18);
341: cVar22 = (char)(uVar11 >> 0x20);
342: cVar23 = (char)(uVar11 >> 0x28);
343: cVar24 = (char)(uVar11 >> 0x30);
344: cVar25 = (char)(uVar11 >> 0x38);
345: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
346: pcVar28[7] = cVar10;
347: pcVar26 = pcVar28 + 8;
348: *pcVar28 = cVar25;
349: pcVar28[1] = cVar24;
350: pcVar28[2] = cVar23;
351: pcVar28[3] = cVar22;
352: pcVar28[4] = cVar33;
353: pcVar28[5] = cVar20;
354: pcVar28[6] = cVar21;
355: }
356: else {
357: pcVar28[1] = '\0';
358: *pcVar28 = cVar25;
359: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
360: *pcVar28 = cVar24;
361: pcVar28[1] = '\0';
362: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
363: *pcVar28 = cVar23;
364: pcVar28[1] = '\0';
365: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
366: *pcVar28 = cVar22;
367: pcVar28[1] = '\0';
368: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
369: *pcVar28 = cVar33;
370: pcVar28[1] = '\0';
371: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
372: *pcVar28 = cVar20;
373: pcVar28[1] = '\0';
374: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
375: *pcVar28 = cVar21;
376: pcVar28[1] = '\0';
377: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
378: *pcVar28 = cVar10;
379: pcVar28[1] = '\0';
380: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
381: }
382: iVar17 = iVar17 + 0x40;
383: uVar11 = SEXT48((int)uVar31);
384: iVar18 = 0;
385: }
386: else {
387: iVar18 = 0;
388: uVar11 = uVar11 << ((byte)iVar32 & 0x3f) | (long)(int)uVar31;
389: pcVar26 = pcVar28;
390: }
391: }
392: sVar1 = psVar5[9];
393: if (sVar1 == 0) {
394: iVar18 = iVar18 + 0x10;
395: pcVar28 = pcVar26;
396: LAB_00109865:
397: sVar1 = psVar5[2];
398: pcVar26 = pcVar28;
399: iVar29 = iVar17;
400: iVar17 = iVar18;
401: if (sVar1 != 0) goto LAB_0010c44d;
402: LAB_00109873:
403: iVar18 = iVar18 + 0x10;
404: pcVar28 = pcVar26;
405: iVar17 = iVar29;
406: }
407: else {
408: uVar31 = (int)sVar1 >> 0x1f;
409: uVar16 = (int)sVar1 + uVar31;
410: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
411: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
412: puVar4[(int)(iVar18 + (uint)bVar15)] << (bVar15 & 0x1f);
413: iVar32 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + (uint)bVar15) + 0x400) +
414: (uint)bVar15;
415: iVar29 = iVar17 - iVar32;
416: if (iVar29 < 0) {
417: uVar11 = (long)((int)uVar31 >> (-(char)iVar29 & 0x1fU)) |
418: uVar11 << ((byte)iVar17 & 0x3f);
419: cVar10 = (char)uVar11;
420: cVar25 = (char)(uVar11 >> 8);
421: cVar24 = (char)(uVar11 >> 0x10);
422: cVar23 = (char)(uVar11 >> 0x18);
423: cVar22 = (char)(uVar11 >> 0x20);
424: cVar21 = (char)(uVar11 >> 0x28);
425: cVar20 = (char)(uVar11 >> 0x30);
426: cVar33 = (char)(uVar11 >> 0x38);
427: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
428: pcVar26[7] = cVar10;
429: pcVar28 = pcVar26 + 8;
430: *pcVar26 = cVar33;
431: pcVar26[1] = cVar20;
432: pcVar26[2] = cVar21;
433: pcVar26[3] = cVar22;
434: pcVar26[4] = cVar23;
435: pcVar26[5] = cVar24;
436: pcVar26[6] = cVar25;
437: }
438: else {
439: pcVar26[1] = '\0';
440: *pcVar26 = cVar33;
441: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
442: *pcVar26 = cVar20;
443: pcVar26[1] = '\0';
444: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
445: *pcVar26 = cVar21;
446: pcVar26[1] = '\0';
447: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
448: *pcVar26 = cVar22;
449: pcVar26[1] = '\0';
450: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
451: *pcVar26 = cVar23;
452: pcVar26[1] = '\0';
453: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
454: *pcVar26 = cVar24;
455: pcVar26[1] = '\0';
456: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
457: *pcVar26 = cVar25;
458: pcVar26[1] = '\0';
459: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
460: *pcVar26 = cVar10;
461: pcVar26[1] = '\0';
462: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
463: }
464: iVar17 = iVar29 + 0x40;
465: uVar11 = SEXT48((int)uVar31);
466: iVar18 = 0;
467: goto LAB_00109865;
468: }
469: iVar18 = 0;
470: iVar17 = 0;
471: uVar11 = uVar11 << ((byte)iVar32 & 0x3f) | (long)(int)uVar31;
472: sVar1 = psVar5[2];
473: if (sVar1 == 0) goto LAB_00109873;
474: LAB_0010c44d:
475: uVar31 = (int)sVar1 >> 0x1f;
476: uVar16 = (int)sVar1 + uVar31;
477: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
478: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
479: puVar4[(int)(iVar17 + (uint)bVar15)] << (bVar15 & 0x1f);
480: iVar32 = (int)*(char *)((long)puVar4 + (long)(int)(iVar17 + (uint)bVar15) + 0x400) +
481: (uint)bVar15;
482: iVar17 = iVar29 - iVar32;
483: if (iVar17 < 0) {
484: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
485: uVar11 << ((byte)iVar29 & 0x3f);
486: cVar10 = (char)uVar11;
487: cVar25 = (char)(uVar11 >> 8);
488: cVar24 = (char)(uVar11 >> 0x10);
489: cVar23 = (char)(uVar11 >> 0x18);
490: cVar33 = (char)(uVar11 >> 0x20);
491: cVar20 = (char)(uVar11 >> 0x28);
492: cVar21 = (char)(uVar11 >> 0x30);
493: cVar22 = (char)(uVar11 >> 0x38);
494: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
495: pcVar26[7] = cVar10;
496: pcVar28 = pcVar26 + 8;
497: *pcVar26 = cVar22;
498: pcVar26[1] = cVar21;
499: pcVar26[2] = cVar20;
500: pcVar26[3] = cVar33;
501: pcVar26[4] = cVar23;
502: pcVar26[5] = cVar24;
503: pcVar26[6] = cVar25;
504: }
505: else {
506: pcVar26[1] = '\0';
507: *pcVar26 = cVar22;
508: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
509: *pcVar26 = cVar21;
510: pcVar26[1] = '\0';
511: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
512: *pcVar26 = cVar20;
513: pcVar26[1] = '\0';
514: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
515: *pcVar26 = cVar33;
516: pcVar26[1] = '\0';
517: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
518: *pcVar26 = cVar23;
519: pcVar26[1] = '\0';
520: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
521: *pcVar26 = cVar24;
522: pcVar26[1] = '\0';
523: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
524: *pcVar26 = cVar25;
525: pcVar26[1] = '\0';
526: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
527: *pcVar26 = cVar10;
528: pcVar26[1] = '\0';
529: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
530: }
531: iVar17 = iVar17 + 0x40;
532: uVar11 = SEXT48((int)uVar31);
533: iVar18 = 0;
534: }
535: else {
536: iVar18 = 0;
537: uVar11 = uVar11 << ((byte)iVar32 & 0x3f) | (long)(int)uVar31;
538: pcVar28 = pcVar26;
539: }
540: }
541: sVar1 = psVar5[3];
542: iVar29 = iVar18 + 0x10;
543: pcVar26 = pcVar28;
544: iVar32 = iVar17;
545: if (sVar1 != 0) {
546: uVar31 = (int)sVar1 >> 0x1f;
547: uVar16 = (int)sVar1 + uVar31;
548: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
549: bVar9 = bVar15 & 0x1f;
550: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
551: puVar4[(int)(iVar18 + (uint)bVar15)] << bVar9;
552: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + (uint)bVar15) + 0x400) +
553: (uint)bVar15;
554: iVar32 = iVar17 - iVar18;
555: if (iVar32 < 0) {
556: uVar11 = (long)((int)uVar31 >> (-(char)iVar32 & 0x1fU)) |
557: uVar11 << ((byte)iVar17 & 0x3f);
558: cVar10 = (char)uVar11;
559: cVar20 = (char)(uVar11 >> 8);
560: cVar21 = (char)(uVar11 >> 0x10);
561: cVar22 = (char)(uVar11 >> 0x18);
562: cVar25 = (char)(uVar11 >> 0x20);
563: cVar24 = (char)(uVar11 >> 0x28);
564: cVar23 = (char)(uVar11 >> 0x30);
565: cVar33 = (char)(uVar11 >> 0x38);
566: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
567: pcVar28[7] = cVar10;
568: pcVar26 = pcVar28 + 8;
569: *pcVar28 = cVar33;
570: pcVar28[1] = cVar23;
571: pcVar28[2] = cVar24;
572: pcVar28[3] = cVar25;
573: pcVar28[4] = cVar22;
574: pcVar28[5] = cVar21;
575: pcVar28[6] = cVar20;
576: }
577: else {
578: pcVar28[1] = '\0';
579: *pcVar28 = cVar33;
580: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
581: *pcVar28 = cVar23;
582: pcVar28[1] = '\0';
583: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
584: *pcVar28 = cVar24;
585: pcVar28[1] = '\0';
586: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
587: *pcVar28 = cVar25;
588: pcVar28[1] = '\0';
589: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
590: *pcVar28 = cVar22;
591: pcVar28[1] = '\0';
592: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
593: *pcVar28 = cVar21;
594: pcVar28[1] = '\0';
595: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
596: *pcVar28 = cVar20;
597: pcVar28[1] = '\0';
598: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
599: *pcVar28 = cVar10;
600: pcVar28[1] = '\0';
601: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
602: }
603: iVar32 = iVar32 + 0x40;
604: uVar11 = SEXT48((int)uVar31);
605: iVar29 = 0 << bVar9;
606: }
607: else {
608: iVar29 = 0 << bVar9;
609: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar31;
610: }
611: }
612: sVar1 = psVar5[10];
613: iVar18 = iVar29 + 0x10;
614: pcVar28 = pcVar26;
615: iVar17 = iVar32;
616: if (sVar1 != 0) {
617: uVar31 = (int)sVar1 >> 0x1f;
618: uVar16 = (int)sVar1 + uVar31;
619: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
620: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
621: puVar4[(int)((uint)bVar15 + iVar29)] << (bVar15 & 0x1f);
622: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)((uint)bVar15 + iVar29) + 0x400) +
623: (uint)bVar15;
624: iVar17 = iVar32 - iVar29;
625: if (iVar17 < 0) {
626: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
627: uVar11 << ((byte)iVar32 & 0x3f);
628: cVar10 = (char)uVar11;
629: cVar25 = (char)(uVar11 >> 8);
630: cVar24 = (char)(uVar11 >> 0x10);
631: cVar23 = (char)(uVar11 >> 0x18);
632: cVar22 = (char)(uVar11 >> 0x20);
633: cVar21 = (char)(uVar11 >> 0x28);
634: cVar20 = (char)(uVar11 >> 0x30);
635: cVar33 = (char)(uVar11 >> 0x38);
636: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
637: pcVar26[7] = cVar10;
638: pcVar28 = pcVar26 + 8;
639: *pcVar26 = cVar33;
640: pcVar26[1] = cVar20;
641: pcVar26[2] = cVar21;
642: pcVar26[3] = cVar22;
643: pcVar26[4] = cVar23;
644: pcVar26[5] = cVar24;
645: pcVar26[6] = cVar25;
646: }
647: else {
648: pcVar26[1] = '\0';
649: *pcVar26 = cVar33;
650: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
651: *pcVar26 = cVar20;
652: pcVar26[1] = '\0';
653: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
654: *pcVar26 = cVar21;
655: pcVar26[1] = '\0';
656: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
657: *pcVar26 = cVar22;
658: pcVar26[1] = '\0';
659: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
660: *pcVar26 = cVar23;
661: pcVar26[1] = '\0';
662: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
663: *pcVar26 = cVar24;
664: pcVar26[1] = '\0';
665: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
666: *pcVar26 = cVar25;
667: pcVar26[1] = '\0';
668: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
669: *pcVar26 = cVar10;
670: pcVar26[1] = '\0';
671: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
672: }
673: iVar17 = iVar17 + 0x40;
674: uVar11 = SEXT48((int)uVar31);
675: iVar18 = 0;
676: }
677: else {
678: iVar18 = 0;
679: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
680: }
681: }
682: sVar1 = psVar5[0x11];
683: iVar29 = iVar18 + 0x10;
684: pcVar26 = pcVar28;
685: iVar32 = iVar17;
686: if (sVar1 != 0) {
687: uVar31 = (int)sVar1 >> 0x1f;
688: uVar16 = (int)sVar1 + uVar31;
689: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
690: bVar9 = bVar15 & 0x1f;
691: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
692: puVar4[(int)(iVar18 + (uint)bVar15)] << bVar9;
693: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + (uint)bVar15) + 0x400) +
694: (uint)bVar15;
695: iVar32 = iVar17 - iVar18;
696: if (iVar32 < 0) {
697: uVar11 = (long)((int)uVar31 >> (-(char)iVar32 & 0x1fU)) |
698: uVar11 << ((byte)iVar17 & 0x3f);
699: cVar10 = (char)uVar11;
700: cVar21 = (char)(uVar11 >> 8);
701: cVar22 = (char)(uVar11 >> 0x10);
702: cVar23 = (char)(uVar11 >> 0x18);
703: cVar24 = (char)(uVar11 >> 0x20);
704: cVar25 = (char)(uVar11 >> 0x28);
705: cVar20 = (char)(uVar11 >> 0x30);
706: cVar33 = (char)(uVar11 >> 0x38);
707: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
708: pcVar28[7] = cVar10;
709: pcVar26 = pcVar28 + 8;
710: *pcVar28 = cVar33;
711: pcVar28[1] = cVar20;
712: pcVar28[2] = cVar25;
713: pcVar28[3] = cVar24;
714: pcVar28[4] = cVar23;
715: pcVar28[5] = cVar22;
716: pcVar28[6] = cVar21;
717: }
718: else {
719: pcVar28[1] = '\0';
720: *pcVar28 = cVar33;
721: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
722: *pcVar28 = cVar20;
723: pcVar28[1] = '\0';
724: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
725: *pcVar28 = cVar25;
726: pcVar28[1] = '\0';
727: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
728: *pcVar28 = cVar24;
729: pcVar28[1] = '\0';
730: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
731: *pcVar28 = cVar23;
732: pcVar28[1] = '\0';
733: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
734: *pcVar28 = cVar22;
735: pcVar28[1] = '\0';
736: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
737: *pcVar28 = cVar21;
738: pcVar28[1] = '\0';
739: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
740: *pcVar28 = cVar10;
741: pcVar28[1] = '\0';
742: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
743: }
744: iVar32 = iVar32 + 0x40;
745: uVar11 = SEXT48((int)uVar31);
746: iVar29 = 0 << bVar9;
747: }
748: else {
749: iVar29 = 0 << bVar9;
750: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar31;
751: }
752: }
753: sVar1 = psVar5[0x18];
754: iVar18 = iVar29 + 0x10;
755: pcVar28 = pcVar26;
756: iVar17 = iVar32;
757: if (sVar1 != 0) {
758: uVar31 = (int)sVar1 >> 0x1f;
759: uVar16 = (int)sVar1 + uVar31;
760: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
761: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
762: puVar4[(int)((uint)bVar15 + iVar29)] << (bVar15 & 0x1f);
763: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)((uint)bVar15 + iVar29) + 0x400) +
764: (uint)bVar15;
765: iVar17 = iVar32 - iVar29;
766: if (iVar17 < 0) {
767: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
768: uVar11 << ((byte)iVar32 & 0x3f);
769: cVar10 = (char)uVar11;
770: cVar25 = (char)(uVar11 >> 8);
771: cVar24 = (char)(uVar11 >> 0x10);
772: cVar23 = (char)(uVar11 >> 0x18);
773: cVar22 = (char)(uVar11 >> 0x20);
774: cVar21 = (char)(uVar11 >> 0x28);
775: cVar20 = (char)(uVar11 >> 0x30);
776: cVar33 = (char)(uVar11 >> 0x38);
777: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
778: pcVar26[7] = cVar10;
779: pcVar28 = pcVar26 + 8;
780: *pcVar26 = cVar33;
781: pcVar26[1] = cVar20;
782: pcVar26[2] = cVar21;
783: pcVar26[3] = cVar22;
784: pcVar26[4] = cVar23;
785: pcVar26[5] = cVar24;
786: pcVar26[6] = cVar25;
787: }
788: else {
789: pcVar26[1] = '\0';
790: *pcVar26 = cVar33;
791: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
792: *pcVar26 = cVar20;
793: pcVar26[1] = '\0';
794: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
795: *pcVar26 = cVar21;
796: pcVar26[1] = '\0';
797: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
798: *pcVar26 = cVar22;
799: pcVar26[1] = '\0';
800: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
801: *pcVar26 = cVar23;
802: pcVar26[1] = '\0';
803: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
804: *pcVar26 = cVar24;
805: pcVar26[1] = '\0';
806: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
807: *pcVar26 = cVar25;
808: pcVar26[1] = '\0';
809: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
810: *pcVar26 = cVar10;
811: pcVar26[1] = '\0';
812: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
813: }
814: iVar17 = iVar17 + 0x40;
815: uVar11 = SEXT48((int)uVar31);
816: iVar18 = 0;
817: }
818: else {
819: iVar18 = 0;
820: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
821: }
822: }
823: sVar1 = psVar5[0x20];
824: iVar29 = iVar18 + 0x10;
825: pcVar26 = pcVar28;
826: iVar32 = iVar17;
827: if (sVar1 != 0) {
828: uVar31 = (int)sVar1 >> 0x1f;
829: uVar16 = (int)sVar1 + uVar31;
830: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
831: bVar9 = bVar15 & 0x1f;
832: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
833: puVar4[(int)(iVar18 + (uint)bVar15)] << bVar9;
834: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + (uint)bVar15) + 0x400) +
835: (uint)bVar15;
836: iVar32 = iVar17 - iVar18;
837: if (iVar32 < 0) {
838: uVar11 = (long)((int)uVar31 >> (-(char)iVar32 & 0x1fU)) |
839: uVar11 << ((byte)iVar17 & 0x3f);
840: cVar10 = (char)uVar11;
841: cVar24 = (char)(uVar11 >> 8);
842: cVar23 = (char)(uVar11 >> 0x10);
843: cVar20 = (char)(uVar11 >> 0x18);
844: cVar33 = (char)(uVar11 >> 0x20);
845: cVar21 = (char)(uVar11 >> 0x28);
846: cVar22 = (char)(uVar11 >> 0x30);
847: cVar25 = (char)(uVar11 >> 0x38);
848: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
849: pcVar28[7] = cVar10;
850: pcVar26 = pcVar28 + 8;
851: *pcVar28 = cVar25;
852: pcVar28[1] = cVar22;
853: pcVar28[2] = cVar21;
854: pcVar28[3] = cVar33;
855: pcVar28[4] = cVar20;
856: pcVar28[5] = cVar23;
857: pcVar28[6] = cVar24;
858: }
859: else {
860: pcVar28[1] = '\0';
861: *pcVar28 = cVar25;
862: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
863: *pcVar28 = cVar22;
864: pcVar28[1] = '\0';
865: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
866: *pcVar28 = cVar21;
867: pcVar28[1] = '\0';
868: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
869: *pcVar28 = cVar33;
870: pcVar28[1] = '\0';
871: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
872: *pcVar28 = cVar20;
873: pcVar28[1] = '\0';
874: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
875: *pcVar28 = cVar23;
876: pcVar28[1] = '\0';
877: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
878: *pcVar28 = cVar24;
879: pcVar28[1] = '\0';
880: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
881: *pcVar28 = cVar10;
882: pcVar28[1] = '\0';
883: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
884: }
885: iVar32 = iVar32 + 0x40;
886: uVar11 = SEXT48((int)uVar31);
887: iVar29 = 0 << bVar9;
888: }
889: else {
890: iVar29 = 0 << bVar9;
891: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar31;
892: }
893: }
894: sVar1 = psVar5[0x19];
895: iVar18 = iVar29 + 0x10;
896: pcVar28 = pcVar26;
897: iVar17 = iVar32;
898: if (sVar1 != 0) {
899: uVar31 = (int)sVar1 >> 0x1f;
900: uVar16 = (int)sVar1 + uVar31;
901: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
902: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
903: puVar4[(int)((uint)bVar15 + iVar29)] << (bVar15 & 0x1f);
904: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)((uint)bVar15 + iVar29) + 0x400) +
905: (uint)bVar15;
906: iVar17 = iVar32 - iVar29;
907: if (iVar17 < 0) {
908: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
909: uVar11 << ((byte)iVar32 & 0x3f);
910: cVar10 = (char)uVar11;
911: cVar25 = (char)(uVar11 >> 8);
912: cVar24 = (char)(uVar11 >> 0x10);
913: cVar23 = (char)(uVar11 >> 0x18);
914: cVar22 = (char)(uVar11 >> 0x20);
915: cVar21 = (char)(uVar11 >> 0x28);
916: cVar20 = (char)(uVar11 >> 0x30);
917: cVar33 = (char)(uVar11 >> 0x38);
918: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
919: pcVar26[7] = cVar10;
920: pcVar28 = pcVar26 + 8;
921: *pcVar26 = cVar33;
922: pcVar26[1] = cVar20;
923: pcVar26[2] = cVar21;
924: pcVar26[3] = cVar22;
925: pcVar26[4] = cVar23;
926: pcVar26[5] = cVar24;
927: pcVar26[6] = cVar25;
928: }
929: else {
930: pcVar26[1] = '\0';
931: *pcVar26 = cVar33;
932: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
933: *pcVar26 = cVar20;
934: pcVar26[1] = '\0';
935: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
936: *pcVar26 = cVar21;
937: pcVar26[1] = '\0';
938: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
939: *pcVar26 = cVar22;
940: pcVar26[1] = '\0';
941: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
942: *pcVar26 = cVar23;
943: pcVar26[1] = '\0';
944: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
945: *pcVar26 = cVar24;
946: pcVar26[1] = '\0';
947: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
948: *pcVar26 = cVar25;
949: pcVar26[1] = '\0';
950: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
951: *pcVar26 = cVar10;
952: pcVar26[1] = '\0';
953: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
954: }
955: iVar17 = iVar17 + 0x40;
956: uVar11 = SEXT48((int)uVar31);
957: iVar18 = 0;
958: }
959: else {
960: iVar18 = 0;
961: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
962: }
963: }
964: sVar1 = psVar5[0x12];
965: iVar29 = iVar18 + 0x10;
966: pcVar26 = pcVar28;
967: iVar32 = iVar17;
968: if (sVar1 != 0) {
969: uVar31 = (int)sVar1 >> 0x1f;
970: uVar16 = (int)sVar1 + uVar31;
971: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
972: bVar9 = bVar15 & 0x1f;
973: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
974: puVar4[(int)(iVar18 + (uint)bVar15)] << bVar9;
975: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + (uint)bVar15) + 0x400) +
976: (uint)bVar15;
977: iVar32 = iVar17 - iVar18;
978: if (iVar32 < 0) {
979: uVar11 = (long)((int)uVar31 >> (-(char)iVar32 & 0x1fU)) |
980: uVar11 << ((byte)iVar17 & 0x3f);
981: cVar10 = (char)uVar11;
982: cVar33 = (char)(uVar11 >> 8);
983: cVar20 = (char)(uVar11 >> 0x10);
984: cVar22 = (char)(uVar11 >> 0x18);
985: cVar23 = (char)(uVar11 >> 0x20);
986: cVar25 = (char)(uVar11 >> 0x28);
987: cVar24 = (char)(uVar11 >> 0x30);
988: cVar21 = (char)(uVar11 >> 0x38);
989: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
990: pcVar28[7] = cVar10;
991: pcVar26 = pcVar28 + 8;
992: *pcVar28 = cVar21;
993: pcVar28[1] = cVar24;
994: pcVar28[2] = cVar25;
995: pcVar28[3] = cVar23;
996: pcVar28[4] = cVar22;
997: pcVar28[5] = cVar20;
998: pcVar28[6] = cVar33;
999: }
1000: else {
1001: pcVar28[1] = '\0';
1002: *pcVar28 = cVar21;
1003: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1004: *pcVar28 = cVar24;
1005: pcVar28[1] = '\0';
1006: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
1007: *pcVar28 = cVar25;
1008: pcVar28[1] = '\0';
1009: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
1010: *pcVar28 = cVar23;
1011: pcVar28[1] = '\0';
1012: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
1013: *pcVar28 = cVar22;
1014: pcVar28[1] = '\0';
1015: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
1016: *pcVar28 = cVar20;
1017: pcVar28[1] = '\0';
1018: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
1019: *pcVar28 = cVar33;
1020: pcVar28[1] = '\0';
1021: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
1022: *pcVar28 = cVar10;
1023: pcVar28[1] = '\0';
1024: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
1025: }
1026: iVar32 = iVar32 + 0x40;
1027: uVar11 = SEXT48((int)uVar31);
1028: iVar29 = 0 << bVar9;
1029: }
1030: else {
1031: iVar29 = 0 << bVar9;
1032: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar31;
1033: }
1034: }
1035: sVar1 = psVar5[0xb];
1036: iVar18 = iVar29 + 0x10;
1037: pcVar28 = pcVar26;
1038: iVar17 = iVar32;
1039: if (sVar1 != 0) {
1040: uVar31 = (int)sVar1 >> 0x1f;
1041: uVar16 = (int)sVar1 + uVar31;
1042: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
1043: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
1044: puVar4[(int)((uint)bVar15 + iVar29)] << (bVar15 & 0x1f);
1045: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)((uint)bVar15 + iVar29) + 0x400) +
1046: (uint)bVar15;
1047: iVar17 = iVar32 - iVar29;
1048: if (iVar17 < 0) {
1049: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1050: uVar11 << ((byte)iVar32 & 0x3f);
1051: cVar10 = (char)uVar11;
1052: cVar25 = (char)(uVar11 >> 8);
1053: cVar33 = (char)(uVar11 >> 0x10);
1054: cVar20 = (char)(uVar11 >> 0x18);
1055: cVar21 = (char)(uVar11 >> 0x20);
1056: cVar24 = (char)(uVar11 >> 0x28);
1057: cVar23 = (char)(uVar11 >> 0x30);
1058: cVar22 = (char)(uVar11 >> 0x38);
1059: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1060: pcVar26[7] = cVar10;
1061: pcVar28 = pcVar26 + 8;
1062: *pcVar26 = cVar22;
1063: pcVar26[1] = cVar23;
1064: pcVar26[2] = cVar24;
1065: pcVar26[3] = cVar21;
1066: pcVar26[4] = cVar20;
1067: pcVar26[5] = cVar33;
1068: pcVar26[6] = cVar25;
1069: }
1070: else {
1071: pcVar26[1] = '\0';
1072: *pcVar26 = cVar22;
1073: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1074: *pcVar26 = cVar23;
1075: pcVar26[1] = '\0';
1076: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
1077: *pcVar26 = cVar24;
1078: pcVar26[1] = '\0';
1079: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
1080: *pcVar26 = cVar21;
1081: pcVar26[1] = '\0';
1082: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
1083: *pcVar26 = cVar20;
1084: pcVar26[1] = '\0';
1085: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
1086: *pcVar26 = cVar33;
1087: pcVar26[1] = '\0';
1088: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
1089: *pcVar26 = cVar25;
1090: pcVar26[1] = '\0';
1091: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
1092: *pcVar26 = cVar10;
1093: pcVar26[1] = '\0';
1094: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
1095: }
1096: iVar17 = iVar17 + 0x40;
1097: uVar11 = SEXT48((int)uVar31);
1098: iVar18 = 0;
1099: }
1100: else {
1101: iVar18 = 0;
1102: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1103: }
1104: }
1105: sVar1 = psVar5[4];
1106: iVar29 = iVar18 + 0x10;
1107: pcVar26 = pcVar28;
1108: iVar32 = iVar17;
1109: if (sVar1 != 0) {
1110: uVar31 = (int)sVar1 >> 0x1f;
1111: uVar16 = (int)sVar1 + uVar31;
1112: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
1113: bVar9 = bVar15 & 0x1f;
1114: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
1115: puVar4[(int)(iVar18 + (uint)bVar15)] << bVar9;
1116: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + (uint)bVar15) + 0x400) +
1117: (uint)bVar15;
1118: iVar32 = iVar17 - iVar18;
1119: if (iVar32 < 0) {
1120: uVar11 = (long)((int)uVar31 >> (-(char)iVar32 & 0x1fU)) |
1121: uVar11 << ((byte)iVar17 & 0x3f);
1122: cVar10 = (char)uVar11;
1123: cVar21 = (char)(uVar11 >> 8);
1124: cVar22 = (char)(uVar11 >> 0x10);
1125: cVar23 = (char)(uVar11 >> 0x18);
1126: cVar24 = (char)(uVar11 >> 0x20);
1127: cVar25 = (char)(uVar11 >> 0x28);
1128: cVar33 = (char)(uVar11 >> 0x30);
1129: cVar20 = (char)(uVar11 >> 0x38);
1130: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1131: pcVar28[7] = cVar10;
1132: pcVar26 = pcVar28 + 8;
1133: *pcVar28 = cVar20;
1134: pcVar28[1] = cVar33;
1135: pcVar28[2] = cVar25;
1136: pcVar28[3] = cVar24;
1137: pcVar28[4] = cVar23;
1138: pcVar28[5] = cVar22;
1139: pcVar28[6] = cVar21;
1140: }
1141: else {
1142: pcVar28[1] = '\0';
1143: *pcVar28 = cVar20;
1144: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1145: *pcVar28 = cVar33;
1146: pcVar28[1] = '\0';
1147: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
1148: *pcVar28 = cVar25;
1149: pcVar28[1] = '\0';
1150: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
1151: *pcVar28 = cVar24;
1152: pcVar28[1] = '\0';
1153: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
1154: *pcVar28 = cVar23;
1155: pcVar28[1] = '\0';
1156: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
1157: *pcVar28 = cVar22;
1158: pcVar28[1] = '\0';
1159: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
1160: *pcVar28 = cVar21;
1161: pcVar28[1] = '\0';
1162: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
1163: *pcVar28 = cVar10;
1164: pcVar28[1] = '\0';
1165: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
1166: }
1167: iVar32 = iVar32 + 0x40;
1168: uVar11 = SEXT48((int)uVar31);
1169: iVar29 = 0 << bVar9;
1170: }
1171: else {
1172: iVar29 = 0 << bVar9;
1173: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar31;
1174: }
1175: }
1176: sVar1 = psVar5[5];
1177: iVar18 = iVar29 + 0x10;
1178: pcVar28 = pcVar26;
1179: iVar17 = iVar32;
1180: if (sVar1 != 0) {
1181: uVar31 = (int)sVar1 >> 0x1f;
1182: uVar16 = (int)sVar1 + uVar31;
1183: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
1184: uVar31 = uVar16 & (int)(1 << (bVar15 & 0x3f)) - 1U |
1185: puVar4[(int)((uint)bVar15 + iVar29)] << (bVar15 & 0x1f);
1186: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)((uint)bVar15 + iVar29) + 0x400) +
1187: (uint)bVar15;
1188: iVar17 = iVar32 - iVar29;
1189: if (iVar17 < 0) {
1190: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1191: uVar11 << ((byte)iVar32 & 0x3f);
1192: cVar10 = (char)uVar11;
1193: cVar22 = (char)(uVar11 >> 8);
1194: cVar25 = (char)(uVar11 >> 0x10);
1195: cVar33 = (char)(uVar11 >> 0x18);
1196: cVar21 = (char)(uVar11 >> 0x20);
1197: cVar20 = (char)(uVar11 >> 0x28);
1198: cVar24 = (char)(uVar11 >> 0x30);
1199: cVar23 = (char)(uVar11 >> 0x38);
1200: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1201: pcVar26[7] = cVar10;
1202: pcVar28 = pcVar26 + 8;
1203: *pcVar26 = cVar23;
1204: pcVar26[1] = cVar24;
1205: pcVar26[2] = cVar20;
1206: pcVar26[3] = cVar21;
1207: pcVar26[4] = cVar33;
1208: pcVar26[5] = cVar25;
1209: pcVar26[6] = cVar22;
1210: }
1211: else {
1212: pcVar26[1] = '\0';
1213: *pcVar26 = cVar23;
1214: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1215: *pcVar26 = cVar24;
1216: pcVar26[1] = '\0';
1217: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
1218: *pcVar26 = cVar20;
1219: pcVar26[1] = '\0';
1220: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
1221: *pcVar26 = cVar21;
1222: pcVar26[1] = '\0';
1223: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
1224: *pcVar26 = cVar33;
1225: pcVar26[1] = '\0';
1226: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
1227: *pcVar26 = cVar25;
1228: pcVar26[1] = '\0';
1229: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
1230: *pcVar26 = cVar22;
1231: pcVar26[1] = '\0';
1232: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
1233: *pcVar26 = cVar10;
1234: pcVar26[1] = '\0';
1235: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
1236: }
1237: iVar17 = iVar17 + 0x40;
1238: uVar11 = SEXT48((int)uVar31);
1239: iVar18 = 0;
1240: }
1241: else {
1242: iVar18 = 0;
1243: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1244: }
1245: }
1246: iVar29 = (int)psVar5[0xc];
1247: bVar15 = (byte)iVar17;
1248: if (psVar5[0xc] == 0) {
1249: sVar1 = psVar5[0x13];
1250: iVar18 = iVar18 + 0x10;
1251: iVar32 = iVar18;
1252: if (sVar1 == 0) goto LAB_0010c760;
1253: uVar16 = (int)sVar1 >> 0x1f;
1254: uVar31 = (int)sVar1 + uVar16;
1255: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1256: iVar32 = iVar17;
1257: if (iVar18 == 0x100) {
1258: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
1259: iVar18 = iVar29;
1260: if (iVar32 < 0) {
1261: uVar11 = uVar11 << (bVar15 & 0x3f);
1262: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
1263: cVar10 = (char)uVar14;
1264: cVar20 = (char)(uVar14 >> 8);
1265: cVar33 = (char)(uVar14 >> 0x10);
1266: cVar21 = (char)(uVar14 >> 0x18);
1267: cVar22 = (char)(uVar11 >> 0x20);
1268: cVar23 = (char)(uVar11 >> 0x28);
1269: cVar24 = (char)(uVar11 >> 0x30);
1270: cVar25 = (char)(uVar11 >> 0x38);
1271: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
1272: pcVar28[7] = cVar10;
1273: pcVar26 = pcVar28 + 8;
1274: *pcVar28 = cVar25;
1275: pcVar28[1] = cVar24;
1276: pcVar28[2] = cVar23;
1277: pcVar28[3] = cVar22;
1278: pcVar28[4] = cVar21;
1279: pcVar28[5] = cVar33;
1280: pcVar28[6] = cVar20;
1281: }
1282: else {
1283: pcVar28[1] = '\0';
1284: *pcVar28 = cVar25;
1285: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1286: *pcVar28 = cVar24;
1287: pcVar28[1] = '\0';
1288: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
1289: *pcVar28 = cVar23;
1290: pcVar28[1] = '\0';
1291: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
1292: *pcVar28 = cVar22;
1293: pcVar28[1] = '\0';
1294: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
1295: *pcVar28 = cVar21;
1296: pcVar28[1] = '\0';
1297: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
1298: *pcVar28 = cVar33;
1299: pcVar28[1] = '\0';
1300: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
1301: *pcVar28 = cVar20;
1302: pcVar28[1] = '\0';
1303: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
1304: *pcVar28 = cVar10;
1305: pcVar28[1] = '\0';
1306: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
1307: }
1308: uVar11 = (ulong)puVar4[0xf0];
1309: pcVar28 = pcVar26;
1310: iVar32 = iVar32 + 0x40;
1311: }
1312: else {
1313: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
1314: }
1315: }
1316: LAB_00109d24:
1317: uVar31 = puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f) |
1318: (int)(1 << ((byte)uVar16 & 0x3f)) - 1U & uVar31;
1319: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
1320: iVar17 = iVar32 - iVar29;
1321: if (iVar17 < 0) {
1322: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1323: uVar11 << ((byte)iVar32 & 0x3f);
1324: cVar10 = (char)uVar11;
1325: cVar22 = (char)(uVar11 >> 8);
1326: cVar20 = (char)(uVar11 >> 0x10);
1327: cVar33 = (char)(uVar11 >> 0x18);
1328: cVar21 = (char)(uVar11 >> 0x20);
1329: cVar23 = (char)(uVar11 >> 0x28);
1330: cVar24 = (char)(uVar11 >> 0x30);
1331: cVar25 = (char)(uVar11 >> 0x38);
1332: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1333: pcVar28[7] = cVar10;
1334: pcVar26 = pcVar28 + 8;
1335: *pcVar28 = cVar25;
1336: pcVar28[1] = cVar24;
1337: pcVar28[2] = cVar23;
1338: pcVar28[3] = cVar21;
1339: pcVar28[4] = cVar33;
1340: pcVar28[5] = cVar20;
1341: pcVar28[6] = cVar22;
1342: }
1343: else {
1344: pcVar28[1] = '\0';
1345: *pcVar28 = cVar25;
1346: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1347: *pcVar28 = cVar24;
1348: pcVar28[1] = '\0';
1349: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
1350: *pcVar28 = cVar23;
1351: pcVar28[1] = '\0';
1352: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
1353: *pcVar28 = cVar21;
1354: pcVar28[1] = '\0';
1355: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
1356: *pcVar28 = cVar33;
1357: pcVar28[1] = '\0';
1358: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
1359: *pcVar28 = cVar20;
1360: pcVar28[1] = '\0';
1361: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
1362: *pcVar28 = cVar22;
1363: pcVar28[1] = '\0';
1364: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
1365: *pcVar28 = cVar10;
1366: pcVar28[1] = '\0';
1367: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
1368: }
1369: iVar17 = iVar17 + 0x40;
1370: uVar11 = SEXT48((int)uVar31);
1371: }
1372: else {
1373: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1374: pcVar26 = pcVar28;
1375: }
1376: iVar29 = (int)psVar5[0x1a];
1377: if (psVar5[0x1a] == 0) goto LAB_0010ca10;
1378: uVar16 = iVar29 >> 0x1f;
1379: uVar31 = uVar16 + iVar29;
1380: iVar29 = 0;
1381: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1382: pcVar28 = pcVar26;
1383: iVar18 = iVar17;
1384: LAB_00109d8f:
1385: uVar31 = puVar4[(int)(iVar29 + uVar16)] << ((byte)uVar16 & 0x1f) |
1386: (int)(1 << ((byte)uVar16 & 0x3f)) - 1U & uVar31;
1387: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar16) + 0x400) + uVar16;
1388: iVar17 = iVar18 - iVar29;
1389: if (iVar17 < 0) {
1390: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1391: uVar11 << ((byte)iVar18 & 0x3f);
1392: cVar10 = (char)uVar11;
1393: cVar33 = (char)(uVar11 >> 8);
1394: cVar20 = (char)(uVar11 >> 0x10);
1395: cVar21 = (char)(uVar11 >> 0x18);
1396: cVar22 = (char)(uVar11 >> 0x20);
1397: cVar23 = (char)(uVar11 >> 0x28);
1398: cVar24 = (char)(uVar11 >> 0x30);
1399: cVar25 = (char)(uVar11 >> 0x38);
1400: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1401: pcVar28[7] = cVar10;
1402: pcVar26 = pcVar28 + 8;
1403: *pcVar28 = cVar25;
1404: pcVar28[1] = cVar24;
1405: pcVar28[2] = cVar23;
1406: pcVar28[3] = cVar22;
1407: pcVar28[4] = cVar21;
1408: pcVar28[5] = cVar20;
1409: pcVar28[6] = cVar33;
1410: }
1411: else {
1412: pcVar28[1] = '\0';
1413: *pcVar28 = cVar25;
1414: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1415: *pcVar28 = cVar24;
1416: pcVar28[1] = '\0';
1417: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
1418: *pcVar28 = cVar23;
1419: pcVar28[1] = '\0';
1420: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
1421: *pcVar28 = cVar22;
1422: pcVar28[1] = '\0';
1423: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
1424: *pcVar28 = cVar21;
1425: pcVar28[1] = '\0';
1426: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
1427: *pcVar28 = cVar20;
1428: pcVar28[1] = '\0';
1429: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
1430: *pcVar28 = cVar33;
1431: pcVar28[1] = '\0';
1432: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
1433: *pcVar28 = cVar10;
1434: pcVar28[1] = '\0';
1435: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
1436: }
1437: iVar17 = iVar17 + 0x40;
1438: uVar11 = SEXT48((int)uVar31);
1439: }
1440: else {
1441: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1442: pcVar26 = pcVar28;
1443: }
1444: iVar18 = (int)psVar5[0x21];
1445: if (psVar5[0x21] == 0) goto LAB_0010c898;
1446: uVar16 = iVar18 >> 0x1f;
1447: uVar31 = uVar16 + iVar18;
1448: iVar18 = 0;
1449: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1450: iVar32 = iVar17;
1451: LAB_00109dfa:
1452: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1453: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
1454: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
1455: iVar17 = iVar32 - iVar29;
1456: if (iVar17 < 0) {
1457: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1458: uVar11 << ((byte)iVar32 & 0x3f);
1459: cVar10 = (char)uVar11;
1460: cVar33 = (char)(uVar11 >> 8);
1461: cVar20 = (char)(uVar11 >> 0x10);
1462: cVar21 = (char)(uVar11 >> 0x18);
1463: cVar22 = (char)(uVar11 >> 0x20);
1464: cVar23 = (char)(uVar11 >> 0x28);
1465: cVar24 = (char)(uVar11 >> 0x30);
1466: cVar25 = (char)(uVar11 >> 0x38);
1467: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1468: pcVar26[7] = cVar10;
1469: pcVar28 = pcVar26 + 8;
1470: *pcVar26 = cVar25;
1471: pcVar26[1] = cVar24;
1472: pcVar26[2] = cVar23;
1473: pcVar26[3] = cVar22;
1474: pcVar26[4] = cVar21;
1475: pcVar26[5] = cVar20;
1476: pcVar26[6] = cVar33;
1477: }
1478: else {
1479: pcVar26[1] = '\0';
1480: *pcVar26 = cVar25;
1481: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1482: *pcVar26 = cVar24;
1483: pcVar26[1] = '\0';
1484: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
1485: *pcVar26 = cVar23;
1486: pcVar26[1] = '\0';
1487: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
1488: *pcVar26 = cVar22;
1489: pcVar26[1] = '\0';
1490: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
1491: *pcVar26 = cVar21;
1492: pcVar26[1] = '\0';
1493: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
1494: *pcVar26 = cVar20;
1495: pcVar26[1] = '\0';
1496: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
1497: *pcVar26 = cVar33;
1498: pcVar26[1] = '\0';
1499: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
1500: *pcVar26 = cVar10;
1501: pcVar26[1] = '\0';
1502: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
1503: }
1504: iVar17 = iVar17 + 0x40;
1505: uVar11 = SEXT48((int)uVar31);
1506: }
1507: else {
1508: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1509: pcVar28 = pcVar26;
1510: }
1511: iVar29 = (int)psVar5[0x28];
1512: pcVar26 = pcVar28;
1513: if (psVar5[0x28] == 0) goto LAB_0010c9a8;
1514: uVar16 = iVar29 >> 0x1f;
1515: uVar31 = uVar16 + iVar29;
1516: iVar29 = 0;
1517: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1518: iVar32 = iVar17;
1519: LAB_00109e64:
1520: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1521: puVar4[(int)(iVar29 + uVar16)] << ((byte)uVar16 & 0x1f);
1522: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar16) + 0x400) + uVar16;
1523: iVar17 = iVar32 - iVar29;
1524: if (iVar17 < 0) {
1525: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1526: uVar11 << ((byte)iVar32 & 0x3f);
1527: cVar10 = (char)uVar11;
1528: cVar33 = (char)(uVar11 >> 8);
1529: cVar20 = (char)(uVar11 >> 0x10);
1530: cVar21 = (char)(uVar11 >> 0x18);
1531: cVar22 = (char)(uVar11 >> 0x20);
1532: cVar23 = (char)(uVar11 >> 0x28);
1533: cVar24 = (char)(uVar11 >> 0x30);
1534: cVar25 = (char)(uVar11 >> 0x38);
1535: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1536: pcVar26[7] = cVar10;
1537: pcVar28 = pcVar26 + 8;
1538: *pcVar26 = cVar25;
1539: pcVar26[1] = cVar24;
1540: pcVar26[2] = cVar23;
1541: pcVar26[3] = cVar22;
1542: pcVar26[4] = cVar21;
1543: pcVar26[5] = cVar20;
1544: pcVar26[6] = cVar33;
1545: }
1546: else {
1547: pcVar26[1] = '\0';
1548: *pcVar26 = cVar25;
1549: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1550: *pcVar26 = cVar24;
1551: pcVar26[1] = '\0';
1552: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
1553: *pcVar26 = cVar23;
1554: pcVar26[1] = '\0';
1555: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
1556: *pcVar26 = cVar22;
1557: pcVar26[1] = '\0';
1558: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
1559: *pcVar26 = cVar21;
1560: pcVar26[1] = '\0';
1561: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
1562: *pcVar26 = cVar20;
1563: pcVar26[1] = '\0';
1564: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
1565: *pcVar26 = cVar33;
1566: pcVar26[1] = '\0';
1567: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
1568: *pcVar26 = cVar10;
1569: pcVar26[1] = '\0';
1570: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
1571: }
1572: iVar17 = iVar17 + 0x40;
1573: uVar11 = SEXT48((int)uVar31);
1574: }
1575: else {
1576: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1577: pcVar28 = pcVar26;
1578: }
1579: iVar18 = (int)psVar5[0x30];
1580: if (psVar5[0x30] == 0) goto LAB_0010bc28;
1581: uVar16 = iVar18 >> 0x1f;
1582: uVar31 = uVar16 + iVar18;
1583: iVar18 = 0;
1584: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1585: pcVar26 = pcVar28;
1586: iVar32 = iVar17;
1587: LAB_00109ece:
1588: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1589: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
1590: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
1591: iVar17 = iVar32 - iVar29;
1592: if (iVar17 < 0) {
1593: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1594: uVar11 << ((byte)iVar32 & 0x3f);
1595: cVar10 = (char)uVar11;
1596: cVar25 = (char)(uVar11 >> 8);
1597: cVar24 = (char)(uVar11 >> 0x10);
1598: cVar23 = (char)(uVar11 >> 0x18);
1599: cVar22 = (char)(uVar11 >> 0x20);
1600: cVar21 = (char)(uVar11 >> 0x28);
1601: cVar20 = (char)(uVar11 >> 0x30);
1602: cVar33 = (char)(uVar11 >> 0x38);
1603: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1604: pcVar26[7] = cVar10;
1605: pcVar28 = pcVar26 + 8;
1606: *pcVar26 = cVar33;
1607: pcVar26[1] = cVar20;
1608: pcVar26[2] = cVar21;
1609: pcVar26[3] = cVar22;
1610: pcVar26[4] = cVar23;
1611: pcVar26[5] = cVar24;
1612: pcVar26[6] = cVar25;
1613: }
1614: else {
1615: pcVar26[1] = '\0';
1616: *pcVar26 = cVar33;
1617: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1618: *pcVar26 = cVar20;
1619: pcVar26[1] = '\0';
1620: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
1621: *pcVar26 = cVar21;
1622: pcVar26[1] = '\0';
1623: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
1624: *pcVar26 = cVar22;
1625: pcVar26[1] = '\0';
1626: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
1627: *pcVar26 = cVar23;
1628: pcVar26[1] = '\0';
1629: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
1630: *pcVar26 = cVar24;
1631: pcVar26[1] = '\0';
1632: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
1633: *pcVar26 = cVar25;
1634: pcVar26[1] = '\0';
1635: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
1636: *pcVar26 = cVar10;
1637: pcVar26[1] = '\0';
1638: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
1639: }
1640: iVar17 = iVar17 + 0x40;
1641: uVar11 = SEXT48((int)uVar31);
1642: }
1643: else {
1644: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1645: pcVar28 = pcVar26;
1646: }
1647: iVar29 = (int)psVar5[0x29];
1648: if (psVar5[0x29] == 0) goto LAB_0010c700;
1649: uVar16 = iVar29 >> 0x1f;
1650: uVar31 = uVar16 + iVar29;
1651: iVar29 = 0;
1652: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1653: iVar32 = iVar17;
1654: LAB_00109f38:
1655: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1656: puVar4[(int)(iVar29 + uVar16)] << ((byte)uVar16 & 0x1f);
1657: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar16) + 0x400) + uVar16;
1658: iVar17 = iVar32 - iVar29;
1659: if (iVar17 < 0) {
1660: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1661: uVar11 << ((byte)iVar32 & 0x3f);
1662: cVar10 = (char)uVar11;
1663: cVar33 = (char)(uVar11 >> 8);
1664: cVar20 = (char)(uVar11 >> 0x10);
1665: cVar21 = (char)(uVar11 >> 0x18);
1666: cVar22 = (char)(uVar11 >> 0x20);
1667: cVar23 = (char)(uVar11 >> 0x28);
1668: cVar24 = (char)(uVar11 >> 0x30);
1669: cVar25 = (char)(uVar11 >> 0x38);
1670: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1671: pcVar28[7] = cVar10;
1672: pcVar26 = pcVar28 + 8;
1673: *pcVar28 = cVar25;
1674: pcVar28[1] = cVar24;
1675: pcVar28[2] = cVar23;
1676: pcVar28[3] = cVar22;
1677: pcVar28[4] = cVar21;
1678: pcVar28[5] = cVar20;
1679: pcVar28[6] = cVar33;
1680: }
1681: else {
1682: pcVar28[1] = '\0';
1683: *pcVar28 = cVar25;
1684: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1685: *pcVar28 = cVar24;
1686: pcVar28[1] = '\0';
1687: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
1688: *pcVar28 = cVar23;
1689: pcVar28[1] = '\0';
1690: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
1691: *pcVar28 = cVar22;
1692: pcVar28[1] = '\0';
1693: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
1694: *pcVar28 = cVar21;
1695: pcVar28[1] = '\0';
1696: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
1697: *pcVar28 = cVar20;
1698: pcVar28[1] = '\0';
1699: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
1700: *pcVar28 = cVar33;
1701: pcVar28[1] = '\0';
1702: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
1703: *pcVar28 = cVar10;
1704: pcVar28[1] = '\0';
1705: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
1706: }
1707: iVar17 = iVar17 + 0x40;
1708: uVar11 = SEXT48((int)uVar31);
1709: }
1710: else {
1711: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1712: pcVar26 = pcVar28;
1713: }
1714: iVar18 = (int)psVar5[0x22];
1715: if (psVar5[0x22] == 0) goto LAB_0010c580;
1716: uVar16 = iVar18 >> 0x1f;
1717: uVar31 = uVar16 + iVar18;
1718: iVar18 = 0;
1719: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1720: pcVar28 = pcVar26;
1721: iVar32 = iVar17;
1722: LAB_00109fa2:
1723: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1724: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
1725: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
1726: iVar17 = iVar32 - iVar29;
1727: if (iVar17 < 0) {
1728: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1729: uVar11 << ((byte)iVar32 & 0x3f);
1730: cVar10 = (char)uVar11;
1731: cVar33 = (char)(uVar11 >> 8);
1732: cVar20 = (char)(uVar11 >> 0x10);
1733: cVar21 = (char)(uVar11 >> 0x18);
1734: cVar22 = (char)(uVar11 >> 0x20);
1735: cVar23 = (char)(uVar11 >> 0x28);
1736: cVar24 = (char)(uVar11 >> 0x30);
1737: cVar25 = (char)(uVar11 >> 0x38);
1738: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1739: pcVar28[7] = cVar10;
1740: pcVar26 = pcVar28 + 8;
1741: *pcVar28 = cVar25;
1742: pcVar28[1] = cVar24;
1743: pcVar28[2] = cVar23;
1744: pcVar28[3] = cVar22;
1745: pcVar28[4] = cVar21;
1746: pcVar28[5] = cVar20;
1747: pcVar28[6] = cVar33;
1748: }
1749: else {
1750: pcVar28[1] = '\0';
1751: *pcVar28 = cVar25;
1752: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1753: *pcVar28 = cVar24;
1754: pcVar28[1] = '\0';
1755: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
1756: *pcVar28 = cVar23;
1757: pcVar28[1] = '\0';
1758: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
1759: *pcVar28 = cVar22;
1760: pcVar28[1] = '\0';
1761: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
1762: *pcVar28 = cVar21;
1763: pcVar28[1] = '\0';
1764: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
1765: *pcVar28 = cVar20;
1766: pcVar28[1] = '\0';
1767: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
1768: *pcVar28 = cVar33;
1769: pcVar28[1] = '\0';
1770: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
1771: *pcVar28 = cVar10;
1772: pcVar28[1] = '\0';
1773: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
1774: }
1775: iVar17 = iVar17 + 0x40;
1776: uVar11 = SEXT48((int)uVar31);
1777: }
1778: else {
1779: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1780: pcVar26 = pcVar28;
1781: }
1782: iVar29 = (int)psVar5[0x1b];
1783: if (psVar5[0x1b] == 0) goto LAB_0010c640;
1784: uVar16 = iVar29 >> 0x1f;
1785: uVar31 = uVar16 + iVar29;
1786: iVar29 = 0;
1787: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1788: iVar32 = iVar17;
1789: LAB_0010a00c:
1790: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1791: puVar4[(int)(iVar29 + uVar16)] << ((byte)uVar16 & 0x1f);
1792: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar16) + 0x400) + uVar16;
1793: iVar17 = iVar32 - iVar29;
1794: if (iVar17 < 0) {
1795: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1796: uVar11 << ((byte)iVar32 & 0x3f);
1797: cVar10 = (char)uVar11;
1798: cVar25 = (char)(uVar11 >> 8);
1799: cVar24 = (char)(uVar11 >> 0x10);
1800: cVar23 = (char)(uVar11 >> 0x18);
1801: cVar22 = (char)(uVar11 >> 0x20);
1802: cVar21 = (char)(uVar11 >> 0x28);
1803: cVar20 = (char)(uVar11 >> 0x30);
1804: cVar33 = (char)(uVar11 >> 0x38);
1805: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1806: pcVar26[7] = cVar10;
1807: pcVar28 = pcVar26 + 8;
1808: *pcVar26 = cVar33;
1809: pcVar26[1] = cVar20;
1810: pcVar26[2] = cVar21;
1811: pcVar26[3] = cVar22;
1812: pcVar26[4] = cVar23;
1813: pcVar26[5] = cVar24;
1814: pcVar26[6] = cVar25;
1815: }
1816: else {
1817: pcVar26[1] = '\0';
1818: *pcVar26 = cVar33;
1819: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1820: *pcVar26 = cVar20;
1821: pcVar26[1] = '\0';
1822: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
1823: *pcVar26 = cVar21;
1824: pcVar26[1] = '\0';
1825: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
1826: *pcVar26 = cVar22;
1827: pcVar26[1] = '\0';
1828: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
1829: *pcVar26 = cVar23;
1830: pcVar26[1] = '\0';
1831: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
1832: *pcVar26 = cVar24;
1833: pcVar26[1] = '\0';
1834: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
1835: *pcVar26 = cVar25;
1836: pcVar26[1] = '\0';
1837: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
1838: *pcVar26 = cVar10;
1839: pcVar26[1] = '\0';
1840: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
1841: }
1842: iVar17 = iVar17 + 0x40;
1843: uVar11 = SEXT48((int)uVar31);
1844: }
1845: else {
1846: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1847: pcVar28 = pcVar26;
1848: }
1849: iVar18 = (int)psVar5[0x14];
1850: if (psVar5[0x14] == 0) goto LAB_0010c4b8;
1851: uVar16 = iVar18 >> 0x1f;
1852: uVar31 = uVar16 + iVar18;
1853: iVar18 = 0;
1854: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1855: pcVar26 = pcVar28;
1856: iVar32 = iVar17;
1857: LAB_0010a076:
1858: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1859: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
1860: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
1861: iVar17 = iVar32 - iVar29;
1862: if (iVar17 < 0) {
1863: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1864: uVar11 << ((byte)iVar32 & 0x3f);
1865: cVar10 = (char)uVar11;
1866: cVar33 = (char)(uVar11 >> 8);
1867: cVar20 = (char)(uVar11 >> 0x10);
1868: cVar21 = (char)(uVar11 >> 0x18);
1869: cVar22 = (char)(uVar11 >> 0x20);
1870: cVar23 = (char)(uVar11 >> 0x28);
1871: cVar24 = (char)(uVar11 >> 0x30);
1872: cVar25 = (char)(uVar11 >> 0x38);
1873: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1874: pcVar26[7] = cVar10;
1875: pcVar28 = pcVar26 + 8;
1876: *pcVar26 = cVar25;
1877: pcVar26[1] = cVar24;
1878: pcVar26[2] = cVar23;
1879: pcVar26[3] = cVar22;
1880: pcVar26[4] = cVar21;
1881: pcVar26[5] = cVar20;
1882: pcVar26[6] = cVar33;
1883: }
1884: else {
1885: pcVar26[1] = '\0';
1886: *pcVar26 = cVar25;
1887: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1888: *pcVar26 = cVar24;
1889: pcVar26[1] = '\0';
1890: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
1891: *pcVar26 = cVar23;
1892: pcVar26[1] = '\0';
1893: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
1894: *pcVar26 = cVar22;
1895: pcVar26[1] = '\0';
1896: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
1897: *pcVar26 = cVar21;
1898: pcVar26[1] = '\0';
1899: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
1900: *pcVar26 = cVar20;
1901: pcVar26[1] = '\0';
1902: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
1903: *pcVar26 = cVar33;
1904: pcVar26[1] = '\0';
1905: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
1906: *pcVar26 = cVar10;
1907: pcVar26[1] = '\0';
1908: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
1909: }
1910: iVar17 = iVar17 + 0x40;
1911: uVar11 = SEXT48((int)uVar31);
1912: }
1913: else {
1914: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1915: pcVar28 = pcVar26;
1916: }
1917: iVar29 = (int)psVar5[0xd];
1918: if (psVar5[0xd] == 0) goto LAB_0010c6a0;
1919: uVar16 = iVar29 >> 0x1f;
1920: uVar31 = uVar16 + iVar29;
1921: iVar29 = 0;
1922: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1923: iVar32 = iVar17;
1924: LAB_0010a0e0:
1925: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1926: puVar4[(int)(iVar29 + uVar16)] << ((byte)uVar16 & 0x1f);
1927: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar16) + 0x400) + uVar16;
1928: iVar17 = iVar32 - iVar29;
1929: if (iVar17 < 0) {
1930: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1931: uVar11 << ((byte)iVar32 & 0x3f);
1932: cVar10 = (char)uVar11;
1933: cVar25 = (char)(uVar11 >> 8);
1934: cVar24 = (char)(uVar11 >> 0x10);
1935: cVar23 = (char)(uVar11 >> 0x18);
1936: cVar22 = (char)(uVar11 >> 0x20);
1937: cVar21 = (char)(uVar11 >> 0x28);
1938: cVar20 = (char)(uVar11 >> 0x30);
1939: cVar33 = (char)(uVar11 >> 0x38);
1940: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
1941: pcVar28[7] = cVar10;
1942: pcVar26 = pcVar28 + 8;
1943: *pcVar28 = cVar33;
1944: pcVar28[1] = cVar20;
1945: pcVar28[2] = cVar21;
1946: pcVar28[3] = cVar22;
1947: pcVar28[4] = cVar23;
1948: pcVar28[5] = cVar24;
1949: pcVar28[6] = cVar25;
1950: }
1951: else {
1952: pcVar28[1] = '\0';
1953: *pcVar28 = cVar33;
1954: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
1955: *pcVar28 = cVar20;
1956: pcVar28[1] = '\0';
1957: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
1958: *pcVar28 = cVar21;
1959: pcVar28[1] = '\0';
1960: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
1961: *pcVar28 = cVar22;
1962: pcVar28[1] = '\0';
1963: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
1964: *pcVar28 = cVar23;
1965: pcVar28[1] = '\0';
1966: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
1967: *pcVar28 = cVar24;
1968: pcVar28[1] = '\0';
1969: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
1970: *pcVar28 = cVar25;
1971: pcVar28[1] = '\0';
1972: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
1973: *pcVar28 = cVar10;
1974: pcVar28[1] = '\0';
1975: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
1976: }
1977: iVar17 = iVar17 + 0x40;
1978: uVar11 = SEXT48((int)uVar31);
1979: }
1980: else {
1981: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
1982: pcVar26 = pcVar28;
1983: }
1984: iVar18 = (int)psVar5[6];
1985: if (psVar5[6] == 0) goto LAB_0010c520;
1986: uVar16 = iVar18 >> 0x1f;
1987: uVar31 = uVar16 + iVar18;
1988: iVar18 = 0;
1989: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
1990: pcVar28 = pcVar26;
1991: iVar32 = iVar17;
1992: LAB_0010a14a:
1993: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
1994: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
1995: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
1996: iVar17 = iVar32 - iVar29;
1997: if (iVar17 < 0) {
1998: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
1999: uVar11 << ((byte)iVar32 & 0x3f);
2000: cVar10 = (char)uVar11;
2001: cVar33 = (char)(uVar11 >> 8);
2002: cVar20 = (char)(uVar11 >> 0x10);
2003: cVar21 = (char)(uVar11 >> 0x18);
2004: cVar22 = (char)(uVar11 >> 0x20);
2005: cVar23 = (char)(uVar11 >> 0x28);
2006: cVar24 = (char)(uVar11 >> 0x30);
2007: cVar25 = (char)(uVar11 >> 0x38);
2008: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2009: pcVar28[7] = cVar10;
2010: pcVar26 = pcVar28 + 8;
2011: *pcVar28 = cVar25;
2012: pcVar28[1] = cVar24;
2013: pcVar28[2] = cVar23;
2014: pcVar28[3] = cVar22;
2015: pcVar28[4] = cVar21;
2016: pcVar28[5] = cVar20;
2017: pcVar28[6] = cVar33;
2018: }
2019: else {
2020: pcVar28[1] = '\0';
2021: *pcVar28 = cVar25;
2022: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2023: *pcVar28 = cVar24;
2024: pcVar28[1] = '\0';
2025: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2026: *pcVar28 = cVar23;
2027: pcVar28[1] = '\0';
2028: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2029: *pcVar28 = cVar22;
2030: pcVar28[1] = '\0';
2031: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2032: *pcVar28 = cVar21;
2033: pcVar28[1] = '\0';
2034: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2035: *pcVar28 = cVar20;
2036: pcVar28[1] = '\0';
2037: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2038: *pcVar28 = cVar33;
2039: pcVar28[1] = '\0';
2040: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
2041: *pcVar28 = cVar10;
2042: pcVar28[1] = '\0';
2043: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2044: }
2045: iVar17 = iVar17 + 0x40;
2046: uVar11 = SEXT48((int)uVar31);
2047: }
2048: else {
2049: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2050: pcVar26 = pcVar28;
2051: }
2052: iVar29 = (int)psVar5[7];
2053: if (psVar5[7] == 0) goto LAB_0010c5e0;
2054: uVar16 = iVar29 >> 0x1f;
2055: uVar31 = uVar16 + iVar29;
2056: iVar29 = 0;
2057: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2058: iVar32 = iVar17;
2059: LAB_0010a1b4:
2060: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2061: puVar4[(int)(iVar29 + uVar16)] << ((byte)uVar16 & 0x1f);
2062: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar16) + 0x400) + uVar16;
2063: iVar17 = iVar32 - iVar29;
2064: if (iVar17 < 0) {
2065: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
2066: uVar11 << ((byte)iVar32 & 0x3f);
2067: cVar10 = (char)uVar11;
2068: cVar20 = (char)(uVar11 >> 8);
2069: cVar21 = (char)(uVar11 >> 0x10);
2070: cVar22 = (char)(uVar11 >> 0x18);
2071: cVar23 = (char)(uVar11 >> 0x20);
2072: cVar25 = (char)(uVar11 >> 0x28);
2073: cVar24 = (char)(uVar11 >> 0x30);
2074: cVar33 = (char)(uVar11 >> 0x38);
2075: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2076: pcVar26[7] = cVar10;
2077: pcVar28 = pcVar26 + 8;
2078: *pcVar26 = cVar33;
2079: pcVar26[1] = cVar24;
2080: pcVar26[2] = cVar25;
2081: pcVar26[3] = cVar23;
2082: pcVar26[4] = cVar22;
2083: pcVar26[5] = cVar21;
2084: pcVar26[6] = cVar20;
2085: }
2086: else {
2087: pcVar26[1] = '\0';
2088: *pcVar26 = cVar33;
2089: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2090: *pcVar26 = cVar24;
2091: pcVar26[1] = '\0';
2092: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
2093: *pcVar26 = cVar25;
2094: pcVar26[1] = '\0';
2095: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
2096: *pcVar26 = cVar23;
2097: pcVar26[1] = '\0';
2098: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
2099: *pcVar26 = cVar22;
2100: pcVar26[1] = '\0';
2101: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
2102: *pcVar26 = cVar21;
2103: pcVar26[1] = '\0';
2104: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
2105: *pcVar26 = cVar20;
2106: pcVar26[1] = '\0';
2107: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
2108: *pcVar26 = cVar10;
2109: pcVar26[1] = '\0';
2110: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
2111: }
2112: iVar17 = iVar17 + 0x40;
2113: uVar11 = SEXT48((int)uVar31);
2114: }
2115: else {
2116: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2117: pcVar28 = pcVar26;
2118: }
2119: iVar18 = (int)psVar5[0xe];
2120: pcVar26 = pcVar28;
2121: if (psVar5[0xe] == 0) goto LAB_0010b6f0;
2122: uVar16 = iVar18 >> 0x1f;
2123: uVar31 = uVar16 + iVar18;
2124: iVar18 = 0;
2125: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2126: iVar32 = iVar17;
2127: LAB_0010a21e:
2128: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2129: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
2130: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
2131: iVar17 = iVar32 - iVar29;
2132: if (iVar17 < 0) {
2133: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
2134: uVar11 << ((byte)iVar32 & 0x3f);
2135: cVar10 = (char)uVar11;
2136: cVar33 = (char)(uVar11 >> 8);
2137: cVar20 = (char)(uVar11 >> 0x10);
2138: cVar21 = (char)(uVar11 >> 0x18);
2139: cVar22 = (char)(uVar11 >> 0x20);
2140: cVar23 = (char)(uVar11 >> 0x28);
2141: cVar24 = (char)(uVar11 >> 0x30);
2142: cVar25 = (char)(uVar11 >> 0x38);
2143: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2144: pcVar26[7] = cVar10;
2145: pcVar28 = pcVar26 + 8;
2146: *pcVar26 = cVar25;
2147: pcVar26[1] = cVar24;
2148: pcVar26[2] = cVar23;
2149: pcVar26[3] = cVar22;
2150: pcVar26[4] = cVar21;
2151: pcVar26[5] = cVar20;
2152: pcVar26[6] = cVar33;
2153: }
2154: else {
2155: pcVar26[1] = '\0';
2156: *pcVar26 = cVar25;
2157: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2158: *pcVar26 = cVar24;
2159: pcVar26[1] = '\0';
2160: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
2161: *pcVar26 = cVar23;
2162: pcVar26[1] = '\0';
2163: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
2164: *pcVar26 = cVar22;
2165: pcVar26[1] = '\0';
2166: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
2167: *pcVar26 = cVar21;
2168: pcVar26[1] = '\0';
2169: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
2170: *pcVar26 = cVar20;
2171: pcVar26[1] = '\0';
2172: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
2173: *pcVar26 = cVar33;
2174: pcVar26[1] = '\0';
2175: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
2176: *pcVar26 = cVar10;
2177: pcVar26[1] = '\0';
2178: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
2179: }
2180: iVar17 = iVar17 + 0x40;
2181: uVar11 = SEXT48((int)uVar31);
2182: }
2183: else {
2184: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2185: pcVar28 = pcVar26;
2186: }
2187: iVar29 = (int)psVar5[0x15];
2188: pcVar26 = pcVar28;
2189: if (psVar5[0x15] == 0) goto LAB_0010ca70;
2190: uVar16 = iVar29 >> 0x1f;
2191: uVar31 = uVar16 + iVar29;
2192: iVar29 = 0;
2193: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2194: iVar32 = iVar17;
2195: LAB_0010a288:
2196: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2197: puVar4[(int)(iVar29 + uVar16)] << ((byte)uVar16 & 0x1f);
2198: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar16) + 0x400) + uVar16;
2199: iVar17 = iVar32 - iVar29;
2200: if (iVar17 < 0) {
2201: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
2202: uVar11 << ((byte)iVar32 & 0x3f);
2203: cVar10 = (char)uVar11;
2204: cVar25 = (char)(uVar11 >> 8);
2205: cVar24 = (char)(uVar11 >> 0x10);
2206: cVar23 = (char)(uVar11 >> 0x18);
2207: cVar22 = (char)(uVar11 >> 0x20);
2208: cVar21 = (char)(uVar11 >> 0x28);
2209: cVar20 = (char)(uVar11 >> 0x30);
2210: cVar33 = (char)(uVar11 >> 0x38);
2211: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2212: pcVar26[7] = cVar10;
2213: pcVar28 = pcVar26 + 8;
2214: *pcVar26 = cVar33;
2215: pcVar26[1] = cVar20;
2216: pcVar26[2] = cVar21;
2217: pcVar26[3] = cVar22;
2218: pcVar26[4] = cVar23;
2219: pcVar26[5] = cVar24;
2220: pcVar26[6] = cVar25;
2221: }
2222: else {
2223: pcVar26[1] = '\0';
2224: *pcVar26 = cVar33;
2225: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2226: *pcVar26 = cVar20;
2227: pcVar26[1] = '\0';
2228: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
2229: *pcVar26 = cVar21;
2230: pcVar26[1] = '\0';
2231: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
2232: *pcVar26 = cVar22;
2233: pcVar26[1] = '\0';
2234: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
2235: *pcVar26 = cVar23;
2236: pcVar26[1] = '\0';
2237: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
2238: *pcVar26 = cVar24;
2239: pcVar26[1] = '\0';
2240: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
2241: *pcVar26 = cVar25;
2242: pcVar26[1] = '\0';
2243: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
2244: *pcVar26 = cVar10;
2245: pcVar26[1] = '\0';
2246: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
2247: }
2248: iVar17 = iVar17 + 0x40;
2249: uVar11 = SEXT48((int)uVar31);
2250: }
2251: else {
2252: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2253: pcVar28 = pcVar26;
2254: }
2255: iVar18 = (int)psVar5[0x1c];
2256: if (psVar5[0x1c] == 0) goto LAB_0010c378;
2257: uVar16 = iVar18 >> 0x1f;
2258: uVar31 = uVar16 + iVar18;
2259: iVar18 = 0;
2260: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2261: pcVar26 = pcVar28;
2262: iVar32 = iVar17;
2263: LAB_0010a2f2:
2264: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2265: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
2266: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
2267: iVar17 = iVar32 - iVar29;
2268: if (iVar17 < 0) {
2269: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
2270: uVar11 << ((byte)iVar32 & 0x3f);
2271: cVar10 = (char)uVar11;
2272: cVar33 = (char)(uVar11 >> 8);
2273: cVar20 = (char)(uVar11 >> 0x10);
2274: cVar21 = (char)(uVar11 >> 0x18);
2275: cVar22 = (char)(uVar11 >> 0x20);
2276: cVar23 = (char)(uVar11 >> 0x28);
2277: cVar24 = (char)(uVar11 >> 0x30);
2278: cVar25 = (char)(uVar11 >> 0x38);
2279: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2280: pcVar26[7] = cVar10;
2281: pcVar28 = pcVar26 + 8;
2282: *pcVar26 = cVar25;
2283: pcVar26[1] = cVar24;
2284: pcVar26[2] = cVar23;
2285: pcVar26[3] = cVar22;
2286: pcVar26[4] = cVar21;
2287: pcVar26[5] = cVar20;
2288: pcVar26[6] = cVar33;
2289: }
2290: else {
2291: pcVar26[1] = '\0';
2292: *pcVar26 = cVar25;
2293: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2294: *pcVar26 = cVar24;
2295: pcVar26[1] = '\0';
2296: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
2297: *pcVar26 = cVar23;
2298: pcVar26[1] = '\0';
2299: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
2300: *pcVar26 = cVar22;
2301: pcVar26[1] = '\0';
2302: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
2303: *pcVar26 = cVar21;
2304: pcVar26[1] = '\0';
2305: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
2306: *pcVar26 = cVar20;
2307: pcVar26[1] = '\0';
2308: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
2309: *pcVar26 = cVar33;
2310: pcVar26[1] = '\0';
2311: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
2312: *pcVar26 = cVar10;
2313: pcVar26[1] = '\0';
2314: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
2315: }
2316: iVar17 = iVar17 + 0x40;
2317: uVar11 = SEXT48((int)uVar31);
2318: }
2319: else {
2320: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2321: pcVar28 = pcVar26;
2322: }
2323: iVar29 = (int)psVar5[0x23];
2324: if (psVar5[0x23] == 0) goto LAB_0010bf30;
2325: uVar16 = iVar29 >> 0x1f;
2326: uVar31 = uVar16 + iVar29;
2327: iVar29 = 0;
2328: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2329: LAB_0010a35c:
2330: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2331: puVar4[(int)(iVar29 + uVar16)] << ((byte)uVar16 & 0x1f);
2332: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar16) + 0x400) + uVar16;
2333: iVar18 = iVar17 - iVar29;
2334: if (iVar18 < 0) {
2335: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
2336: uVar11 << ((byte)iVar17 & 0x3f);
2337: cVar10 = (char)uVar11;
2338: cVar33 = (char)(uVar11 >> 8);
2339: cVar20 = (char)(uVar11 >> 0x10);
2340: cVar21 = (char)(uVar11 >> 0x18);
2341: cVar22 = (char)(uVar11 >> 0x20);
2342: cVar23 = (char)(uVar11 >> 0x28);
2343: cVar24 = (char)(uVar11 >> 0x30);
2344: cVar25 = (char)(uVar11 >> 0x38);
2345: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2346: pcVar28[7] = cVar10;
2347: pcVar26 = pcVar28 + 8;
2348: *pcVar28 = cVar25;
2349: pcVar28[1] = cVar24;
2350: pcVar28[2] = cVar23;
2351: pcVar28[3] = cVar22;
2352: pcVar28[4] = cVar21;
2353: pcVar28[5] = cVar20;
2354: pcVar28[6] = cVar33;
2355: }
2356: else {
2357: pcVar28[1] = '\0';
2358: *pcVar28 = cVar25;
2359: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2360: *pcVar28 = cVar24;
2361: pcVar28[1] = '\0';
2362: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2363: *pcVar28 = cVar23;
2364: pcVar28[1] = '\0';
2365: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2366: *pcVar28 = cVar22;
2367: pcVar28[1] = '\0';
2368: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2369: *pcVar28 = cVar21;
2370: pcVar28[1] = '\0';
2371: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2372: *pcVar28 = cVar20;
2373: pcVar28[1] = '\0';
2374: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2375: *pcVar28 = cVar33;
2376: pcVar28[1] = '\0';
2377: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
2378: *pcVar28 = cVar10;
2379: pcVar28[1] = '\0';
2380: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2381: }
2382: sVar1 = psVar5[0x2a];
2383: uVar11 = SEXT48((int)uVar31);
2384: iVar17 = iVar18 + 0x40;
2385: pcVar28 = pcVar26;
2386: }
2387: else {
2388: sVar1 = psVar5[0x2a];
2389: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2390: iVar17 = iVar18;
2391: }
2392: iVar18 = (int)sVar1;
2393: if (sVar1 == 0) goto LAB_0010a3aa;
2394: uVar16 = iVar18 >> 0x1f;
2395: uVar31 = uVar16 + iVar18;
2396: iVar18 = 0;
2397: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2398: LAB_0010bfb2:
2399: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2400: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
2401: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
2402: iVar18 = iVar17 - iVar29;
2403: if (iVar18 < 0) {
2404: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
2405: uVar11 << ((byte)iVar17 & 0x3f);
2406: cVar10 = (char)uVar11;
2407: cVar25 = (char)(uVar11 >> 8);
2408: cVar24 = (char)(uVar11 >> 0x10);
2409: cVar23 = (char)(uVar11 >> 0x18);
2410: cVar22 = (char)(uVar11 >> 0x20);
2411: cVar21 = (char)(uVar11 >> 0x28);
2412: cVar20 = (char)(uVar11 >> 0x30);
2413: cVar33 = (char)(uVar11 >> 0x38);
2414: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2415: pcVar28[7] = cVar10;
2416: pcVar26 = pcVar28 + 8;
2417: *pcVar28 = cVar33;
2418: pcVar28[1] = cVar20;
2419: pcVar28[2] = cVar21;
2420: pcVar28[3] = cVar22;
2421: pcVar28[4] = cVar23;
2422: pcVar28[5] = cVar24;
2423: pcVar28[6] = cVar25;
2424: }
2425: else {
2426: pcVar28[1] = '\0';
2427: *pcVar28 = cVar33;
2428: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2429: *pcVar28 = cVar20;
2430: pcVar28[1] = '\0';
2431: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2432: *pcVar28 = cVar21;
2433: pcVar28[1] = '\0';
2434: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2435: *pcVar28 = cVar22;
2436: pcVar28[1] = '\0';
2437: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2438: *pcVar28 = cVar23;
2439: pcVar28[1] = '\0';
2440: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2441: *pcVar28 = cVar24;
2442: pcVar28[1] = '\0';
2443: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2444: *pcVar28 = cVar25;
2445: pcVar28[1] = '\0';
2446: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2447: *pcVar28 = cVar10;
2448: pcVar28[1] = '\0';
2449: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2450: }
2451: sVar1 = psVar5[0x31];
2452: uVar11 = SEXT48((int)uVar31);
2453: iVar17 = iVar18 + 0x40;
2454: pcVar28 = pcVar26;
2455: }
2456: else {
2457: sVar1 = psVar5[0x31];
2458: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2459: iVar17 = iVar18;
2460: }
2461: iVar29 = (int)sVar1;
2462: if (iVar29 == 0) goto LAB_0010c000;
2463: uVar31 = iVar29 >> 0x1f;
2464: uVar16 = uVar31 + iVar29;
2465: iVar29 = 0;
2466: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
2467: LAB_0010a430:
2468: uVar16 = uVar16 & (int)(1 << ((byte)uVar31 & 0x3f)) - 1U |
2469: puVar4[(int)(iVar29 + uVar31)] << ((byte)uVar31 & 0x1f);
2470: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar31) + 0x400) + uVar31;
2471: iVar18 = iVar17 - iVar29;
2472: if (iVar18 < 0) {
2473: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
2474: uVar11 << ((byte)iVar17 & 0x3f);
2475: cVar10 = (char)uVar11;
2476: cVar33 = (char)(uVar11 >> 8);
2477: cVar24 = (char)(uVar11 >> 0x10);
2478: cVar25 = (char)(uVar11 >> 0x18);
2479: cVar23 = (char)(uVar11 >> 0x20);
2480: cVar20 = (char)(uVar11 >> 0x28);
2481: cVar21 = (char)(uVar11 >> 0x30);
2482: cVar22 = (char)(uVar11 >> 0x38);
2483: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2484: pcVar28[7] = cVar10;
2485: pcVar26 = pcVar28 + 8;
2486: *pcVar28 = cVar22;
2487: pcVar28[1] = cVar21;
2488: pcVar28[2] = cVar20;
2489: pcVar28[3] = cVar23;
2490: pcVar28[4] = cVar25;
2491: pcVar28[5] = cVar24;
2492: pcVar28[6] = cVar33;
2493: }
2494: else {
2495: pcVar28[1] = '\0';
2496: *pcVar28 = cVar22;
2497: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2498: *pcVar28 = cVar21;
2499: pcVar28[1] = '\0';
2500: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2501: *pcVar28 = cVar20;
2502: pcVar28[1] = '\0';
2503: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2504: *pcVar28 = cVar23;
2505: pcVar28[1] = '\0';
2506: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2507: *pcVar28 = cVar25;
2508: pcVar28[1] = '\0';
2509: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2510: *pcVar28 = cVar24;
2511: pcVar28[1] = '\0';
2512: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2513: *pcVar28 = cVar33;
2514: pcVar28[1] = '\0';
2515: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
2516: *pcVar28 = cVar10;
2517: pcVar28[1] = '\0';
2518: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2519: }
2520: uVar11 = SEXT48((int)uVar16);
2521: sVar1 = psVar5[0x38];
2522: iVar17 = iVar18 + 0x40;
2523: pcVar28 = pcVar26;
2524: }
2525: else {
2526: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
2527: sVar1 = psVar5[0x38];
2528: iVar17 = iVar18;
2529: }
2530: iVar18 = (int)sVar1;
2531: if (sVar1 == 0) goto LAB_0010a47e;
2532: uVar16 = iVar18 >> 0x1f;
2533: uVar31 = uVar16 + iVar18;
2534: iVar18 = 0;
2535: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2536: LAB_0010c086:
2537: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2538: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
2539: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
2540: iVar18 = iVar17 - iVar29;
2541: if (iVar18 < 0) {
2542: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
2543: uVar11 << ((byte)iVar17 & 0x3f);
2544: cVar10 = (char)uVar11;
2545: cVar33 = (char)(uVar11 >> 8);
2546: cVar25 = (char)(uVar11 >> 0x10);
2547: cVar24 = (char)(uVar11 >> 0x18);
2548: cVar23 = (char)(uVar11 >> 0x20);
2549: cVar22 = (char)(uVar11 >> 0x28);
2550: cVar21 = (char)(uVar11 >> 0x30);
2551: cVar20 = (char)(uVar11 >> 0x38);
2552: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2553: pcVar28[7] = cVar10;
2554: pcVar26 = pcVar28 + 8;
2555: *pcVar28 = cVar20;
2556: pcVar28[1] = cVar21;
2557: pcVar28[2] = cVar22;
2558: pcVar28[3] = cVar23;
2559: pcVar28[4] = cVar24;
2560: pcVar28[5] = cVar25;
2561: pcVar28[6] = cVar33;
2562: }
2563: else {
2564: pcVar28[1] = '\0';
2565: *pcVar28 = cVar20;
2566: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2567: *pcVar28 = cVar21;
2568: pcVar28[1] = '\0';
2569: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2570: *pcVar28 = cVar22;
2571: pcVar28[1] = '\0';
2572: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2573: *pcVar28 = cVar23;
2574: pcVar28[1] = '\0';
2575: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2576: *pcVar28 = cVar24;
2577: pcVar28[1] = '\0';
2578: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2579: *pcVar28 = cVar25;
2580: pcVar28[1] = '\0';
2581: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2582: *pcVar28 = cVar33;
2583: pcVar28[1] = '\0';
2584: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
2585: *pcVar28 = cVar10;
2586: pcVar28[1] = '\0';
2587: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2588: }
2589: uVar11 = SEXT48((int)uVar31);
2590: sVar1 = psVar5[0x39];
2591: iVar17 = iVar18 + 0x40;
2592: pcVar28 = pcVar26;
2593: }
2594: else {
2595: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2596: sVar1 = psVar5[0x39];
2597: iVar17 = iVar18;
2598: }
2599: iVar29 = (int)sVar1;
2600: if (iVar29 == 0) goto LAB_0010c0d4;
2601: uVar31 = iVar29 >> 0x1f;
2602: uVar16 = uVar31 + iVar29;
2603: iVar29 = 0;
2604: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
2605: LAB_0010a504:
2606: uVar16 = uVar16 & (int)(1 << ((byte)uVar31 & 0x3f)) - 1U |
2607: puVar4[(int)(iVar29 + uVar31)] << ((byte)uVar31 & 0x1f);
2608: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar31) + 0x400) + uVar31;
2609: iVar18 = iVar17 - iVar29;
2610: if (iVar18 < 0) {
2611: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
2612: uVar11 << ((byte)iVar17 & 0x3f);
2613: cVar10 = (char)uVar11;
2614: cVar25 = (char)(uVar11 >> 8);
2615: cVar24 = (char)(uVar11 >> 0x10);
2616: cVar23 = (char)(uVar11 >> 0x18);
2617: cVar22 = (char)(uVar11 >> 0x20);
2618: cVar21 = (char)(uVar11 >> 0x28);
2619: cVar20 = (char)(uVar11 >> 0x30);
2620: cVar33 = (char)(uVar11 >> 0x38);
2621: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2622: pcVar28[7] = cVar10;
2623: pcVar26 = pcVar28 + 8;
2624: *pcVar28 = cVar33;
2625: pcVar28[1] = cVar20;
2626: pcVar28[2] = cVar21;
2627: pcVar28[3] = cVar22;
2628: pcVar28[4] = cVar23;
2629: pcVar28[5] = cVar24;
2630: pcVar28[6] = cVar25;
2631: }
2632: else {
2633: pcVar28[1] = '\0';
2634: *pcVar28 = cVar33;
2635: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2636: *pcVar28 = cVar20;
2637: pcVar28[1] = '\0';
2638: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2639: *pcVar28 = cVar21;
2640: pcVar28[1] = '\0';
2641: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2642: *pcVar28 = cVar22;
2643: pcVar28[1] = '\0';
2644: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2645: *pcVar28 = cVar23;
2646: pcVar28[1] = '\0';
2647: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2648: *pcVar28 = cVar24;
2649: pcVar28[1] = '\0';
2650: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2651: *pcVar28 = cVar25;
2652: pcVar28[1] = '\0';
2653: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2654: *pcVar28 = cVar10;
2655: pcVar28[1] = '\0';
2656: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2657: }
2658: sVar1 = psVar5[0x32];
2659: uVar11 = SEXT48((int)uVar16);
2660: iVar17 = iVar18 + 0x40;
2661: pcVar28 = pcVar26;
2662: }
2663: else {
2664: sVar1 = psVar5[0x32];
2665: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
2666: iVar17 = iVar18;
2667: }
2668: iVar18 = (int)sVar1;
2669: if (sVar1 == 0) goto LAB_0010a552;
2670: uVar16 = iVar18 >> 0x1f;
2671: uVar31 = uVar16 + iVar18;
2672: iVar18 = 0;
2673: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2674: LAB_0010c15a:
2675: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2676: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
2677: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
2678: iVar18 = iVar17 - iVar29;
2679: if (iVar18 < 0) {
2680: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
2681: uVar11 << ((byte)iVar17 & 0x3f);
2682: cVar10 = (char)uVar11;
2683: cVar25 = (char)(uVar11 >> 8);
2684: cVar24 = (char)(uVar11 >> 0x10);
2685: cVar23 = (char)(uVar11 >> 0x18);
2686: cVar22 = (char)(uVar11 >> 0x20);
2687: cVar21 = (char)(uVar11 >> 0x28);
2688: cVar20 = (char)(uVar11 >> 0x30);
2689: cVar33 = (char)(uVar11 >> 0x38);
2690: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2691: pcVar28[7] = cVar10;
2692: pcVar26 = pcVar28 + 8;
2693: *pcVar28 = cVar33;
2694: pcVar28[1] = cVar20;
2695: pcVar28[2] = cVar21;
2696: pcVar28[3] = cVar22;
2697: pcVar28[4] = cVar23;
2698: pcVar28[5] = cVar24;
2699: pcVar28[6] = cVar25;
2700: }
2701: else {
2702: pcVar28[1] = '\0';
2703: *pcVar28 = cVar33;
2704: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2705: *pcVar28 = cVar20;
2706: pcVar28[1] = '\0';
2707: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2708: *pcVar28 = cVar21;
2709: pcVar28[1] = '\0';
2710: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2711: *pcVar28 = cVar22;
2712: pcVar28[1] = '\0';
2713: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2714: *pcVar28 = cVar23;
2715: pcVar28[1] = '\0';
2716: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2717: *pcVar28 = cVar24;
2718: pcVar28[1] = '\0';
2719: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2720: *pcVar28 = cVar25;
2721: pcVar28[1] = '\0';
2722: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2723: *pcVar28 = cVar10;
2724: pcVar28[1] = '\0';
2725: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2726: }
2727: sVar1 = psVar5[0x2b];
2728: uVar11 = SEXT48((int)uVar31);
2729: iVar17 = iVar18 + 0x40;
2730: pcVar28 = pcVar26;
2731: }
2732: else {
2733: sVar1 = psVar5[0x2b];
2734: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2735: iVar17 = iVar18;
2736: }
2737: iVar29 = (int)sVar1;
2738: if (iVar29 == 0) goto LAB_0010c1a8;
2739: uVar31 = iVar29 >> 0x1f;
2740: uVar16 = uVar31 + iVar29;
2741: iVar29 = 0;
2742: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
2743: LAB_0010a5d8:
2744: uVar16 = uVar16 & (int)(1 << ((byte)uVar31 & 0x3f)) - 1U |
2745: puVar4[(int)(iVar29 + uVar31)] << ((byte)uVar31 & 0x1f);
2746: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar31) + 0x400) + uVar31;
2747: iVar18 = iVar17 - iVar29;
2748: if (iVar18 < 0) {
2749: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
2750: uVar11 << ((byte)iVar17 & 0x3f);
2751: cVar10 = (char)uVar11;
2752: cVar25 = (char)(uVar11 >> 8);
2753: cVar24 = (char)(uVar11 >> 0x10);
2754: cVar23 = (char)(uVar11 >> 0x18);
2755: cVar22 = (char)(uVar11 >> 0x20);
2756: cVar21 = (char)(uVar11 >> 0x28);
2757: cVar20 = (char)(uVar11 >> 0x30);
2758: cVar33 = (char)(uVar11 >> 0x38);
2759: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2760: pcVar28[7] = cVar10;
2761: pcVar26 = pcVar28 + 8;
2762: *pcVar28 = cVar33;
2763: pcVar28[1] = cVar20;
2764: pcVar28[2] = cVar21;
2765: pcVar28[3] = cVar22;
2766: pcVar28[4] = cVar23;
2767: pcVar28[5] = cVar24;
2768: pcVar28[6] = cVar25;
2769: }
2770: else {
2771: pcVar28[1] = '\0';
2772: *pcVar28 = cVar33;
2773: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2774: *pcVar28 = cVar20;
2775: pcVar28[1] = '\0';
2776: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2777: *pcVar28 = cVar21;
2778: pcVar28[1] = '\0';
2779: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2780: *pcVar28 = cVar22;
2781: pcVar28[1] = '\0';
2782: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2783: *pcVar28 = cVar23;
2784: pcVar28[1] = '\0';
2785: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2786: *pcVar28 = cVar24;
2787: pcVar28[1] = '\0';
2788: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2789: *pcVar28 = cVar25;
2790: pcVar28[1] = '\0';
2791: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2792: *pcVar28 = cVar10;
2793: pcVar28[1] = '\0';
2794: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2795: }
2796: sVar1 = psVar5[0x24];
2797: uVar11 = SEXT48((int)uVar16);
2798: iVar17 = iVar18 + 0x40;
2799: pcVar28 = pcVar26;
2800: }
2801: else {
2802: sVar1 = psVar5[0x24];
2803: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
2804: iVar17 = iVar18;
2805: }
2806: iVar18 = (int)sVar1;
2807: if (sVar1 == 0) goto LAB_0010a626;
2808: uVar16 = iVar18 >> 0x1f;
2809: uVar31 = uVar16 + iVar18;
2810: iVar18 = 0;
2811: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2812: LAB_0010c22e:
2813: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2814: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
2815: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
2816: iVar18 = iVar17 - iVar29;
2817: if (iVar18 < 0) {
2818: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
2819: uVar11 << ((byte)iVar17 & 0x3f);
2820: cVar10 = (char)uVar11;
2821: cVar25 = (char)(uVar11 >> 8);
2822: cVar24 = (char)(uVar11 >> 0x10);
2823: cVar20 = (char)(uVar11 >> 0x18);
2824: cVar33 = (char)(uVar11 >> 0x20);
2825: cVar21 = (char)(uVar11 >> 0x28);
2826: cVar22 = (char)(uVar11 >> 0x30);
2827: cVar23 = (char)(uVar11 >> 0x38);
2828: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2829: pcVar28[7] = cVar10;
2830: pcVar26 = pcVar28 + 8;
2831: *pcVar28 = cVar23;
2832: pcVar28[1] = cVar22;
2833: pcVar28[2] = cVar21;
2834: pcVar28[3] = cVar33;
2835: pcVar28[4] = cVar20;
2836: pcVar28[5] = cVar24;
2837: pcVar28[6] = cVar25;
2838: }
2839: else {
2840: pcVar28[1] = '\0';
2841: *pcVar28 = cVar23;
2842: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2843: *pcVar28 = cVar22;
2844: pcVar28[1] = '\0';
2845: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2846: *pcVar28 = cVar21;
2847: pcVar28[1] = '\0';
2848: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2849: *pcVar28 = cVar33;
2850: pcVar28[1] = '\0';
2851: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
2852: *pcVar28 = cVar20;
2853: pcVar28[1] = '\0';
2854: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2855: *pcVar28 = cVar24;
2856: pcVar28[1] = '\0';
2857: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2858: *pcVar28 = cVar25;
2859: pcVar28[1] = '\0';
2860: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2861: *pcVar28 = cVar10;
2862: pcVar28[1] = '\0';
2863: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2864: }
2865: sVar1 = psVar5[0x1d];
2866: uVar11 = SEXT48((int)uVar31);
2867: iVar17 = iVar18 + 0x40;
2868: pcVar28 = pcVar26;
2869: }
2870: else {
2871: sVar1 = psVar5[0x1d];
2872: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
2873: iVar17 = iVar18;
2874: }
2875: iVar29 = (int)sVar1;
2876: if (iVar29 == 0) goto LAB_0010c27c;
2877: uVar31 = iVar29 >> 0x1f;
2878: uVar16 = uVar31 + iVar29;
2879: iVar29 = 0;
2880: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
2881: LAB_0010a6ac:
2882: uVar16 = uVar16 & (int)(1 << ((byte)uVar31 & 0x3f)) - 1U |
2883: puVar4[(int)(iVar29 + uVar31)] << ((byte)uVar31 & 0x1f);
2884: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar31) + 0x400) + uVar31;
2885: iVar18 = iVar17 - iVar29;
2886: if (iVar18 < 0) {
2887: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
2888: uVar11 << ((byte)iVar17 & 0x3f);
2889: cVar10 = (char)uVar11;
2890: cVar25 = (char)(uVar11 >> 8);
2891: cVar24 = (char)(uVar11 >> 0x10);
2892: cVar23 = (char)(uVar11 >> 0x18);
2893: cVar22 = (char)(uVar11 >> 0x20);
2894: cVar21 = (char)(uVar11 >> 0x28);
2895: cVar20 = (char)(uVar11 >> 0x30);
2896: cVar33 = (char)(uVar11 >> 0x38);
2897: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2898: pcVar28[7] = cVar10;
2899: pcVar26 = pcVar28 + 8;
2900: *pcVar28 = cVar33;
2901: pcVar28[1] = cVar20;
2902: pcVar28[2] = cVar21;
2903: pcVar28[3] = cVar22;
2904: pcVar28[4] = cVar23;
2905: pcVar28[5] = cVar24;
2906: pcVar28[6] = cVar25;
2907: }
2908: else {
2909: pcVar28[1] = '\0';
2910: *pcVar28 = cVar33;
2911: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2912: *pcVar28 = cVar20;
2913: pcVar28[1] = '\0';
2914: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
2915: *pcVar28 = cVar21;
2916: pcVar28[1] = '\0';
2917: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2918: *pcVar28 = cVar22;
2919: pcVar28[1] = '\0';
2920: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2921: *pcVar28 = cVar23;
2922: pcVar28[1] = '\0';
2923: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2924: *pcVar28 = cVar24;
2925: pcVar28[1] = '\0';
2926: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2927: *pcVar28 = cVar25;
2928: pcVar28[1] = '\0';
2929: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2930: *pcVar28 = cVar10;
2931: pcVar28[1] = '\0';
2932: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
2933: }
2934: sVar1 = psVar5[0x16];
2935: uVar11 = SEXT48((int)uVar16);
2936: iVar17 = iVar18 + 0x40;
2937: pcVar28 = pcVar26;
2938: }
2939: else {
2940: sVar1 = psVar5[0x16];
2941: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
2942: iVar17 = iVar18;
2943: }
2944: iVar18 = (int)sVar1;
2945: if (sVar1 == 0) goto LAB_0010a6fa;
2946: uVar16 = iVar18 >> 0x1f;
2947: uVar31 = uVar16 + iVar18;
2948: iVar18 = 0;
2949: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
2950: iVar32 = iVar17;
2951: LAB_0010c302:
2952: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
2953: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
2954: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
2955: iVar17 = iVar32 - iVar29;
2956: if (iVar17 < 0) {
2957: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
2958: uVar11 << ((byte)iVar32 & 0x3f);
2959: cVar10 = (char)uVar11;
2960: cVar20 = (char)(uVar11 >> 8);
2961: cVar25 = (char)(uVar11 >> 0x10);
2962: cVar24 = (char)(uVar11 >> 0x18);
2963: cVar23 = (char)(uVar11 >> 0x20);
2964: cVar22 = (char)(uVar11 >> 0x28);
2965: cVar21 = (char)(uVar11 >> 0x30);
2966: cVar33 = (char)(uVar11 >> 0x38);
2967: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
2968: pcVar28[7] = cVar10;
2969: pcVar26 = pcVar28 + 8;
2970: *pcVar28 = cVar33;
2971: pcVar28[1] = cVar21;
2972: pcVar28[2] = cVar22;
2973: pcVar28[3] = cVar23;
2974: pcVar28[4] = cVar24;
2975: pcVar28[5] = cVar25;
2976: pcVar28[6] = cVar20;
2977: }
2978: else {
2979: pcVar28[1] = '\0';
2980: *pcVar28 = cVar33;
2981: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
2982: *pcVar28 = cVar21;
2983: pcVar28[1] = '\0';
2984: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
2985: *pcVar28 = cVar22;
2986: pcVar28[1] = '\0';
2987: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
2988: *pcVar28 = cVar23;
2989: pcVar28[1] = '\0';
2990: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
2991: *pcVar28 = cVar24;
2992: pcVar28[1] = '\0';
2993: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
2994: *pcVar28 = cVar25;
2995: pcVar28[1] = '\0';
2996: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
2997: *pcVar28 = cVar20;
2998: pcVar28[1] = '\0';
2999: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
3000: *pcVar28 = cVar10;
3001: pcVar28[1] = '\0';
3002: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
3003: }
3004: iVar17 = iVar17 + 0x40;
3005: uVar11 = SEXT48((int)uVar31);
3006: pcVar28 = pcVar26;
3007: }
3008: else {
3009: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
3010: }
3011: iVar29 = (int)psVar5[0xf];
3012: if (iVar29 != 0) {
3013: uVar31 = iVar29 >> 0x1f;
3014: uVar16 = uVar31 + iVar29;
3015: iVar29 = 0;
3016: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
3017: goto LAB_0010a780;
3018: }
3019: LAB_0010bc90:
3020: sVar1 = psVar5[0x17];
3021: iVar18 = iVar29 + 0x10;
3022: if (sVar1 != 0) {
3023: uVar16 = (int)sVar1 >> 0x1f;
3024: uVar31 = (int)sVar1 + uVar16;
3025: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
3026: if (0xff < iVar18) {
3027: iVar18 = iVar29 + -0xf0;
3028: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
3029: if (iVar32 < 0) {
3030: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
3031: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
3032: cVar10 = (char)uVar14;
3033: cVar25 = (char)(uVar14 >> 8);
3034: cVar24 = (char)(uVar14 >> 0x10);
3035: cVar23 = (char)(uVar14 >> 0x18);
3036: cVar22 = (char)(uVar11 >> 0x20);
3037: cVar21 = (char)(uVar11 >> 0x28);
3038: cVar20 = (char)(uVar11 >> 0x30);
3039: cVar33 = (char)(uVar11 >> 0x38);
3040: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3041: pcVar28[7] = cVar10;
3042: pcVar26 = pcVar28 + 8;
3043: *pcVar28 = cVar33;
3044: pcVar28[1] = cVar20;
3045: pcVar28[2] = cVar21;
3046: pcVar28[3] = cVar22;
3047: pcVar28[4] = cVar23;
3048: pcVar28[5] = cVar24;
3049: pcVar28[6] = cVar25;
3050: }
3051: else {
3052: pcVar28[1] = '\0';
3053: *pcVar28 = cVar33;
3054: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3055: *pcVar28 = cVar20;
3056: pcVar28[1] = '\0';
3057: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
3058: *pcVar28 = cVar21;
3059: pcVar28[1] = '\0';
3060: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
3061: *pcVar28 = cVar22;
3062: pcVar28[1] = '\0';
3063: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
3064: *pcVar28 = cVar23;
3065: pcVar28[1] = '\0';
3066: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
3067: *pcVar28 = cVar24;
3068: pcVar28[1] = '\0';
3069: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
3070: *pcVar28 = cVar25;
3071: pcVar28[1] = '\0';
3072: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
3073: *pcVar28 = cVar10;
3074: pcVar28[1] = '\0';
3075: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
3076: }
3077: uVar11 = (ulong)puVar4[0xf0];
3078: iVar32 = iVar32 + 0x40;
3079: uVar14 = uVar11;
3080: }
3081: else {
3082: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
3083: pcVar26 = pcVar28;
3084: uVar14 = (ulong)puVar4[0xf0];
3085: }
3086: pcVar28 = pcVar26;
3087: iVar17 = iVar32;
3088: if (0xff < iVar18) {
3089: iVar18 = iVar29 + -0x1f0;
3090: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
3091: if (iVar17 < 0) {
3092: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
3093: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
3094: cVar10 = (char)uVar14;
3095: cVar33 = (char)(uVar14 >> 8);
3096: cVar20 = (char)(uVar14 >> 0x10);
3097: cVar21 = (char)(uVar14 >> 0x18);
3098: cVar25 = (char)(uVar11 >> 0x20);
3099: cVar24 = (char)(uVar11 >> 0x28);
3100: cVar22 = (char)(uVar11 >> 0x30);
3101: cVar23 = (char)(uVar11 >> 0x38);
3102: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3103: pcVar26[7] = cVar10;
3104: pcVar28 = pcVar26 + 8;
3105: *pcVar26 = cVar23;
3106: pcVar26[1] = cVar22;
3107: pcVar26[2] = cVar24;
3108: pcVar26[3] = cVar25;
3109: pcVar26[4] = cVar21;
3110: pcVar26[5] = cVar20;
3111: pcVar26[6] = cVar33;
3112: }
3113: else {
3114: pcVar26[1] = '\0';
3115: *pcVar26 = cVar23;
3116: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3117: *pcVar26 = cVar22;
3118: pcVar26[1] = '\0';
3119: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3120: *pcVar26 = cVar24;
3121: pcVar26[1] = '\0';
3122: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3123: *pcVar26 = cVar25;
3124: pcVar26[1] = '\0';
3125: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
3126: *pcVar26 = cVar21;
3127: pcVar26[1] = '\0';
3128: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3129: *pcVar26 = cVar20;
3130: pcVar26[1] = '\0';
3131: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
3132: *pcVar26 = cVar33;
3133: pcVar26[1] = '\0';
3134: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3135: *pcVar26 = cVar10;
3136: pcVar26[1] = '\0';
3137: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3138: }
3139: iVar17 = iVar17 + 0x40;
3140: uVar11 = (ulong)puVar4[0xf0];
3141: }
3142: else {
3143: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
3144: }
3145: }
3146: }
3147: goto LAB_0010bd16;
3148: }
3149: LAB_0010a7ce:
3150: sVar1 = psVar5[0x1e];
3151: iVar29 = iVar18 + 0x10;
3152: if (sVar1 != 0) {
3153: uVar31 = (int)sVar1 >> 0x1f;
3154: uVar16 = (int)sVar1 + uVar31;
3155: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
3156: if (0xff < iVar29) {
3157: iVar29 = iVar18 + -0xf0;
3158: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
3159: if (iVar32 < 0) {
3160: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
3161: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
3162: cVar10 = (char)uVar14;
3163: cVar25 = (char)(uVar14 >> 8);
3164: cVar24 = (char)(uVar14 >> 0x10);
3165: cVar23 = (char)(uVar14 >> 0x18);
3166: cVar22 = (char)(uVar11 >> 0x20);
3167: cVar21 = (char)(uVar11 >> 0x28);
3168: cVar20 = (char)(uVar11 >> 0x30);
3169: cVar33 = (char)(uVar11 >> 0x38);
3170: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3171: pcVar28[7] = cVar10;
3172: pcVar26 = pcVar28 + 8;
3173: *pcVar28 = cVar33;
3174: pcVar28[1] = cVar20;
3175: pcVar28[2] = cVar21;
3176: pcVar28[3] = cVar22;
3177: pcVar28[4] = cVar23;
3178: pcVar28[5] = cVar24;
3179: pcVar28[6] = cVar25;
3180: }
3181: else {
3182: pcVar28[1] = '\0';
3183: *pcVar28 = cVar33;
3184: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3185: *pcVar28 = cVar20;
3186: pcVar28[1] = '\0';
3187: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
3188: *pcVar28 = cVar21;
3189: pcVar28[1] = '\0';
3190: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
3191: *pcVar28 = cVar22;
3192: pcVar28[1] = '\0';
3193: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
3194: *pcVar28 = cVar23;
3195: pcVar28[1] = '\0';
3196: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
3197: *pcVar28 = cVar24;
3198: pcVar28[1] = '\0';
3199: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
3200: *pcVar28 = cVar25;
3201: pcVar28[1] = '\0';
3202: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
3203: *pcVar28 = cVar10;
3204: pcVar28[1] = '\0';
3205: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
3206: }
3207: uVar11 = (ulong)puVar4[0xf0];
3208: iVar32 = iVar32 + 0x40;
3209: uVar14 = uVar11;
3210: }
3211: else {
3212: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
3213: pcVar26 = pcVar28;
3214: uVar14 = (ulong)puVar4[0xf0];
3215: }
3216: pcVar28 = pcVar26;
3217: iVar17 = iVar32;
3218: if (0xff < iVar29) {
3219: iVar29 = iVar18 + -0x1f0;
3220: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
3221: if (iVar17 < 0) {
3222: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
3223: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
3224: cVar10 = (char)uVar14;
3225: cVar33 = (char)(uVar14 >> 8);
3226: cVar24 = (char)(uVar14 >> 0x10);
3227: cVar25 = (char)(uVar14 >> 0x18);
3228: cVar23 = (char)(uVar11 >> 0x20);
3229: cVar22 = (char)(uVar11 >> 0x28);
3230: cVar21 = (char)(uVar11 >> 0x30);
3231: cVar20 = (char)(uVar11 >> 0x38);
3232: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3233: pcVar26[7] = cVar10;
3234: pcVar28 = pcVar26 + 8;
3235: *pcVar26 = cVar20;
3236: pcVar26[1] = cVar21;
3237: pcVar26[2] = cVar22;
3238: pcVar26[3] = cVar23;
3239: pcVar26[4] = cVar25;
3240: pcVar26[5] = cVar24;
3241: pcVar26[6] = cVar33;
3242: }
3243: else {
3244: pcVar26[1] = '\0';
3245: *pcVar26 = cVar20;
3246: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3247: *pcVar26 = cVar21;
3248: pcVar26[1] = '\0';
3249: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3250: *pcVar26 = cVar22;
3251: pcVar26[1] = '\0';
3252: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3253: *pcVar26 = cVar23;
3254: pcVar26[1] = '\0';
3255: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
3256: *pcVar26 = cVar25;
3257: pcVar26[1] = '\0';
3258: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
3259: *pcVar26 = cVar24;
3260: pcVar26[1] = '\0';
3261: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3262: *pcVar26 = cVar33;
3263: pcVar26[1] = '\0';
3264: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3265: *pcVar26 = cVar10;
3266: pcVar26[1] = '\0';
3267: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3268: }
3269: iVar17 = iVar17 + 0x40;
3270: uVar11 = (ulong)puVar4[0xf0];
3271: }
3272: else {
3273: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
3274: }
3275: }
3276: }
3277: goto LAB_0010a854;
3278: }
3279: LAB_0010bd64:
3280: sVar1 = psVar5[0x25];
3281: iVar18 = iVar29 + 0x10;
3282: if (sVar1 != 0) {
3283: uVar16 = (int)sVar1 >> 0x1f;
3284: uVar31 = (int)sVar1 + uVar16;
3285: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
3286: if (0xff < iVar18) {
3287: iVar18 = iVar29 + -0xf0;
3288: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
3289: if (iVar32 < 0) {
3290: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
3291: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
3292: cVar10 = (char)uVar14;
3293: cVar33 = (char)(uVar14 >> 8);
3294: cVar20 = (char)(uVar14 >> 0x10);
3295: cVar22 = (char)(uVar14 >> 0x18);
3296: cVar25 = (char)(uVar11 >> 0x20);
3297: cVar24 = (char)(uVar11 >> 0x28);
3298: cVar23 = (char)(uVar11 >> 0x30);
3299: cVar21 = (char)(uVar11 >> 0x38);
3300: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3301: pcVar28[7] = cVar10;
3302: pcVar26 = pcVar28 + 8;
3303: *pcVar28 = cVar21;
3304: pcVar28[1] = cVar23;
3305: pcVar28[2] = cVar24;
3306: pcVar28[3] = cVar25;
3307: pcVar28[4] = cVar22;
3308: pcVar28[5] = cVar20;
3309: pcVar28[6] = cVar33;
3310: }
3311: else {
3312: pcVar28[1] = '\0';
3313: *pcVar28 = cVar21;
3314: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3315: *pcVar28 = cVar23;
3316: pcVar28[1] = '\0';
3317: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
3318: *pcVar28 = cVar24;
3319: pcVar28[1] = '\0';
3320: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
3321: *pcVar28 = cVar25;
3322: pcVar28[1] = '\0';
3323: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
3324: *pcVar28 = cVar22;
3325: pcVar28[1] = '\0';
3326: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
3327: *pcVar28 = cVar20;
3328: pcVar28[1] = '\0';
3329: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
3330: *pcVar28 = cVar33;
3331: pcVar28[1] = '\0';
3332: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
3333: *pcVar28 = cVar10;
3334: pcVar28[1] = '\0';
3335: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
3336: }
3337: uVar11 = (ulong)puVar4[0xf0];
3338: iVar32 = iVar32 + 0x40;
3339: uVar14 = uVar11;
3340: }
3341: else {
3342: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
3343: pcVar26 = pcVar28;
3344: uVar14 = (ulong)puVar4[0xf0];
3345: }
3346: pcVar28 = pcVar26;
3347: iVar17 = iVar32;
3348: if (0xff < iVar18) {
3349: iVar18 = iVar29 + -0x1f0;
3350: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
3351: if (iVar17 < 0) {
3352: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
3353: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
3354: cVar10 = (char)uVar14;
3355: cVar33 = (char)(uVar14 >> 8);
3356: cVar20 = (char)(uVar14 >> 0x10);
3357: cVar21 = (char)(uVar14 >> 0x18);
3358: cVar22 = (char)(uVar11 >> 0x20);
3359: cVar25 = (char)(uVar11 >> 0x28);
3360: cVar24 = (char)(uVar11 >> 0x30);
3361: cVar23 = (char)(uVar11 >> 0x38);
3362: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3363: pcVar26[7] = cVar10;
3364: pcVar28 = pcVar26 + 8;
3365: *pcVar26 = cVar23;
3366: pcVar26[1] = cVar24;
3367: pcVar26[2] = cVar25;
3368: pcVar26[3] = cVar22;
3369: pcVar26[4] = cVar21;
3370: pcVar26[5] = cVar20;
3371: pcVar26[6] = cVar33;
3372: }
3373: else {
3374: pcVar26[1] = '\0';
3375: *pcVar26 = cVar23;
3376: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3377: *pcVar26 = cVar24;
3378: pcVar26[1] = '\0';
3379: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3380: *pcVar26 = cVar25;
3381: pcVar26[1] = '\0';
3382: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
3383: *pcVar26 = cVar22;
3384: pcVar26[1] = '\0';
3385: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3386: *pcVar26 = cVar21;
3387: pcVar26[1] = '\0';
3388: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3389: *pcVar26 = cVar20;
3390: pcVar26[1] = '\0';
3391: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
3392: *pcVar26 = cVar33;
3393: pcVar26[1] = '\0';
3394: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3395: *pcVar26 = cVar10;
3396: pcVar26[1] = '\0';
3397: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3398: }
3399: iVar17 = iVar17 + 0x40;
3400: uVar11 = (ulong)puVar4[0xf0];
3401: }
3402: else {
3403: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
3404: }
3405: }
3406: }
3407: goto LAB_0010bdea;
3408: }
3409: LAB_0010a8a2:
3410: sVar1 = psVar5[0x2c];
3411: iVar29 = iVar18 + 0x10;
3412: if (sVar1 != 0) {
3413: uVar31 = (int)sVar1 >> 0x1f;
3414: uVar16 = (int)sVar1 + uVar31;
3415: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
3416: if (0xff < iVar29) {
3417: iVar29 = iVar18 + -0xf0;
3418: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
3419: if (iVar32 < 0) {
3420: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
3421: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
3422: cVar10 = (char)uVar14;
3423: cVar33 = (char)(uVar14 >> 8);
3424: cVar20 = (char)(uVar14 >> 0x10);
3425: cVar21 = (char)(uVar14 >> 0x18);
3426: cVar22 = (char)(uVar11 >> 0x20);
3427: cVar23 = (char)(uVar11 >> 0x28);
3428: cVar24 = (char)(uVar11 >> 0x30);
3429: cVar25 = (char)(uVar11 >> 0x38);
3430: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3431: pcVar28[7] = cVar10;
3432: pcVar26 = pcVar28 + 8;
3433: *pcVar28 = cVar25;
3434: pcVar28[1] = cVar24;
3435: pcVar28[2] = cVar23;
3436: pcVar28[3] = cVar22;
3437: pcVar28[4] = cVar21;
3438: pcVar28[5] = cVar20;
3439: pcVar28[6] = cVar33;
3440: }
3441: else {
3442: pcVar28[1] = '\0';
3443: *pcVar28 = cVar25;
3444: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3445: *pcVar28 = cVar24;
3446: pcVar28[1] = '\0';
3447: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
3448: *pcVar28 = cVar23;
3449: pcVar28[1] = '\0';
3450: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
3451: *pcVar28 = cVar22;
3452: pcVar28[1] = '\0';
3453: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
3454: *pcVar28 = cVar21;
3455: pcVar28[1] = '\0';
3456: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
3457: *pcVar28 = cVar20;
3458: pcVar28[1] = '\0';
3459: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
3460: *pcVar28 = cVar33;
3461: pcVar28[1] = '\0';
3462: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
3463: *pcVar28 = cVar10;
3464: pcVar28[1] = '\0';
3465: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
3466: }
3467: uVar11 = (ulong)puVar4[0xf0];
3468: iVar32 = iVar32 + 0x40;
3469: uVar14 = uVar11;
3470: }
3471: else {
3472: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
3473: pcVar26 = pcVar28;
3474: uVar14 = (ulong)puVar4[0xf0];
3475: }
3476: pcVar28 = pcVar26;
3477: iVar17 = iVar32;
3478: if (0xff < iVar29) {
3479: iVar29 = iVar18 + -0x1f0;
3480: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
3481: if (iVar17 < 0) {
3482: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
3483: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
3484: cVar10 = (char)uVar14;
3485: cVar22 = (char)(uVar14 >> 8);
3486: cVar21 = (char)(uVar14 >> 0x10);
3487: cVar33 = (char)(uVar14 >> 0x18);
3488: cVar20 = (char)(uVar11 >> 0x20);
3489: cVar24 = (char)(uVar11 >> 0x28);
3490: cVar25 = (char)(uVar11 >> 0x30);
3491: cVar23 = (char)(uVar11 >> 0x38);
3492: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3493: pcVar26[7] = cVar10;
3494: pcVar28 = pcVar26 + 8;
3495: *pcVar26 = cVar23;
3496: pcVar26[1] = cVar25;
3497: pcVar26[2] = cVar24;
3498: pcVar26[3] = cVar20;
3499: pcVar26[4] = cVar33;
3500: pcVar26[5] = cVar21;
3501: pcVar26[6] = cVar22;
3502: }
3503: else {
3504: pcVar26[1] = '\0';
3505: *pcVar26 = cVar23;
3506: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3507: *pcVar26 = cVar25;
3508: pcVar26[1] = '\0';
3509: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
3510: *pcVar26 = cVar24;
3511: pcVar26[1] = '\0';
3512: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3513: *pcVar26 = cVar20;
3514: pcVar26[1] = '\0';
3515: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
3516: *pcVar26 = cVar33;
3517: pcVar26[1] = '\0';
3518: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3519: *pcVar26 = cVar21;
3520: pcVar26[1] = '\0';
3521: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3522: *pcVar26 = cVar22;
3523: pcVar26[1] = '\0';
3524: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3525: *pcVar26 = cVar10;
3526: pcVar26[1] = '\0';
3527: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3528: }
3529: iVar17 = iVar17 + 0x40;
3530: uVar11 = (ulong)puVar4[0xf0];
3531: }
3532: else {
3533: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
3534: }
3535: }
3536: }
3537: goto LAB_0010a928;
3538: }
3539: LAB_0010be38:
3540: sVar1 = psVar5[0x33];
3541: iVar18 = iVar29 + 0x10;
3542: pcVar26 = pcVar28;
3543: if (sVar1 != 0) {
3544: uVar16 = (int)sVar1 >> 0x1f;
3545: uVar31 = (int)sVar1 + uVar16;
3546: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
3547: iVar32 = iVar17;
3548: if (0xff < iVar18) {
3549: iVar18 = iVar29 + -0xf0;
3550: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
3551: if (iVar32 < 0) {
3552: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
3553: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
3554: cVar10 = (char)uVar14;
3555: cVar25 = (char)(uVar14 >> 8);
3556: cVar24 = (char)(uVar14 >> 0x10);
3557: cVar23 = (char)(uVar14 >> 0x18);
3558: cVar33 = (char)(uVar11 >> 0x20);
3559: cVar20 = (char)(uVar11 >> 0x28);
3560: cVar21 = (char)(uVar11 >> 0x30);
3561: cVar22 = (char)(uVar11 >> 0x38);
3562: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3563: pcVar28[7] = cVar10;
3564: pcVar26 = pcVar28 + 8;
3565: *pcVar28 = cVar22;
3566: pcVar28[1] = cVar21;
3567: pcVar28[2] = cVar20;
3568: pcVar28[3] = cVar33;
3569: pcVar28[4] = cVar23;
3570: pcVar28[5] = cVar24;
3571: pcVar28[6] = cVar25;
3572: }
3573: else {
3574: pcVar28[1] = '\0';
3575: *pcVar28 = cVar22;
3576: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3577: *pcVar28 = cVar21;
3578: pcVar28[1] = '\0';
3579: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
3580: *pcVar28 = cVar20;
3581: pcVar28[1] = '\0';
3582: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
3583: *pcVar28 = cVar33;
3584: pcVar28[1] = '\0';
3585: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
3586: *pcVar28 = cVar23;
3587: pcVar28[1] = '\0';
3588: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
3589: *pcVar28 = cVar24;
3590: pcVar28[1] = '\0';
3591: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
3592: *pcVar28 = cVar25;
3593: pcVar28[1] = '\0';
3594: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
3595: *pcVar28 = cVar10;
3596: pcVar28[1] = '\0';
3597: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
3598: }
3599: uVar11 = (ulong)puVar4[0xf0];
3600: iVar32 = iVar32 + 0x40;
3601: uVar14 = uVar11;
3602: }
3603: else {
3604: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
3605: uVar14 = (ulong)puVar4[0xf0];
3606: }
3607: pcVar28 = pcVar26;
3608: if (0xff < iVar18) {
3609: iVar18 = iVar29 + -0x1f0;
3610: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
3611: if (iVar17 < 0) {
3612: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
3613: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
3614: cVar10 = (char)uVar14;
3615: cVar33 = (char)(uVar14 >> 8);
3616: cVar20 = (char)(uVar14 >> 0x10);
3617: cVar21 = (char)(uVar14 >> 0x18);
3618: cVar22 = (char)(uVar11 >> 0x20);
3619: cVar23 = (char)(uVar11 >> 0x28);
3620: cVar24 = (char)(uVar11 >> 0x30);
3621: cVar25 = (char)(uVar11 >> 0x38);
3622: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3623: pcVar26[7] = cVar10;
3624: pcVar28 = pcVar26 + 8;
3625: *pcVar26 = cVar25;
3626: pcVar26[1] = cVar24;
3627: pcVar26[2] = cVar23;
3628: pcVar26[3] = cVar22;
3629: pcVar26[4] = cVar21;
3630: pcVar26[5] = cVar20;
3631: pcVar26[6] = cVar33;
3632: }
3633: else {
3634: pcVar26[1] = '\0';
3635: *pcVar26 = cVar25;
3636: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3637: *pcVar26 = cVar24;
3638: pcVar26[1] = '\0';
3639: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3640: *pcVar26 = cVar23;
3641: pcVar26[1] = '\0';
3642: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
3643: *pcVar26 = cVar22;
3644: pcVar26[1] = '\0';
3645: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3646: *pcVar26 = cVar21;
3647: pcVar26[1] = '\0';
3648: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3649: *pcVar26 = cVar20;
3650: pcVar26[1] = '\0';
3651: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
3652: *pcVar26 = cVar33;
3653: pcVar26[1] = '\0';
3654: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3655: *pcVar26 = cVar10;
3656: pcVar26[1] = '\0';
3657: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3658: }
3659: uVar11 = (ulong)puVar4[0xf0];
3660: iVar32 = iVar17 + 0x40;
3661: }
3662: else {
3663: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
3664: iVar32 = iVar17;
3665: }
3666: }
3667: }
3668: goto LAB_0010bebe;
3669: }
3670: LAB_0010a976:
3671: sVar1 = psVar5[0x3a];
3672: iVar29 = iVar18 + 0x10;
3673: if (sVar1 == 0) goto LAB_0010b750;
3674: uVar31 = (int)sVar1 >> 0x1f;
3675: uVar16 = (int)sVar1 + uVar31;
3676: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
3677: if (0xff < iVar29) {
3678: iVar29 = iVar18 + -0xf0;
3679: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
3680: if (iVar32 < 0) {
3681: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
3682: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
3683: cVar10 = (char)uVar14;
3684: cVar33 = (char)(uVar14 >> 8);
3685: cVar20 = (char)(uVar14 >> 0x10);
3686: cVar21 = (char)(uVar14 >> 0x18);
3687: cVar22 = (char)(uVar11 >> 0x20);
3688: cVar23 = (char)(uVar11 >> 0x28);
3689: cVar24 = (char)(uVar11 >> 0x30);
3690: cVar25 = (char)(uVar11 >> 0x38);
3691: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3692: pcVar26[7] = cVar10;
3693: pcVar28 = pcVar26 + 8;
3694: *pcVar26 = cVar25;
3695: pcVar26[1] = cVar24;
3696: pcVar26[2] = cVar23;
3697: pcVar26[3] = cVar22;
3698: pcVar26[4] = cVar21;
3699: pcVar26[5] = cVar20;
3700: pcVar26[6] = cVar33;
3701: }
3702: else {
3703: pcVar26[1] = '\0';
3704: *pcVar26 = cVar25;
3705: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3706: *pcVar26 = cVar24;
3707: pcVar26[1] = '\0';
3708: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3709: *pcVar26 = cVar23;
3710: pcVar26[1] = '\0';
3711: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
3712: *pcVar26 = cVar22;
3713: pcVar26[1] = '\0';
3714: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3715: *pcVar26 = cVar21;
3716: pcVar26[1] = '\0';
3717: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3718: *pcVar26 = cVar20;
3719: pcVar26[1] = '\0';
3720: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
3721: *pcVar26 = cVar33;
3722: pcVar26[1] = '\0';
3723: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3724: *pcVar26 = cVar10;
3725: pcVar26[1] = '\0';
3726: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3727: }
3728: uVar11 = (ulong)puVar4[0xf0];
3729: iVar32 = iVar32 + 0x40;
3730: uVar14 = uVar11;
3731: }
3732: else {
3733: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
3734: pcVar28 = pcVar26;
3735: uVar14 = (ulong)puVar4[0xf0];
3736: }
3737: pcVar26 = pcVar28;
3738: iVar17 = iVar32;
3739: if (0xff < iVar29) {
3740: iVar29 = iVar18 + -0x1f0;
3741: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
3742: if (iVar17 < 0) {
3743: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
3744: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
3745: cVar10 = (char)uVar14;
3746: cVar25 = (char)(uVar14 >> 8);
3747: cVar24 = (char)(uVar14 >> 0x10);
3748: cVar33 = (char)(uVar14 >> 0x18);
3749: cVar20 = (char)(uVar11 >> 0x20);
3750: cVar21 = (char)(uVar11 >> 0x28);
3751: cVar22 = (char)(uVar11 >> 0x30);
3752: cVar23 = (char)(uVar11 >> 0x38);
3753: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
3754: pcVar28[7] = cVar10;
3755: pcVar26 = pcVar28 + 8;
3756: *pcVar28 = cVar23;
3757: pcVar28[1] = cVar22;
3758: pcVar28[2] = cVar21;
3759: pcVar28[3] = cVar20;
3760: pcVar28[4] = cVar33;
3761: pcVar28[5] = cVar24;
3762: pcVar28[6] = cVar25;
3763: }
3764: else {
3765: pcVar28[1] = '\0';
3766: *pcVar28 = cVar23;
3767: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3768: *pcVar28 = cVar22;
3769: pcVar28[1] = '\0';
3770: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
3771: *pcVar28 = cVar21;
3772: pcVar28[1] = '\0';
3773: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
3774: *pcVar28 = cVar20;
3775: pcVar28[1] = '\0';
3776: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
3777: *pcVar28 = cVar33;
3778: pcVar28[1] = '\0';
3779: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
3780: *pcVar28 = cVar24;
3781: pcVar28[1] = '\0';
3782: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
3783: *pcVar28 = cVar25;
3784: pcVar28[1] = '\0';
3785: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
3786: *pcVar28 = cVar10;
3787: pcVar28[1] = '\0';
3788: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
3789: }
3790: iVar17 = iVar17 + 0x40;
3791: uVar11 = (ulong)puVar4[0xf0];
3792: }
3793: else {
3794: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
3795: }
3796: }
3797: }
3798: LAB_0010a9fc:
3799: uVar16 = uVar16 & (int)(1 << ((byte)uVar31 & 0x3f)) - 1U |
3800: puVar4[(int)(iVar29 + uVar31)] << ((byte)uVar31 & 0x1f);
3801: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar31) + 0x400) + uVar31;
3802: iVar18 = iVar17 - iVar29;
3803: if (iVar18 < 0) {
3804: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
3805: uVar11 << ((byte)iVar17 & 0x3f);
3806: cVar10 = (char)uVar11;
3807: cVar33 = (char)(uVar11 >> 8);
3808: cVar23 = (char)(uVar11 >> 0x10);
3809: cVar24 = (char)(uVar11 >> 0x18);
3810: cVar25 = (char)(uVar11 >> 0x20);
3811: cVar22 = (char)(uVar11 >> 0x28);
3812: cVar21 = (char)(uVar11 >> 0x30);
3813: cVar20 = (char)(uVar11 >> 0x38);
3814: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
3815: pcVar26[7] = cVar10;
3816: pcVar28 = pcVar26 + 8;
3817: *pcVar26 = cVar20;
3818: pcVar26[1] = cVar21;
3819: pcVar26[2] = cVar22;
3820: pcVar26[3] = cVar25;
3821: pcVar26[4] = cVar24;
3822: pcVar26[5] = cVar23;
3823: pcVar26[6] = cVar33;
3824: }
3825: else {
3826: pcVar26[1] = '\0';
3827: *pcVar26 = cVar20;
3828: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3829: *pcVar26 = cVar21;
3830: pcVar26[1] = '\0';
3831: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3832: *pcVar26 = cVar22;
3833: pcVar26[1] = '\0';
3834: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3835: *pcVar26 = cVar25;
3836: pcVar26[1] = '\0';
3837: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
3838: *pcVar26 = cVar24;
3839: pcVar26[1] = '\0';
3840: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3841: *pcVar26 = cVar23;
3842: pcVar26[1] = '\0';
3843: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
3844: *pcVar26 = cVar33;
3845: pcVar26[1] = '\0';
3846: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3847: *pcVar26 = cVar10;
3848: pcVar26[1] = '\0';
3849: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3850: }
3851: sVar1 = psVar5[0x3b];
3852: uVar11 = SEXT48((int)uVar16);
3853: iVar17 = iVar18 + 0x40;
3854: pcVar26 = pcVar28;
3855: }
3856: else {
3857: sVar1 = psVar5[0x3b];
3858: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
3859: iVar17 = iVar18;
3860: }
3861: uVar31 = SEXT24(sVar1);
3862: if (sVar1 == 0) goto LAB_0010aa4a;
3863: uVar35 = (int)uVar31 >> 0x1f;
3864: uVar16 = uVar31 + uVar35;
3865: uVar31 = 0;
3866: uVar35 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar35 ^ uVar16)];
3867: LAB_0010b7f2:
3868: uVar16 = uVar16 & (int)(1 << ((byte)uVar35 & 0x3f)) - 1U |
3869: puVar4[(int)(uVar31 + uVar35)] << ((byte)uVar35 & 0x1f);
3870: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar31 + uVar35) + 0x400) + uVar35;
3871: iVar18 = iVar17 - iVar29;
3872: if (iVar18 < 0) {
3873: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
3874: uVar11 << ((byte)iVar17 & 0x3f);
3875: cVar10 = (char)uVar11;
3876: cVar22 = (char)(uVar11 >> 8);
3877: cVar21 = (char)(uVar11 >> 0x10);
3878: cVar20 = (char)(uVar11 >> 0x18);
3879: cVar33 = (char)(uVar11 >> 0x20);
3880: cVar23 = (char)(uVar11 >> 0x28);
3881: cVar24 = (char)(uVar11 >> 0x30);
3882: cVar25 = (char)(uVar11 >> 0x38);
3883: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
3884: pcVar26[7] = cVar10;
3885: pcVar28 = pcVar26 + 8;
3886: *pcVar26 = cVar25;
3887: pcVar26[1] = cVar24;
3888: pcVar26[2] = cVar23;
3889: pcVar26[3] = cVar33;
3890: pcVar26[4] = cVar20;
3891: pcVar26[5] = cVar21;
3892: pcVar26[6] = cVar22;
3893: }
3894: else {
3895: pcVar26[1] = '\0';
3896: *pcVar26 = cVar25;
3897: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3898: *pcVar26 = cVar24;
3899: pcVar26[1] = '\0';
3900: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3901: *pcVar26 = cVar23;
3902: pcVar26[1] = '\0';
3903: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
3904: *pcVar26 = cVar33;
3905: pcVar26[1] = '\0';
3906: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3907: *pcVar26 = cVar20;
3908: pcVar26[1] = '\0';
3909: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
3910: *pcVar26 = cVar21;
3911: pcVar26[1] = '\0';
3912: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3913: *pcVar26 = cVar22;
3914: pcVar26[1] = '\0';
3915: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3916: *pcVar26 = cVar10;
3917: pcVar26[1] = '\0';
3918: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3919: }
3920: sVar1 = psVar5[0x34];
3921: uVar11 = SEXT48((int)uVar16);
3922: iVar17 = iVar18 + 0x40;
3923: pcVar26 = pcVar28;
3924: }
3925: else {
3926: sVar1 = psVar5[0x34];
3927: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
3928: iVar17 = iVar18;
3929: }
3930: uVar16 = SEXT24(sVar1);
3931: if (uVar16 == 0) goto LAB_0010b840;
3932: uVar31 = (int)uVar16 >> 0x1f;
3933: uVar35 = uVar16 + uVar31;
3934: uVar16 = 0;
3935: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar35)];
3936: LAB_0010aaec:
3937: uVar31 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
3938: puVar4[(int)(uVar16 + uVar19)] << ((byte)uVar19 & 0x1f);
3939: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar16 + uVar19) + 0x400) + uVar19;
3940: iVar18 = iVar17 - iVar29;
3941: if (iVar18 < 0) {
3942: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
3943: uVar11 << ((byte)iVar17 & 0x3f);
3944: cVar10 = (char)uVar11;
3945: cVar33 = (char)(uVar11 >> 8);
3946: cVar20 = (char)(uVar11 >> 0x10);
3947: cVar21 = (char)(uVar11 >> 0x18);
3948: cVar22 = (char)(uVar11 >> 0x20);
3949: cVar23 = (char)(uVar11 >> 0x28);
3950: cVar24 = (char)(uVar11 >> 0x30);
3951: cVar25 = (char)(uVar11 >> 0x38);
3952: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
3953: pcVar26[7] = cVar10;
3954: pcVar28 = pcVar26 + 8;
3955: *pcVar26 = cVar25;
3956: pcVar26[1] = cVar24;
3957: pcVar26[2] = cVar23;
3958: pcVar26[3] = cVar22;
3959: pcVar26[4] = cVar21;
3960: pcVar26[5] = cVar20;
3961: pcVar26[6] = cVar33;
3962: }
3963: else {
3964: pcVar26[1] = '\0';
3965: *pcVar26 = cVar25;
3966: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
3967: *pcVar26 = cVar24;
3968: pcVar26[1] = '\0';
3969: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
3970: *pcVar26 = cVar23;
3971: pcVar26[1] = '\0';
3972: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
3973: *pcVar26 = cVar22;
3974: pcVar26[1] = '\0';
3975: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
3976: *pcVar26 = cVar21;
3977: pcVar26[1] = '\0';
3978: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
3979: *pcVar26 = cVar20;
3980: pcVar26[1] = '\0';
3981: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
3982: *pcVar26 = cVar33;
3983: pcVar26[1] = '\0';
3984: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
3985: *pcVar26 = cVar10;
3986: pcVar26[1] = '\0';
3987: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
3988: }
3989: sVar1 = psVar5[0x2d];
3990: uVar11 = SEXT48((int)uVar31);
3991: iVar17 = iVar18 + 0x40;
3992: pcVar26 = pcVar28;
3993: }
3994: else {
3995: sVar1 = psVar5[0x2d];
3996: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
3997: iVar17 = iVar18;
3998: }
3999: uVar31 = SEXT24(sVar1);
4000: if (sVar1 == 0) goto LAB_0010ab3a;
4001: uVar16 = (int)uVar31 >> 0x1f;
4002: uVar35 = uVar31 + uVar16;
4003: uVar31 = 0;
4004: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar35)];
4005: LAB_0010b8e2:
4006: uVar16 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
4007: puVar4[(int)(uVar31 + uVar19)] << ((byte)uVar19 & 0x1f);
4008: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar31 + uVar19) + 0x400) + uVar19;
4009: iVar18 = iVar17 - iVar29;
4010: if (iVar18 < 0) {
4011: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
4012: uVar11 << ((byte)iVar17 & 0x3f);
4013: cVar10 = (char)uVar11;
4014: cVar33 = (char)(uVar11 >> 8);
4015: cVar20 = (char)(uVar11 >> 0x10);
4016: cVar21 = (char)(uVar11 >> 0x18);
4017: cVar22 = (char)(uVar11 >> 0x20);
4018: cVar23 = (char)(uVar11 >> 0x28);
4019: cVar24 = (char)(uVar11 >> 0x30);
4020: cVar25 = (char)(uVar11 >> 0x38);
4021: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4022: pcVar26[7] = cVar10;
4023: pcVar28 = pcVar26 + 8;
4024: *pcVar26 = cVar25;
4025: pcVar26[1] = cVar24;
4026: pcVar26[2] = cVar23;
4027: pcVar26[3] = cVar22;
4028: pcVar26[4] = cVar21;
4029: pcVar26[5] = cVar20;
4030: pcVar26[6] = cVar33;
4031: }
4032: else {
4033: pcVar26[1] = '\0';
4034: *pcVar26 = cVar25;
4035: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4036: *pcVar26 = cVar24;
4037: pcVar26[1] = '\0';
4038: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4039: *pcVar26 = cVar23;
4040: pcVar26[1] = '\0';
4041: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4042: *pcVar26 = cVar22;
4043: pcVar26[1] = '\0';
4044: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4045: *pcVar26 = cVar21;
4046: pcVar26[1] = '\0';
4047: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4048: *pcVar26 = cVar20;
4049: pcVar26[1] = '\0';
4050: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4051: *pcVar26 = cVar33;
4052: pcVar26[1] = '\0';
4053: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
4054: *pcVar26 = cVar10;
4055: pcVar26[1] = '\0';
4056: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4057: }
4058: sVar1 = psVar5[0x26];
4059: uVar11 = SEXT48((int)uVar16);
4060: iVar17 = iVar18 + 0x40;
4061: pcVar26 = pcVar28;
4062: }
4063: else {
4064: sVar1 = psVar5[0x26];
4065: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
4066: iVar17 = iVar18;
4067: }
4068: uVar16 = SEXT24(sVar1);
4069: if (uVar16 == 0) goto LAB_0010b930;
4070: uVar31 = (int)uVar16 >> 0x1f;
4071: uVar35 = uVar31 + uVar16;
4072: uVar16 = 0;
4073: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar35)];
4074: LAB_0010abdc:
4075: uVar31 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
4076: puVar4[(int)(uVar16 + uVar19)] << ((byte)uVar19 & 0x1f);
4077: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar16 + uVar19) + 0x400) + uVar19;
4078: iVar18 = iVar17 - iVar29;
4079: if (iVar18 < 0) {
4080: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
4081: uVar11 << ((byte)iVar17 & 0x3f);
4082: cVar10 = (char)uVar11;
4083: cVar33 = (char)(uVar11 >> 8);
4084: cVar20 = (char)(uVar11 >> 0x10);
4085: cVar21 = (char)(uVar11 >> 0x18);
4086: cVar22 = (char)(uVar11 >> 0x20);
4087: cVar23 = (char)(uVar11 >> 0x28);
4088: cVar24 = (char)(uVar11 >> 0x30);
4089: cVar25 = (char)(uVar11 >> 0x38);
4090: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4091: pcVar26[7] = cVar10;
4092: pcVar28 = pcVar26 + 8;
4093: *pcVar26 = cVar25;
4094: pcVar26[1] = cVar24;
4095: pcVar26[2] = cVar23;
4096: pcVar26[3] = cVar22;
4097: pcVar26[4] = cVar21;
4098: pcVar26[5] = cVar20;
4099: pcVar26[6] = cVar33;
4100: }
4101: else {
4102: pcVar26[1] = '\0';
4103: *pcVar26 = cVar25;
4104: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4105: *pcVar26 = cVar24;
4106: pcVar26[1] = '\0';
4107: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4108: *pcVar26 = cVar23;
4109: pcVar26[1] = '\0';
4110: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4111: *pcVar26 = cVar22;
4112: pcVar26[1] = '\0';
4113: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4114: *pcVar26 = cVar21;
4115: pcVar26[1] = '\0';
4116: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4117: *pcVar26 = cVar20;
4118: pcVar26[1] = '\0';
4119: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4120: *pcVar26 = cVar33;
4121: pcVar26[1] = '\0';
4122: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
4123: *pcVar26 = cVar10;
4124: pcVar26[1] = '\0';
4125: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4126: }
4127: sVar1 = psVar5[0x1f];
4128: uVar11 = SEXT48((int)uVar31);
4129: iVar17 = iVar18 + 0x40;
4130: pcVar26 = pcVar28;
4131: }
4132: else {
4133: sVar1 = psVar5[0x1f];
4134: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
4135: iVar17 = iVar18;
4136: }
4137: uVar31 = SEXT24(sVar1);
4138: if (sVar1 == 0) goto LAB_0010ac2a;
4139: uVar16 = (int)uVar31 >> 0x1f;
4140: uVar35 = uVar16 + uVar31;
4141: uVar31 = 0;
4142: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar35)];
4143: LAB_0010b9d2:
4144: uVar16 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
4145: puVar4[(int)(uVar31 + uVar19)] << ((byte)uVar19 & 0x1f);
4146: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar31 + uVar19) + 0x400) + uVar19;
4147: iVar18 = iVar17 - iVar29;
4148: if (iVar18 < 0) {
4149: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
4150: uVar11 << ((byte)iVar17 & 0x3f);
4151: cVar10 = (char)uVar11;
4152: cVar25 = (char)(uVar11 >> 8);
4153: cVar24 = (char)(uVar11 >> 0x10);
4154: cVar23 = (char)(uVar11 >> 0x18);
4155: cVar22 = (char)(uVar11 >> 0x20);
4156: cVar21 = (char)(uVar11 >> 0x28);
4157: cVar20 = (char)(uVar11 >> 0x30);
4158: cVar33 = (char)(uVar11 >> 0x38);
4159: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4160: pcVar26[7] = cVar10;
4161: pcVar28 = pcVar26 + 8;
4162: *pcVar26 = cVar33;
4163: pcVar26[1] = cVar20;
4164: pcVar26[2] = cVar21;
4165: pcVar26[3] = cVar22;
4166: pcVar26[4] = cVar23;
4167: pcVar26[5] = cVar24;
4168: pcVar26[6] = cVar25;
4169: }
4170: else {
4171: pcVar26[1] = '\0';
4172: *pcVar26 = cVar33;
4173: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4174: *pcVar26 = cVar20;
4175: pcVar26[1] = '\0';
4176: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4177: *pcVar26 = cVar21;
4178: pcVar26[1] = '\0';
4179: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4180: *pcVar26 = cVar22;
4181: pcVar26[1] = '\0';
4182: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4183: *pcVar26 = cVar23;
4184: pcVar26[1] = '\0';
4185: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4186: *pcVar26 = cVar24;
4187: pcVar26[1] = '\0';
4188: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4189: *pcVar26 = cVar25;
4190: pcVar26[1] = '\0';
4191: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
4192: *pcVar26 = cVar10;
4193: pcVar26[1] = '\0';
4194: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4195: }
4196: sVar1 = psVar5[0x27];
4197: uVar11 = SEXT48((int)uVar16);
4198: iVar17 = iVar18 + 0x40;
4199: pcVar26 = pcVar28;
4200: }
4201: else {
4202: sVar1 = psVar5[0x27];
4203: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
4204: iVar17 = iVar18;
4205: }
4206: uVar16 = SEXT24(sVar1);
4207: if (uVar16 == 0) goto LAB_0010ba20;
4208: uVar31 = (int)uVar16 >> 0x1f;
4209: uVar35 = uVar16 + uVar31;
4210: uVar16 = 0;
4211: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar35)];
4212: LAB_0010accc:
4213: uVar31 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
4214: puVar4[(int)(uVar16 + uVar19)] << ((byte)uVar19 & 0x1f);
4215: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar16 + uVar19) + 0x400) + uVar19;
4216: iVar18 = iVar17 - iVar29;
4217: if (iVar18 < 0) {
4218: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
4219: uVar11 << ((byte)iVar17 & 0x3f);
4220: cVar10 = (char)uVar11;
4221: cVar33 = (char)(uVar11 >> 8);
4222: cVar20 = (char)(uVar11 >> 0x10);
4223: cVar21 = (char)(uVar11 >> 0x18);
4224: cVar22 = (char)(uVar11 >> 0x20);
4225: cVar23 = (char)(uVar11 >> 0x28);
4226: cVar24 = (char)(uVar11 >> 0x30);
4227: cVar25 = (char)(uVar11 >> 0x38);
4228: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4229: pcVar26[7] = cVar10;
4230: pcVar28 = pcVar26 + 8;
4231: *pcVar26 = cVar25;
4232: pcVar26[1] = cVar24;
4233: pcVar26[2] = cVar23;
4234: pcVar26[3] = cVar22;
4235: pcVar26[4] = cVar21;
4236: pcVar26[5] = cVar20;
4237: pcVar26[6] = cVar33;
4238: }
4239: else {
4240: pcVar26[1] = '\0';
4241: *pcVar26 = cVar25;
4242: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4243: *pcVar26 = cVar24;
4244: pcVar26[1] = '\0';
4245: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4246: *pcVar26 = cVar23;
4247: pcVar26[1] = '\0';
4248: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4249: *pcVar26 = cVar22;
4250: pcVar26[1] = '\0';
4251: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4252: *pcVar26 = cVar21;
4253: pcVar26[1] = '\0';
4254: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4255: *pcVar26 = cVar20;
4256: pcVar26[1] = '\0';
4257: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4258: *pcVar26 = cVar33;
4259: pcVar26[1] = '\0';
4260: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
4261: *pcVar26 = cVar10;
4262: pcVar26[1] = '\0';
4263: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4264: }
4265: sVar1 = psVar5[0x2e];
4266: uVar11 = SEXT48((int)uVar31);
4267: iVar17 = iVar18 + 0x40;
4268: pcVar26 = pcVar28;
4269: }
4270: else {
4271: sVar1 = psVar5[0x2e];
4272: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
4273: iVar17 = iVar18;
4274: }
4275: uVar31 = SEXT24(sVar1);
4276: if (sVar1 == 0) goto LAB_0010ad1a;
4277: uVar16 = (int)uVar31 >> 0x1f;
4278: uVar35 = uVar31 + uVar16;
4279: uVar31 = 0;
4280: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar35)];
4281: LAB_0010bac2:
4282: uVar16 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
4283: puVar4[(int)(uVar31 + uVar19)] << ((byte)uVar19 & 0x1f);
4284: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar31 + uVar19) + 0x400) + uVar19;
4285: iVar18 = iVar17 - iVar29;
4286: if (iVar18 < 0) {
4287: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
4288: uVar11 << ((byte)iVar17 & 0x3f);
4289: cVar10 = (char)uVar11;
4290: cVar20 = (char)(uVar11 >> 8);
4291: cVar21 = (char)(uVar11 >> 0x10);
4292: cVar22 = (char)(uVar11 >> 0x18);
4293: cVar23 = (char)(uVar11 >> 0x20);
4294: cVar24 = (char)(uVar11 >> 0x28);
4295: cVar25 = (char)(uVar11 >> 0x30);
4296: cVar33 = (char)(uVar11 >> 0x38);
4297: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4298: pcVar26[7] = cVar10;
4299: pcVar28 = pcVar26 + 8;
4300: *pcVar26 = cVar33;
4301: pcVar26[1] = cVar25;
4302: pcVar26[2] = cVar24;
4303: pcVar26[3] = cVar23;
4304: pcVar26[4] = cVar22;
4305: pcVar26[5] = cVar21;
4306: pcVar26[6] = cVar20;
4307: }
4308: else {
4309: pcVar26[1] = '\0';
4310: *pcVar26 = cVar33;
4311: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4312: *pcVar26 = cVar25;
4313: pcVar26[1] = '\0';
4314: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
4315: *pcVar26 = cVar24;
4316: pcVar26[1] = '\0';
4317: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4318: *pcVar26 = cVar23;
4319: pcVar26[1] = '\0';
4320: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4321: *pcVar26 = cVar22;
4322: pcVar26[1] = '\0';
4323: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4324: *pcVar26 = cVar21;
4325: pcVar26[1] = '\0';
4326: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4327: *pcVar26 = cVar20;
4328: pcVar26[1] = '\0';
4329: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4330: *pcVar26 = cVar10;
4331: pcVar26[1] = '\0';
4332: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4333: }
4334: sVar1 = psVar5[0x35];
4335: uVar11 = SEXT48((int)uVar16);
4336: iVar17 = iVar18 + 0x40;
4337: pcVar26 = pcVar28;
4338: }
4339: else {
4340: sVar1 = psVar5[0x35];
4341: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
4342: iVar17 = iVar18;
4343: }
4344: uVar16 = SEXT24(sVar1);
4345: if (uVar16 == 0) goto LAB_0010bb10;
4346: uVar31 = (int)uVar16 >> 0x1f;
4347: uVar35 = uVar16 + uVar31;
4348: uVar16 = 0;
4349: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar35)];
4350: LAB_0010adbc:
4351: uVar31 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
4352: puVar4[(int)(uVar16 + uVar19)] << ((byte)uVar19 & 0x1f);
4353: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar16 + uVar19) + 0x400) + uVar19;
4354: iVar18 = iVar17 - iVar29;
4355: if (iVar18 < 0) {
4356: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
4357: uVar11 << ((byte)iVar17 & 0x3f);
4358: cVar10 = (char)uVar11;
4359: cVar33 = (char)(uVar11 >> 8);
4360: cVar20 = (char)(uVar11 >> 0x10);
4361: cVar21 = (char)(uVar11 >> 0x18);
4362: cVar22 = (char)(uVar11 >> 0x20);
4363: cVar23 = (char)(uVar11 >> 0x28);
4364: cVar24 = (char)(uVar11 >> 0x30);
4365: cVar25 = (char)(uVar11 >> 0x38);
4366: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4367: pcVar26[7] = cVar10;
4368: pcVar28 = pcVar26 + 8;
4369: *pcVar26 = cVar25;
4370: pcVar26[1] = cVar24;
4371: pcVar26[2] = cVar23;
4372: pcVar26[3] = cVar22;
4373: pcVar26[4] = cVar21;
4374: pcVar26[5] = cVar20;
4375: pcVar26[6] = cVar33;
4376: }
4377: else {
4378: pcVar26[1] = '\0';
4379: *pcVar26 = cVar25;
4380: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4381: *pcVar26 = cVar24;
4382: pcVar26[1] = '\0';
4383: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4384: *pcVar26 = cVar23;
4385: pcVar26[1] = '\0';
4386: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4387: *pcVar26 = cVar22;
4388: pcVar26[1] = '\0';
4389: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4390: *pcVar26 = cVar21;
4391: pcVar26[1] = '\0';
4392: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4393: *pcVar26 = cVar20;
4394: pcVar26[1] = '\0';
4395: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4396: *pcVar26 = cVar33;
4397: pcVar26[1] = '\0';
4398: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
4399: *pcVar26 = cVar10;
4400: pcVar26[1] = '\0';
4401: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4402: }
4403: sVar1 = psVar5[0x3c];
4404: uVar11 = SEXT48((int)uVar31);
4405: iVar17 = iVar18 + 0x40;
4406: pcVar26 = pcVar28;
4407: }
4408: else {
4409: sVar1 = psVar5[0x3c];
4410: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
4411: iVar17 = iVar18;
4412: }
4413: uVar31 = SEXT24(sVar1);
4414: if (sVar1 == 0) goto LAB_0010ae0a;
4415: uVar16 = (int)uVar31 >> 0x1f;
4416: uVar35 = uVar16 + uVar31;
4417: uVar31 = 0;
4418: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar35)];
4419: iVar29 = iVar17;
4420: LAB_0010bbb2:
4421: uVar16 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
4422: puVar4[(int)(uVar31 + uVar19)] << ((byte)uVar19 & 0x1f);
4423: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(uVar31 + uVar19) + 0x400) + uVar19;
4424: iVar17 = iVar29 - iVar18;
4425: if (iVar17 < 0) {
4426: uVar11 = (long)((int)uVar16 >> (-(char)iVar17 & 0x1fU)) |
4427: uVar11 << ((byte)iVar29 & 0x3f);
4428: cVar10 = (char)uVar11;
4429: cVar20 = (char)(uVar11 >> 8);
4430: cVar23 = (char)(uVar11 >> 0x10);
4431: cVar21 = (char)(uVar11 >> 0x18);
4432: cVar22 = (char)(uVar11 >> 0x20);
4433: cVar25 = (char)(uVar11 >> 0x28);
4434: cVar24 = (char)(uVar11 >> 0x30);
4435: cVar33 = (char)(uVar11 >> 0x38);
4436: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4437: pcVar26[7] = cVar10;
4438: pcVar28 = pcVar26 + 8;
4439: *pcVar26 = cVar33;
4440: pcVar26[1] = cVar24;
4441: pcVar26[2] = cVar25;
4442: pcVar26[3] = cVar22;
4443: pcVar26[4] = cVar21;
4444: pcVar26[5] = cVar23;
4445: pcVar26[6] = cVar20;
4446: }
4447: else {
4448: pcVar26[1] = '\0';
4449: *pcVar26 = cVar33;
4450: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4451: *pcVar26 = cVar24;
4452: pcVar26[1] = '\0';
4453: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4454: *pcVar26 = cVar25;
4455: pcVar26[1] = '\0';
4456: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
4457: *pcVar26 = cVar22;
4458: pcVar26[1] = '\0';
4459: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4460: *pcVar26 = cVar21;
4461: pcVar26[1] = '\0';
4462: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4463: *pcVar26 = cVar23;
4464: pcVar26[1] = '\0';
4465: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4466: *pcVar26 = cVar20;
4467: pcVar26[1] = '\0';
4468: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4469: *pcVar26 = cVar10;
4470: pcVar26[1] = '\0';
4471: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4472: }
4473: iVar17 = iVar17 + 0x40;
4474: uVar11 = SEXT48((int)uVar16);
4475: pcVar26 = pcVar28;
4476: }
4477: else {
4478: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar16;
4479: }
4480: uVar16 = SEXT24(psVar5[0x3d]);
4481: if (uVar16 != 0) {
4482: uVar31 = (int)uVar16 >> 0x1f;
4483: uVar35 = uVar31 + uVar16;
4484: uVar16 = 0;
4485: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar35)];
4486: goto LAB_0010aeac;
4487: }
4488: LAB_0010b5d8:
4489: sVar1 = psVar5[0x36];
4490: uVar31 = uVar16 + 0x10;
4491: if (sVar1 != 0) {
4492: uVar19 = (int)sVar1 >> 0x1f;
4493: uVar35 = (int)sVar1 + uVar19;
4494: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
4495: iVar29 = iVar17;
4496: if (0xff < (int)uVar31) {
4497: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
4498: if (iVar29 < 0) {
4499: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
4500: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
4501: cVar10 = (char)uVar14;
4502: cVar21 = (char)(uVar14 >> 8);
4503: cVar22 = (char)(uVar14 >> 0x10);
4504: cVar25 = (char)(uVar14 >> 0x18);
4505: cVar24 = (char)(uVar11 >> 0x20);
4506: cVar23 = (char)(uVar11 >> 0x28);
4507: cVar33 = (char)(uVar11 >> 0x30);
4508: cVar20 = (char)(uVar11 >> 0x38);
4509: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
4510: pcVar26[7] = cVar10;
4511: pcVar28 = pcVar26 + 8;
4512: *pcVar26 = cVar20;
4513: pcVar26[1] = cVar33;
4514: pcVar26[2] = cVar23;
4515: pcVar26[3] = cVar24;
4516: pcVar26[4] = cVar25;
4517: pcVar26[5] = cVar22;
4518: pcVar26[6] = cVar21;
4519: }
4520: else {
4521: pcVar26[1] = '\0';
4522: *pcVar26 = cVar20;
4523: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4524: *pcVar26 = cVar33;
4525: pcVar26[1] = '\0';
4526: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
4527: *pcVar26 = cVar23;
4528: pcVar26[1] = '\0';
4529: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4530: *pcVar26 = cVar24;
4531: pcVar26[1] = '\0';
4532: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4533: *pcVar26 = cVar25;
4534: pcVar26[1] = '\0';
4535: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
4536: *pcVar26 = cVar22;
4537: pcVar26[1] = '\0';
4538: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4539: *pcVar26 = cVar21;
4540: pcVar26[1] = '\0';
4541: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4542: *pcVar26 = cVar10;
4543: pcVar26[1] = '\0';
4544: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4545: }
4546: uVar11 = (ulong)puVar4[0xf0];
4547: iVar29 = iVar29 + 0x40;
4548: uVar14 = uVar11;
4549: }
4550: else {
4551: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
4552: pcVar28 = pcVar26;
4553: uVar14 = (ulong)puVar4[0xf0];
4554: }
4555: pcVar26 = pcVar28;
4556: if (0xff < (int)(uVar16 - 0xf0)) {
4557: iVar17 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
4558: if (iVar17 < 0) {
4559: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
4560: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
4561: cVar10 = (char)uVar14;
4562: cVar33 = (char)(uVar14 >> 8);
4563: cVar20 = (char)(uVar14 >> 0x10);
4564: cVar21 = (char)(uVar14 >> 0x18);
4565: cVar22 = (char)(uVar11 >> 0x20);
4566: cVar23 = (char)(uVar11 >> 0x28);
4567: cVar24 = (char)(uVar11 >> 0x30);
4568: cVar25 = (char)(uVar11 >> 0x38);
4569: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
4570: pcVar28[7] = cVar10;
4571: pcVar27 = pcVar28 + 8;
4572: *pcVar28 = cVar25;
4573: pcVar28[1] = cVar24;
4574: pcVar28[2] = cVar23;
4575: pcVar28[3] = cVar22;
4576: pcVar28[4] = cVar21;
4577: pcVar28[5] = cVar20;
4578: pcVar28[6] = cVar33;
4579: }
4580: else {
4581: pcVar28[1] = '\0';
4582: *pcVar28 = cVar25;
4583: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4584: *pcVar28 = cVar24;
4585: pcVar28[1] = '\0';
4586: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
4587: *pcVar28 = cVar23;
4588: pcVar28[1] = '\0';
4589: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
4590: *pcVar28 = cVar22;
4591: pcVar28[1] = '\0';
4592: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
4593: *pcVar28 = cVar21;
4594: pcVar28[1] = '\0';
4595: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
4596: *pcVar28 = cVar20;
4597: pcVar28[1] = '\0';
4598: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
4599: *pcVar28 = cVar33;
4600: pcVar28[1] = '\0';
4601: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
4602: *pcVar28 = cVar10;
4603: pcVar28[1] = '\0';
4604: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
4605: }
4606: uVar11 = (ulong)puVar4[0xf0];
4607: iVar17 = iVar17 + 0x40;
4608: uVar14 = uVar11;
4609: }
4610: else {
4611: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
4612: pcVar27 = pcVar28;
4613: }
4614: pcVar26 = pcVar27;
4615: iVar29 = iVar17;
4616: if (0x2ef < (int)uVar16) {
4617: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
4618: if (iVar29 < 0) {
4619: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
4620: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
4621: cVar10 = (char)uVar14;
4622: cVar22 = (char)(uVar14 >> 8);
4623: cVar21 = (char)(uVar14 >> 0x10);
4624: cVar20 = (char)(uVar14 >> 0x18);
4625: cVar33 = (char)(uVar11 >> 0x20);
4626: cVar23 = (char)(uVar11 >> 0x28);
4627: cVar24 = (char)(uVar11 >> 0x30);
4628: cVar25 = (char)(uVar11 >> 0x38);
4629: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
4630: pcVar27[7] = cVar10;
4631: pcVar26 = pcVar27 + 8;
4632: *pcVar27 = cVar25;
4633: pcVar27[1] = cVar24;
4634: pcVar27[2] = cVar23;
4635: pcVar27[3] = cVar33;
4636: pcVar27[4] = cVar20;
4637: pcVar27[5] = cVar21;
4638: pcVar27[6] = cVar22;
4639: }
4640: else {
4641: pcVar27[1] = '\0';
4642: *pcVar27 = cVar25;
4643: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4644: *pcVar27 = cVar24;
4645: pcVar27[1] = '\0';
4646: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
4647: *pcVar27 = cVar23;
4648: pcVar27[1] = '\0';
4649: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
4650: *pcVar27 = cVar33;
4651: pcVar27[1] = '\0';
4652: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
4653: *pcVar27 = cVar20;
4654: pcVar27[1] = '\0';
4655: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
4656: *pcVar27 = cVar21;
4657: pcVar27[1] = '\0';
4658: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
4659: *pcVar27 = cVar22;
4660: pcVar27[1] = '\0';
4661: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
4662: *pcVar27 = cVar10;
4663: pcVar27[1] = '\0';
4664: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
4665: }
4666: iVar29 = iVar29 + 0x40;
4667: uVar11 = (ulong)puVar4[0xf0];
4668: }
4669: else {
4670: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
4671: }
4672: }
4673: }
4674: uVar31 = uVar16 - 0xf0 & 0xff;
4675: }
4676: goto LAB_0010b67a;
4677: }
4678: LAB_0010aefa:
4679: sVar1 = psVar5[0x2f];
4680: uVar16 = uVar31 + 0x10;
4681: if (sVar1 == 0) goto LAB_0010b4c0;
4682: uVar35 = (int)sVar1 >> 0x1f;
4683: uVar19 = (int)sVar1 + uVar35;
4684: uVar35 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar35 ^ uVar19)];
4685: if (0xff < (int)uVar16) {
4686: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
4687: if (iVar29 < 0) {
4688: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
4689: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
4690: cVar10 = (char)uVar14;
4691: cVar25 = (char)(uVar14 >> 8);
4692: cVar24 = (char)(uVar14 >> 0x10);
4693: cVar23 = (char)(uVar14 >> 0x18);
4694: cVar22 = (char)(uVar11 >> 0x20);
4695: cVar21 = (char)(uVar11 >> 0x28);
4696: cVar20 = (char)(uVar11 >> 0x30);
4697: cVar33 = (char)(uVar11 >> 0x38);
4698: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
4699: pcVar26[7] = cVar10;
4700: pcVar28 = pcVar26 + 8;
4701: *pcVar26 = cVar33;
4702: pcVar26[1] = cVar20;
4703: pcVar26[2] = cVar21;
4704: pcVar26[3] = cVar22;
4705: pcVar26[4] = cVar23;
4706: pcVar26[5] = cVar24;
4707: pcVar26[6] = cVar25;
4708: }
4709: else {
4710: pcVar26[1] = '\0';
4711: *pcVar26 = cVar33;
4712: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4713: *pcVar26 = cVar20;
4714: pcVar26[1] = '\0';
4715: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4716: *pcVar26 = cVar21;
4717: pcVar26[1] = '\0';
4718: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4719: *pcVar26 = cVar22;
4720: pcVar26[1] = '\0';
4721: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4722: *pcVar26 = cVar23;
4723: pcVar26[1] = '\0';
4724: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4725: *pcVar26 = cVar24;
4726: pcVar26[1] = '\0';
4727: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4728: *pcVar26 = cVar25;
4729: pcVar26[1] = '\0';
4730: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
4731: *pcVar26 = cVar10;
4732: pcVar26[1] = '\0';
4733: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4734: }
4735: uVar11 = (ulong)puVar4[0xf0];
4736: iVar29 = iVar29 + 0x40;
4737: uVar14 = uVar11;
4738: }
4739: else {
4740: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
4741: pcVar28 = pcVar26;
4742: uVar14 = (ulong)puVar4[0xf0];
4743: }
4744: pcVar26 = pcVar28;
4745: iVar17 = iVar29;
4746: if (0xff < (int)(uVar31 - 0xf0)) {
4747: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
4748: if (iVar18 < 0) {
4749: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
4750: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
4751: cVar10 = (char)uVar14;
4752: cVar33 = (char)(uVar14 >> 8);
4753: cVar20 = (char)(uVar14 >> 0x10);
4754: cVar21 = (char)(uVar14 >> 0x18);
4755: cVar22 = (char)(uVar11 >> 0x20);
4756: cVar23 = (char)(uVar11 >> 0x28);
4757: cVar24 = (char)(uVar11 >> 0x30);
4758: cVar25 = (char)(uVar11 >> 0x38);
4759: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
4760: pcVar28[7] = cVar10;
4761: pcVar27 = pcVar28 + 8;
4762: *pcVar28 = cVar25;
4763: pcVar28[1] = cVar24;
4764: pcVar28[2] = cVar23;
4765: pcVar28[3] = cVar22;
4766: pcVar28[4] = cVar21;
4767: pcVar28[5] = cVar20;
4768: pcVar28[6] = cVar33;
4769: }
4770: else {
4771: pcVar28[1] = '\0';
4772: *pcVar28 = cVar25;
4773: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4774: *pcVar28 = cVar24;
4775: pcVar28[1] = '\0';
4776: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
4777: *pcVar28 = cVar23;
4778: pcVar28[1] = '\0';
4779: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
4780: *pcVar28 = cVar22;
4781: pcVar28[1] = '\0';
4782: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
4783: *pcVar28 = cVar21;
4784: pcVar28[1] = '\0';
4785: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
4786: *pcVar28 = cVar20;
4787: pcVar28[1] = '\0';
4788: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
4789: *pcVar28 = cVar33;
4790: pcVar28[1] = '\0';
4791: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
4792: *pcVar28 = cVar10;
4793: pcVar28[1] = '\0';
4794: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
4795: }
4796: uVar11 = (ulong)puVar4[0xf0];
4797: iVar18 = iVar18 + 0x40;
4798: uVar14 = uVar11;
4799: }
4800: else {
4801: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
4802: pcVar27 = pcVar28;
4803: }
4804: pcVar26 = pcVar27;
4805: iVar17 = iVar18;
4806: if (0x2ef < (int)uVar31) {
4807: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
4808: if (iVar17 < 0) {
4809: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
4810: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
4811: cVar10 = (char)uVar14;
4812: cVar25 = (char)(uVar14 >> 8);
4813: cVar24 = (char)(uVar14 >> 0x10);
4814: cVar23 = (char)(uVar14 >> 0x18);
4815: cVar33 = (char)(uVar11 >> 0x20);
4816: cVar20 = (char)(uVar11 >> 0x28);
4817: cVar21 = (char)(uVar11 >> 0x30);
4818: cVar22 = (char)(uVar11 >> 0x38);
4819: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
4820: pcVar27[7] = cVar10;
4821: pcVar26 = pcVar27 + 8;
4822: *pcVar27 = cVar22;
4823: pcVar27[1] = cVar21;
4824: pcVar27[2] = cVar20;
4825: pcVar27[3] = cVar33;
4826: pcVar27[4] = cVar23;
4827: pcVar27[5] = cVar24;
4828: pcVar27[6] = cVar25;
4829: }
4830: else {
4831: pcVar27[1] = '\0';
4832: *pcVar27 = cVar22;
4833: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4834: *pcVar27 = cVar21;
4835: pcVar27[1] = '\0';
4836: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
4837: *pcVar27 = cVar20;
4838: pcVar27[1] = '\0';
4839: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
4840: *pcVar27 = cVar33;
4841: pcVar27[1] = '\0';
4842: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
4843: *pcVar27 = cVar23;
4844: pcVar27[1] = '\0';
4845: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
4846: *pcVar27 = cVar24;
4847: pcVar27[1] = '\0';
4848: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
4849: *pcVar27 = cVar25;
4850: pcVar27[1] = '\0';
4851: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
4852: *pcVar27 = cVar10;
4853: pcVar27[1] = '\0';
4854: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
4855: }
4856: iVar17 = iVar17 + 0x40;
4857: uVar11 = (ulong)puVar4[0xf0];
4858: }
4859: else {
4860: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
4861: }
4862: }
4863: }
4864: uVar16 = uVar31 - 0xf0 & 0xff;
4865: }
4866: LAB_0010af9c:
4867: uVar31 = uVar19 & (int)(1 << ((byte)uVar35 & 0x3f)) - 1U |
4868: puVar4[(int)(uVar16 + uVar35)] << ((byte)uVar35 & 0x1f);
4869: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar16 + uVar35) + 0x400) + uVar35;
4870: iVar18 = iVar17 - iVar29;
4871: if (iVar18 < 0) {
4872: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
4873: uVar11 << ((byte)iVar17 & 0x3f);
4874: cVar10 = (char)uVar11;
4875: cVar25 = (char)(uVar11 >> 8);
4876: cVar24 = (char)(uVar11 >> 0x10);
4877: cVar33 = (char)(uVar11 >> 0x18);
4878: cVar20 = (char)(uVar11 >> 0x20);
4879: cVar21 = (char)(uVar11 >> 0x28);
4880: cVar22 = (char)(uVar11 >> 0x30);
4881: cVar23 = (char)(uVar11 >> 0x38);
4882: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4883: pcVar26[7] = cVar10;
4884: pcVar28 = pcVar26 + 8;
4885: *pcVar26 = cVar23;
4886: pcVar26[1] = cVar22;
4887: pcVar26[2] = cVar21;
4888: pcVar26[3] = cVar20;
4889: pcVar26[4] = cVar33;
4890: pcVar26[5] = cVar24;
4891: pcVar26[6] = cVar25;
4892: }
4893: else {
4894: pcVar26[1] = '\0';
4895: *pcVar26 = cVar23;
4896: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4897: *pcVar26 = cVar22;
4898: pcVar26[1] = '\0';
4899: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4900: *pcVar26 = cVar21;
4901: pcVar26[1] = '\0';
4902: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4903: *pcVar26 = cVar20;
4904: pcVar26[1] = '\0';
4905: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4906: *pcVar26 = cVar33;
4907: pcVar26[1] = '\0';
4908: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
4909: *pcVar26 = cVar24;
4910: pcVar26[1] = '\0';
4911: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4912: *pcVar26 = cVar25;
4913: pcVar26[1] = '\0';
4914: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
4915: *pcVar26 = cVar10;
4916: pcVar26[1] = '\0';
4917: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4918: }
4919: sVar1 = psVar5[0x37];
4920: uVar11 = SEXT48((int)uVar31);
4921: iVar17 = iVar18 + 0x40;
4922: pcVar26 = pcVar28;
4923: }
4924: else {
4925: sVar1 = psVar5[0x37];
4926: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
4927: iVar17 = iVar18;
4928: }
4929: uVar31 = SEXT24(sVar1);
4930: pcVar28 = pcVar26;
4931: if (sVar1 == 0) goto LAB_0010afea;
4932: uVar16 = (int)uVar31 >> 0x1f;
4933: uVar35 = uVar31 + uVar16;
4934: uVar31 = 0;
4935: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar35)];
4936: iVar29 = iVar17;
4937: LAB_0010b562:
4938: uVar16 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
4939: puVar4[(int)(uVar31 + uVar19)] << ((byte)uVar19 & 0x1f);
4940: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(uVar31 + uVar19) + 0x400) + uVar19;
4941: iVar17 = iVar29 - iVar18;
4942: if (iVar17 < 0) {
4943: uVar11 = (long)((int)uVar16 >> (-(char)iVar17 & 0x1fU)) |
4944: uVar11 << ((byte)iVar29 & 0x3f);
4945: cVar10 = (char)uVar11;
4946: cVar23 = (char)(uVar11 >> 8);
4947: cVar22 = (char)(uVar11 >> 0x10);
4948: cVar21 = (char)(uVar11 >> 0x18);
4949: cVar20 = (char)(uVar11 >> 0x20);
4950: cVar33 = (char)(uVar11 >> 0x28);
4951: cVar24 = (char)(uVar11 >> 0x30);
4952: cVar25 = (char)(uVar11 >> 0x38);
4953: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
4954: pcVar26[7] = cVar10;
4955: pcVar28 = pcVar26 + 8;
4956: *pcVar26 = cVar25;
4957: pcVar26[1] = cVar24;
4958: pcVar26[2] = cVar33;
4959: pcVar26[3] = cVar20;
4960: pcVar26[4] = cVar21;
4961: pcVar26[5] = cVar22;
4962: pcVar26[6] = cVar23;
4963: }
4964: else {
4965: pcVar26[1] = '\0';
4966: *pcVar26 = cVar25;
4967: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
4968: *pcVar26 = cVar24;
4969: pcVar26[1] = '\0';
4970: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
4971: *pcVar26 = cVar33;
4972: pcVar26[1] = '\0';
4973: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
4974: *pcVar26 = cVar20;
4975: pcVar26[1] = '\0';
4976: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
4977: *pcVar26 = cVar21;
4978: pcVar26[1] = '\0';
4979: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
4980: *pcVar26 = cVar22;
4981: pcVar26[1] = '\0';
4982: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
4983: *pcVar26 = cVar23;
4984: pcVar26[1] = '\0';
4985: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
4986: *pcVar26 = cVar10;
4987: pcVar26[1] = '\0';
4988: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
4989: }
4990: iVar17 = iVar17 + 0x40;
4991: uVar11 = SEXT48((int)uVar16);
4992: }
4993: else {
4994: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar16;
4995: pcVar28 = pcVar26;
4996: }
4997: uVar16 = SEXT24(psVar5[0x3e]);
4998: pcVar26 = pcVar28;
4999: if (psVar5[0x3e] != 0) {
5000: uVar31 = (int)uVar16 >> 0x1f;
5001: uVar35 = uVar16 + uVar31;
5002: uVar16 = 0;
5003: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar35)];
5004: iVar29 = iVar17;
5005: goto LAB_0010b08c;
5006: }
5007: LAB_0010b4b0:
5008: uVar16 = uVar16 + 0x10;
5009: }
5010: else {
5011: uVar31 = iVar29 + (iVar29 >> 0x1f);
5012: bVar9 = (&DAT_0016c7a0)[(int)(iVar29 >> 0x1f ^ uVar31)];
5013: uVar31 = uVar31 & (int)(1 << (bVar9 & 0x3f)) - 1U |
5014: puVar4[(int)(iVar18 + (uint)bVar9)] << (bVar9 & 0x1f);
5015: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + (uint)bVar9) + 0x400) +
5016: (uint)bVar9;
5017: iVar17 = iVar17 - iVar29;
5018: if (iVar17 < 0) {
5019: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) | uVar11 << (bVar15 & 0x3f);
5020: cVar10 = (char)uVar11;
5021: cVar23 = (char)(uVar11 >> 8);
5022: cVar24 = (char)(uVar11 >> 0x10);
5023: cVar25 = (char)(uVar11 >> 0x18);
5024: cVar33 = (char)(uVar11 >> 0x20);
5025: cVar21 = (char)(uVar11 >> 0x28);
5026: cVar20 = (char)(uVar11 >> 0x30);
5027: cVar22 = (char)(uVar11 >> 0x38);
5028: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
5029: pcVar28[7] = cVar10;
5030: pcVar26 = pcVar28 + 8;
5031: *pcVar28 = cVar22;
5032: pcVar28[1] = cVar20;
5033: pcVar28[2] = cVar21;
5034: pcVar28[3] = cVar33;
5035: pcVar28[4] = cVar25;
5036: pcVar28[5] = cVar24;
5037: pcVar28[6] = cVar23;
5038: }
5039: else {
5040: pcVar28[1] = '\0';
5041: *pcVar28 = cVar22;
5042: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5043: *pcVar28 = cVar20;
5044: pcVar28[1] = '\0';
5045: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
5046: *pcVar28 = cVar21;
5047: pcVar28[1] = '\0';
5048: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
5049: *pcVar28 = cVar33;
5050: pcVar28[1] = '\0';
5051: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
5052: *pcVar28 = cVar25;
5053: pcVar28[1] = '\0';
5054: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
5055: *pcVar28 = cVar24;
5056: pcVar28[1] = '\0';
5057: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
5058: *pcVar28 = cVar23;
5059: pcVar28[1] = '\0';
5060: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
5061: *pcVar28 = cVar10;
5062: pcVar28[1] = '\0';
5063: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
5064: }
5065: iVar17 = iVar17 + 0x40;
5066: uVar11 = SEXT48((int)uVar31);
5067: pcVar28 = pcVar26;
5068: }
5069: else {
5070: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
5071: }
5072: iVar32 = (int)psVar5[0x13];
5073: if (psVar5[0x13] != 0) {
5074: iVar18 = 0;
5075: uVar31 = (iVar32 >> 0x1f) + iVar32;
5076: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(iVar32 >> 0x1f ^ uVar31)];
5077: iVar32 = iVar17;
5078: goto LAB_00109d24;
5079: }
5080: LAB_0010c760:
5081: sVar1 = psVar5[0x1a];
5082: iVar29 = iVar32 + 0x10;
5083: pcVar26 = pcVar28;
5084: if (sVar1 != 0) {
5085: uVar16 = (int)sVar1 >> 0x1f;
5086: uVar31 = (int)sVar1 + uVar16;
5087: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5088: iVar18 = iVar17;
5089: if (0xff < iVar29) {
5090: iVar29 = iVar32 + -0xf0;
5091: iVar18 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5092: if (iVar18 < 0) {
5093: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5094: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
5095: cVar10 = (char)uVar14;
5096: cVar33 = (char)(uVar14 >> 8);
5097: cVar24 = (char)(uVar14 >> 0x10);
5098: cVar23 = (char)(uVar14 >> 0x18);
5099: cVar22 = (char)(uVar11 >> 0x20);
5100: cVar21 = (char)(uVar11 >> 0x28);
5101: cVar20 = (char)(uVar11 >> 0x30);
5102: cVar25 = (char)(uVar11 >> 0x38);
5103: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5104: pcVar28[7] = cVar10;
5105: pcVar26 = pcVar28 + 8;
5106: *pcVar28 = cVar25;
5107: pcVar28[1] = cVar20;
5108: pcVar28[2] = cVar21;
5109: pcVar28[3] = cVar22;
5110: pcVar28[4] = cVar23;
5111: pcVar28[5] = cVar24;
5112: pcVar28[6] = cVar33;
5113: }
5114: else {
5115: pcVar28[1] = '\0';
5116: *pcVar28 = cVar25;
5117: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5118: *pcVar28 = cVar20;
5119: pcVar28[1] = '\0';
5120: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
5121: *pcVar28 = cVar21;
5122: pcVar28[1] = '\0';
5123: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
5124: *pcVar28 = cVar22;
5125: pcVar28[1] = '\0';
5126: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
5127: *pcVar28 = cVar23;
5128: pcVar28[1] = '\0';
5129: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
5130: *pcVar28 = cVar24;
5131: pcVar28[1] = '\0';
5132: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
5133: *pcVar28 = cVar33;
5134: pcVar28[1] = '\0';
5135: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
5136: *pcVar28 = cVar10;
5137: pcVar28[1] = '\0';
5138: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
5139: }
5140: uVar11 = (ulong)puVar4[0xf0];
5141: pcVar28 = pcVar26;
5142: iVar18 = iVar18 + 0x40;
5143: }
5144: else {
5145: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5146: }
5147: }
5148: goto LAB_00109d8f;
5149: }
5150: LAB_0010ca10:
5151: sVar1 = psVar5[0x21];
5152: iVar18 = iVar29 + 0x10;
5153: if (sVar1 != 0) {
5154: uVar16 = (int)sVar1 >> 0x1f;
5155: uVar31 = (int)sVar1 + uVar16;
5156: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5157: iVar32 = iVar17;
5158: if (0xff < iVar18) {
5159: iVar18 = iVar29 + -0xf0;
5160: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5161: if (iVar32 < 0) {
5162: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5163: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5164: cVar10 = (char)uVar14;
5165: cVar22 = (char)(uVar14 >> 8);
5166: cVar21 = (char)(uVar14 >> 0x10);
5167: cVar20 = (char)(uVar14 >> 0x18);
5168: cVar33 = (char)(uVar11 >> 0x20);
5169: cVar23 = (char)(uVar11 >> 0x28);
5170: cVar25 = (char)(uVar11 >> 0x30);
5171: cVar24 = (char)(uVar11 >> 0x38);
5172: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5173: pcVar26[7] = cVar10;
5174: pcVar28 = pcVar26 + 8;
5175: *pcVar26 = cVar24;
5176: pcVar26[1] = cVar25;
5177: pcVar26[2] = cVar23;
5178: pcVar26[3] = cVar33;
5179: pcVar26[4] = cVar20;
5180: pcVar26[5] = cVar21;
5181: pcVar26[6] = cVar22;
5182: }
5183: else {
5184: pcVar26[1] = '\0';
5185: *pcVar26 = cVar24;
5186: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5187: *pcVar26 = cVar25;
5188: pcVar26[1] = '\0';
5189: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
5190: *pcVar26 = cVar23;
5191: pcVar26[1] = '\0';
5192: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
5193: *pcVar26 = cVar33;
5194: pcVar26[1] = '\0';
5195: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
5196: *pcVar26 = cVar20;
5197: pcVar26[1] = '\0';
5198: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
5199: *pcVar26 = cVar21;
5200: pcVar26[1] = '\0';
5201: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
5202: *pcVar26 = cVar22;
5203: pcVar26[1] = '\0';
5204: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
5205: *pcVar26 = cVar10;
5206: pcVar26[1] = '\0';
5207: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
5208: }
5209: uVar11 = (ulong)puVar4[0xf0];
5210: pcVar26 = pcVar28;
5211: iVar32 = iVar32 + 0x40;
5212: }
5213: else {
5214: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5215: }
5216: }
5217: goto LAB_00109dfa;
5218: }
5219: LAB_0010c898:
5220: sVar1 = psVar5[0x28];
5221: iVar29 = iVar18 + 0x10;
5222: if (sVar1 != 0) {
5223: uVar16 = (int)sVar1 >> 0x1f;
5224: uVar31 = (int)sVar1 + uVar16;
5225: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5226: iVar32 = iVar17;
5227: if (0xff < iVar29) {
5228: iVar29 = iVar18 + -0xf0;
5229: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5230: if (iVar32 < 0) {
5231: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5232: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5233: cVar10 = (char)uVar14;
5234: cVar25 = (char)(uVar14 >> 8);
5235: cVar24 = (char)(uVar14 >> 0x10);
5236: cVar23 = (char)(uVar14 >> 0x18);
5237: cVar22 = (char)(uVar11 >> 0x20);
5238: cVar33 = (char)(uVar11 >> 0x28);
5239: cVar20 = (char)(uVar11 >> 0x30);
5240: cVar21 = (char)(uVar11 >> 0x38);
5241: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5242: pcVar26[7] = cVar10;
5243: pcVar28 = pcVar26 + 8;
5244: *pcVar26 = cVar21;
5245: pcVar26[1] = cVar20;
5246: pcVar26[2] = cVar33;
5247: pcVar26[3] = cVar22;
5248: pcVar26[4] = cVar23;
5249: pcVar26[5] = cVar24;
5250: pcVar26[6] = cVar25;
5251: }
5252: else {
5253: pcVar26[1] = '\0';
5254: *pcVar26 = cVar21;
5255: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5256: *pcVar26 = cVar20;
5257: pcVar26[1] = '\0';
5258: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
5259: *pcVar26 = cVar33;
5260: pcVar26[1] = '\0';
5261: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
5262: *pcVar26 = cVar22;
5263: pcVar26[1] = '\0';
5264: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
5265: *pcVar26 = cVar23;
5266: pcVar26[1] = '\0';
5267: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
5268: *pcVar26 = cVar24;
5269: pcVar26[1] = '\0';
5270: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
5271: *pcVar26 = cVar25;
5272: pcVar26[1] = '\0';
5273: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
5274: *pcVar26 = cVar10;
5275: pcVar26[1] = '\0';
5276: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
5277: }
5278: uVar11 = (ulong)puVar4[0xf0];
5279: pcVar26 = pcVar28;
5280: iVar32 = iVar32 + 0x40;
5281: }
5282: else {
5283: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5284: }
5285: }
5286: goto LAB_00109e64;
5287: }
5288: LAB_0010c9a8:
5289: sVar1 = psVar5[0x30];
5290: iVar18 = iVar29 + 0x10;
5291: pcVar28 = pcVar26;
5292: if (sVar1 != 0) {
5293: uVar16 = (int)sVar1 >> 0x1f;
5294: uVar31 = (int)sVar1 + uVar16;
5295: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5296: iVar32 = iVar17;
5297: if (0xff < iVar18) {
5298: iVar18 = iVar29 + -0xf0;
5299: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5300: if (iVar32 < 0) {
5301: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5302: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5303: cVar10 = (char)uVar14;
5304: cVar23 = (char)(uVar14 >> 8);
5305: cVar22 = (char)(uVar14 >> 0x10);
5306: cVar21 = (char)(uVar14 >> 0x18);
5307: cVar20 = (char)(uVar11 >> 0x20);
5308: cVar33 = (char)(uVar11 >> 0x28);
5309: cVar24 = (char)(uVar11 >> 0x30);
5310: cVar25 = (char)(uVar11 >> 0x38);
5311: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5312: pcVar26[7] = cVar10;
5313: pcVar28 = pcVar26 + 8;
5314: *pcVar26 = cVar25;
5315: pcVar26[1] = cVar24;
5316: pcVar26[2] = cVar33;
5317: pcVar26[3] = cVar20;
5318: pcVar26[4] = cVar21;
5319: pcVar26[5] = cVar22;
5320: pcVar26[6] = cVar23;
5321: }
5322: else {
5323: pcVar26[1] = '\0';
5324: *pcVar26 = cVar25;
5325: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5326: *pcVar26 = cVar24;
5327: pcVar26[1] = '\0';
5328: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
5329: *pcVar26 = cVar33;
5330: pcVar26[1] = '\0';
5331: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
5332: *pcVar26 = cVar20;
5333: pcVar26[1] = '\0';
5334: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
5335: *pcVar26 = cVar21;
5336: pcVar26[1] = '\0';
5337: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
5338: *pcVar26 = cVar22;
5339: pcVar26[1] = '\0';
5340: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
5341: *pcVar26 = cVar23;
5342: pcVar26[1] = '\0';
5343: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
5344: *pcVar26 = cVar10;
5345: pcVar26[1] = '\0';
5346: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
5347: }
5348: uVar11 = (ulong)puVar4[0xf0];
5349: pcVar26 = pcVar28;
5350: iVar32 = iVar32 + 0x40;
5351: }
5352: else {
5353: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5354: }
5355: }
5356: goto LAB_00109ece;
5357: }
5358: LAB_0010bc28:
5359: sVar1 = psVar5[0x29];
5360: iVar29 = iVar18 + 0x10;
5361: if (sVar1 != 0) {
5362: uVar16 = (int)sVar1 >> 0x1f;
5363: uVar31 = (int)sVar1 + uVar16;
5364: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5365: iVar32 = iVar17;
5366: if (0xff < iVar29) {
5367: iVar29 = iVar18 + -0xf0;
5368: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5369: if (iVar32 < 0) {
5370: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5371: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5372: cVar10 = (char)uVar14;
5373: cVar24 = (char)(uVar14 >> 8);
5374: cVar25 = (char)(uVar14 >> 0x10);
5375: cVar23 = (char)(uVar14 >> 0x18);
5376: cVar22 = (char)(uVar11 >> 0x20);
5377: cVar21 = (char)(uVar11 >> 0x28);
5378: cVar20 = (char)(uVar11 >> 0x30);
5379: cVar33 = (char)(uVar11 >> 0x38);
5380: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5381: pcVar28[7] = cVar10;
5382: pcVar26 = pcVar28 + 8;
5383: *pcVar28 = cVar33;
5384: pcVar28[1] = cVar20;
5385: pcVar28[2] = cVar21;
5386: pcVar28[3] = cVar22;
5387: pcVar28[4] = cVar23;
5388: pcVar28[5] = cVar25;
5389: pcVar28[6] = cVar24;
5390: }
5391: else {
5392: pcVar28[1] = '\0';
5393: *pcVar28 = cVar33;
5394: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5395: *pcVar28 = cVar20;
5396: pcVar28[1] = '\0';
5397: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
5398: *pcVar28 = cVar21;
5399: pcVar28[1] = '\0';
5400: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
5401: *pcVar28 = cVar22;
5402: pcVar28[1] = '\0';
5403: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
5404: *pcVar28 = cVar23;
5405: pcVar28[1] = '\0';
5406: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
5407: *pcVar28 = cVar25;
5408: pcVar28[1] = '\0';
5409: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
5410: *pcVar28 = cVar24;
5411: pcVar28[1] = '\0';
5412: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
5413: *pcVar28 = cVar10;
5414: pcVar28[1] = '\0';
5415: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
5416: }
5417: uVar11 = (ulong)puVar4[0xf0];
5418: pcVar28 = pcVar26;
5419: iVar32 = iVar32 + 0x40;
5420: }
5421: else {
5422: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5423: }
5424: }
5425: goto LAB_00109f38;
5426: }
5427: LAB_0010c700:
5428: sVar1 = psVar5[0x22];
5429: iVar18 = iVar29 + 0x10;
5430: pcVar26 = pcVar28;
5431: if (sVar1 != 0) {
5432: uVar16 = (int)sVar1 >> 0x1f;
5433: uVar31 = (int)sVar1 + uVar16;
5434: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5435: iVar32 = iVar17;
5436: if (0xff < iVar18) {
5437: iVar18 = iVar29 + -0xf0;
5438: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5439: if (iVar32 < 0) {
5440: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5441: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5442: cVar10 = (char)uVar14;
5443: cVar25 = (char)(uVar14 >> 8);
5444: cVar24 = (char)(uVar14 >> 0x10);
5445: cVar23 = (char)(uVar14 >> 0x18);
5446: cVar22 = (char)(uVar11 >> 0x20);
5447: cVar21 = (char)(uVar11 >> 0x28);
5448: cVar20 = (char)(uVar11 >> 0x30);
5449: cVar33 = (char)(uVar11 >> 0x38);
5450: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5451: pcVar28[7] = cVar10;
5452: pcVar26 = pcVar28 + 8;
5453: *pcVar28 = cVar33;
5454: pcVar28[1] = cVar20;
5455: pcVar28[2] = cVar21;
5456: pcVar28[3] = cVar22;
5457: pcVar28[4] = cVar23;
5458: pcVar28[5] = cVar24;
5459: pcVar28[6] = cVar25;
5460: }
5461: else {
5462: pcVar28[1] = '\0';
5463: *pcVar28 = cVar33;
5464: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5465: *pcVar28 = cVar20;
5466: pcVar28[1] = '\0';
5467: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
5468: *pcVar28 = cVar21;
5469: pcVar28[1] = '\0';
5470: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
5471: *pcVar28 = cVar22;
5472: pcVar28[1] = '\0';
5473: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
5474: *pcVar28 = cVar23;
5475: pcVar28[1] = '\0';
5476: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
5477: *pcVar28 = cVar24;
5478: pcVar28[1] = '\0';
5479: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
5480: *pcVar28 = cVar25;
5481: pcVar28[1] = '\0';
5482: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
5483: *pcVar28 = cVar10;
5484: pcVar28[1] = '\0';
5485: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
5486: }
5487: uVar11 = (ulong)puVar4[0xf0];
5488: pcVar28 = pcVar26;
5489: iVar32 = iVar32 + 0x40;
5490: }
5491: else {
5492: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5493: }
5494: }
5495: goto LAB_00109fa2;
5496: }
5497: LAB_0010c580:
5498: sVar1 = psVar5[0x1b];
5499: iVar29 = iVar18 + 0x10;
5500: if (sVar1 != 0) {
5501: uVar16 = (int)sVar1 >> 0x1f;
5502: uVar31 = (int)sVar1 + uVar16;
5503: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5504: iVar32 = iVar17;
5505: if (0xff < iVar29) {
5506: iVar29 = iVar18 + -0xf0;
5507: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5508: if (iVar32 < 0) {
5509: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5510: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5511: cVar10 = (char)uVar14;
5512: cVar33 = (char)(uVar14 >> 8);
5513: cVar20 = (char)(uVar14 >> 0x10);
5514: cVar21 = (char)(uVar14 >> 0x18);
5515: cVar22 = (char)(uVar11 >> 0x20);
5516: cVar25 = (char)(uVar11 >> 0x28);
5517: cVar24 = (char)(uVar11 >> 0x30);
5518: cVar23 = (char)(uVar11 >> 0x38);
5519: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5520: pcVar26[7] = cVar10;
5521: pcVar28 = pcVar26 + 8;
5522: *pcVar26 = cVar23;
5523: pcVar26[1] = cVar24;
5524: pcVar26[2] = cVar25;
5525: pcVar26[3] = cVar22;
5526: pcVar26[4] = cVar21;
5527: pcVar26[5] = cVar20;
5528: pcVar26[6] = cVar33;
5529: }
5530: else {
5531: pcVar26[1] = '\0';
5532: *pcVar26 = cVar23;
5533: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5534: *pcVar26 = cVar24;
5535: pcVar26[1] = '\0';
5536: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
5537: *pcVar26 = cVar25;
5538: pcVar26[1] = '\0';
5539: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
5540: *pcVar26 = cVar22;
5541: pcVar26[1] = '\0';
5542: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
5543: *pcVar26 = cVar21;
5544: pcVar26[1] = '\0';
5545: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
5546: *pcVar26 = cVar20;
5547: pcVar26[1] = '\0';
5548: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
5549: *pcVar26 = cVar33;
5550: pcVar26[1] = '\0';
5551: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
5552: *pcVar26 = cVar10;
5553: pcVar26[1] = '\0';
5554: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
5555: }
5556: uVar11 = (ulong)puVar4[0xf0];
5557: pcVar26 = pcVar28;
5558: iVar32 = iVar32 + 0x40;
5559: }
5560: else {
5561: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5562: }
5563: }
5564: goto LAB_0010a00c;
5565: }
5566: LAB_0010c640:
5567: sVar1 = psVar5[0x14];
5568: iVar18 = iVar29 + 0x10;
5569: pcVar28 = pcVar26;
5570: if (sVar1 != 0) {
5571: uVar16 = (int)sVar1 >> 0x1f;
5572: uVar31 = (int)sVar1 + uVar16;
5573: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5574: iVar32 = iVar17;
5575: if (0xff < iVar18) {
5576: iVar18 = iVar29 + -0xf0;
5577: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5578: if (iVar32 < 0) {
5579: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5580: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5581: cVar10 = (char)uVar14;
5582: cVar33 = (char)(uVar14 >> 8);
5583: cVar20 = (char)(uVar14 >> 0x10);
5584: cVar21 = (char)(uVar14 >> 0x18);
5585: cVar22 = (char)(uVar11 >> 0x20);
5586: cVar23 = (char)(uVar11 >> 0x28);
5587: cVar24 = (char)(uVar11 >> 0x30);
5588: cVar25 = (char)(uVar11 >> 0x38);
5589: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5590: pcVar26[7] = cVar10;
5591: pcVar28 = pcVar26 + 8;
5592: *pcVar26 = cVar25;
5593: pcVar26[1] = cVar24;
5594: pcVar26[2] = cVar23;
5595: pcVar26[3] = cVar22;
5596: pcVar26[4] = cVar21;
5597: pcVar26[5] = cVar20;
5598: pcVar26[6] = cVar33;
5599: }
5600: else {
5601: pcVar26[1] = '\0';
5602: *pcVar26 = cVar25;
5603: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5604: *pcVar26 = cVar24;
5605: pcVar26[1] = '\0';
5606: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
5607: *pcVar26 = cVar23;
5608: pcVar26[1] = '\0';
5609: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
5610: *pcVar26 = cVar22;
5611: pcVar26[1] = '\0';
5612: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
5613: *pcVar26 = cVar21;
5614: pcVar26[1] = '\0';
5615: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
5616: *pcVar26 = cVar20;
5617: pcVar26[1] = '\0';
5618: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
5619: *pcVar26 = cVar33;
5620: pcVar26[1] = '\0';
5621: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
5622: *pcVar26 = cVar10;
5623: pcVar26[1] = '\0';
5624: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
5625: }
5626: uVar11 = (ulong)puVar4[0xf0];
5627: pcVar26 = pcVar28;
5628: iVar32 = iVar32 + 0x40;
5629: }
5630: else {
5631: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5632: }
5633: }
5634: goto LAB_0010a076;
5635: }
5636: LAB_0010c4b8:
5637: sVar1 = psVar5[0xd];
5638: iVar29 = iVar18 + 0x10;
5639: if (sVar1 != 0) {
5640: uVar16 = (int)sVar1 >> 0x1f;
5641: uVar31 = (int)sVar1 + uVar16;
5642: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5643: iVar32 = iVar17;
5644: if (0xff < iVar29) {
5645: iVar29 = iVar18 + -0xf0;
5646: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5647: if (iVar32 < 0) {
5648: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5649: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5650: cVar10 = (char)uVar14;
5651: cVar33 = (char)(uVar14 >> 8);
5652: cVar20 = (char)(uVar14 >> 0x10);
5653: cVar21 = (char)(uVar14 >> 0x18);
5654: cVar22 = (char)(uVar11 >> 0x20);
5655: cVar23 = (char)(uVar11 >> 0x28);
5656: cVar24 = (char)(uVar11 >> 0x30);
5657: cVar25 = (char)(uVar11 >> 0x38);
5658: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5659: pcVar28[7] = cVar10;
5660: pcVar26 = pcVar28 + 8;
5661: *pcVar28 = cVar25;
5662: pcVar28[1] = cVar24;
5663: pcVar28[2] = cVar23;
5664: pcVar28[3] = cVar22;
5665: pcVar28[4] = cVar21;
5666: pcVar28[5] = cVar20;
5667: pcVar28[6] = cVar33;
5668: }
5669: else {
5670: pcVar28[1] = '\0';
5671: *pcVar28 = cVar25;
5672: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5673: *pcVar28 = cVar24;
5674: pcVar28[1] = '\0';
5675: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
5676: *pcVar28 = cVar23;
5677: pcVar28[1] = '\0';
5678: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
5679: *pcVar28 = cVar22;
5680: pcVar28[1] = '\0';
5681: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
5682: *pcVar28 = cVar21;
5683: pcVar28[1] = '\0';
5684: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
5685: *pcVar28 = cVar20;
5686: pcVar28[1] = '\0';
5687: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
5688: *pcVar28 = cVar33;
5689: pcVar28[1] = '\0';
5690: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
5691: *pcVar28 = cVar10;
5692: pcVar28[1] = '\0';
5693: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
5694: }
5695: uVar11 = (ulong)puVar4[0xf0];
5696: pcVar28 = pcVar26;
5697: iVar32 = iVar32 + 0x40;
5698: }
5699: else {
5700: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5701: }
5702: }
5703: goto LAB_0010a0e0;
5704: }
5705: LAB_0010c6a0:
5706: sVar1 = psVar5[6];
5707: iVar18 = iVar29 + 0x10;
5708: pcVar26 = pcVar28;
5709: if (sVar1 != 0) {
5710: uVar16 = (int)sVar1 >> 0x1f;
5711: uVar31 = (int)sVar1 + uVar16;
5712: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5713: iVar32 = iVar17;
5714: if (0xff < iVar18) {
5715: iVar18 = iVar29 + -0xf0;
5716: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5717: if (iVar32 < 0) {
5718: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5719: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5720: cVar10 = (char)uVar14;
5721: cVar33 = (char)(uVar14 >> 8);
5722: cVar20 = (char)(uVar14 >> 0x10);
5723: cVar21 = (char)(uVar14 >> 0x18);
5724: cVar22 = (char)(uVar11 >> 0x20);
5725: cVar23 = (char)(uVar11 >> 0x28);
5726: cVar24 = (char)(uVar11 >> 0x30);
5727: cVar25 = (char)(uVar11 >> 0x38);
5728: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5729: pcVar28[7] = cVar10;
5730: pcVar26 = pcVar28 + 8;
5731: *pcVar28 = cVar25;
5732: pcVar28[1] = cVar24;
5733: pcVar28[2] = cVar23;
5734: pcVar28[3] = cVar22;
5735: pcVar28[4] = cVar21;
5736: pcVar28[5] = cVar20;
5737: pcVar28[6] = cVar33;
5738: }
5739: else {
5740: pcVar28[1] = '\0';
5741: *pcVar28 = cVar25;
5742: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5743: *pcVar28 = cVar24;
5744: pcVar28[1] = '\0';
5745: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
5746: *pcVar28 = cVar23;
5747: pcVar28[1] = '\0';
5748: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
5749: *pcVar28 = cVar22;
5750: pcVar28[1] = '\0';
5751: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
5752: *pcVar28 = cVar21;
5753: pcVar28[1] = '\0';
5754: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
5755: *pcVar28 = cVar20;
5756: pcVar28[1] = '\0';
5757: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
5758: *pcVar28 = cVar33;
5759: pcVar28[1] = '\0';
5760: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
5761: *pcVar28 = cVar10;
5762: pcVar28[1] = '\0';
5763: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
5764: }
5765: uVar11 = (ulong)puVar4[0xf0];
5766: pcVar28 = pcVar26;
5767: iVar32 = iVar32 + 0x40;
5768: }
5769: else {
5770: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5771: }
5772: }
5773: goto LAB_0010a14a;
5774: }
5775: LAB_0010c520:
5776: sVar1 = psVar5[7];
5777: iVar29 = iVar18 + 0x10;
5778: if (sVar1 != 0) {
5779: uVar16 = (int)sVar1 >> 0x1f;
5780: uVar31 = (int)sVar1 + uVar16;
5781: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5782: iVar32 = iVar17;
5783: if (0xff < iVar29) {
5784: iVar29 = iVar18 + -0xf0;
5785: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5786: if (iVar32 < 0) {
5787: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5788: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5789: cVar10 = (char)uVar14;
5790: cVar25 = (char)(uVar14 >> 8);
5791: cVar24 = (char)(uVar14 >> 0x10);
5792: cVar23 = (char)(uVar14 >> 0x18);
5793: cVar22 = (char)(uVar11 >> 0x20);
5794: cVar21 = (char)(uVar11 >> 0x28);
5795: cVar20 = (char)(uVar11 >> 0x30);
5796: cVar33 = (char)(uVar11 >> 0x38);
5797: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5798: pcVar26[7] = cVar10;
5799: pcVar28 = pcVar26 + 8;
5800: *pcVar26 = cVar33;
5801: pcVar26[1] = cVar20;
5802: pcVar26[2] = cVar21;
5803: pcVar26[3] = cVar22;
5804: pcVar26[4] = cVar23;
5805: pcVar26[5] = cVar24;
5806: pcVar26[6] = cVar25;
5807: }
5808: else {
5809: pcVar26[1] = '\0';
5810: *pcVar26 = cVar33;
5811: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5812: *pcVar26 = cVar20;
5813: pcVar26[1] = '\0';
5814: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
5815: *pcVar26 = cVar21;
5816: pcVar26[1] = '\0';
5817: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
5818: *pcVar26 = cVar22;
5819: pcVar26[1] = '\0';
5820: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
5821: *pcVar26 = cVar23;
5822: pcVar26[1] = '\0';
5823: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
5824: *pcVar26 = cVar24;
5825: pcVar26[1] = '\0';
5826: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
5827: *pcVar26 = cVar25;
5828: pcVar26[1] = '\0';
5829: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
5830: *pcVar26 = cVar10;
5831: pcVar26[1] = '\0';
5832: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
5833: }
5834: uVar11 = (ulong)puVar4[0xf0];
5835: pcVar26 = pcVar28;
5836: iVar32 = iVar32 + 0x40;
5837: }
5838: else {
5839: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5840: }
5841: }
5842: goto LAB_0010a1b4;
5843: }
5844: LAB_0010c5e0:
5845: sVar1 = psVar5[0xe];
5846: iVar18 = iVar29 + 0x10;
5847: if (sVar1 != 0) {
5848: uVar16 = (int)sVar1 >> 0x1f;
5849: uVar31 = (int)sVar1 + uVar16;
5850: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5851: iVar32 = iVar17;
5852: if (0xff < iVar18) {
5853: iVar18 = iVar29 + -0xf0;
5854: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5855: if (iVar32 < 0) {
5856: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5857: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5858: cVar10 = (char)uVar14;
5859: cVar25 = (char)(uVar14 >> 8);
5860: cVar24 = (char)(uVar14 >> 0x10);
5861: cVar23 = (char)(uVar14 >> 0x18);
5862: cVar22 = (char)(uVar11 >> 0x20);
5863: cVar21 = (char)(uVar11 >> 0x28);
5864: cVar20 = (char)(uVar11 >> 0x30);
5865: cVar33 = (char)(uVar11 >> 0x38);
5866: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5867: pcVar26[7] = cVar10;
5868: pcVar28 = pcVar26 + 8;
5869: *pcVar26 = cVar33;
5870: pcVar26[1] = cVar20;
5871: pcVar26[2] = cVar21;
5872: pcVar26[3] = cVar22;
5873: pcVar26[4] = cVar23;
5874: pcVar26[5] = cVar24;
5875: pcVar26[6] = cVar25;
5876: }
5877: else {
5878: pcVar26[1] = '\0';
5879: *pcVar26 = cVar33;
5880: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5881: *pcVar26 = cVar20;
5882: pcVar26[1] = '\0';
5883: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
5884: *pcVar26 = cVar21;
5885: pcVar26[1] = '\0';
5886: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
5887: *pcVar26 = cVar22;
5888: pcVar26[1] = '\0';
5889: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
5890: *pcVar26 = cVar23;
5891: pcVar26[1] = '\0';
5892: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
5893: *pcVar26 = cVar24;
5894: pcVar26[1] = '\0';
5895: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
5896: *pcVar26 = cVar25;
5897: pcVar26[1] = '\0';
5898: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
5899: *pcVar26 = cVar10;
5900: pcVar26[1] = '\0';
5901: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
5902: }
5903: uVar11 = (ulong)puVar4[0xf0];
5904: pcVar26 = pcVar28;
5905: iVar32 = iVar32 + 0x40;
5906: }
5907: else {
5908: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5909: }
5910: }
5911: goto LAB_0010a21e;
5912: }
5913: LAB_0010b6f0:
5914: sVar1 = psVar5[0x15];
5915: iVar29 = iVar18 + 0x10;
5916: if (sVar1 != 0) {
5917: uVar16 = (int)sVar1 >> 0x1f;
5918: uVar31 = (int)sVar1 + uVar16;
5919: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5920: iVar32 = iVar17;
5921: if (0xff < iVar29) {
5922: iVar29 = iVar18 + -0xf0;
5923: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5924: if (iVar32 < 0) {
5925: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5926: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5927: cVar10 = (char)uVar14;
5928: cVar33 = (char)(uVar14 >> 8);
5929: cVar23 = (char)(uVar14 >> 0x10);
5930: cVar24 = (char)(uVar14 >> 0x18);
5931: cVar25 = (char)(uVar11 >> 0x20);
5932: cVar22 = (char)(uVar11 >> 0x28);
5933: cVar21 = (char)(uVar11 >> 0x30);
5934: cVar20 = (char)(uVar11 >> 0x38);
5935: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
5936: pcVar26[7] = cVar10;
5937: pcVar28 = pcVar26 + 8;
5938: *pcVar26 = cVar20;
5939: pcVar26[1] = cVar21;
5940: pcVar26[2] = cVar22;
5941: pcVar26[3] = cVar25;
5942: pcVar26[4] = cVar24;
5943: pcVar26[5] = cVar23;
5944: pcVar26[6] = cVar33;
5945: }
5946: else {
5947: pcVar26[1] = '\0';
5948: *pcVar26 = cVar20;
5949: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
5950: *pcVar26 = cVar21;
5951: pcVar26[1] = '\0';
5952: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
5953: *pcVar26 = cVar22;
5954: pcVar26[1] = '\0';
5955: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
5956: *pcVar26 = cVar25;
5957: pcVar26[1] = '\0';
5958: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
5959: *pcVar26 = cVar24;
5960: pcVar26[1] = '\0';
5961: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
5962: *pcVar26 = cVar23;
5963: pcVar26[1] = '\0';
5964: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
5965: *pcVar26 = cVar33;
5966: pcVar26[1] = '\0';
5967: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
5968: *pcVar26 = cVar10;
5969: pcVar26[1] = '\0';
5970: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
5971: }
5972: uVar11 = (ulong)puVar4[0xf0];
5973: pcVar26 = pcVar28;
5974: iVar32 = iVar32 + 0x40;
5975: }
5976: else {
5977: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
5978: }
5979: }
5980: goto LAB_0010a288;
5981: }
5982: LAB_0010ca70:
5983: sVar1 = psVar5[0x1c];
5984: iVar18 = iVar29 + 0x10;
5985: pcVar28 = pcVar26;
5986: if (sVar1 != 0) {
5987: uVar16 = (int)sVar1 >> 0x1f;
5988: uVar31 = (int)sVar1 + uVar16;
5989: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
5990: iVar32 = iVar17;
5991: if (0xff < iVar18) {
5992: iVar18 = iVar29 + -0xf0;
5993: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
5994: if (iVar32 < 0) {
5995: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
5996: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
5997: cVar10 = (char)uVar14;
5998: cVar25 = (char)(uVar14 >> 8);
5999: cVar24 = (char)(uVar14 >> 0x10);
6000: cVar23 = (char)(uVar14 >> 0x18);
6001: cVar22 = (char)(uVar11 >> 0x20);
6002: cVar21 = (char)(uVar11 >> 0x28);
6003: cVar20 = (char)(uVar11 >> 0x30);
6004: cVar33 = (char)(uVar11 >> 0x38);
6005: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6006: pcVar26[7] = cVar10;
6007: pcVar28 = pcVar26 + 8;
6008: *pcVar26 = cVar33;
6009: pcVar26[1] = cVar20;
6010: pcVar26[2] = cVar21;
6011: pcVar26[3] = cVar22;
6012: pcVar26[4] = cVar23;
6013: pcVar26[5] = cVar24;
6014: pcVar26[6] = cVar25;
6015: }
6016: else {
6017: pcVar26[1] = '\0';
6018: *pcVar26 = cVar33;
6019: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6020: *pcVar26 = cVar20;
6021: pcVar26[1] = '\0';
6022: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
6023: *pcVar26 = cVar21;
6024: pcVar26[1] = '\0';
6025: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
6026: *pcVar26 = cVar22;
6027: pcVar26[1] = '\0';
6028: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
6029: *pcVar26 = cVar23;
6030: pcVar26[1] = '\0';
6031: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
6032: *pcVar26 = cVar24;
6033: pcVar26[1] = '\0';
6034: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
6035: *pcVar26 = cVar25;
6036: pcVar26[1] = '\0';
6037: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
6038: *pcVar26 = cVar10;
6039: pcVar26[1] = '\0';
6040: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
6041: }
6042: uVar11 = (ulong)puVar4[0xf0];
6043: pcVar26 = pcVar28;
6044: iVar32 = iVar32 + 0x40;
6045: }
6046: else {
6047: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6048: }
6049: }
6050: goto LAB_0010a2f2;
6051: }
6052: LAB_0010c378:
6053: sVar1 = psVar5[0x23];
6054: iVar29 = iVar18 + 0x10;
6055: if (sVar1 != 0) {
6056: uVar16 = (int)sVar1 >> 0x1f;
6057: uVar31 = (int)sVar1 + uVar16;
6058: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
6059: if (0xff < iVar29) {
6060: iVar29 = iVar18 + -0xf0;
6061: iVar18 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
6062: if (iVar18 < 0) {
6063: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
6064: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
6065: cVar10 = (char)uVar14;
6066: cVar24 = (char)(uVar14 >> 8);
6067: cVar23 = (char)(uVar14 >> 0x10);
6068: cVar22 = (char)(uVar14 >> 0x18);
6069: cVar33 = (char)(uVar11 >> 0x20);
6070: cVar21 = (char)(uVar11 >> 0x28);
6071: cVar25 = (char)(uVar11 >> 0x30);
6072: cVar20 = (char)(uVar11 >> 0x38);
6073: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6074: pcVar28[7] = cVar10;
6075: pcVar26 = pcVar28 + 8;
6076: *pcVar28 = cVar20;
6077: pcVar28[1] = cVar25;
6078: pcVar28[2] = cVar21;
6079: pcVar28[3] = cVar33;
6080: pcVar28[4] = cVar22;
6081: pcVar28[5] = cVar23;
6082: pcVar28[6] = cVar24;
6083: }
6084: else {
6085: pcVar28[1] = '\0';
6086: *pcVar28 = cVar20;
6087: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6088: *pcVar28 = cVar25;
6089: pcVar28[1] = '\0';
6090: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
6091: *pcVar28 = cVar21;
6092: pcVar28[1] = '\0';
6093: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
6094: *pcVar28 = cVar33;
6095: pcVar28[1] = '\0';
6096: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
6097: *pcVar28 = cVar22;
6098: pcVar28[1] = '\0';
6099: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
6100: *pcVar28 = cVar23;
6101: pcVar28[1] = '\0';
6102: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
6103: *pcVar28 = cVar24;
6104: pcVar28[1] = '\0';
6105: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
6106: *pcVar28 = cVar10;
6107: pcVar28[1] = '\0';
6108: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
6109: }
6110: iVar17 = iVar18 + 0x40;
6111: uVar11 = (ulong)puVar4[0xf0];
6112: pcVar28 = pcVar26;
6113: }
6114: else {
6115: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6116: iVar17 = iVar18;
6117: }
6118: }
6119: goto LAB_0010a35c;
6120: }
6121: LAB_0010bf30:
6122: sVar1 = psVar5[0x2a];
6123: iVar18 = iVar29 + 0x10;
6124: if (sVar1 != 0) {
6125: uVar16 = (int)sVar1 >> 0x1f;
6126: uVar31 = (int)sVar1 + uVar16;
6127: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
6128: if (0xff < iVar18) {
6129: iVar18 = iVar29 + -0xf0;
6130: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
6131: if (iVar29 < 0) {
6132: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
6133: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
6134: cVar10 = (char)uVar14;
6135: cVar25 = (char)(uVar14 >> 8);
6136: cVar24 = (char)(uVar14 >> 0x10);
6137: cVar23 = (char)(uVar14 >> 0x18);
6138: cVar22 = (char)(uVar11 >> 0x20);
6139: cVar21 = (char)(uVar11 >> 0x28);
6140: cVar20 = (char)(uVar11 >> 0x30);
6141: cVar33 = (char)(uVar11 >> 0x38);
6142: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6143: pcVar28[7] = cVar10;
6144: pcVar26 = pcVar28 + 8;
6145: *pcVar28 = cVar33;
6146: pcVar28[1] = cVar20;
6147: pcVar28[2] = cVar21;
6148: pcVar28[3] = cVar22;
6149: pcVar28[4] = cVar23;
6150: pcVar28[5] = cVar24;
6151: pcVar28[6] = cVar25;
6152: }
6153: else {
6154: pcVar28[1] = '\0';
6155: *pcVar28 = cVar33;
6156: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6157: *pcVar28 = cVar20;
6158: pcVar28[1] = '\0';
6159: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
6160: *pcVar28 = cVar21;
6161: pcVar28[1] = '\0';
6162: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
6163: *pcVar28 = cVar22;
6164: pcVar28[1] = '\0';
6165: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
6166: *pcVar28 = cVar23;
6167: pcVar28[1] = '\0';
6168: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
6169: *pcVar28 = cVar24;
6170: pcVar28[1] = '\0';
6171: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
6172: *pcVar28 = cVar25;
6173: pcVar28[1] = '\0';
6174: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
6175: *pcVar28 = cVar10;
6176: pcVar28[1] = '\0';
6177: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
6178: }
6179: uVar11 = (ulong)puVar4[0xf0];
6180: iVar29 = iVar29 + 0x40;
6181: uVar14 = uVar11;
6182: }
6183: else {
6184: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6185: pcVar26 = pcVar28;
6186: uVar14 = (ulong)puVar4[0xf0];
6187: }
6188: pcVar28 = pcVar26;
6189: iVar17 = iVar29;
6190: if (iVar18 == 0x100) {
6191: iVar17 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
6192: if (iVar17 < 0) {
6193: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
6194: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
6195: cVar10 = (char)uVar14;
6196: cVar24 = (char)(uVar14 >> 8);
6197: cVar23 = (char)(uVar14 >> 0x10);
6198: cVar22 = (char)(uVar14 >> 0x18);
6199: cVar25 = (char)(uVar11 >> 0x20);
6200: cVar21 = (char)(uVar11 >> 0x28);
6201: cVar33 = (char)(uVar11 >> 0x30);
6202: cVar20 = (char)(uVar11 >> 0x38);
6203: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6204: pcVar26[7] = cVar10;
6205: pcVar28 = pcVar26 + 8;
6206: *pcVar26 = cVar20;
6207: pcVar26[1] = cVar33;
6208: pcVar26[2] = cVar21;
6209: pcVar26[3] = cVar25;
6210: pcVar26[4] = cVar22;
6211: pcVar26[5] = cVar23;
6212: pcVar26[6] = cVar24;
6213: }
6214: else {
6215: pcVar26[1] = '\0';
6216: *pcVar26 = cVar20;
6217: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6218: *pcVar26 = cVar33;
6219: pcVar26[1] = '\0';
6220: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
6221: *pcVar26 = cVar21;
6222: pcVar26[1] = '\0';
6223: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
6224: *pcVar26 = cVar25;
6225: pcVar26[1] = '\0';
6226: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
6227: *pcVar26 = cVar22;
6228: pcVar26[1] = '\0';
6229: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
6230: *pcVar26 = cVar23;
6231: pcVar26[1] = '\0';
6232: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
6233: *pcVar26 = cVar24;
6234: pcVar26[1] = '\0';
6235: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
6236: *pcVar26 = cVar10;
6237: pcVar26[1] = '\0';
6238: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
6239: }
6240: iVar17 = iVar17 + 0x40;
6241: uVar11 = (ulong)puVar4[0xf0];
6242: iVar18 = 0;
6243: }
6244: else {
6245: iVar18 = 0;
6246: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
6247: }
6248: }
6249: }
6250: goto LAB_0010bfb2;
6251: }
6252: LAB_0010a3aa:
6253: sVar1 = psVar5[0x31];
6254: iVar29 = iVar18 + 0x10;
6255: if (sVar1 != 0) {
6256: uVar31 = (int)sVar1 >> 0x1f;
6257: uVar16 = (int)sVar1 + uVar31;
6258: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
6259: if (0xff < iVar29) {
6260: iVar29 = iVar18 + -0xf0;
6261: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
6262: if (iVar32 < 0) {
6263: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
6264: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
6265: cVar10 = (char)uVar14;
6266: cVar20 = (char)(uVar14 >> 8);
6267: cVar22 = (char)(uVar14 >> 0x10);
6268: cVar23 = (char)(uVar14 >> 0x18);
6269: cVar24 = (char)(uVar11 >> 0x20);
6270: cVar25 = (char)(uVar11 >> 0x28);
6271: cVar21 = (char)(uVar11 >> 0x30);
6272: cVar33 = (char)(uVar11 >> 0x38);
6273: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6274: pcVar28[7] = cVar10;
6275: pcVar26 = pcVar28 + 8;
6276: *pcVar28 = cVar33;
6277: pcVar28[1] = cVar21;
6278: pcVar28[2] = cVar25;
6279: pcVar28[3] = cVar24;
6280: pcVar28[4] = cVar23;
6281: pcVar28[5] = cVar22;
6282: pcVar28[6] = cVar20;
6283: }
6284: else {
6285: pcVar28[1] = '\0';
6286: *pcVar28 = cVar33;
6287: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6288: *pcVar28 = cVar21;
6289: pcVar28[1] = '\0';
6290: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
6291: *pcVar28 = cVar25;
6292: pcVar28[1] = '\0';
6293: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
6294: *pcVar28 = cVar24;
6295: pcVar28[1] = '\0';
6296: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
6297: *pcVar28 = cVar23;
6298: pcVar28[1] = '\0';
6299: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
6300: *pcVar28 = cVar22;
6301: pcVar28[1] = '\0';
6302: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
6303: *pcVar28 = cVar20;
6304: pcVar28[1] = '\0';
6305: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
6306: *pcVar28 = cVar10;
6307: pcVar28[1] = '\0';
6308: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
6309: }
6310: uVar11 = (ulong)puVar4[0xf0];
6311: iVar32 = iVar32 + 0x40;
6312: uVar14 = uVar11;
6313: }
6314: else {
6315: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6316: pcVar26 = pcVar28;
6317: uVar14 = (ulong)puVar4[0xf0];
6318: }
6319: pcVar28 = pcVar26;
6320: iVar17 = iVar32;
6321: if (0xff < iVar29) {
6322: iVar29 = iVar18 + -0x1f0;
6323: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
6324: if (iVar17 < 0) {
6325: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
6326: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
6327: cVar10 = (char)uVar14;
6328: cVar33 = (char)(uVar14 >> 8);
6329: cVar23 = (char)(uVar14 >> 0x10);
6330: cVar24 = (char)(uVar14 >> 0x18);
6331: cVar25 = (char)(uVar11 >> 0x20);
6332: cVar20 = (char)(uVar11 >> 0x28);
6333: cVar21 = (char)(uVar11 >> 0x30);
6334: cVar22 = (char)(uVar11 >> 0x38);
6335: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6336: pcVar26[7] = cVar10;
6337: pcVar28 = pcVar26 + 8;
6338: *pcVar26 = cVar22;
6339: pcVar26[1] = cVar21;
6340: pcVar26[2] = cVar20;
6341: pcVar26[3] = cVar25;
6342: pcVar26[4] = cVar24;
6343: pcVar26[5] = cVar23;
6344: pcVar26[6] = cVar33;
6345: }
6346: else {
6347: pcVar26[1] = '\0';
6348: *pcVar26 = cVar22;
6349: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6350: *pcVar26 = cVar21;
6351: pcVar26[1] = '\0';
6352: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
6353: *pcVar26 = cVar20;
6354: pcVar26[1] = '\0';
6355: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
6356: *pcVar26 = cVar25;
6357: pcVar26[1] = '\0';
6358: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
6359: *pcVar26 = cVar24;
6360: pcVar26[1] = '\0';
6361: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
6362: *pcVar26 = cVar23;
6363: pcVar26[1] = '\0';
6364: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
6365: *pcVar26 = cVar33;
6366: pcVar26[1] = '\0';
6367: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
6368: *pcVar26 = cVar10;
6369: pcVar26[1] = '\0';
6370: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
6371: }
6372: iVar17 = iVar17 + 0x40;
6373: uVar11 = (ulong)puVar4[0xf0];
6374: }
6375: else {
6376: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
6377: }
6378: }
6379: }
6380: goto LAB_0010a430;
6381: }
6382: LAB_0010c000:
6383: sVar1 = psVar5[0x38];
6384: iVar18 = iVar29 + 0x10;
6385: if (sVar1 != 0) {
6386: uVar16 = (int)sVar1 >> 0x1f;
6387: uVar31 = (int)sVar1 + uVar16;
6388: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
6389: if (0xff < iVar18) {
6390: iVar18 = iVar29 + -0xf0;
6391: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
6392: if (iVar32 < 0) {
6393: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
6394: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
6395: cVar10 = (char)uVar14;
6396: cVar25 = (char)(uVar14 >> 8);
6397: cVar24 = (char)(uVar14 >> 0x10);
6398: cVar23 = (char)(uVar14 >> 0x18);
6399: cVar22 = (char)(uVar11 >> 0x20);
6400: cVar21 = (char)(uVar11 >> 0x28);
6401: cVar20 = (char)(uVar11 >> 0x30);
6402: cVar33 = (char)(uVar11 >> 0x38);
6403: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6404: pcVar28[7] = cVar10;
6405: pcVar26 = pcVar28 + 8;
6406: *pcVar28 = cVar33;
6407: pcVar28[1] = cVar20;
6408: pcVar28[2] = cVar21;
6409: pcVar28[3] = cVar22;
6410: pcVar28[4] = cVar23;
6411: pcVar28[5] = cVar24;
6412: pcVar28[6] = cVar25;
6413: }
6414: else {
6415: pcVar28[1] = '\0';
6416: *pcVar28 = cVar33;
6417: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6418: *pcVar28 = cVar20;
6419: pcVar28[1] = '\0';
6420: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
6421: *pcVar28 = cVar21;
6422: pcVar28[1] = '\0';
6423: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
6424: *pcVar28 = cVar22;
6425: pcVar28[1] = '\0';
6426: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
6427: *pcVar28 = cVar23;
6428: pcVar28[1] = '\0';
6429: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
6430: *pcVar28 = cVar24;
6431: pcVar28[1] = '\0';
6432: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
6433: *pcVar28 = cVar25;
6434: pcVar28[1] = '\0';
6435: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
6436: *pcVar28 = cVar10;
6437: pcVar28[1] = '\0';
6438: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
6439: }
6440: uVar11 = (ulong)puVar4[0xf0];
6441: iVar32 = iVar32 + 0x40;
6442: uVar14 = uVar11;
6443: }
6444: else {
6445: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6446: pcVar26 = pcVar28;
6447: uVar14 = (ulong)puVar4[0xf0];
6448: }
6449: pcVar28 = pcVar26;
6450: iVar17 = iVar32;
6451: if (0xff < iVar18) {
6452: iVar18 = iVar29 + -0x1f0;
6453: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
6454: if (iVar17 < 0) {
6455: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
6456: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
6457: cVar10 = (char)uVar14;
6458: cVar25 = (char)(uVar14 >> 8);
6459: cVar33 = (char)(uVar14 >> 0x10);
6460: cVar22 = (char)(uVar14 >> 0x18);
6461: cVar21 = (char)(uVar11 >> 0x20);
6462: cVar20 = (char)(uVar11 >> 0x28);
6463: cVar23 = (char)(uVar11 >> 0x30);
6464: cVar24 = (char)(uVar11 >> 0x38);
6465: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6466: pcVar26[7] = cVar10;
6467: pcVar28 = pcVar26 + 8;
6468: *pcVar26 = cVar24;
6469: pcVar26[1] = cVar23;
6470: pcVar26[2] = cVar20;
6471: pcVar26[3] = cVar21;
6472: pcVar26[4] = cVar22;
6473: pcVar26[5] = cVar33;
6474: pcVar26[6] = cVar25;
6475: }
6476: else {
6477: pcVar26[1] = '\0';
6478: *pcVar26 = cVar24;
6479: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6480: *pcVar26 = cVar23;
6481: pcVar26[1] = '\0';
6482: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
6483: *pcVar26 = cVar20;
6484: pcVar26[1] = '\0';
6485: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
6486: *pcVar26 = cVar21;
6487: pcVar26[1] = '\0';
6488: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
6489: *pcVar26 = cVar22;
6490: pcVar26[1] = '\0';
6491: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
6492: *pcVar26 = cVar33;
6493: pcVar26[1] = '\0';
6494: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
6495: *pcVar26 = cVar25;
6496: pcVar26[1] = '\0';
6497: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
6498: *pcVar26 = cVar10;
6499: pcVar26[1] = '\0';
6500: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
6501: }
6502: iVar17 = iVar17 + 0x40;
6503: uVar11 = (ulong)puVar4[0xf0];
6504: }
6505: else {
6506: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
6507: }
6508: }
6509: }
6510: goto LAB_0010c086;
6511: }
6512: LAB_0010a47e:
6513: sVar1 = psVar5[0x39];
6514: iVar29 = iVar18 + 0x10;
6515: if (sVar1 != 0) {
6516: uVar31 = (int)sVar1 >> 0x1f;
6517: uVar16 = (int)sVar1 + uVar31;
6518: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
6519: if (0xff < iVar29) {
6520: iVar29 = iVar18 + -0xf0;
6521: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
6522: if (iVar32 < 0) {
6523: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
6524: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
6525: cVar10 = (char)uVar14;
6526: cVar25 = (char)(uVar14 >> 8);
6527: cVar24 = (char)(uVar14 >> 0x10);
6528: cVar23 = (char)(uVar14 >> 0x18);
6529: cVar22 = (char)(uVar11 >> 0x20);
6530: cVar21 = (char)(uVar11 >> 0x28);
6531: cVar20 = (char)(uVar11 >> 0x30);
6532: cVar33 = (char)(uVar11 >> 0x38);
6533: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6534: pcVar28[7] = cVar10;
6535: pcVar26 = pcVar28 + 8;
6536: *pcVar28 = cVar33;
6537: pcVar28[1] = cVar20;
6538: pcVar28[2] = cVar21;
6539: pcVar28[3] = cVar22;
6540: pcVar28[4] = cVar23;
6541: pcVar28[5] = cVar24;
6542: pcVar28[6] = cVar25;
6543: }
6544: else {
6545: pcVar28[1] = '\0';
6546: *pcVar28 = cVar33;
6547: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6548: *pcVar28 = cVar20;
6549: pcVar28[1] = '\0';
6550: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
6551: *pcVar28 = cVar21;
6552: pcVar28[1] = '\0';
6553: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
6554: *pcVar28 = cVar22;
6555: pcVar28[1] = '\0';
6556: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
6557: *pcVar28 = cVar23;
6558: pcVar28[1] = '\0';
6559: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
6560: *pcVar28 = cVar24;
6561: pcVar28[1] = '\0';
6562: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
6563: *pcVar28 = cVar25;
6564: pcVar28[1] = '\0';
6565: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
6566: *pcVar28 = cVar10;
6567: pcVar28[1] = '\0';
6568: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
6569: }
6570: uVar11 = (ulong)puVar4[0xf0];
6571: iVar32 = iVar32 + 0x40;
6572: uVar14 = uVar11;
6573: }
6574: else {
6575: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6576: pcVar26 = pcVar28;
6577: uVar14 = (ulong)puVar4[0xf0];
6578: }
6579: pcVar28 = pcVar26;
6580: iVar17 = iVar32;
6581: if (0xff < iVar29) {
6582: iVar29 = iVar18 + -0x1f0;
6583: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
6584: if (iVar17 < 0) {
6585: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
6586: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
6587: cVar10 = (char)uVar14;
6588: cVar25 = (char)(uVar14 >> 8);
6589: cVar24 = (char)(uVar14 >> 0x10);
6590: cVar23 = (char)(uVar14 >> 0x18);
6591: cVar22 = (char)(uVar11 >> 0x20);
6592: cVar21 = (char)(uVar11 >> 0x28);
6593: cVar20 = (char)(uVar11 >> 0x30);
6594: cVar33 = (char)(uVar11 >> 0x38);
6595: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6596: pcVar26[7] = cVar10;
6597: pcVar28 = pcVar26 + 8;
6598: *pcVar26 = cVar33;
6599: pcVar26[1] = cVar20;
6600: pcVar26[2] = cVar21;
6601: pcVar26[3] = cVar22;
6602: pcVar26[4] = cVar23;
6603: pcVar26[5] = cVar24;
6604: pcVar26[6] = cVar25;
6605: }
6606: else {
6607: pcVar26[1] = '\0';
6608: *pcVar26 = cVar33;
6609: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6610: *pcVar26 = cVar20;
6611: pcVar26[1] = '\0';
6612: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
6613: *pcVar26 = cVar21;
6614: pcVar26[1] = '\0';
6615: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
6616: *pcVar26 = cVar22;
6617: pcVar26[1] = '\0';
6618: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
6619: *pcVar26 = cVar23;
6620: pcVar26[1] = '\0';
6621: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
6622: *pcVar26 = cVar24;
6623: pcVar26[1] = '\0';
6624: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
6625: *pcVar26 = cVar25;
6626: pcVar26[1] = '\0';
6627: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
6628: *pcVar26 = cVar10;
6629: pcVar26[1] = '\0';
6630: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
6631: }
6632: iVar17 = iVar17 + 0x40;
6633: uVar11 = (ulong)puVar4[0xf0];
6634: }
6635: else {
6636: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
6637: }
6638: }
6639: }
6640: goto LAB_0010a504;
6641: }
6642: LAB_0010c0d4:
6643: sVar1 = psVar5[0x32];
6644: iVar18 = iVar29 + 0x10;
6645: if (sVar1 != 0) {
6646: uVar16 = (int)sVar1 >> 0x1f;
6647: uVar31 = (int)sVar1 + uVar16;
6648: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
6649: if (0xff < iVar18) {
6650: iVar18 = iVar29 + -0xf0;
6651: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
6652: if (iVar32 < 0) {
6653: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
6654: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
6655: cVar10 = (char)uVar14;
6656: cVar25 = (char)(uVar14 >> 8);
6657: cVar24 = (char)(uVar14 >> 0x10);
6658: cVar23 = (char)(uVar14 >> 0x18);
6659: cVar33 = (char)(uVar11 >> 0x20);
6660: cVar20 = (char)(uVar11 >> 0x28);
6661: cVar21 = (char)(uVar11 >> 0x30);
6662: cVar22 = (char)(uVar11 >> 0x38);
6663: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6664: pcVar28[7] = cVar10;
6665: pcVar26 = pcVar28 + 8;
6666: *pcVar28 = cVar22;
6667: pcVar28[1] = cVar21;
6668: pcVar28[2] = cVar20;
6669: pcVar28[3] = cVar33;
6670: pcVar28[4] = cVar23;
6671: pcVar28[5] = cVar24;
6672: pcVar28[6] = cVar25;
6673: }
6674: else {
6675: pcVar28[1] = '\0';
6676: *pcVar28 = cVar22;
6677: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6678: *pcVar28 = cVar21;
6679: pcVar28[1] = '\0';
6680: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
6681: *pcVar28 = cVar20;
6682: pcVar28[1] = '\0';
6683: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
6684: *pcVar28 = cVar33;
6685: pcVar28[1] = '\0';
6686: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
6687: *pcVar28 = cVar23;
6688: pcVar28[1] = '\0';
6689: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
6690: *pcVar28 = cVar24;
6691: pcVar28[1] = '\0';
6692: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
6693: *pcVar28 = cVar25;
6694: pcVar28[1] = '\0';
6695: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
6696: *pcVar28 = cVar10;
6697: pcVar28[1] = '\0';
6698: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
6699: }
6700: uVar11 = (ulong)puVar4[0xf0];
6701: iVar32 = iVar32 + 0x40;
6702: uVar14 = uVar11;
6703: }
6704: else {
6705: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6706: pcVar26 = pcVar28;
6707: uVar14 = (ulong)puVar4[0xf0];
6708: }
6709: pcVar28 = pcVar26;
6710: iVar17 = iVar32;
6711: if (0xff < iVar18) {
6712: iVar18 = iVar29 + -0x1f0;
6713: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
6714: if (iVar17 < 0) {
6715: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
6716: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
6717: cVar10 = (char)uVar14;
6718: cVar23 = (char)(uVar14 >> 8);
6719: cVar24 = (char)(uVar14 >> 0x10);
6720: cVar25 = (char)(uVar14 >> 0x18);
6721: cVar22 = (char)(uVar11 >> 0x20);
6722: cVar21 = (char)(uVar11 >> 0x28);
6723: cVar20 = (char)(uVar11 >> 0x30);
6724: cVar33 = (char)(uVar11 >> 0x38);
6725: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6726: pcVar26[7] = cVar10;
6727: pcVar28 = pcVar26 + 8;
6728: *pcVar26 = cVar33;
6729: pcVar26[1] = cVar20;
6730: pcVar26[2] = cVar21;
6731: pcVar26[3] = cVar22;
6732: pcVar26[4] = cVar25;
6733: pcVar26[5] = cVar24;
6734: pcVar26[6] = cVar23;
6735: }
6736: else {
6737: pcVar26[1] = '\0';
6738: *pcVar26 = cVar33;
6739: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6740: *pcVar26 = cVar20;
6741: pcVar26[1] = '\0';
6742: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
6743: *pcVar26 = cVar21;
6744: pcVar26[1] = '\0';
6745: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
6746: *pcVar26 = cVar22;
6747: pcVar26[1] = '\0';
6748: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
6749: *pcVar26 = cVar25;
6750: pcVar26[1] = '\0';
6751: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
6752: *pcVar26 = cVar24;
6753: pcVar26[1] = '\0';
6754: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
6755: *pcVar26 = cVar23;
6756: pcVar26[1] = '\0';
6757: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
6758: *pcVar26 = cVar10;
6759: pcVar26[1] = '\0';
6760: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
6761: }
6762: iVar17 = iVar17 + 0x40;
6763: uVar11 = (ulong)puVar4[0xf0];
6764: }
6765: else {
6766: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
6767: }
6768: }
6769: }
6770: goto LAB_0010c15a;
6771: }
6772: LAB_0010a552:
6773: sVar1 = psVar5[0x2b];
6774: iVar29 = iVar18 + 0x10;
6775: if (sVar1 != 0) {
6776: uVar31 = (int)sVar1 >> 0x1f;
6777: uVar16 = (int)sVar1 + uVar31;
6778: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
6779: if (0xff < iVar29) {
6780: iVar29 = iVar18 + -0xf0;
6781: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
6782: if (iVar32 < 0) {
6783: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
6784: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
6785: cVar10 = (char)uVar14;
6786: cVar23 = (char)(uVar14 >> 8);
6787: cVar25 = (char)(uVar14 >> 0x10);
6788: cVar24 = (char)(uVar14 >> 0x18);
6789: cVar33 = (char)(uVar11 >> 0x20);
6790: cVar20 = (char)(uVar11 >> 0x28);
6791: cVar21 = (char)(uVar11 >> 0x30);
6792: cVar22 = (char)(uVar11 >> 0x38);
6793: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6794: pcVar28[7] = cVar10;
6795: pcVar26 = pcVar28 + 8;
6796: *pcVar28 = cVar22;
6797: pcVar28[1] = cVar21;
6798: pcVar28[2] = cVar20;
6799: pcVar28[3] = cVar33;
6800: pcVar28[4] = cVar24;
6801: pcVar28[5] = cVar25;
6802: pcVar28[6] = cVar23;
6803: }
6804: else {
6805: pcVar28[1] = '\0';
6806: *pcVar28 = cVar22;
6807: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6808: *pcVar28 = cVar21;
6809: pcVar28[1] = '\0';
6810: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
6811: *pcVar28 = cVar20;
6812: pcVar28[1] = '\0';
6813: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
6814: *pcVar28 = cVar33;
6815: pcVar28[1] = '\0';
6816: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
6817: *pcVar28 = cVar24;
6818: pcVar28[1] = '\0';
6819: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
6820: *pcVar28 = cVar25;
6821: pcVar28[1] = '\0';
6822: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
6823: *pcVar28 = cVar23;
6824: pcVar28[1] = '\0';
6825: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
6826: *pcVar28 = cVar10;
6827: pcVar28[1] = '\0';
6828: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
6829: }
6830: uVar11 = (ulong)puVar4[0xf0];
6831: iVar32 = iVar32 + 0x40;
6832: uVar14 = uVar11;
6833: }
6834: else {
6835: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6836: pcVar26 = pcVar28;
6837: uVar14 = (ulong)puVar4[0xf0];
6838: }
6839: pcVar28 = pcVar26;
6840: iVar17 = iVar32;
6841: if (0xff < iVar29) {
6842: iVar29 = iVar18 + -0x1f0;
6843: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
6844: if (iVar17 < 0) {
6845: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
6846: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
6847: cVar10 = (char)uVar14;
6848: cVar21 = (char)(uVar14 >> 8);
6849: cVar20 = (char)(uVar14 >> 0x10);
6850: cVar33 = (char)(uVar14 >> 0x18);
6851: cVar22 = (char)(uVar11 >> 0x20);
6852: cVar25 = (char)(uVar11 >> 0x28);
6853: cVar24 = (char)(uVar11 >> 0x30);
6854: cVar23 = (char)(uVar11 >> 0x38);
6855: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6856: pcVar26[7] = cVar10;
6857: pcVar28 = pcVar26 + 8;
6858: *pcVar26 = cVar23;
6859: pcVar26[1] = cVar24;
6860: pcVar26[2] = cVar25;
6861: pcVar26[3] = cVar22;
6862: pcVar26[4] = cVar33;
6863: pcVar26[5] = cVar20;
6864: pcVar26[6] = cVar21;
6865: }
6866: else {
6867: pcVar26[1] = '\0';
6868: *pcVar26 = cVar23;
6869: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6870: *pcVar26 = cVar24;
6871: pcVar26[1] = '\0';
6872: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
6873: *pcVar26 = cVar25;
6874: pcVar26[1] = '\0';
6875: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
6876: *pcVar26 = cVar22;
6877: pcVar26[1] = '\0';
6878: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
6879: *pcVar26 = cVar33;
6880: pcVar26[1] = '\0';
6881: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
6882: *pcVar26 = cVar20;
6883: pcVar26[1] = '\0';
6884: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
6885: *pcVar26 = cVar21;
6886: pcVar26[1] = '\0';
6887: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
6888: *pcVar26 = cVar10;
6889: pcVar26[1] = '\0';
6890: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
6891: }
6892: iVar17 = iVar17 + 0x40;
6893: uVar11 = (ulong)puVar4[0xf0];
6894: }
6895: else {
6896: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
6897: }
6898: }
6899: }
6900: goto LAB_0010a5d8;
6901: }
6902: LAB_0010c1a8:
6903: sVar1 = psVar5[0x24];
6904: iVar18 = iVar29 + 0x10;
6905: if (sVar1 != 0) {
6906: uVar16 = (int)sVar1 >> 0x1f;
6907: uVar31 = (int)sVar1 + uVar16;
6908: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
6909: if (0xff < iVar18) {
6910: iVar18 = iVar29 + -0xf0;
6911: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
6912: if (iVar32 < 0) {
6913: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
6914: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
6915: cVar10 = (char)uVar14;
6916: cVar24 = (char)(uVar14 >> 8);
6917: cVar25 = (char)(uVar14 >> 0x10);
6918: cVar23 = (char)(uVar14 >> 0x18);
6919: cVar22 = (char)(uVar11 >> 0x20);
6920: cVar21 = (char)(uVar11 >> 0x28);
6921: cVar20 = (char)(uVar11 >> 0x30);
6922: cVar33 = (char)(uVar11 >> 0x38);
6923: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6924: pcVar28[7] = cVar10;
6925: pcVar26 = pcVar28 + 8;
6926: *pcVar28 = cVar33;
6927: pcVar28[1] = cVar20;
6928: pcVar28[2] = cVar21;
6929: pcVar28[3] = cVar22;
6930: pcVar28[4] = cVar23;
6931: pcVar28[5] = cVar25;
6932: pcVar28[6] = cVar24;
6933: }
6934: else {
6935: pcVar28[1] = '\0';
6936: *pcVar28 = cVar33;
6937: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
6938: *pcVar28 = cVar20;
6939: pcVar28[1] = '\0';
6940: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
6941: *pcVar28 = cVar21;
6942: pcVar28[1] = '\0';
6943: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
6944: *pcVar28 = cVar22;
6945: pcVar28[1] = '\0';
6946: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
6947: *pcVar28 = cVar23;
6948: pcVar28[1] = '\0';
6949: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
6950: *pcVar28 = cVar25;
6951: pcVar28[1] = '\0';
6952: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
6953: *pcVar28 = cVar24;
6954: pcVar28[1] = '\0';
6955: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
6956: *pcVar28 = cVar10;
6957: pcVar28[1] = '\0';
6958: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
6959: }
6960: uVar11 = (ulong)puVar4[0xf0];
6961: iVar32 = iVar32 + 0x40;
6962: uVar14 = uVar11;
6963: }
6964: else {
6965: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
6966: pcVar26 = pcVar28;
6967: uVar14 = (ulong)puVar4[0xf0];
6968: }
6969: pcVar28 = pcVar26;
6970: iVar17 = iVar32;
6971: if (0xff < iVar18) {
6972: iVar18 = iVar29 + -0x1f0;
6973: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
6974: if (iVar17 < 0) {
6975: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
6976: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
6977: cVar10 = (char)uVar14;
6978: cVar25 = (char)(uVar14 >> 8);
6979: cVar24 = (char)(uVar14 >> 0x10);
6980: cVar23 = (char)(uVar14 >> 0x18);
6981: cVar22 = (char)(uVar11 >> 0x20);
6982: cVar21 = (char)(uVar11 >> 0x28);
6983: cVar20 = (char)(uVar11 >> 0x30);
6984: cVar33 = (char)(uVar11 >> 0x38);
6985: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
6986: pcVar26[7] = cVar10;
6987: pcVar28 = pcVar26 + 8;
6988: *pcVar26 = cVar33;
6989: pcVar26[1] = cVar20;
6990: pcVar26[2] = cVar21;
6991: pcVar26[3] = cVar22;
6992: pcVar26[4] = cVar23;
6993: pcVar26[5] = cVar24;
6994: pcVar26[6] = cVar25;
6995: }
6996: else {
6997: pcVar26[1] = '\0';
6998: *pcVar26 = cVar33;
6999: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7000: *pcVar26 = cVar20;
7001: pcVar26[1] = '\0';
7002: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
7003: *pcVar26 = cVar21;
7004: pcVar26[1] = '\0';
7005: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
7006: *pcVar26 = cVar22;
7007: pcVar26[1] = '\0';
7008: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
7009: *pcVar26 = cVar23;
7010: pcVar26[1] = '\0';
7011: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
7012: *pcVar26 = cVar24;
7013: pcVar26[1] = '\0';
7014: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
7015: *pcVar26 = cVar25;
7016: pcVar26[1] = '\0';
7017: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
7018: *pcVar26 = cVar10;
7019: pcVar26[1] = '\0';
7020: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
7021: }
7022: iVar17 = iVar17 + 0x40;
7023: uVar11 = (ulong)puVar4[0xf0];
7024: }
7025: else {
7026: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
7027: }
7028: }
7029: }
7030: goto LAB_0010c22e;
7031: }
7032: LAB_0010a626:
7033: sVar1 = psVar5[0x1d];
7034: iVar29 = iVar18 + 0x10;
7035: if (sVar1 != 0) {
7036: uVar31 = (int)sVar1 >> 0x1f;
7037: uVar16 = (int)sVar1 + uVar31;
7038: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
7039: if (0xff < iVar29) {
7040: iVar29 = iVar18 + -0xf0;
7041: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
7042: if (iVar32 < 0) {
7043: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
7044: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
7045: cVar10 = (char)uVar14;
7046: cVar20 = (char)(uVar14 >> 8);
7047: cVar25 = (char)(uVar14 >> 0x10);
7048: cVar24 = (char)(uVar14 >> 0x18);
7049: cVar23 = (char)(uVar11 >> 0x20);
7050: cVar22 = (char)(uVar11 >> 0x28);
7051: cVar21 = (char)(uVar11 >> 0x30);
7052: cVar33 = (char)(uVar11 >> 0x38);
7053: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7054: pcVar28[7] = cVar10;
7055: pcVar26 = pcVar28 + 8;
7056: *pcVar28 = cVar33;
7057: pcVar28[1] = cVar21;
7058: pcVar28[2] = cVar22;
7059: pcVar28[3] = cVar23;
7060: pcVar28[4] = cVar24;
7061: pcVar28[5] = cVar25;
7062: pcVar28[6] = cVar20;
7063: }
7064: else {
7065: pcVar28[1] = '\0';
7066: *pcVar28 = cVar33;
7067: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7068: *pcVar28 = cVar21;
7069: pcVar28[1] = '\0';
7070: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
7071: *pcVar28 = cVar22;
7072: pcVar28[1] = '\0';
7073: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7074: *pcVar28 = cVar23;
7075: pcVar28[1] = '\0';
7076: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7077: *pcVar28 = cVar24;
7078: pcVar28[1] = '\0';
7079: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7080: *pcVar28 = cVar25;
7081: pcVar28[1] = '\0';
7082: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
7083: *pcVar28 = cVar20;
7084: pcVar28[1] = '\0';
7085: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
7086: *pcVar28 = cVar10;
7087: pcVar28[1] = '\0';
7088: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7089: }
7090: uVar11 = (ulong)puVar4[0xf0];
7091: iVar32 = iVar32 + 0x40;
7092: uVar14 = uVar11;
7093: }
7094: else {
7095: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
7096: pcVar26 = pcVar28;
7097: uVar14 = (ulong)puVar4[0xf0];
7098: }
7099: pcVar28 = pcVar26;
7100: iVar17 = iVar32;
7101: if (0xff < iVar29) {
7102: iVar29 = iVar18 + -0x1f0;
7103: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
7104: if (iVar17 < 0) {
7105: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
7106: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
7107: cVar10 = (char)uVar14;
7108: cVar25 = (char)(uVar14 >> 8);
7109: cVar24 = (char)(uVar14 >> 0x10);
7110: cVar23 = (char)(uVar14 >> 0x18);
7111: cVar22 = (char)(uVar11 >> 0x20);
7112: cVar21 = (char)(uVar11 >> 0x28);
7113: cVar20 = (char)(uVar11 >> 0x30);
7114: cVar33 = (char)(uVar11 >> 0x38);
7115: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7116: pcVar26[7] = cVar10;
7117: pcVar28 = pcVar26 + 8;
7118: *pcVar26 = cVar33;
7119: pcVar26[1] = cVar20;
7120: pcVar26[2] = cVar21;
7121: pcVar26[3] = cVar22;
7122: pcVar26[4] = cVar23;
7123: pcVar26[5] = cVar24;
7124: pcVar26[6] = cVar25;
7125: }
7126: else {
7127: pcVar26[1] = '\0';
7128: *pcVar26 = cVar33;
7129: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7130: *pcVar26 = cVar20;
7131: pcVar26[1] = '\0';
7132: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
7133: *pcVar26 = cVar21;
7134: pcVar26[1] = '\0';
7135: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
7136: *pcVar26 = cVar22;
7137: pcVar26[1] = '\0';
7138: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
7139: *pcVar26 = cVar23;
7140: pcVar26[1] = '\0';
7141: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
7142: *pcVar26 = cVar24;
7143: pcVar26[1] = '\0';
7144: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
7145: *pcVar26 = cVar25;
7146: pcVar26[1] = '\0';
7147: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
7148: *pcVar26 = cVar10;
7149: pcVar26[1] = '\0';
7150: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
7151: }
7152: iVar17 = iVar17 + 0x40;
7153: uVar11 = (ulong)puVar4[0xf0];
7154: }
7155: else {
7156: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
7157: }
7158: }
7159: }
7160: goto LAB_0010a6ac;
7161: }
7162: LAB_0010c27c:
7163: sVar1 = psVar5[0x16];
7164: iVar18 = iVar29 + 0x10;
7165: if (sVar1 != 0) {
7166: uVar16 = (int)sVar1 >> 0x1f;
7167: uVar31 = (int)sVar1 + uVar16;
7168: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
7169: iVar32 = iVar17;
7170: if (0xff < iVar18) {
7171: iVar18 = iVar29 + -0xf0;
7172: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
7173: if (iVar32 < 0) {
7174: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
7175: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
7176: cVar10 = (char)uVar14;
7177: cVar33 = (char)(uVar14 >> 8);
7178: cVar20 = (char)(uVar14 >> 0x10);
7179: cVar21 = (char)(uVar14 >> 0x18);
7180: cVar22 = (char)(uVar11 >> 0x20);
7181: cVar23 = (char)(uVar11 >> 0x28);
7182: cVar24 = (char)(uVar11 >> 0x30);
7183: cVar25 = (char)(uVar11 >> 0x38);
7184: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7185: pcVar28[7] = cVar10;
7186: pcVar26 = pcVar28 + 8;
7187: *pcVar28 = cVar25;
7188: pcVar28[1] = cVar24;
7189: pcVar28[2] = cVar23;
7190: pcVar28[3] = cVar22;
7191: pcVar28[4] = cVar21;
7192: pcVar28[5] = cVar20;
7193: pcVar28[6] = cVar33;
7194: }
7195: else {
7196: pcVar28[1] = '\0';
7197: *pcVar28 = cVar25;
7198: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7199: *pcVar28 = cVar24;
7200: pcVar28[1] = '\0';
7201: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7202: *pcVar28 = cVar23;
7203: pcVar28[1] = '\0';
7204: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7205: *pcVar28 = cVar22;
7206: pcVar28[1] = '\0';
7207: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7208: *pcVar28 = cVar21;
7209: pcVar28[1] = '\0';
7210: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
7211: *pcVar28 = cVar20;
7212: pcVar28[1] = '\0';
7213: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
7214: *pcVar28 = cVar33;
7215: pcVar28[1] = '\0';
7216: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
7217: *pcVar28 = cVar10;
7218: pcVar28[1] = '\0';
7219: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7220: }
7221: uVar11 = (ulong)puVar4[0xf0];
7222: iVar32 = iVar32 + 0x40;
7223: uVar14 = uVar11;
7224: }
7225: else {
7226: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
7227: pcVar26 = pcVar28;
7228: uVar14 = (ulong)puVar4[0xf0];
7229: }
7230: pcVar28 = pcVar26;
7231: if (0xff < iVar18) {
7232: iVar18 = iVar29 + -0x1f0;
7233: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
7234: if (iVar17 < 0) {
7235: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
7236: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
7237: cVar10 = (char)uVar14;
7238: cVar33 = (char)(uVar14 >> 8);
7239: cVar20 = (char)(uVar14 >> 0x10);
7240: cVar21 = (char)(uVar14 >> 0x18);
7241: cVar22 = (char)(uVar11 >> 0x20);
7242: cVar23 = (char)(uVar11 >> 0x28);
7243: cVar24 = (char)(uVar11 >> 0x30);
7244: cVar25 = (char)(uVar11 >> 0x38);
7245: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7246: pcVar26[7] = cVar10;
7247: pcVar28 = pcVar26 + 8;
7248: *pcVar26 = cVar25;
7249: pcVar26[1] = cVar24;
7250: pcVar26[2] = cVar23;
7251: pcVar26[3] = cVar22;
7252: pcVar26[4] = cVar21;
7253: pcVar26[5] = cVar20;
7254: pcVar26[6] = cVar33;
7255: }
7256: else {
7257: pcVar26[1] = '\0';
7258: *pcVar26 = cVar25;
7259: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7260: *pcVar26 = cVar24;
7261: pcVar26[1] = '\0';
7262: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
7263: *pcVar26 = cVar23;
7264: pcVar26[1] = '\0';
7265: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
7266: *pcVar26 = cVar22;
7267: pcVar26[1] = '\0';
7268: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
7269: *pcVar26 = cVar21;
7270: pcVar26[1] = '\0';
7271: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
7272: *pcVar26 = cVar20;
7273: pcVar26[1] = '\0';
7274: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
7275: *pcVar26 = cVar33;
7276: pcVar26[1] = '\0';
7277: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
7278: *pcVar26 = cVar10;
7279: pcVar26[1] = '\0';
7280: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
7281: }
7282: uVar11 = (ulong)puVar4[0xf0];
7283: iVar32 = iVar17 + 0x40;
7284: }
7285: else {
7286: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
7287: iVar32 = iVar17;
7288: }
7289: }
7290: }
7291: goto LAB_0010c302;
7292: }
7293: LAB_0010a6fa:
7294: sVar1 = psVar5[0xf];
7295: iVar29 = iVar18 + 0x10;
7296: if (sVar1 == 0) goto LAB_0010bc90;
7297: uVar31 = (int)sVar1 >> 0x1f;
7298: uVar16 = (int)sVar1 + uVar31;
7299: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
7300: if (0xff < iVar29) {
7301: iVar29 = iVar18 + -0xf0;
7302: iVar32 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
7303: if (iVar32 < 0) {
7304: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
7305: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
7306: cVar10 = (char)uVar14;
7307: cVar25 = (char)(uVar14 >> 8);
7308: cVar24 = (char)(uVar14 >> 0x10);
7309: cVar23 = (char)(uVar14 >> 0x18);
7310: cVar22 = (char)(uVar11 >> 0x20);
7311: cVar21 = (char)(uVar11 >> 0x28);
7312: cVar20 = (char)(uVar11 >> 0x30);
7313: cVar33 = (char)(uVar11 >> 0x38);
7314: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7315: pcVar28[7] = cVar10;
7316: pcVar26 = pcVar28 + 8;
7317: *pcVar28 = cVar33;
7318: pcVar28[1] = cVar20;
7319: pcVar28[2] = cVar21;
7320: pcVar28[3] = cVar22;
7321: pcVar28[4] = cVar23;
7322: pcVar28[5] = cVar24;
7323: pcVar28[6] = cVar25;
7324: }
7325: else {
7326: pcVar28[1] = '\0';
7327: *pcVar28 = cVar33;
7328: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7329: *pcVar28 = cVar20;
7330: pcVar28[1] = '\0';
7331: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
7332: *pcVar28 = cVar21;
7333: pcVar28[1] = '\0';
7334: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
7335: *pcVar28 = cVar22;
7336: pcVar28[1] = '\0';
7337: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7338: *pcVar28 = cVar23;
7339: pcVar28[1] = '\0';
7340: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7341: *pcVar28 = cVar24;
7342: pcVar28[1] = '\0';
7343: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7344: *pcVar28 = cVar25;
7345: pcVar28[1] = '\0';
7346: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
7347: *pcVar28 = cVar10;
7348: pcVar28[1] = '\0';
7349: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7350: }
7351: uVar11 = (ulong)puVar4[0xf0];
7352: iVar32 = iVar32 + 0x40;
7353: uVar14 = uVar11;
7354: }
7355: else {
7356: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
7357: pcVar26 = pcVar28;
7358: uVar14 = (ulong)puVar4[0xf0];
7359: }
7360: pcVar28 = pcVar26;
7361: iVar17 = iVar32;
7362: if (0xff < iVar29) {
7363: iVar29 = iVar18 + -0x1f0;
7364: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
7365: if (iVar17 < 0) {
7366: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
7367: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
7368: cVar10 = (char)uVar14;
7369: cVar33 = (char)(uVar14 >> 8);
7370: cVar20 = (char)(uVar14 >> 0x10);
7371: cVar21 = (char)(uVar14 >> 0x18);
7372: cVar22 = (char)(uVar11 >> 0x20);
7373: cVar23 = (char)(uVar11 >> 0x28);
7374: cVar24 = (char)(uVar11 >> 0x30);
7375: cVar25 = (char)(uVar11 >> 0x38);
7376: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7377: pcVar26[7] = cVar10;
7378: pcVar28 = pcVar26 + 8;
7379: *pcVar26 = cVar25;
7380: pcVar26[1] = cVar24;
7381: pcVar26[2] = cVar23;
7382: pcVar26[3] = cVar22;
7383: pcVar26[4] = cVar21;
7384: pcVar26[5] = cVar20;
7385: pcVar26[6] = cVar33;
7386: }
7387: else {
7388: pcVar26[1] = '\0';
7389: *pcVar26 = cVar25;
7390: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7391: *pcVar26 = cVar24;
7392: pcVar26[1] = '\0';
7393: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
7394: *pcVar26 = cVar23;
7395: pcVar26[1] = '\0';
7396: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
7397: *pcVar26 = cVar22;
7398: pcVar26[1] = '\0';
7399: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
7400: *pcVar26 = cVar21;
7401: pcVar26[1] = '\0';
7402: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
7403: *pcVar26 = cVar20;
7404: pcVar26[1] = '\0';
7405: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
7406: *pcVar26 = cVar33;
7407: pcVar26[1] = '\0';
7408: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
7409: *pcVar26 = cVar10;
7410: pcVar26[1] = '\0';
7411: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
7412: }
7413: iVar17 = iVar17 + 0x40;
7414: uVar11 = (ulong)puVar4[0xf0];
7415: }
7416: else {
7417: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
7418: }
7419: }
7420: }
7421: LAB_0010a780:
7422: uVar16 = uVar16 & (int)(1 << ((byte)uVar31 & 0x3f)) - 1U |
7423: puVar4[(int)(iVar29 + uVar31)] << ((byte)uVar31 & 0x1f);
7424: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar31) + 0x400) + uVar31;
7425: iVar18 = iVar17 - iVar29;
7426: if (iVar18 < 0) {
7427: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
7428: uVar11 << ((byte)iVar17 & 0x3f);
7429: cVar10 = (char)uVar11;
7430: cVar33 = (char)(uVar11 >> 8);
7431: cVar21 = (char)(uVar11 >> 0x10);
7432: cVar22 = (char)(uVar11 >> 0x18);
7433: cVar23 = (char)(uVar11 >> 0x20);
7434: cVar24 = (char)(uVar11 >> 0x28);
7435: cVar25 = (char)(uVar11 >> 0x30);
7436: cVar20 = (char)(uVar11 >> 0x38);
7437: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
7438: pcVar28[7] = cVar10;
7439: pcVar26 = pcVar28 + 8;
7440: *pcVar28 = cVar20;
7441: pcVar28[1] = cVar25;
7442: pcVar28[2] = cVar24;
7443: pcVar28[3] = cVar23;
7444: pcVar28[4] = cVar22;
7445: pcVar28[5] = cVar21;
7446: pcVar28[6] = cVar33;
7447: }
7448: else {
7449: pcVar28[1] = '\0';
7450: *pcVar28 = cVar20;
7451: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7452: *pcVar28 = cVar25;
7453: pcVar28[1] = '\0';
7454: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
7455: *pcVar28 = cVar24;
7456: pcVar28[1] = '\0';
7457: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7458: *pcVar28 = cVar23;
7459: pcVar28[1] = '\0';
7460: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7461: *pcVar28 = cVar22;
7462: pcVar28[1] = '\0';
7463: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7464: *pcVar28 = cVar21;
7465: pcVar28[1] = '\0';
7466: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
7467: *pcVar28 = cVar33;
7468: pcVar28[1] = '\0';
7469: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
7470: *pcVar28 = cVar10;
7471: pcVar28[1] = '\0';
7472: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7473: }
7474: sVar1 = psVar5[0x17];
7475: uVar11 = SEXT48((int)uVar16);
7476: iVar17 = iVar18 + 0x40;
7477: pcVar28 = pcVar26;
7478: }
7479: else {
7480: sVar1 = psVar5[0x17];
7481: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
7482: iVar17 = iVar18;
7483: }
7484: iVar18 = (int)sVar1;
7485: if (sVar1 == 0) goto LAB_0010a7ce;
7486: uVar16 = iVar18 >> 0x1f;
7487: uVar31 = uVar16 + iVar18;
7488: iVar18 = 0;
7489: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
7490: LAB_0010bd16:
7491: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
7492: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
7493: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
7494: iVar18 = iVar17 - iVar29;
7495: if (iVar18 < 0) {
7496: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
7497: uVar11 << ((byte)iVar17 & 0x3f);
7498: cVar10 = (char)uVar11;
7499: cVar33 = (char)(uVar11 >> 8);
7500: cVar20 = (char)(uVar11 >> 0x10);
7501: cVar21 = (char)(uVar11 >> 0x18);
7502: cVar22 = (char)(uVar11 >> 0x20);
7503: cVar23 = (char)(uVar11 >> 0x28);
7504: cVar24 = (char)(uVar11 >> 0x30);
7505: cVar25 = (char)(uVar11 >> 0x38);
7506: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
7507: pcVar28[7] = cVar10;
7508: pcVar26 = pcVar28 + 8;
7509: *pcVar28 = cVar25;
7510: pcVar28[1] = cVar24;
7511: pcVar28[2] = cVar23;
7512: pcVar28[3] = cVar22;
7513: pcVar28[4] = cVar21;
7514: pcVar28[5] = cVar20;
7515: pcVar28[6] = cVar33;
7516: }
7517: else {
7518: pcVar28[1] = '\0';
7519: *pcVar28 = cVar25;
7520: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7521: *pcVar28 = cVar24;
7522: pcVar28[1] = '\0';
7523: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7524: *pcVar28 = cVar23;
7525: pcVar28[1] = '\0';
7526: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7527: *pcVar28 = cVar22;
7528: pcVar28[1] = '\0';
7529: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7530: *pcVar28 = cVar21;
7531: pcVar28[1] = '\0';
7532: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
7533: *pcVar28 = cVar20;
7534: pcVar28[1] = '\0';
7535: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
7536: *pcVar28 = cVar33;
7537: pcVar28[1] = '\0';
7538: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
7539: *pcVar28 = cVar10;
7540: pcVar28[1] = '\0';
7541: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7542: }
7543: sVar1 = psVar5[0x1e];
7544: uVar11 = SEXT48((int)uVar31);
7545: iVar17 = iVar18 + 0x40;
7546: pcVar28 = pcVar26;
7547: }
7548: else {
7549: sVar1 = psVar5[0x1e];
7550: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
7551: iVar17 = iVar18;
7552: }
7553: iVar29 = (int)sVar1;
7554: if (iVar29 == 0) goto LAB_0010bd64;
7555: uVar31 = iVar29 >> 0x1f;
7556: uVar16 = uVar31 + iVar29;
7557: iVar29 = 0;
7558: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
7559: LAB_0010a854:
7560: uVar16 = uVar16 & (int)(1 << ((byte)uVar31 & 0x3f)) - 1U |
7561: puVar4[(int)(iVar29 + uVar31)] << ((byte)uVar31 & 0x1f);
7562: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar31) + 0x400) + uVar31;
7563: iVar18 = iVar17 - iVar29;
7564: if (iVar18 < 0) {
7565: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
7566: uVar11 << ((byte)iVar17 & 0x3f);
7567: cVar10 = (char)uVar11;
7568: cVar25 = (char)(uVar11 >> 8);
7569: cVar24 = (char)(uVar11 >> 0x10);
7570: cVar23 = (char)(uVar11 >> 0x18);
7571: cVar22 = (char)(uVar11 >> 0x20);
7572: cVar33 = (char)(uVar11 >> 0x28);
7573: cVar20 = (char)(uVar11 >> 0x30);
7574: cVar21 = (char)(uVar11 >> 0x38);
7575: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
7576: pcVar28[7] = cVar10;
7577: pcVar26 = pcVar28 + 8;
7578: *pcVar28 = cVar21;
7579: pcVar28[1] = cVar20;
7580: pcVar28[2] = cVar33;
7581: pcVar28[3] = cVar22;
7582: pcVar28[4] = cVar23;
7583: pcVar28[5] = cVar24;
7584: pcVar28[6] = cVar25;
7585: }
7586: else {
7587: pcVar28[1] = '\0';
7588: *pcVar28 = cVar21;
7589: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7590: *pcVar28 = cVar20;
7591: pcVar28[1] = '\0';
7592: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
7593: *pcVar28 = cVar33;
7594: pcVar28[1] = '\0';
7595: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
7596: *pcVar28 = cVar22;
7597: pcVar28[1] = '\0';
7598: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7599: *pcVar28 = cVar23;
7600: pcVar28[1] = '\0';
7601: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7602: *pcVar28 = cVar24;
7603: pcVar28[1] = '\0';
7604: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7605: *pcVar28 = cVar25;
7606: pcVar28[1] = '\0';
7607: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
7608: *pcVar28 = cVar10;
7609: pcVar28[1] = '\0';
7610: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7611: }
7612: sVar1 = psVar5[0x25];
7613: uVar11 = SEXT48((int)uVar16);
7614: iVar17 = iVar18 + 0x40;
7615: pcVar28 = pcVar26;
7616: }
7617: else {
7618: sVar1 = psVar5[0x25];
7619: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
7620: iVar17 = iVar18;
7621: }
7622: iVar18 = (int)sVar1;
7623: if (sVar1 == 0) goto LAB_0010a8a2;
7624: uVar16 = iVar18 >> 0x1f;
7625: uVar31 = uVar16 + iVar18;
7626: iVar18 = 0;
7627: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
7628: LAB_0010bdea:
7629: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
7630: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
7631: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
7632: iVar18 = iVar17 - iVar29;
7633: if (iVar18 < 0) {
7634: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
7635: uVar11 << ((byte)iVar17 & 0x3f);
7636: cVar10 = (char)uVar11;
7637: cVar25 = (char)(uVar11 >> 8);
7638: cVar24 = (char)(uVar11 >> 0x10);
7639: cVar23 = (char)(uVar11 >> 0x18);
7640: cVar22 = (char)(uVar11 >> 0x20);
7641: cVar33 = (char)(uVar11 >> 0x28);
7642: cVar20 = (char)(uVar11 >> 0x30);
7643: cVar21 = (char)(uVar11 >> 0x38);
7644: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
7645: pcVar28[7] = cVar10;
7646: pcVar26 = pcVar28 + 8;
7647: *pcVar28 = cVar21;
7648: pcVar28[1] = cVar20;
7649: pcVar28[2] = cVar33;
7650: pcVar28[3] = cVar22;
7651: pcVar28[4] = cVar23;
7652: pcVar28[5] = cVar24;
7653: pcVar28[6] = cVar25;
7654: }
7655: else {
7656: pcVar28[1] = '\0';
7657: *pcVar28 = cVar21;
7658: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7659: *pcVar28 = cVar20;
7660: pcVar28[1] = '\0';
7661: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
7662: *pcVar28 = cVar33;
7663: pcVar28[1] = '\0';
7664: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
7665: *pcVar28 = cVar22;
7666: pcVar28[1] = '\0';
7667: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7668: *pcVar28 = cVar23;
7669: pcVar28[1] = '\0';
7670: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7671: *pcVar28 = cVar24;
7672: pcVar28[1] = '\0';
7673: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7674: *pcVar28 = cVar25;
7675: pcVar28[1] = '\0';
7676: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
7677: *pcVar28 = cVar10;
7678: pcVar28[1] = '\0';
7679: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7680: }
7681: sVar1 = psVar5[0x2c];
7682: uVar11 = SEXT48((int)uVar31);
7683: iVar17 = iVar18 + 0x40;
7684: pcVar28 = pcVar26;
7685: }
7686: else {
7687: sVar1 = psVar5[0x2c];
7688: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
7689: iVar17 = iVar18;
7690: }
7691: iVar29 = (int)sVar1;
7692: if (iVar29 == 0) goto LAB_0010be38;
7693: uVar31 = iVar29 >> 0x1f;
7694: uVar16 = uVar31 + iVar29;
7695: iVar29 = 0;
7696: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
7697: LAB_0010a928:
7698: uVar16 = uVar16 & (int)(1 << ((byte)uVar31 & 0x3f)) - 1U |
7699: puVar4[(int)(iVar29 + uVar31)] << ((byte)uVar31 & 0x1f);
7700: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar29 + uVar31) + 0x400) + uVar31;
7701: iVar18 = iVar17 - iVar29;
7702: if (iVar18 < 0) {
7703: uVar11 = (long)((int)uVar16 >> (-(char)iVar18 & 0x1fU)) |
7704: uVar11 << ((byte)iVar17 & 0x3f);
7705: cVar10 = (char)uVar11;
7706: cVar24 = (char)(uVar11 >> 8);
7707: cVar23 = (char)(uVar11 >> 0x10);
7708: cVar22 = (char)(uVar11 >> 0x18);
7709: cVar21 = (char)(uVar11 >> 0x20);
7710: cVar33 = (char)(uVar11 >> 0x28);
7711: cVar20 = (char)(uVar11 >> 0x30);
7712: cVar25 = (char)(uVar11 >> 0x38);
7713: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
7714: pcVar28[7] = cVar10;
7715: pcVar26 = pcVar28 + 8;
7716: *pcVar28 = cVar25;
7717: pcVar28[1] = cVar20;
7718: pcVar28[2] = cVar33;
7719: pcVar28[3] = cVar21;
7720: pcVar28[4] = cVar22;
7721: pcVar28[5] = cVar23;
7722: pcVar28[6] = cVar24;
7723: }
7724: else {
7725: pcVar28[1] = '\0';
7726: *pcVar28 = cVar25;
7727: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7728: *pcVar28 = cVar20;
7729: pcVar28[1] = '\0';
7730: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
7731: *pcVar28 = cVar33;
7732: pcVar28[1] = '\0';
7733: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
7734: *pcVar28 = cVar21;
7735: pcVar28[1] = '\0';
7736: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
7737: *pcVar28 = cVar22;
7738: pcVar28[1] = '\0';
7739: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7740: *pcVar28 = cVar23;
7741: pcVar28[1] = '\0';
7742: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7743: *pcVar28 = cVar24;
7744: pcVar28[1] = '\0';
7745: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7746: *pcVar28 = cVar10;
7747: pcVar28[1] = '\0';
7748: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7749: }
7750: sVar1 = psVar5[0x33];
7751: uVar11 = SEXT48((int)uVar16);
7752: iVar17 = iVar18 + 0x40;
7753: pcVar28 = pcVar26;
7754: }
7755: else {
7756: sVar1 = psVar5[0x33];
7757: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar16;
7758: iVar17 = iVar18;
7759: }
7760: iVar18 = (int)sVar1;
7761: pcVar26 = pcVar28;
7762: if (sVar1 == 0) goto LAB_0010a976;
7763: uVar16 = iVar18 >> 0x1f;
7764: uVar31 = uVar16 + iVar18;
7765: iVar18 = 0;
7766: uVar16 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar31)];
7767: iVar32 = iVar17;
7768: LAB_0010bebe:
7769: uVar31 = uVar31 & (int)(1 << ((byte)uVar16 & 0x3f)) - 1U |
7770: puVar4[(int)(iVar18 + uVar16)] << ((byte)uVar16 & 0x1f);
7771: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(iVar18 + uVar16) + 0x400) + uVar16;
7772: iVar17 = iVar32 - iVar29;
7773: if (iVar17 < 0) {
7774: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
7775: uVar11 << ((byte)iVar32 & 0x3f);
7776: cVar10 = (char)uVar11;
7777: cVar22 = (char)(uVar11 >> 8);
7778: cVar23 = (char)(uVar11 >> 0x10);
7779: cVar24 = (char)(uVar11 >> 0x18);
7780: cVar25 = (char)(uVar11 >> 0x20);
7781: cVar21 = (char)(uVar11 >> 0x28);
7782: cVar33 = (char)(uVar11 >> 0x30);
7783: cVar20 = (char)(uVar11 >> 0x38);
7784: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
7785: pcVar28[7] = cVar10;
7786: pcVar26 = pcVar28 + 8;
7787: *pcVar28 = cVar20;
7788: pcVar28[1] = cVar33;
7789: pcVar28[2] = cVar21;
7790: pcVar28[3] = cVar25;
7791: pcVar28[4] = cVar24;
7792: pcVar28[5] = cVar23;
7793: pcVar28[6] = cVar22;
7794: }
7795: else {
7796: pcVar28[1] = '\0';
7797: *pcVar28 = cVar20;
7798: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7799: *pcVar28 = cVar33;
7800: pcVar28[1] = '\0';
7801: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
7802: *pcVar28 = cVar21;
7803: pcVar28[1] = '\0';
7804: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
7805: *pcVar28 = cVar25;
7806: pcVar28[1] = '\0';
7807: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
7808: *pcVar28 = cVar24;
7809: pcVar28[1] = '\0';
7810: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7811: *pcVar28 = cVar23;
7812: pcVar28[1] = '\0';
7813: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7814: *pcVar28 = cVar22;
7815: pcVar28[1] = '\0';
7816: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7817: *pcVar28 = cVar10;
7818: pcVar28[1] = '\0';
7819: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7820: }
7821: iVar17 = iVar17 + 0x40;
7822: uVar11 = SEXT48((int)uVar31);
7823: }
7824: else {
7825: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
7826: pcVar26 = pcVar28;
7827: }
7828: iVar29 = (int)psVar5[0x3a];
7829: if (iVar29 != 0) {
7830: uVar31 = iVar29 >> 0x1f;
7831: uVar16 = uVar31 + iVar29;
7832: iVar29 = 0;
7833: uVar31 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar16)];
7834: goto LAB_0010a9fc;
7835: }
7836: LAB_0010b750:
7837: sVar1 = psVar5[0x3b];
7838: uVar31 = iVar29 + 0x10;
7839: if (sVar1 != 0) {
7840: uVar35 = (int)sVar1 >> 0x1f;
7841: uVar16 = (int)sVar1 + uVar35;
7842: uVar35 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar35 ^ uVar16)];
7843: if (0xff < (int)uVar31) {
7844: iVar18 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
7845: if (iVar18 < 0) {
7846: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
7847: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
7848: cVar10 = (char)uVar14;
7849: cVar20 = (char)(uVar14 >> 8);
7850: cVar22 = (char)(uVar14 >> 0x10);
7851: cVar23 = (char)(uVar14 >> 0x18);
7852: cVar24 = (char)(uVar11 >> 0x20);
7853: cVar25 = (char)(uVar11 >> 0x28);
7854: cVar21 = (char)(uVar11 >> 0x30);
7855: cVar33 = (char)(uVar11 >> 0x38);
7856: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7857: pcVar26[7] = cVar10;
7858: pcVar28 = pcVar26 + 8;
7859: *pcVar26 = cVar33;
7860: pcVar26[1] = cVar21;
7861: pcVar26[2] = cVar25;
7862: pcVar26[3] = cVar24;
7863: pcVar26[4] = cVar23;
7864: pcVar26[5] = cVar22;
7865: pcVar26[6] = cVar20;
7866: }
7867: else {
7868: pcVar26[1] = '\0';
7869: *pcVar26 = cVar33;
7870: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7871: *pcVar26 = cVar21;
7872: pcVar26[1] = '\0';
7873: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
7874: *pcVar26 = cVar25;
7875: pcVar26[1] = '\0';
7876: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
7877: *pcVar26 = cVar24;
7878: pcVar26[1] = '\0';
7879: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
7880: *pcVar26 = cVar23;
7881: pcVar26[1] = '\0';
7882: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
7883: *pcVar26 = cVar22;
7884: pcVar26[1] = '\0';
7885: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
7886: *pcVar26 = cVar20;
7887: pcVar26[1] = '\0';
7888: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
7889: *pcVar26 = cVar10;
7890: pcVar26[1] = '\0';
7891: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
7892: }
7893: uVar11 = (ulong)puVar4[0xf0];
7894: iVar18 = iVar18 + 0x40;
7895: uVar14 = uVar11;
7896: }
7897: else {
7898: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
7899: pcVar28 = pcVar26;
7900: uVar14 = (ulong)puVar4[0xf0];
7901: }
7902: pcVar26 = pcVar28;
7903: iVar17 = iVar18;
7904: if (0xff < (int)(iVar29 - 0xf0U)) {
7905: iVar32 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
7906: if (iVar32 < 0) {
7907: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
7908: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar32 & 0x1fU);
7909: cVar10 = (char)uVar14;
7910: cVar25 = (char)(uVar14 >> 8);
7911: cVar24 = (char)(uVar14 >> 0x10);
7912: cVar20 = (char)(uVar14 >> 0x18);
7913: cVar23 = (char)(uVar11 >> 0x20);
7914: cVar22 = (char)(uVar11 >> 0x28);
7915: cVar21 = (char)(uVar11 >> 0x30);
7916: cVar33 = (char)(uVar11 >> 0x38);
7917: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7918: pcVar28[7] = cVar10;
7919: pcVar27 = pcVar28 + 8;
7920: *pcVar28 = cVar33;
7921: pcVar28[1] = cVar21;
7922: pcVar28[2] = cVar22;
7923: pcVar28[3] = cVar23;
7924: pcVar28[4] = cVar20;
7925: pcVar28[5] = cVar24;
7926: pcVar28[6] = cVar25;
7927: }
7928: else {
7929: pcVar28[1] = '\0';
7930: *pcVar28 = cVar33;
7931: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7932: *pcVar28 = cVar21;
7933: pcVar28[1] = '\0';
7934: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
7935: *pcVar28 = cVar22;
7936: pcVar28[1] = '\0';
7937: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
7938: *pcVar28 = cVar23;
7939: pcVar28[1] = '\0';
7940: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
7941: *pcVar28 = cVar20;
7942: pcVar28[1] = '\0';
7943: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
7944: *pcVar28 = cVar24;
7945: pcVar28[1] = '\0';
7946: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
7947: *pcVar28 = cVar25;
7948: pcVar28[1] = '\0';
7949: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
7950: *pcVar28 = cVar10;
7951: pcVar28[1] = '\0';
7952: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
7953: }
7954: uVar11 = (ulong)puVar4[0xf0];
7955: iVar32 = iVar32 + 0x40;
7956: uVar14 = uVar11;
7957: }
7958: else {
7959: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
7960: pcVar27 = pcVar28;
7961: }
7962: pcVar26 = pcVar27;
7963: iVar17 = iVar32;
7964: if (iVar29 == 0x2f0) {
7965: iVar17 = iVar32 - (char)*(byte *)(puVar4 + 0x13c);
7966: if (iVar17 < 0) {
7967: uVar11 = uVar11 << ((byte)iVar32 & 0x3f);
7968: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
7969: cVar10 = (char)uVar14;
7970: cVar25 = (char)(uVar14 >> 8);
7971: cVar24 = (char)(uVar14 >> 0x10);
7972: cVar23 = (char)(uVar14 >> 0x18);
7973: cVar33 = (char)(uVar11 >> 0x20);
7974: cVar22 = (char)(uVar11 >> 0x28);
7975: cVar21 = (char)(uVar11 >> 0x30);
7976: cVar20 = (char)(uVar11 >> 0x38);
7977: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
7978: pcVar27[7] = cVar10;
7979: pcVar26 = pcVar27 + 8;
7980: *pcVar27 = cVar20;
7981: pcVar27[1] = cVar21;
7982: pcVar27[2] = cVar22;
7983: pcVar27[3] = cVar33;
7984: pcVar27[4] = cVar23;
7985: pcVar27[5] = cVar24;
7986: pcVar27[6] = cVar25;
7987: }
7988: else {
7989: pcVar27[1] = '\0';
7990: *pcVar27 = cVar20;
7991: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
7992: *pcVar27 = cVar21;
7993: pcVar27[1] = '\0';
7994: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
7995: *pcVar27 = cVar22;
7996: pcVar27[1] = '\0';
7997: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
7998: *pcVar27 = cVar33;
7999: pcVar27[1] = '\0';
8000: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
8001: *pcVar27 = cVar23;
8002: pcVar27[1] = '\0';
8003: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
8004: *pcVar27 = cVar24;
8005: pcVar27[1] = '\0';
8006: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
8007: *pcVar27 = cVar25;
8008: pcVar27[1] = '\0';
8009: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
8010: *pcVar27 = cVar10;
8011: pcVar27[1] = '\0';
8012: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
8013: }
8014: iVar17 = iVar17 + 0x40;
8015: uVar11 = (ulong)puVar4[0xf0];
8016: }
8017: else {
8018: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8019: }
8020: }
8021: }
8022: uVar31 = iVar29 - 0xf0U & 0xff;
8023: }
8024: goto LAB_0010b7f2;
8025: }
8026: LAB_0010aa4a:
8027: sVar1 = psVar5[0x34];
8028: uVar16 = uVar31 + 0x10;
8029: if (sVar1 != 0) {
8030: uVar19 = (int)sVar1 >> 0x1f;
8031: uVar35 = (int)sVar1 + uVar19;
8032: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
8033: if (0xff < (int)uVar16) {
8034: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
8035: if (iVar29 < 0) {
8036: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
8037: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
8038: cVar10 = (char)uVar14;
8039: cVar33 = (char)(uVar14 >> 8);
8040: cVar20 = (char)(uVar14 >> 0x10);
8041: cVar21 = (char)(uVar14 >> 0x18);
8042: cVar22 = (char)(uVar11 >> 0x20);
8043: cVar25 = (char)(uVar11 >> 0x28);
8044: cVar24 = (char)(uVar11 >> 0x30);
8045: cVar23 = (char)(uVar11 >> 0x38);
8046: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8047: pcVar26[7] = cVar10;
8048: pcVar28 = pcVar26 + 8;
8049: *pcVar26 = cVar23;
8050: pcVar26[1] = cVar24;
8051: pcVar26[2] = cVar25;
8052: pcVar26[3] = cVar22;
8053: pcVar26[4] = cVar21;
8054: pcVar26[5] = cVar20;
8055: pcVar26[6] = cVar33;
8056: }
8057: else {
8058: pcVar26[1] = '\0';
8059: *pcVar26 = cVar23;
8060: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8061: *pcVar26 = cVar24;
8062: pcVar26[1] = '\0';
8063: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
8064: *pcVar26 = cVar25;
8065: pcVar26[1] = '\0';
8066: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
8067: *pcVar26 = cVar22;
8068: pcVar26[1] = '\0';
8069: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
8070: *pcVar26 = cVar21;
8071: pcVar26[1] = '\0';
8072: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
8073: *pcVar26 = cVar20;
8074: pcVar26[1] = '\0';
8075: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
8076: *pcVar26 = cVar33;
8077: pcVar26[1] = '\0';
8078: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
8079: *pcVar26 = cVar10;
8080: pcVar26[1] = '\0';
8081: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
8082: }
8083: uVar11 = (ulong)puVar4[0xf0];
8084: iVar29 = iVar29 + 0x40;
8085: uVar14 = uVar11;
8086: }
8087: else {
8088: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
8089: pcVar28 = pcVar26;
8090: uVar14 = (ulong)puVar4[0xf0];
8091: }
8092: pcVar26 = pcVar28;
8093: iVar17 = iVar29;
8094: if (0xff < (int)(uVar31 - 0xf0)) {
8095: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
8096: if (iVar18 < 0) {
8097: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
8098: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
8099: cVar10 = (char)uVar14;
8100: cVar25 = (char)(uVar14 >> 8);
8101: cVar24 = (char)(uVar14 >> 0x10);
8102: cVar23 = (char)(uVar14 >> 0x18);
8103: cVar22 = (char)(uVar11 >> 0x20);
8104: cVar21 = (char)(uVar11 >> 0x28);
8105: cVar20 = (char)(uVar11 >> 0x30);
8106: cVar33 = (char)(uVar11 >> 0x38);
8107: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8108: pcVar28[7] = cVar10;
8109: pcVar27 = pcVar28 + 8;
8110: *pcVar28 = cVar33;
8111: pcVar28[1] = cVar20;
8112: pcVar28[2] = cVar21;
8113: pcVar28[3] = cVar22;
8114: pcVar28[4] = cVar23;
8115: pcVar28[5] = cVar24;
8116: pcVar28[6] = cVar25;
8117: }
8118: else {
8119: pcVar28[1] = '\0';
8120: *pcVar28 = cVar33;
8121: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8122: *pcVar28 = cVar20;
8123: pcVar28[1] = '\0';
8124: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
8125: *pcVar28 = cVar21;
8126: pcVar28[1] = '\0';
8127: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
8128: *pcVar28 = cVar22;
8129: pcVar28[1] = '\0';
8130: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
8131: *pcVar28 = cVar23;
8132: pcVar28[1] = '\0';
8133: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
8134: *pcVar28 = cVar24;
8135: pcVar28[1] = '\0';
8136: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
8137: *pcVar28 = cVar25;
8138: pcVar28[1] = '\0';
8139: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
8140: *pcVar28 = cVar10;
8141: pcVar28[1] = '\0';
8142: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
8143: }
8144: uVar11 = (ulong)puVar4[0xf0];
8145: iVar18 = iVar18 + 0x40;
8146: uVar14 = uVar11;
8147: }
8148: else {
8149: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8150: pcVar27 = pcVar28;
8151: }
8152: pcVar26 = pcVar27;
8153: iVar17 = iVar18;
8154: if (0x2ef < (int)uVar31) {
8155: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
8156: if (iVar17 < 0) {
8157: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
8158: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
8159: cVar10 = (char)uVar14;
8160: cVar20 = (char)(uVar14 >> 8);
8161: cVar21 = (char)(uVar14 >> 0x10);
8162: cVar25 = (char)(uVar14 >> 0x18);
8163: cVar24 = (char)(uVar11 >> 0x20);
8164: cVar23 = (char)(uVar11 >> 0x28);
8165: cVar22 = (char)(uVar11 >> 0x30);
8166: cVar33 = (char)(uVar11 >> 0x38);
8167: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8168: pcVar27[7] = cVar10;
8169: pcVar26 = pcVar27 + 8;
8170: *pcVar27 = cVar33;
8171: pcVar27[1] = cVar22;
8172: pcVar27[2] = cVar23;
8173: pcVar27[3] = cVar24;
8174: pcVar27[4] = cVar25;
8175: pcVar27[5] = cVar21;
8176: pcVar27[6] = cVar20;
8177: }
8178: else {
8179: pcVar27[1] = '\0';
8180: *pcVar27 = cVar33;
8181: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8182: *pcVar27 = cVar22;
8183: pcVar27[1] = '\0';
8184: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
8185: *pcVar27 = cVar23;
8186: pcVar27[1] = '\0';
8187: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
8188: *pcVar27 = cVar24;
8189: pcVar27[1] = '\0';
8190: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
8191: *pcVar27 = cVar25;
8192: pcVar27[1] = '\0';
8193: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
8194: *pcVar27 = cVar21;
8195: pcVar27[1] = '\0';
8196: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
8197: *pcVar27 = cVar20;
8198: pcVar27[1] = '\0';
8199: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
8200: *pcVar27 = cVar10;
8201: pcVar27[1] = '\0';
8202: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
8203: }
8204: iVar17 = iVar17 + 0x40;
8205: uVar11 = (ulong)puVar4[0xf0];
8206: }
8207: else {
8208: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8209: }
8210: }
8211: }
8212: uVar16 = uVar31 - 0xf0 & 0xff;
8213: }
8214: goto LAB_0010aaec;
8215: }
8216: LAB_0010b840:
8217: sVar1 = psVar5[0x2d];
8218: uVar31 = uVar16 + 0x10;
8219: if (sVar1 != 0) {
8220: uVar19 = (int)sVar1 >> 0x1f;
8221: uVar35 = (int)sVar1 + uVar19;
8222: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
8223: if (0xff < (int)uVar31) {
8224: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
8225: if (iVar29 < 0) {
8226: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
8227: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
8228: cVar10 = (char)uVar14;
8229: cVar25 = (char)(uVar14 >> 8);
8230: cVar24 = (char)(uVar14 >> 0x10);
8231: cVar23 = (char)(uVar14 >> 0x18);
8232: cVar22 = (char)(uVar11 >> 0x20);
8233: cVar21 = (char)(uVar11 >> 0x28);
8234: cVar20 = (char)(uVar11 >> 0x30);
8235: cVar33 = (char)(uVar11 >> 0x38);
8236: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8237: pcVar26[7] = cVar10;
8238: pcVar28 = pcVar26 + 8;
8239: *pcVar26 = cVar33;
8240: pcVar26[1] = cVar20;
8241: pcVar26[2] = cVar21;
8242: pcVar26[3] = cVar22;
8243: pcVar26[4] = cVar23;
8244: pcVar26[5] = cVar24;
8245: pcVar26[6] = cVar25;
8246: }
8247: else {
8248: pcVar26[1] = '\0';
8249: *pcVar26 = cVar33;
8250: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8251: *pcVar26 = cVar20;
8252: pcVar26[1] = '\0';
8253: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
8254: *pcVar26 = cVar21;
8255: pcVar26[1] = '\0';
8256: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
8257: *pcVar26 = cVar22;
8258: pcVar26[1] = '\0';
8259: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
8260: *pcVar26 = cVar23;
8261: pcVar26[1] = '\0';
8262: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
8263: *pcVar26 = cVar24;
8264: pcVar26[1] = '\0';
8265: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
8266: *pcVar26 = cVar25;
8267: pcVar26[1] = '\0';
8268: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
8269: *pcVar26 = cVar10;
8270: pcVar26[1] = '\0';
8271: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
8272: }
8273: uVar11 = (ulong)puVar4[0xf0];
8274: iVar29 = iVar29 + 0x40;
8275: uVar14 = uVar11;
8276: }
8277: else {
8278: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
8279: pcVar28 = pcVar26;
8280: uVar14 = (ulong)puVar4[0xf0];
8281: }
8282: pcVar26 = pcVar28;
8283: iVar17 = iVar29;
8284: if (0xff < (int)(uVar16 - 0xf0)) {
8285: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
8286: if (iVar18 < 0) {
8287: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
8288: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
8289: cVar10 = (char)uVar14;
8290: cVar33 = (char)(uVar14 >> 8);
8291: cVar20 = (char)(uVar14 >> 0x10);
8292: cVar21 = (char)(uVar14 >> 0x18);
8293: cVar22 = (char)(uVar11 >> 0x20);
8294: cVar23 = (char)(uVar11 >> 0x28);
8295: cVar24 = (char)(uVar11 >> 0x30);
8296: cVar25 = (char)(uVar11 >> 0x38);
8297: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8298: pcVar28[7] = cVar10;
8299: pcVar27 = pcVar28 + 8;
8300: *pcVar28 = cVar25;
8301: pcVar28[1] = cVar24;
8302: pcVar28[2] = cVar23;
8303: pcVar28[3] = cVar22;
8304: pcVar28[4] = cVar21;
8305: pcVar28[5] = cVar20;
8306: pcVar28[6] = cVar33;
8307: }
8308: else {
8309: pcVar28[1] = '\0';
8310: *pcVar28 = cVar25;
8311: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8312: *pcVar28 = cVar24;
8313: pcVar28[1] = '\0';
8314: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
8315: *pcVar28 = cVar23;
8316: pcVar28[1] = '\0';
8317: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
8318: *pcVar28 = cVar22;
8319: pcVar28[1] = '\0';
8320: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
8321: *pcVar28 = cVar21;
8322: pcVar28[1] = '\0';
8323: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
8324: *pcVar28 = cVar20;
8325: pcVar28[1] = '\0';
8326: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
8327: *pcVar28 = cVar33;
8328: pcVar28[1] = '\0';
8329: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
8330: *pcVar28 = cVar10;
8331: pcVar28[1] = '\0';
8332: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
8333: }
8334: uVar11 = (ulong)puVar4[0xf0];
8335: iVar18 = iVar18 + 0x40;
8336: uVar14 = uVar11;
8337: }
8338: else {
8339: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8340: pcVar27 = pcVar28;
8341: }
8342: pcVar26 = pcVar27;
8343: iVar17 = iVar18;
8344: if (0x2ef < (int)uVar16) {
8345: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
8346: if (iVar17 < 0) {
8347: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
8348: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
8349: cVar10 = (char)uVar14;
8350: cVar22 = (char)(uVar14 >> 8);
8351: cVar23 = (char)(uVar14 >> 0x10);
8352: cVar25 = (char)(uVar14 >> 0x18);
8353: cVar24 = (char)(uVar11 >> 0x20);
8354: cVar21 = (char)(uVar11 >> 0x28);
8355: cVar20 = (char)(uVar11 >> 0x30);
8356: cVar33 = (char)(uVar11 >> 0x38);
8357: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8358: pcVar27[7] = cVar10;
8359: pcVar26 = pcVar27 + 8;
8360: *pcVar27 = cVar33;
8361: pcVar27[1] = cVar20;
8362: pcVar27[2] = cVar21;
8363: pcVar27[3] = cVar24;
8364: pcVar27[4] = cVar25;
8365: pcVar27[5] = cVar23;
8366: pcVar27[6] = cVar22;
8367: }
8368: else {
8369: pcVar27[1] = '\0';
8370: *pcVar27 = cVar33;
8371: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8372: *pcVar27 = cVar20;
8373: pcVar27[1] = '\0';
8374: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
8375: *pcVar27 = cVar21;
8376: pcVar27[1] = '\0';
8377: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
8378: *pcVar27 = cVar24;
8379: pcVar27[1] = '\0';
8380: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
8381: *pcVar27 = cVar25;
8382: pcVar27[1] = '\0';
8383: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
8384: *pcVar27 = cVar23;
8385: pcVar27[1] = '\0';
8386: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
8387: *pcVar27 = cVar22;
8388: pcVar27[1] = '\0';
8389: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
8390: *pcVar27 = cVar10;
8391: pcVar27[1] = '\0';
8392: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
8393: }
8394: iVar17 = iVar17 + 0x40;
8395: uVar11 = (ulong)puVar4[0xf0];
8396: }
8397: else {
8398: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8399: }
8400: }
8401: }
8402: uVar31 = uVar16 - 0xf0 & 0xff;
8403: }
8404: goto LAB_0010b8e2;
8405: }
8406: LAB_0010ab3a:
8407: sVar1 = psVar5[0x26];
8408: uVar16 = uVar31 + 0x10;
8409: if (sVar1 != 0) {
8410: uVar19 = (int)sVar1 >> 0x1f;
8411: uVar35 = (int)sVar1 + uVar19;
8412: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
8413: if (0xff < (int)uVar16) {
8414: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
8415: if (iVar29 < 0) {
8416: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
8417: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
8418: cVar10 = (char)uVar14;
8419: cVar25 = (char)(uVar14 >> 8);
8420: cVar24 = (char)(uVar14 >> 0x10);
8421: cVar23 = (char)(uVar14 >> 0x18);
8422: cVar22 = (char)(uVar11 >> 0x20);
8423: cVar21 = (char)(uVar11 >> 0x28);
8424: cVar20 = (char)(uVar11 >> 0x30);
8425: cVar33 = (char)(uVar11 >> 0x38);
8426: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8427: pcVar26[7] = cVar10;
8428: pcVar28 = pcVar26 + 8;
8429: *pcVar26 = cVar33;
8430: pcVar26[1] = cVar20;
8431: pcVar26[2] = cVar21;
8432: pcVar26[3] = cVar22;
8433: pcVar26[4] = cVar23;
8434: pcVar26[5] = cVar24;
8435: pcVar26[6] = cVar25;
8436: }
8437: else {
8438: pcVar26[1] = '\0';
8439: *pcVar26 = cVar33;
8440: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8441: *pcVar26 = cVar20;
8442: pcVar26[1] = '\0';
8443: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
8444: *pcVar26 = cVar21;
8445: pcVar26[1] = '\0';
8446: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
8447: *pcVar26 = cVar22;
8448: pcVar26[1] = '\0';
8449: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
8450: *pcVar26 = cVar23;
8451: pcVar26[1] = '\0';
8452: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
8453: *pcVar26 = cVar24;
8454: pcVar26[1] = '\0';
8455: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
8456: *pcVar26 = cVar25;
8457: pcVar26[1] = '\0';
8458: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
8459: *pcVar26 = cVar10;
8460: pcVar26[1] = '\0';
8461: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
8462: }
8463: uVar11 = (ulong)puVar4[0xf0];
8464: iVar29 = iVar29 + 0x40;
8465: uVar14 = uVar11;
8466: }
8467: else {
8468: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
8469: pcVar28 = pcVar26;
8470: uVar14 = (ulong)puVar4[0xf0];
8471: }
8472: pcVar26 = pcVar28;
8473: iVar17 = iVar29;
8474: if (0xff < (int)(uVar31 - 0xf0)) {
8475: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
8476: if (iVar18 < 0) {
8477: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
8478: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
8479: cVar10 = (char)uVar14;
8480: cVar33 = (char)(uVar14 >> 8);
8481: cVar20 = (char)(uVar14 >> 0x10);
8482: cVar21 = (char)(uVar14 >> 0x18);
8483: cVar22 = (char)(uVar11 >> 0x20);
8484: cVar23 = (char)(uVar11 >> 0x28);
8485: cVar24 = (char)(uVar11 >> 0x30);
8486: cVar25 = (char)(uVar11 >> 0x38);
8487: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8488: pcVar28[7] = cVar10;
8489: pcVar27 = pcVar28 + 8;
8490: *pcVar28 = cVar25;
8491: pcVar28[1] = cVar24;
8492: pcVar28[2] = cVar23;
8493: pcVar28[3] = cVar22;
8494: pcVar28[4] = cVar21;
8495: pcVar28[5] = cVar20;
8496: pcVar28[6] = cVar33;
8497: }
8498: else {
8499: pcVar28[1] = '\0';
8500: *pcVar28 = cVar25;
8501: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8502: *pcVar28 = cVar24;
8503: pcVar28[1] = '\0';
8504: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
8505: *pcVar28 = cVar23;
8506: pcVar28[1] = '\0';
8507: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
8508: *pcVar28 = cVar22;
8509: pcVar28[1] = '\0';
8510: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
8511: *pcVar28 = cVar21;
8512: pcVar28[1] = '\0';
8513: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
8514: *pcVar28 = cVar20;
8515: pcVar28[1] = '\0';
8516: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
8517: *pcVar28 = cVar33;
8518: pcVar28[1] = '\0';
8519: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
8520: *pcVar28 = cVar10;
8521: pcVar28[1] = '\0';
8522: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
8523: }
8524: uVar11 = (ulong)puVar4[0xf0];
8525: iVar18 = iVar18 + 0x40;
8526: uVar14 = uVar11;
8527: }
8528: else {
8529: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8530: pcVar27 = pcVar28;
8531: }
8532: pcVar26 = pcVar27;
8533: iVar17 = iVar18;
8534: if (0x2ef < (int)uVar31) {
8535: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
8536: if (iVar17 < 0) {
8537: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
8538: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
8539: cVar10 = (char)uVar14;
8540: cVar25 = (char)(uVar14 >> 8);
8541: cVar24 = (char)(uVar14 >> 0x10);
8542: cVar22 = (char)(uVar14 >> 0x18);
8543: cVar33 = (char)(uVar11 >> 0x20);
8544: cVar20 = (char)(uVar11 >> 0x28);
8545: cVar21 = (char)(uVar11 >> 0x30);
8546: cVar23 = (char)(uVar11 >> 0x38);
8547: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8548: pcVar27[7] = cVar10;
8549: pcVar26 = pcVar27 + 8;
8550: *pcVar27 = cVar23;
8551: pcVar27[1] = cVar21;
8552: pcVar27[2] = cVar20;
8553: pcVar27[3] = cVar33;
8554: pcVar27[4] = cVar22;
8555: pcVar27[5] = cVar24;
8556: pcVar27[6] = cVar25;
8557: }
8558: else {
8559: pcVar27[1] = '\0';
8560: *pcVar27 = cVar23;
8561: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8562: *pcVar27 = cVar21;
8563: pcVar27[1] = '\0';
8564: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
8565: *pcVar27 = cVar20;
8566: pcVar27[1] = '\0';
8567: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
8568: *pcVar27 = cVar33;
8569: pcVar27[1] = '\0';
8570: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
8571: *pcVar27 = cVar22;
8572: pcVar27[1] = '\0';
8573: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
8574: *pcVar27 = cVar24;
8575: pcVar27[1] = '\0';
8576: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
8577: *pcVar27 = cVar25;
8578: pcVar27[1] = '\0';
8579: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
8580: *pcVar27 = cVar10;
8581: pcVar27[1] = '\0';
8582: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
8583: }
8584: iVar17 = iVar17 + 0x40;
8585: uVar11 = (ulong)puVar4[0xf0];
8586: }
8587: else {
8588: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8589: }
8590: }
8591: }
8592: uVar16 = uVar31 - 0xf0 & 0xff;
8593: }
8594: goto LAB_0010abdc;
8595: }
8596: LAB_0010b930:
8597: sVar1 = psVar5[0x1f];
8598: uVar31 = uVar16 + 0x10;
8599: if (sVar1 != 0) {
8600: uVar19 = (int)sVar1 >> 0x1f;
8601: uVar35 = (int)sVar1 + uVar19;
8602: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
8603: if (0xff < (int)uVar31) {
8604: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
8605: if (iVar29 < 0) {
8606: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
8607: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
8608: cVar10 = (char)uVar14;
8609: cVar25 = (char)(uVar14 >> 8);
8610: cVar24 = (char)(uVar14 >> 0x10);
8611: cVar23 = (char)(uVar14 >> 0x18);
8612: cVar33 = (char)(uVar11 >> 0x20);
8613: cVar22 = (char)(uVar11 >> 0x28);
8614: cVar21 = (char)(uVar11 >> 0x30);
8615: cVar20 = (char)(uVar11 >> 0x38);
8616: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8617: pcVar26[7] = cVar10;
8618: pcVar28 = pcVar26 + 8;
8619: *pcVar26 = cVar20;
8620: pcVar26[1] = cVar21;
8621: pcVar26[2] = cVar22;
8622: pcVar26[3] = cVar33;
8623: pcVar26[4] = cVar23;
8624: pcVar26[5] = cVar24;
8625: pcVar26[6] = cVar25;
8626: }
8627: else {
8628: pcVar26[1] = '\0';
8629: *pcVar26 = cVar20;
8630: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8631: *pcVar26 = cVar21;
8632: pcVar26[1] = '\0';
8633: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
8634: *pcVar26 = cVar22;
8635: pcVar26[1] = '\0';
8636: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
8637: *pcVar26 = cVar33;
8638: pcVar26[1] = '\0';
8639: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
8640: *pcVar26 = cVar23;
8641: pcVar26[1] = '\0';
8642: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
8643: *pcVar26 = cVar24;
8644: pcVar26[1] = '\0';
8645: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
8646: *pcVar26 = cVar25;
8647: pcVar26[1] = '\0';
8648: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
8649: *pcVar26 = cVar10;
8650: pcVar26[1] = '\0';
8651: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
8652: }
8653: uVar11 = (ulong)puVar4[0xf0];
8654: iVar29 = iVar29 + 0x40;
8655: uVar14 = uVar11;
8656: }
8657: else {
8658: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
8659: pcVar28 = pcVar26;
8660: uVar14 = (ulong)puVar4[0xf0];
8661: }
8662: pcVar26 = pcVar28;
8663: iVar17 = iVar29;
8664: if (0xff < (int)(uVar16 - 0xf0)) {
8665: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
8666: if (iVar18 < 0) {
8667: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
8668: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
8669: cVar10 = (char)uVar14;
8670: cVar25 = (char)(uVar14 >> 8);
8671: cVar24 = (char)(uVar14 >> 0x10);
8672: cVar23 = (char)(uVar14 >> 0x18);
8673: cVar22 = (char)(uVar11 >> 0x20);
8674: cVar21 = (char)(uVar11 >> 0x28);
8675: cVar20 = (char)(uVar11 >> 0x30);
8676: cVar33 = (char)(uVar11 >> 0x38);
8677: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8678: pcVar28[7] = cVar10;
8679: pcVar27 = pcVar28 + 8;
8680: *pcVar28 = cVar33;
8681: pcVar28[1] = cVar20;
8682: pcVar28[2] = cVar21;
8683: pcVar28[3] = cVar22;
8684: pcVar28[4] = cVar23;
8685: pcVar28[5] = cVar24;
8686: pcVar28[6] = cVar25;
8687: }
8688: else {
8689: pcVar28[1] = '\0';
8690: *pcVar28 = cVar33;
8691: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8692: *pcVar28 = cVar20;
8693: pcVar28[1] = '\0';
8694: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
8695: *pcVar28 = cVar21;
8696: pcVar28[1] = '\0';
8697: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
8698: *pcVar28 = cVar22;
8699: pcVar28[1] = '\0';
8700: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
8701: *pcVar28 = cVar23;
8702: pcVar28[1] = '\0';
8703: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
8704: *pcVar28 = cVar24;
8705: pcVar28[1] = '\0';
8706: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
8707: *pcVar28 = cVar25;
8708: pcVar28[1] = '\0';
8709: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
8710: *pcVar28 = cVar10;
8711: pcVar28[1] = '\0';
8712: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
8713: }
8714: uVar11 = (ulong)puVar4[0xf0];
8715: iVar18 = iVar18 + 0x40;
8716: uVar14 = uVar11;
8717: }
8718: else {
8719: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8720: pcVar27 = pcVar28;
8721: }
8722: pcVar26 = pcVar27;
8723: iVar17 = iVar18;
8724: if (0x2ef < (int)uVar16) {
8725: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
8726: if (iVar17 < 0) {
8727: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
8728: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
8729: cVar10 = (char)uVar14;
8730: cVar22 = (char)(uVar14 >> 8);
8731: cVar23 = (char)(uVar14 >> 0x10);
8732: cVar24 = (char)(uVar14 >> 0x18);
8733: cVar25 = (char)(uVar11 >> 0x20);
8734: cVar33 = (char)(uVar11 >> 0x28);
8735: cVar20 = (char)(uVar11 >> 0x30);
8736: cVar21 = (char)(uVar11 >> 0x38);
8737: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8738: pcVar27[7] = cVar10;
8739: pcVar26 = pcVar27 + 8;
8740: *pcVar27 = cVar21;
8741: pcVar27[1] = cVar20;
8742: pcVar27[2] = cVar33;
8743: pcVar27[3] = cVar25;
8744: pcVar27[4] = cVar24;
8745: pcVar27[5] = cVar23;
8746: pcVar27[6] = cVar22;
8747: }
8748: else {
8749: pcVar27[1] = '\0';
8750: *pcVar27 = cVar21;
8751: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8752: *pcVar27 = cVar20;
8753: pcVar27[1] = '\0';
8754: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
8755: *pcVar27 = cVar33;
8756: pcVar27[1] = '\0';
8757: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
8758: *pcVar27 = cVar25;
8759: pcVar27[1] = '\0';
8760: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
8761: *pcVar27 = cVar24;
8762: pcVar27[1] = '\0';
8763: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
8764: *pcVar27 = cVar23;
8765: pcVar27[1] = '\0';
8766: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
8767: *pcVar27 = cVar22;
8768: pcVar27[1] = '\0';
8769: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
8770: *pcVar27 = cVar10;
8771: pcVar27[1] = '\0';
8772: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
8773: }
8774: iVar17 = iVar17 + 0x40;
8775: uVar11 = (ulong)puVar4[0xf0];
8776: }
8777: else {
8778: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8779: }
8780: }
8781: }
8782: uVar31 = uVar16 - 0xf0 & 0xff;
8783: }
8784: goto LAB_0010b9d2;
8785: }
8786: LAB_0010ac2a:
8787: sVar1 = psVar5[0x27];
8788: uVar16 = uVar31 + 0x10;
8789: if (sVar1 != 0) {
8790: uVar19 = (int)sVar1 >> 0x1f;
8791: uVar35 = (int)sVar1 + uVar19;
8792: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
8793: if (0xff < (int)uVar16) {
8794: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
8795: if (iVar29 < 0) {
8796: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
8797: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
8798: cVar10 = (char)uVar14;
8799: cVar24 = (char)(uVar14 >> 8);
8800: cVar23 = (char)(uVar14 >> 0x10);
8801: cVar22 = (char)(uVar14 >> 0x18);
8802: cVar21 = (char)(uVar11 >> 0x20);
8803: cVar33 = (char)(uVar11 >> 0x28);
8804: cVar20 = (char)(uVar11 >> 0x30);
8805: cVar25 = (char)(uVar11 >> 0x38);
8806: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8807: pcVar26[7] = cVar10;
8808: pcVar28 = pcVar26 + 8;
8809: *pcVar26 = cVar25;
8810: pcVar26[1] = cVar20;
8811: pcVar26[2] = cVar33;
8812: pcVar26[3] = cVar21;
8813: pcVar26[4] = cVar22;
8814: pcVar26[5] = cVar23;
8815: pcVar26[6] = cVar24;
8816: }
8817: else {
8818: pcVar26[1] = '\0';
8819: *pcVar26 = cVar25;
8820: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8821: *pcVar26 = cVar20;
8822: pcVar26[1] = '\0';
8823: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
8824: *pcVar26 = cVar33;
8825: pcVar26[1] = '\0';
8826: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
8827: *pcVar26 = cVar21;
8828: pcVar26[1] = '\0';
8829: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
8830: *pcVar26 = cVar22;
8831: pcVar26[1] = '\0';
8832: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
8833: *pcVar26 = cVar23;
8834: pcVar26[1] = '\0';
8835: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
8836: *pcVar26 = cVar24;
8837: pcVar26[1] = '\0';
8838: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
8839: *pcVar26 = cVar10;
8840: pcVar26[1] = '\0';
8841: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
8842: }
8843: uVar11 = (ulong)puVar4[0xf0];
8844: iVar29 = iVar29 + 0x40;
8845: uVar14 = uVar11;
8846: }
8847: else {
8848: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
8849: pcVar28 = pcVar26;
8850: uVar14 = (ulong)puVar4[0xf0];
8851: }
8852: pcVar26 = pcVar28;
8853: iVar17 = iVar29;
8854: if (0xff < (int)(uVar31 - 0xf0)) {
8855: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
8856: if (iVar18 < 0) {
8857: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
8858: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
8859: cVar10 = (char)uVar14;
8860: cVar25 = (char)(uVar14 >> 8);
8861: cVar24 = (char)(uVar14 >> 0x10);
8862: cVar23 = (char)(uVar14 >> 0x18);
8863: cVar22 = (char)(uVar11 >> 0x20);
8864: cVar21 = (char)(uVar11 >> 0x28);
8865: cVar20 = (char)(uVar11 >> 0x30);
8866: cVar33 = (char)(uVar11 >> 0x38);
8867: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8868: pcVar28[7] = cVar10;
8869: pcVar27 = pcVar28 + 8;
8870: *pcVar28 = cVar33;
8871: pcVar28[1] = cVar20;
8872: pcVar28[2] = cVar21;
8873: pcVar28[3] = cVar22;
8874: pcVar28[4] = cVar23;
8875: pcVar28[5] = cVar24;
8876: pcVar28[6] = cVar25;
8877: }
8878: else {
8879: pcVar28[1] = '\0';
8880: *pcVar28 = cVar33;
8881: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8882: *pcVar28 = cVar20;
8883: pcVar28[1] = '\0';
8884: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
8885: *pcVar28 = cVar21;
8886: pcVar28[1] = '\0';
8887: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
8888: *pcVar28 = cVar22;
8889: pcVar28[1] = '\0';
8890: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
8891: *pcVar28 = cVar23;
8892: pcVar28[1] = '\0';
8893: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
8894: *pcVar28 = cVar24;
8895: pcVar28[1] = '\0';
8896: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
8897: *pcVar28 = cVar25;
8898: pcVar28[1] = '\0';
8899: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
8900: *pcVar28 = cVar10;
8901: pcVar28[1] = '\0';
8902: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
8903: }
8904: uVar11 = (ulong)puVar4[0xf0];
8905: iVar18 = iVar18 + 0x40;
8906: uVar14 = uVar11;
8907: }
8908: else {
8909: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8910: pcVar27 = pcVar28;
8911: }
8912: pcVar26 = pcVar27;
8913: iVar17 = iVar18;
8914: if (0x2ef < (int)uVar31) {
8915: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
8916: if (iVar17 < 0) {
8917: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
8918: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
8919: cVar10 = (char)uVar14;
8920: cVar25 = (char)(uVar14 >> 8);
8921: cVar24 = (char)(uVar14 >> 0x10);
8922: cVar23 = (char)(uVar14 >> 0x18);
8923: cVar22 = (char)(uVar11 >> 0x20);
8924: cVar33 = (char)(uVar11 >> 0x28);
8925: cVar20 = (char)(uVar11 >> 0x30);
8926: cVar21 = (char)(uVar11 >> 0x38);
8927: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8928: pcVar27[7] = cVar10;
8929: pcVar26 = pcVar27 + 8;
8930: *pcVar27 = cVar21;
8931: pcVar27[1] = cVar20;
8932: pcVar27[2] = cVar33;
8933: pcVar27[3] = cVar22;
8934: pcVar27[4] = cVar23;
8935: pcVar27[5] = cVar24;
8936: pcVar27[6] = cVar25;
8937: }
8938: else {
8939: pcVar27[1] = '\0';
8940: *pcVar27 = cVar21;
8941: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
8942: *pcVar27 = cVar20;
8943: pcVar27[1] = '\0';
8944: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
8945: *pcVar27 = cVar33;
8946: pcVar27[1] = '\0';
8947: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
8948: *pcVar27 = cVar22;
8949: pcVar27[1] = '\0';
8950: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
8951: *pcVar27 = cVar23;
8952: pcVar27[1] = '\0';
8953: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
8954: *pcVar27 = cVar24;
8955: pcVar27[1] = '\0';
8956: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
8957: *pcVar27 = cVar25;
8958: pcVar27[1] = '\0';
8959: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
8960: *pcVar27 = cVar10;
8961: pcVar27[1] = '\0';
8962: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
8963: }
8964: iVar17 = iVar17 + 0x40;
8965: uVar11 = (ulong)puVar4[0xf0];
8966: }
8967: else {
8968: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
8969: }
8970: }
8971: }
8972: uVar16 = uVar31 - 0xf0 & 0xff;
8973: }
8974: goto LAB_0010accc;
8975: }
8976: LAB_0010ba20:
8977: sVar1 = psVar5[0x2e];
8978: uVar31 = uVar16 + 0x10;
8979: if (sVar1 != 0) {
8980: uVar19 = (int)sVar1 >> 0x1f;
8981: uVar35 = (int)sVar1 + uVar19;
8982: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
8983: if (0xff < (int)uVar31) {
8984: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
8985: if (iVar29 < 0) {
8986: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
8987: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
8988: cVar10 = (char)uVar14;
8989: cVar25 = (char)(uVar14 >> 8);
8990: cVar24 = (char)(uVar14 >> 0x10);
8991: cVar23 = (char)(uVar14 >> 0x18);
8992: cVar22 = (char)(uVar11 >> 0x20);
8993: cVar21 = (char)(uVar11 >> 0x28);
8994: cVar20 = (char)(uVar11 >> 0x30);
8995: cVar33 = (char)(uVar11 >> 0x38);
8996: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
8997: pcVar26[7] = cVar10;
8998: pcVar28 = pcVar26 + 8;
8999: *pcVar26 = cVar33;
9000: pcVar26[1] = cVar20;
9001: pcVar26[2] = cVar21;
9002: pcVar26[3] = cVar22;
9003: pcVar26[4] = cVar23;
9004: pcVar26[5] = cVar24;
9005: pcVar26[6] = cVar25;
9006: }
9007: else {
9008: pcVar26[1] = '\0';
9009: *pcVar26 = cVar33;
9010: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9011: *pcVar26 = cVar20;
9012: pcVar26[1] = '\0';
9013: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
9014: *pcVar26 = cVar21;
9015: pcVar26[1] = '\0';
9016: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
9017: *pcVar26 = cVar22;
9018: pcVar26[1] = '\0';
9019: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
9020: *pcVar26 = cVar23;
9021: pcVar26[1] = '\0';
9022: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
9023: *pcVar26 = cVar24;
9024: pcVar26[1] = '\0';
9025: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
9026: *pcVar26 = cVar25;
9027: pcVar26[1] = '\0';
9028: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
9029: *pcVar26 = cVar10;
9030: pcVar26[1] = '\0';
9031: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
9032: }
9033: uVar11 = (ulong)puVar4[0xf0];
9034: iVar29 = iVar29 + 0x40;
9035: uVar14 = uVar11;
9036: }
9037: else {
9038: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
9039: pcVar28 = pcVar26;
9040: uVar14 = (ulong)puVar4[0xf0];
9041: }
9042: pcVar26 = pcVar28;
9043: iVar17 = iVar29;
9044: if (0xff < (int)(uVar16 - 0xf0)) {
9045: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
9046: if (iVar18 < 0) {
9047: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
9048: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
9049: cVar10 = (char)uVar14;
9050: cVar23 = (char)(uVar14 >> 8);
9051: cVar21 = (char)(uVar14 >> 0x10);
9052: cVar20 = (char)(uVar14 >> 0x18);
9053: cVar33 = (char)(uVar11 >> 0x20);
9054: cVar22 = (char)(uVar11 >> 0x28);
9055: cVar24 = (char)(uVar11 >> 0x30);
9056: cVar25 = (char)(uVar11 >> 0x38);
9057: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9058: pcVar28[7] = cVar10;
9059: pcVar27 = pcVar28 + 8;
9060: *pcVar28 = cVar25;
9061: pcVar28[1] = cVar24;
9062: pcVar28[2] = cVar22;
9063: pcVar28[3] = cVar33;
9064: pcVar28[4] = cVar20;
9065: pcVar28[5] = cVar21;
9066: pcVar28[6] = cVar23;
9067: }
9068: else {
9069: pcVar28[1] = '\0';
9070: *pcVar28 = cVar25;
9071: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9072: *pcVar28 = cVar24;
9073: pcVar28[1] = '\0';
9074: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
9075: *pcVar28 = cVar22;
9076: pcVar28[1] = '\0';
9077: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
9078: *pcVar28 = cVar33;
9079: pcVar28[1] = '\0';
9080: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
9081: *pcVar28 = cVar20;
9082: pcVar28[1] = '\0';
9083: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
9084: *pcVar28 = cVar21;
9085: pcVar28[1] = '\0';
9086: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
9087: *pcVar28 = cVar23;
9088: pcVar28[1] = '\0';
9089: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
9090: *pcVar28 = cVar10;
9091: pcVar28[1] = '\0';
9092: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
9093: }
9094: uVar11 = (ulong)puVar4[0xf0];
9095: iVar18 = iVar18 + 0x40;
9096: uVar14 = uVar11;
9097: }
9098: else {
9099: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9100: pcVar27 = pcVar28;
9101: }
9102: pcVar26 = pcVar27;
9103: iVar17 = iVar18;
9104: if (0x2ef < (int)uVar16) {
9105: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
9106: if (iVar17 < 0) {
9107: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
9108: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
9109: cVar10 = (char)uVar14;
9110: cVar20 = (char)(uVar14 >> 8);
9111: cVar33 = (char)(uVar14 >> 0x10);
9112: cVar23 = (char)(uVar14 >> 0x18);
9113: cVar24 = (char)(uVar11 >> 0x20);
9114: cVar21 = (char)(uVar11 >> 0x28);
9115: cVar22 = (char)(uVar11 >> 0x30);
9116: cVar25 = (char)(uVar11 >> 0x38);
9117: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9118: pcVar27[7] = cVar10;
9119: pcVar26 = pcVar27 + 8;
9120: *pcVar27 = cVar25;
9121: pcVar27[1] = cVar22;
9122: pcVar27[2] = cVar21;
9123: pcVar27[3] = cVar24;
9124: pcVar27[4] = cVar23;
9125: pcVar27[5] = cVar33;
9126: pcVar27[6] = cVar20;
9127: }
9128: else {
9129: pcVar27[1] = '\0';
9130: *pcVar27 = cVar25;
9131: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9132: *pcVar27 = cVar22;
9133: pcVar27[1] = '\0';
9134: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
9135: *pcVar27 = cVar21;
9136: pcVar27[1] = '\0';
9137: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
9138: *pcVar27 = cVar24;
9139: pcVar27[1] = '\0';
9140: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
9141: *pcVar27 = cVar23;
9142: pcVar27[1] = '\0';
9143: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
9144: *pcVar27 = cVar33;
9145: pcVar27[1] = '\0';
9146: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
9147: *pcVar27 = cVar20;
9148: pcVar27[1] = '\0';
9149: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
9150: *pcVar27 = cVar10;
9151: pcVar27[1] = '\0';
9152: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
9153: }
9154: iVar17 = iVar17 + 0x40;
9155: uVar11 = (ulong)puVar4[0xf0];
9156: }
9157: else {
9158: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9159: }
9160: }
9161: }
9162: uVar31 = uVar16 - 0xf0 & 0xff;
9163: }
9164: goto LAB_0010bac2;
9165: }
9166: LAB_0010ad1a:
9167: sVar1 = psVar5[0x35];
9168: uVar16 = uVar31 + 0x10;
9169: if (sVar1 != 0) {
9170: uVar19 = (int)sVar1 >> 0x1f;
9171: uVar35 = (int)sVar1 + uVar19;
9172: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
9173: if (0xff < (int)uVar16) {
9174: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
9175: if (iVar29 < 0) {
9176: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
9177: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
9178: cVar10 = (char)uVar14;
9179: cVar25 = (char)(uVar14 >> 8);
9180: cVar24 = (char)(uVar14 >> 0x10);
9181: cVar33 = (char)(uVar14 >> 0x18);
9182: cVar20 = (char)(uVar11 >> 0x20);
9183: cVar21 = (char)(uVar11 >> 0x28);
9184: cVar22 = (char)(uVar11 >> 0x30);
9185: cVar23 = (char)(uVar11 >> 0x38);
9186: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9187: pcVar26[7] = cVar10;
9188: pcVar28 = pcVar26 + 8;
9189: *pcVar26 = cVar23;
9190: pcVar26[1] = cVar22;
9191: pcVar26[2] = cVar21;
9192: pcVar26[3] = cVar20;
9193: pcVar26[4] = cVar33;
9194: pcVar26[5] = cVar24;
9195: pcVar26[6] = cVar25;
9196: }
9197: else {
9198: pcVar26[1] = '\0';
9199: *pcVar26 = cVar23;
9200: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9201: *pcVar26 = cVar22;
9202: pcVar26[1] = '\0';
9203: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
9204: *pcVar26 = cVar21;
9205: pcVar26[1] = '\0';
9206: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
9207: *pcVar26 = cVar20;
9208: pcVar26[1] = '\0';
9209: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
9210: *pcVar26 = cVar33;
9211: pcVar26[1] = '\0';
9212: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
9213: *pcVar26 = cVar24;
9214: pcVar26[1] = '\0';
9215: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
9216: *pcVar26 = cVar25;
9217: pcVar26[1] = '\0';
9218: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
9219: *pcVar26 = cVar10;
9220: pcVar26[1] = '\0';
9221: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
9222: }
9223: uVar11 = (ulong)puVar4[0xf0];
9224: iVar29 = iVar29 + 0x40;
9225: uVar14 = uVar11;
9226: }
9227: else {
9228: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
9229: pcVar28 = pcVar26;
9230: uVar14 = (ulong)puVar4[0xf0];
9231: }
9232: pcVar26 = pcVar28;
9233: iVar17 = iVar29;
9234: if (0xff < (int)(uVar31 - 0xf0)) {
9235: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
9236: if (iVar18 < 0) {
9237: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
9238: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
9239: cVar10 = (char)uVar14;
9240: cVar25 = (char)(uVar14 >> 8);
9241: cVar24 = (char)(uVar14 >> 0x10);
9242: cVar23 = (char)(uVar14 >> 0x18);
9243: cVar22 = (char)(uVar11 >> 0x20);
9244: cVar21 = (char)(uVar11 >> 0x28);
9245: cVar20 = (char)(uVar11 >> 0x30);
9246: cVar33 = (char)(uVar11 >> 0x38);
9247: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9248: pcVar28[7] = cVar10;
9249: pcVar27 = pcVar28 + 8;
9250: *pcVar28 = cVar33;
9251: pcVar28[1] = cVar20;
9252: pcVar28[2] = cVar21;
9253: pcVar28[3] = cVar22;
9254: pcVar28[4] = cVar23;
9255: pcVar28[5] = cVar24;
9256: pcVar28[6] = cVar25;
9257: }
9258: else {
9259: pcVar28[1] = '\0';
9260: *pcVar28 = cVar33;
9261: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9262: *pcVar28 = cVar20;
9263: pcVar28[1] = '\0';
9264: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
9265: *pcVar28 = cVar21;
9266: pcVar28[1] = '\0';
9267: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
9268: *pcVar28 = cVar22;
9269: pcVar28[1] = '\0';
9270: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
9271: *pcVar28 = cVar23;
9272: pcVar28[1] = '\0';
9273: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
9274: *pcVar28 = cVar24;
9275: pcVar28[1] = '\0';
9276: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
9277: *pcVar28 = cVar25;
9278: pcVar28[1] = '\0';
9279: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
9280: *pcVar28 = cVar10;
9281: pcVar28[1] = '\0';
9282: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
9283: }
9284: uVar11 = (ulong)puVar4[0xf0];
9285: iVar18 = iVar18 + 0x40;
9286: uVar14 = uVar11;
9287: }
9288: else {
9289: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9290: pcVar27 = pcVar28;
9291: }
9292: pcVar26 = pcVar27;
9293: iVar17 = iVar18;
9294: if (0x2ef < (int)uVar31) {
9295: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
9296: if (iVar17 < 0) {
9297: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
9298: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
9299: cVar10 = (char)uVar14;
9300: cVar24 = (char)(uVar14 >> 8);
9301: cVar20 = (char)(uVar14 >> 0x10);
9302: cVar33 = (char)(uVar14 >> 0x18);
9303: cVar21 = (char)(uVar11 >> 0x20);
9304: cVar22 = (char)(uVar11 >> 0x28);
9305: cVar23 = (char)(uVar11 >> 0x30);
9306: cVar25 = (char)(uVar11 >> 0x38);
9307: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9308: pcVar27[7] = cVar10;
9309: pcVar26 = pcVar27 + 8;
9310: *pcVar27 = cVar25;
9311: pcVar27[1] = cVar23;
9312: pcVar27[2] = cVar22;
9313: pcVar27[3] = cVar21;
9314: pcVar27[4] = cVar33;
9315: pcVar27[5] = cVar20;
9316: pcVar27[6] = cVar24;
9317: }
9318: else {
9319: pcVar27[1] = '\0';
9320: *pcVar27 = cVar25;
9321: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9322: *pcVar27 = cVar23;
9323: pcVar27[1] = '\0';
9324: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
9325: *pcVar27 = cVar22;
9326: pcVar27[1] = '\0';
9327: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
9328: *pcVar27 = cVar21;
9329: pcVar27[1] = '\0';
9330: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
9331: *pcVar27 = cVar33;
9332: pcVar27[1] = '\0';
9333: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
9334: *pcVar27 = cVar20;
9335: pcVar27[1] = '\0';
9336: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
9337: *pcVar27 = cVar24;
9338: pcVar27[1] = '\0';
9339: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
9340: *pcVar27 = cVar10;
9341: pcVar27[1] = '\0';
9342: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
9343: }
9344: iVar17 = iVar17 + 0x40;
9345: uVar11 = (ulong)puVar4[0xf0];
9346: }
9347: else {
9348: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9349: }
9350: }
9351: }
9352: uVar16 = uVar31 - 0xf0 & 0xff;
9353: }
9354: goto LAB_0010adbc;
9355: }
9356: LAB_0010bb10:
9357: sVar1 = psVar5[0x3c];
9358: uVar31 = uVar16 + 0x10;
9359: if (sVar1 != 0) {
9360: uVar19 = (int)sVar1 >> 0x1f;
9361: uVar35 = (int)sVar1 + uVar19;
9362: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
9363: iVar29 = iVar17;
9364: if (0xff < (int)uVar31) {
9365: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
9366: if (iVar29 < 0) {
9367: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
9368: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
9369: cVar10 = (char)uVar14;
9370: cVar25 = (char)(uVar14 >> 8);
9371: cVar20 = (char)(uVar14 >> 0x10);
9372: cVar21 = (char)(uVar14 >> 0x18);
9373: cVar23 = (char)(uVar11 >> 0x20);
9374: cVar24 = (char)(uVar11 >> 0x28);
9375: cVar22 = (char)(uVar11 >> 0x30);
9376: cVar33 = (char)(uVar11 >> 0x38);
9377: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9378: pcVar26[7] = cVar10;
9379: pcVar28 = pcVar26 + 8;
9380: *pcVar26 = cVar33;
9381: pcVar26[1] = cVar22;
9382: pcVar26[2] = cVar24;
9383: pcVar26[3] = cVar23;
9384: pcVar26[4] = cVar21;
9385: pcVar26[5] = cVar20;
9386: pcVar26[6] = cVar25;
9387: }
9388: else {
9389: pcVar26[1] = '\0';
9390: *pcVar26 = cVar33;
9391: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9392: *pcVar26 = cVar22;
9393: pcVar26[1] = '\0';
9394: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
9395: *pcVar26 = cVar24;
9396: pcVar26[1] = '\0';
9397: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
9398: *pcVar26 = cVar23;
9399: pcVar26[1] = '\0';
9400: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
9401: *pcVar26 = cVar21;
9402: pcVar26[1] = '\0';
9403: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
9404: *pcVar26 = cVar20;
9405: pcVar26[1] = '\0';
9406: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
9407: *pcVar26 = cVar25;
9408: pcVar26[1] = '\0';
9409: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
9410: *pcVar26 = cVar10;
9411: pcVar26[1] = '\0';
9412: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
9413: }
9414: uVar11 = (ulong)puVar4[0xf0];
9415: iVar29 = iVar29 + 0x40;
9416: uVar14 = uVar11;
9417: }
9418: else {
9419: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
9420: pcVar28 = pcVar26;
9421: uVar14 = (ulong)puVar4[0xf0];
9422: }
9423: pcVar26 = pcVar28;
9424: if (0xff < (int)(uVar16 - 0xf0)) {
9425: iVar17 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
9426: if (iVar17 < 0) {
9427: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
9428: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
9429: cVar10 = (char)uVar14;
9430: cVar24 = (char)(uVar14 >> 8);
9431: cVar23 = (char)(uVar14 >> 0x10);
9432: cVar21 = (char)(uVar14 >> 0x18);
9433: cVar33 = (char)(uVar11 >> 0x20);
9434: cVar20 = (char)(uVar11 >> 0x28);
9435: cVar22 = (char)(uVar11 >> 0x30);
9436: cVar25 = (char)(uVar11 >> 0x38);
9437: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9438: pcVar28[7] = cVar10;
9439: pcVar27 = pcVar28 + 8;
9440: *pcVar28 = cVar25;
9441: pcVar28[1] = cVar22;
9442: pcVar28[2] = cVar20;
9443: pcVar28[3] = cVar33;
9444: pcVar28[4] = cVar21;
9445: pcVar28[5] = cVar23;
9446: pcVar28[6] = cVar24;
9447: }
9448: else {
9449: pcVar28[1] = '\0';
9450: *pcVar28 = cVar25;
9451: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9452: *pcVar28 = cVar22;
9453: pcVar28[1] = '\0';
9454: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
9455: *pcVar28 = cVar20;
9456: pcVar28[1] = '\0';
9457: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
9458: *pcVar28 = cVar33;
9459: pcVar28[1] = '\0';
9460: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
9461: *pcVar28 = cVar21;
9462: pcVar28[1] = '\0';
9463: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
9464: *pcVar28 = cVar23;
9465: pcVar28[1] = '\0';
9466: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
9467: *pcVar28 = cVar24;
9468: pcVar28[1] = '\0';
9469: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
9470: *pcVar28 = cVar10;
9471: pcVar28[1] = '\0';
9472: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
9473: }
9474: uVar11 = (ulong)puVar4[0xf0];
9475: iVar17 = iVar17 + 0x40;
9476: uVar14 = uVar11;
9477: }
9478: else {
9479: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9480: pcVar27 = pcVar28;
9481: }
9482: pcVar26 = pcVar27;
9483: iVar29 = iVar17;
9484: if (0x2ef < (int)uVar16) {
9485: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
9486: if (iVar29 < 0) {
9487: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
9488: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
9489: cVar10 = (char)uVar14;
9490: cVar25 = (char)(uVar14 >> 8);
9491: cVar23 = (char)(uVar14 >> 0x10);
9492: cVar20 = (char)(uVar14 >> 0x18);
9493: cVar24 = (char)(uVar11 >> 0x20);
9494: cVar21 = (char)(uVar11 >> 0x28);
9495: cVar33 = (char)(uVar11 >> 0x30);
9496: cVar22 = (char)(uVar11 >> 0x38);
9497: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9498: pcVar27[7] = cVar10;
9499: pcVar26 = pcVar27 + 8;
9500: *pcVar27 = cVar22;
9501: pcVar27[1] = cVar33;
9502: pcVar27[2] = cVar21;
9503: pcVar27[3] = cVar24;
9504: pcVar27[4] = cVar20;
9505: pcVar27[5] = cVar23;
9506: pcVar27[6] = cVar25;
9507: }
9508: else {
9509: pcVar27[1] = '\0';
9510: *pcVar27 = cVar22;
9511: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9512: *pcVar27 = cVar33;
9513: pcVar27[1] = '\0';
9514: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
9515: *pcVar27 = cVar21;
9516: pcVar27[1] = '\0';
9517: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
9518: *pcVar27 = cVar24;
9519: pcVar27[1] = '\0';
9520: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
9521: *pcVar27 = cVar20;
9522: pcVar27[1] = '\0';
9523: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
9524: *pcVar27 = cVar23;
9525: pcVar27[1] = '\0';
9526: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
9527: *pcVar27 = cVar25;
9528: pcVar27[1] = '\0';
9529: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
9530: *pcVar27 = cVar10;
9531: pcVar27[1] = '\0';
9532: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
9533: }
9534: iVar29 = iVar29 + 0x40;
9535: uVar11 = (ulong)puVar4[0xf0];
9536: }
9537: else {
9538: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9539: }
9540: }
9541: }
9542: uVar31 = uVar16 - 0xf0 & 0xff;
9543: }
9544: goto LAB_0010bbb2;
9545: }
9546: LAB_0010ae0a:
9547: sVar1 = psVar5[0x3d];
9548: uVar16 = uVar31 + 0x10;
9549: if (sVar1 == 0) goto LAB_0010b5d8;
9550: uVar19 = (int)sVar1 >> 0x1f;
9551: uVar35 = (int)sVar1 + uVar19;
9552: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
9553: if (0xff < (int)uVar16) {
9554: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
9555: if (iVar29 < 0) {
9556: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
9557: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
9558: cVar10 = (char)uVar14;
9559: cVar23 = (char)(uVar14 >> 8);
9560: cVar24 = (char)(uVar14 >> 0x10);
9561: cVar25 = (char)(uVar14 >> 0x18);
9562: cVar22 = (char)(uVar11 >> 0x20);
9563: cVar21 = (char)(uVar11 >> 0x28);
9564: cVar20 = (char)(uVar11 >> 0x30);
9565: cVar33 = (char)(uVar11 >> 0x38);
9566: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9567: pcVar26[7] = cVar10;
9568: pcVar28 = pcVar26 + 8;
9569: *pcVar26 = cVar33;
9570: pcVar26[1] = cVar20;
9571: pcVar26[2] = cVar21;
9572: pcVar26[3] = cVar22;
9573: pcVar26[4] = cVar25;
9574: pcVar26[5] = cVar24;
9575: pcVar26[6] = cVar23;
9576: }
9577: else {
9578: pcVar26[1] = '\0';
9579: *pcVar26 = cVar33;
9580: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9581: *pcVar26 = cVar20;
9582: pcVar26[1] = '\0';
9583: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
9584: *pcVar26 = cVar21;
9585: pcVar26[1] = '\0';
9586: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
9587: *pcVar26 = cVar22;
9588: pcVar26[1] = '\0';
9589: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
9590: *pcVar26 = cVar25;
9591: pcVar26[1] = '\0';
9592: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
9593: *pcVar26 = cVar24;
9594: pcVar26[1] = '\0';
9595: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
9596: *pcVar26 = cVar23;
9597: pcVar26[1] = '\0';
9598: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
9599: *pcVar26 = cVar10;
9600: pcVar26[1] = '\0';
9601: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
9602: }
9603: uVar11 = (ulong)puVar4[0xf0];
9604: iVar29 = iVar29 + 0x40;
9605: uVar14 = uVar11;
9606: }
9607: else {
9608: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
9609: pcVar28 = pcVar26;
9610: uVar14 = (ulong)puVar4[0xf0];
9611: }
9612: pcVar26 = pcVar28;
9613: iVar17 = iVar29;
9614: if (0xff < (int)(uVar31 - 0xf0)) {
9615: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
9616: if (iVar18 < 0) {
9617: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
9618: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
9619: cVar10 = (char)uVar14;
9620: cVar33 = (char)(uVar14 >> 8);
9621: cVar20 = (char)(uVar14 >> 0x10);
9622: cVar21 = (char)(uVar14 >> 0x18);
9623: cVar22 = (char)(uVar11 >> 0x20);
9624: cVar23 = (char)(uVar11 >> 0x28);
9625: cVar24 = (char)(uVar11 >> 0x30);
9626: cVar25 = (char)(uVar11 >> 0x38);
9627: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9628: pcVar28[7] = cVar10;
9629: pcVar27 = pcVar28 + 8;
9630: *pcVar28 = cVar25;
9631: pcVar28[1] = cVar24;
9632: pcVar28[2] = cVar23;
9633: pcVar28[3] = cVar22;
9634: pcVar28[4] = cVar21;
9635: pcVar28[5] = cVar20;
9636: pcVar28[6] = cVar33;
9637: }
9638: else {
9639: pcVar28[1] = '\0';
9640: *pcVar28 = cVar25;
9641: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9642: *pcVar28 = cVar24;
9643: pcVar28[1] = '\0';
9644: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
9645: *pcVar28 = cVar23;
9646: pcVar28[1] = '\0';
9647: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
9648: *pcVar28 = cVar22;
9649: pcVar28[1] = '\0';
9650: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
9651: *pcVar28 = cVar21;
9652: pcVar28[1] = '\0';
9653: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
9654: *pcVar28 = cVar20;
9655: pcVar28[1] = '\0';
9656: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
9657: *pcVar28 = cVar33;
9658: pcVar28[1] = '\0';
9659: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
9660: *pcVar28 = cVar10;
9661: pcVar28[1] = '\0';
9662: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
9663: }
9664: uVar11 = (ulong)puVar4[0xf0];
9665: iVar18 = iVar18 + 0x40;
9666: uVar14 = uVar11;
9667: }
9668: else {
9669: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9670: pcVar27 = pcVar28;
9671: }
9672: pcVar26 = pcVar27;
9673: iVar17 = iVar18;
9674: if (0x2ef < (int)uVar31) {
9675: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
9676: if (iVar17 < 0) {
9677: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
9678: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
9679: cVar10 = (char)uVar14;
9680: cVar23 = (char)(uVar14 >> 8);
9681: cVar24 = (char)(uVar14 >> 0x10);
9682: cVar25 = (char)(uVar14 >> 0x18);
9683: cVar33 = (char)(uVar11 >> 0x20);
9684: cVar20 = (char)(uVar11 >> 0x28);
9685: cVar21 = (char)(uVar11 >> 0x30);
9686: cVar22 = (char)(uVar11 >> 0x38);
9687: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9688: pcVar27[7] = cVar10;
9689: pcVar26 = pcVar27 + 8;
9690: *pcVar27 = cVar22;
9691: pcVar27[1] = cVar21;
9692: pcVar27[2] = cVar20;
9693: pcVar27[3] = cVar33;
9694: pcVar27[4] = cVar25;
9695: pcVar27[5] = cVar24;
9696: pcVar27[6] = cVar23;
9697: }
9698: else {
9699: pcVar27[1] = '\0';
9700: *pcVar27 = cVar22;
9701: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9702: *pcVar27 = cVar21;
9703: pcVar27[1] = '\0';
9704: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
9705: *pcVar27 = cVar20;
9706: pcVar27[1] = '\0';
9707: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
9708: *pcVar27 = cVar33;
9709: pcVar27[1] = '\0';
9710: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
9711: *pcVar27 = cVar25;
9712: pcVar27[1] = '\0';
9713: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
9714: *pcVar27 = cVar24;
9715: pcVar27[1] = '\0';
9716: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
9717: *pcVar27 = cVar23;
9718: pcVar27[1] = '\0';
9719: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
9720: *pcVar27 = cVar10;
9721: pcVar27[1] = '\0';
9722: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
9723: }
9724: iVar17 = iVar17 + 0x40;
9725: uVar11 = (ulong)puVar4[0xf0];
9726: }
9727: else {
9728: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9729: }
9730: }
9731: }
9732: uVar16 = uVar31 - 0xf0 & 0xff;
9733: }
9734: LAB_0010aeac:
9735: uVar31 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
9736: puVar4[(int)(uVar16 + uVar19)] << ((byte)uVar19 & 0x1f);
9737: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar16 + uVar19) + 0x400) + uVar19;
9738: iVar18 = iVar17 - iVar29;
9739: if (iVar18 < 0) {
9740: uVar11 = (long)((int)uVar31 >> (-(char)iVar18 & 0x1fU)) |
9741: uVar11 << ((byte)iVar17 & 0x3f);
9742: cVar10 = (char)uVar11;
9743: cVar25 = (char)(uVar11 >> 8);
9744: cVar24 = (char)(uVar11 >> 0x10);
9745: cVar23 = (char)(uVar11 >> 0x18);
9746: cVar21 = (char)(uVar11 >> 0x20);
9747: cVar20 = (char)(uVar11 >> 0x28);
9748: cVar33 = (char)(uVar11 >> 0x30);
9749: cVar22 = (char)(uVar11 >> 0x38);
9750: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
9751: pcVar26[7] = cVar10;
9752: pcVar28 = pcVar26 + 8;
9753: *pcVar26 = cVar22;
9754: pcVar26[1] = cVar33;
9755: pcVar26[2] = cVar20;
9756: pcVar26[3] = cVar21;
9757: pcVar26[4] = cVar23;
9758: pcVar26[5] = cVar24;
9759: pcVar26[6] = cVar25;
9760: }
9761: else {
9762: pcVar26[1] = '\0';
9763: *pcVar26 = cVar22;
9764: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9765: *pcVar26 = cVar33;
9766: pcVar26[1] = '\0';
9767: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
9768: *pcVar26 = cVar20;
9769: pcVar26[1] = '\0';
9770: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
9771: *pcVar26 = cVar21;
9772: pcVar26[1] = '\0';
9773: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
9774: *pcVar26 = cVar23;
9775: pcVar26[1] = '\0';
9776: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
9777: *pcVar26 = cVar24;
9778: pcVar26[1] = '\0';
9779: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
9780: *pcVar26 = cVar25;
9781: pcVar26[1] = '\0';
9782: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
9783: *pcVar26 = cVar10;
9784: pcVar26[1] = '\0';
9785: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
9786: }
9787: sVar1 = psVar5[0x36];
9788: uVar11 = SEXT48((int)uVar31);
9789: iVar17 = iVar18 + 0x40;
9790: pcVar26 = pcVar28;
9791: }
9792: else {
9793: sVar1 = psVar5[0x36];
9794: uVar11 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
9795: iVar17 = iVar18;
9796: }
9797: uVar31 = SEXT24(sVar1);
9798: if (sVar1 == 0) goto LAB_0010aefa;
9799: uVar16 = (int)uVar31 >> 0x1f;
9800: uVar35 = uVar31 + uVar16;
9801: uVar31 = 0;
9802: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar16 ^ uVar35)];
9803: iVar29 = iVar17;
9804: LAB_0010b67a:
9805: uVar16 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
9806: puVar4[(int)(uVar31 + uVar19)] << ((byte)uVar19 & 0x1f);
9807: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(uVar31 + uVar19) + 0x400) + uVar19;
9808: iVar17 = iVar29 - iVar18;
9809: if (iVar17 < 0) {
9810: uVar11 = (long)((int)uVar16 >> (-(char)iVar17 & 0x1fU)) |
9811: uVar11 << ((byte)iVar29 & 0x3f);
9812: cVar10 = (char)uVar11;
9813: cVar25 = (char)(uVar11 >> 8);
9814: cVar24 = (char)(uVar11 >> 0x10);
9815: cVar23 = (char)(uVar11 >> 0x18);
9816: cVar22 = (char)(uVar11 >> 0x20);
9817: cVar21 = (char)(uVar11 >> 0x28);
9818: cVar20 = (char)(uVar11 >> 0x30);
9819: cVar33 = (char)(uVar11 >> 0x38);
9820: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
9821: pcVar26[7] = cVar10;
9822: pcVar28 = pcVar26 + 8;
9823: *pcVar26 = cVar33;
9824: pcVar26[1] = cVar20;
9825: pcVar26[2] = cVar21;
9826: pcVar26[3] = cVar22;
9827: pcVar26[4] = cVar23;
9828: pcVar26[5] = cVar24;
9829: pcVar26[6] = cVar25;
9830: }
9831: else {
9832: pcVar26[1] = '\0';
9833: *pcVar26 = cVar33;
9834: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9835: *pcVar26 = cVar20;
9836: pcVar26[1] = '\0';
9837: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
9838: *pcVar26 = cVar21;
9839: pcVar26[1] = '\0';
9840: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
9841: *pcVar26 = cVar22;
9842: pcVar26[1] = '\0';
9843: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
9844: *pcVar26 = cVar23;
9845: pcVar26[1] = '\0';
9846: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
9847: *pcVar26 = cVar24;
9848: pcVar26[1] = '\0';
9849: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
9850: *pcVar26 = cVar25;
9851: pcVar26[1] = '\0';
9852: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
9853: *pcVar26 = cVar10;
9854: pcVar26[1] = '\0';
9855: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
9856: }
9857: iVar17 = iVar17 + 0x40;
9858: uVar11 = SEXT48((int)uVar16);
9859: pcVar26 = pcVar28;
9860: }
9861: else {
9862: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar16;
9863: }
9864: uVar16 = SEXT24(psVar5[0x2f]);
9865: if (uVar16 != 0) {
9866: uVar31 = (int)uVar16 >> 0x1f;
9867: uVar19 = uVar16 + uVar31;
9868: uVar16 = 0;
9869: uVar35 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar31 ^ uVar19)];
9870: goto LAB_0010af9c;
9871: }
9872: LAB_0010b4c0:
9873: sVar1 = psVar5[0x37];
9874: uVar31 = uVar16 + 0x10;
9875: pcVar28 = pcVar26;
9876: if (sVar1 != 0) {
9877: uVar19 = (int)sVar1 >> 0x1f;
9878: uVar35 = (int)sVar1 + uVar19;
9879: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
9880: iVar29 = iVar17;
9881: if (0xff < (int)uVar31) {
9882: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
9883: if (iVar29 < 0) {
9884: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
9885: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
9886: cVar10 = (char)uVar14;
9887: cVar22 = (char)(uVar14 >> 8);
9888: cVar23 = (char)(uVar14 >> 0x10);
9889: cVar24 = (char)(uVar14 >> 0x18);
9890: cVar25 = (char)(uVar11 >> 0x20);
9891: cVar21 = (char)(uVar11 >> 0x28);
9892: cVar20 = (char)(uVar11 >> 0x30);
9893: cVar33 = (char)(uVar11 >> 0x38);
9894: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9895: pcVar26[7] = cVar10;
9896: pcVar28 = pcVar26 + 8;
9897: *pcVar26 = cVar33;
9898: pcVar26[1] = cVar20;
9899: pcVar26[2] = cVar21;
9900: pcVar26[3] = cVar25;
9901: pcVar26[4] = cVar24;
9902: pcVar26[5] = cVar23;
9903: pcVar26[6] = cVar22;
9904: }
9905: else {
9906: pcVar26[1] = '\0';
9907: *pcVar26 = cVar33;
9908: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9909: *pcVar26 = cVar20;
9910: pcVar26[1] = '\0';
9911: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
9912: *pcVar26 = cVar21;
9913: pcVar26[1] = '\0';
9914: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
9915: *pcVar26 = cVar25;
9916: pcVar26[1] = '\0';
9917: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
9918: *pcVar26 = cVar24;
9919: pcVar26[1] = '\0';
9920: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
9921: *pcVar26 = cVar23;
9922: pcVar26[1] = '\0';
9923: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
9924: *pcVar26 = cVar22;
9925: pcVar26[1] = '\0';
9926: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
9927: *pcVar26 = cVar10;
9928: pcVar26[1] = '\0';
9929: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
9930: }
9931: uVar11 = (ulong)puVar4[0xf0];
9932: iVar29 = iVar29 + 0x40;
9933: uVar14 = uVar11;
9934: }
9935: else {
9936: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
9937: uVar14 = (ulong)puVar4[0xf0];
9938: }
9939: pcVar26 = pcVar28;
9940: if (0xff < (int)(uVar16 - 0xf0)) {
9941: iVar17 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
9942: if (iVar17 < 0) {
9943: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
9944: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
9945: cVar10 = (char)uVar14;
9946: cVar24 = (char)(uVar14 >> 8);
9947: cVar23 = (char)(uVar14 >> 0x10);
9948: cVar22 = (char)(uVar14 >> 0x18);
9949: cVar33 = (char)(uVar11 >> 0x20);
9950: cVar20 = (char)(uVar11 >> 0x28);
9951: cVar21 = (char)(uVar11 >> 0x30);
9952: cVar25 = (char)(uVar11 >> 0x38);
9953: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
9954: pcVar28[7] = cVar10;
9955: pcVar27 = pcVar28 + 8;
9956: *pcVar28 = cVar25;
9957: pcVar28[1] = cVar21;
9958: pcVar28[2] = cVar20;
9959: pcVar28[3] = cVar33;
9960: pcVar28[4] = cVar22;
9961: pcVar28[5] = cVar23;
9962: pcVar28[6] = cVar24;
9963: }
9964: else {
9965: pcVar28[1] = '\0';
9966: *pcVar28 = cVar25;
9967: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
9968: *pcVar28 = cVar21;
9969: pcVar28[1] = '\0';
9970: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
9971: *pcVar28 = cVar20;
9972: pcVar28[1] = '\0';
9973: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
9974: *pcVar28 = cVar33;
9975: pcVar28[1] = '\0';
9976: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
9977: *pcVar28 = cVar22;
9978: pcVar28[1] = '\0';
9979: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
9980: *pcVar28 = cVar23;
9981: pcVar28[1] = '\0';
9982: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
9983: *pcVar28 = cVar24;
9984: pcVar28[1] = '\0';
9985: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
9986: *pcVar28 = cVar10;
9987: pcVar28[1] = '\0';
9988: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
9989: }
9990: uVar11 = (ulong)puVar4[0xf0];
9991: iVar17 = iVar17 + 0x40;
9992: uVar14 = uVar11;
9993: }
9994: else {
9995: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
9996: pcVar27 = pcVar28;
9997: }
9998: pcVar26 = pcVar27;
9999: iVar29 = iVar17;
10000: if (0x2ef < (int)uVar16) {
10001: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
10002: if (iVar29 < 0) {
10003: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
10004: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
10005: cVar10 = (char)uVar14;
10006: cVar33 = (char)(uVar14 >> 8);
10007: cVar20 = (char)(uVar14 >> 0x10);
10008: cVar21 = (char)(uVar14 >> 0x18);
10009: cVar22 = (char)(uVar11 >> 0x20);
10010: cVar23 = (char)(uVar11 >> 0x28);
10011: cVar24 = (char)(uVar11 >> 0x30);
10012: cVar25 = (char)(uVar11 >> 0x38);
10013: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
10014: pcVar27[7] = cVar10;
10015: pcVar26 = pcVar27 + 8;
10016: *pcVar27 = cVar25;
10017: pcVar27[1] = cVar24;
10018: pcVar27[2] = cVar23;
10019: pcVar27[3] = cVar22;
10020: pcVar27[4] = cVar21;
10021: pcVar27[5] = cVar20;
10022: pcVar27[6] = cVar33;
10023: }
10024: else {
10025: pcVar27[1] = '\0';
10026: *pcVar27 = cVar25;
10027: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10028: *pcVar27 = cVar24;
10029: pcVar27[1] = '\0';
10030: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
10031: *pcVar27 = cVar23;
10032: pcVar27[1] = '\0';
10033: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
10034: *pcVar27 = cVar22;
10035: pcVar27[1] = '\0';
10036: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
10037: *pcVar27 = cVar21;
10038: pcVar27[1] = '\0';
10039: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
10040: *pcVar27 = cVar20;
10041: pcVar27[1] = '\0';
10042: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
10043: *pcVar27 = cVar33;
10044: pcVar27[1] = '\0';
10045: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
10046: *pcVar27 = cVar10;
10047: pcVar27[1] = '\0';
10048: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
10049: }
10050: iVar29 = iVar29 + 0x40;
10051: uVar11 = (ulong)puVar4[0xf0];
10052: }
10053: else {
10054: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
10055: }
10056: }
10057: }
10058: uVar31 = uVar16 - 0xf0 & 0xff;
10059: }
10060: goto LAB_0010b562;
10061: }
10062: LAB_0010afea:
10063: sVar1 = psVar5[0x3e];
10064: uVar16 = uVar31 + 0x10;
10065: pcVar26 = pcVar28;
10066: if (sVar1 == 0) goto LAB_0010b4b0;
10067: uVar19 = (int)sVar1 >> 0x1f;
10068: uVar35 = (int)sVar1 + uVar19;
10069: uVar19 = (uint)(byte)(&DAT_0016c7a0)[(int)(uVar19 ^ uVar35)];
10070: iVar29 = iVar17;
10071: if (0xff < (int)uVar16) {
10072: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
10073: if (iVar29 < 0) {
10074: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
10075: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
10076: cVar10 = (char)uVar14;
10077: cVar25 = (char)(uVar14 >> 8);
10078: cVar24 = (char)(uVar14 >> 0x10);
10079: cVar23 = (char)(uVar14 >> 0x18);
10080: cVar22 = (char)(uVar11 >> 0x20);
10081: cVar21 = (char)(uVar11 >> 0x28);
10082: cVar20 = (char)(uVar11 >> 0x30);
10083: cVar33 = (char)(uVar11 >> 0x38);
10084: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
10085: pcVar28[7] = cVar10;
10086: pcVar26 = pcVar28 + 8;
10087: *pcVar28 = cVar33;
10088: pcVar28[1] = cVar20;
10089: pcVar28[2] = cVar21;
10090: pcVar28[3] = cVar22;
10091: pcVar28[4] = cVar23;
10092: pcVar28[5] = cVar24;
10093: pcVar28[6] = cVar25;
10094: }
10095: else {
10096: pcVar28[1] = '\0';
10097: *pcVar28 = cVar33;
10098: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10099: *pcVar28 = cVar20;
10100: pcVar28[1] = '\0';
10101: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
10102: *pcVar28 = cVar21;
10103: pcVar28[1] = '\0';
10104: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
10105: *pcVar28 = cVar22;
10106: pcVar28[1] = '\0';
10107: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
10108: *pcVar28 = cVar23;
10109: pcVar28[1] = '\0';
10110: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
10111: *pcVar28 = cVar24;
10112: pcVar28[1] = '\0';
10113: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
10114: *pcVar28 = cVar25;
10115: pcVar28[1] = '\0';
10116: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
10117: *pcVar28 = cVar10;
10118: pcVar28[1] = '\0';
10119: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
10120: }
10121: uVar11 = (ulong)puVar4[0xf0];
10122: iVar29 = iVar29 + 0x40;
10123: uVar14 = uVar11;
10124: }
10125: else {
10126: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
10127: uVar14 = (ulong)puVar4[0xf0];
10128: }
10129: pcVar28 = pcVar26;
10130: if (0xff < (int)(uVar31 - 0xf0)) {
10131: iVar17 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
10132: if (iVar17 < 0) {
10133: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
10134: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
10135: cVar10 = (char)uVar14;
10136: cVar20 = (char)(uVar14 >> 8);
10137: cVar33 = (char)(uVar14 >> 0x10);
10138: cVar21 = (char)(uVar14 >> 0x18);
10139: cVar22 = (char)(uVar11 >> 0x20);
10140: cVar23 = (char)(uVar11 >> 0x28);
10141: cVar24 = (char)(uVar11 >> 0x30);
10142: cVar25 = (char)(uVar11 >> 0x38);
10143: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
10144: pcVar26[7] = cVar10;
10145: pcVar27 = pcVar26 + 8;
10146: *pcVar26 = cVar25;
10147: pcVar26[1] = cVar24;
10148: pcVar26[2] = cVar23;
10149: pcVar26[3] = cVar22;
10150: pcVar26[4] = cVar21;
10151: pcVar26[5] = cVar33;
10152: pcVar26[6] = cVar20;
10153: }
10154: else {
10155: pcVar26[1] = '\0';
10156: *pcVar26 = cVar25;
10157: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10158: *pcVar26 = cVar24;
10159: pcVar26[1] = '\0';
10160: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
10161: *pcVar26 = cVar23;
10162: pcVar26[1] = '\0';
10163: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
10164: *pcVar26 = cVar22;
10165: pcVar26[1] = '\0';
10166: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
10167: *pcVar26 = cVar21;
10168: pcVar26[1] = '\0';
10169: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
10170: *pcVar26 = cVar33;
10171: pcVar26[1] = '\0';
10172: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
10173: *pcVar26 = cVar20;
10174: pcVar26[1] = '\0';
10175: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
10176: *pcVar26 = cVar10;
10177: pcVar26[1] = '\0';
10178: pcVar27 = pcVar26 + (ulong)(cVar10 == -1) + 1;
10179: }
10180: uVar11 = (ulong)puVar4[0xf0];
10181: iVar17 = iVar17 + 0x40;
10182: uVar14 = uVar11;
10183: }
10184: else {
10185: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
10186: pcVar27 = pcVar26;
10187: }
10188: pcVar28 = pcVar27;
10189: iVar29 = iVar17;
10190: if (0x2ef < (int)uVar31) {
10191: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
10192: if (iVar29 < 0) {
10193: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
10194: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
10195: cVar10 = (char)uVar14;
10196: cVar25 = (char)(uVar14 >> 8);
10197: cVar24 = (char)(uVar14 >> 0x10);
10198: cVar23 = (char)(uVar14 >> 0x18);
10199: cVar22 = (char)(uVar11 >> 0x20);
10200: cVar21 = (char)(uVar11 >> 0x28);
10201: cVar20 = (char)(uVar11 >> 0x30);
10202: cVar33 = (char)(uVar11 >> 0x38);
10203: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
10204: pcVar27[7] = cVar10;
10205: pcVar28 = pcVar27 + 8;
10206: *pcVar27 = cVar33;
10207: pcVar27[1] = cVar20;
10208: pcVar27[2] = cVar21;
10209: pcVar27[3] = cVar22;
10210: pcVar27[4] = cVar23;
10211: pcVar27[5] = cVar24;
10212: pcVar27[6] = cVar25;
10213: }
10214: else {
10215: pcVar27[1] = '\0';
10216: *pcVar27 = cVar33;
10217: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10218: *pcVar27 = cVar20;
10219: pcVar27[1] = '\0';
10220: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
10221: *pcVar27 = cVar21;
10222: pcVar27[1] = '\0';
10223: pcVar27 = pcVar27 + (ulong)(cVar21 == -1) + 1;
10224: *pcVar27 = cVar22;
10225: pcVar27[1] = '\0';
10226: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
10227: *pcVar27 = cVar23;
10228: pcVar27[1] = '\0';
10229: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
10230: *pcVar27 = cVar24;
10231: pcVar27[1] = '\0';
10232: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
10233: *pcVar27 = cVar25;
10234: pcVar27[1] = '\0';
10235: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
10236: *pcVar27 = cVar10;
10237: pcVar27[1] = '\0';
10238: pcVar28 = pcVar27 + (ulong)(cVar10 == -1) + 1;
10239: }
10240: iVar29 = iVar29 + 0x40;
10241: uVar11 = (ulong)puVar4[0xf0];
10242: }
10243: else {
10244: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
10245: }
10246: }
10247: }
10248: uVar16 = uVar31 - 0xf0 & 0xff;
10249: }
10250: LAB_0010b08c:
10251: uVar31 = uVar35 & (int)(1 << ((byte)uVar19 & 0x3f)) - 1U |
10252: puVar4[(int)(uVar16 + uVar19)] << ((byte)uVar19 & 0x1f);
10253: iVar18 = (int)*(char *)((long)puVar4 + (long)(int)(uVar16 + uVar19) + 0x400) + uVar19;
10254: iVar17 = iVar29 - iVar18;
10255: if (iVar17 < 0) {
10256: uVar11 = (long)((int)uVar31 >> (-(char)iVar17 & 0x1fU)) |
10257: uVar11 << ((byte)iVar29 & 0x3f);
10258: cVar10 = (char)uVar11;
10259: cVar25 = (char)(uVar11 >> 8);
10260: cVar24 = (char)(uVar11 >> 0x10);
10261: cVar23 = (char)(uVar11 >> 0x18);
10262: cVar22 = (char)(uVar11 >> 0x20);
10263: cVar21 = (char)(uVar11 >> 0x28);
10264: cVar20 = (char)(uVar11 >> 0x30);
10265: cVar33 = (char)(uVar11 >> 0x38);
10266: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
10267: pcVar28[7] = cVar10;
10268: pcVar26 = pcVar28 + 8;
10269: *pcVar28 = cVar33;
10270: pcVar28[1] = cVar20;
10271: pcVar28[2] = cVar21;
10272: pcVar28[3] = cVar22;
10273: pcVar28[4] = cVar23;
10274: pcVar28[5] = cVar24;
10275: pcVar28[6] = cVar25;
10276: }
10277: else {
10278: pcVar28[1] = '\0';
10279: *pcVar28 = cVar33;
10280: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10281: *pcVar28 = cVar20;
10282: pcVar28[1] = '\0';
10283: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
10284: *pcVar28 = cVar21;
10285: pcVar28[1] = '\0';
10286: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
10287: *pcVar28 = cVar22;
10288: pcVar28[1] = '\0';
10289: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
10290: *pcVar28 = cVar23;
10291: pcVar28[1] = '\0';
10292: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
10293: *pcVar28 = cVar24;
10294: pcVar28[1] = '\0';
10295: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
10296: *pcVar28 = cVar25;
10297: pcVar28[1] = '\0';
10298: pcVar28 = pcVar28 + (ulong)(cVar25 == -1) + 1;
10299: *pcVar28 = cVar10;
10300: pcVar28[1] = '\0';
10301: pcVar26 = pcVar28 + (ulong)(cVar10 == -1) + 1;
10302: }
10303: iVar17 = iVar17 + 0x40;
10304: uVar11 = SEXT48((int)uVar31);
10305: uVar16 = 0;
10306: }
10307: else {
10308: uVar16 = 0;
10309: uVar11 = uVar11 << ((byte)iVar18 & 0x3f) | (long)(int)uVar31;
10310: pcVar26 = pcVar28;
10311: }
10312: }
10313: sVar1 = psVar5[0x3f];
10314: if (sVar1 == 0) {
10315: iStack624 = iVar17 - (char)*(byte *)(puVar4 + 0x100);
10316: if (iStack624 < 0) {
10317: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
10318: uVar14 = *puVar4 >> (-(char)iStack624 & 0x1fU) | uVar11;
10319: cVar10 = (char)uVar14;
10320: cVar25 = (char)(uVar14 >> 8);
10321: cVar24 = (char)(uVar14 >> 0x10);
10322: cVar23 = (char)(uVar14 >> 0x18);
10323: cVar22 = (char)(uVar11 >> 0x20);
10324: cVar21 = (char)(uVar11 >> 0x28);
10325: cVar20 = (char)(uVar11 >> 0x30);
10326: cVar33 = (char)(uVar11 >> 0x38);
10327: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
10328: pcVar26[7] = cVar10;
10329: *pcVar26 = cVar33;
10330: pcVar26[1] = cVar20;
10331: pcVar26[2] = cVar21;
10332: pcVar26[3] = cVar22;
10333: pcVar26[4] = cVar23;
10334: pcVar26[5] = cVar24;
10335: pcVar26[6] = cVar25;
10336: pcVar26 = pcVar26 + 8;
10337: }
10338: else {
10339: pcVar26[1] = '\0';
10340: *pcVar26 = cVar33;
10341: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10342: *pcVar26 = cVar20;
10343: pcVar26[1] = '\0';
10344: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
10345: *pcVar26 = cVar21;
10346: pcVar26[1] = '\0';
10347: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
10348: *pcVar26 = cVar22;
10349: pcVar26[1] = '\0';
10350: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
10351: *pcVar26 = cVar23;
10352: pcVar26[1] = '\0';
10353: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
10354: *pcVar26 = cVar24;
10355: pcVar26[1] = '\0';
10356: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
10357: *pcVar26 = cVar25;
10358: pcVar26[1] = '\0';
10359: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
10360: *pcVar26 = cVar10;
10361: pcVar26[1] = '\0';
10362: pcVar26 = pcVar26 + (ulong)(cVar10 == -1) + 1;
10363: }
10364: iStack624 = iStack624 + 0x40;
10365: uStack632 = (ulong)*puVar4;
10366: }
10367: else {
10368: uStack632 = uVar11 << (*(byte *)(puVar4 + 0x100) & 0x3f) | (ulong)*puVar4;
10369: }
10370: }
10371: else {
10372: uVar31 = (int)sVar1 >> 0x1f;
10373: uVar35 = (int)sVar1 + uVar31;
10374: bVar15 = (&DAT_0016c7a0)[(int)(uVar31 ^ uVar35)];
10375: if (0xff < (int)uVar16) {
10376: iVar29 = iVar17 - (char)*(byte *)(puVar4 + 0x13c);
10377: if (iVar29 < 0) {
10378: uVar11 = uVar11 << ((byte)iVar17 & 0x3f);
10379: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar29 & 0x1fU);
10380: cVar10 = (char)uVar14;
10381: cVar23 = (char)(uVar14 >> 8);
10382: cVar22 = (char)(uVar14 >> 0x10);
10383: cVar21 = (char)(uVar14 >> 0x18);
10384: cVar33 = (char)(uVar11 >> 0x20);
10385: cVar20 = (char)(uVar11 >> 0x28);
10386: cVar24 = (char)(uVar11 >> 0x30);
10387: cVar25 = (char)(uVar11 >> 0x38);
10388: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
10389: pcVar26[7] = cVar10;
10390: pcVar28 = pcVar26 + 8;
10391: *pcVar26 = cVar25;
10392: pcVar26[1] = cVar24;
10393: pcVar26[2] = cVar20;
10394: pcVar26[3] = cVar33;
10395: pcVar26[4] = cVar21;
10396: pcVar26[5] = cVar22;
10397: pcVar26[6] = cVar23;
10398: }
10399: else {
10400: pcVar26[1] = '\0';
10401: *pcVar26 = cVar25;
10402: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10403: *pcVar26 = cVar24;
10404: pcVar26[1] = '\0';
10405: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
10406: *pcVar26 = cVar20;
10407: pcVar26[1] = '\0';
10408: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
10409: *pcVar26 = cVar33;
10410: pcVar26[1] = '\0';
10411: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
10412: *pcVar26 = cVar21;
10413: pcVar26[1] = '\0';
10414: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
10415: *pcVar26 = cVar22;
10416: pcVar26[1] = '\0';
10417: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
10418: *pcVar26 = cVar23;
10419: pcVar26[1] = '\0';
10420: pcVar26 = pcVar26 + (ulong)(cVar23 == -1) + 1;
10421: *pcVar26 = cVar10;
10422: pcVar26[1] = '\0';
10423: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
10424: }
10425: uVar11 = (ulong)puVar4[0xf0];
10426: iVar29 = iVar29 + 0x40;
10427: uVar14 = uVar11;
10428: }
10429: else {
10430: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | (ulong)puVar4[0xf0];
10431: pcVar28 = pcVar26;
10432: uVar14 = (ulong)puVar4[0xf0];
10433: }
10434: pcVar26 = pcVar28;
10435: iVar17 = iVar29;
10436: if (0xff < (int)(uVar16 - 0x100)) {
10437: iVar18 = iVar29 - (char)*(byte *)(puVar4 + 0x13c);
10438: if (iVar18 < 0) {
10439: uVar11 = uVar11 << ((byte)iVar29 & 0x3f);
10440: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar18 & 0x1fU);
10441: cVar10 = (char)uVar14;
10442: cVar33 = (char)(uVar14 >> 8);
10443: cVar20 = (char)(uVar14 >> 0x10);
10444: cVar21 = (char)(uVar14 >> 0x18);
10445: cVar22 = (char)(uVar11 >> 0x20);
10446: cVar23 = (char)(uVar11 >> 0x28);
10447: cVar24 = (char)(uVar11 >> 0x30);
10448: cVar25 = (char)(uVar11 >> 0x38);
10449: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
10450: pcVar28[7] = cVar10;
10451: pcVar27 = pcVar28 + 8;
10452: *pcVar28 = cVar25;
10453: pcVar28[1] = cVar24;
10454: pcVar28[2] = cVar23;
10455: pcVar28[3] = cVar22;
10456: pcVar28[4] = cVar21;
10457: pcVar28[5] = cVar20;
10458: pcVar28[6] = cVar33;
10459: }
10460: else {
10461: pcVar28[1] = '\0';
10462: *pcVar28 = cVar25;
10463: pcVar28 = pcVar28 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10464: *pcVar28 = cVar24;
10465: pcVar28[1] = '\0';
10466: pcVar28 = pcVar28 + (ulong)(cVar24 == -1) + 1;
10467: *pcVar28 = cVar23;
10468: pcVar28[1] = '\0';
10469: pcVar28 = pcVar28 + (ulong)(cVar23 == -1) + 1;
10470: *pcVar28 = cVar22;
10471: pcVar28[1] = '\0';
10472: pcVar28 = pcVar28 + (ulong)(cVar22 == -1) + 1;
10473: *pcVar28 = cVar21;
10474: pcVar28[1] = '\0';
10475: pcVar28 = pcVar28 + (ulong)(cVar21 == -1) + 1;
10476: *pcVar28 = cVar20;
10477: pcVar28[1] = '\0';
10478: pcVar28 = pcVar28 + (ulong)(cVar20 == -1) + 1;
10479: *pcVar28 = cVar33;
10480: pcVar28[1] = '\0';
10481: pcVar28 = pcVar28 + (ulong)(cVar33 == -1) + 1;
10482: *pcVar28 = cVar10;
10483: pcVar28[1] = '\0';
10484: pcVar27 = pcVar28 + (ulong)(cVar10 == -1) + 1;
10485: }
10486: uVar11 = (ulong)puVar4[0xf0];
10487: iVar18 = iVar18 + 0x40;
10488: uVar14 = uVar11;
10489: }
10490: else {
10491: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
10492: pcVar27 = pcVar28;
10493: }
10494: pcVar26 = pcVar27;
10495: iVar17 = iVar18;
10496: if (0x2ff < (int)uVar16) {
10497: iVar17 = iVar18 - (char)*(byte *)(puVar4 + 0x13c);
10498: if (iVar17 < 0) {
10499: uVar11 = uVar11 << ((byte)iVar18 & 0x3f);
10500: uVar14 = uVar11 | puVar4[0xf0] >> (-(char)iVar17 & 0x1fU);
10501: cVar10 = (char)uVar14;
10502: cVar20 = (char)(uVar14 >> 8);
10503: cVar33 = (char)(uVar14 >> 0x10);
10504: cVar24 = (char)(uVar14 >> 0x18);
10505: cVar25 = (char)(uVar11 >> 0x20);
10506: cVar23 = (char)(uVar11 >> 0x28);
10507: cVar22 = (char)(uVar11 >> 0x30);
10508: cVar21 = (char)(uVar11 >> 0x38);
10509: if ((~(uVar14 + 0x101010101010101) & uVar14 & 0x8080808080808080) == 0) {
10510: pcVar27[7] = cVar10;
10511: pcVar26 = pcVar27 + 8;
10512: *pcVar27 = cVar21;
10513: pcVar27[1] = cVar22;
10514: pcVar27[2] = cVar23;
10515: pcVar27[3] = cVar25;
10516: pcVar27[4] = cVar24;
10517: pcVar27[5] = cVar33;
10518: pcVar27[6] = cVar20;
10519: }
10520: else {
10521: pcVar27[1] = '\0';
10522: *pcVar27 = cVar21;
10523: pcVar27 = pcVar27 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10524: *pcVar27 = cVar22;
10525: pcVar27[1] = '\0';
10526: pcVar27 = pcVar27 + (ulong)(cVar22 == -1) + 1;
10527: *pcVar27 = cVar23;
10528: pcVar27[1] = '\0';
10529: pcVar27 = pcVar27 + (ulong)(cVar23 == -1) + 1;
10530: *pcVar27 = cVar25;
10531: pcVar27[1] = '\0';
10532: pcVar27 = pcVar27 + (ulong)(cVar25 == -1) + 1;
10533: *pcVar27 = cVar24;
10534: pcVar27[1] = '\0';
10535: pcVar27 = pcVar27 + (ulong)(cVar24 == -1) + 1;
10536: *pcVar27 = cVar33;
10537: pcVar27[1] = '\0';
10538: pcVar27 = pcVar27 + (ulong)(cVar33 == -1) + 1;
10539: *pcVar27 = cVar20;
10540: pcVar27[1] = '\0';
10541: pcVar27 = pcVar27 + (ulong)(cVar20 == -1) + 1;
10542: *pcVar27 = cVar10;
10543: pcVar27[1] = '\0';
10544: pcVar26 = pcVar27 + (ulong)(cVar10 == -1) + 1;
10545: }
10546: iVar17 = iVar17 + 0x40;
10547: uVar11 = (ulong)puVar4[0xf0];
10548: }
10549: else {
10550: uVar11 = uVar11 << (*(byte *)(puVar4 + 0x13c) & 0x3f) | uVar14;
10551: }
10552: }
10553: }
10554: uVar16 = uVar16 - 0x100 & 0xff;
10555: }
10556: uVar31 = uVar35 & (int)(1 << (bVar15 & 0x3f)) - 1U |
10557: puVar4[(int)(uVar16 + bVar15)] << (bVar15 & 0x1f);
10558: iVar29 = (int)*(char *)((long)puVar4 + (long)(int)(uVar16 + bVar15) + 0x400) +
10559: (uint)bVar15;
10560: iStack624 = iVar17 - iVar29;
10561: if (iStack624 < 0) {
10562: uVar11 = (long)((int)uVar31 >> (-(char)iStack624 & 0x1fU)) |
10563: uVar11 << ((byte)iVar17 & 0x3f);
10564: cVar10 = (char)uVar11;
10565: cVar22 = (char)(uVar11 >> 8);
10566: cVar21 = (char)(uVar11 >> 0x10);
10567: cVar20 = (char)(uVar11 >> 0x18);
10568: cVar33 = (char)(uVar11 >> 0x20);
10569: cVar25 = (char)(uVar11 >> 0x28);
10570: cVar24 = (char)(uVar11 >> 0x30);
10571: cVar23 = (char)(uVar11 >> 0x38);
10572: if ((~(uVar11 + 0x101010101010101) & uVar11 & 0x8080808080808080) == 0) {
10573: pcVar26[7] = cVar10;
10574: pcVar28 = pcVar26 + 8;
10575: *pcVar26 = cVar23;
10576: pcVar26[1] = cVar24;
10577: pcVar26[2] = cVar25;
10578: pcVar26[3] = cVar33;
10579: pcVar26[4] = cVar20;
10580: pcVar26[5] = cVar21;
10581: pcVar26[6] = cVar22;
10582: }
10583: else {
10584: pcVar26[1] = '\0';
10585: *pcVar26 = cVar23;
10586: pcVar26 = pcVar26 + (ulong)(uVar11 >> 0x38 == 0xff) + 1;
10587: *pcVar26 = cVar24;
10588: pcVar26[1] = '\0';
10589: pcVar26 = pcVar26 + (ulong)(cVar24 == -1) + 1;
10590: *pcVar26 = cVar25;
10591: pcVar26[1] = '\0';
10592: pcVar26 = pcVar26 + (ulong)(cVar25 == -1) + 1;
10593: *pcVar26 = cVar33;
10594: pcVar26[1] = '\0';
10595: pcVar26 = pcVar26 + (ulong)(cVar33 == -1) + 1;
10596: *pcVar26 = cVar20;
10597: pcVar26[1] = '\0';
10598: pcVar26 = pcVar26 + (ulong)(cVar20 == -1) + 1;
10599: *pcVar26 = cVar21;
10600: pcVar26[1] = '\0';
10601: pcVar26 = pcVar26 + (ulong)(cVar21 == -1) + 1;
10602: *pcVar26 = cVar22;
10603: pcVar26[1] = '\0';
10604: pcVar26 = pcVar26 + (ulong)(cVar22 == -1) + 1;
10605: *pcVar26 = cVar10;
10606: pcVar26[1] = '\0';
10607: pcVar28 = pcVar26 + (ulong)(cVar10 == -1) + 1;
10608: }
10609: iStack624 = iStack624 + 0x40;
10610: uStack632 = SEXT48((int)uVar31);
10611: pcVar26 = pcVar28;
10612: }
10613: else {
10614: uStack632 = uVar11 << ((byte)iVar29 & 0x3f) | (long)(int)uVar31;
10615: }
10616: }
10617: if (pcStack640 < (char *)0x200) {
10618: pcVar26 = pcVar26 + -(long)acStack584;
10619: pcVar28 = acStack584;
10620: while (pcVar26 != (char *)0x0) {
10621: pcVar27 = pcVar26;
10622: if (pcStack640 <= pcVar26) {
10623: pcVar27 = pcStack640;
10624: }
10625: memcpy(pcStack648,pcVar28,(size_t)pcVar27);
10626: pcStack648 = pcStack648 + (long)pcVar27;
10627: pcStack640 = pcStack640 + -(long)pcVar27;
10628: if (pcStack640 == (char *)0x0) {
10629: ppcVar6 = *(char ***)(lStack600 + 0x28);
10630: uVar12 = (*(code *)ppcVar6[3])();
10631: if ((int)uVar12 == 0) goto LAB_0010b2e8;
10632: pcStack648 = *ppcVar6;
10633: pcStack640 = ppcVar6[1];
10634: }
10635: pcVar26 = pcVar26 + -(long)pcVar27;
10636: pcVar28 = pcVar28 + (long)pcVar27;
10637: }
10638: }
10639: else {
10640: pcStack640 = pcStack640 + -(long)(pcVar26 + -(long)pcStack648);
10641: pcStack648 = pcVar26;
10642: }
10643: (&iStack620)[lVar30] = (int)**(short **)(param_2 + -8 + lStack680 * 8);
10644: iVar17 = (int)lStack680;
10645: lStack680 = lStack680 + 1;
10646: } while (*(int *)(param_1 + 0x170) != iVar17 && iVar17 <= *(int *)(param_1 + 0x170));
10647: }
10648: }
10649: else {
10650: if (0 < *(int *)(param_1 + 0x170)) {
10651: lVar34 = 1;
10652: do {
10653: lVar30 = (long)*(int *)(param_1 + 0x170 + lVar34 * 4);
10654: lVar13 = *(long *)(param_1 + 0x148 + lVar30 * 8);
10655: uVar12 = *(undefined8 *)(lVar3 + 0x40 + (long)*(int *)(lVar13 + 0x14) * 8);
10656: uVar7 = *(undefined8 *)(lVar3 + 0x60 + (long)*(int *)(lVar13 + 0x18) * 8);
10657: uVar8 = *(undefined8 *)(param_2 + -8 + lVar34 * 8);
10658: if (pcStack640 < (char *)0x200) {
10659: lVar13 = FUN_0016c280(&pcStack648,acStack584,uVar8,(&iStack620)[lVar30],uVar12,uVar7);
10660: pcVar26 = (char *)(lVar13 - (long)acStack584);
10661: pcVar28 = acStack584;
10662: while (pcVar26 != (char *)0x0) {
10663: pcVar27 = pcVar26;
10664: if (pcStack640 <= pcVar26) {
10665: pcVar27 = pcStack640;
10666: }
10667: memcpy(pcStack648,pcVar28,(size_t)pcVar27);
10668: pcStack648 = pcStack648 + (long)pcVar27;
10669: pcStack640 = pcStack640 + -(long)pcVar27;
10670: if (pcStack640 == (char *)0x0) {
10671: ppcVar6 = *(char ***)(lStack600 + 0x28);
10672: uVar12 = (*(code *)ppcVar6[3])();
10673: if ((int)uVar12 == 0) goto LAB_0010b2e8;
10674: pcStack648 = *ppcVar6;
10675: pcStack640 = ppcVar6[1];
10676: }
10677: pcVar26 = pcVar26 + -(long)pcVar27;
10678: pcVar28 = pcVar28 + (long)pcVar27;
10679: }
10680: }
10681: else {
10682: pcVar28 = (char *)FUN_0016c280(&pcStack648,pcStack648,uVar8,(&iStack620)[lVar30],uVar12,
10683: uVar7);
10684: pcStack640 = pcStack640 + -(long)(pcVar28 + -(long)pcStack648);
10685: pcStack648 = pcVar28;
10686: }
10687: (&iStack620)[lVar30] = (int)**(short **)(param_2 + -8 + lVar34 * 8);
10688: iVar17 = (int)lVar34;
10689: lVar34 = lVar34 + 1;
10690: } while (*(int *)(param_1 + 0x170) != iVar17 && iVar17 <= *(int *)(param_1 + 0x170));
10691: }
10692: }
10693: ppcVar6 = *(char ***)(param_1 + 0x28);
10694: *ppcVar6 = pcStack648;
10695: ppcVar6[1] = pcStack640;
10696: iVar17 = *(int *)(param_1 + 0x118);
10697: uVar12 = 1;
10698: *(undefined4 *)(lVar3 + 0x18) = (undefined4)uStack632;
10699: *(undefined4 *)(lVar3 + 0x1c) = uStack632._4_4_;
10700: *(int *)(lVar3 + 0x20) = iStack624;
10701: *(int *)(lVar3 + 0x24) = iStack620;
10702: *(undefined4 *)(lVar3 + 0x28) = (undefined4)uStack616;
10703: *(undefined4 *)(lVar3 + 0x2c) = uStack616._4_4_;
10704: *(undefined4 *)(lVar3 + 0x30) = (undefined4)uStack608;
10705: *(undefined4 *)(lVar3 + 0x34) = uStack608._4_4_;
10706: if (iVar17 != 0) {
10707: if (*(int *)(lVar3 + 0x38) == 0) {
10708: *(int *)(lVar3 + 0x38) = iVar17;
10709: *(uint *)(lVar3 + 0x3c) = *(int *)(lVar3 + 0x3c) + 1U & 7;
10710: }
10711: *(int *)(lVar3 + 0x38) = *(int *)(lVar3 + 0x38) + -1;
10712: uVar12 = 1;
10713: }
10714: LAB_0010b2e8:
10715: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
10716: /* WARNING: Subroutine does not return */
10717: __stack_chk_fail();
10718: }
10719: return uVar12;
10720: }
10721: 
