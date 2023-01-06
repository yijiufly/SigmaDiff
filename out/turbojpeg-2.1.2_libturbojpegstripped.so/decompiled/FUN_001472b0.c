1: 
2: void FUN_001472b0(long param_1,uint param_2,uint param_3,uint param_4)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: long lVar3;
8: short *psVar4;
9: int iVar5;
10: byte bVar6;
11: int iVar7;
12: int iVar8;
13: long lVar9;
14: long lVar10;
15: uint uVar11;
16: int iVar12;
17: ulong uVar13;
18: long lVar14;
19: long lVar15;
20: byte *pbVar16;
21: long *plVar17;
22: byte *pbVar18;
23: long lVar19;
24: long lVar20;
25: uint uVar21;
26: int iVar22;
27: ulong uVar23;
28: long lVar24;
29: long lVar25;
30: long lVar26;
31: short *psVar27;
32: long lVar28;
33: long lVar29;
34: long lVar30;
35: long lVar31;
36: long lVar32;
37: int iVar33;
38: long lVar34;
39: long lVar35;
40: long lVar36;
41: long lVar37;
42: int iVar38;
43: int iVar39;
44: long lVar40;
45: long in_FS_OFFSET;
46: byte *pbStack2648;
47: long alStack2504 [128];
48: long alStack1480 [128];
49: byte abStack456 [392];
50: long lStack64;
51: 
52: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
53: iVar39 = ((int)param_2 >> 2) * 0x20;
54: lVar9 = *(long *)(*(long *)(param_1 + 0x270) + 0x30);
55: iVar38 = ((int)param_3 >> 3) * 0x20;
56: iVar5 = iVar38 + 2;
57: iVar38 = iVar38 + 0x1e;
58: iVar33 = ((int)param_4 >> 2) * 0x20;
59: iVar22 = *(int *)(param_1 + 0x9c);
60: iVar1 = iVar39 + 4;
61: iVar39 = iVar39 + 0x1c;
62: iVar2 = iVar33 + 4;
63: iVar33 = iVar33 + 0x1c;
64: uVar23 = (ulong)*(uint *)(param_1 + 0x40);
65: if (iVar22 < 1) {
66: iVar22 = 0;
67: }
68: else {
69: plVar17 = *(long **)(param_1 + 0xa0);
70: lVar32 = 0x7fffffff;
71: lVar15 = *plVar17;
72: lVar34 = plVar17[1];
73: lVar10 = plVar17[2];
74: uVar13 = (ulong)*(uint *)(param_1 + 0x40);
75: iVar7 = *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018f080 + uVar13 * 4) * 4);
76: iVar8 = *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018f020 + uVar13 * 4) * 4);
77: iVar12 = *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018efc0 + uVar13 * 4) * 4);
78: lVar30 = 0;
79: do {
80: uVar11 = (uint)*(byte *)(lVar15 + lVar30);
81: if ((int)uVar11 < iVar1) {
82: lVar19 = (long)(int)((uVar11 - iVar1) * iVar7);
83: lVar14 = (long)(int)((uVar11 - iVar39) * iVar7);
84: lVar19 = lVar19 * lVar19;
85: lVar14 = lVar14 * lVar14;
86: LAB_0014740a:
87: bVar6 = *(byte *)(lVar34 + lVar30);
88: uVar21 = (uint)bVar6;
89: if (iVar5 <= (int)(uint)bVar6) goto LAB_001474e0;
90: LAB_0014741b:
91: lVar29 = (long)(int)((uVar21 - iVar5) * iVar8);
92: lVar19 = lVar19 + lVar29 * lVar29;
93: LAB_00147432:
94: lVar29 = (long)(int)((uVar21 - iVar38) * iVar8);
95: lVar14 = lVar14 + lVar29 * lVar29;
96: bVar6 = *(byte *)(lVar10 + lVar30);
97: uVar11 = (uint)bVar6;
98: if (iVar2 <= (int)(uint)bVar6) goto LAB_0014751e;
99: LAB_00147453:
100: lVar29 = (long)(int)((uVar11 - iVar2) * iVar12);
101: lVar19 = lVar19 + lVar29 * lVar29;
102: LAB_00147465:
103: lVar29 = (long)(int)((uVar11 - iVar33) * iVar12);
104: lVar14 = lVar29 * lVar29 + lVar14;
105: }
106: else {
107: if ((int)uVar11 <= iVar39) {
108: if (iVar1 + iVar39 >> 1 < (int)uVar11) {
109: lVar19 = 0;
110: lVar14 = (long)(int)((uVar11 - iVar1) * iVar7);
111: lVar14 = lVar14 * lVar14;
112: }
113: else {
114: lVar19 = 0;
115: lVar14 = (long)(int)((uVar11 - iVar39) * iVar7);
116: lVar14 = lVar14 * lVar14;
117: }
118: goto LAB_0014740a;
119: }
120: uVar21 = (uint)*(byte *)(lVar34 + lVar30);
121: lVar19 = (long)(int)((uVar11 - iVar39) * iVar7);
122: lVar19 = lVar19 * lVar19;
123: lVar14 = (long)(int)((uVar11 - iVar1) * iVar7);
124: lVar14 = lVar14 * lVar14;
125: if ((int)uVar21 < iVar5) goto LAB_0014741b;
126: LAB_001474e0:
127: if (iVar38 < (int)uVar21) {
128: lVar29 = (long)(int)((uVar21 - iVar38) * iVar8);
129: lVar19 = lVar19 + lVar29 * lVar29;
130: }
131: else {
132: if ((int)uVar21 <= iVar5 + iVar38 >> 1) goto LAB_00147432;
133: }
134: lVar29 = (long)(int)((uVar21 - iVar5) * iVar8);
135: lVar14 = lVar14 + lVar29 * lVar29;
136: uVar11 = (uint)*(byte *)(lVar10 + lVar30);
137: if ((int)uVar11 < iVar2) goto LAB_00147453;
138: LAB_0014751e:
139: if ((int)uVar11 <= iVar33) {
140: if (iVar2 + iVar33 >> 1 < (int)uVar11) goto LAB_00147536;
141: goto LAB_00147465;
142: }
143: lVar29 = (long)(int)((uVar11 - iVar33) * iVar12);
144: lVar19 = lVar19 + lVar29 * lVar29;
145: LAB_00147536:
146: lVar29 = (long)(int)((uVar11 - iVar2) * iVar12);
147: lVar14 = lVar29 * lVar29 + lVar14;
148: }
149: if (lVar14 < lVar32) {
150: lVar32 = lVar14;
151: }
152: alStack2504[lVar30] = lVar19;
153: lVar30 = lVar30 + 1;
154: } while (lVar30 != (ulong)(iVar22 - 1) + 1);
155: iVar22 = 0;
156: lVar15 = 0;
157: do {
158: plVar17 = alStack2504 + lVar15;
159: if (*plVar17 == lVar32 || *plVar17 < lVar32) {
160: lVar34 = (long)iVar22;
161: iVar22 = iVar22 + 1;
162: abStack456[lVar34 + 0x80] = (byte)lVar15;
163: }
164: lVar15 = lVar15 + 1;
165: } while (lVar15 != lVar30);
166: }
167: plVar17 = alStack2504;
168: do {
169: *plVar17 = 0x7fffffff;
170: plVar17[1] = 0x7fffffff;
171: plVar17 = plVar17 + 2;
172: } while (alStack1480 != plVar17);
173: if (iVar22 != 0) {
174: plVar17 = *(long **)(param_1 + 0xa0);
175: lVar15 = *plVar17;
176: iVar39 = *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018f080 + uVar23 * 4) * 4);
177: lVar34 = plVar17[1];
178: iVar7 = *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018f020 + uVar23 * 4) * 4);
179: lVar10 = plVar17[2];
180: iVar33 = iVar7 * 4;
181: iVar8 = *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018efc0 + uVar23 * 4) * 4);
182: iVar38 = iVar39 * 8;
183: iVar12 = iVar8 * 8;
184: lVar32 = (long)(iVar12 * iVar8 * 0x10);
185: lVar30 = (long)(iVar7 * 8 * iVar33);
186: pbVar16 = abStack456 + 0x80;
187: pbStack2648 = abStack456 + 0x81;
188: while( true ) {
189: bVar6 = *pbVar16;
190: uVar23 = (ulong)bVar6;
191: lVar20 = 0;
192: lVar36 = (long)(int)((iVar1 - (uint)*(byte *)(lVar15 + uVar23)) * iVar39);
193: lVar19 = (long)(int)((iVar5 - (uint)*(byte *)(lVar34 + uVar23)) * iVar7);
194: lVar29 = (long)(int)((iVar2 - (uint)*(byte *)(lVar10 + uVar23)) * iVar8);
195: lVar28 = lVar19 * (iVar7 * 8) + (long)(iVar33 * iVar33);
196: lVar37 = lVar36 * (iVar39 * 0x10) + (long)(iVar38 * iVar38);
197: lVar14 = lVar28 + lVar30;
198: lVar35 = lVar29 * lVar29 + lVar36 * lVar36 + lVar19 * lVar19;
199: lVar31 = lVar29 * (iVar8 * 0x10) + (long)(iVar12 * iVar12);
200: lVar19 = lVar30 + lVar14;
201: lVar29 = lVar30 + lVar19;
202: lVar36 = lVar31 + lVar32;
203: lVar24 = lVar29 + lVar30;
204: lVar25 = lVar24 + lVar30;
205: lVar3 = lVar32 + lVar36;
206: plVar17 = alStack2504;
207: do {
208: if (lVar35 < *plVar17) {
209: *plVar17 = lVar35;
210: abStack456[lVar20] = bVar6;
211: }
212: lVar26 = lVar31 + lVar35;
213: if (lVar26 < plVar17[1]) {
214: plVar17[1] = lVar26;
215: abStack456[lVar20 + 1] = bVar6;
216: }
217: lVar26 = lVar26 + lVar36;
218: if (lVar26 < plVar17[2]) {
219: plVar17[2] = lVar26;
220: abStack456[lVar20 + 2] = bVar6;
221: }
222: if (lVar26 + lVar3 < plVar17[3]) {
223: plVar17[3] = lVar26 + lVar3;
224: abStack456[lVar20 + 3] = bVar6;
225: }
226: lVar26 = lVar28 + lVar35;
227: if (lVar26 < plVar17[4]) {
228: plVar17[4] = lVar26;
229: abStack456[lVar20 + 4] = bVar6;
230: }
231: lVar40 = lVar31 + lVar26;
232: if (plVar17[5] != lVar40 && lVar40 <= plVar17[5]) {
233: plVar17[5] = lVar40;
234: abStack456[lVar20 + 5] = bVar6;
235: }
236: lVar40 = lVar40 + lVar36;
237: if (lVar40 < plVar17[6]) {
238: plVar17[6] = lVar40;
239: abStack456[lVar20 + 6] = bVar6;
240: }
241: if (lVar40 + lVar3 < plVar17[7]) {
242: plVar17[7] = lVar40 + lVar3;
243: abStack456[lVar20 + 7] = bVar6;
244: }
245: lVar26 = lVar26 + lVar14;
246: if (plVar17[8] != lVar26 && lVar26 <= plVar17[8]) {
247: plVar17[8] = lVar26;
248: abStack456[lVar20 + 8] = bVar6;
249: }
250: lVar40 = lVar31 + lVar26;
251: if (lVar40 < plVar17[9]) {
252: plVar17[9] = lVar40;
253: abStack456[lVar20 + 9] = bVar6;
254: }
255: lVar40 = lVar40 + lVar36;
256: if (lVar40 < plVar17[10]) {
257: plVar17[10] = lVar40;
258: abStack456[lVar20 + 10] = bVar6;
259: }
260: if (lVar40 + lVar3 < plVar17[0xb]) {
261: plVar17[0xb] = lVar40 + lVar3;
262: abStack456[lVar20 + 0xb] = bVar6;
263: }
264: lVar26 = lVar26 + lVar19;
265: if (lVar26 < plVar17[0xc]) {
266: plVar17[0xc] = lVar26;
267: abStack456[lVar20 + 0xc] = bVar6;
268: }
269: lVar40 = lVar31 + lVar26;
270: if (lVar40 < plVar17[0xd]) {
271: plVar17[0xd] = lVar40;
272: abStack456[lVar20 + 0xd] = bVar6;
273: }
274: lVar40 = lVar40 + lVar36;
275: if (lVar40 < plVar17[0xe]) {
276: plVar17[0xe] = lVar40;
277: abStack456[lVar20 + 0xe] = bVar6;
278: }
279: lVar40 = lVar40 + lVar3;
280: if (plVar17[0xf] != lVar40 && lVar40 <= plVar17[0xf]) {
281: plVar17[0xf] = lVar40;
282: abStack456[lVar20 + 0xf] = bVar6;
283: }
284: lVar26 = lVar26 + lVar29;
285: if (plVar17[0x10] != lVar26 && lVar26 <= plVar17[0x10]) {
286: plVar17[0x10] = lVar26;
287: abStack456[lVar20 + 0x10] = bVar6;
288: }
289: lVar40 = lVar31 + lVar26;
290: if (lVar40 < plVar17[0x11]) {
291: plVar17[0x11] = lVar40;
292: abStack456[lVar20 + 0x11] = bVar6;
293: }
294: lVar40 = lVar40 + lVar36;
295: if (lVar40 < plVar17[0x12]) {
296: plVar17[0x12] = lVar40;
297: abStack456[lVar20 + 0x12] = bVar6;
298: }
299: if (lVar40 + lVar3 < plVar17[0x13]) {
300: plVar17[0x13] = lVar40 + lVar3;
301: abStack456[lVar20 + 0x13] = bVar6;
302: }
303: lVar26 = lVar26 + lVar24;
304: if (plVar17[0x14] != lVar26 && lVar26 <= plVar17[0x14]) {
305: plVar17[0x14] = lVar26;
306: abStack456[lVar20 + 0x14] = bVar6;
307: }
308: lVar40 = lVar31 + lVar26;
309: if (lVar40 < plVar17[0x15]) {
310: plVar17[0x15] = lVar40;
311: abStack456[lVar20 + 0x15] = bVar6;
312: }
313: lVar40 = lVar40 + lVar36;
314: if (plVar17[0x16] != lVar40 && lVar40 <= plVar17[0x16]) {
315: plVar17[0x16] = lVar40;
316: abStack456[lVar20 + 0x16] = bVar6;
317: }
318: if (lVar40 + lVar3 < plVar17[0x17]) {
319: plVar17[0x17] = lVar40 + lVar3;
320: abStack456[lVar20 + 0x17] = bVar6;
321: }
322: lVar26 = lVar26 + lVar25;
323: if (lVar26 < plVar17[0x18]) {
324: plVar17[0x18] = lVar26;
325: abStack456[lVar20 + 0x18] = bVar6;
326: }
327: lVar40 = lVar31 + lVar26;
328: if (lVar40 < plVar17[0x19]) {
329: plVar17[0x19] = lVar40;
330: abStack456[lVar20 + 0x19] = bVar6;
331: }
332: lVar40 = lVar40 + lVar36;
333: if (lVar40 < plVar17[0x1a]) {
334: plVar17[0x1a] = lVar40;
335: abStack456[lVar20 + 0x1a] = bVar6;
336: }
337: lVar40 = lVar40 + lVar3;
338: if (plVar17[0x1b] != lVar40 && lVar40 <= plVar17[0x1b]) {
339: plVar17[0x1b] = lVar40;
340: abStack456[lVar20 + 0x1b] = bVar6;
341: }
342: lVar26 = lVar26 + lVar25 + lVar30;
343: if (plVar17[0x1c] != lVar26 && lVar26 <= plVar17[0x1c]) {
344: plVar17[0x1c] = lVar26;
345: abStack456[lVar20 + 0x1c] = bVar6;
346: }
347: lVar26 = lVar26 + lVar31;
348: if (lVar26 < plVar17[0x1d]) {
349: plVar17[0x1d] = lVar26;
350: abStack456[lVar20 + 0x1d] = bVar6;
351: }
352: lVar26 = lVar26 + lVar36;
353: if (lVar26 < plVar17[0x1e]) {
354: plVar17[0x1e] = lVar26;
355: abStack456[lVar20 + 0x1e] = bVar6;
356: }
357: if (lVar26 + lVar3 < plVar17[0x1f]) {
358: plVar17[0x1f] = lVar26 + lVar3;
359: abStack456[lVar20 + 0x1f] = bVar6;
360: }
361: lVar20 = lVar20 + 0x20;
362: lVar35 = lVar35 + lVar37;
363: plVar17 = plVar17 + 0x20;
364: lVar37 = lVar37 + iVar39 * 0x10 * iVar38;
365: } while (lVar20 != 0x80);
366: if (pbStack2648 == abStack456 + 0x81 + (iVar22 - 1)) break;
367: pbVar16 = pbStack2648;
368: pbStack2648 = pbStack2648 + 1;
369: }
370: }
371: lVar34 = (long)(int)(param_3 & 0xfffffff8) * 0x40;
372: lVar15 = (long)(int)(param_4 & 0xfffffffc) * 2;
373: plVar17 = (long *)(lVar9 + (long)(int)(param_2 & 0xfffffffc) * 8);
374: pbVar16 = abStack456;
375: do {
376: lVar9 = *plVar17;
377: psVar4 = (short *)(lVar9 + lVar15 + lVar34);
378: *psVar4 = *pbVar16 + 1;
379: psVar4[1] = pbVar16[1] + 1;
380: psVar4[2] = pbVar16[2] + 1;
381: psVar4[3] = pbVar16[3] + 1;
382: psVar4 = (short *)(lVar9 + lVar15 + 0x40 + lVar34);
383: *psVar4 = pbVar16[4] + 1;
384: psVar4[1] = pbVar16[5] + 1;
385: psVar4[2] = pbVar16[6] + 1;
386: psVar4[3] = pbVar16[7] + 1;
387: psVar4 = (short *)(lVar9 + lVar15 + 0x80 + lVar34);
388: *psVar4 = pbVar16[8] + 1;
389: psVar4[1] = pbVar16[9] + 1;
390: psVar4[2] = pbVar16[10] + 1;
391: psVar4[3] = pbVar16[0xb] + 1;
392: psVar4 = (short *)(lVar9 + lVar15 + 0xc0 + lVar34);
393: *psVar4 = pbVar16[0xc] + 1;
394: psVar4[1] = pbVar16[0xd] + 1;
395: psVar4[2] = pbVar16[0xe] + 1;
396: psVar4[3] = pbVar16[0xf] + 1;
397: psVar4 = (short *)(lVar9 + lVar15 + 0x100 + lVar34);
398: *psVar4 = pbVar16[0x10] + 1;
399: psVar4[1] = pbVar16[0x11] + 1;
400: psVar4[2] = pbVar16[0x12] + 1;
401: psVar4[3] = pbVar16[0x13] + 1;
402: psVar4 = (short *)(lVar9 + lVar15 + 0x140 + lVar34);
403: *psVar4 = pbVar16[0x14] + 1;
404: psVar4[1] = pbVar16[0x15] + 1;
405: psVar4[2] = pbVar16[0x16] + 1;
406: psVar4[3] = pbVar16[0x17] + 1;
407: psVar4 = (short *)(lVar9 + lVar15 + 0x180 + lVar34);
408: psVar27 = (short *)(lVar9 + lVar15 + 0x1c0 + lVar34);
409: *psVar4 = pbVar16[0x18] + 1;
410: psVar4[1] = pbVar16[0x19] + 1;
411: psVar4[2] = pbVar16[0x1a] + 1;
412: psVar4[3] = pbVar16[0x1b] + 1;
413: *psVar27 = pbVar16[0x1c] + 1;
414: psVar27[1] = pbVar16[0x1d] + 1;
415: pbVar18 = pbVar16 + 0x20;
416: plVar17 = plVar17 + 1;
417: psVar27[2] = pbVar16[0x1e] + 1;
418: psVar27[3] = pbVar16[0x1f] + 1;
419: pbVar16 = pbVar18;
420: } while (pbVar18 != abStack456 + 0x80);
421: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
422: /* WARNING: Subroutine does not return */
423: __stack_chk_fail(0x7fffffff);
424: }
425: return;
426: }
427: 
