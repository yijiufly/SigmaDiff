1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00146ad0(uint param_1,long param_2,int *param_3)
5: 
6: {
7: long lVar1;
8: ushort uVar2;
9: ushort uVar3;
10: ushort uVar4;
11: ushort uVar5;
12: short *psVar6;
13: short *psVar7;
14: short *psVar8;
15: short *psVar9;
16: short *psVar10;
17: short *psVar11;
18: short *psVar12;
19: long lVar13;
20: int iVar14;
21: int iVar15;
22: uint uVar16;
23: int iVar17;
24: uint uVar18;
25: long lVar19;
26: short *psVar20;
27: int iVar21;
28: long lVar22;
29: long lVar23;
30: int iVar24;
31: int iVar25;
32: short *psVar26;
33: long lVar27;
34: ulong uVar28;
35: short *psVar29;
36: long lVar30;
37: int iVar31;
38: ulong uVar32;
39: short sVar38;
40: uint6 uVar33;
41: short sVar39;
42: long lVar35;
43: short sVar40;
44: short sVar41;
45: short sVar42;
46: undefined auVar37 [16];
47: uint uVar43;
48: int iVar46;
49: undefined4 uVar47;
50: long lVar48;
51: long lVar49;
52: ushort uVar50;
53: short sVar51;
54: long *plStack120;
55: int iStack112;
56: int iStack108;
57: undefined8 uVar34;
58: undefined auVar36 [12];
59: undefined auVar44 [16];
60: undefined auVar45 [16];
61: 
62: uVar32 = (ulong)param_1;
63: iVar25 = *param_3;
64: lVar13 = (long)iVar25;
65: iVar15 = param_3[1];
66: lVar1 = *(long *)(param_2 + 0x30);
67: iVar21 = param_3[2];
68: iStack112 = param_3[3];
69: iVar17 = param_3[4];
70: iVar31 = param_3[5];
71: iVar24 = iVar15;
72: if (iVar25 < iVar15) {
73: lVar13 = (long)iVar25;
74: do {
75: iVar46 = (int)lVar13;
76: if (iVar21 <= iStack112) {
77: psVar26 = (short *)((long)iVar17 * 2 + 2 + (long)iVar21 * 0x40 +
78: *(long *)(lVar1 + lVar13 * 8));
79: iVar24 = iVar21;
80: do {
81: if (iVar17 <= iVar31) {
82: sVar38 = psVar26[-1];
83: iVar14 = iVar17;
84: psVar29 = psVar26;
85: while( true ) {
86: if (sVar38 != 0) {
87: *param_3 = iVar46;
88: if (iVar15 <= iVar46) goto LAB_00146c0e;
89: goto LAB_00146b99;
90: }
91: iVar14 = iVar14 + 1;
92: if (iVar31 < iVar14) break;
93: sVar38 = *psVar29;
94: psVar29 = psVar29 + 1;
95: }
96: }
97: iVar24 = iVar24 + 1;
98: psVar26 = psVar26 + 0x20;
99: } while (iVar24 <= iStack112);
100: }
101: lVar13 = lVar13 + 1;
102: iVar46 = iVar25;
103: } while ((int)lVar13 <= iVar15);
104: LAB_00146b99:
105: lVar13 = (long)iVar15;
106: do {
107: iVar24 = (int)lVar13;
108: if (iVar21 <= iStack112) {
109: psVar26 = (short *)(*(long *)(lVar1 + lVar13 * 8) +
110: (long)iVar17 * 2 + 2 + (long)iVar21 * 0x40);
111: iVar25 = iVar21;
112: do {
113: if (iVar17 <= iVar31) {
114: sVar38 = psVar26[-1];
115: iVar14 = iVar17;
116: psVar29 = psVar26;
117: while( true ) {
118: if (sVar38 != 0) {
119: param_3[1] = iVar24;
120: lVar13 = (long)iVar46;
121: goto LAB_00146c11;
122: }
123: iVar14 = iVar14 + 1;
124: if (iVar31 < iVar14) break;
125: sVar38 = *psVar29;
126: psVar29 = psVar29 + 1;
127: }
128: }
129: iVar25 = iVar25 + 1;
130: psVar26 = psVar26 + 0x20;
131: } while (iVar25 <= iStack112);
132: }
133: lVar13 = lVar13 + -1;
134: } while (iVar46 <= (int)lVar13);
135: LAB_00146c0e:
136: lVar13 = (long)iVar46;
137: iVar24 = iVar15;
138: }
139: LAB_00146c11:
140: iVar25 = (int)lVar13;
141: iStack108 = iVar21;
142: if (iVar21 < iStack112) {
143: lVar30 = (long)iVar17;
144: lVar27 = (long)iVar21 << 6;
145: do {
146: lVar22 = (long)iVar25;
147: iVar15 = iVar25;
148: while (iVar15 <= iVar24) {
149: lVar19 = *(long *)(lVar1 + lVar22 * 8) + lVar27;
150: if (iVar17 <= iVar31) {
151: sVar38 = *(short *)(lVar19 + lVar30 * 2);
152: iVar15 = iVar17;
153: psVar26 = (short *)(lVar19 + lVar30 * 2 + 2);
154: while( true ) {
155: if (sVar38 != 0) {
156: param_3[2] = iStack108;
157: iVar21 = iStack108;
158: if (iStack112 <= iStack108) goto LAB_00146d0f;
159: goto LAB_00146c9d;
160: }
161: iVar15 = iVar15 + 1;
162: if (iVar31 < iVar15) break;
163: sVar38 = *psVar26;
164: psVar26 = psVar26 + 1;
165: }
166: }
167: lVar22 = lVar22 + 1;
168: iVar15 = (int)lVar22;
169: }
170: iStack108 = iStack108 + 1;
171: lVar27 = lVar27 + 0x40;
172: } while (iStack108 <= iStack112);
173: LAB_00146c9d:
174: uVar28 = SEXT48(iStack112);
175: lVar27 = uVar28 << 6;
176: do {
177: lVar22 = (long)iVar25;
178: iVar46 = (int)uVar28;
179: iVar15 = iVar25;
180: while (iStack108 = iVar21, iVar15 <= iVar24) {
181: lVar19 = *(long *)(lVar1 + lVar22 * 8) + lVar27;
182: if (iVar17 <= iVar31) {
183: sVar38 = *(short *)(lVar19 + lVar30 * 2);
184: iVar15 = iVar17;
185: psVar26 = (short *)(lVar19 + lVar30 * 2 + 2);
186: while( true ) {
187: if (sVar38 != 0) {
188: param_3[3] = iVar46;
189: iStack112 = iVar46;
190: goto LAB_00146d0f;
191: }
192: iVar15 = iVar15 + 1;
193: if (iVar31 < iVar15) break;
194: sVar38 = *psVar26;
195: psVar26 = psVar26 + 1;
196: }
197: }
198: lVar22 = lVar22 + 1;
199: iVar15 = (int)lVar22;
200: }
201: uVar28 = (ulong)(iVar46 - 1U);
202: lVar27 = lVar27 + -0x40;
203: } while (iVar21 <= (int)(iVar46 - 1U));
204: }
205: LAB_00146d0f:
206: iVar15 = iVar17;
207: if (iVar17 < iVar31) {
208: lVar27 = (long)iVar17 * 2;
209: lVar30 = (long)iStack108 * 0x40;
210: do {
211: lVar22 = (long)iVar25;
212: iVar21 = iVar25;
213: while (iVar21 <= iVar24) {
214: lVar19 = *(long *)(lVar1 + lVar22 * 8) + lVar30;
215: psVar26 = (short *)(lVar19 + lVar27);
216: if (iStack108 <= iStack112) {
217: if (*(short *)(lVar19 + (long)iVar15 * 2) != 0) {
218: LAB_00146d8c:
219: param_3[4] = iVar15;
220: iVar17 = iVar15;
221: if (iVar31 <= iVar15) goto LAB_00146e0d;
222: goto LAB_00146d99;
223: }
224: uVar28 = (long)iStack108 & 0xffffffff;
225: while( true ) {
226: uVar16 = (int)uVar28 + 1;
227: uVar28 = (ulong)uVar16;
228: psVar26 = psVar26 + 0x20;
229: if (iStack112 < (int)uVar16) break;
230: if (*psVar26 != 0) goto LAB_00146d8c;
231: }
232: }
233: lVar22 = lVar22 + 1;
234: iVar21 = (int)lVar22;
235: }
236: iVar15 = iVar15 + 1;
237: lVar27 = lVar27 + 2;
238: } while (iVar15 <= iVar31);
239: LAB_00146d99:
240: iVar15 = iVar17;
241: lVar27 = (long)iVar31 * 2;
242: iVar21 = iVar31;
243: do {
244: lVar22 = (long)iVar25;
245: iVar17 = iVar25;
246: while (iVar17 <= iVar24) {
247: lVar19 = *(long *)(lVar1 + lVar22 * 8) + lVar30;
248: psVar26 = (short *)(lVar19 + lVar27);
249: if (iStack108 <= iStack112) {
250: sVar38 = *(short *)(lVar19 + (long)iVar21 * 2);
251: iVar17 = iStack108;
252: while( true ) {
253: if (sVar38 != 0) {
254: param_3[5] = iVar21;
255: iVar31 = iVar21;
256: goto LAB_00146e0d;
257: }
258: iVar17 = iVar17 + 1;
259: psVar26 = psVar26 + 0x20;
260: if (iStack112 < iVar17) break;
261: sVar38 = *psVar26;
262: }
263: }
264: lVar22 = lVar22 + 1;
265: iVar17 = (int)lVar22;
266: }
267: iVar21 = iVar21 + -1;
268: lVar27 = lVar27 + -2;
269: } while (iVar15 <= iVar21);
270: }
271: LAB_00146e0d:
272: lVar27 = (long)((iVar24 - iVar25) * 8 *
273: *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018f080 + uVar32 * 4) * 4));
274: lVar22 = (long)((iStack112 - iStack108) * 4 *
275: *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018f020 + uVar32 * 4) * 4));
276: lVar30 = (long)((iVar31 - iVar15) * 8 *
277: *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018efc0 + uVar32 * 4) * 4));
278: *(long *)(param_3 + 6) = lVar27 * lVar27 + lVar22 * lVar22 + lVar30 * lVar30;
279: if (iVar24 < iVar25) {
280: lVar27 = 0;
281: }
282: else {
283: plStack120 = (long *)(lVar1 + lVar13 * 8);
284: lVar30 = (long)iVar15 * 2;
285: lVar27 = 0;
286: lVar22 = (long)iStack108 * 0x40;
287: do {
288: if (iStack108 <= iStack112) {
289: lVar19 = *plStack120;
290: psVar26 = (short *)(lVar30 + lVar22 + lVar19);
291: lVar23 = (long)iStack108 * 0x20 + (long)iVar15;
292: do {
293: if (iVar15 <= iVar31) {
294: uVar16 = -(int)((ulong)psVar26 >> 1) & 7;
295: uVar18 = uVar16 + 7;
296: if (uVar18 < 10) {
297: uVar18 = 10;
298: }
299: psVar29 = psVar26;
300: iVar21 = iVar15;
301: if (uVar18 <= (uint)(iVar31 - iVar15)) {
302: if (uVar16 != 0) {
303: lVar27 = (lVar27 + 1) - (ulong)(*psVar26 == 0);
304: psVar29 = psVar26 + 1;
305: iVar21 = iVar15 + 1;
306: if (uVar16 != 1) {
307: lVar27 = (lVar27 + 1) - (ulong)(psVar26[1] == 0);
308: psVar29 = psVar26 + 2;
309: iVar21 = iVar15 + 2;
310: if (uVar16 != 2) {
311: lVar27 = (lVar27 + 1) - (ulong)(psVar26[2] == 0);
312: psVar29 = psVar26 + 3;
313: iVar21 = iVar15 + 3;
314: if (uVar16 != 3) {
315: lVar27 = (lVar27 + 1) - (ulong)(psVar26[3] == 0);
316: psVar29 = psVar26 + 4;
317: iVar21 = iVar15 + 4;
318: if (uVar16 != 4) {
319: lVar27 = (lVar27 + 1) - (ulong)(psVar26[4] == 0);
320: psVar29 = psVar26 + 5;
321: iVar21 = iVar15 + 5;
322: if (uVar16 != 5) {
323: lVar27 = (lVar27 + 1) - (ulong)(psVar26[5] == 0);
324: psVar29 = psVar26 + 6;
325: iVar21 = iVar15 + 6;
326: if (uVar16 == 7) {
327: lVar27 = (lVar27 + 1) - (ulong)(psVar26[6] == 0);
328: psVar29 = psVar26 + 7;
329: iVar21 = iVar15 + 7;
330: }
331: }
332: }
333: }
334: }
335: }
336: }
337: lVar48 = 0;
338: lVar49 = 0;
339: iVar17 = ((iVar31 + 1) - iVar15) - uVar16;
340: psVar20 = (short *)(lVar19 + ((ulong)uVar16 + lVar23) * 2);
341: uVar18 = 0;
342: uVar16 = (iVar17 - 8U >> 3) + 1;
343: do {
344: sVar38 = *psVar20;
345: psVar6 = psVar20 + 1;
346: psVar7 = psVar20 + 2;
347: psVar8 = psVar20 + 3;
348: psVar9 = psVar20 + 4;
349: psVar10 = psVar20 + 5;
350: psVar11 = psVar20 + 6;
351: psVar12 = psVar20 + 7;
352: uVar18 = uVar18 + 1;
353: psVar20 = psVar20 + 8;
354: auVar37 = ~CONCAT214(-(ushort)(*psVar12 == 0),
355: CONCAT212(-(ushort)(*psVar11 == 0),
356: CONCAT210(-(ushort)(*psVar10 == 0),
357: CONCAT28(-(ushort)(*psVar9 == 0),
358: CONCAT26(-(ushort)(*psVar8 == 0),
359: CONCAT24(-(ushort)(*
360: psVar7 == 0),
361: CONCAT22(-(ushort)(*psVar6 == 0),
362: -(ushort)(sVar38 == 0)))))))) &
363: _DAT_0018f0d0;
364: uVar50 = -(ushort)(SUB162(auVar37,0) < 0);
365: sVar38 = SUB162(auVar37 >> 0x20,0);
366: sVar51 = -(ushort)(sVar38 < 0);
367: sVar39 = SUB162(auVar37 >> 0x30,0);
368: uVar2 = (ushort)(sVar39 < 0);
369: sVar40 = SUB162(auVar37 >> 0x40,0);
370: uVar3 = (ushort)(sVar40 < 0);
371: sVar41 = SUB162(auVar37 >> 0x50,0);
372: uVar4 = (ushort)(sVar41 < 0);
373: sVar42 = SUB162(auVar37 >> 0x60,0);
374: uVar5 = (ushort)(sVar42 < 0);
375: uVar47 = SUB164(CONCAT214(-uVar2,CONCAT212(sVar39,SUB1612(auVar37,0))) >> 0x60,0);
376: auVar45 = CONCAT610(SUB166(CONCAT412(uVar47,CONCAT210(sVar51,SUB1610(auVar37,0))) >>
377: 0x50,0),CONCAT28(sVar38,SUB168(auVar37,0)));
378: uVar32 = SUB168(auVar45 >> 0x40,0);
379: auVar44 = CONCAT106(SUB1610(CONCAT88(uVar32,(((ulong)CONCAT24(sVar51,CONCAT22(-(
380: ushort)(SUB162(auVar37 >> 0x10,0) < 0),uVar50)) &
381: 0xffff0000) >> 0x10) << 0x30) >> 0x30,0),
382: (SUB166(auVar37,0) >> 0x10) << 0x20);
383: uVar43 = SUB164(auVar37,0) & 0xffff | (uint)uVar50 << 0x10;
384: uVar33 = CONCAT24(sVar41,CONCAT22(-uVar3,sVar40));
385: uVar34 = CONCAT26(-uVar4,uVar33);
386: auVar36 = CONCAT210(-uVar5,CONCAT28(sVar42,uVar34));
387: iVar46 = SUB164(auVar44 >> 0x20,0);
388: uVar32 = uVar32 & 0xffffffff | (ulong)-(uint)(SUB164(auVar45 >> 0x40,0) < 0) << 0x20
389: ;
390: uVar28 = SUB168(CONCAT124(SUB1612(auVar44 >> 0x20,0),uVar43),0);
391: lVar35 = CONCAT44(-(uint)(uVar5 != 0),SUB124(auVar36 >> 0x40,0));
392: lVar48 = lVar48 + (uVar28 & 0xffffffff | (ulong)-(uint)((int)uVar43 < 0) << 0x20) +
393: uVar32 + ((ulong)uVar33 & 0xffffffff | (ulong)-(uint)(uVar3 != 0) << 0x20)
394: + lVar35;
395: lVar49 = lVar49 + SUB168(CONCAT412(-(uint)(iVar46 < 0),CONCAT48(iVar46,uVar28)) >>
396: 0x40,0) +
397: SUB168(CONCAT412(-(uint)(uVar2 != 0),CONCAT48(uVar47,uVar32)) >> 0x40,0) +
398: SUB168(CONCAT412(-(uint)(uVar4 != 0),
399: CONCAT48((int)((ulong)uVar34 >> 0x20),uVar34)) >> 0x40,0)
400: + SUB168(CONCAT412(-(uint)(auVar37 < (undefined  [16])0x0 != 0),
401: CONCAT48(SUB164(CONCAT214(-(ushort)(auVar37 <
402: (undefined  [16])0x0)
403: ,CONCAT212(SUB162(auVar37 >>
404: 0x70,0),
405: auVar36)) >> 0x60,0
406: ),lVar35)) >> 0x40,0);
407: } while (uVar18 < uVar16);
408: lVar27 = lVar27 + lVar48 + lVar49;
409: uVar16 = uVar16 * 8;
410: psVar29 = psVar29 + uVar16;
411: iVar21 = iVar21 + uVar16;
412: if (uVar16 - iVar17 == 0) goto LAB_00147210;
413: }
414: lVar27 = (lVar27 + 1) - (ulong)(*psVar29 == 0);
415: if (iVar21 + 1 <= iVar31) {
416: if (psVar29[1] != 0) {
417: lVar27 = lVar27 + 1;
418: }
419: if (iVar21 + 2 <= iVar31) {
420: if (psVar29[2] != 0) {
421: lVar27 = lVar27 + 1;
422: }
423: if (iVar21 + 3 <= iVar31) {
424: if (psVar29[3] != 0) {
425: lVar27 = lVar27 + 1;
426: }
427: if (iVar21 + 4 <= iVar31) {
428: if (psVar29[4] != 0) {
429: lVar27 = lVar27 + 1;
430: }
431: if (iVar21 + 5 <= iVar31) {
432: if (psVar29[5] != 0) {
433: lVar27 = lVar27 + 1;
434: }
435: if (iVar21 + 6 <= iVar31) {
436: if (psVar29[6] != 0) {
437: lVar27 = lVar27 + 1;
438: }
439: if (iVar21 + 7 <= iVar31) {
440: if (psVar29[7] != 0) {
441: lVar27 = lVar27 + 1;
442: }
443: if (iVar21 + 8 <= iVar31) {
444: if (psVar29[8] != 0) {
445: lVar27 = lVar27 + 1;
446: }
447: if (iVar21 + 9 <= iVar31) {
448: if (psVar29[9] != 0) {
449: lVar27 = lVar27 + 1;
450: }
451: if (iVar21 + 10 <= iVar31) {
452: if (psVar29[10] != 0) {
453: lVar27 = lVar27 + 1;
454: }
455: if (iVar21 + 0xb <= iVar31) {
456: if (psVar29[0xb] != 0) {
457: lVar27 = lVar27 + 1;
458: }
459: if (iVar21 + 0xc <= iVar31) {
460: if (psVar29[0xc] != 0) {
461: lVar27 = lVar27 + 1;
462: }
463: if ((iVar21 + 0xd <= iVar31) && (psVar29[0xd] != 0)) {
464: lVar27 = lVar27 + 1;
465: }
466: }
467: }
468: }
469: }
470: }
471: }
472: }
473: }
474: }
475: }
476: }
477: }
478: }
479: LAB_00147210:
480: psVar26 = psVar26 + 0x20;
481: lVar23 = lVar23 + 0x20;
482: } while (psVar26 !=
483: (short *)(lVar19 + lVar22 + 0x40 + (ulong)(uint)(iStack112 - iStack108) * 0x40 +
484: lVar30));
485: }
486: plStack120 = plStack120 + 1;
487: } while (plStack120 != (long *)(lVar1 + 8 + (lVar13 + (ulong)(uint)(iVar24 - iVar25)) * 8));
488: }
489: *(long *)(param_3 + 8) = lVar27;
490: return;
491: }
492: 
