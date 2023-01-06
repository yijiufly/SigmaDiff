1: 
2: /* WARNING: Type propagation algorithm not settling */
3: 
4: void FUN_00121000(long param_1,long *param_2,uint param_3,undefined8 *param_4,int param_5)
5: 
6: {
7: undefined *puVar1;
8: undefined auVar2 [16];
9: uint uVar3;
10: int iVar4;
11: int iVar5;
12: int iVar6;
13: int iVar7;
14: undefined *puVar8;
15: undefined *puVar9;
16: undefined8 *puVar10;
17: long lVar11;
18: int iVar12;
19: long lVar13;
20: ulong uVar14;
21: uint uVar15;
22: uint uVar16;
23: undefined uVar19;
24: undefined uVar20;
25: uint3 uVar17;
26: undefined uVar21;
27: undefined uVar22;
28: undefined uVar23;
29: undefined uVar24;
30: undefined uVar25;
31: undefined uVar26;
32: undefined uVar27;
33: undefined uVar28;
34: undefined uVar29;
35: undefined uVar30;
36: undefined uVar31;
37: undefined uVar32;
38: undefined uVar33;
39: undefined uVar34;
40: undefined uVar35;
41: undefined uVar36;
42: undefined uVar37;
43: uint3 uVar38;
44: undefined uVar47;
45: undefined uVar48;
46: undefined uVar49;
47: undefined uVar50;
48: undefined auVar51 [16];
49: undefined in_XMM4_Ba;
50: undefined in_XMM4_Bb;
51: undefined in_XMM4_Bc;
52: undefined in_XMM4_Bd;
53: undefined in_XMM4_Be;
54: undefined in_XMM4_Bf;
55: undefined uVar52;
56: undefined in_XMM4_Bg;
57: undefined in_XMM4_Bh;
58: undefined in_XMM4_Bi;
59: undefined in_XMM4_Bj;
60: undefined in_XMM4_Bk;
61: undefined in_XMM4_Bl;
62: undefined in_XMM4_Bm;
63: undefined in_XMM4_Bn;
64: undefined in_XMM4_Bo;
65: undefined in_XMM4_Bp;
66: uint5 uVar18;
67: uint5 uVar39;
68: uint7 uVar40;
69: undefined8 uVar41;
70: unkbyte9 Var42;
71: unkbyte10 Var43;
72: undefined auVar44 [11];
73: undefined auVar45 [12];
74: undefined auVar46 [13];
75: 
76: switch(*(undefined4 *)(param_1 + 0x40)) {
77: case 6:
78: uVar3 = *(uint *)(param_1 + 0x88);
79: while (param_5 = param_5 + -1, -1 < param_5) {
80: uVar15 = param_3 + 1;
81: puVar10 = param_4 + 1;
82: lVar13 = *(long *)(*param_2 + (ulong)param_3 * 8);
83: lVar11 = 0;
84: puVar9 = (undefined *)*param_4;
85: param_4 = puVar10;
86: param_3 = uVar15;
87: if (uVar3 != 0) {
88: do {
89: uVar52 = *(undefined *)(lVar13 + lVar11);
90: lVar11 = lVar11 + 1;
91: puVar9[2] = uVar52;
92: puVar9[1] = uVar52;
93: *puVar9 = uVar52;
94: puVar9 = puVar9 + 3;
95: } while ((uint)lVar11 < uVar3);
96: }
97: }
98: break;
99: case 7:
100: case 0xc:
101: uVar3 = *(uint *)(param_1 + 0x88);
102: iVar4 = -(uint)(CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ==
103: CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))));
104: iVar5 = -(uint)(CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ==
105: CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))));
106: iVar6 = -(uint)(CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ==
107: CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))));
108: uVar52 = (undefined)((uint)iVar6 >> 0x10);
109: iVar7 = -(uint)(CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ==
110: CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))));
111: uVar15 = uVar3 & 0xfffffff0;
112: code_r0x001214d0:
113: while( true ) {
114: do {
115: param_5 = param_5 + -1;
116: if (param_5 < 0) {
117: return;
118: }
119: puVar10 = param_4 + 1;
120: uVar16 = param_3 + 1;
121: puVar9 = *(undefined **)(*param_2 + (ulong)param_3 * 8);
122: puVar8 = (undefined *)*param_4;
123: param_4 = puVar10;
124: param_3 = uVar16;
125: } while (uVar3 == 0);
126: if ((puVar9 + uVar3 <= puVar8 || puVar8 + (ulong)uVar3 * 4 <= puVar9) && (0xf < uVar3)) break;
127: lVar13 = 0;
128: do {
129: uVar20 = puVar9[lVar13];
130: lVar13 = lVar13 + 1;
131: puVar8[3] = 0xff;
132: puVar8[2] = uVar20;
133: puVar8[1] = uVar20;
134: *puVar8 = uVar20;
135: puVar8 = puVar8 + 4;
136: } while ((uint)lVar13 < uVar3);
137: }
138: if (uVar3 >> 4 != 0) goto code_r0x00121528;
139: uVar20 = *puVar9;
140: puVar8[3] = 0xff;
141: puVar8[2] = uVar20;
142: puVar8[1] = uVar20;
143: *puVar8 = uVar20;
144: uVar14 = 1;
145: goto code_r0x00121bd6;
146: case 8:
147: uVar3 = *(uint *)(param_1 + 0x88);
148: while (param_5 = param_5 + -1, -1 < param_5) {
149: uVar15 = param_3 + 1;
150: puVar10 = param_4 + 1;
151: lVar13 = *(long *)(*param_2 + (ulong)param_3 * 8);
152: lVar11 = 0;
153: puVar9 = (undefined *)*param_4;
154: param_4 = puVar10;
155: param_3 = uVar15;
156: if (uVar3 != 0) {
157: do {
158: uVar52 = *(undefined *)(lVar13 + lVar11);
159: lVar11 = lVar11 + 1;
160: *puVar9 = uVar52;
161: puVar9[1] = uVar52;
162: puVar9[2] = uVar52;
163: puVar9 = puVar9 + 3;
164: } while ((uint)lVar11 < uVar3);
165: }
166: }
167: break;
168: case 9:
169: case 0xd:
170: uVar3 = *(uint *)(param_1 + 0x88);
171: iVar4 = -(uint)(CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ==
172: CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))));
173: iVar5 = -(uint)(CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ==
174: CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))));
175: iVar6 = -(uint)(CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ==
176: CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))));
177: uVar52 = (undefined)((uint)iVar6 >> 0x10);
178: iVar7 = -(uint)(CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ==
179: CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))));
180: uVar15 = uVar3 & 0xfffffff0;
181: code_r0x001213a0:
182: while( true ) {
183: do {
184: param_5 = param_5 + -1;
185: if (param_5 < 0) {
186: return;
187: }
188: puVar10 = param_4 + 1;
189: uVar16 = param_3 + 1;
190: puVar9 = *(undefined **)(*param_2 + (ulong)param_3 * 8);
191: puVar8 = (undefined *)*param_4;
192: param_4 = puVar10;
193: param_3 = uVar16;
194: } while (uVar3 == 0);
195: if ((puVar9 + uVar3 <= puVar8 || puVar8 + (ulong)uVar3 * 4 <= puVar9) && (0xf < uVar3)) break;
196: lVar13 = 0;
197: do {
198: uVar20 = puVar9[lVar13];
199: lVar13 = lVar13 + 1;
200: puVar8[3] = 0xff;
201: *puVar8 = uVar20;
202: puVar8[1] = uVar20;
203: puVar8[2] = uVar20;
204: puVar8 = puVar8 + 4;
205: } while ((uint)lVar13 < uVar3);
206: }
207: if (uVar3 >> 4 != 0) goto code_r0x001213f8;
208: uVar20 = *puVar9;
209: puVar8[3] = 0xff;
210: *puVar8 = uVar20;
211: puVar8[1] = uVar20;
212: puVar8[2] = uVar20;
213: uVar14 = 1;
214: goto code_r0x001219de;
215: case 10:
216: case 0xe:
217: uVar3 = *(uint *)(param_1 + 0x88);
218: iVar4 = -(uint)(CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ==
219: CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))));
220: iVar5 = -(uint)(CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ==
221: CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))));
222: uVar52 = (undefined)((uint)iVar5 >> 8);
223: uVar20 = (undefined)((uint)iVar5 >> 0x10);
224: uVar22 = (undefined)((uint)iVar5 >> 0x18);
225: iVar6 = -(uint)(CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ==
226: CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))));
227: iVar7 = -(uint)(CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ==
228: CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))));
229: uVar24 = (undefined)((uint)iVar7 >> 8);
230: uVar26 = (undefined)((uint)iVar7 >> 0x10);
231: uVar15 = uVar3 & 0xfffffff0;
232: param_5 = param_5 + -1;
233: while (-1 < param_5) {
234: puVar9 = *(undefined **)(*param_2 + (ulong)param_3 * 8);
235: puVar8 = (undefined *)*param_4;
236: if (uVar3 != 0) {
237: if ((puVar8 < puVar9 + uVar3 && puVar9 < puVar8 + (ulong)uVar3 * 4) || (uVar3 < 0x10)) {
238: lVar13 = 0;
239: do {
240: uVar19 = puVar9[lVar13];
241: lVar13 = lVar13 + 1;
242: *puVar8 = 0xff;
243: puVar8[1] = uVar19;
244: puVar8[2] = uVar19;
245: puVar8[3] = uVar19;
246: puVar8 = puVar8 + 4;
247: } while ((uint)lVar13 < uVar3);
248: }
249: else {
250: if (uVar3 >> 4 == 0) {
251: uVar19 = *puVar9;
252: *puVar8 = 0xff;
253: puVar8[1] = uVar19;
254: puVar8[2] = uVar19;
255: puVar8[3] = uVar19;
256: uVar14 = 1;
257: code_r0x001215ee:
258: iVar12 = (int)uVar14;
259: uVar19 = puVar9[uVar14];
260: puVar8[4] = 0xff;
261: puVar8[5] = uVar19;
262: puVar8[6] = uVar19;
263: puVar8[7] = uVar19;
264: if (iVar12 + 1U < uVar3) {
265: uVar19 = puVar9[iVar12 + 1U];
266: puVar8[8] = 0xff;
267: puVar8[9] = uVar19;
268: puVar8[10] = uVar19;
269: puVar8[0xb] = uVar19;
270: if (iVar12 + 2U < uVar3) {
271: uVar19 = puVar9[iVar12 + 2U];
272: puVar8[0xc] = 0xff;
273: puVar8[0xd] = uVar19;
274: puVar8[0xe] = uVar19;
275: puVar8[0xf] = uVar19;
276: if (iVar12 + 3U < uVar3) {
277: uVar19 = puVar9[iVar12 + 3U];
278: puVar8[0x10] = 0xff;
279: puVar8[0x11] = uVar19;
280: puVar8[0x12] = uVar19;
281: puVar8[0x13] = uVar19;
282: if (iVar12 + 4U < uVar3) {
283: uVar19 = puVar9[iVar12 + 4U];
284: puVar8[0x14] = 0xff;
285: puVar8[0x15] = uVar19;
286: puVar8[0x16] = uVar19;
287: puVar8[0x17] = uVar19;
288: if (iVar12 + 5U < uVar3) {
289: uVar19 = puVar9[iVar12 + 5U];
290: puVar8[0x18] = 0xff;
291: puVar8[0x19] = uVar19;
292: puVar8[0x1a] = uVar19;
293: puVar8[0x1b] = uVar19;
294: if (iVar12 + 6U < uVar3) {
295: uVar19 = puVar9[iVar12 + 6U];
296: puVar8[0x1c] = 0xff;
297: puVar8[0x1d] = uVar19;
298: puVar8[0x1e] = uVar19;
299: puVar8[0x1f] = uVar19;
300: if (iVar12 + 7U < uVar3) {
301: uVar19 = puVar9[iVar12 + 7U];
302: puVar8[0x20] = 0xff;
303: puVar8[0x21] = uVar19;
304: puVar8[0x22] = uVar19;
305: puVar8[0x23] = uVar19;
306: if (iVar12 + 8U < uVar3) {
307: uVar19 = puVar9[iVar12 + 8U];
308: puVar8[0x24] = 0xff;
309: puVar8[0x25] = uVar19;
310: puVar8[0x26] = uVar19;
311: puVar8[0x27] = uVar19;
312: if (iVar12 + 9U < uVar3) {
313: uVar19 = puVar9[iVar12 + 9U];
314: puVar8[0x28] = 0xff;
315: puVar8[0x29] = uVar19;
316: puVar8[0x2a] = uVar19;
317: puVar8[0x2b] = uVar19;
318: if (iVar12 + 10U < uVar3) {
319: uVar19 = puVar9[iVar12 + 10U];
320: puVar8[0x2c] = 0xff;
321: puVar8[0x2d] = uVar19;
322: puVar8[0x2e] = uVar19;
323: puVar8[0x2f] = uVar19;
324: if (iVar12 + 0xbU < uVar3) {
325: uVar19 = puVar9[iVar12 + 0xbU];
326: puVar8[0x30] = 0xff;
327: puVar8[0x31] = uVar19;
328: puVar8[0x32] = uVar19;
329: puVar8[0x33] = uVar19;
330: if (iVar12 + 0xcU < uVar3) {
331: uVar19 = puVar9[iVar12 + 0xcU];
332: puVar8[0x34] = 0xff;
333: puVar8[0x35] = uVar19;
334: puVar8[0x36] = uVar19;
335: puVar8[0x37] = uVar19;
336: if (iVar12 + 0xdU < uVar3) {
337: uVar19 = puVar9[iVar12 + 0xdU];
338: puVar8[0x38] = 0xff;
339: puVar8[0x39] = uVar19;
340: puVar8[0x3a] = uVar19;
341: puVar8[0x3b] = uVar19;
342: }
343: }
344: }
345: }
346: }
347: }
348: }
349: }
350: }
351: }
352: }
353: }
354: }
355: }
356: else {
357: lVar13 = 0;
358: uVar16 = 0;
359: do {
360: auVar2 = *(undefined (*) [16])(puVar9 + lVar13);
361: uVar18 = CONCAT14((char)((uint)iVar6 >> 0x18),
362: CONCAT13((char)((uint)iVar6 >> 0x10),
363: CONCAT12((char)((uint)iVar6 >> 8),
364: CONCAT11((char)iVar6,uVar22))));
365: auVar46 = ZEXT613(CONCAT15((char)iVar7,uVar18)) << 0x38;
366: uVar16 = uVar16 + 1;
367: uVar29 = SUB161(auVar2 >> 0x38,0);
368: uVar28 = SUB161(auVar2 >> 0x30,0);
369: uVar27 = SUB161(auVar2 >> 0x28,0);
370: uVar25 = SUB161(auVar2 >> 0x20,0);
371: uVar23 = SUB161(auVar2 >> 0x18,0);
372: uVar21 = SUB161(auVar2 >> 0x10,0);
373: uVar19 = SUB161(auVar2 >> 8,0);
374: auVar51 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(
375: SUB1610((ZEXT916(CONCAT81((long)(CONCAT72(CONCAT61
376: (CONCAT51(CONCAT41(CONCAT31(CONCAT21(CONCAT11(
377: uVar29,uVar22),uVar28),uVar20),uVar27),uVar52),
378: uVar25),CONCAT11((char)iVar5,uVar22)) >> 8),uVar23
379: )) << 0x38) >> 0x30,0),uVar21)) << 0x28) >> 0x20,0
380: ),uVar19),((uint3)iVar4 >> 8) << 0x10) >> 0x10,0),
381: SUB161(auVar2,0))) << 8;
382: uVar47 = SUB121((ZEXT512(uVar18) << 0x38) >> 0x40,0);
383: uVar30 = SUB161(auVar2 >> 0x40,0);
384: uVar38 = CONCAT12(SUB131(auVar46 >> 0x48,0),CONCAT11(uVar30,uVar47));
385: uVar31 = SUB161(auVar2 >> 0x48,0);
386: uVar48 = SUB131(auVar46 >> 0x50,0);
387: uVar39 = CONCAT14(uVar48,CONCAT13(uVar31,uVar38));
388: uVar32 = SUB161(auVar2 >> 0x50,0);
389: uVar49 = SUB131(auVar46 >> 0x58,0);
390: uVar40 = CONCAT16(uVar49,CONCAT15(uVar32,uVar39));
391: uVar33 = SUB161(auVar2 >> 0x58,0);
392: uVar41 = CONCAT17(uVar33,uVar40);
393: uVar50 = SUB131(auVar46 >> 0x60,0);
394: Var42 = CONCAT18(uVar50,uVar41);
395: uVar34 = SUB161(auVar2 >> 0x60,0);
396: Var43 = CONCAT19(uVar34,Var42);
397: auVar44 = CONCAT110(uVar24,Var43);
398: uVar35 = SUB161(auVar2 >> 0x68,0);
399: auVar45 = CONCAT111(uVar35,auVar44);
400: auVar46 = CONCAT112(uVar26,auVar45);
401: uVar36 = SUB161(auVar2 >> 0x70,0);
402: uVar37 = SUB161(auVar2 >> 0x78,0);
403: uVar17 = CONCAT12(uVar31,CONCAT11(uVar30,uVar30));
404: uVar18 = CONCAT14(uVar32,CONCAT13(uVar31,uVar17));
405: *(undefined (*) [16])(puVar8 + lVar13 * 4) =
406: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(
407: CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610
408: (SUB166(CONCAT511(SUB165(CONCAT412(SUB164(
409: CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(uVar23
410: ,CONCAT114(uVar23,SUB1614(auVar51,0))) >> 0x70,0),
411: CONCAT113(uVar23,SUB1613(auVar51,0))) >> 0x68,0),
412: CONCAT112((char)((uint)iVar4 >> 0x18),
413: SUB1612(auVar51,0))) >> 0x60,0),
414: CONCAT111(uVar21,SUB1611(auVar51,0))) >> 0x58,0),
415: CONCAT110(uVar21,SUB1610(auVar51,0))) >> 0x50,0),
416: CONCAT19(uVar21,SUB169(auVar51,0))) >> 0x48,0),
417: CONCAT18((char)((uint)iVar4 >> 0x10),
418: SUB168(auVar51,0))) >> 0x40,0),uVar19),
419: (SUB167(auVar51,0) >> 0x18) << 0x30) >> 0x30,0),
420: uVar19),(SUB165(auVar51,0) >> 0x10) << 0x20) >>
421: 0x20,0),SUB161(auVar2,0)),
422: (SUB163(auVar51,0) >> 8) << 0x10) >> 0x10,0),
423: (ushort)iVar4 & 0xff | SUB162(auVar2,0) << 8);
424: puVar1 = puVar8 + lVar13 * 4 + 0x10;
425: *puVar1 = (char)iVar5;
426: puVar1[1] = uVar25;
427: puVar1[2] = uVar25;
428: puVar1[3] = uVar25;
429: puVar1[4] = uVar52;
430: puVar1[5] = uVar27;
431: puVar1[6] = uVar27;
432: puVar1[7] = uVar27;
433: puVar1[8] = uVar20;
434: puVar1[9] = uVar28;
435: puVar1[10] = uVar28;
436: puVar1[0xb] = uVar28;
437: puVar1[0xc] = uVar22;
438: puVar1[0xd] = uVar29;
439: puVar1[0xe] = uVar29;
440: puVar1[0xf] = uVar29;
441: *(undefined (*) [16])(puVar8 + lVar13 * 4 + 0x20) =
442: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106
443: (SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
444: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
445: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
446: CONCAT115(uVar33,CONCAT114(uVar33,CONCAT113(uVar36
447: ,auVar46))) >> 0x70,0),CONCAT113(uVar33,auVar46))
448: >> 0x68,0),CONCAT112(uVar49,auVar45)) >> 0x60,0),
449: CONCAT111(uVar32,auVar44)) >> 0x58,0),
450: CONCAT110(uVar32,Var43)) >> 0x50,0),
451: CONCAT19(uVar32,Var42)) >> 0x48,0),
452: CONCAT18(uVar48,uVar41)) >> 0x40,0),
453: (((ulong)CONCAT16(uVar33,CONCAT15(uVar32,uVar18))
454: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
455: (uVar40 >> 0x18) << 0x30) >> 0x30,0),
456: (((uint6)uVar18 & 0xff0000) >> 0x10) << 0x28) >>
457: 0x28,0),(uVar39 >> 0x10) << 0x20) >> 0x20,0),
458: ((uVar17 & 0xff00) >> 8) << 0x18) >> 0x18,0),
459: (uVar38 >> 8) << 0x10) >> 0x10,0),
460: CONCAT11(uVar30,uVar47));
461: puVar1 = puVar8 + lVar13 * 4 + 0x30;
462: *puVar1 = uVar50;
463: puVar1[1] = uVar34;
464: puVar1[2] = uVar34;
465: puVar1[3] = uVar34;
466: puVar1[4] = uVar24;
467: puVar1[5] = uVar35;
468: puVar1[6] = uVar35;
469: puVar1[7] = uVar35;
470: puVar1[8] = uVar26;
471: puVar1[9] = uVar36;
472: puVar1[10] = uVar36;
473: puVar1[0xb] = uVar36;
474: puVar1[0xc] = (char)((uint)iVar7 >> 0x18);
475: puVar1[0xd] = uVar37;
476: puVar1[0xe] = uVar37;
477: puVar1[0xf] = uVar37;
478: lVar13 = lVar13 + 0x10;
479: } while (uVar16 < uVar3 >> 4);
480: puVar8 = puVar8 + (ulong)uVar15 * 4;
481: if (uVar3 != uVar15) {
482: uVar19 = puVar9[uVar15];
483: *puVar8 = 0xff;
484: puVar8[1] = uVar19;
485: puVar8[2] = uVar19;
486: puVar8[3] = uVar19;
487: uVar14 = (ulong)(uVar15 + 1);
488: if (uVar15 + 1 < uVar3) goto code_r0x001215ee;
489: }
490: }
491: }
492: }
493: param_5 = param_5 + -1;
494: param_4 = param_4 + 1;
495: param_3 = param_3 + 1;
496: }
497: break;
498: case 0xb:
499: case 0xf:
500: uVar3 = *(uint *)(param_1 + 0x88);
501: iVar4 = -(uint)(CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ==
502: CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))));
503: iVar5 = -(uint)(CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ==
504: CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))));
505: uVar52 = (undefined)((uint)iVar5 >> 8);
506: uVar20 = (undefined)((uint)iVar5 >> 0x10);
507: uVar22 = (undefined)((uint)iVar5 >> 0x18);
508: iVar6 = -(uint)(CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ==
509: CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))));
510: iVar7 = -(uint)(CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ==
511: CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))));
512: uVar24 = (undefined)((uint)iVar7 >> 8);
513: uVar26 = (undefined)((uint)iVar7 >> 0x10);
514: uVar15 = uVar3 & 0xfffffff0;
515: code_r0x001211b0:
516: while( true ) {
517: do {
518: param_5 = param_5 + -1;
519: if (param_5 < 0) {
520: return;
521: }
522: puVar10 = param_4 + 1;
523: uVar16 = param_3 + 1;
524: puVar9 = *(undefined **)(*param_2 + (ulong)param_3 * 8);
525: puVar8 = (undefined *)*param_4;
526: param_4 = puVar10;
527: param_3 = uVar16;
528: } while (uVar3 == 0);
529: if ((puVar9 + uVar3 <= puVar8 || puVar8 + (ulong)uVar3 * 4 <= puVar9) && (0xf < uVar3)) break;
530: lVar13 = 0;
531: do {
532: uVar19 = puVar9[lVar13];
533: lVar13 = lVar13 + 1;
534: *puVar8 = 0xff;
535: puVar8[3] = uVar19;
536: puVar8[2] = uVar19;
537: puVar8[1] = uVar19;
538: puVar8 = puVar8 + 4;
539: } while ((uint)lVar13 < uVar3);
540: }
541: if (uVar3 >> 4 != 0) goto code_r0x00121204;
542: uVar19 = *puVar9;
543: *puVar8 = 0xff;
544: puVar8[3] = uVar19;
545: puVar8[2] = uVar19;
546: puVar8[1] = uVar19;
547: uVar14 = 1;
548: goto code_r0x001217e6;
549: default:
550: uVar3 = *(uint *)(param_1 + 0x88);
551: while (param_5 = param_5 + -1, -1 < param_5) {
552: uVar15 = param_3 + 1;
553: puVar10 = param_4 + 1;
554: lVar13 = *(long *)(*param_2 + (ulong)param_3 * 8);
555: lVar11 = 0;
556: puVar9 = (undefined *)*param_4;
557: param_4 = puVar10;
558: param_3 = uVar15;
559: if (uVar3 != 0) {
560: do {
561: uVar52 = *(undefined *)(lVar13 + lVar11);
562: lVar11 = lVar11 + 1;
563: puVar9[2] = uVar52;
564: puVar9[1] = uVar52;
565: *puVar9 = uVar52;
566: puVar9 = puVar9 + 3;
567: } while ((uint)lVar11 < uVar3);
568: }
569: }
570: }
571: return;
572: code_r0x00121204:
573: lVar13 = 0;
574: uVar16 = 0;
575: do {
576: auVar2 = *(undefined (*) [16])(puVar9 + lVar13);
577: uVar18 = CONCAT14((char)((uint)iVar6 >> 0x18),
578: CONCAT13((char)((uint)iVar6 >> 0x10),
579: CONCAT12((char)((uint)iVar6 >> 8),CONCAT11((char)iVar6,uVar22))));
580: auVar46 = ZEXT613(CONCAT15((char)iVar7,uVar18)) << 0x38;
581: uVar16 = uVar16 + 1;
582: uVar29 = SUB161(auVar2 >> 0x38,0);
583: uVar28 = SUB161(auVar2 >> 0x30,0);
584: uVar27 = SUB161(auVar2 >> 0x28,0);
585: uVar25 = SUB161(auVar2 >> 0x20,0);
586: uVar23 = SUB161(auVar2 >> 0x18,0);
587: uVar21 = SUB161(auVar2 >> 0x10,0);
588: uVar19 = SUB161(auVar2 >> 8,0);
589: auVar51 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
590: ZEXT916(CONCAT81((long)(CONCAT72(CONCAT61(CONCAT51
591: (CONCAT41(CONCAT31(CONCAT21(CONCAT11(uVar29,uVar22
592: ),uVar28),
593: uVar20),uVar27),uVar52),uVar25)
594: ,CONCAT11((char)iVar5,uVar22)) >> 8),uVar23)) <<
595: 0x38) >> 0x30,0),uVar21)) << 0x28) >> 0x20,0),
596: uVar19),((uint3)iVar4 >> 8) << 0x10) >> 0x10,0),
597: SUB161(auVar2,0))) << 8;
598: uVar47 = SUB121((ZEXT512(uVar18) << 0x38) >> 0x40,0);
599: uVar30 = SUB161(auVar2 >> 0x40,0);
600: uVar38 = CONCAT12(SUB131(auVar46 >> 0x48,0),CONCAT11(uVar30,uVar47));
601: uVar31 = SUB161(auVar2 >> 0x48,0);
602: uVar48 = SUB131(auVar46 >> 0x50,0);
603: uVar39 = CONCAT14(uVar48,CONCAT13(uVar31,uVar38));
604: uVar32 = SUB161(auVar2 >> 0x50,0);
605: uVar49 = SUB131(auVar46 >> 0x58,0);
606: uVar40 = CONCAT16(uVar49,CONCAT15(uVar32,uVar39));
607: uVar33 = SUB161(auVar2 >> 0x58,0);
608: uVar41 = CONCAT17(uVar33,uVar40);
609: uVar50 = SUB131(auVar46 >> 0x60,0);
610: Var42 = CONCAT18(uVar50,uVar41);
611: uVar34 = SUB161(auVar2 >> 0x60,0);
612: Var43 = CONCAT19(uVar34,Var42);
613: auVar44 = CONCAT110(uVar24,Var43);
614: uVar35 = SUB161(auVar2 >> 0x68,0);
615: auVar45 = CONCAT111(uVar35,auVar44);
616: auVar46 = CONCAT112(uVar26,auVar45);
617: uVar36 = SUB161(auVar2 >> 0x70,0);
618: uVar37 = SUB161(auVar2 >> 0x78,0);
619: uVar17 = CONCAT12(uVar31,CONCAT11(uVar30,uVar30));
620: uVar18 = CONCAT14(uVar32,CONCAT13(uVar31,uVar17));
621: *(undefined (*) [16])(puVar8 + lVar13 * 4) =
622: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81
623: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
624: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
625: CONCAT214(SUB162(CONCAT115(uVar23,CONCAT114(uVar23
626: ,SUB1614(auVar51,0))) >> 0x70,0),
627: CONCAT113(uVar23,SUB1613(auVar51,0))) >> 0x68,0),
628: CONCAT112((char)((uint)iVar4 >> 0x18),
629: SUB1612(auVar51,0))) >> 0x60,0),
630: CONCAT111(uVar21,SUB1611(auVar51,0))) >> 0x58,0),
631: CONCAT110(uVar21,SUB1610(auVar51,0))) >> 0x50,0),
632: CONCAT19(uVar21,SUB169(auVar51,0))) >> 0x48,0),
633: CONCAT18((char)((uint)iVar4 >> 0x10),
634: SUB168(auVar51,0))) >> 0x40,0),uVar19),
635: (SUB167(auVar51,0) >> 0x18) << 0x30) >> 0x30,0),
636: uVar19),(SUB165(auVar51,0) >> 0x10) << 0x20) >>
637: 0x20,0),SUB161(auVar2,0)),
638: (SUB163(auVar51,0) >> 8) << 0x10) >> 0x10,0),
639: (ushort)iVar4 & 0xff | SUB162(auVar2,0) << 8);
640: puVar1 = puVar8 + lVar13 * 4 + 0x10;
641: *puVar1 = (char)iVar5;
642: puVar1[1] = uVar25;
643: puVar1[2] = uVar25;
644: puVar1[3] = uVar25;
645: puVar1[4] = uVar52;
646: puVar1[5] = uVar27;
647: puVar1[6] = uVar27;
648: puVar1[7] = uVar27;
649: puVar1[8] = uVar20;
650: puVar1[9] = uVar28;
651: puVar1[10] = uVar28;
652: puVar1[0xb] = uVar28;
653: puVar1[0xc] = uVar22;
654: puVar1[0xd] = uVar29;
655: puVar1[0xe] = uVar29;
656: puVar1[0xf] = uVar29;
657: *(undefined (*) [16])(puVar8 + lVar13 * 4 + 0x20) =
658: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
659: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
660: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
661: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
662: uVar33,CONCAT114(uVar33,CONCAT113(uVar36,auVar46))
663: ) >> 0x70,0),CONCAT113(uVar33,auVar46)) >> 0x68,0)
664: ,CONCAT112(uVar49,auVar45)) >> 0x60,0),
665: CONCAT111(uVar32,auVar44)) >> 0x58,0),
666: CONCAT110(uVar32,Var43)) >> 0x50,0),
667: CONCAT19(uVar32,Var42)) >> 0x48,0),
668: CONCAT18(uVar48,uVar41)) >> 0x40,0),
669: (((ulong)CONCAT16(uVar33,CONCAT15(uVar32,uVar18))
670: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
671: (uVar40 >> 0x18) << 0x30) >> 0x30,0),
672: (((uint6)uVar18 & 0xff0000) >> 0x10) << 0x28) >>
673: 0x28,0),(uVar39 >> 0x10) << 0x20) >> 0x20,0),
674: ((uVar17 & 0xff00) >> 8) << 0x18) >> 0x18,0),
675: (uVar38 >> 8) << 0x10) >> 0x10,0),CONCAT11(uVar30,uVar47));
676: puVar1 = puVar8 + lVar13 * 4 + 0x30;
677: *puVar1 = uVar50;
678: puVar1[1] = uVar34;
679: puVar1[2] = uVar34;
680: puVar1[3] = uVar34;
681: puVar1[4] = uVar24;
682: puVar1[5] = uVar35;
683: puVar1[6] = uVar35;
684: puVar1[7] = uVar35;
685: puVar1[8] = uVar26;
686: puVar1[9] = uVar36;
687: puVar1[10] = uVar36;
688: puVar1[0xb] = uVar36;
689: puVar1[0xc] = (char)((uint)iVar7 >> 0x18);
690: puVar1[0xd] = uVar37;
691: puVar1[0xe] = uVar37;
692: puVar1[0xf] = uVar37;
693: lVar13 = lVar13 + 0x10;
694: } while (uVar16 < uVar3 >> 4);
695: puVar8 = puVar8 + (ulong)uVar15 * 4;
696: if (uVar3 != uVar15) {
697: uVar19 = puVar9[uVar15];
698: *puVar8 = 0xff;
699: puVar8[3] = uVar19;
700: puVar8[2] = uVar19;
701: puVar8[1] = uVar19;
702: uVar14 = (ulong)(uVar15 + 1);
703: if (uVar15 + 1 < uVar3) {
704: code_r0x001217e6:
705: iVar12 = (int)uVar14;
706: uVar19 = puVar9[uVar14];
707: puVar8[4] = 0xff;
708: puVar8[7] = uVar19;
709: puVar8[6] = uVar19;
710: puVar8[5] = uVar19;
711: if (iVar12 + 1U < uVar3) {
712: uVar19 = puVar9[iVar12 + 1U];
713: puVar8[8] = 0xff;
714: puVar8[0xb] = uVar19;
715: puVar8[10] = uVar19;
716: puVar8[9] = uVar19;
717: if (iVar12 + 2U < uVar3) {
718: uVar19 = puVar9[iVar12 + 2U];
719: puVar8[0xc] = 0xff;
720: puVar8[0xf] = uVar19;
721: puVar8[0xe] = uVar19;
722: puVar8[0xd] = uVar19;
723: if (iVar12 + 3U < uVar3) {
724: uVar19 = puVar9[iVar12 + 3U];
725: puVar8[0x10] = 0xff;
726: puVar8[0x13] = uVar19;
727: puVar8[0x12] = uVar19;
728: puVar8[0x11] = uVar19;
729: if (iVar12 + 4U < uVar3) {
730: uVar19 = puVar9[iVar12 + 4U];
731: puVar8[0x14] = 0xff;
732: puVar8[0x17] = uVar19;
733: puVar8[0x16] = uVar19;
734: puVar8[0x15] = uVar19;
735: if (iVar12 + 5U < uVar3) {
736: uVar19 = puVar9[iVar12 + 5U];
737: puVar8[0x18] = 0xff;
738: puVar8[0x1b] = uVar19;
739: puVar8[0x1a] = uVar19;
740: puVar8[0x19] = uVar19;
741: if (iVar12 + 6U < uVar3) {
742: uVar19 = puVar9[iVar12 + 6U];
743: puVar8[0x1c] = 0xff;
744: puVar8[0x1f] = uVar19;
745: puVar8[0x1e] = uVar19;
746: puVar8[0x1d] = uVar19;
747: if (iVar12 + 7U < uVar3) {
748: uVar19 = puVar9[iVar12 + 7U];
749: puVar8[0x20] = 0xff;
750: puVar8[0x23] = uVar19;
751: puVar8[0x22] = uVar19;
752: puVar8[0x21] = uVar19;
753: if (iVar12 + 8U < uVar3) {
754: uVar19 = puVar9[iVar12 + 8U];
755: puVar8[0x24] = 0xff;
756: puVar8[0x27] = uVar19;
757: puVar8[0x26] = uVar19;
758: puVar8[0x25] = uVar19;
759: if (iVar12 + 9U < uVar3) {
760: uVar19 = puVar9[iVar12 + 9U];
761: puVar8[0x28] = 0xff;
762: puVar8[0x2b] = uVar19;
763: puVar8[0x2a] = uVar19;
764: puVar8[0x29] = uVar19;
765: if (iVar12 + 10U < uVar3) {
766: uVar19 = puVar9[iVar12 + 10U];
767: puVar8[0x2c] = 0xff;
768: puVar8[0x2f] = uVar19;
769: puVar8[0x2e] = uVar19;
770: puVar8[0x2d] = uVar19;
771: if (iVar12 + 0xbU < uVar3) {
772: uVar19 = puVar9[iVar12 + 0xbU];
773: puVar8[0x30] = 0xff;
774: puVar8[0x33] = uVar19;
775: puVar8[0x32] = uVar19;
776: puVar8[0x31] = uVar19;
777: if (iVar12 + 0xcU < uVar3) {
778: uVar19 = puVar9[iVar12 + 0xcU];
779: puVar8[0x34] = 0xff;
780: puVar8[0x37] = uVar19;
781: puVar8[0x36] = uVar19;
782: puVar8[0x35] = uVar19;
783: if (iVar12 + 0xdU < uVar3) {
784: uVar19 = puVar9[iVar12 + 0xdU];
785: puVar8[0x38] = 0xff;
786: puVar8[0x3b] = uVar19;
787: puVar8[0x3a] = uVar19;
788: puVar8[0x39] = uVar19;
789: }
790: }
791: }
792: }
793: }
794: }
795: }
796: }
797: }
798: }
799: }
800: }
801: }
802: }
803: }
804: goto code_r0x001211b0;
805: code_r0x001213f8:
806: lVar13 = 0;
807: uVar16 = 0;
808: do {
809: auVar2 = *(undefined (*) [16])(puVar9 + lVar13);
810: uVar16 = uVar16 + 1;
811: uVar23 = SUB161(auVar2 >> 0x38,0);
812: uVar21 = SUB161(auVar2 >> 0x30,0);
813: uVar19 = SUB161(auVar2 >> 0x28,0);
814: uVar26 = SUB161(auVar2 >> 0x20,0);
815: uVar24 = SUB161(auVar2 >> 0x18,0);
816: uVar22 = SUB161(auVar2 >> 0x10,0);
817: uVar20 = SUB161(auVar2 >> 8,0);
818: auVar51 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
819: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
820: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
821: (SUB163(CONCAT214(SUB162(CONCAT115(uVar23,
822: CONCAT114(uVar23,SUB1614(auVar2,0))) >> 0x70,0),
823: CONCAT113(uVar21,SUB1613(auVar2,0))) >> 0x68,0),
824: CONCAT112(uVar21,SUB1612(auVar2,0))) >> 0x60,0),
825: CONCAT111(uVar19,SUB1611(auVar2,0))) >> 0x58,0),
826: CONCAT110(uVar19,SUB1610(auVar2,0))) >> 0x50,0),
827: CONCAT19(uVar26,SUB169(auVar2,0))) >> 0x48,0),
828: CONCAT18(uVar26,SUB168(auVar2,0))) >> 0x40,0),
829: uVar24)) << 0x38) >> 0x30,0),uVar22)) << 0x28) >>
830: 0x20,0),uVar20),(SUB163(auVar2,0) >> 8) << 0x10)
831: >> 0x10,0),SUB161(auVar2,0))) << 8;
832: uVar25 = SUB161(auVar2 >> 0x40,0);
833: uVar27 = SUB161(auVar2 >> 0x48,0);
834: uVar38 = CONCAT12(uVar27,CONCAT11(uVar25,uVar25));
835: uVar28 = SUB161(auVar2 >> 0x50,0);
836: uVar39 = CONCAT14(uVar28,CONCAT13(uVar27,uVar38));
837: uVar29 = SUB161(auVar2 >> 0x58,0);
838: uVar40 = CONCAT16(uVar29,CONCAT15(uVar28,uVar39));
839: uVar41 = CONCAT17(uVar29,uVar40);
840: uVar30 = SUB161(auVar2 >> 0x60,0);
841: Var42 = CONCAT18(uVar30,uVar41);
842: Var43 = CONCAT19(uVar30,Var42);
843: uVar31 = SUB161(auVar2 >> 0x68,0);
844: auVar44 = CONCAT110(uVar31,Var43);
845: auVar45 = CONCAT111(uVar31,auVar44);
846: uVar32 = SUB161(auVar2 >> 0x70,0);
847: auVar46 = CONCAT112(uVar32,auVar45);
848: uVar33 = SUB161(auVar2 >> 0x78,0);
849: uVar17 = CONCAT12(uVar27,CONCAT11((char)iVar6,uVar25));
850: uVar18 = CONCAT14(uVar28,CONCAT13((char)((uint)iVar6 >> 8),uVar17));
851: *(undefined (*) [16])(puVar8 + lVar13 * 4) =
852: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81
853: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
854: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
855: CONCAT214(SUB162(CONCAT115((char)((uint)iVar4 >>
856: 0x18),
857: CONCAT114(uVar24,
858: SUB1614(auVar51,0))) >> 0x70,0),
859: CONCAT113(uVar24,SUB1613(auVar51,0))) >> 0x68,0),
860: CONCAT112(uVar24,SUB1612(auVar51,0))) >> 0x60,0),
861: CONCAT111((char)((uint)iVar4 >> 0x10),
862: SUB1611(auVar51,0))) >> 0x58,0),
863: CONCAT110(uVar22,SUB1610(auVar51,0))) >> 0x50,0),
864: CONCAT19(uVar22,SUB169(auVar51,0))) >> 0x48,0),
865: CONCAT18(uVar22,SUB168(auVar51,0))) >> 0x40,0),
866: (char)((uint)iVar4 >> 8)),
867: (SUB167(auVar51,0) >> 0x18) << 0x30) >> 0x30,0),
868: uVar20),(SUB165(auVar51,0) >> 0x10) << 0x20) >>
869: 0x20,0),(char)iVar4),
870: (SUB163(auVar51,0) >> 8) << 0x10) >> 0x10,0),
871: SUB162(auVar2,0) & 0xff | SUB162(auVar2,0) << 8);
872: puVar1 = puVar8 + lVar13 * 4 + 0x10;
873: *puVar1 = uVar26;
874: puVar1[1] = uVar26;
875: puVar1[2] = uVar26;
876: puVar1[3] = (char)iVar5;
877: puVar1[4] = uVar19;
878: puVar1[5] = uVar19;
879: puVar1[6] = uVar19;
880: puVar1[7] = (char)((uint)iVar5 >> 8);
881: puVar1[8] = uVar21;
882: puVar1[9] = uVar21;
883: puVar1[10] = uVar21;
884: puVar1[0xb] = (char)((uint)iVar5 >> 0x10);
885: puVar1[0xc] = uVar23;
886: puVar1[0xd] = uVar23;
887: puVar1[0xe] = uVar23;
888: puVar1[0xf] = (char)((uint)iVar5 >> 0x18);
889: *(undefined (*) [16])(puVar8 + lVar13 * 4 + 0x20) =
890: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
891: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
892: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
893: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115((char
894: )((uint)iVar6 >> 0x18),
895: CONCAT114(uVar29,CONCAT113(uVar32,auVar46))) >>
896: 0x70,0),CONCAT113(uVar29,auVar46)) >> 0x68,0),
897: CONCAT112(uVar29,auVar45)) >> 0x60,0),
898: CONCAT111(uVar52,auVar44)) >> 0x58,0),
899: CONCAT110(uVar28,Var43)) >> 0x50,0),
900: CONCAT19(uVar28,Var42)) >> 0x48,0),
901: CONCAT18(uVar28,uVar41)) >> 0x40,0),
902: (((ulong)CONCAT16(uVar29,CONCAT15(uVar52,uVar18))
903: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
904: (uVar40 >> 0x18) << 0x30) >> 0x30,0),
905: (((uint6)uVar18 & 0xff0000) >> 0x10) << 0x28) >>
906: 0x28,0),(uVar39 >> 0x10) << 0x20) >> 0x20,0),
907: ((uVar17 & 0xff00) >> 8) << 0x18) >> 0x18,0),
908: (uVar38 >> 8) << 0x10) >> 0x10,0),CONCAT11(uVar25,uVar25));
909: puVar1 = puVar8 + lVar13 * 4 + 0x30;
910: *puVar1 = uVar30;
911: puVar1[1] = uVar30;
912: puVar1[2] = uVar30;
913: puVar1[3] = (char)iVar7;
914: puVar1[4] = uVar31;
915: puVar1[5] = uVar31;
916: puVar1[6] = uVar31;
917: puVar1[7] = (char)((uint)iVar7 >> 8);
918: puVar1[8] = uVar32;
919: puVar1[9] = uVar32;
920: puVar1[10] = uVar32;
921: puVar1[0xb] = (char)((uint)iVar7 >> 0x10);
922: puVar1[0xc] = uVar33;
923: puVar1[0xd] = uVar33;
924: puVar1[0xe] = uVar33;
925: puVar1[0xf] = (char)((uint)iVar7 >> 0x18);
926: lVar13 = lVar13 + 0x10;
927: } while (uVar16 < uVar3 >> 4);
928: puVar8 = puVar8 + (ulong)uVar15 * 4;
929: if (uVar3 != uVar15) {
930: uVar20 = puVar9[uVar15];
931: puVar8[3] = 0xff;
932: *puVar8 = uVar20;
933: puVar8[1] = uVar20;
934: puVar8[2] = uVar20;
935: uVar14 = (ulong)(uVar15 + 1);
936: if (uVar15 + 1 < uVar3) {
937: code_r0x001219de:
938: iVar12 = (int)uVar14;
939: uVar20 = puVar9[uVar14];
940: puVar8[7] = 0xff;
941: puVar8[4] = uVar20;
942: puVar8[5] = uVar20;
943: puVar8[6] = uVar20;
944: if (iVar12 + 1U < uVar3) {
945: uVar20 = puVar9[iVar12 + 1U];
946: puVar8[0xb] = 0xff;
947: puVar8[8] = uVar20;
948: puVar8[9] = uVar20;
949: puVar8[10] = uVar20;
950: if (iVar12 + 2U < uVar3) {
951: uVar20 = puVar9[iVar12 + 2U];
952: puVar8[0xf] = 0xff;
953: puVar8[0xc] = uVar20;
954: puVar8[0xd] = uVar20;
955: puVar8[0xe] = uVar20;
956: if (iVar12 + 3U < uVar3) {
957: uVar20 = puVar9[iVar12 + 3U];
958: puVar8[0x13] = 0xff;
959: puVar8[0x10] = uVar20;
960: puVar8[0x11] = uVar20;
961: puVar8[0x12] = uVar20;
962: if (iVar12 + 4U < uVar3) {
963: uVar20 = puVar9[iVar12 + 4U];
964: puVar8[0x17] = 0xff;
965: puVar8[0x14] = uVar20;
966: puVar8[0x15] = uVar20;
967: puVar8[0x16] = uVar20;
968: if (iVar12 + 5U < uVar3) {
969: uVar20 = puVar9[iVar12 + 5U];
970: puVar8[0x1b] = 0xff;
971: puVar8[0x18] = uVar20;
972: puVar8[0x19] = uVar20;
973: puVar8[0x1a] = uVar20;
974: if (iVar12 + 6U < uVar3) {
975: uVar20 = puVar9[iVar12 + 6U];
976: puVar8[0x1f] = 0xff;
977: puVar8[0x1c] = uVar20;
978: puVar8[0x1d] = uVar20;
979: puVar8[0x1e] = uVar20;
980: if (iVar12 + 7U < uVar3) {
981: uVar20 = puVar9[iVar12 + 7U];
982: puVar8[0x23] = 0xff;
983: puVar8[0x20] = uVar20;
984: puVar8[0x21] = uVar20;
985: puVar8[0x22] = uVar20;
986: if (iVar12 + 8U < uVar3) {
987: uVar20 = puVar9[iVar12 + 8U];
988: puVar8[0x27] = 0xff;
989: puVar8[0x24] = uVar20;
990: puVar8[0x25] = uVar20;
991: puVar8[0x26] = uVar20;
992: if (iVar12 + 9U < uVar3) {
993: uVar20 = puVar9[iVar12 + 9U];
994: puVar8[0x2b] = 0xff;
995: puVar8[0x28] = uVar20;
996: puVar8[0x29] = uVar20;
997: puVar8[0x2a] = uVar20;
998: if (iVar12 + 10U < uVar3) {
999: uVar20 = puVar9[iVar12 + 10U];
1000: puVar8[0x2f] = 0xff;
1001: puVar8[0x2c] = uVar20;
1002: puVar8[0x2d] = uVar20;
1003: puVar8[0x2e] = uVar20;
1004: if (iVar12 + 0xbU < uVar3) {
1005: uVar20 = puVar9[iVar12 + 0xbU];
1006: puVar8[0x33] = 0xff;
1007: puVar8[0x30] = uVar20;
1008: puVar8[0x31] = uVar20;
1009: puVar8[0x32] = uVar20;
1010: if (iVar12 + 0xcU < uVar3) {
1011: uVar20 = puVar9[iVar12 + 0xcU];
1012: puVar8[0x37] = 0xff;
1013: puVar8[0x34] = uVar20;
1014: puVar8[0x35] = uVar20;
1015: puVar8[0x36] = uVar20;
1016: if (iVar12 + 0xdU < uVar3) {
1017: uVar20 = puVar9[iVar12 + 0xdU];
1018: puVar8[0x3b] = 0xff;
1019: puVar8[0x38] = uVar20;
1020: puVar8[0x39] = uVar20;
1021: puVar8[0x3a] = uVar20;
1022: }
1023: }
1024: }
1025: }
1026: }
1027: }
1028: }
1029: }
1030: }
1031: }
1032: }
1033: }
1034: }
1035: }
1036: }
1037: goto code_r0x001213a0;
1038: code_r0x00121528:
1039: lVar13 = 0;
1040: uVar16 = 0;
1041: do {
1042: auVar2 = *(undefined (*) [16])(puVar9 + lVar13);
1043: uVar16 = uVar16 + 1;
1044: uVar23 = SUB161(auVar2 >> 0x38,0);
1045: uVar21 = SUB161(auVar2 >> 0x30,0);
1046: uVar19 = SUB161(auVar2 >> 0x28,0);
1047: uVar26 = SUB161(auVar2 >> 0x20,0);
1048: uVar24 = SUB161(auVar2 >> 0x18,0);
1049: uVar22 = SUB161(auVar2 >> 0x10,0);
1050: uVar20 = SUB161(auVar2 >> 8,0);
1051: auVar51 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1052: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
1053: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
1054: (SUB163(CONCAT214(SUB162(CONCAT115(uVar23,
1055: CONCAT114(uVar23,SUB1614(auVar2,0))) >> 0x70,0),
1056: CONCAT113(uVar21,SUB1613(auVar2,0))) >> 0x68,0),
1057: CONCAT112(uVar21,SUB1612(auVar2,0))) >> 0x60,0),
1058: CONCAT111(uVar19,SUB1611(auVar2,0))) >> 0x58,0),
1059: CONCAT110(uVar19,SUB1610(auVar2,0))) >> 0x50,0),
1060: CONCAT19(uVar26,SUB169(auVar2,0))) >> 0x48,0),
1061: CONCAT18(uVar26,SUB168(auVar2,0))) >> 0x40,0),
1062: uVar24)) << 0x38) >> 0x30,0),uVar22)) << 0x28) >>
1063: 0x20,0),uVar20),(SUB163(auVar2,0) >> 8) << 0x10)
1064: >> 0x10,0),SUB161(auVar2,0))) << 8;
1065: uVar25 = SUB161(auVar2 >> 0x40,0);
1066: uVar27 = SUB161(auVar2 >> 0x48,0);
1067: uVar38 = CONCAT12(uVar27,CONCAT11(uVar25,uVar25));
1068: uVar28 = SUB161(auVar2 >> 0x50,0);
1069: uVar39 = CONCAT14(uVar28,CONCAT13(uVar27,uVar38));
1070: uVar29 = SUB161(auVar2 >> 0x58,0);
1071: uVar40 = CONCAT16(uVar29,CONCAT15(uVar28,uVar39));
1072: uVar41 = CONCAT17(uVar29,uVar40);
1073: uVar30 = SUB161(auVar2 >> 0x60,0);
1074: Var42 = CONCAT18(uVar30,uVar41);
1075: Var43 = CONCAT19(uVar30,Var42);
1076: uVar31 = SUB161(auVar2 >> 0x68,0);
1077: auVar44 = CONCAT110(uVar31,Var43);
1078: auVar45 = CONCAT111(uVar31,auVar44);
1079: uVar32 = SUB161(auVar2 >> 0x70,0);
1080: auVar46 = CONCAT112(uVar32,auVar45);
1081: uVar33 = SUB161(auVar2 >> 0x78,0);
1082: uVar17 = CONCAT12(uVar27,CONCAT11((char)iVar6,uVar25));
1083: uVar18 = CONCAT14(uVar28,CONCAT13((char)((uint)iVar6 >> 8),uVar17));
1084: *(undefined (*) [16])(puVar8 + lVar13 * 4) =
1085: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81
1086: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
1087: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
1088: CONCAT214(SUB162(CONCAT115((char)((uint)iVar4 >>
1089: 0x18),
1090: CONCAT114(uVar24,
1091: SUB1614(auVar51,0))) >> 0x70,0),
1092: CONCAT113(uVar24,SUB1613(auVar51,0))) >> 0x68,0),
1093: CONCAT112(uVar24,SUB1612(auVar51,0))) >> 0x60,0),
1094: CONCAT111((char)((uint)iVar4 >> 0x10),
1095: SUB1611(auVar51,0))) >> 0x58,0),
1096: CONCAT110(uVar22,SUB1610(auVar51,0))) >> 0x50,0),
1097: CONCAT19(uVar22,SUB169(auVar51,0))) >> 0x48,0),
1098: CONCAT18(uVar22,SUB168(auVar51,0))) >> 0x40,0),
1099: (char)((uint)iVar4 >> 8)),
1100: (SUB167(auVar51,0) >> 0x18) << 0x30) >> 0x30,0),
1101: uVar20),(SUB165(auVar51,0) >> 0x10) << 0x20) >>
1102: 0x20,0),(char)iVar4),
1103: (SUB163(auVar51,0) >> 8) << 0x10) >> 0x10,0),
1104: SUB162(auVar2,0) & 0xff | SUB162(auVar2,0) << 8);
1105: puVar1 = puVar8 + lVar13 * 4 + 0x10;
1106: *puVar1 = uVar26;
1107: puVar1[1] = uVar26;
1108: puVar1[2] = uVar26;
1109: puVar1[3] = (char)iVar5;
1110: puVar1[4] = uVar19;
1111: puVar1[5] = uVar19;
1112: puVar1[6] = uVar19;
1113: puVar1[7] = (char)((uint)iVar5 >> 8);
1114: puVar1[8] = uVar21;
1115: puVar1[9] = uVar21;
1116: puVar1[10] = uVar21;
1117: puVar1[0xb] = (char)((uint)iVar5 >> 0x10);
1118: puVar1[0xc] = uVar23;
1119: puVar1[0xd] = uVar23;
1120: puVar1[0xe] = uVar23;
1121: puVar1[0xf] = (char)((uint)iVar5 >> 0x18);
1122: *(undefined (*) [16])(puVar8 + lVar13 * 4 + 0x20) =
1123: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
1124: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1125: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1126: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115((char
1127: )((uint)iVar6 >> 0x18),
1128: CONCAT114(uVar29,CONCAT113(uVar32,auVar46))) >>
1129: 0x70,0),CONCAT113(uVar29,auVar46)) >> 0x68,0),
1130: CONCAT112(uVar29,auVar45)) >> 0x60,0),
1131: CONCAT111(uVar52,auVar44)) >> 0x58,0),
1132: CONCAT110(uVar28,Var43)) >> 0x50,0),
1133: CONCAT19(uVar28,Var42)) >> 0x48,0),
1134: CONCAT18(uVar28,uVar41)) >> 0x40,0),
1135: (((ulong)CONCAT16(uVar29,CONCAT15(uVar52,uVar18))
1136: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
1137: (uVar40 >> 0x18) << 0x30) >> 0x30,0),
1138: (((uint6)uVar18 & 0xff0000) >> 0x10) << 0x28) >>
1139: 0x28,0),(uVar39 >> 0x10) << 0x20) >> 0x20,0),
1140: ((uVar17 & 0xff00) >> 8) << 0x18) >> 0x18,0),
1141: (uVar38 >> 8) << 0x10) >> 0x10,0),CONCAT11(uVar25,uVar25));
1142: puVar1 = puVar8 + lVar13 * 4 + 0x30;
1143: *puVar1 = uVar30;
1144: puVar1[1] = uVar30;
1145: puVar1[2] = uVar30;
1146: puVar1[3] = (char)iVar7;
1147: puVar1[4] = uVar31;
1148: puVar1[5] = uVar31;
1149: puVar1[6] = uVar31;
1150: puVar1[7] = (char)((uint)iVar7 >> 8);
1151: puVar1[8] = uVar32;
1152: puVar1[9] = uVar32;
1153: puVar1[10] = uVar32;
1154: puVar1[0xb] = (char)((uint)iVar7 >> 0x10);
1155: puVar1[0xc] = uVar33;
1156: puVar1[0xd] = uVar33;
1157: puVar1[0xe] = uVar33;
1158: puVar1[0xf] = (char)((uint)iVar7 >> 0x18);
1159: lVar13 = lVar13 + 0x10;
1160: } while (uVar16 < uVar3 >> 4);
1161: puVar8 = puVar8 + (ulong)uVar15 * 4;
1162: if (uVar3 != uVar15) {
1163: uVar20 = puVar9[uVar15];
1164: puVar8[3] = 0xff;
1165: puVar8[2] = uVar20;
1166: puVar8[1] = uVar20;
1167: *puVar8 = uVar20;
1168: uVar14 = (ulong)(uVar15 + 1);
1169: if (uVar15 + 1 < uVar3) {
1170: code_r0x00121bd6:
1171: iVar12 = (int)uVar14;
1172: uVar20 = puVar9[uVar14];
1173: puVar8[7] = 0xff;
1174: puVar8[6] = uVar20;
1175: puVar8[5] = uVar20;
1176: puVar8[4] = uVar20;
1177: if (iVar12 + 1U < uVar3) {
1178: uVar20 = puVar9[iVar12 + 1U];
1179: puVar8[0xb] = 0xff;
1180: puVar8[10] = uVar20;
1181: puVar8[9] = uVar20;
1182: puVar8[8] = uVar20;
1183: if (iVar12 + 2U < uVar3) {
1184: uVar20 = puVar9[iVar12 + 2U];
1185: puVar8[0xf] = 0xff;
1186: puVar8[0xe] = uVar20;
1187: puVar8[0xd] = uVar20;
1188: puVar8[0xc] = uVar20;
1189: if (iVar12 + 3U < uVar3) {
1190: uVar20 = puVar9[iVar12 + 3U];
1191: puVar8[0x13] = 0xff;
1192: puVar8[0x12] = uVar20;
1193: puVar8[0x11] = uVar20;
1194: puVar8[0x10] = uVar20;
1195: if (iVar12 + 4U < uVar3) {
1196: uVar20 = puVar9[iVar12 + 4U];
1197: puVar8[0x17] = 0xff;
1198: puVar8[0x16] = uVar20;
1199: puVar8[0x15] = uVar20;
1200: puVar8[0x14] = uVar20;
1201: if (iVar12 + 5U < uVar3) {
1202: uVar20 = puVar9[iVar12 + 5U];
1203: puVar8[0x1b] = 0xff;
1204: puVar8[0x1a] = uVar20;
1205: puVar8[0x19] = uVar20;
1206: puVar8[0x18] = uVar20;
1207: if (iVar12 + 6U < uVar3) {
1208: uVar20 = puVar9[iVar12 + 6U];
1209: puVar8[0x1f] = 0xff;
1210: puVar8[0x1e] = uVar20;
1211: puVar8[0x1d] = uVar20;
1212: puVar8[0x1c] = uVar20;
1213: if (iVar12 + 7U < uVar3) {
1214: uVar20 = puVar9[iVar12 + 7U];
1215: puVar8[0x23] = 0xff;
1216: puVar8[0x22] = uVar20;
1217: puVar8[0x21] = uVar20;
1218: puVar8[0x20] = uVar20;
1219: if (iVar12 + 8U < uVar3) {
1220: uVar20 = puVar9[iVar12 + 8U];
1221: puVar8[0x27] = 0xff;
1222: puVar8[0x26] = uVar20;
1223: puVar8[0x25] = uVar20;
1224: puVar8[0x24] = uVar20;
1225: if (iVar12 + 9U < uVar3) {
1226: uVar20 = puVar9[iVar12 + 9U];
1227: puVar8[0x2b] = 0xff;
1228: puVar8[0x2a] = uVar20;
1229: puVar8[0x29] = uVar20;
1230: puVar8[0x28] = uVar20;
1231: if (iVar12 + 10U < uVar3) {
1232: uVar20 = puVar9[iVar12 + 10U];
1233: puVar8[0x2f] = 0xff;
1234: puVar8[0x2e] = uVar20;
1235: puVar8[0x2d] = uVar20;
1236: puVar8[0x2c] = uVar20;
1237: if (iVar12 + 0xbU < uVar3) {
1238: uVar20 = puVar9[iVar12 + 0xbU];
1239: puVar8[0x33] = 0xff;
1240: puVar8[0x32] = uVar20;
1241: puVar8[0x31] = uVar20;
1242: puVar8[0x30] = uVar20;
1243: if (iVar12 + 0xcU < uVar3) {
1244: uVar20 = puVar9[iVar12 + 0xcU];
1245: puVar8[0x37] = 0xff;
1246: puVar8[0x36] = uVar20;
1247: puVar8[0x35] = uVar20;
1248: puVar8[0x34] = uVar20;
1249: if (iVar12 + 0xdU < uVar3) {
1250: uVar20 = puVar9[iVar12 + 0xdU];
1251: puVar8[0x3b] = 0xff;
1252: puVar8[0x3a] = uVar20;
1253: puVar8[0x39] = uVar20;
1254: puVar8[0x38] = uVar20;
1255: }
1256: }
1257: }
1258: }
1259: }
1260: }
1261: }
1262: }
1263: }
1264: }
1265: }
1266: }
1267: }
1268: }
1269: }
1270: goto code_r0x001214d0;
1271: }
1272: 
