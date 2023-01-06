1: 
2: void FUN_00121ef0(long param_1,long *param_2,uint param_3,undefined8 *param_4,int param_5)
3: 
4: {
5: undefined *puVar1;
6: undefined *puVar2;
7: undefined *puVar3;
8: undefined auVar4 [16];
9: undefined uVar5;
10: uint uVar6;
11: undefined *puVar7;
12: long lVar8;
13: long lVar9;
14: undefined uVar10;
15: undefined uVar11;
16: undefined uVar12;
17: undefined uVar13;
18: undefined uVar14;
19: undefined uVar15;
20: undefined uVar16;
21: undefined uVar17;
22: undefined uVar18;
23: ulong uVar19;
24: ulong uVar20;
25: undefined *puVar21;
26: long lVar22;
27: undefined8 *puVar23;
28: long lVar24;
29: undefined *puVar25;
30: uint uVar26;
31: uint uVar27;
32: uint3 uVar28;
33: undefined uVar30;
34: undefined uVar31;
35: undefined uVar32;
36: undefined uVar33;
37: undefined uVar34;
38: undefined uVar35;
39: uint3 uVar36;
40: undefined uVar45;
41: undefined uVar46;
42: undefined uVar47;
43: undefined uVar51;
44: undefined uVar52;
45: undefined uVar53;
46: undefined uVar54;
47: undefined auVar48 [16];
48: undefined auVar50 [16];
49: undefined auVar55 [12];
50: uint5 uVar29;
51: uint5 uVar37;
52: uint7 uVar38;
53: undefined8 uVar39;
54: unkbyte9 Var40;
55: unkbyte10 Var41;
56: undefined auVar42 [11];
57: undefined auVar43 [12];
58: undefined auVar44 [13];
59: undefined auVar49 [16];
60: 
61: switch(*(undefined4 *)(param_1 + 0x40)) {
62: case 6:
63: uVar6 = *(uint *)(param_1 + 0x88);
64: while (param_5 = param_5 + -1, puVar23 = param_4, -1 < param_5) {
65: while( true ) {
66: uVar20 = (ulong)param_3;
67: param_4 = puVar23 + 1;
68: param_3 = param_3 + 1;
69: lVar24 = *(long *)(*param_2 + uVar20 * 8);
70: lVar8 = *(long *)(param_2[1] + uVar20 * 8);
71: lVar9 = *(long *)(param_2[2] + uVar20 * 8);
72: lVar22 = 0;
73: puVar25 = (undefined *)*puVar23;
74: if (uVar6 == 0) break;
75: do {
76: *puVar25 = *(undefined *)(lVar24 + lVar22);
77: puVar25[1] = *(undefined *)(lVar8 + lVar22);
78: puVar2 = (undefined *)(lVar9 + lVar22);
79: lVar22 = lVar22 + 1;
80: puVar25[2] = *puVar2;
81: puVar25 = puVar25 + 3;
82: } while ((uint)lVar22 < uVar6);
83: param_5 = param_5 + -1;
84: puVar23 = param_4;
85: if (param_5 < 0) {
86: return;
87: }
88: }
89: }
90: break;
91: case 7:
92: case 0xc:
93: uVar6 = *(uint *)(param_1 + 0x88);
94: uVar20 = (ulong)uVar6;
95: uVar27 = uVar6 & 0xfffffff0;
96: code_r0x001222a8:
97: while( true ) {
98: do {
99: param_5 = param_5 + -1;
100: if (param_5 < 0) {
101: return;
102: }
103: uVar19 = (ulong)param_3;
104: puVar23 = param_4 + 1;
105: param_3 = param_3 + 1;
106: puVar25 = *(undefined **)(*param_2 + uVar19 * 8);
107: puVar2 = *(undefined **)(param_2[1] + uVar19 * 8);
108: puVar7 = *(undefined **)(param_2[2] + uVar19 * 8);
109: puVar21 = (undefined *)*param_4;
110: param_4 = puVar23;
111: } while (uVar6 == 0);
112: puVar1 = puVar21 + uVar20 * 4;
113: if ((0xf < uVar6 &&
114: ((puVar7 + uVar20 <= puVar21 || puVar1 <= puVar7) &&
115: (puVar2 + uVar20 <= puVar21 || puVar1 <= puVar2))) &&
116: (puVar25 + uVar20 <= puVar21 || puVar1 <= puVar25)) break;
117: lVar24 = 0;
118: do {
119: *puVar21 = puVar25[lVar24];
120: puVar21[1] = puVar2[lVar24];
121: uVar5 = puVar7[lVar24];
122: lVar24 = lVar24 + 1;
123: puVar21[3] = 0xff;
124: puVar21[2] = uVar5;
125: puVar21 = puVar21 + 4;
126: } while ((uint)lVar24 < uVar6);
127: }
128: if (uVar6 >> 4 != 0) goto code_r0x00122343;
129: uVar26 = 0;
130: goto code_r0x001225e0;
131: case 8:
132: uVar6 = *(uint *)(param_1 + 0x88);
133: while (param_5 = param_5 + -1, -1 < param_5) {
134: uVar20 = (ulong)param_3;
135: puVar23 = param_4 + 1;
136: param_3 = param_3 + 1;
137: lVar24 = *(long *)(*param_2 + uVar20 * 8);
138: lVar8 = *(long *)(param_2[1] + uVar20 * 8);
139: lVar9 = *(long *)(param_2[2] + uVar20 * 8);
140: lVar22 = 0;
141: puVar25 = (undefined *)*param_4;
142: param_4 = puVar23;
143: if (uVar6 != 0) {
144: do {
145: puVar25[2] = *(undefined *)(lVar24 + lVar22);
146: puVar25[1] = *(undefined *)(lVar8 + lVar22);
147: puVar2 = (undefined *)(lVar9 + lVar22);
148: lVar22 = lVar22 + 1;
149: *puVar25 = *puVar2;
150: puVar25 = puVar25 + 3;
151: } while ((uint)lVar22 < uVar6);
152: }
153: }
154: break;
155: case 9:
156: case 0xd:
157: uVar6 = *(uint *)(param_1 + 0x88);
158: uVar20 = (ulong)uVar6;
159: uVar27 = uVar6 & 0xfffffff0;
160: code_r0x00122470:
161: while( true ) {
162: do {
163: param_5 = param_5 + -1;
164: if (param_5 < 0) {
165: return;
166: }
167: uVar19 = (ulong)param_3;
168: puVar23 = param_4 + 1;
169: param_3 = param_3 + 1;
170: puVar25 = *(undefined **)(*param_2 + uVar19 * 8);
171: puVar2 = *(undefined **)(param_2[1] + uVar19 * 8);
172: puVar7 = *(undefined **)(param_2[2] + uVar19 * 8);
173: puVar21 = (undefined *)*param_4;
174: param_4 = puVar23;
175: } while (uVar6 == 0);
176: puVar1 = puVar21 + uVar20 * 4;
177: if ((0xf < uVar6 &&
178: ((puVar25 + uVar20 <= puVar21 || puVar1 <= puVar25) &&
179: (puVar2 + uVar20 <= puVar21 || puVar1 <= puVar2))) &&
180: (puVar7 + uVar20 <= puVar21 || puVar1 <= puVar7)) break;
181: lVar24 = 0;
182: do {
183: puVar21[2] = puVar25[lVar24];
184: puVar21[1] = puVar2[lVar24];
185: uVar5 = puVar7[lVar24];
186: lVar24 = lVar24 + 1;
187: puVar21[3] = 0xff;
188: *puVar21 = uVar5;
189: puVar21 = puVar21 + 4;
190: } while ((uint)lVar24 < uVar6);
191: }
192: if (uVar6 >> 4 != 0) goto code_r0x0012250f;
193: uVar26 = 0;
194: goto code_r0x00122660;
195: case 10:
196: case 0xe:
197: uVar6 = *(uint *)(param_1 + 0x88);
198: auVar43 = CONCAT48(0xffffffff,0xffffffffffffffff);
199: uVar20 = (ulong)uVar6;
200: uVar27 = uVar6 & 0xfffffff0;
201: code_r0x00121f58:
202: while( true ) {
203: do {
204: param_5 = param_5 + -1;
205: if (param_5 < 0) {
206: return;
207: }
208: uVar19 = (ulong)param_3;
209: puVar23 = param_4 + 1;
210: param_3 = param_3 + 1;
211: puVar25 = *(undefined **)(*param_2 + uVar19 * 8);
212: puVar2 = *(undefined **)(param_2[1] + uVar19 * 8);
213: puVar7 = *(undefined **)(param_2[2] + uVar19 * 8);
214: puVar21 = (undefined *)*param_4;
215: param_4 = puVar23;
216: } while (uVar6 == 0);
217: puVar1 = puVar21 + uVar20 * 4;
218: if ((0xf < uVar6 &&
219: ((puVar25 + uVar20 <= puVar21 || puVar1 <= puVar25) &&
220: (puVar2 + uVar20 <= puVar21 || puVar1 <= puVar2))) &&
221: (puVar7 + uVar20 <= puVar21 || puVar1 <= puVar7)) break;
222: lVar24 = 0;
223: do {
224: puVar21[3] = puVar25[lVar24];
225: puVar21[2] = puVar2[lVar24];
226: uVar5 = puVar7[lVar24];
227: lVar24 = lVar24 + 1;
228: *puVar21 = 0xff;
229: puVar21[1] = uVar5;
230: puVar21 = puVar21 + 4;
231: } while ((uint)lVar24 < uVar6);
232: }
233: if (uVar6 >> 4 != 0) goto code_r0x00121ff7;
234: uVar26 = 0;
235: goto code_r0x00122620;
236: case 0xb:
237: case 0xf:
238: uVar6 = *(uint *)(param_1 + 0x88);
239: auVar43 = CONCAT48(0xffffffff,0xffffffffffffffff);
240: uVar20 = (ulong)uVar6;
241: uVar27 = uVar6 & 0xfffffff0;
242: code_r0x001220c0:
243: while( true ) {
244: do {
245: param_5 = param_5 + -1;
246: if (param_5 < 0) {
247: return;
248: }
249: uVar19 = (ulong)param_3;
250: puVar23 = param_4 + 1;
251: param_3 = param_3 + 1;
252: puVar25 = *(undefined **)(*param_2 + uVar19 * 8);
253: puVar2 = *(undefined **)(param_2[1] + uVar19 * 8);
254: puVar7 = *(undefined **)(param_2[2] + uVar19 * 8);
255: puVar21 = (undefined *)*param_4;
256: param_4 = puVar23;
257: } while (uVar6 == 0);
258: puVar1 = puVar21 + uVar20 * 4;
259: if ((0xf < uVar6 &&
260: ((puVar25 + uVar20 <= puVar21 || puVar1 <= puVar25) &&
261: (puVar2 + uVar20 <= puVar21 || puVar1 <= puVar2))) &&
262: (puVar7 + uVar20 <= puVar21 || puVar1 <= puVar7)) break;
263: lVar24 = 0;
264: do {
265: puVar21[1] = puVar25[lVar24];
266: puVar21[2] = puVar2[lVar24];
267: uVar5 = puVar7[lVar24];
268: lVar24 = lVar24 + 1;
269: *puVar21 = 0xff;
270: puVar21[3] = uVar5;
271: puVar21 = puVar21 + 4;
272: } while ((uint)lVar24 < uVar6);
273: }
274: if (uVar6 >> 4 != 0) goto code_r0x0012215f;
275: uVar26 = 0;
276: goto code_r0x001225a0;
277: default:
278: uVar6 = *(uint *)(param_1 + 0x88);
279: while (param_5 = param_5 + -1, -1 < param_5) {
280: uVar20 = (ulong)param_3;
281: puVar23 = param_4 + 1;
282: param_3 = param_3 + 1;
283: lVar24 = *(long *)(*param_2 + uVar20 * 8);
284: lVar8 = *(long *)(param_2[1] + uVar20 * 8);
285: lVar9 = *(long *)(param_2[2] + uVar20 * 8);
286: lVar22 = 0;
287: puVar25 = (undefined *)*param_4;
288: param_4 = puVar23;
289: if (uVar6 != 0) {
290: do {
291: *puVar25 = *(undefined *)(lVar24 + lVar22);
292: puVar25[1] = *(undefined *)(lVar8 + lVar22);
293: puVar2 = (undefined *)(lVar9 + lVar22);
294: lVar22 = lVar22 + 1;
295: puVar25[2] = *puVar2;
296: puVar25 = puVar25 + 3;
297: } while ((uint)lVar22 < uVar6);
298: }
299: }
300: }
301: return;
302: code_r0x0012215f:
303: lVar24 = 0;
304: uVar26 = 0;
305: do {
306: puVar3 = puVar2 + lVar24;
307: uVar5 = puVar3[10];
308: uVar10 = puVar3[0xb];
309: uVar11 = puVar3[0xc];
310: uVar12 = puVar3[0xd];
311: uVar13 = puVar3[0xe];
312: uVar14 = puVar3[0xf];
313: uVar26 = uVar26 + 1;
314: auVar4 = *(undefined (*) [16])(puVar25 + lVar24);
315: auVar49 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
316: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
317: (puVar3[7],
318: CONCAT114(0xff,SUB1614(CONCAT412(0xffffffff,
319: auVar43),0))) >>
320: 0x70,0),CONCAT113(puVar3[6],
321: SUB1613(CONCAT412(0xffffffff,
322: auVar43),0)))
323: >> 0x68,0),CONCAT112(0xff,auVar43)) >> 0x60,0),
324: CONCAT111(puVar3[5],SUB1211(auVar43,0))) >> 0x58,0
325: ),CONCAT110(0xff,SUB1210(auVar43,0))) >> 0x50,0),
326: CONCAT19(puVar3[4],SUB129(auVar43,0))) >> 0x48,0),
327: CONCAT18(0xff,0xffffffffffffffff)) >> 0x40,0),
328: puVar3[3])) << 0x38 | (undefined  [16])0xffffffffffffff;
329: auVar50 = CONCAT97(SUB169(auVar49 >> 0x38,0),0xff000000000000) | (undefined  [16])0xffffffffffff
330: ;
331: auVar48 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(
332: auVar50 >> 0x30,0),puVar3[2]) |
333: SUB1611((undefined  [16])0xffffffffff >> 0x28,0),
334: 0xff00000000) >> 0x20,0) |
335: SUB1612((undefined  [16])0xffffffff >> 0x20,0),
336: puVar3[1]) |
337: SUB1613((undefined  [16])0xffffff >> 0x18,0),
338: 0xff0000) >> 0x10,0) |
339: SUB1614((undefined  [16])0xffff >> 0x10,0),*puVar3)) << 8 |
340: (undefined  [16])0xff;
341: puVar1 = puVar7 + lVar24;
342: uVar15 = puVar1[4];
343: uVar16 = puVar1[5];
344: uVar17 = puVar1[6];
345: uVar18 = puVar1[7];
346: uVar31 = puVar1[10];
347: uVar33 = puVar1[0xb];
348: uVar35 = puVar1[0xc];
349: uVar45 = puVar1[0xd];
350: uVar46 = puVar1[0xe];
351: uVar47 = puVar1[0xf];
352: uVar36 = CONCAT12(0xff,CONCAT11(puVar3[8],0xff));
353: uVar37 = CONCAT14(0xff,CONCAT13(puVar3[9],uVar36));
354: uVar38 = CONCAT16(0xff,CONCAT15(uVar5,uVar37));
355: uVar39 = CONCAT17(uVar10,uVar38);
356: Var40 = CONCAT18(0xff,uVar39);
357: Var41 = CONCAT19(uVar11,Var40);
358: auVar42 = CONCAT110(0xff,Var41);
359: auVar55 = CONCAT111(uVar12,auVar42);
360: auVar44 = CONCAT112(0xff,auVar55);
361: uVar30 = SUB161(auVar4 >> 0x40,0);
362: uVar28 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar1[8],uVar30));
363: uVar32 = SUB161(auVar4 >> 0x50,0);
364: uVar29 = CONCAT14(uVar32,CONCAT13(puVar1[9],uVar28));
365: uVar34 = SUB161(auVar4 >> 0x58,0);
366: *(undefined (*) [16])(puVar21 + lVar24 * 4) =
367: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81
368: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
369: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
370: CONCAT214(SUB162(CONCAT115(puVar1[3],
371: CONCAT114(SUB161(
372: auVar49 >> 0x38,0),SUB1614(auVar48,0))) >> 0x70,0)
373: ,CONCAT113(SUB161(auVar4 >> 0x18,0),
374: SUB1613(auVar48,0))) >> 0x68,0),
375: CONCAT112(SUB161(auVar50 >> 0x30,0),
376: SUB1612(auVar48,0))) >> 0x60,0),
377: CONCAT111(puVar1[2],SUB1611(auVar48,0))) >> 0x58,0
378: ),CONCAT110(puVar3[2],SUB1610(auVar48,0))) >> 0x50
379: ,0),CONCAT19(SUB161(auVar4 >> 0x10,0),
380: SUB169(auVar48,0))) >> 0x48,0),
381: CONCAT18(0xff,SUB168(auVar48,0))) >> 0x40,0),
382: puVar1[1]),(SUB167(auVar48,0) >> 0x18) << 0x30) >>
383: 0x30,0),SUB161(auVar4 >> 8,0)),
384: (SUB165(auVar48,0) >> 0x10) << 0x20) >> 0x20,0),
385: *puVar1),(SUB163(auVar48,0) >> 8) << 0x10) >> 0x10,0)
386: ,SUB162(auVar4,0) << 8) | (undefined  [16])0xff;
387: puVar1 = puVar21 + lVar24 * 4 + 0x10;
388: *puVar1 = 0xff;
389: puVar1[1] = SUB161(auVar4 >> 0x20,0);
390: puVar1[2] = SUB161(auVar49 >> 0x48,0);
391: puVar1[3] = uVar15;
392: puVar1[4] = SUB161(auVar49 >> 0x50,0);
393: puVar1[5] = SUB161(auVar4 >> 0x28,0);
394: puVar1[6] = SUB161(auVar49 >> 0x58,0);
395: puVar1[7] = uVar16;
396: puVar1[8] = SUB161(auVar49 >> 0x60,0);
397: puVar1[9] = SUB161(auVar4 >> 0x30,0);
398: puVar1[10] = SUB161(auVar49 >> 0x68,0);
399: puVar1[0xb] = uVar17;
400: puVar1[0xc] = SUB161(auVar49 >> 0x70,0);
401: puVar1[0xd] = SUB161(auVar4 >> 0x38,0);
402: puVar1[0xe] = SUB161(auVar49 >> 0x78,0);
403: puVar1[0xf] = uVar18;
404: *(undefined (*) [16])(puVar21 + lVar24 * 4 + 0x20) =
405: ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
406: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
407: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
408: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
409: CONCAT115(uVar33,CONCAT114(uVar10,CONCAT113(uVar13
410: ,auVar44))) >> 0x70,0),CONCAT113(uVar34,auVar44))
411: >> 0x68,0),CONCAT112(0xff,auVar55)) >> 0x60,0),
412: CONCAT111(uVar31,auVar42)) >> 0x58,0),
413: CONCAT110(uVar5,Var41)) >> 0x50,0),
414: CONCAT19(uVar32,Var40)) >> 0x48,0),
415: CONCAT18(0xff,uVar39)) >> 0x40,0),
416: (((ulong)CONCAT16(uVar34,CONCAT15(uVar31,uVar29))
417: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
418: (uVar38 >> 0x18) << 0x30) >> 0x30,0),
419: (((uint6)uVar29 & 0xff0000) >> 0x10) << 0x28) >>
420: 0x28,0),(uVar37 >> 0x10) << 0x20) >> 0x20,0),
421: ((uVar28 & 0xff00) >> 8) << 0x18) >> 0x18,0),
422: (uVar36 >> 8) << 0x10) >> 0x10,0),uVar30)) << 8 |
423: (undefined  [16])0xff;
424: puVar1 = puVar21 + lVar24 * 4 + 0x30;
425: *puVar1 = 0xff;
426: puVar1[1] = SUB161(auVar4 >> 0x60,0);
427: puVar1[2] = uVar11;
428: puVar1[3] = uVar35;
429: puVar1[4] = 0xff;
430: puVar1[5] = SUB161(auVar4 >> 0x68,0);
431: puVar1[6] = uVar12;
432: puVar1[7] = uVar45;
433: puVar1[8] = 0xff;
434: puVar1[9] = SUB161(auVar4 >> 0x70,0);
435: puVar1[10] = uVar13;
436: puVar1[0xb] = uVar46;
437: puVar1[0xc] = 0xff;
438: puVar1[0xd] = SUB161(auVar4 >> 0x78,0);
439: puVar1[0xe] = uVar14;
440: puVar1[0xf] = uVar47;
441: lVar24 = lVar24 + 0x10;
442: } while (uVar26 < uVar6 >> 4);
443: puVar21 = puVar21 + (ulong)uVar27 * 4;
444: uVar26 = uVar27;
445: if (uVar6 != uVar27) {
446: code_r0x001225a0:
447: do {
448: uVar19 = (ulong)uVar26;
449: uVar26 = uVar26 + 1;
450: puVar21[1] = puVar25[uVar19];
451: puVar21[2] = puVar2[uVar19];
452: uVar5 = puVar7[uVar19];
453: *puVar21 = 0xff;
454: puVar21[3] = uVar5;
455: puVar21 = puVar21 + 4;
456: } while (uVar26 < uVar6);
457: }
458: goto code_r0x001220c0;
459: code_r0x00121ff7:
460: lVar24 = 0;
461: uVar26 = 0;
462: do {
463: puVar3 = puVar2 + lVar24;
464: uVar5 = puVar3[10];
465: uVar10 = puVar3[0xb];
466: uVar11 = puVar3[0xc];
467: uVar12 = puVar3[0xd];
468: uVar13 = puVar3[0xe];
469: uVar14 = puVar3[0xf];
470: uVar26 = uVar26 + 1;
471: auVar4 = *(undefined (*) [16])(puVar7 + lVar24);
472: auVar49 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
473: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
474: (puVar3[7],
475: CONCAT114(0xff,SUB1614(CONCAT412(0xffffffff,
476: auVar43),0))) >>
477: 0x70,0),CONCAT113(puVar3[6],
478: SUB1613(CONCAT412(0xffffffff,
479: auVar43),0)))
480: >> 0x68,0),CONCAT112(0xff,auVar43)) >> 0x60,0),
481: CONCAT111(puVar3[5],SUB1211(auVar43,0))) >> 0x58,0
482: ),CONCAT110(0xff,SUB1210(auVar43,0))) >> 0x50,0),
483: CONCAT19(puVar3[4],SUB129(auVar43,0))) >> 0x48,0),
484: CONCAT18(0xff,0xffffffffffffffff)) >> 0x40,0),
485: puVar3[3])) << 0x38 | (undefined  [16])0xffffffffffffff;
486: auVar50 = CONCAT97(SUB169(auVar49 >> 0x38,0),0xff000000000000) | (undefined  [16])0xffffffffffff
487: ;
488: auVar48 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(
489: auVar50 >> 0x30,0),puVar3[2]) |
490: SUB1611((undefined  [16])0xffffffffff >> 0x28,0),
491: 0xff00000000) >> 0x20,0) |
492: SUB1612((undefined  [16])0xffffffff >> 0x20,0),
493: puVar3[1]) |
494: SUB1613((undefined  [16])0xffffff >> 0x18,0),
495: 0xff0000) >> 0x10,0) |
496: SUB1614((undefined  [16])0xffff >> 0x10,0),*puVar3)) << 8 |
497: (undefined  [16])0xff;
498: puVar1 = puVar25 + lVar24;
499: uVar15 = puVar1[4];
500: uVar16 = puVar1[5];
501: uVar17 = puVar1[6];
502: uVar18 = puVar1[7];
503: uVar31 = puVar1[10];
504: uVar33 = puVar1[0xb];
505: uVar35 = puVar1[0xc];
506: uVar45 = puVar1[0xd];
507: uVar46 = puVar1[0xe];
508: uVar47 = puVar1[0xf];
509: uVar36 = CONCAT12(0xff,CONCAT11(puVar3[8],0xff));
510: uVar37 = CONCAT14(0xff,CONCAT13(puVar3[9],uVar36));
511: uVar38 = CONCAT16(0xff,CONCAT15(uVar5,uVar37));
512: uVar39 = CONCAT17(uVar10,uVar38);
513: Var40 = CONCAT18(0xff,uVar39);
514: Var41 = CONCAT19(uVar11,Var40);
515: auVar42 = CONCAT110(0xff,Var41);
516: auVar55 = CONCAT111(uVar12,auVar42);
517: auVar44 = CONCAT112(0xff,auVar55);
518: uVar30 = SUB161(auVar4 >> 0x40,0);
519: uVar28 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar1[8],uVar30));
520: uVar32 = SUB161(auVar4 >> 0x50,0);
521: uVar29 = CONCAT14(uVar32,CONCAT13(puVar1[9],uVar28));
522: uVar34 = SUB161(auVar4 >> 0x58,0);
523: *(undefined (*) [16])(puVar21 + lVar24 * 4) =
524: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81
525: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
526: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
527: CONCAT214(SUB162(CONCAT115(puVar1[3],
528: CONCAT114(SUB161(
529: auVar49 >> 0x38,0),SUB1614(auVar48,0))) >> 0x70,0)
530: ,CONCAT113(SUB161(auVar4 >> 0x18,0),
531: SUB1613(auVar48,0))) >> 0x68,0),
532: CONCAT112(SUB161(auVar50 >> 0x30,0),
533: SUB1612(auVar48,0))) >> 0x60,0),
534: CONCAT111(puVar1[2],SUB1611(auVar48,0))) >> 0x58,0
535: ),CONCAT110(puVar3[2],SUB1610(auVar48,0))) >> 0x50
536: ,0),CONCAT19(SUB161(auVar4 >> 0x10,0),
537: SUB169(auVar48,0))) >> 0x48,0),
538: CONCAT18(0xff,SUB168(auVar48,0))) >> 0x40,0),
539: puVar1[1]),(SUB167(auVar48,0) >> 0x18) << 0x30) >>
540: 0x30,0),SUB161(auVar4 >> 8,0)),
541: (SUB165(auVar48,0) >> 0x10) << 0x20) >> 0x20,0),
542: *puVar1),(SUB163(auVar48,0) >> 8) << 0x10) >> 0x10,0)
543: ,SUB162(auVar4,0) << 8) | (undefined  [16])0xff;
544: puVar1 = puVar21 + lVar24 * 4 + 0x10;
545: *puVar1 = 0xff;
546: puVar1[1] = SUB161(auVar4 >> 0x20,0);
547: puVar1[2] = SUB161(auVar49 >> 0x48,0);
548: puVar1[3] = uVar15;
549: puVar1[4] = SUB161(auVar49 >> 0x50,0);
550: puVar1[5] = SUB161(auVar4 >> 0x28,0);
551: puVar1[6] = SUB161(auVar49 >> 0x58,0);
552: puVar1[7] = uVar16;
553: puVar1[8] = SUB161(auVar49 >> 0x60,0);
554: puVar1[9] = SUB161(auVar4 >> 0x30,0);
555: puVar1[10] = SUB161(auVar49 >> 0x68,0);
556: puVar1[0xb] = uVar17;
557: puVar1[0xc] = SUB161(auVar49 >> 0x70,0);
558: puVar1[0xd] = SUB161(auVar4 >> 0x38,0);
559: puVar1[0xe] = SUB161(auVar49 >> 0x78,0);
560: puVar1[0xf] = uVar18;
561: *(undefined (*) [16])(puVar21 + lVar24 * 4 + 0x20) =
562: ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
563: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
564: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
565: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
566: CONCAT115(uVar33,CONCAT114(uVar10,CONCAT113(uVar13
567: ,auVar44))) >> 0x70,0),CONCAT113(uVar34,auVar44))
568: >> 0x68,0),CONCAT112(0xff,auVar55)) >> 0x60,0),
569: CONCAT111(uVar31,auVar42)) >> 0x58,0),
570: CONCAT110(uVar5,Var41)) >> 0x50,0),
571: CONCAT19(uVar32,Var40)) >> 0x48,0),
572: CONCAT18(0xff,uVar39)) >> 0x40,0),
573: (((ulong)CONCAT16(uVar34,CONCAT15(uVar31,uVar29))
574: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
575: (uVar38 >> 0x18) << 0x30) >> 0x30,0),
576: (((uint6)uVar29 & 0xff0000) >> 0x10) << 0x28) >>
577: 0x28,0),(uVar37 >> 0x10) << 0x20) >> 0x20,0),
578: ((uVar28 & 0xff00) >> 8) << 0x18) >> 0x18,0),
579: (uVar36 >> 8) << 0x10) >> 0x10,0),uVar30)) << 8 |
580: (undefined  [16])0xff;
581: puVar1 = puVar21 + lVar24 * 4 + 0x30;
582: *puVar1 = 0xff;
583: puVar1[1] = SUB161(auVar4 >> 0x60,0);
584: puVar1[2] = uVar11;
585: puVar1[3] = uVar35;
586: puVar1[4] = 0xff;
587: puVar1[5] = SUB161(auVar4 >> 0x68,0);
588: puVar1[6] = uVar12;
589: puVar1[7] = uVar45;
590: puVar1[8] = 0xff;
591: puVar1[9] = SUB161(auVar4 >> 0x70,0);
592: puVar1[10] = uVar13;
593: puVar1[0xb] = uVar46;
594: puVar1[0xc] = 0xff;
595: puVar1[0xd] = SUB161(auVar4 >> 0x78,0);
596: puVar1[0xe] = uVar14;
597: puVar1[0xf] = uVar47;
598: lVar24 = lVar24 + 0x10;
599: } while (uVar26 < uVar6 >> 4);
600: puVar21 = puVar21 + (ulong)uVar27 * 4;
601: uVar26 = uVar27;
602: if (uVar6 != uVar27) {
603: code_r0x00122620:
604: do {
605: uVar19 = (ulong)uVar26;
606: uVar26 = uVar26 + 1;
607: puVar21[3] = puVar25[uVar19];
608: puVar21[2] = puVar2[uVar19];
609: uVar5 = puVar7[uVar19];
610: *puVar21 = 0xff;
611: puVar21[1] = uVar5;
612: puVar21 = puVar21 + 4;
613: } while (uVar26 < uVar6);
614: }
615: goto code_r0x00121f58;
616: code_r0x0012250f:
617: lVar24 = 0;
618: uVar26 = 0;
619: do {
620: auVar4 = *(undefined (*) [16])(puVar7 + lVar24);
621: uVar26 = uVar26 + 1;
622: puVar1 = puVar25 + lVar24;
623: uVar5 = puVar1[4];
624: uVar10 = puVar1[5];
625: uVar11 = puVar1[6];
626: uVar12 = puVar1[7];
627: uVar13 = puVar1[10];
628: uVar14 = puVar1[0xb];
629: uVar15 = puVar1[0xc];
630: uVar16 = puVar1[0xd];
631: uVar17 = puVar1[0xe];
632: uVar18 = puVar1[0xf];
633: auVar48 = *(undefined (*) [16])(puVar2 + lVar24);
634: uVar45 = SUB161(auVar4 >> 0x40,0);
635: uVar36 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar1[8],uVar45));
636: uVar46 = SUB161(auVar4 >> 0x50,0);
637: uVar37 = CONCAT14(uVar46,CONCAT13(puVar1[9],uVar36));
638: uVar47 = SUB161(auVar4 >> 0x58,0);
639: uVar38 = CONCAT16(uVar47,CONCAT15(uVar13,uVar37));
640: uVar39 = CONCAT17(uVar14,uVar38);
641: uVar30 = SUB161(auVar4 >> 0x60,0);
642: Var40 = CONCAT18(uVar30,uVar39);
643: Var41 = CONCAT19(uVar15,Var40);
644: uVar32 = SUB161(auVar4 >> 0x68,0);
645: auVar42 = CONCAT110(uVar32,Var41);
646: auVar43 = CONCAT111(uVar16,auVar42);
647: uVar34 = SUB161(auVar4 >> 0x70,0);
648: auVar44 = CONCAT112(uVar34,auVar43);
649: uVar54 = SUB161(auVar4 >> 0x38,0);
650: uVar53 = SUB161(auVar4 >> 0x30,0);
651: uVar52 = SUB161(auVar4 >> 0x28,0);
652: uVar51 = SUB161(auVar4 >> 0x20,0);
653: auVar50 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
654: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
655: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
656: (SUB163(CONCAT214(SUB162(CONCAT115(uVar12,
657: CONCAT114(uVar54,SUB1614(auVar4,0))) >> 0x70,0),
658: CONCAT113(uVar11,SUB1613(auVar4,0))) >> 0x68,0),
659: CONCAT112(uVar53,SUB1612(auVar4,0))) >> 0x60,0),
660: CONCAT111(uVar10,SUB1611(auVar4,0))) >> 0x58,0),
661: CONCAT110(uVar52,SUB1610(auVar4,0))) >> 0x50,0),
662: CONCAT19(uVar5,SUB169(auVar4,0))) >> 0x48,0),
663: CONCAT18(uVar51,SUB168(auVar4,0))) >> 0x40,0),
664: puVar1[3])) << 0x38) >> 0x30,0),puVar1[2])) <<
665: 0x28) >> 0x20,0),puVar1[1]),
666: (SUB163(auVar4,0) >> 8) << 0x10) >> 0x10,0),
667: *puVar1)) << 8;
668: uVar31 = SUB161(auVar48 >> 0x40,0);
669: uVar28 = CONCAT12(SUB161(auVar48 >> 0x48,0),CONCAT11(0xff,uVar31));
670: uVar33 = SUB161(auVar48 >> 0x50,0);
671: uVar29 = CONCAT14(uVar33,CONCAT13(0xff,uVar28));
672: uVar35 = SUB161(auVar48 >> 0x58,0);
673: *(undefined (*) [16])(puVar21 + lVar24 * 4) =
674: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
675: SUB169(CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(
676: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
677: (SUB163(CONCAT214(SUB162(CONCAT115(0xff,CONCAT114(
678: puVar1[3],SUB1614(auVar50,0))) >> 0x70,0),
679: CONCAT113(SUB161(auVar48 >> 0x18,0),
680: SUB1613(auVar50,0))) >> 0x68,0),
681: CONCAT112(SUB161(auVar4 >> 0x18,0),
682: SUB1612(auVar50,0))) >> 0x60,0),
683: CONCAT111(0xff,SUB1611(auVar50,0))) >> 0x58,0),
684: CONCAT110(puVar1[2],SUB1610(auVar50,0))) >> 0x50,0
685: ),CONCAT19(SUB161(auVar48 >> 0x10,0),
686: SUB169(auVar50,0))) >> 0x48,0),
687: CONCAT18(SUB161(auVar4 >> 0x10,0),
688: SUB168(auVar50,0))) >> 0x40,0),
689: SUB168(auVar50,0)) >> 0x38,0) &
690: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
691: ,0) |
692: SUB169((undefined  [16])0xff00000000000000 >> 0x38
693: ,0),(SUB167(auVar50,0) >> 0x18) << 0x30) >>
694: 0x30,0),SUB161(auVar48 >> 8,0)),
695: (SUB165(auVar50,0) >> 0x10) << 0x20) >> 0x20,0),
696: SUB164(auVar50,0)) >> 0x18,0) &
697: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0) |
698: SUB1613((undefined  [16])0xff000000 >> 0x18,0),
699: (SUB163(auVar50,0) >> 8) << 0x10) >> 0x10,0),
700: SUB162(auVar4,0) & 0xff | SUB162(auVar48,0) << 8);
701: puVar1 = puVar21 + lVar24 * 4 + 0x10;
702: *puVar1 = uVar51;
703: puVar1[1] = SUB161(auVar48 >> 0x20,0);
704: puVar1[2] = uVar5;
705: puVar1[3] = 0xff;
706: puVar1[4] = uVar52;
707: puVar1[5] = SUB161(auVar48 >> 0x28,0);
708: puVar1[6] = uVar10;
709: puVar1[7] = 0xff;
710: puVar1[8] = uVar53;
711: puVar1[9] = SUB161(auVar48 >> 0x30,0);
712: puVar1[10] = uVar11;
713: puVar1[0xb] = 0xff;
714: puVar1[0xc] = uVar54;
715: puVar1[0xd] = SUB161(auVar48 >> 0x38,0);
716: puVar1[0xe] = uVar12;
717: puVar1[0xf] = 0xff;
718: *(undefined (*) [16])(puVar21 + lVar24 * 4 + 0x20) =
719: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
720: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
721: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
722: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(0xff,
723: CONCAT114(uVar14,CONCAT113(uVar17,auVar44))) >>
724: 0x70,0),CONCAT113(uVar35,auVar44)) >> 0x68,0),
725: CONCAT112(uVar47,auVar43)) >> 0x60,0),
726: CONCAT111(0xff,auVar42)) >> 0x58,0),
727: CONCAT110(uVar13,Var41)) >> 0x50,0),
728: CONCAT19(uVar33,Var40)) >> 0x48,0),
729: CONCAT18(uVar46,uVar39)) >> 0x40,0),
730: (((ulong)CONCAT16(uVar35,CONCAT15(0xff,uVar29)) &
731: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
732: (uVar38 >> 0x18) << 0x30) >> 0x30,0),
733: (((uint6)uVar29 & 0xff0000) >> 0x10) << 0x28) >>
734: 0x28,0),(uVar37 >> 0x10) << 0x20) >> 0x20,0),
735: ((uVar28 & 0xff00) >> 8) << 0x18) >> 0x18,0),
736: (uVar36 >> 8) << 0x10) >> 0x10,0),CONCAT11(uVar31,uVar45));
737: puVar1 = puVar21 + lVar24 * 4 + 0x30;
738: *puVar1 = uVar30;
739: puVar1[1] = SUB161(auVar48 >> 0x60,0);
740: puVar1[2] = uVar15;
741: puVar1[3] = 0xff;
742: puVar1[4] = uVar32;
743: puVar1[5] = SUB161(auVar48 >> 0x68,0);
744: puVar1[6] = uVar16;
745: puVar1[7] = 0xff;
746: puVar1[8] = uVar34;
747: puVar1[9] = SUB161(auVar48 >> 0x70,0);
748: puVar1[10] = uVar17;
749: puVar1[0xb] = 0xff;
750: puVar1[0xc] = SUB161(auVar4 >> 0x78,0);
751: puVar1[0xd] = SUB161(auVar48 >> 0x78,0);
752: puVar1[0xe] = uVar18;
753: puVar1[0xf] = 0xff;
754: lVar24 = lVar24 + 0x10;
755: } while (uVar26 < uVar6 >> 4);
756: puVar21 = puVar21 + (ulong)uVar27 * 4;
757: uVar26 = uVar27;
758: if (uVar6 != uVar27) {
759: code_r0x00122660:
760: do {
761: uVar19 = (ulong)uVar26;
762: uVar26 = uVar26 + 1;
763: puVar21[2] = puVar25[uVar19];
764: puVar21[1] = puVar2[uVar19];
765: uVar5 = puVar7[uVar19];
766: puVar21[3] = 0xff;
767: *puVar21 = uVar5;
768: puVar21 = puVar21 + 4;
769: } while (uVar26 < uVar6);
770: }
771: goto code_r0x00122470;
772: code_r0x00122343:
773: lVar24 = 0;
774: uVar26 = 0;
775: do {
776: auVar4 = *(undefined (*) [16])(puVar25 + lVar24);
777: uVar26 = uVar26 + 1;
778: puVar1 = puVar7 + lVar24;
779: uVar5 = puVar1[4];
780: uVar10 = puVar1[5];
781: uVar11 = puVar1[6];
782: uVar12 = puVar1[7];
783: uVar13 = puVar1[10];
784: uVar14 = puVar1[0xb];
785: uVar15 = puVar1[0xc];
786: uVar16 = puVar1[0xd];
787: uVar17 = puVar1[0xe];
788: uVar18 = puVar1[0xf];
789: auVar48 = *(undefined (*) [16])(puVar2 + lVar24);
790: uVar45 = SUB161(auVar4 >> 0x40,0);
791: uVar36 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar1[8],uVar45));
792: uVar46 = SUB161(auVar4 >> 0x50,0);
793: uVar37 = CONCAT14(uVar46,CONCAT13(puVar1[9],uVar36));
794: uVar47 = SUB161(auVar4 >> 0x58,0);
795: uVar38 = CONCAT16(uVar47,CONCAT15(uVar13,uVar37));
796: uVar39 = CONCAT17(uVar14,uVar38);
797: uVar30 = SUB161(auVar4 >> 0x60,0);
798: Var40 = CONCAT18(uVar30,uVar39);
799: Var41 = CONCAT19(uVar15,Var40);
800: uVar32 = SUB161(auVar4 >> 0x68,0);
801: auVar42 = CONCAT110(uVar32,Var41);
802: auVar43 = CONCAT111(uVar16,auVar42);
803: uVar34 = SUB161(auVar4 >> 0x70,0);
804: auVar44 = CONCAT112(uVar34,auVar43);
805: uVar54 = SUB161(auVar4 >> 0x38,0);
806: uVar53 = SUB161(auVar4 >> 0x30,0);
807: uVar52 = SUB161(auVar4 >> 0x28,0);
808: uVar51 = SUB161(auVar4 >> 0x20,0);
809: auVar50 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
810: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
811: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
812: (SUB163(CONCAT214(SUB162(CONCAT115(uVar12,
813: CONCAT114(uVar54,SUB1614(auVar4,0))) >> 0x70,0),
814: CONCAT113(uVar11,SUB1613(auVar4,0))) >> 0x68,0),
815: CONCAT112(uVar53,SUB1612(auVar4,0))) >> 0x60,0),
816: CONCAT111(uVar10,SUB1611(auVar4,0))) >> 0x58,0),
817: CONCAT110(uVar52,SUB1610(auVar4,0))) >> 0x50,0),
818: CONCAT19(uVar5,SUB169(auVar4,0))) >> 0x48,0),
819: CONCAT18(uVar51,SUB168(auVar4,0))) >> 0x40,0),
820: puVar1[3])) << 0x38) >> 0x30,0),puVar1[2])) <<
821: 0x28) >> 0x20,0),puVar1[1]),
822: (SUB163(auVar4,0) >> 8) << 0x10) >> 0x10,0),
823: *puVar1)) << 8;
824: uVar31 = SUB161(auVar48 >> 0x40,0);
825: uVar28 = CONCAT12(SUB161(auVar48 >> 0x48,0),CONCAT11(0xff,uVar31));
826: uVar33 = SUB161(auVar48 >> 0x50,0);
827: uVar29 = CONCAT14(uVar33,CONCAT13(0xff,uVar28));
828: uVar35 = SUB161(auVar48 >> 0x58,0);
829: *(undefined (*) [16])(puVar21 + lVar24 * 4) =
830: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
831: SUB169(CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(
832: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
833: (SUB163(CONCAT214(SUB162(CONCAT115(0xff,CONCAT114(
834: puVar1[3],SUB1614(auVar50,0))) >> 0x70,0),
835: CONCAT113(SUB161(auVar48 >> 0x18,0),
836: SUB1613(auVar50,0))) >> 0x68,0),
837: CONCAT112(SUB161(auVar4 >> 0x18,0),
838: SUB1612(auVar50,0))) >> 0x60,0),
839: CONCAT111(0xff,SUB1611(auVar50,0))) >> 0x58,0),
840: CONCAT110(puVar1[2],SUB1610(auVar50,0))) >> 0x50,0
841: ),CONCAT19(SUB161(auVar48 >> 0x10,0),
842: SUB169(auVar50,0))) >> 0x48,0),
843: CONCAT18(SUB161(auVar4 >> 0x10,0),
844: SUB168(auVar50,0))) >> 0x40,0),
845: SUB168(auVar50,0)) >> 0x38,0) &
846: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
847: ,0) |
848: SUB169((undefined  [16])0xff00000000000000 >> 0x38
849: ,0),(SUB167(auVar50,0) >> 0x18) << 0x30) >>
850: 0x30,0),SUB161(auVar48 >> 8,0)),
851: (SUB165(auVar50,0) >> 0x10) << 0x20) >> 0x20,0),
852: SUB164(auVar50,0)) >> 0x18,0) &
853: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0) |
854: SUB1613((undefined  [16])0xff000000 >> 0x18,0),
855: (SUB163(auVar50,0) >> 8) << 0x10) >> 0x10,0),
856: SUB162(auVar4,0) & 0xff | SUB162(auVar48,0) << 8);
857: puVar1 = puVar21 + lVar24 * 4 + 0x10;
858: *puVar1 = uVar51;
859: puVar1[1] = SUB161(auVar48 >> 0x20,0);
860: puVar1[2] = uVar5;
861: puVar1[3] = 0xff;
862: puVar1[4] = uVar52;
863: puVar1[5] = SUB161(auVar48 >> 0x28,0);
864: puVar1[6] = uVar10;
865: puVar1[7] = 0xff;
866: puVar1[8] = uVar53;
867: puVar1[9] = SUB161(auVar48 >> 0x30,0);
868: puVar1[10] = uVar11;
869: puVar1[0xb] = 0xff;
870: puVar1[0xc] = uVar54;
871: puVar1[0xd] = SUB161(auVar48 >> 0x38,0);
872: puVar1[0xe] = uVar12;
873: puVar1[0xf] = 0xff;
874: *(undefined (*) [16])(puVar21 + lVar24 * 4 + 0x20) =
875: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
876: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
877: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
878: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(0xff,
879: CONCAT114(uVar14,CONCAT113(uVar17,auVar44))) >>
880: 0x70,0),CONCAT113(uVar35,auVar44)) >> 0x68,0),
881: CONCAT112(uVar47,auVar43)) >> 0x60,0),
882: CONCAT111(0xff,auVar42)) >> 0x58,0),
883: CONCAT110(uVar13,Var41)) >> 0x50,0),
884: CONCAT19(uVar33,Var40)) >> 0x48,0),
885: CONCAT18(uVar46,uVar39)) >> 0x40,0),
886: (((ulong)CONCAT16(uVar35,CONCAT15(0xff,uVar29)) &
887: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
888: (uVar38 >> 0x18) << 0x30) >> 0x30,0),
889: (((uint6)uVar29 & 0xff0000) >> 0x10) << 0x28) >>
890: 0x28,0),(uVar37 >> 0x10) << 0x20) >> 0x20,0),
891: ((uVar28 & 0xff00) >> 8) << 0x18) >> 0x18,0),
892: (uVar36 >> 8) << 0x10) >> 0x10,0),CONCAT11(uVar31,uVar45));
893: puVar1 = puVar21 + lVar24 * 4 + 0x30;
894: *puVar1 = uVar30;
895: puVar1[1] = SUB161(auVar48 >> 0x60,0);
896: puVar1[2] = uVar15;
897: puVar1[3] = 0xff;
898: puVar1[4] = uVar32;
899: puVar1[5] = SUB161(auVar48 >> 0x68,0);
900: puVar1[6] = uVar16;
901: puVar1[7] = 0xff;
902: puVar1[8] = uVar34;
903: puVar1[9] = SUB161(auVar48 >> 0x70,0);
904: puVar1[10] = uVar17;
905: puVar1[0xb] = 0xff;
906: puVar1[0xc] = SUB161(auVar4 >> 0x78,0);
907: puVar1[0xd] = SUB161(auVar48 >> 0x78,0);
908: puVar1[0xe] = uVar18;
909: puVar1[0xf] = 0xff;
910: lVar24 = lVar24 + 0x10;
911: } while (uVar26 < uVar6 >> 4);
912: puVar21 = puVar21 + (ulong)uVar27 * 4;
913: uVar26 = uVar27;
914: if (uVar6 != uVar27) {
915: code_r0x001225e0:
916: do {
917: uVar19 = (ulong)uVar26;
918: uVar26 = uVar26 + 1;
919: *puVar21 = puVar25[uVar19];
920: puVar21[1] = puVar2[uVar19];
921: uVar5 = puVar7[uVar19];
922: puVar21[3] = 0xff;
923: puVar21[2] = uVar5;
924: puVar21 = puVar21 + 4;
925: } while (uVar26 < uVar6);
926: }
927: goto code_r0x001222a8;
928: }
929: 
