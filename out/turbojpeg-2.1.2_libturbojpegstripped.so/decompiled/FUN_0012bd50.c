1: 
2: /* WARNING: Type propagation algorithm not settling */
3: 
4: void FUN_0012bd50(long param_1,long *param_2,uint param_3,undefined8 *param_4,int param_5)
5: 
6: {
7: undefined *puVar1;
8: undefined *puVar2;
9: undefined *puVar3;
10: undefined auVar4 [16];
11: undefined uVar5;
12: uint uVar6;
13: long lVar7;
14: long lVar8;
15: undefined *puVar9;
16: undefined uVar10;
17: undefined uVar11;
18: undefined uVar12;
19: undefined uVar13;
20: undefined uVar14;
21: undefined uVar15;
22: undefined uVar16;
23: undefined uVar17;
24: undefined uVar18;
25: undefined uVar19;
26: undefined uVar20;
27: uint uVar21;
28: ulong uVar22;
29: ulong uVar23;
30: undefined *puVar24;
31: undefined *puVar25;
32: undefined8 *puVar26;
33: ulong uVar27;
34: long lVar28;
35: long lVar29;
36: uint uVar30;
37: uint3 uVar31;
38: uint7 uVar33;
39: undefined uVar40;
40: undefined uVar41;
41: undefined uVar42;
42: undefined uVar43;
43: undefined uVar44;
44: undefined uVar45;
45: undefined uVar46;
46: undefined uVar47;
47: undefined uVar48;
48: uint3 uVar49;
49: undefined uVar51;
50: undefined uVar52;
51: undefined uVar53;
52: undefined uVar57;
53: undefined auVar54 [16];
54: undefined auVar56 [16];
55: undefined auVar58 [12];
56: uint5 uVar32;
57: undefined8 uVar34;
58: unkbyte9 Var35;
59: unkbyte10 Var36;
60: undefined auVar37 [11];
61: undefined auVar38 [12];
62: undefined auVar39 [13];
63: uint5 uVar50;
64: undefined auVar55 [16];
65: 
66: uVar6 = *(uint *)(param_1 + 0x88);
67: switch(*(undefined4 *)(param_1 + 0x40)) {
68: case 6:
69: while (param_5 = param_5 + -1, puVar26 = param_4, -1 < param_5) {
70: while( true ) {
71: uVar23 = (ulong)param_3;
72: param_4 = puVar26 + 1;
73: param_3 = param_3 + 1;
74: lVar28 = *(long *)(*param_2 + uVar23 * 8);
75: lVar7 = *(long *)(param_2[1] + uVar23 * 8);
76: lVar8 = *(long *)(param_2[2] + uVar23 * 8);
77: puVar9 = (undefined *)*puVar26;
78: if (uVar6 == 0) break;
79: lVar29 = 0;
80: puVar24 = puVar9;
81: do {
82: puVar25 = puVar24 + 3;
83: *puVar24 = *(undefined *)(lVar28 + lVar29);
84: puVar24[1] = *(undefined *)(lVar7 + lVar29);
85: puVar3 = (undefined *)(lVar8 + lVar29);
86: lVar29 = lVar29 + 1;
87: puVar24[2] = *puVar3;
88: puVar24 = puVar25;
89: } while (puVar25 != puVar9 + (ulong)(uVar6 - 1) * 3 + 3);
90: param_5 = param_5 + -1;
91: puVar26 = param_4;
92: if (param_5 < 0) {
93: return;
94: }
95: }
96: }
97: break;
98: case 7:
99: case 0xc:
100: uVar23 = (ulong)uVar6;
101: uVar21 = uVar6 & 0xfffffff0;
102: code_r0x0012c668:
103: while( true ) {
104: do {
105: param_5 = param_5 + -1;
106: if (param_5 < 0) {
107: return;
108: }
109: uVar22 = (ulong)param_3;
110: puVar26 = param_4 + 1;
111: param_3 = param_3 + 1;
112: puVar9 = *(undefined **)(*param_2 + uVar22 * 8);
113: puVar24 = *(undefined **)(param_2[1] + uVar22 * 8);
114: puVar3 = *(undefined **)(param_2[2] + uVar22 * 8);
115: puVar25 = (undefined *)*param_4;
116: param_4 = puVar26;
117: } while (uVar6 == 0);
118: puVar1 = puVar25 + uVar23 * 4;
119: if ((0xf < uVar6 &&
120: ((puVar1 <= puVar24 || puVar24 + uVar23 <= puVar25) &&
121: (puVar9 + uVar23 <= puVar25 || puVar1 <= puVar9))) &&
122: (puVar3 + uVar23 <= puVar25 || puVar1 <= puVar3)) break;
123: lVar28 = 0;
124: do {
125: *puVar25 = puVar9[lVar28];
126: puVar25[1] = puVar24[lVar28];
127: uVar5 = puVar3[lVar28];
128: lVar28 = lVar28 + 1;
129: puVar25[3] = 0xff;
130: puVar25[2] = uVar5;
131: puVar25 = puVar25 + 4;
132: } while (lVar28 != (ulong)(uVar6 - 1) + 1);
133: }
134: if (0xe < uVar6 - 1) goto code_r0x0012c705;
135: uVar30 = 0;
136: goto code_r0x0012c783;
137: case 8:
138: while (param_5 = param_5 + -1, -1 < param_5) {
139: uVar23 = (ulong)param_3;
140: puVar26 = param_4 + 1;
141: param_3 = param_3 + 1;
142: lVar28 = *(long *)(*param_2 + uVar23 * 8);
143: lVar7 = *(long *)(param_2[1] + uVar23 * 8);
144: lVar8 = *(long *)(param_2[2] + uVar23 * 8);
145: puVar9 = (undefined *)*param_4;
146: param_4 = puVar26;
147: if (uVar6 != 0) {
148: lVar29 = 0;
149: puVar24 = puVar9;
150: do {
151: puVar25 = puVar24 + 3;
152: puVar24[2] = *(undefined *)(lVar28 + lVar29);
153: puVar24[1] = *(undefined *)(lVar7 + lVar29);
154: puVar3 = (undefined *)(lVar8 + lVar29);
155: lVar29 = lVar29 + 1;
156: *puVar24 = *puVar3;
157: puVar24 = puVar25;
158: } while (puVar25 != puVar9 + (ulong)(uVar6 - 1) * 3 + 3);
159: }
160: }
161: break;
162: case 9:
163: case 0xd:
164: uVar23 = (ulong)uVar6;
165: uVar21 = uVar6 & 0xfffffff0;
166: code_r0x0012cae8:
167: while( true ) {
168: do {
169: param_5 = param_5 + -1;
170: if (param_5 < 0) {
171: return;
172: }
173: uVar22 = (ulong)param_3;
174: puVar26 = param_4 + 1;
175: param_3 = param_3 + 1;
176: puVar9 = *(undefined **)(*param_2 + uVar22 * 8);
177: puVar24 = *(undefined **)(param_2[1] + uVar22 * 8);
178: puVar3 = *(undefined **)(param_2[2] + uVar22 * 8);
179: puVar25 = (undefined *)*param_4;
180: param_4 = puVar26;
181: } while (uVar6 == 0);
182: puVar1 = puVar25 + uVar23 * 4;
183: if ((0xf < uVar6 &&
184: ((puVar1 <= puVar9 || puVar9 + uVar23 <= puVar25) &&
185: (puVar24 + uVar23 <= puVar25 || puVar1 <= puVar24))) &&
186: (puVar3 + uVar23 <= puVar25 || puVar1 <= puVar3)) break;
187: lVar28 = 0;
188: do {
189: puVar25[2] = puVar9[lVar28];
190: puVar25[1] = puVar24[lVar28];
191: uVar5 = puVar3[lVar28];
192: lVar28 = lVar28 + 1;
193: puVar25[3] = 0xff;
194: *puVar25 = uVar5;
195: puVar25 = puVar25 + 4;
196: } while (lVar28 != (ulong)(uVar6 - 1) + 1);
197: }
198: if (0xe < uVar6 - 1) goto code_r0x0012cb89;
199: uVar30 = 0;
200: goto code_r0x0012cc03;
201: case 10:
202: case 0xe:
203: uVar23 = (ulong)uVar6;
204: auVar38 = CONCAT48(0xffffffff,0xffffffffffffffff);
205: uVar21 = uVar6 & 0xfffffff0;
206: code_r0x0012bdc8:
207: while( true ) {
208: do {
209: param_5 = param_5 + -1;
210: if (param_5 < 0) {
211: return;
212: }
213: uVar22 = (ulong)param_3;
214: puVar26 = param_4 + 1;
215: param_3 = param_3 + 1;
216: puVar9 = *(undefined **)(*param_2 + uVar22 * 8);
217: puVar24 = *(undefined **)(param_2[1] + uVar22 * 8);
218: puVar3 = *(undefined **)(param_2[2] + uVar22 * 8);
219: puVar25 = (undefined *)*param_4;
220: param_4 = puVar26;
221: } while (uVar6 == 0);
222: puVar1 = puVar25 + uVar23 * 4;
223: if ((0xf < uVar6 &&
224: ((puVar1 <= puVar9 || puVar9 + uVar23 <= puVar25) &&
225: (puVar24 + uVar23 <= puVar25 || puVar1 <= puVar24))) &&
226: (puVar3 + uVar23 <= puVar25 || puVar1 <= puVar3)) break;
227: lVar28 = 0;
228: do {
229: puVar25[3] = puVar9[lVar28];
230: puVar25[2] = puVar24[lVar28];
231: uVar5 = puVar3[lVar28];
232: lVar28 = lVar28 + 1;
233: *puVar25 = 0xff;
234: puVar25[1] = uVar5;
235: puVar25 = puVar25 + 4;
236: } while (lVar28 != (ulong)(uVar6 - 1) + 1);
237: }
238: if (0xe < uVar6 - 1) goto code_r0x0012be69;
239: uVar30 = 0;
240: goto code_r0x0012beeb;
241: case 0xb:
242: case 0xf:
243: uVar23 = (ulong)uVar6;
244: auVar38 = CONCAT48(0xffffffff,0xffffffffffffffff);
245: uVar21 = uVar6 & 0xfffffff0;
246: code_r0x0012c1d8:
247: while( true ) {
248: do {
249: param_5 = param_5 + -1;
250: if (param_5 < 0) {
251: return;
252: }
253: uVar22 = (ulong)param_3;
254: puVar26 = param_4 + 1;
255: param_3 = param_3 + 1;
256: puVar9 = *(undefined **)(*param_2 + uVar22 * 8);
257: puVar24 = *(undefined **)(param_2[1] + uVar22 * 8);
258: puVar3 = *(undefined **)(param_2[2] + uVar22 * 8);
259: puVar25 = (undefined *)*param_4;
260: param_4 = puVar26;
261: } while (uVar6 == 0);
262: puVar1 = puVar25 + uVar23 * 4;
263: if ((0xf < uVar6 &&
264: ((puVar1 <= puVar9 || puVar9 + uVar23 <= puVar25) &&
265: (puVar24 + uVar23 <= puVar25 || puVar1 <= puVar24))) &&
266: (puVar3 + uVar23 <= puVar25 || puVar1 <= puVar3)) break;
267: lVar28 = 0;
268: do {
269: puVar25[1] = puVar9[lVar28];
270: puVar25[2] = puVar24[lVar28];
271: uVar5 = puVar3[lVar28];
272: lVar28 = lVar28 + 1;
273: *puVar25 = 0xff;
274: puVar25[3] = uVar5;
275: puVar25 = puVar25 + 4;
276: } while (lVar28 != (ulong)(uVar6 - 1) + 1);
277: }
278: if (0xe < uVar6 - 1) goto code_r0x0012c279;
279: uVar30 = 0;
280: goto code_r0x0012c2fb;
281: default:
282: while (param_5 = param_5 + -1, -1 < param_5) {
283: uVar23 = (ulong)param_3;
284: puVar26 = param_4 + 1;
285: param_3 = param_3 + 1;
286: lVar28 = *(long *)(*param_2 + uVar23 * 8);
287: lVar7 = *(long *)(param_2[1] + uVar23 * 8);
288: lVar8 = *(long *)(param_2[2] + uVar23 * 8);
289: puVar9 = (undefined *)*param_4;
290: param_4 = puVar26;
291: if (uVar6 != 0) {
292: lVar29 = 0;
293: puVar24 = puVar9;
294: do {
295: puVar25 = puVar24 + 3;
296: *puVar24 = *(undefined *)(lVar28 + lVar29);
297: puVar24[1] = *(undefined *)(lVar7 + lVar29);
298: puVar3 = (undefined *)(lVar8 + lVar29);
299: lVar29 = lVar29 + 1;
300: puVar24[2] = *puVar3;
301: puVar24 = puVar25;
302: } while (puVar25 != puVar9 + (ulong)(uVar6 - 1) * 3 + 3);
303: }
304: }
305: }
306: return;
307: code_r0x0012c279:
308: lVar28 = 0;
309: uVar30 = 0;
310: do {
311: auVar4 = *(undefined (*) [16])(puVar9 + lVar28);
312: uVar30 = uVar30 + 1;
313: puVar1 = puVar24 + lVar28;
314: uVar5 = puVar1[2];
315: uVar10 = puVar1[10];
316: uVar11 = puVar1[0xb];
317: uVar12 = puVar1[0xc];
318: uVar13 = puVar1[0xd];
319: uVar14 = puVar1[0xe];
320: uVar15 = puVar1[0xf];
321: puVar2 = puVar3 + lVar28;
322: uVar16 = *puVar2;
323: uVar17 = puVar2[1];
324: uVar18 = puVar2[2];
325: uVar19 = puVar2[3];
326: uVar20 = puVar2[4];
327: uVar41 = puVar2[5];
328: uVar43 = puVar2[6];
329: uVar45 = puVar2[7];
330: uVar46 = puVar2[10];
331: uVar47 = puVar2[0xb];
332: uVar48 = puVar2[0xc];
333: uVar51 = puVar2[0xd];
334: uVar52 = puVar2[0xe];
335: uVar53 = puVar2[0xf];
336: auVar55 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
337: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
338: (puVar1[7],
339: CONCAT114(0xff,SUB1614(CONCAT412(0xffffffff,
340: auVar38),0))) >>
341: 0x70,0),CONCAT113(puVar1[6],
342: SUB1613(CONCAT412(0xffffffff,
343: auVar38),0)))
344: >> 0x68,0),CONCAT112(0xff,auVar38)) >> 0x60,0),
345: CONCAT111(puVar1[5],SUB1211(auVar38,0))) >> 0x58,0
346: ),CONCAT110(0xff,SUB1210(auVar38,0))) >> 0x50,0),
347: CONCAT19(puVar1[4],SUB129(auVar38,0))) >> 0x48,0),
348: CONCAT18(0xff,0xffffffffffffffff)) >> 0x40,0),
349: puVar1[3])) << 0x38 | (undefined  [16])0xffffffffffffff;
350: auVar56 = CONCAT97(SUB169(auVar55 >> 0x38,0),0xff000000000000) | (undefined  [16])0xffffffffffff
351: ;
352: auVar54 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(
353: auVar56 >> 0x30,0),uVar5) |
354: SUB1611((undefined  [16])0xffffffffff >> 0x28,0),
355: 0xff00000000) >> 0x20,0) |
356: SUB1612((undefined  [16])0xffffffff >> 0x20,0),
357: puVar1[1]) |
358: SUB1613((undefined  [16])0xffffff >> 0x18,0),
359: 0xff0000) >> 0x10,0) |
360: SUB1614((undefined  [16])0xffff >> 0x10,0),*puVar1)) << 8 |
361: (undefined  [16])0xff;
362: uVar49 = CONCAT12(0xff,CONCAT11(puVar1[8],0xff));
363: uVar50 = CONCAT14(0xff,CONCAT13(puVar1[9],uVar49));
364: uVar33 = CONCAT16(0xff,CONCAT15(uVar10,uVar50));
365: uVar34 = CONCAT17(uVar11,uVar33);
366: Var35 = CONCAT18(0xff,uVar34);
367: Var36 = CONCAT19(uVar12,Var35);
368: auVar37 = CONCAT110(0xff,Var36);
369: auVar58 = CONCAT111(uVar13,auVar37);
370: auVar39 = CONCAT112(0xff,auVar58);
371: uVar40 = SUB161(auVar4 >> 0x40,0);
372: uVar31 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar2[8],uVar40));
373: uVar42 = SUB161(auVar4 >> 0x50,0);
374: uVar32 = CONCAT14(uVar42,CONCAT13(puVar2[9],uVar31));
375: uVar44 = SUB161(auVar4 >> 0x58,0);
376: puVar1 = puVar25 + lVar28 * 4 + 0x10;
377: *puVar1 = 0xff;
378: puVar1[1] = SUB161(auVar4 >> 0x20,0);
379: puVar1[2] = SUB161(auVar55 >> 0x48,0);
380: puVar1[3] = uVar20;
381: puVar1[4] = SUB161(auVar55 >> 0x50,0);
382: puVar1[5] = SUB161(auVar4 >> 0x28,0);
383: puVar1[6] = SUB161(auVar55 >> 0x58,0);
384: puVar1[7] = uVar41;
385: puVar1[8] = SUB161(auVar55 >> 0x60,0);
386: puVar1[9] = SUB161(auVar4 >> 0x30,0);
387: puVar1[10] = SUB161(auVar55 >> 0x68,0);
388: puVar1[0xb] = uVar43;
389: puVar1[0xc] = SUB161(auVar55 >> 0x70,0);
390: puVar1[0xd] = SUB161(auVar4 >> 0x38,0);
391: puVar1[0xe] = SUB161(auVar55 >> 0x78,0);
392: puVar1[0xf] = uVar45;
393: *(undefined (*) [16])(puVar25 + lVar28 * 4) =
394: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81
395: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
396: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
397: CONCAT214(SUB162(CONCAT115(uVar19,CONCAT114(SUB161
398: (auVar55 >> 0x38,0),SUB1614(auVar54,0))) >> 0x70,0
399: ),CONCAT113(SUB161(auVar4 >> 0x18,0),
400: SUB1613(auVar54,0))) >> 0x68,0),
401: CONCAT112(SUB161(auVar56 >> 0x30,0),
402: SUB1612(auVar54,0))) >> 0x60,0),
403: CONCAT111(uVar18,SUB1611(auVar54,0))) >> 0x58,0),
404: CONCAT110(uVar5,SUB1610(auVar54,0))) >> 0x50,0),
405: CONCAT19(SUB161(auVar4 >> 0x10,0),
406: SUB169(auVar54,0))) >> 0x48,0),
407: CONCAT18(0xff,SUB168(auVar54,0))) >> 0x40,0),
408: uVar17),(SUB167(auVar54,0) >> 0x18) << 0x30) >>
409: 0x30,0),SUB161(auVar4 >> 8,0)),
410: (SUB165(auVar54,0) >> 0x10) << 0x20) >> 0x20,0),
411: uVar16),(SUB163(auVar54,0) >> 8) << 0x10) >> 0x10,0),
412: SUB162(auVar4,0) << 8) | (undefined  [16])0xff;
413: puVar1 = puVar25 + lVar28 * 4 + 0x30;
414: *puVar1 = 0xff;
415: puVar1[1] = SUB161(auVar4 >> 0x60,0);
416: puVar1[2] = uVar12;
417: puVar1[3] = uVar48;
418: puVar1[4] = 0xff;
419: puVar1[5] = SUB161(auVar4 >> 0x68,0);
420: puVar1[6] = uVar13;
421: puVar1[7] = uVar51;
422: puVar1[8] = 0xff;
423: puVar1[9] = SUB161(auVar4 >> 0x70,0);
424: puVar1[10] = uVar14;
425: puVar1[0xb] = uVar52;
426: puVar1[0xc] = 0xff;
427: puVar1[0xd] = SUB161(auVar4 >> 0x78,0);
428: puVar1[0xe] = uVar15;
429: puVar1[0xf] = uVar53;
430: *(undefined (*) [16])(puVar25 + lVar28 * 4 + 0x20) =
431: ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
432: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
433: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
434: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
435: CONCAT115(uVar47,CONCAT114(uVar11,CONCAT113(uVar14
436: ,auVar39))) >> 0x70,0),CONCAT113(uVar44,auVar39))
437: >> 0x68,0),CONCAT112(0xff,auVar58)) >> 0x60,0),
438: CONCAT111(uVar46,auVar37)) >> 0x58,0),
439: CONCAT110(uVar10,Var36)) >> 0x50,0),
440: CONCAT19(uVar42,Var35)) >> 0x48,0),
441: CONCAT18(0xff,uVar34)) >> 0x40,0),
442: (((ulong)CONCAT16(uVar44,CONCAT15(uVar46,uVar32))
443: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
444: (uVar33 >> 0x18) << 0x30) >> 0x30,0),
445: (((uint6)uVar32 & 0xff0000) >> 0x10) << 0x28) >>
446: 0x28,0),(uVar50 >> 0x10) << 0x20) >> 0x20,0),
447: ((uVar31 & 0xff00) >> 8) << 0x18) >> 0x18,0),
448: (uVar49 >> 8) << 0x10) >> 0x10,0),uVar40)) << 8 |
449: (undefined  [16])0xff;
450: lVar28 = lVar28 + 0x10;
451: } while (uVar30 < uVar6 >> 4);
452: puVar25 = puVar25 + (ulong)uVar21 * 4;
453: uVar30 = uVar21;
454: if (uVar6 != uVar21) {
455: code_r0x0012c2fb:
456: uVar22 = (ulong)uVar30;
457: puVar25[1] = puVar9[uVar22];
458: puVar25[2] = puVar24[uVar22];
459: uVar5 = puVar3[uVar22];
460: *puVar25 = 0xff;
461: puVar25[3] = uVar5;
462: uVar22 = (ulong)(uVar30 + 1);
463: if (uVar30 + 1 < uVar6) {
464: puVar25[5] = puVar9[uVar22];
465: puVar25[6] = puVar24[uVar22];
466: uVar5 = puVar3[uVar22];
467: puVar25[4] = 0xff;
468: puVar25[7] = uVar5;
469: uVar22 = (ulong)(uVar30 + 2);
470: if (uVar30 + 2 < uVar6) {
471: puVar25[9] = puVar9[uVar22];
472: puVar25[10] = puVar24[uVar22];
473: uVar5 = puVar3[uVar22];
474: puVar25[8] = 0xff;
475: puVar25[0xb] = uVar5;
476: uVar22 = (ulong)(uVar30 + 3);
477: if (uVar30 + 3 < uVar6) {
478: puVar25[0xd] = puVar9[uVar22];
479: puVar25[0xe] = puVar24[uVar22];
480: uVar5 = puVar3[uVar22];
481: puVar25[0xc] = 0xff;
482: puVar25[0xf] = uVar5;
483: uVar22 = (ulong)(uVar30 + 4);
484: if (uVar30 + 4 < uVar6) {
485: puVar25[0x11] = puVar9[uVar22];
486: puVar25[0x12] = puVar24[uVar22];
487: uVar5 = puVar3[uVar22];
488: puVar25[0x10] = 0xff;
489: puVar25[0x13] = uVar5;
490: uVar22 = (ulong)(uVar30 + 5);
491: if (uVar30 + 5 < uVar6) {
492: puVar25[0x15] = puVar9[uVar22];
493: puVar25[0x16] = puVar24[uVar22];
494: uVar5 = puVar3[uVar22];
495: puVar25[0x14] = 0xff;
496: puVar25[0x17] = uVar5;
497: uVar22 = (ulong)(uVar30 + 6);
498: if (uVar30 + 6 < uVar6) {
499: puVar25[0x19] = puVar9[uVar22];
500: puVar25[0x1a] = puVar24[uVar22];
501: uVar5 = puVar3[uVar22];
502: puVar25[0x18] = 0xff;
503: puVar25[0x1b] = uVar5;
504: uVar22 = (ulong)(uVar30 + 7);
505: if (uVar30 + 7 < uVar6) {
506: puVar25[0x1d] = puVar9[uVar22];
507: puVar25[0x1e] = puVar24[uVar22];
508: uVar5 = puVar3[uVar22];
509: puVar25[0x1c] = 0xff;
510: puVar25[0x1f] = uVar5;
511: uVar22 = (ulong)(uVar30 + 8);
512: if (uVar30 + 8 < uVar6) {
513: puVar25[0x21] = puVar9[uVar22];
514: puVar25[0x22] = puVar24[uVar22];
515: uVar5 = puVar3[uVar22];
516: puVar25[0x20] = 0xff;
517: puVar25[0x23] = uVar5;
518: uVar22 = (ulong)(uVar30 + 9);
519: if (uVar30 + 9 < uVar6) {
520: puVar25[0x25] = puVar9[uVar22];
521: puVar25[0x26] = puVar24[uVar22];
522: uVar5 = puVar3[uVar22];
523: puVar25[0x24] = 0xff;
524: puVar25[0x27] = uVar5;
525: uVar22 = (ulong)(uVar30 + 10);
526: if (uVar30 + 10 < uVar6) {
527: puVar25[0x29] = puVar9[uVar22];
528: puVar25[0x2a] = puVar24[uVar22];
529: uVar5 = puVar3[uVar22];
530: puVar25[0x28] = 0xff;
531: puVar25[0x2b] = uVar5;
532: uVar22 = (ulong)(uVar30 + 0xb);
533: if (uVar30 + 0xb < uVar6) {
534: puVar25[0x2d] = puVar9[uVar22];
535: puVar25[0x2e] = puVar24[uVar22];
536: uVar5 = puVar3[uVar22];
537: puVar25[0x2c] = 0xff;
538: puVar25[0x2f] = uVar5;
539: uVar22 = (ulong)(uVar30 + 0xc);
540: if (uVar30 + 0xc < uVar6) {
541: puVar25[0x31] = puVar9[uVar22];
542: puVar25[0x32] = puVar24[uVar22];
543: uVar5 = puVar3[uVar22];
544: puVar25[0x30] = 0xff;
545: puVar25[0x33] = uVar5;
546: uVar22 = (ulong)(uVar30 + 0xd);
547: if (uVar30 + 0xd < uVar6) {
548: uVar27 = (ulong)(uVar30 + 0xe);
549: puVar25[0x35] = puVar9[uVar22];
550: puVar25[0x36] = puVar24[uVar22];
551: uVar5 = puVar3[uVar22];
552: puVar25[0x34] = 0xff;
553: puVar25[0x37] = uVar5;
554: if (uVar30 + 0xe < uVar6) {
555: puVar25[0x39] = puVar9[uVar27];
556: puVar25[0x3a] = puVar24[uVar27];
557: uVar5 = puVar3[uVar27];
558: puVar25[0x38] = 0xff;
559: puVar25[0x3b] = uVar5;
560: }
561: }
562: }
563: }
564: }
565: }
566: }
567: }
568: }
569: }
570: }
571: }
572: }
573: }
574: }
575: goto code_r0x0012c1d8;
576: code_r0x0012be69:
577: lVar28 = 0;
578: uVar30 = 0;
579: do {
580: auVar4 = *(undefined (*) [16])(puVar3 + lVar28);
581: uVar30 = uVar30 + 1;
582: puVar1 = puVar9 + lVar28;
583: uVar5 = *puVar1;
584: uVar10 = puVar1[1];
585: uVar11 = puVar1[2];
586: uVar12 = puVar1[3];
587: uVar13 = puVar1[4];
588: uVar14 = puVar1[5];
589: uVar15 = puVar1[6];
590: uVar16 = puVar1[7];
591: uVar17 = puVar1[10];
592: uVar18 = puVar1[0xb];
593: uVar19 = puVar1[0xc];
594: uVar20 = puVar1[0xd];
595: uVar41 = puVar1[0xe];
596: uVar43 = puVar1[0xf];
597: puVar2 = puVar24 + lVar28;
598: uVar45 = puVar2[2];
599: uVar46 = puVar2[10];
600: uVar47 = puVar2[0xb];
601: uVar48 = puVar2[0xc];
602: uVar51 = puVar2[0xd];
603: uVar52 = puVar2[0xe];
604: uVar53 = puVar2[0xf];
605: uVar40 = SUB161(auVar4 >> 0x40,0);
606: uVar31 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar1[8],uVar40));
607: uVar42 = SUB161(auVar4 >> 0x50,0);
608: uVar32 = CONCAT14(uVar42,CONCAT13(puVar1[9],uVar31));
609: uVar44 = SUB161(auVar4 >> 0x58,0);
610: auVar55 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
611: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
612: (puVar2[7],
613: CONCAT114(0xff,SUB1614(CONCAT412(0xffffffff,
614: auVar38),0))) >>
615: 0x70,0),CONCAT113(puVar2[6],
616: SUB1613(CONCAT412(0xffffffff,
617: auVar38),0)))
618: >> 0x68,0),CONCAT112(0xff,auVar38)) >> 0x60,0),
619: CONCAT111(puVar2[5],SUB1211(auVar38,0))) >> 0x58,0
620: ),CONCAT110(0xff,SUB1210(auVar38,0))) >> 0x50,0),
621: CONCAT19(puVar2[4],SUB129(auVar38,0))) >> 0x48,0),
622: CONCAT18(0xff,0xffffffffffffffff)) >> 0x40,0),
623: puVar2[3])) << 0x38 | (undefined  [16])0xffffffffffffff;
624: auVar56 = CONCAT97(SUB169(auVar55 >> 0x38,0),0xff000000000000) | (undefined  [16])0xffffffffffff
625: ;
626: auVar54 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(
627: auVar56 >> 0x30,0),uVar45) |
628: SUB1611((undefined  [16])0xffffffffff >> 0x28,0),
629: 0xff00000000) >> 0x20,0) |
630: SUB1612((undefined  [16])0xffffffff >> 0x20,0),
631: puVar2[1]) |
632: SUB1613((undefined  [16])0xffffff >> 0x18,0),
633: 0xff0000) >> 0x10,0) |
634: SUB1614((undefined  [16])0xffff >> 0x10,0),*puVar2)) << 8 |
635: (undefined  [16])0xff;
636: uVar49 = CONCAT12(0xff,CONCAT11(puVar2[8],0xff));
637: uVar50 = CONCAT14(0xff,CONCAT13(puVar2[9],uVar49));
638: uVar33 = CONCAT16(0xff,CONCAT15(uVar46,uVar50));
639: uVar34 = CONCAT17(uVar47,uVar33);
640: Var35 = CONCAT18(0xff,uVar34);
641: Var36 = CONCAT19(uVar48,Var35);
642: auVar37 = CONCAT110(0xff,Var36);
643: auVar58 = CONCAT111(uVar51,auVar37);
644: auVar39 = CONCAT112(0xff,auVar58);
645: puVar1 = puVar25 + lVar28 * 4 + 0x10;
646: *puVar1 = 0xff;
647: puVar1[1] = SUB161(auVar4 >> 0x20,0);
648: puVar1[2] = SUB161(auVar55 >> 0x48,0);
649: puVar1[3] = uVar13;
650: puVar1[4] = SUB161(auVar55 >> 0x50,0);
651: puVar1[5] = SUB161(auVar4 >> 0x28,0);
652: puVar1[6] = SUB161(auVar55 >> 0x58,0);
653: puVar1[7] = uVar14;
654: puVar1[8] = SUB161(auVar55 >> 0x60,0);
655: puVar1[9] = SUB161(auVar4 >> 0x30,0);
656: puVar1[10] = SUB161(auVar55 >> 0x68,0);
657: puVar1[0xb] = uVar15;
658: puVar1[0xc] = SUB161(auVar55 >> 0x70,0);
659: puVar1[0xd] = SUB161(auVar4 >> 0x38,0);
660: puVar1[0xe] = SUB161(auVar55 >> 0x78,0);
661: puVar1[0xf] = uVar16;
662: *(undefined (*) [16])(puVar25 + lVar28 * 4) =
663: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81
664: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
665: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
666: CONCAT214(SUB162(CONCAT115(uVar12,CONCAT114(SUB161
667: (auVar55 >> 0x38,0),SUB1614(auVar54,0))) >> 0x70,0
668: ),CONCAT113(SUB161(auVar4 >> 0x18,0),
669: SUB1613(auVar54,0))) >> 0x68,0),
670: CONCAT112(SUB161(auVar56 >> 0x30,0),
671: SUB1612(auVar54,0))) >> 0x60,0),
672: CONCAT111(uVar11,SUB1611(auVar54,0))) >> 0x58,0),
673: CONCAT110(uVar45,SUB1610(auVar54,0))) >> 0x50,0),
674: CONCAT19(SUB161(auVar4 >> 0x10,0),
675: SUB169(auVar54,0))) >> 0x48,0),
676: CONCAT18(0xff,SUB168(auVar54,0))) >> 0x40,0),
677: uVar10),(SUB167(auVar54,0) >> 0x18) << 0x30) >>
678: 0x30,0),SUB161(auVar4 >> 8,0)),
679: (SUB165(auVar54,0) >> 0x10) << 0x20) >> 0x20,0),
680: uVar5),(SUB163(auVar54,0) >> 8) << 0x10) >> 0x10,0),
681: SUB162(auVar4,0) << 8) | (undefined  [16])0xff;
682: puVar1 = puVar25 + lVar28 * 4 + 0x30;
683: *puVar1 = 0xff;
684: puVar1[1] = SUB161(auVar4 >> 0x60,0);
685: puVar1[2] = uVar48;
686: puVar1[3] = uVar19;
687: puVar1[4] = 0xff;
688: puVar1[5] = SUB161(auVar4 >> 0x68,0);
689: puVar1[6] = uVar51;
690: puVar1[7] = uVar20;
691: puVar1[8] = 0xff;
692: puVar1[9] = SUB161(auVar4 >> 0x70,0);
693: puVar1[10] = uVar52;
694: puVar1[0xb] = uVar41;
695: puVar1[0xc] = 0xff;
696: puVar1[0xd] = SUB161(auVar4 >> 0x78,0);
697: puVar1[0xe] = uVar53;
698: puVar1[0xf] = uVar43;
699: *(undefined (*) [16])(puVar25 + lVar28 * 4 + 0x20) =
700: ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
701: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
702: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
703: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
704: CONCAT115(uVar18,CONCAT114(uVar47,CONCAT113(uVar52
705: ,auVar39))) >> 0x70,0),CONCAT113(uVar44,auVar39))
706: >> 0x68,0),CONCAT112(0xff,auVar58)) >> 0x60,0),
707: CONCAT111(uVar17,auVar37)) >> 0x58,0),
708: CONCAT110(uVar46,Var36)) >> 0x50,0),
709: CONCAT19(uVar42,Var35)) >> 0x48,0),
710: CONCAT18(0xff,uVar34)) >> 0x40,0),
711: (((ulong)CONCAT16(uVar44,CONCAT15(uVar17,uVar32))
712: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
713: (uVar33 >> 0x18) << 0x30) >> 0x30,0),
714: (((uint6)uVar32 & 0xff0000) >> 0x10) << 0x28) >>
715: 0x28,0),(uVar50 >> 0x10) << 0x20) >> 0x20,0),
716: ((uVar31 & 0xff00) >> 8) << 0x18) >> 0x18,0),
717: (uVar49 >> 8) << 0x10) >> 0x10,0),uVar40)) << 8 |
718: (undefined  [16])0xff;
719: lVar28 = lVar28 + 0x10;
720: } while (uVar30 < uVar6 >> 4);
721: puVar25 = puVar25 + (ulong)uVar21 * 4;
722: uVar30 = uVar21;
723: if (uVar6 != uVar21) {
724: code_r0x0012beeb:
725: uVar22 = (ulong)uVar30;
726: puVar25[3] = puVar9[uVar22];
727: puVar25[2] = puVar24[uVar22];
728: uVar5 = puVar3[uVar22];
729: *puVar25 = 0xff;
730: puVar25[1] = uVar5;
731: uVar22 = (ulong)(uVar30 + 1);
732: if (uVar30 + 1 < uVar6) {
733: puVar25[7] = puVar9[uVar22];
734: puVar25[6] = puVar24[uVar22];
735: uVar5 = puVar3[uVar22];
736: puVar25[4] = 0xff;
737: puVar25[5] = uVar5;
738: uVar22 = (ulong)(uVar30 + 2);
739: if (uVar30 + 2 < uVar6) {
740: puVar25[0xb] = puVar9[uVar22];
741: puVar25[10] = puVar24[uVar22];
742: uVar5 = puVar3[uVar22];
743: puVar25[8] = 0xff;
744: puVar25[9] = uVar5;
745: uVar22 = (ulong)(uVar30 + 3);
746: if (uVar30 + 3 < uVar6) {
747: puVar25[0xf] = puVar9[uVar22];
748: puVar25[0xe] = puVar24[uVar22];
749: uVar5 = puVar3[uVar22];
750: puVar25[0xc] = 0xff;
751: puVar25[0xd] = uVar5;
752: uVar22 = (ulong)(uVar30 + 4);
753: if (uVar30 + 4 < uVar6) {
754: puVar25[0x13] = puVar9[uVar22];
755: puVar25[0x12] = puVar24[uVar22];
756: uVar5 = puVar3[uVar22];
757: puVar25[0x10] = 0xff;
758: puVar25[0x11] = uVar5;
759: uVar22 = (ulong)(uVar30 + 5);
760: if (uVar30 + 5 < uVar6) {
761: puVar25[0x17] = puVar9[uVar22];
762: puVar25[0x16] = puVar24[uVar22];
763: uVar5 = puVar3[uVar22];
764: puVar25[0x14] = 0xff;
765: puVar25[0x15] = uVar5;
766: uVar22 = (ulong)(uVar30 + 6);
767: if (uVar30 + 6 < uVar6) {
768: puVar25[0x1b] = puVar9[uVar22];
769: puVar25[0x1a] = puVar24[uVar22];
770: uVar5 = puVar3[uVar22];
771: puVar25[0x18] = 0xff;
772: puVar25[0x19] = uVar5;
773: uVar22 = (ulong)(uVar30 + 7);
774: if (uVar30 + 7 < uVar6) {
775: puVar25[0x1f] = puVar9[uVar22];
776: puVar25[0x1e] = puVar24[uVar22];
777: uVar5 = puVar3[uVar22];
778: puVar25[0x1c] = 0xff;
779: puVar25[0x1d] = uVar5;
780: uVar22 = (ulong)(uVar30 + 8);
781: if (uVar30 + 8 < uVar6) {
782: puVar25[0x23] = puVar9[uVar22];
783: puVar25[0x22] = puVar24[uVar22];
784: uVar5 = puVar3[uVar22];
785: puVar25[0x20] = 0xff;
786: puVar25[0x21] = uVar5;
787: uVar22 = (ulong)(uVar30 + 9);
788: if (uVar30 + 9 < uVar6) {
789: puVar25[0x27] = puVar9[uVar22];
790: puVar25[0x26] = puVar24[uVar22];
791: uVar5 = puVar3[uVar22];
792: puVar25[0x24] = 0xff;
793: puVar25[0x25] = uVar5;
794: uVar22 = (ulong)(uVar30 + 10);
795: if (uVar30 + 10 < uVar6) {
796: puVar25[0x2b] = puVar9[uVar22];
797: puVar25[0x2a] = puVar24[uVar22];
798: uVar5 = puVar3[uVar22];
799: puVar25[0x28] = 0xff;
800: puVar25[0x29] = uVar5;
801: uVar22 = (ulong)(uVar30 + 0xb);
802: if (uVar30 + 0xb < uVar6) {
803: puVar25[0x2f] = puVar9[uVar22];
804: puVar25[0x2e] = puVar24[uVar22];
805: uVar5 = puVar3[uVar22];
806: puVar25[0x2c] = 0xff;
807: puVar25[0x2d] = uVar5;
808: uVar22 = (ulong)(uVar30 + 0xc);
809: if (uVar30 + 0xc < uVar6) {
810: puVar25[0x33] = puVar9[uVar22];
811: puVar25[0x32] = puVar24[uVar22];
812: uVar5 = puVar3[uVar22];
813: puVar25[0x30] = 0xff;
814: puVar25[0x31] = uVar5;
815: uVar22 = (ulong)(uVar30 + 0xd);
816: if (uVar30 + 0xd < uVar6) {
817: uVar27 = (ulong)(uVar30 + 0xe);
818: puVar25[0x37] = puVar9[uVar22];
819: puVar25[0x36] = puVar24[uVar22];
820: uVar5 = puVar3[uVar22];
821: puVar25[0x34] = 0xff;
822: puVar25[0x35] = uVar5;
823: if (uVar30 + 0xe < uVar6) {
824: puVar25[0x3b] = puVar9[uVar27];
825: puVar25[0x3a] = puVar24[uVar27];
826: uVar5 = puVar3[uVar27];
827: puVar25[0x38] = 0xff;
828: puVar25[0x39] = uVar5;
829: }
830: }
831: }
832: }
833: }
834: }
835: }
836: }
837: }
838: }
839: }
840: }
841: }
842: }
843: }
844: goto code_r0x0012bdc8;
845: code_r0x0012cb89:
846: lVar28 = 0;
847: uVar30 = 0;
848: do {
849: auVar4 = *(undefined (*) [16])(puVar3 + lVar28);
850: uVar30 = uVar30 + 1;
851: puVar1 = puVar9 + lVar28;
852: uVar5 = puVar1[2];
853: uVar10 = puVar1[3];
854: uVar11 = puVar1[4];
855: uVar12 = puVar1[5];
856: uVar13 = puVar1[6];
857: uVar14 = puVar1[7];
858: uVar15 = puVar1[10];
859: uVar16 = puVar1[0xb];
860: uVar17 = puVar1[0xc];
861: uVar18 = puVar1[0xd];
862: uVar19 = puVar1[0xe];
863: uVar20 = puVar1[0xf];
864: auVar54 = *(undefined (*) [16])(puVar24 + lVar28);
865: uVar41 = SUB161(auVar4 >> 0x40,0);
866: uVar31 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar1[8],uVar41));
867: uVar43 = SUB161(auVar4 >> 0x50,0);
868: uVar32 = CONCAT14(uVar43,CONCAT13(puVar1[9],uVar31));
869: uVar45 = SUB161(auVar4 >> 0x58,0);
870: uVar33 = CONCAT16(uVar45,CONCAT15(uVar15,uVar32));
871: uVar34 = CONCAT17(uVar16,uVar33);
872: uVar46 = SUB161(auVar4 >> 0x60,0);
873: Var35 = CONCAT18(uVar46,uVar34);
874: Var36 = CONCAT19(uVar17,Var35);
875: uVar47 = SUB161(auVar4 >> 0x68,0);
876: auVar37 = CONCAT110(uVar47,Var36);
877: auVar38 = CONCAT111(uVar18,auVar37);
878: uVar48 = SUB161(auVar4 >> 0x70,0);
879: auVar39 = CONCAT112(uVar48,auVar38);
880: uVar57 = SUB161(auVar4 >> 0x38,0);
881: uVar44 = SUB161(auVar4 >> 0x30,0);
882: uVar42 = SUB161(auVar4 >> 0x28,0);
883: uVar40 = SUB161(auVar4 >> 0x20,0);
884: auVar56 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
885: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
886: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
887: (SUB163(CONCAT214(SUB162(CONCAT115(uVar14,
888: CONCAT114(uVar57,SUB1614(auVar4,0))) >> 0x70,0),
889: CONCAT113(uVar13,SUB1613(auVar4,0))) >> 0x68,0),
890: CONCAT112(uVar44,SUB1612(auVar4,0))) >> 0x60,0),
891: CONCAT111(uVar12,SUB1611(auVar4,0))) >> 0x58,0),
892: CONCAT110(uVar42,SUB1610(auVar4,0))) >> 0x50,0),
893: CONCAT19(uVar11,SUB169(auVar4,0))) >> 0x48,0),
894: CONCAT18(uVar40,SUB168(auVar4,0))) >> 0x40,0),
895: uVar10)) << 0x38) >> 0x30,0),uVar5)) << 0x28) >>
896: 0x20,0),puVar1[1]),(SUB163(auVar4,0) >> 8) << 0x10
897: ) >> 0x10,0),*puVar1)) << 8;
898: uVar51 = SUB161(auVar54 >> 0x40,0);
899: uVar49 = CONCAT12(SUB161(auVar54 >> 0x48,0),CONCAT11(0xff,uVar51));
900: uVar52 = SUB161(auVar54 >> 0x50,0);
901: uVar50 = CONCAT14(uVar52,CONCAT13(0xff,uVar49));
902: uVar53 = SUB161(auVar54 >> 0x58,0);
903: puVar1 = puVar25 + lVar28 * 4 + 0x10;
904: *puVar1 = uVar40;
905: puVar1[1] = SUB161(auVar54 >> 0x20,0);
906: puVar1[2] = uVar11;
907: puVar1[3] = 0xff;
908: puVar1[4] = uVar42;
909: puVar1[5] = SUB161(auVar54 >> 0x28,0);
910: puVar1[6] = uVar12;
911: puVar1[7] = 0xff;
912: puVar1[8] = uVar44;
913: puVar1[9] = SUB161(auVar54 >> 0x30,0);
914: puVar1[10] = uVar13;
915: puVar1[0xb] = 0xff;
916: puVar1[0xc] = uVar57;
917: puVar1[0xd] = SUB161(auVar54 >> 0x38,0);
918: puVar1[0xe] = uVar14;
919: puVar1[0xf] = 0xff;
920: *(undefined (*) [16])(puVar25 + lVar28 * 4) =
921: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
922: SUB169(CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(
923: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
924: (SUB163(CONCAT214(SUB162(CONCAT115(0xff,CONCAT114(
925: uVar10,SUB1614(auVar56,0))) >> 0x70,0),
926: CONCAT113(SUB161(auVar54 >> 0x18,0),
927: SUB1613(auVar56,0))) >> 0x68,0),
928: CONCAT112(SUB161(auVar4 >> 0x18,0),
929: SUB1612(auVar56,0))) >> 0x60,0),
930: CONCAT111(0xff,SUB1611(auVar56,0))) >> 0x58,0),
931: CONCAT110(uVar5,SUB1610(auVar56,0))) >> 0x50,0),
932: CONCAT19(SUB161(auVar54 >> 0x10,0),
933: SUB169(auVar56,0))) >> 0x48,0),
934: CONCAT18(SUB161(auVar4 >> 0x10,0),
935: SUB168(auVar56,0))) >> 0x40,0),
936: SUB168(auVar56,0)) >> 0x38,0) &
937: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
938: ,0) |
939: SUB169((undefined  [16])0xff00000000000000 >> 0x38
940: ,0),(SUB167(auVar56,0) >> 0x18) << 0x30) >>
941: 0x30,0),SUB161(auVar54 >> 8,0)),
942: (SUB165(auVar56,0) >> 0x10) << 0x20) >> 0x20,0),
943: SUB164(auVar56,0)) >> 0x18,0) &
944: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0) |
945: SUB1613((undefined  [16])0xff000000 >> 0x18,0),
946: (SUB163(auVar56,0) >> 8) << 0x10) >> 0x10,0),
947: SUB162(auVar4,0) & 0xff | SUB162(auVar54,0) << 8);
948: *(undefined (*) [16])(puVar25 + lVar28 * 4 + 0x20) =
949: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
950: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
951: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
952: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(0xff,
953: CONCAT114(uVar16,CONCAT113(uVar19,auVar39))) >>
954: 0x70,0),CONCAT113(uVar53,auVar39)) >> 0x68,0),
955: CONCAT112(uVar45,auVar38)) >> 0x60,0),
956: CONCAT111(0xff,auVar37)) >> 0x58,0),
957: CONCAT110(uVar15,Var36)) >> 0x50,0),
958: CONCAT19(uVar52,Var35)) >> 0x48,0),
959: CONCAT18(uVar43,uVar34)) >> 0x40,0),
960: (((ulong)CONCAT16(uVar53,CONCAT15(0xff,uVar50)) &
961: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
962: (uVar33 >> 0x18) << 0x30) >> 0x30,0),
963: (((uint6)uVar50 & 0xff0000) >> 0x10) << 0x28) >>
964: 0x28,0),(uVar32 >> 0x10) << 0x20) >> 0x20,0),
965: ((uVar49 & 0xff00) >> 8) << 0x18) >> 0x18,0),
966: (uVar31 >> 8) << 0x10) >> 0x10,0),CONCAT11(uVar51,uVar41));
967: puVar1 = puVar25 + lVar28 * 4 + 0x30;
968: *puVar1 = uVar46;
969: puVar1[1] = SUB161(auVar54 >> 0x60,0);
970: puVar1[2] = uVar17;
971: puVar1[3] = 0xff;
972: puVar1[4] = uVar47;
973: puVar1[5] = SUB161(auVar54 >> 0x68,0);
974: puVar1[6] = uVar18;
975: puVar1[7] = 0xff;
976: puVar1[8] = uVar48;
977: puVar1[9] = SUB161(auVar54 >> 0x70,0);
978: puVar1[10] = uVar19;
979: puVar1[0xb] = 0xff;
980: puVar1[0xc] = SUB161(auVar4 >> 0x78,0);
981: puVar1[0xd] = SUB161(auVar54 >> 0x78,0);
982: puVar1[0xe] = uVar20;
983: puVar1[0xf] = 0xff;
984: lVar28 = lVar28 + 0x10;
985: } while (uVar30 < uVar6 >> 4);
986: puVar25 = puVar25 + (ulong)uVar21 * 4;
987: uVar30 = uVar21;
988: if (uVar6 != uVar21) {
989: code_r0x0012cc03:
990: uVar22 = (ulong)uVar30;
991: puVar25[2] = puVar9[uVar22];
992: puVar25[1] = puVar24[uVar22];
993: uVar5 = puVar3[uVar22];
994: puVar25[3] = 0xff;
995: *puVar25 = uVar5;
996: uVar22 = (ulong)(uVar30 + 1);
997: if (uVar30 + 1 < uVar6) {
998: puVar25[6] = puVar9[uVar22];
999: puVar25[5] = puVar24[uVar22];
1000: uVar5 = puVar3[uVar22];
1001: puVar25[7] = 0xff;
1002: puVar25[4] = uVar5;
1003: uVar22 = (ulong)(uVar30 + 2);
1004: if (uVar30 + 2 < uVar6) {
1005: puVar25[10] = puVar9[uVar22];
1006: puVar25[9] = puVar24[uVar22];
1007: uVar5 = puVar3[uVar22];
1008: puVar25[0xb] = 0xff;
1009: puVar25[8] = uVar5;
1010: uVar22 = (ulong)(uVar30 + 3);
1011: if (uVar30 + 3 < uVar6) {
1012: puVar25[0xe] = puVar9[uVar22];
1013: puVar25[0xd] = puVar24[uVar22];
1014: uVar5 = puVar3[uVar22];
1015: puVar25[0xf] = 0xff;
1016: puVar25[0xc] = uVar5;
1017: uVar22 = (ulong)(uVar30 + 4);
1018: if (uVar30 + 4 < uVar6) {
1019: puVar25[0x12] = puVar9[uVar22];
1020: puVar25[0x11] = puVar24[uVar22];
1021: uVar5 = puVar3[uVar22];
1022: puVar25[0x13] = 0xff;
1023: puVar25[0x10] = uVar5;
1024: uVar22 = (ulong)(uVar30 + 5);
1025: if (uVar30 + 5 < uVar6) {
1026: puVar25[0x16] = puVar9[uVar22];
1027: puVar25[0x15] = puVar24[uVar22];
1028: uVar5 = puVar3[uVar22];
1029: puVar25[0x17] = 0xff;
1030: puVar25[0x14] = uVar5;
1031: uVar22 = (ulong)(uVar30 + 6);
1032: if (uVar30 + 6 < uVar6) {
1033: puVar25[0x1a] = puVar9[uVar22];
1034: puVar25[0x19] = puVar24[uVar22];
1035: uVar5 = puVar3[uVar22];
1036: puVar25[0x1b] = 0xff;
1037: puVar25[0x18] = uVar5;
1038: uVar22 = (ulong)(uVar30 + 7);
1039: if (uVar30 + 7 < uVar6) {
1040: puVar25[0x1e] = puVar9[uVar22];
1041: puVar25[0x1d] = puVar24[uVar22];
1042: uVar5 = puVar3[uVar22];
1043: puVar25[0x1f] = 0xff;
1044: puVar25[0x1c] = uVar5;
1045: uVar22 = (ulong)(uVar30 + 8);
1046: if (uVar30 + 8 < uVar6) {
1047: puVar25[0x22] = puVar9[uVar22];
1048: puVar25[0x21] = puVar24[uVar22];
1049: uVar5 = puVar3[uVar22];
1050: puVar25[0x23] = 0xff;
1051: puVar25[0x20] = uVar5;
1052: uVar22 = (ulong)(uVar30 + 9);
1053: if (uVar30 + 9 < uVar6) {
1054: puVar25[0x26] = puVar9[uVar22];
1055: puVar25[0x25] = puVar24[uVar22];
1056: uVar5 = puVar3[uVar22];
1057: puVar25[0x27] = 0xff;
1058: puVar25[0x24] = uVar5;
1059: uVar22 = (ulong)(uVar30 + 10);
1060: if (uVar30 + 10 < uVar6) {
1061: puVar25[0x2a] = puVar9[uVar22];
1062: puVar25[0x29] = puVar24[uVar22];
1063: uVar5 = puVar3[uVar22];
1064: puVar25[0x2b] = 0xff;
1065: puVar25[0x28] = uVar5;
1066: uVar22 = (ulong)(uVar30 + 0xb);
1067: if (uVar30 + 0xb < uVar6) {
1068: puVar25[0x2e] = puVar9[uVar22];
1069: puVar25[0x2d] = puVar24[uVar22];
1070: uVar5 = puVar3[uVar22];
1071: puVar25[0x2f] = 0xff;
1072: puVar25[0x2c] = uVar5;
1073: uVar22 = (ulong)(uVar30 + 0xc);
1074: if (uVar30 + 0xc < uVar6) {
1075: puVar25[0x32] = puVar9[uVar22];
1076: puVar25[0x31] = puVar24[uVar22];
1077: uVar5 = puVar3[uVar22];
1078: puVar25[0x33] = 0xff;
1079: puVar25[0x30] = uVar5;
1080: uVar22 = (ulong)(uVar30 + 0xd);
1081: if (uVar30 + 0xd < uVar6) {
1082: uVar27 = (ulong)(uVar30 + 0xe);
1083: puVar25[0x36] = puVar9[uVar22];
1084: puVar25[0x35] = puVar24[uVar22];
1085: uVar5 = puVar3[uVar22];
1086: puVar25[0x37] = 0xff;
1087: puVar25[0x34] = uVar5;
1088: if (uVar30 + 0xe < uVar6) {
1089: puVar25[0x3a] = puVar9[uVar27];
1090: puVar25[0x39] = puVar24[uVar27];
1091: uVar5 = puVar3[uVar27];
1092: puVar25[0x3b] = 0xff;
1093: puVar25[0x38] = uVar5;
1094: }
1095: }
1096: }
1097: }
1098: }
1099: }
1100: }
1101: }
1102: }
1103: }
1104: }
1105: }
1106: }
1107: }
1108: }
1109: goto code_r0x0012cae8;
1110: code_r0x0012c705:
1111: lVar28 = 0;
1112: uVar30 = 0;
1113: do {
1114: auVar4 = *(undefined (*) [16])(puVar9 + lVar28);
1115: uVar30 = uVar30 + 1;
1116: puVar1 = puVar3 + lVar28;
1117: uVar5 = puVar1[2];
1118: uVar10 = puVar1[3];
1119: uVar11 = puVar1[4];
1120: uVar12 = puVar1[5];
1121: uVar13 = puVar1[6];
1122: uVar14 = puVar1[7];
1123: uVar15 = puVar1[10];
1124: uVar16 = puVar1[0xb];
1125: uVar17 = puVar1[0xc];
1126: uVar18 = puVar1[0xd];
1127: uVar19 = puVar1[0xe];
1128: uVar20 = puVar1[0xf];
1129: auVar54 = *(undefined (*) [16])(puVar24 + lVar28);
1130: uVar41 = SUB161(auVar4 >> 0x40,0);
1131: uVar31 = CONCAT12(SUB161(auVar4 >> 0x48,0),CONCAT11(puVar1[8],uVar41));
1132: uVar43 = SUB161(auVar4 >> 0x50,0);
1133: uVar32 = CONCAT14(uVar43,CONCAT13(puVar1[9],uVar31));
1134: uVar45 = SUB161(auVar4 >> 0x58,0);
1135: uVar33 = CONCAT16(uVar45,CONCAT15(uVar15,uVar32));
1136: uVar34 = CONCAT17(uVar16,uVar33);
1137: uVar46 = SUB161(auVar4 >> 0x60,0);
1138: Var35 = CONCAT18(uVar46,uVar34);
1139: Var36 = CONCAT19(uVar17,Var35);
1140: uVar47 = SUB161(auVar4 >> 0x68,0);
1141: auVar37 = CONCAT110(uVar47,Var36);
1142: auVar38 = CONCAT111(uVar18,auVar37);
1143: uVar48 = SUB161(auVar4 >> 0x70,0);
1144: auVar39 = CONCAT112(uVar48,auVar38);
1145: uVar57 = SUB161(auVar4 >> 0x38,0);
1146: uVar44 = SUB161(auVar4 >> 0x30,0);
1147: uVar42 = SUB161(auVar4 >> 0x28,0);
1148: uVar40 = SUB161(auVar4 >> 0x20,0);
1149: auVar56 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1150: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
1151: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
1152: (SUB163(CONCAT214(SUB162(CONCAT115(uVar14,
1153: CONCAT114(uVar57,SUB1614(auVar4,0))) >> 0x70,0),
1154: CONCAT113(uVar13,SUB1613(auVar4,0))) >> 0x68,0),
1155: CONCAT112(uVar44,SUB1612(auVar4,0))) >> 0x60,0),
1156: CONCAT111(uVar12,SUB1611(auVar4,0))) >> 0x58,0),
1157: CONCAT110(uVar42,SUB1610(auVar4,0))) >> 0x50,0),
1158: CONCAT19(uVar11,SUB169(auVar4,0))) >> 0x48,0),
1159: CONCAT18(uVar40,SUB168(auVar4,0))) >> 0x40,0),
1160: uVar10)) << 0x38) >> 0x30,0),uVar5)) << 0x28) >>
1161: 0x20,0),puVar1[1]),(SUB163(auVar4,0) >> 8) << 0x10
1162: ) >> 0x10,0),*puVar1)) << 8;
1163: uVar51 = SUB161(auVar54 >> 0x40,0);
1164: uVar49 = CONCAT12(SUB161(auVar54 >> 0x48,0),CONCAT11(0xff,uVar51));
1165: uVar52 = SUB161(auVar54 >> 0x50,0);
1166: uVar50 = CONCAT14(uVar52,CONCAT13(0xff,uVar49));
1167: uVar53 = SUB161(auVar54 >> 0x58,0);
1168: puVar1 = puVar25 + lVar28 * 4 + 0x10;
1169: *puVar1 = uVar40;
1170: puVar1[1] = SUB161(auVar54 >> 0x20,0);
1171: puVar1[2] = uVar11;
1172: puVar1[3] = 0xff;
1173: puVar1[4] = uVar42;
1174: puVar1[5] = SUB161(auVar54 >> 0x28,0);
1175: puVar1[6] = uVar12;
1176: puVar1[7] = 0xff;
1177: puVar1[8] = uVar44;
1178: puVar1[9] = SUB161(auVar54 >> 0x30,0);
1179: puVar1[10] = uVar13;
1180: puVar1[0xb] = 0xff;
1181: puVar1[0xc] = uVar57;
1182: puVar1[0xd] = SUB161(auVar54 >> 0x38,0);
1183: puVar1[0xe] = uVar14;
1184: puVar1[0xf] = 0xff;
1185: *(undefined (*) [16])(puVar25 + lVar28 * 4) =
1186: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
1187: SUB169(CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(
1188: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
1189: (SUB163(CONCAT214(SUB162(CONCAT115(0xff,CONCAT114(
1190: uVar10,SUB1614(auVar56,0))) >> 0x70,0),
1191: CONCAT113(SUB161(auVar54 >> 0x18,0),
1192: SUB1613(auVar56,0))) >> 0x68,0),
1193: CONCAT112(SUB161(auVar4 >> 0x18,0),
1194: SUB1612(auVar56,0))) >> 0x60,0),
1195: CONCAT111(0xff,SUB1611(auVar56,0))) >> 0x58,0),
1196: CONCAT110(uVar5,SUB1610(auVar56,0))) >> 0x50,0),
1197: CONCAT19(SUB161(auVar54 >> 0x10,0),
1198: SUB169(auVar56,0))) >> 0x48,0),
1199: CONCAT18(SUB161(auVar4 >> 0x10,0),
1200: SUB168(auVar56,0))) >> 0x40,0),
1201: SUB168(auVar56,0)) >> 0x38,0) &
1202: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1203: ,0) |
1204: SUB169((undefined  [16])0xff00000000000000 >> 0x38
1205: ,0),(SUB167(auVar56,0) >> 0x18) << 0x30) >>
1206: 0x30,0),SUB161(auVar54 >> 8,0)),
1207: (SUB165(auVar56,0) >> 0x10) << 0x20) >> 0x20,0),
1208: SUB164(auVar56,0)) >> 0x18,0) &
1209: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0) |
1210: SUB1613((undefined  [16])0xff000000 >> 0x18,0),
1211: (SUB163(auVar56,0) >> 8) << 0x10) >> 0x10,0),
1212: SUB162(auVar4,0) & 0xff | SUB162(auVar54,0) << 8);
1213: *(undefined (*) [16])(puVar25 + lVar28 * 4 + 0x20) =
1214: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
1215: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1216: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1217: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(0xff,
1218: CONCAT114(uVar16,CONCAT113(uVar19,auVar39))) >>
1219: 0x70,0),CONCAT113(uVar53,auVar39)) >> 0x68,0),
1220: CONCAT112(uVar45,auVar38)) >> 0x60,0),
1221: CONCAT111(0xff,auVar37)) >> 0x58,0),
1222: CONCAT110(uVar15,Var36)) >> 0x50,0),
1223: CONCAT19(uVar52,Var35)) >> 0x48,0),
1224: CONCAT18(uVar43,uVar34)) >> 0x40,0),
1225: (((ulong)CONCAT16(uVar53,CONCAT15(0xff,uVar50)) &
1226: 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
1227: (uVar33 >> 0x18) << 0x30) >> 0x30,0),
1228: (((uint6)uVar50 & 0xff0000) >> 0x10) << 0x28) >>
1229: 0x28,0),(uVar32 >> 0x10) << 0x20) >> 0x20,0),
1230: ((uVar49 & 0xff00) >> 8) << 0x18) >> 0x18,0),
1231: (uVar31 >> 8) << 0x10) >> 0x10,0),CONCAT11(uVar51,uVar41));
1232: puVar1 = puVar25 + lVar28 * 4 + 0x30;
1233: *puVar1 = uVar46;
1234: puVar1[1] = SUB161(auVar54 >> 0x60,0);
1235: puVar1[2] = uVar17;
1236: puVar1[3] = 0xff;
1237: puVar1[4] = uVar47;
1238: puVar1[5] = SUB161(auVar54 >> 0x68,0);
1239: puVar1[6] = uVar18;
1240: puVar1[7] = 0xff;
1241: puVar1[8] = uVar48;
1242: puVar1[9] = SUB161(auVar54 >> 0x70,0);
1243: puVar1[10] = uVar19;
1244: puVar1[0xb] = 0xff;
1245: puVar1[0xc] = SUB161(auVar4 >> 0x78,0);
1246: puVar1[0xd] = SUB161(auVar54 >> 0x78,0);
1247: puVar1[0xe] = uVar20;
1248: puVar1[0xf] = 0xff;
1249: lVar28 = lVar28 + 0x10;
1250: } while (uVar30 < uVar6 >> 4);
1251: puVar25 = puVar25 + (ulong)uVar21 * 4;
1252: uVar30 = uVar21;
1253: if (uVar6 != uVar21) {
1254: code_r0x0012c783:
1255: uVar22 = (ulong)uVar30;
1256: *puVar25 = puVar9[uVar22];
1257: puVar25[1] = puVar24[uVar22];
1258: uVar5 = puVar3[uVar22];
1259: puVar25[3] = 0xff;
1260: puVar25[2] = uVar5;
1261: uVar22 = (ulong)(uVar30 + 1);
1262: if (uVar30 + 1 < uVar6) {
1263: puVar25[4] = puVar9[uVar22];
1264: puVar25[5] = puVar24[uVar22];
1265: uVar5 = puVar3[uVar22];
1266: puVar25[7] = 0xff;
1267: puVar25[6] = uVar5;
1268: uVar22 = (ulong)(uVar30 + 2);
1269: if (uVar30 + 2 < uVar6) {
1270: puVar25[8] = puVar9[uVar22];
1271: puVar25[9] = puVar24[uVar22];
1272: uVar5 = puVar3[uVar22];
1273: puVar25[0xb] = 0xff;
1274: puVar25[10] = uVar5;
1275: uVar22 = (ulong)(uVar30 + 3);
1276: if (uVar30 + 3 < uVar6) {
1277: puVar25[0xc] = puVar9[uVar22];
1278: puVar25[0xd] = puVar24[uVar22];
1279: uVar5 = puVar3[uVar22];
1280: puVar25[0xf] = 0xff;
1281: puVar25[0xe] = uVar5;
1282: uVar22 = (ulong)(uVar30 + 4);
1283: if (uVar30 + 4 < uVar6) {
1284: puVar25[0x10] = puVar9[uVar22];
1285: puVar25[0x11] = puVar24[uVar22];
1286: uVar5 = puVar3[uVar22];
1287: puVar25[0x13] = 0xff;
1288: puVar25[0x12] = uVar5;
1289: uVar22 = (ulong)(uVar30 + 5);
1290: if (uVar30 + 5 < uVar6) {
1291: puVar25[0x14] = puVar9[uVar22];
1292: puVar25[0x15] = puVar24[uVar22];
1293: uVar5 = puVar3[uVar22];
1294: puVar25[0x17] = 0xff;
1295: puVar25[0x16] = uVar5;
1296: uVar22 = (ulong)(uVar30 + 6);
1297: if (uVar30 + 6 < uVar6) {
1298: puVar25[0x18] = puVar9[uVar22];
1299: puVar25[0x19] = puVar24[uVar22];
1300: uVar5 = puVar3[uVar22];
1301: puVar25[0x1b] = 0xff;
1302: puVar25[0x1a] = uVar5;
1303: uVar22 = (ulong)(uVar30 + 7);
1304: if (uVar30 + 7 < uVar6) {
1305: puVar25[0x1c] = puVar9[uVar22];
1306: puVar25[0x1d] = puVar24[uVar22];
1307: uVar5 = puVar3[uVar22];
1308: puVar25[0x1f] = 0xff;
1309: puVar25[0x1e] = uVar5;
1310: uVar22 = (ulong)(uVar30 + 8);
1311: if (uVar30 + 8 < uVar6) {
1312: puVar25[0x20] = puVar9[uVar22];
1313: puVar25[0x21] = puVar24[uVar22];
1314: uVar5 = puVar3[uVar22];
1315: puVar25[0x23] = 0xff;
1316: puVar25[0x22] = uVar5;
1317: uVar22 = (ulong)(uVar30 + 9);
1318: if (uVar30 + 9 < uVar6) {
1319: puVar25[0x24] = puVar9[uVar22];
1320: puVar25[0x25] = puVar24[uVar22];
1321: uVar5 = puVar3[uVar22];
1322: puVar25[0x27] = 0xff;
1323: puVar25[0x26] = uVar5;
1324: uVar22 = (ulong)(uVar30 + 10);
1325: if (uVar30 + 10 < uVar6) {
1326: puVar25[0x28] = puVar9[uVar22];
1327: puVar25[0x29] = puVar24[uVar22];
1328: uVar5 = puVar3[uVar22];
1329: puVar25[0x2b] = 0xff;
1330: puVar25[0x2a] = uVar5;
1331: uVar22 = (ulong)(uVar30 + 0xb);
1332: if (uVar30 + 0xb < uVar6) {
1333: puVar25[0x2c] = puVar9[uVar22];
1334: puVar25[0x2d] = puVar24[uVar22];
1335: uVar5 = puVar3[uVar22];
1336: puVar25[0x2f] = 0xff;
1337: puVar25[0x2e] = uVar5;
1338: uVar22 = (ulong)(uVar30 + 0xc);
1339: if (uVar30 + 0xc < uVar6) {
1340: puVar25[0x30] = puVar9[uVar22];
1341: puVar25[0x31] = puVar24[uVar22];
1342: uVar5 = puVar3[uVar22];
1343: puVar25[0x33] = 0xff;
1344: puVar25[0x32] = uVar5;
1345: uVar22 = (ulong)(uVar30 + 0xd);
1346: if (uVar30 + 0xd < uVar6) {
1347: uVar27 = (ulong)(uVar30 + 0xe);
1348: puVar25[0x34] = puVar9[uVar22];
1349: puVar25[0x35] = puVar24[uVar22];
1350: uVar5 = puVar3[uVar22];
1351: puVar25[0x37] = 0xff;
1352: puVar25[0x36] = uVar5;
1353: if (uVar30 + 0xe < uVar6) {
1354: puVar25[0x38] = puVar9[uVar27];
1355: puVar25[0x39] = puVar24[uVar27];
1356: uVar5 = puVar3[uVar27];
1357: puVar25[0x3b] = 0xff;
1358: puVar25[0x3a] = uVar5;
1359: }
1360: }
1361: }
1362: }
1363: }
1364: }
1365: }
1366: }
1367: }
1368: }
1369: }
1370: }
1371: }
1372: }
1373: }
1374: goto code_r0x0012c668;
1375: }
1376: 
