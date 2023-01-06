1: 
2: void FUN_00105370(long param_1,long *param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: undefined *puVar1;
6: undefined *puVar2;
7: undefined auVar3 [16];
8: uint uVar4;
9: undefined *puVar5;
10: undefined *puVar6;
11: undefined *puVar7;
12: long lVar8;
13: ulong uVar9;
14: uint6 uVar10;
15: uint uVar11;
16: undefined uVar12;
17: undefined uVar13;
18: undefined uVar14;
19: undefined uVar15;
20: undefined uVar16;
21: undefined uVar17;
22: undefined uVar18;
23: undefined uVar19;
24: undefined uVar20;
25: undefined uVar21;
26: undefined uVar22;
27: ulong uVar23;
28: uint uVar24;
29: undefined *puVar25;
30: long lVar26;
31: long *plVar27;
32: long lVar28;
33: undefined (*pauVar29) [16];
34: long lVar30;
35: ulong uVar31;
36: uint uVar32;
37: uint uVar33;
38: ulong uVar34;
39: ulong uVar35;
40: undefined uVar37;
41: undefined uVar39;
42: undefined uVar42;
43: undefined auVar36 [16];
44: byte bVar45;
45: undefined uVar46;
46: undefined uVar47;
47: undefined uVar48;
48: undefined uVar49;
49: undefined uVar50;
50: uint7 uVar51;
51: uint6 uVar52;
52: undefined auVar44 [16];
53: undefined uVar56;
54: undefined uVar57;
55: undefined uVar58;
56: undefined uVar59;
57: undefined uVar60;
58: undefined auVar53 [16];
59: undefined auVar54 [16];
60: undefined auVar55 [16];
61: undefined uVar64;
62: undefined uVar65;
63: undefined uVar66;
64: undefined auVar61 [16];
65: undefined auVar62 [16];
66: undefined uVar67;
67: undefined auVar63 [16];
68: uint3 uVar68;
69: undefined uVar69;
70: undefined uVar70;
71: undefined uVar71;
72: undefined uVar73;
73: undefined uVar74;
74: uint3 uVar72;
75: undefined uVar75;
76: undefined uVar76;
77: undefined uVar77;
78: undefined uVar78;
79: undefined uVar79;
80: undefined uVar80;
81: undefined uVar81;
82: undefined uVar82;
83: undefined uVar83;
84: undefined uVar84;
85: undefined uVar85;
86: uint3 uVar86;
87: uint5 uVar88;
88: undefined uVar38;
89: undefined uVar40;
90: undefined uVar41;
91: undefined uVar43;
92: uint5 uVar87;
93: 
94: uVar34 = (ulong)param_4;
95: switch(*(undefined4 *)(param_1 + 0x3c)) {
96: case 6:
97: uVar4 = *(uint *)(param_1 + 0x30);
98: while (param_5 = param_5 + -1, plVar27 = param_2, uVar35 = uVar34, -1 < param_5) {
99: while( true ) {
100: param_2 = plVar27 + 1;
101: uVar34 = (ulong)((int)uVar35 + 1);
102: lVar30 = *(long *)(*param_3 + uVar35 * 8);
103: lVar28 = *(long *)(param_3[1] + uVar35 * 8);
104: lVar8 = *(long *)(param_3[2] + uVar35 * 8);
105: lVar26 = 0;
106: puVar25 = (undefined *)*plVar27;
107: if (uVar4 == 0) break;
108: do {
109: *(undefined *)(lVar30 + lVar26) = *puVar25;
110: *(undefined *)(lVar28 + lVar26) = puVar25[1];
111: *(undefined *)(lVar8 + lVar26) = puVar25[2];
112: lVar26 = lVar26 + 1;
113: puVar25 = puVar25 + 3;
114: } while ((uint)lVar26 < uVar4);
115: param_5 = param_5 + -1;
116: plVar27 = param_2;
117: uVar35 = uVar34;
118: if (param_5 < 0) {
119: return;
120: }
121: }
122: }
123: break;
124: case 7:
125: case 0xc:
126: uVar4 = *(uint *)(param_1 + 0x30);
127: uVar35 = (ulong)uVar4;
128: uVar24 = uVar4 - 1 >> 4;
129: uVar32 = uVar4 - 1 & 0xfffffff0;
130: code_r0x00105990:
131: while( true ) {
132: do {
133: param_5 = param_5 + -1;
134: if (param_5 < 0) {
135: return;
136: }
137: plVar27 = param_2 + 1;
138: uVar31 = (ulong)((int)uVar34 + 1);
139: puVar25 = (undefined *)*param_2;
140: puVar5 = *(undefined **)(*param_3 + uVar34 * 8);
141: puVar6 = *(undefined **)(param_3[1] + uVar34 * 8);
142: puVar7 = *(undefined **)(param_3[2] + uVar34 * 8);
143: param_2 = plVar27;
144: uVar34 = uVar31;
145: } while (uVar4 == 0);
146: puVar1 = puVar25 + uVar35 * 4;
147: if (((((((puVar5 + uVar35 <= puVar25 || puVar1 <= puVar5) &&
148: (puVar6 + uVar35 <= puVar25 || puVar1 <= puVar6)) && 0xf < uVar4) &&
149: (puVar7 + uVar35 <= puVar25 || puVar1 <= puVar7)) &&
150: (puVar6 + 0x10 <= puVar5 || puVar5 + 0x10 <= puVar6)) &&
151: (puVar7 + 0x10 <= puVar5 || puVar5 + 0x10 <= puVar7)) &&
152: (puVar7 + 0x10 <= puVar6 || puVar6 + 0x10 <= puVar7)) break;
153: lVar30 = 0;
154: do {
155: puVar5[lVar30] = *puVar25;
156: puVar6[lVar30] = puVar25[1];
157: puVar7[lVar30] = puVar25[2];
158: lVar30 = lVar30 + 1;
159: puVar25 = puVar25 + 4;
160: } while ((uint)lVar30 < uVar4);
161: }
162: if (uVar24 != 0) goto code_r0x00105a7c;
163: uVar33 = 0;
164: goto code_r0x00105f18;
165: case 8:
166: uVar4 = *(uint *)(param_1 + 0x30);
167: while (param_5 = param_5 + -1, -1 < param_5) {
168: plVar27 = param_2 + 1;
169: uVar35 = (ulong)((int)uVar34 + 1);
170: puVar25 = (undefined *)*param_2;
171: lVar30 = *(long *)(*param_3 + uVar34 * 8);
172: lVar28 = *(long *)(param_3[1] + uVar34 * 8);
173: lVar8 = *(long *)(param_3[2] + uVar34 * 8);
174: lVar26 = 0;
175: param_2 = plVar27;
176: uVar34 = uVar35;
177: if (uVar4 != 0) {
178: do {
179: *(undefined *)(lVar30 + lVar26) = puVar25[2];
180: *(undefined *)(lVar28 + lVar26) = puVar25[1];
181: *(undefined *)(lVar8 + lVar26) = *puVar25;
182: lVar26 = lVar26 + 1;
183: puVar25 = puVar25 + 3;
184: } while ((uint)lVar26 < uVar4);
185: }
186: }
187: break;
188: case 9:
189: case 0xd:
190: uVar4 = *(uint *)(param_1 + 0x30);
191: uVar35 = (ulong)uVar4;
192: uVar24 = uVar4 - 1 >> 4;
193: uVar32 = uVar4 - 1 & 0xfffffff0;
194: code_r0x00105c88:
195: while( true ) {
196: do {
197: param_5 = param_5 + -1;
198: if (param_5 < 0) {
199: return;
200: }
201: plVar27 = param_2 + 1;
202: uVar31 = (ulong)((int)uVar34 + 1);
203: puVar25 = (undefined *)*param_2;
204: puVar5 = *(undefined **)(*param_3 + uVar34 * 8);
205: puVar6 = *(undefined **)(param_3[1] + uVar34 * 8);
206: puVar7 = *(undefined **)(param_3[2] + uVar34 * 8);
207: param_2 = plVar27;
208: uVar34 = uVar31;
209: } while (uVar4 == 0);
210: puVar1 = puVar25 + uVar35 * 4;
211: if (((((((puVar6 + uVar35 <= puVar25 || puVar1 <= puVar6) &&
212: (puVar5 + uVar35 <= puVar25 || puVar1 <= puVar5)) && 0xf < uVar4) &&
213: (puVar7 + uVar35 <= puVar25 || puVar1 <= puVar7)) &&
214: (puVar6 + 0x10 <= puVar5 || puVar5 + 0x10 <= puVar6)) &&
215: (puVar7 + 0x10 <= puVar5 || puVar5 + 0x10 <= puVar7)) &&
216: (puVar7 + 0x10 <= puVar6 || puVar6 + 0x10 <= puVar7)) break;
217: lVar30 = 0;
218: do {
219: puVar5[lVar30] = puVar25[2];
220: puVar6[lVar30] = puVar25[1];
221: puVar7[lVar30] = *puVar25;
222: lVar30 = lVar30 + 1;
223: puVar25 = puVar25 + 4;
224: } while ((uint)lVar30 < uVar4);
225: }
226: if (uVar24 != 0) goto code_r0x00105d78;
227: uVar33 = 0;
228: goto code_r0x00105f88;
229: case 10:
230: case 0xe:
231: uVar4 = *(uint *)(param_1 + 0x30);
232: uVar35 = (ulong)uVar4;
233: uVar24 = uVar4 - 1 & 0xfffffff0;
234: code_r0x001053e0:
235: while( true ) {
236: do {
237: param_5 = param_5 + -1;
238: if (param_5 < 0) {
239: return;
240: }
241: plVar27 = param_2 + 1;
242: uVar31 = (ulong)((int)uVar34 + 1);
243: lVar30 = *param_2;
244: puVar25 = *(undefined **)(*param_3 + uVar34 * 8);
245: puVar5 = *(undefined **)(param_3[1] + uVar34 * 8);
246: puVar6 = *(undefined **)(param_3[2] + uVar34 * 8);
247: uVar34 = uVar31;
248: param_2 = plVar27;
249: } while (uVar4 == 0);
250: pauVar29 = (undefined (*) [16])(lVar30 + 1);
251: puVar7 = *pauVar29 + uVar35 * 4;
252: if ((((((((undefined (*) [16])(puVar5 + uVar35) <= pauVar29 || puVar7 <= puVar5) &&
253: ((undefined (*) [16])(puVar25 + uVar35) <= pauVar29 || puVar7 <= puVar25)) &&
254: 0xf < uVar4) && ((undefined (*) [16])(puVar6 + uVar35) <= pauVar29 || puVar7 <= puVar6)
255: ) && (puVar5 + 0x10 <= puVar25 || puVar25 + 0x10 <= puVar5)) &&
256: (puVar6 + 0x10 <= puVar25 || puVar25 + 0x10 <= puVar6)) &&
257: (puVar6 + 0x10 <= puVar5 || puVar5 + 0x10 <= puVar6)) break;
258: lVar28 = 0;
259: do {
260: puVar25[lVar28] = *(undefined *)(lVar30 + 3);
261: puVar5[lVar28] = *(undefined *)(lVar30 + 2);
262: puVar6[lVar28] = *(undefined *)(lVar30 + 1);
263: lVar28 = lVar28 + 1;
264: lVar30 = lVar30 + 4;
265: } while ((uint)lVar28 < uVar4);
266: }
267: if (uVar24 != 0) goto code_r0x001054df;
268: uVar32 = 0;
269: goto code_r0x00105f50;
270: case 0xb:
271: case 0xf:
272: uVar4 = *(uint *)(param_1 + 0x30);
273: uVar35 = (ulong)uVar4;
274: uVar24 = uVar4 - 1 & 0xfffffff0;
275: code_r0x00105680:
276: while( true ) {
277: do {
278: param_5 = param_5 + -1;
279: if (param_5 < 0) {
280: return;
281: }
282: plVar27 = param_2 + 1;
283: uVar31 = (ulong)((int)uVar34 + 1);
284: lVar30 = *param_2;
285: puVar25 = *(undefined **)(*param_3 + uVar34 * 8);
286: puVar5 = *(undefined **)(param_3[1] + uVar34 * 8);
287: puVar6 = *(undefined **)(param_3[2] + uVar34 * 8);
288: uVar34 = uVar31;
289: param_2 = plVar27;
290: } while (uVar4 == 0);
291: pauVar29 = (undefined (*) [16])(lVar30 + 1);
292: puVar7 = *pauVar29 + uVar35 * 4;
293: if ((((((((undefined (*) [16])(puVar5 + uVar35) <= pauVar29 || puVar7 <= puVar5) &&
294: ((undefined (*) [16])(puVar25 + uVar35) <= pauVar29 || puVar7 <= puVar25)) &&
295: 0xf < uVar4) && ((undefined (*) [16])(puVar6 + uVar35) <= pauVar29 || puVar7 <= puVar6)
296: ) && (puVar5 + 0x10 <= puVar25 || puVar25 + 0x10 <= puVar5)) &&
297: (puVar6 + 0x10 <= puVar25 || puVar25 + 0x10 <= puVar6)) &&
298: (puVar6 + 0x10 <= puVar5 || puVar5 + 0x10 <= puVar6)) break;
299: lVar28 = 0;
300: do {
301: puVar25[lVar28] = *(undefined *)(lVar30 + 1);
302: puVar5[lVar28] = *(undefined *)(lVar30 + 2);
303: puVar6[lVar28] = *(undefined *)(lVar30 + 3);
304: lVar28 = lVar28 + 1;
305: lVar30 = lVar30 + 4;
306: } while ((uint)lVar28 < uVar4);
307: }
308: if (uVar24 != 0) goto code_r0x0010577f;
309: uVar32 = 0;
310: goto code_r0x00105ee0;
311: default:
312: uVar4 = *(uint *)(param_1 + 0x30);
313: while (param_5 = param_5 + -1, -1 < param_5) {
314: plVar27 = param_2 + 1;
315: uVar35 = (ulong)((int)uVar34 + 1);
316: puVar25 = (undefined *)*param_2;
317: lVar30 = *(long *)(*param_3 + uVar34 * 8);
318: lVar28 = *(long *)(param_3[1] + uVar34 * 8);
319: lVar8 = *(long *)(param_3[2] + uVar34 * 8);
320: lVar26 = 0;
321: param_2 = plVar27;
322: uVar34 = uVar35;
323: if (uVar4 != 0) {
324: do {
325: *(undefined *)(lVar30 + lVar26) = *puVar25;
326: *(undefined *)(lVar28 + lVar26) = puVar25[1];
327: *(undefined *)(lVar8 + lVar26) = puVar25[2];
328: lVar26 = lVar26 + 1;
329: puVar25 = puVar25 + 3;
330: } while ((uint)lVar26 < uVar4);
331: }
332: }
333: }
334: return;
335: code_r0x0010577f:
336: lVar28 = 0;
337: uVar32 = 0;
338: do {
339: auVar55 = *pauVar29;
340: uVar32 = uVar32 + 1;
341: uVar64 = pauVar29[1][0];
342: uVar65 = pauVar29[1][1];
343: uVar57 = pauVar29[1][2];
344: uVar73 = pauVar29[1][3];
345: uVar58 = pauVar29[1][4];
346: uVar59 = pauVar29[1][5];
347: uVar66 = pauVar29[1][6];
348: uVar60 = pauVar29[1][9];
349: uVar67 = pauVar29[1][10];
350: uVar74 = pauVar29[1][0xc];
351: auVar3 = pauVar29[2];
352: uVar82 = SUB161(auVar55 >> 0x40,0);
353: uVar69 = SUB161(auVar55 >> 0x48,0);
354: uVar70 = SUB161(auVar55 >> 0x50,0);
355: uVar83 = SUB161(auVar55 >> 0x58,0);
356: uVar84 = SUB161(auVar55 >> 0x60,0);
357: uVar71 = SUB161(auVar55 >> 0x68,0);
358: uVar85 = SUB161(auVar55 >> 0x78,0);
359: uVar75 = pauVar29[3][1];
360: uVar76 = pauVar29[3][2];
361: uVar12 = pauVar29[3][3];
362: uVar13 = pauVar29[3][4];
363: uVar14 = pauVar29[3][5];
364: uVar15 = pauVar29[3][6];
365: uVar16 = pauVar29[3][7];
366: uVar17 = pauVar29[3][8];
367: uVar18 = pauVar29[3][9];
368: uVar19 = pauVar29[3][10];
369: uVar20 = pauVar29[3][0xb];
370: uVar21 = pauVar29[3][0xc];
371: uVar22 = pauVar29[3][0xd];
372: uVar37 = pauVar29[3][0xe];
373: uVar50 = SUB161(auVar55 >> 0x38,0);
374: uVar48 = SUB161(auVar55 >> 0x30,0);
375: uVar47 = SUB161(auVar55 >> 0x28,0);
376: bVar45 = SUB161(auVar55 >> 0x20,0);
377: uVar51 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(
378: SUB162(CONCAT115(pauVar29[1][7],
379: CONCAT114(uVar50,SUB1614(auVar55,
380: 0))) >> 0x70,0),
381: CONCAT113(uVar66,SUB1613(auVar55,0))) >> 0x68,0),
382: CONCAT112(uVar48,SUB1612(auVar55,0))) >> 0x60,0),
383: CONCAT111(uVar59,SUB1611(auVar55,0))) >> 0x58,0),
384: CONCAT110(uVar47,SUB1610(auVar55,0))) >> 0x50,0),
385: CONCAT19(uVar58,SUB169(auVar55,0))) >> 0x48,0);
386: auVar44 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
387: CONCAT79(uVar51,CONCAT18(bVar45,SUB168(auVar55,0))
388: ) >> 0x40,0),uVar73)) << 0x38) >> 0x30,0),
389: uVar57)) << 0x28) >> 0x20,0),uVar65)) << 0x18 &
390: (undefined  [16])0xffffffffffff0000;
391: uVar56 = SUB161(auVar55 >> 8,0);
392: auVar53 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
393: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
394: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
395: (SUB162(CONCAT115(pauVar29[1][7],
396: CONCAT114(uVar50,SUB1614(auVar55
397: ,0))) >> 0x70,0),
398: CONCAT113(uVar66,SUB1613(auVar55,0))) >> 0x68,0),
399: CONCAT112(uVar48,SUB1612(auVar55,0))) >> 0x60,0),
400: CONCAT111(uVar59,SUB1611(auVar55,0))) >> 0x58,0),
401: CONCAT110(uVar47,SUB1610(auVar55,0))) >> 0x50,0),
402: CONCAT19(uVar58,SUB169(auVar55,0))) >> 0x48,0),
403: CONCAT18(bVar45,SUB168(auVar55,0))) >> 0x40,0),
404: uVar73),(SUB167(auVar55,0) >> 0x18) << 0x30) >>
405: 0x30,0),uVar57),
406: (SUB165(auVar55,0) >> 0x10) << 0x20) >> 0x20,0),
407: uVar65),uVar56)) << 0x10;
408: uVar77 = SUB161(auVar3 >> 0x40,0);
409: uVar78 = SUB161(auVar3 >> 0x50,0);
410: uVar79 = SUB161(auVar3 >> 0x58,0);
411: uVar80 = SUB161(auVar3 >> 0x60,0);
412: uVar81 = SUB161(auVar3 >> 0x70,0);
413: uVar43 = SUB161(auVar3 >> 0x38,0);
414: uVar41 = SUB161(auVar3 >> 0x30,0);
415: uVar40 = SUB161(auVar3 >> 0x28,0);
416: uVar38 = SUB161(auVar3 >> 0x20,0);
417: auVar36 = ZEXT1416(SUB1614((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
418: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
419: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
420: uVar16,CONCAT114(uVar43,SUB1614(auVar3,0))) >>
421: 0x70,0),CONCAT113(uVar15,SUB1613(auVar3,0))) >>
422: 0x68,0),CONCAT112(uVar41,SUB1612(auVar3,0))) >>
423: 0x60,0),CONCAT111(uVar14,SUB1611(auVar3,0))) >>
424: 0x58,0),CONCAT110(uVar40,SUB1610(auVar3,0))) >>
425: 0x50,0),CONCAT19(uVar13,SUB169(auVar3,0))) >> 0x48
426: ,0),CONCAT18(uVar38,SUB168(auVar3,0))) >> 0x40,0),
427: uVar12)) << 0x38) >> 0x30,0),uVar76)) << 0x28) >>
428: 0x10,0) & SUB1614((undefined  [16])0xffffffff00000000 >> 0x10,0) &
429: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0)) << 0x10;
430: uVar49 = SUB161(auVar55 >> 0x18,0);
431: uVar52 = SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
432: pauVar29[1][0xb],
433: CONCAT114(uVar73,SUB1614(auVar44,0))) >> 0x70,0),
434: CONCAT113(uVar83,SUB1613(auVar44,0))) >> 0x68,0),
435: CONCAT112(uVar49,SUB1612(auVar44,0))) >> 0x60,0),
436: CONCAT111(uVar67,SUB1611(auVar44,0))) >> 0x58,0),
437: CONCAT110(uVar57,SUB1610(auVar44,0))) >> 0x50,0);
438: uVar46 = SUB161(auVar55 >> 0x10,0);
439: auVar44 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(uVar52,
440: CONCAT19(uVar70,SUB169(auVar44,0))) >> 0x48,0),
441: CONCAT18(uVar46,SUB168(auVar44,0))) >> 0x40,0),
442: uVar60)) << 0x38) >> 0x30,0),uVar69)) << 0x28 &
443: (undefined  [16])0xffffffff00000000;
444: uVar42 = SUB161(auVar3 >> 0x18,0);
445: uVar39 = SUB161(auVar3 >> 0x10,0);
446: uVar72 = CONCAT12(uVar70,CONCAT11(uVar48,uVar46));
447: uVar88 = CONCAT14(uVar57,CONCAT13(SUB161(auVar55 >> 0x70,0),uVar72));
448: auVar44 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
449: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
450: (CONCAT214(SUB162(CONCAT115(pauVar29[1][0xd],
451: CONCAT114(uVar60,
452: SUB1614(auVar44,0))) >> 0x70,0),
453: CONCAT113(uVar59,SUB1613(auVar44,0))) >> 0x68,0),
454: CONCAT112(uVar65,SUB1612(auVar44,0))) >> 0x60,0),
455: CONCAT111(uVar71,SUB1611(auVar44,0))) >> 0x58,0),
456: CONCAT110(uVar69,SUB1610(auVar44,0))) >> 0x50,0),
457: CONCAT19(uVar47,SUB169(auVar44,0))) >> 0x48,0),
458: CONCAT18(uVar56,SUB168(auVar44,0))) >> 0x40,0),
459: uVar74)) << 0x38) >> 0x10,0) &
460: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0) &
461: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
462: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),bVar45)) <<
463: 8;
464: uVar23 = SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(
465: SUB163(CONCAT214(SUB162(CONCAT115(pauVar29[1][0xe]
466: ,CONCAT114(
467: uVar74,SUB1614(auVar44,0))) >> 0x70,0),
468: CONCAT113(uVar67,SUB1613(auVar44,0))) >> 0x68,0),
469: CONCAT112(pauVar29[1][8],SUB1612(auVar44,0))) >>
470: 0x60,0),CONCAT111(uVar66,SUB1611(auVar44,0))) >>
471: 0x58,0),CONCAT110(uVar58,SUB1610(auVar44,0))) >>
472: 0x50,0),CONCAT19(uVar57,SUB169(auVar44,0))) >>
473: 0x48,0),CONCAT18(uVar64,SUB168(auVar44,0))) >> 0x40,0);
474: uVar31 = (ulong)CONCAT16(uVar67,CONCAT15(uVar66,uVar88)) & 0xff000000;
475: uVar65 = (undefined)((uint6)uVar88 >> 0x10);
476: uVar33 = uVar72 & 0xff00;
477: auVar44 = CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT88(uVar23,(uVar31 >> 0x18) << 0x38) >> 0x20,
478: 0) &
479: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
480: SUB1612((undefined  [16])0xff00000000000000 >> 0x20,0) &
481: SUB1612((undefined  [16])0xffffff0000000000 >> 0x20,0),
482: (uVar33 >> 8) << 0x18) >> 0x18,0),
483: (SUB163(auVar44,0) >> 8) << 0x10) & (undefined  [16])0xffffffffffff0000;
484: auVar53 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
485: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
486: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
487: pauVar29[1][0xb],
488: CONCAT114(SUB161(auVar53 >> 0x38,0),
489: SUB1614(auVar53,0))) >> 0x70,0),
490: CONCAT113(uVar83,SUB1613(auVar53,0))) >> 0x68,0),
491: CONCAT112(SUB161(auVar53 >> 0x30,0),
492: SUB1612(auVar53,0))) >> 0x60,0),
493: CONCAT111(uVar67,SUB1611(auVar53,0))) >> 0x58,0),
494: CONCAT110(SUB161(auVar53 >> 0x28,0),
495: SUB1610(auVar53,0))) >> 0x50,0),
496: CONCAT19(uVar70,SUB169(auVar53,0))) >> 0x48,0),
497: CONCAT18(SUB161(auVar53 >> 0x20,0),
498: SUB168(auVar53,0))) >> 0x40,0),uVar60),
499: (SUB167(auVar53,0) >> 0x18) << 0x30) >> 0x30,0),
500: uVar69),uVar56)) << 0x20 &
501: (undefined  [16])0xffffffffff000000;
502: auVar54 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
503: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
504: (pauVar29[1][0xd],
505: CONCAT114(SUB161(auVar53 >> 0x38,0),
506: SUB1614(auVar53,0))) >> 0x70,0),
507: CONCAT113(uVar59,SUB1613(auVar53,0))) >> 0x68,0),
508: CONCAT112(SUB161(auVar53 >> 0x30,0),
509: SUB1612(auVar53,0))) >> 0x60,0),
510: CONCAT111(uVar71,SUB1611(auVar53,0))) >> 0x58,0),
511: CONCAT110(SUB161(auVar53 >> 0x28,0),
512: SUB1610(auVar53,0))) >> 0x50,0),
513: CONCAT19(uVar47,SUB169(auVar53,0))) >> 0x48,0),
514: CONCAT18(SUB161(auVar53 >> 0x20,0),SUB168(auVar53,0))
515: ) >> 0x40,0),uVar74)) << 0x38;
516: auVar53 = auVar54 & (undefined  [16])0xffff000000000000;
517: auVar54 = auVar54 & (undefined  [16])0xffff000000000000;
518: uVar10 = (uint6)CONCAT14(uVar58,CONCAT13(uVar76,CONCAT12(uVar57,CONCAT11(pauVar29[3][0],uVar64))
519: ));
520: uVar48 = (undefined)(uVar31 >> 0x18);
521: auVar61 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
522: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
523: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
524: (CONCAT115(uVar81,CONCAT114(uVar48,SUB1614(auVar44
525: ,0))) >> 0x70,0),
526: CONCAT113(uVar80,SUB1613(auVar44,0))) >> 0x68,0),
527: CONCAT112(uVar84,SUB1612(auVar44,0))) >> 0x60,0),
528: CONCAT111(uVar78,SUB1611(auVar44,0))) >> 0x58,0),
529: CONCAT110(uVar65,SUB1610(auVar44,0))) >> 0x50,0),
530: CONCAT19(uVar77,SUB169(auVar44,0))) >> 0x48,0),
531: CONCAT18(uVar82,SUB168(auVar44,0))) >> 0x40,0),
532: uVar41) & 0xffffffffffffffff &
533: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
534: ,0)) << 0x38) >> 0x30,0),uVar38)) << 0x28)
535: >> 0x20,0),uVar39)) << 0x18 &
536: (undefined  [16])0xffffffffffff0000;
537: uVar57 = SUB161(auVar54 >> 0x48,0);
538: uVar58 = SUB161(auVar53 >> 0x50,0);
539: uVar59 = SUB161(auVar53 >> 0x58,0);
540: uVar60 = SUB161(auVar53 >> 0x60,0);
541: auVar44 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
542: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
543: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
544: (SUB162(CONCAT115(uVar81,CONCAT114(uVar48,SUB1614(
545: auVar44,0))) >> 0x70,0),
546: CONCAT113(uVar80,SUB1613(auVar44,0))) >> 0x68,0),
547: CONCAT112(uVar84,SUB1612(auVar44,0))) >> 0x60,0),
548: CONCAT111(uVar78,SUB1611(auVar44,0))) >> 0x58,0),
549: CONCAT110(uVar65,SUB1610(auVar44,0))) >> 0x50,0),
550: CONCAT19(uVar77,SUB169(auVar44,0))) >> 0x48,0),
551: CONCAT18(uVar82,SUB168(auVar44,0))) >> 0x40,0),
552: uVar41) & 0xffffffffffffffff &
553: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
554: ,0),(SUB167(auVar44,0) >> 0x18) << 0x30) >>
555: 0x30,0),uVar38),
556: (SUB165(auVar44,0) >> 0x10) << 0x20) >> 0x20,0),
557: uVar39),uVar46)) << 0x10;
558: uVar47 = (undefined)(uVar33 >> 8);
559: uVar71 = (undefined)(uVar10 >> 0x20);
560: uVar70 = (undefined)(uVar10 >> 0x18);
561: uVar69 = (undefined)(uVar10 >> 0x10);
562: uVar56 = (undefined)(uVar10 >> 8);
563: auVar61 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
564: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
565: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
566: (SUB163(CONCAT214(SUB162(CONCAT115(uVar15,
567: CONCAT114(uVar41,SUB1614(auVar61,0))) >> 0x70,0),
568: CONCAT113(uVar66,SUB1613(auVar61,0))) >> 0x68,0),
569: CONCAT112(uVar47,SUB1612(auVar61,0))) >> 0x60,0),
570: CONCAT111(uVar13,SUB1611(auVar61,0))) >> 0x58,0),
571: CONCAT110(uVar38,SUB1610(auVar61,0))) >> 0x50,0),
572: CONCAT19(uVar71,SUB169(auVar61,0))) >> 0x48,0),
573: CONCAT18(bVar45,SUB168(auVar61,0))) >> 0x40,0),
574: uVar70)) << 0x38) >> 0x30,0) &
575: SUB1610((undefined  [16])0xffffffffffffffff >>
576: 0x30,0),uVar69)) << 0x28) >> 0x20,0),
577: uVar56)) << 0x18) >> 0x10,0),uVar64)) << 8;
578: uVar68 = SUB153(CONCAT141(SUB1614((ZEXT1216(SUB1612((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
579: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
580: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
581: uVar20,CONCAT114(uVar12,SUB1614(auVar36,0))) >>
582: 0x70,0),CONCAT113(uVar79,SUB1613(auVar36,0))) >>
583: 0x68,0),CONCAT112(uVar42,SUB1612(auVar36,0))) >>
584: 0x60,0),CONCAT111(uVar19,SUB1611(auVar36,0))) >>
585: 0x58,0),CONCAT110(uVar76,SUB1610(auVar36,0))) >>
586: 0x50,0),CONCAT19(uVar78,SUB169(auVar36,0))) >>
587: 0x48,0),CONCAT18(uVar39,SUB168(auVar36,0))) >>
588: 0x40,0),uVar18)) << 0x38) >> 0x20,0) &
589: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,
590: 0) &
591: SUB1612((undefined  [16])0xffffff0000000000 >> 0x20,
592: 0)) << 0x20) >> 0x10,0) &
593: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),uVar77),0) <<
594: 0x10 | (uint3)CONCAT11(pauVar29[1][8],uVar82);
595: auVar36 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
596: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
597: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
598: uVar15,CONCAT114(SUB161(auVar44 >> 0x38,0),
599: SUB1614(auVar44,0))) >> 0x70,0),
600: CONCAT113(uVar66,SUB1613(auVar44,0))) >> 0x68,0),
601: CONCAT112(SUB161(auVar44 >> 0x30,0),
602: SUB1612(auVar44,0))) >> 0x60,0),
603: CONCAT111(uVar13,SUB1611(auVar44,0))) >> 0x58,0),
604: CONCAT110(SUB161(auVar44 >> 0x28,0),
605: SUB1610(auVar44,0))) >> 0x50,0),
606: CONCAT19(uVar71,SUB169(auVar44,0))) >> 0x48,0),
607: CONCAT18(SUB161(auVar44 >> 0x20,0),
608: SUB168(auVar44,0))) >> 0x40,0),uVar70),
609: (SUB167(auVar44,0) >> 0x18) << 0x30) >> 0x30,0) &
610: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
611: uVar69),uVar46)) << 0x20 &
612: (undefined  [16])0xffffffffff000000;
613: uVar72 = CONCAT12(uVar71,CONCAT11(uVar84,bVar45));
614: uVar88 = CONCAT14(uVar38,CONCAT13(uVar74,uVar72));
615: auVar61 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612((ZEXT916(CONCAT81(
616: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
617: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
618: (SUB162(CONCAT115(uVar19,CONCAT114(uVar70,SUB1614(
619: auVar61,0))) >> 0x70,0),
620: CONCAT113(uVar78,SUB1613(auVar61,0))) >> 0x68,0),
621: CONCAT112(uVar39,SUB1612(auVar61,0))) >> 0x60,0),
622: CONCAT111(uVar67,SUB1611(auVar61,0))) >> 0x58,0),
623: CONCAT110(uVar69,SUB1610(auVar61,0))) >> 0x50,0),
624: CONCAT19(uVar65,SUB169(auVar61,0))) >> 0x48,0),
625: CONCAT18(uVar46,SUB168(auVar61,0))) >> 0x40,0),
626: uVar17) & 0xffffffffffffffff) << 0x38) >> 0x20,0)
627: & SUB1612((undefined  [16])0xffff000000000000 >>
628: 0x20,0) &
629: SUB1612((undefined  [16])0xffffff0000000000 >>
630: 0x20,0),((uVar68 & 0xff00) >> 8) << 0x18)
631: >> 0x18,0),(SUB163(auVar61,0) >> 8) << 0x10) >>
632: 0x10,0),uVar82)) << 8;
633: auVar36 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
634: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
635: (uVar19,CONCAT114(SUB161(auVar36 >> 0x38,0),
636: SUB1614(auVar36,0))) >> 0x70,0),
637: CONCAT113(uVar78,SUB1613(auVar36,0))) >> 0x68,0),
638: CONCAT112(SUB161(auVar36 >> 0x30,0),
639: SUB1612(auVar36,0))) >> 0x60,0),
640: CONCAT111(uVar67,SUB1611(auVar36,0))) >> 0x58,0),
641: CONCAT110(SUB161(auVar36 >> 0x28,0),
642: SUB1610(auVar36,0))) >> 0x50,0),
643: CONCAT19(uVar65,SUB169(auVar36,0))) >> 0x48,0),
644: CONCAT18(SUB161(auVar36 >> 0x20,0),SUB168(auVar36,0))
645: ) >> 0x40,0),uVar17) & 0xffffffffffffffff) << 0x38;
646: auVar44 = auVar36 & (undefined  [16])0xffff000000000000;
647: auVar36 = auVar36 & (undefined  [16])0xffff000000000000;
648: *(undefined (*) [16])(puVar25 + lVar28) =
649: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
650: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
651: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
652: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
653: uVar21,CONCAT114(uVar17,SUB1614(auVar61,0))) >>
654: 0x70,0),CONCAT113(uVar13,SUB1613(auVar61,0))) >>
655: 0x68,0),CONCAT112(uVar56,SUB1612(auVar61,0))) >>
656: 0x60,0),CONCAT111(uVar80,SUB1611(auVar61,0))) >>
657: 0x58,0),CONCAT110((char)((uint6)CONCAT14(uVar65,(
658: uint)uVar68) >> 0x10),SUB1610(auVar61,0))) >> 0x50
659: ,0),CONCAT19(uVar38,SUB169(auVar61,0))) >> 0x48,0)
660: ,CONCAT18(SUB161(auVar3,0),SUB168(auVar61,0))) >>
661: 0x40,0),(((ulong)CONCAT16(uVar13,CONCAT15(uVar80,
662: uVar88)) & 0xff000000) >> 0x18) << 0x38) >> 0x38,0
663: ) & SUB169((undefined  [16])0xffffffffffffffff >>
664: 0x38,0) &
665: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
666: ,0) &
667: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
668: ,0) &
669: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
670: ,0),(SUB167(auVar61,0) >> 0x18) << 0x30) >>
671: 0x30,0),(((uint6)uVar88 & 0xff0000) >> 0x10) <<
672: 0x28) >> 0x28,0),
673: (SUB165(auVar61,0) >> 0x10) << 0x20) >> 0x20,0),
674: ((uVar72 & 0xff00) >> 8) << 0x18) >> 0x18,0),
675: (SUB163(auVar61,0) >> 8) << 0x10) >> 0x10,0),
676: SUB162(auVar55,0) & 0xff | (ushort)bVar45 << 8);
677: uVar64 = SUB161(auVar3 >> 8,0);
678: auVar55 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
679: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
680: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
681: (SUB162(CONCAT115(uVar16,CONCAT114(uVar43,SUB1614(
682: auVar3,0))) >> 0x70,0),
683: CONCAT113(uVar15,SUB1613(auVar3,0))) >> 0x68,0),
684: CONCAT112(uVar41,SUB1612(auVar3,0))) >> 0x60,0),
685: CONCAT111(uVar14,SUB1611(auVar3,0))) >> 0x58,0),
686: CONCAT110(uVar40,SUB1610(auVar3,0))) >> 0x50,0),
687: CONCAT19(uVar13,SUB169(auVar3,0))) >> 0x48,0),
688: CONCAT18(uVar38,SUB168(auVar3,0))) >> 0x40,0),
689: uVar12),(SUB167(auVar3,0) >> 0x18) << 0x30) >>
690: 0x30,0),uVar76),(SUB165(auVar3,0) >> 0x10) << 0x20
691: ) >> 0x20,0),uVar75),uVar64)) << 0x10;
692: auVar55 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
693: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
694: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
695: uVar20,CONCAT114(SUB161(auVar55 >> 0x38,0),
696: SUB1614(auVar55,0))) >> 0x70,0),
697: CONCAT113(uVar79,SUB1613(auVar55,0))) >> 0x68,0),
698: CONCAT112(SUB161(auVar55 >> 0x30,0),
699: SUB1612(auVar55,0))) >> 0x60,0),
700: CONCAT111(uVar19,SUB1611(auVar55,0))) >> 0x58,0),
701: CONCAT110(SUB161(auVar55 >> 0x28,0),
702: SUB1610(auVar55,0))) >> 0x50,0),
703: CONCAT19(uVar78,SUB169(auVar55,0))) >> 0x48,0),
704: CONCAT18(SUB161(auVar55 >> 0x20,0),
705: SUB168(auVar55,0))) >> 0x40,0),uVar18),
706: (SUB167(auVar55,0) >> 0x18) << 0x30) >> 0x30,0),
707: SUB161(auVar3 >> 0x48,0)),uVar64)) << 0x20 &
708: (undefined  [16])0xffffffffff000000;
709: auVar61 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
710: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
711: (uVar22,CONCAT114(SUB161(auVar55 >> 0x38,0),
712: SUB1614(auVar55,0))) >> 0x70,0),
713: CONCAT113(uVar14,SUB1613(auVar55,0))) >> 0x68,0),
714: CONCAT112(SUB161(auVar55 >> 0x30,0),
715: SUB1612(auVar55,0))) >> 0x60,0),
716: CONCAT111(SUB161(auVar3 >> 0x68,0),
717: SUB1611(auVar55,0))) >> 0x58,0),
718: CONCAT110(SUB161(auVar55 >> 0x28,0),
719: SUB1610(auVar55,0))) >> 0x50,0),
720: CONCAT19(uVar40,SUB169(auVar55,0))) >> 0x48,0),
721: CONCAT18(SUB161(auVar55 >> 0x20,0),SUB168(auVar55,0))
722: ) >> 0x40,0),uVar21)) << 0x38;
723: auVar63 = auVar61 & (undefined  [16])0xffff000000000000;
724: auVar61 = auVar61 & (undefined  [16])0xffff000000000000;
725: uVar65 = SUB161(auVar61 >> 0x48,0);
726: uVar64 = SUB161(auVar63 >> 0x50,0);
727: uVar67 = SUB161(auVar63 >> 0x58,0);
728: uVar9 = (ulong)(uVar51 & 0xff000000000000 |
729: (uint7)CONCAT15(SUB161(auVar63 >> 0x68,0),
730: CONCAT14(SUB161(auVar53 >> 0x68,0),
731: CONCAT13(uVar12,CONCAT12(uVar73,CONCAT11(SUB161(auVar63 
732: >> 0x60,0),uVar60))))));
733: uVar31 = ((ulong)CONCAT14(uVar67,CONCAT13(uVar79,CONCAT12(uVar64,CONCAT11(uVar43,uVar65)))) &
734: 0xff00) << 0x10;
735: auVar55 = CONCAT88((long)(CONCAT72(CONCAT61(CONCAT51(CONCAT41(CONCAT31(CONCAT21(CONCAT11(SUB161(
736: auVar3 >> 0x78,0),uVar85),uVar67),uVar59),uVar79),
737: uVar83),uVar64),CONCAT11(uVar58,uVar85)) >> 8),
738: (uVar31 >> 0x18) << 0x38) & (undefined  [16])0xff00000000000000;
739: uVar76 = (undefined)(uVar9 >> 0x28);
740: uVar75 = (undefined)(uVar9 >> 0x20);
741: uVar74 = (undefined)(uVar9 >> 0x10);
742: uVar73 = (undefined)(uVar9 >> 8);
743: auVar55 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
744: ZEXT916(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
745: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
746: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
747: uVar16,CONCAT114((char)(uVar31 >> 0x18),
748: SUB1614(auVar55,0))) >> 0x70,0),
749: CONCAT113((char)(uVar9 >> 0x30),SUB1613(auVar55,0)
750: )) >> 0x68,0),
751: CONCAT112(uVar50,SUB1612(auVar55,0))) >> 0x60,0),
752: CONCAT111(uVar76,SUB1611(auVar55,0))) >> 0x58,0),
753: CONCAT110(uVar65,SUB1610(auVar55,0))) >> 0x50,0),
754: CONCAT19(uVar75,SUB169(auVar55,0))) >> 0x48,0),
755: CONCAT18(uVar57,SUB168(auVar55,0))) >> 0x40,0),
756: ((uVar9 & 0xff000000) >> 0x18) << 0x38) >> 0x38,0)
757: & SUB169((undefined  [16])0xffffffffffffffff >>
758: 0x38,0) &
759: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
760: ,0)) << 0x38) >> 0x30,0),uVar74)) << 0x28)
761: >> 0x20,0),uVar73)) << 0x18) >> 0x10,0),uVar60))
762: << 8;
763: uVar31 = (ulong)CONCAT16(uVar79,uVar52 & 0xff0000000000 |
764: (uint6)CONCAT14(uVar83,CONCAT13(SUB161(auVar63 >> 0x70,0),
765: CONCAT12(uVar64,CONCAT11(SUB161(
766: auVar53 >> 0x70,0),uVar58)))));
767: uVar64 = (undefined)(uVar31 >> 0x10);
768: auVar55 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
769: ZEXT916(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
770: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
771: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
772: uVar20,CONCAT114((char)((uVar9 & 0xff000000) >>
773: 0x18),SUB1614(auVar55,0)))
774: >> 0x70,0),
775: CONCAT113((char)(uVar31 >> 0x30),
776: SUB1613(auVar55,0))) >> 0x68,0),
777: CONCAT112(uVar42,SUB1612(auVar55,0))) >> 0x60,0),
778: CONCAT111((char)(uVar31 >> 0x28),
779: SUB1611(auVar55,0))) >> 0x58,0),
780: CONCAT110(uVar74,SUB1610(auVar55,0))) >> 0x50,0),
781: CONCAT19((char)(uVar31 >> 0x20),SUB169(auVar55,0))
782: ) >> 0x48,0),CONCAT18(uVar49,SUB168(auVar55,0)))
783: >> 0x40,0),((uVar31 & 0xff000000) >> 0x18) << 0x38
784: ) >> 0x38,0) &
785: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
786: ,0) &
787: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
788: ,0)) << 0x38) >> 0x30,0),uVar64)) << 0x28)
789: >> 0x20,0),(char)(uVar31 >> 8)),
790: (SUB163(auVar55,0) >> 8) << 0x10) >> 0x10,0),
791: uVar58)) << 8;
792: uVar72 = CONCAT12(uVar75,CONCAT11(uVar59,uVar57));
793: uVar88 = CONCAT14(uVar65,CONCAT13(SUB161(auVar53 >> 0x78,0),uVar72));
794: *(undefined (*) [16])(puVar5 + lVar28) =
795: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
796: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
797: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
798: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
799: SUB161(auVar63 >> 0x78,0),
800: CONCAT114((char)((uVar31 & 0xff000000) >> 0x18),
801: SUB1614(auVar55,0))) >> 0x70,0),
802: CONCAT113(uVar76,SUB1613(auVar55,0))) >> 0x68,0),
803: CONCAT112(uVar73,SUB1612(auVar55,0))) >> 0x60,0),
804: CONCAT111(uVar67,SUB1611(auVar55,0))) >> 0x58,0),
805: CONCAT110(uVar64,SUB1610(auVar55,0))) >> 0x50,0),
806: CONCAT19(uVar65,SUB169(auVar55,0))) >> 0x48,0),
807: CONCAT18(SUB161(auVar61 >> 0x40,0),
808: SUB168(auVar55,0))) >> 0x40,0),
809: (((ulong)CONCAT16(uVar76,CONCAT15(uVar67,uVar88))
810: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0) &
811: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
812: ,0),(SUB167(auVar55,0) >> 0x18) << 0x30) >>
813: 0x30,0),(((uint6)uVar88 & 0xff0000) >> 0x10) <<
814: 0x28) >> 0x28,0),
815: (SUB165(auVar55,0) >> 0x10) << 0x20) >> 0x20,0),
816: ((uVar72 & 0xff00) >> 8) << 0x18) >> 0x18,0),
817: (SUB163(auVar55,0) >> 8) << 0x10) >> 0x10,0),
818: SUB162(auVar54 >> 0x40,0));
819: *(undefined (*) [16])(puVar6 + lVar28) =
820: CONCAT115(uVar37,CONCAT114(SUB161(auVar44 >> 0x78,0),
821: CONCAT113(uVar15,CONCAT112(SUB161(auVar44 >> 0x70,0),
822: CONCAT111(uVar81,CONCAT110(SUB161(
823: auVar44 >> 0x68,0),
824: CONCAT19(uVar41,CONCAT18(SUB161(auVar44 >> 0x60,0)
825: ,uVar23 & 
826: 0xff00000000000000 |
827: (ulong)CONCAT16(SUB161(auVar44 >> 0x58,0),
828: CONCAT15(uVar66,CONCAT14(SUB161(
829: auVar44 >> 0x50,0),
830: CONCAT13(uVar48,CONCAT12(SUB161(auVar36 >> 0x48,0)
831: ,CONCAT11(uVar47,SUB161(
832: auVar36 >> 0x40,0)))))))))))))));
833: lVar28 = lVar28 + 0x10;
834: pauVar29 = pauVar29[4];
835: } while (uVar32 < uVar4 - 1 >> 4);
836: lVar30 = lVar30 + (ulong)uVar24 * 4;
837: uVar32 = uVar24;
838: if (uVar4 != uVar24) {
839: code_r0x00105ee0:
840: do {
841: uVar31 = (ulong)uVar32;
842: uVar32 = uVar32 + 1;
843: puVar25[uVar31] = *(undefined *)(lVar30 + 1);
844: puVar5[uVar31] = *(undefined *)(lVar30 + 2);
845: puVar6[uVar31] = *(undefined *)(lVar30 + 3);
846: lVar30 = lVar30 + 4;
847: } while (uVar32 < uVar4);
848: }
849: goto code_r0x00105680;
850: code_r0x001054df:
851: lVar28 = 0;
852: uVar32 = 0;
853: do {
854: auVar55 = *pauVar29;
855: uVar32 = uVar32 + 1;
856: uVar64 = pauVar29[1][0];
857: uVar65 = pauVar29[1][1];
858: uVar57 = pauVar29[1][2];
859: uVar73 = pauVar29[1][3];
860: uVar58 = pauVar29[1][4];
861: uVar59 = pauVar29[1][5];
862: uVar66 = pauVar29[1][6];
863: uVar60 = pauVar29[1][9];
864: uVar67 = pauVar29[1][10];
865: uVar74 = pauVar29[1][0xc];
866: auVar3 = pauVar29[2];
867: uVar71 = SUB161(auVar55 >> 0x40,0);
868: uVar79 = SUB161(auVar55 >> 0x48,0);
869: uVar80 = SUB161(auVar55 >> 0x50,0);
870: uVar81 = SUB161(auVar55 >> 0x58,0);
871: uVar82 = SUB161(auVar55 >> 0x60,0);
872: uVar83 = SUB161(auVar55 >> 0x68,0);
873: uVar84 = SUB161(auVar55 >> 0x78,0);
874: uVar75 = pauVar29[3][1];
875: uVar76 = pauVar29[3][2];
876: uVar12 = pauVar29[3][3];
877: uVar13 = pauVar29[3][4];
878: uVar14 = pauVar29[3][5];
879: uVar15 = pauVar29[3][6];
880: uVar16 = pauVar29[3][7];
881: uVar17 = pauVar29[3][8];
882: uVar18 = pauVar29[3][9];
883: uVar19 = pauVar29[3][10];
884: uVar20 = pauVar29[3][0xb];
885: uVar21 = pauVar29[3][0xc];
886: uVar22 = pauVar29[3][0xd];
887: uVar49 = SUB161(auVar55 >> 0x38,0);
888: uVar47 = SUB161(auVar55 >> 0x30,0);
889: uVar46 = SUB161(auVar55 >> 0x28,0);
890: uVar42 = SUB161(auVar55 >> 0x20,0);
891: uVar51 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(
892: SUB162(CONCAT115(pauVar29[1][7],
893: CONCAT114(uVar49,SUB1614(auVar55,
894: 0))) >> 0x70,0),
895: CONCAT113(uVar66,SUB1613(auVar55,0))) >> 0x68,0),
896: CONCAT112(uVar47,SUB1612(auVar55,0))) >> 0x60,0),
897: CONCAT111(uVar59,SUB1611(auVar55,0))) >> 0x58,0),
898: CONCAT110(uVar46,SUB1610(auVar55,0))) >> 0x50,0),
899: CONCAT19(uVar58,SUB169(auVar55,0))) >> 0x48,0);
900: auVar36 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
901: CONCAT79(uVar51,CONCAT18(uVar42,SUB168(auVar55,0))
902: ) >> 0x40,0),uVar73)) << 0x38) >> 0x30,0),
903: uVar57)) << 0x28) >> 0x20,0),uVar65)) << 0x18 &
904: (undefined  [16])0xffffffffffff0000;
905: uVar50 = SUB161(auVar55 >> 8,0);
906: auVar53 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
907: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
908: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
909: (SUB162(CONCAT115(pauVar29[1][7],
910: CONCAT114(uVar49,SUB1614(auVar55
911: ,0))) >> 0x70,0),
912: CONCAT113(uVar66,SUB1613(auVar55,0))) >> 0x68,0),
913: CONCAT112(uVar47,SUB1612(auVar55,0))) >> 0x60,0),
914: CONCAT111(uVar59,SUB1611(auVar55,0))) >> 0x58,0),
915: CONCAT110(uVar46,SUB1610(auVar55,0))) >> 0x50,0),
916: CONCAT19(uVar58,SUB169(auVar55,0))) >> 0x48,0),
917: CONCAT18(uVar42,SUB168(auVar55,0))) >> 0x40,0),
918: uVar73),(SUB167(auVar55,0) >> 0x18) << 0x30) >>
919: 0x30,0),uVar57),
920: (SUB165(auVar55,0) >> 0x10) << 0x20) >> 0x20,0),
921: uVar65),uVar50)) << 0x10;
922: uVar56 = SUB161(auVar3 >> 0x40,0);
923: uVar77 = SUB161(auVar3 >> 0x50,0);
924: uVar78 = SUB161(auVar3 >> 0x58,0);
925: uVar69 = SUB161(auVar3 >> 0x60,0);
926: uVar70 = SUB161(auVar3 >> 0x70,0);
927: uVar41 = SUB161(auVar3 >> 0x38,0);
928: uVar40 = SUB161(auVar3 >> 0x30,0);
929: uVar39 = SUB161(auVar3 >> 0x28,0);
930: uVar37 = SUB161(auVar3 >> 0x20,0);
931: uVar48 = SUB161(auVar55 >> 0x18,0);
932: uVar52 = SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
933: pauVar29[1][0xb],
934: CONCAT114(uVar73,SUB1614(auVar36,0))) >> 0x70,0),
935: CONCAT113(uVar81,SUB1613(auVar36,0))) >> 0x68,0),
936: CONCAT112(uVar48,SUB1612(auVar36,0))) >> 0x60,0),
937: CONCAT111(uVar67,SUB1611(auVar36,0))) >> 0x58,0),
938: CONCAT110(uVar57,SUB1610(auVar36,0))) >> 0x50,0);
939: uVar43 = SUB161(auVar55 >> 0x10,0);
940: auVar36 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(uVar52,
941: CONCAT19(uVar80,SUB169(auVar36,0))) >> 0x48,0),
942: CONCAT18(uVar43,SUB168(auVar36,0))) >> 0x40,0),
943: uVar60)) << 0x38) >> 0x30,0),uVar79)) << 0x28 &
944: (undefined  [16])0xffffffff00000000;
945: uVar38 = SUB161(auVar3 >> 0x10,0);
946: uVar72 = CONCAT12(uVar80,CONCAT11(uVar47,uVar43));
947: uVar88 = CONCAT14(uVar57,CONCAT13(SUB161(auVar55 >> 0x70,0),uVar72));
948: auVar36 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
949: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
950: (CONCAT214(SUB162(CONCAT115(pauVar29[1][0xd],
951: CONCAT114(uVar60,
952: SUB1614(auVar36,0))) >> 0x70,0),
953: CONCAT113(uVar59,SUB1613(auVar36,0))) >> 0x68,0),
954: CONCAT112(uVar65,SUB1612(auVar36,0))) >> 0x60,0),
955: CONCAT111(uVar83,SUB1611(auVar36,0))) >> 0x58,0),
956: CONCAT110(uVar79,SUB1610(auVar36,0))) >> 0x50,0),
957: CONCAT19(uVar46,SUB169(auVar36,0))) >> 0x48,0),
958: CONCAT18(uVar50,SUB168(auVar36,0))) >> 0x40,0),
959: uVar74)) << 0x38) >> 0x10,0) &
960: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0) &
961: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
962: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),uVar42)) <<
963: 8;
964: uVar9 = SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(
965: SUB163(CONCAT214(SUB162(CONCAT115(pauVar29[1][0xe]
966: ,CONCAT114(
967: uVar74,SUB1614(auVar36,0))) >> 0x70,0),
968: CONCAT113(uVar67,SUB1613(auVar36,0))) >> 0x68,0),
969: CONCAT112(pauVar29[1][8],SUB1612(auVar36,0))) >>
970: 0x60,0),CONCAT111(uVar66,SUB1611(auVar36,0))) >>
971: 0x58,0),CONCAT110(uVar58,SUB1610(auVar36,0))) >>
972: 0x50,0),CONCAT19(uVar57,SUB169(auVar36,0))) >>
973: 0x48,0),CONCAT18(uVar64,SUB168(auVar36,0))) >> 0x40,0);
974: uVar31 = (ulong)CONCAT16(uVar67,CONCAT15(uVar66,uVar88)) & 0xff000000;
975: uVar65 = (undefined)((uint6)uVar88 >> 0x10);
976: uVar33 = uVar72 & 0xff00;
977: auVar44 = CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT88(uVar9,(uVar31 >> 0x18) << 0x38) >> 0x20,0
978: ) &
979: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
980: SUB1612((undefined  [16])0xff00000000000000 >> 0x20,0) &
981: SUB1612((undefined  [16])0xffffff0000000000 >> 0x20,0),
982: (uVar33 >> 8) << 0x18) >> 0x18,0),
983: (SUB163(auVar36,0) >> 8) << 0x10) & (undefined  [16])0xffffffffffff0000;
984: auVar36 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
985: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
986: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
987: pauVar29[1][0xb],
988: CONCAT114(SUB161(auVar53 >> 0x38,0),
989: SUB1614(auVar53,0))) >> 0x70,0),
990: CONCAT113(uVar81,SUB1613(auVar53,0))) >> 0x68,0),
991: CONCAT112(SUB161(auVar53 >> 0x30,0),
992: SUB1612(auVar53,0))) >> 0x60,0),
993: CONCAT111(uVar67,SUB1611(auVar53,0))) >> 0x58,0),
994: CONCAT110(SUB161(auVar53 >> 0x28,0),
995: SUB1610(auVar53,0))) >> 0x50,0),
996: CONCAT19(uVar80,SUB169(auVar53,0))) >> 0x48,0),
997: CONCAT18(SUB161(auVar53 >> 0x20,0),
998: SUB168(auVar53,0))) >> 0x40,0),uVar60),
999: (SUB167(auVar53,0) >> 0x18) << 0x30) >> 0x30,0),
1000: uVar79),uVar50)) << 0x20 &
1001: (undefined  [16])0xffffffffff000000;
1002: auVar54 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
1003: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
1004: (pauVar29[1][0xd],
1005: CONCAT114(SUB161(auVar36 >> 0x38,0),
1006: SUB1614(auVar36,0))) >> 0x70,0),
1007: CONCAT113(uVar59,SUB1613(auVar36,0))) >> 0x68,0),
1008: CONCAT112(SUB161(auVar36 >> 0x30,0),
1009: SUB1612(auVar36,0))) >> 0x60,0),
1010: CONCAT111(uVar83,SUB1611(auVar36,0))) >> 0x58,0),
1011: CONCAT110(SUB161(auVar36 >> 0x28,0),
1012: SUB1610(auVar36,0))) >> 0x50,0),
1013: CONCAT19(uVar46,SUB169(auVar36,0))) >> 0x48,0),
1014: CONCAT18(SUB161(auVar36 >> 0x20,0),SUB168(auVar36,0))
1015: ) >> 0x40,0),uVar74)) << 0x38;
1016: auVar53 = auVar54 & (undefined  [16])0xffff000000000000;
1017: auVar54 = auVar54 & (undefined  [16])0xffff000000000000;
1018: uVar10 = (uint6)CONCAT14(uVar58,CONCAT13(uVar76,CONCAT12(uVar57,CONCAT11(pauVar29[3][0],uVar64))
1019: ));
1020: uVar46 = (undefined)(uVar31 >> 0x18);
1021: auVar36 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
1022: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
1023: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
1024: (SUB162(CONCAT115(uVar70,CONCAT114(uVar46,SUB1614(
1025: auVar44,0))) >> 0x70,0),
1026: CONCAT113(uVar69,SUB1613(auVar44,0))) >> 0x68,0),
1027: CONCAT112(uVar82,SUB1612(auVar44,0))) >> 0x60,0),
1028: CONCAT111(uVar77,SUB1611(auVar44,0))) >> 0x58,0),
1029: CONCAT110(uVar65,SUB1610(auVar44,0))) >> 0x50,0),
1030: CONCAT19(uVar56,SUB169(auVar44,0))) >> 0x48,0),
1031: CONCAT18(uVar71,SUB168(auVar44,0))) >> 0x40,0),
1032: uVar40) & 0xffffffffffffffff &
1033: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1034: ,0),(SUB167(auVar44,0) >> 0x18) << 0x30) >>
1035: 0x30,0),uVar37),
1036: (SUB165(auVar44,0) >> 0x10) << 0x20) >> 0x20,0),
1037: uVar38),uVar43));
1038: auVar61 = auVar36 << 0x10;
1039: uVar57 = SUB161(auVar54 >> 0x48,0);
1040: uVar58 = SUB161(auVar53 >> 0x50,0);
1041: uVar59 = SUB161(auVar53 >> 0x58,0);
1042: uVar60 = SUB161(auVar53 >> 0x60,0);
1043: auVar44 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
1044: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
1045: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
1046: (CONCAT115(uVar70,CONCAT114(uVar46,SUB1614(auVar44
1047: ,0))) >> 0x70,0),
1048: CONCAT113(uVar69,SUB1613(auVar44,0))) >> 0x68,0),
1049: CONCAT112(uVar82,SUB1612(auVar44,0))) >> 0x60,0),
1050: CONCAT111(uVar77,SUB1611(auVar44,0))) >> 0x58,0),
1051: CONCAT110(uVar65,SUB1610(auVar44,0))) >> 0x50,0),
1052: CONCAT19(uVar56,SUB169(auVar44,0))) >> 0x48,0),
1053: CONCAT18(uVar71,SUB168(auVar44,0))) >> 0x40,0),
1054: uVar40) & 0xffffffffffffffff &
1055: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1056: ,0)) << 0x38) >> 0x30,0),uVar37)) << 0x28)
1057: >> 0x20,0),uVar38)) << 0x18 &
1058: (undefined  [16])0xffffffffffff0000;
1059: uVar71 = (undefined)(uVar10 >> 0x20);
1060: uVar70 = (undefined)(uVar10 >> 0x18);
1061: uVar69 = (undefined)(uVar10 >> 0x10);
1062: auVar62 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
1063: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1064: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1065: uVar15,CONCAT114(SUB161(auVar61 >> 0x38,0),
1066: SUB1614(auVar61,0))) >> 0x70,0),
1067: CONCAT113(uVar66,SUB1613(auVar61,0))) >> 0x68,0),
1068: CONCAT112(SUB161(auVar61 >> 0x30,0),
1069: SUB1612(auVar61,0))) >> 0x60,0),
1070: CONCAT111(uVar13,SUB1611(auVar61,0))) >> 0x58,0),
1071: CONCAT110(SUB161(auVar61 >> 0x28,0),
1072: SUB1610(auVar61,0))) >> 0x50,0),
1073: CONCAT19(uVar71,SUB169(auVar61,0))) >> 0x48,0),
1074: CONCAT18(SUB161(auVar61 >> 0x20,0),
1075: SUB168(auVar61,0))) >> 0x40,0),uVar70),
1076: (SUB167(auVar61,0) >> 0x18) << 0x30) >> 0x30,0) &
1077: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
1078: uVar69),uVar43)) << 0x20;
1079: auVar63 = auVar62 & (undefined  [16])0xffffffffff000000;
1080: auVar62 = auVar62 & (undefined  [16])0xffffffffff000000;
1081: uVar65 = SUB161(auVar61 >> 0x40,0);
1082: uVar72 = CONCAT12(SUB161(auVar61 >> 0x48,0),CONCAT11(pauVar29[1][8],uVar65));
1083: uVar46 = SUB161(auVar36 >> 0x40,0);
1084: uVar47 = SUB161(auVar36 >> 0x48,0);
1085: uVar50 = SUB161(auVar36 >> 0x58,0);
1086: uVar56 = (undefined)(uVar10 >> 8);
1087: auVar44 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1088: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
1089: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
1090: (SUB163(CONCAT214(SUB162(CONCAT115(uVar15,
1091: CONCAT114(uVar40,SUB1614(auVar44,0))) >> 0x70,0),
1092: CONCAT113(uVar66,SUB1613(auVar44,0))) >> 0x68,0),
1093: CONCAT112((char)(uVar33 >> 8),SUB1612(auVar44,0)))
1094: >> 0x60,0),CONCAT111(uVar13,SUB1611(auVar44,0)))
1095: >> 0x58,0),CONCAT110(uVar37,SUB1610(auVar44,0)))
1096: >> 0x50,0),CONCAT19(uVar71,SUB169(auVar44,0))) >>
1097: 0x48,0),CONCAT18(uVar42,SUB168(auVar44,0))) >>
1098: 0x40,0),uVar70)) << 0x38) >> 0x30,0) &
1099: SUB1610((undefined  [16])0xffffffffffffffff >>
1100: 0x30,0),uVar69)) << 0x28) >> 0x20,0),
1101: uVar56)) << 0x18) >> 0x10,0),uVar64)) << 8;
1102: bVar45 = SUB161(auVar62 >> 0x40,0);
1103: uVar86 = CONCAT12(SUB161(auVar62 >> 0x48,0),CONCAT11(SUB161(auVar36 >> 0x50,0),bVar45));
1104: uVar42 = SUB161(auVar63 >> 0x50,0);
1105: uVar87 = CONCAT14(uVar42,CONCAT13(uVar74,uVar86));
1106: uVar71 = SUB161(auVar63 >> 0x58,0);
1107: auVar62 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
1108: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
1109: (uVar19,CONCAT114(SUB161(auVar62 >> 0x38,0),
1110: SUB1614(auVar62,0))) >> 0x70,0),
1111: CONCAT113(uVar47,SUB1613(auVar62,0))) >> 0x68,0),
1112: CONCAT112(SUB161(auVar62 >> 0x30,0),
1113: SUB1612(auVar62,0))) >> 0x60,0),
1114: CONCAT111(uVar67,SUB1611(auVar62,0))) >> 0x58,0),
1115: CONCAT110(SUB161(auVar62 >> 0x28,0),
1116: SUB1610(auVar62,0))) >> 0x50,0),
1117: CONCAT19(uVar46,SUB169(auVar62,0))) >> 0x48,0),
1118: CONCAT18(SUB161(auVar62 >> 0x20,0),SUB168(auVar62,0))
1119: ) >> 0x40,0),uVar17) & 0xffffffffffffffff) << 0x38;
1120: auVar61 = auVar62 & (undefined  [16])0xffff000000000000;
1121: auVar62 = auVar62 & (undefined  [16])0xffff000000000000;
1122: auVar44 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612((ZEXT1016(SUB1610((
1123: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
1124: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
1125: (SUB163(CONCAT214(SUB162(CONCAT115(uVar19,
1126: CONCAT114(uVar70,SUB1614(auVar44,0))) >> 0x70,0),
1127: CONCAT113(uVar47,SUB1613(auVar44,0))) >> 0x68,0),
1128: CONCAT112(uVar38,SUB1612(auVar44,0))) >> 0x60,0),
1129: CONCAT111(uVar67,SUB1611(auVar44,0))) >> 0x58,0),
1130: CONCAT110(uVar69,SUB1610(auVar44,0))) >> 0x50,0),
1131: CONCAT19(uVar46,SUB169(auVar44,0))) >> 0x48,0),
1132: CONCAT18(uVar43,SUB168(auVar44,0))) >> 0x40,0),
1133: uVar17)) << 0x38) >> 0x30,0) &
1134: SUB1610((undefined  [16])0xffffffffffffffff >>
1135: 0x30,0)) << 0x30) >> 0x20,0) &
1136: SUB1612((undefined  [16])0xffffff0000000000 >>
1137: 0x20,0),((uVar72 & 0xff00) >> 8) << 0x18)
1138: >> 0x18,0),(SUB163(auVar44,0) >> 8) << 0x10) >>
1139: 0x10,0),uVar65)) << 8;
1140: *(undefined (*) [16])(puVar25 + lVar28) =
1141: CONCAT115(pauVar29[3][0xe],
1142: CONCAT114(SUB161(auVar61 >> 0x78,0),
1143: CONCAT113(SUB161(auVar63 >> 0x78,0),
1144: CONCAT112(SUB161(auVar61 >> 0x70,0),
1145: CONCAT111(SUB161(auVar36 >> 0x68,0),
1146: CONCAT110(SUB161(auVar61 >> 0x68,0),
1147: CONCAT19(SUB161(auVar63 >> 0x70
1148: ,0),
1149: CONCAT18(SUB161(
1150: auVar61 >> 0x60,0),
1151: uVar9 & 0xff00000000000000 |
1152: (ulong)CONCAT16(SUB161(auVar61 >> 0x58,0),
1153: CONCAT15(SUB161(auVar63 >> 0x68,0)
1154: ,CONCAT14(SUB161(auVar61 
1155: >> 0x50,0),
1156: CONCAT13(SUB161(auVar36 >> 0x60,0),
1157: CONCAT12(SUB161(auVar62 >> 0x48,0),
1158: CONCAT11(SUB161(auVar63 >> 0x60,
1159: 0),
1160: SUB161(auVar62 >> 0x40,
1161: 0)))))))))))))))
1162: ;
1163: uVar64 = SUB161(auVar3 >> 8,0);
1164: auVar36 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
1165: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
1166: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
1167: (SUB162(CONCAT115(uVar16,CONCAT114(uVar41,SUB1614(
1168: auVar3,0))) >> 0x70,0),
1169: CONCAT113(uVar15,SUB1613(auVar3,0))) >> 0x68,0),
1170: CONCAT112(uVar40,SUB1612(auVar3,0))) >> 0x60,0),
1171: CONCAT111(uVar14,SUB1611(auVar3,0))) >> 0x58,0),
1172: CONCAT110(uVar39,SUB1610(auVar3,0))) >> 0x50,0),
1173: CONCAT19(uVar13,SUB169(auVar3,0))) >> 0x48,0),
1174: CONCAT18(uVar37,SUB168(auVar3,0))) >> 0x40,0),
1175: uVar12),(SUB167(auVar3,0) >> 0x18) << 0x30) >>
1176: 0x30,0),uVar76),(SUB165(auVar3,0) >> 0x10) << 0x20
1177: ) >> 0x20,0),uVar75),uVar64)) << 0x10;
1178: auVar36 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
1179: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1180: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1181: uVar20,CONCAT114(SUB161(auVar36 >> 0x38,0),
1182: SUB1614(auVar36,0))) >> 0x70,0),
1183: CONCAT113(uVar78,SUB1613(auVar36,0))) >> 0x68,0),
1184: CONCAT112(SUB161(auVar36 >> 0x30,0),
1185: SUB1612(auVar36,0))) >> 0x60,0),
1186: CONCAT111(uVar19,SUB1611(auVar36,0))) >> 0x58,0),
1187: CONCAT110(SUB161(auVar36 >> 0x28,0),
1188: SUB1610(auVar36,0))) >> 0x50,0),
1189: CONCAT19(uVar77,SUB169(auVar36,0))) >> 0x48,0),
1190: CONCAT18(SUB161(auVar36 >> 0x20,0),
1191: SUB168(auVar36,0))) >> 0x40,0),uVar18),
1192: (SUB167(auVar36,0) >> 0x18) << 0x30) >> 0x30,0),
1193: SUB161(auVar3 >> 0x48,0)),uVar64)) << 0x20 &
1194: (undefined  [16])0xffffffffff000000;
1195: auVar61 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
1196: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
1197: (uVar22,CONCAT114(SUB161(auVar36 >> 0x38,0),
1198: SUB1614(auVar36,0))) >> 0x70,0),
1199: CONCAT113(uVar14,SUB1613(auVar36,0))) >> 0x68,0),
1200: CONCAT112(SUB161(auVar36 >> 0x30,0),
1201: SUB1612(auVar36,0))) >> 0x60,0),
1202: CONCAT111(SUB161(auVar3 >> 0x68,0),
1203: SUB1611(auVar36,0))) >> 0x58,0),
1204: CONCAT110(SUB161(auVar36 >> 0x28,0),
1205: SUB1610(auVar36,0))) >> 0x50,0),
1206: CONCAT19(uVar39,SUB169(auVar36,0))) >> 0x48,0),
1207: CONCAT18(SUB161(auVar36 >> 0x20,0),SUB168(auVar36,0))
1208: ) >> 0x40,0),uVar21)) << 0x38;
1209: auVar63 = auVar61 & (undefined  [16])0xffff000000000000;
1210: auVar61 = auVar61 & (undefined  [16])0xffff000000000000;
1211: uVar65 = SUB161(auVar61 >> 0x48,0);
1212: uVar64 = SUB161(auVar63 >> 0x50,0);
1213: uVar66 = SUB161(auVar63 >> 0x58,0);
1214: uVar9 = (ulong)(uVar51 & 0xff000000000000 |
1215: (uint7)CONCAT15(SUB161(auVar63 >> 0x68,0),
1216: CONCAT14(SUB161(auVar53 >> 0x68,0),
1217: CONCAT13(uVar12,CONCAT12(uVar73,CONCAT11(SUB161(auVar63 
1218: >> 0x60,0),uVar60))))));
1219: uVar31 = ((ulong)CONCAT14(uVar66,CONCAT13(uVar78,CONCAT12(uVar64,CONCAT11(uVar41,uVar65)))) &
1220: 0xff00) << 0x10;
1221: auVar36 = CONCAT88((long)(CONCAT72(CONCAT61(CONCAT51(CONCAT41(CONCAT31(CONCAT21(CONCAT11(SUB161(
1222: auVar3 >> 0x78,0),uVar84),uVar66),uVar59),uVar78),
1223: uVar81),uVar64),CONCAT11(uVar58,uVar84)) >> 8),
1224: (uVar31 >> 0x18) << 0x38) & (undefined  [16])0xff00000000000000;
1225: uVar75 = (undefined)(uVar9 >> 0x28);
1226: uVar74 = (undefined)(uVar9 >> 0x20);
1227: uVar67 = (undefined)(uVar9 >> 0x10);
1228: uVar73 = (undefined)(uVar9 >> 8);
1229: auVar36 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1230: ZEXT916(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1231: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1232: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1233: uVar16,CONCAT114((char)(uVar31 >> 0x18),
1234: SUB1614(auVar36,0))) >> 0x70,0),
1235: CONCAT113((char)(uVar9 >> 0x30),SUB1613(auVar36,0)
1236: )) >> 0x68,0),
1237: CONCAT112(uVar49,SUB1612(auVar36,0))) >> 0x60,0),
1238: CONCAT111(uVar75,SUB1611(auVar36,0))) >> 0x58,0),
1239: CONCAT110(uVar65,SUB1610(auVar36,0))) >> 0x50,0),
1240: CONCAT19(uVar74,SUB169(auVar36,0))) >> 0x48,0),
1241: CONCAT18(uVar57,SUB168(auVar36,0))) >> 0x40,0),
1242: ((uVar9 & 0xff000000) >> 0x18) << 0x38) >> 0x38,0)
1243: & SUB169((undefined  [16])0xffffffffffffffff >>
1244: 0x38,0) &
1245: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1246: ,0)) << 0x38) >> 0x30,0),uVar67)) << 0x28)
1247: >> 0x20,0),uVar73)) << 0x18) >> 0x10,0),uVar60))
1248: << 8;
1249: uVar31 = (ulong)CONCAT16(uVar78,uVar52 & 0xff0000000000 |
1250: (uint6)CONCAT14(uVar81,CONCAT13(SUB161(auVar63 >> 0x70,0),
1251: CONCAT12(uVar64,CONCAT11(SUB161(
1252: auVar53 >> 0x70,0),uVar58)))));
1253: uVar64 = (undefined)(uVar31 >> 0x10);
1254: auVar36 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1255: ZEXT916(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1256: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1257: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1258: uVar20,CONCAT114((char)((uVar9 & 0xff000000) >>
1259: 0x18),SUB1614(auVar36,0)))
1260: >> 0x70,0),
1261: CONCAT113((char)(uVar31 >> 0x30),
1262: SUB1613(auVar36,0))) >> 0x68,0),
1263: CONCAT112(SUB161(auVar3 >> 0x18,0),
1264: SUB1612(auVar36,0))) >> 0x60,0),
1265: CONCAT111((char)(uVar31 >> 0x28),
1266: SUB1611(auVar36,0))) >> 0x58,0),
1267: CONCAT110(uVar67,SUB1610(auVar36,0))) >> 0x50,0),
1268: CONCAT19((char)(uVar31 >> 0x20),SUB169(auVar36,0))
1269: ) >> 0x48,0),CONCAT18(uVar48,SUB168(auVar36,0)))
1270: >> 0x40,0),((uVar31 & 0xff000000) >> 0x18) << 0x38
1271: ) >> 0x38,0) &
1272: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1273: ,0) &
1274: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1275: ,0)) << 0x38) >> 0x30,0),uVar64)) << 0x28)
1276: >> 0x20,0),(char)(uVar31 >> 8)),
1277: (SUB163(auVar36,0) >> 8) << 0x10) >> 0x10,0),
1278: uVar58)) << 8;
1279: uVar68 = CONCAT12(uVar74,CONCAT11(uVar59,uVar57));
1280: uVar88 = CONCAT14(uVar65,CONCAT13(SUB161(auVar53 >> 0x78,0),uVar68));
1281: *(undefined (*) [16])(puVar5 + lVar28) =
1282: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
1283: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1284: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1285: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1286: SUB161(auVar63 >> 0x78,0),
1287: CONCAT114((char)((uVar31 & 0xff000000) >> 0x18),
1288: SUB1614(auVar36,0))) >> 0x70,0),
1289: CONCAT113(uVar75,SUB1613(auVar36,0))) >> 0x68,0),
1290: CONCAT112(uVar73,SUB1612(auVar36,0))) >> 0x60,0),
1291: CONCAT111(uVar66,SUB1611(auVar36,0))) >> 0x58,0),
1292: CONCAT110(uVar64,SUB1610(auVar36,0))) >> 0x50,0),
1293: CONCAT19(uVar65,SUB169(auVar36,0))) >> 0x48,0),
1294: CONCAT18(SUB161(auVar61 >> 0x40,0),
1295: SUB168(auVar36,0))) >> 0x40,0),
1296: (((ulong)CONCAT16(uVar75,CONCAT15(uVar66,uVar88))
1297: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0) &
1298: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1299: ,0),(SUB167(auVar36,0) >> 0x18) << 0x30) >>
1300: 0x30,0),(((uint6)uVar88 & 0xff0000) >> 0x10) <<
1301: 0x28) >> 0x28,0),
1302: (SUB165(auVar36,0) >> 0x10) << 0x20) >> 0x20,0),
1303: ((uVar68 & 0xff00) >> 8) << 0x18) >> 0x18,0),
1304: (SUB163(auVar36,0) >> 8) << 0x10) >> 0x10,0),
1305: SUB162(auVar54 >> 0x40,0));
1306: *(undefined (*) [16])(puVar6 + lVar28) =
1307: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
1308: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1309: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1310: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1311: uVar21,CONCAT114(uVar17,SUB1614(auVar44,0))) >>
1312: 0x70,0),CONCAT113(uVar71,SUB1613(auVar44,0))) >>
1313: 0x68,0),CONCAT112(uVar56,SUB1612(auVar44,0))) >>
1314: 0x60,0),CONCAT111(uVar50,SUB1611(auVar44,0))) >>
1315: 0x58,0),CONCAT110((char)((uint6)CONCAT14(uVar46,(
1316: uint)uVar72) >> 0x10),SUB1610(auVar44,0))) >> 0x50
1317: ,0),CONCAT19(uVar42,SUB169(auVar44,0))) >> 0x48,0)
1318: ,CONCAT18(SUB161(auVar3,0),SUB168(auVar44,0))) >>
1319: 0x40,0),(((ulong)CONCAT16(uVar71,CONCAT15(uVar50,
1320: uVar87)) & 0xff000000) >> 0x18) << 0x38) >> 0x38,0
1321: ) & SUB169((undefined  [16])0xffffffffffffffff >>
1322: 0x38,0) &
1323: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1324: ,0) &
1325: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1326: ,0),(SUB167(auVar44,0) >> 0x18) << 0x30) >>
1327: 0x30,0),(((uint6)uVar87 & 0xff0000) >> 0x10) <<
1328: 0x28) >> 0x28,0),
1329: (SUB165(auVar44,0) >> 0x10) << 0x20) >> 0x20,0),
1330: ((uVar86 & 0xff00) >> 8) << 0x18) >> 0x18,0),
1331: (SUB163(auVar44,0) >> 8) << 0x10) >> 0x10,0),
1332: SUB162(auVar55,0) & 0xff | (ushort)bVar45 << 8);
1333: lVar28 = lVar28 + 0x10;
1334: pauVar29 = pauVar29[4];
1335: } while (uVar32 < uVar4 - 1 >> 4);
1336: lVar30 = lVar30 + (ulong)uVar24 * 4;
1337: uVar32 = uVar24;
1338: if (uVar4 != uVar24) {
1339: code_r0x00105f50:
1340: do {
1341: uVar31 = (ulong)uVar32;
1342: uVar32 = uVar32 + 1;
1343: puVar25[uVar31] = *(undefined *)(lVar30 + 3);
1344: puVar5[uVar31] = *(undefined *)(lVar30 + 2);
1345: puVar6[uVar31] = *(undefined *)(lVar30 + 1);
1346: lVar30 = lVar30 + 4;
1347: } while (uVar32 < uVar4);
1348: }
1349: goto code_r0x001053e0;
1350: code_r0x00105d78:
1351: lVar30 = 0;
1352: uVar33 = 0;
1353: do {
1354: auVar55 = *(undefined (*) [16])(puVar25 + lVar30 * 4);
1355: uVar33 = uVar33 + 1;
1356: puVar1 = puVar25 + lVar30 * 4 + 0x10;
1357: uVar64 = *puVar1;
1358: uVar65 = puVar1[1];
1359: uVar57 = puVar1[2];
1360: uVar73 = puVar1[3];
1361: uVar58 = puVar1[4];
1362: uVar59 = puVar1[5];
1363: uVar66 = puVar1[6];
1364: uVar60 = puVar1[9];
1365: uVar67 = puVar1[10];
1366: uVar74 = puVar1[0xc];
1367: auVar3 = *(undefined (*) [16])(puVar25 + lVar30 * 4 + 0x20);
1368: uVar71 = SUB161(auVar55 >> 0x40,0);
1369: uVar79 = SUB161(auVar55 >> 0x48,0);
1370: uVar80 = SUB161(auVar55 >> 0x50,0);
1371: uVar81 = SUB161(auVar55 >> 0x58,0);
1372: uVar82 = SUB161(auVar55 >> 0x60,0);
1373: uVar83 = SUB161(auVar55 >> 0x68,0);
1374: uVar84 = SUB161(auVar55 >> 0x78,0);
1375: puVar2 = puVar25 + lVar30 * 4 + 0x30;
1376: uVar75 = puVar2[1];
1377: uVar76 = puVar2[2];
1378: uVar12 = puVar2[3];
1379: uVar13 = puVar2[4];
1380: uVar14 = puVar2[5];
1381: uVar15 = puVar2[6];
1382: uVar16 = puVar2[7];
1383: uVar17 = puVar2[8];
1384: uVar18 = puVar2[9];
1385: uVar19 = puVar2[10];
1386: uVar20 = puVar2[0xb];
1387: uVar21 = puVar2[0xc];
1388: uVar22 = puVar2[0xd];
1389: uVar49 = SUB161(auVar55 >> 0x38,0);
1390: uVar47 = SUB161(auVar55 >> 0x30,0);
1391: uVar46 = SUB161(auVar55 >> 0x28,0);
1392: uVar42 = SUB161(auVar55 >> 0x20,0);
1393: uVar51 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(
1394: SUB162(CONCAT115(puVar1[7],
1395: CONCAT114(uVar49,SUB1614(auVar55,
1396: 0))) >> 0x70,0),
1397: CONCAT113(uVar66,SUB1613(auVar55,0))) >> 0x68,0),
1398: CONCAT112(uVar47,SUB1612(auVar55,0))) >> 0x60,0),
1399: CONCAT111(uVar59,SUB1611(auVar55,0))) >> 0x58,0),
1400: CONCAT110(uVar46,SUB1610(auVar55,0))) >> 0x50,0),
1401: CONCAT19(uVar58,SUB169(auVar55,0))) >> 0x48,0);
1402: auVar36 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
1403: CONCAT79(uVar51,CONCAT18(uVar42,SUB168(auVar55,0))
1404: ) >> 0x40,0),uVar73)) << 0x38) >> 0x30,0),
1405: uVar57)) << 0x28) >> 0x20,0),uVar65)) << 0x18 &
1406: (undefined  [16])0xffffffffffff0000;
1407: uVar50 = SUB161(auVar55 >> 8,0);
1408: auVar53 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
1409: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
1410: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
1411: (SUB162(CONCAT115(puVar1[7],
1412: CONCAT114(uVar49,SUB1614(auVar55
1413: ,0))) >> 0x70,0),
1414: CONCAT113(uVar66,SUB1613(auVar55,0))) >> 0x68,0),
1415: CONCAT112(uVar47,SUB1612(auVar55,0))) >> 0x60,0),
1416: CONCAT111(uVar59,SUB1611(auVar55,0))) >> 0x58,0),
1417: CONCAT110(uVar46,SUB1610(auVar55,0))) >> 0x50,0),
1418: CONCAT19(uVar58,SUB169(auVar55,0))) >> 0x48,0),
1419: CONCAT18(uVar42,SUB168(auVar55,0))) >> 0x40,0),
1420: uVar73),(SUB167(auVar55,0) >> 0x18) << 0x30) >>
1421: 0x30,0),uVar57),
1422: (SUB165(auVar55,0) >> 0x10) << 0x20) >> 0x20,0),
1423: uVar65),uVar50)) << 0x10;
1424: uVar56 = SUB161(auVar3 >> 0x40,0);
1425: uVar77 = SUB161(auVar3 >> 0x50,0);
1426: uVar78 = SUB161(auVar3 >> 0x58,0);
1427: uVar69 = SUB161(auVar3 >> 0x60,0);
1428: uVar70 = SUB161(auVar3 >> 0x70,0);
1429: uVar41 = SUB161(auVar3 >> 0x38,0);
1430: uVar40 = SUB161(auVar3 >> 0x30,0);
1431: uVar39 = SUB161(auVar3 >> 0x28,0);
1432: uVar37 = SUB161(auVar3 >> 0x20,0);
1433: uVar48 = SUB161(auVar55 >> 0x18,0);
1434: uVar52 = SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1435: puVar1[0xb],CONCAT114(uVar73,SUB1614(auVar36,0)))
1436: >> 0x70,0),CONCAT113(uVar81,SUB1613(auVar36,0)))
1437: >> 0x68,0),CONCAT112(uVar48,SUB1612(auVar36,0)))
1438: >> 0x60,0),CONCAT111(uVar67,SUB1611(auVar36,0)))
1439: >> 0x58,0),CONCAT110(uVar57,SUB1610(auVar36,0))) >> 0x50,0);
1440: uVar43 = SUB161(auVar55 >> 0x10,0);
1441: auVar36 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(uVar52,
1442: CONCAT19(uVar80,SUB169(auVar36,0))) >> 0x48,0),
1443: CONCAT18(uVar43,SUB168(auVar36,0))) >> 0x40,0),
1444: uVar60)) << 0x38) >> 0x30,0),uVar79)) << 0x28 &
1445: (undefined  [16])0xffffffff00000000;
1446: uVar38 = SUB161(auVar3 >> 0x10,0);
1447: uVar72 = CONCAT12(uVar80,CONCAT11(uVar47,uVar43));
1448: uVar88 = CONCAT14(uVar57,CONCAT13(SUB161(auVar55 >> 0x70,0),uVar72));
1449: auVar36 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
1450: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
1451: (CONCAT214(SUB162(CONCAT115(puVar1[0xd],
1452: CONCAT114(uVar60,
1453: SUB1614(auVar36,0))) >> 0x70,0),
1454: CONCAT113(uVar59,SUB1613(auVar36,0))) >> 0x68,0),
1455: CONCAT112(uVar65,SUB1612(auVar36,0))) >> 0x60,0),
1456: CONCAT111(uVar83,SUB1611(auVar36,0))) >> 0x58,0),
1457: CONCAT110(uVar79,SUB1610(auVar36,0))) >> 0x50,0),
1458: CONCAT19(uVar46,SUB169(auVar36,0))) >> 0x48,0),
1459: CONCAT18(uVar50,SUB168(auVar36,0))) >> 0x40,0),
1460: uVar74)) << 0x38) >> 0x10,0) &
1461: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0) &
1462: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
1463: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),uVar42)) <<
1464: 8;
1465: uVar9 = SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(
1466: SUB163(CONCAT214(SUB162(CONCAT115(puVar1[0xe],
1467: CONCAT114(uVar74
1468: ,SUB1614(auVar36,0))) >> 0x70,0),
1469: CONCAT113(uVar67,SUB1613(auVar36,0))) >> 0x68,0),
1470: CONCAT112(puVar1[8],SUB1612(auVar36,0))) >> 0x60,0
1471: ),CONCAT111(uVar66,SUB1611(auVar36,0))) >> 0x58,0)
1472: ,CONCAT110(uVar58,SUB1610(auVar36,0))) >> 0x50,0),
1473: CONCAT19(uVar57,SUB169(auVar36,0))) >> 0x48,0),
1474: CONCAT18(uVar64,SUB168(auVar36,0))) >> 0x40,0);
1475: uVar31 = (ulong)CONCAT16(uVar67,CONCAT15(uVar66,uVar88)) & 0xff000000;
1476: uVar65 = (undefined)((uint6)uVar88 >> 0x10);
1477: uVar11 = uVar72 & 0xff00;
1478: auVar44 = CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT88(uVar9,(uVar31 >> 0x18) << 0x38) >> 0x20,0
1479: ) &
1480: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1481: SUB1612((undefined  [16])0xff00000000000000 >> 0x20,0) &
1482: SUB1612((undefined  [16])0xffffff0000000000 >> 0x20,0),
1483: (uVar11 >> 8) << 0x18) >> 0x18,0),
1484: (SUB163(auVar36,0) >> 8) << 0x10) & (undefined  [16])0xffffffffffff0000;
1485: auVar36 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
1486: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1487: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1488: puVar1[0xb],
1489: CONCAT114(SUB161(auVar53 >> 0x38,0),
1490: SUB1614(auVar53,0))) >> 0x70,0),
1491: CONCAT113(uVar81,SUB1613(auVar53,0))) >> 0x68,0),
1492: CONCAT112(SUB161(auVar53 >> 0x30,0),
1493: SUB1612(auVar53,0))) >> 0x60,0),
1494: CONCAT111(uVar67,SUB1611(auVar53,0))) >> 0x58,0),
1495: CONCAT110(SUB161(auVar53 >> 0x28,0),
1496: SUB1610(auVar53,0))) >> 0x50,0),
1497: CONCAT19(uVar80,SUB169(auVar53,0))) >> 0x48,0),
1498: CONCAT18(SUB161(auVar53 >> 0x20,0),
1499: SUB168(auVar53,0))) >> 0x40,0),uVar60),
1500: (SUB167(auVar53,0) >> 0x18) << 0x30) >> 0x30,0),
1501: uVar79),uVar50)) << 0x20 &
1502: (undefined  [16])0xffffffffff000000;
1503: auVar53 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
1504: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
1505: (puVar1[0xd],
1506: CONCAT114(SUB161(auVar36 >> 0x38,0),
1507: SUB1614(auVar36,0))) >> 0x70,0),
1508: CONCAT113(uVar59,SUB1613(auVar36,0))) >> 0x68,0),
1509: CONCAT112(SUB161(auVar36 >> 0x30,0),
1510: SUB1612(auVar36,0))) >> 0x60,0),
1511: CONCAT111(uVar83,SUB1611(auVar36,0))) >> 0x58,0),
1512: CONCAT110(SUB161(auVar36 >> 0x28,0),
1513: SUB1610(auVar36,0))) >> 0x50,0),
1514: CONCAT19(uVar46,SUB169(auVar36,0))) >> 0x48,0),
1515: CONCAT18(SUB161(auVar36 >> 0x20,0),SUB168(auVar36,0))
1516: ) >> 0x40,0),uVar74)) << 0x38;
1517: auVar54 = auVar53 & (undefined  [16])0xffff000000000000;
1518: auVar53 = auVar53 & (undefined  [16])0xffff000000000000;
1519: uVar10 = (uint6)CONCAT14(uVar58,CONCAT13(uVar76,CONCAT12(uVar57,CONCAT11(*puVar2,uVar64))));
1520: uVar46 = (undefined)(uVar31 >> 0x18);
1521: auVar36 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
1522: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
1523: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
1524: (SUB162(CONCAT115(uVar70,CONCAT114(uVar46,SUB1614(
1525: auVar44,0))) >> 0x70,0),
1526: CONCAT113(uVar69,SUB1613(auVar44,0))) >> 0x68,0),
1527: CONCAT112(uVar82,SUB1612(auVar44,0))) >> 0x60,0),
1528: CONCAT111(uVar77,SUB1611(auVar44,0))) >> 0x58,0),
1529: CONCAT110(uVar65,SUB1610(auVar44,0))) >> 0x50,0),
1530: CONCAT19(uVar56,SUB169(auVar44,0))) >> 0x48,0),
1531: CONCAT18(uVar71,SUB168(auVar44,0))) >> 0x40,0),
1532: uVar40) & 0xffffffffffffffff &
1533: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1534: ,0),(SUB167(auVar44,0) >> 0x18) << 0x30) >>
1535: 0x30,0),uVar37),
1536: (SUB165(auVar44,0) >> 0x10) << 0x20) >> 0x20,0),
1537: uVar38),uVar43));
1538: auVar61 = auVar36 << 0x10;
1539: uVar57 = SUB161(auVar53 >> 0x48,0);
1540: uVar58 = SUB161(auVar54 >> 0x50,0);
1541: uVar59 = SUB161(auVar54 >> 0x58,0);
1542: uVar60 = SUB161(auVar54 >> 0x60,0);
1543: auVar44 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
1544: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
1545: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
1546: (CONCAT115(uVar70,CONCAT114(uVar46,SUB1614(auVar44
1547: ,0))) >> 0x70,0),
1548: CONCAT113(uVar69,SUB1613(auVar44,0))) >> 0x68,0),
1549: CONCAT112(uVar82,SUB1612(auVar44,0))) >> 0x60,0),
1550: CONCAT111(uVar77,SUB1611(auVar44,0))) >> 0x58,0),
1551: CONCAT110(uVar65,SUB1610(auVar44,0))) >> 0x50,0),
1552: CONCAT19(uVar56,SUB169(auVar44,0))) >> 0x48,0),
1553: CONCAT18(uVar71,SUB168(auVar44,0))) >> 0x40,0),
1554: uVar40) & 0xffffffffffffffff &
1555: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1556: ,0)) << 0x38) >> 0x30,0),uVar37)) << 0x28)
1557: >> 0x20,0),uVar38)) << 0x18 &
1558: (undefined  [16])0xffffffffffff0000;
1559: uVar71 = (undefined)(uVar10 >> 0x20);
1560: uVar70 = (undefined)(uVar10 >> 0x18);
1561: uVar69 = (undefined)(uVar10 >> 0x10);
1562: auVar63 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
1563: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1564: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1565: uVar15,CONCAT114(SUB161(auVar61 >> 0x38,0),
1566: SUB1614(auVar61,0))) >> 0x70,0),
1567: CONCAT113(uVar66,SUB1613(auVar61,0))) >> 0x68,0),
1568: CONCAT112(SUB161(auVar61 >> 0x30,0),
1569: SUB1612(auVar61,0))) >> 0x60,0),
1570: CONCAT111(uVar13,SUB1611(auVar61,0))) >> 0x58,0),
1571: CONCAT110(SUB161(auVar61 >> 0x28,0),
1572: SUB1610(auVar61,0))) >> 0x50,0),
1573: CONCAT19(uVar71,SUB169(auVar61,0))) >> 0x48,0),
1574: CONCAT18(SUB161(auVar61 >> 0x20,0),
1575: SUB168(auVar61,0))) >> 0x40,0),uVar70),
1576: (SUB167(auVar61,0) >> 0x18) << 0x30) >> 0x30,0) &
1577: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
1578: uVar69),uVar43)) << 0x20;
1579: auVar62 = auVar63 & (undefined  [16])0xffffffffff000000;
1580: auVar63 = auVar63 & (undefined  [16])0xffffffffff000000;
1581: uVar65 = SUB161(auVar61 >> 0x40,0);
1582: uVar72 = CONCAT12(SUB161(auVar61 >> 0x48,0),CONCAT11(puVar1[8],uVar65));
1583: uVar46 = SUB161(auVar36 >> 0x40,0);
1584: uVar47 = SUB161(auVar36 >> 0x48,0);
1585: uVar50 = SUB161(auVar36 >> 0x58,0);
1586: uVar56 = (undefined)(uVar10 >> 8);
1587: auVar44 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1588: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
1589: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
1590: (SUB163(CONCAT214(SUB162(CONCAT115(uVar15,
1591: CONCAT114(uVar40,SUB1614(auVar44,0))) >> 0x70,0),
1592: CONCAT113(uVar66,SUB1613(auVar44,0))) >> 0x68,0),
1593: CONCAT112((char)(uVar11 >> 8),SUB1612(auVar44,0)))
1594: >> 0x60,0),CONCAT111(uVar13,SUB1611(auVar44,0)))
1595: >> 0x58,0),CONCAT110(uVar37,SUB1610(auVar44,0)))
1596: >> 0x50,0),CONCAT19(uVar71,SUB169(auVar44,0))) >>
1597: 0x48,0),CONCAT18(uVar42,SUB168(auVar44,0))) >>
1598: 0x40,0),uVar70)) << 0x38) >> 0x30,0) &
1599: SUB1610((undefined  [16])0xffffffffffffffff >>
1600: 0x30,0),uVar69)) << 0x28) >> 0x20,0),
1601: uVar56)) << 0x18) >> 0x10,0),uVar64)) << 8;
1602: bVar45 = SUB161(auVar63 >> 0x40,0);
1603: uVar86 = CONCAT12(SUB161(auVar63 >> 0x48,0),CONCAT11(SUB161(auVar36 >> 0x50,0),bVar45));
1604: uVar42 = SUB161(auVar62 >> 0x50,0);
1605: uVar87 = CONCAT14(uVar42,CONCAT13(uVar74,uVar86));
1606: uVar71 = SUB161(auVar62 >> 0x58,0);
1607: auVar63 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
1608: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
1609: (uVar19,CONCAT114(SUB161(auVar63 >> 0x38,0),
1610: SUB1614(auVar63,0))) >> 0x70,0),
1611: CONCAT113(uVar47,SUB1613(auVar63,0))) >> 0x68,0),
1612: CONCAT112(SUB161(auVar63 >> 0x30,0),
1613: SUB1612(auVar63,0))) >> 0x60,0),
1614: CONCAT111(uVar67,SUB1611(auVar63,0))) >> 0x58,0),
1615: CONCAT110(SUB161(auVar63 >> 0x28,0),
1616: SUB1610(auVar63,0))) >> 0x50,0),
1617: CONCAT19(uVar46,SUB169(auVar63,0))) >> 0x48,0),
1618: CONCAT18(SUB161(auVar63 >> 0x20,0),SUB168(auVar63,0))
1619: ) >> 0x40,0),uVar17) & 0xffffffffffffffff) << 0x38;
1620: auVar61 = auVar63 & (undefined  [16])0xffff000000000000;
1621: auVar63 = auVar63 & (undefined  [16])0xffff000000000000;
1622: auVar44 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612((ZEXT1016(SUB1610((
1623: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
1624: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
1625: (SUB163(CONCAT214(SUB162(CONCAT115(uVar19,
1626: CONCAT114(uVar70,SUB1614(auVar44,0))) >> 0x70,0),
1627: CONCAT113(uVar47,SUB1613(auVar44,0))) >> 0x68,0),
1628: CONCAT112(uVar38,SUB1612(auVar44,0))) >> 0x60,0),
1629: CONCAT111(uVar67,SUB1611(auVar44,0))) >> 0x58,0),
1630: CONCAT110(uVar69,SUB1610(auVar44,0))) >> 0x50,0),
1631: CONCAT19(uVar46,SUB169(auVar44,0))) >> 0x48,0),
1632: CONCAT18(uVar43,SUB168(auVar44,0))) >> 0x40,0),
1633: uVar17)) << 0x38) >> 0x30,0) &
1634: SUB1610((undefined  [16])0xffffffffffffffff >>
1635: 0x30,0)) << 0x30) >> 0x20,0) &
1636: SUB1612((undefined  [16])0xffffff0000000000 >>
1637: 0x20,0),((uVar72 & 0xff00) >> 8) << 0x18)
1638: >> 0x18,0),(SUB163(auVar44,0) >> 8) << 0x10) >>
1639: 0x10,0),uVar65)) << 8;
1640: *(undefined (*) [16])(puVar5 + lVar30) =
1641: CONCAT115(puVar2[0xe],
1642: CONCAT114(SUB161(auVar61 >> 0x78,0),
1643: CONCAT113(SUB161(auVar62 >> 0x78,0),
1644: CONCAT112(SUB161(auVar61 >> 0x70,0),
1645: CONCAT111(SUB161(auVar36 >> 0x68,0),
1646: CONCAT110(SUB161(auVar61 >> 0x68,0),
1647: CONCAT19(SUB161(auVar62 >> 0x70
1648: ,0),
1649: CONCAT18(SUB161(
1650: auVar61 >> 0x60,0),
1651: uVar9 & 0xff00000000000000 |
1652: (ulong)CONCAT16(SUB161(auVar61 >> 0x58,0),
1653: CONCAT15(SUB161(auVar62 >> 0x68,0)
1654: ,CONCAT14(SUB161(auVar61 
1655: >> 0x50,0),
1656: CONCAT13(SUB161(auVar36 >> 0x60,0),
1657: CONCAT12(SUB161(auVar63 >> 0x48,0),
1658: CONCAT11(SUB161(auVar62 >> 0x60,
1659: 0),
1660: SUB161(auVar63 >> 0x40,
1661: 0)))))))))))))))
1662: ;
1663: uVar64 = SUB161(auVar3 >> 8,0);
1664: auVar36 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
1665: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
1666: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
1667: (SUB162(CONCAT115(uVar16,CONCAT114(uVar41,SUB1614(
1668: auVar3,0))) >> 0x70,0),
1669: CONCAT113(uVar15,SUB1613(auVar3,0))) >> 0x68,0),
1670: CONCAT112(uVar40,SUB1612(auVar3,0))) >> 0x60,0),
1671: CONCAT111(uVar14,SUB1611(auVar3,0))) >> 0x58,0),
1672: CONCAT110(uVar39,SUB1610(auVar3,0))) >> 0x50,0),
1673: CONCAT19(uVar13,SUB169(auVar3,0))) >> 0x48,0),
1674: CONCAT18(uVar37,SUB168(auVar3,0))) >> 0x40,0),
1675: uVar12),(SUB167(auVar3,0) >> 0x18) << 0x30) >>
1676: 0x30,0),uVar76),(SUB165(auVar3,0) >> 0x10) << 0x20
1677: ) >> 0x20,0),uVar75),uVar64)) << 0x10;
1678: auVar36 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
1679: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1680: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1681: uVar20,CONCAT114(SUB161(auVar36 >> 0x38,0),
1682: SUB1614(auVar36,0))) >> 0x70,0),
1683: CONCAT113(uVar78,SUB1613(auVar36,0))) >> 0x68,0),
1684: CONCAT112(SUB161(auVar36 >> 0x30,0),
1685: SUB1612(auVar36,0))) >> 0x60,0),
1686: CONCAT111(uVar19,SUB1611(auVar36,0))) >> 0x58,0),
1687: CONCAT110(SUB161(auVar36 >> 0x28,0),
1688: SUB1610(auVar36,0))) >> 0x50,0),
1689: CONCAT19(uVar77,SUB169(auVar36,0))) >> 0x48,0),
1690: CONCAT18(SUB161(auVar36 >> 0x20,0),
1691: SUB168(auVar36,0))) >> 0x40,0),uVar18),
1692: (SUB167(auVar36,0) >> 0x18) << 0x30) >> 0x30,0),
1693: SUB161(auVar3 >> 0x48,0)),uVar64)) << 0x20 &
1694: (undefined  [16])0xffffffffff000000;
1695: auVar61 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
1696: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
1697: (uVar22,CONCAT114(SUB161(auVar36 >> 0x38,0),
1698: SUB1614(auVar36,0))) >> 0x70,0),
1699: CONCAT113(uVar14,SUB1613(auVar36,0))) >> 0x68,0),
1700: CONCAT112(SUB161(auVar36 >> 0x30,0),
1701: SUB1612(auVar36,0))) >> 0x60,0),
1702: CONCAT111(SUB161(auVar3 >> 0x68,0),
1703: SUB1611(auVar36,0))) >> 0x58,0),
1704: CONCAT110(SUB161(auVar36 >> 0x28,0),
1705: SUB1610(auVar36,0))) >> 0x50,0),
1706: CONCAT19(uVar39,SUB169(auVar36,0))) >> 0x48,0),
1707: CONCAT18(SUB161(auVar36 >> 0x20,0),SUB168(auVar36,0))
1708: ) >> 0x40,0),uVar21)) << 0x38;
1709: auVar63 = auVar61 & (undefined  [16])0xffff000000000000;
1710: auVar61 = auVar61 & (undefined  [16])0xffff000000000000;
1711: uVar65 = SUB161(auVar61 >> 0x48,0);
1712: uVar64 = SUB161(auVar63 >> 0x50,0);
1713: uVar66 = SUB161(auVar63 >> 0x58,0);
1714: uVar9 = (ulong)(uVar51 & 0xff000000000000 |
1715: (uint7)CONCAT15(SUB161(auVar63 >> 0x68,0),
1716: CONCAT14(SUB161(auVar54 >> 0x68,0),
1717: CONCAT13(uVar12,CONCAT12(uVar73,CONCAT11(SUB161(auVar63 
1718: >> 0x60,0),uVar60))))));
1719: uVar31 = ((ulong)CONCAT14(uVar66,CONCAT13(uVar78,CONCAT12(uVar64,CONCAT11(uVar41,uVar65)))) &
1720: 0xff00) << 0x10;
1721: auVar36 = CONCAT88((long)(CONCAT72(CONCAT61(CONCAT51(CONCAT41(CONCAT31(CONCAT21(CONCAT11(SUB161(
1722: auVar3 >> 0x78,0),uVar84),uVar66),uVar59),uVar78),
1723: uVar81),uVar64),CONCAT11(uVar58,uVar84)) >> 8),
1724: (uVar31 >> 0x18) << 0x38) & (undefined  [16])0xff00000000000000;
1725: uVar75 = (undefined)(uVar9 >> 0x28);
1726: uVar74 = (undefined)(uVar9 >> 0x20);
1727: uVar67 = (undefined)(uVar9 >> 0x10);
1728: uVar73 = (undefined)(uVar9 >> 8);
1729: auVar36 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1730: ZEXT916(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1731: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1732: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1733: uVar16,CONCAT114((char)(uVar31 >> 0x18),
1734: SUB1614(auVar36,0))) >> 0x70,0),
1735: CONCAT113((char)(uVar9 >> 0x30),SUB1613(auVar36,0)
1736: )) >> 0x68,0),
1737: CONCAT112(uVar49,SUB1612(auVar36,0))) >> 0x60,0),
1738: CONCAT111(uVar75,SUB1611(auVar36,0))) >> 0x58,0),
1739: CONCAT110(uVar65,SUB1610(auVar36,0))) >> 0x50,0),
1740: CONCAT19(uVar74,SUB169(auVar36,0))) >> 0x48,0),
1741: CONCAT18(uVar57,SUB168(auVar36,0))) >> 0x40,0),
1742: ((uVar9 & 0xff000000) >> 0x18) << 0x38) >> 0x38,0)
1743: & SUB169((undefined  [16])0xffffffffffffffff >>
1744: 0x38,0) &
1745: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1746: ,0)) << 0x38) >> 0x30,0),uVar67)) << 0x28)
1747: >> 0x20,0),uVar73)) << 0x18) >> 0x10,0),uVar60))
1748: << 8;
1749: uVar31 = (ulong)CONCAT16(uVar78,uVar52 & 0xff0000000000 |
1750: (uint6)CONCAT14(uVar81,CONCAT13(SUB161(auVar63 >> 0x70,0),
1751: CONCAT12(uVar64,CONCAT11(SUB161(
1752: auVar54 >> 0x70,0),uVar58)))));
1753: uVar64 = (undefined)(uVar31 >> 0x10);
1754: auVar36 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1755: ZEXT916(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1756: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1757: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1758: uVar20,CONCAT114((char)((uVar9 & 0xff000000) >>
1759: 0x18),SUB1614(auVar36,0)))
1760: >> 0x70,0),
1761: CONCAT113((char)(uVar31 >> 0x30),
1762: SUB1613(auVar36,0))) >> 0x68,0),
1763: CONCAT112(SUB161(auVar3 >> 0x18,0),
1764: SUB1612(auVar36,0))) >> 0x60,0),
1765: CONCAT111((char)(uVar31 >> 0x28),
1766: SUB1611(auVar36,0))) >> 0x58,0),
1767: CONCAT110(uVar67,SUB1610(auVar36,0))) >> 0x50,0),
1768: CONCAT19((char)(uVar31 >> 0x20),SUB169(auVar36,0))
1769: ) >> 0x48,0),CONCAT18(uVar48,SUB168(auVar36,0)))
1770: >> 0x40,0),((uVar31 & 0xff000000) >> 0x18) << 0x38
1771: ) >> 0x38,0) &
1772: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1773: ,0) &
1774: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1775: ,0)) << 0x38) >> 0x30,0),uVar64)) << 0x28)
1776: >> 0x20,0),(char)(uVar31 >> 8)),
1777: (SUB163(auVar36,0) >> 8) << 0x10) >> 0x10,0),
1778: uVar58)) << 8;
1779: uVar68 = CONCAT12(uVar74,CONCAT11(uVar59,uVar57));
1780: uVar88 = CONCAT14(uVar65,CONCAT13(SUB161(auVar54 >> 0x78,0),uVar68));
1781: *(undefined (*) [16])(puVar6 + lVar30) =
1782: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
1783: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1784: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1785: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1786: SUB161(auVar63 >> 0x78,0),
1787: CONCAT114((char)((uVar31 & 0xff000000) >> 0x18),
1788: SUB1614(auVar36,0))) >> 0x70,0),
1789: CONCAT113(uVar75,SUB1613(auVar36,0))) >> 0x68,0),
1790: CONCAT112(uVar73,SUB1612(auVar36,0))) >> 0x60,0),
1791: CONCAT111(uVar66,SUB1611(auVar36,0))) >> 0x58,0),
1792: CONCAT110(uVar64,SUB1610(auVar36,0))) >> 0x50,0),
1793: CONCAT19(uVar65,SUB169(auVar36,0))) >> 0x48,0),
1794: CONCAT18(SUB161(auVar61 >> 0x40,0),
1795: SUB168(auVar36,0))) >> 0x40,0),
1796: (((ulong)CONCAT16(uVar75,CONCAT15(uVar66,uVar88))
1797: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0) &
1798: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1799: ,0),(SUB167(auVar36,0) >> 0x18) << 0x30) >>
1800: 0x30,0),(((uint6)uVar88 & 0xff0000) >> 0x10) <<
1801: 0x28) >> 0x28,0),
1802: (SUB165(auVar36,0) >> 0x10) << 0x20) >> 0x20,0),
1803: ((uVar68 & 0xff00) >> 8) << 0x18) >> 0x18,0),
1804: (SUB163(auVar36,0) >> 8) << 0x10) >> 0x10,0),
1805: SUB162(auVar53 >> 0x40,0));
1806: *(undefined (*) [16])(puVar7 + lVar30) =
1807: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
1808: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
1809: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1810: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1811: uVar21,CONCAT114(uVar17,SUB1614(auVar44,0))) >>
1812: 0x70,0),CONCAT113(uVar71,SUB1613(auVar44,0))) >>
1813: 0x68,0),CONCAT112(uVar56,SUB1612(auVar44,0))) >>
1814: 0x60,0),CONCAT111(uVar50,SUB1611(auVar44,0))) >>
1815: 0x58,0),CONCAT110((char)((uint6)CONCAT14(uVar46,(
1816: uint)uVar72) >> 0x10),SUB1610(auVar44,0))) >> 0x50
1817: ,0),CONCAT19(uVar42,SUB169(auVar44,0))) >> 0x48,0)
1818: ,CONCAT18(SUB161(auVar3,0),SUB168(auVar44,0))) >>
1819: 0x40,0),(((ulong)CONCAT16(uVar71,CONCAT15(uVar50,
1820: uVar87)) & 0xff000000) >> 0x18) << 0x38) >> 0x38,0
1821: ) & SUB169((undefined  [16])0xffffffffffffffff >>
1822: 0x38,0) &
1823: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1824: ,0) &
1825: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
1826: ,0),(SUB167(auVar44,0) >> 0x18) << 0x30) >>
1827: 0x30,0),(((uint6)uVar87 & 0xff0000) >> 0x10) <<
1828: 0x28) >> 0x28,0),
1829: (SUB165(auVar44,0) >> 0x10) << 0x20) >> 0x20,0),
1830: ((uVar86 & 0xff00) >> 8) << 0x18) >> 0x18,0),
1831: (SUB163(auVar44,0) >> 8) << 0x10) >> 0x10,0),
1832: SUB162(auVar55,0) & 0xff | (ushort)bVar45 << 8);
1833: lVar30 = lVar30 + 0x10;
1834: } while (uVar33 < uVar24);
1835: puVar25 = puVar25 + (ulong)uVar32 * 4;
1836: uVar33 = uVar32;
1837: if (uVar4 != uVar32) {
1838: code_r0x00105f88:
1839: do {
1840: uVar31 = (ulong)uVar33;
1841: uVar33 = uVar33 + 1;
1842: puVar5[uVar31] = puVar25[2];
1843: puVar6[uVar31] = puVar25[1];
1844: puVar7[uVar31] = *puVar25;
1845: puVar25 = puVar25 + 4;
1846: } while (uVar33 < uVar4);
1847: }
1848: goto code_r0x00105c88;
1849: code_r0x00105a7c:
1850: lVar30 = 0;
1851: uVar33 = 0;
1852: do {
1853: auVar55 = *(undefined (*) [16])(puVar25 + lVar30 * 4);
1854: uVar33 = uVar33 + 1;
1855: puVar1 = puVar25 + lVar30 * 4 + 0x10;
1856: uVar64 = *puVar1;
1857: uVar65 = puVar1[1];
1858: uVar57 = puVar1[2];
1859: uVar73 = puVar1[3];
1860: uVar58 = puVar1[4];
1861: uVar59 = puVar1[5];
1862: uVar66 = puVar1[6];
1863: uVar60 = puVar1[9];
1864: uVar67 = puVar1[10];
1865: uVar74 = puVar1[0xc];
1866: auVar3 = *(undefined (*) [16])(puVar25 + lVar30 * 4 + 0x20);
1867: uVar82 = SUB161(auVar55 >> 0x40,0);
1868: uVar69 = SUB161(auVar55 >> 0x48,0);
1869: uVar70 = SUB161(auVar55 >> 0x50,0);
1870: uVar83 = SUB161(auVar55 >> 0x58,0);
1871: uVar84 = SUB161(auVar55 >> 0x60,0);
1872: uVar71 = SUB161(auVar55 >> 0x68,0);
1873: uVar85 = SUB161(auVar55 >> 0x78,0);
1874: puVar2 = puVar25 + lVar30 * 4 + 0x30;
1875: uVar75 = puVar2[1];
1876: uVar76 = puVar2[2];
1877: uVar12 = puVar2[3];
1878: uVar13 = puVar2[4];
1879: uVar14 = puVar2[5];
1880: uVar15 = puVar2[6];
1881: uVar16 = puVar2[7];
1882: uVar17 = puVar2[8];
1883: uVar18 = puVar2[9];
1884: uVar19 = puVar2[10];
1885: uVar20 = puVar2[0xb];
1886: uVar21 = puVar2[0xc];
1887: uVar22 = puVar2[0xd];
1888: uVar37 = puVar2[0xe];
1889: uVar50 = SUB161(auVar55 >> 0x38,0);
1890: uVar48 = SUB161(auVar55 >> 0x30,0);
1891: uVar47 = SUB161(auVar55 >> 0x28,0);
1892: bVar45 = SUB161(auVar55 >> 0x20,0);
1893: uVar51 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(
1894: SUB162(CONCAT115(puVar1[7],
1895: CONCAT114(uVar50,SUB1614(auVar55,
1896: 0))) >> 0x70,0),
1897: CONCAT113(uVar66,SUB1613(auVar55,0))) >> 0x68,0),
1898: CONCAT112(uVar48,SUB1612(auVar55,0))) >> 0x60,0),
1899: CONCAT111(uVar59,SUB1611(auVar55,0))) >> 0x58,0),
1900: CONCAT110(uVar47,SUB1610(auVar55,0))) >> 0x50,0),
1901: CONCAT19(uVar58,SUB169(auVar55,0))) >> 0x48,0);
1902: auVar44 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
1903: CONCAT79(uVar51,CONCAT18(bVar45,SUB168(auVar55,0))
1904: ) >> 0x40,0),uVar73)) << 0x38) >> 0x30,0),
1905: uVar57)) << 0x28) >> 0x20,0),uVar65)) << 0x18 &
1906: (undefined  [16])0xffffffffffff0000;
1907: uVar56 = SUB161(auVar55 >> 8,0);
1908: auVar53 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
1909: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
1910: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
1911: (SUB162(CONCAT115(puVar1[7],
1912: CONCAT114(uVar50,SUB1614(auVar55
1913: ,0))) >> 0x70,0),
1914: CONCAT113(uVar66,SUB1613(auVar55,0))) >> 0x68,0),
1915: CONCAT112(uVar48,SUB1612(auVar55,0))) >> 0x60,0),
1916: CONCAT111(uVar59,SUB1611(auVar55,0))) >> 0x58,0),
1917: CONCAT110(uVar47,SUB1610(auVar55,0))) >> 0x50,0),
1918: CONCAT19(uVar58,SUB169(auVar55,0))) >> 0x48,0),
1919: CONCAT18(bVar45,SUB168(auVar55,0))) >> 0x40,0),
1920: uVar73),(SUB167(auVar55,0) >> 0x18) << 0x30) >>
1921: 0x30,0),uVar57),
1922: (SUB165(auVar55,0) >> 0x10) << 0x20) >> 0x20,0),
1923: uVar65),uVar56)) << 0x10;
1924: uVar77 = SUB161(auVar3 >> 0x40,0);
1925: uVar78 = SUB161(auVar3 >> 0x50,0);
1926: uVar79 = SUB161(auVar3 >> 0x58,0);
1927: uVar80 = SUB161(auVar3 >> 0x60,0);
1928: uVar81 = SUB161(auVar3 >> 0x70,0);
1929: uVar43 = SUB161(auVar3 >> 0x38,0);
1930: uVar41 = SUB161(auVar3 >> 0x30,0);
1931: uVar40 = SUB161(auVar3 >> 0x28,0);
1932: uVar38 = SUB161(auVar3 >> 0x20,0);
1933: auVar36 = ZEXT1416(SUB1614((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
1934: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
1935: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1936: uVar16,CONCAT114(uVar43,SUB1614(auVar3,0))) >>
1937: 0x70,0),CONCAT113(uVar15,SUB1613(auVar3,0))) >>
1938: 0x68,0),CONCAT112(uVar41,SUB1612(auVar3,0))) >>
1939: 0x60,0),CONCAT111(uVar14,SUB1611(auVar3,0))) >>
1940: 0x58,0),CONCAT110(uVar40,SUB1610(auVar3,0))) >>
1941: 0x50,0),CONCAT19(uVar13,SUB169(auVar3,0))) >> 0x48
1942: ,0),CONCAT18(uVar38,SUB168(auVar3,0))) >> 0x40,0),
1943: uVar12)) << 0x38) >> 0x30,0),uVar76)) << 0x28) >>
1944: 0x10,0) & SUB1614((undefined  [16])0xffffffff00000000 >> 0x10,0) &
1945: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0)) << 0x10;
1946: uVar49 = SUB161(auVar55 >> 0x18,0);
1947: uVar52 = SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
1948: puVar1[0xb],CONCAT114(uVar73,SUB1614(auVar44,0)))
1949: >> 0x70,0),CONCAT113(uVar83,SUB1613(auVar44,0)))
1950: >> 0x68,0),CONCAT112(uVar49,SUB1612(auVar44,0)))
1951: >> 0x60,0),CONCAT111(uVar67,SUB1611(auVar44,0)))
1952: >> 0x58,0),CONCAT110(uVar57,SUB1610(auVar44,0))) >> 0x50,0);
1953: uVar46 = SUB161(auVar55 >> 0x10,0);
1954: auVar44 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(uVar52,
1955: CONCAT19(uVar70,SUB169(auVar44,0))) >> 0x48,0),
1956: CONCAT18(uVar46,SUB168(auVar44,0))) >> 0x40,0),
1957: uVar60)) << 0x38) >> 0x30,0),uVar69)) << 0x28 &
1958: (undefined  [16])0xffffffff00000000;
1959: uVar42 = SUB161(auVar3 >> 0x18,0);
1960: uVar39 = SUB161(auVar3 >> 0x10,0);
1961: uVar72 = CONCAT12(uVar70,CONCAT11(uVar48,uVar46));
1962: uVar88 = CONCAT14(uVar57,CONCAT13(SUB161(auVar55 >> 0x70,0),uVar72));
1963: auVar44 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
1964: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
1965: (CONCAT214(SUB162(CONCAT115(puVar1[0xd],
1966: CONCAT114(uVar60,
1967: SUB1614(auVar44,0))) >> 0x70,0),
1968: CONCAT113(uVar59,SUB1613(auVar44,0))) >> 0x68,0),
1969: CONCAT112(uVar65,SUB1612(auVar44,0))) >> 0x60,0),
1970: CONCAT111(uVar71,SUB1611(auVar44,0))) >> 0x58,0),
1971: CONCAT110(uVar69,SUB1610(auVar44,0))) >> 0x50,0),
1972: CONCAT19(uVar47,SUB169(auVar44,0))) >> 0x48,0),
1973: CONCAT18(uVar56,SUB168(auVar44,0))) >> 0x40,0),
1974: uVar74)) << 0x38) >> 0x10,0) &
1975: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0) &
1976: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
1977: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),bVar45)) <<
1978: 8;
1979: uVar23 = SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(
1980: SUB163(CONCAT214(SUB162(CONCAT115(puVar1[0xe],
1981: CONCAT114(uVar74
1982: ,SUB1614(auVar44,0))) >> 0x70,0),
1983: CONCAT113(uVar67,SUB1613(auVar44,0))) >> 0x68,0),
1984: CONCAT112(puVar1[8],SUB1612(auVar44,0))) >> 0x60,0
1985: ),CONCAT111(uVar66,SUB1611(auVar44,0))) >> 0x58,0)
1986: ,CONCAT110(uVar58,SUB1610(auVar44,0))) >> 0x50,0),
1987: CONCAT19(uVar57,SUB169(auVar44,0))) >> 0x48,0),
1988: CONCAT18(uVar64,SUB168(auVar44,0))) >> 0x40,0);
1989: uVar31 = (ulong)CONCAT16(uVar67,CONCAT15(uVar66,uVar88)) & 0xff000000;
1990: uVar65 = (undefined)((uint6)uVar88 >> 0x10);
1991: uVar11 = uVar72 & 0xff00;
1992: auVar44 = CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT88(uVar23,(uVar31 >> 0x18) << 0x38) >> 0x20,
1993: 0) &
1994: SUB1612((undefined  [16])0xffffffffffffffff >> 0x20,0) &
1995: SUB1612((undefined  [16])0xff00000000000000 >> 0x20,0) &
1996: SUB1612((undefined  [16])0xffffff0000000000 >> 0x20,0),
1997: (uVar11 >> 8) << 0x18) >> 0x18,0),
1998: (SUB163(auVar44,0) >> 8) << 0x10) & (undefined  [16])0xffffffffffff0000;
1999: auVar53 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
2000: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
2001: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
2002: puVar1[0xb],
2003: CONCAT114(SUB161(auVar53 >> 0x38,0),
2004: SUB1614(auVar53,0))) >> 0x70,0),
2005: CONCAT113(uVar83,SUB1613(auVar53,0))) >> 0x68,0),
2006: CONCAT112(SUB161(auVar53 >> 0x30,0),
2007: SUB1612(auVar53,0))) >> 0x60,0),
2008: CONCAT111(uVar67,SUB1611(auVar53,0))) >> 0x58,0),
2009: CONCAT110(SUB161(auVar53 >> 0x28,0),
2010: SUB1610(auVar53,0))) >> 0x50,0),
2011: CONCAT19(uVar70,SUB169(auVar53,0))) >> 0x48,0),
2012: CONCAT18(SUB161(auVar53 >> 0x20,0),
2013: SUB168(auVar53,0))) >> 0x40,0),uVar60),
2014: (SUB167(auVar53,0) >> 0x18) << 0x30) >> 0x30,0),
2015: uVar69),uVar56)) << 0x20 &
2016: (undefined  [16])0xffffffffff000000;
2017: auVar54 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
2018: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
2019: (puVar1[0xd],
2020: CONCAT114(SUB161(auVar53 >> 0x38,0),
2021: SUB1614(auVar53,0))) >> 0x70,0),
2022: CONCAT113(uVar59,SUB1613(auVar53,0))) >> 0x68,0),
2023: CONCAT112(SUB161(auVar53 >> 0x30,0),
2024: SUB1612(auVar53,0))) >> 0x60,0),
2025: CONCAT111(uVar71,SUB1611(auVar53,0))) >> 0x58,0),
2026: CONCAT110(SUB161(auVar53 >> 0x28,0),
2027: SUB1610(auVar53,0))) >> 0x50,0),
2028: CONCAT19(uVar47,SUB169(auVar53,0))) >> 0x48,0),
2029: CONCAT18(SUB161(auVar53 >> 0x20,0),SUB168(auVar53,0))
2030: ) >> 0x40,0),uVar74)) << 0x38;
2031: auVar53 = auVar54 & (undefined  [16])0xffff000000000000;
2032: auVar54 = auVar54 & (undefined  [16])0xffff000000000000;
2033: uVar10 = (uint6)CONCAT14(uVar58,CONCAT13(uVar76,CONCAT12(uVar57,CONCAT11(*puVar2,uVar64))));
2034: uVar48 = (undefined)(uVar31 >> 0x18);
2035: auVar61 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
2036: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
2037: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
2038: (CONCAT115(uVar81,CONCAT114(uVar48,SUB1614(auVar44
2039: ,0))) >> 0x70,0),
2040: CONCAT113(uVar80,SUB1613(auVar44,0))) >> 0x68,0),
2041: CONCAT112(uVar84,SUB1612(auVar44,0))) >> 0x60,0),
2042: CONCAT111(uVar78,SUB1611(auVar44,0))) >> 0x58,0),
2043: CONCAT110(uVar65,SUB1610(auVar44,0))) >> 0x50,0),
2044: CONCAT19(uVar77,SUB169(auVar44,0))) >> 0x48,0),
2045: CONCAT18(uVar82,SUB168(auVar44,0))) >> 0x40,0),
2046: uVar41) & 0xffffffffffffffff &
2047: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2048: ,0)) << 0x38) >> 0x30,0),uVar38)) << 0x28)
2049: >> 0x20,0),uVar39)) << 0x18 &
2050: (undefined  [16])0xffffffffffff0000;
2051: uVar57 = SUB161(auVar54 >> 0x48,0);
2052: uVar58 = SUB161(auVar53 >> 0x50,0);
2053: uVar59 = SUB161(auVar53 >> 0x58,0);
2054: uVar60 = SUB161(auVar53 >> 0x60,0);
2055: auVar44 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
2056: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
2057: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
2058: (SUB162(CONCAT115(uVar81,CONCAT114(uVar48,SUB1614(
2059: auVar44,0))) >> 0x70,0),
2060: CONCAT113(uVar80,SUB1613(auVar44,0))) >> 0x68,0),
2061: CONCAT112(uVar84,SUB1612(auVar44,0))) >> 0x60,0),
2062: CONCAT111(uVar78,SUB1611(auVar44,0))) >> 0x58,0),
2063: CONCAT110(uVar65,SUB1610(auVar44,0))) >> 0x50,0),
2064: CONCAT19(uVar77,SUB169(auVar44,0))) >> 0x48,0),
2065: CONCAT18(uVar82,SUB168(auVar44,0))) >> 0x40,0),
2066: uVar41) & 0xffffffffffffffff &
2067: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2068: ,0),(SUB167(auVar44,0) >> 0x18) << 0x30) >>
2069: 0x30,0),uVar38),
2070: (SUB165(auVar44,0) >> 0x10) << 0x20) >> 0x20,0),
2071: uVar39),uVar46)) << 0x10;
2072: uVar47 = (undefined)(uVar11 >> 8);
2073: uVar71 = (undefined)(uVar10 >> 0x20);
2074: uVar70 = (undefined)(uVar10 >> 0x18);
2075: uVar69 = (undefined)(uVar10 >> 0x10);
2076: uVar56 = (undefined)(uVar10 >> 8);
2077: auVar61 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
2078: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
2079: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
2080: (SUB163(CONCAT214(SUB162(CONCAT115(uVar15,
2081: CONCAT114(uVar41,SUB1614(auVar61,0))) >> 0x70,0),
2082: CONCAT113(uVar66,SUB1613(auVar61,0))) >> 0x68,0),
2083: CONCAT112(uVar47,SUB1612(auVar61,0))) >> 0x60,0),
2084: CONCAT111(uVar13,SUB1611(auVar61,0))) >> 0x58,0),
2085: CONCAT110(uVar38,SUB1610(auVar61,0))) >> 0x50,0),
2086: CONCAT19(uVar71,SUB169(auVar61,0))) >> 0x48,0),
2087: CONCAT18(bVar45,SUB168(auVar61,0))) >> 0x40,0),
2088: uVar70)) << 0x38) >> 0x30,0) &
2089: SUB1610((undefined  [16])0xffffffffffffffff >>
2090: 0x30,0),uVar69)) << 0x28) >> 0x20,0),
2091: uVar56)) << 0x18) >> 0x10,0),uVar64)) << 8;
2092: uVar68 = SUB153(CONCAT141(SUB1614((ZEXT1216(SUB1612((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
2093: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
2094: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
2095: uVar20,CONCAT114(uVar12,SUB1614(auVar36,0))) >>
2096: 0x70,0),CONCAT113(uVar79,SUB1613(auVar36,0))) >>
2097: 0x68,0),CONCAT112(uVar42,SUB1612(auVar36,0))) >>
2098: 0x60,0),CONCAT111(uVar19,SUB1611(auVar36,0))) >>
2099: 0x58,0),CONCAT110(uVar76,SUB1610(auVar36,0))) >>
2100: 0x50,0),CONCAT19(uVar78,SUB169(auVar36,0))) >>
2101: 0x48,0),CONCAT18(uVar39,SUB168(auVar36,0))) >>
2102: 0x40,0),uVar18)) << 0x38) >> 0x20,0) &
2103: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,
2104: 0) &
2105: SUB1612((undefined  [16])0xffffff0000000000 >> 0x20,
2106: 0)) << 0x20) >> 0x10,0) &
2107: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),uVar77),0) <<
2108: 0x10 | (uint3)CONCAT11(puVar1[8],uVar82);
2109: auVar36 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
2110: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
2111: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
2112: uVar15,CONCAT114(SUB161(auVar44 >> 0x38,0),
2113: SUB1614(auVar44,0))) >> 0x70,0),
2114: CONCAT113(uVar66,SUB1613(auVar44,0))) >> 0x68,0),
2115: CONCAT112(SUB161(auVar44 >> 0x30,0),
2116: SUB1612(auVar44,0))) >> 0x60,0),
2117: CONCAT111(uVar13,SUB1611(auVar44,0))) >> 0x58,0),
2118: CONCAT110(SUB161(auVar44 >> 0x28,0),
2119: SUB1610(auVar44,0))) >> 0x50,0),
2120: CONCAT19(uVar71,SUB169(auVar44,0))) >> 0x48,0),
2121: CONCAT18(SUB161(auVar44 >> 0x20,0),
2122: SUB168(auVar44,0))) >> 0x40,0),uVar70),
2123: (SUB167(auVar44,0) >> 0x18) << 0x30) >> 0x30,0) &
2124: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
2125: uVar69),uVar46)) << 0x20 &
2126: (undefined  [16])0xffffffffff000000;
2127: uVar72 = CONCAT12(uVar71,CONCAT11(uVar84,bVar45));
2128: uVar88 = CONCAT14(uVar38,CONCAT13(uVar74,uVar72));
2129: auVar61 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612((ZEXT916(CONCAT81(
2130: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
2131: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
2132: (SUB162(CONCAT115(uVar19,CONCAT114(uVar70,SUB1614(
2133: auVar61,0))) >> 0x70,0),
2134: CONCAT113(uVar78,SUB1613(auVar61,0))) >> 0x68,0),
2135: CONCAT112(uVar39,SUB1612(auVar61,0))) >> 0x60,0),
2136: CONCAT111(uVar67,SUB1611(auVar61,0))) >> 0x58,0),
2137: CONCAT110(uVar69,SUB1610(auVar61,0))) >> 0x50,0),
2138: CONCAT19(uVar65,SUB169(auVar61,0))) >> 0x48,0),
2139: CONCAT18(uVar46,SUB168(auVar61,0))) >> 0x40,0),
2140: uVar17) & 0xffffffffffffffff) << 0x38) >> 0x20,0)
2141: & SUB1612((undefined  [16])0xffff000000000000 >>
2142: 0x20,0) &
2143: SUB1612((undefined  [16])0xffffff0000000000 >>
2144: 0x20,0),((uVar68 & 0xff00) >> 8) << 0x18)
2145: >> 0x18,0),(SUB163(auVar61,0) >> 8) << 0x10) >>
2146: 0x10,0),uVar82)) << 8;
2147: auVar36 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
2148: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
2149: (uVar19,CONCAT114(SUB161(auVar36 >> 0x38,0),
2150: SUB1614(auVar36,0))) >> 0x70,0),
2151: CONCAT113(uVar78,SUB1613(auVar36,0))) >> 0x68,0),
2152: CONCAT112(SUB161(auVar36 >> 0x30,0),
2153: SUB1612(auVar36,0))) >> 0x60,0),
2154: CONCAT111(uVar67,SUB1611(auVar36,0))) >> 0x58,0),
2155: CONCAT110(SUB161(auVar36 >> 0x28,0),
2156: SUB1610(auVar36,0))) >> 0x50,0),
2157: CONCAT19(uVar65,SUB169(auVar36,0))) >> 0x48,0),
2158: CONCAT18(SUB161(auVar36 >> 0x20,0),SUB168(auVar36,0))
2159: ) >> 0x40,0),uVar17) & 0xffffffffffffffff) << 0x38;
2160: auVar44 = auVar36 & (undefined  [16])0xffff000000000000;
2161: auVar36 = auVar36 & (undefined  [16])0xffff000000000000;
2162: *(undefined (*) [16])(puVar5 + lVar30) =
2163: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
2164: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
2165: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
2166: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
2167: uVar21,CONCAT114(uVar17,SUB1614(auVar61,0))) >>
2168: 0x70,0),CONCAT113(uVar13,SUB1613(auVar61,0))) >>
2169: 0x68,0),CONCAT112(uVar56,SUB1612(auVar61,0))) >>
2170: 0x60,0),CONCAT111(uVar80,SUB1611(auVar61,0))) >>
2171: 0x58,0),CONCAT110((char)((uint6)CONCAT14(uVar65,(
2172: uint)uVar68) >> 0x10),SUB1610(auVar61,0))) >> 0x50
2173: ,0),CONCAT19(uVar38,SUB169(auVar61,0))) >> 0x48,0)
2174: ,CONCAT18(SUB161(auVar3,0),SUB168(auVar61,0))) >>
2175: 0x40,0),(((ulong)CONCAT16(uVar13,CONCAT15(uVar80,
2176: uVar88)) & 0xff000000) >> 0x18) << 0x38) >> 0x38,0
2177: ) & SUB169((undefined  [16])0xffffffffffffffff >>
2178: 0x38,0) &
2179: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2180: ,0) &
2181: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2182: ,0) &
2183: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2184: ,0),(SUB167(auVar61,0) >> 0x18) << 0x30) >>
2185: 0x30,0),(((uint6)uVar88 & 0xff0000) >> 0x10) <<
2186: 0x28) >> 0x28,0),
2187: (SUB165(auVar61,0) >> 0x10) << 0x20) >> 0x20,0),
2188: ((uVar72 & 0xff00) >> 8) << 0x18) >> 0x18,0),
2189: (SUB163(auVar61,0) >> 8) << 0x10) >> 0x10,0),
2190: SUB162(auVar55,0) & 0xff | (ushort)bVar45 << 8);
2191: uVar64 = SUB161(auVar3 >> 8,0);
2192: auVar55 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81(
2193: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
2194: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
2195: (SUB162(CONCAT115(uVar16,CONCAT114(uVar43,SUB1614(
2196: auVar3,0))) >> 0x70,0),
2197: CONCAT113(uVar15,SUB1613(auVar3,0))) >> 0x68,0),
2198: CONCAT112(uVar41,SUB1612(auVar3,0))) >> 0x60,0),
2199: CONCAT111(uVar14,SUB1611(auVar3,0))) >> 0x58,0),
2200: CONCAT110(uVar40,SUB1610(auVar3,0))) >> 0x50,0),
2201: CONCAT19(uVar13,SUB169(auVar3,0))) >> 0x48,0),
2202: CONCAT18(uVar38,SUB168(auVar3,0))) >> 0x40,0),
2203: uVar12),(SUB167(auVar3,0) >> 0x18) << 0x30) >>
2204: 0x30,0),uVar76),(SUB165(auVar3,0) >> 0x10) << 0x20
2205: ) >> 0x20,0),uVar75),uVar64)) << 0x10;
2206: auVar55 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
2207: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
2208: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
2209: uVar20,CONCAT114(SUB161(auVar55 >> 0x38,0),
2210: SUB1614(auVar55,0))) >> 0x70,0),
2211: CONCAT113(uVar79,SUB1613(auVar55,0))) >> 0x68,0),
2212: CONCAT112(SUB161(auVar55 >> 0x30,0),
2213: SUB1612(auVar55,0))) >> 0x60,0),
2214: CONCAT111(uVar19,SUB1611(auVar55,0))) >> 0x58,0),
2215: CONCAT110(SUB161(auVar55 >> 0x28,0),
2216: SUB1610(auVar55,0))) >> 0x50,0),
2217: CONCAT19(uVar78,SUB169(auVar55,0))) >> 0x48,0),
2218: CONCAT18(SUB161(auVar55 >> 0x20,0),
2219: SUB168(auVar55,0))) >> 0x40,0),uVar18),
2220: (SUB167(auVar55,0) >> 0x18) << 0x30) >> 0x30,0),
2221: SUB161(auVar3 >> 0x48,0)),uVar64)) << 0x20 &
2222: (undefined  [16])0xffffffffff000000;
2223: auVar63 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
2224: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
2225: (uVar22,CONCAT114(SUB161(auVar55 >> 0x38,0),
2226: SUB1614(auVar55,0))) >> 0x70,0),
2227: CONCAT113(uVar14,SUB1613(auVar55,0))) >> 0x68,0),
2228: CONCAT112(SUB161(auVar55 >> 0x30,0),
2229: SUB1612(auVar55,0))) >> 0x60,0),
2230: CONCAT111(SUB161(auVar3 >> 0x68,0),
2231: SUB1611(auVar55,0))) >> 0x58,0),
2232: CONCAT110(SUB161(auVar55 >> 0x28,0),
2233: SUB1610(auVar55,0))) >> 0x50,0),
2234: CONCAT19(uVar40,SUB169(auVar55,0))) >> 0x48,0),
2235: CONCAT18(SUB161(auVar55 >> 0x20,0),SUB168(auVar55,0))
2236: ) >> 0x40,0),uVar21)) << 0x38;
2237: auVar61 = auVar63 & (undefined  [16])0xffff000000000000;
2238: auVar63 = auVar63 & (undefined  [16])0xffff000000000000;
2239: uVar65 = SUB161(auVar63 >> 0x48,0);
2240: uVar64 = SUB161(auVar61 >> 0x50,0);
2241: uVar67 = SUB161(auVar61 >> 0x58,0);
2242: uVar9 = (ulong)(uVar51 & 0xff000000000000 |
2243: (uint7)CONCAT15(SUB161(auVar61 >> 0x68,0),
2244: CONCAT14(SUB161(auVar53 >> 0x68,0),
2245: CONCAT13(uVar12,CONCAT12(uVar73,CONCAT11(SUB161(auVar61 
2246: >> 0x60,0),uVar60))))));
2247: uVar31 = ((ulong)CONCAT14(uVar67,CONCAT13(uVar79,CONCAT12(uVar64,CONCAT11(uVar43,uVar65)))) &
2248: 0xff00) << 0x10;
2249: auVar55 = CONCAT88((long)(CONCAT72(CONCAT61(CONCAT51(CONCAT41(CONCAT31(CONCAT21(CONCAT11(SUB161(
2250: auVar3 >> 0x78,0),uVar85),uVar67),uVar59),uVar79),
2251: uVar83),uVar64),CONCAT11(uVar58,uVar85)) >> 8),
2252: (uVar31 >> 0x18) << 0x38) & (undefined  [16])0xff00000000000000;
2253: uVar76 = (undefined)(uVar9 >> 0x28);
2254: uVar75 = (undefined)(uVar9 >> 0x20);
2255: uVar74 = (undefined)(uVar9 >> 0x10);
2256: uVar73 = (undefined)(uVar9 >> 8);
2257: auVar55 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
2258: ZEXT916(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
2259: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
2260: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
2261: uVar16,CONCAT114((char)(uVar31 >> 0x18),
2262: SUB1614(auVar55,0))) >> 0x70,0),
2263: CONCAT113((char)(uVar9 >> 0x30),SUB1613(auVar55,0)
2264: )) >> 0x68,0),
2265: CONCAT112(uVar50,SUB1612(auVar55,0))) >> 0x60,0),
2266: CONCAT111(uVar76,SUB1611(auVar55,0))) >> 0x58,0),
2267: CONCAT110(uVar65,SUB1610(auVar55,0))) >> 0x50,0),
2268: CONCAT19(uVar75,SUB169(auVar55,0))) >> 0x48,0),
2269: CONCAT18(uVar57,SUB168(auVar55,0))) >> 0x40,0),
2270: ((uVar9 & 0xff000000) >> 0x18) << 0x38) >> 0x38,0)
2271: & SUB169((undefined  [16])0xffffffffffffffff >>
2272: 0x38,0) &
2273: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2274: ,0)) << 0x38) >> 0x30,0),uVar74)) << 0x28)
2275: >> 0x20,0),uVar73)) << 0x18) >> 0x10,0),uVar60))
2276: << 8;
2277: uVar31 = (ulong)CONCAT16(uVar79,uVar52 & 0xff0000000000 |
2278: (uint6)CONCAT14(uVar83,CONCAT13(SUB161(auVar61 >> 0x70,0),
2279: CONCAT12(uVar64,CONCAT11(SUB161(
2280: auVar53 >> 0x70,0),uVar58)))));
2281: uVar64 = (undefined)(uVar31 >> 0x10);
2282: auVar55 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
2283: ZEXT916(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
2284: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
2285: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
2286: uVar20,CONCAT114((char)((uVar9 & 0xff000000) >>
2287: 0x18),SUB1614(auVar55,0)))
2288: >> 0x70,0),
2289: CONCAT113((char)(uVar31 >> 0x30),
2290: SUB1613(auVar55,0))) >> 0x68,0),
2291: CONCAT112(uVar42,SUB1612(auVar55,0))) >> 0x60,0),
2292: CONCAT111((char)(uVar31 >> 0x28),
2293: SUB1611(auVar55,0))) >> 0x58,0),
2294: CONCAT110(uVar74,SUB1610(auVar55,0))) >> 0x50,0),
2295: CONCAT19((char)(uVar31 >> 0x20),SUB169(auVar55,0))
2296: ) >> 0x48,0),CONCAT18(uVar49,SUB168(auVar55,0)))
2297: >> 0x40,0),((uVar31 & 0xff000000) >> 0x18) << 0x38
2298: ) >> 0x38,0) &
2299: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2300: ,0) &
2301: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2302: ,0)) << 0x38) >> 0x30,0),uVar64)) << 0x28)
2303: >> 0x20,0),(char)(uVar31 >> 8)),
2304: (SUB163(auVar55,0) >> 8) << 0x10) >> 0x10,0),
2305: uVar58)) << 8;
2306: uVar72 = CONCAT12(uVar75,CONCAT11(uVar59,uVar57));
2307: uVar88 = CONCAT14(uVar65,CONCAT13(SUB161(auVar53 >> 0x78,0),uVar72));
2308: *(undefined (*) [16])(puVar6 + lVar30) =
2309: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
2310: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
2311: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
2312: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
2313: SUB161(auVar61 >> 0x78,0),
2314: CONCAT114((char)((uVar31 & 0xff000000) >> 0x18),
2315: SUB1614(auVar55,0))) >> 0x70,0),
2316: CONCAT113(uVar76,SUB1613(auVar55,0))) >> 0x68,0),
2317: CONCAT112(uVar73,SUB1612(auVar55,0))) >> 0x60,0),
2318: CONCAT111(uVar67,SUB1611(auVar55,0))) >> 0x58,0),
2319: CONCAT110(uVar64,SUB1610(auVar55,0))) >> 0x50,0),
2320: CONCAT19(uVar65,SUB169(auVar55,0))) >> 0x48,0),
2321: CONCAT18(SUB161(auVar63 >> 0x40,0),
2322: SUB168(auVar55,0))) >> 0x40,0),
2323: (((ulong)CONCAT16(uVar76,CONCAT15(uVar67,uVar88))
2324: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0) &
2325: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
2326: ,0),(SUB167(auVar55,0) >> 0x18) << 0x30) >>
2327: 0x30,0),(((uint6)uVar88 & 0xff0000) >> 0x10) <<
2328: 0x28) >> 0x28,0),
2329: (SUB165(auVar55,0) >> 0x10) << 0x20) >> 0x20,0),
2330: ((uVar72 & 0xff00) >> 8) << 0x18) >> 0x18,0),
2331: (SUB163(auVar55,0) >> 8) << 0x10) >> 0x10,0),
2332: SUB162(auVar54 >> 0x40,0));
2333: *(undefined (*) [16])(puVar7 + lVar30) =
2334: CONCAT115(uVar37,CONCAT114(SUB161(auVar44 >> 0x78,0),
2335: CONCAT113(uVar15,CONCAT112(SUB161(auVar44 >> 0x70,0),
2336: CONCAT111(uVar81,CONCAT110(SUB161(
2337: auVar44 >> 0x68,0),
2338: CONCAT19(uVar41,CONCAT18(SUB161(auVar44 >> 0x60,0)
2339: ,uVar23 & 
2340: 0xff00000000000000 |
2341: (ulong)CONCAT16(SUB161(auVar44 >> 0x58,0),
2342: CONCAT15(uVar66,CONCAT14(SUB161(
2343: auVar44 >> 0x50,0),
2344: CONCAT13(uVar48,CONCAT12(SUB161(auVar36 >> 0x48,0)
2345: ,CONCAT11(uVar47,SUB161(
2346: auVar36 >> 0x40,0)))))))))))))));
2347: lVar30 = lVar30 + 0x10;
2348: } while (uVar33 < uVar24);
2349: puVar25 = puVar25 + (ulong)uVar32 * 4;
2350: uVar33 = uVar32;
2351: if (uVar4 != uVar32) {
2352: code_r0x00105f18:
2353: do {
2354: uVar31 = (ulong)uVar33;
2355: uVar33 = uVar33 + 1;
2356: puVar5[uVar31] = *puVar25;
2357: puVar6[uVar31] = puVar25[1];
2358: puVar7[uVar31] = puVar25[2];
2359: puVar25 = puVar25 + 4;
2360: } while (uVar33 < uVar4);
2361: }
2362: goto code_r0x00105990;
2363: }
2364: 
