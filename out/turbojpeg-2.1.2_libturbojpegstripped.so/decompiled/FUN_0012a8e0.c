1: 
2: void FUN_0012a8e0(long param_1,long *param_2,uint param_3,long *param_4,int param_5)
3: 
4: {
5: undefined *puVar1;
6: undefined auVar2 [16];
7: undefined auVar3 [16];
8: undefined uVar4;
9: int iVar5;
10: uint uVar6;
11: long lVar7;
12: long lVar8;
13: undefined uVar9;
14: undefined uVar10;
15: undefined uVar11;
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
27: undefined uVar23;
28: undefined uVar24;
29: undefined uVar25;
30: undefined uVar26;
31: undefined uVar27;
32: undefined uVar28;
33: undefined uVar29;
34: undefined uVar30;
35: undefined uVar31;
36: undefined uVar32;
37: undefined uVar33;
38: undefined *puVar34;
39: ulong uVar35;
40: undefined *puVar36;
41: ulong uVar37;
42: undefined *puVar38;
43: long *plVar39;
44: uint uVar40;
45: long lVar41;
46: undefined *puVar42;
47: undefined *puVar43;
48: long lVar44;
49: uint uVar45;
50: ulong uVar46;
51: uint3 uVar47;
52: undefined uVar56;
53: undefined uVar57;
54: undefined uVar58;
55: undefined uVar59;
56: undefined uVar60;
57: undefined uVar61;
58: uint3 uVar62;
59: undefined uVar64;
60: undefined uVar65;
61: undefined uVar66;
62: undefined auVar67 [16];
63: uint5 uVar48;
64: uint7 uVar49;
65: undefined8 uVar50;
66: unkbyte9 Var51;
67: unkbyte10 Var52;
68: undefined auVar53 [11];
69: undefined auVar54 [12];
70: undefined auVar55 [13];
71: uint5 uVar63;
72: undefined uVar68;
73: undefined uVar69;
74: undefined uVar70;
75: undefined uVar71;
76: 
77: iVar5 = *(int *)(param_1 + 0x38);
78: uVar6 = *(uint *)(param_1 + 0x88);
79: if (iVar5 == 3) {
80: while (param_5 = param_5 + -1, -1 < param_5) {
81: uVar37 = (ulong)param_3;
82: plVar39 = param_4 + 1;
83: param_3 = param_3 + 1;
84: lVar41 = *(long *)(*param_2 + uVar37 * 8);
85: lVar7 = *(long *)(param_2[1] + uVar37 * 8);
86: lVar8 = *(long *)(param_2[2] + uVar37 * 8);
87: puVar1 = (undefined *)*param_4;
88: param_4 = plVar39;
89: if (uVar6 != 0) {
90: lVar44 = 0;
91: puVar34 = puVar1;
92: do {
93: puVar38 = puVar34 + 3;
94: *puVar34 = *(undefined *)(lVar41 + lVar44);
95: puVar34[1] = *(undefined *)(lVar7 + lVar44);
96: puVar43 = (undefined *)(lVar8 + lVar44);
97: lVar44 = lVar44 + 1;
98: puVar34[2] = *puVar43;
99: puVar34 = puVar38;
100: } while (puVar1 + (ulong)(uVar6 - 1) * 3 + 3 != puVar38);
101: }
102: }
103: }
104: else {
105: if (iVar5 == 4) {
106: uVar37 = (ulong)uVar6;
107: uVar45 = uVar6 & 0xfffffff0;
108: LAB_0012a9d0:
109: while( true ) {
110: do {
111: param_5 = param_5 + -1;
112: if (param_5 < 0) {
113: return;
114: }
115: uVar35 = (ulong)param_3;
116: plVar39 = param_4 + 1;
117: param_3 = param_3 + 1;
118: puVar1 = *(undefined **)(*param_2 + uVar35 * 8);
119: puVar34 = *(undefined **)(param_2[1] + uVar35 * 8);
120: puVar43 = *(undefined **)(param_2[2] + uVar35 * 8);
121: puVar38 = *(undefined **)(param_2[3] + uVar35 * 8);
122: puVar36 = (undefined *)*param_4;
123: param_4 = plVar39;
124: } while (uVar6 == 0);
125: puVar42 = puVar36 + uVar37 * 4;
126: if (((((puVar1 + uVar37 <= puVar36 || puVar42 <= puVar1) &&
127: (puVar42 <= puVar34 || puVar34 + uVar37 <= puVar36)) && 0xf < uVar6) &&
128: (puVar43 + uVar37 <= puVar36 || puVar42 <= puVar43)) &&
129: (puVar38 + uVar37 <= puVar36 || puVar42 <= puVar38)) break;
130: lVar41 = 0;
131: do {
132: *puVar36 = puVar1[lVar41];
133: puVar36[1] = puVar34[lVar41];
134: puVar36[2] = puVar43[lVar41];
135: puVar42 = puVar38 + lVar41;
136: lVar41 = lVar41 + 1;
137: puVar36[3] = *puVar42;
138: puVar36 = puVar36 + 4;
139: } while (lVar41 != (ulong)(uVar6 - 1) + 1);
140: }
141: if (0xe < uVar6 - 1) goto code_r0x0012aa91;
142: uVar40 = 0;
143: goto LAB_0012ab1e;
144: }
145: if (((0 < param_5) && (0 < iVar5)) && (uVar6 != 0)) {
146: uVar45 = param_5 + param_3;
147: do {
148: lVar41 = 0;
149: do {
150: puVar34 = *(undefined **)(param_2[lVar41] + (ulong)param_3 * 8);
151: puVar43 = (undefined *)(*param_4 + lVar41);
152: puVar1 = puVar34 + (ulong)(uVar6 - 1) + 1;
153: do {
154: uVar4 = *puVar34;
155: puVar34 = puVar34 + 1;
156: *puVar43 = uVar4;
157: puVar43 = puVar43 + iVar5;
158: } while (puVar34 != puVar1);
159: lVar41 = lVar41 + 1;
160: } while (lVar41 != (ulong)(iVar5 - 1) + 1);
161: param_3 = param_3 + 1;
162: param_4 = param_4 + 1;
163: } while (param_3 != uVar45);
164: }
165: }
166: return;
167: code_r0x0012aa91:
168: lVar41 = 0;
169: uVar40 = 0;
170: do {
171: auVar2 = *(undefined (*) [16])(puVar1 + lVar41);
172: uVar40 = uVar40 + 1;
173: puVar42 = puVar43 + lVar41;
174: uVar4 = puVar42[2];
175: uVar9 = puVar42[3];
176: uVar10 = puVar42[4];
177: uVar11 = puVar42[5];
178: uVar12 = puVar42[6];
179: uVar13 = puVar42[7];
180: uVar14 = puVar42[10];
181: uVar15 = puVar42[0xb];
182: uVar16 = puVar42[0xc];
183: uVar17 = puVar42[0xd];
184: uVar18 = puVar42[0xe];
185: uVar19 = puVar42[0xf];
186: auVar3 = *(undefined (*) [16])(puVar34 + lVar41);
187: uVar56 = SUB161(auVar2 >> 0x40,0);
188: uVar47 = CONCAT12(SUB161(auVar2 >> 0x48,0),CONCAT11(puVar42[8],uVar56));
189: uVar57 = SUB161(auVar2 >> 0x50,0);
190: uVar48 = CONCAT14(uVar57,CONCAT13(puVar42[9],uVar47));
191: uVar58 = SUB161(auVar2 >> 0x58,0);
192: uVar49 = CONCAT16(uVar58,CONCAT15(uVar14,uVar48));
193: uVar50 = CONCAT17(uVar15,uVar49);
194: uVar59 = SUB161(auVar2 >> 0x60,0);
195: Var51 = CONCAT18(uVar59,uVar50);
196: Var52 = CONCAT19(uVar16,Var51);
197: uVar60 = SUB161(auVar2 >> 0x68,0);
198: auVar53 = CONCAT110(uVar60,Var52);
199: auVar54 = CONCAT111(uVar17,auVar53);
200: uVar61 = SUB161(auVar2 >> 0x70,0);
201: auVar55 = CONCAT112(uVar61,auVar54);
202: uVar71 = SUB161(auVar2 >> 0x38,0);
203: uVar70 = SUB161(auVar2 >> 0x30,0);
204: uVar69 = SUB161(auVar2 >> 0x28,0);
205: uVar68 = SUB161(auVar2 >> 0x20,0);
206: auVar67 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
207: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
208: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
209: (SUB163(CONCAT214(SUB162(CONCAT115(uVar13,
210: CONCAT114(uVar71,SUB1614(auVar2,0))) >> 0x70,0),
211: CONCAT113(uVar12,SUB1613(auVar2,0))) >> 0x68,0),
212: CONCAT112(uVar70,SUB1612(auVar2,0))) >> 0x60,0),
213: CONCAT111(uVar11,SUB1611(auVar2,0))) >> 0x58,0),
214: CONCAT110(uVar69,SUB1610(auVar2,0))) >> 0x50,0),
215: CONCAT19(uVar10,SUB169(auVar2,0))) >> 0x48,0),
216: CONCAT18(uVar68,SUB168(auVar2,0))) >> 0x40,0),
217: uVar9)) << 0x38) >> 0x30,0),uVar4)) << 0x28) >>
218: 0x20,0),puVar42[1]),
219: (SUB163(auVar2,0) >> 8) << 0x10) >> 0x10,0),
220: *puVar42)) << 8;
221: puVar42 = puVar38 + lVar41;
222: uVar20 = *puVar42;
223: uVar21 = puVar42[1];
224: uVar22 = puVar42[2];
225: uVar23 = puVar42[3];
226: uVar24 = puVar42[4];
227: uVar25 = puVar42[5];
228: uVar26 = puVar42[6];
229: uVar27 = puVar42[7];
230: uVar28 = puVar42[10];
231: uVar29 = puVar42[0xb];
232: uVar30 = puVar42[0xc];
233: uVar31 = puVar42[0xd];
234: uVar32 = puVar42[0xe];
235: uVar33 = puVar42[0xf];
236: uVar64 = SUB161(auVar3 >> 0x40,0);
237: uVar62 = CONCAT12(SUB161(auVar3 >> 0x48,0),CONCAT11(puVar42[8],uVar64));
238: uVar65 = SUB161(auVar3 >> 0x50,0);
239: uVar63 = CONCAT14(uVar65,CONCAT13(puVar42[9],uVar62));
240: uVar66 = SUB161(auVar3 >> 0x58,0);
241: puVar42 = puVar36 + lVar41 * 4 + 0x10;
242: *puVar42 = uVar68;
243: puVar42[1] = SUB161(auVar3 >> 0x20,0);
244: puVar42[2] = uVar10;
245: puVar42[3] = uVar24;
246: puVar42[4] = uVar69;
247: puVar42[5] = SUB161(auVar3 >> 0x28,0);
248: puVar42[6] = uVar11;
249: puVar42[7] = uVar25;
250: puVar42[8] = uVar70;
251: puVar42[9] = SUB161(auVar3 >> 0x30,0);
252: puVar42[10] = uVar12;
253: puVar42[0xb] = uVar26;
254: puVar42[0xc] = uVar71;
255: puVar42[0xd] = SUB161(auVar3 >> 0x38,0);
256: puVar42[0xe] = uVar13;
257: puVar42[0xf] = uVar27;
258: *(undefined (*) [16])(puVar36 + lVar41 * 4) =
259: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(CONCAT81
260: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
261: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
262: CONCAT214(SUB162(CONCAT115(uVar23,CONCAT114(uVar9,
263: SUB1614(auVar67,0))) >> 0x70,0),
264: CONCAT113(SUB161(auVar3 >> 0x18,0),
265: SUB1613(auVar67,0))) >> 0x68,0),
266: CONCAT112(SUB161(auVar2 >> 0x18,0),
267: SUB1612(auVar67,0))) >> 0x60,0),
268: CONCAT111(uVar22,SUB1611(auVar67,0))) >> 0x58,0),
269: CONCAT110(uVar4,SUB1610(auVar67,0))) >> 0x50,0),
270: CONCAT19(SUB161(auVar3 >> 0x10,0),
271: SUB169(auVar67,0))) >> 0x48,0),
272: CONCAT18(SUB161(auVar2 >> 0x10,0),
273: SUB168(auVar67,0))) >> 0x40,0),uVar21),
274: (SUB167(auVar67,0) >> 0x18) << 0x30) >> 0x30,0),
275: SUB161(auVar3 >> 8,0)),
276: (SUB165(auVar67,0) >> 0x10) << 0x20) >> 0x20,0),
277: uVar20),(SUB163(auVar67,0) >> 8) << 0x10) >> 0x10,0),
278: SUB162(auVar2,0) & 0xff | SUB162(auVar3,0) << 8);
279: *(undefined (*) [16])(puVar36 + lVar41 * 4 + 0x20) =
280: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(
281: CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(SUB167(
282: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
283: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
284: uVar29,CONCAT114(uVar15,CONCAT113(uVar18,auVar55))
285: ) >> 0x70,0),CONCAT113(uVar66,auVar55)) >> 0x68,0)
286: ,CONCAT112(uVar58,auVar54)) >> 0x60,0),
287: CONCAT111(uVar28,auVar53)) >> 0x58,0),
288: CONCAT110(uVar14,Var52)) >> 0x50,0),
289: CONCAT19(uVar65,Var51)) >> 0x48,0),
290: CONCAT18(uVar57,uVar50)) >> 0x40,0),
291: (((ulong)CONCAT16(uVar66,CONCAT15(uVar28,uVar63))
292: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
293: (uVar49 >> 0x18) << 0x30) >> 0x30,0),
294: (((uint6)uVar63 & 0xff0000) >> 0x10) << 0x28) >>
295: 0x28,0),(uVar48 >> 0x10) << 0x20) >> 0x20,0),
296: ((uVar62 & 0xff00) >> 8) << 0x18) >> 0x18,0),
297: (uVar47 >> 8) << 0x10) >> 0x10,0),CONCAT11(uVar64,uVar56));
298: puVar42 = puVar36 + lVar41 * 4 + 0x30;
299: *puVar42 = uVar59;
300: puVar42[1] = SUB161(auVar3 >> 0x60,0);
301: puVar42[2] = uVar16;
302: puVar42[3] = uVar30;
303: puVar42[4] = uVar60;
304: puVar42[5] = SUB161(auVar3 >> 0x68,0);
305: puVar42[6] = uVar17;
306: puVar42[7] = uVar31;
307: puVar42[8] = uVar61;
308: puVar42[9] = SUB161(auVar3 >> 0x70,0);
309: puVar42[10] = uVar18;
310: puVar42[0xb] = uVar32;
311: puVar42[0xc] = SUB161(auVar2 >> 0x78,0);
312: puVar42[0xd] = SUB161(auVar3 >> 0x78,0);
313: puVar42[0xe] = uVar19;
314: puVar42[0xf] = uVar33;
315: lVar41 = lVar41 + 0x10;
316: } while (uVar40 < uVar6 >> 4);
317: puVar36 = puVar36 + (ulong)uVar45 * 4;
318: uVar40 = uVar45;
319: if (uVar6 != uVar45) {
320: LAB_0012ab1e:
321: uVar35 = (ulong)uVar40;
322: *puVar36 = puVar1[uVar35];
323: puVar36[1] = puVar34[uVar35];
324: puVar36[2] = puVar43[uVar35];
325: puVar36[3] = puVar38[uVar35];
326: uVar35 = (ulong)(uVar40 + 1);
327: if (uVar40 + 1 < uVar6) {
328: puVar36[4] = puVar1[uVar35];
329: puVar36[5] = puVar34[uVar35];
330: puVar36[6] = puVar43[uVar35];
331: puVar36[7] = puVar38[uVar35];
332: uVar35 = (ulong)(uVar40 + 2);
333: if (uVar40 + 2 < uVar6) {
334: puVar36[8] = puVar1[uVar35];
335: puVar36[9] = puVar34[uVar35];
336: puVar36[10] = puVar43[uVar35];
337: puVar36[0xb] = puVar38[uVar35];
338: uVar35 = (ulong)(uVar40 + 3);
339: if (uVar40 + 3 < uVar6) {
340: puVar36[0xc] = puVar1[uVar35];
341: puVar36[0xd] = puVar34[uVar35];
342: puVar36[0xe] = puVar43[uVar35];
343: puVar36[0xf] = puVar38[uVar35];
344: uVar35 = (ulong)(uVar40 + 4);
345: if (uVar40 + 4 < uVar6) {
346: puVar36[0x10] = puVar1[uVar35];
347: puVar36[0x11] = puVar34[uVar35];
348: puVar36[0x12] = puVar43[uVar35];
349: puVar36[0x13] = puVar38[uVar35];
350: uVar35 = (ulong)(uVar40 + 5);
351: if (uVar40 + 5 < uVar6) {
352: puVar36[0x14] = puVar1[uVar35];
353: puVar36[0x15] = puVar34[uVar35];
354: puVar36[0x16] = puVar43[uVar35];
355: puVar36[0x17] = puVar38[uVar35];
356: uVar35 = (ulong)(uVar40 + 6);
357: if (uVar40 + 6 < uVar6) {
358: puVar36[0x18] = puVar1[uVar35];
359: puVar36[0x19] = puVar34[uVar35];
360: puVar36[0x1a] = puVar43[uVar35];
361: puVar36[0x1b] = puVar38[uVar35];
362: uVar35 = (ulong)(uVar40 + 7);
363: if (uVar40 + 7 < uVar6) {
364: puVar36[0x1c] = puVar1[uVar35];
365: puVar36[0x1d] = puVar34[uVar35];
366: puVar36[0x1e] = puVar43[uVar35];
367: puVar36[0x1f] = puVar38[uVar35];
368: uVar35 = (ulong)(uVar40 + 8);
369: if (uVar40 + 8 < uVar6) {
370: puVar36[0x20] = puVar1[uVar35];
371: puVar36[0x21] = puVar34[uVar35];
372: puVar36[0x22] = puVar43[uVar35];
373: puVar36[0x23] = puVar38[uVar35];
374: uVar35 = (ulong)(uVar40 + 9);
375: if (uVar40 + 9 < uVar6) {
376: puVar36[0x24] = puVar1[uVar35];
377: puVar36[0x25] = puVar34[uVar35];
378: puVar36[0x26] = puVar43[uVar35];
379: puVar36[0x27] = puVar38[uVar35];
380: uVar35 = (ulong)(uVar40 + 10);
381: if (uVar40 + 10 < uVar6) {
382: puVar36[0x28] = puVar1[uVar35];
383: puVar36[0x29] = puVar34[uVar35];
384: puVar36[0x2a] = puVar43[uVar35];
385: puVar36[0x2b] = puVar38[uVar35];
386: uVar35 = (ulong)(uVar40 + 0xb);
387: if (uVar40 + 0xb < uVar6) {
388: puVar36[0x2c] = puVar1[uVar35];
389: puVar36[0x2d] = puVar34[uVar35];
390: puVar36[0x2e] = puVar43[uVar35];
391: puVar36[0x2f] = puVar38[uVar35];
392: uVar35 = (ulong)(uVar40 + 0xc);
393: if (uVar40 + 0xc < uVar6) {
394: puVar36[0x30] = puVar1[uVar35];
395: puVar36[0x31] = puVar34[uVar35];
396: puVar36[0x32] = puVar43[uVar35];
397: puVar36[0x33] = puVar38[uVar35];
398: uVar35 = (ulong)(uVar40 + 0xd);
399: if (uVar40 + 0xd < uVar6) {
400: uVar46 = (ulong)(uVar40 + 0xe);
401: puVar36[0x34] = puVar1[uVar35];
402: puVar36[0x35] = puVar34[uVar35];
403: puVar36[0x36] = puVar43[uVar35];
404: puVar36[0x37] = puVar38[uVar35];
405: if (uVar40 + 0xe < uVar6) {
406: puVar36[0x38] = puVar1[uVar46];
407: puVar36[0x39] = puVar34[uVar46];
408: puVar36[0x3a] = puVar43[uVar46];
409: puVar36[0x3b] = puVar38[uVar46];
410: }
411: }
412: }
413: }
414: }
415: }
416: }
417: }
418: }
419: }
420: }
421: }
422: }
423: }
424: }
425: goto LAB_0012a9d0;
426: }
427: 
