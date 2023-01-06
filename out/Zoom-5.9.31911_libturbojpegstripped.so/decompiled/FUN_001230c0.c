1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_001230c0(long param_1,long *param_2,uint param_3,ushort **param_4,int param_5)
5: 
6: {
7: byte *pbVar1;
8: byte *pbVar2;
9: byte *pbVar3;
10: ushort **ppuVar4;
11: uint6 uVar5;
12: byte bVar6;
13: byte bVar7;
14: byte bVar8;
15: byte bVar9;
16: byte bVar10;
17: byte bVar11;
18: byte bVar12;
19: byte bVar13;
20: byte bVar14;
21: byte bVar15;
22: byte bVar16;
23: byte bVar17;
24: byte bVar18;
25: byte bVar19;
26: byte bVar20;
27: byte bVar21;
28: byte bVar22;
29: byte bVar23;
30: byte bVar24;
31: byte bVar25;
32: byte bVar26;
33: byte bVar27;
34: byte bVar28;
35: byte bVar29;
36: byte bVar30;
37: byte bVar31;
38: byte bVar32;
39: byte bVar33;
40: byte bVar34;
41: byte bVar35;
42: byte bVar36;
43: byte bVar37;
44: byte bVar38;
45: byte bVar39;
46: byte bVar40;
47: byte bVar41;
48: uint5 uVar42;
49: ulong uVar43;
50: long lVar44;
51: uint uVar45;
52: ushort *puVar46;
53: uint uVar47;
54: ushort *puVar48;
55: ushort *puVar49;
56: ushort *puVar50;
57: uint uVar51;
58: uint *puVar52;
59: ushort *puVar53;
60: ushort *puVar54;
61: ushort *puVar55;
62: uint uVar56;
63: undefined2 uVar57;
64: uint uVar60;
65: undefined uVar70;
66: undefined uVar71;
67: undefined uVar72;
68: undefined uVar73;
69: undefined uVar75;
70: byte bVar76;
71: undefined auVar69 [16];
72: unkuint10 Var74;
73: undefined uVar80;
74: undefined uVar81;
75: undefined uVar82;
76: undefined uVar83;
77: unkuint10 Var77;
78: unkuint10 Var78;
79: unkuint10 Var79;
80: undefined uVar92;
81: undefined uVar93;
82: undefined uVar94;
83: undefined uVar95;
84: undefined uVar96;
85: undefined auVar86 [13];
86: undefined auVar84 [16];
87: undefined auVar85 [16];
88: undefined auVar89 [13];
89: unkuint10 Var90;
90: unkuint10 Var91;
91: undefined2 uVar97;
92: uint uVar100;
93: uint uVar101;
94: uint5 uVar102;
95: undefined uVar112;
96: undefined uVar113;
97: byte bVar114;
98: undefined uVar115;
99: undefined uVar116;
100: undefined auVar111 [16];
101: undefined2 uVar117;
102: uint uVar119;
103: undefined uVar130;
104: undefined uVar131;
105: byte bVar132;
106: undefined uVar133;
107: undefined uVar134;
108: undefined auVar128 [16];
109: undefined auVar129 [16];
110: ushort uVar135;
111: uint uVar136;
112: undefined uVar141;
113: undefined auVar140 [16];
114: uint7 uVar142;
115: uint uVar143;
116: uint7 uVar148;
117: undefined auVar147 [16];
118: uint uVar149;
119: uint uVar150;
120: byte bVar155;
121: undefined uVar156;
122: uint7 uVar157;
123: undefined auVar154 [16];
124: uint5 uVar158;
125: undefined auVar159 [14];
126: ushort uVar160;
127: uint uVar161;
128: ushort uVar164;
129: undefined auVar163 [16];
130: undefined auVar165 [14];
131: ushort uVar166;
132: undefined auVar167 [16];
133: unkuint10 Var168;
134: undefined auVar169 [16];
135: uint3 uVar58;
136: undefined4 uVar59;
137: uint5 uVar61;
138: uint5 uVar62;
139: undefined6 uVar63;
140: uint7 uVar64;
141: undefined8 uVar65;
142: unkbyte10 Var66;
143: undefined auVar67 [12];
144: undefined auVar68 [12];
145: undefined auVar87 [13];
146: undefined auVar88 [13];
147: uint3 uVar98;
148: undefined4 uVar99;
149: uint5 uVar103;
150: undefined6 uVar104;
151: uint7 uVar105;
152: undefined8 uVar106;
153: ulong uVar107;
154: unkbyte10 Var108;
155: undefined auVar109 [12];
156: undefined auVar110 [14];
157: undefined4 uVar118;
158: uint5 uVar120;
159: undefined6 uVar121;
160: uint7 uVar122;
161: undefined8 uVar123;
162: ulong uVar124;
163: unkbyte10 Var125;
164: undefined auVar126 [12];
165: undefined auVar127 [14];
166: ulong uVar137;
167: undefined auVar138 [12];
168: undefined auVar139 [14];
169: ulong uVar144;
170: undefined auVar145 [12];
171: undefined auVar146 [14];
172: ulong uVar151;
173: undefined auVar152 [12];
174: undefined auVar153 [14];
175: undefined auVar162 [14];
176: 
177: uVar56 = *(uint *)(param_1 + 0x88);
178: while (param_5 = param_5 + -1, -1 < param_5) {
179: /* WARNING: Read-only address (ram,0x00189850) is written */
180: /* WARNING: Read-only address (ram,0x00189860) is written */
181: uVar43 = (ulong)param_3;
182: ppuVar4 = param_4 + 1;
183: param_3 = param_3 + 1;
184: puVar55 = *(ushort **)(*param_2 + uVar43 * 8);
185: puVar54 = *(ushort **)(param_2[1] + uVar43 * 8);
186: puVar48 = *(ushort **)(param_2[2] + uVar43 * 8);
187: puVar49 = *param_4;
188: puVar46 = puVar49;
189: puVar53 = puVar48;
190: if (((ulong)puVar49 & 3) != 0) {
191: bVar76 = *(byte *)puVar55;
192: bVar114 = *(byte *)puVar54;
193: puVar46 = puVar49 + 1;
194: uVar56 = uVar56 - 1;
195: puVar53 = (ushort *)((long)puVar48 + 1);
196: puVar54 = (ushort *)((long)puVar54 + 1);
197: puVar55 = (ushort *)((long)puVar55 + 1);
198: *puVar49 = (ushort)((bVar76 & 0xf8) << 8) | (ushort)((bVar114 & 0xfc) << 3) |
199: (ushort)(*(byte *)puVar48 >> 3);
200: }
201: uVar47 = uVar56 >> 1;
202: if (uVar47 != 0) {
203: uVar43 = (ulong)uVar47;
204: puVar48 = puVar46 + uVar43 * 2;
205: if (((puVar46 < puVar53 + uVar43 && puVar53 < puVar48 ||
206: puVar46 < puVar54 + uVar43 && puVar54 < puVar48) || uVar47 < 0x10) ||
207: (puVar46 < puVar55 + uVar43 && puVar55 < puVar48)) {
208: lVar44 = 0;
209: puVar48 = puVar55;
210: puVar49 = puVar54;
211: puVar50 = puVar53;
212: do {
213: *(uint *)(puVar46 + lVar44 * 2) =
214: (*(byte *)puVar49 & 0xfc) << 3 | (*(byte *)puVar48 & 0xf8) << 8 |
215: (uint)(*(byte *)puVar50 >> 3) |
216: ((*(byte *)((long)puVar49 + 1) & 0xfc) << 3 |
217: (*(byte *)((long)puVar48 + 1) & 0xf8) << 8 |
218: (uint)(*(byte *)((long)puVar50 + 1) >> 3)) << 0x10;
219: lVar44 = lVar44 + 1;
220: puVar48 = puVar48 + 1;
221: puVar49 = puVar49 + 1;
222: puVar50 = puVar50 + 1;
223: } while ((uint)lVar44 < uVar47);
224: }
225: else {
226: lVar44 = 0;
227: uVar45 = 0;
228: uVar51 = (uVar56 >> 5) << 4;
229: do {
230: auVar129 = *(undefined (*) [16])((long)puVar55 + lVar44);
231: uVar45 = uVar45 + 1;
232: pbVar1 = (byte *)((long)puVar55 + lVar44 + 0x10);
233: bVar76 = pbVar1[1];
234: bVar114 = pbVar1[2];
235: bVar6 = pbVar1[3];
236: bVar7 = pbVar1[4];
237: bVar132 = pbVar1[5];
238: bVar8 = pbVar1[6];
239: bVar9 = pbVar1[7];
240: bVar10 = pbVar1[9];
241: bVar11 = pbVar1[10];
242: bVar12 = pbVar1[0xb];
243: bVar13 = pbVar1[0xc];
244: bVar14 = pbVar1[0xe];
245: bVar15 = pbVar1[0xf];
246: uVar92 = SUB161(auVar129 >> 0x38,0);
247: uVar83 = SUB161(auVar129 >> 0x30,0);
248: uVar81 = SUB161(auVar129 >> 0x28,0);
249: uVar75 = SUB161(auVar129 >> 0x20,0);
250: uVar73 = SUB161(auVar129 >> 8,0);
251: auVar128 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
252: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
253: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
254: (CONCAT214(SUB162(CONCAT115(bVar9,CONCAT114(uVar92
255: ,SUB1614(auVar129,0))) >> 0x70,0),
256: CONCAT113(bVar8,SUB1613(auVar129,0))) >> 0x68,0),
257: CONCAT112(uVar83,SUB1612(auVar129,0))) >> 0x60,0),
258: CONCAT111(bVar132,SUB1611(auVar129,0))) >> 0x58,0)
259: ,CONCAT110(uVar81,SUB1610(auVar129,0))) >> 0x50,0)
260: ,CONCAT19(bVar7,SUB169(auVar129,0))) >> 0x48,0),
261: CONCAT18(uVar75,SUB168(auVar129,0))) >> 0x40,0),
262: bVar6),(SUB167(auVar129,0) >> 0x18) << 0x30) >>
263: 0x30,0),bVar114),
264: (SUB165(auVar129,0) >> 0x10) << 0x20) >> 0x20,0),
265: bVar76),uVar73)) << 0x10;
266: uVar70 = SUB161(auVar129 >> 0x48,0);
267: uVar71 = SUB161(auVar129 >> 0x50,0);
268: uVar80 = SUB161(auVar129 >> 0x58,0);
269: uVar72 = SUB161(auVar129 >> 0x68,0);
270: uVar82 = SUB161(auVar129 >> 0x78,0);
271: pbVar2 = (byte *)((long)puVar53 + lVar44 + 0x10);
272: bVar16 = pbVar2[1];
273: bVar17 = pbVar2[2];
274: bVar18 = pbVar2[3];
275: bVar19 = pbVar2[4];
276: bVar20 = pbVar2[5];
277: bVar21 = pbVar2[6];
278: bVar22 = pbVar2[7];
279: bVar23 = pbVar2[9];
280: bVar24 = pbVar2[10];
281: bVar25 = pbVar2[0xb];
282: bVar26 = pbVar2[0xc];
283: bVar27 = pbVar2[0xe];
284: bVar28 = pbVar2[0xf];
285: uVar157 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
286: CONCAT214(SUB162(CONCAT115(bVar9,CONCAT114(uVar92,
287: SUB1614(auVar129,0))) >> 0x70,0),
288: CONCAT113(bVar8,SUB1613(auVar129,0))) >> 0x68,0),
289: CONCAT112(uVar83,SUB1612(auVar129,0))) >> 0x60,0),
290: CONCAT111(bVar132,SUB1611(auVar129,0))) >> 0x58,0)
291: ,CONCAT110(uVar81,SUB1610(auVar129,0))) >> 0x50,0)
292: ,CONCAT19(bVar7,SUB169(auVar129,0))) >> 0x48,0);
293: auVar147 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168
294: (CONCAT79(uVar157,CONCAT18(uVar75,SUB168(auVar129,
295: 0))) >> 0x40,0),bVar6)) << 0x38) >> 0x30,0),
296: bVar114)) << 0x28) >> 0x20,0),bVar76)) << 0x18 &
297: (undefined  [16])0xffffffffffff0000;
298: pbVar3 = (byte *)((long)puVar54 + lVar44 + 0x10);
299: bVar29 = pbVar3[1];
300: bVar30 = pbVar3[2];
301: bVar31 = pbVar3[3];
302: bVar32 = pbVar3[4];
303: bVar33 = pbVar3[5];
304: bVar34 = pbVar3[6];
305: bVar35 = pbVar3[7];
306: bVar36 = pbVar3[9];
307: bVar37 = pbVar3[10];
308: bVar38 = pbVar3[0xb];
309: bVar39 = pbVar3[0xc];
310: bVar40 = pbVar3[0xe];
311: bVar41 = pbVar3[0xf];
312: auVar128 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
313: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
314: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
315: bVar12,CONCAT114(SUB161(auVar128 >> 0x38,0),
316: SUB1614(auVar128,0))) >> 0x70,0),
317: CONCAT113(uVar80,SUB1613(auVar128,0))) >> 0x68,0),
318: CONCAT112(SUB161(auVar128 >> 0x30,0),
319: SUB1612(auVar128,0))) >> 0x60,0),
320: CONCAT111(bVar11,SUB1611(auVar128,0))) >> 0x58,0),
321: CONCAT110(SUB161(auVar128 >> 0x28,0),
322: SUB1610(auVar128,0))) >> 0x50,0),
323: CONCAT19(uVar71,SUB169(auVar128,0))) >> 0x48,0),
324: CONCAT18(SUB161(auVar128 >> 0x20,0),
325: SUB168(auVar128,0))) >> 0x40,0),bVar10),
326: (SUB167(auVar128,0) >> 0x18) << 0x30) >> 0x30,0),
327: uVar70),uVar73)) << 0x20 &
328: (undefined  [16])0xffffffffff000000;
329: uVar156 = SUB161(auVar129 >> 0x18,0);
330: bVar155 = SUB161(auVar129 >> 0x10,0);
331: auVar147 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
332: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
333: (SUB163(CONCAT214(SUB162(CONCAT115(bVar12,
334: CONCAT114(bVar6,SUB1614(auVar147,0))) >> 0x70,0),
335: CONCAT113(uVar80,SUB1613(auVar147,0))) >> 0x68,0),
336: CONCAT112(uVar156,SUB1612(auVar147,0))) >> 0x60,0)
337: ,CONCAT111(bVar11,SUB1611(auVar147,0))) >> 0x58,0)
338: ,CONCAT110(bVar114,SUB1610(auVar147,0))) >> 0x50,0
339: ),CONCAT19(uVar71,SUB169(auVar147,0))) >> 0x48,0),
340: CONCAT18(bVar155,SUB168(auVar147,0))) >> 0x40,0),
341: bVar10)) << 0x38) >> 0x30,0),uVar70)) << 0x28 &
342: (undefined  [16])0xffffffff00000000;
343: auVar147 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
344: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
345: (SUB163(CONCAT214(SUB162(CONCAT115(pbVar1[0xd],
346: CONCAT114(
347: bVar10,SUB1614(auVar147,0))) >> 0x70,0),
348: CONCAT113(bVar132,SUB1613(auVar147,0))) >> 0x68,0)
349: ,CONCAT112(bVar76,SUB1612(auVar147,0))) >> 0x60,0)
350: ,CONCAT111(uVar72,SUB1611(auVar147,0))) >> 0x58,0)
351: ,CONCAT110(uVar70,SUB1610(auVar147,0))) >> 0x50,0)
352: ,CONCAT19(uVar81,SUB169(auVar147,0))) >> 0x48,0),
353: CONCAT18(uVar73,SUB168(auVar147,0))) >> 0x40,0),
354: bVar13)) << 0x38) >> 0x10,0) &
355: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0) &
356: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
357: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),
358: uVar75)) << 8;
359: uVar58 = CONCAT12(uVar71,CONCAT11(uVar83,bVar155));
360: uVar102 = CONCAT14(bVar114,CONCAT13(SUB161(auVar129 >> 0x70,0),uVar58));
361: auVar128 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
362: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
363: (CONCAT115(pbVar1[0xd],
364: CONCAT114(SUB161(auVar128 >> 0x38,0),
365: SUB1614(auVar128,0))) >> 0x70
366: ,0),CONCAT113(bVar132,SUB1613(auVar128,0))) >>
367: 0x68,0),CONCAT112(SUB161(auVar128 >> 0x30,0),
368: SUB1612(auVar128,0))) >> 0x60,0)
369: ,CONCAT111(uVar72,SUB1611(auVar128,0))) >> 0x58,0)
370: ,CONCAT110(SUB161(auVar128 >> 0x28,0),
371: SUB1610(auVar128,0))) >> 0x50,0),
372: CONCAT19(uVar81,SUB169(auVar128,0))) >> 0x48,0),
373: CONCAT18(SUB161(auVar128 >> 0x20,0),
374: SUB168(auVar128,0))) >> 0x40,0),bVar13))
375: << 0x38;
376: auVar84 = auVar128 & (undefined  [16])0xffff000000000000;
377: auVar128 = auVar128 & (undefined  [16])0xffff000000000000;
378: uVar43 = (ulong)CONCAT16(bVar11,CONCAT15(bVar8,uVar102)) & 0xff000000;
379: uVar135 = SUB162(auVar129,0) & 0xff | (ushort)bVar155 << 8;
380: auVar147 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT79(
381: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
382: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
383: CONCAT115(bVar14,CONCAT114(bVar13,SUB1614(auVar147
384: ,0))) >> 0x70,0),
385: CONCAT113(bVar11,SUB1613(auVar147,0))) >> 0x68,0),
386: CONCAT112(pbVar1[8],SUB1612(auVar147,0))) >> 0x60,
387: 0),CONCAT111(bVar8,SUB1611(auVar147,0))) >> 0x58,0
388: ),CONCAT110(bVar7,SUB1610(auVar147,0))) >> 0x50,0)
389: ,CONCAT19(bVar114,SUB169(auVar147,0))) >> 0x48,0),
390: CONCAT18(*pbVar1,SUB168(auVar147,0))) >> 0x40,0),
391: (uVar43 >> 0x18) << 0x38) >> 0x20,0) &
392: SUB1612((undefined  [16])0xffffffffffffffff >>
393: 0x20,0) &
394: SUB1612((undefined  [16])0xff00000000000000 >>
395: 0x20,0) &
396: SUB1612((undefined  [16])0xffffff0000000000 >>
397: 0x20,0),((uVar58 & 0xff00) >> 8) << 0x18)
398: >> 0x18,0),(SUB163(auVar147,0) >> 8) << 0x10) >>
399: 0x10,0),uVar135);
400: uVar117 = CONCAT11(uVar156,SUB161(auVar128 >> 0x40,0));
401: uVar118 = CONCAT13(uVar92,CONCAT12(SUB161(auVar128 >> 0x48,0),uVar117));
402: uVar130 = SUB161(auVar84 >> 0x50,0);
403: uVar103 = CONCAT14(uVar130,uVar118);
404: uVar121 = CONCAT15(uVar80,uVar103);
405: uVar131 = SUB161(auVar84 >> 0x58,0);
406: uVar122 = CONCAT16(uVar131,uVar121);
407: uVar123 = CONCAT17(uVar82,uVar122);
408: bVar132 = SUB161(auVar84 >> 0x60,0);
409: Var125 = CONCAT19(bVar6,CONCAT18(bVar132,uVar123));
410: uVar133 = SUB161(auVar84 >> 0x68,0);
411: auVar109 = CONCAT111(bVar9,CONCAT110(uVar133,Var125));
412: uVar134 = SUB161(auVar84 >> 0x70,0);
413: auVar128 = *(undefined (*) [16])((long)puVar54 + lVar44);
414: uVar149 = (uint)CONCAT12(bVar114,(ushort)*pbVar1);
415: uVar42 = CONCAT14(bVar7,uVar149);
416: uVar151 = (ulong)CONCAT16(bVar8,(uint6)uVar42);
417: auVar152 = ZEXT1112(CONCAT110(bVar11,(unkuint10)
418: (CONCAT18(pbVar1[8],uVar151) & 0xffffffffffffffff)));
419: auVar153 = ZEXT1314(CONCAT112(bVar13,auVar152));
420: auVar154 = CONCAT97((unkuint9)
421: (SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411(
422: SUB154(CONCAT312(SUB153(CONCAT213(SUB152(CONCAT114
423: ((char)(uVar43 >> 0x18),
424: ZEXT1314(SUB1613(auVar147,0))) >> 0x68,0),
425: CONCAT112(SUB161(auVar129 >> 0x60,0),
426: SUB1612(auVar147,0))) >> 0x60,0),
427: ZEXT1112(SUB1611(auVar147,0))) >> 0x58,0),
428: CONCAT110((char)((uint6)uVar102 >> 0x10),
429: SUB1610(auVar147,0))) >> 0x50,0),
430: (unkuint10)SUB169(auVar147,0)) >> 0x48,0),
431: CONCAT18(SUB161(auVar129 >> 0x40,0),
432: SUB168(auVar147,0))) >> 0x40,0),
433: SUB168(auVar147,0)) >> 0x38,0) & 0xff) &
434: SUB169((undefined  [16])0xffffffffffffffff >> 0x38,0),
435: (SUB167(auVar147,0) >> 0x18) << 0x30) &
436: (undefined  [16])0xffff000000000000;
437: auVar111 = CONCAT115(SUB1611(auVar154 >> 0x28,0),(SUB165(auVar147,0) >> 0x10) << 0x20) &
438: (undefined  [16])0xffffffff00000000;
439: auVar147 = CONCAT142(SUB1614(CONCAT133(SUB1613(auVar111 >> 0x18,0),
440: (SUB163(auVar147,0) >> 8) << 0x10) >> 0x10,0),
441: uVar135) & (undefined  [16])0xffffffffffff00ff;
442: uVar70 = SUB161(auVar128 >> 0x48,0);
443: uVar71 = SUB161(auVar128 >> 0x50,0);
444: uVar81 = SUB161(auVar128 >> 0x58,0);
445: uVar72 = SUB161(auVar128 >> 0x68,0);
446: uVar83 = SUB161(auVar128 >> 0x78,0);
447: uVar94 = SUB161(auVar128 >> 0x38,0);
448: uVar93 = SUB161(auVar128 >> 0x30,0);
449: uVar92 = SUB161(auVar128 >> 0x28,0);
450: uVar75 = SUB161(auVar128 >> 0x20,0);
451: uVar73 = SUB161(auVar128 >> 8,0);
452: auVar129 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
453: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
454: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
455: (CONCAT214(SUB162(CONCAT115(bVar35,CONCAT114(
456: uVar94,SUB1614(auVar128,0))) >> 0x70,0),
457: CONCAT113(bVar34,SUB1613(auVar128,0))) >> 0x68,0),
458: CONCAT112(uVar93,SUB1612(auVar128,0))) >> 0x60,0),
459: CONCAT111(bVar33,SUB1611(auVar128,0))) >> 0x58,0),
460: CONCAT110(uVar92,SUB1610(auVar128,0))) >> 0x50,0),
461: CONCAT19(bVar32,SUB169(auVar128,0))) >> 0x48,0),
462: CONCAT18(uVar75,SUB168(auVar128,0))) >> 0x40,0),
463: bVar31),(SUB167(auVar128,0) >> 0x18) << 0x30) >>
464: 0x30,0),bVar30),
465: (SUB165(auVar128,0) >> 0x10) << 0x20) >> 0x20,0),
466: bVar29),uVar73)) << 0x10;
467: uVar148 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
468: CONCAT214(SUB162(CONCAT115(bVar35,CONCAT114(uVar94
469: ,SUB1614(auVar128,0))) >> 0x70,0),
470: CONCAT113(bVar34,SUB1613(auVar128,0))) >> 0x68,0),
471: CONCAT112(uVar93,SUB1612(auVar128,0))) >> 0x60,0),
472: CONCAT111(bVar33,SUB1611(auVar128,0))) >> 0x58,0),
473: CONCAT110(uVar92,SUB1610(auVar128,0))) >> 0x50,0),
474: CONCAT19(bVar32,SUB169(auVar128,0))) >> 0x48,0);
475: auVar69 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
476: CONCAT79(uVar148,CONCAT18(uVar75,SUB168(auVar128,0
477: ))) >> 0x40
478: ,0),bVar31)) << 0x38) >> 0x30,0),bVar30)) << 0x28)
479: >> 0x20,0),bVar29)) << 0x18 &
480: (undefined  [16])0xffffffffffff0000;
481: auVar129 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
482: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
483: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
484: bVar38,CONCAT114(SUB161(auVar129 >> 0x38,0),
485: SUB1614(auVar129,0))) >> 0x70,0),
486: CONCAT113(uVar81,SUB1613(auVar129,0))) >> 0x68,0),
487: CONCAT112(SUB161(auVar129 >> 0x30,0),
488: SUB1612(auVar129,0))) >> 0x60,0),
489: CONCAT111(bVar37,SUB1611(auVar129,0))) >> 0x58,0),
490: CONCAT110(SUB161(auVar129 >> 0x28,0),
491: SUB1610(auVar129,0))) >> 0x50,0),
492: CONCAT19(uVar71,SUB169(auVar129,0))) >> 0x48,0),
493: CONCAT18(SUB161(auVar129 >> 0x20,0),
494: SUB168(auVar129,0))) >> 0x40,0),bVar36),
495: (SUB167(auVar129,0) >> 0x18) << 0x30) >> 0x30,0),
496: uVar70),uVar73)) << 0x20 &
497: (undefined  [16])0xffffffffff000000;
498: uVar95 = SUB161(auVar128 >> 0x18,0);
499: bVar76 = SUB161(auVar128 >> 0x10,0);
500: auVar69 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
501: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
502: (SUB163(CONCAT214(SUB162(CONCAT115(bVar38,
503: CONCAT114(bVar31,SUB1614(auVar69,0))) >> 0x70,0),
504: CONCAT113(uVar81,SUB1613(auVar69,0))) >> 0x68,0),
505: CONCAT112(uVar95,SUB1612(auVar69,0))) >> 0x60,0),
506: CONCAT111(bVar37,SUB1611(auVar69,0))) >> 0x58,0),
507: CONCAT110(bVar30,SUB1610(auVar69,0))) >> 0x50,0),
508: CONCAT19(uVar71,SUB169(auVar69,0))) >> 0x48,0),
509: CONCAT18(bVar76,SUB168(auVar69,0))) >> 0x40,0),
510: bVar36)) << 0x38) >> 0x30,0),uVar70)) << 0x28 &
511: (undefined  [16])0xffffffff00000000;
512: auVar140 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
513: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
514: (SUB163(CONCAT214(SUB162(CONCAT115(pbVar3[0xd],
515: CONCAT114(
516: bVar36,SUB1614(auVar69,0))) >> 0x70,0),
517: CONCAT113(bVar33,SUB1613(auVar69,0))) >> 0x68,0),
518: CONCAT112(bVar29,SUB1612(auVar69,0))) >> 0x60,0),
519: CONCAT111(uVar72,SUB1611(auVar69,0))) >> 0x58,0),
520: CONCAT110(uVar70,SUB1610(auVar69,0))) >> 0x50,0),
521: CONCAT19(uVar92,SUB169(auVar69,0))) >> 0x48,0),
522: CONCAT18(uVar73,SUB168(auVar69,0))) >> 0x40,0),
523: bVar39)) << 0x38) >> 0x10,0) &
524: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0) &
525: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
526: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),
527: uVar75)) << 8;
528: uVar58 = CONCAT12(uVar71,CONCAT11(uVar93,bVar76));
529: uVar102 = CONCAT14(bVar30,CONCAT13(SUB161(auVar128 >> 0x70,0),uVar58));
530: auVar69 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
531: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
532: (CONCAT115(pbVar3[0xd],
533: CONCAT114(SUB161(auVar129 >> 0x38,0),
534: SUB1614(auVar129,0))) >> 0x70
535: ,0),CONCAT113(bVar33,SUB1613(auVar129,0))) >>
536: 0x68,0),CONCAT112(SUB161(auVar129 >> 0x30,0),
537: SUB1612(auVar129,0))) >> 0x60,0)
538: ,CONCAT111(uVar72,SUB1611(auVar129,0))) >> 0x58,0)
539: ,CONCAT110(SUB161(auVar129 >> 0x28,0),
540: SUB1610(auVar129,0))) >> 0x50,0),
541: CONCAT19(uVar92,SUB169(auVar129,0))) >> 0x48,0),
542: CONCAT18(SUB161(auVar129 >> 0x20,0),
543: SUB168(auVar129,0))) >> 0x40,0),bVar39))
544: << 0x38;
545: auVar85 = auVar69 & (undefined  [16])0xffff000000000000;
546: auVar69 = auVar69 & (undefined  [16])0xffff000000000000;
547: auVar129 = *(undefined (*) [16])((long)puVar53 + lVar44);
548: uVar43 = (ulong)CONCAT16(bVar37,CONCAT15(bVar34,uVar102)) & 0xff000000;
549: uVar5 = (uint6)uVar102 & 0xff0000;
550: uVar135 = SUB162(auVar128,0) & 0xff | (ushort)bVar76 << 8;
551: auVar140 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT106(SUB1610(
552: CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
553: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
554: (CONCAT214(SUB162(CONCAT115(bVar40,CONCAT114(
555: bVar39,SUB1614(auVar140,0))) >> 0x70,0),
556: CONCAT113(bVar37,SUB1613(auVar140,0))) >> 0x68,0),
557: CONCAT112(pbVar3[8],SUB1612(auVar140,0))) >> 0x60,
558: 0),CONCAT111(bVar34,SUB1611(auVar140,0))) >> 0x58,
559: 0),CONCAT110(bVar32,SUB1610(auVar140,0))) >> 0x50,
560: 0),CONCAT19(bVar30,SUB169(auVar140,0))) >> 0x48,0)
561: ,CONCAT18(*pbVar3,SUB168(auVar140,0))) >> 0x40,0),
562: (uVar43 >> 0x18) << 0x38) >> 0x30,0) &
563: SUB1610((undefined  [16])0xffffffffffffffff >>
564: 0x30,0) &
565: SUB1610((undefined  [16])0xff00000000000000 >>
566: 0x30,0),(uVar5 >> 0x10) << 0x28) >> 0x20,0
567: ) & SUB1612((undefined  [16])0xffffff0000000000 >>
568: 0x20,0),
569: ((uVar58 & 0xff00) >> 8) << 0x18) >> 0x18,0),
570: (SUB163(auVar140,0) >> 8) << 0x10) >> 0x10,0),
571: uVar135);
572: uVar97 = CONCAT11(uVar95,SUB161(auVar69 >> 0x40,0));
573: uVar98 = CONCAT12(SUB161(auVar69 >> 0x48,0),uVar97);
574: uVar99 = CONCAT13(uVar94,uVar98);
575: uVar112 = SUB161(auVar85 >> 0x50,0);
576: uVar62 = CONCAT14(uVar112,uVar99);
577: uVar104 = CONCAT15(uVar81,uVar62);
578: uVar113 = SUB161(auVar85 >> 0x58,0);
579: uVar105 = CONCAT16(uVar113,uVar104);
580: uVar106 = CONCAT17(uVar83,uVar105);
581: bVar114 = SUB161(auVar85 >> 0x60,0);
582: Var108 = CONCAT19(bVar31,CONCAT18(bVar114,uVar106));
583: uVar115 = SUB161(auVar85 >> 0x68,0);
584: auVar68 = CONCAT111(bVar35,CONCAT110(uVar115,Var108));
585: uVar116 = SUB161(auVar85 >> 0x70,0);
586: uVar92 = SUB161(auVar129 >> 0x48,0);
587: uVar93 = SUB161(auVar129 >> 0x50,0);
588: uVar94 = SUB161(auVar129 >> 0x58,0);
589: uVar95 = SUB161(auVar129 >> 0x68,0);
590: uVar96 = SUB161(auVar129 >> 0x78,0);
591: auVar88 = SUB1613(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9)
592: (SUB158(CONCAT78(SUB157(
593: CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411(SUB154(
594: CONCAT312(SUB153(CONCAT213(SUB152(CONCAT114((char)
595: (uVar43 >> 0x18),SUB1614(auVar140,0)) >> 0x68,0),
596: CONCAT112(SUB161(auVar128 >> 0x60,0),
597: SUB1612(auVar140,0))) >> 0x60,0),
598: SUB1612(auVar140,0)) >> 0x58,0),
599: CONCAT110((char)(uVar5 >> 0x10),
600: SUB1610(auVar140,0))) >> 0x50,0),
601: SUB1610(auVar140,0)) >> 0x48,0),
602: CONCAT18(SUB161(auVar128 >> 0x40,0),
603: SUB168(auVar140,0))) >> 0x40,0),
604: SUB168(auVar140,0)) >> 0x38,0) & 0xff) &
605: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
606: ,0) &
607: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
608: ,0) &
609: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
610: ,0) &
611: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
612: ,0),(SUB167(auVar140,0) >> 0x18) << 0x30)
613: >> 0x30,0),SUB166(auVar140,0)) >> 0x28,0) &
614: SUB1611((undefined  [16])0xffff00ffffffffff >> 0x28,0),
615: (SUB165(auVar140,0) >> 0x10) << 0x20) >> 0x18,0) &
616: SUB1613((undefined  [16])0xffffffff00000000 >> 0x18,0) &
617: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
618: auVar140 = CONCAT142(SUB1614(CONCAT133(auVar88,(SUB163(auVar140,0) >> 8) << 0x10) >> 0x10,
619: 0),uVar135) & (undefined  [16])0xffffffffffff00ff;
620: uVar143 = (uint)CONCAT12(bVar30,(ushort)*pbVar3);
621: uVar102 = CONCAT14(bVar32,uVar143);
622: uVar144 = (ulong)CONCAT16(bVar34,(uint6)uVar102);
623: auVar145 = ZEXT1112(CONCAT110(bVar37,(unkuint10)
624: (CONCAT18(pbVar3[8],uVar144) & 0xffffffffffffffff)));
625: auVar146 = ZEXT1314(CONCAT112(bVar39,auVar145));
626: uVar75 = SUB161(auVar129 >> 0x38,0);
627: uVar73 = SUB161(auVar129 >> 0x30,0);
628: uVar72 = SUB161(auVar129 >> 0x28,0);
629: uVar71 = SUB161(auVar129 >> 0x20,0);
630: uVar70 = SUB161(auVar129 >> 8,0);
631: auVar128 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
632: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
633: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
634: (CONCAT214(SUB162(CONCAT115(bVar22,CONCAT114(
635: uVar75,SUB1614(auVar129,0))) >> 0x70,0),
636: CONCAT113(bVar21,SUB1613(auVar129,0))) >> 0x68,0),
637: CONCAT112(uVar73,SUB1612(auVar129,0))) >> 0x60,0),
638: CONCAT111(bVar20,SUB1611(auVar129,0))) >> 0x58,0),
639: CONCAT110(uVar72,SUB1610(auVar129,0))) >> 0x50,0),
640: CONCAT19(bVar19,SUB169(auVar129,0))) >> 0x48,0),
641: CONCAT18(uVar71,SUB168(auVar129,0))) >> 0x40,0),
642: bVar18),(SUB167(auVar129,0) >> 0x18) << 0x30) >>
643: 0x30,0),bVar17),
644: (SUB165(auVar129,0) >> 0x10) << 0x20) >> 0x20,0),
645: bVar16),uVar70)) << 0x10;
646: uVar142 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
647: CONCAT214(SUB162(CONCAT115(bVar22,CONCAT114(uVar75
648: ,SUB1614(auVar129,0))) >> 0x70,0),
649: CONCAT113(bVar21,SUB1613(auVar129,0))) >> 0x68,0),
650: CONCAT112(uVar73,SUB1612(auVar129,0))) >> 0x60,0),
651: CONCAT111(bVar20,SUB1611(auVar129,0))) >> 0x58,0),
652: CONCAT110(uVar72,SUB1610(auVar129,0))) >> 0x50,0),
653: CONCAT19(bVar19,SUB169(auVar129,0))) >> 0x48,0);
654: auVar69 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
655: CONCAT79(uVar142,CONCAT18(uVar71,SUB168(auVar129,0
656: ))) >> 0x40
657: ,0),bVar18)) << 0x38) >> 0x30,0),bVar17)) << 0x28)
658: >> 0x20,0),bVar16)) << 0x18 &
659: (undefined  [16])0xffffffffffff0000;
660: auVar128 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
661: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
662: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
663: bVar25,CONCAT114(SUB161(auVar128 >> 0x38,0),
664: SUB1614(auVar128,0))) >> 0x70,0),
665: CONCAT113(uVar94,SUB1613(auVar128,0))) >> 0x68,0),
666: CONCAT112(SUB161(auVar128 >> 0x30,0),
667: SUB1612(auVar128,0))) >> 0x60,0),
668: CONCAT111(bVar24,SUB1611(auVar128,0))) >> 0x58,0),
669: CONCAT110(SUB161(auVar128 >> 0x28,0),
670: SUB1610(auVar128,0))) >> 0x50,0),
671: CONCAT19(uVar93,SUB169(auVar128,0))) >> 0x48,0),
672: CONCAT18(SUB161(auVar128 >> 0x20,0),
673: SUB168(auVar128,0))) >> 0x40,0),bVar23),
674: (SUB167(auVar128,0) >> 0x18) << 0x30) >> 0x30,0),
675: uVar92),uVar70)) << 0x20 &
676: (undefined  [16])0xffffffffff000000;
677: uVar141 = SUB161(auVar129 >> 0x18,0);
678: bVar76 = SUB161(auVar129 >> 0x10,0);
679: auVar69 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
680: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
681: (SUB163(CONCAT214(SUB162(CONCAT115(bVar25,
682: CONCAT114(bVar18,SUB1614(auVar69,0))) >> 0x70,0),
683: CONCAT113(uVar94,SUB1613(auVar69,0))) >> 0x68,0),
684: CONCAT112(uVar141,SUB1612(auVar69,0))) >> 0x60,0),
685: CONCAT111(bVar24,SUB1611(auVar69,0))) >> 0x58,0),
686: CONCAT110(bVar17,SUB1610(auVar69,0))) >> 0x50,0),
687: CONCAT19(uVar93,SUB169(auVar69,0))) >> 0x48,0),
688: CONCAT18(bVar76,SUB168(auVar69,0))) >> 0x40,0),
689: bVar23)) << 0x38) >> 0x30,0),uVar92)) << 0x28 &
690: (undefined  [16])0xffffffff00000000;
691: auVar163 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
692: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
693: (SUB163(CONCAT214(SUB162(CONCAT115(pbVar2[0xd],
694: CONCAT114(
695: bVar23,SUB1614(auVar69,0))) >> 0x70,0),
696: CONCAT113(bVar20,SUB1613(auVar69,0))) >> 0x68,0),
697: CONCAT112(bVar16,SUB1612(auVar69,0))) >> 0x60,0),
698: CONCAT111(uVar95,SUB1611(auVar69,0))) >> 0x58,0),
699: CONCAT110(uVar92,SUB1610(auVar69,0))) >> 0x50,0),
700: CONCAT19(uVar72,SUB169(auVar69,0))) >> 0x48,0),
701: CONCAT18(uVar70,SUB168(auVar69,0))) >> 0x40,0),
702: bVar26)) << 0x38) >> 0x10,0) &
703: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0) &
704: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
705: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),
706: uVar71)) << 8;
707: uVar58 = CONCAT12(uVar93,CONCAT11(uVar73,bVar76));
708: uVar158 = CONCAT14(bVar17,CONCAT13(SUB161(auVar129 >> 0x70,0),uVar58));
709: auVar69 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
710: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
711: (CONCAT115(pbVar2[0xd],
712: CONCAT114(SUB161(auVar128 >> 0x38,0),
713: SUB1614(auVar128,0))) >> 0x70
714: ,0),CONCAT113(bVar20,SUB1613(auVar128,0))) >>
715: 0x68,0),CONCAT112(SUB161(auVar128 >> 0x30,0),
716: SUB1612(auVar128,0))) >> 0x60,0)
717: ,CONCAT111(uVar95,SUB1611(auVar128,0))) >> 0x58,0)
718: ,CONCAT110(SUB161(auVar128 >> 0x28,0),
719: SUB1610(auVar128,0))) >> 0x50,0),
720: CONCAT19(uVar72,SUB169(auVar128,0))) >> 0x48,0),
721: CONCAT18(SUB161(auVar128 >> 0x20,0),
722: SUB168(auVar128,0))) >> 0x40,0),bVar26))
723: << 0x38;
724: auVar128 = auVar69 & (undefined  [16])0xffff000000000000;
725: auVar69 = auVar69 & (undefined  [16])0xffff000000000000;
726: uVar60 = (uint)SUB132(auVar88 >> 0x28,0);
727: uVar160 = SUB132(auVar88 >> 0x58,0);
728: auVar110 = CONCAT212(uVar160,ZEXT1012(CONCAT28(SUB132(auVar88 >> 0x48,0),
729: (ulong)CONCAT24(SUB132(auVar88 >> 0x38,0),
730: uVar60))));
731: uVar43 = (ulong)CONCAT16(bVar24,CONCAT15(bVar21,uVar158)) & 0xff000000;
732: uVar5 = (uint6)uVar158 & 0xff0000;
733: uVar135 = SUB162(auVar129,0) & 0xff | (ushort)bVar76 << 8;
734: auVar163 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT106(SUB1610(
735: CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
736: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
737: (CONCAT214(SUB162(CONCAT115(bVar27,CONCAT114(
738: bVar26,SUB1614(auVar163,0))) >> 0x70,0),
739: CONCAT113(bVar24,SUB1613(auVar163,0))) >> 0x68,0),
740: CONCAT112(pbVar2[8],SUB1612(auVar163,0))) >> 0x60,
741: 0),CONCAT111(bVar21,SUB1611(auVar163,0))) >> 0x58,
742: 0),CONCAT110(bVar19,SUB1610(auVar163,0))) >> 0x50,
743: 0),CONCAT19(bVar17,SUB169(auVar163,0))) >> 0x48,0)
744: ,CONCAT18(*pbVar2,SUB168(auVar163,0))) >> 0x40,0),
745: (uVar43 >> 0x18) << 0x38) >> 0x30,0) &
746: SUB1610((undefined  [16])0xffffffffffffffff >>
747: 0x30,0) &
748: SUB1610((undefined  [16])0xff00000000000000 >>
749: 0x30,0),(uVar5 >> 0x10) << 0x28) >> 0x20,0
750: ) & SUB1612((undefined  [16])0xffffff0000000000 >>
751: 0x20,0),
752: ((uVar58 & 0xff00) >> 8) << 0x18) >> 0x18,0),
753: (SUB163(auVar163,0) >> 8) << 0x10) >> 0x10,0),
754: uVar135);
755: uVar57 = CONCAT11(uVar141,SUB161(auVar69 >> 0x40,0));
756: uVar58 = CONCAT12(SUB161(auVar69 >> 0x48,0),uVar57);
757: uVar59 = CONCAT13(uVar75,uVar58);
758: uVar70 = SUB161(auVar128 >> 0x50,0);
759: uVar61 = CONCAT14(uVar70,uVar59);
760: uVar63 = CONCAT15(uVar94,uVar61);
761: uVar71 = SUB161(auVar128 >> 0x58,0);
762: uVar64 = CONCAT16(uVar71,uVar63);
763: uVar65 = CONCAT17(uVar96,uVar64);
764: bVar76 = SUB161(auVar128 >> 0x60,0);
765: Var66 = CONCAT19(bVar18,CONCAT18(bVar76,uVar65));
766: uVar72 = SUB161(auVar128 >> 0x68,0);
767: auVar67 = CONCAT111(bVar22,CONCAT110(uVar72,Var66));
768: uVar73 = SUB161(auVar128 >> 0x70,0);
769: Var77 = (unkuint10)
770: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar140 >> 0x30,0),
771: SUB1612(auVar140,0)) >> 0x50,0),
772: CONCAT28(SUB162(auVar140 >> 0x20,0),
773: SUB168(auVar140,0))) >> 0x40,0),
774: SUB168(auVar140,0)) >> 0x30,0) &
775: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
776: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
777: uVar136 = (uint)CONCAT12(bVar17,(ushort)*pbVar2);
778: uVar158 = CONCAT14(bVar19,uVar136);
779: uVar137 = (ulong)CONCAT16(bVar21,(uint6)uVar158);
780: auVar138 = ZEXT1112(CONCAT110(bVar24,(unkuint10)
781: (CONCAT18(pbVar2[8],uVar137) & 0xffffffffffffffff)));
782: auVar139 = ZEXT1314(CONCAT112(bVar26,auVar138));
783: auVar167 = CONCAT412((uint)uVar160 << 3,
784: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar110 >> 0x20,0)) >> 0x20,0) << 3
785: ,CONCAT44(SUB164(ZEXT1416(auVar110) >> 0x20,0) << 3,
786: uVar60 << 3))) & _DAT_00189860;
787: auVar86 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9
788: )(SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510
789: (SUB155(CONCAT411(SUB154(CONCAT312(SUB153(
790: CONCAT213(SUB152(CONCAT114((char)(uVar43 >> 0x18),
791: SUB1614(auVar163,0)) >>
792: 0x68,0),
793: CONCAT112(SUB161(auVar129 >> 0x60,0),
794: SUB1612(auVar163,0))) >> 0x60,
795: 0),SUB1612(auVar163,0)) >> 0x58,0),
796: CONCAT110((char)(uVar5 >> 0x10),
797: SUB1610(auVar163,0))) >> 0x50,0),
798: SUB1610(auVar163,0)) >> 0x48,0),
799: CONCAT18(SUB161(auVar129 >> 0x40,0),
800: SUB168(auVar163,0))) >> 0x40,0),
801: SUB168(auVar163,0)) >> 0x38,0) & 0xff) &
802: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
803: ,0) &
804: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
805: ,0) &
806: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
807: ,0) &
808: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
809: ,0),(SUB167(auVar163,0) >> 0x18) << 0x30)
810: >> 0x30,0),SUB166(auVar163,0)) >> 0x28,0) &
811: SUB1611((undefined  [16])0xffff00ffffffffff >>
812: 0x28,0),
813: (SUB165(auVar163,0) >> 0x10) << 0x20) >> 0x20,0),
814: SUB164(auVar163,0)) >> 0x18,0) &
815: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
816: auVar69 = CONCAT142(SUB1614(CONCAT133(auVar86,(SUB163(auVar163,0) >> 8) << 0x10) >> 0x10,0
817: ),uVar135) & (undefined  [16])0xffffffffffff00ff;
818: uVar119 = (uint)CONCAT12(bVar6,(ushort)bVar132);
819: uVar120 = CONCAT14(uVar133,uVar119);
820: uVar124 = (ulong)(uVar157 & 0xff000000000000 | (uint7)uVar120);
821: auVar126 = ZEXT1112(CONCAT110(bVar12,(unkuint10)CONCAT18(uVar134,uVar124)));
822: auVar127 = ZEXT1314(CONCAT112(SUB161(auVar84 >> 0x78,0),auVar126));
823: auVar87 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9
824: )SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(
825: SUB155(CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213
826: (SUB152(CONCAT114(uVar82,CONCAT113(bVar12,
827: CONCAT112(uVar134,auVar109))) >> 0x68,0),
828: CONCAT112(uVar131,auVar109)) >> 0x60,0),auVar109)
829: >> 0x58,0),CONCAT110(uVar80,Var125)) >> 0x50,0),
830: Var125) >> 0x48,0),CONCAT18(uVar130,uVar123)) >>
831: 0x40,0),uVar123) >> 0x38,0) &
832: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
833: ,0) &
834: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
835: ,0) &
836: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
837: ,0) &
838: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
839: ,0),(uVar122 >> 0x18) << 0x30) >> 0x30,0),
840: uVar121) >> 0x28,0) &
841: SUB1611((undefined  [16])0xffff00ffffffffff >>
842: 0x28,0),(uVar103 >> 0x10) << 0x20) >> 0x20
843: ,0),uVar118) >> 0x18,0) &
844: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
845: auVar84 = CONCAT142(CONCAT131(auVar87,uVar156),uVar117) &
846: (undefined  [16])0xffffffffffff00ff;
847: uVar100 = (uint)CONCAT12(bVar31,(ushort)bVar114);
848: uVar103 = CONCAT14(uVar115,uVar100);
849: uVar107 = (ulong)(uVar148 & 0xff000000000000 | (uint7)uVar103);
850: auVar109 = ZEXT1112(CONCAT110(bVar38,(unkuint10)CONCAT18(uVar116,uVar107)));
851: auVar110 = ZEXT1314(CONCAT112(SUB161(auVar85 >> 0x78,0),auVar109));
852: auVar88 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9
853: )SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(
854: SUB155(CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213
855: (SUB152(CONCAT114(uVar83,CONCAT113(bVar38,
856: CONCAT112(uVar116,auVar68))) >> 0x68,0),
857: CONCAT112(uVar113,auVar68)) >> 0x60,0),auVar68) >>
858: 0x58,0),CONCAT110(uVar81,Var108)) >> 0x50,0),
859: Var108) >> 0x48,0),CONCAT18(uVar112,uVar106)) >>
860: 0x40,0),uVar106) >> 0x38,0) &
861: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
862: ,0) &
863: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
864: ,0) &
865: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
866: ,0) &
867: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
868: ,0),(uVar105 >> 0x18) << 0x30) >> 0x30,0),
869: uVar104) >> 0x28,0) &
870: SUB1611((undefined  [16])0xffff00ffffffffff >>
871: 0x28,0),(uVar62 >> 0x10) << 0x20) >> 0x20,
872: 0),uVar99) >> 0x18,0) &
873: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
874: auVar85 = CONCAT142(SUB1614(CONCAT133(auVar88,(uVar98 >> 8) << 0x10) >> 0x10,0),uVar97) &
875: (undefined  [16])0xffffffffffff00ff;
876: uVar60 = (uint)CONCAT12(bVar18,(ushort)bVar76);
877: uVar62 = CONCAT14(uVar72,uVar60);
878: uVar43 = (ulong)(uVar142 & 0xff000000000000 | (uint7)uVar62);
879: auVar68 = ZEXT1112(CONCAT110(bVar25,(unkuint10)CONCAT18(uVar73,uVar43)));
880: auVar129 = ZEXT1516(CONCAT114(bVar28,ZEXT1314(CONCAT112(SUB161(auVar128 >> 0x78,0),auVar68
881: ))));
882: auVar89 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9
883: )SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(
884: SUB155(CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213
885: (SUB152(CONCAT114(uVar96,CONCAT113(bVar25,
886: CONCAT112(uVar73,auVar67))) >> 0x68,0),
887: CONCAT112(uVar71,auVar67)) >> 0x60,0),auVar67) >>
888: 0x58,0),CONCAT110(uVar94,Var66)) >> 0x50,0),Var66)
889: >> 0x48,0),CONCAT18(uVar70,uVar65)) >> 0x40,0),
890: uVar65) >> 0x38,0) &
891: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
892: ,0) &
893: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
894: ,0) &
895: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
896: ,0) &
897: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
898: ,0),(uVar64 >> 0x18) << 0x30) >> 0x30,0),
899: uVar63) >> 0x28,0) &
900: SUB1611((undefined  [16])0xffff00ffffffffff >>
901: 0x28,0),(uVar61 >> 0x10) << 0x20) >> 0x20,
902: 0),uVar59) >> 0x18,0) &
903: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
904: auVar128 = CONCAT142(SUB1614(CONCAT133(auVar89,(uVar58 >> 8) << 0x10) >> 0x10,0),uVar57) &
905: (undefined  [16])0xffffffffffff00ff;
906: Var74 = (unkuint10)
907: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar154 >> 0x30,0),
908: SUB1612(auVar147,0)) >> 0x50,0),
909: CONCAT28(SUB162(auVar111 >> 0x20,0),
910: SUB168(auVar147,0))) >> 0x40,0),
911: SUB168(auVar147,0)) >> 0x30,0) &
912: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
913: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
914: Var90 = (unkuint10)
915: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar85 >> 0x30,0),
916: SUB1612(auVar85,0)) >> 0x50,0),
917: CONCAT28(SUB162(auVar85 >> 0x20,0),
918: SUB168(auVar85,0))) >> 0x40,0),
919: SUB168(auVar85,0)) >> 0x30,0) &
920: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
921: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
922: uVar101 = (uint)SUB162(auVar154 >> 0x40,0);
923: uVar135 = SUB162(auVar154 >> 0x70,0);
924: auVar159 = CONCAT212(uVar135,ZEXT1012(CONCAT28(SUB162(auVar154 >> 0x60,0),
925: (ulong)CONCAT24(SUB162(auVar154 >> 0x50,0),
926: uVar101))));
927: auVar169 = CONCAT412((uint)uVar135 << 8,
928: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar159 >> 0x20,0)) >> 0x20,0) << 8
929: ,CONCAT44(SUB164(ZEXT1416(auVar159) >> 0x20,0) << 8,
930: uVar101 << 8))) & _DAT_00189850;
931: uVar166 = SUB132(auVar86 >> 0x58,0);
932: auVar165 = CONCAT212(uVar166,ZEXT1012(CONCAT28(SUB132(auVar86 >> 0x48,0),
933: (ulong)SUB132(auVar86 >> 0x38,0) << 0x20)))
934: ;
935: uVar150 = (uint)SUB132(auVar88 >> 0x28,0);
936: uVar160 = SUB132(auVar88 >> 0x58,0);
937: auVar159 = CONCAT212(uVar160,ZEXT1012(CONCAT28(SUB132(auVar88 >> 0x48,0),
938: (ulong)CONCAT24(SUB132(auVar88 >> 0x38,0),
939: uVar150))));
940: Var78 = (unkuint10)
941: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar69 >> 0x30,0),
942: SUB1612(auVar69,0)) >> 0x50,0),
943: CONCAT28(SUB162(auVar69 >> 0x20,0),
944: SUB168(auVar69,0))) >> 0x40,0),
945: SUB168(auVar69,0)) >> 0x30,0) &
946: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
947: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
948: uVar101 = (uint)SUB142(auVar110 >> 0x40,0);
949: auVar88 = CONCAT112(bVar41,ZEXT1012(CONCAT28((short)((unkuint10)
950: SUB159(CONCAT114(bVar41,auVar110) >>
951: 0x30,0) >> 0x30),
952: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
953: CONCAT114(bVar41,auVar110) >> 0x10,0)) >> 0x40,0),
954: uVar101))));
955: Var168 = (unkuint10)
956: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar110 >> 0x30,0),
957: auVar109) >> 0x50,0),
958: CONCAT28(SUB122(auVar109 >> 0x20,0),uVar107)) >>
959: 0x40,0),uVar107) >> 0x30,0) &
960: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
961: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
962: Var79 = (unkuint10)
963: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar84 >> 0x30,0),
964: SUB1612(auVar84,0)) >> 0x50,0),
965: CONCAT28(SUB162(auVar84 >> 0x20,0),
966: SUB168(auVar84,0))) >> 0x40,0),
967: SUB168(auVar84,0)) >> 0x30,0) &
968: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
969: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
970: uVar161 = (uint)SUB132(auVar87 >> 0x28,0);
971: uVar164 = SUB132(auVar87 >> 0x58,0);
972: auVar162 = CONCAT212(uVar164,ZEXT1012(CONCAT28(SUB132(auVar87 >> 0x48,0),
973: (ulong)CONCAT24(SUB132(auVar87 >> 0x38,0),
974: uVar161))));
975: auVar111 = CONCAT412((uint)bVar41 << 3,
976: CONCAT48(SUB124(ZEXT912(SUB139(auVar88 >> 0x20,0)) >> 0x20,0) << 3,
977: CONCAT44(SUB164(ZEXT1316(auVar88) >> 0x20,0) << 3,
978: uVar101 << 3))) & _DAT_00189860;
979: Var91 = (unkuint10)
980: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar128 >> 0x30,0),
981: SUB1612(auVar128,0)) >> 0x50,0),
982: CONCAT28(SUB162(auVar128 >> 0x20,0),
983: SUB168(auVar128,0))) >> 0x40,0),
984: SUB168(auVar128,0)) >> 0x30,0) &
985: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
986: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
987: uVar135 = SUB132(auVar89 >> 0x58,0);
988: auVar110 = CONCAT212(uVar135,ZEXT1012(CONCAT28(SUB132(auVar89 >> 0x48,0),
989: (ulong)SUB132(auVar89 >> 0x38,0) << 0x20)))
990: ;
991: uVar101 = (uint)SUB142(auVar146 >> 0x40,0);
992: auVar88 = CONCAT112(bVar40,ZEXT1012(CONCAT28((short)((unkuint10)
993: SUB159(CONCAT114(bVar40,auVar146) >>
994: 0x30,0) >> 0x30),
995: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
996: CONCAT114(bVar40,auVar146) >> 0x10,0)) >> 0x40,0),
997: uVar101))));
998: auVar163 = CONCAT412((uint)uVar164 << 8,
999: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar162 >> 0x20,0)) >> 0x20,0) << 8
1000: ,CONCAT44(SUB164(ZEXT1416(auVar162) >> 0x20,0) << 8,
1001: uVar161 << 8))) & _DAT_00189850 |
1002: CONCAT412((uint)uVar160 << 3,
1003: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar159 >> 0x20,0)) >> 0x20,0) << 3
1004: ,CONCAT44(SUB164(ZEXT1416(auVar159) >> 0x20,0) << 3,
1005: uVar150 << 3))) & _DAT_00189860 |
1006: ZEXT1416(CONCAT212(uVar135 >> 3,
1007: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar110 >> 0x20,0)) >>
1008: 0x20,0) >> 3,
1009: CONCAT44(SUB164(ZEXT1416(auVar110) >> 0x20,0) >> 3,
1010: (uint)(ushort)(SUB132(auVar89 >> 0x28,0)
1011: >> 3)))));
1012: puVar52 = (uint *)(puVar46 + lVar44);
1013: *puVar52 = (SUB164(auVar147,0) & 0xf8) << 8 | (SUB164(auVar140,0) & 0xfc) << 3 |
1014: (SUB164(auVar69,0) & 0xffff) >> 3 |
1015: ((SUB164(auVar84,0) & 0xf8) << 8 | (SUB164(auVar85,0) & 0xfc) << 3 |
1016: (SUB164(auVar128,0) & 0xffff) >> 3) << 0x10;
1017: puVar52[1] = (SUB164(CONCAT106(Var74,(SUB166(auVar147,0) >> 0x10) << 0x20) >> 0x20,0) &
1018: 0xf8) << 8 |
1019: (SUB164(CONCAT106(Var77,(SUB166(auVar140,0) >> 0x10) << 0x20) >> 0x20,0) &
1020: 0xfc) << 3 |
1021: SUB164(CONCAT106(Var78,(SUB166(auVar69,0) >> 0x10) << 0x20) >> 0x20,0) >> 3 |
1022: ((SUB164(CONCAT106(Var79,(SUB166(auVar84,0) >> 0x10) << 0x20) >> 0x20,0) &
1023: 0xf8) << 8 |
1024: (SUB164(CONCAT106(Var90,(SUB166(auVar85,0) >> 0x10) << 0x20) >> 0x20,0) &
1025: 0xfc) << 3 |
1026: SUB164(CONCAT106(Var91,(SUB166(auVar128,0) >> 0x10) << 0x20) >> 0x20,0) >> 3)
1027: << 0x10;
1028: puVar52[2] = ((uint)(Var74 >> 0x10) & 0xf8) << 8 | ((uint)(Var77 >> 0x10) & 0xfc) << 3 |
1029: (uint)(Var78 >> 0x10) >> 3 |
1030: (((uint)(Var79 >> 0x10) & 0xf8) << 8 | ((uint)(Var90 >> 0x10) & 0xfc) << 3 |
1031: (uint)(Var91 >> 0x10) >> 3) << 0x10;
1032: puVar52[3] = ((uint)(Var74 >> 0x30) & 0xf8) << 8 | ((uint)(Var77 >> 0x30) & 0xfc) << 3 |
1033: (uint)(Var78 >> 0x33) |
1034: (((uint)(Var79 >> 0x30) & 0xf8) << 8 | ((uint)(Var90 >> 0x30) & 0xfc) << 3 |
1035: (uint)(Var91 >> 0x33)) << 0x10;
1036: Var77 = (unkuint10)
1037: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar146 >> 0x30,0),
1038: auVar145) >> 0x50,0),
1039: CONCAT28(SUB122(auVar145 >> 0x20,0),uVar144)) >>
1040: 0x40,0),uVar144) >> 0x30,0) &
1041: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
1042: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
1043: Var74 = (unkuint10)
1044: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar153 >> 0x30,0),
1045: auVar152) >> 0x50,0),
1046: CONCAT28(SUB122(auVar152 >> 0x20,0),uVar151)) >>
1047: 0x40,0),uVar151) >> 0x30,0) &
1048: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
1049: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
1050: uVar150 = (uint)SUB142(auVar153 >> 0x40,0);
1051: auVar87 = CONCAT112(bVar14,ZEXT1012(CONCAT28(SUB162(ZEXT1516(CONCAT114(bVar14,auVar153))
1052: >> 0x60,0),
1053: (ulong)CONCAT24(SUB162(ZEXT1516(CONCAT114(
1054: bVar14,auVar153)) >> 0x50,0),uVar150))));
1055: auVar147 = CONCAT412((uint)bVar40 << 3,
1056: CONCAT48(SUB124(ZEXT912(SUB139(auVar88 >> 0x20,0)) >> 0x20,0) << 3,
1057: CONCAT44(SUB164(ZEXT1316(auVar88) >> 0x20,0) << 3,
1058: uVar101 << 3))) & _DAT_00189860;
1059: auVar154 = CONCAT412((uint)bVar14 << 8,
1060: CONCAT48(SUB124(ZEXT912(SUB139(auVar87 >> 0x20,0)) >> 0x20,0) << 8,
1061: CONCAT44(SUB164(ZEXT1316(auVar87) >> 0x20,0) << 8,
1062: uVar150 << 8))) & _DAT_00189850;
1063: auVar88 = CONCAT112(bVar27,ZEXT1012(CONCAT28((short)((unkuint10)
1064: SUB159(CONCAT114(bVar27,auVar139) >>
1065: 0x30,0) >> 0x30),
1066: (ulong)SUB142(ZEXT1314(SUB1513(CONCAT114(
1067: bVar27,auVar139) >> 0x10,0)) >> 0x40,0) << 0x20)))
1068: ;
1069: Var78 = (unkuint10)
1070: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar139 >> 0x30,0),
1071: auVar138) >> 0x50,0),
1072: CONCAT28(SUB122(auVar138 >> 0x20,0),uVar137)) >>
1073: 0x40,0),uVar137) >> 0x30,0) &
1074: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
1075: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
1076: *(undefined (*) [16])(puVar46 + lVar44 + 8) =
1077: auVar169 | auVar167 |
1078: ZEXT1416(CONCAT212(uVar166 >> 3,
1079: CONCAT48(SUB124(ZEXT1012(SUB1410(auVar165 >> 0x20,0)) >> 0x20,0)
1080: >> 3,CONCAT44(SUB164(ZEXT1416(auVar165) >> 0x20,0) >> 3,
1081: (uint)(ushort)(SUB132(auVar86 >> 0x28,0) >>
1082: 3))))) |
1083: CONCAT412(SUB164(auVar163 >> 0x60,0) << 0x10,
1084: CONCAT48(SUB164(auVar163 >> 0x40,0) << 0x10,
1085: CONCAT44(SUB164(auVar163 >> 0x20,0) << 0x10,
1086: SUB164(auVar163,0) << 0x10)));
1087: uVar101 = (uint)SUB142(auVar127 >> 0x40,0);
1088: auVar87 = CONCAT112(bVar15,ZEXT1012(CONCAT28((short)((unkuint10)
1089: SUB159(CONCAT114(bVar15,auVar127) >>
1090: 0x30,0) >> 0x30),
1091: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
1092: CONCAT114(bVar15,auVar127) >> 0x10,0)) >> 0x40,0),
1093: uVar101))));
1094: Var79 = (unkuint10)
1095: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar127 >> 0x30,0),
1096: auVar126) >> 0x50,0),
1097: CONCAT28(SUB122(auVar126 >> 0x20,0),uVar124)) >>
1098: 0x40,0),uVar124) >> 0x30,0) &
1099: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
1100: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
1101: auVar128 = CONCAT412((uint)bVar15 << 8,
1102: CONCAT48(SUB124(ZEXT912(SUB139(auVar87 >> 0x20,0)) >> 0x20,0) << 8,
1103: CONCAT44(SUB164(ZEXT1316(auVar87) >> 0x20,0) << 8,
1104: uVar101 << 8))) & _DAT_00189850;
1105: Var90 = (unkuint10)
1106: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar129 >> 0x30,0),
1107: auVar68) >> 0x50,0),
1108: CONCAT28(SUB162(auVar129 >> 0x20,0),uVar43)) >>
1109: 0x40,0),uVar43) >> 0x30,0) &
1110: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
1111: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
1112: auVar87 = CONCAT112(bVar28,ZEXT1012(CONCAT28(SUB162(auVar129 >> 0x60,0),
1113: (ulong)SUB162(auVar129 >> 0x50,0) << 0x20)));
1114: puVar52 = (uint *)(puVar46 + lVar44 + 0x10);
1115: *puVar52 = (uVar149 & 0xf8) << 8 | (uVar143 & 0xfc) << 3 | (uVar136 & 0xffff) >> 3 |
1116: ((uVar119 & 0xf8) << 8 | (uVar100 & 0xfc) << 3 | (uVar60 & 0xffff) >> 3) <<
1117: 0x10;
1118: puVar52[1] = (SUB164(CONCAT106(Var74,(uint6)(uVar42 >> 0x10) << 0x20) >> 0x20,0) & 0xf8)
1119: << 8 | (SUB164(CONCAT106(Var77,(uint6)(uVar102 >> 0x10) << 0x20) >> 0x20,0) &
1120: 0xfc) << 3 |
1121: SUB164(CONCAT106(Var78,(uint6)(uVar158 >> 0x10) << 0x20) >> 0x20,0) >> 3 |
1122: ((SUB164(CONCAT106(Var79,(uint6)(uVar120 >> 0x10) << 0x20) >> 0x20,0) & 0xf8)
1123: << 8 | (SUB164(CONCAT106(Var168,(uint6)(uVar103 >> 0x10) << 0x20) >> 0x20,0)
1124: & 0xfc) << 3 |
1125: SUB164(CONCAT106(Var90,(uint6)(uVar62 >> 0x10) << 0x20) >> 0x20,0) >> 3) <<
1126: 0x10;
1127: puVar52[2] = ((uint)(Var74 >> 0x10) & 0xf8) << 8 | ((uint)(Var77 >> 0x10) & 0xfc) << 3 |
1128: (uint)(Var78 >> 0x10) >> 3 |
1129: (((uint)(Var79 >> 0x10) & 0xf8) << 8 | ((uint)(Var168 >> 0x10) & 0xfc) << 3 |
1130: (uint)(Var90 >> 0x10) >> 3) << 0x10;
1131: puVar52[3] = ((uint)(Var74 >> 0x30) & 0xf8) << 8 | ((uint)(Var77 >> 0x30) & 0xfc) << 3 |
1132: (uint)(Var78 >> 0x33) |
1133: (((uint)(Var79 >> 0x30) & 0xf8) << 8 | ((uint)(Var168 >> 0x30) & 0xfc) << 3 |
1134: (uint)(Var90 >> 0x33)) << 0x10;
1135: auVar129 = auVar128 | auVar111 |
1136: ZEXT1316(CONCAT112(bVar28 >> 3,
1137: CONCAT48(SUB124(ZEXT912(SUB139(auVar87 >> 0x20,0)) >> 0x20,0
1138: ) >> 3,
1139: CONCAT44(SUB164(ZEXT1316(auVar87) >> 0x20,0) >> 3,
1140: (uint)(ushort)(SUB162(auVar129 >> 0x40,0)
1141: >> 3)))));
1142: *(undefined (*) [16])(puVar46 + lVar44 + 0x18) =
1143: auVar154 | auVar147 |
1144: ZEXT1316(CONCAT112(bVar27 >> 3,
1145: CONCAT48(SUB124(ZEXT912(SUB139(auVar88 >> 0x20,0)) >> 0x20,0) >> 3
1146: ,CONCAT44(SUB164(ZEXT1316(auVar88) >> 0x20,0) >> 3,
1147: (uint)(ushort)(SUB142(auVar139 >> 0x40,0) >> 3)
1148: )))) |
1149: CONCAT412(SUB164(auVar129 >> 0x60,0) << 0x10,
1150: CONCAT48(SUB164(auVar129 >> 0x40,0) << 0x10,
1151: CONCAT44(SUB164(auVar129 >> 0x20,0) << 0x10,
1152: SUB164(auVar129,0) << 0x10)));
1153: lVar44 = lVar44 + 0x20;
1154: } while (uVar45 < uVar56 >> 5);
1155: uVar43 = (ulong)uVar51;
1156: puVar48 = puVar53 + uVar43;
1157: puVar49 = puVar54 + uVar43;
1158: puVar50 = puVar55 + uVar43;
1159: puVar52 = (uint *)(puVar46 + uVar43 * 2);
1160: if (uVar47 != uVar51) {
1161: do {
1162: uVar51 = uVar51 + 1;
1163: *puVar52 = (*(byte *)puVar49 & 0xfc) << 3 | (*(byte *)puVar50 & 0xf8) << 8 |
1164: (uint)(*(byte *)puVar48 >> 3) |
1165: ((*(byte *)((long)puVar49 + 1) & 0xfc) << 3 |
1166: (*(byte *)((long)puVar50 + 1) & 0xf8) << 8 |
1167: (uint)(*(byte *)((long)puVar48 + 1) >> 3)) << 0x10;
1168: puVar48 = puVar48 + 1;
1169: puVar49 = puVar49 + 1;
1170: puVar50 = puVar50 + 1;
1171: puVar52 = puVar52 + 1;
1172: } while (uVar51 < uVar47);
1173: }
1174: }
1175: lVar44 = (ulong)(uVar47 - 1) + 1;
1176: puVar46 = puVar46 + lVar44 * 2;
1177: puVar55 = puVar55 + lVar44;
1178: puVar54 = puVar54 + lVar44;
1179: puVar53 = puVar53 + lVar44;
1180: }
1181: param_4 = ppuVar4;
1182: if ((uVar56 & 1) != 0) {
1183: *puVar46 = (ushort)((*(byte *)puVar55 & 0xf8) << 8) | (ushort)((*(byte *)puVar54 & 0xfc) << 3)
1184: | (ushort)(*(byte *)puVar53 >> 3);
1185: }
1186: }
1187: /* WARNING: Read-only address (ram,0x00189850) is written */
1188: /* WARNING: Read-only address (ram,0x00189860) is written */
1189: return;
1190: }
1191: 
