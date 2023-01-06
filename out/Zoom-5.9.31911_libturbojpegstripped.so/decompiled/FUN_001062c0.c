1: 
2: void FUN_001062c0(long param_1,long *param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: undefined *puVar1;
6: undefined *puVar2;
7: undefined *puVar3;
8: undefined *puVar4;
9: undefined *puVar5;
10: int iVar6;
11: uint uVar7;
12: long lVar8;
13: undefined *puVar9;
14: undefined *puVar10;
15: undefined *puVar11;
16: undefined *puVar12;
17: uint6 uVar13;
18: uint uVar14;
19: undefined uVar15;
20: undefined uVar16;
21: undefined uVar17;
22: undefined uVar18;
23: undefined uVar19;
24: undefined uVar20;
25: undefined uVar21;
26: undefined uVar22;
27: uint3 uVar23;
28: ulong uVar24;
29: long lVar25;
30: long lVar26;
31: ulong uVar27;
32: undefined *puVar28;
33: ulong uVar29;
34: long lVar30;
35: uint uVar31;
36: uint uVar32;
37: ulong uVar33;
38: long *plVar34;
39: undefined uVar36;
40: undefined uVar37;
41: undefined auVar35 [16];
42: undefined uVar39;
43: undefined uVar40;
44: uint7 uVar41;
45: uint6 uVar42;
46: undefined auVar38 [16];
47: undefined uVar50;
48: byte bVar51;
49: byte bVar52;
50: undefined auVar43 [16];
51: undefined auVar44 [16];
52: byte bVar57;
53: undefined uVar58;
54: undefined uVar59;
55: undefined uVar60;
56: byte bVar61;
57: undefined uVar62;
58: undefined auVar53 [16];
59: undefined auVar55 [16];
60: undefined auVar56 [16];
61: undefined uVar64;
62: undefined uVar66;
63: undefined uVar67;
64: undefined uVar68;
65: undefined uVar69;
66: undefined auVar63 [16];
67: undefined uVar70;
68: undefined uVar71;
69: undefined uVar72;
70: undefined uVar73;
71: undefined uVar74;
72: undefined uVar75;
73: byte bVar76;
74: undefined uVar77;
75: undefined uVar78;
76: undefined uVar79;
77: undefined uVar80;
78: undefined uVar81;
79: undefined uVar82;
80: undefined uVar83;
81: undefined uVar84;
82: uint3 uVar85;
83: uint3 uVar86;
84: undefined uVar88;
85: undefined uVar89;
86: undefined uVar45;
87: undefined uVar46;
88: undefined uVar47;
89: undefined uVar48;
90: undefined uVar49;
91: undefined auVar54 [16];
92: undefined uVar65;
93: uint5 uVar87;
94: 
95: uVar33 = (ulong)param_4;
96: iVar6 = *(int *)(param_1 + 0x4c);
97: uVar7 = *(uint *)(param_1 + 0x30);
98: if (iVar6 == 3) {
99: while (param_5 = param_5 + -1, -1 < param_5) {
100: plVar34 = param_2 + 1;
101: uVar27 = (ulong)((int)uVar33 + 1);
102: lVar30 = *(long *)(*param_3 + uVar33 * 8);
103: lVar8 = *(long *)(param_3[1] + uVar33 * 8);
104: lVar25 = *(long *)(param_3[2] + uVar33 * 8);
105: lVar26 = 0;
106: puVar28 = (undefined *)*param_2;
107: uVar33 = uVar27;
108: param_2 = plVar34;
109: if (uVar7 != 0) {
110: do {
111: *(undefined *)(lVar30 + lVar26) = *puVar28;
112: *(undefined *)(lVar8 + lVar26) = puVar28[1];
113: *(undefined *)(lVar25 + lVar26) = puVar28[2];
114: lVar26 = lVar26 + 1;
115: puVar28 = puVar28 + 3;
116: } while ((uint)lVar26 < uVar7);
117: }
118: }
119: }
120: else {
121: if (iVar6 == 4) {
122: uVar27 = (ulong)uVar7;
123: uVar32 = uVar7 & 0xfffffff0;
124: LAB_001063dc:
125: param_5 = param_5 + -1;
126: if (-1 < param_5) {
127: plVar34 = param_2 + 1;
128: uVar29 = (ulong)((int)uVar33 + 1);
129: puVar28 = (undefined *)*param_2;
130: puVar9 = *(undefined **)(*param_3 + uVar33 * 8);
131: puVar10 = *(undefined **)(param_3[1] + uVar33 * 8);
132: puVar11 = *(undefined **)(param_3[2] + uVar33 * 8);
133: puVar12 = *(undefined **)(param_3[3] + uVar33 * 8);
134: uVar33 = uVar29;
135: param_2 = plVar34;
136: if (uVar7 != 0) {
137: puVar1 = puVar11 + 0x10;
138: puVar2 = puVar12 + 0x10;
139: puVar3 = puVar10 + 0x10;
140: puVar5 = puVar28 + uVar27 * 4;
141: puVar4 = puVar9 + 0x10;
142: if (((((((((puVar9 + uVar27 <= puVar28 || puVar5 <= puVar9) &&
143: (((puVar11 + uVar27 <= puVar28 || puVar5 <= puVar11) &&
144: (puVar10 + uVar27 <= puVar28 || puVar5 <= puVar10)) && 0xf < uVar7)) &&
145: (puVar12 + uVar27 <= puVar28 || puVar5 <= puVar12)) &&
146: (puVar3 <= puVar9 || puVar4 <= puVar10)) &&
147: (puVar1 <= puVar9 || puVar4 <= puVar11)) && (puVar2 <= puVar9 || puVar4 <= puVar12)
148: ) && (puVar1 <= puVar10 || puVar3 <= puVar11)) &&
149: (puVar2 <= puVar10 || puVar3 <= puVar12)) && (puVar2 <= puVar11 || puVar1 <= puVar12)
150: ) {
151: if (uVar32 == 0) {
152: uVar31 = 0;
153: }
154: else {
155: lVar30 = 0;
156: uVar31 = 0;
157: do {
158: auVar55 = *(undefined (*) [16])(puVar28 + lVar30 * 4);
159: uVar31 = uVar31 + 1;
160: puVar1 = puVar28 + lVar30 * 4 + 0x10;
161: uVar70 = *puVar1;
162: uVar71 = puVar1[1];
163: uVar64 = puVar1[2];
164: uVar72 = puVar1[3];
165: uVar65 = puVar1[4];
166: uVar36 = puVar1[5];
167: uVar15 = puVar1[6];
168: uVar37 = puVar1[9];
169: uVar73 = puVar1[10];
170: uVar80 = puVar1[0xc];
171: uVar16 = puVar1[0xf];
172: uVar58 = SUB161(auVar55 >> 0x38,0);
173: uVar47 = SUB161(auVar55 >> 0x30,0);
174: uVar46 = SUB161(auVar55 >> 0x28,0);
175: bVar57 = SUB161(auVar55 >> 0x20,0);
176: uVar45 = SUB161(auVar55 >> 8,0);
177: auVar38 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
178: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
179: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
180: (CONCAT214(SUB162(CONCAT115(puVar1[7],
181: CONCAT114(uVar58,
182: SUB1614(auVar55,0))) >> 0x70,0),
183: CONCAT113(uVar15,SUB1613(auVar55,0))) >> 0x68,0),
184: CONCAT112(uVar47,SUB1612(auVar55,0))) >> 0x60,0),
185: CONCAT111(uVar36,SUB1611(auVar55,0))) >> 0x58,0),
186: CONCAT110(uVar46,SUB1610(auVar55,0))) >> 0x50,0),
187: CONCAT19(uVar65,SUB169(auVar55,0))) >> 0x48,0),
188: CONCAT18(bVar57,SUB168(auVar55,0))) >> 0x40,0),
189: uVar72),(SUB167(auVar55,0) >> 0x18) << 0x30) >>
190: 0x30,0),uVar64),
191: (SUB165(auVar55,0) >> 0x10) << 0x20) >> 0x20,0),
192: uVar71),uVar45)) << 0x10;
193: uVar66 = SUB161(auVar55 >> 0x40,0);
194: uVar48 = SUB161(auVar55 >> 0x48,0);
195: uVar49 = SUB161(auVar55 >> 0x50,0);
196: uVar67 = SUB161(auVar55 >> 0x58,0);
197: uVar68 = SUB161(auVar55 >> 0x60,0);
198: uVar59 = SUB161(auVar55 >> 0x68,0);
199: uVar69 = SUB161(auVar55 >> 0x78,0);
200: auVar56 = *(undefined (*) [16])(puVar28 + lVar30 * 4 + 0x20);
201: uVar41 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
202: CONCAT214(SUB162(CONCAT115(puVar1[7],
203: CONCAT114(uVar58,
204: SUB1614(auVar55,0))) >> 0x70,0),
205: CONCAT113(uVar15,SUB1613(auVar55,0))) >> 0x68,0),
206: CONCAT112(uVar47,SUB1612(auVar55,0))) >> 0x60,0),
207: CONCAT111(uVar36,SUB1611(auVar55,0))) >> 0x58,0),
208: CONCAT110(uVar46,SUB1610(auVar55,0))) >> 0x50,0),
209: CONCAT19(uVar65,SUB169(auVar55,0))) >> 0x48,0);
210: auVar35 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(
211: SUB168(CONCAT79(uVar41,CONCAT18(bVar57,SUB168(
212: auVar55,0))) >> 0x40,0),uVar72)) << 0x38) >> 0x30,
213: 0),uVar64)) << 0x28) >> 0x20,0),uVar71)) << 0x18 &
214: (undefined  [16])0xffffffffffff0000;
215: puVar2 = puVar28 + lVar30 * 4 + 0x30;
216: uVar81 = puVar2[2];
217: uVar82 = puVar2[3];
218: uVar83 = puVar2[4];
219: uVar50 = puVar2[5];
220: uVar17 = puVar2[6];
221: uVar18 = puVar2[7];
222: uVar84 = puVar2[8];
223: uVar19 = puVar2[10];
224: uVar20 = puVar2[0xb];
225: uVar21 = puVar2[0xe];
226: uVar22 = puVar2[0xf];
227: auVar38 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(
228: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
229: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
230: CONCAT115(puVar1[0xb],
231: CONCAT114(SUB161(auVar38 >> 0x38,0),
232: SUB1614(auVar38,0))) >> 0x70,0
233: ),CONCAT113(uVar67,SUB1613(auVar38,0))) >> 0x68,0)
234: ,CONCAT112(SUB161(auVar38 >> 0x30,0),
235: SUB1612(auVar38,0))) >> 0x60,0),
236: CONCAT111(uVar73,SUB1611(auVar38,0))) >> 0x58,0),
237: CONCAT110(SUB161(auVar38 >> 0x28,0),
238: SUB1610(auVar38,0))) >> 0x50,0),
239: CONCAT19(uVar49,SUB169(auVar38,0))) >> 0x48,0),
240: CONCAT18(SUB161(auVar38 >> 0x20,0),
241: SUB168(auVar38,0))) >> 0x40,0),uVar37),
242: (SUB167(auVar38,0) >> 0x18) << 0x30) >> 0x30,0),
243: uVar48),uVar45)) << 0x20 &
244: (undefined  [16])0xffffffffff000000;
245: uVar40 = SUB161(auVar55 >> 0x18,0);
246: uVar42 = SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
247: CONCAT115(puVar1[0xb],
248: CONCAT114(uVar72,SUB1614(auVar35,0))) >>
249: 0x70,0),CONCAT113(uVar67,SUB1613(auVar35,0))) >>
250: 0x68,0),CONCAT112(uVar40,SUB1612(auVar35,0))) >>
251: 0x60,0),CONCAT111(uVar73,SUB1611(auVar35,0))) >>
252: 0x58,0),CONCAT110(uVar64,SUB1610(auVar35,0))) >>
253: 0x50,0);
254: uVar39 = SUB161(auVar55 >> 0x10,0);
255: auVar35 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
256: CONCAT610(uVar42,CONCAT19(uVar49,SUB169(auVar35,0)
257: )) >> 0x48,0),
258: CONCAT18(uVar39,SUB168(auVar35,0))) >> 0x40,0),
259: uVar37)) << 0x38) >> 0x30,0),uVar48)) << 0x28 &
260: (undefined  [16])0xffffffff00000000;
261: uVar74 = SUB161(auVar56 >> 0x40,0);
262: uVar75 = SUB161(auVar56 >> 0x50,0);
263: bVar76 = SUB161(auVar56 >> 0x58,0);
264: uVar77 = SUB161(auVar56 >> 0x60,0);
265: uVar78 = SUB161(auVar56 >> 0x70,0);
266: uVar79 = SUB161(auVar56 >> 0x78,0);
267: auVar53 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
268: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
269: (CONCAT115(puVar1[0xd],
270: CONCAT114(SUB161(auVar38 >> 0x38,0),
271: SUB1614(auVar38,0))) >> 0x70,
272: 0),CONCAT113(uVar36,SUB1613(auVar38,0))) >> 0x68,
273: 0),CONCAT112(SUB161(auVar38 >> 0x30,0),
274: SUB1612(auVar38,0))) >> 0x60,0),
275: CONCAT111(uVar59,SUB1611(auVar38,0))) >> 0x58,0),
276: CONCAT110(SUB161(auVar38 >> 0x28,0),
277: SUB1610(auVar38,0))) >> 0x50,0),
278: CONCAT19(uVar46,SUB169(auVar38,0))) >> 0x48,0),
279: CONCAT18(SUB161(auVar38 >> 0x20,0),
280: SUB168(auVar38,0))) >> 0x40,0),uVar80))
281: << 0x38;
282: auVar54 = auVar53 & (undefined  [16])0xffff000000000000;
283: auVar53 = auVar53 & (undefined  [16])0xffff000000000000;
284: uVar85 = CONCAT12(uVar49,CONCAT11(uVar47,uVar39));
285: uVar87 = CONCAT14(uVar64,CONCAT13(SUB161(auVar55 >> 0x70,0),uVar85));
286: auVar38 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
287: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
288: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
289: puVar1[0xd],CONCAT114(uVar37,SUB1614(auVar35,0)))
290: >> 0x70,0),CONCAT113(uVar36,SUB1613(auVar35,0)))
291: >> 0x68,0),CONCAT112(uVar71,SUB1612(auVar35,0)))
292: >> 0x60,0),CONCAT111(uVar59,SUB1611(auVar35,0)))
293: >> 0x58,0),CONCAT110(uVar48,SUB1610(auVar35,0)))
294: >> 0x50,0),CONCAT19(uVar46,SUB169(auVar35,0))) >>
295: 0x48,0),CONCAT18(uVar45,SUB168(auVar35,0))) >>
296: 0x40,0),uVar80)) << 0x38) >> 0x10,0) &
297: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0)
298: & SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0
299: ) &
300: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),
301: bVar57)) << 8;
302: uVar49 = SUB161(auVar56 >> 0x38,0);
303: uVar48 = SUB161(auVar56 >> 0x30,0);
304: uVar47 = SUB161(auVar56 >> 0x28,0);
305: uVar46 = SUB161(auVar56 >> 0x20,0);
306: uVar45 = SUB161(auVar56 >> 8,0);
307: auVar43 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
308: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
309: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
310: (CONCAT214(SUB162(CONCAT115(uVar18,CONCAT114(
311: uVar49,SUB1614(auVar56,0))) >> 0x70,0),
312: CONCAT113(uVar17,SUB1613(auVar56,0))) >> 0x68,0),
313: CONCAT112(uVar48,SUB1612(auVar56,0))) >> 0x60,0),
314: CONCAT111(uVar50,SUB1611(auVar56,0))) >> 0x58,0),
315: CONCAT110(uVar47,SUB1610(auVar56,0))) >> 0x50,0),
316: CONCAT19(uVar83,SUB169(auVar56,0))) >> 0x48,0),
317: CONCAT18(uVar46,SUB168(auVar56,0))) >> 0x40,0),
318: uVar82),(SUB167(auVar56,0) >> 0x18) << 0x30) >>
319: 0x30,0),uVar81),
320: (SUB165(auVar56,0) >> 0x10) << 0x20) >> 0x20,0),
321: puVar2[1]),uVar45)) << 0x10;
322: auVar35 = ZEXT1416(SUB1614((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
323: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
324: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
325: (CONCAT115(uVar18,CONCAT114(uVar49,SUB1614(auVar56
326: ,0))) >> 0x70,0),
327: CONCAT113(uVar17,SUB1613(auVar56,0))) >> 0x68,0),
328: CONCAT112(uVar48,SUB1612(auVar56,0))) >> 0x60,0),
329: CONCAT111(uVar50,SUB1611(auVar56,0))) >> 0x58,0),
330: CONCAT110(uVar47,SUB1610(auVar56,0))) >> 0x50,0),
331: CONCAT19(uVar83,SUB169(auVar56,0))) >> 0x48,0),
332: CONCAT18(uVar46,SUB168(auVar56,0))) >> 0x40,0),
333: uVar82)) << 0x38) >> 0x30,0),uVar81)) << 0x28) >>
334: 0x10,0) &
335: SUB1614((undefined  [16])0xffffffff00000000 >> 0x10,0) &
336: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0)) << 0x10;
337: uVar24 = SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(
338: CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(puVar1
339: [0xe],CONCAT114(uVar80,SUB1614(auVar38,0))) >>
340: 0x70,0),CONCAT113(uVar73,SUB1613(auVar38,0))) >>
341: 0x68,0),CONCAT112(puVar1[8],SUB1612(auVar38,0)))
342: >> 0x60,0),CONCAT111(uVar15,SUB1611(auVar38,0)))
343: >> 0x58,0),CONCAT110(uVar65,SUB1610(auVar38,0)))
344: >> 0x50,0),CONCAT19(uVar64,SUB169(auVar38,0))) >>
345: 0x48,0),CONCAT18(uVar70,SUB168(auVar38,0))) >> 0x40,
346: 0);
347: uVar29 = (ulong)CONCAT16(uVar73,CONCAT15(uVar15,uVar87)) & 0xff000000;
348: uVar71 = (undefined)((uint6)uVar87 >> 0x10);
349: uVar14 = uVar85 & 0xff00;
350: auVar38 = CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT88(uVar24,(uVar29 >> 0x18) <<
351: 0x38) >> 0x20,0) &
352: SUB1612((undefined  [16])0xffffffffffffffff >>
353: 0x20,0) &
354: SUB1612((undefined  [16])0xff00000000000000 >>
355: 0x20,0) &
356: SUB1612((undefined  [16])0xffffff0000000000 >>
357: 0x20,0),(uVar14 >> 8) << 0x18) >> 0x18
358: ,0),(SUB163(auVar38,0) >> 8) << 0x10) &
359: (undefined  [16])0xffffffffffff0000;
360: uVar59 = SUB161(auVar53 >> 0x48,0);
361: uVar60 = SUB161(auVar54 >> 0x50,0);
362: uVar85 = CONCAT12(uVar60,CONCAT11(uVar58,uVar59));
363: bVar61 = SUB161(auVar54 >> 0x58,0);
364: uVar62 = SUB161(auVar54 >> 0x60,0);
365: uVar37 = SUB161(auVar56 >> 0x18,0);
366: uVar36 = SUB161(auVar56 >> 0x10,0);
367: auVar43 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(
368: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
369: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
370: CONCAT115(uVar20,CONCAT114(SUB161(auVar43 >> 0x38,
371: 0),
372: SUB1614(auVar43,0))) >>
373: 0x70,0),CONCAT113(bVar76,SUB1613(auVar43,0))) >>
374: 0x68,0),CONCAT112(SUB161(auVar43 >> 0x30,0),
375: SUB1612(auVar43,0))) >> 0x60,0),
376: CONCAT111(uVar19,SUB1611(auVar43,0))) >> 0x58,0),
377: CONCAT110(SUB161(auVar43 >> 0x28,0),
378: SUB1610(auVar43,0))) >> 0x50,0),
379: CONCAT19(uVar75,SUB169(auVar43,0))) >> 0x48,0),
380: CONCAT18(SUB161(auVar43 >> 0x20,0),
381: SUB168(auVar43,0))) >> 0x40,0),puVar2[9])
382: ,(SUB167(auVar43,0) >> 0x18) << 0x30) >> 0x30,0),
383: SUB161(auVar56 >> 0x48,0)),uVar45)) << 0x20 &
384: (undefined  [16])0xffffffffff000000;
385: auVar44 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
386: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
387: (CONCAT115(puVar2[0xd],
388: CONCAT114(SUB161(auVar43 >> 0x38,0),
389: SUB1614(auVar43,0))) >> 0x70,
390: 0),CONCAT113(uVar50,SUB1613(auVar43,0))) >> 0x68,
391: 0),CONCAT112(SUB161(auVar43 >> 0x30,0),
392: SUB1612(auVar43,0))) >> 0x60,0),
393: CONCAT111(SUB161(auVar56 >> 0x68,0),
394: SUB1611(auVar43,0))) >> 0x58,0),
395: CONCAT110(SUB161(auVar43 >> 0x28,0),
396: SUB1610(auVar43,0))) >> 0x50,0),
397: CONCAT19(uVar47,SUB169(auVar43,0))) >> 0x48,0),
398: CONCAT18(SUB161(auVar43 >> 0x20,0),
399: SUB168(auVar43,0))) >> 0x40,0),
400: puVar2[0xc])) << 0x38;
401: auVar43 = auVar44 & (undefined  [16])0xffff000000000000;
402: auVar44 = auVar44 & (undefined  [16])0xffff000000000000;
403: uVar50 = SUB161(auVar44 >> 0x48,0);
404: bVar51 = SUB161(auVar43 >> 0x50,0);
405: bVar52 = SUB161(auVar43 >> 0x58,0);
406: uVar13 = (uint6)CONCAT14(uVar65,CONCAT13(uVar81,CONCAT12(uVar64,CONCAT11(*puVar2,
407: uVar70))));
408: uVar65 = (undefined)(uVar29 >> 0x18);
409: auVar63 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(
410: SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(
411: SUB165(CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214
412: (SUB162(CONCAT115(uVar78,CONCAT114(uVar65,SUB1614(
413: auVar38,0))) >> 0x70,0),
414: CONCAT113(uVar77,SUB1613(auVar38,0))) >> 0x68,0),
415: CONCAT112(uVar68,SUB1612(auVar38,0))) >> 0x60,0),
416: CONCAT111(uVar75,SUB1611(auVar38,0))) >> 0x58,0),
417: CONCAT110(uVar71,SUB1610(auVar38,0))) >> 0x50,0),
418: CONCAT19(uVar74,SUB169(auVar38,0))) >> 0x48,0),
419: CONCAT18(uVar66,SUB168(auVar38,0))) >> 0x40,0),
420: uVar48) & 0xffffffffffffffff &
421: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
422: ,0)) << 0x38) >> 0x30,0),uVar46)) << 0x28)
423: >> 0x20,0),uVar36)) << 0x18 &
424: (undefined  [16])0xffffffffffff0000;
425: uVar29 = (ulong)(uVar41 & 0xff000000000000 |
426: (uint7)CONCAT15(SUB161(auVar43 >> 0x68,0),
427: CONCAT14(SUB161(auVar54 >> 0x68,0),
428: CONCAT13(uVar82,CONCAT12(uVar72,CONCAT11(
429: SUB161(auVar43 >> 0x60,0),uVar62))))));
430: auVar38 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
431: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
432: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
433: (CONCAT214(SUB162(CONCAT115(uVar78,CONCAT114(
434: uVar65,SUB1614(auVar38,0))) >> 0x70,0),
435: CONCAT113(uVar77,SUB1613(auVar38,0))) >> 0x68,0),
436: CONCAT112(uVar68,SUB1612(auVar38,0))) >> 0x60,0),
437: CONCAT111(uVar75,SUB1611(auVar38,0))) >> 0x58,0),
438: CONCAT110(uVar71,SUB1610(auVar38,0))) >> 0x50,0),
439: CONCAT19(uVar74,SUB169(auVar38,0))) >> 0x48,0),
440: CONCAT18(uVar66,SUB168(auVar38,0))) >> 0x40,0),
441: uVar48) & 0xffffffffffffffff &
442: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
443: ,0),(SUB167(auVar38,0) >> 0x18) << 0x30) >>
444: 0x30,0),uVar46),
445: (SUB165(auVar38,0) >> 0x10) << 0x20) >> 0x20,0),
446: uVar36),uVar39)) << 0x10;
447: uVar64 = (undefined)(uVar14 >> 8);
448: uVar89 = (undefined)(uVar13 >> 0x20);
449: uVar88 = (undefined)(uVar13 >> 0x18);
450: uVar47 = (undefined)(uVar13 >> 0x10);
451: uVar45 = (undefined)(uVar13 >> 8);
452: auVar63 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101
453: (SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
454: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
455: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
456: uVar17,CONCAT114(uVar48,SUB1614(auVar63,0))) >>
457: 0x70,0),CONCAT113(uVar15,SUB1613(auVar63,0))) >>
458: 0x68,0),CONCAT112(uVar64,SUB1612(auVar63,0))) >>
459: 0x60,0),CONCAT111(uVar83,SUB1611(auVar63,0))) >>
460: 0x58,0),CONCAT110(uVar46,SUB1610(auVar63,0))) >>
461: 0x50,0),CONCAT19(uVar89,SUB169(auVar63,0))) >>
462: 0x48,0),CONCAT18(bVar57,SUB168(auVar63,0))) >>
463: 0x40,0),uVar88)) << 0x38) >> 0x30,0) &
464: SUB1610((undefined  [16])0xffffffffffffffff >>
465: 0x30,0),uVar47)) << 0x28) >> 0x20,0),
466: uVar45)) << 0x18) >> 0x10,0),uVar70)) << 8;
467: uVar86 = SUB153(CONCAT141(SUB1614((ZEXT1216(SUB1612((ZEXT916(CONCAT81(SUB168(
468: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
469: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
470: (CONCAT115(uVar20,CONCAT114(uVar82,SUB1614(auVar35
471: ,0))) >> 0x70,0),
472: CONCAT113(bVar76,SUB1613(auVar35,0))) >> 0x68,0),
473: CONCAT112(uVar37,SUB1612(auVar35,0))) >> 0x60,0),
474: CONCAT111(uVar19,SUB1611(auVar35,0))) >> 0x58,0),
475: CONCAT110(uVar81,SUB1610(auVar35,0))) >> 0x50,0),
476: CONCAT19(uVar75,SUB169(auVar35,0))) >> 0x48,0),
477: CONCAT18(uVar36,SUB168(auVar35,0))) >> 0x40,0),
478: puVar2[9])) << 0x38) >> 0x20,0) &
479: SUB1612((undefined  [16])0xffff000000000000 >>
480: 0x20,0) &
481: SUB1612((undefined  [16])0xffffff0000000000 >>
482: 0x20,0)) << 0x20) >> 0x10,0) &
483: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),
484: uVar74),0) << 0x10 | (uint3)CONCAT11(puVar1[8],uVar66);
485: auVar35 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(
486: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
487: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
488: CONCAT115(uVar17,CONCAT114(SUB161(auVar38 >> 0x38,
489: 0),
490: SUB1614(auVar38,0))) >>
491: 0x70,0),CONCAT113(uVar15,SUB1613(auVar38,0))) >>
492: 0x68,0),CONCAT112(SUB161(auVar38 >> 0x30,0),
493: SUB1612(auVar38,0))) >> 0x60,0),
494: CONCAT111(uVar83,SUB1611(auVar38,0))) >> 0x58,0),
495: CONCAT110(SUB161(auVar38 >> 0x28,0),
496: SUB1610(auVar38,0))) >> 0x50,0),
497: CONCAT19(uVar89,SUB169(auVar38,0))) >> 0x48,0),
498: CONCAT18(SUB161(auVar38 >> 0x20,0),
499: SUB168(auVar38,0))) >> 0x40,0),uVar88),
500: (SUB167(auVar38,0) >> 0x18) << 0x30) >> 0x30,0) &
501: SUB1610((undefined  [16])0xffffffffffffffff >>
502: 0x30,0),uVar47),uVar39)) << 0x20 &
503: (undefined  [16])0xffffffffff000000;
504: uVar23 = CONCAT12(uVar89,CONCAT11(uVar68,bVar57));
505: uVar87 = CONCAT14(uVar46,CONCAT13(uVar80,uVar23));
506: auVar63 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612((ZEXT916(
507: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
508: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
509: (CONCAT214(SUB162(CONCAT115(uVar19,CONCAT114(
510: uVar88,SUB1614(auVar63,0))) >> 0x70,0),
511: CONCAT113(uVar75,SUB1613(auVar63,0))) >> 0x68,0),
512: CONCAT112(uVar36,SUB1612(auVar63,0))) >> 0x60,0),
513: CONCAT111(uVar73,SUB1611(auVar63,0))) >> 0x58,0),
514: CONCAT110(uVar47,SUB1610(auVar63,0))) >> 0x50,0),
515: CONCAT19(uVar71,SUB169(auVar63,0))) >> 0x48,0),
516: CONCAT18(uVar39,SUB168(auVar63,0))) >> 0x40,0),
517: uVar84) & 0xffffffffffffffff) << 0x38) >> 0x20,0)
518: & SUB1612((undefined  [16])0xffff000000000000 >>
519: 0x20,0) &
520: SUB1612((undefined  [16])0xffffff0000000000 >>
521: 0x20,0),((uVar86 & 0xff00) >> 8) << 0x18)
522: >> 0x18,0),(SUB163(auVar63,0) >> 8) << 0x10) >>
523: 0x10,0),uVar66)) << 8;
524: auVar35 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
525: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
526: (CONCAT115(uVar19,CONCAT114(SUB161(auVar35 >> 0x38
527: ,0),
528: SUB1614(auVar35,0)))
529: >> 0x70,0),CONCAT113(uVar75,SUB1613(auVar35,0)))
530: >> 0x68,0),
531: CONCAT112(SUB161(auVar35 >> 0x30,0),
532: SUB1612(auVar35,0))) >> 0x60,0),
533: CONCAT111(uVar73,SUB1611(auVar35,0))) >> 0x58,0),
534: CONCAT110(SUB161(auVar35 >> 0x28,0),
535: SUB1610(auVar35,0))) >> 0x50,0),
536: CONCAT19(uVar71,SUB169(auVar35,0))) >> 0x48,0),
537: CONCAT18(SUB161(auVar35 >> 0x20,0),
538: SUB168(auVar35,0))) >> 0x40,0),uVar84) &
539: 0xffffffffffffffff) << 0x38;
540: auVar38 = auVar35 & (undefined  [16])0xffff000000000000;
541: auVar35 = auVar35 & (undefined  [16])0xffff000000000000;
542: *(undefined (*) [16])(puVar9 + lVar30) =
543: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(
544: CONCAT106(SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(
545: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
546: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
547: (CONCAT115(puVar2[0xc],
548: CONCAT114(uVar84,SUB1614(auVar63,0)))
549: >> 0x70,0),CONCAT113(uVar83,SUB1613(auVar63,0)))
550: >> 0x68,0),CONCAT112(uVar45,SUB1612(auVar63,0)))
551: >> 0x60,0),CONCAT111(uVar77,SUB1611(auVar63,0)))
552: >> 0x58,0),
553: CONCAT110((char)((uint6)CONCAT14(uVar71,(uint)
554: uVar86) >> 0x10),SUB1610(auVar63,0))) >> 0x50,0),
555: CONCAT19(uVar46,SUB169(auVar63,0))) >> 0x48,0),
556: CONCAT18(SUB161(auVar56,0),SUB168(auVar63,0))) >>
557: 0x40,0),(((ulong)CONCAT16(uVar83,CONCAT15(uVar77,
558: uVar87)) & 0xff000000) >> 0x18) << 0x38) >> 0x38,0
559: ) & SUB169((undefined  [16])0xffffffffffffffff >>
560: 0x38,0) &
561: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
562: ,0) &
563: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
564: ,0) &
565: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
566: ,0),(SUB167(auVar63,0) >> 0x18) << 0x30) >>
567: 0x30,0),(((uint6)uVar87 & 0xff0000) >> 0x10) <<
568: 0x28) >> 0x28,0),
569: (SUB165(auVar63,0) >> 0x10) << 0x20) >> 0x20,0),
570: ((uVar23 & 0xff00) >> 8) << 0x18) >> 0x18,0),
571: (SUB163(auVar63,0) >> 8) << 0x10) >> 0x10,0),
572: SUB162(auVar55,0) & 0xff | (ushort)bVar57 << 8);
573: auVar55 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
574: CONCAT81(CONCAT71((uint7)CONCAT11(uVar79,uVar69)
575: << 0x28 | (uint7)bVar52 << 0x20
576: | (uint7)bVar61 << 0x18 |
577: (uint7)bVar76 << 0x10 |
578: (uint7)CONCAT11(uVar67,uVar72) &
579: 0xffffffffffff00 | (uint7)bVar51
580: ,uVar60),uVar49),
581: (uint7)(CONCAT14(bVar61,CONCAT13(uVar67,uVar85))
582: >> 8) << 0x30) >> 0x30,0),uVar50),
583: (uint5)uVar85 << 0x20) >> 0x20,0),uVar37),uVar40))
584: << 0x10;
585: auVar56 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(
586: CONCAT71((uint7)CONCAT11(uVar79,uVar69) << 0x28 |
587: (uint7)bVar52 << 0x20 |
588: (uint7)bVar61 << 0x18 |
589: (uint7)bVar76 << 0x10 |
590: (uint7)CONCAT11(uVar67,uVar72) &
591: 0xffffffffffff00 | (uint7)bVar51,uVar60),
592: uVar49)) << 0x38) >> 0x30,0),uVar50)) << 0x28) >>
593: 0x20,0),uVar37)) << 0x18 &
594: (undefined  [16])0xffffffffffff0000;
595: uVar84 = (undefined)(uVar29 >> 0x30);
596: uVar83 = (undefined)(uVar29 >> 0x28);
597: uVar70 = (undefined)(uVar29 >> 0x20);
598: uVar82 = (undefined)(uVar29 >> 0x18);
599: uVar81 = (undefined)(uVar29 >> 0x10);
600: auVar55 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(
601: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
602: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
603: CONCAT115(uVar18,CONCAT114(SUB161(auVar55 >> 0x38,
604: 0),
605: SUB1614(auVar55,0))) >>
606: 0x70,0),CONCAT113(uVar84,SUB1613(auVar55,0))) >>
607: 0x68,0),CONCAT112(SUB161(auVar55 >> 0x30,0),
608: SUB1612(auVar55,0))) >> 0x60,0),
609: CONCAT111(uVar83,SUB1611(auVar55,0))) >> 0x58,0),
610: CONCAT110(SUB161(auVar55 >> 0x28,0),
611: SUB1610(auVar55,0))) >> 0x50,0),
612: CONCAT19(uVar70,SUB169(auVar55,0))) >> 0x48,0),
613: CONCAT18(SUB161(auVar55 >> 0x20,0),
614: SUB168(auVar55,0))) >> 0x40,0),uVar82),
615: (SUB167(auVar55,0) >> 0x18) << 0x30) >> 0x30,0) &
616: SUB1610((undefined  [16])0xffffffffffffffff >>
617: 0x30,0),uVar81),uVar40)) << 0x20 &
618: (undefined  [16])0xffffffffff000000;
619: uVar80 = (undefined)(uVar29 >> 8);
620: auVar63 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101
621: (SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
622: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
623: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
624: uVar18,CONCAT114(uVar49,SUB1614(auVar56,0))) >>
625: 0x70,0),CONCAT113(uVar84,SUB1613(auVar56,0))) >>
626: 0x68,0),CONCAT112(uVar58,SUB1612(auVar56,0))) >>
627: 0x60,0),CONCAT111(uVar83,SUB1611(auVar56,0))) >>
628: 0x58,0),CONCAT110(uVar50,SUB1610(auVar56,0))) >>
629: 0x50,0),CONCAT19(uVar70,SUB169(auVar56,0))) >>
630: 0x48,0),CONCAT18(uVar59,SUB168(auVar56,0))) >>
631: 0x40,0),uVar82)) << 0x38) >> 0x30,0) &
632: SUB1610((undefined  [16])0xffffffffffffffff >>
633: 0x30,0),uVar81)) << 0x28) >> 0x20,0),
634: uVar80)) << 0x18) >> 0x10,0),uVar62)) << 8;
635: uVar29 = (ulong)CONCAT16(bVar76,uVar42 & 0xff0000000000 |
636: (uint6)CONCAT14(uVar67,CONCAT13(SUB161(auVar43 >>
637: 0x70,0),
638: CONCAT12(bVar51,
639: CONCAT11(SUB161(auVar54 >> 0x70,0),uVar60)))));
640: uVar73 = (undefined)(uVar29 >> 0x30);
641: uVar36 = (undefined)(uVar29 >> 0x28);
642: uVar72 = (undefined)(uVar29 >> 0x20);
643: uVar71 = (undefined)(uVar29 >> 0x18);
644: auVar55 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
645: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
646: (CONCAT115(uVar20,CONCAT114(SUB161(auVar55 >> 0x38
647: ,0),
648: SUB1614(auVar55,0)))
649: >> 0x70,0),CONCAT113(uVar73,SUB1613(auVar55,0)))
650: >> 0x68,0),
651: CONCAT112(SUB161(auVar55 >> 0x30,0),
652: SUB1612(auVar55,0))) >> 0x60,0),
653: CONCAT111(uVar36,SUB1611(auVar55,0))) >> 0x58,0),
654: CONCAT110(SUB161(auVar55 >> 0x28,0),
655: SUB1610(auVar55,0))) >> 0x50,0),
656: CONCAT19(uVar72,SUB169(auVar55,0))) >> 0x48,0),
657: CONCAT18(SUB161(auVar55 >> 0x20,0),
658: SUB168(auVar55,0))) >> 0x40,0),uVar71) &
659: 0xffffffffffffffff) << 0x38;
660: auVar56 = auVar55 & (undefined  [16])0xffff000000000000;
661: auVar55 = auVar55 & (undefined  [16])0xffff000000000000;
662: uVar85 = CONCAT12(uVar70,CONCAT11(bVar61,uVar59));
663: uVar87 = CONCAT14(uVar50,CONCAT13(SUB161(auVar54 >> 0x78,0),uVar85));
664: uVar70 = (undefined)(uVar29 >> 0x10);
665: auVar54 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101
666: (SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(
667: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
668: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
669: uVar20,CONCAT114(uVar82,SUB1614(auVar63,0))) >>
670: 0x70,0),CONCAT113(uVar73,SUB1613(auVar63,0))) >>
671: 0x68,0),CONCAT112(uVar37,SUB1612(auVar63,0))) >>
672: 0x60,0),CONCAT111(uVar36,SUB1611(auVar63,0))) >>
673: 0x58,0),CONCAT110(uVar81,SUB1610(auVar63,0))) >>
674: 0x50,0),CONCAT19(uVar72,SUB169(auVar63,0))) >>
675: 0x48,0),CONCAT18(uVar40,SUB168(auVar63,0))) >>
676: 0x40,0),uVar71)) << 0x38) >> 0x30,0) &
677: SUB1610((undefined  [16])0xffffffffffffffff >>
678: 0x30,0),uVar70)) << 0x28) >> 0x20,0),
679: (char)(uVar29 >> 8)),
680: (SUB163(auVar63,0) >> 8) << 0x10) >> 0x10,0),
681: uVar60)) << 8;
682: *(undefined (*) [16])(puVar10 + lVar30) =
683: CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(
684: CONCAT106(SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(
685: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
686: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
687: (CONCAT115(SUB161(auVar43 >> 0x78,0),
688: CONCAT114(uVar71,SUB1614(auVar54,0)))
689: >> 0x70,0),CONCAT113(uVar83,SUB1613(auVar54,0)))
690: >> 0x68,0),CONCAT112(uVar80,SUB1612(auVar54,0)))
691: >> 0x60,0),CONCAT111(bVar52,SUB1611(auVar54,0)))
692: >> 0x58,0),CONCAT110(uVar70,SUB1610(auVar54,0)))
693: >> 0x50,0),CONCAT19(uVar50,SUB169(auVar54,0))) >>
694: 0x48,0),CONCAT18(SUB161(auVar44 >> 0x40,0),
695: SUB168(auVar54,0))) >> 0x40,0),
696: (((ulong)CONCAT16(uVar83,CONCAT15(bVar52,uVar87))
697: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
698: (SUB167(auVar54,0) >> 0x18) << 0x30) >> 0x30,0),
699: (((uint6)uVar87 & 0xff0000) >> 0x10) << 0x28) >>
700: 0x28,0),(SUB165(auVar54,0) >> 0x10) << 0x20) >>
701: 0x20,0),((uVar85 & 0xff00) >> 8) << 0x18) >> 0x18,
702: 0),(SUB163(auVar54,0) >> 8) << 0x10) >> 0x10,0),
703: SUB162(auVar53 >> 0x40,0));
704: *(undefined (*) [16])(puVar11 + lVar30) =
705: CONCAT115(uVar21,CONCAT114(SUB161(auVar38 >> 0x78,0),
706: CONCAT113(uVar17,CONCAT112(SUB161(auVar38 >> 0x70,0)
707: ,CONCAT111(uVar78,
708: CONCAT110(SUB161(auVar38 >> 0x68,0),
709: CONCAT19(uVar48,CONCAT18(SUB161(auVar38 
710: >> 0x60,0),
711: uVar24 & 0xff00000000000000 |
712: (ulong)CONCAT16(SUB161(auVar38 >> 0x58,0),
713: CONCAT15(uVar15,CONCAT14(SUB161(
714: auVar38 >> 0x50,0),
715: CONCAT13(uVar65,CONCAT12(SUB161(auVar35 >> 0x48,0)
716: ,CONCAT11(uVar64,SUB161(
717: auVar35 >> 0x40,0)))))))))))))));
718: puVar1 = puVar12 + lVar30;
719: *puVar1 = SUB161(auVar55 >> 0x40,0);
720: puVar1[1] = uVar58;
721: puVar1[2] = SUB161(auVar55 >> 0x48,0);
722: puVar1[3] = uVar69;
723: puVar1[4] = SUB161(auVar56 >> 0x50,0);
724: puVar1[5] = uVar84;
725: puVar1[6] = SUB161(auVar56 >> 0x58,0);
726: puVar1[7] = uVar16;
727: puVar1[8] = SUB161(auVar56 >> 0x60,0);
728: puVar1[9] = uVar49;
729: puVar1[10] = SUB161(auVar56 >> 0x68,0);
730: puVar1[0xb] = uVar79;
731: puVar1[0xc] = SUB161(auVar56 >> 0x70,0);
732: puVar1[0xd] = uVar18;
733: puVar1[0xe] = SUB161(auVar56 >> 0x78,0);
734: puVar1[0xf] = uVar22;
735: lVar30 = lVar30 + 0x10;
736: } while (uVar31 < uVar7 >> 4);
737: puVar28 = puVar28 + (ulong)uVar32 * 4;
738: uVar31 = uVar32;
739: if (uVar7 == uVar32) goto LAB_001063dc;
740: }
741: do {
742: uVar29 = (ulong)uVar31;
743: uVar31 = uVar31 + 1;
744: puVar9[uVar29] = *puVar28;
745: puVar10[uVar29] = puVar28[1];
746: puVar11[uVar29] = puVar28[2];
747: puVar12[uVar29] = puVar28[3];
748: puVar28 = puVar28 + 4;
749: } while (uVar31 < uVar7);
750: goto LAB_001063dc;
751: }
752: lVar30 = 0;
753: do {
754: puVar9[lVar30] = *puVar28;
755: puVar10[lVar30] = puVar28[1];
756: puVar11[lVar30] = puVar28[2];
757: puVar12[lVar30] = puVar28[3];
758: lVar30 = lVar30 + 1;
759: puVar28 = puVar28 + 4;
760: } while ((uint)lVar30 < uVar7);
761: }
762: goto LAB_001063dc;
763: }
764: }
765: else {
766: if (0 < param_5) {
767: do {
768: if (0 < iVar6) {
769: lVar30 = 0;
770: do {
771: puVar28 = (undefined *)(lVar30 + *param_2);
772: lVar8 = *(long *)(param_3[lVar30] + uVar33 * 8);
773: lVar25 = 0;
774: if (uVar7 != 0) {
775: do {
776: uVar70 = *puVar28;
777: puVar28 = puVar28 + iVar6;
778: *(undefined *)(lVar8 + lVar25) = uVar70;
779: lVar25 = lVar25 + 1;
780: } while ((uint)lVar25 < uVar7);
781: }
782: lVar30 = lVar30 + 1;
783: } while ((int)lVar30 < iVar6);
784: }
785: uVar32 = (int)uVar33 + 1;
786: uVar33 = (ulong)uVar32;
787: param_2 = param_2 + 1;
788: } while (uVar32 != param_5 + param_4);
789: }
790: }
791: }
792: return;
793: }
794: 
