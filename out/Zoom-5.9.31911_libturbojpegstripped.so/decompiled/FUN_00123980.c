1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00123980(long param_1,long *param_2,uint param_3,undefined (**param_4) [16],int param_5)
5: 
6: {
7: byte bVar1;
8: byte bVar2;
9: unkuint9 Var3;
10: uint6 uVar4;
11: undefined uVar5;
12: undefined uVar6;
13: undefined uVar7;
14: undefined uVar8;
15: undefined uVar9;
16: undefined uVar10;
17: undefined uVar11;
18: undefined auVar12 [16];
19: undefined auVar13 [16];
20: undefined (*pauVar14) [16];
21: undefined (*pauVar15) [16];
22: uint *puVar16;
23: uint uVar17;
24: ulong uVar18;
25: byte *pbVar19;
26: uint uVar20;
27: uint uVar21;
28: undefined (*pauVar22) [16];
29: undefined (*pauVar23) [16];
30: uint uVar24;
31: uint uVar25;
32: uint uVar26;
33: byte bVar33;
34: undefined uVar36;
35: ushort uVar38;
36: ushort uVar40;
37: undefined auVar31 [16];
38: undefined2 uVar41;
39: uint uVar44;
40: uint uVar45;
41: ushort uVar56;
42: undefined uVar57;
43: undefined uVar58;
44: undefined uVar60;
45: ushort uVar59;
46: undefined uVar61;
47: undefined auVar53 [16];
48: undefined auVar54 [16];
49: uint uVar63;
50: uint uVar64;
51: int iVar65;
52: uint uVar66;
53: uint uVar67;
54: undefined auVar62 [16];
55: uint uVar68;
56: uint uVar69;
57: undefined uVar75;
58: undefined uVar76;
59: undefined uVar77;
60: undefined uVar78;
61: undefined uVar79;
62: undefined auVar70 [13];
63: unkuint10 Var72;
64: unkuint10 Var73;
65: undefined auVar71 [13];
66: unkuint10 Var74;
67: uint5 uVar80;
68: undefined auVar81 [12];
69: ushort uVar84;
70: ushort uVar85;
71: undefined auVar86 [12];
72: ushort uVar89;
73: ushort uVar90;
74: uint uVar91;
75: uint uVar92;
76: uint uVar93;
77: uint uVar94;
78: ulong uVar27;
79: undefined auVar28 [12];
80: undefined auVar29 [12];
81: undefined auVar30 [14];
82: undefined uVar32;
83: undefined uVar34;
84: undefined uVar35;
85: undefined uVar37;
86: uint7 uVar39;
87: uint3 uVar42;
88: undefined4 uVar43;
89: uint5 uVar46;
90: uint5 uVar47;
91: undefined6 uVar48;
92: uint7 uVar49;
93: undefined8 uVar50;
94: unkbyte10 Var51;
95: undefined auVar52 [12];
96: undefined uVar55;
97: undefined auVar82 [14];
98: ushort uVar83;
99: undefined auVar87 [14];
100: ushort uVar88;
101: 
102: auVar13 = _DAT_00189860;
103: auVar12 = _DAT_00189850;
104: param_5 = param_5 + -1;
105: uVar24 = *(uint *)(param_1 + 0x88);
106: while (-1 < param_5) {
107: pauVar14 = *param_4;
108: pauVar23 = *(undefined (**) [16])(*param_2 + (ulong)param_3 * 8);
109: pauVar22 = pauVar14;
110: if (((ulong)pauVar14 & 3) != 0) {
111: bVar1 = (*pauVar23)[0];
112: pauVar22 = (undefined (*) [16])(*pauVar14 + 2);
113: uVar24 = uVar24 - 1;
114: pauVar23 = (undefined (*) [16])(*pauVar23 + 1);
115: *(ushort *)*pauVar14 =
116: (ushort)((bVar1 & 0xf8) << 8) | (ushort)bVar1 * 8 & 0x7e0 | (ushort)(bVar1 >> 3);
117: }
118: uVar17 = uVar24 >> 1;
119: if (uVar17 != 0) {
120: if ((pauVar22 < (undefined (*) [16])(*pauVar23 + (ulong)uVar17 * 2) &&
121: pauVar23 < (undefined (*) [16])(*pauVar22 + (ulong)uVar17 * 4)) || (uVar17 < 0x10)) {
122: uVar18 = (ulong)(uVar17 - 1);
123: pauVar14 = pauVar23;
124: pauVar15 = pauVar22;
125: do {
126: bVar1 = (*pauVar14)[0];
127: bVar2 = (*pauVar14)[1];
128: pauVar14 = (undefined (*) [16])(*pauVar14 + 2);
129: *(uint *)*pauVar15 =
130: (uint)bVar1 * 8 & 0x7e0 | (bVar1 & 0xf8) << 8 | (uint)(bVar1 >> 3) |
131: ((uint)bVar2 * 8 & 0x7e0 | (bVar2 & 0xf8) << 8 | (uint)(bVar2 >> 3)) << 0x10;
132: pauVar15 = (undefined (*) [16])(*pauVar15 + 4);
133: } while (pauVar14 != (undefined (*) [16])(*pauVar23 + uVar18 * 2 + 2));
134: }
135: else {
136: uVar20 = 0;
137: uVar21 = (uVar24 >> 5) << 4;
138: pauVar14 = pauVar22;
139: pauVar15 = pauVar23;
140: do {
141: auVar62 = *pauVar15;
142: uVar20 = uVar20 + 1;
143: uVar57 = pauVar15[1][1];
144: uVar5 = pauVar15[1][2];
145: uVar6 = pauVar15[1][3];
146: uVar7 = pauVar15[1][4];
147: uVar58 = pauVar15[1][5];
148: uVar8 = pauVar15[1][6];
149: uVar61 = pauVar15[1][7];
150: uVar60 = pauVar15[1][9];
151: uVar9 = pauVar15[1][10];
152: uVar10 = pauVar15[1][0xb];
153: uVar11 = pauVar15[1][0xc];
154: bVar1 = pauVar15[1][0xe];
155: bVar2 = pauVar15[1][0xf];
156: uVar75 = SUB161(auVar62 >> 0x48,0);
157: uVar76 = SUB161(auVar62 >> 0x50,0);
158: uVar77 = SUB161(auVar62 >> 0x58,0);
159: uVar78 = SUB161(auVar62 >> 0x68,0);
160: uVar79 = SUB161(auVar62 >> 0x78,0);
161: uVar37 = SUB161(auVar62 >> 0x38,0);
162: uVar35 = SUB161(auVar62 >> 0x30,0);
163: uVar34 = SUB161(auVar62 >> 0x28,0);
164: uVar32 = SUB161(auVar62 >> 0x20,0);
165: uVar39 = SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
166: CONCAT214(SUB162(CONCAT115(uVar61,CONCAT114(uVar37
167: ,SUB1614(auVar62,0))) >> 0x70,0),
168: CONCAT113(uVar8,SUB1613(auVar62,0))) >> 0x68,0),
169: CONCAT112(uVar35,SUB1612(auVar62,0))) >> 0x60,0),
170: CONCAT111(uVar58,SUB1611(auVar62,0))) >> 0x58,0),
171: CONCAT110(uVar34,SUB1610(auVar62,0))) >> 0x50,0),
172: CONCAT19(uVar7,SUB169(auVar62,0))) >> 0x48,0);
173: auVar31 = ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(
174: CONCAT79(uVar39,CONCAT18(uVar32,SUB168(auVar62,0))
175: ) >> 0x40,0),uVar6)) << 0x38) >> 0x30,0),
176: uVar5)) << 0x28) >> 0x20,0),uVar57)) << 0x18 &
177: (undefined  [16])0xffffffffffff0000;
178: uVar55 = SUB161(auVar62 >> 8,0);
179: auVar53 = ZEXT1416(CONCAT131(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
180: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
181: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
182: (CONCAT214(SUB162(CONCAT115(uVar61,CONCAT114(
183: uVar37,SUB1614(auVar62,0))) >> 0x70,0),
184: CONCAT113(uVar8,SUB1613(auVar62,0))) >> 0x68,0),
185: CONCAT112(uVar35,SUB1612(auVar62,0))) >> 0x60,0),
186: CONCAT111(uVar58,SUB1611(auVar62,0))) >> 0x58,0),
187: CONCAT110(uVar34,SUB1610(auVar62,0))) >> 0x50,0),
188: CONCAT19(uVar7,SUB169(auVar62,0))) >> 0x48,0),
189: CONCAT18(uVar32,SUB168(auVar62,0))) >> 0x40,0),
190: uVar6),(SUB167(auVar62,0) >> 0x18) << 0x30) >>
191: 0x30,0),uVar5),(SUB165(auVar62,0) >> 0x10) << 0x20
192: ) >> 0x20,0),uVar57),uVar55)) << 0x10;
193: uVar36 = SUB161(auVar62 >> 0x18,0);
194: bVar33 = SUB161(auVar62 >> 0x10,0);
195: auVar31 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
196: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
197: (SUB163(CONCAT214(SUB162(CONCAT115(uVar10,
198: CONCAT114(uVar6,SUB1614(auVar31,0))) >> 0x70,0),
199: CONCAT113(uVar77,SUB1613(auVar31,0))) >> 0x68,0),
200: CONCAT112(uVar36,SUB1612(auVar31,0))) >> 0x60,0),
201: CONCAT111(uVar9,SUB1611(auVar31,0))) >> 0x58,0),
202: CONCAT110(uVar5,SUB1610(auVar31,0))) >> 0x50,0),
203: CONCAT19(uVar76,SUB169(auVar31,0))) >> 0x48,0),
204: CONCAT18(bVar33,SUB168(auVar31,0))) >> 0x40,0),
205: uVar60)) << 0x38) >> 0x30,0),uVar75)) << 0x28 &
206: (undefined  [16])0xffffffff00000000;
207: auVar53 = ZEXT1216(CONCAT111(CONCAT101(SUB1610(CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(
208: CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(SUB164
209: (CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(
210: uVar10,CONCAT114(SUB161(auVar53 >> 0x38,0),
211: SUB1614(auVar53,0))) >> 0x70,0),
212: CONCAT113(uVar77,SUB1613(auVar53,0))) >> 0x68,0),
213: CONCAT112(SUB161(auVar53 >> 0x30,0),
214: SUB1612(auVar53,0))) >> 0x60,0),
215: CONCAT111(uVar9,SUB1611(auVar53,0))) >> 0x58,0),
216: CONCAT110(SUB161(auVar53 >> 0x28,0),
217: SUB1610(auVar53,0))) >> 0x50,0),
218: CONCAT19(uVar76,SUB169(auVar53,0))) >> 0x48,0),
219: CONCAT18(SUB161(auVar53 >> 0x20,0),
220: SUB168(auVar53,0))) >> 0x40,0),uVar60),
221: (SUB167(auVar53,0) >> 0x18) << 0x30) >> 0x30,0),
222: uVar75),uVar55)) << 0x20 &
223: (undefined  [16])0xffffffffff000000;
224: auVar31 = ZEXT1516(CONCAT141(SUB1614((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
225: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
226: (SUB163(CONCAT214(SUB162(CONCAT115(pauVar15[1]
227: [0xd],CONCAT114
228: (uVar60,SUB1614(auVar31,0))) >> 0x70,0),
229: CONCAT113(uVar58,SUB1613(auVar31,0))) >> 0x68,0),
230: CONCAT112(uVar57,SUB1612(auVar31,0))) >> 0x60,0),
231: CONCAT111(uVar78,SUB1611(auVar31,0))) >> 0x58,0),
232: CONCAT110(uVar75,SUB1610(auVar31,0))) >> 0x50,0),
233: CONCAT19(uVar34,SUB169(auVar31,0))) >> 0x48,0),
234: CONCAT18(uVar55,SUB168(auVar31,0))) >> 0x40,0),
235: uVar11)) << 0x38) >> 0x10,0) &
236: SUB1614((undefined  [16])0xffff000000000000 >> 0x10,0) &
237: SUB1614((undefined  [16])0xffffff0000000000 >> 0x10,0) &
238: SUB1614((undefined  [16])0xffffffffff000000 >> 0x10,0),uVar32
239: )) << 8;
240: uVar42 = CONCAT12(uVar76,CONCAT11(uVar35,bVar33));
241: uVar80 = CONCAT14(uVar5,CONCAT13(SUB161(auVar62 >> 0x70,0),uVar42));
242: auVar53 = ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
243: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
244: (CONCAT115(pauVar15[1][0xd],
245: CONCAT114(SUB161(auVar53 >> 0x38,0),
246: SUB1614(auVar53,0))) >> 0x70,
247: 0),CONCAT113(uVar58,SUB1613(auVar53,0))) >> 0x68,
248: 0),CONCAT112(SUB161(auVar53 >> 0x30,0),
249: SUB1612(auVar53,0))) >> 0x60,0),
250: CONCAT111(uVar78,SUB1611(auVar53,0))) >> 0x58,0),
251: CONCAT110(SUB161(auVar53 >> 0x28,0),
252: SUB1610(auVar53,0))) >> 0x50,0),
253: CONCAT19(uVar34,SUB169(auVar53,0))) >> 0x48,0),
254: CONCAT18(SUB161(auVar53 >> 0x20,0),
255: SUB168(auVar53,0))) >> 0x40,0),uVar11))
256: << 0x38;
257: auVar54 = auVar53 & (undefined  [16])0xffff000000000000;
258: auVar53 = auVar53 & (undefined  [16])0xffff000000000000;
259: uVar18 = (ulong)CONCAT16(uVar9,CONCAT15(uVar8,uVar80)) & 0xff000000;
260: uVar4 = (uint6)uVar80 & 0xff0000;
261: uVar38 = SUB162(auVar62,0) & 0xff | (ushort)bVar33 << 8;
262: auVar31 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88
263: (SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511
264: (SUB165(CONCAT412(SUB164(CONCAT313(SUB163(
265: CONCAT214(SUB162(CONCAT115(bVar1,CONCAT114(uVar11,
266: SUB1614(auVar31,0))) >> 0x70,0),
267: CONCAT113(uVar9,SUB1613(auVar31,0))) >> 0x68,0),
268: CONCAT112(pauVar15[1][8],SUB1612(auVar31,0))) >>
269: 0x60,0),CONCAT111(uVar8,SUB1611(auVar31,0))) >>
270: 0x58,0),CONCAT110(uVar7,SUB1610(auVar31,0))) >>
271: 0x50,0),CONCAT19(uVar5,SUB169(auVar31,0))) >> 0x48
272: ,0),CONCAT18(pauVar15[1][0],SUB168(auVar31,0))) >>
273: 0x40,0),(uVar18 >> 0x18) << 0x38) >> 0x30,0) &
274: SUB1610((undefined  [16])0xffffffffffffffff >>
275: 0x30,0) &
276: SUB1610((undefined  [16])0xff00000000000000 >>
277: 0x30,0),(uVar4 >> 0x10) << 0x28) >> 0x20,0
278: ) & SUB1612((undefined  [16])0xffffff0000000000 >>
279: 0x20,0),
280: ((uVar42 & 0xff00) >> 8) << 0x18) >> 0x18,0),
281: (SUB163(auVar31,0) >> 8) << 0x10) >> 0x10,0),uVar38)
282: ;
283: uVar41 = CONCAT11(uVar36,SUB161(auVar53 >> 0x40,0));
284: uVar42 = CONCAT12(SUB161(auVar53 >> 0x48,0),uVar41);
285: uVar43 = CONCAT13(uVar37,uVar42);
286: uVar57 = SUB161(auVar54 >> 0x50,0);
287: uVar46 = CONCAT14(uVar57,uVar43);
288: uVar48 = CONCAT15(uVar77,uVar46);
289: uVar58 = SUB161(auVar54 >> 0x58,0);
290: uVar49 = CONCAT16(uVar58,uVar48);
291: uVar50 = CONCAT17(uVar79,uVar49);
292: bVar33 = SUB161(auVar54 >> 0x60,0);
293: Var51 = CONCAT19(uVar6,CONCAT18(bVar33,uVar50));
294: uVar60 = SUB161(auVar54 >> 0x68,0);
295: auVar52 = CONCAT111(uVar61,CONCAT110(uVar60,Var51));
296: uVar61 = SUB161(auVar54 >> 0x70,0);
297: uVar25 = (uint)CONCAT12(uVar5,(ushort)(byte)pauVar15[1][0]);
298: uVar80 = CONCAT14(uVar7,uVar25);
299: uVar27 = (ulong)CONCAT16(uVar8,(uint6)uVar80);
300: auVar28 = ZEXT1112(CONCAT110(uVar9,(unkuint10)
301: (CONCAT18(pauVar15[1][8],uVar27) & 0xffffffffffffffff))
302: );
303: auVar30 = ZEXT1314(CONCAT112(uVar11,auVar28));
304: auVar70 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9
305: )(SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510
306: (SUB155(CONCAT411(SUB154(CONCAT312(SUB153(
307: CONCAT213(SUB152(CONCAT114((char)(uVar18 >> 0x18),
308: SUB1614(auVar31,0)) >>
309: 0x68,0),
310: CONCAT112(SUB161(auVar62 >> 0x60,0),
311: SUB1612(auVar31,0))) >> 0x60,0
312: ),SUB1612(auVar31,0)) >> 0x58,0),
313: CONCAT110((char)(uVar4 >> 0x10),SUB1610(auVar31,0)
314: )) >> 0x50,0),SUB1610(auVar31,0)) >> 0x48
315: ,0),CONCAT18(SUB161(auVar62 >> 0x40,0),
316: SUB168(auVar31,0))) >> 0x40,0),
317: SUB168(auVar31,0)) >> 0x38,0) & 0xff) &
318: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
319: ,0) &
320: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
321: ,0) &
322: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
323: ,0) &
324: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
325: ,0),(SUB167(auVar31,0) >> 0x18) << 0x30) >>
326: 0x30,0),SUB166(auVar31,0)) >> 0x28,0) &
327: SUB1611((undefined  [16])0xffff00ffffffffff >>
328: 0x28,0),
329: (SUB165(auVar31,0) >> 0x10) << 0x20) >> 0x20,0),
330: SUB164(auVar31,0)) >> 0x18,0) &
331: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
332: auVar62 = CONCAT142(SUB1614(CONCAT133(auVar70,(SUB163(auVar31,0) >> 8) << 0x10) >> 0x10,0)
333: ,uVar38) & (undefined  [16])0xffffffffffff00ff;
334: Var72 = (unkuint10)
335: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar62 >> 0x30,0),
336: SUB1612(auVar62,0)) >> 0x50,0),
337: CONCAT28(SUB162(auVar62 >> 0x20,0),
338: SUB168(auVar62,0))) >> 0x40,0),
339: SUB168(auVar62,0)) >> 0x30,0) &
340: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
341: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
342: uVar63 = SUB164(auVar62,0) & 0xffff;
343: uVar88 = SUB132(auVar70 >> 0x28,0);
344: uVar69 = (uint)uVar88;
345: uVar89 = SUB132(auVar70 >> 0x48,0);
346: auVar86 = ZEXT1012(CONCAT28(uVar89,(ulong)CONCAT24(SUB132(auVar70 >> 0x38,0),uVar69)));
347: uVar90 = SUB132(auVar70 >> 0x58,0);
348: auVar87 = CONCAT212(uVar90,auVar86);
349: uVar38 = SUB142(auVar30 >> 0x40,0);
350: uVar26 = (uint)uVar38;
351: uVar40 = SUB162(ZEXT1516(CONCAT114(bVar1,auVar30)) >> 0x60,0);
352: auVar29 = ZEXT1012(CONCAT28(uVar40,(ulong)CONCAT24(SUB162(ZEXT1516(CONCAT114(bVar1,auVar30
353: )) >> 0x50,0),
354: uVar26)));
355: auVar70 = CONCAT112(bVar1,auVar29);
356: Var73 = (unkuint10)
357: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar30 >> 0x30,0),
358: auVar28) >> 0x50,0),
359: CONCAT28(SUB122(auVar28 >> 0x20,0),uVar27)) >>
360: 0x40,0),uVar27) >> 0x30,0) &
361: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
362: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
363: uVar25 = uVar25 & 0xffff;
364: uVar66 = SUB164(CONCAT106(Var72,(SUB166(auVar62,0) >> 0x10) << 0x20) >> 0x20,0);
365: uVar91 = (uint)(Var72 >> 0x10);
366: uVar93 = (uint)(Var72 >> 0x30);
367: uVar44 = (uint)CONCAT12(uVar6,(ushort)bVar33);
368: uVar47 = CONCAT14(uVar60,uVar44);
369: uVar18 = (ulong)(uVar39 & 0xff000000000000 | (uint7)uVar47);
370: auVar28 = ZEXT1112(CONCAT110(uVar10,(unkuint10)CONCAT18(uVar61,uVar18)));
371: auVar30 = ZEXT1314(CONCAT112(SUB161(auVar54 >> 0x78,0),auVar28));
372: auVar71 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((unkuint9
373: )SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(
374: SUB155(CONCAT411(SUB154(CONCAT312(SUB153(CONCAT213
375: (SUB152(CONCAT114(uVar79,CONCAT113(uVar10,
376: CONCAT112(uVar61,auVar52))) >> 0x68,0),
377: CONCAT112(uVar58,auVar52)) >> 0x60,0),auVar52) >>
378: 0x58,0),CONCAT110(uVar77,Var51)) >> 0x50,0),Var51)
379: >> 0x48,0),CONCAT18(uVar57,uVar50)) >> 0x40,0),
380: uVar50) >> 0x38,0) &
381: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
382: ,0) &
383: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
384: ,0) &
385: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
386: ,0) &
387: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
388: ,0),(uVar49 >> 0x18) << 0x30) >> 0x30,0),
389: uVar48) >> 0x28,0) &
390: SUB1611((undefined  [16])0xffff00ffffffffff >>
391: 0x28,0),(uVar46 >> 0x10) << 0x20) >> 0x20,
392: 0),uVar43) >> 0x18,0) &
393: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
394: auVar62 = CONCAT142(SUB1614(CONCAT133(auVar71,(uVar42 >> 8) << 0x10) >> 0x10,0),uVar41) &
395: (undefined  [16])0xffffffffffff00ff;
396: Var72 = (unkuint10)
397: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar62 >> 0x30,0),
398: SUB1612(auVar62,0)) >> 0x50,0),
399: CONCAT28(SUB162(auVar62 >> 0x20,0),
400: SUB168(auVar62,0))) >> 0x40,0),
401: SUB168(auVar62,0)) >> 0x30,0) &
402: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
403: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
404: uVar64 = SUB164(auVar62,0) & 0xffff;
405: uVar83 = SUB132(auVar71 >> 0x28,0);
406: uVar68 = (uint)uVar83;
407: uVar84 = SUB132(auVar71 >> 0x48,0);
408: auVar81 = ZEXT1012(CONCAT28(uVar84,(ulong)CONCAT24(SUB132(auVar71 >> 0x38,0),uVar68)));
409: uVar85 = SUB132(auVar71 >> 0x58,0);
410: auVar82 = CONCAT212(uVar85,auVar81);
411: uVar56 = SUB142(auVar30 >> 0x40,0);
412: uVar45 = (uint)uVar56;
413: uVar59 = (ushort)((unkuint10)SUB159(CONCAT114(bVar2,auVar30) >> 0x30,0) >> 0x30);
414: auVar52 = ZEXT1012(CONCAT28(uVar59,(ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(CONCAT114(bVar2
415: ,auVar30) >> 0x10,0)) >> 0x40,0),uVar45)));
416: auVar71 = CONCAT112(bVar2,auVar52);
417: Var74 = (unkuint10)
418: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar30 >> 0x30,0),
419: auVar28) >> 0x50,0),
420: CONCAT28(SUB122(auVar28 >> 0x20,0),uVar18)) >>
421: 0x40,0),uVar18) >> 0x30,0) &
422: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
423: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
424: uVar44 = uVar44 & 0xffff;
425: uVar67 = SUB164(CONCAT106(Var72,(SUB166(auVar62,0) >> 0x10) << 0x20) >> 0x20,0);
426: uVar92 = (uint)(Var72 >> 0x10);
427: uVar94 = (uint)(Var72 >> 0x30);
428: auVar62 = CONCAT412(uVar94 << 8,CONCAT48(uVar92 << 8,CONCAT44(uVar67 << 8,uVar64 << 8))) &
429: auVar12 | CONCAT412(uVar94 << 3,
430: CONCAT48(uVar92 << 3,CONCAT44(uVar67 << 3,uVar64 << 3))) &
431: auVar13 |
432: CONCAT412(uVar94 >> 3,CONCAT48(uVar92 >> 3,CONCAT44(uVar67 >> 3,uVar64 >> 3)));
433: *pauVar14 = CONCAT412(uVar93 << 8,CONCAT48(uVar91 << 8,CONCAT44(uVar66 << 8,uVar63 << 8)))
434: & auVar12 |
435: CONCAT412(uVar93 << 3,CONCAT48(uVar91 << 3,CONCAT44(uVar66 << 3,uVar63 << 3)))
436: & auVar13 |
437: CONCAT412(uVar93 >> 3,CONCAT48(uVar91 >> 3,CONCAT44(uVar66 >> 3,uVar63 >> 3)))
438: | CONCAT412(SUB164(auVar62 >> 0x60,0) << 0x10,
439: CONCAT48(SUB164(auVar62 >> 0x40,0) << 0x10,
440: CONCAT44(SUB164(auVar62 >> 0x20,0) << 0x10,
441: SUB164(auVar62,0) << 0x10)));
442: uVar63 = SUB164(ZEXT1416(auVar87) >> 0x20,0);
443: uVar66 = SUB124(ZEXT1012(SUB1410(auVar87 >> 0x20,0)) >> 0x20,0);
444: uVar64 = SUB164(ZEXT1416(auVar82) >> 0x20,0);
445: uVar67 = SUB124(ZEXT1012(SUB1410(auVar82 >> 0x20,0)) >> 0x20,0);
446: auVar62 = CONCAT412((uint)uVar85 << 8,
447: CONCAT48(uVar67 << 8,CONCAT44(uVar64 << 8,uVar68 << 8))) & auVar12 |
448: CONCAT412((uint)uVar85 << 3,
449: CONCAT48((uint)uVar84 << 3,
450: CONCAT44(SUB124(auVar81 >> 0x20,0) << 3,uVar68 << 3))) &
451: auVar13 | ZEXT1416(CONCAT212(uVar85 >> 3,
452: CONCAT48(uVar67 >> 3,
453: CONCAT44(uVar64 >> 3,(uint)(uVar83 >> 3)))
454: ));
455: pauVar14[1] = CONCAT412((uint)uVar90 << 8,
456: CONCAT48((uint)uVar89 << 8,
457: CONCAT44(SUB124(auVar86 >> 0x20,0) << 8,uVar69 << 8))) &
458: auVar12 | CONCAT412((uint)uVar90 << 3,
459: CONCAT48(uVar66 << 3,CONCAT44(uVar63 << 3,uVar69 << 3)))
460: & auVar13 |
461: ZEXT1416(CONCAT212(uVar90 >> 3,
462: CONCAT48(uVar66 >> 3,
463: CONCAT44(uVar63 >> 3,(uint)(uVar88 >> 3))))) |
464: CONCAT412(SUB164(auVar62 >> 0x60,0) << 0x10,
465: CONCAT48(SUB164(auVar62 >> 0x40,0) << 0x10,
466: CONCAT44(SUB164(auVar62 >> 0x20,0) << 0x10,
467: SUB164(auVar62,0) << 0x10)));
468: uVar63 = SUB164(CONCAT106(Var73,(uint6)(uVar80 >> 0x10) << 0x20) >> 0x20,0);
469: uVar66 = (uint)(Var73 >> 0x10);
470: uVar68 = (uint)(Var73 >> 0x30);
471: uVar64 = SUB164(CONCAT106(Var74,(uint6)(uVar47 >> 0x10) << 0x20) >> 0x20,0);
472: uVar67 = (uint)(Var74 >> 0x10);
473: uVar69 = (uint)(Var74 >> 0x30);
474: auVar62 = CONCAT412(uVar69 << 8,CONCAT48(uVar67 << 8,CONCAT44(uVar64 << 8,uVar44 << 8))) &
475: auVar12 | CONCAT412(uVar69 << 3,
476: CONCAT48(uVar67 << 3,CONCAT44(uVar64 << 3,uVar44 << 3))) &
477: auVar13 |
478: CONCAT412(uVar69 >> 3,CONCAT48(uVar67 >> 3,CONCAT44(uVar64 >> 3,uVar44 >> 3)));
479: pauVar14[2] = CONCAT412(uVar68 << 8,
480: CONCAT48(uVar66 << 8,CONCAT44(uVar63 << 8,uVar25 << 8))) & auVar12
481: | CONCAT412(uVar68 << 3,
482: CONCAT48(uVar66 << 3,CONCAT44(uVar63 << 3,uVar25 << 3))) &
483: auVar13 |
484: CONCAT412(uVar68 >> 3,
485: CONCAT48(uVar66 >> 3,CONCAT44(uVar63 >> 3,uVar25 >> 3))) |
486: CONCAT412(SUB164(auVar62 >> 0x60,0) << 0x10,
487: CONCAT48(SUB164(auVar62 >> 0x40,0) << 0x10,
488: CONCAT44(SUB164(auVar62 >> 0x20,0) << 0x10,
489: SUB164(auVar62,0) << 0x10)));
490: uVar25 = SUB164(ZEXT1316(auVar70) >> 0x20,0);
491: uVar44 = SUB124(ZEXT912(SUB139(auVar70 >> 0x20,0)) >> 0x20,0);
492: Var3 = SUB139(auVar71 >> 0x20,0);
493: iVar65 = SUB164(ZEXT1316(auVar71) >> 0x20,0);
494: auVar62 = CONCAT412((uint)(ushort)bVar2 << 8,
495: CONCAT48(SUB124(ZEXT912(Var3) >> 0x20,0) << 8,
496: CONCAT44(iVar65 << 8,uVar45 << 8))) & auVar12 |
497: CONCAT412((uint)(ushort)bVar2 << 3,
498: CONCAT48(SUB124(ZEXT912(Var3) >> 0x20,0) << 3,
499: CONCAT44(iVar65 << 3,uVar45 << 3))) & auVar13 |
500: ZEXT1316(CONCAT112(bVar2 >> 3,
501: ZEXT1012(CONCAT28(uVar59 >> 3,
502: CONCAT44(SUB124(auVar52 >> 0x20,0) >> 3,
503: (uint)(uVar56 >> 3))))));
504: pauVar14[3] = CONCAT412((uint)bVar1 << 8,
505: CONCAT48((uint)uVar40 << 8,
506: CONCAT44(SUB124(auVar29 >> 0x20,0) << 8,uVar26 << 8))) &
507: auVar12 | CONCAT412((uint)bVar1 << 3,
508: CONCAT48(uVar44 << 3,CONCAT44(uVar25 << 3,uVar26 << 3)))
509: & auVar13 |
510: ZEXT1316(CONCAT112(bVar1 >> 3,
511: CONCAT48(uVar44 >> 3,
512: CONCAT44(uVar25 >> 3,(uint)(uVar38 >> 3))))) |
513: CONCAT412(SUB164(auVar62 >> 0x60,0) << 0x10,
514: CONCAT48(SUB164(auVar62 >> 0x40,0) << 0x10,
515: CONCAT44(SUB164(auVar62 >> 0x20,0) << 0x10,
516: SUB164(auVar62,0) << 0x10)));
517: pauVar14 = pauVar14[4];
518: pauVar15 = pauVar15[2];
519: } while (uVar20 < uVar24 >> 5);
520: pbVar19 = *pauVar23 + (ulong)uVar21 * 2;
521: puVar16 = (uint *)(*pauVar22 + (ulong)uVar21 * 4);
522: if (uVar17 != uVar21) {
523: do {
524: bVar1 = *pbVar19;
525: uVar21 = uVar21 + 1;
526: bVar2 = pbVar19[1];
527: *puVar16 = (uint)bVar1 * 8 & 0x7e0 | (bVar1 & 0xf8) << 8 | (uint)(bVar1 >> 3) |
528: ((uint)bVar2 * 8 & 0x7e0 | (bVar2 & 0xf8) << 8 | (uint)(bVar2 >> 3)) << 0x10;
529: puVar16 = puVar16 + 1;
530: pbVar19 = pbVar19 + 2;
531: } while (uVar21 < uVar17);
532: }
533: uVar18 = (ulong)(uVar17 - 1);
534: }
535: pauVar23 = (undefined (*) [16])(*pauVar23 + uVar18 * 2 + 2);
536: pauVar22 = (undefined (*) [16])(*pauVar22 + uVar18 * 4 + 4);
537: }
538: if ((uVar24 & 1) != 0) {
539: bVar1 = (*pauVar23)[0];
540: *(ushort *)*pauVar22 =
541: (ushort)((bVar1 & 0xf8) << 8) | (ushort)bVar1 * 8 & 0x7e0 | (ushort)(bVar1 >> 3);
542: }
543: param_5 = param_5 + -1;
544: param_4 = param_4 + 1;
545: param_3 = param_3 + 1;
546: }
547: return;
548: }
549: 
