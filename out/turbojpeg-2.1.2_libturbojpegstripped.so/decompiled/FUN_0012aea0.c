1: 
2: void FUN_0012aea0(long param_1,long *param_2,uint param_3,undefined (**param_4) [16],int param_5)
3: 
4: {
5: undefined auVar1 [16];
6: uint uVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: undefined *puVar7;
12: undefined (**ppauVar8) [16];
13: undefined (*pauVar9) [16];
14: undefined (*pauVar10) [16];
15: undefined (*pauVar11) [16];
16: undefined *puVar12;
17: undefined (*pauVar13) [16];
18: uint uVar14;
19: uint uVar15;
20: undefined uVar18;
21: undefined uVar19;
22: uint3 uVar16;
23: undefined uVar20;
24: undefined uVar21;
25: undefined uVar22;
26: undefined uVar23;
27: undefined uVar24;
28: undefined uVar25;
29: undefined uVar26;
30: undefined uVar27;
31: undefined uVar28;
32: undefined uVar29;
33: undefined uVar30;
34: undefined uVar31;
35: undefined uVar32;
36: undefined uVar33;
37: undefined uVar34;
38: undefined uVar35;
39: undefined uVar36;
40: uint3 uVar37;
41: undefined uVar46;
42: undefined uVar47;
43: undefined uVar48;
44: undefined uVar49;
45: undefined auVar50 [16];
46: undefined in_XMM4_Ba;
47: undefined in_XMM4_Bb;
48: undefined in_XMM4_Bc;
49: undefined in_XMM4_Bd;
50: undefined in_XMM4_Be;
51: undefined in_XMM4_Bf;
52: undefined uVar51;
53: undefined in_XMM4_Bg;
54: undefined in_XMM4_Bh;
55: undefined in_XMM4_Bi;
56: undefined in_XMM4_Bj;
57: undefined in_XMM4_Bk;
58: undefined in_XMM4_Bl;
59: undefined in_XMM4_Bm;
60: undefined in_XMM4_Bn;
61: undefined in_XMM4_Bo;
62: undefined in_XMM4_Bp;
63: uint5 uVar17;
64: uint5 uVar38;
65: uint7 uVar39;
66: undefined8 uVar40;
67: unkbyte9 Var41;
68: unkbyte10 Var42;
69: undefined auVar43 [11];
70: undefined auVar44 [12];
71: undefined auVar45 [13];
72: 
73: uVar2 = *(uint *)(param_1 + 0x88);
74: switch(*(undefined4 *)(param_1 + 0x40)) {
75: case 6:
76: while (param_5 = param_5 + -1, -1 < param_5) {
77: ppauVar8 = param_4 + 1;
78: uVar15 = param_3 + 1;
79: puVar12 = *(undefined **)(*param_2 + (ulong)param_3 * 8);
80: pauVar13 = *param_4;
81: param_4 = ppauVar8;
82: param_3 = uVar15;
83: if (uVar2 != 0) {
84: pauVar9 = pauVar13;
85: do {
86: uVar51 = *puVar12;
87: puVar7 = *pauVar9;
88: puVar12 = puVar12 + 1;
89: (*pauVar9)[2] = uVar51;
90: (*pauVar9)[1] = uVar51;
91: (*pauVar9)[0] = uVar51;
92: pauVar9 = (undefined (*) [16])(puVar7 + 3);
93: } while ((undefined (*) [16])(puVar7 + 3) !=
94: (undefined (*) [16])(*pauVar13 + (ulong)(uVar2 - 1) * 3 + 3));
95: }
96: }
97: break;
98: case 7:
99: case 0xc:
100: uVar15 = uVar2 & 0xfffffff0;
101: iVar3 = -(uint)(CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ==
102: CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))));
103: iVar4 = -(uint)(CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ==
104: CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))));
105: iVar5 = -(uint)(CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ==
106: CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))));
107: uVar51 = (undefined)((uint)iVar5 >> 0x10);
108: iVar6 = -(uint)(CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ==
109: CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))));
110: code_r0x0012b588:
111: while( true ) {
112: do {
113: param_5 = param_5 + -1;
114: if (param_5 < 0) {
115: return;
116: }
117: ppauVar8 = param_4 + 1;
118: uVar14 = param_3 + 1;
119: pauVar13 = *(undefined (**) [16])(*param_2 + (ulong)param_3 * 8);
120: pauVar9 = *param_4;
121: param_4 = ppauVar8;
122: param_3 = uVar14;
123: } while (uVar2 == 0);
124: if (((undefined (*) [16])(*pauVar13 + uVar2) <= pauVar9 ||
125: (undefined (*) [16])(*pauVar9 + (ulong)uVar2 * 4) <= pauVar13) && (0xf < uVar2)) break;
126: puVar12 = *pauVar13;
127: do {
128: uVar19 = (*pauVar13)[0];
129: pauVar13 = (undefined (*) [16])(*pauVar13 + 1);
130: (*pauVar9)[3] = 0xff;
131: (*pauVar9)[2] = uVar19;
132: (*pauVar9)[1] = uVar19;
133: (*pauVar9)[0] = uVar19;
134: pauVar9 = (undefined (*) [16])(*pauVar9 + 4);
135: } while (pauVar13 != (undefined (*) [16])(puVar12 + (ulong)(uVar2 - 1) + 1));
136: }
137: if (0xe < uVar2 - 1) goto code_r0x0012b5e1;
138: uVar14 = 0;
139: goto code_r0x0012b658;
140: case 8:
141: while (param_5 = param_5 + -1, -1 < param_5) {
142: ppauVar8 = param_4 + 1;
143: uVar15 = param_3 + 1;
144: puVar12 = *(undefined **)(*param_2 + (ulong)param_3 * 8);
145: pauVar13 = *param_4;
146: param_4 = ppauVar8;
147: param_3 = uVar15;
148: if (uVar2 != 0) {
149: pauVar9 = pauVar13;
150: do {
151: uVar51 = *puVar12;
152: puVar7 = *pauVar9;
153: puVar12 = puVar12 + 1;
154: (*pauVar9)[0] = uVar51;
155: (*pauVar9)[1] = uVar51;
156: (*pauVar9)[2] = uVar51;
157: pauVar9 = (undefined (*) [16])(puVar7 + 3);
158: } while ((undefined (*) [16])(puVar7 + 3) !=
159: (undefined (*) [16])(*pauVar13 + (ulong)(uVar2 - 1) * 3 + 3));
160: }
161: }
162: break;
163: case 9:
164: case 0xd:
165: uVar15 = uVar2 & 0xfffffff0;
166: iVar3 = -(uint)(CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ==
167: CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))));
168: iVar4 = -(uint)(CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ==
169: CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))));
170: iVar5 = -(uint)(CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ==
171: CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))));
172: uVar51 = (undefined)((uint)iVar5 >> 0x10);
173: iVar6 = -(uint)(CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ==
174: CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))));
175: code_r0x0012b8f8:
176: while( true ) {
177: do {
178: param_5 = param_5 + -1;
179: if (param_5 < 0) {
180: return;
181: }
182: ppauVar8 = param_4 + 1;
183: uVar14 = param_3 + 1;
184: pauVar13 = *(undefined (**) [16])(*param_2 + (ulong)param_3 * 8);
185: pauVar9 = *param_4;
186: param_4 = ppauVar8;
187: param_3 = uVar14;
188: } while (uVar2 == 0);
189: if (((undefined (*) [16])(*pauVar13 + uVar2) <= pauVar9 ||
190: (undefined (*) [16])(*pauVar9 + (ulong)uVar2 * 4) <= pauVar13) && (0xf < uVar2)) break;
191: puVar12 = *pauVar13;
192: do {
193: uVar19 = (*pauVar13)[0];
194: pauVar13 = (undefined (*) [16])(*pauVar13 + 1);
195: (*pauVar9)[3] = 0xff;
196: (*pauVar9)[0] = uVar19;
197: (*pauVar9)[1] = uVar19;
198: (*pauVar9)[2] = uVar19;
199: pauVar9 = (undefined (*) [16])(*pauVar9 + 4);
200: } while (pauVar13 != (undefined (*) [16])(puVar12 + (ulong)(uVar2 - 1) + 1));
201: }
202: if (0xe < uVar2 - 1) goto code_r0x0012b951;
203: uVar14 = 0;
204: goto code_r0x0012b9c8;
205: case 10:
206: case 0xe:
207: uVar15 = uVar2 & 0xfffffff0;
208: param_5 = param_5 + -1;
209: iVar3 = -(uint)(CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ==
210: CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))));
211: iVar4 = -(uint)(CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ==
212: CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))));
213: uVar51 = (undefined)((uint)iVar4 >> 8);
214: uVar19 = (undefined)((uint)iVar4 >> 0x10);
215: uVar21 = (undefined)((uint)iVar4 >> 0x18);
216: iVar5 = -(uint)(CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ==
217: CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))));
218: iVar6 = -(uint)(CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ==
219: CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))));
220: uVar23 = (undefined)((uint)iVar6 >> 8);
221: uVar25 = (undefined)((uint)iVar6 >> 0x10);
222: while (-1 < param_5) {
223: pauVar13 = *(undefined (**) [16])(*param_2 + (ulong)param_3 * 8);
224: pauVar9 = *param_4;
225: if (uVar2 != 0) {
226: if ((pauVar9 < (undefined (*) [16])(*pauVar13 + uVar2) &&
227: pauVar13 < (undefined (*) [16])(*pauVar9 + (ulong)uVar2 * 4)) || (uVar2 < 0x10)) {
228: puVar12 = *pauVar13;
229: do {
230: uVar18 = (*pauVar13)[0];
231: pauVar13 = (undefined (*) [16])(*pauVar13 + 1);
232: (*pauVar9)[0] = 0xff;
233: (*pauVar9)[1] = uVar18;
234: (*pauVar9)[2] = uVar18;
235: (*pauVar9)[3] = uVar18;
236: pauVar9 = (undefined (*) [16])(*pauVar9 + 4);
237: } while (pauVar13 != (undefined (*) [16])(puVar12 + (ulong)(uVar2 - 1) + 1));
238: }
239: else {
240: if (uVar2 - 1 < 0xf) {
241: uVar14 = 0;
242: }
243: else {
244: uVar14 = 0;
245: pauVar10 = pauVar13;
246: pauVar11 = pauVar9;
247: do {
248: auVar1 = *pauVar10;
249: uVar14 = uVar14 + 1;
250: pauVar10 = pauVar10[1];
251: uVar28 = SUB161(auVar1 >> 0x38,0);
252: uVar27 = SUB161(auVar1 >> 0x30,0);
253: uVar26 = SUB161(auVar1 >> 0x28,0);
254: uVar24 = SUB161(auVar1 >> 0x20,0);
255: uVar22 = SUB161(auVar1 >> 0x18,0);
256: uVar20 = SUB161(auVar1 >> 0x10,0);
257: uVar18 = SUB161(auVar1 >> 8,0);
258: auVar50 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(
259: SUB1610((ZEXT916(CONCAT81((long)(CONCAT72(CONCAT61
260: (CONCAT51(CONCAT41(CONCAT31(CONCAT21(CONCAT11(
261: uVar28,uVar21),uVar27),uVar19),uVar26),uVar51),
262: uVar24),CONCAT11((char)iVar4,uVar21)) >> 8),uVar22
263: )) << 0x38) >> 0x30,0),uVar20)) << 0x28) >> 0x20,0
264: ),uVar18),((uint3)iVar3 >> 8) << 0x10) >> 0x10,0),
265: SUB161(auVar1,0))) << 8;
266: uVar17 = CONCAT14((char)((uint)iVar5 >> 0x18),
267: CONCAT13((char)((uint)iVar5 >> 0x10),
268: CONCAT12((char)((uint)iVar5 >> 8),
269: CONCAT11((char)iVar5,uVar21))));
270: auVar45 = ZEXT613(CONCAT15((char)iVar6,uVar17)) << 0x38;
271: uVar46 = SUB121((ZEXT512(uVar17) << 0x38) >> 0x40,0);
272: uVar29 = SUB161(auVar1 >> 0x40,0);
273: uVar37 = CONCAT12(SUB131(auVar45 >> 0x48,0),CONCAT11(uVar29,uVar46));
274: uVar30 = SUB161(auVar1 >> 0x48,0);
275: uVar47 = SUB131(auVar45 >> 0x50,0);
276: uVar38 = CONCAT14(uVar47,CONCAT13(uVar30,uVar37));
277: uVar31 = SUB161(auVar1 >> 0x50,0);
278: uVar48 = SUB131(auVar45 >> 0x58,0);
279: uVar39 = CONCAT16(uVar48,CONCAT15(uVar31,uVar38));
280: uVar32 = SUB161(auVar1 >> 0x58,0);
281: uVar40 = CONCAT17(uVar32,uVar39);
282: uVar49 = SUB131(auVar45 >> 0x60,0);
283: Var41 = CONCAT18(uVar49,uVar40);
284: uVar33 = SUB161(auVar1 >> 0x60,0);
285: Var42 = CONCAT19(uVar33,Var41);
286: auVar43 = CONCAT110(uVar23,Var42);
287: uVar34 = SUB161(auVar1 >> 0x68,0);
288: auVar44 = CONCAT111(uVar34,auVar43);
289: auVar45 = CONCAT112(uVar25,auVar44);
290: uVar35 = SUB161(auVar1 >> 0x70,0);
291: uVar36 = SUB161(auVar1 >> 0x78,0);
292: uVar16 = CONCAT12(uVar30,CONCAT11(uVar29,uVar29));
293: uVar17 = CONCAT14(uVar31,CONCAT13(uVar30,uVar16));
294: pauVar11[1][0] = (char)iVar4;
295: pauVar11[1][1] = uVar24;
296: pauVar11[1][2] = uVar24;
297: pauVar11[1][3] = uVar24;
298: pauVar11[1][4] = uVar51;
299: pauVar11[1][5] = uVar26;
300: pauVar11[1][6] = uVar26;
301: pauVar11[1][7] = uVar26;
302: pauVar11[1][8] = uVar19;
303: pauVar11[1][9] = uVar27;
304: pauVar11[1][10] = uVar27;
305: pauVar11[1][0xb] = uVar27;
306: pauVar11[1][0xc] = uVar21;
307: pauVar11[1][0xd] = uVar28;
308: pauVar11[1][0xe] = uVar28;
309: pauVar11[1][0xf] = uVar28;
310: *pauVar11 = CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(
311: CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610
312: (SUB166(CONCAT511(SUB165(CONCAT412(SUB164(
313: CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(uVar22
314: ,CONCAT114(uVar22,SUB1614(auVar50,0))) >> 0x70,0),
315: CONCAT113(uVar22,SUB1613(auVar50,0))) >> 0x68,0),
316: CONCAT112((char)((uint)iVar3 >> 0x18),
317: SUB1612(auVar50,0))) >> 0x60,0),
318: CONCAT111(uVar20,SUB1611(auVar50,0))) >> 0x58,0),
319: CONCAT110(uVar20,SUB1610(auVar50,0))) >> 0x50,0),
320: CONCAT19(uVar20,SUB169(auVar50,0))) >> 0x48,0),
321: CONCAT18((char)((uint)iVar3 >> 0x10),
322: SUB168(auVar50,0))) >> 0x40,0),uVar18),
323: (SUB167(auVar50,0) >> 0x18) << 0x30) >> 0x30,0),
324: uVar18),(SUB165(auVar50,0) >> 0x10) << 0x20) >>
325: 0x20,0),SUB161(auVar1,0)),
326: (SUB163(auVar50,0) >> 8) << 0x10) >> 0x10,0),
327: (ushort)iVar3 & 0xff | SUB162(auVar1,0) << 8);
328: pauVar11[2] = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(
329: CONCAT106(SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(
330: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
331: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
332: (CONCAT115(uVar32,CONCAT114(uVar32,CONCAT113(
333: uVar35,auVar45))) >> 0x70,0),
334: CONCAT113(uVar32,auVar45)) >> 0x68,0),
335: CONCAT112(uVar48,auVar44)) >> 0x60,0),
336: CONCAT111(uVar31,auVar43)) >> 0x58,0),
337: CONCAT110(uVar31,Var42)) >> 0x50,0),
338: CONCAT19(uVar31,Var41)) >> 0x48,0),
339: CONCAT18(uVar47,uVar40)) >> 0x40,0),
340: (((ulong)CONCAT16(uVar32,CONCAT15(uVar31,uVar17))
341: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
342: (uVar39 >> 0x18) << 0x30) >> 0x30,0),
343: (((uint6)uVar17 & 0xff0000) >> 0x10) << 0x28) >>
344: 0x28,0),(uVar38 >> 0x10) << 0x20) >> 0x20,0),
345: ((uVar16 & 0xff00) >> 8) << 0x18) >> 0x18,0),
346: (uVar37 >> 8) << 0x10) >> 0x10,0),
347: CONCAT11(uVar29,uVar46));
348: pauVar11[3][0] = uVar49;
349: pauVar11[3][1] = uVar33;
350: pauVar11[3][2] = uVar33;
351: pauVar11[3][3] = uVar33;
352: pauVar11[3][4] = uVar23;
353: pauVar11[3][5] = uVar34;
354: pauVar11[3][6] = uVar34;
355: pauVar11[3][7] = uVar34;
356: pauVar11[3][8] = uVar25;
357: pauVar11[3][9] = uVar35;
358: pauVar11[3][10] = uVar35;
359: pauVar11[3][0xb] = uVar35;
360: pauVar11[3][0xc] = (char)((uint)iVar6 >> 0x18);
361: pauVar11[3][0xd] = uVar36;
362: pauVar11[3][0xe] = uVar36;
363: pauVar11[3][0xf] = uVar36;
364: pauVar11 = pauVar11[4];
365: } while (uVar14 < uVar2 >> 4);
366: pauVar9 = (undefined (*) [16])(*pauVar9 + (ulong)uVar15 * 4);
367: uVar14 = uVar15;
368: if (uVar2 == uVar15) goto code_r0x0012b1c0;
369: }
370: uVar18 = (*pauVar13)[uVar14];
371: (*pauVar9)[0] = 0xff;
372: (*pauVar9)[1] = uVar18;
373: (*pauVar9)[2] = uVar18;
374: (*pauVar9)[3] = uVar18;
375: if (uVar14 + 1 < uVar2) {
376: uVar18 = (*pauVar13)[uVar14 + 1];
377: (*pauVar9)[4] = 0xff;
378: (*pauVar9)[5] = uVar18;
379: (*pauVar9)[6] = uVar18;
380: (*pauVar9)[7] = uVar18;
381: if (uVar14 + 2 < uVar2) {
382: uVar18 = (*pauVar13)[uVar14 + 2];
383: (*pauVar9)[8] = 0xff;
384: (*pauVar9)[9] = uVar18;
385: (*pauVar9)[10] = uVar18;
386: (*pauVar9)[0xb] = uVar18;
387: if (uVar14 + 3 < uVar2) {
388: uVar18 = (*pauVar13)[uVar14 + 3];
389: (*pauVar9)[0xc] = 0xff;
390: (*pauVar9)[0xd] = uVar18;
391: (*pauVar9)[0xe] = uVar18;
392: (*pauVar9)[0xf] = uVar18;
393: if (uVar14 + 4 < uVar2) {
394: uVar18 = (*pauVar13)[uVar14 + 4];
395: pauVar9[1][0] = 0xff;
396: pauVar9[1][1] = uVar18;
397: pauVar9[1][2] = uVar18;
398: pauVar9[1][3] = uVar18;
399: if (uVar14 + 5 < uVar2) {
400: uVar18 = (*pauVar13)[uVar14 + 5];
401: pauVar9[1][4] = 0xff;
402: pauVar9[1][5] = uVar18;
403: pauVar9[1][6] = uVar18;
404: pauVar9[1][7] = uVar18;
405: if (uVar14 + 6 < uVar2) {
406: uVar18 = (*pauVar13)[uVar14 + 6];
407: pauVar9[1][8] = 0xff;
408: pauVar9[1][9] = uVar18;
409: pauVar9[1][10] = uVar18;
410: pauVar9[1][0xb] = uVar18;
411: if (uVar14 + 7 < uVar2) {
412: uVar18 = (*pauVar13)[uVar14 + 7];
413: pauVar9[1][0xc] = 0xff;
414: pauVar9[1][0xd] = uVar18;
415: pauVar9[1][0xe] = uVar18;
416: pauVar9[1][0xf] = uVar18;
417: if (uVar14 + 8 < uVar2) {
418: uVar18 = (*pauVar13)[uVar14 + 8];
419: pauVar9[2][0] = 0xff;
420: pauVar9[2][1] = uVar18;
421: pauVar9[2][2] = uVar18;
422: pauVar9[2][3] = uVar18;
423: if (uVar14 + 9 < uVar2) {
424: uVar18 = (*pauVar13)[uVar14 + 9];
425: pauVar9[2][4] = 0xff;
426: pauVar9[2][5] = uVar18;
427: pauVar9[2][6] = uVar18;
428: pauVar9[2][7] = uVar18;
429: if (uVar14 + 10 < uVar2) {
430: uVar18 = (*pauVar13)[uVar14 + 10];
431: pauVar9[2][8] = 0xff;
432: pauVar9[2][9] = uVar18;
433: pauVar9[2][10] = uVar18;
434: pauVar9[2][0xb] = uVar18;
435: if (uVar14 + 0xb < uVar2) {
436: uVar18 = (*pauVar13)[uVar14 + 0xb];
437: pauVar9[2][0xc] = 0xff;
438: pauVar9[2][0xd] = uVar18;
439: pauVar9[2][0xe] = uVar18;
440: pauVar9[2][0xf] = uVar18;
441: if (uVar14 + 0xc < uVar2) {
442: uVar18 = (*pauVar13)[uVar14 + 0xc];
443: pauVar9[3][0] = 0xff;
444: pauVar9[3][1] = uVar18;
445: pauVar9[3][2] = uVar18;
446: pauVar9[3][3] = uVar18;
447: if (uVar14 + 0xd < uVar2) {
448: uVar18 = (*pauVar13)[uVar14 + 0xd];
449: pauVar9[3][4] = 0xff;
450: pauVar9[3][5] = uVar18;
451: pauVar9[3][6] = uVar18;
452: pauVar9[3][7] = uVar18;
453: if (uVar14 + 0xe < uVar2) {
454: uVar18 = (*pauVar13)[uVar14 + 0xe];
455: pauVar9[3][8] = 0xff;
456: pauVar9[3][9] = uVar18;
457: pauVar9[3][10] = uVar18;
458: pauVar9[3][0xb] = uVar18;
459: }
460: }
461: }
462: }
463: }
464: }
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
475: code_r0x0012b1c0:
476: param_5 = param_5 + -1;
477: param_4 = param_4 + 1;
478: param_3 = param_3 + 1;
479: }
480: break;
481: case 0xb:
482: case 0xf:
483: uVar15 = uVar2 & 0xfffffff0;
484: iVar3 = -(uint)(CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ==
485: CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))));
486: iVar4 = -(uint)(CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ==
487: CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))));
488: uVar51 = (undefined)((uint)iVar4 >> 8);
489: uVar19 = (undefined)((uint)iVar4 >> 0x10);
490: uVar21 = (undefined)((uint)iVar4 >> 0x18);
491: iVar5 = -(uint)(CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ==
492: CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))));
493: iVar6 = -(uint)(CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ==
494: CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))));
495: uVar23 = (undefined)((uint)iVar6 >> 8);
496: uVar25 = (undefined)((uint)iVar6 >> 0x10);
497: code_r0x0012b220:
498: while( true ) {
499: do {
500: param_5 = param_5 + -1;
501: if (param_5 < 0) {
502: return;
503: }
504: ppauVar8 = param_4 + 1;
505: uVar14 = param_3 + 1;
506: pauVar13 = *(undefined (**) [16])(*param_2 + (ulong)param_3 * 8);
507: pauVar9 = *param_4;
508: param_4 = ppauVar8;
509: param_3 = uVar14;
510: } while (uVar2 == 0);
511: if (((undefined (*) [16])(*pauVar13 + uVar2) <= pauVar9 ||
512: (undefined (*) [16])(*pauVar9 + (ulong)uVar2 * 4) <= pauVar13) && (0xf < uVar2)) break;
513: puVar12 = *pauVar13;
514: do {
515: uVar18 = (*pauVar13)[0];
516: pauVar13 = (undefined (*) [16])(*pauVar13 + 1);
517: (*pauVar9)[0] = 0xff;
518: (*pauVar9)[3] = uVar18;
519: (*pauVar9)[2] = uVar18;
520: (*pauVar9)[1] = uVar18;
521: pauVar9 = (undefined (*) [16])(*pauVar9 + 4);
522: } while (pauVar13 != (undefined (*) [16])(puVar12 + (ulong)(uVar2 - 1) + 1));
523: }
524: if (0xe < uVar2 - 1) goto code_r0x0012b274;
525: uVar14 = 0;
526: goto code_r0x0012b2eb;
527: default:
528: while (param_5 = param_5 + -1, -1 < param_5) {
529: ppauVar8 = param_4 + 1;
530: uVar15 = param_3 + 1;
531: puVar12 = *(undefined **)(*param_2 + (ulong)param_3 * 8);
532: pauVar13 = *param_4;
533: param_4 = ppauVar8;
534: param_3 = uVar15;
535: if (uVar2 != 0) {
536: pauVar9 = pauVar13;
537: do {
538: uVar51 = *puVar12;
539: puVar7 = *pauVar9;
540: puVar12 = puVar12 + 1;
541: (*pauVar9)[2] = uVar51;
542: (*pauVar9)[1] = uVar51;
543: (*pauVar9)[0] = uVar51;
544: pauVar9 = (undefined (*) [16])(puVar7 + 3);
545: } while ((undefined (*) [16])(puVar7 + 3) !=
546: (undefined (*) [16])(*pauVar13 + (ulong)(uVar2 - 1) * 3 + 3));
547: }
548: }
549: }
550: return;
551: code_r0x0012b274:
552: uVar14 = 0;
553: pauVar10 = pauVar9;
554: pauVar11 = pauVar13;
555: do {
556: auVar1 = *pauVar11;
557: uVar14 = uVar14 + 1;
558: pauVar11 = pauVar11[1];
559: uVar28 = SUB161(auVar1 >> 0x38,0);
560: uVar27 = SUB161(auVar1 >> 0x30,0);
561: uVar26 = SUB161(auVar1 >> 0x28,0);
562: uVar24 = SUB161(auVar1 >> 0x20,0);
563: uVar22 = SUB161(auVar1 >> 0x18,0);
564: uVar20 = SUB161(auVar1 >> 0x10,0);
565: uVar18 = SUB161(auVar1 >> 8,0);
566: auVar50 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
567: ZEXT916(CONCAT81((long)(CONCAT72(CONCAT61(CONCAT51
568: (CONCAT41(CONCAT31(CONCAT21(CONCAT11(uVar28,uVar21
569: ),uVar27),
570: uVar19),uVar26),uVar51),uVar24)
571: ,CONCAT11((char)iVar4,uVar21)) >> 8),uVar22)) <<
572: 0x38) >> 0x30,0),uVar20)) << 0x28) >> 0x20,0),
573: uVar18),((uint3)iVar3 >> 8) << 0x10) >> 0x10,0),
574: SUB161(auVar1,0))) << 8;
575: uVar17 = CONCAT14((char)((uint)iVar5 >> 0x18),
576: CONCAT13((char)((uint)iVar5 >> 0x10),
577: CONCAT12((char)((uint)iVar5 >> 8),CONCAT11((char)iVar5,uVar21))));
578: auVar45 = ZEXT613(CONCAT15((char)iVar6,uVar17)) << 0x38;
579: uVar46 = SUB121((ZEXT512(uVar17) << 0x38) >> 0x40,0);
580: uVar29 = SUB161(auVar1 >> 0x40,0);
581: uVar37 = CONCAT12(SUB131(auVar45 >> 0x48,0),CONCAT11(uVar29,uVar46));
582: uVar30 = SUB161(auVar1 >> 0x48,0);
583: uVar47 = SUB131(auVar45 >> 0x50,0);
584: uVar38 = CONCAT14(uVar47,CONCAT13(uVar30,uVar37));
585: uVar31 = SUB161(auVar1 >> 0x50,0);
586: uVar48 = SUB131(auVar45 >> 0x58,0);
587: uVar39 = CONCAT16(uVar48,CONCAT15(uVar31,uVar38));
588: uVar32 = SUB161(auVar1 >> 0x58,0);
589: uVar40 = CONCAT17(uVar32,uVar39);
590: uVar49 = SUB131(auVar45 >> 0x60,0);
591: Var41 = CONCAT18(uVar49,uVar40);
592: uVar33 = SUB161(auVar1 >> 0x60,0);
593: Var42 = CONCAT19(uVar33,Var41);
594: auVar43 = CONCAT110(uVar23,Var42);
595: uVar34 = SUB161(auVar1 >> 0x68,0);
596: auVar44 = CONCAT111(uVar34,auVar43);
597: auVar45 = CONCAT112(uVar25,auVar44);
598: uVar35 = SUB161(auVar1 >> 0x70,0);
599: uVar36 = SUB161(auVar1 >> 0x78,0);
600: uVar16 = CONCAT12(uVar30,CONCAT11(uVar29,uVar29));
601: uVar17 = CONCAT14(uVar31,CONCAT13(uVar30,uVar16));
602: pauVar10[1][0] = (char)iVar4;
603: pauVar10[1][1] = uVar24;
604: pauVar10[1][2] = uVar24;
605: pauVar10[1][3] = uVar24;
606: pauVar10[1][4] = uVar51;
607: pauVar10[1][5] = uVar26;
608: pauVar10[1][6] = uVar26;
609: pauVar10[1][7] = uVar26;
610: pauVar10[1][8] = uVar19;
611: pauVar10[1][9] = uVar27;
612: pauVar10[1][10] = uVar27;
613: pauVar10[1][0xb] = uVar27;
614: pauVar10[1][0xc] = uVar21;
615: pauVar10[1][0xd] = uVar28;
616: pauVar10[1][0xe] = uVar28;
617: pauVar10[1][0xf] = uVar28;
618: *pauVar10 = CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
619: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
620: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
621: (CONCAT214(SUB162(CONCAT115(uVar22,CONCAT114(
622: uVar22,SUB1614(auVar50,0))) >> 0x70,0),
623: CONCAT113(uVar22,SUB1613(auVar50,0))) >> 0x68,0),
624: CONCAT112((char)((uint)iVar3 >> 0x18),
625: SUB1612(auVar50,0))) >> 0x60,0),
626: CONCAT111(uVar20,SUB1611(auVar50,0))) >> 0x58,0),
627: CONCAT110(uVar20,SUB1610(auVar50,0))) >> 0x50,0),
628: CONCAT19(uVar20,SUB169(auVar50,0))) >> 0x48,0),
629: CONCAT18((char)((uint)iVar3 >> 0x10),
630: SUB168(auVar50,0))) >> 0x40,0),uVar18),
631: (SUB167(auVar50,0) >> 0x18) << 0x30) >> 0x30,0),
632: uVar18),(SUB165(auVar50,0) >> 0x10) << 0x20) >>
633: 0x20,0),SUB161(auVar1,0)),
634: (SUB163(auVar50,0) >> 8) << 0x10) >> 0x10,0),
635: (ushort)iVar3 & 0xff | SUB162(auVar1,0) << 8);
636: pauVar10[2] = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
637: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
638: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
639: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
640: CONCAT115(uVar32,CONCAT114(uVar32,CONCAT113(uVar35
641: ,auVar45))) >> 0x70,0),CONCAT113(uVar32,auVar45))
642: >> 0x68,0),CONCAT112(uVar48,auVar44)) >> 0x60,0),
643: CONCAT111(uVar31,auVar43)) >> 0x58,0),
644: CONCAT110(uVar31,Var42)) >> 0x50,0),
645: CONCAT19(uVar31,Var41)) >> 0x48,0),
646: CONCAT18(uVar47,uVar40)) >> 0x40,0),
647: (((ulong)CONCAT16(uVar32,CONCAT15(uVar31,uVar17))
648: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
649: (uVar39 >> 0x18) << 0x30) >> 0x30,0),
650: (((uint6)uVar17 & 0xff0000) >> 0x10) << 0x28) >>
651: 0x28,0),(uVar38 >> 0x10) << 0x20) >> 0x20,0),
652: ((uVar16 & 0xff00) >> 8) << 0x18) >> 0x18,0),
653: (uVar37 >> 8) << 0x10) >> 0x10,0),
654: CONCAT11(uVar29,uVar46));
655: pauVar10[3][0] = uVar49;
656: pauVar10[3][1] = uVar33;
657: pauVar10[3][2] = uVar33;
658: pauVar10[3][3] = uVar33;
659: pauVar10[3][4] = uVar23;
660: pauVar10[3][5] = uVar34;
661: pauVar10[3][6] = uVar34;
662: pauVar10[3][7] = uVar34;
663: pauVar10[3][8] = uVar25;
664: pauVar10[3][9] = uVar35;
665: pauVar10[3][10] = uVar35;
666: pauVar10[3][0xb] = uVar35;
667: pauVar10[3][0xc] = (char)((uint)iVar6 >> 0x18);
668: pauVar10[3][0xd] = uVar36;
669: pauVar10[3][0xe] = uVar36;
670: pauVar10[3][0xf] = uVar36;
671: pauVar10 = pauVar10[4];
672: } while (uVar14 < uVar2 >> 4);
673: pauVar9 = (undefined (*) [16])(*pauVar9 + (ulong)uVar15 * 4);
674: uVar14 = uVar15;
675: if (uVar2 != uVar15) {
676: code_r0x0012b2eb:
677: uVar18 = (*pauVar13)[uVar14];
678: (*pauVar9)[0] = 0xff;
679: (*pauVar9)[3] = uVar18;
680: (*pauVar9)[2] = uVar18;
681: (*pauVar9)[1] = uVar18;
682: if (uVar14 + 1 < uVar2) {
683: uVar18 = (*pauVar13)[uVar14 + 1];
684: (*pauVar9)[4] = 0xff;
685: (*pauVar9)[7] = uVar18;
686: (*pauVar9)[6] = uVar18;
687: (*pauVar9)[5] = uVar18;
688: if (uVar14 + 2 < uVar2) {
689: uVar18 = (*pauVar13)[uVar14 + 2];
690: (*pauVar9)[8] = 0xff;
691: (*pauVar9)[0xb] = uVar18;
692: (*pauVar9)[10] = uVar18;
693: (*pauVar9)[9] = uVar18;
694: if (uVar14 + 3 < uVar2) {
695: uVar18 = (*pauVar13)[uVar14 + 3];
696: (*pauVar9)[0xc] = 0xff;
697: (*pauVar9)[0xf] = uVar18;
698: (*pauVar9)[0xe] = uVar18;
699: (*pauVar9)[0xd] = uVar18;
700: if (uVar14 + 4 < uVar2) {
701: uVar18 = (*pauVar13)[uVar14 + 4];
702: pauVar9[1][0] = 0xff;
703: pauVar9[1][3] = uVar18;
704: pauVar9[1][2] = uVar18;
705: pauVar9[1][1] = uVar18;
706: if (uVar14 + 5 < uVar2) {
707: uVar18 = (*pauVar13)[uVar14 + 5];
708: pauVar9[1][4] = 0xff;
709: pauVar9[1][7] = uVar18;
710: pauVar9[1][6] = uVar18;
711: pauVar9[1][5] = uVar18;
712: if (uVar14 + 6 < uVar2) {
713: uVar18 = (*pauVar13)[uVar14 + 6];
714: pauVar9[1][8] = 0xff;
715: pauVar9[1][0xb] = uVar18;
716: pauVar9[1][10] = uVar18;
717: pauVar9[1][9] = uVar18;
718: if (uVar14 + 7 < uVar2) {
719: uVar18 = (*pauVar13)[uVar14 + 7];
720: pauVar9[1][0xc] = 0xff;
721: pauVar9[1][0xf] = uVar18;
722: pauVar9[1][0xe] = uVar18;
723: pauVar9[1][0xd] = uVar18;
724: if (uVar14 + 8 < uVar2) {
725: uVar18 = (*pauVar13)[uVar14 + 8];
726: pauVar9[2][0] = 0xff;
727: pauVar9[2][3] = uVar18;
728: pauVar9[2][2] = uVar18;
729: pauVar9[2][1] = uVar18;
730: if (uVar14 + 9 < uVar2) {
731: uVar18 = (*pauVar13)[uVar14 + 9];
732: pauVar9[2][4] = 0xff;
733: pauVar9[2][7] = uVar18;
734: pauVar9[2][6] = uVar18;
735: pauVar9[2][5] = uVar18;
736: if (uVar14 + 10 < uVar2) {
737: uVar18 = (*pauVar13)[uVar14 + 10];
738: pauVar9[2][8] = 0xff;
739: pauVar9[2][0xb] = uVar18;
740: pauVar9[2][10] = uVar18;
741: pauVar9[2][9] = uVar18;
742: if (uVar14 + 0xb < uVar2) {
743: uVar18 = (*pauVar13)[uVar14 + 0xb];
744: pauVar9[2][0xc] = 0xff;
745: pauVar9[2][0xf] = uVar18;
746: pauVar9[2][0xe] = uVar18;
747: pauVar9[2][0xd] = uVar18;
748: if (uVar14 + 0xc < uVar2) {
749: uVar18 = (*pauVar13)[uVar14 + 0xc];
750: pauVar9[3][0] = 0xff;
751: pauVar9[3][3] = uVar18;
752: pauVar9[3][2] = uVar18;
753: pauVar9[3][1] = uVar18;
754: if (uVar14 + 0xd < uVar2) {
755: uVar18 = (*pauVar13)[uVar14 + 0xd];
756: pauVar9[3][4] = 0xff;
757: pauVar9[3][7] = uVar18;
758: pauVar9[3][6] = uVar18;
759: pauVar9[3][5] = uVar18;
760: if (uVar14 + 0xe < uVar2) {
761: uVar18 = (*pauVar13)[uVar14 + 0xe];
762: pauVar9[3][8] = 0xff;
763: pauVar9[3][0xb] = uVar18;
764: pauVar9[3][10] = uVar18;
765: pauVar9[3][9] = uVar18;
766: }
767: }
768: }
769: }
770: }
771: }
772: }
773: }
774: }
775: }
776: }
777: }
778: }
779: }
780: }
781: goto code_r0x0012b220;
782: code_r0x0012b951:
783: uVar14 = 0;
784: pauVar10 = pauVar13;
785: pauVar11 = pauVar9;
786: do {
787: auVar1 = *pauVar10;
788: uVar14 = uVar14 + 1;
789: pauVar10 = pauVar10[1];
790: uVar22 = SUB161(auVar1 >> 0x38,0);
791: uVar20 = SUB161(auVar1 >> 0x30,0);
792: uVar18 = SUB161(auVar1 >> 0x28,0);
793: uVar25 = SUB161(auVar1 >> 0x20,0);
794: uVar23 = SUB161(auVar1 >> 0x18,0);
795: uVar21 = SUB161(auVar1 >> 0x10,0);
796: uVar19 = SUB161(auVar1 >> 8,0);
797: auVar50 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
798: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
799: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
800: (SUB163(CONCAT214(SUB162(CONCAT115(uVar22,
801: CONCAT114(uVar22,SUB1614(auVar1,0))) >> 0x70,0),
802: CONCAT113(uVar20,SUB1613(auVar1,0))) >> 0x68,0),
803: CONCAT112(uVar20,SUB1612(auVar1,0))) >> 0x60,0),
804: CONCAT111(uVar18,SUB1611(auVar1,0))) >> 0x58,0),
805: CONCAT110(uVar18,SUB1610(auVar1,0))) >> 0x50,0),
806: CONCAT19(uVar25,SUB169(auVar1,0))) >> 0x48,0),
807: CONCAT18(uVar25,SUB168(auVar1,0))) >> 0x40,0),
808: uVar23)) << 0x38) >> 0x30,0),uVar21)) << 0x28) >>
809: 0x20,0),uVar19),(SUB163(auVar1,0) >> 8) << 0x10)
810: >> 0x10,0),SUB161(auVar1,0))) << 8;
811: uVar24 = SUB161(auVar1 >> 0x40,0);
812: uVar26 = SUB161(auVar1 >> 0x48,0);
813: uVar37 = CONCAT12(uVar26,CONCAT11(uVar24,uVar24));
814: uVar27 = SUB161(auVar1 >> 0x50,0);
815: uVar38 = CONCAT14(uVar27,CONCAT13(uVar26,uVar37));
816: uVar28 = SUB161(auVar1 >> 0x58,0);
817: uVar39 = CONCAT16(uVar28,CONCAT15(uVar27,uVar38));
818: uVar40 = CONCAT17(uVar28,uVar39);
819: uVar29 = SUB161(auVar1 >> 0x60,0);
820: Var41 = CONCAT18(uVar29,uVar40);
821: Var42 = CONCAT19(uVar29,Var41);
822: uVar30 = SUB161(auVar1 >> 0x68,0);
823: auVar43 = CONCAT110(uVar30,Var42);
824: auVar44 = CONCAT111(uVar30,auVar43);
825: uVar31 = SUB161(auVar1 >> 0x70,0);
826: auVar45 = CONCAT112(uVar31,auVar44);
827: uVar32 = SUB161(auVar1 >> 0x78,0);
828: uVar16 = CONCAT12(uVar26,CONCAT11((char)iVar5,uVar24));
829: uVar17 = CONCAT14(uVar27,CONCAT13((char)((uint)iVar5 >> 8),uVar16));
830: pauVar11[1][0] = uVar25;
831: pauVar11[1][1] = uVar25;
832: pauVar11[1][2] = uVar25;
833: pauVar11[1][3] = (char)iVar4;
834: pauVar11[1][4] = uVar18;
835: pauVar11[1][5] = uVar18;
836: pauVar11[1][6] = uVar18;
837: pauVar11[1][7] = (char)((uint)iVar4 >> 8);
838: pauVar11[1][8] = uVar20;
839: pauVar11[1][9] = uVar20;
840: pauVar11[1][10] = uVar20;
841: pauVar11[1][0xb] = (char)((uint)iVar4 >> 0x10);
842: pauVar11[1][0xc] = uVar22;
843: pauVar11[1][0xd] = uVar22;
844: pauVar11[1][0xe] = uVar22;
845: pauVar11[1][0xf] = (char)((uint)iVar4 >> 0x18);
846: *pauVar11 = CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
847: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
848: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
849: (CONCAT214(SUB162(CONCAT115((char)((uint)iVar3 >>
850: 0x18),
851: CONCAT114(uVar23,
852: SUB1614(auVar50,0))) >> 0x70,0),
853: CONCAT113(uVar23,SUB1613(auVar50,0))) >> 0x68,0),
854: CONCAT112(uVar23,SUB1612(auVar50,0))) >> 0x60,0),
855: CONCAT111((char)((uint)iVar3 >> 0x10),
856: SUB1611(auVar50,0))) >> 0x58,0),
857: CONCAT110(uVar21,SUB1610(auVar50,0))) >> 0x50,0),
858: CONCAT19(uVar21,SUB169(auVar50,0))) >> 0x48,0),
859: CONCAT18(uVar21,SUB168(auVar50,0))) >> 0x40,0),
860: (char)((uint)iVar3 >> 8)),
861: (SUB167(auVar50,0) >> 0x18) << 0x30) >> 0x30,0),
862: uVar19),(SUB165(auVar50,0) >> 0x10) << 0x20) >>
863: 0x20,0),(char)iVar3),
864: (SUB163(auVar50,0) >> 8) << 0x10) >> 0x10,0),
865: SUB162(auVar1,0) & 0xff | SUB162(auVar1,0) << 8);
866: pauVar11[2] = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
867: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
868: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
869: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
870: CONCAT115((char)((uint)iVar5 >> 0x18),
871: CONCAT114(uVar28,CONCAT113(uVar31,
872: auVar45))) >> 0x70,0),CONCAT113(uVar28,auVar45))
873: >> 0x68,0),CONCAT112(uVar28,auVar44)) >> 0x60,0),
874: CONCAT111(uVar51,auVar43)) >> 0x58,0),
875: CONCAT110(uVar27,Var42)) >> 0x50,0),
876: CONCAT19(uVar27,Var41)) >> 0x48,0),
877: CONCAT18(uVar27,uVar40)) >> 0x40,0),
878: (((ulong)CONCAT16(uVar28,CONCAT15(uVar51,uVar17))
879: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
880: (uVar39 >> 0x18) << 0x30) >> 0x30,0),
881: (((uint6)uVar17 & 0xff0000) >> 0x10) << 0x28) >>
882: 0x28,0),(uVar38 >> 0x10) << 0x20) >> 0x20,0),
883: ((uVar16 & 0xff00) >> 8) << 0x18) >> 0x18,0),
884: (uVar37 >> 8) << 0x10) >> 0x10,0),
885: CONCAT11(uVar24,uVar24));
886: pauVar11[3][0] = uVar29;
887: pauVar11[3][1] = uVar29;
888: pauVar11[3][2] = uVar29;
889: pauVar11[3][3] = (char)iVar6;
890: pauVar11[3][4] = uVar30;
891: pauVar11[3][5] = uVar30;
892: pauVar11[3][6] = uVar30;
893: pauVar11[3][7] = (char)((uint)iVar6 >> 8);
894: pauVar11[3][8] = uVar31;
895: pauVar11[3][9] = uVar31;
896: pauVar11[3][10] = uVar31;
897: pauVar11[3][0xb] = (char)((uint)iVar6 >> 0x10);
898: pauVar11[3][0xc] = uVar32;
899: pauVar11[3][0xd] = uVar32;
900: pauVar11[3][0xe] = uVar32;
901: pauVar11[3][0xf] = (char)((uint)iVar6 >> 0x18);
902: pauVar11 = pauVar11[4];
903: } while (uVar14 < uVar2 >> 4);
904: pauVar9 = (undefined (*) [16])(*pauVar9 + (ulong)uVar15 * 4);
905: uVar14 = uVar15;
906: if (uVar2 != uVar15) {
907: code_r0x0012b9c8:
908: uVar19 = (*pauVar13)[uVar14];
909: (*pauVar9)[3] = 0xff;
910: (*pauVar9)[0] = uVar19;
911: (*pauVar9)[1] = uVar19;
912: (*pauVar9)[2] = uVar19;
913: if (uVar14 + 1 < uVar2) {
914: uVar19 = (*pauVar13)[uVar14 + 1];
915: (*pauVar9)[7] = 0xff;
916: (*pauVar9)[4] = uVar19;
917: (*pauVar9)[5] = uVar19;
918: (*pauVar9)[6] = uVar19;
919: if (uVar14 + 2 < uVar2) {
920: uVar19 = (*pauVar13)[uVar14 + 2];
921: (*pauVar9)[0xb] = 0xff;
922: (*pauVar9)[8] = uVar19;
923: (*pauVar9)[9] = uVar19;
924: (*pauVar9)[10] = uVar19;
925: if (uVar14 + 3 < uVar2) {
926: uVar19 = (*pauVar13)[uVar14 + 3];
927: (*pauVar9)[0xf] = 0xff;
928: (*pauVar9)[0xc] = uVar19;
929: (*pauVar9)[0xd] = uVar19;
930: (*pauVar9)[0xe] = uVar19;
931: if (uVar14 + 4 < uVar2) {
932: uVar19 = (*pauVar13)[uVar14 + 4];
933: pauVar9[1][3] = 0xff;
934: pauVar9[1][0] = uVar19;
935: pauVar9[1][1] = uVar19;
936: pauVar9[1][2] = uVar19;
937: if (uVar14 + 5 < uVar2) {
938: uVar19 = (*pauVar13)[uVar14 + 5];
939: pauVar9[1][7] = 0xff;
940: pauVar9[1][4] = uVar19;
941: pauVar9[1][5] = uVar19;
942: pauVar9[1][6] = uVar19;
943: if (uVar14 + 6 < uVar2) {
944: uVar19 = (*pauVar13)[uVar14 + 6];
945: pauVar9[1][0xb] = 0xff;
946: pauVar9[1][8] = uVar19;
947: pauVar9[1][9] = uVar19;
948: pauVar9[1][10] = uVar19;
949: if (uVar14 + 7 < uVar2) {
950: uVar19 = (*pauVar13)[uVar14 + 7];
951: pauVar9[1][0xf] = 0xff;
952: pauVar9[1][0xc] = uVar19;
953: pauVar9[1][0xd] = uVar19;
954: pauVar9[1][0xe] = uVar19;
955: if (uVar14 + 8 < uVar2) {
956: uVar19 = (*pauVar13)[uVar14 + 8];
957: pauVar9[2][3] = 0xff;
958: pauVar9[2][0] = uVar19;
959: pauVar9[2][1] = uVar19;
960: pauVar9[2][2] = uVar19;
961: if (uVar14 + 9 < uVar2) {
962: uVar19 = (*pauVar13)[uVar14 + 9];
963: pauVar9[2][7] = 0xff;
964: pauVar9[2][4] = uVar19;
965: pauVar9[2][5] = uVar19;
966: pauVar9[2][6] = uVar19;
967: if (uVar14 + 10 < uVar2) {
968: uVar19 = (*pauVar13)[uVar14 + 10];
969: pauVar9[2][0xb] = 0xff;
970: pauVar9[2][8] = uVar19;
971: pauVar9[2][9] = uVar19;
972: pauVar9[2][10] = uVar19;
973: if (uVar14 + 0xb < uVar2) {
974: uVar19 = (*pauVar13)[uVar14 + 0xb];
975: pauVar9[2][0xf] = 0xff;
976: pauVar9[2][0xc] = uVar19;
977: pauVar9[2][0xd] = uVar19;
978: pauVar9[2][0xe] = uVar19;
979: if (uVar14 + 0xc < uVar2) {
980: uVar19 = (*pauVar13)[uVar14 + 0xc];
981: pauVar9[3][3] = 0xff;
982: pauVar9[3][0] = uVar19;
983: pauVar9[3][1] = uVar19;
984: pauVar9[3][2] = uVar19;
985: if (uVar14 + 0xd < uVar2) {
986: uVar19 = (*pauVar13)[uVar14 + 0xd];
987: pauVar9[3][7] = 0xff;
988: pauVar9[3][4] = uVar19;
989: pauVar9[3][5] = uVar19;
990: pauVar9[3][6] = uVar19;
991: if (uVar14 + 0xe < uVar2) {
992: uVar19 = (*pauVar13)[uVar14 + 0xe];
993: pauVar9[3][0xb] = 0xff;
994: pauVar9[3][8] = uVar19;
995: pauVar9[3][9] = uVar19;
996: pauVar9[3][10] = uVar19;
997: }
998: }
999: }
1000: }
1001: }
1002: }
1003: }
1004: }
1005: }
1006: }
1007: }
1008: }
1009: }
1010: }
1011: }
1012: goto code_r0x0012b8f8;
1013: code_r0x0012b5e1:
1014: uVar14 = 0;
1015: pauVar10 = pauVar13;
1016: pauVar11 = pauVar9;
1017: do {
1018: auVar1 = *pauVar10;
1019: uVar14 = uVar14 + 1;
1020: pauVar10 = pauVar10[1];
1021: uVar22 = SUB161(auVar1 >> 0x38,0);
1022: uVar20 = SUB161(auVar1 >> 0x30,0);
1023: uVar18 = SUB161(auVar1 >> 0x28,0);
1024: uVar25 = SUB161(auVar1 >> 0x20,0);
1025: uVar23 = SUB161(auVar1 >> 0x18,0);
1026: uVar21 = SUB161(auVar1 >> 0x10,0);
1027: uVar19 = SUB161(auVar1 >> 8,0);
1028: auVar50 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(CONCAT121(SUB1612((ZEXT1116(CONCAT101(SUB1610((
1029: ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
1030: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
1031: (SUB163(CONCAT214(SUB162(CONCAT115(uVar22,
1032: CONCAT114(uVar22,SUB1614(auVar1,0))) >> 0x70,0),
1033: CONCAT113(uVar20,SUB1613(auVar1,0))) >> 0x68,0),
1034: CONCAT112(uVar20,SUB1612(auVar1,0))) >> 0x60,0),
1035: CONCAT111(uVar18,SUB1611(auVar1,0))) >> 0x58,0),
1036: CONCAT110(uVar18,SUB1610(auVar1,0))) >> 0x50,0),
1037: CONCAT19(uVar25,SUB169(auVar1,0))) >> 0x48,0),
1038: CONCAT18(uVar25,SUB168(auVar1,0))) >> 0x40,0),
1039: uVar23)) << 0x38) >> 0x30,0),uVar21)) << 0x28) >>
1040: 0x20,0),uVar19),(SUB163(auVar1,0) >> 8) << 0x10)
1041: >> 0x10,0),SUB161(auVar1,0))) << 8;
1042: uVar24 = SUB161(auVar1 >> 0x40,0);
1043: uVar26 = SUB161(auVar1 >> 0x48,0);
1044: uVar37 = CONCAT12(uVar26,CONCAT11(uVar24,uVar24));
1045: uVar27 = SUB161(auVar1 >> 0x50,0);
1046: uVar38 = CONCAT14(uVar27,CONCAT13(uVar26,uVar37));
1047: uVar28 = SUB161(auVar1 >> 0x58,0);
1048: uVar39 = CONCAT16(uVar28,CONCAT15(uVar27,uVar38));
1049: uVar40 = CONCAT17(uVar28,uVar39);
1050: uVar29 = SUB161(auVar1 >> 0x60,0);
1051: Var41 = CONCAT18(uVar29,uVar40);
1052: Var42 = CONCAT19(uVar29,Var41);
1053: uVar30 = SUB161(auVar1 >> 0x68,0);
1054: auVar43 = CONCAT110(uVar30,Var42);
1055: auVar44 = CONCAT111(uVar30,auVar43);
1056: uVar31 = SUB161(auVar1 >> 0x70,0);
1057: auVar45 = CONCAT112(uVar31,auVar44);
1058: uVar32 = SUB161(auVar1 >> 0x78,0);
1059: uVar16 = CONCAT12(uVar26,CONCAT11((char)iVar5,uVar24));
1060: uVar17 = CONCAT14(uVar27,CONCAT13((char)((uint)iVar5 >> 8),uVar16));
1061: pauVar11[1][0] = uVar25;
1062: pauVar11[1][1] = uVar25;
1063: pauVar11[1][2] = uVar25;
1064: pauVar11[1][3] = (char)iVar4;
1065: pauVar11[1][4] = uVar18;
1066: pauVar11[1][5] = uVar18;
1067: pauVar11[1][6] = uVar18;
1068: pauVar11[1][7] = (char)((uint)iVar4 >> 8);
1069: pauVar11[1][8] = uVar20;
1070: pauVar11[1][9] = uVar20;
1071: pauVar11[1][10] = uVar20;
1072: pauVar11[1][0xb] = (char)((uint)iVar4 >> 0x10);
1073: pauVar11[1][0xc] = uVar22;
1074: pauVar11[1][0xd] = uVar22;
1075: pauVar11[1][0xe] = uVar22;
1076: pauVar11[1][0xf] = (char)((uint)iVar4 >> 0x18);
1077: *pauVar11 = CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
1078: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
1079: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
1080: (CONCAT214(SUB162(CONCAT115((char)((uint)iVar3 >>
1081: 0x18),
1082: CONCAT114(uVar23,
1083: SUB1614(auVar50,0))) >> 0x70,0),
1084: CONCAT113(uVar23,SUB1613(auVar50,0))) >> 0x68,0),
1085: CONCAT112(uVar23,SUB1612(auVar50,0))) >> 0x60,0),
1086: CONCAT111((char)((uint)iVar3 >> 0x10),
1087: SUB1611(auVar50,0))) >> 0x58,0),
1088: CONCAT110(uVar21,SUB1610(auVar50,0))) >> 0x50,0),
1089: CONCAT19(uVar21,SUB169(auVar50,0))) >> 0x48,0),
1090: CONCAT18(uVar21,SUB168(auVar50,0))) >> 0x40,0),
1091: (char)((uint)iVar3 >> 8)),
1092: (SUB167(auVar50,0) >> 0x18) << 0x30) >> 0x30,0),
1093: uVar19),(SUB165(auVar50,0) >> 0x10) << 0x20) >>
1094: 0x20,0),(char)iVar3),
1095: (SUB163(auVar50,0) >> 8) << 0x10) >> 0x10,0),
1096: SUB162(auVar1,0) & 0xff | SUB162(auVar1,0) << 8);
1097: pauVar11[2] = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
1098: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
1099: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
1100: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
1101: CONCAT115((char)((uint)iVar5 >> 0x18),
1102: CONCAT114(uVar28,CONCAT113(uVar31,
1103: auVar45))) >> 0x70,0),CONCAT113(uVar28,auVar45))
1104: >> 0x68,0),CONCAT112(uVar28,auVar44)) >> 0x60,0),
1105: CONCAT111(uVar51,auVar43)) >> 0x58,0),
1106: CONCAT110(uVar27,Var42)) >> 0x50,0),
1107: CONCAT19(uVar27,Var41)) >> 0x48,0),
1108: CONCAT18(uVar27,uVar40)) >> 0x40,0),
1109: (((ulong)CONCAT16(uVar28,CONCAT15(uVar51,uVar17))
1110: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
1111: (uVar39 >> 0x18) << 0x30) >> 0x30,0),
1112: (((uint6)uVar17 & 0xff0000) >> 0x10) << 0x28) >>
1113: 0x28,0),(uVar38 >> 0x10) << 0x20) >> 0x20,0),
1114: ((uVar16 & 0xff00) >> 8) << 0x18) >> 0x18,0),
1115: (uVar37 >> 8) << 0x10) >> 0x10,0),
1116: CONCAT11(uVar24,uVar24));
1117: pauVar11[3][0] = uVar29;
1118: pauVar11[3][1] = uVar29;
1119: pauVar11[3][2] = uVar29;
1120: pauVar11[3][3] = (char)iVar6;
1121: pauVar11[3][4] = uVar30;
1122: pauVar11[3][5] = uVar30;
1123: pauVar11[3][6] = uVar30;
1124: pauVar11[3][7] = (char)((uint)iVar6 >> 8);
1125: pauVar11[3][8] = uVar31;
1126: pauVar11[3][9] = uVar31;
1127: pauVar11[3][10] = uVar31;
1128: pauVar11[3][0xb] = (char)((uint)iVar6 >> 0x10);
1129: pauVar11[3][0xc] = uVar32;
1130: pauVar11[3][0xd] = uVar32;
1131: pauVar11[3][0xe] = uVar32;
1132: pauVar11[3][0xf] = (char)((uint)iVar6 >> 0x18);
1133: pauVar11 = pauVar11[4];
1134: } while (uVar14 < uVar2 >> 4);
1135: pauVar9 = (undefined (*) [16])(*pauVar9 + (ulong)uVar15 * 4);
1136: uVar14 = uVar15;
1137: if (uVar2 != uVar15) {
1138: code_r0x0012b658:
1139: uVar19 = (*pauVar13)[uVar14];
1140: (*pauVar9)[3] = 0xff;
1141: (*pauVar9)[2] = uVar19;
1142: (*pauVar9)[1] = uVar19;
1143: (*pauVar9)[0] = uVar19;
1144: if (uVar14 + 1 < uVar2) {
1145: uVar19 = (*pauVar13)[uVar14 + 1];
1146: (*pauVar9)[7] = 0xff;
1147: (*pauVar9)[6] = uVar19;
1148: (*pauVar9)[5] = uVar19;
1149: (*pauVar9)[4] = uVar19;
1150: if (uVar14 + 2 < uVar2) {
1151: uVar19 = (*pauVar13)[uVar14 + 2];
1152: (*pauVar9)[0xb] = 0xff;
1153: (*pauVar9)[10] = uVar19;
1154: (*pauVar9)[9] = uVar19;
1155: (*pauVar9)[8] = uVar19;
1156: if (uVar14 + 3 < uVar2) {
1157: uVar19 = (*pauVar13)[uVar14 + 3];
1158: (*pauVar9)[0xf] = 0xff;
1159: (*pauVar9)[0xe] = uVar19;
1160: (*pauVar9)[0xd] = uVar19;
1161: (*pauVar9)[0xc] = uVar19;
1162: if (uVar14 + 4 < uVar2) {
1163: uVar19 = (*pauVar13)[uVar14 + 4];
1164: pauVar9[1][3] = 0xff;
1165: pauVar9[1][2] = uVar19;
1166: pauVar9[1][1] = uVar19;
1167: pauVar9[1][0] = uVar19;
1168: if (uVar14 + 5 < uVar2) {
1169: uVar19 = (*pauVar13)[uVar14 + 5];
1170: pauVar9[1][7] = 0xff;
1171: pauVar9[1][6] = uVar19;
1172: pauVar9[1][5] = uVar19;
1173: pauVar9[1][4] = uVar19;
1174: if (uVar14 + 6 < uVar2) {
1175: uVar19 = (*pauVar13)[uVar14 + 6];
1176: pauVar9[1][0xb] = 0xff;
1177: pauVar9[1][10] = uVar19;
1178: pauVar9[1][9] = uVar19;
1179: pauVar9[1][8] = uVar19;
1180: if (uVar14 + 7 < uVar2) {
1181: uVar19 = (*pauVar13)[uVar14 + 7];
1182: pauVar9[1][0xf] = 0xff;
1183: pauVar9[1][0xe] = uVar19;
1184: pauVar9[1][0xd] = uVar19;
1185: pauVar9[1][0xc] = uVar19;
1186: if (uVar14 + 8 < uVar2) {
1187: uVar19 = (*pauVar13)[uVar14 + 8];
1188: pauVar9[2][3] = 0xff;
1189: pauVar9[2][2] = uVar19;
1190: pauVar9[2][1] = uVar19;
1191: pauVar9[2][0] = uVar19;
1192: if (uVar14 + 9 < uVar2) {
1193: uVar19 = (*pauVar13)[uVar14 + 9];
1194: pauVar9[2][7] = 0xff;
1195: pauVar9[2][6] = uVar19;
1196: pauVar9[2][5] = uVar19;
1197: pauVar9[2][4] = uVar19;
1198: if (uVar14 + 10 < uVar2) {
1199: uVar19 = (*pauVar13)[uVar14 + 10];
1200: pauVar9[2][0xb] = 0xff;
1201: pauVar9[2][10] = uVar19;
1202: pauVar9[2][9] = uVar19;
1203: pauVar9[2][8] = uVar19;
1204: if (uVar14 + 0xb < uVar2) {
1205: uVar19 = (*pauVar13)[uVar14 + 0xb];
1206: pauVar9[2][0xf] = 0xff;
1207: pauVar9[2][0xe] = uVar19;
1208: pauVar9[2][0xd] = uVar19;
1209: pauVar9[2][0xc] = uVar19;
1210: if (uVar14 + 0xc < uVar2) {
1211: uVar19 = (*pauVar13)[uVar14 + 0xc];
1212: pauVar9[3][3] = 0xff;
1213: pauVar9[3][2] = uVar19;
1214: pauVar9[3][1] = uVar19;
1215: pauVar9[3][0] = uVar19;
1216: if (uVar14 + 0xd < uVar2) {
1217: uVar19 = (*pauVar13)[uVar14 + 0xd];
1218: pauVar9[3][7] = 0xff;
1219: pauVar9[3][6] = uVar19;
1220: pauVar9[3][5] = uVar19;
1221: pauVar9[3][4] = uVar19;
1222: if (uVar14 + 0xe < uVar2) {
1223: uVar19 = (*pauVar13)[uVar14 + 0xe];
1224: pauVar9[3][0xb] = 0xff;
1225: pauVar9[3][10] = uVar19;
1226: pauVar9[3][9] = uVar19;
1227: pauVar9[3][8] = uVar19;
1228: }
1229: }
1230: }
1231: }
1232: }
1233: }
1234: }
1235: }
1236: }
1237: }
1238: }
1239: }
1240: }
1241: }
1242: }
1243: goto code_r0x0012b588;
1244: }
1245: 
