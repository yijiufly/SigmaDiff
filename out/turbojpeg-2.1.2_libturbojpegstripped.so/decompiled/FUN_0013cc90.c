1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_0013cc90(long param_1,long param_2,long param_3,long *param_4)
5: 
6: {
7: undefined *puVar1;
8: long lVar2;
9: byte *pbVar3;
10: byte *pbVar4;
11: char cVar5;
12: char cVar16;
13: undefined auVar20 [16];
14: undefined auVar21 [16];
15: undefined (*pauVar22) [16];
16: ulong uVar23;
17: undefined (*pauVar24) [16];
18: undefined (*pauVar25) [16];
19: undefined (*pauVar26) [16];
20: long lVar27;
21: uint uVar28;
22: uint uVar29;
23: undefined (*pauVar30) [16];
24: uint uVar31;
25: int iVar32;
26: ushort uVar33;
27: uint3 uVar34;
28: int iVar35;
29: uint uVar36;
30: int iVar48;
31: int iVar50;
32: byte bVar52;
33: byte bVar53;
34: undefined auVar46 [16];
35: int iVar49;
36: int iVar51;
37: undefined auVar47 [16];
38: uint3 uVar54;
39: undefined8 uVar56;
40: int iVar59;
41: int iVar60;
42: undefined auVar58 [16];
43: uint uVar61;
44: uint uVar62;
45: undefined2 uVar67;
46: int iVar68;
47: int iVar71;
48: int iVar72;
49: undefined auVar63 [16];
50: undefined auVar64 [16];
51: unkuint10 Var69;
52: undefined auVar65 [16];
53: unkuint10 Var70;
54: short sVar73;
55: uint uVar74;
56: short sVar78;
57: short sVar79;
58: short sVar80;
59: ulong uVar76;
60: short sVar81;
61: short sVar83;
62: int iVar82;
63: short sVar84;
64: short sVar85;
65: undefined auVar86 [12];
66: short sVar87;
67: uint uVar88;
68: short sVar91;
69: short sVar92;
70: short sVar93;
71: short sVar94;
72: int iVar95;
73: int iVar96;
74: int iVar97;
75: int iVar98;
76: int iVar99;
77: int iVar101;
78: int iVar102;
79: int iVar103;
80: int iVar104;
81: int iVar106;
82: int iVar107;
83: int iVar108;
84: char cVar6;
85: char cVar7;
86: char cVar8;
87: char cVar9;
88: char cVar10;
89: char cVar11;
90: char cVar12;
91: char cVar13;
92: char cVar14;
93: char cVar15;
94: char cVar17;
95: char cVar18;
96: char cVar19;
97: uint5 uVar37;
98: uint7 uVar38;
99: undefined8 uVar39;
100: unkbyte9 Var40;
101: unkbyte10 Var41;
102: undefined auVar42 [11];
103: undefined auVar43 [12];
104: undefined auVar44 [13];
105: undefined auVar45 [14];
106: uint5 uVar55;
107: undefined auVar57 [12];
108: undefined auVar66 [13];
109: uint6 uVar75;
110: undefined auVar77 [14];
111: uint6 uVar89;
112: unkbyte10 Var90;
113: undefined auVar100 [16];
114: undefined auVar105 [12];
115: 
116: auVar21 = _DAT_0018d920;
117: auVar20 = _DAT_0016c610;
118: lVar2 = *param_4;
119: if (0 < *(int *)(param_1 + 0x19c)) {
120: lVar27 = 1;
121: do {
122: pbVar3 = *(byte **)(param_3 + -8 + lVar27 * 8);
123: pbVar4 = *(byte **)(lVar2 + -8 + lVar27 * 8);
124: bVar52 = *pbVar3;
125: pauVar26 = (undefined (*) [16])(pbVar3 + 1);
126: pauVar30 = (undefined (*) [16])(pbVar4 + 2);
127: *pbVar4 = bVar52;
128: pbVar4[1] = (byte)((int)((uint)bVar52 + (uint)bVar52 * 2 + 2 + (uint)pbVar3[1]) >> 2);
129: iVar32 = *(int *)(param_2 + 0x28);
130: uVar31 = iVar32 - 2;
131: if (uVar31 != 0) {
132: if ((pauVar30 < (undefined (*) [16])(pbVar3 + (ulong)uVar31 + 2) &&
133: pbVar3 < *pauVar30 + (ulong)uVar31 * 2) || (uVar31 < 0x10)) {
134: uVar23 = (ulong)(iVar32 - 3);
135: pauVar22 = pauVar26;
136: pauVar25 = pauVar30;
137: do {
138: pauVar24 = (undefined (*) [16])(*pauVar22 + 1);
139: iVar32 = (uint)(byte)(*pauVar22)[0] + (uint)(byte)(*pauVar22)[0] * 2;
140: (*pauVar25)[0] = (char)((int)(iVar32 + 1 + (uint)(byte)pauVar22[-1][0xf]) >> 2);
141: (*pauVar25)[1] = (char)((int)(iVar32 + 2 + (uint)(byte)(*pauVar24)[0]) >> 2);
142: pauVar22 = pauVar24;
143: pauVar25 = (undefined (*) [16])(*pauVar25 + 2);
144: } while (pauVar24 != (undefined (*) [16])(pbVar3 + uVar23 + 2));
145: }
146: else {
147: uVar28 = 0;
148: uVar29 = (iVar32 - 0x12U >> 4) + 1;
149: pauVar22 = pauVar26;
150: pauVar25 = pauVar30;
151: do {
152: auVar58 = *pauVar22;
153: uVar28 = uVar28 + 1;
154: uVar33 = (ushort)SUB161(auVar58 >> 0x40,0);
155: bVar52 = SUB161(auVar58 >> 0x70,0);
156: auVar45 = ZEXT1314(CONCAT112(bVar52,ZEXT1112(CONCAT110(SUB161(auVar58 >> 0x68,0),
157: (unkuint10)
158: CONCAT18(SUB161(auVar58 >> 0x60,0
159: ),(ulong)CONCAT16(
160: SUB161(auVar58 >> 0x58,0),
161: (uint6)CONCAT14(SUB161(auVar58 >> 0x50,0),
162: (uint)CONCAT12(SUB161(auVar58 >>
163: 0x48,0),
164: uVar33))))))));
165: bVar53 = SUB161(auVar58 >> 0x78,0);
166: auVar65 = CONCAT97((unkuint9)
167: SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411(
168: SUB154(CONCAT312(SUB153(CONCAT213(SUB152(CONCAT114
169: (SUB161(auVar58 >> 0x38,0),
170: ZEXT1314(SUB1613(auVar58,0))) >> 0x68,0),
171: CONCAT112(SUB161(auVar58 >> 0x30,0),
172: SUB1612(auVar58,0))) >> 0x60,0),
173: ZEXT1112(SUB1611(auVar58,0))) >> 0x58,0),
174: CONCAT110(SUB161(auVar58 >> 0x28,0),
175: SUB1610(auVar58,0))) >> 0x50,0),
176: (unkuint10)SUB169(auVar58,0)) >> 0x48,0),
177: CONCAT18(SUB161(auVar58 >> 0x20,0),
178: SUB168(auVar58,0))) >> 0x40,0),
179: SUB168(auVar58,0)) >> 0x38,0) &
180: SUB169((undefined  [16])0xffffffffffffffff >> 0x38,0),
181: (SUB167(auVar58,0) >> 0x18) << 0x30) &
182: (undefined  [16])0xffff000000000000;
183: auVar47 = CONCAT115(SUB1611(auVar65 >> 0x28,0),(SUB165(auVar58,0) >> 0x10) << 0x20);
184: auVar63 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar47 >> 0x20,0),SUB164(auVar58,0)) >>
185: 0x18,0) &
186: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0),
187: (SUB163(auVar58,0) >> 8) << 0x10);
188: sVar73 = SUB162(auVar21,0) * uVar33;
189: sVar78 = SUB162(auVar21 >> 0x10,0);
190: sVar91 = SUB162(auVar21 >> 0x20,0);
191: sVar79 = sVar91 * SUB142(auVar45 >> 0x20,0);
192: uVar75 = CONCAT24(sVar79,CONCAT22(sVar78 * SUB142(auVar45 >> 0x10,0),sVar73));
193: sVar92 = SUB162(auVar21 >> 0x30,0);
194: sVar80 = sVar92 * SUB142(auVar45 >> 0x30,0);
195: uVar39 = CONCAT26(sVar80,uVar75);
196: sVar93 = SUB162(auVar21 >> 0x40,0);
197: sVar81 = sVar93 * SUB142(auVar45 >> 0x40,0);
198: Var41 = CONCAT28(sVar81,uVar39);
199: sVar94 = SUB162(auVar21 >> 0x50,0);
200: sVar83 = sVar94 * SUB142(auVar45 >> 0x50,0);
201: sVar84 = SUB162(auVar21 >> 0x60,0);
202: sVar85 = SUB162(auVar21 >> 0x70,0);
203: auVar46 = pmulhw(ZEXT1516(CONCAT114(bVar53,auVar45)),auVar21);
204: sVar87 = SUB162(auVar21,0) * (SUB162(auVar58,0) & 0xff);
205: sVar91 = sVar91 * SUB162(auVar47 >> 0x20,0);
206: uVar89 = CONCAT24(sVar91,CONCAT22(sVar78 * SUB162(auVar63 >> 0x10,0),sVar87));
207: sVar92 = sVar92 * SUB162(auVar65 >> 0x30,0);
208: uVar56 = CONCAT26(sVar92,uVar89);
209: sVar93 = sVar93 * SUB162(auVar65 >> 0x40,0);
210: Var90 = CONCAT28(sVar93,uVar56);
211: sVar94 = sVar94 * SUB162(auVar65 >> 0x50,0);
212: auVar47 = *(undefined (*) [16])(pauVar22[-1] + 0xf);
213: auVar63 = pmulhw(CONCAT142(SUB1614(auVar63 >> 0x10,0),SUB162(auVar58,0)) &
214: (undefined  [16])0xffffffffffff00ff,auVar21);
215: iVar60 = SUB164(CONCAT214(SUB162(auVar63 >> 0x30,0),
216: CONCAT212(sVar92,CONCAT210(sVar94,Var90))) >> 0x60,0);
217: auVar58 = CONCAT610(SUB166(CONCAT412(iVar60,CONCAT210(SUB162(auVar63 >> 0x20,0),Var90))
218: >> 0x50,0),CONCAT28(sVar91,uVar56));
219: iVar72 = CONCAT22(SUB162(auVar63,0),sVar87);
220: iVar103 = SUB164(CONCAT214(SUB162(auVar46 >> 0x30,0),
221: CONCAT212(sVar80,CONCAT210(sVar83,Var41))) >> 0x60,0);
222: auVar100 = CONCAT610(SUB166(CONCAT412(iVar103,CONCAT210(SUB162(auVar46 >> 0x20,0),Var41)
223: ) >> 0x50,0),CONCAT28(sVar79,uVar39));
224: iVar99 = CONCAT22(SUB162(auVar46,0),sVar73);
225: iVar104 = CONCAT22(SUB162(auVar63 >> 0x40,0),sVar93);
226: uVar39 = CONCAT26(SUB162(auVar63 >> 0x50,0),CONCAT24(sVar94,iVar104));
227: auVar105 = CONCAT210(SUB162(auVar63 >> 0x60,0),
228: CONCAT28(sVar84 * SUB162(auVar65 >> 0x60,0),uVar39));
229: iVar95 = CONCAT22(SUB162(auVar46 >> 0x40,0),sVar81);
230: uVar56 = CONCAT26(SUB162(auVar46 >> 0x50,0),CONCAT24(sVar83,iVar95));
231: auVar86 = CONCAT210(SUB162(auVar46 >> 0x60,0),CONCAT28(sVar84 * (ushort)bVar52,uVar56));
232: auVar66 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
233: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
234: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
235: (CONCAT213(SUB152(CONCAT114(SUB161(auVar47 >> 0x38
236: ,0),
237: SUB1614(auVar47,0)) >>
238: 0x68,0),
239: CONCAT112(SUB161(auVar47 >> 0x30,0),
240: SUB1612(auVar47,0))) >> 0x60,
241: 0),SUB1612(auVar47,0)) >> 0x58,0),
242: CONCAT110(SUB161(auVar47 >> 0x28,0),
243: SUB1610(auVar47,0))) >> 0x50,0),
244: SUB1610(auVar47,0)) >> 0x48,0),
245: CONCAT18(SUB161(auVar47 >> 0x20,0),
246: SUB168(auVar47,0))) >> 0x40,0),
247: SUB168(auVar47,0)) >> 0x38,0) &
248: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
249: ,0) &
250: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
251: ,0) &
252: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
253: ,0) &
254: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
255: ,0),(SUB167(auVar47,0) >> 0x18) << 0x30) >>
256: 0x30,0),SUB166(auVar47,0)) >> 0x28,0) &
257: SUB1611((undefined  [16])0xffff00ffffffffff >>
258: 0x28,0),
259: (SUB165(auVar47,0) >> 0x10) << 0x20) >> 0x20,0),
260: SUB164(auVar47,0)) >> 0x18,0) &
261: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
262: auVar64 = CONCAT142(SUB1614(CONCAT133(auVar66,(SUB163(auVar47,0) >> 8) << 0x10) >> 0x10,
263: 0),SUB162(auVar47,0)) & (undefined  [16])0xffffffffffff00ff;
264: uVar88 = (uint)CONCAT12(SUB161(auVar47 >> 0x48,0),(ushort)SUB161(auVar47 >> 0x40,0));
265: uVar37 = CONCAT14(SUB161(auVar47 >> 0x50,0),uVar88);
266: uVar76 = (ulong)CONCAT16(SUB161(auVar47 >> 0x58,0),(uint6)uVar37);
267: auVar57 = ZEXT1112(CONCAT110(SUB161(auVar47 >> 0x68,0),
268: (unkuint10)CONCAT18(SUB161(auVar47 >> 0x60,0),uVar76)));
269: auVar77 = ZEXT1314(CONCAT112(SUB161(auVar47 >> 0x70,0),auVar57));
270: bVar52 = SUB161(auVar47 >> 0x78,0);
271: uVar36 = (uint)SUB132(auVar66 >> 0x28,0);
272: auVar43 = ZEXT1012(CONCAT28(SUB132(auVar66 >> 0x48,0),
273: (ulong)CONCAT24(SUB132(auVar66 >> 0x38,0),uVar36)));
274: uVar33 = SUB132(auVar66 >> 0x58,0);
275: uVar62 = SUB144(CONCAT212(SUB162(auVar64 >> 0x30,0),ZEXT1012(SUB1610(auVar64,0))) >>
276: 0x50,0);
277: auVar45 = CONCAT410(uVar62,CONCAT28(SUB162(auVar64 >> 0x20,0),SUB168(auVar64,0)));
278: iVar106 = (int)((ulong)uVar39 >> 0x20);
279: iVar107 = SUB124(auVar105 >> 0x40,0);
280: iVar108 = SUB164(CONCAT214(SUB162(auVar63 >> 0x70,0),
281: CONCAT212(sVar85 * SUB162(auVar65 >> 0x70,0),auVar105)) >>
282: 0x60,0);
283: iVar68 = SUB124(auVar43 >> 0x20,0) + iVar106 + 1;
284: iVar71 = SUB164(ZEXT1416(CONCAT212(uVar33,auVar43)) >> 0x40,0) + iVar107 + 1;
285: uVar61 = (int)(uVar36 + iVar104 + 1) >> 2;
286: iVar82 = SUB164(CONCAT106(CONCAT82(SUB168(auVar58 >> 0x40,0),SUB162(auVar63 >> 0x10,0)),
287: (uVar89 >> 0x10) << 0x20) >> 0x20,0);
288: iVar59 = SUB164(auVar58 >> 0x40,0);
289: iVar35 = (SUB164(auVar64,0) & 0xffff) + iVar72 + 1;
290: iVar48 = SUB164(CONCAT106((unkuint10)
291: SUB148(CONCAT68(SUB146(auVar45 >> 0x40,0),SUB168(auVar64,0))
292: >> 0x30,0) &
293: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0),
294: (SUB166(auVar64,0) >> 0x10) << 0x20) >> 0x20,0) + iVar82 + 1;
295: iVar50 = SUB164(ZEXT1416(auVar45) >> 0x40,0) + iVar59 + 1;
296: uVar36 = iVar35 >> 2;
297: iVar49 = iVar48 >> 2;
298: uVar39 = CONCAT44(iVar49,uVar36);
299: iVar51 = iVar50 >> 2;
300: auVar43 = CONCAT48(iVar51,uVar39);
301: uVar67 = (undefined2)(iVar68 >> 2);
302: auVar58 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214((short)(iVar68 >>
303: 0x12),
304: CONCAT212((short)(
305: iVar48 >> 0x12),auVar43)) >> 0x60,0),
306: CONCAT210(uVar67,SUB1210(auVar43,0))) >> 0x50,0),
307: CONCAT28((short)iVar49,uVar39)) >> 0x40,0),
308: (ulong)(uVar61 >> 0x10) << 0x30) &
309: (undefined  [16])0xffff000000000000;
310: sVar73 = (short)(iVar50 >> 0x12);
311: uVar23 = (ulong)CONCAT24(sVar73,(iVar71 >> 2) << 0x10) & 0xffff0000;
312: auVar58 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
313: (short)(iVar71 >> 0x12),
314: CONCAT212((short)((ulong)uVar61 >> 0x10),
315: SUB1612(auVar58,0))) >> 0x60,0),
316: CONCAT210(sVar73,SUB1610(auVar58,0))) >> 0x50,0),
317: CONCAT28((short)(iVar35 >> 0x12),SUB168(auVar58,0)
318: )) >> 0x40,0),(uVar23 >> 0x10) << 0x30) >>
319: 0x20,0) &
320: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
321: iVar51 << 0x10);
322: uVar74 = (uint)SUB142(auVar77 >> 0x40,0);
323: auVar66 = CONCAT112(bVar52,ZEXT1012(CONCAT28((short)((unkuint10)
324: SUB159(CONCAT114(bVar52,auVar77) >>
325: 0x30,0) >> 0x30),
326: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
327: CONCAT114(bVar52,auVar77) >> 0x10,0)) >> 0x40,0),
328: uVar74))));
329: Var69 = (unkuint10)
330: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar77 >> 0x30,0),
331: auVar57) >> 0x50,0),
332: CONCAT28(SUB122(auVar57 >> 0x20,0),uVar76)) >>
333: 0x40,0),uVar76) >> 0x30,0) &
334: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
335: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
336: iVar96 = (int)((ulong)uVar56 >> 0x20);
337: iVar97 = SUB124(auVar86 >> 0x40,0);
338: iVar98 = SUB164(CONCAT214(SUB162(auVar46 >> 0x70,0),
339: CONCAT212(sVar85 * (ushort)bVar53,auVar86)) >> 0x60,0);
340: iVar68 = SUB164(ZEXT1316(auVar66) >> 0x20,0) + iVar96 + 1;
341: iVar71 = SUB124(ZEXT912(SUB139(auVar66 >> 0x20,0)) >> 0x20,0) + iVar97 + 1;
342: uVar74 = (int)(uVar74 + iVar95 + 1) >> 2;
343: auVar47 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412
344: (SUB164(CONCAT214((short)((int)((uint)uVar33 +
345: iVar108 + 1) >> 2)
346: ,CONCAT212((short)(uVar23 >>
347: 0x10),
348: SUB1612(auVar58,0)))
349: >> 0x60,0),
350: CONCAT210(uVar67,SUB1610(auVar58,0))) >> 0x50,0),
351: CONCAT28((short)uVar61,SUB168(auVar58,0))) >> 0x40
352: ,0),(((ulong)CONCAT24(uVar67,((int)((uVar62 >>
353: 0x10) + iVar60
354: + 1) >> 2) <<
355: 0x10) & 0xffff0000)
356: >> 0x10) << 0x30) >> 0x30,0),
357: (SUB166(auVar58,0) >> 0x10) << 0x20) >> 0x20,0),
358: uVar36 & 0xffff | iVar49 << 0x10) & auVar20;
359: iVar101 = SUB164(CONCAT106(CONCAT82(SUB168(auVar100 >> 0x40,0),SUB162(auVar46 >> 0x10,0)
360: ),(uVar75 >> 0x10) << 0x20) >> 0x20,0);
361: iVar102 = SUB164(auVar100 >> 0x40,0);
362: iVar35 = (uVar88 & 0xffff) + iVar99 + 1;
363: iVar48 = SUB164(CONCAT106(Var69,(uint6)(uVar37 >> 0x10) << 0x20) >> 0x20,0) + iVar101 +
364: 1;
365: iVar50 = (int)(Var69 >> 0x10) + iVar102 + 1;
366: uVar62 = iVar35 >> 2;
367: iVar49 = iVar48 >> 2;
368: uVar39 = CONCAT44(iVar49,uVar62);
369: iVar51 = iVar50 >> 2;
370: auVar43 = CONCAT48(iVar51,uVar39);
371: uVar67 = (undefined2)(iVar68 >> 2);
372: auVar58 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214((short)(iVar68 >>
373: 0x12),
374: CONCAT212((short)(
375: iVar48 >> 0x12),auVar43)) >> 0x60,0),
376: CONCAT210(uVar67,SUB1210(auVar43,0))) >> 0x50,0),
377: CONCAT28((short)iVar49,uVar39)) >> 0x40,0),
378: (ulong)(uVar74 >> 0x10) << 0x30) &
379: (undefined  [16])0xffff000000000000;
380: sVar73 = (short)(iVar50 >> 0x12);
381: uVar23 = (ulong)CONCAT24(sVar73,(iVar71 >> 2) << 0x10) & 0xffff0000;
382: auVar65 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
383: (short)(iVar71 >> 0x12),
384: CONCAT212((short)((ulong)uVar74 >> 0x10),
385: SUB1612(auVar58,0))) >> 0x60,0),
386: CONCAT210(sVar73,SUB1610(auVar58,0))) >> 0x50,0),
387: CONCAT28((short)(iVar35 >> 0x12),SUB168(auVar58,0)
388: )) >> 0x40,0),(uVar23 >> 0x10) << 0x30) >>
389: 0x20,0) &
390: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
391: iVar51 << 0x10);
392: auVar58 = *(undefined (*) [16])(*pauVar22 + 1);
393: auVar66 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
394: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
395: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
396: (CONCAT213(SUB152(CONCAT114(SUB161(auVar58 >> 0x38
397: ,0),
398: SUB1614(auVar58,0)) >>
399: 0x68,0),
400: CONCAT112(SUB161(auVar58 >> 0x30,0),
401: SUB1612(auVar58,0))) >> 0x60,
402: 0),SUB1612(auVar58,0)) >> 0x58,0),
403: CONCAT110(SUB161(auVar58 >> 0x28,0),
404: SUB1610(auVar58,0))) >> 0x50,0),
405: SUB1610(auVar58,0)) >> 0x48,0),
406: CONCAT18(SUB161(auVar58 >> 0x20,0),
407: SUB168(auVar58,0))) >> 0x40,0),
408: SUB168(auVar58,0)) >> 0x38,0) &
409: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
410: ,0) &
411: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
412: ,0) &
413: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
414: ,0) &
415: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
416: ,0),(SUB167(auVar58,0) >> 0x18) << 0x30) >>
417: 0x30,0),SUB166(auVar58,0)) >> 0x28,0) &
418: SUB1611((undefined  [16])0xffff00ffffffffff >>
419: 0x28,0),
420: (SUB165(auVar58,0) >> 0x10) << 0x20) >> 0x20,0),
421: SUB164(auVar58,0)) >> 0x18,0) &
422: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
423: auVar46 = CONCAT142(SUB1614(CONCAT133(auVar66,(SUB163(auVar58,0) >> 8) << 0x10) >> 0x10,
424: 0),SUB162(auVar58,0)) & (undefined  [16])0xffffffffffff00ff;
425: uVar36 = (uint)CONCAT12(SUB161(auVar58 >> 0x48,0),(ushort)SUB161(auVar58 >> 0x40,0));
426: uVar55 = CONCAT14(SUB161(auVar58 >> 0x50,0),uVar36);
427: uVar76 = (ulong)CONCAT16(SUB161(auVar58 >> 0x58,0),(uint6)uVar55);
428: auVar86 = ZEXT1112(CONCAT110(SUB161(auVar58 >> 0x68,0),
429: (unkuint10)CONCAT18(SUB161(auVar58 >> 0x60,0),uVar76)));
430: auVar45 = ZEXT1314(CONCAT112(SUB161(auVar58 >> 0x70,0),auVar86));
431: bVar53 = SUB161(auVar58 >> 0x78,0);
432: auVar65 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412
433: (SUB164(CONCAT214((short)((int)((uint)bVar52 +
434: iVar98 + 1) >> 2),
435: CONCAT212((short)(uVar23 >> 0x10
436: ),SUB1612(
437: auVar65,0))) >> 0x60,0),
438: CONCAT210(uVar67,SUB1610(auVar65,0))) >> 0x50,0),
439: CONCAT28((short)uVar74,SUB168(auVar65,0))) >> 0x40
440: ,0),(((ulong)CONCAT24(uVar67,((int)(Var69 >> 0x30)
441: + iVar103 + 1 >> 2)
442: << 0x10) & 0xffff0000
443: ) >> 0x10) << 0x30) >> 0x30,0),
444: (SUB166(auVar65,0) >> 0x10) << 0x20) >> 0x20,0),
445: uVar62 & 0xffff | iVar49 << 0x10) & auVar20;
446: sVar73 = SUB162(auVar47,0);
447: cVar5 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar47,0) - (0xff < sVar73);
448: sVar73 = SUB162(auVar47 >> 0x10,0);
449: sVar78 = SUB162(auVar47 >> 0x20,0);
450: uVar34 = CONCAT12((0 < sVar78) * (sVar78 < 0xff) * SUB161(auVar47 >> 0x20,0) -
451: (0xff < sVar78),
452: CONCAT11((0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar47 >> 0x10,0) -
453: (0xff < sVar73),cVar5));
454: sVar73 = SUB162(auVar47 >> 0x30,0);
455: sVar78 = SUB162(auVar47 >> 0x40,0);
456: cVar6 = (0 < sVar78) * (sVar78 < 0xff) * SUB161(auVar47 >> 0x40,0) - (0xff < sVar78);
457: uVar37 = CONCAT14(cVar6,CONCAT13((0 < sVar73) * (sVar73 < 0xff) *
458: SUB161(auVar47 >> 0x30,0) - (0xff < sVar73),uVar34));
459: sVar73 = SUB162(auVar47 >> 0x50,0);
460: cVar7 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar47 >> 0x50,0) - (0xff < sVar73);
461: sVar73 = SUB162(auVar47 >> 0x60,0);
462: cVar8 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar47 >> 0x60,0) - (0xff < sVar73);
463: uVar38 = CONCAT16(cVar8,CONCAT15(cVar7,uVar37));
464: sVar73 = SUB162(auVar47 >> 0x70,0);
465: cVar9 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar47 >> 0x70,0) - (0xff < sVar73);
466: uVar39 = CONCAT17(cVar9,uVar38);
467: sVar73 = SUB162(auVar65,0);
468: cVar10 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar65,0) - (0xff < sVar73);
469: Var40 = CONCAT18(cVar10,uVar39);
470: sVar73 = SUB162(auVar65 >> 0x10,0);
471: cVar11 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar65 >> 0x10,0) - (0xff < sVar73);
472: Var41 = CONCAT19(cVar11,Var40);
473: sVar73 = SUB162(auVar65 >> 0x20,0);
474: cVar12 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar65 >> 0x20,0) - (0xff < sVar73);
475: auVar42 = CONCAT110(cVar12,Var41);
476: sVar73 = SUB162(auVar65 >> 0x30,0);
477: cVar13 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar65 >> 0x30,0) - (0xff < sVar73);
478: auVar43 = CONCAT111(cVar13,auVar42);
479: sVar73 = SUB162(auVar65 >> 0x40,0);
480: cVar14 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar65 >> 0x40,0) - (0xff < sVar73);
481: auVar44 = CONCAT112(cVar14,auVar43);
482: sVar73 = SUB162(auVar65 >> 0x50,0);
483: cVar15 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar65 >> 0x50,0) - (0xff < sVar73);
484: sVar93 = SUB162(auVar65 >> 0x60,0);
485: sVar94 = SUB162(auVar65 >> 0x70,0);
486: uVar62 = (uint)SUB132(auVar66 >> 0x28,0);
487: uVar33 = SUB132(auVar66 >> 0x58,0);
488: auVar77 = CONCAT212(uVar33,ZEXT1012(CONCAT28(SUB132(auVar66 >> 0x48,0),
489: (ulong)CONCAT24(SUB132(auVar66 >> 0x38,0),
490: uVar62))));
491: Var69 = (unkuint10)
492: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar46 >> 0x30,0),
493: SUB1612(auVar46,0)) >> 0x50,0)
494: ,CONCAT28(SUB162(auVar46 >> 0x20,0),
495: SUB168(auVar46,0))) >> 0x40,0),
496: SUB168(auVar46,0)) >> 0x30,0) &
497: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
498: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
499: iVar68 = SUB164(ZEXT1416(auVar77) >> 0x20,0) + iVar106 + 2;
500: iVar71 = SUB124(ZEXT1012(SUB1410(auVar77 >> 0x20,0)) >> 0x20,0) + iVar107 + 2;
501: uVar88 = (int)(uVar62 + iVar104 + 2) >> 2;
502: iVar35 = iVar72 + (SUB164(auVar46,0) & 0xffff) + 2;
503: iVar48 = iVar82 + SUB164(CONCAT106(Var69,(SUB166(auVar46,0) >> 0x10) << 0x20) >> 0x20,0)
504: + 2;
505: iVar50 = iVar59 + (int)(Var69 >> 0x10) + 2;
506: uVar62 = iVar35 >> 2;
507: iVar49 = iVar48 >> 2;
508: uVar56 = CONCAT44(iVar49,uVar62);
509: iVar51 = iVar50 >> 2;
510: auVar57 = CONCAT48(iVar51,uVar56);
511: uVar67 = (undefined2)(iVar68 >> 2);
512: auVar58 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214((short)(iVar68 >>
513: 0x12),
514: CONCAT212((short)(
515: iVar48 >> 0x12),auVar57)) >> 0x60,0),
516: CONCAT210(uVar67,SUB1210(auVar57,0))) >> 0x50,0),
517: CONCAT28((short)iVar49,uVar56)) >> 0x40,0),
518: (ulong)(uVar88 >> 0x10) << 0x30) &
519: (undefined  [16])0xffff000000000000;
520: sVar73 = (short)(iVar50 >> 0x12);
521: uVar23 = (ulong)CONCAT24(sVar73,(iVar71 >> 2) << 0x10) & 0xffff0000;
522: auVar58 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
523: (short)(iVar71 >> 0x12),
524: CONCAT212((short)((ulong)uVar88 >> 0x10),
525: SUB1612(auVar58,0))) >> 0x60,0),
526: CONCAT210(sVar73,SUB1610(auVar58,0))) >> 0x50,0),
527: CONCAT28((short)(iVar35 >> 0x12),SUB168(auVar58,0)
528: )) >> 0x40,0),(uVar23 >> 0x10) << 0x30) >>
529: 0x20,0) &
530: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
531: iVar51 << 0x10);
532: Var70 = (unkuint10)
533: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar45 >> 0x30,0),
534: auVar86) >> 0x50,0),
535: CONCAT28(SUB122(auVar86 >> 0x20,0),uVar76)) >>
536: 0x40,0),uVar76) >> 0x30,0) &
537: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
538: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
539: uVar61 = (uint)SUB142(auVar45 >> 0x40,0);
540: auVar66 = CONCAT112(bVar53,ZEXT1012(CONCAT28((short)((unkuint10)
541: SUB159(CONCAT114(bVar53,auVar45) >>
542: 0x30,0) >> 0x30),
543: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
544: CONCAT114(bVar53,auVar45) >> 0x10,0)) >> 0x40,0),
545: uVar61))));
546: iVar35 = (uVar36 & 0xffff) + iVar99 + 2;
547: iVar48 = SUB164(CONCAT106(Var70,(uint6)(uVar55 >> 0x10) << 0x20) >> 0x20,0) + iVar101 +
548: 2;
549: iVar51 = (int)(Var70 >> 0x10) + iVar102 + 2;
550: uVar36 = iVar35 >> 2;
551: iVar50 = iVar48 >> 2;
552: uVar56 = CONCAT44(iVar50,uVar36);
553: iVar72 = iVar51 >> 2;
554: auVar57 = CONCAT48(iVar72,uVar56);
555: auVar58 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412
556: (SUB164(CONCAT214((short)((int)((uint)uVar33 +
557: iVar108 + 2) >> 2)
558: ,CONCAT212((short)(uVar23 >>
559: 0x10),
560: SUB1612(auVar58,0)))
561: >> 0x60,0),
562: CONCAT210(uVar67,SUB1610(auVar58,0))) >> 0x50,0),
563: CONCAT28((short)uVar88,SUB168(auVar58,0))) >> 0x40
564: ,0),(((ulong)CONCAT24(uVar67,(iVar60 + (int)(Var69
565: >> 
566: 0x30) + 2 >> 2) << 0x10) & 0xffff0000) >> 0x10) <<
567: 0x30) >> 0x30,0),
568: (SUB166(auVar58,0) >> 0x10) << 0x20) >> 0x20,0),
569: uVar62 & 0xffff | iVar49 << 0x10) & auVar20;
570: iVar49 = SUB164(ZEXT1316(auVar66) >> 0x20,0) + iVar96 + 2;
571: iVar82 = SUB124(ZEXT912(SUB139(auVar66 >> 0x20,0)) >> 0x20,0) + iVar97 + 2;
572: uVar62 = (int)(uVar61 + iVar95 + 2) >> 2;
573: uVar67 = (undefined2)(iVar49 >> 2);
574: auVar47 = CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214((short)(iVar49 >>
575: 0x12),
576: CONCAT212((short)(
577: iVar48 >> 0x12),auVar57)) >> 0x60,0),
578: CONCAT210(uVar67,SUB1210(auVar57,0))) >> 0x50,0),
579: CONCAT28((short)iVar50,uVar56)) >> 0x40,0),
580: (ulong)(uVar62 >> 0x10) << 0x30) &
581: (undefined  [16])0xffff000000000000;
582: sVar73 = (short)(iVar51 >> 0x12);
583: uVar23 = (ulong)CONCAT24(sVar73,(iVar82 >> 2) << 0x10) & 0xffff0000;
584: auVar47 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
585: (short)(iVar82 >> 0x12),
586: CONCAT212((short)((ulong)uVar62 >> 0x10),
587: SUB1612(auVar47,0))) >> 0x60,0),
588: CONCAT210(sVar73,SUB1610(auVar47,0))) >> 0x50,0),
589: CONCAT28((short)(iVar35 >> 0x12),SUB168(auVar47,0)
590: )) >> 0x40,0),(uVar23 >> 0x10) << 0x30) >>
591: 0x20,0) &
592: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
593: iVar72 << 0x10);
594: auVar47 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412
595: (SUB164(CONCAT214((short)((int)((uint)bVar53 +
596: iVar98 + 2) >> 2),
597: CONCAT212((short)(uVar23 >> 0x10
598: ),SUB1612(
599: auVar47,0))) >> 0x60,0),
600: CONCAT210(uVar67,SUB1610(auVar47,0))) >> 0x50,0),
601: CONCAT28((short)uVar62,SUB168(auVar47,0))) >> 0x40
602: ,0),(((ulong)CONCAT24(uVar67,((int)(Var70 >> 0x30)
603: + iVar103 + 2 >> 2)
604: << 0x10) & 0xffff0000
605: ) >> 0x10) << 0x30) >> 0x30,0),
606: (SUB166(auVar47,0) >> 0x10) << 0x20) >> 0x20,0),
607: uVar36 & 0xffff | iVar50 << 0x10) & auVar20;
608: sVar73 = SUB162(auVar58,0);
609: cVar16 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar58,0) - (0xff < sVar73);
610: sVar73 = SUB162(auVar58 >> 0x10,0);
611: sVar78 = SUB162(auVar58 >> 0x20,0);
612: uVar54 = CONCAT12((0 < sVar78) * (sVar78 < 0xff) * SUB161(auVar58 >> 0x20,0) -
613: (0xff < sVar78),
614: CONCAT11((0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar58 >> 0x10,0) -
615: (0xff < sVar73),cVar16));
616: sVar73 = SUB162(auVar58 >> 0x30,0);
617: sVar78 = SUB162(auVar58 >> 0x40,0);
618: cVar17 = (0 < sVar78) * (sVar78 < 0xff) * SUB161(auVar58 >> 0x40,0) - (0xff < sVar78);
619: uVar55 = CONCAT14(cVar17,CONCAT13((0 < sVar73) * (sVar73 < 0xff) *
620: SUB161(auVar58 >> 0x30,0) - (0xff < sVar73),uVar54));
621: sVar73 = SUB162(auVar58 >> 0x50,0);
622: cVar18 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar58 >> 0x50,0) - (0xff < sVar73);
623: sVar73 = SUB162(auVar58 >> 0x60,0);
624: cVar19 = (0 < sVar73) * (sVar73 < 0xff) * SUB161(auVar58 >> 0x60,0) - (0xff < sVar73);
625: sVar73 = SUB162(auVar58 >> 0x70,0);
626: sVar78 = SUB162(auVar47,0);
627: sVar91 = SUB162(auVar47 >> 0x10,0);
628: sVar79 = SUB162(auVar47 >> 0x20,0);
629: sVar80 = SUB162(auVar47 >> 0x30,0);
630: sVar92 = SUB162(auVar47 >> 0x40,0);
631: sVar81 = SUB162(auVar47 >> 0x50,0);
632: sVar83 = SUB162(auVar47 >> 0x60,0);
633: sVar84 = SUB162(auVar47 >> 0x70,0);
634: pauVar25[1][0] = cVar10;
635: pauVar25[1][1] = (0 < sVar78) * (sVar78 < 0xff) * SUB161(auVar47,0) - (0xff < sVar78);
636: pauVar25[1][2] = cVar11;
637: pauVar25[1][3] =
638: (0 < sVar91) * (sVar91 < 0xff) * SUB161(auVar47 >> 0x10,0) - (0xff < sVar91);
639: pauVar25[1][4] = cVar12;
640: pauVar25[1][5] =
641: (0 < sVar79) * (sVar79 < 0xff) * SUB161(auVar47 >> 0x20,0) - (0xff < sVar79);
642: pauVar25[1][6] = cVar13;
643: pauVar25[1][7] =
644: (0 < sVar80) * (sVar80 < 0xff) * SUB161(auVar47 >> 0x30,0) - (0xff < sVar80);
645: pauVar25[1][8] = cVar14;
646: pauVar25[1][9] =
647: (0 < sVar92) * (sVar92 < 0xff) * SUB161(auVar47 >> 0x40,0) - (0xff < sVar92);
648: pauVar25[1][10] = cVar15;
649: pauVar25[1][0xb] =
650: (0 < sVar81) * (sVar81 < 0xff) * SUB161(auVar47 >> 0x50,0) - (0xff < sVar81);
651: pauVar25[1][0xc] =
652: (0 < sVar93) * (sVar93 < 0xff) * SUB161(auVar65 >> 0x60,0) - (0xff < sVar93);
653: pauVar25[1][0xd] =
654: (0 < sVar83) * (sVar83 < 0xff) * SUB161(auVar47 >> 0x60,0) - (0xff < sVar83);
655: pauVar25[1][0xe] =
656: (0 < sVar94) * (sVar94 < 0xff) * SUB161(auVar65 >> 0x70,0) - (0xff < sVar94);
657: pauVar25[1][0xf] =
658: (0 < sVar84) * (sVar84 < 0xff) * SUB161(auVar47 >> 0x70,0) - (0xff < sVar84);
659: *pauVar25 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(
660: CONCAT106(SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(
661: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
662: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
663: (CONCAT115((0 < sVar73) * (sVar73 < 0xff) *
664: SUB161(auVar58 >> 0x70,0) -
665: (0xff < sVar73),
666: CONCAT114(cVar9,CONCAT113(cVar15,
667: auVar44))) >> 0x70,0),CONCAT113(cVar19,auVar44))
668: >> 0x68,0),CONCAT112(cVar8,auVar43)) >> 0x60,0),
669: CONCAT111(cVar18,auVar42)) >> 0x58,0),
670: CONCAT110(cVar7,Var41)) >> 0x50,0),
671: CONCAT19(cVar17,Var40)) >> 0x48,0),
672: CONCAT18(cVar6,uVar39)) >> 0x40,0),
673: (((ulong)CONCAT16(cVar19,CONCAT15(cVar18,uVar55))
674: & 0xff000000) >> 0x18) << 0x38) >> 0x38,0),
675: (uVar38 >> 0x18) << 0x30) >> 0x30,0),
676: (((uint6)uVar55 & 0xff0000) >> 0x10) << 0x28) >>
677: 0x28,0),(uVar37 >> 0x10) << 0x20) >> 0x20,0),
678: ((uVar54 & 0xff00) >> 8) << 0x18) >> 0x18,0),
679: (uVar34 >> 8) << 0x10) >> 0x10,0),
680: CONCAT11(cVar16,cVar5));
681: pauVar22 = pauVar22[1];
682: pauVar25 = pauVar25[2];
683: } while (uVar28 < uVar29);
684: uVar28 = uVar29 * 0x10;
685: iVar35 = uVar31 + uVar29 * -0x10;
686: pbVar3 = *pauVar26 + uVar28;
687: puVar1 = *pauVar30 + (ulong)uVar28 * 2;
688: if (uVar31 != uVar28) {
689: iVar48 = (uint)*pbVar3 + (uint)*pbVar3 * 2;
690: *puVar1 = (char)((int)(iVar48 + 1 + (uint)pbVar3[-1]) >> 2);
691: puVar1[1] = (char)((int)(iVar48 + 2 + (uint)pbVar3[1]) >> 2);
692: if (iVar35 != 1) {
693: iVar48 = (uint)pbVar3[1] + (uint)pbVar3[1] * 2;
694: puVar1[2] = (char)((int)(iVar48 + 1 + (uint)*pbVar3) >> 2);
695: puVar1[3] = (char)((int)(iVar48 + 2 + (uint)pbVar3[2]) >> 2);
696: if (iVar35 != 2) {
697: iVar48 = (uint)pbVar3[2] + (uint)pbVar3[2] * 2;
698: puVar1[4] = (char)((int)(iVar48 + 1 + (uint)pbVar3[1]) >> 2);
699: puVar1[5] = (char)((int)(iVar48 + 2 + (uint)pbVar3[3]) >> 2);
700: if (iVar35 != 3) {
701: iVar48 = (uint)pbVar3[3] + (uint)pbVar3[3] * 2;
702: puVar1[6] = (char)((int)(iVar48 + 1 + (uint)pbVar3[2]) >> 2);
703: puVar1[7] = (char)((int)(iVar48 + 2 + (uint)pbVar3[4]) >> 2);
704: if (iVar35 != 4) {
705: iVar48 = (uint)pbVar3[4] + (uint)pbVar3[4] * 2;
706: puVar1[8] = (char)((int)(iVar48 + 1 + (uint)pbVar3[3]) >> 2);
707: puVar1[9] = (char)((int)(iVar48 + 2 + (uint)pbVar3[5]) >> 2);
708: if (iVar35 != 5) {
709: iVar48 = (uint)pbVar3[5] + (uint)pbVar3[5] * 2;
710: puVar1[10] = (char)((int)(iVar48 + 1 + (uint)pbVar3[4]) >> 2);
711: puVar1[0xb] = (char)((int)(iVar48 + 2 + (uint)pbVar3[6]) >> 2);
712: if (iVar35 != 6) {
713: iVar48 = (uint)pbVar3[6] + (uint)pbVar3[6] * 2;
714: puVar1[0xc] = (char)((int)(iVar48 + 1 + (uint)pbVar3[5]) >> 2);
715: puVar1[0xd] = (char)((int)(iVar48 + 2 + (uint)pbVar3[7]) >> 2);
716: if (iVar35 != 7) {
717: iVar48 = (uint)pbVar3[7] + (uint)pbVar3[7] * 2;
718: puVar1[0xe] = (char)((int)(iVar48 + 1 + (uint)pbVar3[6]) >> 2);
719: puVar1[0xf] = (char)((int)(iVar48 + 2 + (uint)pbVar3[8]) >> 2);
720: if (iVar35 != 8) {
721: iVar48 = (uint)pbVar3[8] + (uint)pbVar3[8] * 2;
722: puVar1[0x10] = (char)((int)(iVar48 + 1 + (uint)pbVar3[7]) >> 2);
723: puVar1[0x11] = (char)((int)(iVar48 + 2 + (uint)pbVar3[9]) >> 2);
724: if (iVar35 != 9) {
725: iVar48 = (uint)pbVar3[9] + (uint)pbVar3[9] * 2;
726: puVar1[0x12] = (char)((int)(iVar48 + 1 + (uint)pbVar3[8]) >> 2);
727: puVar1[0x13] = (char)((int)(iVar48 + 2 + (uint)pbVar3[10]) >> 2);
728: if (iVar35 != 10) {
729: iVar48 = (uint)pbVar3[10] + (uint)pbVar3[10] * 2;
730: puVar1[0x14] = (char)((int)(iVar48 + 1 + (uint)pbVar3[9]) >> 2);
731: puVar1[0x15] = (char)((int)(iVar48 + 2 + (uint)pbVar3[0xb]) >> 2);
732: if (iVar35 != 0xb) {
733: iVar48 = (uint)pbVar3[0xb] + (uint)pbVar3[0xb] * 2;
734: puVar1[0x16] = (char)((int)(iVar48 + 1 + (uint)pbVar3[10]) >> 2);
735: puVar1[0x17] = (char)((int)(iVar48 + 2 + (uint)pbVar3[0xc]) >> 2);
736: if (iVar35 != 0xc) {
737: iVar48 = (uint)pbVar3[0xc] + (uint)pbVar3[0xc] * 2;
738: puVar1[0x18] = (char)((int)(iVar48 + 1 + (uint)pbVar3[0xb]) >> 2
739: );
740: puVar1[0x19] = (char)((int)(iVar48 + 2 + (uint)pbVar3[0xd]) >> 2
741: );
742: if (iVar35 != 0xd) {
743: iVar48 = (uint)pbVar3[0xd] + (uint)pbVar3[0xd] * 2;
744: puVar1[0x1a] = (char)((int)(iVar48 + 1 + (uint)pbVar3[0xc]) >>
745: 2);
746: puVar1[0x1b] = (char)((int)(iVar48 + 2 + (uint)pbVar3[0xe]) >>
747: 2);
748: if (iVar35 != 0xe) {
749: iVar35 = (uint)pbVar3[0xe] + (uint)pbVar3[0xe] * 2;
750: puVar1[0x1c] = (char)((int)(iVar35 + 1 + (uint)pbVar3[0xd])
751: >> 2);
752: puVar1[0x1d] = (char)((int)(iVar35 + 2 + (uint)pbVar3[0xf])
753: >> 2);
754: }
755: }
756: }
757: }
758: }
759: }
760: }
761: }
762: }
763: }
764: }
765: }
766: }
767: }
768: }
769: uVar23 = (ulong)(iVar32 - 3);
770: }
771: pauVar30 = (undefined (*) [16])(*pauVar30 + uVar23 * 2 + 2);
772: pauVar26 = (undefined (*) [16])(*pauVar26 + uVar23 + 1);
773: }
774: bVar52 = (*pauVar26)[0];
775: bVar53 = pauVar26[-1][0xf];
776: (*pauVar30)[1] = bVar52;
777: (*pauVar30)[0] = (char)((int)((uint)bVar52 + (uint)bVar52 * 2 + 1 + (uint)bVar53) >> 2);
778: iVar32 = (int)lVar27;
779: lVar27 = lVar27 + 1;
780: } while (*(int *)(param_1 + 0x19c) != iVar32 && iVar32 <= *(int *)(param_1 + 0x19c));
781: }
782: return;
783: }
784: 
