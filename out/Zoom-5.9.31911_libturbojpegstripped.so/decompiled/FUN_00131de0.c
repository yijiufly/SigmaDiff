1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00131de0(long param_1,long param_2,long param_3,long *param_4)
5: 
6: {
7: long lVar1;
8: int6 iVar2;
9: long lVar3;
10: int6 iVar4;
11: long lVar5;
12: int6 iVar6;
13: long lVar7;
14: ulong uVar8;
15: ulong uVar9;
16: undefined auVar10 [16];
17: int iVar11;
18: byte *pbVar12;
19: byte *pbVar13;
20: byte *pbVar15;
21: uint uVar17;
22: int iVar18;
23: ulong uVar19;
24: byte *pbVar20;
25: long lVar21;
26: long lVar22;
27: uint uVar23;
28: uint uVar24;
29: int iVar26;
30: int iVar27;
31: undefined auVar25 [16];
32: ushort uVar29;
33: int iVar30;
34: uint uVar31;
35: undefined uVar40;
36: int iVar41;
37: undefined uVar45;
38: int iVar46;
39: byte bVar48;
40: undefined auVar36 [16];
41: uint uVar42;
42: uint uVar47;
43: undefined auVar37 [16];
44: undefined auVar38 [16];
45: undefined uVar50;
46: undefined auVar49 [16];
47: undefined uVar51;
48: undefined uVar57;
49: uint5 uVar52;
50: undefined uVar55;
51: undefined uVar56;
52: undefined uVar58;
53: uint7 uVar53;
54: undefined uVar60;
55: undefined uVar61;
56: short sVar62;
57: undefined uVar63;
58: unkuint10 Var59;
59: uint3 uVar64;
60: undefined auVar66 [14];
61: undefined uVar69;
62: undefined auVar67 [13];
63: unkuint10 Var68;
64: int iVar70;
65: uint uVar71;
66: undefined auVar72 [12];
67: int iVar74;
68: byte bVar75;
69: short sVar76;
70: short sVar77;
71: uint uVar78;
72: int iVar79;
73: uint uVar80;
74: undefined2 uVar81;
75: int iVar82;
76: int iVar83;
77: int iVar84;
78: uint uVar85;
79: int iVar86;
80: int iVar87;
81: uint uVar88;
82: int iVar89;
83: short sVar90;
84: int iVar91;
85: short sVar96;
86: short sVar98;
87: int iVar97;
88: short sVar99;
89: short sVar101;
90: int iVar100;
91: int iVar102;
92: short sVar103;
93: int iVar104;
94: short sVar107;
95: short sVar109;
96: int iVar108;
97: short sVar110;
98: short sVar112;
99: int iVar111;
100: int iVar113;
101: byte *pbVar14;
102: byte *pbVar16;
103: int iVar28;
104: undefined8 uVar32;
105: undefined auVar33 [12];
106: undefined auVar34 [14];
107: undefined auVar35 [16];
108: undefined uVar39;
109: undefined uVar43;
110: undefined uVar44;
111: ulong uVar54;
112: uint5 uVar65;
113: undefined auVar73 [16];
114: uint6 uVar92;
115: undefined8 uVar93;
116: unkbyte10 Var94;
117: undefined auVar95 [12];
118: uint6 uVar105;
119: unkbyte10 Var106;
120: 
121: auVar10 = _DAT_00189ce0;
122: lVar22 = 0;
123: lVar1 = *param_4;
124: if (0 < *(int *)(param_1 + 0x19c)) {
125: do {
126: pbVar14 = *(byte **)(param_3 + lVar22 * 8);
127: bVar48 = *pbVar14;
128: pbVar16 = *(byte **)(lVar1 + lVar22 * 8);
129: pbVar20 = pbVar14 + 1;
130: pbVar12 = pbVar16 + 2;
131: *pbVar16 = bVar48;
132: pbVar16[1] = (byte)((int)((uint)bVar48 + (uint)bVar48 * 2 + 2 + (uint)pbVar14[1]) >> 2);
133: iVar11 = *(int *)(param_2 + 0x28);
134: uVar23 = iVar11 - 2;
135: if (uVar23 != 0) {
136: uVar19 = (ulong)uVar23;
137: pbVar13 = pbVar12 + uVar19 * 2;
138: if (((pbVar12 < pbVar20 + uVar19 && pbVar20 < pbVar13 ||
139: pbVar12 < pbVar14 + uVar19 && pbVar14 < pbVar13) || uVar23 < 0x10) ||
140: (pbVar12 < pbVar14 + 2 + uVar19 && pbVar14 + 2 < pbVar13)) {
141: pbVar16 = pbVar20;
142: pbVar13 = pbVar12;
143: do {
144: pbVar15 = pbVar16 + 1;
145: iVar18 = (uint)*pbVar16 + (uint)*pbVar16 * 2;
146: *pbVar13 = (byte)((int)(iVar18 + 1 + (uint)pbVar16[-1]) >> 2);
147: pbVar13[1] = (byte)((int)(iVar18 + 2 + (uint)*pbVar15) >> 2);
148: pbVar16 = pbVar15;
149: pbVar13 = pbVar13 + 2;
150: } while (pbVar15 != pbVar14 + (ulong)(iVar11 - 3U) + 2);
151: lVar21 = (ulong)(iVar11 - 3U) + 1;
152: pbVar20 = pbVar20 + lVar21;
153: pbVar12 = pbVar12 + lVar21 * 2;
154: }
155: else {
156: lVar21 = 0;
157: uVar24 = 0;
158: uVar17 = uVar23 & 0xfffffff0;
159: do {
160: auVar37 = *(undefined (*) [16])(pbVar14 + lVar21 + 1);
161: uVar24 = uVar24 + 1;
162: uVar29 = (ushort)SUB161(auVar37 >> 0x40,0);
163: auVar34 = ZEXT1314(CONCAT112(SUB161(auVar37 >> 0x70,0),
164: ZEXT1112(CONCAT110(SUB161(auVar37 >> 0x68,0),
165: (unkuint10)
166: CONCAT18(SUB161(auVar37 >> 0x60,0),
167: (ulong)CONCAT16(SUB161(auVar37 
168: >> 0x58,0),
169: (uint6)CONCAT14(SUB161(auVar37 >> 0x50,0),
170: (uint)CONCAT12(SUB161(auVar37 >>
171: 0x48,0),
172: uVar29))))))));
173: bVar48 = SUB161(auVar37 >> 0x78,0);
174: auVar35 = ZEXT1516(CONCAT114(bVar48,auVar34));
175: auVar38 = CONCAT97((unkuint9)
176: SUB158(CONCAT78(SUB157(CONCAT69(SUB156(CONCAT510(SUB155(CONCAT411(
177: SUB154(CONCAT312(SUB153(CONCAT213(SUB152(CONCAT114
178: (SUB161(auVar37 >> 0x38,0),
179: ZEXT1314(SUB1613(auVar37,0))) >> 0x68,0),
180: CONCAT112(SUB161(auVar37 >> 0x30,0),
181: SUB1612(auVar37,0))) >> 0x60,0),
182: ZEXT1112(SUB1611(auVar37,0))) >> 0x58,0),
183: CONCAT110(SUB161(auVar37 >> 0x28,0),
184: SUB1610(auVar37,0))) >> 0x50,0),
185: (unkuint10)SUB169(auVar37,0)) >> 0x48,0),
186: CONCAT18(SUB161(auVar37 >> 0x20,0),
187: SUB168(auVar37,0))) >> 0x40,0),
188: SUB168(auVar37,0)) >> 0x38,0) &
189: SUB169((undefined  [16])0xffffffffffffffff >> 0x38,0),
190: (SUB167(auVar37,0) >> 0x18) << 0x30) &
191: (undefined  [16])0xffff000000000000;
192: auVar49 = CONCAT115(SUB1611(auVar38 >> 0x28,0),(SUB165(auVar37,0) >> 0x10) << 0x20);
193: auVar25 = CONCAT133(SUB1613(CONCAT124(SUB1612(auVar49 >> 0x20,0),SUB164(auVar37,0)) >>
194: 0x18,0) &
195: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0),
196: (SUB163(auVar37,0) >> 8) << 0x10);
197: auVar36 = pmulhw(auVar35,auVar10);
198: sVar90 = uVar29 * SUB162(auVar10,0);
199: sVar62 = SUB162(auVar10 >> 0x10,0);
200: sVar107 = SUB162(auVar10 >> 0x20,0);
201: sVar96 = SUB162(auVar35 >> 0x20,0) * sVar107;
202: uVar92 = CONCAT24(sVar96,CONCAT22(SUB142(auVar34 >> 0x10,0) * sVar62,sVar90));
203: sVar109 = SUB162(auVar10 >> 0x30,0);
204: sVar98 = SUB162(auVar35 >> 0x30,0) * sVar109;
205: uVar32 = CONCAT26(sVar98,uVar92);
206: sVar110 = SUB162(auVar10 >> 0x40,0);
207: sVar99 = SUB162(auVar35 >> 0x40,0) * sVar110;
208: Var94 = CONCAT28(sVar99,uVar32);
209: sVar112 = SUB162(auVar10 >> 0x50,0);
210: sVar101 = SUB162(auVar35 >> 0x50,0) * sVar112;
211: sVar76 = SUB162(auVar10 >> 0x60,0);
212: sVar77 = SUB162(auVar10 >> 0x70,0);
213: sVar103 = (SUB162(auVar37,0) & 0xff) * SUB162(auVar10,0);
214: sVar107 = SUB162(auVar49 >> 0x20,0) * sVar107;
215: uVar105 = CONCAT24(sVar107,CONCAT22(SUB162(auVar25 >> 0x10,0) * sVar62,sVar103));
216: sVar109 = SUB162(auVar38 >> 0x30,0) * sVar109;
217: uVar93 = CONCAT26(sVar109,uVar105);
218: sVar110 = SUB162(auVar38 >> 0x40,0) * sVar110;
219: Var106 = CONCAT28(sVar110,uVar93);
220: sVar112 = SUB162(auVar38 >> 0x50,0) * sVar112;
221: auVar49 = pmulhw(CONCAT142(SUB1614(auVar25 >> 0x10,0),SUB162(auVar37,0)) &
222: (undefined  [16])0xffffffffffff00ff,auVar10);
223: iVar74 = SUB164(CONCAT214(SUB162(auVar36 >> 0x30,0),
224: CONCAT212(sVar98,CONCAT210(sVar101,Var94))) >> 0x60,0);
225: auVar73 = CONCAT610(SUB166(CONCAT412(iVar74,CONCAT210(SUB162(auVar36 >> 0x20,0),Var94))
226: >> 0x50,0),CONCAT28(sVar96,uVar32));
227: iVar70 = CONCAT22(SUB162(auVar36,0),sVar90);
228: iVar28 = SUB164(CONCAT214(SUB162(auVar49 >> 0x30,0),
229: CONCAT212(sVar109,CONCAT210(sVar112,Var106))) >> 0x60,0);
230: auVar25 = CONCAT610(SUB166(CONCAT412(iVar28,CONCAT210(SUB162(auVar49 >> 0x20,0),Var106))
231: >> 0x50,0),CONCAT28(sVar107,uVar93));
232: iVar18 = CONCAT22(SUB162(auVar49,0),sVar103);
233: iVar104 = CONCAT22(SUB162(auVar49 >> 0x40,0),sVar110);
234: uVar32 = CONCAT26(SUB162(auVar49 >> 0x50,0),CONCAT24(sVar112,iVar104));
235: auVar33 = CONCAT210(SUB162(auVar49 >> 0x60,0),
236: CONCAT28(SUB162(auVar38 >> 0x60,0) * sVar76,uVar32));
237: auVar37 = *(undefined (*) [16])(pbVar14 + lVar21);
238: iVar91 = CONCAT22(SUB162(auVar36 >> 0x40,0),sVar99);
239: uVar93 = CONCAT26(SUB162(auVar36 >> 0x50,0),CONCAT24(sVar101,iVar91));
240: auVar95 = CONCAT210(SUB162(auVar36 >> 0x60,0),
241: CONCAT28(SUB162(auVar35 >> 0x60,0) * sVar76,uVar93));
242: uVar80 = (uint)CONCAT12(SUB161(auVar37 >> 0x48,0),(ushort)SUB161(auVar37 >> 0x40,0));
243: uVar52 = CONCAT14(SUB161(auVar37 >> 0x50,0),uVar80);
244: uVar54 = (ulong)CONCAT16(SUB161(auVar37 >> 0x58,0),(uint6)uVar52);
245: auVar72 = ZEXT1112(CONCAT110(SUB161(auVar37 >> 0x68,0),
246: (unkuint10)CONCAT18(SUB161(auVar37 >> 0x60,0),uVar54)));
247: auVar34 = ZEXT1314(CONCAT112(SUB161(auVar37 >> 0x70,0),auVar72));
248: bVar75 = SUB161(auVar37 >> 0x78,0);
249: auVar67 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
250: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
251: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
252: (CONCAT213(SUB152(CONCAT114(SUB161(auVar37 >> 0x38
253: ,0),
254: SUB1614(auVar37,0)) >>
255: 0x68,0),
256: CONCAT112(SUB161(auVar37 >> 0x30,0),
257: SUB1612(auVar37,0))) >> 0x60,
258: 0),SUB1612(auVar37,0)) >> 0x58,0),
259: CONCAT110(SUB161(auVar37 >> 0x28,0),
260: SUB1610(auVar37,0))) >> 0x50,0),
261: SUB1610(auVar37,0)) >> 0x48,0),
262: CONCAT18(SUB161(auVar37 >> 0x20,0),
263: SUB168(auVar37,0))) >> 0x40,0),
264: SUB168(auVar37,0)) >> 0x38,0) &
265: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
266: ,0) &
267: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
268: ,0) &
269: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
270: ,0) &
271: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
272: ,0),(SUB167(auVar37,0) >> 0x18) << 0x30) >>
273: 0x30,0),SUB166(auVar37,0)) >> 0x28,0) &
274: SUB1611((undefined  [16])0xffff00ffffffffff >>
275: 0x28,0),
276: (SUB165(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
277: SUB164(auVar37,0)) >> 0x18,0) &
278: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
279: auVar37 = CONCAT142(SUB1614(CONCAT133(auVar67,(SUB163(auVar37,0) >> 8) << 0x10) >> 0x10,
280: 0),SUB162(auVar37,0)) & (undefined  [16])0xffffffffffff00ff;
281: Var68 = (unkuint10)
282: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar37 >> 0x30,0),
283: SUB1612(auVar37,0)) >> 0x50,0)
284: ,CONCAT28(SUB162(auVar37 >> 0x20,0),
285: SUB168(auVar37,0))) >> 0x40,0),
286: SUB168(auVar37,0)) >> 0x30,0) &
287: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
288: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
289: uVar31 = (uint)SUB132(auVar67 >> 0x28,0);
290: uVar29 = SUB132(auVar67 >> 0x58,0);
291: auVar66 = CONCAT212(uVar29,ZEXT1012(CONCAT28(SUB132(auVar67 >> 0x48,0),
292: (ulong)CONCAT24(SUB132(auVar67 >> 0x38,0),
293: uVar31))));
294: iVar108 = (int)((ulong)uVar32 >> 0x20);
295: iVar111 = SUB124(auVar33 >> 0x40,0);
296: iVar113 = SUB164(CONCAT214(SUB162(auVar49 >> 0x70,0),
297: CONCAT212(SUB162(auVar38 >> 0x70,0) * sVar77,auVar33)) >>
298: 0x60,0);
299: iVar82 = SUB164(ZEXT1416(auVar66) >> 0x20,0) + iVar108 + 1;
300: iVar86 = SUB124(ZEXT1012(SUB1410(auVar66 >> 0x20,0)) >> 0x20,0) + iVar111 + 1;
301: uVar78 = (int)(uVar31 + iVar104 + 1) >> 2;
302: iVar83 = iVar82 >> 2;
303: iVar89 = (int)((uint)uVar29 + iVar113 + 1) >> 2;
304: iVar26 = SUB164(CONCAT106(CONCAT82(SUB168(auVar25 >> 0x40,0),SUB162(auVar49 >> 0x10,0)),
305: (uVar105 >> 0x10) << 0x20) >> 0x20,0);
306: iVar27 = SUB164(auVar25 >> 0x40,0);
307: iVar30 = (SUB164(auVar37,0) & 0xffff) + iVar18 + 1;
308: iVar41 = SUB164(CONCAT106(Var68,(SUB166(auVar37,0) >> 0x10) << 0x20) >> 0x20,0) + iVar26
309: + 1;
310: iVar46 = (int)(Var68 >> 0x10) + iVar27 + 1;
311: uVar31 = iVar30 >> 2;
312: uVar42 = iVar41 >> 2;
313: uVar32 = CONCAT44(uVar42,uVar31);
314: uVar47 = iVar46 >> 2;
315: auVar33 = CONCAT48(uVar47,uVar32);
316: uVar81 = (undefined2)iVar83;
317: uVar31 = uVar31 & 0xffff;
318: auVar37 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
319: (short)(iVar82 >> 0x12),
320: CONCAT212((short)(iVar41 >> 0x12),auVar33)) >>
321: 0x60,0),CONCAT210(uVar81,SUB1210(auVar33,0))) >>
322: 0x50,0),CONCAT28((short)uVar42,uVar32)) >> 0x40,0)
323: ,(ulong)(uVar78 >> 0x10) << 0x30) >> 0x20,0) &
324: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
325: uVar78 << 0x10);
326: uVar47 = uVar47 & 0xffff;
327: sVar62 = (short)(iVar46 >> 0x12);
328: uVar19 = (ulong)CONCAT24(sVar62,(iVar86 >> 2) << 0x10) & 0xffff0000;
329: lVar3 = (uVar19 >> 0x10) << 0x30;
330: iVar2 = (SUB166(auVar37,0) >> 0x10) << 0x20;
331: auVar37 = CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412
332: (SUB164(CONCAT214((short)(iVar86 >> 0x12),
333: CONCAT212((short)((ulong)uVar78
334: >> 0x10),
335: SUB1612(auVar37,0)))
336: >> 0x60,0),
337: CONCAT210(sVar62,SUB1610(auVar37,0))) >> 0x50,0),
338: CONCAT28((short)(iVar30 >> 0x12),SUB168(auVar37,0)
339: )) >> 0x40,0),lVar3) >> 0x30,0),iVar2) >>
340: 0x20,0),uVar47 << 0x10);
341: uVar88 = (uint)SUB142(auVar34 >> 0x40,0);
342: auVar67 = CONCAT112(bVar75,ZEXT1012(CONCAT28((short)((unkuint10)
343: SUB159(CONCAT114(bVar75,auVar34) >>
344: 0x30,0) >> 0x30),
345: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
346: CONCAT114(bVar75,auVar34) >> 0x10,0)) >> 0x40,0),
347: uVar88))));
348: Var59 = (unkuint10)
349: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar34 >> 0x30,0),
350: auVar72) >> 0x50,0),
351: CONCAT28(SUB122(auVar72 >> 0x20,0),uVar54)) >>
352: 0x40,0),uVar54) >> 0x30,0) &
353: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
354: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
355: uVar54 = (ulong)CONCAT24(uVar81,((int)(Var68 >> 0x30) + iVar28 + 1 >> 2) << 0x10) &
356: 0xffff0000;
357: lVar5 = (uVar54 >> 0x10) << 0x30;
358: iVar4 = (SUB166(auVar37,0) >> 0x10) << 0x20;
359: auVar37 = CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
360: (short)iVar89,
361: CONCAT212((short)(uVar19 >> 0x10),
362: SUB1612(auVar37,0))) >> 0x60,0),
363: CONCAT210(uVar81,SUB1610(auVar37,0))) >> 0x50,0),
364: CONCAT28((short)uVar78,SUB168(auVar37,0))) >> 0x40
365: ,0),lVar5) >> 0x30,0),iVar4) &
366: (undefined  [16])0xffffffff00000000;
367: iVar97 = (int)((ulong)uVar93 >> 0x20);
368: iVar100 = SUB124(auVar95 >> 0x40,0);
369: iVar102 = SUB164(CONCAT214(SUB162(auVar36 >> 0x70,0),
370: CONCAT212((ushort)bVar48 * sVar77,auVar95)) >> 0x60,0);
371: iVar46 = SUB164(ZEXT1316(auVar67) >> 0x20,0) + iVar97 + 1;
372: iVar86 = SUB124(ZEXT912(SUB139(auVar67 >> 0x20,0)) >> 0x20,0) + iVar100 + 1;
373: uVar71 = (int)(uVar88 + iVar91 + 1) >> 2;
374: iVar82 = iVar46 >> 2;
375: iVar30 = SUB164(CONCAT106(CONCAT82(SUB168(auVar73 >> 0x40,0),SUB162(auVar36 >> 0x10,0)),
376: (uVar92 >> 0x10) << 0x20) >> 0x20,0);
377: iVar41 = SUB164(auVar73 >> 0x40,0);
378: iVar79 = (uVar80 & 0xffff) + iVar70 + 1;
379: iVar84 = SUB164(CONCAT106(Var59,(uint6)(uVar52 >> 0x10) << 0x20) >> 0x20,0) + iVar30 + 1
380: ;
381: iVar87 = (int)(Var59 >> 0x10) + iVar41 + 1;
382: uVar80 = iVar79 >> 2;
383: uVar85 = iVar84 >> 2;
384: uVar32 = CONCAT44(uVar85,uVar80);
385: uVar88 = iVar87 >> 2;
386: auVar33 = CONCAT48(uVar88,uVar32);
387: uVar80 = uVar80 & 0xffff;
388: auVar38 = CONCAT124(SUB1612(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(SUB164(CONCAT214(
389: (short)(iVar46 >> 0x12),
390: CONCAT212((short)(iVar84 >> 0x12),auVar33)) >>
391: 0x60,0),CONCAT210((short)iVar82,SUB1210(auVar33,0)
392: )) >> 0x50,0),
393: CONCAT28((short)uVar85,uVar32)) >> 0x40,0),
394: (ulong)(uVar71 >> 0x10) << 0x30) >> 0x20,0) &
395: SUB1612((undefined  [16])0xffff000000000000 >> 0x20,0),
396: uVar71 << 0x10);
397: uVar88 = uVar88 & 0xffff;
398: sVar62 = (short)(iVar87 >> 0x12);
399: uVar8 = (ulong)CONCAT24(sVar62,(iVar86 >> 2) << 0x10) & 0xffff0000;
400: lVar7 = (uVar8 >> 0x10) << 0x30;
401: iVar6 = (SUB166(auVar38,0) >> 0x10) << 0x20;
402: uVar9 = (ulong)CONCAT24((short)iVar82,((int)(Var59 >> 0x30) + iVar74 + 1 >> 2) << 0x10)
403: & 0xffff0000;
404: uVar61 = (undefined)((uint6)iVar2 >> 0x28);
405: uVar69 = (undefined)iVar83;
406: uVar60 = (undefined)iVar82;
407: uVar57 = (undefined)((uint)iVar83 >> 8);
408: uVar63 = (undefined)((int)((uint)bVar75 + iVar102 + 1) >> 2);
409: uVar58 = (undefined)(uVar9 >> 0x10);
410: uVar44 = (undefined)(uVar54 >> 0x10);
411: uVar55 = (undefined)
412: (((SUB166(CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(
413: CONCAT412(SUB164(CONCAT214((short)(iVar86 >> 0x12)
414: ,CONCAT212((short)((
415: ulong)uVar71 >> 0x10),SUB1612(auVar38,0))) >> 0x60
416: ,0),CONCAT210(sVar62,SUB1610(auVar38,0))) >> 0x50,
417: 0),CONCAT28((short)(iVar79 >> 0x12),
418: SUB168(auVar38,0))) >> 0x40,0),lVar7)
419: >> 0x30,0),iVar6) >> 0x20,0),uVar88 << 0x10),0) >>
420: 0x10) << 0x20) >> 0x28);
421: uVar43 = (undefined)((uint6)iVar4 >> 0x28);
422: uVar50 = (undefined)uVar88;
423: uVar39 = (undefined)uVar47;
424: uVar45 = (undefined)(((uVar85 & 0xffff) << 0x10) >> 0x18);
425: uVar56 = (undefined)(uVar85 & 0xffff);
426: uVar51 = (undefined)uVar80;
427: auVar37 = ZEXT1116(CONCAT101(SUB1610((ZEXT916(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(
428: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
429: (SUB163(CONCAT214(SUB162(CONCAT115((char)(((uVar9 
430: >> 0x10) << 0x30) >> 0x38),
431: CONCAT114((char)((ulong)lVar5 >> 0x38),
432: SUB1614(auVar37,0))) >> 0x70,0),
433: CONCAT113(uVar58,SUB1613(auVar37,0))) >> 0x68,0),
434: CONCAT112(uVar44,SUB1612(auVar37,0))) >> 0x60,0),
435: CONCAT111(uVar55,SUB1611(auVar37,0))) >> 0x58,0),
436: CONCAT110(uVar43,SUB1610(auVar37,0))) >> 0x50,0),
437: CONCAT19(uVar50,SUB169(auVar37,0))) >> 0x48,0),
438: CONCAT18(uVar39,SUB168(auVar37,0))) >> 0x40,0),
439: uVar45)) << 0x38) >> 0x30,0),uVar56)) << 0x28 &
440: (undefined  [16])0xffffffff00000000;
441: uVar40 = (undefined)(uVar42 & 0xffff);
442: uVar54 = ((ulong)CONCAT14(uVar57,CONCAT13(uVar60,CONCAT12(uVar69,CONCAT11((char)((uint6)
443: iVar6 >> 0x28),uVar61)))) & 0xff00) << 0x10;
444: auVar37 = CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412(
445: SUB164(CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115
446: ((char)((uint)iVar82 >> 8),
447: CONCAT114(uVar45,SUB1614(auVar37,0))) >> 0x70,0),
448: CONCAT113(uVar57,SUB1613(auVar37,0))) >> 0x68,0),
449: CONCAT112((char)(((uVar42 & 0xffff) << 0x10) >>
450: 0x18),SUB1612(auVar37,0))) >> 0x60
451: ,0),CONCAT111(uVar60,SUB1611(auVar37,0))) >> 0x58,
452: 0),CONCAT110(uVar56,SUB1610(auVar37,0))) >> 0x50,0
453: ),CONCAT19(uVar69,SUB169(auVar37,0))) >> 0x48,0),
454: CONCAT18(uVar40,SUB168(auVar37,0))) >> 0x40,0),
455: (uVar54 >> 0x18) << 0x38) & (undefined  [16])0xff00000000000000;
456: uVar53 = CONCAT16(uVar55,CONCAT15((char)((ulong)lVar3 >> 0x38),
457: CONCAT14(uVar43,CONCAT13((char)(uVar8 >> 0x10),
458: CONCAT12(uVar50,CONCAT11((
459: char)(uVar19 >> 0x10),uVar39))))));
460: uVar19 = (ulong)uVar53;
461: uVar57 = (undefined)(uVar19 >> 0x10);
462: uVar55 = (undefined)(uVar19 >> 8);
463: auVar38 = ZEXT1516(CONCAT141(SUB1614((ZEXT1316(CONCAT121(SUB1612((ZEXT1116(CONCAT101(
464: SUB1610(CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(
465: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
466: (SUB163(CONCAT214(SUB162(CONCAT115((char)((ulong)
467: lVar7 >> 0x38),
468: CONCAT114((char)(uVar54 >> 0x18),
469: SUB1614(auVar37,0))) >> 0x70,0),
470: CONCAT113((char)(uVar19 >> 0x30),
471: SUB1613(auVar37,0))) >> 0x68,0),
472: CONCAT112((char)(uVar80 >> 8),SUB1612(auVar37,0)))
473: >> 0x60,0),
474: CONCAT111((char)(uVar19 >> 0x28),
475: SUB1611(auVar37,0))) >> 0x58,0),
476: CONCAT110(uVar61,SUB1610(auVar37,0))) >> 0x50,0),
477: CONCAT19((char)(uVar19 >> 0x20),SUB169(auVar37,0))
478: ) >> 0x48,0),
479: CONCAT18((char)(uVar31 >> 8),SUB168(auVar37,0)))
480: >> 0x40,0),(ulong)(uVar53 >> 0x18) << 0x38) >>
481: 0x30,0) & SUB1610((undefined  [16])
482: 0xffffffffffffffff >> 0x30,0) &
483: SUB1610((undefined  [16])0xffffffffffffffff >>
484: 0x30,0) &
485: SUB1610((undefined  [16])0xff00000000000000 >>
486: 0x30,0),uVar57)) << 0x28) >> 0x20,0),
487: uVar55)) << 0x18) >> 0x10,0),uVar39)) << 8;
488: uVar64 = CONCAT12(uVar69,CONCAT11(uVar44,uVar40));
489: uVar65 = CONCAT14(uVar56,CONCAT13((char)iVar89,uVar64));
490: auVar37 = *(undefined (*) [16])(pbVar14 + lVar21 + 2);
491: uVar45 = (undefined)(uVar19 >> 0x18);
492: uVar19 = (ulong)CONCAT16(uVar60,CONCAT15(uVar58,uVar65)) & 0xff000000;
493: auVar38 = ZEXT1516(CONCAT141(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT88(SUB168
494: (CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165
495: (CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(
496: SUB162(CONCAT115(uVar63,CONCAT114(uVar45,SUB1614(
497: auVar38,0))) >> 0x70,0),
498: CONCAT113(uVar60,SUB1613(auVar38,0))) >> 0x68,0),
499: CONCAT112((char)uVar71,SUB1612(auVar38,0))) >>
500: 0x60,0),CONCAT111(uVar58,SUB1611(auVar38,0))) >>
501: 0x58,0),CONCAT110(uVar57,SUB1610(auVar38,0))) >>
502: 0x50,0),CONCAT19(uVar56,SUB169(auVar38,0))) >>
503: 0x48,0),CONCAT18(uVar51,SUB168(auVar38,0))) >>
504: 0x40,0),(uVar19 >> 0x18) << 0x38) >> 0x20,0) &
505: SUB1612((undefined  [16])0xffffffffffffffff >>
506: 0x20,0) &
507: SUB1612((undefined  [16])0xff00000000000000 >>
508: 0x20,0) &
509: SUB1612((undefined  [16])0xffffff0000000000 >>
510: 0x20,0),((uVar64 & 0xff00) >> 8) << 0x18)
511: >> 0x18,0),(SUB163(auVar38,0) >> 8) << 0x10) >>
512: 0x10,0),uVar40)) << 8;
513: auVar67 = SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(SUB1610(CONCAT97((
514: unkuint9)SUB158(CONCAT78(SUB157(CONCAT69(SUB156(
515: CONCAT510(SUB155(CONCAT411(SUB154(CONCAT312(SUB153
516: (CONCAT213(SUB152(CONCAT114(SUB161(auVar37 >> 0x38
517: ,0),
518: SUB1614(auVar37,0)) >>
519: 0x68,0),
520: CONCAT112(SUB161(auVar37 >> 0x30,0),
521: SUB1612(auVar37,0))) >> 0x60,
522: 0),SUB1612(auVar37,0)) >> 0x58,0),
523: CONCAT110(SUB161(auVar37 >> 0x28,0),
524: SUB1610(auVar37,0))) >> 0x50,0),
525: SUB1610(auVar37,0)) >> 0x48,0),
526: CONCAT18(SUB161(auVar37 >> 0x20,0),
527: SUB168(auVar37,0))) >> 0x40,0),
528: SUB168(auVar37,0)) >> 0x38,0) &
529: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
530: ,0) &
531: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
532: ,0) &
533: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
534: ,0) &
535: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
536: ,0),(SUB167(auVar37,0) >> 0x18) << 0x30) >>
537: 0x30,0),SUB166(auVar37,0)) >> 0x28,0) &
538: SUB1611((undefined  [16])0xffff00ffffffffff >>
539: 0x28,0),
540: (SUB165(auVar37,0) >> 0x10) << 0x20) >> 0x20,0),
541: SUB164(auVar37,0)) >> 0x18,0) &
542: SUB1613((undefined  [16])0xffffffff00ffffff >> 0x18,0);
543: auVar25 = CONCAT142(SUB1614(CONCAT133(auVar67,(SUB163(auVar37,0) >> 8) << 0x10) >> 0x10,
544: 0),SUB162(auVar37,0)) & (undefined  [16])0xffffffffffff00ff;
545: uVar47 = (uint)CONCAT12(SUB161(auVar37 >> 0x48,0),(ushort)SUB161(auVar37 >> 0x40,0));
546: uVar52 = CONCAT14(SUB161(auVar37 >> 0x50,0),uVar47);
547: uVar54 = (ulong)CONCAT16(SUB161(auVar37 >> 0x58,0),(uint6)uVar52);
548: auVar33 = ZEXT1112(CONCAT110(SUB161(auVar37 >> 0x68,0),
549: (unkuint10)CONCAT18(SUB161(auVar37 >> 0x60,0),uVar54)));
550: auVar34 = ZEXT1314(CONCAT112(SUB161(auVar37 >> 0x70,0),auVar33));
551: bVar48 = SUB161(auVar37 >> 0x78,0);
552: Var59 = (unkuint10)
553: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB162(auVar25 >> 0x30,0),
554: SUB1612(auVar25,0)) >> 0x50,0)
555: ,CONCAT28(SUB162(auVar25 >> 0x20,0),
556: SUB168(auVar25,0))) >> 0x40,0),
557: SUB168(auVar25,0)) >> 0x30,0) &
558: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
559: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
560: uVar88 = (uint)SUB132(auVar67 >> 0x28,0);
561: uVar29 = SUB132(auVar67 >> 0x58,0);
562: auVar66 = CONCAT212(uVar29,ZEXT1012(CONCAT28(SUB132(auVar67 >> 0x48,0),
563: (ulong)CONCAT24(SUB132(auVar67 >> 0x38,0),
564: uVar88))));
565: uVar40 = (undefined)(iVar27 + (int)(Var59 >> 0x10) + 2 >> 2);
566: uVar44 = (undefined)
567: (iVar26 + SUB164(CONCAT106(Var59,(SUB166(auVar25,0) >> 0x10) << 0x20) >> 0x20,0
568: ) + 2 >> 2);
569: uVar80 = (uint)SUB142(auVar34 >> 0x40,0);
570: auVar67 = CONCAT112(bVar48,ZEXT1012(CONCAT28((short)((unkuint10)
571: SUB159(CONCAT114(bVar48,auVar34) >>
572: 0x30,0) >> 0x30),
573: (ulong)CONCAT24(SUB142(ZEXT1314(SUB1513(
574: CONCAT114(bVar48,auVar34) >> 0x10,0)) >> 0x40,0),
575: uVar80))));
576: Var68 = (unkuint10)
577: SUB148(CONCAT68(SUB146(CONCAT410(SUB144(CONCAT212(SUB142(auVar34 >> 0x30,0),
578: auVar33) >> 0x50,0),
579: CONCAT28(SUB122(auVar33 >> 0x20,0),uVar54)) >>
580: 0x40,0),uVar54) >> 0x30,0) &
581: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0) &
582: SUB1610((undefined  [16])0xffffffffffffffff >> 0x30,0);
583: uVar43 = (undefined)
584: (iVar30 + SUB164(CONCAT106(Var68,(uint6)(uVar52 >> 0x10) << 0x20) >> 0x20,0) +
585: 2 >> 2);
586: uVar39 = (undefined)(iVar74 + (int)(Var68 >> 0x30) + 2 >> 2);
587: uVar61 = (undefined)(SUB164(ZEXT1416(auVar66) >> 0x20,0) + iVar108 + 2 >> 2);
588: uVar50 = (undefined)(SUB164(ZEXT1316(auVar67) >> 0x20,0) + iVar97 + 2 >> 2);
589: uVar54 = (ulong)CONCAT13((char)(SUB124(ZEXT912(SUB139(auVar67 >> 0x20,0)) >> 0x20,0) +
590: iVar100 + 2 >> 2),
591: CONCAT12((char)(iVar41 + (int)(Var68 >> 0x10) + 2 >> 2),
592: CONCAT11((char)(SUB124(ZEXT1012(SUB1410(auVar66 >>
593: 0x20,0)) >>
594: 0x20,0) + iVar111 + 2 >> 2),
595: uVar40)));
596: uVar53 = CONCAT16(uVar50,CONCAT15(uVar39,CONCAT14(uVar43,CONCAT13((char)((int)((uint)
597: uVar29 + iVar113 + 2) >> 2),
598: CONCAT12(uVar61,CONCAT11((char)(iVar28 + (int)(
599: Var59 >> 0x30) + 2 >> 2),uVar44))))));
600: *(undefined (*) [16])(pbVar12 + lVar21 * 2) =
601: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
602: SUB169(CONCAT88(SUB168(CONCAT79(SUB167(CONCAT610(
603: SUB166(CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313
604: (SUB163(CONCAT214(SUB162(CONCAT115((char)((ulong)
605: uVar53 >> 0x18),
606: CONCAT114((char)(uVar19 >> 0x18),
607: SUB1614(auVar38,0))) >> 0x70,0),
608: CONCAT113((char)(uVar54 >> 8),SUB1613(auVar38,0)))
609: >> 0x68,0),CONCAT112(uVar55,SUB1612(auVar38,0)))
610: >> 0x60,0),CONCAT111(uVar61,SUB1611(auVar38,0)))
611: >> 0x58,0),
612: CONCAT110((char)((uint6)uVar65 >> 0x10),
613: SUB1610(auVar38,0))) >> 0x50,0),
614: CONCAT19((char)((int)(uVar88 + iVar104 + 2) >> 2),
615: SUB169(auVar38,0))) >> 0x48,0),
616: CONCAT18((char)uVar78,SUB168(auVar38,0))) >> 0x40,
617: 0),(((ulong)uVar53 & 0xff00) >> 8) << 0x38) >>
618: 0x38,0) & SUB169((undefined  [16])
619: 0xffffffffffffffff >> 0x38,0) &
620: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
621: ,0) &
622: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
623: ,0) &
624: SUB169((undefined  [16])0xffffffffffffffff >> 0x38
625: ,0),(SUB167(auVar38,0) >> 0x18) << 0x30) >>
626: 0x30,0),uVar40),
627: (SUB165(auVar38,0) >> 0x10) << 0x20) >> 0x20,0) &
628: SUB1612((undefined  [16])0xffffffffffffffff >>
629: 0x20,0),uVar44),
630: (SUB163(auVar38,0) >> 8) << 0x10) >> 0x10,0) &
631: SUB1614((undefined  [16])0xffffffffffffffff >> 0x10,0),
632: (ushort)uVar31 & 0xff |
633: (short)((int)(iVar18 + (SUB164(auVar25,0) & 0xffff) + 2) >> 2) << 8);
634: *(undefined (*) [16])(pbVar16 + lVar21 * 2 + 0x12) =
635: CONCAT115((char)((int)((uint)bVar48 + iVar102 + 2) >> 2),
636: CONCAT114(uVar63,CONCAT113((char)(uVar54 >> 0x18),
637: CONCAT112(uVar45,CONCAT111(uVar50,CONCAT110(
638: uVar60,CONCAT19((char)((uint3)(ushort)((short)((
639: int)(uVar80 + iVar91 + 2) >> 2) << 8) >> 8),
640: CONCAT18((char)uVar71,
641: CONCAT17(uVar39,CONCAT16(uVar58,CONCAT15(
642: (char)(uVar54 >> 0x10),
643: CONCAT14(uVar57,CONCAT13(uVar43,CONCAT12(uVar56,
644: CONCAT11((char)((int)(iVar70 + (uVar47 & 0xffff) +
645: 2) >> 2),uVar51))))))))))))))
646: ) & (undefined  [16])0xffffffffffffffff;
647: lVar21 = lVar21 + 0x10;
648: } while (uVar24 < uVar23 >> 4);
649: if (uVar23 != uVar17) {
650: pbVar14 = pbVar20 + uVar17;
651: pbVar16 = pbVar12 + (ulong)uVar17 * 2;
652: do {
653: pbVar13 = pbVar14 + 1;
654: iVar18 = (uint)*pbVar14 + (uint)*pbVar14 * 2;
655: *pbVar16 = (byte)((int)(iVar18 + 1 + (uint)pbVar14[-1]) >> 2);
656: pbVar16[1] = (byte)((int)(iVar18 + 2 + (uint)*pbVar13) >> 2);
657: pbVar14 = pbVar13;
658: pbVar16 = pbVar16 + 2;
659: } while (pbVar13 != pbVar20 + uVar17 + (ulong)((uVar23 - uVar17) - 1) + 1);
660: }
661: lVar21 = (ulong)(iVar11 - 3) + 1;
662: pbVar12 = pbVar12 + lVar21 * 2;
663: pbVar20 = pbVar20 + lVar21;
664: }
665: }
666: bVar48 = *pbVar20;
667: bVar75 = pbVar20[-1];
668: pbVar12[1] = bVar48;
669: *pbVar12 = (byte)((int)((uint)bVar48 + (uint)bVar48 * 2 + 1 + (uint)bVar75) >> 2);
670: iVar11 = (int)lVar22 + 1;
671: lVar22 = lVar22 + 1;
672: } while (*(int *)(param_1 + 0x19c) != iVar11 && iVar11 <= *(int *)(param_1 + 0x19c));
673: }
674: return;
675: }
676: 
