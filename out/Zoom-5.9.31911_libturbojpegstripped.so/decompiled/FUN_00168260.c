1: 
2: /* WARNING: Type propagation algorithm not settling */
3: /* WARNING: Could not reconcile some variable overlaps */
4: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
5: 
6: void FUN_00168260(long param_1,long param_2,undefined (**param_3) [32],undefined (**param_4) [16])
7: 
8: {
9: uint uVar1;
10: bool bVar2;
11: ulong uVar3;
12: ulong uVar4;
13: undefined (*pauVar5) [32];
14: undefined (*pauVar6) [16];
15: undefined (*pauVar7) [32];
16: undefined (*pauVar8) [32];
17: undefined (*pauVar9) [32];
18: ulong uVar10;
19: undefined (*pauVar11) [16];
20: undefined (*pauVar12) [32];
21: undefined8 in_R10;
22: undefined8 in_R11;
23: short sVar13;
24: short sVar15;
25: short sVar16;
26: short sVar17;
27: short sVar18;
28: short sVar19;
29: short sVar20;
30: short sVar21;
31: undefined auVar22 [16];
32: undefined auVar14 [32];
33: undefined in_YMM0 [32];
34: undefined auVar23 [14];
35: undefined auVar24 [16];
36: undefined auVar25 [16];
37: undefined auVar32 [16];
38: undefined auVar26 [32];
39: undefined auVar31 [32];
40: undefined in_YMM1 [32];
41: undefined auVar33 [14];
42: undefined auVar34 [16];
43: undefined auVar35 [16];
44: undefined auVar43 [16];
45: undefined auVar36 [32];
46: undefined auVar42 [32];
47: undefined in_YMM2 [32];
48: byte bVar44;
49: undefined uVar46;
50: undefined uVar47;
51: undefined uVar48;
52: undefined uVar49;
53: undefined uVar50;
54: undefined uVar51;
55: undefined uVar52;
56: undefined uVar53;
57: undefined uVar54;
58: undefined uVar55;
59: undefined uVar56;
60: undefined uVar57;
61: undefined uVar58;
62: undefined uVar59;
63: undefined uVar60;
64: undefined auVar45 [32];
65: undefined auVar61 [16];
66: undefined in_YMM3 [32];
67: short sVar62;
68: ushort uVar63;
69: undefined4 uVar64;
70: short sVar71;
71: short sVar72;
72: short sVar73;
73: short sVar74;
74: short sVar75;
75: short sVar76;
76: short sVar77;
77: undefined auVar69 [16];
78: undefined auVar70 [32];
79: short sVar78;
80: ushort uVar79;
81: byte bVar87;
82: undefined auVar86 [32];
83: short sVar88;
84: ushort uVar89;
85: byte bVar99;
86: undefined auVar96 [16];
87: undefined auVar97 [32];
88: undefined auVar98 [32];
89: undefined in_YMM8 [32];
90: undefined in_YMM9 [32];
91: undefined in_YMM10_H [16];
92: undefined auStack160 [8];
93: undefined auStack152 [8];
94: undefined auStack144 [24];
95: undefined auStack96 [16];
96: undefined auStack80 [16];
97: undefined auStack64 [32];
98: undefined auStack32 [16];
99: undefined auVar27 [32];
100: undefined auVar28 [32];
101: undefined auVar29 [32];
102: undefined auVar30 [32];
103: undefined auVar37 [32];
104: undefined auVar38 [32];
105: undefined auVar39 [32];
106: undefined auVar40 [32];
107: undefined auVar41 [32];
108: undefined6 uVar65;
109: undefined8 uVar66;
110: unkbyte10 Var67;
111: undefined auVar68 [12];
112: undefined4 uVar80;
113: undefined6 uVar81;
114: undefined8 uVar82;
115: unkbyte10 Var83;
116: undefined auVar84 [12];
117: undefined auVar85 [14];
118: undefined4 uVar90;
119: undefined6 uVar91;
120: undefined8 uVar92;
121: unkbyte10 Var93;
122: undefined auVar94 [12];
123: undefined auVar95 [14];
124: 
125: uVar1 = *(uint *)(param_2 + 0x28);
126: uVar10 = (ulong)uVar1;
127: uVar3 = (ulong)*(uint *)(param_1 + 0x19c);
128: if ((DAT_003a61e0 & 0x80) == 0) {
129: auStack96 = CONCAT88(in_R10,auStack96._0_8_);
130: _auStack96 = CONCAT248(stack0xffffffffffffffa8,in_R11);
131: if ((uVar10 != 0) && (uVar3 != 0)) {
132: pauVar11 = *param_4;
133: do {
134: auVar14 = _auStack160;
135: _auStack160 = CONCAT824(uVar3,CONCAT816(pauVar11,_auStack160));
136: _auStack160 = CONCAT88(param_3,SUB328(auVar14,0));
137: pauVar5 = param_3[-1];
138: pauVar8 = *param_3;
139: pauVar9 = param_3[1];
140: pauVar6 = *(undefined (**) [16])*pauVar11;
141: pauVar11 = *(undefined (**) [16])((long)*pauVar11 + 8);
142: if ((uVar1 & 0xf) != 0) {
143: _auStack160 = CONCAT248(_auStack152,pauVar6);
144: (*pauVar5)[uVar10] = pauVar5[-1][uVar10 + 0x1f];
145: (*pauVar8)[uVar10] = pauVar8[-1][uVar10 + 0x1f];
146: (*pauVar9)[uVar10] = pauVar9[-1][uVar10 + 0x1f];
147: }
148: auVar24 = *(undefined (*) [16])*pauVar8;
149: auVar22 = SUB3216(in_YMM0 >> 0x80,0);
150: auVar35 = *(undefined (*) [16])*pauVar5;
151: auVar32 = SUB3216(in_YMM1 >> 0x80,0);
152: auVar69 = *(undefined (*) [16])*pauVar9;
153: auVar43 = SUB3216(in_YMM2 >> 0x80,0);
154: auVar45 = in_YMM3 & (undefined  [32])0xffffffffffffffff;
155: auVar61 = SUB3216(in_YMM3 >> 0x80,0);
156: uVar52 = SUB321(auVar45 >> 0x38,0);
157: auVar97 = CONCAT1715(SUB3217(CONCAT1616(auVar22,CONCAT115(uVar52,SUB1615(auVar24,0))) >>
158: 0x78,0),CONCAT114(SUB161(auVar24 >> 0x38,0),SUB1614(auVar24,0))
159: );
160: uVar51 = SUB321(auVar45 >> 0x30,0);
161: auVar86 = CONCAT1913(SUB3219(CONCAT1814(SUB3218(auVar97 >> 0x70,0),
162: CONCAT113(uVar51,SUB1613(auVar24,0))) >> 0x68,0),
163: CONCAT112(SUB161(auVar24 >> 0x30,0),SUB1612(auVar24,0)));
164: uVar50 = SUB321(auVar45 >> 0x28,0);
165: auVar70 = CONCAT2111(SUB3221(CONCAT2012(SUB3220(auVar86 >> 0x60,0),
166: CONCAT111(uVar50,SUB1611(auVar24,0))) >> 0x58,0),
167: CONCAT110(SUB161(auVar24 >> 0x28,0),SUB1610(auVar24,0)));
168: uVar49 = SUB321(auVar45 >> 0x20,0);
169: auVar42 = CONCAT239(SUB3223(CONCAT2210(SUB3222(auVar70 >> 0x50,0),
170: CONCAT19(uVar49,SUB169(auVar24,0))) >> 0x48,0),
171: CONCAT18(SUB161(auVar24 >> 0x20,0),SUB168(auVar24,0)));
172: uVar48 = SUB321(auVar45 >> 0x18,0);
173: auVar31 = CONCAT257(CONCAT241(SUB3224(auVar42 >> 0x40,0),uVar48),
174: (SUB167(auVar24,0) >> 0x18) << 0x30);
175: uVar47 = SUB321(auVar45 >> 0x10,0);
176: auVar14 = CONCAT275(CONCAT261(SUB3226(auVar31 >> 0x30,0),uVar47),
177: (SUB165(auVar24,0) >> 0x10) << 0x20);
178: uVar46 = SUB321(auVar45 >> 8,0);
179: bVar44 = SUB321(auVar45,0);
180: uVar53 = SUB321(auVar45 >> 0x40,0);
181: sVar62 = CONCAT11(uVar53,SUB161(auVar24 >> 0x40,0));
182: uVar54 = SUB321(auVar45 >> 0x48,0);
183: uVar64 = CONCAT13(uVar54,CONCAT12(SUB161(auVar24 >> 0x48,0),sVar62));
184: uVar55 = SUB321(auVar45 >> 0x50,0);
185: uVar65 = CONCAT15(uVar55,CONCAT14(SUB161(auVar24 >> 0x50,0),uVar64));
186: uVar56 = SUB321(auVar45 >> 0x58,0);
187: uVar66 = CONCAT17(uVar56,CONCAT16(SUB161(auVar24 >> 0x58,0),uVar65));
188: uVar57 = SUB321(auVar45 >> 0x60,0);
189: Var67 = CONCAT19(uVar57,CONCAT18(SUB161(auVar24 >> 0x60,0),uVar66));
190: uVar58 = SUB321(auVar45 >> 0x68,0);
191: auVar68 = CONCAT111(uVar58,CONCAT110(SUB161(auVar24 >> 0x68,0),Var67));
192: uVar59 = SUB321(auVar45 >> 0x70,0);
193: auVar23 = CONCAT113(uVar59,CONCAT112(SUB161(auVar24 >> 0x70,0),auVar68));
194: uVar60 = SUB321(auVar45 >> 0x78,0);
195: auVar30 = CONCAT1715(SUB3217(CONCAT1616(auVar32,CONCAT115(uVar52,SUB1615(auVar35,0))) >>
196: 0x78,0),CONCAT114(SUB161(auVar35 >> 0x38,0),SUB1614(auVar35,0))
197: );
198: auVar29 = CONCAT1913(SUB3219(CONCAT1814(SUB3218(auVar30 >> 0x70,0),
199: CONCAT113(uVar51,SUB1613(auVar35,0))) >> 0x68,0),
200: CONCAT112(SUB161(auVar35 >> 0x30,0),SUB1612(auVar35,0)));
201: auVar28 = CONCAT2111(SUB3221(CONCAT2012(SUB3220(auVar29 >> 0x60,0),
202: CONCAT111(uVar50,SUB1611(auVar35,0))) >> 0x58,0),
203: CONCAT110(SUB161(auVar35 >> 0x28,0),SUB1610(auVar35,0)));
204: auVar27 = CONCAT239(SUB3223(CONCAT2210(SUB3222(auVar28 >> 0x50,0),
205: CONCAT19(uVar49,SUB169(auVar35,0))) >> 0x48,0),
206: CONCAT18(SUB161(auVar35 >> 0x20,0),SUB168(auVar35,0)));
207: auVar98 = CONCAT257(CONCAT241(SUB3224(auVar27 >> 0x40,0),uVar48),
208: (SUB167(auVar35,0) >> 0x18) << 0x30);
209: auVar26 = CONCAT275(CONCAT261(SUB3226(auVar98 >> 0x30,0),uVar47),
210: (SUB165(auVar35,0) >> 0x10) << 0x20);
211: sVar78 = CONCAT11(uVar53,SUB161(auVar35 >> 0x40,0));
212: uVar80 = CONCAT13(uVar54,CONCAT12(SUB161(auVar35 >> 0x48,0),sVar78));
213: uVar81 = CONCAT15(uVar55,CONCAT14(SUB161(auVar35 >> 0x50,0),uVar80));
214: uVar82 = CONCAT17(uVar56,CONCAT16(SUB161(auVar35 >> 0x58,0),uVar81));
215: Var83 = CONCAT19(uVar57,CONCAT18(SUB161(auVar35 >> 0x60,0),uVar82));
216: auVar84 = CONCAT111(uVar58,CONCAT110(SUB161(auVar35 >> 0x68,0),Var83));
217: auVar85 = CONCAT113(uVar59,CONCAT112(SUB161(auVar35 >> 0x70,0),auVar84));
218: auVar41 = CONCAT1715(SUB3217(CONCAT1616(auVar43,CONCAT115(uVar52,SUB1615(auVar69,0))) >>
219: 0x78,0),CONCAT114(SUB161(auVar69 >> 0x38,0),SUB1614(auVar69,0))
220: );
221: auVar40 = CONCAT1913(SUB3219(CONCAT1814(SUB3218(auVar41 >> 0x70,0),
222: CONCAT113(uVar51,SUB1613(auVar69,0))) >> 0x68,0),
223: CONCAT112(SUB161(auVar69 >> 0x30,0),SUB1612(auVar69,0)));
224: auVar39 = CONCAT2111(SUB3221(CONCAT2012(SUB3220(auVar40 >> 0x60,0),
225: CONCAT111(uVar50,SUB1611(auVar69,0))) >> 0x58,0),
226: CONCAT110(SUB161(auVar69 >> 0x28,0),SUB1610(auVar69,0)));
227: auVar38 = CONCAT239(SUB3223(CONCAT2210(SUB3222(auVar39 >> 0x50,0),
228: CONCAT19(uVar49,SUB169(auVar69,0))) >> 0x48,0),
229: CONCAT18(SUB161(auVar69 >> 0x20,0),SUB168(auVar69,0)));
230: auVar37 = CONCAT257(CONCAT241(SUB3224(auVar38 >> 0x40,0),uVar48),
231: (SUB167(auVar69,0) >> 0x18) << 0x30);
232: auVar36 = CONCAT275(CONCAT261(SUB3226(auVar37 >> 0x30,0),uVar47),
233: (SUB165(auVar69,0) >> 0x10) << 0x20);
234: sVar88 = CONCAT11(uVar53,SUB161(auVar69 >> 0x40,0));
235: uVar90 = CONCAT13(uVar54,CONCAT12(SUB161(auVar69 >> 0x48,0),sVar88));
236: uVar91 = CONCAT15(uVar55,CONCAT14(SUB161(auVar69 >> 0x50,0),uVar90));
237: uVar92 = CONCAT17(uVar56,CONCAT16(SUB161(auVar69 >> 0x58,0),uVar91));
238: Var93 = CONCAT19(uVar57,CONCAT18(SUB161(auVar69 >> 0x60,0),uVar92));
239: auVar94 = CONCAT111(uVar58,CONCAT110(SUB161(auVar69 >> 0x68,0),Var93));
240: auVar95 = CONCAT113(uVar59,CONCAT112(SUB161(auVar69 >> 0x70,0),auVar94));
241: sVar13 = (SUB162(auVar24,0) & 0xff | (ushort)bVar44 << 8) * 3;
242: sVar15 = SUB322(CONCAT293(CONCAT281(SUB3228(auVar14 >> 0x20,0),uVar46),
243: (SUB163(auVar24,0) >> 8) << 0x10) >> 0x10,0) * 3;
244: sVar16 = SUB322(auVar14 >> 0x20,0) * 3;
245: sVar17 = SUB322(auVar31 >> 0x30,0) * 3;
246: sVar18 = SUB322(auVar42 >> 0x40,0) * 3;
247: sVar19 = SUB322(auVar70 >> 0x50,0) * 3;
248: sVar20 = SUB322(auVar86 >> 0x60,0) * 3;
249: sVar21 = SUB322(auVar97 >> 0x70,0) * 3;
250: in_YMM0 = ZEXT2632(CONCAT1610(auVar22,CONCAT28(sVar21,CONCAT26(sVar20,CONCAT24(sVar19,
251: CONCAT22(sVar18,sVar17)))))) << 0x30;
252: sVar62 = sVar62 * 3;
253: sVar71 = (short)((uint)uVar64 >> 0x10) * 3;
254: sVar72 = (short)((uint6)uVar65 >> 0x20) * 3;
255: sVar73 = (short)((ulong)uVar66 >> 0x30) * 3;
256: sVar74 = (short)((unkuint10)Var67 >> 0x40) * 3;
257: sVar75 = SUB122(auVar68 >> 0x50,0) * 3;
258: sVar76 = SUB142(auVar23 >> 0x60,0) * 3;
259: sVar77 = SUB162(CONCAT115(uVar60,CONCAT114(SUB161(auVar24 >> 0x78,0),auVar23)) >> 0x70,0) *
260: 3;
261: auStack64._0_16_ =
262: CONCAT115(0xff,CONCAT114(0xff,CONCAT113(0xff,CONCAT112(0xff,CONCAT111(0xff,CONCAT110(
263: 0xff,CONCAT19(0xff,CONCAT18(0xff,
264: 0xffffffffffffffff)))))))) >> 0x70;
265: auVar23 = CONCAT212(SUB322(auVar29 >> 0x60,0) + sVar20,
266: CONCAT210(SUB322(auVar28 >> 0x50,0) + sVar19,
267: CONCAT28(SUB322(auVar27 >> 0x40,0) + sVar18,
268: CONCAT26(SUB322(auVar98 >> 0x30,0) + sVar17,
269: CONCAT24(SUB322(auVar26 >> 0x20,0) + sVar16,
270: CONCAT22(SUB322(CONCAT293(CONCAT281
271: (SUB3228(auVar26 >> 0x20,0),uVar46),
272: (SUB163(auVar35,0) >> 8) << 0x10) >> 0x10,0) +
273: sVar15,(SUB162(auVar35,0) & 0xff |
274: (ushort)bVar44 << 8) + sVar13))))));
275: auVar33 = CONCAT212(SUB322(auVar40 >> 0x60,0) + sVar20,
276: CONCAT210(SUB322(auVar39 >> 0x50,0) + sVar19,
277: CONCAT28(SUB322(auVar38 >> 0x40,0) + sVar18,
278: CONCAT26(SUB322(auVar37 >> 0x30,0) + sVar17,
279: CONCAT24(SUB322(auVar36 >> 0x20,0) + sVar16,
280: CONCAT22(SUB322(CONCAT293(CONCAT281
281: (SUB3228(auVar36 >> 0x20,0),uVar46),
282: (SUB163(auVar69,0) >> 8) << 0x10) >> 0x10,0) +
283: sVar15,(SUB162(auVar69,0) & 0xff |
284: (ushort)bVar44 << 8) + sVar13))))));
285: *pauVar6 = CONCAT214(SUB322(auVar30 >> 0x70,0) + sVar21,auVar23);
286: pauVar6[1] = CONCAT214(SUB162(CONCAT115(uVar60,CONCAT114(SUB161(auVar35 >> 0x78,0),auVar85))
287: >> 0x70,0) + sVar77,
288: CONCAT212(SUB142(auVar85 >> 0x60,0) + sVar76,
289: CONCAT210(SUB122(auVar84 >> 0x50,0) + sVar75,
290: CONCAT28((short)((unkuint10)Var83 >> 0x40) +
291: sVar74,CONCAT26((short)((ulong)uVar82 >>
292: 0x30) + sVar73,
293: CONCAT24((short)((uint6)
294: uVar81 >> 0x20) + sVar72,
295: CONCAT22((short)((uint)uVar80 >> 0x10) + sVar71,
296: sVar78 + sVar62)))))));
297: *pauVar11 = CONCAT214(SUB322(auVar41 >> 0x70,0) + sVar21,auVar33);
298: pauVar11[1] = CONCAT214(SUB162(CONCAT115(uVar60,CONCAT114(SUB161(auVar69 >> 0x78,0),auVar95)
299: ) >> 0x70,0) + sVar77,
300: CONCAT212(SUB142(auVar95 >> 0x60,0) + sVar76,
301: CONCAT210(SUB122(auVar94 >> 0x50,0) + sVar75,
302: CONCAT28((short)((unkuint10)Var93 >> 0x40) +
303: sVar74,CONCAT26((short)((ulong)uVar92
304: >> 0x30) +
305: sVar73,CONCAT24((short)
306: ((uint6)uVar91 >> 0x20) + sVar72,
307: CONCAT22((short)((uint)uVar90 >> 0x10) + sVar71,
308: sVar88 + sVar62)))))));
309: auVar24 = ZEXT1416(auVar23) & auStack64._0_16_;
310: in_YMM1 = CONCAT1616(auVar32,auVar24);
311: auStack64._0_16_ = ZEXT1416(auVar33) & auStack64._0_16_;
312: in_YMM2 = CONCAT1616(auVar43,auStack64._0_16_);
313: _auStack96 = CONCAT1616(auVar24,auStack96);
314: uVar3 = uVar10 + 0xf & 0xfffffffffffffff0;
315: if (0x10 < uVar3) goto LAB_0015d1f7;
316: do {
317: auVar32 = SUB3216(in_YMM1 >> 0x80,0);
318: auStack32 = pslldq(CONCAT115(0xff,CONCAT114(0xff,CONCAT113(0xff,CONCAT112(0xff,CONCAT111(
319: 0xff,CONCAT110(0xff,CONCAT19(0xff,CONCAT18(0xff,
320: 0xffffffffffffffff)))))))),0xe);
321: auVar43 = SUB3216(in_YMM2 >> 0x80,0);
322: auStack64._16_16_ = auStack32 & pauVar6[1];
323: auStack32 = auStack32 & pauVar11[1];
324: while( true ) {
325: auVar24 = *pauVar6;
326: auVar35 = pauVar6[1];
327: auVar61 = SUB3216(auVar45 >> 0x80,0);
328: auVar22 = SUB3216(in_YMM0 >> 0x80,0);
329: auVar69 = pslldq(auVar35,0xe);
330: auVar96 = pslldq(auVar35,2);
331: auVar69 = auVar24 >> 0x10 | auVar69;
332: auVar96 = auVar24 >> 0x70 | auVar96;
333: auVar25 = pslldq(auVar24,2);
334: auVar25 = auVar25 | auStack80;
335: auVar34 = auVar35 >> 0x10 | auStack64._16_16_;
336: _auStack96 = CONCAT1616(auVar35 >> 0x70,auStack96);
337: sVar62 = SUB162(auVar24,0) * 3;
338: sVar71 = SUB162(auVar24 >> 0x10,0) * 3;
339: sVar72 = SUB162(auVar24 >> 0x20,0) * 3;
340: sVar73 = SUB162(auVar24 >> 0x30,0) * 3;
341: sVar74 = SUB162(auVar24 >> 0x40,0) * 3;
342: sVar75 = SUB162(auVar24 >> 0x50,0) * 3;
343: sVar76 = SUB162(auVar24 >> 0x60,0) * 3;
344: sVar77 = SUB162(auVar24 >> 0x70,0) * 3;
345: sVar13 = SUB162(auVar35,0) * 3;
346: sVar15 = SUB162(auVar35 >> 0x10,0) * 3;
347: sVar16 = SUB162(auVar35 >> 0x20,0) * 3;
348: sVar17 = SUB162(auVar35 >> 0x30,0) * 3;
349: sVar18 = SUB162(auVar35 >> 0x40,0) * 3;
350: sVar19 = SUB162(auVar35 >> 0x50,0) * 3;
351: sVar20 = SUB162(auVar35 >> 0x60,0) * 3;
352: sVar21 = SUB162(auVar35 >> 0x70,0) * 3;
353: auVar24 = psllw(CONCAT214((ushort)(SUB162(auVar69 >> 0x70,0) + 7 + sVar77) >> 4,
354: CONCAT212((ushort)(SUB162(auVar69 >> 0x60,0) + 7 + sVar76) >>
355: 4,CONCAT210((ushort)(SUB162(auVar69 >> 0x50,0) + 7 +
356: sVar75) >> 4,
357: CONCAT28((ushort)(SUB162(auVar69 >> 0x40
358: ,0) + 7 +
359: sVar74) >> 4,
360: CONCAT26((ushort)(SUB162(
361: auVar69 >> 0x30,0) + 7 + sVar73) >> 4,
362: CONCAT24((ushort)(SUB162(auVar69 >> 0x20,0) + 7 +
363: sVar72) >> 4,
364: CONCAT22((ushort)(SUB162(auVar69 >> 0x10,
365: 0) + 7 + sVar71)
366: >> 4,(ushort)(SUB162(auVar69,0)
367: + 7 + sVar62) >> 4
368: ))))))),8);
369: auVar35 = psllw(CONCAT214((ushort)(SUB162(auVar34 >> 0x70,0) + 7 + sVar21) >> 4,
370: CONCAT212((ushort)(SUB162(auVar34 >> 0x60,0) + 7 + sVar20) >>
371: 4,CONCAT210((ushort)(SUB162(auVar34 >> 0x50,0) + 7 +
372: sVar19) >> 4,
373: CONCAT28((ushort)(SUB162(auVar34 >> 0x40
374: ,0) + 7 +
375: sVar18) >> 4,
376: CONCAT26((ushort)(SUB162(
377: auVar34 >> 0x30,0) + 7 + sVar17) >> 4,
378: CONCAT24((ushort)(SUB162(auVar34 >> 0x20,0) + 7 +
379: sVar16) >> 4,
380: CONCAT22((ushort)(SUB162(auVar34 >> 0x10,
381: 0) + 7 + sVar15)
382: >> 4,(ushort)(SUB162(auVar34,0)
383: + 7 + sVar13) >> 4
384: ))))))),8);
385: *pauVar6 = CONCAT214((ushort)(SUB162(auVar25 >> 0x70,0) + 8 + sVar77) >> 4,
386: CONCAT212((ushort)(SUB162(auVar25 >> 0x60,0) + 8 + sVar76) >> 4,
387: CONCAT210((ushort)(SUB162(auVar25 >> 0x50,0) + 8 + sVar75
388: ) >> 4,
389: CONCAT28((ushort)(SUB162(auVar25 >> 0x40,0) + 8
390: + sVar74) >> 4,
391: CONCAT26((ushort)(SUB162(auVar25 >>
392: 0x30,0) + 8 +
393: sVar73) >> 4,
394: CONCAT24((ushort)(SUB162(
395: auVar25 >> 0x20,0) + 8 + sVar72) >> 4,
396: CONCAT22((ushort)(SUB162(auVar25 >> 0x10,0) + 8 +
397: sVar71) >> 4,
398: (ushort)(SUB162(auVar25,0) + 8 + sVar62)
399: >> 4))))))) | auVar24;
400: pauVar6[1] = CONCAT214((ushort)(SUB162(auVar96 >> 0x70,0) + 8 + sVar21) >> 4,
401: CONCAT212((ushort)(SUB162(auVar96 >> 0x60,0) + 8 + sVar20) >> 4,
402: CONCAT210((ushort)(SUB162(auVar96 >> 0x50,0) + 8 +
403: sVar19) >> 4,
404: CONCAT28((ushort)(SUB162(auVar96 >> 0x40,0) +
405: 8 + sVar18) >> 4,
406: CONCAT26((ushort)(SUB162(auVar96 >>
407: 0x30,0) + 8
408: + sVar17) >> 4,
409: CONCAT24((ushort)(SUB162(
410: auVar96 >> 0x20,0) + 8 + sVar16) >> 4,
411: CONCAT22((ushort)(SUB162(auVar96 >> 0x10,0) + 8 +
412: sVar15) >> 4,
413: (ushort)(SUB162(auVar96,0) + 8 + sVar13)
414: >> 4))))))) | auVar35;
415: auVar24 = *pauVar11;
416: auVar35 = pauVar11[1];
417: auVar34 = pslldq(auVar35,0xe);
418: auVar69 = pslldq(auVar35,2);
419: in_YMM2 = CONCAT1616(auVar43,auVar69);
420: auVar34 = auVar24 >> 0x10 | auVar34;
421: auVar69 = auVar24 >> 0x70 | auVar69;
422: auVar25 = pslldq(auVar24,2);
423: auVar96 = auVar35 >> 0x70;
424: auVar45 = CONCAT1616(auVar61,auVar96);
425: auVar25 = auVar25 | auStack64._0_16_;
426: auStack32 = auVar35 >> 0x10 | auStack32;
427: auStack64 = CONCAT1616(auStack64._16_16_,auVar96);
428: sVar62 = SUB162(auVar24,0) * 3;
429: sVar71 = SUB162(auVar24 >> 0x10,0) * 3;
430: sVar72 = SUB162(auVar24 >> 0x20,0) * 3;
431: sVar73 = SUB162(auVar24 >> 0x30,0) * 3;
432: sVar74 = SUB162(auVar24 >> 0x40,0) * 3;
433: sVar75 = SUB162(auVar24 >> 0x50,0) * 3;
434: sVar76 = SUB162(auVar24 >> 0x60,0) * 3;
435: sVar77 = SUB162(auVar24 >> 0x70,0) * 3;
436: sVar13 = SUB162(auVar35,0) * 3;
437: sVar15 = SUB162(auVar35 >> 0x10,0) * 3;
438: sVar16 = SUB162(auVar35 >> 0x20,0) * 3;
439: sVar17 = SUB162(auVar35 >> 0x30,0) * 3;
440: sVar18 = SUB162(auVar35 >> 0x40,0) * 3;
441: sVar19 = SUB162(auVar35 >> 0x50,0) * 3;
442: sVar20 = SUB162(auVar35 >> 0x60,0) * 3;
443: sVar21 = SUB162(auVar35 >> 0x70,0) * 3;
444: auVar35 = psllw(CONCAT214((ushort)(SUB162(auVar34 >> 0x70,0) + 7 + sVar77) >> 4,
445: CONCAT212((ushort)(SUB162(auVar34 >> 0x60,0) + 7 + sVar76) >>
446: 4,CONCAT210((ushort)(SUB162(auVar34 >> 0x50,0) + 7 +
447: sVar75) >> 4,
448: CONCAT28((ushort)(SUB162(auVar34 >> 0x40
449: ,0) + 7 +
450: sVar74) >> 4,
451: CONCAT26((ushort)(SUB162(
452: auVar34 >> 0x30,0) + 7 + sVar73) >> 4,
453: CONCAT24((ushort)(SUB162(auVar34 >> 0x20,0) + 7 +
454: sVar72) >> 4,
455: CONCAT22((ushort)(SUB162(auVar34 >> 0x10,
456: 0) + 7 + sVar71)
457: >> 4,(ushort)(SUB162(auVar34,0)
458: + 7 + sVar62) >> 4
459: ))))))),8);
460: auVar24 = psllw(CONCAT214((ushort)(SUB162(auStack32 >> 0x70,0) + 7 + sVar21) >> 4,
461: CONCAT212((ushort)(SUB162(auStack32 >> 0x60,0) + 7 + sVar20)
462: >> 4,CONCAT210((ushort)(SUB162(auStack32 >> 0x50,0)
463: + 7 + sVar19) >> 4,
464: CONCAT28((ushort)(SUB162(auStack32 >>
465: 0x40,0) + 7
466: + sVar18) >> 4,
467: CONCAT26((ushort)(SUB162(
468: auStack32 >> 0x30,0) + 7 + sVar17) >> 4,
469: CONCAT24((ushort)(SUB162(auStack32 >> 0x20,0) + 7
470: + sVar16) >> 4,
471: CONCAT22((ushort)(SUB162(auStack32 >>
472: 0x10,0) + 7 +
473: sVar15) >> 4,
474: (ushort)(SUB162(auStack32,0) + 7
475: + sVar13) >> 4))))))),8)
476: ;
477: auVar35 = CONCAT214((ushort)(SUB162(auVar25 >> 0x70,0) + 8 + sVar77) >> 4,
478: CONCAT212((ushort)(SUB162(auVar25 >> 0x60,0) + 8 + sVar76) >> 4,
479: CONCAT210((ushort)(SUB162(auVar25 >> 0x50,0) + 8 + sVar75)
480: >> 4,CONCAT28((ushort)(SUB162(auVar25 >> 0x40,0)
481: + 8 + sVar74) >> 4,
482: CONCAT26((ushort)(SUB162(auVar25 
483: >> 0x30,0) + 8 + sVar73) >> 4,
484: CONCAT24((ushort)(SUB162(auVar25 >> 0x20,0) + 8 +
485: sVar72) >> 4,
486: CONCAT22((ushort)(SUB162(auVar25 >> 0x10,
487: 0) + 8 + sVar71)
488: >> 4,(ushort)(SUB162(auVar25,0)
489: + 8 + sVar62) >> 4
490: ))))))) | auVar35;
491: in_YMM1 = CONCAT1616(auVar32,auVar35);
492: auVar24 = CONCAT214((ushort)(SUB162(auVar69 >> 0x70,0) + 8 + sVar21) >> 4,
493: CONCAT212((ushort)(SUB162(auVar69 >> 0x60,0) + 8 + sVar20) >> 4,
494: CONCAT210((ushort)(SUB162(auVar69 >> 0x50,0) + 8 + sVar19)
495: >> 4,CONCAT28((ushort)(SUB162(auVar69 >> 0x40,0)
496: + 8 + sVar18) >> 4,
497: CONCAT26((ushort)(SUB162(auVar69 
498: >> 0x30,0) + 8 + sVar17) >> 4,
499: CONCAT24((ushort)(SUB162(auVar69 >> 0x20,0) + 8 +
500: sVar16) >> 4,
501: CONCAT22((ushort)(SUB162(auVar69 >> 0x10,
502: 0) + 8 + sVar15)
503: >> 4,(ushort)(SUB162(auVar69,0)
504: + 8 + sVar13) >> 4
505: ))))))) | auVar24;
506: in_YMM0 = CONCAT1616(auVar22,auVar24);
507: *pauVar11 = auVar35;
508: pauVar11[1] = auVar24;
509: uVar3 = uVar3 - 0x10;
510: pauVar5 = (undefined (*) [32])(*pauVar5 + 0x10);
511: pauVar8 = (undefined (*) [32])(*pauVar8 + 0x10);
512: pauVar9 = (undefined (*) [32])(*pauVar9 + 0x10);
513: pauVar6 = pauVar6[2];
514: pauVar11 = pauVar11[2];
515: auStack64._0_16_ = auVar96;
516: if (uVar3 < 0x11) break;
517: LAB_0015d1f7:
518: auVar24 = *(undefined (*) [16])(*pauVar8 + 0x10);
519: auVar35 = *(undefined (*) [16])(*pauVar5 + 0x10);
520: auVar69 = *(undefined (*) [16])(*pauVar9 + 0x10);
521: auVar45 = ZEXT1632(auVar61) << 0x80;
522: auVar31 = CONCAT248(SUB3224(CONCAT239(SUB3223(CONCAT2210(SUB3222(CONCAT2111(SUB3221(
523: CONCAT2012(SUB3220(CONCAT1913(SUB3219(CONCAT1814(
524: SUB3218(CONCAT1715(SUB3217(CONCAT1616(auVar22,
525: auVar24) >> 0x78,0) &
526: SUB3217((undefined  [32])0xffffffffffffffff >>
527: 0x78,0),
528: CONCAT114(SUB161(auVar24 >> 0x38,0),
529: SUB1614(auVar24,0))) >> 0x70,0),
530: ZEXT1314(SUB1613(auVar24,0))) >> 0x68,0),
531: CONCAT112(SUB161(auVar24 >> 0x30,0),
532: SUB1612(auVar24,0))) >> 0x60,0),
533: ZEXT1112(SUB1611(auVar24,0))) >> 0x58,0),
534: CONCAT110(SUB161(auVar24 >> 0x28,0),
535: SUB1610(auVar24,0))) >> 0x50,0),
536: (unkuint10)SUB169(auVar24,0)) >> 0x48,0),
537: CONCAT18(SUB161(auVar24 >> 0x20,0),
538: SUB168(auVar24,0))) >> 0x40,0),
539: SUB168(auVar24,0)) & (undefined  [32])0xffffffffffffffff;
540: auVar14 = CONCAT257(SUB3225(auVar31 >> 0x38,0),(SUB167(auVar24,0) >> 0x18) << 0x30) &
541: (undefined  [32])0xffff000000000000;
542: auVar98 = CONCAT275(SUB3227(auVar14 >> 0x28,0),(SUB165(auVar24,0) >> 0x10) << 0x20);
543: uVar63 = (ushort)SUB161(auVar24 >> 0x40,0);
544: bVar44 = SUB161(auVar24 >> 0x78,0);
545: auVar22 = ZEXT1516(CONCAT114(bVar44,ZEXT1314(CONCAT112(SUB161(auVar24 >> 0x70,0),
546: ZEXT1112(CONCAT110(SUB161(auVar24
547: >> 0x68
548: ,0),(unkuint10)
549: CONCAT18(SUB161(auVar24 >> 0x60,0),
550: (ulong)CONCAT16(SUB161(auVar24 >>
551: 0x58,0),
552: (uint6)CONCAT14(
553: SUB161(auVar24 >> 0x50,0),
554: (uint)CONCAT12(SUB161(auVar24 >> 0x48,0),uVar63)))
555: )))))));
556: auVar70 = CONCAT248(SUB3224(CONCAT239(SUB3223(CONCAT2210(SUB3222(CONCAT2111(SUB3221(
557: CONCAT2012(SUB3220(CONCAT1913(SUB3219(CONCAT1814(
558: SUB3218(CONCAT1715(SUB3217(CONCAT1616(auVar32,
559: auVar35) >> 0x78,0) &
560: SUB3217((undefined  [32])0xffffffffffffffff >>
561: 0x78,0),
562: CONCAT114(SUB161(auVar35 >> 0x38,0),
563: SUB1614(auVar35,0))) >> 0x70,0),
564: ZEXT1314(SUB1613(auVar35,0))) >> 0x68,0),
565: CONCAT112(SUB161(auVar35 >> 0x30,0),
566: SUB1612(auVar35,0))) >> 0x60,0),
567: ZEXT1112(SUB1611(auVar35,0))) >> 0x58,0),
568: CONCAT110(SUB161(auVar35 >> 0x28,0),
569: SUB1610(auVar35,0))) >> 0x50,0),
570: (unkuint10)SUB169(auVar35,0)) >> 0x48,0),
571: CONCAT18(SUB161(auVar35 >> 0x20,0),
572: SUB168(auVar35,0))) >> 0x40,0),
573: SUB168(auVar35,0)) & (undefined  [32])0xffffffffffffffff;
574: auVar42 = CONCAT257(SUB3225(auVar70 >> 0x38,0),(SUB167(auVar35,0) >> 0x18) << 0x30) &
575: (undefined  [32])0xffff000000000000;
576: auVar26 = CONCAT275(SUB3227(auVar42 >> 0x28,0),(SUB165(auVar35,0) >> 0x10) << 0x20);
577: uVar79 = (ushort)SUB161(auVar35 >> 0x40,0);
578: bVar87 = SUB161(auVar35 >> 0x78,0);
579: auVar61 = ZEXT1516(CONCAT114(bVar87,ZEXT1314(CONCAT112(SUB161(auVar35 >> 0x70,0),
580: ZEXT1112(CONCAT110(SUB161(auVar35
581: >> 0x68
582: ,0),(unkuint10)
583: CONCAT18(SUB161(auVar35 >> 0x60,0),
584: (ulong)CONCAT16(SUB161(auVar35 >>
585: 0x58,0),
586: (uint6)CONCAT14(
587: SUB161(auVar35 >> 0x50,0),
588: (uint)CONCAT12(SUB161(auVar35 >> 0x48,0),uVar79)))
589: )))))));
590: auVar97 = CONCAT248(SUB3224(CONCAT239(SUB3223(CONCAT2210(SUB3222(CONCAT2111(SUB3221(
591: CONCAT2012(SUB3220(CONCAT1913(SUB3219(CONCAT1814(
592: SUB3218(CONCAT1715(SUB3217(CONCAT1616(auVar43,
593: auVar69) >> 0x78,0) &
594: SUB3217((undefined  [32])0xffffffffffffffff >>
595: 0x78,0),
596: CONCAT114(SUB161(auVar69 >> 0x38,0),
597: SUB1614(auVar69,0))) >> 0x70,0),
598: ZEXT1314(SUB1613(auVar69,0))) >> 0x68,0),
599: CONCAT112(SUB161(auVar69 >> 0x30,0),
600: SUB1612(auVar69,0))) >> 0x60,0),
601: ZEXT1112(SUB1611(auVar69,0))) >> 0x58,0),
602: CONCAT110(SUB161(auVar69 >> 0x28,0),
603: SUB1610(auVar69,0))) >> 0x50,0),
604: (unkuint10)SUB169(auVar69,0)) >> 0x48,0),
605: CONCAT18(SUB161(auVar69 >> 0x20,0),
606: SUB168(auVar69,0))) >> 0x40,0),
607: SUB168(auVar69,0)) & (undefined  [32])0xffffffffffffffff;
608: auVar86 = CONCAT257(SUB3225(auVar97 >> 0x38,0),(SUB167(auVar69,0) >> 0x18) << 0x30) &
609: (undefined  [32])0xffff000000000000;
610: auVar27 = CONCAT275(SUB3227(auVar86 >> 0x28,0),(SUB165(auVar69,0) >> 0x10) << 0x20);
611: uVar89 = (ushort)SUB161(auVar69 >> 0x40,0);
612: bVar99 = SUB161(auVar69 >> 0x78,0);
613: auVar25 = ZEXT1516(CONCAT114(bVar99,ZEXT1314(CONCAT112(SUB161(auVar69 >> 0x70,0),
614: ZEXT1112(CONCAT110(SUB161(auVar69
615: >> 0x68
616: ,0),(unkuint10)
617: CONCAT18(SUB161(auVar69 >> 0x60,0),
618: (ulong)CONCAT16(SUB161(auVar69 >>
619: 0x58,0),
620: (uint6)CONCAT14(
621: SUB161(auVar69 >> 0x50,0),
622: (uint)CONCAT12(SUB161(auVar69 >> 0x48,0),uVar89)))
623: )))))));
624: sVar13 = (SUB162(auVar24,0) & 0xff) * 3;
625: sVar15 = SUB322(CONCAT293(SUB3229(CONCAT284(SUB3228(auVar98 >> 0x20,0),SUB164(auVar24,0)
626: ) >> 0x18,0) &
627: SUB3229((undefined  [32])0xffffffff00ffffff >> 0x18,0),
628: (SUB163(auVar24,0) >> 8) << 0x10) >> 0x10,0) * 3;
629: sVar16 = SUB322(auVar98 >> 0x20,0) * 3;
630: sVar17 = SUB322(auVar14 >> 0x30,0) * 3;
631: sVar18 = SUB322(auVar14 >> 0x40,0) * 3;
632: sVar19 = SUB322(auVar14 >> 0x50,0) * 3;
633: sVar20 = SUB322(auVar14 >> 0x60,0) * 3;
634: sVar21 = SUB322(auVar14 >> 0x70,0) * 3;
635: in_YMM0 = ZEXT2632(CONCAT1610(SUB3216(auVar31 >> 0x80,0),
636: CONCAT28(sVar21,CONCAT26(sVar20,CONCAT24(sVar19,CONCAT22(
637: sVar18,sVar17)))))) << 0x30;
638: sVar62 = uVar63 * 3;
639: sVar71 = SUB162(auVar22 >> 0x10,0) * 3;
640: sVar72 = SUB162(auVar22 >> 0x20,0) * 3;
641: sVar73 = SUB162(auVar22 >> 0x30,0) * 3;
642: sVar74 = SUB162(auVar22 >> 0x40,0) * 3;
643: sVar75 = SUB162(auVar22 >> 0x50,0) * 3;
644: sVar76 = SUB162(auVar22 >> 0x60,0) * 3;
645: sVar77 = (ushort)bVar44 * 3;
646: auVar32 = SUB3216(auVar70 >> 0x80,0);
647: auVar24 = CONCAT214(SUB322(auVar42 >> 0x70,0) + sVar21,
648: CONCAT212(SUB322(auVar42 >> 0x60,0) + sVar20,
649: CONCAT210(SUB322(auVar42 >> 0x50,0) + sVar19,
650: CONCAT28(SUB322(auVar42 >> 0x40,0) + sVar18,
651: CONCAT26(SUB322(auVar42 >> 0x30,0) +
652: sVar17,CONCAT24(SUB322(auVar26
653: >> 0x20
654: ,0) + sVar16,
655: CONCAT22(SUB322(CONCAT293(SUB3229(CONCAT284(
656: SUB3228(auVar26 >> 0x20,0),SUB164(auVar35,0)) >>
657: 0x18,0) & SUB3229((undefined  [32])
658: 0xffffffff00ffffff >> 0x18,0),
659: (SUB163(auVar35,0) >> 8) << 0x10) >> 0x10,0) +
660: sVar15,(SUB162(auVar35,0) & 0xff) + sVar13)))))));
661: auVar43 = SUB3216(auVar97 >> 0x80,0);
662: auVar35 = CONCAT214(SUB322(auVar86 >> 0x70,0) + sVar21,
663: CONCAT212(SUB322(auVar86 >> 0x60,0) + sVar20,
664: CONCAT210(SUB322(auVar86 >> 0x50,0) + sVar19,
665: CONCAT28(SUB322(auVar86 >> 0x40,0) + sVar18,
666: CONCAT26(SUB322(auVar86 >> 0x30,0) +
667: sVar17,CONCAT24(SUB322(auVar27
668: >> 0x20
669: ,0) + sVar16,
670: CONCAT22(SUB322(CONCAT293(SUB3229(CONCAT284(
671: SUB3228(auVar27 >> 0x20,0),SUB164(auVar69,0)) >>
672: 0x18,0) & SUB3229((undefined  [32])
673: 0xffffffff00ffffff >> 0x18,0),
674: (SUB163(auVar69,0) >> 8) << 0x10) >> 0x10,0) +
675: sVar15,(SUB162(auVar69,0) & 0xff) + sVar13)))))));
676: pauVar6[2] = auVar24;
677: pauVar6[3] = CONCAT214((ushort)bVar87 + sVar77,
678: CONCAT212(SUB162(auVar61 >> 0x60,0) + sVar76,
679: CONCAT210(SUB162(auVar61 >> 0x50,0) + sVar75,
680: CONCAT28(SUB162(auVar61 >> 0x40,0) + sVar74,
681: CONCAT26(SUB162(auVar61 >> 0x30,0) +
682: sVar73,CONCAT24(SUB162(
683: auVar61 >> 0x20,0) + sVar72,
684: CONCAT22(SUB162(auVar61 >> 0x10,0) + sVar71,
685: uVar79 + sVar62)))))));
686: pauVar11[2] = auVar35;
687: pauVar11[3] = CONCAT214((ushort)bVar99 + sVar77,
688: CONCAT212(SUB162(auVar25 >> 0x60,0) + sVar76,
689: CONCAT210(SUB162(auVar25 >> 0x50,0) + sVar75,
690: CONCAT28(SUB162(auVar25 >> 0x40,0) + sVar74,
691: CONCAT26(SUB162(auVar25 >> 0x30,0)
692: + sVar73,CONCAT24(SUB162(
693: auVar25 >> 0x20,0) + sVar72,
694: CONCAT22(SUB162(auVar25 >> 0x10,0) + sVar71,
695: uVar89 + sVar62)))))));
696: auStack64._16_16_ = pslldq(auVar24,0xe);
697: auStack32 = pslldq(auVar35,0xe);
698: }
699: } while (uVar3 != 0);
700: param_3 = (undefined (**) [32])(auStack152 + 8);
701: pauVar11 = (undefined (*) [16])(auStack144._0_8_ + 0x10);
702: uVar3 = auStack144._8_8_ - 2;
703: in_YMM3 = auVar45;
704: } while (uVar3 != 0 && 1 < auStack144._8_8_);
705: }
706: return;
707: }
708: if ((uVar10 != 0) && (uVar3 != 0)) {
709: pauVar11 = *param_4;
710: do {
711: pauVar5 = param_3[-1];
712: pauVar8 = *param_3;
713: pauVar9 = param_3[1];
714: pauVar7 = *(undefined (**) [32])*pauVar11;
715: pauVar12 = *(undefined (**) [32])((long)*pauVar11 + 8);
716: in_YMM8 = vpxor_avx2(in_YMM8,in_YMM8);
717: auVar24 = vpcmpeqb_avx(SUB3216(in_YMM9,0),SUB3216(in_YMM9,0));
718: auVar35 = vpsrldq_avx(auVar24,0xe);
719: auVar24 = vpslldq_avx(auVar24,0xe);
720: in_YMM9 = vperm2i128_avx2(ZEXT1632(auVar24),ZEXT1632(auVar24),1);
721: if ((uVar1 & 0x1f) != 0) {
722: (*pauVar5)[uVar10] = pauVar5[-1][uVar10 + 0x1f];
723: (*pauVar8)[uVar10] = pauVar8[-1][uVar10 + 0x1f];
724: (*pauVar9)[uVar10] = pauVar9[-1][uVar10 + 0x1f];
725: }
726: auVar14 = vmovdqu_avx(*pauVar8);
727: auVar31 = vmovdqu_avx(*pauVar5);
728: auVar42 = vmovdqu_avx(*pauVar9);
729: auVar70 = vpunpckhbw_avx2(auVar14,in_YMM8);
730: auVar86 = vpunpcklbw_avx2(auVar14,in_YMM8);
731: auVar14 = vperm2i128_avx2(auVar86,auVar70,0x20);
732: auVar86 = vperm2i128_avx2(auVar86,auVar70,0x31);
733: auVar70 = vpunpckhbw_avx2(auVar31,in_YMM8);
734: auVar97 = vpunpcklbw_avx2(auVar31,in_YMM8);
735: auVar31 = vperm2i128_avx2(auVar97,auVar70,0x20);
736: auVar97 = vperm2i128_avx2(auVar97,auVar70,0x31);
737: auVar98 = vpunpckhbw_avx2(auVar42,in_YMM8);
738: auVar70 = vpunpcklbw_avx2(auVar42,in_YMM8);
739: auVar42 = vperm2i128_avx2(auVar70,auVar98,0x20);
740: auVar98 = vperm2i128_avx2(auVar70,auVar98,0x31);
741: auVar14 = vpmullw_avx2(auVar14,_DAT_0019d000);
742: auVar70 = vpmullw_avx2(auVar86,_DAT_0019d000);
743: auVar31 = vpaddw_avx2(auVar31,auVar14);
744: auVar86 = vpaddw_avx2(auVar97,auVar70);
745: auVar42 = vpaddw_avx2(auVar42,auVar14);
746: auVar70 = vpaddw_avx2(auVar98,auVar70);
747: auVar14 = vmovdqu_avx(auVar31);
748: *pauVar7 = auVar14;
749: auVar14 = vmovdqu_avx(auVar86);
750: pauVar7[1] = auVar14;
751: auVar14 = vmovdqu_avx(auVar42);
752: *pauVar12 = auVar14;
753: auVar14 = vmovdqu_avx(auVar70);
754: pauVar12[1] = auVar14;
755: auVar14 = vpand_avx2(auVar31,CONCAT1616(in_YMM10_H,auVar35));
756: auVar31 = vpand_avx2(auVar42,CONCAT1616(in_YMM10_H,auVar35));
757: _auStack160 = vmovdqa_avx(auVar14);
758: unique0x00000a70 = vmovdqa_avx(auVar31);
759: uVar4 = uVar10 + 0x1f & 0xffffffffffffffe0;
760: if (0x20 < uVar4) goto LAB_00166d39;
761: do {
762: auVar14 = vpand_avx2(in_YMM9,pauVar7[1]);
763: auVar31 = vpand_avx2(in_YMM9,pauVar12[1]);
764: _auStack96 = vmovdqa_avx(auVar14);
765: auStack64 = vmovdqa_avx(auVar31);
766: while( true ) {
767: auVar98 = vmovdqu_avx(*pauVar7);
768: auVar70 = vmovdqu_avx(pauVar7[1]);
769: auVar14 = vperm2i128_avx2(in_YMM8,auVar98,3);
770: auVar14 = vpalignr_avx2(auVar14,auVar98,2);
771: auVar31 = vperm2i128_avx2(in_YMM8,auVar70,0x20);
772: auVar31 = vpslldq_avx2(auVar31,0xe);
773: auVar42 = vperm2i128_avx2(in_YMM8,auVar98,3);
774: auVar42 = vpsrldq_avx2(auVar42,0xe);
775: auVar86 = vperm2i128_avx2(in_YMM8,auVar70,0x20);
776: auVar86 = vpalignr_avx2(auVar70,auVar86,0xe);
777: auVar14 = vpor_avx2(auVar14,auVar31);
778: auVar97 = vpor_avx2(auVar42,auVar86);
779: auVar31 = vperm2i128_avx2(in_YMM8,auVar70,3);
780: auVar42 = vpalignr_avx2(auVar31,auVar70,2);
781: auVar31 = vperm2i128_avx2(in_YMM8,auVar70,3);
782: auVar86 = vpsrldq_avx2(auVar31,0xe);
783: auVar31 = vperm2i128_avx2(in_YMM8,auVar98,0x20);
784: auVar31 = vpalignr_avx2(auVar98,auVar31,0xe);
785: auVar31 = vpor_avx2(auVar31,_auStack160);
786: auVar42 = vpor_avx2(auVar42,_auStack96);
787: _auStack160 = vmovdqa_avx(auVar86);
788: auVar98 = vpmullw_avx2(auVar98,_DAT_0019d000);
789: auVar70 = vpmullw_avx2(auVar70,_DAT_0019d000);
790: auVar31 = vpaddw_avx2(auVar31,_DAT_0019d040);
791: auVar86 = vpaddw_avx2(auVar97,_DAT_0019d040);
792: auVar14 = vpaddw_avx2(auVar14,_DAT_0019d020);
793: auVar42 = vpaddw_avx2(auVar42,_DAT_0019d020);
794: auVar31 = vpaddw_avx2(auVar31,auVar98);
795: auVar86 = vpaddw_avx2(auVar86,auVar70);
796: auVar31 = vpsrlw_avx2(auVar31,4);
797: auVar86 = vpsrlw_avx2(auVar86,4);
798: auVar14 = vpaddw_avx2(auVar14,auVar98);
799: auVar42 = vpaddw_avx2(auVar42,auVar70);
800: auVar14 = vpsrlw_avx2(auVar14,4);
801: auVar42 = vpsrlw_avx2(auVar42,4);
802: auVar14 = vpsllw_avx2(auVar14,8);
803: auVar42 = vpsllw_avx2(auVar42,8);
804: auVar14 = vpor_avx2(auVar31,auVar14);
805: auVar31 = vpor_avx2(auVar86,auVar42);
806: auVar14 = vmovdqu_avx(auVar14);
807: *pauVar7 = auVar14;
808: auVar14 = vmovdqu_avx(auVar31);
809: pauVar7[1] = auVar14;
810: auVar97 = vmovdqu_avx(*pauVar12);
811: auVar70 = vmovdqu_avx(pauVar12[1]);
812: auVar14 = vperm2i128_avx2(in_YMM8,auVar97,3);
813: auVar86 = vpalignr_avx2(auVar14,auVar97,2);
814: auVar14 = vperm2i128_avx2(in_YMM8,auVar70,0x20);
815: auVar42 = vpslldq_avx2(auVar14,0xe);
816: auVar14 = vperm2i128_avx2(in_YMM8,auVar97,3);
817: auVar14 = vpsrldq_avx2(auVar14,0xe);
818: auVar31 = vperm2i128_avx2(in_YMM8,auVar70,0x20);
819: auVar31 = vpalignr_avx2(auVar70,auVar31,0xe);
820: auVar98 = vpor_avx2(auVar86,auVar42);
821: auVar14 = vpor_avx2(auVar14,auVar31);
822: auVar31 = vperm2i128_avx2(in_YMM8,auVar70,3);
823: auVar86 = vpalignr_avx2(auVar31,auVar70,2);
824: auVar31 = vperm2i128_avx2(in_YMM8,auVar70,3);
825: auVar42 = vpsrldq_avx2(auVar31,0xe);
826: auVar31 = vperm2i128_avx2(in_YMM8,auVar97,0x20);
827: auVar31 = vpalignr_avx2(auVar97,auVar31,0xe);
828: auVar31 = vpor_avx2(auVar31,stack0xffffffffffffff80);
829: auVar86 = vpor_avx2(auVar86,auStack64);
830: unique0x00000a70 = vmovdqa_avx(auVar42);
831: auVar97 = vpmullw_avx2(auVar97,_DAT_0019d000);
832: auVar42 = vpmullw_avx2(auVar70,_DAT_0019d000);
833: auVar31 = vpaddw_avx2(auVar31,_DAT_0019d040);
834: auVar14 = vpaddw_avx2(auVar14,_DAT_0019d040);
835: auVar98 = vpaddw_avx2(auVar98,_DAT_0019d020);
836: auVar70 = vpaddw_avx2(auVar86,_DAT_0019d020);
837: auVar31 = vpaddw_avx2(auVar31,auVar97);
838: auVar14 = vpaddw_avx2(auVar14,auVar42);
839: auVar31 = vpsrlw_avx2(auVar31,4);
840: auVar14 = vpsrlw_avx2(auVar14,4);
841: auVar86 = vpaddw_avx2(auVar98,auVar97);
842: auVar42 = vpaddw_avx2(auVar70,auVar42);
843: auVar70 = vpsrlw_avx2(auVar86,4);
844: auVar42 = vpsrlw_avx2(auVar42,4);
845: auVar86 = vpsllw_avx2(auVar70,8);
846: auVar70 = vpsllw_avx2(auVar42,8);
847: auVar42 = vpor_avx2(auVar31,auVar86);
848: auVar31 = vpor_avx2(auVar14,auVar70);
849: auVar14 = vmovdqu_avx(auVar42);
850: *pauVar12 = auVar14;
851: auVar14 = vmovdqu_avx(auVar31);
852: pauVar12[1] = auVar14;
853: uVar4 = uVar4 - 0x20;
854: pauVar5 = pauVar5[1];
855: pauVar8 = pauVar8[1];
856: pauVar9 = pauVar9[1];
857: pauVar7 = pauVar7[2];
858: pauVar12 = pauVar12[2];
859: if (uVar4 < 0x21) break;
860: LAB_00166d39:
861: auVar14 = vmovdqu_avx(pauVar8[1]);
862: auVar31 = vmovdqu_avx(pauVar5[1]);
863: auVar42 = vmovdqu_avx(pauVar9[1]);
864: auVar70 = vpunpckhbw_avx2(auVar14,in_YMM8);
865: auVar86 = vpunpcklbw_avx2(auVar14,in_YMM8);
866: auVar14 = vperm2i128_avx2(auVar86,auVar70,0x20);
867: auVar70 = vperm2i128_avx2(auVar86,auVar70,0x31);
868: auVar86 = vpunpckhbw_avx2(auVar31,in_YMM8);
869: auVar97 = vpunpcklbw_avx2(auVar31,in_YMM8);
870: auVar31 = vperm2i128_avx2(auVar97,auVar86,0x20);
871: auVar86 = vperm2i128_avx2(auVar97,auVar86,0x31);
872: auVar97 = vpunpckhbw_avx2(auVar42,in_YMM8);
873: auVar98 = vpunpcklbw_avx2(auVar42,in_YMM8);
874: auVar42 = vperm2i128_avx2(auVar98,auVar97,0x20);
875: auVar97 = vperm2i128_avx2(auVar98,auVar97,0x31);
876: auVar14 = vpmullw_avx2(auVar14,_DAT_0019d000);
877: auVar70 = vpmullw_avx2(auVar70,_DAT_0019d000);
878: auVar31 = vpaddw_avx2(auVar31,auVar14);
879: auVar86 = vpaddw_avx2(auVar86,auVar70);
880: auVar42 = vpaddw_avx2(auVar42,auVar14);
881: auVar70 = vpaddw_avx2(auVar97,auVar70);
882: auVar14 = vmovdqu_avx(auVar31);
883: pauVar7[2] = auVar14;
884: auVar14 = vmovdqu_avx(auVar86);
885: pauVar7[3] = auVar14;
886: auVar14 = vmovdqu_avx(auVar42);
887: pauVar12[2] = auVar14;
888: auVar14 = vmovdqu_avx(auVar70);
889: pauVar12[3] = auVar14;
890: auVar14 = vperm2i128_avx2(in_YMM8,auVar31,0x20);
891: auVar14 = vpslldq_avx2(auVar14,0xe);
892: auVar31 = vperm2i128_avx2(in_YMM8,auVar42,0x20);
893: auVar31 = vpslldq_avx2(auVar31,0xe);
894: _auStack96 = vmovdqa_avx(auVar14);
895: auStack64 = vmovdqa_avx(auVar31);
896: }
897: } while (uVar4 != 0);
898: param_3 = param_3 + 1;
899: pauVar11 = pauVar11[1];
900: uVar4 = uVar3 - 2;
901: bVar2 = 1 < (long)uVar3;
902: uVar3 = uVar4;
903: } while (uVar4 != 0 && bVar2);
904: }
905: vzeroupper_avx();
906: return;
907: }
908: 
