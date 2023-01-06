1: 
2: /* WARNING: Type propagation algorithm not settling */
3: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
4: 
5: void FUN_00168290(long param_1,long param_2,undefined (**param_3) [32],undefined (**param_4) [32])
6: 
7: {
8: uint uVar1;
9: bool bVar2;
10: ulong uVar3;
11: ulong uVar4;
12: undefined (*pauVar5) [32];
13: ulong uVar6;
14: undefined (*pauVar7) [16];
15: undefined (*pauVar8) [32];
16: undefined (*pauVar9) [32];
17: byte bVar10;
18: undefined uVar12;
19: undefined uVar13;
20: undefined uVar14;
21: undefined uVar15;
22: undefined uVar16;
23: undefined uVar17;
24: undefined uVar18;
25: undefined uVar19;
26: undefined uVar20;
27: undefined uVar21;
28: undefined uVar22;
29: undefined uVar23;
30: undefined uVar24;
31: undefined uVar25;
32: undefined uVar26;
33: undefined auVar11 [32];
34: undefined in_YMM0 [32];
35: short sVar27;
36: short sVar29;
37: short sVar30;
38: short sVar31;
39: short sVar32;
40: short sVar33;
41: short sVar34;
42: short sVar35;
43: undefined auVar36 [16];
44: undefined auVar28 [32];
45: undefined in_YMM1 [32];
46: undefined auVar37 [16];
47: undefined auVar41 [16];
48: undefined auVar38 [32];
49: undefined auVar40 [32];
50: undefined in_YMM2 [32];
51: undefined auVar42 [16];
52: undefined auVar50 [16];
53: undefined auVar43 [32];
54: undefined auVar49 [32];
55: undefined in_YMM3 [32];
56: short sVar51;
57: undefined4 uVar52;
58: short sVar59;
59: short sVar60;
60: short sVar61;
61: short sVar62;
62: short sVar63;
63: short sVar64;
64: short sVar65;
65: undefined auVar58 [32];
66: short sVar66;
67: undefined auVar73 [32];
68: short sVar74;
69: undefined auVar81 [16];
70: undefined auVar82 [32];
71: undefined auVar83 [32];
72: undefined auVar84 [32];
73: undefined in_YMM7 [32];
74: undefined auVar85 [32];
75: undefined in_YMM9 [32];
76: undefined in_YMM10_H [16];
77: undefined auVar39 [32];
78: undefined auVar44 [32];
79: undefined auVar45 [32];
80: undefined auVar46 [32];
81: undefined auVar47 [32];
82: undefined auVar48 [32];
83: undefined6 uVar53;
84: undefined8 uVar54;
85: unkbyte10 Var55;
86: undefined auVar56 [12];
87: undefined auVar57 [14];
88: undefined4 uVar67;
89: undefined6 uVar68;
90: undefined8 uVar69;
91: unkbyte10 Var70;
92: undefined auVar71 [12];
93: undefined auVar72 [14];
94: undefined4 uVar75;
95: undefined6 uVar76;
96: undefined8 uVar77;
97: unkbyte10 Var78;
98: undefined auVar79 [12];
99: undefined auVar80 [14];
100: 
101: uVar1 = *(uint *)(param_2 + 0x28);
102: uVar6 = (ulong)uVar1;
103: uVar4 = (ulong)*(uint *)(param_1 + 0x19c);
104: if ((DAT_003a61e0 & 0x80) == 0) {
105: if ((uVar6 != 0) && (uVar4 != 0)) {
106: pauVar8 = *param_4;
107: do {
108: pauVar5 = *param_3;
109: pauVar7 = *(undefined (**) [16])*pauVar8;
110: if ((uVar1 & 0xf) != 0) {
111: (*pauVar5)[uVar6] = pauVar5[-1][uVar6 + 0x1f];
112: }
113: in_YMM0 = in_YMM0 & (undefined  [32])0xffffffffffffffff;
114: in_YMM7 = CONCAT1616(SUB3216(in_YMM7 >> 0x80,0),
115: CONCAT115(0xff,CONCAT114(0xff,CONCAT113(0xff,CONCAT112(0xff,CONCAT111(
116: 0xff,CONCAT110(0xff,CONCAT19(0xff,CONCAT18(0xff,
117: 0xffffffffffffffff)))))))) >> 0x78 &
118: *(undefined (*) [16])*pauVar5);
119: uVar3 = uVar6 + 0xf & 0xfffffffffffffff0;
120: if (0x10 < uVar3) goto LAB_0015cfa2;
121: do {
122: auVar81 = pslldq(CONCAT115(0xff,CONCAT114(0xff,CONCAT113(0xff,CONCAT112(0xff,CONCAT111(
123: 0xff,CONCAT110(0xff,CONCAT19(0xff,CONCAT18(0xff,
124: 0xffffffffffffffff)))))))),0xf);
125: auVar81 = auVar81 & *(undefined (*) [16])*pauVar5;
126: while( true ) {
127: auVar42 = *(undefined (*) [16])*pauVar5;
128: auVar36 = SUB3216(in_YMM1 >> 0x80,0);
129: auVar41 = SUB3216(in_YMM2 >> 0x80,0);
130: auVar50 = SUB3216(in_YMM3 >> 0x80,0);
131: auVar37 = pslldq(auVar42,1);
132: auVar37 = auVar37 | SUB3216(in_YMM7,0);
133: auVar81 = auVar42 >> 8 | auVar81;
134: in_YMM7 = CONCAT1616(SUB3216(in_YMM7 >> 0x80,0),auVar42 >> 0x78);
135: uVar18 = SUB321(in_YMM0 >> 0x38,0);
136: auVar82 = CONCAT1715(SUB3217(CONCAT1616(auVar36,CONCAT115(uVar18,SUB1615(auVar42,0))) >>
137: 0x78,0),
138: CONCAT114(SUB161(auVar42 >> 0x38,0),SUB1614(auVar42,0)));
139: uVar17 = SUB321(in_YMM0 >> 0x30,0);
140: auVar84 = CONCAT1913(SUB3219(CONCAT1814(SUB3218(auVar82 >> 0x70,0),
141: CONCAT113(uVar17,SUB1613(auVar42,0))) >> 0x68,0)
142: ,CONCAT112(SUB161(auVar42 >> 0x30,0),SUB1612(auVar42,0)));
143: uVar16 = SUB321(in_YMM0 >> 0x28,0);
144: auVar40 = CONCAT2111(SUB3221(CONCAT2012(SUB3220(auVar84 >> 0x60,0),
145: CONCAT111(uVar16,SUB1611(auVar42,0))) >> 0x58,0)
146: ,CONCAT110(SUB161(auVar42 >> 0x28,0),SUB1610(auVar42,0)));
147: uVar15 = SUB321(in_YMM0 >> 0x20,0);
148: auVar28 = CONCAT239(SUB3223(CONCAT2210(SUB3222(auVar40 >> 0x50,0),
149: CONCAT19(uVar15,SUB169(auVar42,0))) >> 0x48,0),
150: CONCAT18(SUB161(auVar42 >> 0x20,0),SUB168(auVar42,0)));
151: uVar14 = SUB321(in_YMM0 >> 0x18,0);
152: auVar11 = CONCAT257(CONCAT241(SUB3224(auVar28 >> 0x40,0),uVar14),
153: (SUB167(auVar42,0) >> 0x18) << 0x30);
154: uVar13 = SUB321(in_YMM0 >> 0x10,0);
155: auVar85 = CONCAT275(CONCAT261(SUB3226(auVar11 >> 0x30,0),uVar13),
156: (SUB165(auVar42,0) >> 0x10) << 0x20);
157: uVar12 = SUB321(in_YMM0 >> 8,0);
158: bVar10 = SUB321(in_YMM0,0);
159: uVar19 = SUB321(in_YMM0 >> 0x40,0);
160: sVar51 = CONCAT11(uVar19,SUB161(auVar42 >> 0x40,0));
161: uVar20 = SUB321(in_YMM0 >> 0x48,0);
162: uVar52 = CONCAT13(uVar20,CONCAT12(SUB161(auVar42 >> 0x48,0),sVar51));
163: uVar21 = SUB321(in_YMM0 >> 0x50,0);
164: uVar53 = CONCAT15(uVar21,CONCAT14(SUB161(auVar42 >> 0x50,0),uVar52));
165: uVar22 = SUB321(in_YMM0 >> 0x58,0);
166: uVar54 = CONCAT17(uVar22,CONCAT16(SUB161(auVar42 >> 0x58,0),uVar53));
167: uVar23 = SUB321(in_YMM0 >> 0x60,0);
168: Var55 = CONCAT19(uVar23,CONCAT18(SUB161(auVar42 >> 0x60,0),uVar54));
169: uVar24 = SUB321(in_YMM0 >> 0x68,0);
170: auVar56 = CONCAT111(uVar24,CONCAT110(SUB161(auVar42 >> 0x68,0),Var55));
171: uVar25 = SUB321(in_YMM0 >> 0x70,0);
172: auVar57 = CONCAT113(uVar25,CONCAT112(SUB161(auVar42 >> 0x70,0),auVar56));
173: uVar26 = SUB321(in_YMM0 >> 0x78,0);
174: auVar39 = CONCAT1715(SUB3217(CONCAT1616(auVar41,CONCAT115(uVar18,SUB1615(auVar37,0))) >>
175: 0x78,0),
176: CONCAT114(SUB161(auVar37 >> 0x38,0),SUB1614(auVar37,0)));
177: auVar38 = CONCAT1913(SUB3219(CONCAT1814(SUB3218(auVar39 >> 0x70,0),
178: CONCAT113(uVar17,SUB1613(auVar37,0))) >> 0x68,0)
179: ,CONCAT112(SUB161(auVar37 >> 0x30,0),SUB1612(auVar37,0)));
180: auVar83 = CONCAT2111(SUB3221(CONCAT2012(SUB3220(auVar38 >> 0x60,0),
181: CONCAT111(uVar16,SUB1611(auVar37,0))) >> 0x58,0)
182: ,CONCAT110(SUB161(auVar37 >> 0x28,0),SUB1610(auVar37,0)));
183: auVar73 = CONCAT239(SUB3223(CONCAT2210(SUB3222(auVar83 >> 0x50,0),
184: CONCAT19(uVar15,SUB169(auVar37,0))) >> 0x48,0),
185: CONCAT18(SUB161(auVar37 >> 0x20,0),SUB168(auVar37,0)));
186: auVar58 = CONCAT257(CONCAT241(SUB3224(auVar73 >> 0x40,0),uVar14),
187: (SUB167(auVar37,0) >> 0x18) << 0x30);
188: auVar49 = CONCAT275(CONCAT261(SUB3226(auVar58 >> 0x30,0),uVar13),
189: (SUB165(auVar37,0) >> 0x10) << 0x20);
190: sVar66 = CONCAT11(uVar19,SUB161(auVar37 >> 0x40,0));
191: uVar67 = CONCAT13(uVar20,CONCAT12(SUB161(auVar37 >> 0x48,0),sVar66));
192: uVar68 = CONCAT15(uVar21,CONCAT14(SUB161(auVar37 >> 0x50,0),uVar67));
193: uVar69 = CONCAT17(uVar22,CONCAT16(SUB161(auVar37 >> 0x58,0),uVar68));
194: Var70 = CONCAT19(uVar23,CONCAT18(SUB161(auVar37 >> 0x60,0),uVar69));
195: auVar71 = CONCAT111(uVar24,CONCAT110(SUB161(auVar37 >> 0x68,0),Var70));
196: auVar72 = CONCAT113(uVar25,CONCAT112(SUB161(auVar37 >> 0x70,0),auVar71));
197: auVar48 = CONCAT1715(SUB3217(CONCAT1616(auVar50,CONCAT115(uVar18,SUB1615(auVar81,0))) >>
198: 0x78,0),
199: CONCAT114(SUB161(auVar81 >> 0x38,0),SUB1614(auVar81,0)));
200: auVar47 = CONCAT1913(SUB3219(CONCAT1814(SUB3218(auVar48 >> 0x70,0),
201: CONCAT113(uVar17,SUB1613(auVar81,0))) >> 0x68,0)
202: ,CONCAT112(SUB161(auVar81 >> 0x30,0),SUB1612(auVar81,0)));
203: auVar46 = CONCAT2111(SUB3221(CONCAT2012(SUB3220(auVar47 >> 0x60,0),
204: CONCAT111(uVar16,SUB1611(auVar81,0))) >> 0x58,0)
205: ,CONCAT110(SUB161(auVar81 >> 0x28,0),SUB1610(auVar81,0)));
206: auVar45 = CONCAT239(SUB3223(CONCAT2210(SUB3222(auVar46 >> 0x50,0),
207: CONCAT19(uVar15,SUB169(auVar81,0))) >> 0x48,0),
208: CONCAT18(SUB161(auVar81 >> 0x20,0),SUB168(auVar81,0)));
209: auVar44 = CONCAT257(CONCAT241(SUB3224(auVar45 >> 0x40,0),uVar14),
210: (SUB167(auVar81,0) >> 0x18) << 0x30);
211: auVar43 = CONCAT275(CONCAT261(SUB3226(auVar44 >> 0x30,0),uVar13),
212: (SUB165(auVar81,0) >> 0x10) << 0x20);
213: sVar74 = CONCAT11(uVar19,SUB161(auVar81 >> 0x40,0));
214: uVar75 = CONCAT13(uVar20,CONCAT12(SUB161(auVar81 >> 0x48,0),sVar74));
215: uVar76 = CONCAT15(uVar21,CONCAT14(SUB161(auVar81 >> 0x50,0),uVar75));
216: uVar77 = CONCAT17(uVar22,CONCAT16(SUB161(auVar81 >> 0x58,0),uVar76));
217: Var78 = CONCAT19(uVar23,CONCAT18(SUB161(auVar81 >> 0x60,0),uVar77));
218: auVar79 = CONCAT111(uVar24,CONCAT110(SUB161(auVar81 >> 0x68,0),Var78));
219: auVar80 = CONCAT113(uVar25,CONCAT112(SUB161(auVar81 >> 0x70,0),auVar79));
220: sVar27 = (SUB162(auVar42,0) & 0xff | (ushort)bVar10 << 8) * 3;
221: sVar29 = SUB322(CONCAT293(CONCAT281(SUB3228(auVar85 >> 0x20,0),uVar12),
222: (SUB163(auVar42,0) >> 8) << 0x10) >> 0x10,0) * 3;
223: sVar30 = SUB322(auVar85 >> 0x20,0) * 3;
224: sVar31 = SUB322(auVar11 >> 0x30,0) * 3;
225: sVar32 = SUB322(auVar28 >> 0x40,0) * 3;
226: sVar33 = SUB322(auVar40 >> 0x50,0) * 3;
227: sVar34 = SUB322(auVar84 >> 0x60,0) * 3;
228: sVar35 = SUB322(auVar82 >> 0x70,0) * 3;
229: in_YMM1 = ZEXT2632(CONCAT1610(auVar36,CONCAT28(sVar35,CONCAT26(sVar34,CONCAT24(sVar33,
230: CONCAT22(sVar32,sVar31)))))) << 0x30;
231: sVar51 = sVar51 * 3;
232: sVar59 = (short)((uint)uVar52 >> 0x10) * 3;
233: sVar60 = (short)((uint6)uVar53 >> 0x20) * 3;
234: sVar61 = (short)((ulong)uVar54 >> 0x30) * 3;
235: sVar62 = (short)((unkuint10)Var55 >> 0x40) * 3;
236: sVar63 = SUB122(auVar56 >> 0x50,0) * 3;
237: sVar64 = SUB142(auVar57 >> 0x60,0) * 3;
238: sVar65 = SUB162(CONCAT115(uVar26,CONCAT114(SUB161(auVar42 >> 0x78,0),auVar57)) >> 0x70,0
239: ) * 3;
240: auVar42 = psllw(CONCAT214((ushort)(SUB322(auVar48 >> 0x70,0) + 2 + sVar35) >> 2,
241: CONCAT212((ushort)(SUB322(auVar47 >> 0x60,0) + 2 + sVar34) >>
242: 2,CONCAT210((ushort)(SUB322(auVar46 >> 0x50,0) + 2 +
243: sVar33) >> 2,
244: CONCAT28((ushort)(SUB322(auVar45 >> 0x40
245: ,0) + 2 +
246: sVar32) >> 2,
247: CONCAT26((ushort)(SUB322(
248: auVar44 >> 0x30,0) + 2 + sVar31) >> 2,
249: CONCAT24((ushort)(SUB322(auVar43 >> 0x20,0) + 2 +
250: sVar30) >> 2,
251: CONCAT22((ushort)(SUB322(CONCAT293(
252: CONCAT281(SUB3228(auVar43 >> 0x20,0),uVar12),
253: (SUB163(auVar81,0) >> 8) << 0x10) >> 0x10,0) + 2 +
254: sVar29) >> 2,
255: (ushort)((SUB162(auVar81,0) & 0xff |
256: (ushort)bVar10 << 8) + 2 + sVar27) >> 2))
257: ))))),8);
258: in_YMM3 = CONCAT1616(auVar50,auVar42);
259: auVar81 = psllw(CONCAT214((ushort)(SUB162(CONCAT115(uVar26,CONCAT114(SUB161(auVar81 >>
260: 0x78,0),
261: auVar80)) >> 0x70,0
262: ) + 2 + sVar65) >> 2,
263: CONCAT212((ushort)(SUB142(auVar80 >> 0x60,0) + 2 + sVar64) >>
264: 2,CONCAT210((ushort)(SUB122(auVar79 >> 0x50,0) + 2 +
265: sVar63) >> 2,
266: CONCAT28((ushort)((short)((unkuint10)
267: Var78 >> 0x40)
268: + 2 + sVar62) >> 2,
269: CONCAT26((ushort)((short)((
270: ulong)uVar77 >> 0x30) + 2 + sVar61) >> 2,
271: CONCAT24((ushort)((short)((uint6)uVar76 >> 0x20) +
272: 2 + sVar60) >> 2,
273: CONCAT22((ushort)((short)((uint)uVar75 >>
274: 0x10) + 2 +
275: sVar59) >> 2,
276: (ushort)(sVar74 + 2 + sVar51) >>
277: 2))))))),8);
278: auVar42 = CONCAT214((ushort)(SUB322(auVar39 >> 0x70,0) + 1 + sVar35) >> 2,
279: CONCAT212((ushort)(SUB322(auVar38 >> 0x60,0) + 1 + sVar34) >> 2,
280: CONCAT210((ushort)(SUB322(auVar83 >> 0x50,0) + 1 + sVar33)
281: >> 2,CONCAT28((ushort)(SUB322(auVar73 >> 0x40,0)
282: + 1 + sVar32) >> 2,
283: CONCAT26((ushort)(SUB322(auVar58 
284: >> 0x30,0) + 1 + sVar31) >> 2,
285: CONCAT24((ushort)(SUB322(auVar49 >> 0x20,0) + 1 +
286: sVar30) >> 2,
287: CONCAT22((ushort)(SUB322(CONCAT293(
288: CONCAT281(SUB3228(auVar49 >> 0x20,0),uVar12),
289: (SUB163(auVar37,0) >> 8) << 0x10) >> 0x10,0) + 1 +
290: sVar29) >> 2,
291: (ushort)((SUB162(auVar37,0) & 0xff |
292: (ushort)bVar10 << 8) + 1 + sVar27) >> 2))
293: ))))) | auVar42;
294: in_YMM2 = CONCAT1616(auVar41,auVar42);
295: *pauVar7 = auVar42;
296: pauVar7[1] = CONCAT214((ushort)(SUB162(CONCAT115(uVar26,CONCAT114(SUB161(auVar37 >> 0x78
297: ,0),auVar72))
298: >> 0x70,0) + 1 + sVar65) >> 2,
299: CONCAT212((ushort)(SUB142(auVar72 >> 0x60,0) + 1 + sVar64) >> 2,
300: CONCAT210((ushort)(SUB122(auVar71 >> 0x50,0) + 1 +
301: sVar63) >> 2,
302: CONCAT28((ushort)((short)((unkuint10)Var70 >>
303: 0x40) + 1 + sVar62)
304: >> 2,CONCAT26((ushort)((short)((
305: ulong)uVar69 >> 0x30) + 1 + sVar61) >> 2,
306: CONCAT24((ushort)((short)((uint6)uVar68 >> 0x20) +
307: 1 + sVar60) >> 2,
308: CONCAT22((ushort)((short)((uint)uVar67 >>
309: 0x10) + 1 +
310: sVar59) >> 2,
311: (ushort)(sVar66 + 1 + sVar51) >>
312: 2))))))) | auVar81;
313: uVar3 = uVar3 - 0x10;
314: pauVar5 = (undefined (*) [32])(*pauVar5 + 0x10);
315: pauVar7 = pauVar7[2];
316: if (uVar3 < 0x11) break;
317: LAB_0015cfa2:
318: auVar81 = pslldq(*(undefined (*) [16])(*pauVar5 + 0x10),0xf);
319: }
320: } while ((int)uVar3 != 0);
321: param_3 = param_3 + 1;
322: pauVar8 = (undefined (*) [32])((long)*pauVar8 + 8);
323: uVar3 = uVar4 - 1;
324: bVar2 = 0 < (long)uVar4;
325: uVar4 = uVar3;
326: } while (uVar3 != 0 && bVar2);
327: }
328: return;
329: }
330: if ((uVar6 != 0) && (uVar4 != 0)) {
331: pauVar8 = *param_4;
332: auVar11 = vpxor_avx2(in_YMM0,in_YMM0);
333: auVar81 = vpcmpeqb_avx(SUB3216(in_YMM9,0),SUB3216(in_YMM9,0));
334: auVar42 = vpsrldq_avx(auVar81,0xf);
335: auVar81 = vpslldq_avx(auVar81,0xf);
336: auVar85 = vperm2i128_avx2(ZEXT1632(auVar81),ZEXT1632(auVar81),1);
337: do {
338: pauVar5 = *param_3;
339: pauVar9 = *(undefined (**) [32])*pauVar8;
340: if ((uVar1 & 0x1f) != 0) {
341: (*pauVar5)[uVar6] = pauVar5[-1][uVar6 + 0x1f];
342: }
343: auVar84 = vpand_avx2(CONCAT1616(in_YMM10_H,auVar42),*pauVar5);
344: uVar3 = uVar6 + 0x1f & 0xffffffffffffffe0;
345: if (0x20 < uVar3) goto LAB_00166aa7;
346: do {
347: auVar82 = vpand_avx2(auVar85,*pauVar5);
348: while( true ) {
349: auVar28 = vmovdqu_avx(*pauVar5);
350: auVar40 = vperm2i128_avx2(auVar11,auVar28,0x20);
351: auVar40 = vpalignr_avx2(auVar28,auVar40,0xf);
352: auVar58 = vperm2i128_avx2(auVar11,auVar28,3);
353: auVar49 = vpalignr_avx2(auVar58,auVar28,1);
354: auVar40 = vpor_avx2(auVar40,auVar84);
355: auVar49 = vpor_avx2(auVar49,auVar82);
356: auVar84 = vpsrldq_avx2(auVar58,0xf);
357: auVar58 = vpunpckhbw_avx2(auVar28,auVar11);
358: auVar28 = vpunpcklbw_avx2(auVar28,auVar11);
359: auVar82 = vperm2i128_avx2(auVar28,auVar58,0x20);
360: auVar58 = vperm2i128_avx2(auVar28,auVar58,0x31);
361: auVar73 = vpunpckhbw_avx2(auVar40,auVar11);
362: auVar40 = vpunpcklbw_avx2(auVar40,auVar11);
363: auVar28 = vperm2i128_avx2(auVar40,auVar73,0x20);
364: auVar73 = vperm2i128_avx2(auVar40,auVar73,0x31);
365: auVar83 = vpunpckhbw_avx2(auVar49,auVar11);
366: auVar49 = vpunpcklbw_avx2(auVar49,auVar11);
367: auVar40 = vperm2i128_avx2(auVar49,auVar83,0x20);
368: auVar83 = vperm2i128_avx2(auVar49,auVar83,0x31);
369: auVar82 = vpmullw_avx2(auVar82,_DAT_0019d000);
370: auVar49 = vpmullw_avx2(auVar58,_DAT_0019d000);
371: auVar28 = vpaddw_avx2(auVar28,_DAT_0019cfc0);
372: auVar58 = vpaddw_avx2(auVar73,_DAT_0019cfc0);
373: auVar40 = vpaddw_avx2(auVar40,_DAT_0019cfe0);
374: auVar73 = vpaddw_avx2(auVar83,_DAT_0019cfe0);
375: auVar28 = vpaddw_avx2(auVar28,auVar82);
376: auVar58 = vpaddw_avx2(auVar58,auVar49);
377: auVar28 = vpsrlw_avx2(auVar28,2);
378: auVar58 = vpsrlw_avx2(auVar58,2);
379: auVar82 = vpaddw_avx2(auVar40,auVar82);
380: auVar40 = vpaddw_avx2(auVar73,auVar49);
381: auVar82 = vpsrlw_avx2(auVar82,2);
382: auVar40 = vpsrlw_avx2(auVar40,2);
383: auVar82 = vpsllw_avx2(auVar82,8);
384: auVar40 = vpsllw_avx2(auVar40,8);
385: auVar82 = vpor_avx2(auVar28,auVar82);
386: auVar28 = vpor_avx2(auVar58,auVar40);
387: auVar82 = vmovdqu_avx(auVar82);
388: *pauVar9 = auVar82;
389: auVar82 = vmovdqu_avx(auVar28);
390: pauVar9[1] = auVar82;
391: uVar3 = uVar3 - 0x20;
392: pauVar5 = pauVar5[1];
393: pauVar9 = pauVar9[2];
394: if (uVar3 < 0x21) break;
395: LAB_00166aa7:
396: auVar82 = vmovdqu_avx(pauVar5[1]);
397: auVar82 = vperm2i128_avx2(auVar11,auVar82,0x20);
398: auVar82 = vpslldq_avx2(auVar82,0xf);
399: }
400: } while ((int)uVar3 != 0);
401: param_3 = param_3 + 1;
402: pauVar8 = (undefined (*) [32])((long)*pauVar8 + 8);
403: uVar3 = uVar4 - 1;
404: bVar2 = 0 < (long)uVar4;
405: uVar4 = uVar3;
406: } while (uVar3 != 0 && bVar2);
407: }
408: vzeroupper_avx();
409: return;
410: }
411: 
