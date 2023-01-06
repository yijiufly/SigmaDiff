1: 
2: void FUN_00168060(long param_1,long param_2,undefined (**param_3) [32],undefined (**param_4) [32])
3: 
4: {
5: undefined uVar1;
6: bool bVar2;
7: ulong uVar3;
8: ulong uVar4;
9: ulong uVar5;
10: long lVar6;
11: long lVar7;
12: ulong uVar8;
13: undefined (*pauVar9) [32];
14: undefined (**ppauVar10) [32];
15: undefined (*pauVar11) [32];
16: undefined *puVar12;
17: undefined (*pauVar13) [32];
18: ulong uVar14;
19: ushort uVar15;
20: ushort uVar19;
21: ushort uVar20;
22: ushort uVar21;
23: ushort uVar22;
24: ushort uVar23;
25: ushort uVar24;
26: undefined auVar16 [16];
27: undefined auVar17 [16];
28: ushort uVar25;
29: undefined auVar18 [32];
30: undefined auVar26 [16];
31: undefined auVar27 [16];
32: undefined auVar28 [32];
33: ushort uVar29;
34: ushort uVar32;
35: ushort uVar33;
36: ushort uVar34;
37: ushort uVar35;
38: ushort uVar36;
39: ushort uVar37;
40: undefined auVar30 [16];
41: ushort uVar38;
42: undefined auVar39 [16];
43: undefined auVar31 [32];
44: undefined in_YMM2 [32];
45: short sVar40;
46: short sVar43;
47: short sVar44;
48: short sVar45;
49: short sVar46;
50: short sVar47;
51: short sVar48;
52: undefined auVar41 [16];
53: short sVar49;
54: undefined auVar50 [16];
55: undefined auVar42 [32];
56: undefined in_YMM3 [32];
57: undefined auVar51 [32];
58: undefined auVar52 [32];
59: undefined auVar53 [16];
60: undefined auVar54 [32];
61: undefined in_YMM6 [32];
62: undefined auVar55 [32];
63: 
64: uVar5 = (ulong)*(uint *)(param_2 + 0xc);
65: uVar4 = (ulong)*(uint *)(param_2 + 0x1c);
66: uVar8 = (ulong)*(uint *)(param_1 + 0x13c);
67: uVar14 = (ulong)*(uint *)(param_1 + 0x30);
68: if ((DAT_003a61e0 & 0x80) != 0) {
69: uVar3 = uVar4 << 3;
70: if (uVar4 != 0) {
71: lVar6 = uVar4 * 0x10 - uVar14;
72: if ((lVar6 != 0 && uVar14 <= uVar4 * 0x10) && (ppauVar10 = param_3, uVar8 != 0)) {
73: do {
74: uVar1 = (**ppauVar10 + uVar14)[-1];
75: lVar7 = lVar6;
76: puVar12 = **ppauVar10 + uVar14;
77: while (lVar7 != 0) {
78: lVar7 = lVar7 + -1;
79: *puVar12 = uVar1;
80: puVar12 = puVar12 + 1;
81: }
82: uVar4 = uVar8 - 1;
83: bVar2 = 0 < (long)uVar8;
84: uVar8 = uVar4;
85: ppauVar10 = ppauVar10 + 1;
86: } while (uVar4 != 0 && bVar2);
87: }
88: if (uVar5 != 0) {
89: auVar53 = vmovd_avx(0x20001);
90: auVar54 = vpcmpeqw_avx2(in_YMM6,in_YMM6);
91: auVar53 = vpshufd_avx(auVar53,0);
92: auVar55 = vperm2i128_avx2(ZEXT1632(auVar53),ZEXT1632(auVar53),0);
93: auVar54 = vpsrlw_avx2(auVar54,8);
94: do {
95: pauVar9 = *param_3;
96: pauVar11 = param_3[1];
97: pauVar13 = *param_4;
98: uVar8 = uVar3;
99: if (0x1f < uVar3) goto LAB_00163518;
100: do {
101: if (uVar8 == 0x18) {
102: auVar18 = vmovdqu_avx(*pauVar9);
103: auVar28 = vmovdqu_avx(*pauVar11);
104: auVar53 = vmovdqu_avx(*(undefined (*) [16])pauVar9[1]);
105: auVar31 = ZEXT1632(auVar53);
106: auVar53 = vmovdqu_avx(*(undefined (*) [16])pauVar11[1]);
107: auVar42 = ZEXT1632(auVar53);
108: uVar8 = 0x20;
109: }
110: else {
111: if (uVar8 == 0x10) {
112: auVar18 = vmovdqu_avx(*pauVar9);
113: auVar28 = vmovdqu_avx(*pauVar11);
114: auVar31 = vpxor_avx2(in_YMM2,in_YMM2);
115: auVar42 = vpxor_avx2(in_YMM3,in_YMM3);
116: uVar8 = 0x20;
117: }
118: else {
119: auVar53 = vmovdqu_avx(*(undefined (*) [16])*pauVar9);
120: auVar18 = ZEXT1632(auVar53);
121: auVar53 = vmovdqu_avx(*(undefined (*) [16])*pauVar11);
122: auVar28 = ZEXT1632(auVar53);
123: auVar31 = vpxor_avx2(in_YMM2,in_YMM2);
124: auVar42 = vpxor_avx2(in_YMM3,in_YMM3);
125: uVar8 = 0x20;
126: }
127: }
128: while( true ) {
129: auVar51 = vpand_avx2(auVar18,auVar54);
130: auVar18 = vpsrlw_avx2(auVar18,8);
131: auVar52 = vpand_avx2(auVar28,auVar54);
132: auVar28 = vpsrlw_avx2(auVar28,8);
133: auVar18 = vpaddw_avx2(auVar18,auVar51);
134: auVar28 = vpaddw_avx2(auVar28,auVar52);
135: auVar51 = vpand_avx2(auVar31,auVar54);
136: auVar31 = vpsrlw_avx2(auVar31,8);
137: auVar52 = vpand_avx2(auVar42,auVar54);
138: auVar42 = vpsrlw_avx2(auVar42,8);
139: auVar31 = vpaddw_avx2(auVar31,auVar51);
140: in_YMM3 = vpaddw_avx2(auVar42,auVar52);
141: auVar18 = vpaddw_avx2(auVar18,auVar28);
142: auVar28 = vpaddw_avx2(auVar31,in_YMM3);
143: auVar18 = vpaddw_avx2(auVar18,auVar55);
144: auVar28 = vpaddw_avx2(auVar28,auVar55);
145: auVar18 = vpsrlw_avx2(auVar18,2);
146: in_YMM2 = vpsrlw_avx2(auVar28,2);
147: auVar18 = vpackuswb_avx2(auVar18,in_YMM2);
148: auVar18 = vpermq_avx2(auVar18,0xd8);
149: auVar18 = vmovdqu_avx(auVar18);
150: *pauVar13 = auVar18;
151: uVar8 = uVar8 - 0x20;
152: pauVar9 = pauVar9[2];
153: pauVar11 = pauVar11[2];
154: pauVar13 = pauVar13[1];
155: if (uVar8 < 0x20) break;
156: LAB_00163518:
157: auVar18 = vmovdqu_avx(*pauVar9);
158: auVar28 = vmovdqu_avx(*pauVar11);
159: auVar31 = vmovdqu_avx(pauVar9[1]);
160: auVar42 = vmovdqu_avx(pauVar11[1]);
161: }
162: } while (uVar8 != 0);
163: param_3 = param_3 + 2;
164: param_4 = param_4 + 1;
165: uVar8 = uVar5 - 1;
166: bVar2 = 0 < (long)uVar5;
167: uVar5 = uVar8;
168: } while (uVar8 != 0 && bVar2);
169: }
170: }
171: vzeroupper_avx();
172: return;
173: }
174: if (uVar4 != 0) {
175: lVar6 = uVar4 * 0x10 - uVar14;
176: if ((lVar6 != 0 && uVar14 <= uVar4 * 0x10) && (ppauVar10 = param_3, uVar8 != 0)) {
177: do {
178: uVar1 = (**ppauVar10 + uVar14)[-1];
179: lVar7 = lVar6;
180: puVar12 = **ppauVar10 + uVar14;
181: while (lVar7 != 0) {
182: lVar7 = lVar7 + -1;
183: *puVar12 = uVar1;
184: puVar12 = puVar12 + 1;
185: }
186: uVar3 = uVar8 - 1;
187: bVar2 = 0 < (long)uVar8;
188: uVar8 = uVar3;
189: ppauVar10 = ppauVar10 + 1;
190: } while (uVar3 != 0 && bVar2);
191: }
192: if (uVar5 != 0) {
193: auVar53 = CONCAT214(0xff,CONCAT212(0xff,CONCAT210(0xff,CONCAT28(0xff,0xff00ff00ff00ff))));
194: do {
195: auVar50 = SUB3216(in_YMM3 >> 0x80,0);
196: auVar39 = SUB3216(in_YMM2 >> 0x80,0);
197: pauVar9 = *param_3;
198: pauVar11 = param_3[1];
199: pauVar13 = *param_4;
200: uVar8 = uVar4 << 3;
201: if (0xf < uVar4 << 3) goto LAB_00159a96;
202: do {
203: auVar16 = *(undefined (*) [16])*pauVar9;
204: auVar26 = *(undefined (*) [16])*pauVar11;
205: auVar54 = in_YMM2 & (undefined  [32])0xffffffffffffffff;
206: auVar55 = in_YMM3 & (undefined  [32])0xffffffffffffffff;
207: uVar8 = 0x10;
208: while( true ) {
209: auVar17 = auVar16 & auVar53;
210: auVar27 = auVar26 & auVar53;
211: auVar39 = SUB3216(auVar54 >> 0x80,0);
212: auVar30 = SUB3216(auVar54,0) & auVar53;
213: auVar50 = SUB3216(auVar55 >> 0x80,0);
214: auVar41 = SUB3216(auVar55,0) & auVar53;
215: sVar40 = SUB162(auVar41,0) + (SUB322(auVar55,0) >> 8);
216: sVar43 = SUB162(auVar41 >> 0x10,0) + (SUB322(auVar55 >> 0x10,0) >> 8);
217: sVar44 = SUB162(auVar41 >> 0x20,0) + (SUB322(auVar55 >> 0x20,0) >> 8);
218: sVar45 = SUB162(auVar41 >> 0x30,0) + (SUB322(auVar55 >> 0x30,0) >> 8);
219: sVar46 = SUB162(auVar41 >> 0x40,0) + (SUB322(auVar55 >> 0x40,0) >> 8);
220: sVar47 = SUB162(auVar41 >> 0x50,0) + (SUB322(auVar55 >> 0x50,0) >> 8);
221: sVar48 = SUB162(auVar41 >> 0x60,0) + (SUB322(auVar55 >> 0x60,0) >> 8);
222: sVar49 = SUB162(auVar41 >> 0x70,0) + (SUB322(auVar55 >> 0x70,0) >> 8);
223: in_YMM3 = CONCAT1616(auVar50,CONCAT214(sVar49,CONCAT212(sVar48,CONCAT210(sVar47,CONCAT28
224: (sVar46,CONCAT26(sVar45,CONCAT24(sVar44,CONCAT22(
225: sVar43,sVar40))))))));
226: uVar15 = (ushort)(SUB162(auVar17,0) + (SUB162(auVar16,0) >> 8) +
227: SUB162(auVar27,0) + (SUB162(auVar26,0) >> 8) + 1) >> 2;
228: uVar19 = (ushort)(SUB162(auVar17 >> 0x10,0) + (SUB162(auVar16 >> 0x10,0) >> 8) +
229: SUB162(auVar27 >> 0x10,0) + (SUB162(auVar26 >> 0x10,0) >> 8) + 2) >> 2
230: ;
231: uVar20 = (ushort)(SUB162(auVar17 >> 0x20,0) + (SUB162(auVar16 >> 0x20,0) >> 8) +
232: SUB162(auVar27 >> 0x20,0) + (SUB162(auVar26 >> 0x20,0) >> 8) + 1) >> 2
233: ;
234: uVar21 = (ushort)(SUB162(auVar17 >> 0x30,0) + (SUB162(auVar16 >> 0x30,0) >> 8) +
235: SUB162(auVar27 >> 0x30,0) + (SUB162(auVar26 >> 0x30,0) >> 8) + 2) >> 2
236: ;
237: uVar22 = (ushort)(SUB162(auVar17 >> 0x40,0) + (SUB162(auVar16 >> 0x40,0) >> 8) +
238: SUB162(auVar27 >> 0x40,0) + (SUB162(auVar26 >> 0x40,0) >> 8) + 1) >> 2
239: ;
240: uVar23 = (ushort)(SUB162(auVar17 >> 0x50,0) + (SUB162(auVar16 >> 0x50,0) >> 8) +
241: SUB162(auVar27 >> 0x50,0) + (SUB162(auVar26 >> 0x50,0) >> 8) + 2) >> 2
242: ;
243: uVar24 = (ushort)(SUB162(auVar17 >> 0x60,0) + (SUB162(auVar16 >> 0x60,0) >> 8) +
244: SUB162(auVar27 >> 0x60,0) + (SUB162(auVar26 >> 0x60,0) >> 8) + 1) >> 2
245: ;
246: uVar25 = (ushort)(SUB162(auVar17 >> 0x70,0) + SUB162(auVar16 >> 0x78,0) +
247: SUB162(auVar27 >> 0x70,0) + SUB162(auVar26 >> 0x78,0) + 2) >> 2;
248: uVar29 = (ushort)(SUB162(auVar30,0) + (SUB322(auVar54,0) >> 8) + sVar40 + 1) >> 2;
249: uVar32 = (ushort)(SUB162(auVar30 >> 0x10,0) + (SUB322(auVar54 >> 0x10,0) >> 8) + sVar43
250: + 2) >> 2;
251: uVar33 = (ushort)(SUB162(auVar30 >> 0x20,0) + (SUB322(auVar54 >> 0x20,0) >> 8) + sVar44
252: + 1) >> 2;
253: uVar34 = (ushort)(SUB162(auVar30 >> 0x30,0) + (SUB322(auVar54 >> 0x30,0) >> 8) + sVar45
254: + 2) >> 2;
255: uVar35 = (ushort)(SUB162(auVar30 >> 0x40,0) + (SUB322(auVar54 >> 0x40,0) >> 8) + sVar46
256: + 1) >> 2;
257: uVar36 = (ushort)(SUB162(auVar30 >> 0x50,0) + (SUB322(auVar54 >> 0x50,0) >> 8) + sVar47
258: + 2) >> 2;
259: uVar37 = (ushort)(SUB162(auVar30 >> 0x60,0) + (SUB322(auVar54 >> 0x60,0) >> 8) + sVar48
260: + 1) >> 2;
261: uVar38 = (ushort)(SUB162(auVar30 >> 0x70,0) + (SUB322(auVar54 >> 0x70,0) >> 8) + sVar49
262: + 2) >> 2;
263: in_YMM2 = CONCAT1616(auVar39,CONCAT214(uVar38,CONCAT212(uVar37,CONCAT210(uVar36,CONCAT28
264: (uVar35,CONCAT26(uVar34,CONCAT24(uVar33,CONCAT22(
265: uVar32,uVar29))))))));
266: *(undefined (*) [16])*pauVar13 =
267: CONCAT115((uVar38 != 0) * (uVar38 < 0xff) * (char)uVar38 - (0xff < uVar38),
268: CONCAT114((uVar37 != 0) * (uVar37 < 0xff) * (char)uVar37 -
269: (0xff < uVar37),
270: CONCAT113((uVar36 != 0) * (uVar36 < 0xff) * (char)uVar36 -
271: (0xff < uVar36),
272: CONCAT112((uVar35 != 0) * (uVar35 < 0xff) *
273: (char)uVar35 - (0xff < uVar35),
274: CONCAT111((uVar34 != 0) * (uVar34 < 0xff) *
275: (char)uVar34 - (0xff < uVar34),
276: CONCAT110((uVar33 != 0) *
277: (uVar33 < 0xff) *
278: (char)uVar33 -
279: (0xff < uVar33),
280: CONCAT19((uVar32 != 0)
281: * (uVar32 < 
282: 0xff) * (char)uVar32 - (0xff < uVar32),
283: CONCAT18((uVar29 != 0) * (uVar29 < 0xff) *
284: (char)uVar29 - (0xff < uVar29),
285: CONCAT17((uVar25 != 0) * (uVar25 < 0xff)
286: * (char)uVar25 - (0xff < uVar25)
287: ,CONCAT16((uVar24 != 0) *
288: (uVar24 < 0xff) *
289: (char)uVar24 -
290: (0xff < uVar24),
291: CONCAT15((uVar23 != 0)
292: * (uVar23 < 
293: 0xff) * (char)uVar23 - (0xff < uVar23),
294: CONCAT14((uVar22 != 0) * (uVar22 < 0xff) *
295: (char)uVar22 - (0xff < uVar22),
296: CONCAT13((uVar21 != 0) * (uVar21 < 0xff)
297: * (char)uVar21 - (0xff < uVar21)
298: ,CONCAT12((uVar20 != 0) *
299: (uVar20 < 0xff) *
300: (char)uVar20 -
301: (0xff < uVar20),
302: CONCAT11((uVar19 != 0)
303: * (uVar19 < 
304: 0xff) * (char)uVar19 - (0xff < uVar19),
305: (uVar15 != 0) * (uVar15 < 0xff) * (char)uVar15 -
306: (0xff < uVar15))))))))))))))));
307: uVar8 = uVar8 - 0x10;
308: pauVar9 = pauVar9[1];
309: pauVar11 = pauVar11[1];
310: pauVar13 = (undefined (*) [32])(*pauVar13 + 0x10);
311: if (uVar8 < 0x10) break;
312: LAB_00159a96:
313: auVar16 = *(undefined (*) [16])*pauVar9;
314: auVar26 = *(undefined (*) [16])*pauVar11;
315: auVar54 = CONCAT1616(auVar39,*(undefined (*) [16])(*pauVar9 + 0x10));
316: auVar55 = CONCAT1616(auVar50,*(undefined (*) [16])(*pauVar11 + 0x10));
317: }
318: } while (uVar8 != 0);
319: param_3 = param_3 + 2;
320: param_4 = param_4 + 1;
321: uVar8 = uVar5 - 1;
322: bVar2 = 0 < (long)uVar5;
323: uVar5 = uVar8;
324: } while (uVar8 != 0 && bVar2);
325: }
326: }
327: return;
328: }
329: 
