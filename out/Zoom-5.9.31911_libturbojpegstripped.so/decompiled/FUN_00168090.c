1: 
2: void FUN_00168090(long param_1,long param_2,undefined (**param_3) [32],undefined (**param_4) [32])
3: 
4: {
5: undefined uVar1;
6: uint uVar2;
7: bool bVar3;
8: ulong uVar4;
9: ulong uVar5;
10: ulong uVar6;
11: long lVar7;
12: long lVar8;
13: ulong uVar9;
14: undefined (**ppauVar10) [32];
15: undefined (*pauVar11) [32];
16: undefined *puVar12;
17: undefined (*pauVar13) [32];
18: ushort uVar14;
19: ushort uVar18;
20: ushort uVar19;
21: ushort uVar20;
22: ushort uVar21;
23: ushort uVar22;
24: ushort uVar23;
25: undefined auVar15 [16];
26: undefined auVar16 [16];
27: ushort uVar24;
28: undefined auVar17 [32];
29: ushort uVar25;
30: ushort uVar28;
31: ushort uVar29;
32: ushort uVar30;
33: ushort uVar31;
34: ushort uVar32;
35: ushort uVar33;
36: undefined auVar26 [16];
37: ushort uVar34;
38: undefined auVar35 [16];
39: undefined auVar27 [32];
40: undefined in_YMM1 [32];
41: undefined auVar36 [32];
42: undefined auVar37 [32];
43: undefined auVar38 [16];
44: undefined auVar39 [32];
45: undefined in_YMM6 [32];
46: undefined auVar40 [32];
47: 
48: uVar2 = *(uint *)(param_2 + 0xc);
49: uVar5 = (ulong)*(uint *)(param_2 + 0x1c);
50: uVar6 = (ulong)*(uint *)(param_1 + 0x13c);
51: uVar9 = (ulong)*(uint *)(param_1 + 0x30);
52: if ((DAT_003a61e0 & 0x80) != 0) {
53: uVar4 = uVar5 << 3;
54: if (uVar5 != 0) {
55: lVar7 = uVar5 * 0x10 - uVar9;
56: if ((lVar7 != 0 && uVar9 <= uVar5 * 0x10) && (ppauVar10 = param_3, uVar6 != 0)) {
57: do {
58: uVar1 = (**ppauVar10 + uVar9)[-1];
59: lVar8 = lVar7;
60: puVar12 = **ppauVar10 + uVar9;
61: while (lVar8 != 0) {
62: lVar8 = lVar8 + -1;
63: *puVar12 = uVar1;
64: puVar12 = puVar12 + 1;
65: }
66: uVar5 = uVar6 - 1;
67: bVar3 = 0 < (long)uVar6;
68: uVar6 = uVar5;
69: ppauVar10 = ppauVar10 + 1;
70: } while (uVar5 != 0 && bVar3);
71: }
72: if (0 < (int)uVar2) {
73: auVar38 = vmovd_avx(0x10000);
74: auVar38 = vpshufd_avx(auVar38,0);
75: auVar40 = vperm2i128_avx2(ZEXT1632(auVar38),ZEXT1632(auVar38),0);
76: auVar39 = vpcmpeqw_avx2(in_YMM6,in_YMM6);
77: auVar39 = vpsrlw_avx2(auVar39,8);
78: uVar6 = (ulong)uVar2;
79: do {
80: pauVar11 = *param_3;
81: pauVar13 = *param_4;
82: uVar5 = uVar4;
83: if (0x1f < uVar4) goto LAB_0016339a;
84: do {
85: if (uVar5 == 0x18) {
86: auVar17 = vmovdqu_avx(*pauVar11);
87: auVar38 = vmovdqu_avx(*(undefined (*) [16])pauVar11[1]);
88: auVar27 = ZEXT1632(auVar38);
89: uVar5 = 0x20;
90: }
91: else {
92: if (uVar5 == 0x10) {
93: auVar17 = vmovdqu_avx(*pauVar11);
94: auVar27 = vpxor_avx2(in_YMM1,in_YMM1);
95: uVar5 = 0x20;
96: }
97: else {
98: auVar38 = vmovdqu_avx(*(undefined (*) [16])*pauVar11);
99: auVar17 = ZEXT1632(auVar38);
100: auVar27 = vpxor_avx2(in_YMM1,in_YMM1);
101: uVar5 = 0x20;
102: }
103: }
104: while( true ) {
105: auVar36 = vpsrlw_avx2(auVar17,8);
106: auVar17 = vpand_avx2(auVar17,auVar39);
107: auVar37 = vpsrlw_avx2(auVar27,8);
108: auVar27 = vpand_avx2(auVar27,auVar39);
109: auVar17 = vpaddw_avx2(auVar17,auVar36);
110: auVar27 = vpaddw_avx2(auVar27,auVar37);
111: auVar17 = vpaddw_avx2(auVar17,auVar40);
112: auVar27 = vpaddw_avx2(auVar27,auVar40);
113: auVar17 = vpsrlw_avx2(auVar17,1);
114: in_YMM1 = vpsrlw_avx2(auVar27,1);
115: auVar17 = vpackuswb_avx2(auVar17,in_YMM1);
116: auVar17 = vpermq_avx2(auVar17,0xd8);
117: auVar17 = vmovdqu_avx(auVar17);
118: *pauVar13 = auVar17;
119: uVar5 = uVar5 - 0x20;
120: pauVar11 = pauVar11[2];
121: pauVar13 = pauVar13[1];
122: if (uVar5 < 0x20) break;
123: LAB_0016339a:
124: auVar17 = vmovdqu_avx(*pauVar11);
125: auVar27 = vmovdqu_avx(pauVar11[1]);
126: }
127: } while (uVar5 != 0);
128: param_3 = param_3 + 1;
129: param_4 = param_4 + 1;
130: uVar5 = uVar6 - 1;
131: bVar3 = 0 < (long)uVar6;
132: uVar6 = uVar5;
133: } while (uVar5 != 0 && bVar3);
134: }
135: }
136: vzeroupper_avx();
137: return;
138: }
139: if (uVar5 != 0) {
140: lVar7 = uVar5 * 0x10 - uVar9;
141: if ((lVar7 != 0 && uVar9 <= uVar5 * 0x10) && (ppauVar10 = param_3, uVar6 != 0)) {
142: do {
143: uVar1 = (**ppauVar10 + uVar9)[-1];
144: lVar8 = lVar7;
145: puVar12 = **ppauVar10 + uVar9;
146: while (lVar8 != 0) {
147: lVar8 = lVar8 + -1;
148: *puVar12 = uVar1;
149: puVar12 = puVar12 + 1;
150: }
151: uVar4 = uVar6 - 1;
152: bVar3 = 0 < (long)uVar6;
153: uVar6 = uVar4;
154: ppauVar10 = ppauVar10 + 1;
155: } while (uVar4 != 0 && bVar3);
156: }
157: if (0 < (int)uVar2) {
158: auVar38 = CONCAT214(0xff,CONCAT212(0xff,CONCAT210(0xff,CONCAT28(0xff,0xff00ff00ff00ff))));
159: uVar6 = (ulong)uVar2;
160: do {
161: auVar35 = SUB3216(in_YMM1 >> 0x80,0);
162: pauVar11 = *param_3;
163: pauVar13 = *param_4;
164: uVar9 = uVar5 << 3;
165: if (0xf < uVar5 << 3) goto LAB_00159949;
166: do {
167: auVar15 = *(undefined (*) [16])*pauVar11;
168: auVar39 = in_YMM1 & (undefined  [32])0xffffffffffffffff;
169: uVar9 = 0x10;
170: while( true ) {
171: auVar16 = auVar15 & auVar38;
172: auVar35 = SUB3216(auVar39 >> 0x80,0);
173: auVar26 = SUB3216(auVar39,0) & auVar38;
174: uVar14 = (ushort)(SUB162(auVar16,0) + (SUB162(auVar15,0) >> 8)) >> 1;
175: uVar18 = (ushort)(SUB162(auVar16 >> 0x10,0) + (SUB162(auVar15 >> 0x10,0) >> 8) + 1) >> 1
176: ;
177: uVar19 = (ushort)(SUB162(auVar16 >> 0x20,0) + (SUB162(auVar15 >> 0x20,0) >> 8)) >> 1;
178: uVar20 = (ushort)(SUB162(auVar16 >> 0x30,0) + (SUB162(auVar15 >> 0x30,0) >> 8) + 1) >> 1
179: ;
180: uVar21 = (ushort)(SUB162(auVar16 >> 0x40,0) + (SUB162(auVar15 >> 0x40,0) >> 8)) >> 1;
181: uVar22 = (ushort)(SUB162(auVar16 >> 0x50,0) + (SUB162(auVar15 >> 0x50,0) >> 8) + 1) >> 1
182: ;
183: uVar23 = (ushort)(SUB162(auVar16 >> 0x60,0) + (SUB162(auVar15 >> 0x60,0) >> 8)) >> 1;
184: uVar24 = (ushort)(SUB162(auVar16 >> 0x70,0) + SUB162(auVar15 >> 0x78,0) + 1) >> 1;
185: uVar25 = (ushort)(SUB162(auVar26,0) + (SUB322(auVar39,0) >> 8)) >> 1;
186: uVar28 = (ushort)(SUB162(auVar26 >> 0x10,0) + (SUB322(auVar39 >> 0x10,0) >> 8) + 1) >> 1
187: ;
188: uVar29 = (ushort)(SUB162(auVar26 >> 0x20,0) + (SUB322(auVar39 >> 0x20,0) >> 8)) >> 1;
189: uVar30 = (ushort)(SUB162(auVar26 >> 0x30,0) + (SUB322(auVar39 >> 0x30,0) >> 8) + 1) >> 1
190: ;
191: uVar31 = (ushort)(SUB162(auVar26 >> 0x40,0) + (SUB322(auVar39 >> 0x40,0) >> 8)) >> 1;
192: uVar32 = (ushort)(SUB162(auVar26 >> 0x50,0) + (SUB322(auVar39 >> 0x50,0) >> 8) + 1) >> 1
193: ;
194: uVar33 = (ushort)(SUB162(auVar26 >> 0x60,0) + (SUB322(auVar39 >> 0x60,0) >> 8)) >> 1;
195: uVar34 = (ushort)(SUB162(auVar26 >> 0x70,0) + (SUB322(auVar39 >> 0x70,0) >> 8) + 1) >> 1
196: ;
197: in_YMM1 = CONCAT1616(auVar35,CONCAT214(uVar34,CONCAT212(uVar33,CONCAT210(uVar32,CONCAT28
198: (uVar31,CONCAT26(uVar30,CONCAT24(uVar29,CONCAT22(
199: uVar28,uVar25))))))));
200: *(undefined (*) [16])*pauVar13 =
201: CONCAT115((uVar34 != 0) * (uVar34 < 0xff) * (char)uVar34 - (0xff < uVar34),
202: CONCAT114((uVar33 != 0) * (uVar33 < 0xff) * (char)uVar33 -
203: (0xff < uVar33),
204: CONCAT113((uVar32 != 0) * (uVar32 < 0xff) * (char)uVar32 -
205: (0xff < uVar32),
206: CONCAT112((uVar31 != 0) * (uVar31 < 0xff) *
207: (char)uVar31 - (0xff < uVar31),
208: CONCAT111((uVar30 != 0) * (uVar30 < 0xff) *
209: (char)uVar30 - (0xff < uVar30),
210: CONCAT110((uVar29 != 0) *
211: (uVar29 < 0xff) *
212: (char)uVar29 -
213: (0xff < uVar29),
214: CONCAT19((uVar28 != 0)
215: * (uVar28 < 
216: 0xff) * (char)uVar28 - (0xff < uVar28),
217: CONCAT18((uVar25 != 0) * (uVar25 < 0xff) *
218: (char)uVar25 - (0xff < uVar25),
219: CONCAT17((uVar24 != 0) * (uVar24 < 0xff)
220: * (char)uVar24 - (0xff < uVar24)
221: ,CONCAT16((uVar23 != 0) *
222: (uVar23 < 0xff) *
223: (char)uVar23 -
224: (0xff < uVar23),
225: CONCAT15((uVar22 != 0)
226: * (uVar22 < 
227: 0xff) * (char)uVar22 - (0xff < uVar22),
228: CONCAT14((uVar21 != 0) * (uVar21 < 0xff) *
229: (char)uVar21 - (0xff < uVar21),
230: CONCAT13((uVar20 != 0) * (uVar20 < 0xff)
231: * (char)uVar20 - (0xff < uVar20)
232: ,CONCAT12((uVar19 != 0) *
233: (uVar19 < 0xff) *
234: (char)uVar19 -
235: (0xff < uVar19),
236: CONCAT11((uVar18 != 0)
237: * (uVar18 < 
238: 0xff) * (char)uVar18 - (0xff < uVar18),
239: (uVar14 != 0) * (uVar14 < 0xff) * (char)uVar14 -
240: (0xff < uVar14))))))))))))))));
241: uVar9 = uVar9 - 0x10;
242: pauVar11 = pauVar11[1];
243: pauVar13 = (undefined (*) [32])(*pauVar13 + 0x10);
244: if (uVar9 < 0x10) break;
245: LAB_00159949:
246: auVar15 = *(undefined (*) [16])*pauVar11;
247: auVar39 = CONCAT1616(auVar35,*(undefined (*) [16])(*pauVar11 + 0x10));
248: }
249: } while (uVar9 != 0);
250: param_3 = param_3 + 1;
251: param_4 = param_4 + 1;
252: uVar9 = uVar6 - 1;
253: bVar3 = 0 < (long)uVar6;
254: uVar6 = uVar9;
255: } while (uVar9 != 0 && bVar3);
256: }
257: }
258: return;
259: }
260: 
