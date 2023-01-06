1: 
2: undefined *
3: FUN_00168770(undefined (*param_1) [32],undefined (*param_2) [32],undefined (*param_3) [32])
4: 
5: {
6: long lVar1;
7: undefined auVar2 [16];
8: undefined auVar3 [32];
9: undefined auVar4 [16];
10: undefined auVar5 [32];
11: undefined auVar6 [16];
12: undefined auVar7 [32];
13: undefined auVar8 [16];
14: undefined auVar9 [32];
15: short sVar12;
16: short sVar13;
17: short sVar14;
18: short sVar15;
19: short sVar16;
20: short sVar17;
21: undefined auVar10 [16];
22: short sVar18;
23: undefined auVar11 [32];
24: short sVar21;
25: short sVar22;
26: short sVar23;
27: short sVar24;
28: short sVar25;
29: short sVar26;
30: undefined auVar19 [16];
31: short sVar27;
32: undefined auVar20 [32];
33: short sVar30;
34: short sVar31;
35: short sVar32;
36: short sVar33;
37: short sVar34;
38: short sVar35;
39: undefined auVar28 [16];
40: short sVar36;
41: undefined auVar29 [32];
42: short sVar39;
43: short sVar40;
44: short sVar41;
45: short sVar42;
46: short sVar43;
47: short sVar44;
48: undefined auVar37 [16];
49: short sVar45;
50: undefined auVar38 [32];
51: 
52: if ((DAT_003a61e0 & 0x80) == 0) {
53: lVar1 = 2;
54: do {
55: auVar10 = psraw(*(undefined (*) [16])*param_3,0xf);
56: auVar19 = psraw(*(undefined (*) [16])(*param_3 + 0x10),0xf);
57: auVar28 = psraw(*(undefined (*) [16])param_3[1],0xf);
58: auVar37 = psraw(*(undefined (*) [16])(param_3[1] + 0x10),0xf);
59: auVar2 = *(undefined (*) [16])*param_3 ^ auVar10;
60: auVar4 = *(undefined (*) [16])(*param_3 + 0x10) ^ auVar19;
61: auVar6 = *(undefined (*) [16])param_3[1] ^ auVar28;
62: auVar8 = *(undefined (*) [16])(param_3[1] + 0x10) ^ auVar37;
63: sVar12 = SUB162(auVar10 >> 0x10,0);
64: sVar13 = SUB162(auVar10 >> 0x20,0);
65: sVar14 = SUB162(auVar10 >> 0x30,0);
66: sVar15 = SUB162(auVar10 >> 0x40,0);
67: sVar16 = SUB162(auVar10 >> 0x50,0);
68: sVar17 = SUB162(auVar10 >> 0x60,0);
69: sVar18 = SUB162(auVar10 >> 0x70,0);
70: sVar21 = SUB162(auVar19 >> 0x10,0);
71: sVar22 = SUB162(auVar19 >> 0x20,0);
72: sVar23 = SUB162(auVar19 >> 0x30,0);
73: sVar24 = SUB162(auVar19 >> 0x40,0);
74: sVar25 = SUB162(auVar19 >> 0x50,0);
75: sVar26 = SUB162(auVar19 >> 0x60,0);
76: sVar27 = SUB162(auVar19 >> 0x70,0);
77: sVar30 = SUB162(auVar28 >> 0x10,0);
78: sVar31 = SUB162(auVar28 >> 0x20,0);
79: sVar32 = SUB162(auVar28 >> 0x30,0);
80: sVar33 = SUB162(auVar28 >> 0x40,0);
81: sVar34 = SUB162(auVar28 >> 0x50,0);
82: sVar35 = SUB162(auVar28 >> 0x60,0);
83: sVar36 = SUB162(auVar28 >> 0x70,0);
84: sVar39 = SUB162(auVar37 >> 0x10,0);
85: sVar40 = SUB162(auVar37 >> 0x20,0);
86: sVar41 = SUB162(auVar37 >> 0x30,0);
87: sVar42 = SUB162(auVar37 >> 0x40,0);
88: sVar43 = SUB162(auVar37 >> 0x50,0);
89: sVar44 = SUB162(auVar37 >> 0x60,0);
90: sVar45 = SUB162(auVar37 >> 0x70,0);
91: auVar2 = pmulhuw(CONCAT214((SUB162(auVar2 >> 0x70,0) - sVar18) + *(short *)(param_2[4] + 0xe),
92: CONCAT212((SUB162(auVar2 >> 0x60,0) - sVar17) +
93: *(short *)(param_2[4] + 0xc),
94: CONCAT210((SUB162(auVar2 >> 0x50,0) - sVar16) +
95: *(short *)(param_2[4] + 10),
96: CONCAT28((SUB162(auVar2 >> 0x40,0) - sVar15) +
97: *(short *)(param_2[4] + 8),
98: CONCAT26((SUB162(auVar2 >> 0x30,0) -
99: sVar14) + *(short *)(param_2[
100: 4] + 6),CONCAT24((SUB162(auVar2 >> 0x20,0) -
101: sVar13) + *(short *)(param_2[4] +
102: 4),
103: CONCAT22((SUB162(auVar2 >> 0x10,0
104: ) - sVar12) +
105: *(short *)(param_2[4] +
106: 2),
107: (SUB162(auVar2,0) -
108: SUB162(auVar10,0)) +
109: *(short *)param_2[4]))))
110: ))),*(undefined (*) [16])*param_2);
111: auVar4 = pmulhuw(CONCAT214((SUB162(auVar4 >> 0x70,0) - sVar27) + *(short *)(param_2[4] + 0x1e)
112: ,CONCAT212((SUB162(auVar4 >> 0x60,0) - sVar26) +
113: *(short *)(param_2[4] + 0x1c),
114: CONCAT210((SUB162(auVar4 >> 0x50,0) - sVar25) +
115: *(short *)(param_2[4] + 0x1a),
116: CONCAT28((SUB162(auVar4 >> 0x40,0) - sVar24) +
117: *(short *)(param_2[4] + 0x18),
118: CONCAT26((SUB162(auVar4 >> 0x30,0) -
119: sVar23) + *(short *)(param_2
120: [4] + 0x16),
121: CONCAT24((SUB162(auVar4 >> 0x20,0) - sVar22) +
122: *(short *)(param_2[4] + 0x14),
123: CONCAT22((SUB162(auVar4 >> 0x10,0) -
124: sVar21) + *(short *)(param_2[4]
125: + 0x12),
126: (SUB162(auVar4,0) -
127: SUB162(auVar19,0)) +
128: *(short *)(param_2[4] + 0x10))))
129: )))),*(undefined (*) [16])(*param_2 + 0x10));
130: auVar6 = pmulhuw(CONCAT214((SUB162(auVar6 >> 0x70,0) - sVar36) + *(short *)(param_2[5] + 0xe),
131: CONCAT212((SUB162(auVar6 >> 0x60,0) - sVar35) +
132: *(short *)(param_2[5] + 0xc),
133: CONCAT210((SUB162(auVar6 >> 0x50,0) - sVar34) +
134: *(short *)(param_2[5] + 10),
135: CONCAT28((SUB162(auVar6 >> 0x40,0) - sVar33) +
136: *(short *)(param_2[5] + 8),
137: CONCAT26((SUB162(auVar6 >> 0x30,0) -
138: sVar32) + *(short *)(param_2[
139: 5] + 6),CONCAT24((SUB162(auVar6 >> 0x20,0) -
140: sVar31) + *(short *)(param_2[5] +
141: 4),
142: CONCAT22((SUB162(auVar6 >> 0x10,0
143: ) - sVar30) +
144: *(short *)(param_2[5] +
145: 2),
146: (SUB162(auVar6,0) -
147: SUB162(auVar28,0)) +
148: *(short *)param_2[5]))))
149: ))),*(undefined (*) [16])param_2[1]);
150: auVar8 = pmulhuw(CONCAT214((SUB162(auVar8 >> 0x70,0) - sVar45) + *(short *)(param_2[5] + 0x1e)
151: ,CONCAT212((SUB162(auVar8 >> 0x60,0) - sVar44) +
152: *(short *)(param_2[5] + 0x1c),
153: CONCAT210((SUB162(auVar8 >> 0x50,0) - sVar43) +
154: *(short *)(param_2[5] + 0x1a),
155: CONCAT28((SUB162(auVar8 >> 0x40,0) - sVar42) +
156: *(short *)(param_2[5] + 0x18),
157: CONCAT26((SUB162(auVar8 >> 0x30,0) -
158: sVar41) + *(short *)(param_2
159: [5] + 0x16),
160: CONCAT24((SUB162(auVar8 >> 0x20,0) - sVar40) +
161: *(short *)(param_2[5] + 0x14),
162: CONCAT22((SUB162(auVar8 >> 0x10,0) -
163: sVar39) + *(short *)(param_2[5]
164: + 0x12),
165: (SUB162(auVar8,0) -
166: SUB162(auVar37,0)) +
167: *(short *)(param_2[5] + 0x10))))
168: )))),*(undefined (*) [16])(param_2[1] + 0x10));
169: auVar2 = pmulhuw(auVar2,*(undefined (*) [16])param_2[8]);
170: auVar4 = pmulhuw(auVar4,*(undefined (*) [16])(param_2[8] + 0x10));
171: auVar6 = pmulhuw(auVar6,*(undefined (*) [16])param_2[9]);
172: auVar8 = pmulhuw(auVar8,*(undefined (*) [16])(param_2[9] + 0x10));
173: auVar2 = auVar2 ^ auVar10;
174: auVar4 = auVar4 ^ auVar19;
175: auVar6 = auVar6 ^ auVar28;
176: auVar8 = auVar8 ^ auVar37;
177: *(undefined (*) [16])*param_1 =
178: CONCAT214(SUB162(auVar2 >> 0x70,0) - sVar18,
179: CONCAT212(SUB162(auVar2 >> 0x60,0) - sVar17,
180: CONCAT210(SUB162(auVar2 >> 0x50,0) - sVar16,
181: CONCAT28(SUB162(auVar2 >> 0x40,0) - sVar15,
182: CONCAT26(SUB162(auVar2 >> 0x30,0) - sVar14,
183: CONCAT24(SUB162(auVar2 >> 0x20,0) -
184: sVar13,CONCAT22(SUB162(auVar2 >>
185: 0x10,0) -
186: sVar12,SUB162(
187: auVar2,0) - SUB162(auVar10,0))))))));
188: *(undefined (*) [16])(*param_1 + 0x10) =
189: CONCAT214(SUB162(auVar4 >> 0x70,0) - sVar27,
190: CONCAT212(SUB162(auVar4 >> 0x60,0) - sVar26,
191: CONCAT210(SUB162(auVar4 >> 0x50,0) - sVar25,
192: CONCAT28(SUB162(auVar4 >> 0x40,0) - sVar24,
193: CONCAT26(SUB162(auVar4 >> 0x30,0) - sVar23,
194: CONCAT24(SUB162(auVar4 >> 0x20,0) -
195: sVar22,CONCAT22(SUB162(auVar4 >>
196: 0x10,0) -
197: sVar21,SUB162(
198: auVar4,0) - SUB162(auVar19,0))))))));
199: *(undefined (*) [16])param_1[1] =
200: CONCAT214(SUB162(auVar6 >> 0x70,0) - sVar36,
201: CONCAT212(SUB162(auVar6 >> 0x60,0) - sVar35,
202: CONCAT210(SUB162(auVar6 >> 0x50,0) - sVar34,
203: CONCAT28(SUB162(auVar6 >> 0x40,0) - sVar33,
204: CONCAT26(SUB162(auVar6 >> 0x30,0) - sVar32,
205: CONCAT24(SUB162(auVar6 >> 0x20,0) -
206: sVar31,CONCAT22(SUB162(auVar6 >>
207: 0x10,0) -
208: sVar30,SUB162(
209: auVar6,0) - SUB162(auVar28,0))))))));
210: *(undefined (*) [16])(param_1[1] + 0x10) =
211: CONCAT214(SUB162(auVar8 >> 0x70,0) - sVar45,
212: CONCAT212(SUB162(auVar8 >> 0x60,0) - sVar44,
213: CONCAT210(SUB162(auVar8 >> 0x50,0) - sVar43,
214: CONCAT28(SUB162(auVar8 >> 0x40,0) - sVar42,
215: CONCAT26(SUB162(auVar8 >> 0x30,0) - sVar41,
216: CONCAT24(SUB162(auVar8 >> 0x20,0) -
217: sVar40,CONCAT22(SUB162(auVar8 >>
218: 0x10,0) -
219: sVar39,SUB162(
220: auVar8,0) - SUB162(auVar37,0))))))));
221: param_3 = param_3[2];
222: param_2 = param_2[2];
223: param_1 = param_1[2];
224: lVar1 = lVar1 + -1;
225: } while (lVar1 != 0);
226: return (undefined *)0x0;
227: }
228: auVar11 = vmovdqu_avx(*param_3);
229: auVar20 = vmovdqu_avx(param_3[1]);
230: auVar29 = vmovdqu_avx(param_3[2]);
231: auVar38 = vmovdqu_avx(param_3[3]);
232: auVar3 = vpabsw_avx2(auVar11);
233: auVar5 = vpabsw_avx2(auVar20);
234: auVar7 = vpabsw_avx2(auVar29);
235: auVar9 = vpabsw_avx2(auVar38);
236: auVar3 = vpaddw_avx2(auVar3,param_2[4]);
237: auVar5 = vpaddw_avx2(auVar5,param_2[5]);
238: auVar7 = vpaddw_avx2(auVar7,param_2[6]);
239: auVar9 = vpaddw_avx2(auVar9,param_2[7]);
240: auVar3 = vpmulhuw_avx2(auVar3,*param_2);
241: auVar5 = vpmulhuw_avx2(auVar5,param_2[1]);
242: auVar7 = vpmulhuw_avx2(auVar7,param_2[2]);
243: auVar9 = vpmulhuw_avx2(auVar9,param_2[3]);
244: auVar3 = vpmulhuw_avx2(auVar3,param_2[8]);
245: auVar5 = vpmulhuw_avx2(auVar5,param_2[9]);
246: auVar7 = vpmulhuw_avx2(auVar7,param_2[10]);
247: auVar9 = vpmulhuw_avx2(auVar9,param_2[0xb]);
248: auVar3 = vpsignw_avx2(auVar3,auVar11);
249: auVar5 = vpsignw_avx2(auVar5,auVar20);
250: auVar7 = vpsignw_avx2(auVar7,auVar29);
251: auVar9 = vpsignw_avx2(auVar9,auVar38);
252: auVar3 = vmovdqu_avx(auVar3);
253: *param_1 = auVar3;
254: auVar3 = vmovdqu_avx(auVar5);
255: param_1[1] = auVar3;
256: auVar3 = vmovdqu_avx(auVar7);
257: param_1[2] = auVar3;
258: auVar3 = vmovdqu_avx(auVar9);
259: param_1[3] = auVar3;
260: vzeroupper_avx();
261: return &stack0xfffffffffffffff8;
262: }
263: 
