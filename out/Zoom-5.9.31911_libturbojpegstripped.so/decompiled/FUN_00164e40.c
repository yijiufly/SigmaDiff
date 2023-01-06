1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00164e40(ulong param_1,long *param_2,ulong param_3,undefined (**param_4) [32])
5: 
6: {
7: undefined4 uVar1;
8: char cVar2;
9: uint uVar3;
10: undefined (*pauVar4) [32];
11: undefined (*pauVar5) [32];
12: undefined (*pauVar6) [32];
13: undefined (*pauVar7) [32];
14: undefined auVar8 [16];
15: undefined in_YMM1 [32];
16: undefined auVar9 [32];
17: undefined in_YMM3 [32];
18: undefined auVar10 [32];
19: undefined auVar11 [32];
20: undefined auVar12 [32];
21: undefined auVar13 [32];
22: undefined auVar14 [32];
23: undefined auVar15 [32];
24: undefined auVar16 [32];
25: undefined auVar17 [32];
26: undefined auVar18 [32];
27: undefined auVar19 [32];
28: 
29: param_1 = param_1 & 0xffffffff;
30: if (param_1 == 0) {
31: LAB_001651ab:
32: vzeroupper_avx();
33: return;
34: }
35: param_3 = param_3 & 0xffffffff;
36: pauVar6 = *(undefined (**) [32])(*param_2 + param_3 * 8);
37: pauVar5 = *(undefined (**) [32])(param_2[1] + param_3 * 8);
38: pauVar4 = *(undefined (**) [32])(param_2[2] + param_3 * 8);
39: pauVar7 = *param_4;
40: do {
41: auVar13 = vmovdqu_avx(*pauVar5);
42: auVar15 = vmovdqu_avx(*pauVar4);
43: auVar9 = vpxor_avx2(in_YMM1,in_YMM1);
44: auVar10 = vpcmpeqw_avx2(in_YMM3,in_YMM3);
45: auVar11 = vpsllw_avx2(auVar10,7);
46: auVar10 = vpermq_avx2(auVar13,0xd8);
47: auVar16 = vpermq_avx2(auVar15,0xd8);
48: auVar13 = vpunpcklbw_avx2(auVar10,auVar9);
49: auVar15 = vpunpckhbw_avx2(auVar10,auVar9);
50: auVar10 = vpunpcklbw_avx2(auVar16,auVar9);
51: auVar9 = vpunpckhbw_avx2(auVar16,auVar9);
52: auVar12 = vpaddw_avx2(auVar15,auVar11);
53: auVar15 = vpaddw_avx2(auVar13,auVar11);
54: auVar13 = vpaddw_avx2(auVar9,auVar11);
55: auVar16 = vpaddw_avx2(auVar10,auVar11);
56: auVar11 = vpaddw_avx2(auVar12,auVar12);
57: auVar9 = vpaddw_avx2(auVar15,auVar15);
58: auVar17 = vpaddw_avx2(auVar13,auVar13);
59: auVar10 = vpaddw_avx2(auVar16,auVar16);
60: auVar11 = vpmulhw_avx2(auVar11,_DAT_0019cf40);
61: auVar9 = vpmulhw_avx2(auVar9,_DAT_0019cf40);
62: auVar17 = vpmulhw_avx2(auVar17,_DAT_0019cf20);
63: auVar10 = vpmulhw_avx2(auVar10,_DAT_0019cf20);
64: auVar11 = vpaddw_avx2(auVar11,_DAT_0019cf80);
65: auVar9 = vpaddw_avx2(auVar9,_DAT_0019cf80);
66: auVar11 = vpsraw_avx2(auVar11,1);
67: auVar9 = vpsraw_avx2(auVar9,1);
68: auVar17 = vpaddw_avx2(auVar17,_DAT_0019cf80);
69: auVar10 = vpaddw_avx2(auVar10,_DAT_0019cf80);
70: auVar18 = vpsraw_avx2(auVar17,1);
71: auVar10 = vpsraw_avx2(auVar10,1);
72: auVar11 = vpaddw_avx2(auVar11,auVar12);
73: auVar9 = vpaddw_avx2(auVar9,auVar15);
74: auVar14 = vpaddw_avx2(auVar11,auVar12);
75: auVar17 = vpaddw_avx2(auVar9,auVar15);
76: auVar9 = vpaddw_avx2(auVar18,auVar13);
77: auVar11 = vpaddw_avx2(auVar10,auVar16);
78: auVar10 = vmovdqa_avx(auVar14);
79: auVar9 = vmovdqa_avx(auVar9);
80: auVar14 = vpunpckhwd_avx2(auVar12,auVar13);
81: auVar12 = vpunpcklwd_avx2(auVar12,auVar13);
82: auVar12 = vpmaddwd_avx2(auVar12,_DAT_0019cf60);
83: auVar14 = vpmaddwd_avx2(auVar14,_DAT_0019cf60);
84: auVar18 = vpunpckhwd_avx2(auVar15,auVar16);
85: auVar15 = vpunpcklwd_avx2(auVar15,auVar16);
86: auVar15 = vpmaddwd_avx2(auVar15,_DAT_0019cf60);
87: auVar18 = vpmaddwd_avx2(auVar18,_DAT_0019cf60);
88: auVar12 = vpaddd_avx2(auVar12,_DAT_0019cfa0);
89: auVar14 = vpaddd_avx2(auVar14,_DAT_0019cfa0);
90: auVar12 = vpsrad_avx2(auVar12,0x10);
91: auVar14 = vpsrad_avx2(auVar14,0x10);
92: auVar15 = vpaddd_avx2(auVar15,_DAT_0019cfa0);
93: auVar18 = vpaddd_avx2(auVar18,_DAT_0019cfa0);
94: auVar15 = vpsrad_avx2(auVar15,0x10);
95: auVar18 = vpsrad_avx2(auVar18,0x10);
96: auVar12 = vpackssdw_avx2(auVar12,auVar14);
97: auVar15 = vpackssdw_avx2(auVar15,auVar18);
98: auVar13 = vpsubw_avx2(auVar12,auVar13);
99: auVar15 = vpsubw_avx2(auVar15,auVar16);
100: auVar13 = vmovdqa_avx(auVar13);
101: cVar2 = '\x02';
102: while( true ) {
103: auVar12 = vmovdqu_avx(*pauVar6);
104: auVar16 = vpcmpeqw_avx2(auVar14,auVar14);
105: auVar16 = vpsrlw_avx2(auVar16,8);
106: auVar18 = vpand_avx2(auVar16,auVar12);
107: auVar19 = vpsrlw_avx2(auVar12,8);
108: auVar16 = vmovdqa_avx(auVar11);
109: auVar12 = vmovdqa_avx(auVar15);
110: auVar14 = vmovdqa_avx(auVar17);
111: auVar11 = vpaddw_avx2(auVar11,auVar18);
112: auVar16 = vpaddw_avx2(auVar16,auVar19);
113: auVar11 = vpackuswb_avx2(auVar11,auVar11);
114: auVar16 = vpackuswb_avx2(auVar16,auVar16);
115: auVar15 = vpaddw_avx2(auVar15,auVar18);
116: auVar12 = vpaddw_avx2(auVar12,auVar19);
117: auVar15 = vpackuswb_avx2(auVar15,auVar15);
118: auVar12 = vpackuswb_avx2(auVar12,auVar12);
119: auVar17 = vpaddw_avx2(auVar17,auVar18);
120: auVar14 = vpaddw_avx2(auVar14,auVar19);
121: auVar17 = vpackuswb_avx2(auVar17,auVar17);
122: auVar14 = vpackuswb_avx2(auVar14,auVar14);
123: auVar11 = vpunpcklbw_avx2(auVar11,auVar15);
124: auVar15 = vpunpcklbw_avx2(auVar17,auVar16);
125: auVar16 = vpunpcklbw_avx2(auVar12,auVar14);
126: auVar12 = vpsrldq_avx2(auVar11,2);
127: auVar14 = vpunpckhwd_avx2(auVar11,auVar15);
128: auVar11 = vpunpcklwd_avx2(auVar11,auVar15);
129: auVar17 = vpsrldq_avx2(auVar15,2);
130: in_YMM1 = vpsrldq_avx2(auVar16,2);
131: auVar15 = vpunpckhwd_avx2(auVar16,auVar12);
132: auVar16 = vpunpcklwd_avx2(auVar16,auVar12);
133: auVar12 = vpunpckhwd_avx2(auVar17,in_YMM1);
134: auVar17 = vpunpcklwd_avx2(auVar17,in_YMM1);
135: auVar18 = vpshufd_avx2(auVar11,0x4e);
136: auVar11 = vpunpckldq_avx2(auVar11,auVar16);
137: auVar16 = vpunpckhdq_avx2(auVar16,auVar17);
138: auVar17 = vpunpckldq_avx2(auVar17,auVar18);
139: auVar18 = vpshufd_avx2(auVar14,0x4e);
140: auVar14 = vpunpckldq_avx2(auVar14,auVar15);
141: auVar15 = vpunpckhdq_avx2(auVar15,auVar12);
142: auVar12 = vpunpckldq_avx2(auVar12,auVar18);
143: auVar17 = vpunpcklqdq_avx2(auVar11,auVar17);
144: auVar14 = vpunpcklqdq_avx2(auVar16,auVar14);
145: auVar15 = vpunpcklqdq_avx2(auVar12,auVar15);
146: auVar11 = vperm2i128_avx2(auVar17,auVar14,0x20);
147: in_YMM3 = vperm2i128_avx2(auVar15,auVar17,0x30);
148: auVar15 = vperm2i128_avx2(auVar14,auVar15,0x31);
149: if (param_1 < 0x20) {
150: param_1 = param_1 * 3;
151: if (param_1 < 0x40) {
152: if (0x1f < param_1) {
153: auVar10 = vmovdqu_avx(auVar11);
154: *pauVar7 = auVar10;
155: pauVar7 = pauVar7[1];
156: auVar11 = vmovdqa_avx(in_YMM3);
157: param_1 = param_1 - 0x20;
158: }
159: }
160: else {
161: auVar10 = vmovdqu_avx(auVar11);
162: *pauVar7 = auVar10;
163: auVar10 = vmovdqu_avx(in_YMM3);
164: pauVar7[1] = auVar10;
165: pauVar7 = pauVar7[2];
166: auVar11 = vmovdqa_avx(auVar15);
167: param_1 = param_1 - 0x40;
168: }
169: auVar8 = SUB3216(auVar11,0);
170: if (0xf < param_1) {
171: auVar8 = vmovdqu_avx(auVar8);
172: *(undefined (*) [16])*pauVar7 = auVar8;
173: pauVar7 = (undefined (*) [32])(*pauVar7 + 0x10);
174: auVar10 = vperm2i128_avx2(auVar11,auVar11,1);
175: auVar8 = SUB3216(auVar10,0);
176: param_1 = param_1 - 0x10;
177: }
178: if (7 < param_1) {
179: vmovq_avx(auVar8);
180: pauVar7 = (undefined (*) [32])(*pauVar7 + 8);
181: param_1 = param_1 - 8;
182: auVar8 = vpsrldq_avx(auVar8,8);
183: }
184: if (3 < param_1) {
185: uVar1 = vmovd_avx(auVar8);
186: *(undefined4 *)*pauVar7 = uVar1;
187: pauVar7 = (undefined (*) [32])(*pauVar7 + 4);
188: param_1 = param_1 - 4;
189: auVar8 = vpsrldq_avx(auVar8,4);
190: }
191: uVar3 = vmovd_avx(auVar8);
192: if (1 < param_1) {
193: *(short *)*pauVar7 = (short)uVar3;
194: pauVar7 = (undefined (*) [32])(*pauVar7 + 2);
195: param_1 = param_1 - 2;
196: uVar3 = uVar3 >> 0x10;
197: }
198: if (param_1 != 0) {
199: (*pauVar7)[0] = (char)uVar3;
200: }
201: goto LAB_001651ab;
202: }
203: if (((ulong)pauVar7 & 0x1f) == 0) {
204: auVar11 = vmovntdq_avx(auVar11);
205: *pauVar7 = auVar11;
206: auVar11 = vmovntdq_avx(in_YMM3);
207: pauVar7[1] = auVar11;
208: auVar11 = vmovntdq_avx(auVar15);
209: pauVar7[2] = auVar11;
210: }
211: else {
212: auVar11 = vmovdqu_avx(auVar11);
213: *pauVar7 = auVar11;
214: auVar11 = vmovdqu_avx(in_YMM3);
215: pauVar7[1] = auVar11;
216: auVar11 = vmovdqu_avx(auVar15);
217: pauVar7[2] = auVar11;
218: }
219: pauVar7 = pauVar7[3];
220: param_1 = param_1 - 0x20;
221: if (param_1 == 0) goto LAB_001651ab;
222: pauVar6 = pauVar6[1];
223: cVar2 = cVar2 + -1;
224: if (cVar2 == '\0') break;
225: auVar11 = vmovdqa_avx(auVar9);
226: auVar15 = vmovdqa_avx(auVar13);
227: auVar17 = vmovdqa_avx(auVar10);
228: }
229: pauVar5 = pauVar5[1];
230: pauVar4 = pauVar4[1];
231: } while( true );
232: }
233: 
