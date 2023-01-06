1: 
2: /* WARNING: Removing unreachable block (ram,0x00161fdf) */
3: /* WARNING: Removing unreachable block (ram,0x00161fe5) */
4: /* WARNING: Removing unreachable block (ram,0x00161feb) */
5: /* WARNING: Switch with 1 destination removed at 0x00167e90 */
6: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
7: 
8: void FUN_00167e30(long param_1,undefined (**param_2) [32],long *param_3,ulong param_4,ulong param_5)
9: 
10: {
11: bool bVar1;
12: undefined auVar2 [16];
13: uint uVar3;
14: ulong uVar4;
15: ulong uVar5;
16: code *UNRECOVERED_JUMPTABLE;
17: ulong uVar6;
18: ulong uVar7;
19: undefined (*pauVar8) [32];
20: undefined (**ppauVar9) [32];
21: undefined (*pauVar10) [32];
22: ulong uVar11;
23: undefined auVar12 [16];
24: undefined auVar13 [32];
25: undefined in_YMM1 [32];
26: undefined auVar14 [32];
27: undefined auVar15 [32];
28: undefined auVar16 [32];
29: undefined auVar17 [32];
30: undefined auVar18 [32];
31: undefined in_YMM5 [32];
32: undefined auVar19 [32];
33: undefined auVar20 [32];
34: undefined in_YMM7 [32];
35: 
36: switch(*(undefined4 *)(param_1 + 0x3c)) {
37: case 6:
38: UNRECOVERED_JUMPTABLE = (code *)&UNK_00157660;
39: break;
40: case 7:
41: case 0xc:
42: UNRECOVERED_JUMPTABLE = (code *)&UNK_00157920;
43: break;
44: case 8:
45: UNRECOVERED_JUMPTABLE = (code *)&UNK_00157ba0;
46: uVar3 = *(uint *)(param_1 + 0x30);
47: goto joined_r0x00167e88;
48: case 9:
49: case 0xd:
50: UNRECOVERED_JUMPTABLE = (code *)&UNK_00157e60;
51: break;
52: case 10:
53: case 0xe:
54: UNRECOVERED_JUMPTABLE = (code *)&UNK_001580e0;
55: break;
56: case 0xb:
57: case 0xf:
58: UNRECOVERED_JUMPTABLE = (code *)&UNK_00158360;
59: break;
60: default:
61: UNRECOVERED_JUMPTABLE = (code *)&LAB_001573a0;
62: }
63: uVar3 = *(uint *)(param_1 + 0x30);
64: joined_r0x00167e88:
65: if ((DAT_003a61e0 & 0x80) != 0) {
66: uVar11 = (ulong)uVar3;
67: if (uVar11 != 0) {
68: ppauVar9 = (undefined (**) [32])(*param_3 + (param_4 & 0xffffffff) * 8);
69: uVar4 = param_5 & 0xffffffff;
70: if ((param_5 & 0xffffffff) != 0) {
71: do {
72: pauVar8 = *param_2;
73: pauVar10 = *ppauVar9;
74: uVar7 = uVar11;
75: if (0x1f < uVar11) goto LAB_00161fcd;
76: do {
77: uVar7 = uVar7 * 3;
78: uVar5 = uVar4;
79: uVar6 = uVar7;
80: if ((uVar7 & 1) != 0) {
81: uVar6 = uVar7 - 1;
82: uVar5 = (ulong)(byte)pauVar8[-1][uVar7 + 0x1f];
83: }
84: uVar3 = (uint)uVar5;
85: uVar7 = uVar6;
86: if ((uVar6 & 2) != 0) {
87: uVar7 = uVar6 - 2;
88: uVar3 = (uint)(uVar5 << 0x10) | (uint)*(ushort *)(pauVar8[-1] + uVar6 + 0x1e);
89: }
90: auVar12 = vmovd_avx(uVar3);
91: uVar5 = uVar7;
92: if ((uVar7 & 4) != 0) {
93: uVar5 = uVar7 - 4;
94: auVar2 = vmovd_avx(*(undefined4 *)(pauVar8[-1] + uVar7 + 0x1c));
95: in_YMM5 = ZEXT1632(auVar2);
96: auVar12 = vpslldq_avx(auVar12,4);
97: auVar12 = vpor_avx(auVar12,auVar2);
98: }
99: uVar7 = uVar5;
100: if ((uVar5 & 8) != 0) {
101: uVar7 = uVar5 - 8;
102: auVar2 = vmovq_avx(ZEXT816(*(ulong *)(pauVar8[-1] + uVar5 + 0x18)));
103: in_YMM1 = ZEXT1632(auVar2);
104: auVar12 = vpslldq_avx(auVar12,8);
105: auVar12 = vpor_avx(auVar12,auVar2);
106: }
107: auVar13 = ZEXT1632(auVar12);
108: uVar5 = uVar7;
109: if ((uVar7 & 0x10) != 0) {
110: uVar5 = uVar7 - 0x10;
111: auVar12 = vmovdqu_avx(*(undefined (*) [16])(pauVar8[-1] + uVar7 + 0x10));
112: in_YMM1 = ZEXT1632(auVar12);
113: auVar13 = vperm2i128_avx2(auVar13,auVar13,1);
114: auVar13 = vpor_avx2(auVar13,in_YMM1);
115: }
116: if ((uVar5 & 0x20) != 0) {
117: uVar5 = uVar5 - 0x20;
118: in_YMM5 = vmovdqa_avx(auVar13);
119: auVar13 = vmovdqu_avx(*pauVar8);
120: }
121: uVar7 = 0x20;
122: if ((uVar5 & 0x40) != 0) {
123: in_YMM1 = vmovdqa_avx(auVar13);
124: auVar13 = vmovdqu_avx(*pauVar8);
125: in_YMM5 = vmovdqu_avx(pauVar8[1]);
126: }
127: while( true ) {
128: auVar14 = vmovdqu_avx(auVar13);
129: auVar13 = CONCAT1616(SUB3216(in_YMM5 >> 0x80,0),SUB3216(auVar13,0));
130: auVar17 = CONCAT1616(SUB3216(auVar14 >> 0x80,0),SUB3216(in_YMM1,0));
131: auVar14 = CONCAT1616(SUB3216(in_YMM1 >> 0x80,0),SUB3216(in_YMM5,0));
132: auVar17 = vperm2i128_avx2(auVar17,auVar17,1);
133: auVar19 = vmovdqa_avx(auVar13);
134: auVar13 = vpslldq_avx2(auVar13,8);
135: auVar19 = vpsrldq_avx2(auVar19,8);
136: auVar13 = vpunpckhbw_avx2(auVar13,auVar17);
137: auVar17 = vpslldq_avx2(auVar17,8);
138: auVar19 = vpunpcklbw_avx2(auVar19,auVar14);
139: auVar17 = vpunpckhbw_avx2(auVar17,auVar14);
140: auVar14 = vmovdqa_avx(auVar13);
141: auVar13 = vpslldq_avx2(auVar13,8);
142: auVar14 = vpsrldq_avx2(auVar14,8);
143: auVar13 = vpunpckhbw_avx2(auVar13,auVar19);
144: auVar19 = vpslldq_avx2(auVar19,8);
145: auVar14 = vpunpcklbw_avx2(auVar14,auVar17);
146: auVar19 = vpunpckhbw_avx2(auVar19,auVar17);
147: auVar17 = vmovdqa_avx(auVar13);
148: auVar13 = vpslldq_avx2(auVar13,8);
149: auVar17 = vpsrldq_avx2(auVar17,8);
150: auVar13 = vpunpckhbw_avx2(auVar13,auVar14);
151: auVar14 = vpslldq_avx2(auVar14,8);
152: auVar15 = vpunpcklbw_avx2(auVar17,auVar19);
153: auVar17 = vpunpckhbw_avx2(auVar14,auVar19);
154: auVar20 = vpxor_avx2(in_YMM7,in_YMM7);
155: auVar14 = vmovdqa_avx(auVar13);
156: auVar13 = vpunpcklbw_avx2(auVar13,auVar20);
157: auVar19 = vpunpckhbw_avx2(auVar14,auVar20);
158: auVar14 = vmovdqa_avx(auVar15);
159: auVar16 = vpunpcklbw_avx2(auVar15,auVar20);
160: auVar14 = vpunpckhbw_avx2(auVar14,auVar20);
161: auVar18 = vmovdqa_avx(auVar17);
162: auVar15 = vpunpcklbw_avx2(auVar17,auVar20);
163: in_YMM5 = vpunpckhbw_avx2(auVar18,auVar20);
164: auVar17 = vmovdqa_avx(auVar14);
165: auVar14 = vpunpcklwd_avx2(auVar14,auVar15);
166: auVar17 = vpunpckhwd_avx2(auVar17,auVar15);
167: in_YMM1 = vpmaddwd_avx2(auVar14,_DAT_0019ce20);
168: auVar14 = vpmaddwd_avx2(auVar17,_DAT_0019ce20);
169: in_YMM7 = vmovdqa_avx(auVar14);
170: auVar14 = vmovdqa_avx(auVar13);
171: auVar13 = vpunpcklwd_avx2(auVar13,auVar19);
172: auVar14 = vpunpckhwd_avx2(auVar14,auVar19);
173: auVar13 = vpmaddwd_avx2(auVar13,_DAT_0019ce20);
174: auVar14 = vpmaddwd_avx2(auVar14,_DAT_0019ce20);
175: auVar13 = vmovdqa_avx(auVar13);
176: auVar14 = vmovdqa_avx(auVar14);
177: auVar17 = vmovdqa_avx(in_YMM5);
178: auVar18 = vmovdqa_avx(auVar16);
179: auVar16 = vmovdqa_avx(auVar17);
180: auVar17 = vpunpcklwd_avx2(auVar17,auVar15);
181: auVar15 = vpunpckhwd_avx2(auVar16,auVar15);
182: auVar17 = vpmaddwd_avx2(auVar17,_DAT_0019ce40);
183: auVar16 = vpmaddwd_avx2(auVar15,_DAT_0019ce40);
184: auVar15 = vmovdqa_avx(_DAT_0019ce60);
185: auVar17 = vpaddd_avx2(auVar17,in_YMM1);
186: auVar16 = vpaddd_avx2(auVar16,in_YMM7);
187: auVar17 = vpaddd_avx2(auVar17,auVar15);
188: auVar15 = vpaddd_avx2(auVar16,auVar15);
189: auVar17 = vpsrld_avx2(auVar17,0x10);
190: auVar15 = vpsrld_avx2(auVar15,0x10);
191: auVar17 = vpackssdw_avx2(auVar17,auVar15);
192: auVar15 = vmovdqa_avx(auVar18);
193: auVar16 = vpunpcklwd_avx2(auVar18,auVar19);
194: auVar19 = vpunpckhwd_avx2(auVar15,auVar19);
195: auVar16 = vpmaddwd_avx2(auVar16,_DAT_0019ce40);
196: auVar15 = vpmaddwd_avx2(auVar19,_DAT_0019ce40);
197: auVar19 = vmovdqa_avx(_DAT_0019ce60);
198: auVar16 = vpaddd_avx2(auVar16,auVar13);
199: auVar13 = vpaddd_avx2(auVar15,auVar14);
200: auVar14 = vpaddd_avx2(auVar16,auVar19);
201: auVar13 = vpaddd_avx2(auVar13,auVar19);
202: auVar14 = vpsrld_avx2(auVar14,0x10);
203: auVar13 = vpsrld_avx2(auVar13,0x10);
204: auVar14 = vpackssdw_avx2(auVar14,auVar13);
205: auVar13 = vpsllw_avx2(auVar17,8);
206: auVar13 = vpor_avx2(auVar14,auVar13);
207: auVar13 = vmovdqu_avx(auVar13);
208: *pauVar10 = auVar13;
209: uVar7 = uVar7 - 0x20;
210: pauVar8 = pauVar8[3];
211: pauVar10 = pauVar10[1];
212: if (uVar7 < 0x20) break;
213: LAB_00161fcd:
214: auVar13 = vmovdqu_avx(*pauVar8);
215: in_YMM5 = vmovdqu_avx(pauVar8[1]);
216: in_YMM1 = vmovdqu_avx(pauVar8[2]);
217: }
218: } while (uVar7 != 0);
219: param_2 = param_2 + 1;
220: ppauVar9 = ppauVar9 + 1;
221: uVar7 = uVar4 - 1;
222: bVar1 = 0 < (long)uVar4;
223: uVar4 = uVar7;
224: } while (uVar7 != 0 && bVar1);
225: }
226: }
227: vzeroupper_avx();
228: return;
229: }
230: /* WARNING: Treating indirect jump as call */
231: (*UNRECOVERED_JUMPTABLE)();
232: return;
233: }
234: 
