1: 
2: /* WARNING: Type propagation algorithm not settling */
3: 
4: undefined *
5: FUN_00168140(long param_1,undefined8 param_2,undefined (**param_3) [32],undefined (**param_4) [32])
6: 
7: {
8: bool bVar1;
9: undefined auVar2 [16];
10: undefined *puVar3;
11: ulong uVar4;
12: ulong uVar5;
13: ulong uVar6;
14: undefined *puVar7;
15: undefined (*pauVar8) [16];
16: undefined (*pauVar9) [32];
17: undefined (*pauVar10) [32];
18: undefined (*pauVar11) [16];
19: undefined (*pauVar12) [32];
20: undefined (*pauVar13) [32];
21: undefined uVar16;
22: undefined uVar17;
23: undefined uVar18;
24: undefined uVar19;
25: undefined auVar14 [32];
26: undefined auVar15 [32];
27: undefined in_YMM0 [32];
28: undefined auVar20 [16];
29: undefined auVar21 [32];
30: undefined auVar26 [16];
31: undefined uVar22;
32: undefined uVar23;
33: undefined uVar24;
34: undefined uVar25;
35: 
36: uVar5 = (ulong)*(uint *)(param_1 + 0x19c);
37: if ((DAT_003a61e0 & 0x80) != 0) {
38: puVar7 = (undefined *)((ulong)*(uint *)(param_1 + 0x88) + 0x1f & 0xffffffffffffffe0);
39: puVar3 = &stack0xfffffffffffffff8;
40: if ((puVar7 != (undefined *)0x0) && (puVar3 = &stack0xfffffffffffffff8, uVar5 != 0)) {
41: pauVar12 = *param_4;
42: do {
43: pauVar10 = *param_3;
44: pauVar9 = *(undefined (**) [32])*pauVar12;
45: pauVar13 = *(undefined (**) [32])((long)*pauVar12 + 8);
46: puVar3 = puVar7;
47: while ((undefined *)0x20 < puVar3) {
48: auVar14 = vmovdqu_avx(*pauVar10);
49: auVar14 = vpermq_avx2(auVar14,0xd8);
50: auVar21 = vpunpckhbw_avx2(auVar14,auVar14);
51: auVar15 = vpunpcklbw_avx2(auVar14,auVar14);
52: auVar14 = vmovdqu_avx(auVar15);
53: *pauVar9 = auVar14;
54: auVar14 = vmovdqu_avx(auVar21);
55: pauVar9[1] = auVar14;
56: auVar14 = vmovdqu_avx(auVar15);
57: *pauVar13 = auVar14;
58: auVar14 = vmovdqu_avx(auVar21);
59: pauVar13[1] = auVar14;
60: puVar3 = puVar3 + -0x40;
61: if (puVar3 == (undefined *)0x0) goto LAB_00167172;
62: pauVar10 = pauVar10[1];
63: pauVar9 = pauVar9[2];
64: pauVar13 = pauVar13[2];
65: }
66: auVar20 = vmovdqu_avx(*(undefined (*) [16])*pauVar10);
67: auVar26 = vpunpckhbw_avx(auVar20,auVar20);
68: auVar2 = vpunpcklbw_avx(auVar20,auVar20);
69: auVar20 = vmovdqu_avx(auVar2);
70: *(undefined (*) [16])*pauVar9 = auVar20;
71: auVar20 = vmovdqu_avx(auVar26);
72: *(undefined (*) [16])(*pauVar9 + 0x10) = auVar20;
73: auVar20 = vmovdqu_avx(auVar2);
74: *(undefined (*) [16])*pauVar13 = auVar20;
75: auVar20 = vmovdqu_avx(auVar26);
76: *(undefined (*) [16])(*pauVar13 + 0x10) = auVar20;
77: LAB_00167172:
78: param_3 = param_3 + 1;
79: pauVar12 = (undefined (*) [32])((long)*pauVar12 + 0x10);
80: uVar6 = uVar5 - 2;
81: bVar1 = 1 < (long)uVar5;
82: uVar5 = uVar6;
83: } while (uVar6 != 0 && bVar1);
84: }
85: vzeroupper_avx();
86: return puVar3;
87: }
88: uVar6 = (ulong)*(uint *)(param_1 + 0x88) + 0x1f & 0xffffffffffffffe0;
89: puVar3 = &stack0xfffffffffffffff8;
90: if ((uVar6 != 0) && (puVar3 = &stack0xfffffffffffffff8, uVar5 != 0)) {
91: pauVar12 = *param_4;
92: do {
93: pauVar10 = *param_3;
94: pauVar8 = *(undefined (**) [16])*pauVar12;
95: pauVar11 = *(undefined (**) [16])((long)*pauVar12 + 8);
96: puVar7 = (undefined *)uVar6;
97: while( true ) {
98: auVar20 = *(undefined (*) [16])*pauVar10;
99: uVar19 = SUB161(auVar20 >> 0x38,0);
100: uVar18 = SUB161(auVar20 >> 0x30,0);
101: uVar17 = SUB161(auVar20 >> 0x28,0);
102: uVar16 = SUB161(auVar20 >> 0x20,0);
103: in_YMM0 = CONCAT302(SUB3230(CONCAT293(SUB3229(CONCAT284(SUB3228(CONCAT275(SUB3227(CONCAT266(
104: SUB3226(CONCAT257(SUB3225(CONCAT248(SUB3224(
105: CONCAT239(SUB3223(CONCAT2210(SUB3222(CONCAT2111(
106: SUB3221(CONCAT2012(SUB3220(CONCAT1913(SUB3219(
107: CONCAT1814(SUB3218(CONCAT1715(SUB3217(CONCAT1616(
108: SUB3216(in_YMM0 >> 0x80,0),
109: CONCAT115(uVar19,SUB1615(auVar20,0))) >> 0x78,0),
110: CONCAT114(uVar19,SUB1614(auVar20,0))) >> 0x70,0),
111: CONCAT113(uVar18,SUB1613(auVar20,0))) >> 0x68,0),
112: CONCAT112(uVar18,SUB1612(auVar20,0))) >> 0x60,0),
113: CONCAT111(uVar17,SUB1611(auVar20,0))) >> 0x58,0),
114: CONCAT110(uVar17,SUB1610(auVar20,0))) >> 0x50,0),
115: CONCAT19(uVar16,SUB169(auVar20,0))) >> 0x48,0),
116: CONCAT18(uVar16,SUB168(auVar20,0))) >> 0x40,0),
117: (SUB168(auVar20,0) >> 0x18) << 0x38) >> 0x38,0),
118: (SUB167(auVar20,0) >> 0x18) << 0x30) >> 0x30,0),
119: (SUB166(auVar20,0) >> 0x10) << 0x28) >> 0x28,0),
120: (SUB165(auVar20,0) >> 0x10) << 0x20) >> 0x20,0),
121: (SUB164(auVar20,0) >> 8) << 0x18) >> 0x18,0),
122: (SUB163(auVar20,0) >> 8) << 0x10) >> 0x10,0),
123: SUB162(auVar20,0) & 0xff | SUB162(auVar20,0) << 8);
124: uVar16 = SUB161(auVar20 >> 0x40,0);
125: uVar17 = SUB161(auVar20 >> 0x48,0);
126: uVar18 = SUB161(auVar20 >> 0x50,0);
127: uVar19 = SUB161(auVar20 >> 0x58,0);
128: uVar22 = SUB161(auVar20 >> 0x60,0);
129: uVar23 = SUB161(auVar20 >> 0x68,0);
130: uVar24 = SUB161(auVar20 >> 0x70,0);
131: uVar25 = SUB161(auVar20 >> 0x78,0);
132: auVar20 = CONCAT115(uVar25,CONCAT114(uVar25,CONCAT113(uVar24,CONCAT112(uVar24,CONCAT111(
133: uVar23,CONCAT110(uVar23,CONCAT19(uVar22,CONCAT18(
134: uVar22,CONCAT17(uVar19,CONCAT16(uVar19,CONCAT15(
135: uVar18,CONCAT14(uVar18,CONCAT13(uVar17,CONCAT12(
136: uVar17,CONCAT11(uVar16,uVar16)))))))))))))));
137: *pauVar8 = SUB3216(in_YMM0,0);
138: pauVar8[1] = auVar20;
139: *pauVar11 = SUB3216(in_YMM0,0);
140: pauVar11[1] = auVar20;
141: puVar3 = puVar7 + -0x20;
142: if (puVar3 == (undefined *)0x0) break;
143: auVar20 = *(undefined (*) [16])(*pauVar10 + 0x10);
144: uVar19 = SUB161(auVar20 >> 0x38,0);
145: uVar18 = SUB161(auVar20 >> 0x30,0);
146: uVar17 = SUB161(auVar20 >> 0x28,0);
147: uVar16 = SUB161(auVar20 >> 0x20,0);
148: auVar26 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
149: SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
150: SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
151: (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
152: CONCAT115(uVar19,CONCAT114(uVar19,SUB1614(auVar20,
153: 0))) >> 0x70,0),
154: CONCAT113(uVar18,SUB1613(auVar20,0))) >> 0x68,0),
155: CONCAT112(uVar18,SUB1612(auVar20,0))) >> 0x60,0),
156: CONCAT111(uVar17,SUB1611(auVar20,0))) >> 0x58,0),
157: CONCAT110(uVar17,SUB1610(auVar20,0))) >> 0x50,0),
158: CONCAT19(uVar16,SUB169(auVar20,0))) >> 0x48,0),
159: CONCAT18(uVar16,SUB168(auVar20,0))) >> 0x40,0),
160: (SUB168(auVar20,0) >> 0x18) << 0x38) >> 0x38,0),
161: (SUB167(auVar20,0) >> 0x18) << 0x30) >> 0x30,0),
162: (SUB166(auVar20,0) >> 0x10) << 0x28) >> 0x28,0),
163: (SUB165(auVar20,0) >> 0x10) << 0x20) >> 0x20,0),
164: (SUB164(auVar20,0) >> 8) << 0x18) >> 0x18,0),
165: (SUB163(auVar20,0) >> 8) << 0x10) >> 0x10,0),
166: SUB162(auVar20,0) & 0xff | SUB162(auVar20,0) << 8);
167: uVar16 = SUB161(auVar20 >> 0x40,0);
168: uVar17 = SUB161(auVar20 >> 0x48,0);
169: uVar18 = SUB161(auVar20 >> 0x50,0);
170: uVar19 = SUB161(auVar20 >> 0x58,0);
171: uVar22 = SUB161(auVar20 >> 0x60,0);
172: uVar23 = SUB161(auVar20 >> 0x68,0);
173: uVar24 = SUB161(auVar20 >> 0x70,0);
174: uVar25 = SUB161(auVar20 >> 0x78,0);
175: pauVar8[2] = auVar26;
176: pauVar8[3][0] = uVar16;
177: pauVar8[3][1] = uVar16;
178: pauVar8[3][2] = uVar17;
179: pauVar8[3][3] = uVar17;
180: pauVar8[3][4] = uVar18;
181: pauVar8[3][5] = uVar18;
182: pauVar8[3][6] = uVar19;
183: pauVar8[3][7] = uVar19;
184: pauVar8[3][8] = uVar22;
185: pauVar8[3][9] = uVar22;
186: pauVar8[3][10] = uVar23;
187: pauVar8[3][0xb] = uVar23;
188: pauVar8[3][0xc] = uVar24;
189: pauVar8[3][0xd] = uVar24;
190: pauVar8[3][0xe] = uVar25;
191: pauVar8[3][0xf] = uVar25;
192: pauVar11[2] = auVar26;
193: pauVar11[3][0] = uVar16;
194: pauVar11[3][1] = uVar16;
195: pauVar11[3][2] = uVar17;
196: pauVar11[3][3] = uVar17;
197: pauVar11[3][4] = uVar18;
198: pauVar11[3][5] = uVar18;
199: pauVar11[3][6] = uVar19;
200: pauVar11[3][7] = uVar19;
201: pauVar11[3][8] = uVar22;
202: pauVar11[3][9] = uVar22;
203: pauVar11[3][10] = uVar23;
204: pauVar11[3][0xb] = uVar23;
205: pauVar11[3][0xc] = uVar24;
206: pauVar11[3][0xd] = uVar24;
207: pauVar11[3][0xe] = uVar25;
208: pauVar11[3][0xf] = uVar25;
209: puVar3 = puVar7 + -0x40;
210: if (puVar3 == (undefined *)0x0) break;
211: pauVar10 = pauVar10[1];
212: pauVar8 = pauVar8[4];
213: pauVar11 = pauVar11[4];
214: puVar7 = puVar3;
215: }
216: param_3 = param_3 + 1;
217: pauVar12 = (undefined (*) [32])((long)*pauVar12 + 0x10);
218: uVar4 = uVar5 - 2;
219: bVar1 = 1 < (long)uVar5;
220: uVar5 = uVar4;
221: } while (uVar4 != 0 && bVar1);
222: }
223: return puVar3;
224: }
225: 
