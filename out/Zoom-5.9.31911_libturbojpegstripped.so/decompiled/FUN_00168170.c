1: 
2: /* WARNING: Type propagation algorithm not settling */
3: 
4: undefined *
5: FUN_00168170(long param_1,undefined8 param_2,undefined (**param_3) [32],undefined (**param_4) [32])
6: 
7: {
8: undefined auVar1 [16];
9: bool bVar2;
10: undefined auVar3 [16];
11: undefined *puVar4;
12: ulong uVar5;
13: ulong uVar6;
14: ulong uVar7;
15: undefined *puVar8;
16: undefined (*pauVar9) [32];
17: undefined (*pauVar10) [16];
18: undefined (*pauVar11) [32];
19: undefined (*pauVar12) [32];
20: undefined uVar14;
21: undefined uVar15;
22: undefined uVar16;
23: undefined uVar17;
24: undefined auVar13 [32];
25: undefined in_YMM0 [32];
26: undefined uVar19;
27: undefined uVar20;
28: undefined uVar21;
29: undefined uVar22;
30: undefined auVar18 [32];
31: undefined uVar23;
32: undefined uVar24;
33: undefined uVar25;
34: undefined uVar26;
35: 
36: uVar6 = (ulong)*(uint *)(param_1 + 0x19c);
37: if ((DAT_003a61e0 & 0x80) != 0) {
38: puVar8 = (undefined *)((ulong)*(uint *)(param_1 + 0x88) + 0x1f & 0xffffffffffffffe0);
39: puVar4 = &stack0xfffffffffffffff8;
40: if ((puVar8 != (undefined *)0x0) && (puVar4 = &stack0xfffffffffffffff8, uVar6 != 0)) {
41: pauVar11 = *param_4;
42: do {
43: pauVar9 = *param_3;
44: pauVar12 = *(undefined (**) [32])*pauVar11;
45: puVar4 = puVar8;
46: while ((undefined *)0x20 < puVar4) {
47: auVar13 = vmovdqu_avx(*pauVar9);
48: auVar13 = vpermq_avx2(auVar13,0xd8);
49: auVar18 = vpunpckhbw_avx2(auVar13,auVar13);
50: auVar13 = vpunpcklbw_avx2(auVar13,auVar13);
51: auVar13 = vmovdqu_avx(auVar13);
52: *pauVar12 = auVar13;
53: auVar13 = vmovdqu_avx(auVar18);
54: pauVar12[1] = auVar13;
55: puVar4 = puVar4 + -0x40;
56: if (puVar4 == (undefined *)0x0) goto LAB_00167094;
57: pauVar9 = pauVar9[1];
58: pauVar12 = pauVar12[2];
59: }
60: auVar1 = vmovdqu_avx(*(undefined (*) [16])*pauVar9);
61: auVar3 = vpunpckhbw_avx(auVar1,auVar1);
62: auVar1 = vpunpcklbw_avx(auVar1,auVar1);
63: auVar1 = vmovdqu_avx(auVar1);
64: *(undefined (*) [16])*pauVar12 = auVar1;
65: auVar1 = vmovdqu_avx(auVar3);
66: *(undefined (*) [16])(*pauVar12 + 0x10) = auVar1;
67: LAB_00167094:
68: param_3 = param_3 + 1;
69: pauVar11 = (undefined (*) [32])((long)*pauVar11 + 8);
70: uVar7 = uVar6 - 1;
71: bVar2 = 0 < (long)uVar6;
72: uVar6 = uVar7;
73: } while (uVar7 != 0 && bVar2);
74: }
75: vzeroupper_avx();
76: return puVar4;
77: }
78: uVar7 = (ulong)*(uint *)(param_1 + 0x88) + 0x1f & 0xffffffffffffffe0;
79: puVar4 = &stack0xfffffffffffffff8;
80: if ((uVar7 != 0) && (puVar4 = &stack0xfffffffffffffff8, uVar6 != 0)) {
81: pauVar11 = *param_4;
82: do {
83: pauVar9 = *param_3;
84: pauVar10 = *(undefined (**) [16])*pauVar11;
85: puVar8 = (undefined *)uVar7;
86: while( true ) {
87: auVar1 = *(undefined (*) [16])*pauVar9;
88: uVar17 = SUB161(auVar1 >> 0x38,0);
89: uVar16 = SUB161(auVar1 >> 0x30,0);
90: uVar15 = SUB161(auVar1 >> 0x28,0);
91: uVar14 = SUB161(auVar1 >> 0x20,0);
92: in_YMM0 = CONCAT302(SUB3230(CONCAT293(SUB3229(CONCAT284(SUB3228(CONCAT275(SUB3227(CONCAT266(
93: SUB3226(CONCAT257(SUB3225(CONCAT248(SUB3224(
94: CONCAT239(SUB3223(CONCAT2210(SUB3222(CONCAT2111(
95: SUB3221(CONCAT2012(SUB3220(CONCAT1913(SUB3219(
96: CONCAT1814(SUB3218(CONCAT1715(SUB3217(CONCAT1616(
97: SUB3216(in_YMM0 >> 0x80,0),
98: CONCAT115(uVar17,SUB1615(auVar1,0))) >> 0x78,0),
99: CONCAT114(uVar17,SUB1614(auVar1,0))) >> 0x70,0),
100: CONCAT113(uVar16,SUB1613(auVar1,0))) >> 0x68,0),
101: CONCAT112(uVar16,SUB1612(auVar1,0))) >> 0x60,0),
102: CONCAT111(uVar15,SUB1611(auVar1,0))) >> 0x58,0),
103: CONCAT110(uVar15,SUB1610(auVar1,0))) >> 0x50,0),
104: CONCAT19(uVar14,SUB169(auVar1,0))) >> 0x48,0),
105: CONCAT18(uVar14,SUB168(auVar1,0))) >> 0x40,0),
106: (SUB168(auVar1,0) >> 0x18) << 0x38) >> 0x38,0),
107: (SUB167(auVar1,0) >> 0x18) << 0x30) >> 0x30,0),
108: (SUB166(auVar1,0) >> 0x10) << 0x28) >> 0x28,0),
109: (SUB165(auVar1,0) >> 0x10) << 0x20) >> 0x20,0),
110: (SUB164(auVar1,0) >> 8) << 0x18) >> 0x18,0),
111: (SUB163(auVar1,0) >> 8) << 0x10) >> 0x10,0),
112: SUB162(auVar1,0) & 0xff | SUB162(auVar1,0) << 8);
113: uVar14 = SUB161(auVar1 >> 0x40,0);
114: uVar15 = SUB161(auVar1 >> 0x48,0);
115: uVar16 = SUB161(auVar1 >> 0x50,0);
116: uVar17 = SUB161(auVar1 >> 0x58,0);
117: uVar19 = SUB161(auVar1 >> 0x60,0);
118: uVar20 = SUB161(auVar1 >> 0x68,0);
119: uVar21 = SUB161(auVar1 >> 0x70,0);
120: uVar22 = SUB161(auVar1 >> 0x78,0);
121: *pauVar10 = SUB3216(in_YMM0,0);
122: pauVar10[1] = CONCAT115(uVar22,CONCAT114(uVar22,CONCAT113(uVar21,CONCAT112(uVar21,CONCAT111(
123: uVar20,CONCAT110(uVar20,CONCAT19(uVar19,CONCAT18(
124: uVar19,CONCAT17(uVar17,CONCAT16(uVar17,CONCAT15(
125: uVar16,CONCAT14(uVar16,CONCAT13(uVar15,CONCAT12(
126: uVar15,CONCAT11(uVar14,uVar14)))))))))))))));
127: puVar4 = puVar8 + -0x20;
128: if (puVar4 == (undefined *)0x0) break;
129: auVar1 = *(undefined (*) [16])(*pauVar9 + 0x10);
130: uVar17 = SUB161(auVar1 >> 0x38,0);
131: uVar16 = SUB161(auVar1 >> 0x30,0);
132: uVar15 = SUB161(auVar1 >> 0x28,0);
133: uVar14 = SUB161(auVar1 >> 0x20,0);
134: uVar19 = SUB161(auVar1 >> 0x40,0);
135: uVar20 = SUB161(auVar1 >> 0x48,0);
136: uVar21 = SUB161(auVar1 >> 0x50,0);
137: uVar22 = SUB161(auVar1 >> 0x58,0);
138: uVar23 = SUB161(auVar1 >> 0x60,0);
139: uVar24 = SUB161(auVar1 >> 0x68,0);
140: uVar25 = SUB161(auVar1 >> 0x70,0);
141: uVar26 = SUB161(auVar1 >> 0x78,0);
142: pauVar10[2] = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(
143: CONCAT106(SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(
144: CONCAT79(SUB167(CONCAT610(SUB166(CONCAT511(SUB165(
145: CONCAT412(SUB164(CONCAT313(SUB163(CONCAT214(SUB162
146: (CONCAT115(uVar17,CONCAT114(uVar17,SUB1614(auVar1,
147: 0))) >> 0x70,0),
148: CONCAT113(uVar16,SUB1613(auVar1,0))) >> 0x68,0),
149: CONCAT112(uVar16,SUB1612(auVar1,0))) >> 0x60,0),
150: CONCAT111(uVar15,SUB1611(auVar1,0))) >> 0x58,0),
151: CONCAT110(uVar15,SUB1610(auVar1,0))) >> 0x50,0),
152: CONCAT19(uVar14,SUB169(auVar1,0))) >> 0x48,0),
153: CONCAT18(uVar14,SUB168(auVar1,0))) >> 0x40,0),
154: (SUB168(auVar1,0) >> 0x18) << 0x38) >> 0x38,0),
155: (SUB167(auVar1,0) >> 0x18) << 0x30) >> 0x30,0),
156: (SUB166(auVar1,0) >> 0x10) << 0x28) >> 0x28,0),
157: (SUB165(auVar1,0) >> 0x10) << 0x20) >> 0x20,0),
158: (SUB164(auVar1,0) >> 8) << 0x18) >> 0x18,0),
159: (SUB163(auVar1,0) >> 8) << 0x10) >> 0x10,0),
160: SUB162(auVar1,0) & 0xff | SUB162(auVar1,0) << 8);
161: pauVar10[3][0] = uVar19;
162: pauVar10[3][1] = uVar19;
163: pauVar10[3][2] = uVar20;
164: pauVar10[3][3] = uVar20;
165: pauVar10[3][4] = uVar21;
166: pauVar10[3][5] = uVar21;
167: pauVar10[3][6] = uVar22;
168: pauVar10[3][7] = uVar22;
169: pauVar10[3][8] = uVar23;
170: pauVar10[3][9] = uVar23;
171: pauVar10[3][10] = uVar24;
172: pauVar10[3][0xb] = uVar24;
173: pauVar10[3][0xc] = uVar25;
174: pauVar10[3][0xd] = uVar25;
175: pauVar10[3][0xe] = uVar26;
176: pauVar10[3][0xf] = uVar26;
177: puVar4 = puVar8 + -0x40;
178: if (puVar4 == (undefined *)0x0) break;
179: pauVar9 = pauVar9[1];
180: pauVar10 = pauVar10[4];
181: puVar8 = puVar4;
182: }
183: param_3 = param_3 + 1;
184: pauVar11 = (undefined (*) [32])((long)*pauVar11 + 8);
185: uVar5 = uVar6 - 1;
186: bVar2 = 0 < (long)uVar6;
187: uVar6 = uVar5;
188: } while (uVar5 != 0 && bVar2);
189: }
190: return puVar4;
191: }
192: 
