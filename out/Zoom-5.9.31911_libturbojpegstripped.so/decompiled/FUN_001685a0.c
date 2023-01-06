1: 
2: void FUN_001685a0(long *param_1,ulong param_2,undefined (*param_3) [32])
3: 
4: {
5: ulong uVar1;
6: ulong uVar2;
7: ulong uVar3;
8: ulong uVar4;
9: long lVar5;
10: undefined auVar6 [14];
11: undefined auVar7 [32];
12: undefined in_YMM0 [32];
13: undefined auVar8 [12];
14: undefined auVar9 [16];
15: undefined auVar10 [32];
16: undefined in_YMM1 [32];
17: undefined auVar12 [16];
18: undefined auVar13 [32];
19: undefined in_YMM2 [32];
20: undefined auVar14 [16];
21: undefined auVar15 [16];
22: undefined auVar17 [29];
23: undefined auVar16 [32];
24: undefined in_YMM3 [32];
25: short sVar18;
26: short sVar21;
27: short sVar22;
28: short sVar23;
29: short sVar24;
30: short sVar25;
31: short sVar26;
32: undefined auVar19 [16];
33: short sVar27;
34: undefined auVar20 [32];
35: undefined in_YMM7 [32];
36: undefined auVar11 [29];
37: 
38: if ((DAT_003a61e0 & 0x80) == 0) {
39: auVar19 = psllw(CONCAT214(0xffff,CONCAT212(0xffff,CONCAT210(0xffff,CONCAT28(0xffff,
40: 0xffffffffffffffff)))),7);
41: param_2 = param_2 & 0xffffffff;
42: lVar5 = 2;
43: do {
44: uVar1 = *(ulong *)(*param_1 + param_2);
45: uVar2 = *(ulong *)(param_1[1] + param_2);
46: uVar3 = *(ulong *)(param_1[2] + param_2);
47: uVar4 = *(ulong *)(param_1[3] + param_2);
48: auVar6 = ZEXT814(uVar1);
49: auVar7 = CONCAT257(SUB3225(CONCAT248(SUB3224(CONCAT239(SUB3223(CONCAT2210(SUB3222(CONCAT2111(
50: SUB3221(CONCAT2012(SUB3220(CONCAT1913(SUB3219(
51: CONCAT1814(SUB3218(CONCAT1715(SUB3217(CONCAT1616(
52: SUB3216(in_YMM0 >> 0x80,0),
53: ZEXT1516(ZEXT815(uVar1))) >> 0x78,0),
54: CONCAT114(SUB151(ZEXT815(uVar1) >> 0x38,0),auVar6)
55: ) >> 0x70,0),ZEXT814(uVar1)) >> 0x68,0),
56: CONCAT112(SUB141(auVar6 >> 0x30,0),ZEXT812(uVar1))
57: ) >> 0x60,0),ZEXT812(uVar1)) >> 0x58,0),
58: CONCAT110(SUB141(auVar6 >> 0x28,0),
59: (unkuint10)uVar1)) >> 0x50,0),
60: (unkuint10)uVar1) >> 0x48,0),
61: CONCAT18(SUB121(ZEXT812(uVar1) >> 0x20,0),uVar1))
62: >> 0x40,0),uVar1) >> 0x38,0) &
63: SUB3225((undefined  [32])0xffffffffffffffff >> 0x38,0),
64: ((uint7)uVar1 >> 0x18) << 0x30) & (undefined  [32])0xffff000000000000;
65: auVar10 = CONCAT275(SUB3227(auVar7 >> 0x28,0),((uint5)uVar1 >> 0x10) << 0x20);
66: auVar6 = ZEXT814(uVar2);
67: auVar8 = ZEXT812(uVar2);
68: auVar11 = SUB3229(CONCAT284(SUB3228(CONCAT275(SUB3227(CONCAT266(SUB3226(CONCAT257(SUB3225(
69: CONCAT248(SUB3224(CONCAT239(SUB3223(CONCAT2210(
70: SUB3222(CONCAT2111(SUB3221(CONCAT2012(SUB3220(
71: CONCAT1913(SUB3219(CONCAT1814(SUB3218(CONCAT1715(
72: SUB3217(CONCAT1616(SUB3216(in_YMM1 >> 0x80,0),
73: ZEXT1516(ZEXT815(uVar2))) >>
74: 0x78,0),
75: CONCAT114(SUB151(ZEXT815(uVar2) >> 0x38,0),auVar6)
76: ) >> 0x70,0),auVar6) >> 0x68,0) &
77: SUB3219((undefined  [32])0xffffffffffffffff >>
78: 0x68,0),
79: CONCAT112(SUB141(auVar6 >> 0x30,0),auVar8)) >>
80: 0x60,0),auVar8) >> 0x58,0) &
81: SUB3221((undefined  [32])0xffffffffffffffff >>
82: 0x58,0),
83: CONCAT110(SUB141(auVar6 >> 0x28,0),
84: (unkuint10)uVar2)) >> 0x50,0),
85: (unkuint10)uVar2) >> 0x48,0) &
86: SUB3223((undefined  [32])0xffffffffffffffff >>
87: 0x48,0),
88: CONCAT18(SUB121(auVar8 >> 0x20,0),uVar2)) >> 0x40,
89: 0),uVar2) >> 0x38,0) &
90: SUB3225((undefined  [32])0xffffffffffffffff >>
91: 0x38,0),((uint7)uVar2 >> 0x18) << 0x30) >>
92: 0x30,0),(int6)uVar2) >> 0x28,0) &
93: SUB3227((undefined  [32])0xffff00ffffffffff >>
94: 0x28,0),((uint5)uVar2 >> 0x10) << 0x20) >>
95: 0x20,0),(int)uVar2) >> 0x18,0) &
96: SUB3229((undefined  [32])0xffffffff00ffffff >> 0x18,0);
97: sVar18 = SUB162(auVar19,0);
98: sVar21 = SUB162(auVar19 >> 0x10,0);
99: sVar22 = SUB162(auVar19 >> 0x20,0);
100: sVar23 = SUB162(auVar19 >> 0x30,0);
101: sVar24 = SUB162(auVar19 >> 0x40,0);
102: sVar25 = SUB162(auVar19 >> 0x50,0);
103: sVar26 = SUB162(auVar19 >> 0x60,0);
104: sVar27 = SUB162(auVar19 >> 0x70,0);
105: auVar9 = CONCAT214(SUB322(auVar7 >> 0x70,0) + sVar27,
106: CONCAT212(SUB322(auVar7 >> 0x60,0) + sVar26,
107: CONCAT210(SUB322(auVar7 >> 0x50,0) + sVar25,
108: CONCAT28(SUB322(auVar7 >> 0x40,0) + sVar24,
109: CONCAT26(SUB322(auVar7 >> 0x30,0) + sVar23,
110: CONCAT24(SUB322(auVar10 >> 0x20,0) +
111: sVar22,CONCAT22(SUB322(
112: CONCAT293(SUB3229(CONCAT284(SUB3228(auVar10 >>
113: 0x20,0),
114: (int)uVar1) >> 0x18,0)
115: & SUB3229((undefined  [32])
116: 0xffffffff00ffffff >> 0x18,0),
117: ((uint3)uVar1 >> 8) << 0x10) >> 0x10,0)
118: + sVar21,((ushort)uVar1 & 0xff) + sVar18)))))));
119: in_YMM0 = CONCAT1616(SUB3216(auVar7 >> 0x80,0),auVar9);
120: auVar12 = CONCAT214(SUB292(auVar11 >> 0x58,0) + sVar27,
121: CONCAT212(SUB292(auVar11 >> 0x48,0) + sVar26,
122: CONCAT210(SUB292(auVar11 >> 0x38,0) + sVar25,
123: CONCAT28(SUB292(auVar11 >> 0x28,0) + sVar24,
124: CONCAT26(SUB292(auVar11 >> 0x18,0) + sVar23,
125: CONCAT24(SUB292(auVar11 >> 8,0) +
126: sVar22,CONCAT22(SUB322(
127: CONCAT293(auVar11,((uint3)uVar2 >> 8) << 0x10) >>
128: 0x10,0) + sVar21,((ushort)uVar2 & 0xff) + sVar18))
129: )))));
130: in_YMM1 = CONCAT1616(SUB2916(auVar11 >> 0x68,0),auVar12);
131: auVar6 = ZEXT814(uVar3);
132: auVar8 = ZEXT812(uVar3);
133: auVar11 = SUB3229(CONCAT284(SUB3228(CONCAT275(SUB3227(CONCAT266(SUB3226(CONCAT257(SUB3225(
134: CONCAT248(SUB3224(CONCAT239(SUB3223(CONCAT2210(
135: SUB3222(CONCAT2111(SUB3221(CONCAT2012(SUB3220(
136: CONCAT1913(SUB3219(CONCAT1814(SUB3218(CONCAT1715(
137: SUB3217(CONCAT1616(SUB3216(in_YMM2 >> 0x80,0),
138: ZEXT1516(ZEXT815(uVar3))) >>
139: 0x78,0),
140: CONCAT114(SUB151(ZEXT815(uVar3) >> 0x38,0),auVar6)
141: ) >> 0x70,0),auVar6) >> 0x68,0) &
142: SUB3219((undefined  [32])0xffffffffffffffff >>
143: 0x68,0),
144: CONCAT112(SUB141(auVar6 >> 0x30,0),auVar8)) >>
145: 0x60,0),auVar8) >> 0x58,0) &
146: SUB3221((undefined  [32])0xffffffffffffffff >>
147: 0x58,0),
148: CONCAT110(SUB141(auVar6 >> 0x28,0),
149: (unkuint10)uVar3)) >> 0x50,0),
150: (unkuint10)uVar3) >> 0x48,0) &
151: SUB3223((undefined  [32])0xffffffffffffffff >>
152: 0x48,0),
153: CONCAT18(SUB121(auVar8 >> 0x20,0),uVar3)) >> 0x40,
154: 0),uVar3) >> 0x38,0) &
155: SUB3225((undefined  [32])0xffffffffffffffff >>
156: 0x38,0),((uint7)uVar3 >> 0x18) << 0x30) >>
157: 0x30,0),(int6)uVar3) >> 0x28,0) &
158: SUB3227((undefined  [32])0xffff00ffffffffff >>
159: 0x28,0),((uint5)uVar3 >> 0x10) << 0x20) >>
160: 0x20,0),(int)uVar3) >> 0x18,0) &
161: SUB3229((undefined  [32])0xffffffff00ffffff >> 0x18,0);
162: auVar6 = ZEXT814(uVar4);
163: auVar8 = ZEXT812(uVar4);
164: auVar17 = SUB3229(CONCAT284(SUB3228(CONCAT275(SUB3227(CONCAT266(SUB3226(CONCAT257(SUB3225(
165: CONCAT248(SUB3224(CONCAT239(SUB3223(CONCAT2210(
166: SUB3222(CONCAT2111(SUB3221(CONCAT2012(SUB3220(
167: CONCAT1913(SUB3219(CONCAT1814(SUB3218(CONCAT1715(
168: SUB3217(CONCAT1616(SUB3216(in_YMM3 >> 0x80,0),
169: ZEXT1516(ZEXT815(uVar4))) >>
170: 0x78,0),
171: CONCAT114(SUB151(ZEXT815(uVar4) >> 0x38,0),auVar6)
172: ) >> 0x70,0),auVar6) >> 0x68,0) &
173: SUB3219((undefined  [32])0xffffffffffffffff >>
174: 0x68,0),
175: CONCAT112(SUB141(auVar6 >> 0x30,0),auVar8)) >>
176: 0x60,0),auVar8) >> 0x58,0) &
177: SUB3221((undefined  [32])0xffffffffffffffff >>
178: 0x58,0),
179: CONCAT110(SUB141(auVar6 >> 0x28,0),
180: (unkuint10)uVar4)) >> 0x50,0),
181: (unkuint10)uVar4) >> 0x48,0) &
182: SUB3223((undefined  [32])0xffffffffffffffff >>
183: 0x48,0),
184: CONCAT18(SUB121(auVar8 >> 0x20,0),uVar4)) >> 0x40,
185: 0),uVar4) >> 0x38,0) &
186: SUB3225((undefined  [32])0xffffffffffffffff >>
187: 0x38,0),((uint7)uVar4 >> 0x18) << 0x30) >>
188: 0x30,0),(int6)uVar4) >> 0x28,0) &
189: SUB3227((undefined  [32])0xffff00ffffffffff >>
190: 0x28,0),((uint5)uVar4 >> 0x10) << 0x20) >>
191: 0x20,0),(int)uVar4) >> 0x18,0) &
192: SUB3229((undefined  [32])0xffffffff00ffffff >> 0x18,0);
193: auVar15 = CONCAT214(SUB292(auVar11 >> 0x58,0) + sVar27,
194: CONCAT212(SUB292(auVar11 >> 0x48,0) + sVar26,
195: CONCAT210(SUB292(auVar11 >> 0x38,0) + sVar25,
196: CONCAT28(SUB292(auVar11 >> 0x28,0) + sVar24,
197: CONCAT26(SUB292(auVar11 >> 0x18,0) + sVar23,
198: CONCAT24(SUB292(auVar11 >> 8,0) +
199: sVar22,CONCAT22(SUB322(
200: CONCAT293(auVar11,((uint3)uVar3 >> 8) << 0x10) >>
201: 0x10,0) + sVar21,((ushort)uVar3 & 0xff) + sVar18))
202: )))));
203: in_YMM2 = CONCAT1616(SUB2916(auVar11 >> 0x68,0),auVar15);
204: auVar14 = CONCAT214(SUB292(auVar17 >> 0x58,0) + sVar27,
205: CONCAT212(SUB292(auVar17 >> 0x48,0) + sVar26,
206: CONCAT210(SUB292(auVar17 >> 0x38,0) + sVar25,
207: CONCAT28(SUB292(auVar17 >> 0x28,0) + sVar24,
208: CONCAT26(SUB292(auVar17 >> 0x18,0) + sVar23,
209: CONCAT24(SUB292(auVar17 >> 8,0) +
210: sVar22,CONCAT22(SUB322(
211: CONCAT293(auVar17,((uint3)uVar4 >> 8) << 0x10) >>
212: 0x10,0) + sVar21,((ushort)uVar4 & 0xff) + sVar18))
213: )))));
214: in_YMM3 = CONCAT1616(SUB2916(auVar17 >> 0x68,0),auVar14);
215: *(undefined (*) [16])*param_3 = auVar9;
216: *(undefined (*) [16])(*param_3 + 0x10) = auVar12;
217: *(undefined (*) [16])param_3[1] = auVar15;
218: *(undefined (*) [16])(param_3[1] + 0x10) = auVar14;
219: param_1 = param_1 + 4;
220: param_3 = param_3[2];
221: lVar5 = lVar5 + -1;
222: } while (lVar5 != 0);
223: return;
224: }
225: param_2 = param_2 & 0xffffffff;
226: auVar19 = pinsrq(ZEXT816(*(ulong *)(*param_1 + param_2)),*(undefined8 *)(param_1[1] + param_2),1);
227: auVar9 = pinsrq(ZEXT816(*(ulong *)(param_1[2] + param_2)),*(undefined8 *)(param_1[3] + param_2),1)
228: ;
229: auVar12 = pinsrq(ZEXT816(*(ulong *)(param_1[4] + param_2)),*(undefined8 *)(param_1[5] + param_2),1
230: );
231: auVar15 = pinsrq(ZEXT816(*(ulong *)(param_1[6] + param_2)),*(undefined8 *)(param_1[7] + param_2),1
232: );
233: auVar7 = vpmovzxbw_avx2(auVar19);
234: auVar10 = vpmovzxbw_avx2(auVar9);
235: auVar13 = vpmovzxbw_avx2(auVar12);
236: auVar16 = vpmovzxbw_avx2(auVar15);
237: auVar20 = vpcmpeqw_avx2(in_YMM7,in_YMM7);
238: auVar20 = vpsllw_avx2(auVar20,7);
239: auVar7 = vpaddw_avx2(auVar7,auVar20);
240: auVar10 = vpaddw_avx2(auVar10,auVar20);
241: auVar13 = vpaddw_avx2(auVar13,auVar20);
242: auVar16 = vpaddw_avx2(auVar16,auVar20);
243: auVar7 = vmovdqu_avx(auVar7);
244: *param_3 = auVar7;
245: auVar7 = vmovdqu_avx(auVar10);
246: param_3[1] = auVar7;
247: auVar7 = vmovdqu_avx(auVar13);
248: param_3[2] = auVar7;
249: auVar7 = vmovdqu_avx(auVar16);
250: param_3[3] = auVar7;
251: vzeroupper_avx();
252: return;
253: }
254: 
