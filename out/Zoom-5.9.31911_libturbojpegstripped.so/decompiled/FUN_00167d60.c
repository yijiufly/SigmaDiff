1: 
2: /* WARNING: Removing unreachable block (ram,0x0015fe5a) */
3: /* WARNING: Removing unreachable block (ram,0x0015fe60) */
4: /* WARNING: Removing unreachable block (ram,0x0015fe66) */
5: /* WARNING: Switch with 1 destination removed at 0x00167dc0 */
6: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
7: 
8: void FUN_00167d60(long param_1,undefined (**param_2) [32],long *param_3,ulong param_4,ulong param_5)
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
19: undefined (**ppauVar8) [32];
20: undefined (*pauVar9) [32];
21: undefined (**ppauVar10) [32];
22: undefined (*pauVar11) [32];
23: undefined (*pauVar12) [32];
24: undefined (**ppauVar13) [32];
25: undefined (*pauVar14) [32];
26: ulong uVar15;
27: undefined auVar16 [16];
28: undefined auVar17 [32];
29: undefined auVar18 [32];
30: undefined auVar19 [32];
31: undefined in_YMM1 [32];
32: undefined auVar20 [32];
33: undefined auVar21 [32];
34: undefined auVar22 [32];
35: undefined auVar23 [32];
36: undefined auVar24 [32];
37: undefined in_YMM5 [32];
38: undefined auVar25 [32];
39: undefined auVar26 [32];
40: undefined auVar27 [32];
41: undefined auVar28 [32];
42: undefined auVar29 [32];
43: undefined auVar30 [32];
44: undefined auVar31 [32];
45: undefined auVar32 [32];
46: undefined in_YMM7 [32];
47: 
48: switch(*(undefined4 *)(param_1 + 0x3c)) {
49: case 6:
50: UNRECOVERED_JUMPTABLE = (code *)&UNK_001558e0;
51: break;
52: case 7:
53: case 0xc:
54: UNRECOVERED_JUMPTABLE = (code *)&UNK_00155d80;
55: break;
56: case 8:
57: UNRECOVERED_JUMPTABLE = (code *)&UNK_001561e0;
58: uVar3 = *(uint *)(param_1 + 0x30);
59: goto joined_r0x00167db8;
60: case 9:
61: case 0xd:
62: UNRECOVERED_JUMPTABLE = (code *)&UNK_00156680;
63: break;
64: case 10:
65: case 0xe:
66: UNRECOVERED_JUMPTABLE = (code *)&UNK_00156ae0;
67: break;
68: case 0xb:
69: case 0xf:
70: UNRECOVERED_JUMPTABLE = (code *)&UNK_00156f40;
71: break;
72: default:
73: UNRECOVERED_JUMPTABLE = (code *)&LAB_00155440;
74: }
75: uVar3 = *(uint *)(param_1 + 0x30);
76: joined_r0x00167db8:
77: if ((DAT_003a61e0 & 0x80) != 0) {
78: uVar15 = (ulong)uVar3;
79: if (uVar15 != 0) {
80: param_4 = param_4 & 0xffffffff;
81: ppauVar13 = (undefined (**) [32])(*param_3 + param_4 * 8);
82: ppauVar10 = (undefined (**) [32])(param_3[1] + param_4 * 8);
83: ppauVar8 = (undefined (**) [32])(param_3[2] + param_4 * 8);
84: uVar4 = param_5 & 0xffffffff;
85: if ((param_5 & 0xffffffff) != 0) {
86: do {
87: pauVar12 = *param_2;
88: pauVar14 = *ppauVar13;
89: pauVar11 = *ppauVar10;
90: pauVar9 = *ppauVar8;
91: uVar7 = uVar15;
92: if (0x1f < uVar15) goto LAB_0015fe48;
93: do {
94: uVar7 = uVar7 * 3;
95: uVar5 = uVar4;
96: uVar6 = uVar7;
97: if ((uVar7 & 1) != 0) {
98: uVar6 = uVar7 - 1;
99: uVar5 = (ulong)(byte)pauVar12[-1][uVar7 + 0x1f];
100: }
101: uVar3 = (uint)uVar5;
102: uVar7 = uVar6;
103: if ((uVar6 & 2) != 0) {
104: uVar7 = uVar6 - 2;
105: uVar3 = (uint)(uVar5 << 0x10) | (uint)*(ushort *)(pauVar12[-1] + uVar6 + 0x1e);
106: }
107: auVar16 = vmovd_avx(uVar3);
108: uVar5 = uVar7;
109: if ((uVar7 & 4) != 0) {
110: uVar5 = uVar7 - 4;
111: auVar2 = vmovd_avx(*(undefined4 *)(pauVar12[-1] + uVar7 + 0x1c));
112: in_YMM5 = ZEXT1632(auVar2);
113: auVar16 = vpslldq_avx(auVar16,4);
114: auVar16 = vpor_avx(auVar16,auVar2);
115: }
116: uVar7 = uVar5;
117: if ((uVar5 & 8) != 0) {
118: uVar7 = uVar5 - 8;
119: auVar2 = vmovq_avx(ZEXT816(*(ulong *)(pauVar12[-1] + uVar5 + 0x18)));
120: in_YMM1 = ZEXT1632(auVar2);
121: auVar16 = vpslldq_avx(auVar16,8);
122: auVar16 = vpor_avx(auVar16,auVar2);
123: }
124: auVar17 = ZEXT1632(auVar16);
125: uVar5 = uVar7;
126: if ((uVar7 & 0x10) != 0) {
127: uVar5 = uVar7 - 0x10;
128: auVar16 = vmovdqu_avx(*(undefined (*) [16])(pauVar12[-1] + uVar7 + 0x10));
129: in_YMM1 = ZEXT1632(auVar16);
130: auVar17 = vperm2i128_avx2(auVar17,auVar17,1);
131: auVar17 = vpor_avx2(auVar17,in_YMM1);
132: }
133: if ((uVar5 & 0x20) != 0) {
134: uVar5 = uVar5 - 0x20;
135: in_YMM5 = vmovdqa_avx(auVar17);
136: auVar17 = vmovdqu_avx(*pauVar12);
137: }
138: uVar7 = 0x20;
139: if ((uVar5 & 0x40) != 0) {
140: in_YMM1 = vmovdqa_avx(auVar17);
141: auVar17 = vmovdqu_avx(*pauVar12);
142: in_YMM5 = vmovdqu_avx(pauVar12[1]);
143: }
144: while( true ) {
145: auVar20 = vmovdqu_avx(auVar17);
146: auVar17 = CONCAT1616(SUB3216(in_YMM5 >> 0x80,0),SUB3216(auVar17,0));
147: auVar23 = CONCAT1616(SUB3216(auVar20 >> 0x80,0),SUB3216(in_YMM1,0));
148: auVar20 = CONCAT1616(SUB3216(in_YMM1 >> 0x80,0),SUB3216(in_YMM5,0));
149: auVar23 = vperm2i128_avx2(auVar23,auVar23,1);
150: auVar25 = vmovdqa_avx(auVar17);
151: auVar17 = vpslldq_avx2(auVar17,8);
152: auVar25 = vpsrldq_avx2(auVar25,8);
153: auVar17 = vpunpckhbw_avx2(auVar17,auVar23);
154: auVar23 = vpslldq_avx2(auVar23,8);
155: auVar25 = vpunpcklbw_avx2(auVar25,auVar20);
156: auVar23 = vpunpckhbw_avx2(auVar23,auVar20);
157: auVar20 = vmovdqa_avx(auVar17);
158: auVar17 = vpslldq_avx2(auVar17,8);
159: auVar20 = vpsrldq_avx2(auVar20,8);
160: auVar17 = vpunpckhbw_avx2(auVar17,auVar25);
161: auVar25 = vpslldq_avx2(auVar25,8);
162: auVar20 = vpunpcklbw_avx2(auVar20,auVar23);
163: auVar26 = vpunpckhbw_avx2(auVar25,auVar23);
164: auVar23 = vmovdqa_avx(auVar17);
165: auVar17 = vpslldq_avx2(auVar17,8);
166: auVar23 = vpsrldq_avx2(auVar23,8);
167: auVar17 = vpunpckhbw_avx2(auVar17,auVar20);
168: auVar20 = vpslldq_avx2(auVar20,8);
169: auVar25 = vpunpcklbw_avx2(auVar23,auVar26);
170: auVar23 = vpunpckhbw_avx2(auVar20,auVar26);
171: auVar30 = vpxor_avx2(in_YMM7,in_YMM7);
172: auVar20 = vmovdqa_avx(auVar17);
173: auVar18 = vpunpcklbw_avx2(auVar17,auVar30);
174: auVar21 = vpunpckhbw_avx2(auVar20,auVar30);
175: auVar17 = vmovdqa_avx(auVar25);
176: auVar25 = vpunpcklbw_avx2(auVar25,auVar30);
177: auVar26 = vpunpckhbw_avx2(auVar17,auVar30);
178: auVar17 = vmovdqa_avx(auVar23);
179: auVar22 = vpunpcklbw_avx2(auVar23,auVar30);
180: auVar24 = vpunpckhbw_avx2(auVar17,auVar30);
181: auVar17 = vmovdqa_avx(auVar18);
182: auVar20 = vmovdqa_avx(auVar26);
183: auVar23 = vmovdqa_avx(auVar25);
184: auVar25 = vmovdqa_avx(auVar24);
185: auVar30 = vmovdqa_avx(auVar26);
186: auVar26 = vpunpcklwd_avx2(auVar26,auVar22);
187: auVar27 = vpunpckhwd_avx2(auVar30,auVar22);
188: auVar31 = vmovdqa_avx(auVar26);
189: auVar30 = vmovdqa_avx(auVar27);
190: auVar19 = vpmaddwd_avx2(auVar26,_DAT_0019cd60);
191: auVar28 = vpmaddwd_avx2(auVar27,_DAT_0019cd60);
192: auVar31 = vpmaddwd_avx2(auVar31,_DAT_0019cda0);
193: auVar27 = vpmaddwd_avx2(auVar30,_DAT_0019cda0);
194: auVar26 = vmovdqa_avx(auVar19);
195: auVar30 = vmovdqa_avx(auVar28);
196: auVar19 = vpxor_avx2(auVar19,auVar19);
197: auVar28 = vpxor_avx2(auVar28,auVar28);
198: auVar19 = vpunpcklwd_avx2(auVar19,auVar24);
199: auVar24 = vpunpckhwd_avx2(auVar28,auVar24);
200: auVar19 = vpsrld_avx2(auVar19,1);
201: auVar28 = vpsrld_avx2(auVar24,1);
202: auVar24 = vmovdqa_avx(_DAT_0019cde0);
203: auVar31 = vpaddd_avx2(auVar31,auVar19);
204: auVar19 = vpaddd_avx2(auVar27,auVar28);
205: auVar27 = vpaddd_avx2(auVar31,auVar24);
206: auVar19 = vpaddd_avx2(auVar19,auVar24);
207: auVar27 = vpsrld_avx2(auVar27,0x10);
208: auVar19 = vpsrld_avx2(auVar19,0x10);
209: auVar32 = vpackssdw_avx2(auVar27,auVar19);
210: auVar24 = vmovdqa_avx(auVar23);
211: auVar19 = vmovdqa_avx(auVar18);
212: auVar18 = vpunpcklwd_avx2(auVar18,auVar21);
213: auVar31 = vpunpckhwd_avx2(auVar19,auVar21);
214: auVar28 = vmovdqa_avx(auVar18);
215: auVar19 = vmovdqa_avx(auVar31);
216: auVar27 = vpmaddwd_avx2(auVar18,_DAT_0019cd60);
217: auVar29 = vpmaddwd_avx2(auVar31,_DAT_0019cd60);
218: auVar31 = vpmaddwd_avx2(auVar28,_DAT_0019cda0);
219: auVar28 = vpmaddwd_avx2(auVar19,_DAT_0019cda0);
220: auVar18 = vmovdqa_avx(auVar27);
221: auVar19 = vmovdqa_avx(auVar29);
222: auVar27 = vpxor_avx2(auVar27,auVar27);
223: auVar29 = vpxor_avx2(auVar29,auVar29);
224: auVar27 = vpunpcklwd_avx2(auVar27,auVar24);
225: auVar24 = vpunpckhwd_avx2(auVar29,auVar24);
226: auVar27 = vpsrld_avx2(auVar27,1);
227: auVar29 = vpsrld_avx2(auVar24,1);
228: auVar24 = vmovdqa_avx(_DAT_0019cde0);
229: auVar31 = vpaddd_avx2(auVar31,auVar27);
230: auVar27 = vpaddd_avx2(auVar28,auVar29);
231: auVar28 = vpaddd_avx2(auVar31,auVar24);
232: auVar27 = vpaddd_avx2(auVar27,auVar24);
233: auVar24 = vpsrld_avx2(auVar28,0x10);
234: auVar27 = vpsrld_avx2(auVar27,0x10);
235: auVar27 = vpackssdw_avx2(auVar24,auVar27);
236: auVar24 = vpsllw_avx2(auVar32,8);
237: auVar27 = vpor_avx2(auVar27,auVar24);
238: auVar27 = vmovdqu_avx(auVar27);
239: *pauVar11 = auVar27;
240: auVar25 = vmovdqa_avx(auVar25);
241: auVar28 = vmovdqa_avx(auVar23);
242: auVar23 = vmovdqa_avx(auVar20);
243: auVar27 = vmovdqa_avx(auVar25);
244: auVar20 = vpunpcklwd_avx2(auVar25,auVar22);
245: auVar25 = vpunpckhwd_avx2(auVar27,auVar22);
246: auVar22 = vmovdqa_avx(auVar20);
247: auVar24 = vmovdqa_avx(auVar25);
248: auVar20 = vpmaddwd_avx2(auVar20,_DAT_0019cd80);
249: auVar27 = vpmaddwd_avx2(auVar25,_DAT_0019cd80);
250: auVar22 = vpmaddwd_avx2(auVar22,_DAT_0019cdc0);
251: auVar24 = vpmaddwd_avx2(auVar24,_DAT_0019cdc0);
252: auVar25 = vmovdqa_avx(_DAT_0019ce00);
253: auVar20 = vpaddd_avx2(auVar20,auVar26);
254: auVar26 = vpaddd_avx2(auVar27,auVar30);
255: auVar20 = vpaddd_avx2(auVar20,auVar25);
256: auVar26 = vpaddd_avx2(auVar26,auVar25);
257: auVar20 = vpsrld_avx2(auVar20,0x10);
258: auVar26 = vpsrld_avx2(auVar26,0x10);
259: auVar20 = vpackssdw_avx2(auVar20,auVar26);
260: auVar25 = vpxor_avx2(auVar25,auVar25);
261: auVar26 = vpxor_avx2(auVar26,auVar26);
262: auVar25 = vpunpcklwd_avx2(auVar25,auVar23);
263: auVar23 = vpunpckhwd_avx2(auVar26,auVar23);
264: auVar25 = vpsrld_avx2(auVar25,1);
265: auVar26 = vpsrld_avx2(auVar23,1);
266: auVar23 = vmovdqa_avx(_DAT_0019cde0);
267: auVar30 = vpaddd_avx2(auVar22,auVar25);
268: auVar25 = vpaddd_avx2(auVar24,auVar26);
269: auVar26 = vpaddd_avx2(auVar30,auVar23);
270: auVar23 = vpaddd_avx2(auVar25,auVar23);
271: auVar25 = vpsrld_avx2(auVar26,0x10);
272: auVar23 = vpsrld_avx2(auVar23,0x10);
273: auVar22 = vpackssdw_avx2(auVar25,auVar23);
274: auVar26 = vmovdqa_avx(auVar17);
275: auVar17 = vmovdqa_avx(auVar28);
276: auVar30 = vpunpcklwd_avx2(auVar28,auVar21);
277: auVar23 = vpunpckhwd_avx2(auVar17,auVar21);
278: auVar17 = vmovdqa_avx(auVar30);
279: auVar25 = vmovdqa_avx(auVar23);
280: auVar24 = vpmaddwd_avx2(auVar30,_DAT_0019cd80);
281: auVar30 = vpmaddwd_avx2(auVar23,_DAT_0019cd80);
282: auVar23 = vpmaddwd_avx2(auVar17,_DAT_0019cdc0);
283: auVar27 = vpmaddwd_avx2(auVar25,_DAT_0019cdc0);
284: auVar25 = vmovdqa_avx(_DAT_0019ce00);
285: auVar18 = vpaddd_avx2(auVar24,auVar18);
286: auVar17 = vpaddd_avx2(auVar30,auVar19);
287: auVar30 = vpaddd_avx2(auVar18,auVar25);
288: auVar17 = vpaddd_avx2(auVar17,auVar25);
289: auVar18 = vpsrld_avx2(auVar30,0x10);
290: auVar30 = vpsrld_avx2(auVar17,0x10);
291: auVar18 = vpackssdw_avx2(auVar18,auVar30);
292: auVar17 = vpsllw_avx2(auVar20,8);
293: auVar17 = vpor_avx2(auVar18,auVar17);
294: auVar17 = vmovdqu_avx(auVar17);
295: *pauVar14 = auVar17;
296: auVar17 = vpxor_avx2(auVar25,auVar25);
297: auVar20 = vpxor_avx2(auVar30,auVar30);
298: auVar17 = vpunpcklwd_avx2(auVar17,auVar26);
299: auVar25 = vpunpckhwd_avx2(auVar20,auVar26);
300: auVar20 = vpsrld_avx2(auVar17,1);
301: auVar25 = vpsrld_avx2(auVar25,1);
302: auVar17 = vmovdqa_avx(_DAT_0019cde0);
303: auVar20 = vpaddd_avx2(auVar23,auVar20);
304: auVar23 = vpaddd_avx2(auVar27,auVar25);
305: auVar20 = vpaddd_avx2(auVar20,auVar17);
306: auVar23 = vpaddd_avx2(auVar23,auVar17);
307: auVar17 = vpsrld_avx2(auVar20,0x10);
308: in_YMM5 = vpsrld_avx2(auVar23,0x10);
309: auVar17 = vpackssdw_avx2(auVar17,in_YMM5);
310: in_YMM7 = vpsllw_avx2(auVar22,8);
311: in_YMM1 = vpor_avx2(auVar17,in_YMM7);
312: auVar17 = vmovdqu_avx(in_YMM1);
313: *pauVar9 = auVar17;
314: uVar7 = uVar7 - 0x20;
315: pauVar12 = pauVar12[3];
316: pauVar14 = pauVar14[1];
317: pauVar11 = pauVar11[1];
318: pauVar9 = pauVar9[1];
319: if (uVar7 < 0x20) break;
320: LAB_0015fe48:
321: auVar17 = vmovdqu_avx(*pauVar12);
322: in_YMM5 = vmovdqu_avx(pauVar12[1]);
323: in_YMM1 = vmovdqu_avx(pauVar12[2]);
324: }
325: } while (uVar7 != 0);
326: param_2 = param_2 + 1;
327: ppauVar13 = ppauVar13 + 1;
328: ppauVar10 = ppauVar10 + 1;
329: ppauVar8 = ppauVar8 + 1;
330: uVar7 = uVar4 - 1;
331: bVar1 = 0 < (long)uVar4;
332: uVar4 = uVar7;
333: } while (uVar7 != 0 && bVar1);
334: }
335: }
336: vzeroupper_avx();
337: return;
338: }
339: /* WARNING: Treating indirect jump as call */
340: (*UNRECOVERED_JUMPTABLE)();
341: return;
342: }
343: 
