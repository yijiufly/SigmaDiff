1: 
2: void thunk_FUN_00155120(undefined (*param_1) [16])
3: 
4: {
5: long lVar1;
6: undefined (*pauVar2) [16];
7: float fVar3;
8: float fVar4;
9: float fVar5;
10: float fVar6;
11: float fVar7;
12: float fVar8;
13: float fVar9;
14: float fVar10;
15: float fVar11;
16: float fVar12;
17: float fVar13;
18: float fVar14;
19: float fVar15;
20: float fVar16;
21: float fVar17;
22: float fVar18;
23: float fVar19;
24: float fVar20;
25: float fVar21;
26: float fVar22;
27: float fVar23;
28: float fVar24;
29: float fVar25;
30: float fVar26;
31: float fVar27;
32: float fVar28;
33: float fVar29;
34: float fVar30;
35: float fVar31;
36: float fVar32;
37: float fVar33;
38: float fVar34;
39: float fVar35;
40: float fVar36;
41: float fVar37;
42: float fVar38;
43: float fVar39;
44: float fVar40;
45: 
46: lVar1 = 2;
47: pauVar2 = param_1;
48: do {
49: fVar11 = *(float *)(pauVar2[6] + 0xc);
50: fVar10 = *(float *)pauVar2[5];
51: fVar29 = *(float *)pauVar2[7];
52: fVar9 = *(float *)(pauVar2[2] + 0xc);
53: fVar8 = *(float *)pauVar2[1];
54: fVar7 = *(float *)pauVar2[3];
55: fVar33 = 0.0 - *(float *)(pauVar2[1] + 8);
56: fVar35 = *(float *)(pauVar2[2] + 4) - *(float *)(pauVar2[3] + 8);
57: fVar37 = 0.0 - *(float *)(pauVar2[5] + 8);
58: fVar39 = *(float *)(pauVar2[6] + 4) - *(float *)(pauVar2[7] + 8);
59: fVar28 = *(float *)*pauVar2 - 0.0;
60: fVar30 = *(float *)pauVar2[2] - *(float *)(pauVar2[3] + 0xc);
61: fVar31 = *(float *)pauVar2[4] - 0.0;
62: fVar32 = *(float *)pauVar2[6] - *(float *)(pauVar2[7] + 0xc);
63: fVar3 = *(float *)(pauVar2[1] + 8) + 0.0;
64: fVar4 = *(float *)(pauVar2[2] + 4) + *(float *)(pauVar2[3] + 8);
65: fVar5 = *(float *)(pauVar2[5] + 8) + 0.0;
66: fVar6 = *(float *)(pauVar2[6] + 4) + *(float *)(pauVar2[7] + 8);
67: fVar20 = *(float *)*pauVar2 + 0.0;
68: fVar22 = *(float *)pauVar2[2] + *(float *)(pauVar2[3] + 0xc);
69: fVar24 = *(float *)pauVar2[4] + 0.0;
70: fVar26 = *(float *)pauVar2[6] + *(float *)(pauVar2[7] + 0xc);
71: fVar34 = fVar8 + 0.0;
72: fVar36 = fVar9 + fVar7;
73: fVar38 = fVar10 + 0.0;
74: fVar40 = fVar11 + fVar29;
75: fVar16 = *(float *)(*pauVar2 + 8) + 0.0;
76: fVar17 = *(float *)(pauVar2[2] + 8) + *(float *)(pauVar2[3] + 4);
77: fVar18 = *(float *)(pauVar2[4] + 8) + 0.0;
78: fVar19 = *(float *)(pauVar2[6] + 8) + *(float *)(pauVar2[7] + 4);
79: fVar12 = *(float *)(*pauVar2 + 8) - 0.0;
80: fVar13 = *(float *)(pauVar2[2] + 8) - *(float *)(pauVar2[3] + 4);
81: fVar14 = *(float *)(pauVar2[4] + 8) - 0.0;
82: fVar15 = *(float *)(pauVar2[6] + 8) - *(float *)(pauVar2[7] + 4);
83: fVar21 = fVar20 - fVar34;
84: fVar23 = fVar22 - fVar36;
85: fVar25 = fVar24 - fVar38;
86: fVar27 = fVar26 - fVar40;
87: fVar20 = fVar20 + fVar34;
88: fVar22 = fVar22 + fVar36;
89: fVar24 = fVar24 + fVar38;
90: fVar26 = fVar26 + fVar40;
91: fVar34 = fVar3 + fVar16;
92: fVar36 = fVar4 + fVar17;
93: fVar38 = fVar5 + fVar18;
94: fVar40 = fVar6 + fVar19;
95: fVar3 = ((fVar3 - fVar16) + fVar21) * 0.7071068;
96: fVar4 = ((fVar4 - fVar17) + fVar23) * 0.7071068;
97: fVar5 = ((fVar5 - fVar18) + fVar25) * 0.7071068;
98: fVar6 = ((fVar6 - fVar19) + fVar27) * 0.7071068;
99: pauVar2[1] = CONCAT412(fVar26 - fVar40,
100: CONCAT48(fVar24 - fVar38,CONCAT44(fVar22 - fVar36,fVar20 - fVar34)));
101: pauVar2[5] = CONCAT412(fVar27 - fVar6,
102: CONCAT48(fVar25 - fVar5,CONCAT44(fVar23 - fVar4,fVar21 - fVar3)));
103: *pauVar2 = CONCAT412(fVar26 + fVar40,
104: CONCAT48(fVar24 + fVar38,CONCAT44(fVar22 + fVar36,fVar20 + fVar34)));
105: pauVar2[4] = CONCAT412(fVar27 + fVar6,
106: CONCAT48(fVar25 + fVar5,CONCAT44(fVar23 + fVar4,fVar21 + fVar3)));
107: fVar8 = (0.0 - fVar8) + fVar12;
108: fVar9 = (fVar9 - fVar7) + fVar13;
109: fVar10 = (0.0 - fVar10) + fVar14;
110: fVar11 = (fVar11 - fVar29) + fVar15;
111: fVar29 = fVar33 + fVar28;
112: fVar16 = fVar35 + fVar30;
113: fVar17 = fVar37 + fVar31;
114: fVar18 = fVar39 + fVar32;
115: fVar24 = (fVar12 + fVar33) * 0.7071068;
116: fVar26 = (fVar13 + fVar35) * 0.7071068;
117: fVar12 = (fVar14 + fVar37) * 0.7071068;
118: fVar13 = (fVar15 + fVar39) * 0.7071068;
119: fVar5 = (fVar8 - fVar29) * 0.3826834;
120: fVar6 = (fVar9 - fVar16) * 0.3826834;
121: fVar20 = (fVar10 - fVar17) * 0.3826834;
122: fVar22 = (fVar11 - fVar18) * 0.3826834;
123: fVar8 = fVar8 * 0.5411961 + fVar5;
124: fVar7 = fVar9 * 0.5411961 + fVar6;
125: fVar3 = fVar10 * 0.5411961 + fVar20;
126: fVar4 = fVar11 * 0.5411961 + fVar22;
127: fVar5 = fVar29 * 1.306563 + fVar5;
128: fVar6 = fVar16 * 1.306563 + fVar6;
129: fVar20 = fVar17 * 1.306563 + fVar20;
130: fVar22 = fVar18 * 1.306563 + fVar22;
131: fVar11 = fVar28 - fVar24;
132: fVar10 = fVar30 - fVar26;
133: fVar29 = fVar31 - fVar12;
134: fVar9 = fVar32 - fVar13;
135: fVar28 = fVar28 + fVar24;
136: fVar30 = fVar30 + fVar26;
137: fVar31 = fVar31 + fVar12;
138: fVar32 = fVar32 + fVar13;
139: pauVar2[6] = CONCAT412(fVar9 - fVar4,
140: CONCAT48(fVar29 - fVar3,CONCAT44(fVar10 - fVar7,fVar11 - fVar8)));
141: pauVar2[7] = CONCAT412(fVar32 - fVar22,
142: CONCAT48(fVar31 - fVar20,CONCAT44(fVar30 - fVar6,fVar28 - fVar5)));
143: pauVar2[3] = CONCAT412(fVar9 + fVar4,
144: CONCAT48(fVar29 + fVar3,CONCAT44(fVar10 + fVar7,fVar11 + fVar8)));
145: pauVar2[2] = CONCAT412(fVar32 + fVar22,
146: CONCAT48(fVar31 + fVar20,CONCAT44(fVar30 + fVar6,fVar28 + fVar5)));
147: pauVar2 = pauVar2[8];
148: lVar1 = lVar1 + -1;
149: } while (lVar1 != 0);
150: lVar1 = 2;
151: do {
152: fVar11 = *(float *)(param_1[6] + 0xc);
153: fVar10 = *(float *)param_1[0xc];
154: fVar29 = *(float *)param_1[0xe];
155: fVar9 = *(float *)(param_1[2] + 0xc);
156: fVar8 = *(float *)param_1[8];
157: fVar7 = *(float *)param_1[10];
158: fVar33 = 0.0 - *(float *)(param_1[8] + 8);
159: fVar35 = *(float *)(param_1[2] + 4) - *(float *)(param_1[10] + 8);
160: fVar37 = 0.0 - *(float *)(param_1[0xc] + 8);
161: fVar39 = *(float *)(param_1[6] + 4) - *(float *)(param_1[0xe] + 8);
162: fVar28 = *(float *)*param_1 - 0.0;
163: fVar30 = *(float *)param_1[2] - *(float *)(param_1[10] + 0xc);
164: fVar31 = *(float *)param_1[4] - 0.0;
165: fVar32 = *(float *)param_1[6] - *(float *)(param_1[0xe] + 0xc);
166: fVar3 = *(float *)(param_1[8] + 8) + 0.0;
167: fVar4 = *(float *)(param_1[2] + 4) + *(float *)(param_1[10] + 8);
168: fVar5 = *(float *)(param_1[0xc] + 8) + 0.0;
169: fVar6 = *(float *)(param_1[6] + 4) + *(float *)(param_1[0xe] + 8);
170: fVar20 = *(float *)*param_1 + 0.0;
171: fVar22 = *(float *)param_1[2] + *(float *)(param_1[10] + 0xc);
172: fVar24 = *(float *)param_1[4] + 0.0;
173: fVar26 = *(float *)param_1[6] + *(float *)(param_1[0xe] + 0xc);
174: fVar34 = fVar8 + 0.0;
175: fVar36 = fVar9 + fVar7;
176: fVar38 = fVar10 + 0.0;
177: fVar40 = fVar11 + fVar29;
178: fVar16 = *(float *)(*param_1 + 8) + 0.0;
179: fVar17 = *(float *)(param_1[2] + 8) + *(float *)(param_1[10] + 4);
180: fVar18 = *(float *)(param_1[4] + 8) + 0.0;
181: fVar19 = *(float *)(param_1[6] + 8) + *(float *)(param_1[0xe] + 4);
182: fVar12 = *(float *)(*param_1 + 8) - 0.0;
183: fVar13 = *(float *)(param_1[2] + 8) - *(float *)(param_1[10] + 4);
184: fVar14 = *(float *)(param_1[4] + 8) - 0.0;
185: fVar15 = *(float *)(param_1[6] + 8) - *(float *)(param_1[0xe] + 4);
186: fVar21 = fVar20 - fVar34;
187: fVar23 = fVar22 - fVar36;
188: fVar25 = fVar24 - fVar38;
189: fVar27 = fVar26 - fVar40;
190: fVar20 = fVar20 + fVar34;
191: fVar22 = fVar22 + fVar36;
192: fVar24 = fVar24 + fVar38;
193: fVar26 = fVar26 + fVar40;
194: fVar34 = fVar3 + fVar16;
195: fVar36 = fVar4 + fVar17;
196: fVar38 = fVar5 + fVar18;
197: fVar40 = fVar6 + fVar19;
198: fVar3 = ((fVar3 - fVar16) + fVar21) * 0.7071068;
199: fVar4 = ((fVar4 - fVar17) + fVar23) * 0.7071068;
200: fVar5 = ((fVar5 - fVar18) + fVar25) * 0.7071068;
201: fVar6 = ((fVar6 - fVar19) + fVar27) * 0.7071068;
202: param_1[8] = CONCAT412(fVar26 - fVar40,
203: CONCAT48(fVar24 - fVar38,CONCAT44(fVar22 - fVar36,fVar20 - fVar34)));
204: param_1[0xc] = CONCAT412(fVar27 - fVar6,
205: CONCAT48(fVar25 - fVar5,CONCAT44(fVar23 - fVar4,fVar21 - fVar3)));
206: *param_1 = CONCAT412(fVar26 + fVar40,
207: CONCAT48(fVar24 + fVar38,CONCAT44(fVar22 + fVar36,fVar20 + fVar34)));
208: param_1[4] = CONCAT412(fVar27 + fVar6,
209: CONCAT48(fVar25 + fVar5,CONCAT44(fVar23 + fVar4,fVar21 + fVar3)));
210: fVar8 = (0.0 - fVar8) + fVar12;
211: fVar9 = (fVar9 - fVar7) + fVar13;
212: fVar10 = (0.0 - fVar10) + fVar14;
213: fVar11 = (fVar11 - fVar29) + fVar15;
214: fVar29 = fVar33 + fVar28;
215: fVar16 = fVar35 + fVar30;
216: fVar17 = fVar37 + fVar31;
217: fVar18 = fVar39 + fVar32;
218: fVar24 = (fVar12 + fVar33) * 0.7071068;
219: fVar26 = (fVar13 + fVar35) * 0.7071068;
220: fVar12 = (fVar14 + fVar37) * 0.7071068;
221: fVar13 = (fVar15 + fVar39) * 0.7071068;
222: fVar5 = (fVar8 - fVar29) * 0.3826834;
223: fVar6 = (fVar9 - fVar16) * 0.3826834;
224: fVar20 = (fVar10 - fVar17) * 0.3826834;
225: fVar22 = (fVar11 - fVar18) * 0.3826834;
226: fVar8 = fVar8 * 0.5411961 + fVar5;
227: fVar7 = fVar9 * 0.5411961 + fVar6;
228: fVar3 = fVar10 * 0.5411961 + fVar20;
229: fVar4 = fVar11 * 0.5411961 + fVar22;
230: fVar5 = fVar29 * 1.306563 + fVar5;
231: fVar6 = fVar16 * 1.306563 + fVar6;
232: fVar20 = fVar17 * 1.306563 + fVar20;
233: fVar22 = fVar18 * 1.306563 + fVar22;
234: fVar11 = fVar28 - fVar24;
235: fVar10 = fVar30 - fVar26;
236: fVar29 = fVar31 - fVar12;
237: fVar9 = fVar32 - fVar13;
238: fVar28 = fVar28 + fVar24;
239: fVar30 = fVar30 + fVar26;
240: fVar31 = fVar31 + fVar12;
241: fVar32 = fVar32 + fVar13;
242: param_1[6] = CONCAT412(fVar9 - fVar4,
243: CONCAT48(fVar29 - fVar3,CONCAT44(fVar10 - fVar7,fVar11 - fVar8)));
244: param_1[0xe] = CONCAT412(fVar32 - fVar22,
245: CONCAT48(fVar31 - fVar20,CONCAT44(fVar30 - fVar6,fVar28 - fVar5)));
246: param_1[10] = CONCAT412(fVar9 + fVar4,
247: CONCAT48(fVar29 + fVar3,CONCAT44(fVar10 + fVar7,fVar11 + fVar8)));
248: param_1[2] = CONCAT412(fVar32 + fVar22,
249: CONCAT48(fVar31 + fVar20,CONCAT44(fVar30 + fVar6,fVar28 + fVar5)));
250: param_1 = param_1[1];
251: lVar1 = lVar1 + -1;
252: } while (lVar1 != 0);
253: return;
254: }
255: 
