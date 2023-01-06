1: 
2: void FUN_00140b60(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: short *psVar7;
12: long lVar8;
13: long lVar9;
14: undefined *puVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: long lVar18;
23: long lVar19;
24: long lVar20;
25: long lVar21;
26: long lVar22;
27: long lVar23;
28: long lVar24;
29: long lVar25;
30: long lVar26;
31: long lVar27;
32: long lVar28;
33: long lVar29;
34: long lVar30;
35: long lVar31;
36: long lVar32;
37: ulong uVar33;
38: long lVar34;
39: long lVar35;
40: long lVar36;
41: long lVar37;
42: long lVar38;
43: long lVar39;
44: long lVar40;
45: long lVar41;
46: long lVar42;
47: int iStack72;
48: int iStack64;
49: int iStack56;
50: 
51: uVar33 = (ulong)param_5;
52: psVar7 = *(short **)(param_2 + 0x58);
53: lVar8 = *(long *)(param_1 + 0x1a8);
54: lVar21 = (long)((int)*param_3 * (int)*psVar7) * 0x2000 + 0x400;
55: lVar28 = (long)((int)param_3[0x10] * (int)psVar7[0x10]) +
56: (long)((int)param_3[0x20] * (int)psVar7[0x20]);
57: lVar22 = (long)((int)param_3[0x10] * (int)psVar7[0x10]) -
58: (long)((int)param_3[0x20] * (int)psVar7[0x20]);
59: lVar23 = lVar21 + lVar22 * 0xb50;
60: lVar9 = lVar28 * 0x194c + lVar23;
61: lVar23 = lVar23 + lVar28 * -0x194c;
62: lVar34 = ((long)((int)param_3[8] * (int)psVar7[8]) +
63: (long)((int)param_3[0x18] * (int)psVar7[0x18])) * 0x1a9a;
64: lVar12 = (long)((int)param_3[8] * (int)psVar7[8]) * 0x1071 + lVar34;
65: lVar34 = (long)((int)param_3[0x18] * (int)psVar7[0x18]) * -0x45a4 + lVar34;
66: lVar29 = (long)((int)param_3[1] * (int)psVar7[1]) * 0x2000 + 0x400;
67: lVar28 = (long)((int)param_3[0x11] * (int)psVar7[0x11]) +
68: (long)((int)param_3[0x21] * (int)psVar7[0x21]);
69: lVar24 = (long)((int)param_3[0x11] * (int)psVar7[0x11]) -
70: (long)((int)param_3[0x21] * (int)psVar7[0x21]);
71: lVar35 = lVar29 + lVar24 * 0xb50;
72: lVar1 = lVar28 * 0x194c + lVar35;
73: lVar35 = lVar35 + lVar28 * -0x194c;
74: lVar13 = ((long)((int)param_3[9] * (int)psVar7[9]) +
75: (long)((int)param_3[0x19] * (int)psVar7[0x19])) * 0x1a9a;
76: lVar2 = (long)((int)param_3[9] * (int)psVar7[9]) * 0x1071 + lVar13;
77: lVar13 = (long)((int)param_3[0x19] * (int)psVar7[0x19]) * -0x45a4 + lVar13;
78: lVar28 = (long)((int)param_3[2] * (int)psVar7[2]) * 0x2000 + 0x400;
79: lVar3 = (long)((int)param_3[0x12] * (int)psVar7[0x12]) +
80: (long)((int)param_3[0x22] * (int)psVar7[0x22]);
81: lVar36 = (long)((int)param_3[0x12] * (int)psVar7[0x12]) -
82: (long)((int)param_3[0x22] * (int)psVar7[0x22]);
83: lVar37 = lVar28 + lVar36 * 0xb50;
84: lVar4 = lVar3 * 0x194c + lVar37;
85: lVar37 = lVar37 + lVar3 * -0x194c;
86: lVar14 = ((long)((int)param_3[10] * (int)psVar7[10]) +
87: (long)((int)param_3[0x1a] * (int)psVar7[0x1a])) * 0x1a9a;
88: lVar25 = (long)((int)param_3[10] * (int)psVar7[10]) * 0x1071 + lVar14;
89: lVar14 = lVar14 + (long)((int)param_3[0x1a] * (int)psVar7[0x1a]) * -0x45a4;
90: lVar38 = (long)(int)(lVar4 + lVar25 >> 0xb);
91: lVar3 = (long)((int)param_3[3] * (int)psVar7[3]) * 0x2000 + 0x400;
92: lVar15 = (long)((int)param_3[0x13] * (int)psVar7[0x13]) +
93: (long)((int)param_3[0x23] * (int)psVar7[0x23]);
94: lVar30 = (long)((int)param_3[0x13] * (int)psVar7[0x13]) -
95: (long)((int)param_3[0x23] * (int)psVar7[0x23]);
96: lVar31 = lVar3 + lVar30 * 0xb50;
97: lVar5 = lVar15 * 0x194c + lVar31;
98: lVar31 = lVar31 + lVar15 * -0x194c;
99: lVar15 = ((long)((int)param_3[0xb] * (int)psVar7[0xb]) +
100: (long)((int)param_3[0x1b] * (int)psVar7[0x1b])) * 0x1a9a;
101: lVar26 = (long)((int)param_3[0x1b] * (int)psVar7[0x1b]) * -0x45a4 + lVar15;
102: lVar15 = (long)((int)param_3[0xb] * (int)psVar7[0xb]) * 0x1071 + lVar15;
103: lVar27 = (long)((int)param_3[4] * (int)psVar7[4]) * 0x2000 + 0x400;
104: lVar17 = (long)((int)param_3[0x14] * (int)psVar7[0x14]) +
105: (long)((int)param_3[0x24] * (int)psVar7[0x24]);
106: lVar32 = (long)((int)param_3[0x14] * (int)psVar7[0x14]) -
107: (long)((int)param_3[0x24] * (int)psVar7[0x24]);
108: lVar19 = lVar27 + lVar32 * 0xb50;
109: lVar6 = lVar17 * 0x194c + lVar19;
110: lVar19 = lVar19 + lVar17 * -0x194c;
111: lVar39 = ((long)((int)param_3[0xc] * (int)psVar7[0xc]) +
112: (long)((int)param_3[0x1c] * (int)psVar7[0x1c])) * 0x1a9a;
113: lVar16 = (long)((int)param_3[0xc] * (int)psVar7[0xc]) * 0x1071 + lVar39;
114: lVar39 = lVar39 + (long)((int)param_3[0x1c] * (int)psVar7[0x1c]) * -0x45a4;
115: lVar41 = (long)(int)(lVar19 + lVar39 >> 0xb);
116: lVar40 = (long)(int)(lVar6 + lVar16 >> 0xb);
117: puVar10 = (undefined *)(*param_4 + uVar33);
118: lVar17 = lVar40 + lVar38;
119: lVar38 = lVar38 - lVar40;
120: lVar11 = ((long)(int)(lVar12 + lVar9 >> 0xb) + 0x10) * 0x2000;
121: lVar40 = lVar38 * 0xb50 + lVar11;
122: lVar18 = lVar40 + lVar17 * 0x194c;
123: lVar40 = lVar40 + lVar17 * -0x194c;
124: lVar20 = (long)(int)(lVar1 + lVar2 >> 0xb);
125: lVar17 = (long)(int)(lVar5 + lVar15 >> 0xb);
126: lVar42 = (lVar17 + lVar20) * 0x1a9a;
127: lVar20 = lVar20 * 0x1071 + lVar42;
128: lVar42 = lVar42 + lVar17 * -0x45a4;
129: *puVar10 = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar20 + lVar18 >> 0x12) & 0x3ff));
130: puVar10[4] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar18 - lVar20 >> 0x12) & 0x3ff));
131: puVar10[1] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar42 + lVar40 >> 0x12) & 0x3ff));
132: puVar10[3] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar40 - lVar42 >> 0x12) & 0x3ff));
133: lVar42 = (long)(int)(lVar37 + lVar14 >> 0xb);
134: lVar18 = lVar41 + lVar42;
135: lVar42 = lVar42 - lVar41;
136: puVar10[2] = *(undefined *)
137: (lVar8 + 0x80 + (ulong)((uint)(lVar11 + lVar38 * -0x2d40 >> 0x12) & 0x3ff));
138: puVar10 = (undefined *)(param_4[1] + uVar33);
139: lVar11 = ((long)(int)(lVar34 + lVar23 >> 0xb) + 0x10) * 0x2000;
140: lVar17 = lVar42 * 0xb50 + lVar11;
141: lVar40 = lVar17 + lVar18 * 0x194c;
142: lVar17 = lVar17 + lVar18 * -0x194c;
143: lVar20 = (long)(int)(lVar35 + lVar13 >> 0xb);
144: lVar18 = (long)(int)(lVar31 + lVar26 >> 0xb);
145: lVar38 = (lVar18 + lVar20) * 0x1a9a;
146: lVar20 = lVar20 * 0x1071 + lVar38;
147: lVar38 = lVar38 + lVar18 * -0x45a4;
148: *puVar10 = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar20 + lVar40 >> 0x12) & 0x3ff));
149: puVar10[4] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar40 - lVar20 >> 0x12) & 0x3ff));
150: lVar40 = (long)(int)(lVar28 + lVar36 * -0x2d40 >> 0xb);
151: puVar10[1] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar38 + lVar17 >> 0x12) & 0x3ff));
152: puVar10[3] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar17 - lVar38 >> 0x12) & 0x3ff));
153: puVar10[2] = *(undefined *)
154: (lVar8 + 0x80 + (ulong)((uint)(lVar11 + lVar42 * -0x2d40 >> 0x12) & 0x3ff));
155: puVar10 = (undefined *)(param_4[2] + uVar33);
156: lVar18 = ((long)(int)(lVar21 + lVar22 * -0x2d40 >> 0xb) + 0x10) * 0x2000;
157: lVar28 = (long)(int)(lVar27 + lVar32 * -0x2d40 >> 0xb);
158: lVar17 = (long)(int)(lVar3 + lVar30 * -0x2d40 >> 0xb);
159: lVar21 = lVar28 + lVar40;
160: lVar40 = lVar40 - lVar28;
161: lVar28 = lVar40 * 0xb50 + lVar18;
162: lVar3 = lVar28 + lVar21 * 0x194c;
163: lVar28 = lVar28 + lVar21 * -0x194c;
164: iStack72 = (int)(lVar29 + lVar24 * -0x2d40 >> 0xb);
165: lVar21 = (lVar17 + iStack72) * 0x1a9a;
166: lVar11 = (long)iStack72 * 0x1071 + lVar21;
167: lVar21 = lVar21 + lVar17 * -0x45a4;
168: *puVar10 = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar11 + lVar3 >> 0x12) & 0x3ff));
169: puVar10[4] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar3 - lVar11 >> 0x12) & 0x3ff));
170: iStack56 = (int)(lVar19 - lVar39 >> 0xb);
171: puVar10[1] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar21 + lVar28 >> 0x12) & 0x3ff));
172: puVar10[3] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar28 - lVar21 >> 0x12) & 0x3ff));
173: puVar10[2] = *(undefined *)
174: (lVar8 + 0x80 + (ulong)((uint)(lVar18 + lVar40 * -0x2d40 >> 0x12) & 0x3ff));
175: puVar10 = (undefined *)(param_4[3] + uVar33);
176: lVar34 = ((long)(int)(lVar23 - lVar34 >> 0xb) + 0x10) * 0x2000;
177: lVar37 = (long)(int)(lVar37 - lVar14 >> 0xb);
178: lVar13 = (long)(int)(lVar35 - lVar13 >> 0xb);
179: lVar21 = lVar37 + iStack56;
180: lVar37 = lVar37 - iStack56;
181: lVar28 = lVar34 + lVar37 * 0xb50;
182: lVar3 = lVar21 * 0x194c + lVar28;
183: lVar28 = lVar28 + lVar21 * -0x194c;
184: lVar35 = (long)(int)(lVar31 - lVar26 >> 0xb);
185: lVar21 = (lVar13 + lVar35) * 0x1a9a;
186: lVar13 = lVar13 * 0x1071 + lVar21;
187: lVar21 = lVar21 + lVar35 * -0x45a4;
188: *puVar10 = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar3 + lVar13 >> 0x12) & 0x3ff));
189: puVar10[4] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar3 - lVar13 >> 0x12) & 0x3ff));
190: puVar10[1] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar28 + lVar21 >> 0x12) & 0x3ff));
191: puVar10[3] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar28 - lVar21 >> 0x12) & 0x3ff));
192: iStack64 = (int)(lVar4 - lVar25 >> 0xb);
193: puVar10[2] = *(undefined *)
194: (lVar8 + 0x80 + (ulong)((uint)(lVar34 + lVar37 * -0x2d40 >> 0x12) & 0x3ff));
195: puVar10 = (undefined *)(uVar33 + param_4[4]);
196: lVar12 = ((long)(int)(lVar9 - lVar12 >> 0xb) + 0x10) * 0x2000;
197: lVar9 = (long)(int)(lVar6 - lVar16 >> 0xb);
198: lVar21 = iStack64 + lVar9;
199: lVar9 = iStack64 - lVar9;
200: lVar35 = (long)(int)(lVar5 - lVar15 >> 0xb);
201: lVar28 = lVar12 + lVar9 * 0xb50;
202: lVar3 = lVar21 * 0x194c + lVar28;
203: lVar28 = lVar28 + lVar21 * -0x194c;
204: lVar34 = (long)(int)(lVar1 - lVar2 >> 0xb);
205: lVar21 = (lVar34 + lVar35) * 0x1a9a;
206: lVar34 = lVar34 * 0x1071 + lVar21;
207: lVar21 = lVar35 * -0x45a4 + lVar21;
208: *puVar10 = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar3 + lVar34 >> 0x12) & 0x3ff));
209: puVar10[4] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar3 - lVar34 >> 0x12) & 0x3ff));
210: puVar10[1] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar28 + lVar21 >> 0x12) & 0x3ff));
211: puVar10[3] = *(undefined *)(lVar8 + 0x80 + (ulong)((uint)(lVar28 - lVar21 >> 0x12) & 0x3ff));
212: puVar10[2] = *(undefined *)
213: (lVar8 + 0x80 + (ulong)((uint)(lVar12 + lVar9 * -0x2d40 >> 0x12) & 0x3ff));
214: return;
215: }
216: 
