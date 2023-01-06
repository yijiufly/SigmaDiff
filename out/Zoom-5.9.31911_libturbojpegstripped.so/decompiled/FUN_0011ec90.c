1: 
2: undefined8 FUN_0011ec90(long param_1)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: int iVar3;
8: long lVar4;
9: long lVar5;
10: int iVar6;
11: int iVar7;
12: int iVar8;
13: long lVar9;
14: undefined8 uVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: uint uStack108;
20: int iStack100;
21: long alStack88 [5];
22: 
23: lVar14 = 0;
24: lVar4 = *(long *)(param_1 + 0x230);
25: if (0 < *(int *)(param_1 + 0x1b0)) {
26: do {
27: lVar9 = *(long *)(param_1 + 0x1b8 + lVar14 * 8);
28: iVar7 = *(int *)(lVar9 + 0xc);
29: lVar9 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
30: (param_1,*(undefined8 *)(lVar4 + 0x90 + (long)*(int *)(lVar9 + 4) * 8),
31: *(int *)(param_1 + 0xb0) * iVar7,iVar7,1);
32: alStack88[lVar14] = lVar9;
33: iVar7 = (int)lVar14 + 1;
34: lVar14 = lVar14 + 1;
35: } while (*(int *)(param_1 + 0x1b0) != iVar7 && iVar7 <= *(int *)(param_1 + 0x1b0));
36: }
37: iStack100 = *(int *)(lVar4 + 0x2c);
38: iVar7 = *(int *)(lVar4 + 0x30);
39: if (iStack100 < iVar7) {
40: uStack108 = *(uint *)(lVar4 + 0x28);
41: lVar14 = (long)iStack100 * 8;
42: do {
43: if (uStack108 <= *(uint *)(param_1 + 0x1d8) && *(uint *)(param_1 + 0x1d8) != uStack108) {
44: do {
45: iVar7 = *(int *)(param_1 + 0x1b0);
46: if (0 < iVar7) {
47: lVar9 = 0;
48: iVar8 = 0;
49: do {
50: while( true ) {
51: lVar5 = *(long *)(param_1 + 0x1b8 + lVar9 * 8);
52: iVar2 = *(int *)(lVar5 + 0x34);
53: iVar3 = *(int *)(lVar5 + 0x38);
54: if (0 < iVar3) break;
55: joined_r0x0011f225:
56: iVar2 = (int)lVar9;
57: lVar9 = lVar9 + 1;
58: if (iVar7 <= iVar2 + 1) goto LAB_0011eed7;
59: }
60: lVar13 = (ulong)(uStack108 * iVar2) * 0x80;
61: lVar5 = alStack88[lVar9];
62: if (iVar2 < 1) goto joined_r0x0011f225;
63: if (iVar2 != 1) {
64: if (iVar2 == 2) {
65: lVar11 = lVar13 + *(long *)(lVar5 + lVar14);
66: *(long *)(lVar4 + 0x38 + (long)iVar8 * 8) = lVar11;
67: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 1) * 8) = lVar11 + 0x80;
68: if (iVar3 != 1) {
69: lVar11 = lVar13 + *(long *)(lVar5 + 8 + lVar14);
70: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 2) * 8) = lVar11;
71: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 3) * 8) = lVar11 + 0x80;
72: if (iVar3 != 2) {
73: lVar11 = lVar13 + *(long *)(lVar5 + 0x10 + lVar14);
74: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 4) * 8) = lVar11;
75: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 5) * 8) = lVar11 + 0x80;
76: if (iVar3 != 3) {
77: lVar11 = lVar13 + *(long *)(lVar5 + 0x18 + lVar14);
78: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 6) * 8) = lVar11;
79: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 7) * 8) = lVar11 + 0x80;
80: if (iVar3 != 4) {
81: lVar13 = lVar13 + *(long *)(lVar5 + 0x20 + lVar14);
82: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 8) * 8) = lVar13;
83: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 9) * 8) = lVar13 + 0x80;
84: }
85: }
86: }
87: }
88: iVar8 = iVar8 + iVar3 * 2;
89: }
90: else {
91: lVar11 = 0;
92: if (iVar2 == 3) {
93: lVar11 = lVar13 + *(long *)(lVar5 + lVar14);
94: *(long *)(lVar4 + 0x38 + (long)iVar8 * 8) = lVar11;
95: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 1) * 8) = lVar11 + 0x80;
96: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 2) * 8) = lVar11 + 0x100;
97: if (iVar3 != 1) {
98: lVar11 = lVar13 + *(long *)(lVar5 + 8 + lVar14);
99: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 3) * 8) = lVar11;
100: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 4) * 8) = lVar11 + 0x80;
101: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 5) * 8) = lVar11 + 0x100;
102: if (iVar3 != 2) {
103: lVar11 = lVar13 + *(long *)(lVar5 + 0x10 + lVar14);
104: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 6) * 8) = lVar11;
105: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 7) * 8) = lVar11 + 0x80;
106: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 8) * 8) = lVar11 + 0x100;
107: if (iVar3 != 3) {
108: lVar13 = lVar13 + *(long *)(lVar5 + 0x18 + lVar14);
109: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 9) * 8) = lVar13;
110: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 10) * 8) = lVar13 + 0x80;
111: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 0xb) * 8) = lVar13 + 0x100;
112: }
113: }
114: }
115: iVar8 = iVar8 + iVar3 * 3;
116: }
117: else {
118: do {
119: while( true ) {
120: lVar12 = lVar13 + *(long *)(lVar5 + lVar14 + lVar11 * 8);
121: *(long *)(lVar4 + 0x38 + (long)iVar8 * 8) = lVar12;
122: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 1) * 8) = lVar12 + 0x80;
123: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 2) * 8) = lVar12 + 0x100;
124: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 3) * 8) = lVar12 + 0x180;
125: iVar6 = iVar8 + 4;
126: if (iVar2 != 4) break;
127: LAB_0011eeb7:
128: iVar8 = iVar6;
129: lVar11 = lVar11 + 1;
130: if (iVar3 <= (int)lVar11) goto joined_r0x0011f225;
131: }
132: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 4) * 8) = lVar12 + 0x200;
133: iVar6 = iVar8 + 5;
134: if (iVar2 != 5) {
135: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 5) * 8) = lVar12 + 0x280;
136: iVar6 = iVar8 + 6;
137: if (iVar2 == 6) goto LAB_0011eeb7;
138: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 6) * 8) = lVar12 + 0x300;
139: iVar6 = iVar8 + 7;
140: if (iVar2 != 7) {
141: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 7) * 8) = lVar12 + 0x380;
142: iVar6 = iVar8 + 8;
143: if (iVar2 == 8) goto LAB_0011eeb7;
144: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 8) * 8) = lVar12 + 0x400;
145: iVar6 = iVar8 + 9;
146: if (iVar2 != 9) {
147: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 9) * 8) = lVar12 + 0x480;
148: iVar6 = iVar8 + 10;
149: }
150: }
151: }
152: iVar8 = iVar6;
153: lVar11 = lVar11 + 1;
154: } while ((int)lVar11 < iVar3);
155: }
156: }
157: goto joined_r0x0011f225;
158: }
159: *(long *)(lVar4 + 0x38 + (long)iVar8 * 8) = lVar13 + *(long *)(lVar5 + lVar14);
160: if (iVar3 != 1) {
161: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 1) * 8) =
162: lVar13 + *(long *)(lVar5 + 8 + lVar14);
163: if (iVar3 != 2) {
164: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 2) * 8) =
165: lVar13 + *(long *)(lVar5 + 0x10 + lVar14);
166: if (iVar3 != 3) {
167: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 3) * 8) =
168: lVar13 + *(long *)(lVar5 + 0x18 + lVar14);
169: if (iVar3 != 4) {
170: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 4) * 8) =
171: lVar13 + *(long *)(lVar5 + 0x20 + lVar14);
172: if (iVar3 != 5) {
173: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 5) * 8) =
174: lVar13 + *(long *)(lVar5 + 0x28 + lVar14);
175: if (iVar3 != 6) {
176: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 6) * 8) =
177: lVar13 + *(long *)(lVar5 + 0x30 + lVar14);
178: if (iVar3 != 7) {
179: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 7) * 8) =
180: lVar13 + *(long *)(lVar5 + 0x38 + lVar14);
181: if (iVar3 != 8) {
182: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 8) * 8) =
183: lVar13 + *(long *)(lVar5 + 0x40 + lVar14);
184: if (iVar3 != 9) {
185: *(long *)(lVar4 + 0x38 + (long)(iVar8 + 9) * 8) =
186: lVar13 + *(long *)(lVar5 + 0x48 + lVar14);
187: }
188: }
189: }
190: }
191: }
192: }
193: }
194: }
195: }
196: iVar8 = iVar8 + iVar3;
197: lVar9 = lVar9 + 1;
198: } while ((int)lVar9 < iVar7);
199: }
200: LAB_0011eed7:
201: uVar10 = (**(code **)(*(long *)(param_1 + 0x250) + 8))();
202: if ((int)uVar10 == 0) {
203: *(int *)(lVar4 + 0x2c) = iStack100;
204: *(uint *)(lVar4 + 0x28) = uStack108;
205: return uVar10;
206: }
207: uStack108 = uStack108 + 1;
208: } while (uStack108 <= *(uint *)(param_1 + 0x1d8) && *(uint *)(param_1 + 0x1d8) != uStack108)
209: ;
210: iVar7 = *(int *)(lVar4 + 0x30);
211: }
212: iStack100 = iStack100 + 1;
213: lVar14 = lVar14 + 8;
214: *(undefined4 *)(lVar4 + 0x28) = 0;
215: if (iVar7 <= iStack100) break;
216: uStack108 = 0;
217: } while( true );
218: }
219: uVar1 = *(int *)(param_1 + 0xb0) + 1;
220: *(uint *)(param_1 + 0xb0) = uVar1;
221: if (uVar1 < *(uint *)(param_1 + 0x1a4)) {
222: lVar4 = *(long *)(param_1 + 0x230);
223: if (*(int *)(param_1 + 0x1b0) < 2) {
224: if (uVar1 < *(uint *)(param_1 + 0x1a4) - 1) {
225: *(undefined4 *)(lVar4 + 0x30) = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0xc);
226: }
227: else {
228: *(undefined4 *)(lVar4 + 0x30) = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0x48);
229: }
230: }
231: else {
232: *(undefined4 *)(lVar4 + 0x30) = 1;
233: }
234: *(undefined4 *)(lVar4 + 0x28) = 0;
235: *(undefined4 *)(lVar4 + 0x2c) = 0;
236: return 3;
237: }
238: (**(code **)(*(long *)(param_1 + 0x240) + 0x18))(param_1);
239: return 4;
240: }
241: 
