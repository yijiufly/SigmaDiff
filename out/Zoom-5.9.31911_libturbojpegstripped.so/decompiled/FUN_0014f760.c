1: 
2: undefined8 FUN_0014f760(code **param_1,uint *param_2)
3: 
4: {
5: code **ppcVar1;
6: bool bVar2;
7: int iVar3;
8: uint uVar4;
9: int iVar5;
10: long lVar6;
11: undefined8 uVar7;
12: int iVar8;
13: uint uVar9;
14: uint uVar10;
15: ulong uVar11;
16: uint uVar12;
17: ulong uVar13;
18: uint uVar14;
19: int iVar15;
20: uint uVar16;
21: long lVar17;
22: 
23: if ((param_2[3] == 0) || (param_1[7] != (code *)0x300000003)) {
24: uVar10 = param_2[1];
25: uVar12 = *(uint *)(param_1 + 7);
26: uVar14 = *(uint *)(param_1 + 6);
27: uVar13 = (ulong)uVar14;
28: uVar16 = *(uint *)((long)param_1 + 0x34);
29: uVar11 = (ulong)uVar16;
30: param_2[0xe] = uVar12;
31: *(uint *)(param_1 + 0x11) = uVar14;
32: *(uint *)((long)param_1 + 0x8c) = uVar16;
33: if (uVar10 != 0) {
34: if (uVar12 == 1) goto LAB_0014fb98;
35: iVar3 = FUN_0014f700(uVar13,uVar11,*(int *)(param_1 + 0x34) * *(int *)(param_1 + 0x33));
36: goto joined_r0x0014fbaa;
37: }
38: }
39: else {
40: uVar10 = param_2[1];
41: param_2[0xe] = 1;
42: uVar13 = (ulong)*(uint *)(param_1 + 6);
43: uVar11 = (ulong)*(uint *)((long)param_1 + 0x34);
44: *(uint *)(param_1 + 0x11) = *(uint *)(param_1 + 6);
45: *(uint *)((long)param_1 + 0x8c) = *(uint *)((long)param_1 + 0x34);
46: if (uVar10 != 0) {
47: LAB_0014fb98:
48: iVar3 = FUN_0014f700();
49: joined_r0x0014fbaa:
50: if (iVar3 == 0) {
51: return 0;
52: }
53: uVar11 = (ulong)*(uint *)((long)param_1 + 0x8c);
54: uVar13 = (ulong)*(uint *)(param_1 + 0x11);
55: }
56: }
57: uVar10 = (uint)uVar11;
58: if ((*param_2 - 3 < 5) && ((1 << ((byte)(*param_2 - 3) & 0x3f) & 0x17U) != 0)) {
59: param_2[0x12] = uVar10;
60: param_2[0x13] = (uint)uVar13;
61: uVar12 = *(uint *)(param_1 + 0x34);
62: if (param_2[0xe] == 1) {
63: param_2[0x16] = uVar12;
64: param_2[0x17] = uVar12;
65: uVar13 = uVar11;
66: goto LAB_0014f88c;
67: }
68: iVar3 = *(int *)(param_1 + 0x33);
69: param_2[0x16] = *(int *)((long)param_1 + 0x19c) * uVar12;
70: param_2[0x17] = uVar12 * iVar3;
71: if (param_2[4] != 0) goto LAB_0014f895;
72: LAB_0014f840:
73: param_2[0x14] = 0;
74: param_2[0x15] = 0;
75: uVar4 = 0;
76: uVar9 = 0;
77: }
78: else {
79: param_2[0x12] = (uint)uVar13;
80: param_2[0x13] = uVar10;
81: uVar10 = *(uint *)(param_1 + 0x34);
82: if (param_2[0xe] == 1) {
83: param_2[0x16] = uVar10;
84: param_2[0x17] = uVar10;
85: }
86: else {
87: iVar3 = *(int *)((long)param_1 + 0x19c);
88: param_2[0x16] = *(int *)(param_1 + 0x33) * uVar10;
89: param_2[0x17] = uVar10 * iVar3;
90: }
91: LAB_0014f88c:
92: uVar10 = (uint)uVar13;
93: uVar11 = uVar13;
94: if (param_2[4] == 0) goto LAB_0014f840;
95: LAB_0014f895:
96: if (param_2[0xb] == 0) {
97: param_2[10] = 0;
98: uVar12 = 0;
99: }
100: else {
101: uVar12 = param_2[10];
102: }
103: if (param_2[0xd] == 0) {
104: param_2[0xc] = 0;
105: }
106: if ((uVar12 < uVar10) && (param_2[0xc] < param_2[0x13])) {
107: uVar10 = param_2[7];
108: if (uVar10 != 0) goto LAB_0014f8d4;
109: LAB_0014f9ab:
110: uVar12 = param_2[0x12] - param_2[10];
111: param_2[6] = uVar12;
112: }
113: else {
114: ppcVar1 = (code **)*param_1;
115: *(undefined4 *)(ppcVar1 + 5) = 0x7c;
116: (**ppcVar1)();
117: uVar10 = param_2[7];
118: if (uVar10 == 0) goto LAB_0014f9ab;
119: LAB_0014f8d4:
120: uVar12 = param_2[6];
121: }
122: uVar14 = param_2[9];
123: if (uVar14 == 0) {
124: param_2[8] = param_2[0x13] - param_2[0xc];
125: }
126: if (((((uVar12 == 0) || (param_2[0x12] < uVar12)) || (uVar16 = param_2[8], uVar16 == 0)) ||
127: ((param_2[0x13] < uVar16 || (uVar9 = param_2[10], param_2[0x12] - uVar12 < uVar9)))) ||
128: (uVar4 = param_2[0xc], param_2[0x13] - uVar16 < uVar4)) {
129: ppcVar1 = (code **)*param_1;
130: *(undefined4 *)(ppcVar1 + 5) = 0x7c;
131: (**ppcVar1)();
132: uVar10 = param_2[7];
133: uVar12 = param_2[6];
134: uVar14 = param_2[9];
135: uVar16 = param_2[8];
136: uVar4 = param_2[0xc];
137: uVar9 = param_2[10];
138: }
139: if (param_2[0xb] == 2) {
140: uVar9 = (param_2[0x12] - uVar12) - uVar9;
141: }
142: if (param_2[0xd] == 2) {
143: uVar4 = (param_2[0x13] - uVar16) - uVar4;
144: }
145: if (uVar10 != 3) {
146: uVar12 = uVar12 + uVar9 % param_2[0x16];
147: }
148: uVar11 = (ulong)uVar12;
149: param_2[0x12] = uVar12;
150: if (uVar14 != 3) {
151: uVar16 = uVar16 + uVar4 % param_2[0x17];
152: }
153: param_2[0x13] = uVar16;
154: uVar9 = uVar9 / param_2[0x16];
155: param_2[0x14] = uVar9;
156: uVar4 = uVar4 / param_2[0x17];
157: param_2[0x15] = uVar4;
158: }
159: if (7 < *param_2) {
160: LAB_0014fcf0:
161: *(undefined8 *)(param_2 + 0x10) = 0;
162: return 1;
163: }
164: switch(*param_2) {
165: case 0:
166: if (*(long *)(param_2 + 0x14) == 0) goto LAB_0014fcf0;
167: break;
168: case 1:
169: if (param_2[2] != 0) {
170: uVar10 = param_2[0x16];
171: iVar3 = (int)(uVar11 / uVar10);
172: if ((iVar3 != 0) && (uVar9 + iVar3 == *(uint *)(param_1 + 0x11) / uVar10)) {
173: param_2[0x12] = uVar10 * iVar3;
174: }
175: }
176: if ((uVar4 == 0) && (param_2[5] == 0)) goto LAB_0014fcf0;
177: break;
178: case 2:
179: if (param_2[2] != 0) {
180: code_r0x0014fc00:
181: uVar10 = param_2[0x17];
182: uVar12 = param_2[0x13] / uVar10;
183: if ((uVar12 != 0) && (uVar4 + uVar12 == *(uint *)((long)param_1 + 0x8c) / uVar10)) {
184: param_2[0x13] = uVar10 * uVar12;
185: }
186: }
187: break;
188: case 3:
189: goto code_r0x0014f9d0;
190: case 4:
191: if (param_2[2] != 0) {
192: uVar10 = param_2[0x16];
193: iVar3 = (int)(uVar11 / uVar10);
194: if ((iVar3 != 0) && (uVar9 + iVar3 == *(uint *)((long)param_1 + 0x8c) / uVar10)) {
195: param_2[0x12] = uVar10 * iVar3;
196: }
197: code_r0x0014fd2b:
198: uVar10 = param_2[0x17];
199: uVar12 = param_2[0x13] / uVar10;
200: if ((uVar12 != 0) && (uVar4 + uVar12 == *(uint *)(param_1 + 0x11) / uVar10)) {
201: bVar2 = true;
202: param_2[0x13] = uVar10 * uVar12;
203: goto code_r0x0014f9d6;
204: }
205: }
206: goto code_r0x0014f9d0;
207: case 5:
208: if (param_2[2] != 0) {
209: uVar10 = param_2[0x16];
210: iVar3 = (int)(uVar11 / uVar10);
211: if ((iVar3 != 0) && (uVar9 + iVar3 == *(uint *)((long)param_1 + 0x8c) / uVar10)) {
212: bVar2 = true;
213: param_2[0x12] = uVar10 * iVar3;
214: goto code_r0x0014f9d6;
215: }
216: }
217: goto code_r0x0014f9d0;
218: case 6:
219: if (param_2[2] != 0) {
220: uVar10 = param_2[0x16];
221: iVar3 = (int)(uVar11 / uVar10);
222: if ((iVar3 != 0) && (uVar9 + iVar3 == *(uint *)(param_1 + 0x11) / uVar10)) {
223: param_2[0x12] = uVar10 * iVar3;
224: }
225: goto code_r0x0014fc00;
226: }
227: break;
228: case 7:
229: if (param_2[2] != 0) goto code_r0x0014fd2b;
230: code_r0x0014f9d0:
231: bVar2 = true;
232: goto code_r0x0014f9d6;
233: }
234: bVar2 = false;
235: code_r0x0014f9d6:
236: lVar6 = (**(code **)param_1[1])(param_1,1,(long)(int)param_2[0xe] << 3);
237: iVar3 = FUN_0013be20(param_2[0x12],(long)(int)param_2[0x16]);
238: iVar5 = FUN_0013be20(param_2[0x13],(long)(int)param_2[0x17]);
239: uVar10 = param_2[0xe];
240: if (0 < (int)uVar10) {
241: lVar17 = 0;
242: if (bVar2) {
243: do {
244: if (uVar10 == 1) {
245: iVar15 = 1;
246: iVar8 = 1;
247: }
248: else {
249: iVar8 = *(int *)(param_1[0x26] + lVar17 * 0x60 + 0xc);
250: iVar15 = *(int *)(param_1[0x26] + lVar17 * 0x60 + 8);
251: }
252: uVar7 = (**(code **)(param_1[1] + 0x28))(param_1,1,0,iVar8 * iVar3,iVar15 * iVar5,iVar15);
253: *(undefined8 *)(lVar6 + lVar17 * 8) = uVar7;
254: uVar10 = param_2[0xe];
255: iVar8 = (int)lVar17;
256: lVar17 = lVar17 + 1;
257: } while (iVar8 + 1 < (int)uVar10);
258: }
259: else {
260: do {
261: if (uVar10 == 1) {
262: iVar15 = 1;
263: iVar8 = 1;
264: }
265: else {
266: iVar8 = *(int *)(param_1[0x26] + lVar17 * 0x60 + 8);
267: iVar15 = *(int *)(param_1[0x26] + lVar17 * 0x60 + 0xc);
268: }
269: uVar7 = (**(code **)(param_1[1] + 0x28))(param_1,1,0,iVar8 * iVar3,iVar15 * iVar5,iVar15);
270: *(undefined8 *)(lVar6 + lVar17 * 8) = uVar7;
271: uVar10 = param_2[0xe];
272: iVar8 = (int)lVar17;
273: lVar17 = lVar17 + 1;
274: } while (iVar8 + 1 < (int)uVar10);
275: }
276: }
277: *(long *)(param_2 + 0x10) = lVar6;
278: return 1;
279: }
280: 
