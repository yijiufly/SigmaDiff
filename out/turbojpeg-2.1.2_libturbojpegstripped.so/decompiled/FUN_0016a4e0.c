1: 
2: void FUN_0016a4e0(code **param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: undefined4 uVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: bool bVar5;
10: bool bVar6;
11: bool bVar7;
12: bool bVar8;
13: int iVar9;
14: uint uVar10;
15: uint uVar11;
16: uint uVar12;
17: ulong uVar13;
18: long lVar14;
19: undefined8 uVar15;
20: void *__s;
21: 
22: iVar9 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
23: if (iVar9 != 0x50) {
24: ppcVar3 = (code **)*param_1;
25: *(undefined4 *)(ppcVar3 + 5) = 0x3f8;
26: (**ppcVar3)(param_1);
27: }
28: uVar10 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
29: if ((0x36 < uVar10) || ((0x6c000000000000U >> ((ulong)uVar10 & 0x3f) & 1) == 0)) {
30: ppcVar3 = (code **)*param_1;
31: *(undefined4 *)(ppcVar3 + 5) = 0x3f8;
32: (**ppcVar3)(param_1);
33: }
34: uVar11 = FUN_00169820(param_1,*(undefined8 *)(param_2 + 0x18),0xffff);
35: iVar9 = FUN_00169820(param_1,*(undefined8 *)(param_2 + 0x18),0xffff);
36: uVar12 = FUN_00169820(param_1,*(undefined8 *)(param_2 + 0x18),0xffff);
37: if ((uVar11 == 0 || iVar9 == 0) || (uVar12 == 0)) {
38: ppcVar3 = (code **)*param_1;
39: *(undefined4 *)(ppcVar3 + 5) = 0x3f8;
40: (**ppcVar3)(param_1);
41: }
42: *(undefined4 *)(param_1 + 9) = 8;
43: *(uint *)(param_1 + 6) = uVar11;
44: *(int *)((long)param_1 + 0x34) = iVar9;
45: uVar1 = *(uint *)((long)param_1 + 0x3c);
46: uVar13 = (ulong)uVar1;
47: *(uint *)(param_2 + 0x50) = uVar12;
48: if (uVar10 == 0x33) {
49: if (uVar1 == 0) {
50: *(undefined4 *)((long)param_1 + 0x3c) = 6;
51: }
52: pcVar4 = *param_1;
53: *(undefined4 *)(pcVar4 + 0x28) = 0x3fd;
54: *(uint *)(pcVar4 + 0x2c) = uVar11;
55: *(int *)(pcVar4 + 0x30) = iVar9;
56: (**(code **)(pcVar4 + 8))(param_1);
57: uVar1 = *(uint *)((long)param_1 + 0x3c);
58: if ((uVar1 - 6 < 10) || (uVar1 == 2)) {
59: uVar2 = *(undefined4 *)(&DAT_00190740 + (ulong)uVar1 * 4);
60: *(code **)(param_2 + 8) = FUN_00169d00;
61: *(undefined4 *)(param_1 + 7) = uVar2;
62: }
63: else {
64: if (uVar1 != 4) {
65: LAB_0016a8d9:
66: ppcVar3 = (code **)*param_1;
67: bVar6 = true;
68: *(undefined4 *)(ppcVar3 + 5) = 9;
69: (**ppcVar3)(param_1);
70: uVar13 = (ulong)*(uint *)((long)param_1 + 0x3c);
71: bVar7 = false;
72: bVar5 = false;
73: goto LAB_0016a77d;
74: }
75: *(code **)(param_2 + 8) = FUN_00169950;
76: *(undefined4 *)(param_1 + 7) = 4;
77: }
78: LAB_0016a9b3:
79: bVar6 = true;
80: }
81: else {
82: if ((int)uVar10 < 0x34) {
83: if (uVar10 == 0x32) {
84: if (uVar1 == 0) {
85: *(undefined4 *)((long)param_1 + 0x3c) = 1;
86: }
87: pcVar4 = *param_1;
88: *(undefined4 *)(pcVar4 + 0x28) = 0x3fb;
89: *(uint *)(pcVar4 + 0x2c) = uVar11;
90: *(int *)(pcVar4 + 0x30) = iVar9;
91: (**(code **)(pcVar4 + 8))(param_1);
92: uVar1 = *(uint *)((long)param_1 + 0x3c);
93: if (uVar1 == 1) {
94: *(code **)(param_2 + 8) = FUN_0016a470;
95: *(undefined4 *)(param_1 + 7) = 1;
96: }
97: else {
98: if ((uVar1 - 6 < 10) || (uVar1 == 2)) {
99: uVar2 = *(undefined4 *)(&DAT_00190740 + (ulong)uVar1 * 4);
100: *(code **)(param_2 + 8) = FUN_0016a230;
101: *(undefined4 *)(param_1 + 7) = uVar2;
102: }
103: else {
104: if (uVar1 != 4) goto LAB_0016a8d9;
105: *(code **)(param_2 + 8) = FUN_00169ff0;
106: *(undefined4 *)(param_1 + 7) = 4;
107: }
108: }
109: goto LAB_0016a9b3;
110: }
111: LAB_0016a770:
112: bVar6 = true;
113: bVar7 = false;
114: bVar5 = true;
115: LAB_0016a77d:
116: bVar8 = bVar5;
117: if ((int)uVar13 - 6U < 10) {
118: LAB_0016a6e8:
119: bVar5 = bVar8;
120: *(undefined4 *)(param_1 + 7) = *(undefined4 *)(&DAT_00190740 + uVar13 * 4);
121: }
122: else {
123: LAB_0016a789:
124: iVar9 = (int)uVar13;
125: bVar8 = bVar5;
126: if (iVar9 == 2) goto LAB_0016a6e8;
127: if (iVar9 == 1) {
128: *(undefined4 *)(param_1 + 7) = 1;
129: }
130: else {
131: if (iVar9 == 4) {
132: *(undefined4 *)(param_1 + 7) = 4;
133: }
134: }
135: }
136: if (bVar5) {
137: uVar13 = (ulong)uVar11;
138: if (uVar10 != 0x36) {
139: if (0xff < uVar12) goto LAB_0016a7bd;
140: goto LAB_0016a7c0;
141: }
142: lVar14 = (ulong)(0xff < uVar12) + 1;
143: goto LAB_0016aa17;
144: }
145: }
146: else {
147: if (uVar10 == 0x35) {
148: if (uVar1 == 0) {
149: *(undefined4 *)((long)param_1 + 0x3c) = 1;
150: }
151: pcVar4 = *param_1;
152: *(undefined4 *)(pcVar4 + 0x28) = 0x3fa;
153: *(uint *)(pcVar4 + 0x2c) = uVar11;
154: *(int *)(pcVar4 + 0x30) = iVar9;
155: (**(code **)(pcVar4 + 8))(param_1,1);
156: if (uVar12 < 0x100) {
157: uVar1 = *(uint *)((long)param_1 + 0x3c);
158: if (uVar12 == 0xff) {
159: if (uVar1 != 1) goto LAB_0016a912;
160: bVar7 = true;
161: bVar6 = false;
162: *(code **)(param_2 + 8) = FUN_00169540;
163: *(undefined4 *)(param_1 + 7) = 1;
164: }
165: else {
166: if (uVar1 == 1) {
167: bVar7 = false;
168: bVar6 = true;
169: *(code **)(param_2 + 8) = FUN_00168ac0;
170: *(undefined4 *)(param_1 + 7) = 1;
171: }
172: else {
173: LAB_0016a912:
174: if ((uVar1 - 6 < 10) || (uVar1 == 2)) {
175: bVar6 = true;
176: uVar2 = *(undefined4 *)(&DAT_00190740 + (ulong)uVar1 * 4);
177: *(code **)(param_2 + 8) = FUN_00168b50;
178: bVar7 = false;
179: *(undefined4 *)(param_1 + 7) = uVar2;
180: }
181: else {
182: if (uVar1 != 4) goto LAB_0016a6b6;
183: bVar7 = false;
184: bVar6 = true;
185: *(code **)(param_2 + 8) = FUN_00168d60;
186: *(undefined4 *)(param_1 + 7) = 4;
187: }
188: }
189: }
190: uVar13 = (ulong)uVar11;
191: }
192: else {
193: if (*(int *)((long)param_1 + 0x3c) != 1) goto LAB_0016a6b6;
194: bVar7 = false;
195: bVar6 = true;
196: *(code **)(param_2 + 8) = FUN_00169590;
197: *(undefined4 *)(param_1 + 7) = 1;
198: LAB_0016a7bd:
199: uVar13 = (ulong)uVar11 * 2;
200: }
201: LAB_0016a7c0:
202: *(ulong *)(param_2 + 0x40) = uVar13;
203: }
204: else {
205: if (uVar10 != 0x36) goto LAB_0016a770;
206: if (uVar1 == 0) {
207: *(undefined4 *)((long)param_1 + 0x3c) = 6;
208: }
209: pcVar4 = *param_1;
210: *(undefined4 *)(pcVar4 + 0x28) = 0x3fc;
211: *(uint *)(pcVar4 + 0x2c) = uVar11;
212: *(int *)(pcVar4 + 0x30) = iVar9;
213: (**(code **)(pcVar4 + 8))(param_1,1);
214: uVar1 = *(uint *)((long)param_1 + 0x3c);
215: uVar13 = (ulong)uVar1;
216: if (uVar12 < 0x100) {
217: if ((uVar12 == 0xff) && ((uVar1 & 0xfffffffb) == 2)) {
218: bVar6 = false;
219: bVar5 = true;
220: *(code **)(param_2 + 8) = FUN_00169540;
221: bVar7 = true;
222: goto LAB_0016a77d;
223: }
224: if ((uVar1 - 6 < 10) || (uVar1 == 2)) {
225: uVar2 = *(undefined4 *)(&DAT_00190740 + uVar13 * 4);
226: *(code **)(param_2 + 8) = FUN_00168fb0;
227: *(undefined4 *)(param_1 + 7) = uVar2;
228: }
229: else {
230: if (uVar1 != 4) goto LAB_0016a6b6;
231: *(code **)(param_2 + 8) = FUN_001691f0;
232: *(undefined4 *)(param_1 + 7) = 4;
233: }
234: bVar7 = false;
235: bVar6 = true;
236: lVar14 = 1;
237: }
238: else {
239: if ((9 < uVar1 - 6) && (uVar1 != 2)) {
240: LAB_0016a6b6:
241: ppcVar3 = (code **)*param_1;
242: bVar6 = true;
243: *(undefined4 *)(ppcVar3 + 5) = 9;
244: (**ppcVar3)(param_1);
245: uVar13 = (ulong)*(uint *)((long)param_1 + 0x3c);
246: bVar7 = false;
247: bVar5 = true;
248: bVar8 = true;
249: if (9 < *(uint *)((long)param_1 + 0x3c) - 6) goto LAB_0016a789;
250: goto LAB_0016a6e8;
251: }
252: bVar6 = true;
253: uVar2 = *(undefined4 *)(&DAT_00190740 + uVar13 * 4);
254: *(code **)(param_2 + 8) = FUN_00169650;
255: bVar7 = false;
256: *(undefined4 *)(param_1 + 7) = uVar2;
257: lVar14 = 2;
258: }
259: LAB_0016aa17:
260: *(ulong *)(param_2 + 0x40) = (ulong)uVar11 * 3 * lVar14;
261: }
262: uVar15 = (**(code **)param_1[1])(param_1,1);
263: *(undefined8 *)(param_2 + 0x30) = uVar15;
264: }
265: if (bVar7) {
266: *(undefined4 *)(param_2 + 0x28) = 1;
267: *(undefined8 *)(param_2 + 0x38) = *(undefined8 *)(param_2 + 0x30);
268: *(long *)(param_2 + 0x20) = param_2 + 0x38;
269: goto LAB_0016a811;
270: }
271: }
272: uVar15 = (**(code **)(param_1[1] + 0x10))(param_1,1,*(int *)(param_1 + 7) * uVar11,1);
273: *(undefined4 *)(param_2 + 0x28) = 1;
274: *(undefined8 *)(param_2 + 0x20) = uVar15;
275: LAB_0016a811:
276: if (bVar6) {
277: uVar13 = 0xff;
278: if (0xfe < uVar12) {
279: uVar13 = (ulong)uVar12;
280: }
281: __s = (void *)(**(code **)param_1[1])(param_1,1,uVar13 + 1);
282: *(void **)(param_2 + 0x48) = __s;
283: memset(__s,0,uVar13 + 1);
284: lVar14 = 0;
285: uVar13 = (ulong)(uVar12 >> 1);
286: do {
287: *(char *)(*(long *)(param_2 + 0x48) + lVar14) = (char)((long)uVar13 / (long)(ulong)uVar12);
288: lVar14 = lVar14 + 1;
289: uVar13 = uVar13 + 0xff;
290: } while (lVar14 != (ulong)uVar12 + 1);
291: }
292: return;
293: }
294: 
