1: 
2: void FUN_00152b10(code **param_1,long param_2)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: bool bVar3;
8: bool bVar4;
9: bool bVar5;
10: bool bVar6;
11: bool bVar7;
12: bool bVar8;
13: int iVar9;
14: uint uVar10;
15: int iVar11;
16: uint uVar12;
17: uint uVar13;
18: ulong uVar14;
19: undefined8 uVar15;
20: long lVar16;
21: long lVar17;
22: ulong uVar18;
23: 
24: iVar9 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
25: if (iVar9 != 0x50) {
26: ppcVar1 = (code **)*param_1;
27: *(undefined4 *)(ppcVar1 + 5) = 0x3f8;
28: (**ppcVar1)(param_1);
29: }
30: iVar9 = _IO_getc(*(_IO_FILE **)(param_2 + 0x18));
31: if ((4 < iVar9 - 0x32U) || ((1 << ((byte)(iVar9 - 0x32U) & 0x3f) & 0x1bU) == 0)) {
32: ppcVar1 = (code **)*param_1;
33: *(undefined4 *)(ppcVar1 + 5) = 0x3f8;
34: (**ppcVar1)(param_1);
35: }
36: uVar10 = FUN_00152a10(param_1,*(undefined8 *)(param_2 + 0x18),0xffff);
37: iVar11 = FUN_00152a10(param_1,*(undefined8 *)(param_2 + 0x18),0xffff);
38: uVar12 = FUN_00152a10(param_1,*(undefined8 *)(param_2 + 0x18),0xffff);
39: if (((uVar10 == 0) || (iVar11 == 0)) || (uVar12 == 0)) {
40: ppcVar1 = (code **)*param_1;
41: *(undefined4 *)(ppcVar1 + 5) = 0x3f8;
42: (**ppcVar1)(param_1);
43: }
44: *(undefined4 *)(param_1 + 9) = 8;
45: *(uint *)(param_1 + 6) = uVar10;
46: *(int *)((long)param_1 + 0x34) = iVar11;
47: *(uint *)(param_2 + 0x50) = uVar12;
48: if (iVar9 == 0x33) {
49: if (*(int *)((long)param_1 + 0x3c) == 0) {
50: *(undefined4 *)((long)param_1 + 0x3c) = 6;
51: }
52: pcVar2 = *param_1;
53: *(uint *)(pcVar2 + 0x2c) = uVar10;
54: *(undefined4 *)(pcVar2 + 0x28) = 0x3fd;
55: *(int *)(*param_1 + 0x30) = iVar11;
56: (**(code **)(*param_1 + 8))(param_1);
57: uVar13 = *(uint *)((long)param_1 + 0x3c);
58: uVar14 = (ulong)uVar13;
59: if ((uVar13 - 6 < 10) || (uVar13 == 2)) {
60: bVar7 = false;
61: *(code **)(param_2 + 8) = FUN_001534d0;
62: LAB_00152e32:
63: bVar6 = false;
64: bVar8 = true;
65: }
66: else {
67: if (uVar13 == 4) {
68: bVar4 = false;
69: *(code **)(param_2 + 8) = FUN_001530f0;
70: LAB_0015300e:
71: bVar5 = true;
72: bVar6 = false;
73: goto LAB_00153016;
74: }
75: LAB_00152f15:
76: ppcVar1 = (code **)*param_1;
77: *(undefined4 *)(ppcVar1 + 5) = 9;
78: (**ppcVar1)(param_1);
79: uVar13 = *(uint *)((long)param_1 + 0x3c);
80: bVar4 = false;
81: bVar3 = uVar13 - 6 < 10 || uVar13 == 2;
82: LAB_00152d39:
83: uVar14 = (ulong)uVar13;
84: bVar6 = false;
85: bVar5 = true;
86: bVar7 = bVar4;
87: bVar8 = bVar5;
88: if (!bVar3) {
89: if (uVar13 == 1) goto LAB_00152fa5;
90: goto LAB_00152d52;
91: }
92: }
93: LAB_00152e3a:
94: bVar5 = bVar8;
95: bVar4 = bVar7;
96: *(undefined4 *)(param_1 + 7) = *(undefined4 *)(&DAT_0018c380 + uVar14 * 4);
97: }
98: else {
99: if (iVar9 < 0x34) {
100: if (iVar9 == 0x32) {
101: if (*(int *)((long)param_1 + 0x3c) == 0) {
102: *(undefined4 *)((long)param_1 + 0x3c) = 1;
103: }
104: pcVar2 = *param_1;
105: *(uint *)(pcVar2 + 0x2c) = uVar10;
106: *(undefined4 *)(pcVar2 + 0x28) = 0x3fb;
107: *(int *)(*param_1 + 0x30) = iVar11;
108: (**(code **)(*param_1 + 8))(param_1);
109: uVar13 = *(uint *)((long)param_1 + 0x3c);
110: uVar14 = (ulong)uVar13;
111: if (uVar13 == 1) {
112: bVar5 = true;
113: bVar6 = false;
114: bVar4 = false;
115: *(code **)(param_2 + 8) = FUN_00153c40;
116: goto LAB_00152fa5;
117: }
118: if ((9 < uVar13 - 6) && (uVar13 != 2)) {
119: if (uVar13 != 4) goto LAB_00152f15;
120: bVar4 = false;
121: *(code **)(param_2 + 8) = FUN_001537e0;
122: goto LAB_0015300e;
123: }
124: bVar7 = false;
125: *(code **)(param_2 + 8) = FUN_00153a00;
126: goto LAB_00152e32;
127: }
128: goto LAB_00152d20;
129: }
130: if (iVar9 == 0x35) {
131: if (*(int *)((long)param_1 + 0x3c) == 0) {
132: *(undefined4 *)((long)param_1 + 0x3c) = 1;
133: }
134: pcVar2 = *param_1;
135: *(uint *)(pcVar2 + 0x2c) = uVar10;
136: *(undefined4 *)(pcVar2 + 0x28) = 0x3fa;
137: *(int *)(*param_1 + 0x30) = iVar11;
138: (**(code **)(*param_1 + 8))(param_1,1);
139: if (0xff < uVar12) {
140: *(code **)(param_2 + 8) = FUN_001528f0;
141: goto LAB_00152d20;
142: }
143: uVar13 = *(uint *)((long)param_1 + 0x3c);
144: uVar14 = (ulong)uVar13;
145: if (uVar12 == 0xff) {
146: if (uVar13 != 1) goto LAB_00152ce8;
147: bVar5 = false;
148: bVar6 = true;
149: bVar4 = true;
150: *(code **)(param_2 + 8) = FUN_001529c0;
151: }
152: else {
153: if (uVar13 != 1) {
154: LAB_00152ce8:
155: if ((uVar13 - 6 < 10) || (uVar13 == 2)) {
156: bVar7 = true;
157: *(code **)(param_2 + 8) = FUN_00152650;
158: goto LAB_00152e32;
159: }
160: if (uVar13 == 4) {
161: bVar4 = true;
162: *(code **)(param_2 + 8) = FUN_00152460;
163: goto LAB_0015300e;
164: }
165: goto LAB_00152d0e;
166: }
167: bVar5 = true;
168: bVar6 = false;
169: bVar4 = true;
170: *(code **)(param_2 + 8) = FUN_00152860;
171: }
172: LAB_00152fa5:
173: *(undefined4 *)(param_1 + 7) = 1;
174: goto LAB_00152d5b;
175: }
176: if (iVar9 != 0x36) {
177: LAB_00152d20:
178: uVar13 = *(uint *)((long)param_1 + 0x3c);
179: bVar4 = true;
180: bVar3 = uVar13 - 6 < 10 || uVar13 == 2;
181: goto LAB_00152d39;
182: }
183: if (*(int *)((long)param_1 + 0x3c) == 0) {
184: *(undefined4 *)((long)param_1 + 0x3c) = 6;
185: }
186: pcVar2 = *param_1;
187: *(uint *)(pcVar2 + 0x2c) = uVar10;
188: *(undefined4 *)(pcVar2 + 0x28) = 0x3fc;
189: *(int *)(*param_1 + 0x30) = iVar11;
190: (**(code **)(*param_1 + 8))(param_1,1);
191: if (0xff < uVar12) {
192: *(code **)(param_2 + 8) = FUN_00152320;
193: goto LAB_00152d20;
194: }
195: uVar13 = *(uint *)((long)param_1 + 0x3c);
196: uVar14 = (ulong)uVar13;
197: if ((uVar12 != 0xff) || ((uVar13 & 0xfffffffb) != 2)) {
198: if ((uVar13 - 6 < 10) || (uVar13 == 2)) {
199: bVar7 = true;
200: *(code **)(param_2 + 8) = FUN_001520e0;
201: goto LAB_00152e32;
202: }
203: if (uVar13 == 4) {
204: bVar4 = true;
205: *(code **)(param_2 + 8) = FUN_00151d80;
206: goto LAB_0015300e;
207: }
208: LAB_00152d0e:
209: ppcVar1 = (code **)*param_1;
210: *(undefined4 *)(ppcVar1 + 5) = 9;
211: (**ppcVar1)(param_1);
212: goto LAB_00152d20;
213: }
214: bVar5 = false;
215: bVar6 = true;
216: bVar4 = true;
217: *(code **)(param_2 + 8) = FUN_001529c0;
218: bVar7 = true;
219: bVar8 = false;
220: if ((uVar13 - 6 < 10) || (bVar8 = bVar5, uVar13 == 2)) goto LAB_00152e3a;
221: LAB_00152d52:
222: if (uVar13 != 4) goto LAB_00152d5b;
223: LAB_00153016:
224: *(undefined4 *)(param_1 + 7) = 4;
225: }
226: LAB_00152d5b:
227: if (bVar4) {
228: if (iVar9 == 0x36) {
229: *(ulong *)(param_2 + 0x40) = (ulong)uVar10 * 3 * (2 - (ulong)(uVar12 < 0x100));
230: }
231: else {
232: *(ulong *)(param_2 + 0x40) = (2 - (ulong)(uVar12 < 0x100)) * (ulong)uVar10;
233: }
234: uVar15 = (**(code **)param_1[1])(param_1,1);
235: *(undefined8 *)(param_2 + 0x30) = uVar15;
236: }
237: if (bVar6) {
238: *(undefined4 *)(param_2 + 0x28) = 1;
239: *(undefined8 *)(param_2 + 0x38) = *(undefined8 *)(param_2 + 0x30);
240: *(long *)(param_2 + 0x20) = param_2 + 0x38;
241: }
242: else {
243: uVar15 = (**(code **)(param_1[1] + 0x10))(param_1,1,*(int *)(param_1 + 7) * uVar10);
244: *(undefined4 *)(param_2 + 0x28) = 1;
245: *(undefined8 *)(param_2 + 0x20) = uVar15;
246: }
247: if (bVar5) {
248: uVar18 = (ulong)uVar12;
249: lVar16 = (**(code **)param_1[1])(param_1,1,uVar18 + 1);
250: *(long *)(param_2 + 0x48) = lVar16;
251: lVar17 = 0;
252: uVar14 = (ulong)(uVar12 >> 1);
253: while( true ) {
254: *(char *)(lVar16 + lVar17) = (char)((long)uVar14 / (long)uVar18);
255: lVar17 = lVar17 + 1;
256: if ((long)uVar18 < lVar17) break;
257: lVar16 = *(long *)(param_2 + 0x48);
258: uVar14 = uVar14 + 0xff;
259: }
260: return;
261: }
262: return;
263: }
264: 
