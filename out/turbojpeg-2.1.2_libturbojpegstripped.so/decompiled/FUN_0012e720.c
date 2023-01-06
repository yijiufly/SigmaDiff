1: 
2: void FUN_0012e720(code **param_1)
3: 
4: {
5: long *plVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: undefined4 uVar4;
9: uint uVar5;
10: int iVar6;
11: code **ppcVar7;
12: undefined4 *puVar8;
13: undefined8 *puVar9;
14: uint uVar10;
15: ulong uVar11;
16: long lVar12;
17: long lVar13;
18: ulong uVar14;
19: ulong uVar15;
20: ulong uVar16;
21: bool bVar17;
22: ulong uVar18;
23: 
24: ppcVar7 = (code **)(**(code **)param_1[1])(param_1,1,0x38);
25: param_1[0x4d] = (code *)ppcVar7;
26: *ppcVar7 = FUN_0012e6f0;
27: uVar5 = *(uint *)((long)param_1 + 0x3c);
28: switch(uVar5) {
29: default:
30: if (*(int *)(param_1 + 7) < 1) {
31: LAB_0012e77a:
32: ppcVar2 = (code **)*param_1;
33: *(undefined4 *)(ppcVar2 + 5) = 10;
34: (**ppcVar2)();
35: uVar5 = *(uint *)((long)param_1 + 0x3c);
36: }
37: break;
38: case 1:
39: if (*(int *)(param_1 + 7) != 1) goto LAB_0012e77a;
40: uVar11 = (ulong)*(uint *)(param_1 + 8);
41: switch(uVar11) {
42: case 1:
43: *(undefined4 *)(param_1 + 0x12) = 1;
44: goto code_r0x0012e8d8;
45: case 2:
46: case 6:
47: case 7:
48: case 8:
49: case 9:
50: case 10:
51: case 0xb:
52: case 0xc:
53: case 0xd:
54: case 0xe:
55: case 0xf:
56: iVar6 = *(int *)(&UNK_0018cf20 + uVar11 * 4);
57: *(int *)(param_1 + 0x12) = iVar6;
58: goto code_r0x0012e879;
59: case 4:
60: goto code_r0x0012e828;
61: case 0x10:
62: goto code_r0x0012e7e8;
63: }
64: goto LAB_0012e890;
65: case 2:
66: case 3:
67: if (*(int *)(param_1 + 7) != 3) goto LAB_0012e77a;
68: break;
69: case 4:
70: case 5:
71: if (*(int *)(param_1 + 7) != 4) goto LAB_0012e77a;
72: uVar10 = *(uint *)(param_1 + 8);
73: uVar11 = (ulong)uVar10;
74: switch(uVar11) {
75: case 1:
76: *(undefined4 *)(param_1 + 0x12) = 1;
77: goto LAB_0012e890;
78: case 2:
79: case 6:
80: case 7:
81: case 8:
82: case 9:
83: case 10:
84: case 0xb:
85: case 0xc:
86: case 0xd:
87: case 0xe:
88: case 0xf:
89: goto code_r0x0012e860;
90: case 4:
91: goto code_r0x0012e828;
92: case 0x10:
93: goto code_r0x0012e7e8;
94: }
95: goto LAB_0012e958;
96: }
97: uVar10 = *(uint *)(param_1 + 8);
98: uVar11 = (ulong)uVar10;
99: switch(uVar11) {
100: default:
101: LAB_0012e958:
102: if (uVar5 == uVar10) {
103: *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 7);
104: code_r0x0012e969:
105: ppcVar7[1] = FUN_0012a8e0;
106: goto LAB_0012e89f;
107: }
108: break;
109: case 1:
110: *(undefined4 *)(param_1 + 0x12) = 1;
111: if ((uVar5 & 0xfffffffd) == 1) {
112: code_r0x0012e8d8:
113: iVar6 = *(int *)(param_1 + 7);
114: ppcVar7[1] = FUN_0012e700;
115: if (1 < iVar6) {
116: pcVar3 = param_1[0x26];
117: puVar8 = (undefined4 *)(pcVar3 + 0x90);
118: do {
119: *puVar8 = 0;
120: puVar8 = puVar8 + 0x18;
121: } while (puVar8 != (undefined4 *)(pcVar3 + (ulong)(iVar6 - 2) * 0x60 + 0xf0));
122: }
123: goto LAB_0012e89f;
124: }
125: if (uVar5 == 2) {
126: ppcVar7[1] = FUN_0012a840;
127: pcVar3 = param_1[0x4d];
128: puVar9 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x1800);
129: *(undefined8 **)(pcVar3 + 0x30) = puVar9;
130: uVar11 = (ulong)((uint)((ulong)puVar9 >> 3) & 1);
131: bVar17 = ((ulong)puVar9 >> 3 & 1) != 0;
132: if (bVar17) {
133: *puVar9 = 0;
134: puVar9[0x100] = 0;
135: puVar9[0x200] = 0x8000;
136: }
137: uVar14 = (ulong)bVar17;
138: uVar16 = 0x100 - uVar11;
139: lVar12 = uVar11 * 8;
140: lVar13 = 0;
141: uVar15 = 0;
142: uVar11 = uVar14;
143: uVar18 = uVar14 + 1;
144: do {
145: uVar15 = uVar15 + 1;
146: plVar1 = (long *)((long)puVar9 + lVar13 + lVar12);
147: *plVar1 = ((uVar11 >> 0x20) * 0x4c8b << 0x20) + (uVar11 & 0xffffffff) * 0x4c8b;
148: plVar1[1] = ((uVar18 >> 0x20) * 0x4c8b << 0x20) + (uVar18 & 0xffffffff) * 0x4c8b;
149: plVar1 = (long *)((long)puVar9 + lVar13 + lVar12 + 0x800);
150: *plVar1 = ((uVar11 >> 0x20) * 0x9646 << 0x20) + (uVar11 & 0xffffffff) * 0x9646;
151: plVar1[1] = ((uVar18 >> 0x20) * 0x9646 << 0x20) + (uVar18 & 0xffffffff) * 0x9646;
152: plVar1 = (long *)((long)puVar9 + lVar13 + lVar12 + 0x1000);
153: *plVar1 = uVar11 * 0x1d2f + 0x8000;
154: plVar1[1] = uVar18 * 0x1d2f + 0x8000;
155: lVar13 = lVar13 + 0x10;
156: uVar11 = uVar11 + 2;
157: uVar18 = uVar18 + 2;
158: } while (uVar15 < uVar16 >> 1);
159: lVar12 = uVar14 + (uVar16 & 0xfffffffffffffffe);
160: if (uVar16 != (uVar16 & 0xfffffffffffffffe)) {
161: puVar9[lVar12] = lVar12 * 0x4c8b;
162: puVar9[lVar12 + 0x100] = lVar12 * 0x9646;
163: puVar9[lVar12 + 0x200] = lVar12 * 0x1d2f + 0x8000;
164: }
165: goto LAB_0012e89f;
166: }
167: break;
168: case 2:
169: case 6:
170: case 7:
171: case 8:
172: case 9:
173: case 10:
174: case 0xb:
175: case 0xc:
176: case 0xd:
177: case 0xe:
178: case 0xf:
179: code_r0x0012e860:
180: iVar6 = *(int *)(&UNK_0018cf20 + uVar11 * 4);
181: *(int *)(param_1 + 0x12) = iVar6;
182: if (uVar5 == 3) {
183: iVar6 = FUN_0016bed0();
184: if (iVar6 == 0) {
185: ppcVar7[1] = FUN_0012a210;
186: FUN_0012a110(param_1);
187: }
188: else {
189: ppcVar7[1] = FUN_0016bf20;
190: }
191: goto LAB_0012e89f;
192: }
193: code_r0x0012e879:
194: if (uVar5 == 1) {
195: ppcVar7[1] = FUN_0012aea0;
196: goto LAB_0012e89f;
197: }
198: if (uVar5 == 2) {
199: if ((((*(int *)(&UNK_0018d040 + uVar11 * 4) != 0) ||
200: (*(int *)(&UNK_0018cfe0 + uVar11 * 4) != 1)) ||
201: (*(int *)(&UNK_0018cf80 + uVar11 * 4) != 2)) || (iVar6 != 3)) {
202: ppcVar7[1] = FUN_0012bd50;
203: goto LAB_0012e89f;
204: }
205: goto code_r0x0012e969;
206: }
207: break;
208: case 4:
209: code_r0x0012e828:
210: *(undefined4 *)(param_1 + 0x12) = 4;
211: if (uVar5 == 5) {
212: ppcVar7[1] = FUN_0012d060;
213: FUN_0012a110(param_1);
214: goto LAB_0012e89f;
215: }
216: if (uVar5 == 4) goto code_r0x0012e969;
217: break;
218: case 0x10:
219: code_r0x0012e7e8:
220: *(undefined4 *)(param_1 + 0x12) = 3;
221: if (*(int *)(param_1 + 0xe) == 0) {
222: if (uVar5 == 3) {
223: iVar6 = FUN_0016bee0();
224: if (iVar6 == 0) {
225: ppcVar7[1] = FUN_0012d1c0;
226: FUN_0012a110(param_1);
227: }
228: else {
229: ppcVar7[1] = FUN_0016bf30;
230: }
231: goto LAB_0012e89f;
232: }
233: if (uVar5 == 1) {
234: ppcVar7[1] = FUN_0012e0b0;
235: goto LAB_0012e89f;
236: }
237: if (uVar5 == 2) {
238: ppcVar7[1] = FUN_0012d860;
239: goto LAB_0012e89f;
240: }
241: }
242: else {
243: if (uVar5 == 3) {
244: ppcVar7[1] = FUN_0012d4c0;
245: FUN_0012a110(param_1);
246: goto LAB_0012e89f;
247: }
248: if (uVar5 == 1) {
249: ppcVar7[1] = FUN_0012e530;
250: goto LAB_0012e89f;
251: }
252: if (uVar5 == 2) {
253: ppcVar7[1] = FUN_0012de60;
254: goto LAB_0012e89f;
255: }
256: }
257: }
258: LAB_0012e890:
259: ppcVar7 = (code **)*param_1;
260: *(undefined4 *)(ppcVar7 + 5) = 0x1b;
261: (**ppcVar7)(param_1);
262: LAB_0012e89f:
263: uVar4 = 1;
264: if (*(int *)((long)param_1 + 0x6c) == 0) {
265: uVar4 = *(undefined4 *)(param_1 + 0x12);
266: }
267: *(undefined4 *)((long)param_1 + 0x94) = uVar4;
268: return;
269: }
270: 
