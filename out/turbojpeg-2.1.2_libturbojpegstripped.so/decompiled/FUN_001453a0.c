1: 
2: void FUN_001453a0(code **param_1)
3: 
4: {
5: code *pcVar1;
6: long lVar2;
7: int iVar3;
8: code *pcVar4;
9: int *piVar5;
10: undefined8 uVar6;
11: long lVar7;
12: byte *pbVar8;
13: int *piVar9;
14: int iVar10;
15: long lVar11;
16: long lVar12;
17: 
18: pcVar1 = param_1[0x4e];
19: param_1[0x14] = *(code **)(pcVar1 + 0x20);
20: *(undefined4 *)((long)param_1 + 0x9c) = *(undefined4 *)(pcVar1 + 0x28);
21: iVar3 = *(int *)(param_1 + 0xe);
22: if (iVar3 == 1) {
23: iVar3 = *(int *)(param_1 + 0x12);
24: pcVar4 = FUN_00145bf0;
25: *(undefined4 *)(pcVar1 + 0x4c) = 0;
26: if (iVar3 == 3) {
27: pcVar4 = FUN_00145240;
28: }
29: *(code **)(pcVar1 + 8) = pcVar4;
30: if (*(int *)(pcVar1 + 0x38) == 0) {
31: FUN_00144f70();
32: }
33: if ((*(long *)(pcVar1 + 0x50) == 0) && (0 < *(int *)(param_1 + 0x12))) {
34: pcVar1 = param_1[0x4e];
35: lVar12 = 0;
36: do {
37: iVar10 = (int)lVar12;
38: iVar3 = *(int *)(pcVar1 + lVar12 * 4 + 0x3c);
39: if (iVar10 == 0) {
40: LAB_00145539:
41: piVar5 = (int *)(**(code **)param_1[1])(param_1,1,0x400);
42: pbVar8 = &DAT_0018ed80;
43: lVar11 = (long)(iVar3 + -1) << 9;
44: piVar9 = piVar5;
45: do {
46: while( true ) {
47: lVar7 = (long)(int)((uint)*pbVar8 * -2 + 0xff);
48: lVar2 = lVar7 * 0xff;
49: if (lVar2 < 0) {
50: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
51: }
52: else {
53: iVar3 = (int)(lVar2 / lVar11);
54: }
55: *piVar9 = iVar3;
56: lVar7 = (long)(int)((uint)pbVar8[1] * -2 + 0xff);
57: lVar2 = lVar7 * 0xff;
58: if (lVar2 < 0) {
59: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
60: }
61: else {
62: iVar3 = (int)(lVar2 / lVar11);
63: }
64: piVar9[1] = iVar3;
65: lVar7 = (long)(int)((uint)pbVar8[2] * -2 + 0xff);
66: lVar2 = lVar7 * 0xff;
67: if (lVar2 < 0) {
68: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
69: }
70: else {
71: iVar3 = (int)(lVar2 / lVar11);
72: }
73: piVar9[2] = iVar3;
74: lVar7 = (long)(int)((uint)pbVar8[3] * -2 + 0xff);
75: lVar2 = lVar7 * 0xff;
76: if (lVar2 < 0) {
77: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
78: }
79: else {
80: iVar3 = (int)(lVar2 / lVar11);
81: }
82: piVar9[3] = iVar3;
83: lVar7 = (long)(int)((uint)pbVar8[4] * -2 + 0xff);
84: lVar2 = lVar7 * 0xff;
85: if (lVar2 < 0) {
86: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
87: }
88: else {
89: iVar3 = (int)(lVar2 / lVar11);
90: }
91: piVar9[4] = iVar3;
92: lVar7 = (long)(int)((uint)pbVar8[5] * -2 + 0xff);
93: lVar2 = lVar7 * 0xff;
94: if (lVar2 < 0) {
95: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
96: }
97: else {
98: iVar3 = (int)(lVar2 / lVar11);
99: }
100: piVar9[5] = iVar3;
101: lVar7 = (long)(int)((uint)pbVar8[6] * -2 + 0xff);
102: lVar2 = lVar7 * 0xff;
103: if (lVar2 < 0) {
104: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
105: }
106: else {
107: iVar3 = (int)(lVar2 / lVar11);
108: }
109: piVar9[6] = iVar3;
110: lVar7 = (long)(int)((uint)pbVar8[7] * -2 + 0xff);
111: lVar2 = lVar7 * 0xff;
112: if (lVar2 < 0) {
113: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
114: }
115: else {
116: iVar3 = (int)(lVar2 / lVar11);
117: }
118: piVar9[7] = iVar3;
119: lVar7 = (long)(int)((uint)pbVar8[8] * -2 + 0xff);
120: lVar2 = lVar7 * 0xff;
121: if (lVar2 < 0) {
122: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
123: }
124: else {
125: iVar3 = (int)(lVar2 / lVar11);
126: }
127: piVar9[8] = iVar3;
128: lVar7 = (long)(int)((uint)pbVar8[9] * -2 + 0xff);
129: lVar2 = lVar7 * 0xff;
130: if (lVar2 < 0) {
131: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
132: }
133: else {
134: iVar3 = (int)(lVar2 / lVar11);
135: }
136: piVar9[9] = iVar3;
137: lVar7 = (long)(int)((uint)pbVar8[10] * -2 + 0xff);
138: lVar2 = lVar7 * 0xff;
139: if (lVar2 < 0) {
140: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
141: }
142: else {
143: iVar3 = (int)(lVar2 / lVar11);
144: }
145: piVar9[10] = iVar3;
146: lVar7 = (long)(int)((uint)pbVar8[0xb] * -2 + 0xff);
147: lVar2 = lVar7 * 0xff;
148: if (lVar2 < 0) {
149: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
150: }
151: else {
152: iVar3 = (int)(lVar2 / lVar11);
153: }
154: piVar9[0xb] = iVar3;
155: lVar7 = (long)(int)((uint)pbVar8[0xc] * -2 + 0xff);
156: lVar2 = lVar7 * 0xff;
157: if (lVar2 < 0) {
158: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
159: }
160: else {
161: iVar3 = (int)(lVar2 / lVar11);
162: }
163: piVar9[0xc] = iVar3;
164: lVar7 = (long)(int)((uint)pbVar8[0xd] * -2 + 0xff);
165: lVar2 = lVar7 * 0xff;
166: if (lVar2 < 0) {
167: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
168: }
169: else {
170: iVar3 = (int)(lVar2 / lVar11);
171: }
172: piVar9[0xd] = iVar3;
173: lVar7 = (long)(int)((uint)pbVar8[0xe] * -2 + 0xff);
174: lVar2 = lVar7 * 0xff;
175: if (lVar2 < 0) {
176: iVar3 = -(int)((lVar7 * -0xff) / lVar11);
177: }
178: else {
179: iVar3 = (int)(lVar2 / lVar11);
180: }
181: piVar9[0xe] = iVar3;
182: lVar7 = (long)(int)((uint)pbVar8[0xf] * -2 + 0xff);
183: lVar2 = lVar7 * 0xff;
184: if (lVar2 < 0) break;
185: pbVar8 = pbVar8 + 0x10;
186: piVar9[0xf] = (int)(lVar2 / lVar11);
187: piVar9 = piVar9 + 0x10;
188: if (pbVar8 == &DAT_0018ee80) goto LAB_001457d0;
189: }
190: pbVar8 = pbVar8 + 0x10;
191: piVar9[0xf] = -(int)((lVar7 * -0xff) / lVar11);
192: piVar9 = piVar9 + 0x10;
193: } while (pbVar8 != &DAT_0018ee80);
194: }
195: else {
196: if (iVar3 == *(int *)(pcVar1 + 0x3c)) {
197: lVar11 = 0;
198: }
199: else {
200: if (iVar10 == 1) goto LAB_00145539;
201: if (iVar3 == *(int *)(pcVar1 + 0x40)) {
202: lVar11 = 1;
203: }
204: else {
205: if ((iVar10 == 2) || (lVar11 = 2, iVar3 != *(int *)(pcVar1 + 0x44)))
206: goto LAB_00145539;
207: }
208: }
209: piVar5 = *(int **)(pcVar1 + lVar11 * 8 + 0x50);
210: if (piVar5 == (int *)0x0) goto LAB_00145539;
211: }
212: LAB_001457d0:
213: *(int **)(pcVar1 + lVar12 * 8 + 0x50) = piVar5;
214: lVar12 = lVar12 + 1;
215: } while (*(int *)(param_1 + 0x12) != iVar10 + 1 && iVar10 + 1 <= *(int *)(param_1 + 0x12));
216: }
217: }
218: else {
219: if (iVar3 == 0) {
220: if (*(int *)(param_1 + 0x12) != 3) {
221: *(code **)(pcVar1 + 8) = FUN_00145100;
222: return;
223: }
224: *(code **)(pcVar1 + 8) = FUN_001451b0;
225: }
226: else {
227: if (iVar3 != 2) {
228: param_1 = (code **)*param_1;
229: *(undefined4 *)(param_1 + 5) = 0x30;
230: /* WARNING: Could not recover jumptable at 0x0014546b. Too many branches */
231: /* WARNING: Treating indirect jump as call */
232: (**param_1)();
233: return;
234: }
235: *(undefined4 *)(pcVar1 + 0x90) = 0;
236: *(code **)(pcVar1 + 8) = FUN_001459b0;
237: iVar3 = *(int *)(param_1 + 0x12);
238: lVar12 = (ulong)(*(int *)(param_1 + 0x11) + 2) * 2;
239: if (*(long *)(pcVar1 + 0x70) == 0) {
240: if (iVar3 < 1) {
241: return;
242: }
243: lVar11 = 1;
244: do {
245: uVar6 = (**(code **)(param_1[1] + 8))(param_1,1,lVar12);
246: *(undefined8 *)(pcVar1 + lVar11 * 8 + 0x68) = uVar6;
247: iVar3 = *(int *)(param_1 + 0x12);
248: iVar10 = (int)lVar11;
249: lVar11 = lVar11 + 1;
250: } while (iVar10 < iVar3);
251: lVar12 = (ulong)(*(int *)(param_1 + 0x11) + 2) * 2;
252: }
253: if (0 < iVar3) {
254: lVar11 = 1;
255: do {
256: FUN_00148a80(*(undefined8 *)(pcVar1 + lVar11 * 8 + 0x68),lVar12);
257: iVar3 = (int)lVar11;
258: lVar11 = lVar11 + 1;
259: } while (*(int *)(param_1 + 0x12) != iVar3 && iVar3 <= *(int *)(param_1 + 0x12));
260: }
261: }
262: }
263: return;
264: }
265: 
