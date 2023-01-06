1: 
2: void FUN_0012c110(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: undefined4 uVar2;
7: int iVar3;
8: code *pcVar4;
9: uint uVar5;
10: code *pcVar6;
11: uint uVar7;
12: int iVar8;
13: code *pcVar9;
14: code *pcVar10;
15: 
16: if (*(int *)((long)param_1 + 0x24) != 0xca) {
17: pcVar6 = *param_1;
18: *(int *)(pcVar6 + 0x2c) = *(int *)((long)param_1 + 0x24);
19: ppcVar1 = (code **)*param_1;
20: *(undefined4 *)(pcVar6 + 0x28) = 0x14;
21: (**ppcVar1)();
22: }
23: uVar7 = *(int *)((long)param_1 + 0x44) * 8;
24: uVar5 = *(uint *)(param_1 + 9);
25: if (uVar5 < uVar7) {
26: if (uVar5 * 2 < uVar7) {
27: if (uVar7 < uVar5 * 3 || uVar7 + uVar5 * -3 == 0) {
28: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 3,8);
29: *(undefined4 *)(param_1 + 0x11) = uVar2;
30: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 3);
31: *(undefined4 *)(param_1 + 0x34) = 3;
32: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
33: uVar7 = 3;
34: }
35: else {
36: if (uVar5 * 4 < uVar7) {
37: if (uVar7 < uVar5 * 5 || uVar7 + uVar5 * -5 == 0) {
38: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 5,8);
39: *(undefined4 *)(param_1 + 0x11) = uVar2;
40: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 5);
41: *(undefined4 *)(param_1 + 0x34) = 5;
42: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
43: uVar7 = 5;
44: }
45: else {
46: if (uVar7 < uVar5 * 6 || uVar7 + uVar5 * -6 == 0) {
47: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 6,8);
48: *(undefined4 *)(param_1 + 0x11) = uVar2;
49: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 6);
50: *(undefined4 *)(param_1 + 0x34) = 6;
51: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
52: uVar7 = 6;
53: }
54: else {
55: if (uVar7 < uVar5 * 7 || uVar7 + uVar5 * -7 == 0) {
56: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 7,8);
57: *(undefined4 *)(param_1 + 0x11) = uVar2;
58: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 7);
59: *(undefined4 *)(param_1 + 0x34) = 7;
60: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
61: uVar7 = 7;
62: }
63: else {
64: if (uVar5 * 8 < uVar7) {
65: if (uVar7 < uVar5 * 9 || uVar7 + uVar5 * -9 == 0) {
66: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 9,8);
67: *(undefined4 *)(param_1 + 0x11) = uVar2;
68: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 9);
69: *(undefined4 *)(param_1 + 0x34) = 9;
70: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
71: uVar7 = 9;
72: }
73: else {
74: if (uVar7 < uVar5 * 10 || uVar7 + uVar5 * -10 == 0) {
75: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 10,8);
76: *(undefined4 *)(param_1 + 0x11) = uVar2;
77: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 10);
78: *(undefined4 *)(param_1 + 0x34) = 10;
79: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
80: uVar7 = 10;
81: }
82: else {
83: if (uVar7 < uVar5 * 0xb || uVar7 + uVar5 * -0xb == 0) {
84: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 0xb,8,
85: (ulong)*(uint *)(param_1 + 6) * 5);
86: *(undefined4 *)(param_1 + 0x11) = uVar2;
87: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 0xb,8,
88: (ulong)*(uint *)((long)param_1 + 0x34) * 5);
89: *(undefined4 *)(param_1 + 0x34) = 0xb;
90: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
91: uVar7 = 0xb;
92: }
93: else {
94: if (uVar7 < uVar5 * 0xc || uVar7 + uVar5 * -0xc == 0) {
95: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 0xc,8);
96: *(undefined4 *)(param_1 + 0x11) = uVar2;
97: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 0xc);
98: *(undefined4 *)(param_1 + 0x34) = 0xc;
99: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
100: uVar7 = 0xc;
101: }
102: else {
103: if (uVar7 < uVar5 * 0xd || uVar7 + uVar5 * -0xd == 0) {
104: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 0xd,8,
105: (ulong)*(uint *)(param_1 + 6) * 3);
106: *(undefined4 *)(param_1 + 0x11) = uVar2;
107: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 0xd,8,
108: (ulong)*(uint *)((long)param_1 + 0x34) * 3);
109: *(undefined4 *)(param_1 + 0x34) = 0xd;
110: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
111: uVar7 = 0xd;
112: }
113: else {
114: if (uVar7 < uVar5 * 0xe || uVar7 + uVar5 * -0xe == 0) {
115: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 0xe,8);
116: *(undefined4 *)(param_1 + 0x11) = uVar2;
117: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 0xe);
118: *(undefined4 *)(param_1 + 0x34) = 0xe;
119: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
120: uVar7 = 0xe;
121: }
122: else {
123: if (uVar7 < uVar5 * 0xf || uVar7 + uVar5 * -0xf == 0) {
124: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 0xf,8);
125: *(undefined4 *)(param_1 + 0x11) = uVar2;
126: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 0xf);
127: *(undefined4 *)(param_1 + 0x34) = 0xf;
128: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
129: uVar7 = 0xf;
130: }
131: else {
132: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) << 4,8);
133: *(undefined4 *)(param_1 + 0x11) = uVar2;
134: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) << 4);
135: *(undefined4 *)(param_1 + 0x34) = 0x10;
136: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
137: uVar7 = 0x10;
138: }
139: }
140: }
141: }
142: }
143: }
144: }
145: }
146: else {
147: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) << 3,8);
148: *(undefined4 *)(param_1 + 0x11) = uVar2;
149: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) << 3);
150: *(undefined4 *)(param_1 + 0x34) = 8;
151: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
152: uVar7 = 8;
153: }
154: }
155: }
156: }
157: }
158: else {
159: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) << 2,8);
160: *(undefined4 *)(param_1 + 0x11) = uVar2;
161: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) << 2);
162: *(undefined4 *)(param_1 + 0x34) = 4;
163: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
164: uVar7 = 4;
165: }
166: }
167: }
168: else {
169: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) * 2,8);
170: *(undefined4 *)(param_1 + 0x11) = uVar2;
171: uVar2 = FUN_0013be20((ulong)*(uint *)((long)param_1 + 0x34) * 2);
172: *(undefined4 *)(param_1 + 0x34) = 2;
173: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
174: uVar7 = 2;
175: }
176: }
177: else {
178: uVar2 = FUN_0013be20(*(undefined4 *)(param_1 + 6),8);
179: *(undefined4 *)(param_1 + 0x11) = uVar2;
180: uVar2 = FUN_0013be20(*(undefined4 *)((long)param_1 + 0x34));
181: *(undefined4 *)(param_1 + 0x34) = 1;
182: *(undefined4 *)((long)param_1 + 0x8c) = uVar2;
183: uVar7 = 1;
184: }
185: iVar3 = *(int *)(param_1 + 7);
186: pcVar6 = param_1[0x26];
187: if (0 < iVar3) {
188: pcVar10 = pcVar6 + ((ulong)(iVar3 - 1) * 3 + 3) * 0x20;
189: pcVar4 = pcVar6;
190: do {
191: *(uint *)(pcVar4 + 0x24) = uVar7;
192: pcVar4 = pcVar4 + 0x60;
193: pcVar9 = pcVar6;
194: } while (pcVar4 != pcVar10);
195: do {
196: while (7 < uVar7) {
197: LAB_0012c462:
198: pcVar4 = pcVar9 + 0x60;
199: *(uint *)(pcVar9 + 0x24) = uVar7;
200: pcVar9 = pcVar4;
201: if (pcVar4 == pcVar10) goto LAB_0012c355;
202: }
203: if ((int)(*(int *)(param_1 + 0x33) * uVar7) % (int)(*(int *)(pcVar9 + 8) * uVar7 * 2) != 0)
204: goto LAB_0012c462;
205: uVar5 = uVar7;
206: do {
207: if (((int)(*(int *)((long)param_1 + 0x19c) * uVar7) %
208: (int)(*(int *)(pcVar9 + 0xc) * uVar5 * 2) != 0) || (uVar5 = uVar5 * 2, 7 < (int)uVar5))
209: break;
210: } while ((int)(*(int *)(param_1 + 0x33) * uVar7) % (int)(uVar5 * *(int *)(pcVar9 + 8) * 2) ==
211: 0);
212: *(uint *)(pcVar9 + 0x24) = uVar5;
213: pcVar9 = pcVar9 + 0x60;
214: } while (pcVar9 != pcVar10);
215: LAB_0012c355:
216: iVar8 = 0;
217: do {
218: iVar8 = iVar8 + 1;
219: uVar2 = FUN_0013be20((ulong)*(uint *)(param_1 + 6) *
220: (long)(*(int *)(pcVar6 + 8) * *(int *)(pcVar6 + 0x24)),
221: (long)(*(int *)(param_1 + 0x33) * 8));
222: *(undefined4 *)(pcVar6 + 0x28) = uVar2;
223: uVar2 = FUN_0013be20();
224: *(undefined4 *)(pcVar6 + 0x2c) = uVar2;
225: iVar3 = *(int *)(param_1 + 7);
226: pcVar6 = pcVar6 + 0x60;
227: } while (iVar8 < iVar3);
228: }
229: switch((ulong)*(uint *)(param_1 + 8)) {
230: default:
231: *(int *)(param_1 + 0x12) = iVar3;
232: break;
233: case 1:
234: *(undefined4 *)(param_1 + 0x12) = 1;
235: iVar3 = 1;
236: break;
237: case 2:
238: case 6:
239: case 7:
240: case 8:
241: case 9:
242: case 10:
243: case 0xb:
244: case 0xc:
245: case 0xd:
246: case 0xe:
247: case 0xf:
248: iVar3 = *(int *)(&DAT_00189c00 + (ulong)*(uint *)(param_1 + 8) * 4);
249: *(int *)(param_1 + 0x12) = iVar3;
250: break;
251: case 3:
252: case 0x10:
253: *(undefined4 *)(param_1 + 0x12) = 3;
254: iVar3 = 3;
255: break;
256: case 4:
257: case 5:
258: *(undefined4 *)(param_1 + 0x12) = 4;
259: iVar3 = 4;
260: }
261: iVar8 = 1;
262: if (*(int *)((long)param_1 + 0x6c) == 0) {
263: iVar8 = iVar3;
264: }
265: *(int *)((long)param_1 + 0x94) = iVar8;
266: iVar3 = FUN_0012bfe0(param_1);
267: uVar2 = 1;
268: if (iVar3 != 0) {
269: uVar2 = *(undefined4 *)((long)param_1 + 0x19c);
270: }
271: *(undefined4 *)(param_1 + 0x13) = uVar2;
272: return;
273: }
274: 
