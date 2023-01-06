1: 
2: void FUN_00136eb0(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: uint uVar2;
7: undefined4 uVar3;
8: int iVar4;
9: code *pcVar5;
10: ulong uVar6;
11: uint uVar7;
12: int iVar8;
13: code *pcVar9;
14: code *pcVar10;
15: code *pcVar11;
16: 
17: iVar4 = *(int *)((long)param_1 + 0x24);
18: if (iVar4 != 0xca) {
19: ppcVar1 = (code **)*param_1;
20: *(undefined4 *)(ppcVar1 + 5) = 0x14;
21: *(int *)((long)ppcVar1 + 0x2c) = iVar4;
22: (**ppcVar1)();
23: }
24: uVar7 = *(uint *)(param_1 + 9);
25: uVar6 = (ulong)*(uint *)(param_1 + 6);
26: uVar2 = *(int *)((long)param_1 + 0x44) << 3;
27: if (uVar7 < uVar2) {
28: if (uVar7 * 2 < uVar2) {
29: if (uVar7 * 3 < uVar2) {
30: if (uVar7 * 4 < uVar2) {
31: if (uVar7 * 5 < uVar2) {
32: if (uVar7 * 6 < uVar2) {
33: if (uVar7 * 7 < uVar2) {
34: if (uVar7 * 8 < uVar2) {
35: if (uVar7 * 9 < uVar2) {
36: if (uVar7 * 10 < uVar2) {
37: if (uVar7 * 0xb < uVar2) {
38: if (uVar7 * 0xc < uVar2) {
39: if (uVar7 * 0xd < uVar2) {
40: if (uVar7 * 0xe < uVar2) {
41: if (uVar7 * 0xf < uVar2) {
42: uVar7 = 0x10;
43: uVar3 = FUN_001489d0(uVar6 << 4,8);
44: *(undefined4 *)(param_1 + 0x11) = uVar3;
45: uVar3 = FUN_001489d0();
46: *(undefined4 *)(param_1 + 0x34) = 0x10;
47: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
48: }
49: else {
50: uVar7 = 0xf;
51: uVar3 = FUN_001489d0(uVar6 * 0xf,8);
52: *(undefined4 *)(param_1 + 0x11) = uVar3;
53: uVar3 = FUN_001489d0();
54: *(undefined4 *)(param_1 + 0x34) = 0xf;
55: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
56: }
57: }
58: else {
59: uVar7 = 0xe;
60: uVar3 = FUN_001489d0(uVar6 * 0xe,8);
61: *(undefined4 *)(param_1 + 0x11) = uVar3;
62: uVar3 = FUN_001489d0();
63: *(undefined4 *)(param_1 + 0x34) = 0xe;
64: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
65: }
66: }
67: else {
68: uVar7 = 0xd;
69: uVar3 = FUN_001489d0(uVar6 * 0xd,8);
70: *(undefined4 *)(param_1 + 0x11) = uVar3;
71: uVar3 = FUN_001489d0();
72: *(undefined4 *)(param_1 + 0x34) = 0xd;
73: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
74: }
75: }
76: else {
77: uVar7 = 0xc;
78: uVar3 = FUN_001489d0(uVar6 * 0xc,8);
79: *(undefined4 *)(param_1 + 0x11) = uVar3;
80: uVar3 = FUN_001489d0();
81: *(undefined4 *)(param_1 + 0x34) = 0xc;
82: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
83: }
84: }
85: else {
86: uVar7 = 0xb;
87: uVar3 = FUN_001489d0(uVar6 * 0xb,8);
88: *(undefined4 *)(param_1 + 0x11) = uVar3;
89: uVar3 = FUN_001489d0();
90: *(undefined4 *)(param_1 + 0x34) = 0xb;
91: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
92: }
93: }
94: else {
95: uVar7 = 10;
96: uVar3 = FUN_001489d0(uVar6 * 10,8);
97: *(undefined4 *)(param_1 + 0x11) = uVar3;
98: uVar3 = FUN_001489d0();
99: *(undefined4 *)(param_1 + 0x34) = 10;
100: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
101: }
102: }
103: else {
104: uVar7 = 9;
105: uVar3 = FUN_001489d0(uVar6 * 9,8);
106: *(undefined4 *)(param_1 + 0x11) = uVar3;
107: uVar3 = FUN_001489d0();
108: *(undefined4 *)(param_1 + 0x34) = 9;
109: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
110: }
111: }
112: else {
113: uVar7 = 8;
114: uVar3 = FUN_001489d0(uVar6 << 3,8);
115: *(undefined4 *)(param_1 + 0x11) = uVar3;
116: uVar3 = FUN_001489d0();
117: *(undefined4 *)(param_1 + 0x34) = 8;
118: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
119: }
120: }
121: else {
122: uVar7 = 7;
123: uVar3 = FUN_001489d0(uVar6 * 7,8);
124: *(undefined4 *)(param_1 + 0x11) = uVar3;
125: uVar3 = FUN_001489d0();
126: *(undefined4 *)(param_1 + 0x34) = 7;
127: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
128: }
129: }
130: else {
131: uVar7 = 6;
132: uVar3 = FUN_001489d0(uVar6 * 6,8);
133: *(undefined4 *)(param_1 + 0x11) = uVar3;
134: uVar3 = FUN_001489d0();
135: *(undefined4 *)(param_1 + 0x34) = 6;
136: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
137: }
138: }
139: else {
140: uVar7 = 5;
141: uVar3 = FUN_001489d0(uVar6 * 5,8);
142: *(undefined4 *)(param_1 + 0x11) = uVar3;
143: uVar3 = FUN_001489d0();
144: *(undefined4 *)(param_1 + 0x34) = 5;
145: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
146: }
147: }
148: else {
149: uVar7 = 4;
150: uVar3 = FUN_001489d0(uVar6 << 2,8);
151: *(undefined4 *)(param_1 + 0x11) = uVar3;
152: uVar3 = FUN_001489d0();
153: *(undefined4 *)(param_1 + 0x34) = 4;
154: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
155: }
156: }
157: else {
158: uVar7 = 3;
159: uVar3 = FUN_001489d0(uVar6 * 3,8);
160: *(undefined4 *)(param_1 + 0x11) = uVar3;
161: uVar3 = FUN_001489d0();
162: *(undefined4 *)(param_1 + 0x34) = 3;
163: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
164: }
165: }
166: else {
167: uVar7 = 2;
168: uVar3 = FUN_001489d0(uVar6 * 2,8);
169: *(undefined4 *)(param_1 + 0x11) = uVar3;
170: uVar3 = FUN_001489d0();
171: *(undefined4 *)(param_1 + 0x34) = 2;
172: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
173: }
174: }
175: else {
176: uVar7 = 1;
177: uVar3 = FUN_001489d0(uVar6,8);
178: *(undefined4 *)(param_1 + 0x11) = uVar3;
179: uVar3 = FUN_001489d0();
180: *(undefined4 *)(param_1 + 0x34) = 1;
181: *(undefined4 *)((long)param_1 + 0x8c) = uVar3;
182: }
183: iVar4 = *(int *)(param_1 + 7);
184: pcVar5 = param_1[0x26];
185: if (0 < iVar4) {
186: pcVar11 = pcVar5;
187: do {
188: *(uint *)(pcVar11 + 0x24) = uVar7;
189: pcVar11 = pcVar11 + 0x60;
190: } while (pcVar11 != pcVar5 + ((ulong)(iVar4 - 1) * 3 + 3) * 0x20);
191: iVar4 = *(int *)(param_1 + 0x33);
192: pcVar9 = pcVar5;
193: do {
194: while ((7 < uVar7 || ((int)(iVar4 * uVar7) % (int)(uVar7 * *(int *)(pcVar9 + 8) * 2) != 0))) {
195: pcVar10 = pcVar9 + 0x60;
196: *(uint *)(pcVar9 + 0x24) = uVar7;
197: pcVar9 = pcVar10;
198: if (pcVar10 == pcVar11) goto LAB_001370db;
199: }
200: uVar2 = uVar7;
201: do {
202: if (((int)(*(int *)((long)param_1 + 0x19c) * uVar7) %
203: (int)(uVar2 * *(int *)(pcVar9 + 0xc) * 2) != 0) || (uVar2 = uVar2 * 2, 7 < (int)uVar2))
204: break;
205: } while ((int)(iVar4 * uVar7) % (int)(uVar2 * *(int *)(pcVar9 + 8) * 2) == 0);
206: *(uint *)(pcVar9 + 0x24) = uVar2;
207: pcVar9 = pcVar9 + 0x60;
208: } while (pcVar9 != pcVar11);
209: LAB_001370db:
210: iVar8 = 0;
211: while( true ) {
212: iVar8 = iVar8 + 1;
213: uVar3 = FUN_001489d0((long)(*(int *)(pcVar5 + 8) * *(int *)(pcVar5 + 0x24)) *
214: (ulong)*(uint *)(param_1 + 6),(long)(iVar4 * 8));
215: *(undefined4 *)(pcVar5 + 0x28) = uVar3;
216: uVar3 = FUN_001489d0();
217: *(undefined4 *)(pcVar5 + 0x2c) = uVar3;
218: iVar4 = *(int *)(param_1 + 7);
219: if (iVar4 <= iVar8) break;
220: iVar4 = *(int *)(param_1 + 0x33);
221: pcVar5 = pcVar5 + 0x60;
222: }
223: }
224: switch((ulong)*(uint *)(param_1 + 8)) {
225: default:
226: *(int *)(param_1 + 0x12) = iVar4;
227: break;
228: case 1:
229: *(undefined4 *)(param_1 + 0x12) = 1;
230: iVar4 = 1;
231: break;
232: case 2:
233: case 6:
234: case 7:
235: case 8:
236: case 9:
237: case 10:
238: case 0xb:
239: case 0xc:
240: case 0xd:
241: case 0xe:
242: case 0xf:
243: iVar4 = *(int *)(&DAT_0018d460 + (ulong)*(uint *)(param_1 + 8) * 4);
244: *(int *)(param_1 + 0x12) = iVar4;
245: break;
246: case 3:
247: case 0x10:
248: *(undefined4 *)(param_1 + 0x12) = 3;
249: iVar4 = 3;
250: break;
251: case 4:
252: case 5:
253: *(undefined4 *)(param_1 + 0x12) = 4;
254: iVar4 = 4;
255: }
256: uVar3 = 1;
257: if (*(int *)((long)param_1 + 0x6c) != 0) {
258: iVar4 = 1;
259: }
260: *(int *)((long)param_1 + 0x94) = iVar4;
261: if ((((*(int *)((long)param_1 + 100) == 0) && (*(int *)(param_1 + 0x31) == 0)) &&
262: (param_1[7] == (code *)0x300000003)) && (iVar4 = FUN_00136e10(param_1), iVar4 != 0)) {
263: *(undefined4 *)(param_1 + 0x13) = *(undefined4 *)((long)param_1 + 0x19c);
264: return;
265: }
266: *(undefined4 *)(param_1 + 0x13) = uVar3;
267: return;
268: }
269: 
