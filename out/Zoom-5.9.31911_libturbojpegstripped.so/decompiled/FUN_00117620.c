1: 
2: void FUN_00117620(code **param_1)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: int iVar5;
10: int *piVar6;
11: int *piVar7;
12: int iVar8;
13: 
14: iVar2 = *(int *)((long)param_1 + 0x4c);
15: if (*(int *)((long)param_1 + 0x24) != 100) {
16: pcVar3 = *param_1;
17: *(int *)(pcVar3 + 0x2c) = *(int *)((long)param_1 + 0x24);
18: ppcVar4 = (code **)*param_1;
19: *(undefined4 *)(pcVar3 + 0x28) = 0x14;
20: (**ppcVar4)();
21: }
22: if (iVar2 == 3) {
23: iVar8 = 10;
24: if (*(int *)(param_1 + 10) != 3) goto LAB_00117858;
25: }
26: else {
27: if (iVar2 < 5) {
28: LAB_00117858:
29: iVar8 = iVar2 * 4 + 2;
30: }
31: else {
32: iVar8 = iVar2 * 6;
33: }
34: }
35: piVar6 = (int *)param_1[0x3f];
36: if ((piVar6 == (int *)0x0) || (*(int *)(param_1 + 0x40) < iVar8)) {
37: iVar5 = 10;
38: if (9 < iVar8) {
39: iVar5 = iVar8;
40: }
41: *(int *)(param_1 + 0x40) = iVar5;
42: piVar6 = (int *)(**(code **)param_1[1])(param_1,0,(long)iVar5 * 0x24);
43: param_1[0x3f] = (code *)piVar6;
44: }
45: param_1[0x1f] = (code *)piVar6;
46: *(int *)(param_1 + 0x1e) = iVar8;
47: if (iVar2 == 3) {
48: iVar8 = *(int *)(param_1 + 10);
49: *piVar6 = 3;
50: piVar6[1] = 0;
51: piVar6[2] = 1;
52: if (iVar8 == 3) {
53: piVar6[3] = 2;
54: piVar6[6] = 0;
55: piVar6[5] = 0;
56: piVar6[7] = 0;
57: piVar6[8] = 1;
58: piVar6[9] = 1;
59: piVar6[10] = 0;
60: piVar6[0xe] = 1;
61: piVar6[0xf] = 5;
62: piVar6[0x10] = 0;
63: piVar6[0x11] = 2;
64: piVar6[0x12] = 1;
65: piVar6[0x13] = 2;
66: piVar6[0x17] = 1;
67: piVar6[0x18] = 0x3f;
68: piVar6[0x19] = 0;
69: piVar6[0x1a] = 1;
70: piVar6[0x1b] = 1;
71: piVar6[0x1c] = 1;
72: piVar6[0x20] = 1;
73: piVar6[0x21] = 0x3f;
74: piVar6[0x22] = 0;
75: piVar6[0x23] = 1;
76: piVar6[0x24] = 1;
77: piVar6[0x25] = 0;
78: piVar6[0x29] = 6;
79: piVar6[0x2a] = 0x3f;
80: piVar6[0x2b] = 0;
81: piVar6[0x2c] = 2;
82: piVar6[0x2d] = 1;
83: piVar6[0x2e] = 0;
84: piVar6[0x32] = 1;
85: piVar6[0x33] = 0x3f;
86: piVar6[0x34] = 2;
87: piVar6[0x35] = 1;
88: piVar6[0x36] = 3;
89: piVar6[0x37] = 0;
90: piVar6[0x38] = 1;
91: piVar6[0x39] = 2;
92: piVar6[0x3c] = 0;
93: piVar6[0x3b] = 0;
94: piVar6[0x3d] = 1;
95: piVar6[0x3e] = 0;
96: piVar6[0x3f] = 1;
97: piVar6[0x40] = 2;
98: piVar6[0x44] = 1;
99: piVar6[0x45] = 0x3f;
100: piVar6[0x46] = 1;
101: piVar6[0x47] = 0;
102: piVar6[0x48] = 1;
103: piVar6[0x49] = 1;
104: piVar6[0x4d] = 1;
105: piVar6[0x4e] = 0x3f;
106: piVar6[0x4f] = 1;
107: piVar6[0x50] = 0;
108: piVar6[0x51] = 1;
109: piVar6[0x52] = 0;
110: piVar6[0x56] = 1;
111: piVar6[0x57] = 0x3f;
112: piVar6[0x58] = 1;
113: piVar6[0x59] = 0;
114: return;
115: }
116: LAB_001176d6:
117: piVar6[3] = 2;
118: if (3 < iVar2) {
119: piVar6[4] = 3;
120: }
121: LAB_001176e9:
122: piVar7 = piVar6 + 9;
123: piVar6[5] = 0;
124: piVar6[6] = 0;
125: piVar6[7] = 0;
126: piVar6[8] = 1;
127: }
128: else {
129: iVar8 = 0;
130: piVar7 = piVar6;
131: if (iVar2 < 5) {
132: *piVar6 = iVar2;
133: if (((0 < iVar2) && (piVar6[1] = 0, 1 < iVar2)) && (piVar6[2] = 1, 2 < iVar2))
134: goto LAB_001176d6;
135: goto LAB_001176e9;
136: }
137: do {
138: piVar7[1] = iVar8;
139: iVar8 = iVar8 + 1;
140: *piVar7 = 1;
141: piVar7[5] = 0;
142: piVar7[6] = 0;
143: piVar7[7] = 0;
144: piVar7[8] = 1;
145: piVar7 = piVar7 + 9;
146: } while (iVar8 != iVar2);
147: piVar7 = piVar6 + (ulong)(iVar2 - 1) * 9 + 9;
148: }
149: if (iVar2 < 1) {
150: *piVar7 = iVar2;
151: }
152: else {
153: iVar8 = 0;
154: piVar6 = piVar7;
155: do {
156: piVar6[1] = iVar8;
157: iVar8 = iVar8 + 1;
158: *piVar6 = 1;
159: piVar6[5] = 1;
160: piVar6[6] = 5;
161: piVar6[7] = 0;
162: piVar6[8] = 2;
163: piVar6 = piVar6 + 9;
164: } while (iVar8 != iVar2);
165: iVar8 = 0;
166: lVar1 = (ulong)(iVar2 - 1) * 9 + 9;
167: piVar7 = piVar7 + lVar1;
168: piVar6 = piVar7;
169: do {
170: piVar6[1] = iVar8;
171: iVar8 = iVar8 + 1;
172: *piVar6 = 1;
173: piVar6[5] = 6;
174: piVar6[6] = 0x3f;
175: piVar6[7] = 0;
176: piVar6[8] = 2;
177: piVar6 = piVar6 + 9;
178: } while (iVar8 != iVar2);
179: iVar8 = 0;
180: piVar6 = piVar7 + lVar1;
181: do {
182: piVar6[1] = iVar8;
183: iVar8 = iVar8 + 1;
184: *piVar6 = 1;
185: piVar6[5] = 1;
186: piVar6[6] = 0x3f;
187: piVar6[7] = 2;
188: piVar6[8] = 1;
189: piVar6 = piVar6 + 9;
190: } while (iVar8 != iVar2);
191: piVar7 = piVar7 + lVar1 + lVar1;
192: iVar8 = 0;
193: piVar6 = piVar7;
194: if (4 < iVar2) {
195: do {
196: piVar6[1] = iVar8;
197: iVar8 = iVar8 + 1;
198: *piVar6 = 1;
199: piVar6[5] = 0;
200: piVar6[6] = 0;
201: piVar6[7] = 1;
202: piVar6[8] = 0;
203: piVar6 = piVar6 + 9;
204: } while (iVar8 != iVar2);
205: piVar6 = piVar7 + lVar1;
206: goto LAB_0011780b;
207: }
208: *piVar7 = iVar2;
209: piVar7[1] = 0;
210: if (((1 < iVar2) && (piVar7[2] = 1, 2 < iVar2)) && (piVar7[3] = 2, 3 < iVar2)) {
211: piVar7[4] = 3;
212: }
213: }
214: piVar6 = piVar7 + 9;
215: piVar7[5] = 0;
216: piVar7[6] = 0;
217: piVar7[7] = 1;
218: piVar7[8] = 0;
219: if (iVar2 < 1) {
220: return;
221: }
222: LAB_0011780b:
223: iVar8 = 0;
224: do {
225: piVar6[1] = iVar8;
226: iVar8 = iVar8 + 1;
227: *piVar6 = 1;
228: piVar6[5] = 1;
229: piVar6[6] = 0x3f;
230: piVar6[7] = 1;
231: piVar6[8] = 0;
232: piVar6 = piVar6 + 9;
233: } while (iVar8 != iVar2);
234: return;
235: }
236: 
