1: 
2: /* WARNING: Type propagation algorithm not settling */
3: 
4: undefined8 FUN_001293b0(code **param_1,undefined4 param_2,undefined4 param_3)
5: 
6: {
7: byte bVar1;
8: byte bVar2;
9: undefined4 uVar3;
10: uint uVar4;
11: byte **ppbVar5;
12: code *pcVar6;
13: code **ppcVar7;
14: int iVar8;
15: byte *pbVar9;
16: uint *puVar10;
17: byte *pbVar11;
18: uint uVar12;
19: byte *pbVar13;
20: 
21: ppbVar5 = (byte **)param_1[5];
22: pbVar9 = ppbVar5[1];
23: pbVar11 = *ppbVar5;
24: *(undefined4 *)(param_1 + 0x27) = param_2;
25: *(undefined4 *)((long)param_1 + 0x13c) = param_3;
26: if (pbVar9 == (byte *)0x0) {
27: iVar8 = (*(code *)ppbVar5[3])();
28: if (iVar8 == 0) {
29: return 0;
30: }
31: pbVar11 = *ppbVar5;
32: pbVar9 = ppbVar5[1];
33: }
34: bVar1 = *pbVar11;
35: if (pbVar9 == (byte *)0x1) {
36: iVar8 = (*(code *)ppbVar5[3])(param_1);
37: if (iVar8 == 0) {
38: return 0;
39: }
40: pbVar11 = *ppbVar5;
41: pbVar9 = ppbVar5[1] + -1;
42: bVar2 = *pbVar11;
43: }
44: else {
45: pbVar11 = pbVar11 + 1;
46: pbVar9 = pbVar9 + -2;
47: bVar2 = *pbVar11;
48: }
49: if (pbVar9 == (byte *)0x0) {
50: iVar8 = (*(code *)ppbVar5[3])(param_1);
51: if (iVar8 == 0) {
52: return 0;
53: }
54: pbVar11 = *ppbVar5;
55: pbVar9 = ppbVar5[1];
56: }
57: else {
58: pbVar11 = pbVar11 + 1;
59: }
60: *(uint *)(param_1 + 0x25) = (uint)*pbVar11;
61: if (pbVar9 == (byte *)0x1) {
62: iVar8 = (*(code *)ppbVar5[3])(param_1);
63: if (iVar8 == 0) {
64: return 0;
65: }
66: pbVar11 = *ppbVar5;
67: iVar8 = (uint)*pbVar11 << 8;
68: pbVar9 = ppbVar5[1] + -1;
69: *(int *)((long)param_1 + 0x34) = iVar8;
70: }
71: else {
72: pbVar11 = pbVar11 + 1;
73: iVar8 = (uint)*pbVar11 << 8;
74: pbVar9 = pbVar9 + -2;
75: *(int *)((long)param_1 + 0x34) = iVar8;
76: }
77: if (pbVar9 == (byte *)0x0) {
78: iVar8 = (*(code *)ppbVar5[3])(param_1);
79: if (iVar8 == 0) {
80: return 0;
81: }
82: pbVar11 = *ppbVar5;
83: pbVar9 = ppbVar5[1];
84: *(uint *)((long)param_1 + 0x34) = *(int *)((long)param_1 + 0x34) + (uint)*pbVar11;
85: }
86: else {
87: pbVar11 = pbVar11 + 1;
88: *(uint *)((long)param_1 + 0x34) = iVar8 + (uint)*pbVar11;
89: }
90: pbVar9 = pbVar9 + -1;
91: if (pbVar9 == (byte *)0x0) {
92: iVar8 = (*(code *)ppbVar5[3])(param_1);
93: if (iVar8 == 0) {
94: return 0;
95: }
96: pbVar11 = *ppbVar5;
97: pbVar9 = ppbVar5[1];
98: }
99: else {
100: pbVar11 = pbVar11 + 1;
101: }
102: iVar8 = (uint)*pbVar11 << 8;
103: pbVar9 = pbVar9 + -1;
104: *(int *)(param_1 + 6) = iVar8;
105: if (pbVar9 == (byte *)0x0) {
106: iVar8 = (*(code *)ppbVar5[3])(param_1);
107: if (iVar8 == 0) {
108: return 0;
109: }
110: pbVar11 = *ppbVar5;
111: pbVar9 = ppbVar5[1];
112: iVar8 = *(int *)(param_1 + 6);
113: }
114: else {
115: pbVar11 = pbVar11 + 1;
116: }
117: pbVar9 = pbVar9 + -1;
118: *(uint *)(param_1 + 6) = iVar8 + (uint)*pbVar11;
119: if (pbVar9 == (byte *)0x0) {
120: iVar8 = (*(code *)ppbVar5[3])(param_1);
121: if (iVar8 == 0) {
122: return 0;
123: }
124: pbVar11 = *ppbVar5;
125: pbVar9 = ppbVar5[1];
126: }
127: else {
128: pbVar11 = pbVar11 + 1;
129: }
130: pbVar9 = pbVar9 + -1;
131: pbVar13 = pbVar11 + 1;
132: *(uint *)(param_1 + 7) = (uint)*pbVar11;
133: pcVar6 = *param_1;
134: *(undefined4 *)(pcVar6 + 0x2c) = *(undefined4 *)((long)param_1 + 0x21c);
135: *(undefined4 *)(pcVar6 + 0x30) = *(undefined4 *)(param_1 + 6);
136: *(undefined4 *)(pcVar6 + 0x34) = *(undefined4 *)((long)param_1 + 0x34);
137: uVar3 = *(undefined4 *)(param_1 + 7);
138: *(undefined4 *)(pcVar6 + 0x28) = 100;
139: *(undefined4 *)(pcVar6 + 0x38) = uVar3;
140: (**(code **)(pcVar6 + 8))(param_1,1);
141: if (*(int *)(param_1[0x49] + 0x1c) != 0) {
142: ppcVar7 = (code **)*param_1;
143: *(undefined4 *)(ppcVar7 + 5) = 0x3a;
144: (**ppcVar7)(param_1);
145: }
146: if (((*(int *)((long)param_1 + 0x34) == 0) || (*(int *)(param_1 + 6) == 0)) ||
147: (iVar8 = *(int *)(param_1 + 7), iVar8 < 1)) {
148: ppcVar7 = (code **)*param_1;
149: *(undefined4 *)(ppcVar7 + 5) = 0x20;
150: (**ppcVar7)(param_1);
151: iVar8 = *(int *)(param_1 + 7);
152: }
153: if ((long)(iVar8 * 3) != (ulong)bVar1 * 0x100 + -8 + (ulong)bVar2) {
154: ppcVar7 = (code **)*param_1;
155: *(undefined4 *)(ppcVar7 + 5) = 0xb;
156: (**ppcVar7)(param_1);
157: iVar8 = *(int *)(param_1 + 7);
158: }
159: puVar10 = (uint *)param_1[0x26];
160: if (puVar10 == (uint *)0x0) {
161: puVar10 = (uint *)(**(code **)param_1[1])(param_1,1,(long)iVar8 * 0x60);
162: iVar8 = *(int *)(param_1 + 7);
163: param_1[0x26] = (code *)puVar10;
164: }
165: if (0 < iVar8) {
166: uVar12 = 0;
167: do {
168: puVar10[1] = uVar12;
169: if (pbVar9 == (byte *)0x0) {
170: iVar8 = (*(code *)ppbVar5[3])(param_1);
171: if (iVar8 == 0) {
172: return 0;
173: }
174: pbVar13 = *ppbVar5;
175: pbVar9 = ppbVar5[1] + -1;
176: *puVar10 = (uint)*pbVar13;
177: if (pbVar9 != (byte *)0x0) goto LAB_001295ae;
178: LAB_001296ab:
179: iVar8 = (*(code *)ppbVar5[3])(param_1);
180: if (iVar8 == 0) {
181: return 0;
182: }
183: pbVar13 = *ppbVar5;
184: pbVar9 = ppbVar5[1];
185: }
186: else {
187: pbVar9 = pbVar9 + -1;
188: *puVar10 = (uint)*pbVar13;
189: if (pbVar9 == (byte *)0x0) goto LAB_001296ab;
190: LAB_001295ae:
191: pbVar13 = pbVar13 + 1;
192: }
193: bVar1 = *pbVar13;
194: pbVar9 = pbVar9 + -1;
195: puVar10[3] = bVar1 & 0xf;
196: puVar10[2] = (int)(uint)bVar1 >> 4;
197: if (pbVar9 == (byte *)0x0) {
198: iVar8 = (*(code *)ppbVar5[3])(param_1);
199: if (iVar8 == 0) {
200: return 0;
201: }
202: pbVar11 = *ppbVar5;
203: pbVar9 = ppbVar5[1];
204: }
205: else {
206: pbVar11 = pbVar13 + 1;
207: }
208: pbVar13 = pbVar11 + 1;
209: pbVar9 = pbVar9 + -1;
210: uVar12 = uVar12 + 1;
211: puVar10[4] = (uint)*pbVar11;
212: pcVar6 = *param_1;
213: *(uint *)(pcVar6 + 0x2c) = *puVar10;
214: *(uint *)(pcVar6 + 0x30) = puVar10[2];
215: *(uint *)(pcVar6 + 0x34) = puVar10[3];
216: uVar4 = puVar10[4];
217: *(undefined4 *)(pcVar6 + 0x28) = 0x65;
218: *(uint *)(pcVar6 + 0x38) = uVar4;
219: (**(code **)(pcVar6 + 8))(param_1,1);
220: puVar10 = puVar10 + 0x18;
221: } while (*(uint *)(param_1 + 7) != uVar12 && (int)uVar12 <= *(int *)(param_1 + 7));
222: }
223: *(undefined4 *)(param_1[0x49] + 0x1c) = 1;
224: *ppbVar5 = pbVar13;
225: ppbVar5[1] = pbVar9;
226: return 1;
227: }
228: 
