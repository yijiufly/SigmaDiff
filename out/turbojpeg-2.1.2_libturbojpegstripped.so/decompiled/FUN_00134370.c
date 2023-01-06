1: 
2: undefined8 FUN_00134370(code **param_1,undefined4 param_2,undefined4 param_3)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: undefined4 uVar3;
8: uint uVar4;
9: byte **ppbVar5;
10: code *pcVar6;
11: code **ppcVar7;
12: int iVar8;
13: byte *pbVar9;
14: uint *puVar10;
15: byte *pbVar11;
16: undefined8 uVar12;
17: byte *pbVar13;
18: uint uVar14;
19: 
20: ppbVar5 = (byte **)param_1[5];
21: pbVar9 = ppbVar5[1];
22: pbVar13 = *ppbVar5;
23: *(undefined4 *)(param_1 + 0x27) = param_2;
24: *(undefined4 *)((long)param_1 + 0x13c) = param_3;
25: if (pbVar9 == (byte *)0x0) {
26: iVar8 = (*(code *)ppbVar5[3])();
27: if (iVar8 != 0) {
28: pbVar13 = *ppbVar5;
29: pbVar9 = ppbVar5[1];
30: goto LAB_001343b2;
31: }
32: LAB_00134688:
33: uVar12 = 0;
34: }
35: else {
36: LAB_001343b2:
37: pbVar9 = pbVar9 + -1;
38: bVar1 = *pbVar13;
39: if (pbVar9 == (byte *)0x0) {
40: iVar8 = (*(code *)ppbVar5[3])(param_1);
41: if (iVar8 == 0) goto LAB_00134688;
42: pbVar13 = *ppbVar5;
43: pbVar9 = ppbVar5[1];
44: }
45: else {
46: pbVar13 = pbVar13 + 1;
47: }
48: pbVar9 = pbVar9 + -1;
49: bVar2 = *pbVar13;
50: if (pbVar9 == (byte *)0x0) {
51: iVar8 = (*(code *)ppbVar5[3])(param_1);
52: if (iVar8 == 0) goto LAB_00134688;
53: pbVar13 = *ppbVar5;
54: pbVar9 = ppbVar5[1];
55: }
56: else {
57: pbVar13 = pbVar13 + 1;
58: }
59: pbVar9 = pbVar9 + -1;
60: *(uint *)(param_1 + 0x25) = (uint)*pbVar13;
61: if (pbVar9 == (byte *)0x0) {
62: iVar8 = (*(code *)ppbVar5[3])(param_1);
63: if (iVar8 == 0) goto LAB_00134688;
64: pbVar13 = *ppbVar5;
65: pbVar9 = ppbVar5[1];
66: }
67: else {
68: pbVar13 = pbVar13 + 1;
69: }
70: iVar8 = (uint)*pbVar13 << 8;
71: pbVar9 = pbVar9 + -1;
72: *(int *)((long)param_1 + 0x34) = iVar8;
73: if (pbVar9 == (byte *)0x0) {
74: iVar8 = (*(code *)ppbVar5[3])(param_1);
75: if (iVar8 == 0) goto LAB_00134688;
76: pbVar13 = *ppbVar5;
77: pbVar9 = ppbVar5[1];
78: iVar8 = *(int *)((long)param_1 + 0x34);
79: }
80: else {
81: pbVar13 = pbVar13 + 1;
82: }
83: pbVar9 = pbVar9 + -1;
84: *(uint *)((long)param_1 + 0x34) = iVar8 + (uint)*pbVar13;
85: if (pbVar9 == (byte *)0x0) {
86: iVar8 = (*(code *)ppbVar5[3])(param_1);
87: if (iVar8 == 0) goto LAB_00134688;
88: pbVar13 = *ppbVar5;
89: pbVar9 = ppbVar5[1];
90: }
91: else {
92: pbVar13 = pbVar13 + 1;
93: }
94: iVar8 = (uint)*pbVar13 << 8;
95: pbVar9 = pbVar9 + -1;
96: *(int *)(param_1 + 6) = iVar8;
97: if (pbVar9 == (byte *)0x0) {
98: iVar8 = (*(code *)ppbVar5[3])(param_1);
99: if (iVar8 == 0) goto LAB_00134688;
100: pbVar13 = *ppbVar5;
101: pbVar9 = ppbVar5[1];
102: iVar8 = *(int *)(param_1 + 6);
103: }
104: else {
105: pbVar13 = pbVar13 + 1;
106: }
107: pbVar9 = pbVar9 + -1;
108: *(uint *)(param_1 + 6) = iVar8 + (uint)*pbVar13;
109: if (pbVar9 == (byte *)0x0) {
110: iVar8 = (*(code *)ppbVar5[3])(param_1);
111: if (iVar8 == 0) goto LAB_00134688;
112: pbVar13 = *ppbVar5;
113: pbVar9 = ppbVar5[1];
114: }
115: else {
116: pbVar13 = pbVar13 + 1;
117: }
118: pbVar9 = pbVar9 + -1;
119: pbVar11 = pbVar13 + 1;
120: *(uint *)(param_1 + 7) = (uint)*pbVar13;
121: pcVar6 = *param_1;
122: *(undefined4 *)(pcVar6 + 0x2c) = *(undefined4 *)((long)param_1 + 0x21c);
123: *(undefined4 *)(pcVar6 + 0x30) = *(undefined4 *)(param_1 + 6);
124: *(undefined4 *)(pcVar6 + 0x34) = *(undefined4 *)((long)param_1 + 0x34);
125: uVar3 = *(undefined4 *)(param_1 + 7);
126: *(undefined4 *)(pcVar6 + 0x28) = 100;
127: *(undefined4 *)(pcVar6 + 0x38) = uVar3;
128: (**(code **)(pcVar6 + 8))(param_1,1);
129: if (*(int *)(param_1[0x49] + 0x1c) != 0) {
130: ppcVar7 = (code **)*param_1;
131: *(undefined4 *)(ppcVar7 + 5) = 0x3a;
132: (**ppcVar7)(param_1);
133: }
134: if (((*(int *)((long)param_1 + 0x34) == 0) || (*(int *)(param_1 + 6) == 0)) ||
135: (iVar8 = *(int *)(param_1 + 7), iVar8 < 1)) {
136: ppcVar7 = (code **)*param_1;
137: *(undefined4 *)(ppcVar7 + 5) = 0x20;
138: (**ppcVar7)(param_1);
139: iVar8 = *(int *)(param_1 + 7);
140: }
141: if ((long)(iVar8 * 3) != (ulong)bVar1 * 0x100 + -8 + (ulong)bVar2) {
142: ppcVar7 = (code **)*param_1;
143: *(undefined4 *)(ppcVar7 + 5) = 0xb;
144: (**ppcVar7)(param_1);
145: iVar8 = *(int *)(param_1 + 7);
146: }
147: puVar10 = (uint *)param_1[0x26];
148: if (puVar10 == (uint *)0x0) {
149: puVar10 = (uint *)(**(code **)param_1[1])(param_1,1,(long)iVar8 * 0x60);
150: param_1[0x26] = (code *)puVar10;
151: iVar8 = *(int *)(param_1 + 7);
152: }
153: if (0 < iVar8) {
154: uVar14 = 0;
155: do {
156: puVar10[1] = uVar14;
157: if (pbVar9 == (byte *)0x0) {
158: iVar8 = (*(code *)ppbVar5[3])(param_1);
159: if (iVar8 == 0) goto LAB_00134688;
160: pbVar11 = *ppbVar5;
161: pbVar9 = ppbVar5[1];
162: }
163: pbVar9 = pbVar9 + -1;
164: *puVar10 = (uint)*pbVar11;
165: pbVar11 = pbVar11 + 1;
166: if (pbVar9 == (byte *)0x0) {
167: iVar8 = (*(code *)ppbVar5[3])(param_1);
168: if (iVar8 == 0) goto LAB_00134688;
169: pbVar11 = *ppbVar5;
170: pbVar9 = ppbVar5[1];
171: }
172: bVar1 = *pbVar11;
173: pbVar9 = pbVar9 + -1;
174: puVar10[2] = (int)(uint)bVar1 >> 4;
175: puVar10[3] = bVar1 & 0xf;
176: if (pbVar9 == (byte *)0x0) {
177: iVar8 = (*(code *)ppbVar5[3])(param_1);
178: if (iVar8 == 0) goto LAB_00134688;
179: pbVar13 = *ppbVar5;
180: pbVar9 = ppbVar5[1];
181: }
182: else {
183: pbVar13 = pbVar11 + 1;
184: }
185: pbVar11 = pbVar13 + 1;
186: pbVar9 = pbVar9 + -1;
187: uVar14 = uVar14 + 1;
188: puVar10[4] = (uint)*pbVar13;
189: pcVar6 = *param_1;
190: *(uint *)(pcVar6 + 0x2c) = *puVar10;
191: *(uint *)(pcVar6 + 0x30) = puVar10[2];
192: *(uint *)(pcVar6 + 0x34) = puVar10[3];
193: uVar4 = puVar10[4];
194: *(undefined4 *)(pcVar6 + 0x28) = 0x65;
195: *(uint *)(pcVar6 + 0x38) = uVar4;
196: (**(code **)(pcVar6 + 8))(param_1,1);
197: puVar10 = puVar10 + 0x18;
198: } while (*(uint *)(param_1 + 7) != uVar14 && (int)uVar14 <= *(int *)(param_1 + 7));
199: }
200: *(undefined4 *)(param_1[0x49] + 0x1c) = 1;
201: *ppbVar5 = pbVar11;
202: uVar12 = 1;
203: ppbVar5[1] = pbVar9;
204: }
205: return uVar12;
206: }
207: 
