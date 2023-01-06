1: 
2: void FUN_00116e30(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: undefined4 *puVar3;
8: int *piVar4;
9: int iVar5;
10: int iVar6;
11: undefined4 uVar7;
12: 
13: if (*(uint *)((long)param_1 + 0x3c) < 0x10) {
14: switch(*(undefined4 *)((long)param_1 + 0x3c)) {
15: case 0:
16: uVar7 = 0;
17: break;
18: case 1:
19: uVar7 = 1;
20: break;
21: default:
22: uVar7 = 3;
23: break;
24: case 4:
25: uVar7 = 4;
26: break;
27: case 5:
28: uVar7 = 5;
29: }
30: if (*(int *)((long)param_1 + 0x24) != 100) {
31: pcVar1 = *param_1;
32: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
33: ppcVar2 = (code **)*param_1;
34: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
35: (**ppcVar2)();
36: }
37: *(undefined4 *)(param_1 + 10) = uVar7;
38: *(undefined4 *)(param_1 + 0x24) = 0;
39: *(undefined4 *)((long)param_1 + 300) = 0;
40: switch(uVar7) {
41: case 0:
42: goto code_r0x00116be0;
43: case 1:
44: puVar3 = (undefined4 *)param_1[0xb];
45: *(undefined4 *)(param_1 + 0x24) = 1;
46: *(undefined4 *)((long)param_1 + 0x4c) = 1;
47: *puVar3 = 1;
48: puVar3[2] = 1;
49: puVar3[3] = 1;
50: puVar3[4] = 0;
51: puVar3[5] = 0;
52: puVar3[6] = 0;
53: return;
54: case 2:
55: puVar3 = (undefined4 *)param_1[0xb];
56: *(undefined4 *)((long)param_1 + 300) = 1;
57: *(undefined4 *)((long)param_1 + 0x4c) = 3;
58: *puVar3 = 0x52;
59: puVar3[2] = 1;
60: puVar3[3] = 1;
61: puVar3[4] = 0;
62: puVar3[5] = 0;
63: puVar3[6] = 0;
64: puVar3[0x18] = 0x47;
65: puVar3[0x1a] = 1;
66: puVar3[0x1b] = 1;
67: puVar3[0x1c] = 0;
68: puVar3[0x1d] = 0;
69: puVar3[0x1e] = 0;
70: puVar3[0x30] = 0x42;
71: puVar3[0x32] = 1;
72: puVar3[0x33] = 1;
73: puVar3[0x34] = 0;
74: puVar3[0x35] = 0;
75: puVar3[0x36] = 0;
76: return;
77: case 3:
78: puVar3 = (undefined4 *)param_1[0xb];
79: *(undefined4 *)(param_1 + 0x24) = 1;
80: *(undefined4 *)((long)param_1 + 0x4c) = 3;
81: *puVar3 = 1;
82: puVar3[2] = 2;
83: puVar3[3] = 2;
84: puVar3[4] = 0;
85: puVar3[5] = 0;
86: puVar3[6] = 0;
87: puVar3[0x18] = 2;
88: puVar3[0x1a] = 1;
89: puVar3[0x1b] = 1;
90: puVar3[0x1c] = 1;
91: puVar3[0x1d] = 1;
92: puVar3[0x1e] = 1;
93: puVar3[0x30] = 3;
94: puVar3[0x32] = 1;
95: puVar3[0x33] = 1;
96: puVar3[0x34] = 1;
97: puVar3[0x35] = 1;
98: puVar3[0x36] = 1;
99: return;
100: case 4:
101: puVar3 = (undefined4 *)param_1[0xb];
102: *(undefined4 *)((long)param_1 + 300) = 1;
103: *(undefined4 *)((long)param_1 + 0x4c) = 4;
104: *puVar3 = 0x43;
105: puVar3[2] = 1;
106: puVar3[3] = 1;
107: puVar3[4] = 0;
108: puVar3[5] = 0;
109: puVar3[6] = 0;
110: puVar3[0x18] = 0x4d;
111: puVar3[0x1a] = 1;
112: puVar3[0x1b] = 1;
113: puVar3[0x1c] = 0;
114: puVar3[0x1d] = 0;
115: puVar3[0x1e] = 0;
116: puVar3[0x30] = 0x59;
117: puVar3[0x32] = 1;
118: puVar3[0x33] = 1;
119: puVar3[0x34] = 0;
120: puVar3[0x35] = 0;
121: puVar3[0x36] = 0;
122: puVar3[0x48] = 0x4b;
123: puVar3[0x4a] = 1;
124: puVar3[0x4b] = 1;
125: puVar3[0x4c] = 0;
126: puVar3[0x4d] = 0;
127: puVar3[0x4e] = 0;
128: return;
129: case 5:
130: puVar3 = (undefined4 *)param_1[0xb];
131: *(undefined4 *)((long)param_1 + 300) = 1;
132: *(undefined4 *)((long)param_1 + 0x4c) = 4;
133: *puVar3 = 1;
134: puVar3[2] = 2;
135: puVar3[3] = 2;
136: puVar3[4] = 0;
137: puVar3[5] = 0;
138: puVar3[6] = 0;
139: puVar3[0x18] = 2;
140: puVar3[0x1a] = 1;
141: puVar3[0x1b] = 1;
142: puVar3[0x1c] = 1;
143: puVar3[0x1d] = 1;
144: puVar3[0x1e] = 1;
145: puVar3[0x30] = 3;
146: puVar3[0x32] = 1;
147: puVar3[0x33] = 1;
148: puVar3[0x34] = 1;
149: puVar3[0x35] = 1;
150: puVar3[0x36] = 1;
151: puVar3[0x48] = 4;
152: puVar3[0x4a] = 2;
153: puVar3[0x4b] = 2;
154: puVar3[0x4c] = 0;
155: puVar3[0x4d] = 0;
156: puVar3[0x4e] = 0;
157: return;
158: default:
159: ppcVar2 = (code **)*param_1;
160: *(undefined4 *)(ppcVar2 + 5) = 10;
161: /* WARNING: Could not recover jumptable at 0x00116dfe. Too many branches */
162: /* WARNING: Treating indirect jump as call */
163: (**ppcVar2)(param_1);
164: return;
165: }
166: }
167: param_1 = (code **)*param_1;
168: *(undefined4 *)(param_1 + 5) = 9;
169: /* WARNING: Could not recover jumptable at 0x00116ead. Too many branches */
170: /* WARNING: Treating indirect jump as call */
171: (**param_1)();
172: return;
173: code_r0x00116be0:
174: iVar5 = *(int *)(param_1 + 7);
175: *(int *)((long)param_1 + 0x4c) = iVar5;
176: if (9 < iVar5 - 1U) {
177: pcVar1 = *param_1;
178: *(int *)(pcVar1 + 0x2c) = iVar5;
179: *(undefined4 *)(pcVar1 + 0x28) = 0x1a;
180: *(undefined4 *)(*param_1 + 0x30) = 10;
181: (**(code **)*param_1)(param_1);
182: iVar5 = *(int *)((long)param_1 + 0x4c);
183: if (iVar5 < 1) {
184: return;
185: }
186: }
187: iVar6 = 0;
188: piVar4 = (int *)param_1[0xb];
189: do {
190: *piVar4 = iVar6;
191: iVar6 = iVar6 + 1;
192: piVar4[2] = 1;
193: piVar4[3] = 1;
194: piVar4[4] = 0;
195: piVar4[5] = 0;
196: piVar4[6] = 0;
197: piVar4 = piVar4 + 0x18;
198: } while (iVar6 != iVar5);
199: return;
200: }
201: 
