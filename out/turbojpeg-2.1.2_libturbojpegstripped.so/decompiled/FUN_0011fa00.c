1: 
2: void FUN_0011fa00(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: undefined4 *puVar2;
7: int *piVar3;
8: int iVar4;
9: int iVar5;
10: undefined4 uVar6;
11: 
12: if (*(uint *)((long)param_1 + 0x3c) < 0x10) {
13: switch(*(undefined4 *)((long)param_1 + 0x3c)) {
14: case 0:
15: uVar6 = 0;
16: break;
17: case 1:
18: uVar6 = 1;
19: break;
20: default:
21: uVar6 = 3;
22: break;
23: case 4:
24: uVar6 = 4;
25: break;
26: case 5:
27: uVar6 = 5;
28: }
29: iVar4 = *(int *)((long)param_1 + 0x24);
30: if (iVar4 != 100) {
31: ppcVar1 = (code **)*param_1;
32: *(undefined4 *)(ppcVar1 + 5) = 0x14;
33: *(int *)((long)ppcVar1 + 0x2c) = iVar4;
34: (**ppcVar1)();
35: }
36: *(undefined4 *)(param_1 + 10) = uVar6;
37: *(undefined4 *)(param_1 + 0x24) = 0;
38: *(undefined4 *)((long)param_1 + 300) = 0;
39: switch(uVar6) {
40: case 0:
41: goto code_r0x0011f850;
42: case 1:
43: puVar2 = (undefined4 *)param_1[0xb];
44: *(undefined4 *)(param_1 + 0x24) = 1;
45: *(undefined4 *)((long)param_1 + 0x4c) = 1;
46: *puVar2 = 1;
47: puVar2[6] = 0;
48: puVar2[2] = 1;
49: puVar2[3] = 1;
50: puVar2[4] = 0;
51: puVar2[5] = 0;
52: return;
53: case 2:
54: puVar2 = (undefined4 *)param_1[0xb];
55: *(undefined4 *)((long)param_1 + 300) = 1;
56: *(undefined4 *)((long)param_1 + 0x4c) = 3;
57: *puVar2 = 0x52;
58: puVar2[6] = 0;
59: puVar2[2] = 1;
60: puVar2[3] = 1;
61: puVar2[4] = 0;
62: puVar2[5] = 0;
63: puVar2[0x18] = 0x47;
64: puVar2[0x1e] = 0;
65: puVar2[0x1a] = 1;
66: puVar2[0x1b] = 1;
67: puVar2[0x1c] = 0;
68: puVar2[0x1d] = 0;
69: puVar2[0x32] = 1;
70: puVar2[0x33] = 1;
71: puVar2[0x34] = 0;
72: puVar2[0x35] = 0;
73: puVar2[0x30] = 0x42;
74: puVar2[0x36] = 0;
75: return;
76: case 3:
77: puVar2 = (undefined4 *)param_1[0xb];
78: *(undefined4 *)(param_1 + 0x24) = 1;
79: *(undefined4 *)((long)param_1 + 0x4c) = 3;
80: puVar2[2] = 2;
81: puVar2[3] = 2;
82: puVar2[4] = 0;
83: puVar2[5] = 0;
84: *puVar2 = 1;
85: puVar2[6] = 0;
86: puVar2[0x18] = 2;
87: puVar2[0x1e] = 1;
88: puVar2[0x1a] = 1;
89: puVar2[0x1b] = 1;
90: puVar2[0x1c] = 1;
91: puVar2[0x1d] = 1;
92: puVar2[0x30] = 3;
93: puVar2[0x36] = 1;
94: puVar2[0x32] = 1;
95: puVar2[0x33] = 1;
96: puVar2[0x34] = 1;
97: puVar2[0x35] = 1;
98: return;
99: case 4:
100: puVar2 = (undefined4 *)param_1[0xb];
101: *(undefined4 *)((long)param_1 + 300) = 1;
102: *(undefined4 *)((long)param_1 + 0x4c) = 4;
103: puVar2[2] = 1;
104: puVar2[3] = 1;
105: puVar2[4] = 0;
106: puVar2[5] = 0;
107: *puVar2 = 0x43;
108: puVar2[6] = 0;
109: puVar2[0x1a] = 1;
110: puVar2[0x1b] = 1;
111: puVar2[0x1c] = 0;
112: puVar2[0x1d] = 0;
113: puVar2[0x32] = 1;
114: puVar2[0x33] = 1;
115: puVar2[0x34] = 0;
116: puVar2[0x35] = 0;
117: puVar2[0x4a] = 1;
118: puVar2[0x4b] = 1;
119: puVar2[0x4c] = 0;
120: puVar2[0x4d] = 0;
121: puVar2[0x18] = 0x4d;
122: puVar2[0x1e] = 0;
123: puVar2[0x30] = 0x59;
124: puVar2[0x36] = 0;
125: puVar2[0x48] = 0x4b;
126: puVar2[0x4e] = 0;
127: return;
128: case 5:
129: puVar2 = (undefined4 *)param_1[0xb];
130: *(undefined4 *)((long)param_1 + 300) = 1;
131: *(undefined4 *)((long)param_1 + 0x4c) = 4;
132: *puVar2 = 1;
133: puVar2[6] = 0;
134: puVar2[2] = 2;
135: puVar2[3] = 2;
136: puVar2[4] = 0;
137: puVar2[5] = 0;
138: puVar2[0x18] = 2;
139: puVar2[0x1e] = 1;
140: puVar2[0x1a] = 1;
141: puVar2[0x1b] = 1;
142: puVar2[0x1c] = 1;
143: puVar2[0x1d] = 1;
144: puVar2[0x32] = 1;
145: puVar2[0x33] = 1;
146: puVar2[0x34] = 1;
147: puVar2[0x35] = 1;
148: puVar2[0x4a] = 2;
149: puVar2[0x4b] = 2;
150: puVar2[0x4c] = 0;
151: puVar2[0x4d] = 0;
152: puVar2[0x30] = 3;
153: puVar2[0x36] = 1;
154: puVar2[0x48] = 4;
155: puVar2[0x4e] = 0;
156: return;
157: default:
158: ppcVar1 = (code **)*param_1;
159: *(undefined4 *)(ppcVar1 + 5) = 10;
160: /* WARNING: Could not recover jumptable at 0x0011f9f6. Too many branches */
161: /* WARNING: Treating indirect jump as call */
162: (**ppcVar1)(param_1);
163: return;
164: }
165: }
166: param_1 = (code **)*param_1;
167: *(undefined4 *)(param_1 + 5) = 9;
168: /* WARNING: Could not recover jumptable at 0x0011fa7a. Too many branches */
169: /* WARNING: Treating indirect jump as call */
170: (**param_1)();
171: return;
172: code_r0x0011f850:
173: iVar4 = *(int *)(param_1 + 7);
174: *(int *)((long)param_1 + 0x4c) = iVar4;
175: if (9 < iVar4 - 1U) {
176: ppcVar1 = (code **)*param_1;
177: *(int *)((long)ppcVar1 + 0x2c) = iVar4;
178: *(undefined4 *)(ppcVar1 + 5) = 0x1a;
179: *(undefined4 *)(ppcVar1 + 6) = 10;
180: (**ppcVar1)(param_1);
181: iVar4 = *(int *)((long)param_1 + 0x4c);
182: if (iVar4 < 1) {
183: return;
184: }
185: }
186: iVar5 = 0;
187: piVar3 = (int *)param_1[0xb];
188: do {
189: *piVar3 = iVar5;
190: iVar5 = iVar5 + 1;
191: piVar3[2] = 1;
192: piVar3[3] = 1;
193: piVar3[4] = 0;
194: piVar3[5] = 0;
195: piVar3[6] = 0;
196: piVar3 = piVar3 + 0x18;
197: } while (iVar4 != iVar5);
198: return;
199: }
200: 
