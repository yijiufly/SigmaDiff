1: 
2: void FUN_001169b0(code **param_1,undefined4 param_2)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: undefined4 *puVar3;
8: int *piVar4;
9: int iVar5;
10: int iVar6;
11: 
12: if (*(int *)((long)param_1 + 0x24) != 100) {
13: pcVar1 = *param_1;
14: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
15: ppcVar2 = (code **)*param_1;
16: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
17: (**ppcVar2)();
18: }
19: *(undefined4 *)(param_1 + 10) = param_2;
20: *(undefined4 *)(param_1 + 0x24) = 0;
21: *(undefined4 *)((long)param_1 + 300) = 0;
22: switch(param_2) {
23: case 0:
24: break;
25: case 1:
26: puVar3 = (undefined4 *)param_1[0xb];
27: *(undefined4 *)(param_1 + 0x24) = 1;
28: *(undefined4 *)((long)param_1 + 0x4c) = 1;
29: *puVar3 = 1;
30: puVar3[2] = 1;
31: puVar3[3] = 1;
32: puVar3[4] = 0;
33: puVar3[5] = 0;
34: puVar3[6] = 0;
35: return;
36: case 2:
37: puVar3 = (undefined4 *)param_1[0xb];
38: *(undefined4 *)((long)param_1 + 300) = 1;
39: *(undefined4 *)((long)param_1 + 0x4c) = 3;
40: *puVar3 = 0x52;
41: puVar3[2] = 1;
42: puVar3[3] = 1;
43: puVar3[4] = 0;
44: puVar3[5] = 0;
45: puVar3[6] = 0;
46: puVar3[0x18] = 0x47;
47: puVar3[0x1a] = 1;
48: puVar3[0x1b] = 1;
49: puVar3[0x1c] = 0;
50: puVar3[0x1d] = 0;
51: puVar3[0x1e] = 0;
52: puVar3[0x30] = 0x42;
53: puVar3[0x32] = 1;
54: puVar3[0x33] = 1;
55: puVar3[0x34] = 0;
56: puVar3[0x35] = 0;
57: puVar3[0x36] = 0;
58: return;
59: case 3:
60: puVar3 = (undefined4 *)param_1[0xb];
61: *(undefined4 *)(param_1 + 0x24) = 1;
62: *(undefined4 *)((long)param_1 + 0x4c) = 3;
63: *puVar3 = 1;
64: puVar3[2] = 2;
65: puVar3[3] = 2;
66: puVar3[4] = 0;
67: puVar3[5] = 0;
68: puVar3[6] = 0;
69: puVar3[0x18] = 2;
70: puVar3[0x1a] = 1;
71: puVar3[0x1b] = 1;
72: puVar3[0x1c] = 1;
73: puVar3[0x1d] = 1;
74: puVar3[0x1e] = 1;
75: puVar3[0x30] = 3;
76: puVar3[0x32] = 1;
77: puVar3[0x33] = 1;
78: puVar3[0x34] = 1;
79: puVar3[0x35] = 1;
80: puVar3[0x36] = 1;
81: return;
82: case 4:
83: puVar3 = (undefined4 *)param_1[0xb];
84: *(undefined4 *)((long)param_1 + 300) = 1;
85: *(undefined4 *)((long)param_1 + 0x4c) = 4;
86: *puVar3 = 0x43;
87: puVar3[2] = 1;
88: puVar3[3] = 1;
89: puVar3[4] = 0;
90: puVar3[5] = 0;
91: puVar3[6] = 0;
92: puVar3[0x18] = 0x4d;
93: puVar3[0x1a] = 1;
94: puVar3[0x1b] = 1;
95: puVar3[0x1c] = 0;
96: puVar3[0x1d] = 0;
97: puVar3[0x1e] = 0;
98: puVar3[0x30] = 0x59;
99: puVar3[0x32] = 1;
100: puVar3[0x33] = 1;
101: puVar3[0x34] = 0;
102: puVar3[0x35] = 0;
103: puVar3[0x36] = 0;
104: puVar3[0x48] = 0x4b;
105: puVar3[0x4a] = 1;
106: puVar3[0x4b] = 1;
107: puVar3[0x4c] = 0;
108: puVar3[0x4d] = 0;
109: puVar3[0x4e] = 0;
110: return;
111: case 5:
112: puVar3 = (undefined4 *)param_1[0xb];
113: *(undefined4 *)((long)param_1 + 300) = 1;
114: *(undefined4 *)((long)param_1 + 0x4c) = 4;
115: *puVar3 = 1;
116: puVar3[2] = 2;
117: puVar3[3] = 2;
118: puVar3[4] = 0;
119: puVar3[5] = 0;
120: puVar3[6] = 0;
121: puVar3[0x18] = 2;
122: puVar3[0x1a] = 1;
123: puVar3[0x1b] = 1;
124: puVar3[0x1c] = 1;
125: puVar3[0x1d] = 1;
126: puVar3[0x1e] = 1;
127: puVar3[0x30] = 3;
128: puVar3[0x32] = 1;
129: puVar3[0x33] = 1;
130: puVar3[0x34] = 1;
131: puVar3[0x35] = 1;
132: puVar3[0x36] = 1;
133: puVar3[0x48] = 4;
134: puVar3[0x4a] = 2;
135: puVar3[0x4b] = 2;
136: puVar3[0x4c] = 0;
137: puVar3[0x4d] = 0;
138: puVar3[0x4e] = 0;
139: return;
140: default:
141: ppcVar2 = (code **)*param_1;
142: *(undefined4 *)(ppcVar2 + 5) = 10;
143: /* WARNING: Could not recover jumptable at 0x00116dfe. Too many branches */
144: /* WARNING: Treating indirect jump as call */
145: (**ppcVar2)(param_1);
146: return;
147: }
148: iVar5 = *(int *)(param_1 + 7);
149: *(int *)((long)param_1 + 0x4c) = iVar5;
150: if (9 < iVar5 - 1U) {
151: pcVar1 = *param_1;
152: *(int *)(pcVar1 + 0x2c) = iVar5;
153: *(undefined4 *)(pcVar1 + 0x28) = 0x1a;
154: *(undefined4 *)(*param_1 + 0x30) = 10;
155: (**(code **)*param_1)(param_1);
156: iVar5 = *(int *)((long)param_1 + 0x4c);
157: if (iVar5 < 1) {
158: return;
159: }
160: }
161: iVar6 = 0;
162: piVar4 = (int *)param_1[0xb];
163: do {
164: *piVar4 = iVar6;
165: iVar6 = iVar6 + 1;
166: piVar4[2] = 1;
167: piVar4[3] = 1;
168: piVar4[4] = 0;
169: piVar4[5] = 0;
170: piVar4[6] = 0;
171: piVar4 = piVar4 + 0x18;
172: } while (iVar6 != iVar5);
173: return;
174: }
175: 
