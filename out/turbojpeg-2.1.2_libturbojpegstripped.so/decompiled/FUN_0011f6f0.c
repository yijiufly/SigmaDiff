1: 
2: void FUN_0011f6f0(code **param_1,undefined4 param_2)
3: 
4: {
5: code **ppcVar1;
6: undefined4 *puVar2;
7: int *piVar3;
8: int iVar4;
9: int iVar5;
10: 
11: iVar4 = *(int *)((long)param_1 + 0x24);
12: if (iVar4 != 100) {
13: ppcVar1 = (code **)*param_1;
14: *(undefined4 *)(ppcVar1 + 5) = 0x14;
15: *(int *)((long)ppcVar1 + 0x2c) = iVar4;
16: (**ppcVar1)();
17: }
18: *(undefined4 *)(param_1 + 10) = param_2;
19: *(undefined4 *)(param_1 + 0x24) = 0;
20: *(undefined4 *)((long)param_1 + 300) = 0;
21: switch(param_2) {
22: case 0:
23: break;
24: case 1:
25: puVar2 = (undefined4 *)param_1[0xb];
26: *(undefined4 *)(param_1 + 0x24) = 1;
27: *(undefined4 *)((long)param_1 + 0x4c) = 1;
28: *puVar2 = 1;
29: puVar2[6] = 0;
30: puVar2[2] = 1;
31: puVar2[3] = 1;
32: puVar2[4] = 0;
33: puVar2[5] = 0;
34: return;
35: case 2:
36: puVar2 = (undefined4 *)param_1[0xb];
37: *(undefined4 *)((long)param_1 + 300) = 1;
38: *(undefined4 *)((long)param_1 + 0x4c) = 3;
39: *puVar2 = 0x52;
40: puVar2[6] = 0;
41: puVar2[2] = 1;
42: puVar2[3] = 1;
43: puVar2[4] = 0;
44: puVar2[5] = 0;
45: puVar2[0x18] = 0x47;
46: puVar2[0x1e] = 0;
47: puVar2[0x1a] = 1;
48: puVar2[0x1b] = 1;
49: puVar2[0x1c] = 0;
50: puVar2[0x1d] = 0;
51: puVar2[0x32] = 1;
52: puVar2[0x33] = 1;
53: puVar2[0x34] = 0;
54: puVar2[0x35] = 0;
55: puVar2[0x30] = 0x42;
56: puVar2[0x36] = 0;
57: return;
58: case 3:
59: puVar2 = (undefined4 *)param_1[0xb];
60: *(undefined4 *)(param_1 + 0x24) = 1;
61: *(undefined4 *)((long)param_1 + 0x4c) = 3;
62: puVar2[2] = 2;
63: puVar2[3] = 2;
64: puVar2[4] = 0;
65: puVar2[5] = 0;
66: *puVar2 = 1;
67: puVar2[6] = 0;
68: puVar2[0x18] = 2;
69: puVar2[0x1e] = 1;
70: puVar2[0x1a] = 1;
71: puVar2[0x1b] = 1;
72: puVar2[0x1c] = 1;
73: puVar2[0x1d] = 1;
74: puVar2[0x30] = 3;
75: puVar2[0x36] = 1;
76: puVar2[0x32] = 1;
77: puVar2[0x33] = 1;
78: puVar2[0x34] = 1;
79: puVar2[0x35] = 1;
80: return;
81: case 4:
82: puVar2 = (undefined4 *)param_1[0xb];
83: *(undefined4 *)((long)param_1 + 300) = 1;
84: *(undefined4 *)((long)param_1 + 0x4c) = 4;
85: puVar2[2] = 1;
86: puVar2[3] = 1;
87: puVar2[4] = 0;
88: puVar2[5] = 0;
89: *puVar2 = 0x43;
90: puVar2[6] = 0;
91: puVar2[0x1a] = 1;
92: puVar2[0x1b] = 1;
93: puVar2[0x1c] = 0;
94: puVar2[0x1d] = 0;
95: puVar2[0x32] = 1;
96: puVar2[0x33] = 1;
97: puVar2[0x34] = 0;
98: puVar2[0x35] = 0;
99: puVar2[0x4a] = 1;
100: puVar2[0x4b] = 1;
101: puVar2[0x4c] = 0;
102: puVar2[0x4d] = 0;
103: puVar2[0x18] = 0x4d;
104: puVar2[0x1e] = 0;
105: puVar2[0x30] = 0x59;
106: puVar2[0x36] = 0;
107: puVar2[0x48] = 0x4b;
108: puVar2[0x4e] = 0;
109: return;
110: case 5:
111: puVar2 = (undefined4 *)param_1[0xb];
112: *(undefined4 *)((long)param_1 + 300) = 1;
113: *(undefined4 *)((long)param_1 + 0x4c) = 4;
114: *puVar2 = 1;
115: puVar2[6] = 0;
116: puVar2[2] = 2;
117: puVar2[3] = 2;
118: puVar2[4] = 0;
119: puVar2[5] = 0;
120: puVar2[0x18] = 2;
121: puVar2[0x1e] = 1;
122: puVar2[0x1a] = 1;
123: puVar2[0x1b] = 1;
124: puVar2[0x1c] = 1;
125: puVar2[0x1d] = 1;
126: puVar2[0x32] = 1;
127: puVar2[0x33] = 1;
128: puVar2[0x34] = 1;
129: puVar2[0x35] = 1;
130: puVar2[0x4a] = 2;
131: puVar2[0x4b] = 2;
132: puVar2[0x4c] = 0;
133: puVar2[0x4d] = 0;
134: puVar2[0x30] = 3;
135: puVar2[0x36] = 1;
136: puVar2[0x48] = 4;
137: puVar2[0x4e] = 0;
138: return;
139: default:
140: ppcVar1 = (code **)*param_1;
141: *(undefined4 *)(ppcVar1 + 5) = 10;
142: /* WARNING: Could not recover jumptable at 0x0011f9f6. Too many branches */
143: /* WARNING: Treating indirect jump as call */
144: (**ppcVar1)(param_1);
145: return;
146: }
147: iVar4 = *(int *)(param_1 + 7);
148: *(int *)((long)param_1 + 0x4c) = iVar4;
149: if (9 < iVar4 - 1U) {
150: ppcVar1 = (code **)*param_1;
151: *(int *)((long)ppcVar1 + 0x2c) = iVar4;
152: *(undefined4 *)(ppcVar1 + 5) = 0x1a;
153: *(undefined4 *)(ppcVar1 + 6) = 10;
154: (**ppcVar1)(param_1);
155: iVar4 = *(int *)((long)param_1 + 0x4c);
156: if (iVar4 < 1) {
157: return;
158: }
159: }
160: iVar5 = 0;
161: piVar3 = (int *)param_1[0xb];
162: do {
163: *piVar3 = iVar5;
164: iVar5 = iVar5 + 1;
165: piVar3[2] = 1;
166: piVar3[3] = 1;
167: piVar3[4] = 0;
168: piVar3[5] = 0;
169: piVar3[6] = 0;
170: piVar3 = piVar3 + 0x18;
171: } while (iVar4 != iVar5);
172: return;
173: }
174: 
