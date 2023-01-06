1: 
2: void FUN_00105040(long param_1,byte **param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: uint uVar1;
6: long lVar2;
7: long lVar3;
8: byte **ppbVar4;
9: byte *pbVar5;
10: ulong uVar6;
11: long lVar7;
12: 
13: if (*(int *)(param_1 + 0x3c) - 6U < 10) {
14: uVar1 = *(uint *)(param_1 + 0x30);
15: lVar2 = *(long *)(*(long *)(param_1 + 0x1d8) + 0x10);
16: switch(*(int *)(param_1 + 0x3c)) {
17: case 6:
18: while (param_5 = param_5 + -1, -1 < param_5) {
19: uVar6 = (ulong)param_4;
20: ppbVar4 = param_2 + 1;
21: param_4 = param_4 + 1;
22: pbVar5 = *param_2;
23: lVar3 = *(long *)(*param_3 + uVar6 * 8);
24: lVar7 = 0;
25: param_2 = ppbVar4;
26: if (uVar1 != 0) {
27: do {
28: *(char *)(lVar3 + lVar7) =
29: (char)((ulong)(*(long *)(lVar2 + (ulong)*pbVar5 * 8) +
30: *(long *)(lVar2 + 0x800 + (ulong)pbVar5[1] * 8) +
31: *(long *)(lVar2 + 0x1000 + (ulong)pbVar5[2] * 8)) >> 0x10);
32: lVar7 = lVar7 + 1;
33: pbVar5 = pbVar5 + 3;
34: } while ((uint)lVar7 < uVar1);
35: }
36: }
37: break;
38: default:
39: while (param_5 = param_5 + -1, -1 < param_5) {
40: uVar6 = (ulong)param_4;
41: ppbVar4 = param_2 + 1;
42: param_4 = param_4 + 1;
43: pbVar5 = *param_2;
44: lVar3 = *(long *)(*param_3 + uVar6 * 8);
45: lVar7 = 0;
46: param_2 = ppbVar4;
47: if (uVar1 != 0) {
48: do {
49: *(char *)(lVar3 + lVar7) =
50: (char)((ulong)(*(long *)(lVar2 + (ulong)*pbVar5 * 8) +
51: *(long *)(lVar2 + 0x800 + (ulong)pbVar5[1] * 8) +
52: *(long *)(lVar2 + 0x1000 + (ulong)pbVar5[2] * 8)) >> 0x10);
53: lVar7 = lVar7 + 1;
54: pbVar5 = pbVar5 + 4;
55: } while ((uint)lVar7 < uVar1);
56: }
57: }
58: break;
59: case 8:
60: while (param_5 = param_5 + -1, -1 < param_5) {
61: uVar6 = (ulong)param_4;
62: ppbVar4 = param_2 + 1;
63: param_4 = param_4 + 1;
64: pbVar5 = *param_2;
65: lVar3 = *(long *)(*param_3 + uVar6 * 8);
66: lVar7 = 0;
67: param_2 = ppbVar4;
68: if (uVar1 != 0) {
69: do {
70: *(char *)(lVar3 + lVar7) =
71: (char)((ulong)(*(long *)(lVar2 + (ulong)pbVar5[2] * 8) +
72: *(long *)(lVar2 + 0x800 + (ulong)pbVar5[1] * 8) +
73: *(long *)(lVar2 + 0x1000 + (ulong)*pbVar5 * 8)) >> 0x10);
74: lVar7 = lVar7 + 1;
75: pbVar5 = pbVar5 + 3;
76: } while ((uint)lVar7 < uVar1);
77: }
78: }
79: break;
80: case 9:
81: case 0xd:
82: while (param_5 = param_5 + -1, -1 < param_5) {
83: uVar6 = (ulong)param_4;
84: ppbVar4 = param_2 + 1;
85: param_4 = param_4 + 1;
86: pbVar5 = *param_2;
87: lVar3 = *(long *)(*param_3 + uVar6 * 8);
88: lVar7 = 0;
89: param_2 = ppbVar4;
90: if (uVar1 != 0) {
91: do {
92: *(char *)(lVar3 + lVar7) =
93: (char)((ulong)(*(long *)(lVar2 + (ulong)pbVar5[2] * 8) +
94: *(long *)(lVar2 + 0x800 + (ulong)pbVar5[1] * 8) +
95: *(long *)(lVar2 + 0x1000 + (ulong)*pbVar5 * 8)) >> 0x10);
96: lVar7 = lVar7 + 1;
97: pbVar5 = pbVar5 + 4;
98: } while ((uint)lVar7 < uVar1);
99: }
100: }
101: break;
102: case 10:
103: case 0xe:
104: while (param_5 = param_5 + -1, -1 < param_5) {
105: uVar6 = (ulong)param_4;
106: ppbVar4 = param_2 + 1;
107: param_4 = param_4 + 1;
108: pbVar5 = *param_2;
109: lVar3 = *(long *)(*param_3 + uVar6 * 8);
110: lVar7 = 0;
111: param_2 = ppbVar4;
112: if (uVar1 != 0) {
113: do {
114: *(char *)(lVar3 + lVar7) =
115: (char)((ulong)(*(long *)(lVar2 + (ulong)pbVar5[3] * 8) +
116: *(long *)(lVar2 + 0x800 + (ulong)pbVar5[2] * 8) +
117: *(long *)(lVar2 + 0x1000 + (ulong)pbVar5[1] * 8)) >> 0x10);
118: lVar7 = lVar7 + 1;
119: pbVar5 = pbVar5 + 4;
120: } while ((uint)lVar7 < uVar1);
121: }
122: }
123: break;
124: case 0xb:
125: case 0xf:
126: while (param_5 = param_5 + -1, ppbVar4 = param_2, -1 < param_5) {
127: while( true ) {
128: uVar6 = (ulong)param_4;
129: param_2 = ppbVar4 + 1;
130: param_4 = param_4 + 1;
131: lVar3 = *(long *)(*param_3 + uVar6 * 8);
132: lVar7 = 0;
133: pbVar5 = *ppbVar4;
134: if (uVar1 == 0) break;
135: do {
136: *(char *)(lVar3 + lVar7) =
137: (char)((ulong)(*(long *)(lVar2 + (ulong)pbVar5[1] * 8) +
138: *(long *)(lVar2 + 0x800 + (ulong)pbVar5[2] * 8) +
139: *(long *)(lVar2 + 0x1000 + (ulong)pbVar5[3] * 8)) >> 0x10);
140: lVar7 = lVar7 + 1;
141: pbVar5 = pbVar5 + 4;
142: } while ((uint)lVar7 < uVar1);
143: param_5 = param_5 + -1;
144: ppbVar4 = param_2;
145: if (param_5 < 0) {
146: return;
147: }
148: }
149: }
150: }
151: }
152: else {
153: uVar1 = *(uint *)(param_1 + 0x30);
154: lVar2 = *(long *)(*(long *)(param_1 + 0x1d8) + 0x10);
155: while (param_5 = param_5 + -1, -1 < param_5) {
156: uVar6 = (ulong)param_4;
157: ppbVar4 = param_2 + 1;
158: param_4 = param_4 + 1;
159: pbVar5 = *param_2;
160: lVar3 = *(long *)(*param_3 + uVar6 * 8);
161: lVar7 = 0;
162: param_2 = ppbVar4;
163: if (uVar1 != 0) {
164: do {
165: *(char *)(lVar3 + lVar7) =
166: (char)((ulong)(*(long *)(lVar2 + (ulong)*pbVar5 * 8) +
167: *(long *)(lVar2 + 0x800 + (ulong)pbVar5[1] * 8) +
168: *(long *)(lVar2 + 0x1000 + (ulong)pbVar5[2] * 8)) >> 0x10);
169: lVar7 = lVar7 + 1;
170: pbVar5 = pbVar5 + 3;
171: } while ((uint)lVar7 < uVar1);
172: }
173: }
174: }
175: return;
176: }
177: 
