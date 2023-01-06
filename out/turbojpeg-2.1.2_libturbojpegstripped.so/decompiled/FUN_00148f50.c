1: 
2: long FUN_00148f50(code **param_1,long *param_2,uint param_3,uint param_4,int param_5)
3: 
4: {
5: undefined8 *puVar1;
6: code **ppcVar2;
7: uint uVar3;
8: int iVar4;
9: ulong uVar5;
10: uint uVar6;
11: uint uVar7;
12: long lVar8;
13: ulong uVar9;
14: ulong uVar10;
15: ulong uVar11;
16: long lVar12;
17: 
18: uVar3 = param_3 + param_4;
19: if (((*(uint *)(param_2 + 1) < uVar3) || (*(uint *)(param_2 + 2) < param_4)) || (*param_2 == 0)) {
20: ppcVar2 = (code **)*param_1;
21: *(undefined4 *)(ppcVar2 + 5) = 0x16;
22: (**ppcVar2)();
23: }
24: uVar7 = *(uint *)((long)param_2 + 0x1c);
25: if ((param_3 < uVar7) || (*(int *)((long)param_2 + 0x14) + uVar7 < uVar3)) {
26: if (*(int *)((long)param_2 + 0x2c) == 0) {
27: ppcVar2 = (code **)*param_1;
28: *(undefined4 *)(ppcVar2 + 5) = 0x45;
29: (**ppcVar2)();
30: uVar7 = *(uint *)((long)param_2 + 0x1c);
31: }
32: uVar5 = (ulong)*(uint *)((long)param_2 + 0x14);
33: uVar10 = (ulong)*(uint *)(param_2 + 4);
34: if (*(int *)(param_2 + 5) != 0) {
35: if (uVar5 != 0) {
36: uVar11 = (ulong)*(uint *)(param_2 + 3);
37: if (uVar5 < *(uint *)(param_2 + 3)) {
38: uVar11 = uVar5;
39: }
40: uVar9 = (ulong)*(uint *)(param_2 + 4) - (ulong)uVar7;
41: if ((long)uVar9 <= (long)uVar11) {
42: uVar11 = uVar9;
43: }
44: uVar9 = (ulong)*(uint *)(param_2 + 1) - (ulong)uVar7;
45: if ((long)uVar11 < (long)uVar9) {
46: uVar9 = uVar11;
47: }
48: if (0 < (long)uVar9) {
49: lVar12 = 0;
50: do {
51: (*(code *)param_2[8])(param_1,param_2 + 7,*(undefined8 *)(*param_2 + lVar12 * 8));
52: uVar11 = (ulong)*(uint *)(param_2 + 3);
53: uVar5 = (ulong)*(uint *)((long)param_2 + 0x14);
54: lVar12 = lVar12 + uVar11;
55: if ((long)uVar5 <= lVar12) {
56: uVar7 = *(uint *)((long)param_2 + 0x1c);
57: uVar10 = (ulong)*(uint *)(param_2 + 4);
58: goto LAB_0014929b;
59: }
60: uVar7 = *(uint *)((long)param_2 + 0x1c);
61: if ((long)(uVar5 - lVar12) <= (long)uVar11) {
62: uVar11 = uVar5 - lVar12;
63: }
64: uVar10 = (ulong)*(uint *)(param_2 + 4);
65: uVar9 = uVar10 - ((ulong)uVar7 + lVar12);
66: if ((long)uVar11 < (long)uVar9) {
67: uVar9 = uVar11;
68: }
69: uVar11 = (ulong)*(uint *)(param_2 + 1) - ((ulong)uVar7 + lVar12);
70: if ((long)uVar9 < (long)uVar11) {
71: uVar11 = uVar9;
72: }
73: } while (0 < (long)uVar11);
74: *(undefined4 *)(param_2 + 5) = 0;
75: goto LAB_00148fe0;
76: }
77: }
78: LAB_0014929b:
79: *(undefined4 *)(param_2 + 5) = 0;
80: }
81: LAB_00148fe0:
82: uVar6 = (uint)uVar10;
83: if (uVar7 < param_3) {
84: *(uint *)((long)param_2 + 0x1c) = param_3;
85: uVar11 = (ulong)param_3;
86: }
87: else {
88: uVar9 = uVar3 - uVar5;
89: if ((long)uVar9 < 0) {
90: uVar9 = 0;
91: }
92: uVar11 = uVar9 & 0xffffffff;
93: *(int *)((long)param_2 + 0x1c) = (int)uVar9;
94: }
95: if (uVar5 != 0) {
96: uVar9 = (ulong)*(uint *)(param_2 + 3);
97: if (uVar5 < *(uint *)(param_2 + 3)) {
98: uVar9 = uVar5;
99: }
100: uVar5 = uVar10 - uVar11;
101: if ((long)uVar9 < (long)(uVar10 - uVar11)) {
102: uVar5 = uVar9;
103: }
104: uVar10 = *(uint *)(param_2 + 1) - uVar11;
105: if ((long)uVar5 < (long)(*(uint *)(param_2 + 1) - uVar11)) {
106: uVar10 = uVar5;
107: }
108: if (0 < (long)uVar10) {
109: lVar12 = 0;
110: do {
111: (*(code *)param_2[7])(param_1,param_2 + 7,*(undefined8 *)(*param_2 + lVar12 * 8));
112: uVar5 = (ulong)*(uint *)(param_2 + 3);
113: lVar12 = lVar12 + uVar5;
114: if ((long)(ulong)*(uint *)((long)param_2 + 0x14) <= lVar12) goto LAB_001490b5;
115: uVar10 = (ulong)*(uint *)((long)param_2 + 0x14) - lVar12;
116: if ((long)uVar10 <= (long)uVar5) {
117: uVar5 = uVar10;
118: }
119: uVar6 = *(uint *)(param_2 + 4);
120: lVar8 = (ulong)*(uint *)((long)param_2 + 0x1c) + lVar12;
121: uVar10 = (ulong)uVar6 - lVar8;
122: if ((long)uVar10 <= (long)uVar5) {
123: uVar5 = uVar10;
124: }
125: uVar10 = (ulong)*(uint *)(param_2 + 1) - lVar8;
126: if ((long)uVar5 < (long)uVar10) {
127: uVar10 = uVar5;
128: }
129: } while (0 < (long)uVar10);
130: }
131: }
132: }
133: else {
134: LAB_001490b5:
135: uVar6 = *(uint *)(param_2 + 4);
136: }
137: if (uVar6 < uVar3) {
138: if (param_3 <= uVar6) {
139: if (param_5 != 0) goto LAB_001490f1;
140: LAB_001491ac:
141: if (*(int *)((long)param_2 + 0x24) == 0) {
142: ppcVar2 = (code **)*param_1;
143: *(undefined4 *)(ppcVar2 + 5) = 0x16;
144: (**ppcVar2)(param_1);
145: iVar4 = *(int *)((long)param_2 + 0x1c);
146: goto LAB_0014916c;
147: }
148: iVar4 = *(int *)((long)param_2 + 0x1c);
149: LAB_00149105:
150: uVar7 = *(uint *)((long)param_2 + 0xc);
151: uVar6 = uVar6 - iVar4;
152: if (uVar6 < uVar3 - iVar4) {
153: lVar12 = (ulong)uVar6 * 8;
154: do {
155: puVar1 = (undefined8 *)(*param_2 + lVar12);
156: lVar12 = lVar12 + 8;
157: FUN_00148a80(*puVar1,(ulong)uVar7 << 7);
158: } while (((ulong)uVar6 + 1 + (ulong)(((uVar3 - iVar4) - 1) - uVar6)) * 8 != lVar12);
159: goto LAB_00149158;
160: }
161: goto LAB_0014915c;
162: }
163: uVar6 = param_3;
164: if (param_5 == 0) goto LAB_001491ac;
165: ppcVar2 = (code **)*param_1;
166: *(undefined4 *)(ppcVar2 + 5) = 0x16;
167: (**ppcVar2)(param_1);
168: LAB_001490f1:
169: iVar4 = *(int *)((long)param_2 + 0x1c);
170: *(uint *)(param_2 + 4) = uVar3;
171: if (*(int *)((long)param_2 + 0x24) != 0) goto LAB_00149105;
172: }
173: else {
174: LAB_00149158:
175: iVar4 = *(int *)((long)param_2 + 0x1c);
176: LAB_0014915c:
177: if (param_5 == 0) goto LAB_0014916c;
178: }
179: *(undefined4 *)(param_2 + 5) = 1;
180: LAB_0014916c:
181: return *param_2 + (ulong)(param_3 - iVar4) * 8;
182: }
183: 
