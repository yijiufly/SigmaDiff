1: 
2: long FUN_00149300(code **param_1,long *param_2,uint param_3,uint param_4,int param_5)
3: 
4: {
5: undefined8 *puVar1;
6: undefined4 uVar2;
7: code **ppcVar3;
8: uint uVar4;
9: int iVar5;
10: ulong uVar6;
11: uint uVar7;
12: uint uVar8;
13: long lVar9;
14: ulong uVar10;
15: ulong uVar11;
16: ulong uVar12;
17: long lVar13;
18: 
19: uVar4 = param_3 + param_4;
20: if (((*(uint *)(param_2 + 1) < uVar4) || (*(uint *)(param_2 + 2) < param_4)) || (*param_2 == 0)) {
21: ppcVar3 = (code **)*param_1;
22: *(undefined4 *)(ppcVar3 + 5) = 0x16;
23: (**ppcVar3)();
24: }
25: uVar8 = *(uint *)((long)param_2 + 0x1c);
26: if ((param_3 < uVar8) || (*(int *)((long)param_2 + 0x14) + uVar8 < uVar4)) {
27: if (*(int *)((long)param_2 + 0x2c) == 0) {
28: ppcVar3 = (code **)*param_1;
29: *(undefined4 *)(ppcVar3 + 5) = 0x45;
30: (**ppcVar3)();
31: uVar8 = *(uint *)((long)param_2 + 0x1c);
32: }
33: uVar6 = (ulong)*(uint *)((long)param_2 + 0x14);
34: uVar11 = (ulong)*(uint *)(param_2 + 4);
35: if (*(int *)(param_2 + 5) != 0) {
36: if (uVar6 != 0) {
37: uVar12 = (ulong)*(uint *)(param_2 + 3);
38: if (uVar6 < *(uint *)(param_2 + 3)) {
39: uVar12 = uVar6;
40: }
41: uVar10 = (ulong)*(uint *)(param_2 + 4) - (ulong)uVar8;
42: if ((long)uVar10 <= (long)uVar12) {
43: uVar12 = uVar10;
44: }
45: uVar10 = (ulong)*(uint *)(param_2 + 1) - (ulong)uVar8;
46: if ((long)uVar12 < (long)uVar10) {
47: uVar10 = uVar12;
48: }
49: if (0 < (long)uVar10) {
50: lVar13 = 0;
51: do {
52: (*(code *)param_2[8])(param_1,param_2 + 7,*(undefined8 *)(*param_2 + lVar13 * 8));
53: uVar12 = (ulong)*(uint *)(param_2 + 3);
54: uVar6 = (ulong)*(uint *)((long)param_2 + 0x14);
55: lVar13 = lVar13 + uVar12;
56: if ((long)uVar6 <= lVar13) {
57: uVar8 = *(uint *)((long)param_2 + 0x1c);
58: uVar11 = (ulong)*(uint *)(param_2 + 4);
59: goto LAB_00149637;
60: }
61: uVar8 = *(uint *)((long)param_2 + 0x1c);
62: if ((long)(uVar6 - lVar13) <= (long)uVar12) {
63: uVar12 = uVar6 - lVar13;
64: }
65: uVar11 = (ulong)*(uint *)(param_2 + 4);
66: uVar10 = uVar11 - ((ulong)uVar8 + lVar13);
67: if ((long)uVar12 < (long)uVar10) {
68: uVar10 = uVar12;
69: }
70: uVar12 = (ulong)*(uint *)(param_2 + 1) - ((ulong)uVar8 + lVar13);
71: if ((long)uVar10 < (long)uVar12) {
72: uVar12 = uVar10;
73: }
74: } while (0 < (long)uVar12);
75: *(undefined4 *)(param_2 + 5) = 0;
76: goto LAB_0014938c;
77: }
78: }
79: LAB_00149637:
80: *(undefined4 *)(param_2 + 5) = 0;
81: }
82: LAB_0014938c:
83: uVar7 = (uint)uVar11;
84: if (uVar8 < param_3) {
85: *(uint *)((long)param_2 + 0x1c) = param_3;
86: uVar12 = (ulong)param_3;
87: }
88: else {
89: uVar10 = uVar4 - uVar6;
90: if ((long)uVar10 < 0) {
91: uVar10 = 0;
92: }
93: uVar12 = uVar10 & 0xffffffff;
94: *(int *)((long)param_2 + 0x1c) = (int)uVar10;
95: }
96: if (uVar6 != 0) {
97: uVar10 = (ulong)*(uint *)(param_2 + 3);
98: if (uVar6 < *(uint *)(param_2 + 3)) {
99: uVar10 = uVar6;
100: }
101: uVar6 = uVar11 - uVar12;
102: if ((long)uVar10 < (long)(uVar11 - uVar12)) {
103: uVar6 = uVar10;
104: }
105: uVar11 = *(uint *)(param_2 + 1) - uVar12;
106: if ((long)uVar6 < (long)(*(uint *)(param_2 + 1) - uVar12)) {
107: uVar11 = uVar6;
108: }
109: if (0 < (long)uVar11) {
110: lVar13 = 0;
111: do {
112: (*(code *)param_2[7])(param_1,param_2 + 7,*(undefined8 *)(*param_2 + lVar13 * 8));
113: uVar6 = (ulong)*(uint *)(param_2 + 3);
114: lVar13 = lVar13 + uVar6;
115: if ((long)(ulong)*(uint *)((long)param_2 + 0x14) <= lVar13) goto LAB_00149465;
116: uVar11 = (ulong)*(uint *)((long)param_2 + 0x14) - lVar13;
117: if ((long)uVar11 <= (long)uVar6) {
118: uVar6 = uVar11;
119: }
120: uVar7 = *(uint *)(param_2 + 4);
121: lVar9 = (ulong)*(uint *)((long)param_2 + 0x1c) + lVar13;
122: uVar11 = (ulong)uVar7 - lVar9;
123: if ((long)uVar11 <= (long)uVar6) {
124: uVar6 = uVar11;
125: }
126: uVar11 = (ulong)*(uint *)(param_2 + 1) - lVar9;
127: if ((long)uVar6 < (long)uVar11) {
128: uVar11 = uVar6;
129: }
130: } while (0 < (long)uVar11);
131: }
132: }
133: }
134: else {
135: LAB_00149465:
136: uVar7 = *(uint *)(param_2 + 4);
137: }
138: if (uVar7 < uVar4) {
139: if (param_3 <= uVar7) {
140: if (param_5 != 0) goto LAB_001494a1;
141: LAB_0014954c:
142: if (*(int *)((long)param_2 + 0x24) == 0) {
143: ppcVar3 = (code **)*param_1;
144: *(undefined4 *)(ppcVar3 + 5) = 0x16;
145: (**ppcVar3)(param_1);
146: iVar5 = *(int *)((long)param_2 + 0x1c);
147: goto LAB_00149514;
148: }
149: iVar5 = *(int *)((long)param_2 + 0x1c);
150: LAB_001494b5:
151: uVar7 = uVar7 - iVar5;
152: uVar2 = *(undefined4 *)((long)param_2 + 0xc);
153: if (uVar7 < uVar4 - iVar5) {
154: lVar13 = (ulong)uVar7 * 8;
155: do {
156: puVar1 = (undefined8 *)(*param_2 + lVar13);
157: lVar13 = lVar13 + 8;
158: FUN_00148a80(*puVar1,uVar2);
159: } while (((ulong)uVar7 + 1 + (ulong)(((uVar4 - iVar5) - 1) - uVar7)) * 8 != lVar13);
160: goto LAB_00149500;
161: }
162: goto LAB_00149504;
163: }
164: uVar7 = param_3;
165: if (param_5 == 0) goto LAB_0014954c;
166: ppcVar3 = (code **)*param_1;
167: *(undefined4 *)(ppcVar3 + 5) = 0x16;
168: (**ppcVar3)(param_1);
169: LAB_001494a1:
170: iVar5 = *(int *)((long)param_2 + 0x1c);
171: *(uint *)(param_2 + 4) = uVar4;
172: if (*(int *)((long)param_2 + 0x24) != 0) goto LAB_001494b5;
173: }
174: else {
175: LAB_00149500:
176: iVar5 = *(int *)((long)param_2 + 0x1c);
177: LAB_00149504:
178: if (param_5 == 0) goto LAB_00149514;
179: }
180: *(undefined4 *)(param_2 + 5) = 1;
181: LAB_00149514:
182: return *param_2 + (ulong)(param_3 - iVar5) * 8;
183: }
184: 
