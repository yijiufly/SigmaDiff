1: 
2: long FUN_0013c410(code **param_1,long *param_2,uint param_3,uint param_4,int param_5)
3: 
4: {
5: code **ppcVar1;
6: uint uVar2;
7: ulong uVar3;
8: ulong uVar4;
9: int iVar5;
10: ulong uVar6;
11: long lVar7;
12: uint uVar8;
13: long lVar9;
14: uint uVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: 
19: uVar2 = param_3 + param_4;
20: if (((*(uint *)(param_2 + 1) <= uVar2 && uVar2 != *(uint *)(param_2 + 1)) ||
21: (*(uint *)(param_2 + 2) <= param_4 && param_4 != *(uint *)(param_2 + 2))) || (*param_2 == 0))
22: {
23: ppcVar1 = (code **)*param_1;
24: *(undefined4 *)(ppcVar1 + 5) = 0x16;
25: (**ppcVar1)();
26: }
27: uVar10 = *(uint *)((long)param_2 + 0x1c);
28: if ((param_3 < uVar10) || (*(int *)((long)param_2 + 0x14) + uVar10 < uVar2)) {
29: if (*(int *)((long)param_2 + 0x2c) == 0) {
30: ppcVar1 = (code **)*param_1;
31: *(undefined4 *)(ppcVar1 + 5) = 0x45;
32: (**ppcVar1)();
33: uVar10 = *(uint *)((long)param_2 + 0x1c);
34: }
35: if (*(int *)(param_2 + 5) == 0) {
36: uVar6 = (ulong)*(uint *)((long)param_2 + 0x14);
37: uVar8 = *(uint *)(param_2 + 4);
38: lVar9 = (ulong)*(uint *)((long)param_2 + 0xc) << 7;
39: }
40: else {
41: uVar6 = (ulong)*(uint *)((long)param_2 + 0x14);
42: uVar8 = *(uint *)(param_2 + 4);
43: lVar9 = (ulong)*(uint *)((long)param_2 + 0xc) * 0x80;
44: if (uVar6 != 0) {
45: uVar4 = (ulong)*(uint *)(param_2 + 3);
46: if (uVar6 <= *(uint *)(param_2 + 3)) {
47: uVar4 = uVar6;
48: }
49: uVar3 = (ulong)*(uint *)(param_2 + 1) - (ulong)uVar10;
50: if ((long)uVar3 < (long)uVar4) {
51: uVar4 = uVar3;
52: }
53: uVar3 = (ulong)uVar8 - (ulong)uVar10;
54: if ((long)uVar4 <= (long)uVar3) {
55: uVar3 = uVar4;
56: }
57: if (0 < (long)uVar3) {
58: lVar9 = 0;
59: do {
60: (*(code *)param_2[8])(param_1,param_2 + 7,*(undefined8 *)(*param_2 + lVar9 * 8));
61: uVar4 = (ulong)*(uint *)(param_2 + 3);
62: uVar6 = (ulong)*(uint *)((long)param_2 + 0x14);
63: lVar9 = lVar9 + uVar4;
64: if ((long)uVar6 <= lVar9) {
65: uVar10 = *(uint *)((long)param_2 + 0x1c);
66: uVar8 = *(uint *)(param_2 + 4);
67: lVar9 = (ulong)*(uint *)((long)param_2 + 0xc) << 7;
68: goto LAB_0013c75d;
69: }
70: uVar10 = *(uint *)((long)param_2 + 0x1c);
71: uVar8 = *(uint *)(param_2 + 4);
72: uVar3 = uVar6 - lVar9;
73: if ((long)uVar4 < (long)(uVar6 - lVar9)) {
74: uVar3 = uVar4;
75: }
76: uVar4 = (ulong)uVar8 - ((ulong)uVar10 + lVar9);
77: if ((long)uVar4 < (long)uVar3) {
78: uVar3 = uVar4;
79: }
80: uVar4 = (ulong)*(uint *)(param_2 + 1) - ((ulong)uVar10 + lVar9);
81: if ((long)uVar3 <= (long)uVar4) {
82: uVar4 = uVar3;
83: }
84: } while (0 < (long)uVar4);
85: lVar9 = (ulong)*(uint *)((long)param_2 + 0xc) << 7;
86: }
87: }
88: LAB_0013c75d:
89: *(undefined4 *)(param_2 + 5) = 0;
90: }
91: if (uVar10 < param_3) {
92: *(uint *)((long)param_2 + 0x1c) = param_3;
93: uVar10 = param_3;
94: }
95: else {
96: uVar10 = 0;
97: if (-1 < (long)(uVar2 - uVar6)) {
98: uVar10 = (uint)(uVar2 - uVar6);
99: }
100: *(uint *)((long)param_2 + 0x1c) = uVar10;
101: }
102: uVar4 = (ulong)uVar10;
103: if (uVar6 != 0) {
104: if (*(uint *)(param_2 + 3) < uVar6) {
105: uVar6 = (ulong)*(uint *)(param_2 + 3);
106: }
107: if ((long)(*(uint *)(param_2 + 1) - uVar4) < (long)uVar6) {
108: uVar6 = *(uint *)(param_2 + 1) - uVar4;
109: }
110: if ((long)(uVar8 - uVar4) < (long)uVar6) {
111: uVar6 = uVar8 - uVar4;
112: }
113: if (0 < (long)uVar6) {
114: lVar13 = 0;
115: lVar12 = uVar4 * lVar9;
116: do {
117: lVar7 = uVar6 * lVar9;
118: (*(code *)param_2[7])
119: (param_1,param_2 + 7,*(undefined8 *)(*param_2 + lVar13 * 8),lVar12,lVar7);
120: uVar4 = (ulong)*(uint *)(param_2 + 3);
121: lVar13 = lVar13 + uVar4;
122: if ((long)(ulong)*(uint *)((long)param_2 + 0x14) <= lVar13) goto LAB_0013c567;
123: uVar8 = *(uint *)(param_2 + 4);
124: uVar6 = (ulong)*(uint *)((long)param_2 + 0x14) - lVar13;
125: if ((long)uVar6 <= (long)uVar4) {
126: uVar4 = uVar6;
127: }
128: lVar11 = (ulong)*(uint *)((long)param_2 + 0x1c) + lVar13;
129: uVar6 = (ulong)uVar8 - lVar11;
130: if ((long)uVar6 < (long)uVar4) {
131: uVar4 = uVar6;
132: }
133: uVar6 = (ulong)*(uint *)(param_2 + 1) - lVar11;
134: if ((long)uVar4 <= (long)uVar6) {
135: uVar6 = uVar4;
136: }
137: lVar12 = lVar12 + lVar7;
138: } while (0 < (long)uVar6);
139: }
140: }
141: }
142: else {
143: LAB_0013c567:
144: uVar8 = *(uint *)(param_2 + 4);
145: }
146: if (uVar8 < uVar2) {
147: if (uVar8 < param_3) {
148: uVar8 = param_3;
149: if (param_5 != 0) {
150: param_1 = (code **)*param_1;
151: *(undefined4 *)(param_1 + 5) = 0x16;
152: (**param_1)();
153: goto LAB_0013c5ba;
154: }
155: LAB_0013c58b:
156: if (*(int *)((long)param_2 + 0x24) == 0) {
157: ppcVar1 = (code **)*param_1;
158: *(undefined4 *)(ppcVar1 + 5) = 0x16;
159: (**ppcVar1)(param_1);
160: iVar5 = *(int *)((long)param_2 + 0x1c);
161: goto LAB_0013c61d;
162: }
163: LAB_0013c5cd:
164: iVar5 = *(int *)((long)param_2 + 0x1c);
165: uVar10 = *(uint *)((long)param_2 + 0xc);
166: uVar8 = uVar8 - iVar5;
167: if (uVar8 < uVar2 - iVar5) {
168: do {
169: uVar6 = (ulong)uVar8;
170: uVar8 = uVar8 + 1;
171: FUN_0013bed0(*(undefined8 *)(*param_2 + uVar6 * 8),(ulong)uVar10 << 7);
172: } while (uVar8 < uVar2 - iVar5);
173: goto LAB_0013c609;
174: }
175: goto LAB_0013c60d;
176: }
177: if (param_5 == 0) goto LAB_0013c58b;
178: LAB_0013c5ba:
179: *(uint *)(param_2 + 4) = uVar2;
180: if (*(int *)((long)param_2 + 0x24) != 0) goto LAB_0013c5cd;
181: iVar5 = *(int *)((long)param_2 + 0x1c);
182: }
183: else {
184: LAB_0013c609:
185: iVar5 = *(int *)((long)param_2 + 0x1c);
186: LAB_0013c60d:
187: if (param_5 == 0) goto LAB_0013c61d;
188: }
189: *(undefined4 *)(param_2 + 5) = 1;
190: LAB_0013c61d:
191: return *param_2 + (ulong)(param_3 - iVar5) * 8;
192: }
193: 
