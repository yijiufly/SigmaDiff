1: 
2: long FUN_0013c7b0(code **param_1,long *param_2,uint param_3,uint param_4,int param_5)
3: 
4: {
5: undefined4 uVar1;
6: code **ppcVar2;
7: uint uVar3;
8: ulong uVar4;
9: ulong uVar5;
10: ulong uVar6;
11: int iVar7;
12: ulong uVar8;
13: long lVar9;
14: uint uVar10;
15: uint uVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: 
20: uVar3 = param_3 + param_4;
21: if (((*(uint *)(param_2 + 1) <= uVar3 && uVar3 != *(uint *)(param_2 + 1)) ||
22: (*(uint *)(param_2 + 2) <= param_4 && param_4 != *(uint *)(param_2 + 2))) || (*param_2 == 0))
23: {
24: ppcVar2 = (code **)*param_1;
25: *(undefined4 *)(ppcVar2 + 5) = 0x16;
26: (**ppcVar2)();
27: }
28: uVar11 = *(uint *)((long)param_2 + 0x1c);
29: if ((param_3 < uVar11) || (*(int *)((long)param_2 + 0x14) + uVar11 < uVar3)) {
30: if (*(int *)((long)param_2 + 0x2c) == 0) {
31: ppcVar2 = (code **)*param_1;
32: *(undefined4 *)(ppcVar2 + 5) = 0x45;
33: (**ppcVar2)();
34: uVar11 = *(uint *)((long)param_2 + 0x1c);
35: }
36: if (*(int *)(param_2 + 5) == 0) {
37: uVar8 = (ulong)*(uint *)((long)param_2 + 0x14);
38: uVar6 = (ulong)*(uint *)((long)param_2 + 0xc);
39: uVar10 = *(uint *)(param_2 + 4);
40: }
41: else {
42: uVar6 = (ulong)*(uint *)((long)param_2 + 0xc);
43: uVar8 = (ulong)*(uint *)((long)param_2 + 0x14);
44: uVar10 = *(uint *)(param_2 + 4);
45: if (uVar8 != 0) {
46: uVar4 = (ulong)*(uint *)(param_2 + 3);
47: if (uVar8 <= *(uint *)(param_2 + 3)) {
48: uVar4 = uVar8;
49: }
50: uVar5 = (ulong)*(uint *)(param_2 + 1) - (ulong)uVar11;
51: if ((long)uVar5 < (long)uVar4) {
52: uVar4 = uVar5;
53: }
54: uVar5 = (ulong)uVar10 - (ulong)uVar11;
55: if ((long)uVar4 <= (long)uVar5) {
56: uVar5 = uVar4;
57: }
58: if (0 < (long)uVar5) {
59: lVar13 = 0;
60: do {
61: (*(code *)param_2[8])(param_1,param_2 + 7,*(undefined8 *)(*param_2 + lVar13 * 8));
62: uVar6 = (ulong)*(uint *)(param_2 + 3);
63: uVar8 = (ulong)*(uint *)((long)param_2 + 0x14);
64: lVar13 = lVar13 + uVar6;
65: if ((long)uVar8 <= lVar13) {
66: uVar6 = (ulong)*(uint *)((long)param_2 + 0xc);
67: uVar11 = *(uint *)((long)param_2 + 0x1c);
68: uVar10 = *(uint *)(param_2 + 4);
69: goto LAB_0013caf1;
70: }
71: uVar11 = *(uint *)((long)param_2 + 0x1c);
72: uVar10 = *(uint *)(param_2 + 4);
73: uVar4 = uVar8 - lVar13;
74: if ((long)uVar6 < (long)(uVar8 - lVar13)) {
75: uVar4 = uVar6;
76: }
77: uVar6 = (ulong)uVar10 - ((ulong)uVar11 + lVar13);
78: if ((long)uVar6 < (long)uVar4) {
79: uVar4 = uVar6;
80: }
81: uVar6 = (ulong)*(uint *)(param_2 + 1) - ((ulong)uVar11 + lVar13);
82: if ((long)uVar4 <= (long)uVar6) {
83: uVar6 = uVar4;
84: }
85: } while (0 < (long)uVar6);
86: uVar6 = (ulong)*(uint *)((long)param_2 + 0xc);
87: }
88: }
89: LAB_0013caf1:
90: *(undefined4 *)(param_2 + 5) = 0;
91: }
92: if (uVar11 < param_3) {
93: *(uint *)((long)param_2 + 0x1c) = param_3;
94: uVar11 = param_3;
95: }
96: else {
97: uVar11 = 0;
98: if (-1 < (long)(uVar3 - uVar8)) {
99: uVar11 = (uint)(uVar3 - uVar8);
100: }
101: *(uint *)((long)param_2 + 0x1c) = uVar11;
102: }
103: uVar4 = (ulong)uVar11;
104: if (uVar8 != 0) {
105: if (*(uint *)(param_2 + 3) < uVar8) {
106: uVar8 = (ulong)*(uint *)(param_2 + 3);
107: }
108: if ((long)(*(uint *)(param_2 + 1) - uVar4) < (long)uVar8) {
109: uVar8 = *(uint *)(param_2 + 1) - uVar4;
110: }
111: if ((long)(uVar10 - uVar4) < (long)uVar8) {
112: uVar8 = uVar10 - uVar4;
113: }
114: if (0 < (long)uVar8) {
115: lVar14 = 0;
116: lVar13 = uVar4 * uVar6;
117: do {
118: lVar9 = uVar8 * uVar6;
119: (*(code *)param_2[7])
120: (param_1,param_2 + 7,*(undefined8 *)(*param_2 + lVar14 * 8),lVar13,lVar9);
121: uVar4 = (ulong)*(uint *)(param_2 + 3);
122: lVar14 = lVar14 + uVar4;
123: if ((long)(ulong)*(uint *)((long)param_2 + 0x14) <= lVar14) goto LAB_0013c907;
124: uVar10 = *(uint *)(param_2 + 4);
125: uVar8 = (ulong)*(uint *)((long)param_2 + 0x14) - lVar14;
126: if ((long)uVar8 <= (long)uVar4) {
127: uVar4 = uVar8;
128: }
129: lVar12 = (ulong)*(uint *)((long)param_2 + 0x1c) + lVar14;
130: uVar8 = (ulong)uVar10 - lVar12;
131: if ((long)uVar8 < (long)uVar4) {
132: uVar4 = uVar8;
133: }
134: uVar8 = (ulong)*(uint *)(param_2 + 1) - lVar12;
135: if ((long)uVar4 <= (long)uVar8) {
136: uVar8 = uVar4;
137: }
138: lVar13 = lVar13 + lVar9;
139: } while (0 < (long)uVar8);
140: }
141: }
142: }
143: else {
144: LAB_0013c907:
145: uVar10 = *(uint *)(param_2 + 4);
146: }
147: if (uVar10 < uVar3) {
148: if (uVar10 < param_3) {
149: uVar10 = param_3;
150: if (param_5 != 0) {
151: param_1 = (code **)*param_1;
152: *(undefined4 *)(param_1 + 5) = 0x16;
153: (**param_1)();
154: goto LAB_0013c95a;
155: }
156: LAB_0013c92b:
157: if (*(int *)((long)param_2 + 0x24) == 0) {
158: ppcVar2 = (code **)*param_1;
159: *(undefined4 *)(ppcVar2 + 5) = 0x16;
160: (**ppcVar2)(param_1);
161: iVar7 = *(int *)((long)param_2 + 0x1c);
162: goto LAB_0013c9bd;
163: }
164: LAB_0013c96d:
165: iVar7 = *(int *)((long)param_2 + 0x1c);
166: uVar1 = *(undefined4 *)((long)param_2 + 0xc);
167: uVar10 = uVar10 - iVar7;
168: if (uVar10 < uVar3 - iVar7) {
169: do {
170: uVar8 = (ulong)uVar10;
171: uVar10 = uVar10 + 1;
172: FUN_0013bed0(*(undefined8 *)(*param_2 + uVar8 * 8),uVar1);
173: } while (uVar10 < uVar3 - iVar7);
174: goto LAB_0013c9a9;
175: }
176: goto LAB_0013c9ad;
177: }
178: if (param_5 == 0) goto LAB_0013c92b;
179: LAB_0013c95a:
180: *(uint *)(param_2 + 4) = uVar3;
181: if (*(int *)((long)param_2 + 0x24) != 0) goto LAB_0013c96d;
182: iVar7 = *(int *)((long)param_2 + 0x1c);
183: }
184: else {
185: LAB_0013c9a9:
186: iVar7 = *(int *)((long)param_2 + 0x1c);
187: LAB_0013c9ad:
188: if (param_5 == 0) goto LAB_0013c9bd;
189: }
190: *(undefined4 *)(param_2 + 5) = 1;
191: LAB_0013c9bd:
192: return *param_2 + (ulong)(param_3 - iVar7) * 8;
193: }
194: 
