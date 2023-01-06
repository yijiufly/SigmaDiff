1: 
2: void FUN_001417a0(long param_1)
3: 
4: {
5: bool bVar1;
6: code **ppcVar2;
7: undefined8 *puVar3;
8: ulong uVar4;
9: int iVar5;
10: uint uVar6;
11: ulong uVar7;
12: code **ppcVar8;
13: code **ppcVar9;
14: undefined8 *puVar10;
15: undefined8 *puVar11;
16: int iVar12;
17: bool bVar13;
18: byte bVar14;
19: 
20: bVar14 = 0;
21: ppcVar2 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x158);
22: *(code ***)(param_1 + 0x250) = ppcVar2;
23: ppcVar8 = ppcVar2 + 10;
24: uVar7 = 0x80;
25: iVar12 = 0x80;
26: *ppcVar2 = FUN_00140180;
27: bVar13 = ((ulong)ppcVar8 & 1) != 0;
28: if (bVar13) {
29: ppcVar8 = (code **)((long)ppcVar2 + 0x51);
30: *(undefined *)(ppcVar2 + 10) = 0;
31: uVar7 = 0x7f;
32: iVar12 = 0x7f;
33: }
34: if (((ulong)ppcVar8 & 2) == 0) {
35: uVar6 = (uint)uVar7;
36: }
37: else {
38: uVar6 = iVar12 - 2;
39: uVar7 = (ulong)uVar6;
40: *(undefined2 *)ppcVar8 = 0;
41: ppcVar8 = (code **)((long)ppcVar8 + 2);
42: }
43: if (((ulong)ppcVar8 & 4) != 0) {
44: *(undefined4 *)ppcVar8 = 0;
45: uVar7 = (ulong)(uVar6 - 4);
46: ppcVar8 = (code **)((long)ppcVar8 + 4);
47: }
48: uVar4 = uVar7 >> 3;
49: while (uVar4 != 0) {
50: uVar4 = uVar4 - 1;
51: *ppcVar8 = (code *)0x0;
52: ppcVar8 = ppcVar8 + (ulong)bVar14 * -2 + 1;
53: }
54: if ((uVar7 & 4) != 0) {
55: *(undefined4 *)ppcVar8 = 0;
56: ppcVar8 = (code **)((long)ppcVar8 + 4);
57: }
58: ppcVar9 = ppcVar8;
59: if ((uVar7 & 2) != 0) {
60: ppcVar9 = (code **)((long)ppcVar8 + 2);
61: *(undefined2 *)ppcVar8 = 0;
62: }
63: if (bVar13) {
64: *(undefined *)ppcVar9 = 0;
65: }
66: ppcVar8 = ppcVar2 + 0x1a;
67: uVar7 = 0x80;
68: iVar12 = 0x80;
69: bVar13 = ((ulong)ppcVar8 & 1) != 0;
70: if (bVar13) {
71: ppcVar8 = (code **)((long)ppcVar2 + 0xd1);
72: *(undefined *)(ppcVar2 + 0x1a) = 0;
73: uVar7 = 0x7f;
74: iVar12 = 0x7f;
75: }
76: ppcVar9 = ppcVar8;
77: if (((ulong)ppcVar8 & 2) != 0) {
78: ppcVar9 = (code **)((long)ppcVar8 + 2);
79: uVar7 = (ulong)(iVar12 - 2);
80: *(undefined2 *)ppcVar8 = 0;
81: }
82: if (((ulong)ppcVar9 & 4) != 0) {
83: *(undefined4 *)ppcVar9 = 0;
84: uVar7 = (ulong)((int)uVar7 - 4);
85: ppcVar9 = (code **)((long)ppcVar9 + 4);
86: }
87: uVar4 = uVar7 >> 3;
88: while (uVar4 != 0) {
89: uVar4 = uVar4 - 1;
90: *ppcVar9 = (code *)0x0;
91: ppcVar9 = ppcVar9 + (ulong)bVar14 * -2 + 1;
92: }
93: if ((uVar7 & 4) != 0) {
94: *(undefined4 *)ppcVar9 = 0;
95: ppcVar9 = (code **)((long)ppcVar9 + 4);
96: }
97: ppcVar8 = ppcVar9;
98: if ((uVar7 & 2) != 0) {
99: ppcVar8 = (code **)((long)ppcVar9 + 2);
100: *(undefined2 *)ppcVar9 = 0;
101: }
102: if (bVar13) {
103: *(undefined *)ppcVar8 = 0;
104: }
105: *(undefined *)(ppcVar2 + 0x2a) = 0x71;
106: if (*(int *)(param_1 + 0x138) != 0) {
107: puVar3 = (undefined8 *)
108: (***(code ***)(param_1 + 8))(param_1,1,(long)(*(int *)(param_1 + 0x38) << 6) * 4);
109: *(undefined8 **)(param_1 + 0xc0) = puVar3;
110: if (0 < *(int *)(param_1 + 0x38)) {
111: iVar12 = 0;
112: do {
113: uVar7 = 0x100;
114: bVar13 = false;
115: iVar5 = 0x100;
116: if (((ulong)puVar3 & 1) == 0) {
117: puVar11 = puVar3;
118: puVar10 = puVar3;
119: bVar1 = false;
120: if (((ulong)puVar3 & 2) != 0) goto LAB_00141950;
121: LAB_001418de:
122: uVar6 = (uint)uVar7;
123: }
124: else {
125: puVar11 = (undefined8 *)((long)puVar3 + 1);
126: *(undefined *)puVar3 = 0xff;
127: uVar7 = 0xff;
128: bVar13 = true;
129: iVar5 = 0xff;
130: puVar10 = puVar11;
131: bVar1 = true;
132: if (((ulong)puVar11 & 2) == 0) goto LAB_001418de;
133: LAB_00141950:
134: bVar13 = bVar1;
135: puVar11 = (undefined8 *)((long)puVar10 + 2);
136: uVar6 = iVar5 - 2;
137: uVar7 = (ulong)uVar6;
138: *(undefined2 *)puVar10 = 0xffff;
139: }
140: if (((ulong)puVar11 & 4) != 0) {
141: *(undefined4 *)puVar11 = 0xffffffff;
142: uVar7 = (ulong)(uVar6 - 4);
143: puVar11 = (undefined8 *)((long)puVar11 + 4);
144: }
145: uVar4 = uVar7 >> 3;
146: while (uVar4 != 0) {
147: uVar4 = uVar4 - 1;
148: *puVar11 = 0xffffffffffffffff;
149: puVar11 = puVar11 + (ulong)bVar14 * -2 + 1;
150: }
151: if ((uVar7 & 4) != 0) {
152: *(undefined4 *)puVar11 = 0xffffffff;
153: puVar11 = (undefined8 *)((long)puVar11 + 4);
154: }
155: puVar10 = puVar11;
156: if ((uVar7 & 2) != 0) {
157: puVar10 = (undefined8 *)((long)puVar11 + 2);
158: *(undefined2 *)puVar11 = 0xffff;
159: }
160: if (bVar13) {
161: *(undefined *)puVar10 = 0xff;
162: }
163: puVar3 = puVar3 + 0x20;
164: iVar12 = iVar12 + 1;
165: } while (*(int *)(param_1 + 0x38) != iVar12 && iVar12 <= *(int *)(param_1 + 0x38));
166: }
167: }
168: return;
169: }
170: 
