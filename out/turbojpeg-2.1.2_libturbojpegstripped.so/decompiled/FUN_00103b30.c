1: 
2: undefined8 FUN_00103b30(long param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: long lVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: long lVar6;
11: undefined2 *puVar7;
12: undefined8 uVar8;
13: long lVar9;
14: int iVar10;
15: int iVar11;
16: int iVar12;
17: int iStack112;
18: long lStack96;
19: uint uStack80;
20: int iStack68;
21: 
22: lVar6 = *(long *)(param_1 + 0x1c8);
23: uVar1 = *(int *)(param_1 + 0x168) - 1;
24: iVar3 = *(int *)(param_1 + 0x140);
25: iStack68 = *(int *)(lVar6 + 0x18);
26: iVar12 = *(int *)(lVar6 + 0x1c);
27: lVar9 = lVar6;
28: if (iStack68 < iVar12) {
29: uStack80 = *(uint *)(lVar6 + 0x14);
30: iStack112 = iStack68 << 3;
31: if (uVar1 < uStack80) goto LAB_00103e7a;
32: do {
33: do {
34: iVar12 = 0;
35: lStack96 = 1;
36: if (0 < *(int *)(param_1 + 0x144)) {
37: do {
38: lVar9 = *(long *)(param_1 + 0x140 + lStack96 * 8);
39: if (uStack80 < uVar1) {
40: iVar4 = *(int *)(lVar9 + 0x34);
41: }
42: else {
43: iVar4 = *(int *)(lVar9 + 0x44);
44: }
45: iVar5 = *(int *)(lVar9 + 0x40);
46: if (0 < *(int *)(lVar9 + 0x38)) {
47: iVar10 = 0;
48: do {
49: lVar2 = lVar6 + (long)iVar12 * 8;
50: if ((*(uint *)(lVar6 + 0x10) < iVar3 - 1U) ||
51: (*(int *)(lVar9 + 0x48) != iStack68 + iVar10 &&
52: iStack68 + iVar10 <= *(int *)(lVar9 + 0x48))) {
53: (**(code **)(*(long *)(param_1 + 0x1e8) + 8))
54: (param_1,lVar9,*(undefined8 *)(param_2 + (long)*(int *)(lVar9 + 4) * 8),
55: *(undefined8 *)(lVar2 + 0x20),iStack112 + iVar10 * 8,uStack80 * iVar5,
56: iVar4);
57: iVar11 = *(int *)(lVar9 + 0x34);
58: if (iVar4 < iVar11) {
59: lVar2 = lVar6 + (long)(iVar4 + iVar12) * 8;
60: FUN_00148a80();
61: iVar11 = *(int *)(lVar9 + 0x34);
62: if ((iVar4 < iVar11) &&
63: (**(undefined2 **)(lVar2 + 0x20) = **(undefined2 **)(lVar2 + 0x18),
64: iVar4 + 1 < iVar11)) {
65: lVar2 = lVar6 + (long)(iVar4 + 1 + iVar12) * 8;
66: **(undefined2 **)(lVar2 + 0x20) = **(undefined2 **)(lVar2 + 0x18);
67: if (iVar4 + 2 < iVar11) {
68: lVar2 = lVar6 + (long)(iVar4 + 2 + iVar12) * 8;
69: **(undefined2 **)(lVar2 + 0x20) = **(undefined2 **)(lVar2 + 0x18);
70: if (iVar4 + 3 < iVar11) {
71: lVar2 = lVar6 + (long)(iVar4 + 3 + iVar12) * 8;
72: **(undefined2 **)(lVar2 + 0x20) = **(undefined2 **)(lVar2 + 0x18);
73: if (iVar4 + 4 < iVar11) {
74: lVar2 = lVar6 + (long)(iVar4 + 4 + iVar12) * 8;
75: **(undefined2 **)(lVar2 + 0x20) = **(undefined2 **)(lVar2 + 0x18);
76: if (iVar4 + 5 < iVar11) {
77: lVar2 = lVar6 + (long)(iVar4 + 5 + iVar12) * 8;
78: **(undefined2 **)(lVar2 + 0x20) = **(undefined2 **)(lVar2 + 0x18);
79: if (iVar4 + 6 < iVar11) {
80: lVar2 = lVar6 + (long)(iVar4 + 6 + iVar12) * 8;
81: **(undefined2 **)(lVar2 + 0x20) = **(undefined2 **)(lVar2 + 0x18);
82: if (iVar4 + 7 < iVar11) {
83: lVar2 = lVar6 + (long)(iVar4 + 7 + iVar12) * 8;
84: **(undefined2 **)(lVar2 + 0x20) = **(undefined2 **)(lVar2 + 0x18);
85: if (iVar4 + 8 < iVar11) {
86: lVar2 = lVar6 + (long)(iVar4 + 8 + iVar12) * 8;
87: **(undefined2 **)(lVar2 + 0x20) =
88: **(undefined2 **)(lVar2 + 0x18);
89: if (iVar4 + 9 < iVar11) {
90: lVar2 = lVar6 + (long)(iVar4 + 9 + iVar12) * 8;
91: **(undefined2 **)(lVar2 + 0x20) =
92: **(undefined2 **)(lVar2 + 0x18);
93: }
94: }
95: }
96: }
97: }
98: }
99: }
100: }
101: }
102: }
103: }
104: else {
105: FUN_00148a80();
106: iVar11 = *(int *)(lVar9 + 0x34);
107: if (0 < iVar11) {
108: puVar7 = *(undefined2 **)(lVar2 + 0x18);
109: **(undefined2 **)(lVar2 + 0x20) = *puVar7;
110: if ((((((iVar11 != 1) &&
111: (**(undefined2 **)(lVar2 + 0x28) = *puVar7, iVar11 != 2)) &&
112: (**(undefined2 **)(lVar2 + 0x30) = *puVar7, iVar11 != 3)) &&
113: ((**(undefined2 **)(lVar2 + 0x38) = *puVar7, iVar11 != 4 &&
114: (**(undefined2 **)(lVar2 + 0x40) = *puVar7, iVar11 != 5)))) &&
115: ((**(undefined2 **)(lVar2 + 0x48) = *puVar7, iVar11 != 6 &&
116: ((**(undefined2 **)(lVar2 + 0x50) = *puVar7, iVar11 != 7 &&
117: (**(undefined2 **)(lVar2 + 0x58) = *puVar7, iVar11 != 8)))))) &&
118: (**(undefined2 **)(lVar2 + 0x60) = *puVar7, iVar11 != 9)) {
119: **(undefined2 **)(lVar2 + 0x68) = *puVar7;
120: }
121: }
122: }
123: iVar12 = iVar12 + iVar11;
124: iVar11 = iVar10 + 1;
125: iVar10 = iVar10 + 1;
126: } while (*(int *)(lVar9 + 0x38) != iVar11 && iVar11 <= *(int *)(lVar9 + 0x38));
127: }
128: iVar4 = (int)lStack96;
129: lStack96 = lStack96 + 1;
130: } while (*(int *)(param_1 + 0x144) != iVar4 && iVar4 <= *(int *)(param_1 + 0x144));
131: }
132: uVar8 = (**(code **)(*(long *)(param_1 + 0x1f0) + 8))();
133: if ((int)uVar8 == 0) {
134: *(int *)(lVar6 + 0x18) = iStack68;
135: *(uint *)(lVar6 + 0x14) = uStack80;
136: return uVar8;
137: }
138: uStack80 = uStack80 + 1;
139: } while (uStack80 <= uVar1);
140: iVar12 = *(int *)(lVar6 + 0x1c);
141: LAB_00103e7a:
142: iStack68 = iStack68 + 1;
143: iStack112 = iStack112 + 8;
144: *(undefined4 *)(lVar6 + 0x14) = 0;
145: uStack80 = 0;
146: } while (iStack68 < iVar12);
147: lVar9 = *(long *)(param_1 + 0x1c8);
148: }
149: *(int *)(lVar6 + 0x10) = *(int *)(lVar6 + 0x10) + 1;
150: if (*(int *)(param_1 + 0x144) < 2) {
151: if (*(uint *)(lVar9 + 0x10) < *(int *)(param_1 + 0x140) - 1U) {
152: *(undefined4 *)(lVar9 + 0x1c) = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0xc);
153: }
154: else {
155: *(undefined4 *)(lVar9 + 0x1c) = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0x48);
156: }
157: }
158: else {
159: *(undefined4 *)(lVar9 + 0x1c) = 1;
160: }
161: *(undefined8 *)(lVar9 + 0x14) = 0;
162: return 1;
163: }
164: 
