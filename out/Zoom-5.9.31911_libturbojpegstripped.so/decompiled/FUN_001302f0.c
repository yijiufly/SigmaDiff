1: 
2: void FUN_001302f0(code **param_1)
3: 
4: {
5: undefined4 uVar1;
6: code *pcVar2;
7: code *pcVar3;
8: code *pcVar4;
9: int iVar5;
10: long lVar6;
11: long lVar7;
12: int iVar8;
13: int iVar9;
14: int *piVar10;
15: bool bVar11;
16: bool bVar12;
17: code **ppcStack72;
18: int iStack64;
19: 
20: iVar5 = *(int *)((long)param_1 + 0x20c);
21: pcVar2 = param_1[0x4a];
22: bVar11 = iVar5 != 0;
23: if (bVar11) {
24: if (*(int *)(param_1 + 0x42) < iVar5) {
25: bVar12 = true;
26: }
27: else {
28: bVar12 = *(int *)(param_1 + 0x36) != 1 || 0x3f < *(int *)(param_1 + 0x42);
29: }
30: }
31: else {
32: bVar12 = *(int *)(param_1 + 0x42) != 0;
33: }
34: if ((((*(int *)((long)param_1 + 0x214) != 0) &&
35: (*(int *)(param_1 + 0x43) != *(int *)((long)param_1 + 0x214) + -1)) ||
36: (0xd < *(int *)(param_1 + 0x43))) || (bVar12)) {
37: pcVar3 = *param_1;
38: *(int *)(pcVar3 + 0x2c) = iVar5;
39: *(undefined4 *)(pcVar3 + 0x28) = 0x10;
40: *(undefined4 *)(*param_1 + 0x30) = *(undefined4 *)(param_1 + 0x42);
41: *(undefined4 *)(*param_1 + 0x34) = *(undefined4 *)((long)param_1 + 0x214);
42: *(undefined4 *)(*param_1 + 0x38) = *(undefined4 *)(param_1 + 0x43);
43: (**(code **)*param_1)();
44: }
45: iVar5 = *(int *)(param_1 + 0x36);
46: if (0 < iVar5) {
47: iStack64 = 0;
48: ppcStack72 = param_1;
49: do {
50: iVar5 = *(int *)(ppcStack72[0x37] + 4);
51: pcVar3 = param_1[0x18];
52: if ((bVar11) && (*(int *)(pcVar3 + (long)iVar5 * 0x100) < 0)) {
53: pcVar4 = *param_1;
54: *(int *)(pcVar4 + 0x2c) = iVar5;
55: *(undefined4 *)(pcVar4 + 0x28) = 0x73;
56: *(undefined4 *)(*param_1 + 0x30) = 0;
57: (**(code **)(*param_1 + 8))(param_1,0xffffffff);
58: }
59: iVar9 = *(int *)((long)param_1 + 0x20c);
60: piVar10 = (int *)((long)(pcVar3 + (long)iVar5 * 0x100) + (long)iVar9 * 4);
61: if (iVar9 <= *(int *)(param_1 + 0x42)) {
62: do {
63: iVar8 = 0;
64: if (-1 < *piVar10) {
65: iVar8 = *piVar10;
66: }
67: if (*(int *)((long)param_1 + 0x214) != iVar8) {
68: pcVar3 = *param_1;
69: *(int *)(pcVar3 + 0x2c) = iVar5;
70: *(undefined4 *)(pcVar3 + 0x28) = 0x73;
71: *(int *)(*param_1 + 0x30) = iVar9;
72: (**(code **)(*param_1 + 8))();
73: }
74: iVar9 = iVar9 + 1;
75: *piVar10 = *(int *)(param_1 + 0x43);
76: piVar10 = piVar10 + 1;
77: } while (iVar9 <= *(int *)(param_1 + 0x42));
78: }
79: iStack64 = iStack64 + 1;
80: iVar5 = *(int *)(param_1 + 0x36);
81: ppcStack72 = ppcStack72 + 1;
82: } while (iStack64 < iVar5);
83: }
84: if (*(int *)((long)param_1 + 0x214) == 0) {
85: if (bVar11) {
86: *(code **)(pcVar2 + 8) = FUN_00130cb0;
87: LAB_001305dc:
88: lVar6 = 0;
89: if (0 < iVar5) {
90: do {
91: lVar7 = (long)*(int *)(param_1[lVar6 + 0x37] + 0x18) + 8;
92: FUN_00125450(param_1,0,*(int *)(param_1[lVar6 + 0x37] + 0x18),pcVar2 + lVar7 * 8);
93: *(undefined8 *)(pcVar2 + 0x60) = *(undefined8 *)(pcVar2 + lVar7 * 8);
94: *(undefined4 *)(pcVar2 + lVar6 * 4 + 0x2c) = 0;
95: iVar5 = (int)lVar6 + 1;
96: lVar6 = lVar6 + 1;
97: } while (*(int *)(param_1 + 0x36) != iVar5 && iVar5 <= *(int *)(param_1 + 0x36));
98: }
99: goto LAB_0013057c;
100: }
101: *(code **)(pcVar2 + 8) = FUN_00131170;
102: }
103: else {
104: if (bVar11) {
105: *(code **)(pcVar2 + 8) = FUN_00130700;
106: goto LAB_001305dc;
107: }
108: *(code **)(pcVar2 + 8) = FUN_00130fe0;
109: }
110: if (0 < iVar5) {
111: if (*(int *)((long)param_1 + 0x214) == 0) {
112: FUN_00125450(param_1);
113: }
114: iVar5 = *(int *)(param_1 + 0x36);
115: *(undefined4 *)(pcVar2 + 0x2c) = 0;
116: if (1 < iVar5) {
117: if (*(int *)((long)param_1 + 0x214) == 0) {
118: FUN_00125450(param_1,1);
119: }
120: iVar5 = *(int *)(param_1 + 0x36);
121: *(undefined4 *)(pcVar2 + 0x30) = 0;
122: if (2 < iVar5) {
123: if (*(int *)((long)param_1 + 0x214) == 0) {
124: FUN_00125450(param_1,1,*(int *)(param_1[0x39] + 0x14),
125: pcVar2 + (long)*(int *)(param_1[0x39] + 0x14) * 8 + 0x40);
126: }
127: iVar5 = *(int *)(param_1 + 0x36);
128: *(undefined4 *)(pcVar2 + 0x34) = 0;
129: if (3 < iVar5) {
130: if (*(int *)((long)param_1 + 0x214) == 0) {
131: FUN_00125450(param_1,1,*(int *)(param_1[0x3a] + 0x14),
132: pcVar2 + (long)*(int *)(param_1[0x3a] + 0x14) * 8 + 0x40);
133: }
134: *(undefined4 *)(pcVar2 + 0x38) = 0;
135: }
136: }
137: }
138: }
139: LAB_0013057c:
140: uVar1 = *(undefined4 *)(param_1 + 0x2e);
141: *(undefined4 *)(pcVar2 + 0x20) = 0;
142: *(undefined8 *)(pcVar2 + 0x18) = 0;
143: *(undefined4 *)(pcVar2 + 0x10) = 0;
144: *(undefined4 *)(pcVar2 + 0x28) = 0;
145: *(undefined4 *)(pcVar2 + 0x3c) = uVar1;
146: return;
147: }
148: 
