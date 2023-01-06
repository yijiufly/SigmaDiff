1: 
2: void FUN_001395a0(code **param_1)
3: 
4: {
5: undefined8 *puVar1;
6: long lVar2;
7: int iVar3;
8: int iVar4;
9: code *pcVar5;
10: long lVar6;
11: undefined8 uVar7;
12: long lVar8;
13: code *pcVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: undefined *puVar13;
18: int iVar14;
19: 
20: pcVar9 = param_1[0x4e];
21: param_1[0x14] = *(code **)(pcVar9 + 0x20);
22: *(undefined4 *)((long)param_1 + 0x9c) = *(undefined4 *)(pcVar9 + 0x28);
23: iVar4 = *(int *)(param_1 + 0xe);
24: if (iVar4 == 1) {
25: iVar4 = *(int *)(param_1 + 0x12);
26: pcVar5 = FUN_00139460;
27: *(undefined4 *)(pcVar9 + 0x4c) = 0;
28: if (iVar4 != 3) {
29: pcVar5 = FUN_00139b00;
30: }
31: *(code **)(pcVar9 + 8) = pcVar5;
32: if (*(int *)(pcVar9 + 0x38) == 0) {
33: FUN_00139170();
34: }
35: if ((*(long *)(pcVar9 + 0x50) == 0) && (pcVar9 = param_1[0x4e], 0 < *(int *)(param_1 + 0x12))) {
36: lVar10 = 0;
37: do {
38: iVar14 = (int)lVar10;
39: iVar4 = *(int *)(pcVar9 + lVar10 * 4 + 0x3c);
40: if (iVar14 == 0) {
41: LAB_00139731:
42: lVar6 = (**(code **)param_1[1])(param_1,1,0x400);
43: puVar13 = &DAT_0018b100;
44: lVar11 = (long)(iVar4 + -1) << 9;
45: lVar12 = lVar6;
46: do {
47: lVar8 = 0;
48: do {
49: lVar2 = (ulong)(byte)puVar13[lVar8] * -0x1fe + 0xfe01;
50: if (lVar2 < 0) {
51: iVar4 = -(int)(-lVar2 / lVar11);
52: }
53: else {
54: iVar4 = (int)(lVar2 / lVar11);
55: }
56: *(int *)(lVar12 + lVar8 * 4) = iVar4;
57: lVar8 = lVar8 + 1;
58: } while (lVar8 != 0x10);
59: lVar12 = lVar12 + 0x40;
60: puVar13 = puVar13 + 0x10;
61: } while (lVar12 != lVar6 + 0x400);
62: }
63: else {
64: if (iVar4 == *(int *)(pcVar9 + 0x3c)) {
65: lVar6 = 0;
66: }
67: else {
68: if (iVar14 == 1) goto LAB_00139731;
69: if (iVar4 == *(int *)(pcVar9 + 0x40)) {
70: lVar6 = 1;
71: }
72: else {
73: if (iVar14 == 2) goto LAB_00139731;
74: if (iVar4 == *(int *)(pcVar9 + 0x44)) {
75: lVar6 = 2;
76: }
77: else {
78: if ((iVar14 == 3) || (lVar6 = 3, iVar4 != *(int *)(pcVar9 + 0x48)))
79: goto LAB_00139731;
80: }
81: }
82: }
83: lVar6 = *(long *)(pcVar9 + lVar6 * 8 + 0x50);
84: if (lVar6 == 0) goto LAB_00139731;
85: }
86: *(long *)(pcVar9 + lVar10 * 8 + 0x50) = lVar6;
87: lVar10 = lVar10 + 1;
88: } while (*(int *)(param_1 + 0x12) != iVar14 + 1 && iVar14 + 1 <= *(int *)(param_1 + 0x12));
89: }
90: }
91: else {
92: if (iVar4 == 0) {
93: pcVar5 = FUN_001393c0;
94: if (*(int *)(param_1 + 0x12) != 3) {
95: pcVar5 = FUN_00139310;
96: }
97: *(code **)(pcVar9 + 8) = pcVar5;
98: return;
99: }
100: if (iVar4 != 2) {
101: param_1 = (code **)*param_1;
102: *(undefined4 *)(param_1 + 5) = 0x30;
103: /* WARNING: Could not recover jumptable at 0x00139655. Too many branches */
104: /* WARNING: Treating indirect jump as call */
105: (**param_1)();
106: return;
107: }
108: *(undefined4 *)(pcVar9 + 0x90) = 0;
109: *(code **)(pcVar9 + 8) = FUN_00139870;
110: if (*(long *)(pcVar9 + 0x70) == 0) {
111: iVar4 = *(int *)(param_1 + 0x11);
112: if (*(int *)(param_1 + 0x12) < 1) {
113: return;
114: }
115: iVar14 = 0;
116: pcVar5 = pcVar9;
117: do {
118: iVar14 = iVar14 + 1;
119: uVar7 = (**(code **)(param_1[1] + 8))(param_1,1,(ulong)(iVar4 + 2) * 2);
120: *(undefined8 *)(pcVar5 + 0x70) = uVar7;
121: iVar3 = *(int *)(param_1 + 0x12);
122: pcVar5 = pcVar5 + 8;
123: } while (iVar14 < iVar3);
124: }
125: else {
126: iVar3 = *(int *)(param_1 + 0x12);
127: }
128: iVar4 = *(int *)(param_1 + 0x11);
129: if (0 < iVar3) {
130: iVar14 = 0;
131: do {
132: puVar1 = (undefined8 *)(pcVar9 + 0x70);
133: iVar14 = iVar14 + 1;
134: pcVar9 = pcVar9 + 8;
135: FUN_0013bed0(*puVar1,(ulong)(iVar4 + 2) * 2);
136: } while (*(int *)(param_1 + 0x12) != iVar14 && iVar14 <= *(int *)(param_1 + 0x12));
137: }
138: }
139: return;
140: }
141: 
