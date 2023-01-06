1: 
2: void FUN_0013ef30(code **param_1,char param_2)
3: 
4: {
5: code *pcVar1;
6: undefined *puVar2;
7: char **ppcVar3;
8: char *pcVar4;
9: code *pcVar5;
10: code **ppcVar6;
11: ulong uVar7;
12: int iVar8;
13: ulong uVar9;
14: long lVar10;
15: undefined8 *puVar11;
16: undefined8 *puVar12;
17: uint uVar13;
18: bool bVar14;
19: byte bVar15;
20: 
21: bVar15 = 0;
22: pcVar1 = param_1[0x3e];
23: FUN_0013ea10();
24: puVar11 = (undefined8 *)param_1[5];
25: puVar2 = (undefined *)*puVar11;
26: *puVar11 = puVar2 + 1;
27: *puVar2 = 0xff;
28: lVar10 = puVar11[1];
29: puVar11[1] = lVar10 + -1;
30: if ((lVar10 + -1 == 0) && (iVar8 = (*(code *)puVar11[3])(), iVar8 == 0)) {
31: ppcVar6 = (code **)*param_1;
32: *(undefined4 *)(ppcVar6 + 5) = 0x18;
33: (**ppcVar6)();
34: }
35: ppcVar3 = (char **)param_1[5];
36: pcVar4 = *ppcVar3;
37: *ppcVar3 = pcVar4 + 1;
38: *pcVar4 = param_2 + -0x30;
39: pcVar4 = ppcVar3[1];
40: ppcVar3[1] = pcVar4 + -1;
41: if ((pcVar4 + -1 == (char *)0x0) && (iVar8 = (*(code *)ppcVar3[3])(), iVar8 == 0)) {
42: ppcVar6 = (code **)*param_1;
43: *(undefined4 *)(ppcVar6 + 5) = 0x18;
44: (**ppcVar6)();
45: }
46: lVar10 = 0;
47: if (0 < *(int *)((long)param_1 + 0x144)) {
48: do {
49: pcVar5 = param_1[lVar10 + 0x29];
50: if ((*(int *)((long)param_1 + 0x134) == 0) ||
51: ((*(int *)((long)param_1 + 0x19c) == 0 && (*(int *)((long)param_1 + 0x1a4) == 0)))) {
52: puVar11 = *(undefined8 **)(pcVar1 + (long)*(int *)(pcVar5 + 0x14) * 8 + 0x68);
53: uVar9 = 0x40;
54: bVar14 = ((ulong)puVar11 & 1) != 0;
55: if (bVar14) {
56: *(undefined *)puVar11 = 0;
57: uVar9 = 0x3f;
58: puVar11 = (undefined8 *)((long)puVar11 + 1);
59: }
60: uVar13 = (uint)uVar9;
61: if (((ulong)puVar11 & 2) != 0) {
62: uVar13 = uVar13 - 2;
63: uVar9 = (ulong)uVar13;
64: *(undefined2 *)puVar11 = 0;
65: puVar11 = (undefined8 *)((long)puVar11 + 2);
66: }
67: if (((ulong)puVar11 & 4) != 0) {
68: *(undefined4 *)puVar11 = 0;
69: uVar9 = (ulong)(uVar13 - 4);
70: puVar11 = (undefined8 *)((long)puVar11 + 4);
71: }
72: uVar7 = uVar9 >> 3;
73: while (uVar7 != 0) {
74: uVar7 = uVar7 - 1;
75: *puVar11 = 0;
76: puVar11 = puVar11 + (ulong)bVar15 * -2 + 1;
77: }
78: if ((uVar9 & 4) != 0) {
79: *(undefined4 *)puVar11 = 0;
80: puVar11 = (undefined8 *)((long)puVar11 + 4);
81: }
82: puVar12 = puVar11;
83: if ((uVar9 & 2) != 0) {
84: puVar12 = (undefined8 *)((long)puVar11 + 2);
85: *(undefined2 *)puVar11 = 0;
86: }
87: if (bVar14) {
88: *(undefined *)puVar12 = 0;
89: }
90: *(undefined4 *)(pcVar1 + lVar10 * 4 + 0x40) = 0;
91: *(undefined4 *)(pcVar1 + lVar10 * 4 + 0x50) = 0;
92: if (*(int *)((long)param_1 + 0x134) != 0) goto LAB_0013f100;
93: LAB_0013f055:
94: uVar9 = 0x100;
95: puVar11 = *(undefined8 **)(pcVar1 + (long)*(int *)(pcVar5 + 0x18) * 8 + 0xe8);
96: bVar14 = ((ulong)puVar11 & 1) != 0;
97: if (bVar14) {
98: *(undefined *)puVar11 = 0;
99: uVar9 = 0xff;
100: puVar11 = (undefined8 *)((long)puVar11 + 1);
101: }
102: uVar13 = (uint)uVar9;
103: if (((ulong)puVar11 & 2) != 0) {
104: uVar13 = uVar13 - 2;
105: uVar9 = (ulong)uVar13;
106: *(undefined2 *)puVar11 = 0;
107: puVar11 = (undefined8 *)((long)puVar11 + 2);
108: }
109: if (((ulong)puVar11 & 4) != 0) {
110: *(undefined4 *)puVar11 = 0;
111: uVar9 = (ulong)(uVar13 - 4);
112: puVar11 = (undefined8 *)((long)puVar11 + 4);
113: }
114: uVar7 = uVar9 >> 3;
115: while (uVar7 != 0) {
116: uVar7 = uVar7 - 1;
117: *puVar11 = 0;
118: puVar11 = puVar11 + (ulong)bVar15 * -2 + 1;
119: }
120: if ((uVar9 & 4) != 0) {
121: *(undefined4 *)puVar11 = 0;
122: puVar11 = (undefined8 *)((long)puVar11 + 4);
123: }
124: puVar12 = puVar11;
125: if ((uVar9 & 2) != 0) {
126: puVar12 = (undefined8 *)((long)puVar11 + 2);
127: *(undefined2 *)puVar11 = 0;
128: }
129: if (bVar14) {
130: *(undefined *)puVar12 = 0;
131: }
132: }
133: else {
134: LAB_0013f100:
135: if (*(int *)(param_1 + 0x34) != 0) goto LAB_0013f055;
136: }
137: iVar8 = (int)lVar10 + 1;
138: lVar10 = lVar10 + 1;
139: } while (*(int *)((long)param_1 + 0x144) != iVar8 && iVar8 <= *(int *)((long)param_1 + 0x144));
140: }
141: *(undefined8 *)(pcVar1 + 0x18) = 0;
142: *(undefined8 *)(pcVar1 + 0x20) = 0x10000;
143: *(undefined8 *)(pcVar1 + 0x28) = 0;
144: *(undefined8 *)(pcVar1 + 0x30) = 0;
145: *(undefined4 *)(pcVar1 + 0x38) = 0xb;
146: *(undefined4 *)(pcVar1 + 0x3c) = 0xffffffff;
147: return;
148: }
149: 
