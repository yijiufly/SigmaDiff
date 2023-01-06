1: 
2: void FUN_00140730(code **param_1)
3: 
4: {
5: undefined4 uVar1;
6: code *pcVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: int iVar5;
10: ulong uVar6;
11: ulong uVar7;
12: long lVar8;
13: undefined8 *puVar9;
14: undefined8 *puVar10;
15: bool bVar11;
16: byte bVar12;
17: 
18: bVar12 = 0;
19: pcVar2 = param_1[0x4a];
20: iVar5 = (**(code **)(param_1[0x49] + 0x10))();
21: if (iVar5 == 0) {
22: ppcVar4 = (code **)*param_1;
23: *(undefined4 *)(ppcVar4 + 5) = 0x18;
24: (**ppcVar4)();
25: }
26: lVar8 = 0;
27: if (0 < *(int *)(param_1 + 0x36)) {
28: do {
29: pcVar3 = param_1[lVar8 + 0x37];
30: if (*(int *)(param_1 + 0x27) == 0) {
31: LAB_00140798:
32: puVar10 = *(undefined8 **)(pcVar2 + (long)*(int *)(pcVar3 + 0x14) * 8 + 0x50);
33: uVar7 = 0x40;
34: iVar5 = 0x40;
35: bVar11 = ((ulong)puVar10 & 1) != 0;
36: if (bVar11) {
37: *(undefined *)puVar10 = 0;
38: puVar10 = (undefined8 *)((long)puVar10 + 1);
39: uVar7 = 0x3f;
40: iVar5 = 0x3f;
41: }
42: puVar9 = puVar10;
43: if (((ulong)puVar10 & 2) != 0) {
44: puVar9 = (undefined8 *)((long)puVar10 + 2);
45: uVar7 = (ulong)(iVar5 - 2);
46: *(undefined2 *)puVar10 = 0;
47: }
48: if (((ulong)puVar9 & 4) != 0) {
49: *(undefined4 *)puVar9 = 0;
50: uVar7 = (ulong)((int)uVar7 - 4);
51: puVar9 = (undefined8 *)((long)puVar9 + 4);
52: }
53: uVar6 = uVar7 >> 3;
54: while (uVar6 != 0) {
55: uVar6 = uVar6 - 1;
56: *puVar9 = 0;
57: puVar9 = puVar9 + (ulong)bVar12 * -2 + 1;
58: }
59: if ((uVar7 & 4) != 0) {
60: *(undefined4 *)puVar9 = 0;
61: puVar9 = (undefined8 *)((long)puVar9 + 4);
62: }
63: puVar10 = puVar9;
64: if ((uVar7 & 2) != 0) {
65: puVar10 = (undefined8 *)((long)puVar9 + 2);
66: *(undefined2 *)puVar9 = 0;
67: }
68: if (bVar11) {
69: *(undefined *)puVar10 = 0;
70: }
71: *(undefined4 *)(pcVar2 + lVar8 * 4 + 0x2c) = 0;
72: *(undefined4 *)(pcVar2 + lVar8 * 4 + 0x3c) = 0;
73: if ((*(int *)(param_1 + 0x27) == 0) || (*(int *)((long)param_1 + 0x20c) != 0)) {
74: LAB_00140814:
75: uVar7 = 0x100;
76: puVar10 = *(undefined8 **)(pcVar2 + (long)*(int *)(pcVar3 + 0x18) * 8 + 0xd0);
77: bVar11 = ((ulong)puVar10 & 1) != 0;
78: if (bVar11) {
79: *(undefined *)puVar10 = 0;
80: uVar7 = 0xff;
81: puVar10 = (undefined8 *)((long)puVar10 + 1);
82: }
83: puVar9 = puVar10;
84: if (((ulong)puVar10 & 2) != 0) {
85: puVar9 = (undefined8 *)((long)puVar10 + 2);
86: uVar7 = (ulong)((int)uVar7 - 2);
87: *(undefined2 *)puVar10 = 0;
88: }
89: if (((ulong)puVar9 & 4) != 0) {
90: *(undefined4 *)puVar9 = 0;
91: uVar7 = (ulong)((int)uVar7 - 4);
92: puVar9 = (undefined8 *)((long)puVar9 + 4);
93: }
94: uVar6 = uVar7 >> 3;
95: while (uVar6 != 0) {
96: uVar6 = uVar6 - 1;
97: *puVar9 = 0;
98: puVar9 = puVar9 + (ulong)bVar12 * -2 + 1;
99: }
100: if ((uVar7 & 4) != 0) {
101: *(undefined4 *)puVar9 = 0;
102: puVar9 = (undefined8 *)((long)puVar9 + 4);
103: }
104: puVar10 = puVar9;
105: if ((uVar7 & 2) != 0) {
106: puVar10 = (undefined8 *)((long)puVar9 + 2);
107: *(undefined2 *)puVar9 = 0;
108: }
109: if (bVar11) {
110: *(undefined *)puVar10 = 0;
111: }
112: }
113: }
114: else {
115: if (*(int *)((long)param_1 + 0x20c) != 0) goto LAB_00140814;
116: if (*(int *)((long)param_1 + 0x214) == 0) goto LAB_00140798;
117: }
118: iVar5 = (int)lVar8;
119: lVar8 = lVar8 + 1;
120: } while (iVar5 + 1 < *(int *)(param_1 + 0x36));
121: }
122: uVar1 = *(undefined4 *)(param_1 + 0x2e);
123: *(undefined8 *)(pcVar2 + 0x18) = 0;
124: *(undefined8 *)(pcVar2 + 0x20) = 0;
125: *(undefined4 *)(pcVar2 + 0x28) = 0xfffffff0;
126: *(undefined4 *)(pcVar2 + 0x4c) = uVar1;
127: return;
128: }
129: 
