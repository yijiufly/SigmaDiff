1: 
2: void FUN_0011c430(long param_1,code **param_2)
3: 
4: {
5: int iVar1;
6: uint uVar2;
7: code *pcVar3;
8: long lVar4;
9: code *pcVar5;
10: undefined8 *puVar6;
11: undefined8 *puVar7;
12: long lVar8;
13: long lVar9;
14: undefined4 *puVar10;
15: undefined4 *puStack80;
16: int iStack68;
17: 
18: iVar1 = *(int *)((long)param_2 + 0x24);
19: if (iVar1 != 100) {
20: pcVar3 = *param_2;
21: *(undefined4 *)(pcVar3 + 0x28) = 0x14;
22: *(int *)(pcVar3 + 0x2c) = iVar1;
23: (**(code **)*param_2)(param_2);
24: }
25: *(undefined4 *)(param_2 + 6) = *(undefined4 *)(param_1 + 0x30);
26: *(undefined4 *)((long)param_2 + 0x34) = *(undefined4 *)(param_1 + 0x34);
27: *(undefined4 *)(param_2 + 7) = *(undefined4 *)(param_1 + 0x38);
28: *(undefined4 *)((long)param_2 + 0x3c) = *(undefined4 *)(param_1 + 0x3c);
29: FUN_00116eb0(param_2);
30: FUN_001169b0(param_2,*(undefined4 *)(param_1 + 0x3c));
31: *(undefined4 *)(param_2 + 9) = *(undefined4 *)(param_1 + 0x128);
32: lVar8 = 0;
33: *(undefined4 *)((long)param_2 + 0x10c) = *(undefined4 *)(param_1 + 0x188);
34: do {
35: puVar7 = *(undefined8 **)(param_1 + 200 + lVar8);
36: if (puVar7 != (undefined8 *)0x0) {
37: puVar6 = *(undefined8 **)((long)param_2 + lVar8 + 0x60);
38: if (puVar6 == (undefined8 *)0x0) {
39: puVar6 = (undefined8 *)FUN_00116760(param_2);
40: *(undefined8 **)((long)param_2 + lVar8 + 0x60) = puVar6;
41: puVar7 = *(undefined8 **)(param_1 + 200 + lVar8);
42: }
43: *puVar6 = *puVar7;
44: puVar6[1] = puVar7[1];
45: puVar6[2] = puVar7[2];
46: puVar6[3] = puVar7[3];
47: puVar6[4] = puVar7[4];
48: puVar6[5] = puVar7[5];
49: puVar6[6] = puVar7[6];
50: puVar6[7] = puVar7[7];
51: puVar6[8] = puVar7[8];
52: puVar6[9] = puVar7[9];
53: puVar6[10] = puVar7[10];
54: puVar6[0xb] = puVar7[0xb];
55: puVar6[0xc] = puVar7[0xc];
56: puVar6[0xd] = puVar7[0xd];
57: puVar6[0xe] = puVar7[0xe];
58: puVar6[0xf] = puVar7[0xf];
59: *(undefined4 *)(*(long *)((long)param_2 + lVar8 + 0x60) + 0x80) = 0;
60: }
61: lVar8 = lVar8 + 8;
62: } while (lVar8 != 0x20);
63: iVar1 = *(int *)(param_1 + 0x38);
64: *(int *)((long)param_2 + 0x4c) = iVar1;
65: if (iVar1 - 1U < 10) {
66: puVar10 = *(undefined4 **)(param_1 + 0x130);
67: puStack80 = (undefined4 *)param_2[0xb];
68: }
69: else {
70: pcVar3 = *param_2;
71: *(int *)(pcVar3 + 0x2c) = iVar1;
72: pcVar5 = *param_2;
73: *(undefined4 *)(pcVar3 + 0x28) = 0x1a;
74: *(undefined4 *)(pcVar5 + 0x30) = 10;
75: (**(code **)*param_2)(param_2);
76: puVar10 = *(undefined4 **)(param_1 + 0x130);
77: puStack80 = (undefined4 *)param_2[0xb];
78: if (*(int *)((long)param_2 + 0x4c) < 1) goto LAB_0011c64c;
79: }
80: iStack68 = 0;
81: do {
82: *puStack80 = *puVar10;
83: puStack80[2] = puVar10[2];
84: puStack80[3] = puVar10[3];
85: uVar2 = puVar10[4];
86: puStack80[4] = uVar2;
87: if ((3 < uVar2) || (lVar8 = *(long *)(param_1 + 200 + (long)(int)uVar2 * 8), lVar8 == 0)) {
88: pcVar3 = *param_2;
89: *(undefined4 *)(pcVar3 + 0x28) = 0x34;
90: *(uint *)(pcVar3 + 0x2c) = uVar2;
91: (**(code **)*param_2)(param_2);
92: lVar8 = *(long *)(param_1 + 200 + (long)(int)uVar2 * 8);
93: }
94: lVar4 = *(long *)(puVar10 + 0x14);
95: lVar9 = 0;
96: if (lVar4 != 0) {
97: do {
98: if (*(short *)(lVar4 + lVar9) != *(short *)(lVar8 + lVar9)) {
99: pcVar3 = *param_2;
100: *(undefined4 *)(pcVar3 + 0x28) = 0x2c;
101: *(uint *)(pcVar3 + 0x2c) = uVar2;
102: (**(code **)*param_2)(param_2);
103: }
104: lVar9 = lVar9 + 2;
105: } while (lVar9 != 0x80);
106: }
107: iStack68 = iStack68 + 1;
108: puVar10 = puVar10 + 0x18;
109: puStack80 = puStack80 + 0x18;
110: } while (*(int *)((long)param_2 + 0x4c) != iStack68 && iStack68 <= *(int *)((long)param_2 + 0x4c))
111: ;
112: LAB_0011c64c:
113: if (*(int *)(param_1 + 0x174) != 0) {
114: if (*(char *)(param_1 + 0x178) == '\x01') {
115: *(undefined *)((long)param_2 + 0x124) = 1;
116: *(undefined *)((long)param_2 + 0x125) = *(undefined *)(param_1 + 0x179);
117: }
118: *(undefined *)((long)param_2 + 0x126) = *(undefined *)(param_1 + 0x17a);
119: *(undefined2 *)(param_2 + 0x25) = *(undefined2 *)(param_1 + 0x17c);
120: *(undefined2 *)((long)param_2 + 0x12a) = *(undefined2 *)(param_1 + 0x17e);
121: }
122: return;
123: }
124: 
