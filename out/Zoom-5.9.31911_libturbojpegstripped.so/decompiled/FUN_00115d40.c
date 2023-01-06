1: 
2: void FUN_00115d40(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: undefined4 uVar4;
9: long lVar5;
10: uint uVar6;
11: int iVar7;
12: uint uVar8;
13: int iVar9;
14: int iVar10;
15: code **ppcVar11;
16: 
17: iVar9 = *(int *)((long)param_1 + 0x144);
18: if (iVar9 == 1) {
19: pcVar1 = param_1[0x29];
20: uVar8 = *(uint *)(pcVar1 + 0xc);
21: *(undefined4 *)(param_1 + 0x2d) = *(undefined4 *)(pcVar1 + 0x1c);
22: uVar6 = *(uint *)(pcVar1 + 0x20);
23: *(uint *)((long)param_1 + 0x16c) = uVar6;
24: *(undefined4 *)(pcVar1 + 0x34) = 1;
25: uVar6 = uVar6 % uVar8;
26: *(undefined4 *)(pcVar1 + 0x38) = 1;
27: *(undefined4 *)(pcVar1 + 0x3c) = 1;
28: *(undefined4 *)(pcVar1 + 0x40) = 8;
29: *(undefined4 *)(pcVar1 + 0x44) = 1;
30: if (uVar6 != 0) {
31: uVar8 = uVar6;
32: }
33: *(uint *)(pcVar1 + 0x48) = uVar8;
34: *(undefined4 *)(param_1 + 0x2e) = 1;
35: *(undefined4 *)((long)param_1 + 0x174) = 0;
36: }
37: else {
38: if (3 < iVar9 - 1U) {
39: pcVar1 = *param_1;
40: *(int *)(pcVar1 + 0x2c) = iVar9;
41: pcVar3 = *param_1;
42: *(undefined4 *)(pcVar1 + 0x28) = 0x1a;
43: *(undefined4 *)(pcVar3 + 0x30) = 4;
44: (**(code **)*param_1)();
45: }
46: uVar4 = FUN_0013be20();
47: *(undefined4 *)(param_1 + 0x2d) = uVar4;
48: uVar4 = FUN_0013be20();
49: *(undefined4 *)((long)param_1 + 0x16c) = uVar4;
50: *(undefined4 *)(param_1 + 0x2e) = 0;
51: if (0 < *(int *)((long)param_1 + 0x144)) {
52: iVar9 = 0;
53: iVar7 = 0;
54: ppcVar11 = param_1;
55: while( true ) {
56: pcVar1 = ppcVar11[0x29];
57: uVar8 = *(uint *)(pcVar1 + 8);
58: uVar6 = *(uint *)(pcVar1 + 0xc);
59: *(uint *)(pcVar1 + 0x34) = uVar8;
60: iVar10 = uVar8 * uVar6;
61: *(uint *)(pcVar1 + 0x38) = uVar6;
62: *(uint *)(pcVar1 + 0x40) = uVar8 * 8;
63: *(int *)(pcVar1 + 0x3c) = iVar10;
64: if (*(uint *)(pcVar1 + 0x1c) % uVar8 != 0) {
65: uVar8 = *(uint *)(pcVar1 + 0x1c) % uVar8;
66: }
67: *(uint *)(pcVar1 + 0x44) = uVar8;
68: if (*(uint *)(pcVar1 + 0x20) % uVar6 != 0) {
69: uVar6 = *(uint *)(pcVar1 + 0x20) % uVar6;
70: }
71: *(uint *)(pcVar1 + 0x48) = uVar6;
72: if (10 < iVar9 + iVar10) {
73: ppcVar2 = (code **)*param_1;
74: *(undefined4 *)(ppcVar2 + 5) = 0xd;
75: (**ppcVar2)();
76: }
77: if (0 < iVar10) {
78: iVar9 = *(int *)(param_1 + 0x2e);
79: *(int *)((long)param_1 + (long)iVar9 * 4 + 0x174) = iVar7;
80: if (0 < iVar10 + -1) {
81: *(int *)((long)param_1 + (long)(iVar9 + 1) * 4 + 0x174) = iVar7;
82: if (2 < iVar10) {
83: *(int *)((long)param_1 + (long)(iVar9 + 2) * 4 + 0x174) = iVar7;
84: if (3 < iVar10) {
85: *(int *)((long)param_1 + (long)(iVar9 + 3) * 4 + 0x174) = iVar7;
86: if (4 < iVar10) {
87: *(int *)((long)param_1 + (long)(iVar9 + 4) * 4 + 0x174) = iVar7;
88: if (5 < iVar10) {
89: *(int *)((long)param_1 + (long)(iVar9 + 5) * 4 + 0x174) = iVar7;
90: if (6 < iVar10) {
91: *(int *)((long)param_1 + (long)(iVar9 + 6) * 4 + 0x174) = iVar7;
92: if (7 < iVar10) {
93: *(int *)((long)param_1 + (long)(iVar9 + 7) * 4 + 0x174) = iVar7;
94: if (8 < iVar10) {
95: *(int *)((long)param_1 + (long)(iVar9 + 8) * 4 + 0x174) = iVar7;
96: if (9 < iVar10) {
97: *(int *)((long)param_1 + (long)(iVar9 + 9) * 4 + 0x174) = iVar7;
98: }
99: }
100: }
101: }
102: }
103: }
104: }
105: }
106: }
107: *(int *)(param_1 + 0x2e) = iVar10 + -1 + iVar9 + 1;
108: }
109: iVar7 = iVar7 + 1;
110: ppcVar11 = ppcVar11 + 1;
111: if (*(int *)((long)param_1 + 0x144) == iVar7 || *(int *)((long)param_1 + 0x144) < iVar7)
112: break;
113: iVar9 = *(int *)(param_1 + 0x2e);
114: }
115: }
116: }
117: if (0 < *(int *)((long)param_1 + 0x11c)) {
118: lVar5 = (long)*(int *)((long)param_1 + 0x11c) * (ulong)*(uint *)(param_1 + 0x2d);
119: uVar4 = 0xffff;
120: if (lVar5 < 0xffff) {
121: uVar4 = (undefined4)lVar5;
122: }
123: *(undefined4 *)(param_1 + 0x23) = uVar4;
124: }
125: return;
126: }
127: 
