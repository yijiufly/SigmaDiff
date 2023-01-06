1: 
2: void FUN_0011e8e0(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: int iVar3;
8: undefined4 uVar4;
9: uint uVar5;
10: int iVar6;
11: uint uVar7;
12: int iVar8;
13: long lVar9;
14: 
15: iVar8 = *(int *)((long)param_1 + 0x144);
16: if (iVar8 == 1) {
17: pcVar2 = param_1[0x29];
18: uVar7 = *(uint *)(pcVar2 + 0xc);
19: *(undefined4 *)(param_1 + 0x2d) = *(undefined4 *)(pcVar2 + 0x1c);
20: uVar5 = *(uint *)(pcVar2 + 0x20);
21: *(uint *)((long)param_1 + 0x16c) = uVar5;
22: *(undefined4 *)(pcVar2 + 0x44) = 1;
23: uVar5 = uVar5 % uVar7;
24: *(undefined4 *)(pcVar2 + 0x34) = 1;
25: *(undefined4 *)(pcVar2 + 0x38) = 1;
26: *(undefined4 *)(pcVar2 + 0x3c) = 1;
27: *(undefined4 *)(pcVar2 + 0x40) = 8;
28: if (uVar5 != 0) {
29: uVar7 = uVar5;
30: }
31: *(uint *)(pcVar2 + 0x48) = uVar7;
32: param_1[0x2e] = (code *)0x1;
33: }
34: else {
35: if (3 < iVar8 - 1U) {
36: ppcVar1 = (code **)*param_1;
37: *(undefined4 *)(ppcVar1 + 5) = 0x1a;
38: *(int *)((long)ppcVar1 + 0x2c) = iVar8;
39: *(undefined4 *)(ppcVar1 + 6) = 4;
40: (**ppcVar1)();
41: }
42: uVar4 = FUN_001489d0();
43: *(undefined4 *)(param_1 + 0x2d) = uVar4;
44: uVar4 = FUN_001489d0();
45: *(undefined4 *)((long)param_1 + 0x16c) = uVar4;
46: *(undefined4 *)(param_1 + 0x2e) = 0;
47: if (0 < *(int *)((long)param_1 + 0x144)) {
48: lVar9 = 0;
49: iVar8 = 0;
50: while( true ) {
51: pcVar2 = param_1[lVar9 + 0x29];
52: iVar3 = (int)lVar9;
53: uVar7 = *(uint *)(pcVar2 + 8);
54: uVar5 = *(uint *)(pcVar2 + 0xc);
55: *(uint *)(pcVar2 + 0x34) = uVar7;
56: iVar6 = uVar7 * uVar5;
57: *(uint *)(pcVar2 + 0x38) = uVar5;
58: *(uint *)(pcVar2 + 0x40) = uVar7 * 8;
59: *(int *)(pcVar2 + 0x3c) = iVar6;
60: if (*(uint *)(pcVar2 + 0x1c) % uVar7 != 0) {
61: uVar7 = *(uint *)(pcVar2 + 0x1c) % uVar7;
62: }
63: *(uint *)(pcVar2 + 0x44) = uVar7;
64: if (*(uint *)(pcVar2 + 0x20) % uVar5 != 0) {
65: uVar5 = *(uint *)(pcVar2 + 0x20) % uVar5;
66: }
67: *(uint *)(pcVar2 + 0x48) = uVar5;
68: if (10 < iVar8 + iVar6) {
69: ppcVar1 = (code **)*param_1;
70: *(undefined4 *)(ppcVar1 + 5) = 0xd;
71: (**ppcVar1)();
72: }
73: if (0 < iVar6) {
74: iVar8 = *(int *)(param_1 + 0x2e);
75: *(int *)((long)param_1 + (long)iVar8 * 4 + 0x174) = iVar3;
76: if (0 < iVar6 + -1) {
77: *(int *)((long)param_1 + (long)(iVar8 + 1) * 4 + 0x174) = iVar3;
78: if (2 < iVar6) {
79: *(int *)((long)param_1 + (long)(iVar8 + 2) * 4 + 0x174) = iVar3;
80: if (3 < iVar6) {
81: *(int *)((long)param_1 + (long)(iVar8 + 3) * 4 + 0x174) = iVar3;
82: if (4 < iVar6) {
83: *(int *)((long)param_1 + (long)(iVar8 + 4) * 4 + 0x174) = iVar3;
84: if (5 < iVar6) {
85: *(int *)((long)param_1 + (long)(iVar8 + 5) * 4 + 0x174) = iVar3;
86: if (6 < iVar6) {
87: *(int *)((long)param_1 + (long)(iVar8 + 6) * 4 + 0x174) = iVar3;
88: if (7 < iVar6) {
89: *(int *)((long)param_1 + (long)(iVar8 + 7) * 4 + 0x174) = iVar3;
90: if (8 < iVar6) {
91: *(int *)((long)param_1 + (long)(iVar8 + 8) * 4 + 0x174) = iVar3;
92: if (9 < iVar6) {
93: *(int *)((long)param_1 + (long)(iVar8 + 9) * 4 + 0x174) = iVar3;
94: }
95: }
96: }
97: }
98: }
99: }
100: }
101: }
102: }
103: *(int *)(param_1 + 0x2e) = iVar6 + -1 + iVar8 + 1;
104: }
105: lVar9 = lVar9 + 1;
106: if (*(int *)((long)param_1 + 0x144) == iVar3 + 1 ||
107: *(int *)((long)param_1 + 0x144) < iVar3 + 1) break;
108: iVar8 = *(int *)(param_1 + 0x2e);
109: }
110: }
111: }
112: if (0 < *(int *)((long)param_1 + 0x11c)) {
113: lVar9 = (ulong)*(uint *)(param_1 + 0x2d) * (long)*(int *)((long)param_1 + 0x11c);
114: if (0xfffe < lVar9) {
115: lVar9 = 0xffff;
116: }
117: *(int *)(param_1 + 0x23) = (int)lVar9;
118: }
119: return;
120: }
121: 
