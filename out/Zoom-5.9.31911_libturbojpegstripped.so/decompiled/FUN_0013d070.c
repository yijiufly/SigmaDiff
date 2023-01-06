1: 
2: void FUN_0013d070(code **param_1)
3: 
4: {
5: uint uVar1;
6: undefined4 uVar2;
7: code *pcVar3;
8: code *pcVar4;
9: ulong uVar5;
10: long lVar6;
11: long *plVar7;
12: ulong uVar8;
13: ulong uVar9;
14: ulong uVar10;
15: 
16: uVar10 = 0;
17: uVar8 = 0;
18: pcVar3 = param_1[1];
19: plVar7 = *(long **)(pcVar3 + 0x88);
20: while (plVar7 != (long *)0x0) {
21: while (*plVar7 == 0) {
22: uVar9 = (ulong)*(uint *)(plVar7 + 1) * (ulong)*(uint *)((long)plVar7 + 0xc);
23: uVar10 = uVar10 + (ulong)*(uint *)((long)plVar7 + 0xc) * (ulong)*(uint *)(plVar7 + 2);
24: if (~uVar8 <= uVar9 && uVar9 - ~uVar8 != 0) {
25: pcVar4 = *param_1;
26: *(undefined4 *)(pcVar4 + 0x28) = 0x36;
27: *(undefined4 *)(pcVar4 + 0x2c) = 10;
28: (**(code **)*param_1)(param_1);
29: }
30: plVar7 = (long *)plVar7[6];
31: uVar8 = uVar8 + uVar9;
32: if (plVar7 == (long *)0x0) goto LAB_0013d0e0;
33: }
34: plVar7 = (long *)plVar7[6];
35: }
36: LAB_0013d0e0:
37: plVar7 = *(long **)(pcVar3 + 0x90);
38: while (plVar7 != (long *)0x0) {
39: while (*plVar7 == 0) {
40: uVar9 = (ulong)*(uint *)(plVar7 + 1) * (ulong)*(uint *)((long)plVar7 + 0xc) * 0x80;
41: uVar10 = uVar10 + (ulong)*(uint *)((long)plVar7 + 0xc) * (ulong)*(uint *)(plVar7 + 2) * 0x80;
42: if (~uVar8 < uVar9) {
43: pcVar4 = *param_1;
44: *(undefined4 *)(pcVar4 + 0x28) = 0x36;
45: *(undefined4 *)(pcVar4 + 0x2c) = 0xb;
46: (**(code **)*param_1)(param_1);
47: }
48: plVar7 = (long *)plVar7[6];
49: uVar8 = uVar8 + uVar9;
50: if (plVar7 == (long *)0x0) goto LAB_0013d138;
51: }
52: plVar7 = (long *)plVar7[6];
53: }
54: LAB_0013d138:
55: if (uVar10 != 0) {
56: uVar5 = FUN_0013d920(param_1,uVar10,uVar8);
57: uVar9 = 1000000000;
58: if (uVar5 < uVar8) {
59: uVar9 = 1;
60: if (uVar5 / uVar10 != 0) {
61: uVar9 = uVar5 / uVar10;
62: }
63: }
64: plVar7 = *(long **)(pcVar3 + 0x88);
65: while (plVar7 != (long *)0x0) {
66: while (*plVar7 == 0) {
67: uVar1 = *(uint *)(plVar7 + 1);
68: if (uVar9 < (long)((ulong)uVar1 - 1) / (long)(ulong)*(uint *)(plVar7 + 2) + 1U) {
69: *(uint *)((long)plVar7 + 0x14) = *(uint *)(plVar7 + 2) * (int)uVar9;
70: FUN_0013d950(param_1,plVar7 + 7,(ulong)*(uint *)((long)plVar7 + 0xc) * (ulong)uVar1);
71: *(undefined4 *)((long)plVar7 + 0x2c) = 1;
72: }
73: else {
74: *(uint *)((long)plVar7 + 0x14) = uVar1;
75: }
76: lVar6 = FUN_0013cdb0(param_1,1,*(undefined4 *)((long)plVar7 + 0xc));
77: *plVar7 = lVar6;
78: uVar2 = *(undefined4 *)(pcVar3 + 0xa0);
79: *(undefined4 *)((long)plVar7 + 0x1c) = 0;
80: *(undefined4 *)(plVar7 + 4) = 0;
81: *(undefined4 *)(plVar7 + 5) = 0;
82: *(undefined4 *)(plVar7 + 3) = uVar2;
83: plVar7 = (long *)plVar7[6];
84: if (plVar7 == (long *)0x0) goto LAB_0013d240;
85: }
86: plVar7 = (long *)plVar7[6];
87: }
88: LAB_0013d240:
89: plVar7 = *(long **)(pcVar3 + 0x90);
90: while (plVar7 != (long *)0x0) {
91: if (*plVar7 == 0) {
92: uVar1 = *(uint *)(plVar7 + 1);
93: if (uVar9 < (long)((ulong)uVar1 - 1) / (long)(ulong)*(uint *)(plVar7 + 2) + 1U) {
94: *(uint *)((long)plVar7 + 0x14) = *(uint *)(plVar7 + 2) * (int)uVar9;
95: FUN_0013d950(param_1,plVar7 + 7,(ulong)*(uint *)((long)plVar7 + 0xc) * (ulong)uVar1 * 0x80
96: );
97: *(undefined4 *)((long)plVar7 + 0x2c) = 1;
98: }
99: else {
100: *(uint *)((long)plVar7 + 0x14) = uVar1;
101: }
102: lVar6 = FUN_0013cb30(param_1,1,*(undefined4 *)((long)plVar7 + 0xc));
103: *plVar7 = lVar6;
104: uVar2 = *(undefined4 *)(pcVar3 + 0xa0);
105: *(undefined4 *)((long)plVar7 + 0x1c) = 0;
106: *(undefined4 *)(plVar7 + 4) = 0;
107: *(undefined4 *)(plVar7 + 5) = 0;
108: *(undefined4 *)(plVar7 + 3) = uVar2;
109: }
110: plVar7 = (long *)plVar7[6];
111: }
112: }
113: return;
114: }
115: 
