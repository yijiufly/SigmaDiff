1: 
2: void FUN_00166fe0(code **param_1,void **param_2,void **param_3,int param_4)
3: 
4: {
5: code **ppcVar1;
6: void *pvVar2;
7: bool bVar3;
8: void **ppvVar4;
9: void *pvVar5;
10: 
11: if ((param_2 == (void **)0x0) || (param_3 == (void **)0x0)) {
12: ppcVar1 = (code **)*param_1;
13: *(undefined4 *)(ppcVar1 + 5) = 0x17;
14: (**ppcVar1)(param_1);
15: }
16: ppvVar4 = (void **)param_1[5];
17: if (ppvVar4 == (void **)0x0) {
18: ppvVar4 = (void **)(**(code **)param_1[1])(param_1,0,0x58);
19: pvVar5 = (void *)0x0;
20: param_1[5] = (code *)ppvVar4;
21: ppvVar4[7] = (void *)0x0;
22: ppvVar4[8] = (void *)0x0;
23: }
24: else {
25: if ((code *)ppvVar4[2] != FUN_00166f00) {
26: ppcVar1 = (code **)*param_1;
27: *(undefined4 *)(ppcVar1 + 5) = 0x17;
28: (**ppcVar1)(param_1);
29: ppvVar4 = (void **)param_1[5];
30: }
31: pvVar5 = ppvVar4[8];
32: }
33: ppvVar4[2] = FUN_00166f00;
34: ppvVar4[3] = FUN_00166f40;
35: ppvVar4[4] = FUN_00166f10;
36: pvVar2 = *param_2;
37: if ((pvVar2 == pvVar5) && (pvVar2 != (void *)0x0)) {
38: if (param_4 == 0) {
39: pvVar5 = *param_3;
40: ppvVar4[5] = param_2;
41: ppvVar4[6] = param_3;
42: *(undefined4 *)(ppvVar4 + 10) = 0;
43: if (pvVar5 == (void *)0x0) goto LAB_0016709c;
44: goto LAB_001670f8;
45: }
46: pvVar5 = *param_3;
47: ppvVar4[5] = param_2;
48: ppvVar4[6] = param_3;
49: *(int *)(ppvVar4 + 10) = param_4;
50: if (pvVar5 != (void *)0x0) {
51: ppvVar4[8] = pvVar2;
52: *ppvVar4 = pvVar2;
53: pvVar5 = ppvVar4[9];
54: goto LAB_001670bf;
55: }
56: bVar3 = true;
57: LAB_00167166:
58: pvVar5 = malloc(0x1000);
59: *param_2 = pvVar5;
60: ppvVar4[7] = pvVar5;
61: if (pvVar5 == (void *)0x0) {
62: ppcVar1 = (code **)*param_1;
63: ppcVar1[5] = (code *)0xa00000036;
64: (**ppcVar1)(param_1);
65: }
66: pvVar5 = *param_2;
67: *param_3 = (void *)0x1000;
68: ppvVar4[8] = pvVar5;
69: *ppvVar4 = pvVar5;
70: if (bVar3) {
71: pvVar5 = ppvVar4[9];
72: goto LAB_001670bf;
73: }
74: LAB_001670b7:
75: pvVar5 = *param_3;
76: }
77: else {
78: ppvVar4[5] = param_2;
79: ppvVar4[6] = param_3;
80: *(int *)(ppvVar4 + 10) = param_4;
81: if ((pvVar2 == (void *)0x0) || (pvVar5 = *param_3, pvVar5 == (void *)0x0)) {
82: if (param_4 != 0) {
83: bVar3 = false;
84: goto LAB_00167166;
85: }
86: LAB_0016709c:
87: ppcVar1 = (code **)*param_1;
88: *(undefined4 *)(ppcVar1 + 5) = 0x17;
89: (**ppcVar1)(param_1);
90: pvVar5 = *param_2;
91: ppvVar4[8] = pvVar5;
92: *ppvVar4 = pvVar5;
93: goto LAB_001670b7;
94: }
95: LAB_001670f8:
96: ppvVar4[8] = pvVar2;
97: *ppvVar4 = pvVar2;
98: }
99: ppvVar4[9] = pvVar5;
100: LAB_001670bf:
101: ppvVar4[1] = pvVar5;
102: return;
103: }
104: 
