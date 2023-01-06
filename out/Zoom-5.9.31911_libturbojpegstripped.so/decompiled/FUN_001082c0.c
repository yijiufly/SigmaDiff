1: 
2: void FUN_001082c0(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: uint uVar2;
7: int iVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: 
11: ppcVar4 = (code **)(**(code **)param_1[1])(param_1,1,0x90);
12: param_1[0x3d] = (code *)ppcVar4;
13: *ppcVar4 = FUN_001071c0;
14: iVar3 = *(int *)((long)param_1 + 0x114);
15: if (iVar3 == 1) {
16: ppcVar4[1] = FUN_00106b80;
17: iVar3 = FUN_00168630();
18: if (iVar3 == 0) {
19: ppcVar4[2] = FUN_00133870;
20: }
21: else {
22: ppcVar4[2] = thunk_FUN_0015d620;
23: }
24: LAB_0010831b:
25: uVar2 = *(uint *)((long)param_1 + 0x114);
26: if (1 < uVar2) goto LAB_0010832a;
27: LAB_001083d8:
28: iVar3 = FUN_00168520();
29: pcVar5 = FUN_00106a90;
30: if (iVar3 != 0) {
31: pcVar5 = FUN_001685a0;
32: }
33: ppcVar4[3] = pcVar5;
34: iVar3 = FUN_001686f0();
35: if (iVar3 == 0) {
36: ppcVar4[4] = FUN_00106b10;
37: }
38: else {
39: ppcVar4[4] = FUN_00168770;
40: }
41: }
42: else {
43: if (iVar3 == 0) {
44: ppcVar4[1] = FUN_00106b80;
45: iVar3 = FUN_001685d0();
46: if (iVar3 == 0) {
47: ppcVar4[2] = FUN_00133ab0;
48: }
49: else {
50: ppcVar4[2] = FUN_001686b0;
51: }
52: goto LAB_0010831b;
53: }
54: if (iVar3 != 2) {
55: ppcVar1 = (code **)*param_1;
56: *(undefined4 *)(ppcVar1 + 5) = 0x30;
57: (**ppcVar1)(param_1);
58: goto LAB_0010831b;
59: }
60: ppcVar4[1] = FUN_00107110;
61: iVar3 = FUN_00168670();
62: if (iVar3 == 0) {
63: ppcVar4[10] = FUN_00132fd0;
64: goto LAB_0010831b;
65: }
66: ppcVar4[10] = thunk_FUN_00155120;
67: uVar2 = *(uint *)((long)param_1 + 0x114);
68: if (uVar2 < 2) goto LAB_001083d8;
69: LAB_0010832a:
70: if (uVar2 == 2) {
71: iVar3 = FUN_00168560();
72: pcVar5 = FUN_00106c30;
73: if (iVar3 != 0) {
74: pcVar5 = thunk_FUN_0015fa20;
75: }
76: ppcVar4[0xb] = pcVar5;
77: iVar3 = FUN_00168730();
78: if (iVar3 != 0) {
79: iVar3 = *(int *)((long)param_1 + 0x114);
80: ppcVar4[0xc] = thunk_FUN_0015fae0;
81: ppcVar1 = (code **)param_1[1];
82: goto joined_r0x0010842b;
83: }
84: ppcVar4[0xc] = FUN_00106ce0;
85: }
86: else {
87: ppcVar1 = (code **)*param_1;
88: *(undefined4 *)(ppcVar1 + 5) = 0x30;
89: (**ppcVar1)(param_1);
90: }
91: }
92: iVar3 = *(int *)((long)param_1 + 0x114);
93: ppcVar1 = (code **)param_1[1];
94: joined_r0x0010842b:
95: if (iVar3 == 2) {
96: pcVar5 = (code *)(**ppcVar1)(param_1,1,0x100);
97: ppcVar4[0x11] = pcVar5;
98: }
99: else {
100: pcVar5 = (code *)(**ppcVar1)(param_1,1,0x80);
101: ppcVar4[9] = pcVar5;
102: }
103: ppcVar4[5] = (code *)0x0;
104: ppcVar4[6] = (code *)0x0;
105: ppcVar4[7] = (code *)0x0;
106: ppcVar4[8] = (code *)0x0;
107: ppcVar4[0xd] = (code *)0x0;
108: ppcVar4[0xe] = (code *)0x0;
109: ppcVar4[0xf] = (code *)0x0;
110: ppcVar4[0x10] = (code *)0x0;
111: return;
112: }
113: 
