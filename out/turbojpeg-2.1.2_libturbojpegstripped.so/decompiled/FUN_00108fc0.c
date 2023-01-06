1: 
2: void FUN_00108fc0(code **param_1)
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
13: *ppcVar4 = FUN_00108100;
14: iVar3 = *(int *)((long)param_1 + 0x114);
15: if (iVar3 == 1) {
16: ppcVar4[1] = FUN_00107590;
17: iVar3 = FUN_0016c100();
18: if (iVar3 == 0) {
19: ppcVar4[2] = FUN_0013f0a0;
20: }
21: else {
22: ppcVar4[2] = FUN_0016c130;
23: }
24: LAB_0010901b:
25: uVar2 = *(uint *)((long)param_1 + 0x114);
26: if (1 < uVar2) goto LAB_0010902a;
27: LAB_001090d8:
28: iVar3 = FUN_0016c0b0();
29: pcVar5 = FUN_00107220;
30: if (iVar3 != 0) {
31: pcVar5 = FUN_0016c0d0;
32: }
33: ppcVar4[3] = pcVar5;
34: iVar3 = FUN_0016c150();
35: if (iVar3 == 0) {
36: ppcVar4[4] = FUN_00107510;
37: }
38: else {
39: ppcVar4[4] = FUN_0016c170;
40: }
41: }
42: else {
43: if (iVar3 == 0) {
44: ppcVar4[1] = FUN_00107590;
45: iVar3 = FUN_0016c0f0();
46: if (iVar3 == 0) {
47: ppcVar4[2] = FUN_0013f2e0;
48: }
49: else {
50: ppcVar4[2] = FUN_0016c120;
51: }
52: goto LAB_0010901b;
53: }
54: if (iVar3 != 2) {
55: ppcVar1 = (code **)*param_1;
56: *(undefined4 *)(ppcVar1 + 5) = 0x30;
57: (**ppcVar1)(param_1);
58: goto LAB_0010901b;
59: }
60: ppcVar4[1] = FUN_00108050;
61: iVar3 = FUN_0016c110();
62: if (iVar3 == 0) {
63: ppcVar4[10] = FUN_0013e180;
64: goto LAB_0010901b;
65: }
66: ppcVar4[10] = FUN_0016c140;
67: uVar2 = *(uint *)((long)param_1 + 0x114);
68: if (uVar2 < 2) goto LAB_001090d8;
69: LAB_0010902a:
70: if (uVar2 == 2) {
71: iVar3 = FUN_0016c0c0();
72: pcVar5 = FUN_00107640;
73: if (iVar3 != 0) {
74: pcVar5 = FUN_0016c0e0;
75: }
76: ppcVar4[0xb] = pcVar5;
77: iVar3 = FUN_0016c160();
78: if (iVar3 != 0) {
79: iVar3 = *(int *)((long)param_1 + 0x114);
80: ppcVar4[0xc] = FUN_0016c180;
81: pcVar5 = *(code **)param_1[1];
82: goto joined_r0x0010912e;
83: }
84: ppcVar4[0xc] = FUN_00107bd0;
85: }
86: else {
87: ppcVar1 = (code **)*param_1;
88: *(undefined4 *)(ppcVar1 + 5) = 0x30;
89: (**ppcVar1)(param_1);
90: }
91: }
92: iVar3 = *(int *)((long)param_1 + 0x114);
93: pcVar5 = *(code **)param_1[1];
94: joined_r0x0010912e:
95: if (iVar3 == 2) {
96: pcVar5 = (code *)(*pcVar5)(param_1,1,0x100);
97: ppcVar4[0x11] = pcVar5;
98: }
99: else {
100: pcVar5 = (code *)(*pcVar5)(param_1,1,0x80);
101: ppcVar4[9] = pcVar5;
102: }
103: ppcVar4[5] = (code *)0x0;
104: ppcVar4[0xd] = (code *)0x0;
105: ppcVar4[6] = (code *)0x0;
106: ppcVar4[0xe] = (code *)0x0;
107: ppcVar4[7] = (code *)0x0;
108: ppcVar4[0xf] = (code *)0x0;
109: ppcVar4[8] = (code *)0x0;
110: ppcVar4[0x10] = (code *)0x0;
111: return;
112: }
113: 
