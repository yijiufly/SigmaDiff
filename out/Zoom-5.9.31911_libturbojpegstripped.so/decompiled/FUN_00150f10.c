1: 
2: void FUN_00150f10(code **param_1,long param_2)
3: 
4: {
5: FILE *__stream;
6: code **ppcVar1;
7: code **ppcVar2;
8: uint uVar3;
9: int iVar4;
10: void **ppvVar5;
11: size_t sVar6;
12: code *UNRECOVERED_JUMPTABLE;
13: uint uVar7;
14: 
15: uVar7 = 0;
16: uVar3 = *(uint *)((long)param_1 + 0x34);
17: UNRECOVERED_JUMPTABLE = (code *)(ulong)uVar3;
18: __stream = *(FILE **)(param_2 + 0x18);
19: ppcVar1 = (code **)param_1[2];
20: if (uVar3 != 0) {
21: if (ppcVar1 == (code **)0x0) {
22: do {
23: ppvVar5 = (void **)(**(code **)(param_1[1] + 0x38))
24: (param_1,*(undefined8 *)(param_2 + 0x40),uVar7,1,1);
25: sVar6 = fread(*ppvVar5,1,(ulong)*(uint *)(param_2 + 0x4c),__stream);
26: if (sVar6 != *(uint *)(param_2 + 0x4c)) {
27: iVar4 = feof(__stream);
28: ppcVar1 = (code **)*param_1;
29: if (iVar4 == 0) {
30: *(undefined4 *)(ppcVar1 + 5) = 0x24;
31: (**ppcVar1)(param_1);
32: }
33: else {
34: *(undefined4 *)(ppcVar1 + 5) = 0x2b;
35: (**ppcVar1)(param_1);
36: }
37: }
38: uVar3 = *(uint *)((long)param_1 + 0x34);
39: uVar7 = uVar7 + 1;
40: } while (uVar7 < uVar3);
41: goto LAB_00150fd1;
42: }
43: do {
44: while( true ) {
45: ppcVar1[2] = UNRECOVERED_JUMPTABLE;
46: ppcVar1[1] = (code *)(ulong)uVar7;
47: (**ppcVar1)(param_1);
48: ppvVar5 = (void **)(**(code **)(param_1[1] + 0x38))
49: (param_1,*(undefined8 *)(param_2 + 0x40),uVar7,1,1);
50: sVar6 = fread(*ppvVar5,1,(ulong)*(uint *)(param_2 + 0x4c),__stream);
51: if (sVar6 != *(uint *)(param_2 + 0x4c)) break;
52: LAB_00150f4c:
53: uVar3 = *(uint *)((long)param_1 + 0x34);
54: UNRECOVERED_JUMPTABLE = (code *)(ulong)uVar3;
55: uVar7 = uVar7 + 1;
56: if (uVar3 <= uVar7) goto LAB_00150fc7;
57: }
58: iVar4 = feof(__stream);
59: ppcVar2 = (code **)*param_1;
60: if (iVar4 == 0) {
61: *(undefined4 *)(ppcVar2 + 5) = 0x24;
62: (**ppcVar2)(param_1);
63: goto LAB_00150f4c;
64: }
65: *(undefined4 *)(ppcVar2 + 5) = 0x2b;
66: uVar7 = uVar7 + 1;
67: (**ppcVar2)(param_1);
68: uVar3 = *(uint *)((long)param_1 + 0x34);
69: UNRECOVERED_JUMPTABLE = (code *)(ulong)uVar3;
70: } while (uVar7 < uVar3);
71: }
72: LAB_00150fc7:
73: if (ppcVar1 != (code **)0x0) {
74: *(int *)(ppcVar1 + 4) = *(int *)(ppcVar1 + 4) + 1;
75: }
76: LAB_00150fd1:
77: iVar4 = *(int *)(param_2 + 0x50);
78: if (iVar4 == 0x18) {
79: *(code **)(param_2 + 8) = FUN_00150c00;
80: UNRECOVERED_JUMPTABLE = FUN_00150c00;
81: }
82: else {
83: if (iVar4 == 0x20) {
84: *(code **)(param_2 + 8) = FUN_00150900;
85: UNRECOVERED_JUMPTABLE = FUN_00150900;
86: }
87: else {
88: if (iVar4 == 8) {
89: *(code **)(param_2 + 8) = FUN_00150460;
90: UNRECOVERED_JUMPTABLE = FUN_00150460;
91: }
92: else {
93: ppcVar1 = (code **)*param_1;
94: *(undefined4 *)(ppcVar1 + 5) = 0x3ea;
95: (**ppcVar1)(param_1);
96: UNRECOVERED_JUMPTABLE = *(code **)(param_2 + 8);
97: uVar3 = *(uint *)((long)param_1 + 0x34);
98: }
99: }
100: }
101: *(uint *)(param_2 + 0x48) = uVar3;
102: /* WARNING: Could not recover jumptable at 0x0015101b. Too many branches */
103: /* WARNING: Treating indirect jump as call */
104: (*UNRECOVERED_JUMPTABLE)(param_1,param_2,UNRECOVERED_JUMPTABLE);
105: return;
106: }
107: 
