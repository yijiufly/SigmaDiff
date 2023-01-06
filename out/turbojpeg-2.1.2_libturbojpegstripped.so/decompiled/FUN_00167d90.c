1: 
2: void FUN_00167d90(code **param_1,long param_2)
3: 
4: {
5: FILE *__stream;
6: code **ppcVar1;
7: code **ppcVar2;
8: int iVar3;
9: uint uVar4;
10: void **ppvVar5;
11: size_t sVar6;
12: code *UNRECOVERED_JUMPTABLE;
13: uint uVar7;
14: 
15: uVar4 = *(uint *)((long)param_1 + 0x34);
16: UNRECOVERED_JUMPTABLE = (code *)(ulong)uVar4;
17: __stream = *(FILE **)(param_2 + 0x18);
18: ppcVar1 = (code **)param_1[2];
19: if (uVar4 != 0) {
20: uVar7 = 0;
21: LAB_00167dce:
22: do {
23: if (ppcVar1 != (code **)0x0) {
24: ppcVar1[2] = UNRECOVERED_JUMPTABLE;
25: ppcVar1[1] = (code *)(ulong)uVar7;
26: (**ppcVar1)(param_1);
27: }
28: ppvVar5 = (void **)(**(code **)(param_1[1] + 0x38))
29: (param_1,*(undefined8 *)(param_2 + 0x40),uVar7,1,1);
30: sVar6 = fread(*ppvVar5,1,(ulong)*(uint *)(param_2 + 0x4c),__stream);
31: if (*(uint *)(param_2 + 0x4c) != sVar6) {
32: iVar3 = feof(__stream);
33: ppcVar2 = (code **)*param_1;
34: if (iVar3 == 0) {
35: *(undefined4 *)(ppcVar2 + 5) = 0x24;
36: uVar7 = uVar7 + 1;
37: (**ppcVar2)(param_1);
38: uVar4 = *(uint *)((long)param_1 + 0x34);
39: UNRECOVERED_JUMPTABLE = (code *)(ulong)uVar4;
40: if (uVar4 <= uVar7) break;
41: goto LAB_00167dce;
42: }
43: *(undefined4 *)(ppcVar2 + 5) = 0x2b;
44: (**ppcVar2)(param_1);
45: }
46: uVar4 = *(uint *)((long)param_1 + 0x34);
47: UNRECOVERED_JUMPTABLE = (code *)(ulong)uVar4;
48: uVar7 = uVar7 + 1;
49: } while (uVar7 < uVar4);
50: }
51: if (ppcVar1 != (code **)0x0) {
52: *(int *)(ppcVar1 + 4) = *(int *)(ppcVar1 + 4) + 1;
53: }
54: iVar3 = *(int *)(param_2 + 0x50);
55: if (iVar3 == 0x18) {
56: UNRECOVERED_JUMPTABLE = FUN_00167770;
57: *(code **)(param_2 + 8) = FUN_00167770;
58: }
59: else {
60: if (iVar3 == 0x20) {
61: UNRECOVERED_JUMPTABLE = FUN_00167a80;
62: *(code **)(param_2 + 8) = FUN_00167a80;
63: }
64: else {
65: if (iVar3 == 8) {
66: UNRECOVERED_JUMPTABLE = FUN_00167340;
67: *(code **)(param_2 + 8) = FUN_00167340;
68: }
69: else {
70: ppcVar1 = (code **)*param_1;
71: *(undefined4 *)(ppcVar1 + 5) = 0x3ea;
72: (**ppcVar1)(param_1);
73: UNRECOVERED_JUMPTABLE = *(code **)(param_2 + 8);
74: uVar4 = *(uint *)((long)param_1 + 0x34);
75: }
76: }
77: }
78: *(uint *)(param_2 + 0x48) = uVar4;
79: /* WARNING: Could not recover jumptable at 0x00167e89. Too many branches */
80: /* WARNING: Treating indirect jump as call */
81: (*UNRECOVERED_JUMPTABLE)(param_1,param_2,UNRECOVERED_JUMPTABLE);
82: return;
83: }
84: 
