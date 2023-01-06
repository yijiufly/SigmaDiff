1: 
2: void FUN_00114360(code **param_1)
3: 
4: {
5: undefined8 *puVar1;
6: undefined *puVar2;
7: long lVar3;
8: int iVar4;
9: ulong uVar5;
10: code **ppcVar6;
11: 
12: puVar1 = (undefined8 *)param_1[5];
13: puVar2 = (undefined *)*puVar1;
14: *puVar1 = puVar2 + 1;
15: *puVar2 = 0xff;
16: lVar3 = puVar1[1];
17: puVar1[1] = lVar3 + -1;
18: if (lVar3 + -1 == 0) {
19: iVar4 = (*(code *)puVar1[3])();
20: if (iVar4 == 0) {
21: ppcVar6 = (code **)*param_1;
22: *(undefined4 *)(ppcVar6 + 5) = 0x18;
23: (**ppcVar6)(param_1);
24: }
25: }
26: puVar1 = (undefined8 *)param_1[5];
27: puVar2 = (undefined *)*puVar1;
28: *puVar1 = puVar2 + 1;
29: *puVar2 = 0xd8;
30: lVar3 = puVar1[1];
31: puVar1[1] = lVar3 + -1;
32: if (lVar3 + -1 == 0) {
33: iVar4 = (*(code *)puVar1[3])(param_1);
34: if (iVar4 == 0) {
35: ppcVar6 = (code **)*param_1;
36: *(undefined4 *)(ppcVar6 + 5) = 0x18;
37: (**ppcVar6)(param_1);
38: }
39: }
40: uVar5 = 0;
41: do {
42: if (param_1[uVar5 + 0xc] != (code *)0x0) {
43: FUN_00113f30(param_1,uVar5 & 0xffffffff);
44: }
45: uVar5 = uVar5 + 1;
46: } while (uVar5 != 4);
47: iVar4 = 0;
48: ppcVar6 = param_1;
49: if (*(int *)((long)param_1 + 0x104) == 0) {
50: do {
51: if (ppcVar6[0x10] != (code *)0x0) {
52: FUN_00113bf0(param_1,iVar4,0);
53: }
54: if (ppcVar6[0x14] != (code *)0x0) {
55: FUN_00113bf0(param_1,iVar4,1);
56: }
57: iVar4 = iVar4 + 1;
58: ppcVar6 = ppcVar6 + 1;
59: } while (iVar4 != 4);
60: }
61: puVar1 = (undefined8 *)param_1[5];
62: puVar2 = (undefined *)*puVar1;
63: *puVar1 = puVar2 + 1;
64: *puVar2 = 0xff;
65: lVar3 = puVar1[1];
66: puVar1[1] = lVar3 + -1;
67: if (lVar3 + -1 == 0) {
68: iVar4 = (*(code *)puVar1[3])(param_1);
69: if (iVar4 == 0) {
70: ppcVar6 = (code **)*param_1;
71: *(undefined4 *)(ppcVar6 + 5) = 0x18;
72: (**ppcVar6)(param_1);
73: }
74: }
75: puVar1 = (undefined8 *)param_1[5];
76: puVar2 = (undefined *)*puVar1;
77: *puVar1 = puVar2 + 1;
78: *puVar2 = 0xd9;
79: lVar3 = puVar1[1];
80: puVar1[1] = lVar3 + -1;
81: if (lVar3 + -1 == 0) {
82: iVar4 = (*(code *)puVar1[3])(param_1);
83: if (iVar4 == 0) {
84: ppcVar6 = (code **)*param_1;
85: *(undefined4 *)(ppcVar6 + 5) = 0x18;
86: /* WARNING: Could not recover jumptable at 0x001144de. Too many branches */
87: /* WARNING: Treating indirect jump as call */
88: (**ppcVar6)(param_1);
89: return;
90: }
91: }
92: return;
93: }
94: 
