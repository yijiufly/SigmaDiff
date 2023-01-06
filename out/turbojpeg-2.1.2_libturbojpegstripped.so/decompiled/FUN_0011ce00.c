1: 
2: void FUN_0011ce00(code **param_1)
3: 
4: {
5: long *plVar1;
6: undefined8 *puVar2;
7: undefined *puVar3;
8: code **ppcVar4;
9: int iVar5;
10: ulong uVar6;
11: 
12: puVar2 = (undefined8 *)param_1[5];
13: puVar3 = (undefined *)*puVar2;
14: *puVar2 = puVar3 + 1;
15: *puVar3 = 0xff;
16: plVar1 = puVar2 + 1;
17: *plVar1 = *plVar1 + -1;
18: if (*plVar1 == 0) {
19: iVar5 = (*(code *)puVar2[3])();
20: if (iVar5 == 0) {
21: ppcVar4 = (code **)*param_1;
22: *(undefined4 *)(ppcVar4 + 5) = 0x18;
23: (**ppcVar4)(param_1);
24: }
25: }
26: puVar2 = (undefined8 *)param_1[5];
27: puVar3 = (undefined *)*puVar2;
28: *puVar2 = puVar3 + 1;
29: *puVar3 = 0xd8;
30: plVar1 = puVar2 + 1;
31: *plVar1 = *plVar1 + -1;
32: if (*plVar1 == 0) {
33: iVar5 = (*(code *)puVar2[3])(param_1);
34: if (iVar5 == 0) {
35: ppcVar4 = (code **)*param_1;
36: *(undefined4 *)(ppcVar4 + 5) = 0x18;
37: (**ppcVar4)(param_1);
38: }
39: }
40: uVar6 = 0;
41: do {
42: if (param_1[uVar6 + 0xc] != (code *)0x0) {
43: FUN_0011ca80(param_1,uVar6 & 0xffffffff);
44: }
45: uVar6 = uVar6 + 1;
46: } while (uVar6 != 4);
47: if (*(int *)((long)param_1 + 0x104) == 0) {
48: uVar6 = 0;
49: do {
50: if (param_1[uVar6 + 0x10] != (code *)0x0) {
51: FUN_0011c800(param_1,uVar6 & 0xffffffff,0);
52: }
53: if (param_1[uVar6 + 0x14] != (code *)0x0) {
54: FUN_0011c800(param_1,uVar6 & 0xffffffff,1);
55: }
56: uVar6 = uVar6 + 1;
57: } while (uVar6 != 4);
58: }
59: puVar2 = (undefined8 *)param_1[5];
60: puVar3 = (undefined *)*puVar2;
61: *puVar2 = puVar3 + 1;
62: *puVar3 = 0xff;
63: plVar1 = puVar2 + 1;
64: *plVar1 = *plVar1 + -1;
65: if (*plVar1 == 0) {
66: iVar5 = (*(code *)puVar2[3])(param_1);
67: if (iVar5 == 0) {
68: ppcVar4 = (code **)*param_1;
69: *(undefined4 *)(ppcVar4 + 5) = 0x18;
70: (**ppcVar4)(param_1);
71: }
72: }
73: puVar2 = (undefined8 *)param_1[5];
74: puVar3 = (undefined *)*puVar2;
75: *puVar2 = puVar3 + 1;
76: *puVar3 = 0xd9;
77: plVar1 = puVar2 + 1;
78: *plVar1 = *plVar1 + -1;
79: if (*plVar1 == 0) {
80: iVar5 = (*(code *)puVar2[3])(param_1);
81: if (iVar5 == 0) {
82: ppcVar4 = (code **)*param_1;
83: *(undefined4 *)(ppcVar4 + 5) = 0x18;
84: /* WARNING: Could not recover jumptable at 0x0011cf36. Too many branches */
85: /* WARNING: Treating indirect jump as call */
86: (**ppcVar4)(param_1);
87: return;
88: }
89: }
90: return;
91: }
92: 
