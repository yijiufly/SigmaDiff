1: 
2: void FUN_0011c3e0(code **param_1,undefined param_2,uint param_3)
3: 
4: {
5: long *plVar1;
6: code **ppcVar2;
7: undefined8 *puVar3;
8: undefined *puVar4;
9: long *plVar5;
10: int iVar6;
11: 
12: if (0xfffd < param_3) {
13: ppcVar2 = (code **)*param_1;
14: *(undefined4 *)(ppcVar2 + 5) = 0xb;
15: (**ppcVar2)();
16: }
17: puVar3 = (undefined8 *)param_1[5];
18: puVar4 = (undefined *)*puVar3;
19: *puVar3 = puVar4 + 1;
20: *puVar4 = 0xff;
21: plVar1 = puVar3 + 1;
22: *plVar1 = *plVar1 + -1;
23: if (*plVar1 == 0) {
24: iVar6 = (*(code *)puVar3[3])(param_1);
25: if (iVar6 == 0) {
26: ppcVar2 = (code **)*param_1;
27: *(undefined4 *)(ppcVar2 + 5) = 0x18;
28: (**ppcVar2)(param_1);
29: }
30: }
31: plVar5 = (long *)param_1[5];
32: puVar4 = (undefined *)*plVar5;
33: *plVar5 = (long)(puVar4 + 1);
34: *puVar4 = param_2;
35: plVar1 = plVar5 + 1;
36: *plVar1 = *plVar1 + -1;
37: if (*plVar1 == 0) {
38: iVar6 = (*(code *)plVar5[3])(param_1);
39: if (iVar6 == 0) {
40: ppcVar2 = (code **)*param_1;
41: *(undefined4 *)(ppcVar2 + 5) = 0x18;
42: (**ppcVar2)(param_1);
43: }
44: }
45: plVar5 = (long *)param_1[5];
46: puVar4 = (undefined *)*plVar5;
47: *plVar5 = (long)(puVar4 + 1);
48: *puVar4 = (char)(param_3 + 2 >> 8);
49: plVar1 = plVar5 + 1;
50: *plVar1 = *plVar1 + -1;
51: if (*plVar1 == 0) {
52: iVar6 = (*(code *)plVar5[3])(param_1);
53: if (iVar6 == 0) {
54: ppcVar2 = (code **)*param_1;
55: *(undefined4 *)(ppcVar2 + 5) = 0x18;
56: (**ppcVar2)(param_1);
57: }
58: }
59: plVar5 = (long *)param_1[5];
60: puVar4 = (undefined *)*plVar5;
61: *plVar5 = (long)(puVar4 + 1);
62: *puVar4 = (char)(param_3 + 2);
63: plVar1 = plVar5 + 1;
64: *plVar1 = *plVar1 + -1;
65: if (*plVar1 == 0) {
66: iVar6 = (*(code *)plVar5[3])(param_1);
67: if (iVar6 == 0) {
68: ppcVar2 = (code **)*param_1;
69: *(undefined4 *)(ppcVar2 + 5) = 0x18;
70: /* WARNING: Could not recover jumptable at 0x0011c4cd. Too many branches */
71: /* WARNING: Treating indirect jump as call */
72: (**ppcVar2)(param_1);
73: return;
74: }
75: }
76: return;
77: }
78: 
