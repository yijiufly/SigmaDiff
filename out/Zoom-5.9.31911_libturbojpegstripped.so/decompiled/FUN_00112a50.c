1: 
2: void FUN_00112a50(code **param_1,undefined param_2,uint param_3)
3: 
4: {
5: code **ppcVar1;
6: undefined8 *puVar2;
7: undefined *puVar3;
8: long lVar4;
9: long *plVar5;
10: int iVar6;
11: 
12: if (0xfffd < param_3) {
13: ppcVar1 = (code **)*param_1;
14: *(undefined4 *)(ppcVar1 + 5) = 0xb;
15: (**ppcVar1)();
16: }
17: puVar2 = (undefined8 *)param_1[5];
18: puVar3 = (undefined *)*puVar2;
19: *puVar2 = puVar3 + 1;
20: *puVar3 = 0xff;
21: lVar4 = puVar2[1];
22: puVar2[1] = lVar4 + -1;
23: if (lVar4 + -1 == 0) {
24: iVar6 = (*(code *)puVar2[3])(param_1);
25: if (iVar6 == 0) {
26: ppcVar1 = (code **)*param_1;
27: *(undefined4 *)(ppcVar1 + 5) = 0x18;
28: (**ppcVar1)(param_1);
29: }
30: }
31: plVar5 = (long *)param_1[5];
32: puVar3 = (undefined *)*plVar5;
33: *plVar5 = (long)(puVar3 + 1);
34: *puVar3 = param_2;
35: lVar4 = plVar5[1];
36: plVar5[1] = lVar4 + -1;
37: if (lVar4 + -1 == 0) {
38: iVar6 = (*(code *)plVar5[3])(param_1);
39: if (iVar6 == 0) {
40: ppcVar1 = (code **)*param_1;
41: *(undefined4 *)(ppcVar1 + 5) = 0x18;
42: (**ppcVar1)(param_1);
43: }
44: }
45: plVar5 = (long *)param_1[5];
46: puVar3 = (undefined *)*plVar5;
47: *plVar5 = (long)(puVar3 + 1);
48: *puVar3 = (char)(param_3 + 2 >> 8);
49: lVar4 = plVar5[1];
50: plVar5[1] = lVar4 + -1;
51: if (lVar4 + -1 == 0) {
52: iVar6 = (*(code *)plVar5[3])(param_1);
53: if (iVar6 == 0) {
54: ppcVar1 = (code **)*param_1;
55: *(undefined4 *)(ppcVar1 + 5) = 0x18;
56: (**ppcVar1)(param_1);
57: }
58: }
59: plVar5 = (long *)param_1[5];
60: puVar3 = (undefined *)*plVar5;
61: *plVar5 = (long)(puVar3 + 1);
62: *puVar3 = (char)(param_3 + 2);
63: lVar4 = plVar5[1];
64: plVar5[1] = lVar4 + -1;
65: if (lVar4 + -1 == 0) {
66: iVar6 = (*(code *)plVar5[3])(param_1);
67: if (iVar6 == 0) {
68: ppcVar1 = (code **)*param_1;
69: *(undefined4 *)(ppcVar1 + 5) = 0x18;
70: /* WARNING: Could not recover jumptable at 0x00112b56. Too many branches */
71: /* WARNING: Treating indirect jump as call */
72: (**ppcVar1)(param_1);
73: return;
74: }
75: }
76: return;
77: }
78: 
