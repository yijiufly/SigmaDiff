1: 
2: void FUN_0011ebc0(code **param_1,long param_2,long param_3)
3: 
4: {
5: code **ppcVar1;
6: long *plVar2;
7: 
8: if ((param_2 == 0) || (param_3 == 0)) {
9: ppcVar1 = (code **)*param_1;
10: *(undefined4 *)(ppcVar1 + 5) = 0x2a;
11: (**ppcVar1)(param_1);
12: }
13: plVar2 = (long *)param_1[5];
14: if (plVar2 == (long *)0x0) {
15: plVar2 = (long *)(**(code **)param_1[1])(param_1,0,0x38);
16: param_1[5] = (code *)plVar2;
17: }
18: else {
19: if ((code *)plVar2[2] != FUN_0011e9c0) {
20: ppcVar1 = (code **)*param_1;
21: *(undefined4 *)(ppcVar1 + 5) = 0x17;
22: (**ppcVar1)(param_1);
23: plVar2 = (long *)param_1[5];
24: }
25: }
26: plVar2[1] = param_3;
27: *plVar2 = param_2;
28: plVar2[2] = (long)FUN_0011e9c0;
29: plVar2[3] = (long)FUN_0011e9d0;
30: plVar2[5] = (long)FUN_0012b9a0;
31: plVar2[6] = (long)FUN_0011ea60;
32: plVar2[4] = (long)FUN_0011ea10;
33: return;
34: }
35: 
