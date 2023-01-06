1: 
2: void FUN_001268f0(code **param_1,void **param_2,void **param_3)
3: 
4: {
5: code **ppcVar1;
6: void **ppvVar2;
7: void *pvVar3;
8: void *pvVar4;
9: 
10: if ((param_2 == (void **)0x0) || (param_3 == (void **)0x0)) {
11: ppcVar1 = (code **)*param_1;
12: *(undefined4 *)(ppcVar1 + 5) = 0x17;
13: (**ppcVar1)(param_1);
14: }
15: ppvVar2 = (void **)param_1[5];
16: if (ppvVar2 == (void **)0x0) {
17: ppvVar2 = (void **)(**(code **)param_1[1])(param_1,0,0x50);
18: param_1[5] = (code *)ppvVar2;
19: }
20: else {
21: if ((code *)ppvVar2[2] != FUN_001266d0) {
22: ppcVar1 = (code **)*param_1;
23: *(undefined4 *)(ppcVar1 + 5) = 0x17;
24: (**ppcVar1)(param_1);
25: ppvVar2 = (void **)param_1[5];
26: }
27: }
28: ppvVar2[7] = (void *)0x0;
29: ppvVar2[2] = FUN_001266d0;
30: ppvVar2[5] = param_2;
31: ppvVar2[6] = param_3;
32: ppvVar2[3] = FUN_001267f0;
33: ppvVar2[4] = FUN_001266e0;
34: pvVar3 = *param_2;
35: if ((pvVar3 == (void *)0x0) || (pvVar4 = *param_3, pvVar4 == (void *)0x0)) {
36: pvVar3 = malloc(0x1000);
37: *param_2 = pvVar3;
38: ppvVar2[7] = pvVar3;
39: if (pvVar3 == (void *)0x0) {
40: ppcVar1 = (code **)*param_1;
41: ppcVar1[5] = (code *)0xa00000036;
42: (**ppcVar1)(param_1);
43: }
44: pvVar3 = *param_2;
45: *param_3 = (void *)0x1000;
46: pvVar4 = (void *)0x1000;
47: }
48: ppvVar2[8] = pvVar3;
49: *ppvVar2 = pvVar3;
50: ppvVar2[9] = pvVar4;
51: ppvVar2[1] = pvVar4;
52: return;
53: }
54: 
