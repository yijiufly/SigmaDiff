1: 
2: void FUN_0011e870(code **param_1,void **param_2,void **param_3)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: void *pvVar3;
8: void **ppvVar4;
9: void *pvVar5;
10: 
11: if ((param_2 == (void **)0x0) || (param_3 == (void **)0x0)) {
12: ppcVar1 = (code **)*param_1;
13: *(undefined4 *)(ppcVar1 + 5) = 0x17;
14: (**ppcVar1)(param_1);
15: }
16: ppvVar4 = (void **)param_1[5];
17: if (ppvVar4 == (void **)0x0) {
18: ppvVar4 = (void **)(**(code **)param_1[1])(param_1,0,0x50);
19: param_1[5] = (code *)ppvVar4;
20: }
21: else {
22: if ((code *)ppvVar4[2] != FUN_0011e650) {
23: ppcVar1 = (code **)*param_1;
24: *(undefined4 *)(ppcVar1 + 5) = 0x17;
25: (**ppcVar1)(param_1);
26: ppvVar4 = (void **)param_1[5];
27: }
28: }
29: ppvVar4[5] = param_2;
30: ppvVar4[6] = param_3;
31: ppvVar4[7] = (void *)0x0;
32: ppvVar4[2] = FUN_0011e650;
33: ppvVar4[3] = FUN_0011e6e0;
34: ppvVar4[4] = FUN_0011e660;
35: pvVar3 = *param_2;
36: if ((pvVar3 == (void *)0x0) || (pvVar5 = *param_3, pvVar5 == (void *)0x0)) {
37: pvVar3 = malloc(0x1000);
38: *param_2 = pvVar3;
39: ppvVar4[7] = pvVar3;
40: if (pvVar3 == (void *)0x0) {
41: pcVar2 = *param_1;
42: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
43: *(undefined4 *)(pcVar2 + 0x2c) = 10;
44: (**(code **)*param_1)(param_1);
45: }
46: pvVar3 = *param_2;
47: *param_3 = (void *)0x1000;
48: pvVar5 = (void *)0x1000;
49: }
50: ppvVar4[8] = pvVar3;
51: *ppvVar4 = pvVar3;
52: ppvVar4[9] = pvVar5;
53: ppvVar4[1] = pvVar5;
54: return;
55: }
56: 
