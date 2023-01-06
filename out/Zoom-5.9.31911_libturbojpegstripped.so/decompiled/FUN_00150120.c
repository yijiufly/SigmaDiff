1: 
2: void FUN_00150120(code **param_1,void **param_2,void **param_3,int param_4)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: void *pvVar3;
8: void **ppvVar4;
9: bool bVar5;
10: 
11: if ((param_2 == (void **)0x0) || (param_3 == (void **)0x0)) {
12: ppcVar1 = (code **)*param_1;
13: *(undefined4 *)(ppcVar1 + 5) = 0x17;
14: (**ppcVar1)(param_1);
15: }
16: ppvVar4 = (void **)param_1[5];
17: if (ppvVar4 == (void **)0x0) {
18: ppvVar4 = (void **)(**(code **)param_1[1])(param_1,0,0x58);
19: param_1[5] = (code *)ppvVar4;
20: ppvVar4[7] = (void *)0x0;
21: ppvVar4[8] = (void *)0x0;
22: }
23: else {
24: if ((code *)ppvVar4[2] != FUN_00150030) {
25: ppcVar1 = (code **)*param_1;
26: *(undefined4 *)(ppcVar1 + 5) = 0x17;
27: (**ppcVar1)(param_1);
28: ppvVar4 = (void **)param_1[5];
29: }
30: }
31: bVar5 = false;
32: ppvVar4[2] = FUN_00150030;
33: ppvVar4[3] = FUN_00150070;
34: ppvVar4[4] = FUN_00150040;
35: if ((ppvVar4[8] == *param_2) && (ppvVar4[8] != (void *)0x0)) {
36: bVar5 = param_4 != 0;
37: }
38: ppvVar4[5] = param_2;
39: ppvVar4[6] = param_3;
40: pvVar3 = *param_2;
41: *(int *)(ppvVar4 + 10) = param_4;
42: if ((pvVar3 == (void *)0x0) || (*param_3 == (void *)0x0)) {
43: if (param_4 != 0) {
44: pvVar3 = malloc(0x1000);
45: *param_2 = pvVar3;
46: ppvVar4[7] = pvVar3;
47: if (pvVar3 == (void *)0x0) {
48: pcVar2 = *param_1;
49: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
50: *(undefined4 *)(pcVar2 + 0x2c) = 10;
51: (**(code **)*param_1)(param_1);
52: }
53: pvVar3 = *param_2;
54: *param_3 = (void *)0x1000;
55: ppvVar4[8] = pvVar3;
56: *ppvVar4 = pvVar3;
57: goto joined_r0x0015022e;
58: }
59: ppcVar1 = (code **)*param_1;
60: *(undefined4 *)(ppcVar1 + 5) = 0x17;
61: (**ppcVar1)(param_1);
62: pvVar3 = *param_2;
63: }
64: ppvVar4[8] = pvVar3;
65: *ppvVar4 = pvVar3;
66: joined_r0x0015022e:
67: if (bVar5) {
68: pvVar3 = ppvVar4[9];
69: }
70: else {
71: pvVar3 = *param_3;
72: ppvVar4[9] = pvVar3;
73: }
74: ppvVar4[1] = pvVar3;
75: return;
76: }
77: 
