1: 
2: void FUN_0012be00(code **param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: code *pcVar4;
9: code *pcVar5;
10: code **ppcVar6;
11: 
12: pcVar4 = param_1[0x44];
13: if (*(int *)(pcVar4 + 0x10) == 0) {
14: if ((*(int *)((long)param_1 + 0x6c) != 0) && (param_1[0x14] == (code *)0x0)) {
15: if ((*(int *)((long)param_1 + 0x74) == 0) || (*(int *)((long)param_1 + 0x84) == 0)) {
16: if (*(int *)((long)param_1 + 0x7c) == 0) {
17: ppcVar6 = (code **)*param_1;
18: *(undefined4 *)(ppcVar6 + 5) = 0x2e;
19: (**ppcVar6)(param_1);
20: }
21: else {
22: param_1[0x4e] = *(code **)(pcVar4 + 0x78);
23: }
24: }
25: else {
26: param_1[0x4e] = *(code **)(pcVar4 + 0x80);
27: *(undefined4 *)(pcVar4 + 0x10) = 1;
28: }
29: }
30: (**(code **)param_1[0x4b])(param_1);
31: (**(code **)(param_1[0x46] + 0x10))(param_1);
32: if (*(int *)((long)param_1 + 0x5c) == 0) {
33: if (*(int *)(pcVar4 + 0x74) == 0) {
34: (**(code **)param_1[0x4d])(param_1);
35: }
36: (**(code **)param_1[0x4c])();
37: if (*(int *)((long)param_1 + 0x6c) != 0) {
38: (**(code **)param_1[0x4e])(param_1);
39: }
40: (**(code **)param_1[0x47])(param_1);
41: (**(code **)param_1[0x45])(param_1);
42: }
43: }
44: else {
45: ppcVar6 = (code **)param_1[0x4e];
46: *(undefined4 *)(pcVar4 + 0x10) = 0;
47: (**ppcVar6)(param_1,0);
48: (**(code **)param_1[0x47])(param_1,2);
49: (**(code **)param_1[0x45])(param_1);
50: }
51: pcVar5 = param_1[2];
52: if (pcVar5 != (code *)0x0) {
53: iVar3 = *(int *)(pcVar4 + 0x10);
54: iVar1 = *(int *)(pcVar4 + 0x70);
55: iVar2 = *(int *)(param_1 + 0xb);
56: *(int *)(pcVar5 + 0x18) = iVar1;
57: iVar1 = (2 - (uint)(iVar3 == 0)) + iVar1;
58: *(int *)(pcVar5 + 0x1c) = iVar1;
59: if ((iVar2 != 0) && (*(int *)(param_1[0x48] + 0x24) == 0)) {
60: *(uint *)(pcVar5 + 0x1c) = (2 - (uint)(*(int *)((long)param_1 + 0x84) == 0)) + iVar1;
61: }
62: }
63: return;
64: }
65: 
