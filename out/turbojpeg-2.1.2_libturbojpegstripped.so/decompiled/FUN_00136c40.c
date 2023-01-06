1: 
2: void FUN_00136c40(code **param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: int iVar6;
11: 
12: pcVar3 = param_1[0x44];
13: if (*(int *)(pcVar3 + 0x10) == 0) {
14: if ((*(int *)((long)param_1 + 0x6c) != 0) && (param_1[0x14] == (code *)0x0)) {
15: if ((*(int *)((long)param_1 + 0x74) == 0) || (*(int *)((long)param_1 + 0x84) == 0)) {
16: if (*(int *)((long)param_1 + 0x7c) == 0) {
17: ppcVar4 = (code **)*param_1;
18: *(undefined4 *)(ppcVar4 + 5) = 0x2e;
19: (**ppcVar4)(param_1);
20: }
21: else {
22: param_1[0x4e] = *(code **)(pcVar3 + 0x80);
23: }
24: }
25: else {
26: param_1[0x4e] = *(code **)(pcVar3 + 0x88);
27: *(undefined4 *)(pcVar3 + 0x10) = 1;
28: }
29: }
30: (**(code **)param_1[0x4b])(param_1);
31: (**(code **)(param_1[0x46] + 0x10))();
32: if (*(int *)((long)param_1 + 0x5c) == 0) {
33: if (*(int *)(pcVar3 + 0x7c) == 0) {
34: (**(code **)param_1[0x4d])(param_1);
35: }
36: (**(code **)param_1[0x4c])(param_1);
37: if (*(int *)((long)param_1 + 0x6c) != 0) {
38: (**(code **)param_1[0x4e])(param_1);
39: }
40: (**(code **)param_1[0x47])(param_1);
41: (**(code **)param_1[0x45])();
42: }
43: }
44: else {
45: ppcVar4 = (code **)param_1[0x4e];
46: *(undefined4 *)(pcVar3 + 0x10) = 0;
47: (**ppcVar4)(param_1,0);
48: (**(code **)param_1[0x47])(param_1,2);
49: (**(code **)param_1[0x45])();
50: }
51: pcVar5 = param_1[2];
52: if (pcVar5 != (code *)0x0) {
53: iVar6 = *(int *)(pcVar3 + 0x10);
54: iVar1 = *(int *)(pcVar3 + 0x78);
55: iVar2 = *(int *)(param_1 + 0xb);
56: *(int *)(pcVar5 + 0x18) = iVar1;
57: iVar6 = iVar1 + 1 + (uint)(iVar6 != 0);
58: *(int *)(pcVar5 + 0x1c) = iVar6;
59: if ((iVar2 != 0) && (*(int *)(param_1[0x48] + 0x24) == 0)) {
60: *(uint *)(pcVar5 + 0x1c) = iVar6 + 1 + (uint)(*(int *)((long)param_1 + 0x84) != 0);
61: }
62: }
63: return;
64: }
65: 
