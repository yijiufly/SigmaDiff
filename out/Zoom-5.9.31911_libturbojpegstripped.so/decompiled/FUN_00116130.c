1: 
2: void FUN_00116130(code **param_1)
3: 
4: {
5: int iVar1;
6: code *pcVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: 
10: pcVar2 = param_1[0x36];
11: iVar1 = *(int *)(pcVar2 + 0x20);
12: if (iVar1 == 1) {
13: FUN_00115ff0();
14: FUN_00115d40();
15: if (((*(int *)((long)param_1 + 0x19c) != 0) || (*(int *)((long)param_1 + 0x1a4) == 0)) ||
16: (*(int *)((long)param_1 + 0x104) != 0)) {
17: (**(code **)param_1[0x3e])(param_1,1);
18: (**(code **)param_1[0x39])(param_1,2);
19: *(undefined4 *)(pcVar2 + 0x18) = 0;
20: goto LAB_001161a3;
21: }
22: *(undefined4 *)(pcVar2 + 0x20) = 2;
23: *(int *)(pcVar2 + 0x24) = *(int *)(pcVar2 + 0x24) + 1;
24: }
25: else {
26: if (iVar1 == 0) {
27: FUN_00115ff0();
28: FUN_00115d40(param_1);
29: if (*(int *)(param_1 + 0x20) == 0) {
30: (**(code **)param_1[0x3b])(param_1);
31: (**(code **)param_1[0x3c])(param_1);
32: (**(code **)param_1[0x38])(param_1,0);
33: }
34: (**(code **)param_1[0x3d])(param_1);
35: (**(code **)param_1[0x3e])(param_1,*(undefined4 *)(param_1 + 0x21));
36: (**(code **)param_1[0x39])(param_1,(1 < *(int *)(pcVar2 + 0x28)) * '\x03');
37: (**(code **)param_1[0x37])(param_1,0);
38: *(uint *)(pcVar2 + 0x18) = (uint)(*(int *)(param_1 + 0x21) == 0);
39: goto LAB_001161a3;
40: }
41: if (iVar1 != 2) {
42: ppcVar4 = (code **)*param_1;
43: *(undefined4 *)(ppcVar4 + 5) = 0x30;
44: (**ppcVar4)();
45: goto LAB_001161a3;
46: }
47: }
48: if (*(int *)(param_1 + 0x21) == 0) {
49: FUN_00115ff0(param_1);
50: FUN_00115d40(param_1);
51: }
52: (**(code **)param_1[0x3e])(param_1,0);
53: (**(code **)param_1[0x39])(param_1,2);
54: if (*(int *)(pcVar2 + 0x2c) == 0) {
55: (**(code **)(param_1[0x3a] + 8))(param_1);
56: }
57: (**(code **)(param_1[0x3a] + 0x10))(param_1);
58: *(undefined4 *)(pcVar2 + 0x18) = 0;
59: LAB_001161a3:
60: iVar1 = *(int *)(pcVar2 + 0x28);
61: *(uint *)(pcVar2 + 0x1c) = (uint)(*(int *)(pcVar2 + 0x24) == iVar1 + -1);
62: pcVar3 = param_1[2];
63: if (pcVar3 != (code *)0x0) {
64: *(int *)(pcVar3 + 0x18) = *(int *)(pcVar2 + 0x24);
65: *(int *)(pcVar3 + 0x1c) = iVar1;
66: }
67: return;
68: }
69: 
