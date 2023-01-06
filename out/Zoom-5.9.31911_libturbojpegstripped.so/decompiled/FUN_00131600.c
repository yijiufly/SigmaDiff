1: 
2: void FUN_00131600(code **param_1,int param_2)
3: 
4: {
5: code *pcVar1;
6: undefined8 uVar2;
7: 
8: pcVar1 = param_1[0x47];
9: if (param_2 == 2) {
10: if (*(long *)(pcVar1 + 0x10) == 0) {
11: param_1 = (code **)*param_1;
12: *(undefined4 *)(param_1 + 5) = 4;
13: (**param_1)();
14: }
15: *(undefined4 *)(pcVar1 + 0x28) = 0;
16: *(undefined4 *)(pcVar1 + 0x24) = 0;
17: *(code **)(pcVar1 + 8) = FUN_00131870;
18: return;
19: }
20: if (param_2 != 3) {
21: if (param_2 == 0) {
22: if (*(int *)((long)param_1 + 0x6c) == 0) {
23: *(undefined8 *)(pcVar1 + 8) = *(undefined8 *)(param_1[0x4c] + 8);
24: }
25: else {
26: *(code **)(pcVar1 + 8) = FUN_00131710;
27: if (*(long *)(pcVar1 + 0x18) == 0) {
28: uVar2 = (**(code **)(param_1[1] + 0x38))
29: (param_1,*(undefined8 *)(pcVar1 + 0x10),0,*(undefined4 *)(pcVar1 + 0x20)
30: ,1);
31: *(undefined8 *)(pcVar1 + 0x18) = uVar2;
32: }
33: }
34: }
35: else {
36: param_1 = (code **)*param_1;
37: *(undefined4 *)(param_1 + 5) = 4;
38: (**param_1)();
39: }
40: *(undefined4 *)(pcVar1 + 0x28) = 0;
41: *(undefined4 *)(pcVar1 + 0x24) = 0;
42: return;
43: }
44: if (*(long *)(pcVar1 + 0x10) == 0) {
45: param_1 = (code **)*param_1;
46: *(undefined4 *)(param_1 + 5) = 4;
47: (**param_1)();
48: }
49: *(undefined4 *)(pcVar1 + 0x28) = 0;
50: *(undefined4 *)(pcVar1 + 0x24) = 0;
51: *(code **)(pcVar1 + 8) = FUN_00131790;
52: return;
53: }
54: 
