1: 
2: void FUN_0013c4b0(code **param_1,int param_2)
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
15: *(undefined8 *)(pcVar1 + 0x24) = 0;
16: *(code **)(pcVar1 + 8) = FUN_0013c730;
17: return;
18: }
19: if (param_2 != 3) {
20: if (param_2 == 0) {
21: if (*(int *)((long)param_1 + 0x6c) == 0) {
22: uVar2 = *(undefined8 *)(param_1[0x4c] + 8);
23: *(undefined8 *)(pcVar1 + 0x24) = 0;
24: *(undefined8 *)(pcVar1 + 8) = uVar2;
25: return;
26: }
27: *(code **)(pcVar1 + 8) = FUN_0013c5a0;
28: if (*(long *)(pcVar1 + 0x18) == 0) {
29: uVar2 = (**(code **)(param_1[1] + 0x38))
30: (param_1,*(undefined8 *)(pcVar1 + 0x10),0,*(undefined4 *)(pcVar1 + 0x20),1
31: );
32: *(undefined8 *)(pcVar1 + 0x18) = uVar2;
33: }
34: }
35: else {
36: param_1 = (code **)*param_1;
37: *(undefined4 *)(param_1 + 5) = 4;
38: (**param_1)();
39: }
40: *(undefined8 *)(pcVar1 + 0x24) = 0;
41: return;
42: }
43: if (*(long *)(pcVar1 + 0x10) == 0) {
44: param_1 = (code **)*param_1;
45: *(undefined4 *)(param_1 + 5) = 4;
46: (**param_1)();
47: }
48: *(undefined8 *)(pcVar1 + 0x24) = 0;
49: *(code **)(pcVar1 + 8) = FUN_0013c650;
50: return;
51: }
52: 
