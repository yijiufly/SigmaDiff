1: 
2: void FUN_00104290(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: code *pcVar2;
7: 
8: iVar1 = *(int *)((long)param_1 + 0x144);
9: pcVar2 = param_1[0x39];
10: *(undefined4 *)(pcVar2 + 0x10) = 0;
11: if (iVar1 < 2) {
12: if (*(int *)(param_1 + 0x28) == 1) {
13: *(undefined4 *)(pcVar2 + 0x1c) = *(undefined4 *)(param_1[0x29] + 0x48);
14: }
15: else {
16: *(undefined4 *)(pcVar2 + 0x1c) = *(undefined4 *)(param_1[0x29] + 0xc);
17: }
18: }
19: else {
20: *(undefined4 *)(pcVar2 + 0x1c) = 1;
21: }
22: *(undefined4 *)(pcVar2 + 0x14) = 0;
23: *(undefined4 *)(pcVar2 + 0x18) = 0;
24: if (param_2 == 2) {
25: if (*(long *)(pcVar2 + 0x70) == 0) {
26: param_1 = (code **)*param_1;
27: *(undefined4 *)(param_1 + 5) = 4;
28: (**param_1)();
29: }
30: *(code **)(pcVar2 + 8) = FUN_00103480;
31: return;
32: }
33: if (param_2 == 3) {
34: if (*(long *)(pcVar2 + 0x70) == 0) {
35: param_1 = (code **)*param_1;
36: *(undefined4 *)(param_1 + 5) = 4;
37: (**param_1)();
38: }
39: *(code **)(pcVar2 + 8) = FUN_00103a60;
40: return;
41: }
42: if (param_2 != 0) {
43: param_1 = (code **)*param_1;
44: *(undefined4 *)(param_1 + 5) = 4;
45: /* WARNING: Could not recover jumptable at 0x001042d9. Too many branches */
46: /* WARNING: Treating indirect jump as call */
47: (**param_1)();
48: return;
49: }
50: if (*(long *)(pcVar2 + 0x70) != 0) {
51: param_1 = (code **)*param_1;
52: *(undefined4 *)(param_1 + 5) = 4;
53: (**param_1)();
54: }
55: *(code **)(pcVar2 + 8) = FUN_00103d20;
56: return;
57: }
58: 
