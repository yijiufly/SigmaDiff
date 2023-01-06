1: 
2: void FUN_0011c010(long param_1)
3: 
4: {
5: bool bVar1;
6: 
7: FUN_0011f0b0();
8: if (*(int *)(param_1 + 0x100) == 0) {
9: FUN_00106ef0(param_1);
10: FUN_00123d50(param_1);
11: FUN_00122bc0(param_1,0);
12: }
13: FUN_00108fc0(param_1);
14: if (*(int *)(param_1 + 0x104) == 0) {
15: if (*(int *)(param_1 + 0x134) == 0) {
16: FUN_0011be10();
17: }
18: else {
19: FUN_001225a0();
20: }
21: }
22: else {
23: FUN_0014c870(param_1);
24: }
25: bVar1 = true;
26: if (*(int *)(param_1 + 0xf0) < 2) {
27: bVar1 = *(int *)(param_1 + 0x108) != 0;
28: }
29: FUN_00104050(param_1,bVar1);
30: FUN_0011c250(param_1,0);
31: FUN_0011e1b0(param_1);
32: (**(code **)(*(long *)(param_1 + 8) + 0x30))(param_1);
33: /* WARNING: Could not recover jumptable at 0x0011c09b. Too many branches */
34: /* WARNING: Treating indirect jump as call */
35: (***(code ***)(param_1 + 0x1d0))(param_1);
36: return;
37: }
38: 
