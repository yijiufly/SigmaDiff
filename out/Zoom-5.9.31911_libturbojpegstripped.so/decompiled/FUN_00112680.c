1: 
2: void FUN_00112680(long param_1)
3: 
4: {
5: bool bVar1;
6: 
7: FUN_00116330();
8: if (*(int *)(param_1 + 0x100) == 0) {
9: FUN_00106730(param_1);
10: FUN_0011b570(param_1);
11: FUN_0011a6a0(param_1,0);
12: }
13: FUN_001082c0(param_1);
14: if (*(int *)(param_1 + 0x104) == 0) {
15: if (*(int *)(param_1 + 0x134) == 0) {
16: FUN_00112400();
17: }
18: else {
19: FUN_0011a070();
20: }
21: }
22: else {
23: FUN_0013ffe0(param_1);
24: }
25: bVar1 = true;
26: if (*(int *)(param_1 + 0xf0) < 2) {
27: bVar1 = *(int *)(param_1 + 0x108) != 0;
28: }
29: FUN_00104380(param_1,bVar1);
30: FUN_001128b0(param_1,0);
31: FUN_00115260(param_1);
32: (**(code **)(*(long *)(param_1 + 8) + 0x30))(param_1);
33: /* WARNING: Could not recover jumptable at 0x0011270b. Too many branches */
34: /* WARNING: Treating indirect jump as call */
35: (***(code ***)(param_1 + 0x1d0))(param_1);
36: return;
37: }
38: 
