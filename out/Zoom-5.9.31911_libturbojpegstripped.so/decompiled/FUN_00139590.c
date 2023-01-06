1: 
2: void FUN_00139590(code **param_1)
3: 
4: {
5: param_1 = (code **)*param_1;
6: *(undefined4 *)(param_1 + 5) = 0x2e;
7: /* WARNING: Could not recover jumptable at 0x0013959d. Too many branches */
8: /* WARNING: Treating indirect jump as call */
9: (**param_1)();
10: return;
11: }
12: 
