1: 
2: void FUN_00115c80(long param_1)
3: 
4: {
5: *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x18) = 0;
6: (**(code **)(*(long *)(param_1 + 0x1d0) + 8))();
7: /* WARNING: Could not recover jumptable at 0x00115cab. Too many branches */
8: /* WARNING: Treating indirect jump as call */
9: (**(code **)(*(long *)(param_1 + 0x1d0) + 0x10))(param_1);
10: return;
11: }
12: 
