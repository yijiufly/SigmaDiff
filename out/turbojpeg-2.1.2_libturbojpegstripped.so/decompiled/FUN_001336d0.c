1: 
2: void FUN_001336d0(long param_1)
3: 
4: {
5: code **ppcVar1;
6: 
7: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,0,0x30);
8: *(code ***)(param_1 + 0x240) = ppcVar1;
9: ppcVar1[4] = (code *)0x0;
10: *(undefined4 *)(ppcVar1 + 5) = 1;
11: *ppcVar1 = FUN_00133380;
12: ppcVar1[1] = FUN_00132d60;
13: ppcVar1[2] = FUN_00132db0;
14: ppcVar1[3] = FUN_00132d40;
15: return;
16: }
17: 
