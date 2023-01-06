1: 
2: void FUN_00132d60(long *param_1)
3: 
4: {
5: code **ppcVar1;
6: 
7: ppcVar1 = (code **)param_1[0x48];
8: *ppcVar1 = FUN_00133380;
9: ppcVar1[4] = (code *)0x0;
10: *(undefined4 *)(ppcVar1 + 5) = 1;
11: (**(code **)(*param_1 + 0x20))();
12: (**(code **)param_1[0x49])(param_1);
13: param_1[0x18] = 0;
14: return;
15: }
16: 
