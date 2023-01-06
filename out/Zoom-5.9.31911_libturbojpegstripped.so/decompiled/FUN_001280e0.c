1: 
2: void FUN_001280e0(long *param_1)
3: 
4: {
5: code **ppcVar1;
6: 
7: ppcVar1 = (code **)param_1[0x48];
8: *ppcVar1 = FUN_00128870;
9: *(undefined4 *)(ppcVar1 + 4) = 0;
10: *(undefined4 *)((long)ppcVar1 + 0x24) = 0;
11: *(undefined4 *)(ppcVar1 + 5) = 1;
12: (**(code **)(*param_1 + 0x20))();
13: (**(code **)param_1[0x49])(param_1);
14: param_1[0x18] = 0;
15: return;
16: }
17: 
