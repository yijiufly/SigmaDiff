1: 
2: void FUN_00128bd0(long param_1)
3: 
4: {
5: code **ppcVar1;
6: 
7: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,0,0x30);
8: *(code ***)(param_1 + 0x240) = ppcVar1;
9: *(undefined4 *)(ppcVar1 + 4) = 0;
10: *(undefined4 *)((long)ppcVar1 + 0x24) = 0;
11: *ppcVar1 = FUN_00128870;
12: ppcVar1[1] = FUN_001280e0;
13: ppcVar1[2] = FUN_00128130;
14: *(undefined4 *)(ppcVar1 + 5) = 1;
15: ppcVar1[3] = FUN_001280c0;
16: return;
17: }
18: 
