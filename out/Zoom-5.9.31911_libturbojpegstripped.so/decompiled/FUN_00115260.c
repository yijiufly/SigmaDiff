1: 
2: void FUN_00115260(long param_1)
3: 
4: {
5: code **ppcVar1;
6: 
7: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x40);
8: *(code ***)(param_1 + 0x1d0) = ppcVar1;
9: *(undefined4 *)(ppcVar1 + 7) = 0;
10: *ppcVar1 = FUN_00113040;
11: ppcVar1[1] = FUN_00114210;
12: ppcVar1[2] = FUN_00114510;
13: ppcVar1[3] = FUN_001129c0;
14: ppcVar1[4] = FUN_00114360;
15: ppcVar1[5] = FUN_00112a50;
16: ppcVar1[6] = FUN_00112970;
17: return;
18: }
19: 
