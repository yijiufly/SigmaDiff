1: 
2: void FUN_00168a70(code *param_1,undefined4 param_2)
3: 
4: {
5: code **ppcVar1;
6: 
7: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x68);
8: ppcVar1[6] = param_1;
9: *(undefined4 *)(ppcVar1 + 0xb) = param_2;
10: *ppcVar1 = FUN_00167ec0;
11: ppcVar1[2] = FUN_00167330;
12: return;
13: }
14: 
