1: 
2: void FUN_001266a0(long param_1)
3: 
4: {
5: undefined8 *puVar1;
6: undefined8 uVar2;
7: 
8: puVar1 = *(undefined8 **)(param_1 + 0x28);
9: uVar2 = (***(code ***)(param_1 + 8))(param_1,1,0x1000);
10: puVar1[1] = 0x1000;
11: puVar1[6] = uVar2;
12: *puVar1 = uVar2;
13: return;
14: }
15: 
