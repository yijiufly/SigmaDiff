1: 
2: void FUN_00136df0(long param_1)
3: 
4: {
5: int *piVar1;
6: long lVar2;
7: 
8: lVar2 = *(long *)(param_1 + 0x220);
9: if (*(int *)(param_1 + 0x6c) != 0) {
10: (**(code **)(*(long *)(param_1 + 0x270) + 0x10))();
11: }
12: piVar1 = (int *)(lVar2 + 0x78);
13: *piVar1 = *piVar1 + 1;
14: return;
15: }
16: 
