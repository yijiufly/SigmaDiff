1: 
2: void FUN_00150040(long param_1)
3: 
4: {
5: long lVar1;
6: 
7: lVar1 = *(long *)(param_1 + 0x28);
8: if (*(int *)(lVar1 + 0x50) != 0) {
9: **(undefined8 **)(lVar1 + 0x28) = *(undefined8 *)(lVar1 + 0x40);
10: }
11: **(long **)(lVar1 + 0x30) = *(long *)(lVar1 + 0x48) - *(long *)(lVar1 + 8);
12: return;
13: }
14: 
