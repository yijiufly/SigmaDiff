1: 
2: void FUN_00154b40(long param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: 
7: if (*(int *)(param_1 + 0x40) != 1) {
8: uVar1 = *(int *)(param_1 + 0x88) * 3;
9: *(uint *)(param_2 + 0x50) = uVar1;
10: *(ulong *)(param_2 + 0x48) = (ulong)uVar1;
11: return;
12: }
13: uVar1 = *(int *)(param_1 + 0x90) * *(int *)(param_1 + 0x88);
14: *(uint *)(param_2 + 0x50) = uVar1;
15: *(ulong *)(param_2 + 0x48) = (ulong)uVar1;
16: return;
17: }
18: 
