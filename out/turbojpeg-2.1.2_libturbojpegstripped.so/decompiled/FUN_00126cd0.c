1: 
2: void FUN_00126cd0(long param_1)
3: 
4: {
5: undefined4 uVar1;
6: long lVar2;
7: 
8: *(undefined4 *)(param_1 + 0xb0) = 0;
9: lVar2 = *(long *)(param_1 + 0x230);
10: if (1 < *(int *)(param_1 + 0x1b0)) {
11: *(undefined4 *)(lVar2 + 0x30) = 1;
12: *(undefined8 *)(lVar2 + 0x28) = 0;
13: return;
14: }
15: if (*(int *)(param_1 + 0x1a4) != 1) {
16: uVar1 = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0xc);
17: *(undefined8 *)(lVar2 + 0x28) = 0;
18: *(undefined4 *)(lVar2 + 0x30) = uVar1;
19: return;
20: }
21: uVar1 = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0x48);
22: *(undefined8 *)(lVar2 + 0x28) = 0;
23: *(undefined4 *)(lVar2 + 0x30) = uVar1;
24: return;
25: }
26: 
