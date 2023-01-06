1: 
2: void FUN_0011ffa0(long param_1)
3: 
4: {
5: undefined4 uVar1;
6: long lVar2;
7: 
8: *(undefined4 *)(param_1 + 0xb0) = 0;
9: lVar2 = *(long *)(param_1 + 0x230);
10: if (1 < *(int *)(param_1 + 0x1b0)) {
11: *(undefined4 *)(lVar2 + 0x30) = 1;
12: *(undefined4 *)(lVar2 + 0x28) = 0;
13: *(undefined4 *)(lVar2 + 0x2c) = 0;
14: return;
15: }
16: if (*(int *)(param_1 + 0x1a4) == 1) {
17: uVar1 = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0x48);
18: *(undefined4 *)(lVar2 + 0x28) = 0;
19: *(undefined4 *)(lVar2 + 0x2c) = 0;
20: *(undefined4 *)(lVar2 + 0x30) = uVar1;
21: return;
22: }
23: uVar1 = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0xc);
24: *(undefined4 *)(lVar2 + 0x28) = 0;
25: *(undefined4 *)(lVar2 + 0x2c) = 0;
26: *(undefined4 *)(lVar2 + 0x30) = uVar1;
27: return;
28: }
29: 
