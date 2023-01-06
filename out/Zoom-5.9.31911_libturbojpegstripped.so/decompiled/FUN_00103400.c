1: 
2: void FUN_00103400(long param_1)
3: 
4: {
5: undefined4 uVar1;
6: long lVar2;
7: 
8: lVar2 = *(long *)(param_1 + 0x1c8);
9: if (1 < *(int *)(param_1 + 0x144)) {
10: *(undefined4 *)(lVar2 + 0x1c) = 1;
11: *(undefined4 *)(lVar2 + 0x14) = 0;
12: *(undefined4 *)(lVar2 + 0x18) = 0;
13: return;
14: }
15: if (*(int *)(param_1 + 0x140) - 1U <= *(uint *)(lVar2 + 0x10)) {
16: uVar1 = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0x48);
17: *(undefined4 *)(lVar2 + 0x14) = 0;
18: *(undefined4 *)(lVar2 + 0x18) = 0;
19: *(undefined4 *)(lVar2 + 0x1c) = uVar1;
20: return;
21: }
22: uVar1 = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0xc);
23: *(undefined4 *)(lVar2 + 0x14) = 0;
24: *(undefined4 *)(lVar2 + 0x18) = 0;
25: *(undefined4 *)(lVar2 + 0x1c) = uVar1;
26: return;
27: }
28: 
