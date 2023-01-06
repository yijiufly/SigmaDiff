1: 
2: void FUN_0011e850(long param_1)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: 
8: lVar2 = *(long *)(param_1 + 0x1b0);
9: (**(code **)(*(long *)(param_1 + 0x1f0) + 0x10))();
10: iVar1 = *(int *)(lVar2 + 0x20);
11: if (iVar1 != 1) {
12: if (iVar1 == 0) {
13: iVar1 = *(int *)(param_1 + 0x108);
14: *(undefined4 *)(lVar2 + 0x20) = 2;
15: if (iVar1 == 0) {
16: *(int *)(lVar2 + 0x2c) = *(int *)(lVar2 + 0x2c) + 1;
17: }
18: }
19: else {
20: if (iVar1 == 2) {
21: if (*(int *)(param_1 + 0x108) != 0) {
22: *(undefined4 *)(lVar2 + 0x20) = 1;
23: }
24: *(int *)(lVar2 + 0x2c) = *(int *)(lVar2 + 0x2c) + 1;
25: }
26: }
27: *(int *)(lVar2 + 0x24) = *(int *)(lVar2 + 0x24) + 1;
28: return;
29: }
30: *(undefined4 *)(lVar2 + 0x20) = 2;
31: *(int *)(lVar2 + 0x24) = *(int *)(lVar2 + 0x24) + 1;
32: return;
33: }
34: 
