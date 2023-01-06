1: 
2: bool FUN_00136e10(long param_1)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: long lVar3;
8: 
9: uVar1 = *(uint *)(param_1 + 0x40);
10: if ((10 < uVar1 - 6) && (uVar1 != 2)) {
11: return false;
12: }
13: if (uVar1 == 0x10) {
14: if (*(int *)(param_1 + 0x90) != 3) {
15: return false;
16: }
17: }
18: else {
19: if (*(int *)(param_1 + 0x90) != *(int *)(&DAT_0018d460 + (ulong)uVar1 * 4)) {
20: return false;
21: }
22: }
23: lVar3 = *(long *)(param_1 + 0x130);
24: if (((((*(int *)(lVar3 + 8) == 2) && (*(int *)(lVar3 + 0x68) == 1)) &&
25: (*(int *)(lVar3 + 200) == 1)) &&
26: ((*(int *)(lVar3 + 0xc) < 3 && (*(int *)(lVar3 + 0x6c) == 1)))) &&
27: ((*(int *)(lVar3 + 0xcc) == 1 &&
28: ((iVar2 = *(int *)(lVar3 + 0x24), iVar2 == *(int *)(param_1 + 0x1a0) &&
29: (iVar2 == *(int *)(lVar3 + 0x84))))))) {
30: return *(int *)(lVar3 + 0xe4) == iVar2;
31: }
32: return false;
33: }
34: 
