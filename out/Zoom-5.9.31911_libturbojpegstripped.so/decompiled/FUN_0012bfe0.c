1: 
2: bool FUN_0012bfe0(long param_1)
3: 
4: {
5: uint uVar1;
6: long lVar2;
7: bool bVar3;
8: int iVar4;
9: 
10: if (*(int *)(param_1 + 100) != 0) {
11: return false;
12: }
13: if (*(int *)(param_1 + 0x188) != 0) {
14: return false;
15: }
16: if (*(long *)(param_1 + 0x38) != 0x300000003) {
17: return false;
18: }
19: uVar1 = *(uint *)(param_1 + 0x40);
20: if ((uVar1 == 0x10) || (uVar1 == 2)) {
21: if (uVar1 == 0x10) {
22: if (*(int *)(param_1 + 0x90) != 3) {
23: return false;
24: }
25: goto LAB_0012c039;
26: }
27: }
28: else {
29: if (9 < uVar1 - 6) {
30: return false;
31: }
32: }
33: if (*(int *)(param_1 + 0x90) != *(int *)(&DAT_00189c00 + (ulong)uVar1 * 4)) {
34: return false;
35: }
36: LAB_0012c039:
37: lVar2 = *(long *)(param_1 + 0x130);
38: bVar3 = false;
39: if (((((*(int *)(lVar2 + 8) == 2) && (*(int *)(lVar2 + 0x68) == 1)) &&
40: (*(int *)(lVar2 + 200) == 1)) &&
41: (((*(int *)(lVar2 + 0xc) < 3 && (*(int *)(lVar2 + 0x6c) == 1)) &&
42: ((*(int *)(lVar2 + 0xcc) == 1 &&
43: ((iVar4 = *(int *)(lVar2 + 0x24), iVar4 == *(int *)(param_1 + 0x1a0) &&
44: (iVar4 == *(int *)(lVar2 + 0x84))))))))) && (iVar4 == *(int *)(lVar2 + 0xe4))) {
45: iVar4 = FUN_001682c0();
46: if ((((iVar4 == 0) && (iVar4 = FUN_00168320(), iVar4 == 0)) &&
47: (iVar4 = FUN_00167cf0(), iVar4 != 0)) && (*(int *)(param_1 + 0x3c) == 3)) {
48: bVar3 = 9 < *(int *)(param_1 + 0x40) - 6U && *(int *)(param_1 + 0x40) != 2;
49: }
50: else {
51: bVar3 = true;
52: }
53: }
54: return bVar3;
55: }
56: 
