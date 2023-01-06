1: 
2: undefined8 FUN_0013f950(long param_1,short **param_2)
3: 
4: {
5: undefined4 uVar1;
6: long lVar2;
7: short *psVar3;
8: int iVar4;
9: 
10: lVar2 = *(long *)(param_1 + 0x1f0);
11: if (*(int *)(param_1 + 0x118) != 0) {
12: iVar4 = *(int *)(lVar2 + 0x60);
13: if (iVar4 == 0) {
14: FUN_0013ef30(param_1,*(undefined4 *)(lVar2 + 100));
15: iVar4 = *(int *)(param_1 + 0x118);
16: *(uint *)(lVar2 + 100) = *(int *)(lVar2 + 100) + 1U & 7;
17: }
18: *(int *)(lVar2 + 0x60) = iVar4 + -1;
19: }
20: iVar4 = 0;
21: uVar1 = *(undefined4 *)(param_1 + 0x1a8);
22: if (0 < *(int *)(param_1 + 0x170)) {
23: do {
24: psVar3 = *param_2;
25: iVar4 = iVar4 + 1;
26: param_2 = param_2 + 1;
27: FUN_0013e5d0(param_1,lVar2 + 0x168,(int)*psVar3 >> ((byte)uVar1 & 0x1f) & 1,uVar1);
28: } while (*(int *)(param_1 + 0x170) != iVar4 && iVar4 <= *(int *)(param_1 + 0x170));
29: }
30: return 1;
31: }
32: 
