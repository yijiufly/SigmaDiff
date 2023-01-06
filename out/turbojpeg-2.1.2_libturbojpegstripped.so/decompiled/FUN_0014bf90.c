1: 
2: undefined8 FUN_0014bf90(long param_1,long param_2)
3: 
4: {
5: undefined4 uVar1;
6: long lVar2;
7: int iVar3;
8: long lVar4;
9: 
10: lVar2 = *(long *)(param_1 + 0x1f0);
11: if (*(int *)(param_1 + 0x118) != 0) {
12: iVar3 = *(int *)(lVar2 + 0x60);
13: if (iVar3 == 0) {
14: FUN_0014b810(param_1,*(undefined4 *)(lVar2 + 100));
15: iVar3 = *(int *)(param_1 + 0x118);
16: *(uint *)(lVar2 + 100) = *(int *)(lVar2 + 100) + 1U & 7;
17: }
18: *(int *)(lVar2 + 0x60) = iVar3 + -1;
19: }
20: uVar1 = *(undefined4 *)(param_1 + 0x1a8);
21: if (0 < *(int *)(param_1 + 0x170)) {
22: lVar4 = 1;
23: do {
24: FUN_0014b010(param_1,lVar2 + 0x168,
25: (int)**(short **)(param_2 + -8 + lVar4 * 8) >> ((byte)uVar1 & 0x1f) & 1,uVar1);
26: iVar3 = (int)lVar4;
27: lVar4 = lVar4 + 1;
28: } while (*(int *)(param_1 + 0x170) != iVar3 && iVar3 <= *(int *)(param_1 + 0x170));
29: }
30: return 1;
31: }
32: 
