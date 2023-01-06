1: 
2: undefined8 FUN_00141240(long param_1,ushort **param_2)
3: 
4: {
5: undefined4 uVar1;
6: long lVar2;
7: int iVar3;
8: int iVar4;
9: 
10: lVar2 = *(long *)(param_1 + 0x250);
11: if (*(int *)(param_1 + 0x170) != 0) {
12: iVar4 = *(int *)(lVar2 + 0x4c);
13: if (iVar4 == 0) {
14: FUN_00140730();
15: iVar4 = *(int *)(lVar2 + 0x4c);
16: }
17: *(int *)(lVar2 + 0x4c) = iVar4 + -1;
18: }
19: uVar1 = *(undefined4 *)(param_1 + 0x218);
20: iVar4 = 0;
21: if (0 < *(int *)(param_1 + 0x1e0)) {
22: do {
23: iVar3 = FUN_00140970(param_1,lVar2 + 0x150);
24: if (iVar3 != 0) {
25: **param_2 = **param_2 | (ushort)(1 << ((byte)uVar1 & 0x1f));
26: }
27: iVar4 = iVar4 + 1;
28: param_2 = param_2 + 1;
29: } while (*(int *)(param_1 + 0x1e0) != iVar4 && iVar4 <= *(int *)(param_1 + 0x1e0));
30: }
31: return 1;
32: }
33: 
