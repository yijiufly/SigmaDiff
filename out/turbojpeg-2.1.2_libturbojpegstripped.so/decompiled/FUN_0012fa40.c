1: 
2: void FUN_0012fa40(long param_1)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: undefined8 *puVar3;
8: ulong uVar4;
9: long lVar5;
10: long lVar6;
11: byte bVar7;
12: 
13: bVar7 = 0;
14: ppcVar2 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x80);
15: *(code ***)(param_1 + 600) = ppcVar2;
16: lVar6 = *(long *)(param_1 + 0x130);
17: *ppcVar2 = FUN_0012ece0;
18: if (0 < *(int *)(param_1 + 0x38)) {
19: lVar5 = 1;
20: do {
21: puVar3 = (undefined8 *)(***(code ***)(param_1 + 8))(param_1,1,0x100);
22: *(undefined8 **)(lVar6 + 0x58) = puVar3;
23: *puVar3 = 0;
24: puVar3[0x1f] = 0;
25: uVar4 = (ulong)(((int)puVar3 - (int)(undefined8 *)((ulong)(puVar3 + 1) & 0xfffffffffffffff8))
26: + 0x100U >> 3);
27: puVar3 = (undefined8 *)((ulong)(puVar3 + 1) & 0xfffffffffffffff8);
28: while (uVar4 != 0) {
29: uVar4 = uVar4 - 1;
30: *puVar3 = 0;
31: puVar3 = puVar3 + (ulong)bVar7 * -2 + 1;
32: }
33: *(undefined4 *)((long)ppcVar2 + lVar5 * 4 + 0x54) = 0xffffffff;
34: iVar1 = (int)lVar5;
35: lVar5 = lVar5 + 1;
36: lVar6 = lVar6 + 0x60;
37: } while (*(int *)(param_1 + 0x38) != iVar1 && iVar1 <= *(int *)(param_1 + 0x38));
38: }
39: return;
40: }
41: 
