1: 
2: void FUN_00123040(long param_1,long param_2,uint param_3,long param_4,int param_5)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: 
10: lVar1 = *(long *)(param_1 + 0x1e0);
11: if (0 < *(int *)(param_1 + 0x4c)) {
12: lVar3 = 1;
13: lVar4 = *(long *)(param_1 + 0x58);
14: do {
15: (**(code **)(lVar1 + 0x10 + lVar3 * 8))
16: (param_1,lVar4,*(long *)(param_2 + -8 + lVar3 * 8) + (ulong)param_3 * 8,
17: *(long *)(param_4 + -8 + lVar3 * 8) +
18: (ulong)(uint)(param_5 * *(int *)(lVar4 + 0xc)) * 8);
19: iVar2 = (int)lVar3;
20: lVar3 = lVar3 + 1;
21: lVar4 = lVar4 + 0x60;
22: } while (*(int *)(param_1 + 0x4c) != iVar2 && iVar2 <= *(int *)(param_1 + 0x4c));
23: }
24: return;
25: }
26: 
