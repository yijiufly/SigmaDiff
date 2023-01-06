1: 
2: void FUN_00117b80(long param_1,long param_2,int param_3,byte param_4,long param_5,ulong *param_6)
3: 
4: {
5: short sVar1;
6: long lVar2;
7: ulong uVar3;
8: ushort uVar4;
9: int iVar5;
10: uint uVar6;
11: 
12: if (param_3 < 1) {
13: uVar3 = 0;
14: }
15: else {
16: lVar2 = 0;
17: uVar3 = 0;
18: do {
19: sVar1 = *(short *)(param_1 + (long)*(int *)(param_2 + lVar2 * 4) * 2);
20: if ((sVar1 != 0) &&
21: (uVar6 = (int)sVar1 >> 0x1f,
22: iVar5 = (int)(((int)sVar1 ^ uVar6) - uVar6) >> (param_4 & 0x1f), iVar5 != 0)) {
23: uVar4 = (ushort)iVar5;
24: *(ushort *)(param_5 + lVar2 * 2) = uVar4;
25: *(ushort *)(param_5 + 0x80 + lVar2 * 2) = uVar4 ^ sVar1 >> 0xf;
26: uVar3 = uVar3 | 1 << ((byte)lVar2 & 0x3f);
27: }
28: lVar2 = lVar2 + 1;
29: } while ((int)lVar2 < param_3);
30: }
31: *param_6 = uVar3;
32: return;
33: }
34: 
