1: 
2: void FUN_00120400(long param_1,long param_2,int param_3,byte param_4,long param_5,ulong *param_6)
3: 
4: {
5: short sVar1;
6: ushort uVar2;
7: int iVar3;
8: long lVar4;
9: ulong uVar5;
10: uint uVar6;
11: 
12: if (0 < param_3) {
13: lVar4 = 0;
14: uVar5 = 0;
15: do {
16: sVar1 = *(short *)(param_1 + (long)*(int *)(param_2 + lVar4 * 4) * 2);
17: if ((sVar1 != 0) &&
18: (uVar6 = (int)sVar1 >> 0x1f,
19: iVar3 = (int)(((int)sVar1 ^ uVar6) - uVar6) >> (param_4 & 0x1f), iVar3 != 0)) {
20: uVar2 = (ushort)iVar3;
21: *(ushort *)(param_5 + lVar4 * 2) = uVar2;
22: *(ushort *)(param_5 + 0x80 + lVar4 * 2) = uVar2 ^ sVar1 >> 0xf;
23: uVar5 = uVar5 | 1 << ((byte)lVar4 & 0x3f);
24: }
25: lVar4 = lVar4 + 1;
26: } while ((ulong)(param_3 - 1) + 1 != lVar4);
27: *param_6 = uVar5;
28: return;
29: }
30: *param_6 = 0;
31: return;
32: }
33: 
