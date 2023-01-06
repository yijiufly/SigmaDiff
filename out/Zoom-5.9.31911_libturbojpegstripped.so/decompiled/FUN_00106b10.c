1: 
2: void FUN_00106b10(long param_1,long param_2,long param_3)
3: 
4: {
5: short sVar1;
6: long lVar2;
7: byte bVar3;
8: uint uVar4;
9: short sVar5;
10: 
11: lVar2 = 0;
12: do {
13: sVar1 = *(short *)(param_3 + lVar2);
14: uVar4 = (uint)*(ushort *)(param_2 + 0x80 + lVar2);
15: bVar3 = (char)*(undefined2 *)(param_2 + 0x180 + lVar2) + 0x10;
16: sVar5 = -(short)(((int)-sVar1 + uVar4) * (uint)*(ushort *)(param_2 + lVar2) >> (bVar3 & 0x1f));
17: if (-1 < sVar1) {
18: sVar5 = (short)(((int)sVar1 + uVar4) * (uint)*(ushort *)(param_2 + lVar2) >> (bVar3 & 0x1f));
19: }
20: *(short *)(param_1 + lVar2) = sVar5;
21: lVar2 = lVar2 + 2;
22: } while (lVar2 != 0x80);
23: return;
24: }
25: 
