1: 
2: void FUN_00107510(long param_1,long param_2,long param_3)
3: 
4: {
5: short sVar1;
6: ushort uVar2;
7: byte bVar3;
8: long lVar4;
9: 
10: lVar4 = 0;
11: do {
12: while( true ) {
13: sVar1 = *(short *)(param_3 + lVar4);
14: uVar2 = *(ushort *)(param_2 + 0x80 + lVar4);
15: bVar3 = (char)*(undefined2 *)(param_2 + 0x180 + lVar4) + 0x10;
16: if (-1 < sVar1) break;
17: *(short *)(param_1 + lVar4) =
18: -(short)(((int)-sVar1 + (uint)uVar2) * (uint)*(ushort *)(param_2 + lVar4) >>
19: (bVar3 & 0x1f));
20: lVar4 = lVar4 + 2;
21: if (lVar4 == 0x80) {
22: return;
23: }
24: }
25: *(short *)(param_1 + lVar4) =
26: (short)(((int)sVar1 + (uint)uVar2) * (uint)*(ushort *)(param_2 + lVar4) >> (bVar3 & 0x1f));
27: lVar4 = lVar4 + 2;
28: } while (lVar4 != 0x80);
29: return;
30: }
31: 
