1: 
2: ulong FUN_00120490(long param_1,long param_2,int param_3,byte param_4,long param_5,ulong *param_6)
3: 
4: {
5: ulong uVar1;
6: uint uVar2;
7: int iVar3;
8: ulong uVar4;
9: ulong uVar5;
10: ulong uVar6;
11: uint uVar7;
12: ulong uVar8;
13: 
14: if (param_3 < 1) {
15: uVar5 = 0;
16: uVar8 = 0;
17: uVar1 = 0;
18: }
19: else {
20: uVar6 = 0;
21: uVar5 = 0;
22: uVar8 = 0;
23: uVar1 = 0;
24: uVar4 = (ulong)(param_3 - 1) + 1;
25: do {
26: while( true ) {
27: uVar2 = SEXT24(*(short *)(param_1 + (long)*(int *)(param_2 + uVar6 * 4) * 2));
28: uVar7 = (int)uVar2 >> 0x1f;
29: iVar3 = (int)((uVar2 ^ uVar7) - uVar7) >> (param_4 & 0x1f);
30: if (iVar3 != 0) break;
31: *(short *)(param_5 + uVar6 * 2) = (short)(0 >> (param_4 & 0x1f));
32: uVar6 = uVar6 + 1;
33: if (uVar4 == uVar6) goto LAB_0012051f;
34: }
35: uVar8 = uVar8 | 1 << ((byte)uVar6 & 0x3f);
36: *(short *)(param_5 + uVar6 * 2) = (short)iVar3;
37: uVar5 = uVar5 | (long)(int)(uVar7 + 1) << ((byte)uVar6 & 0x3f);
38: if (iVar3 == 1) {
39: uVar1 = uVar6 & 0xffffffff;
40: }
41: uVar6 = uVar6 + 1;
42: } while (uVar4 != uVar6);
43: }
44: LAB_0012051f:
45: *param_6 = uVar8;
46: param_6[1] = uVar5;
47: return uVar1;
48: }
49: 
