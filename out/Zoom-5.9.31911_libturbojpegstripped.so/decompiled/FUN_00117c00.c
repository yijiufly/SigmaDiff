1: 
2: ulong FUN_00117c00(long param_1,long param_2,int param_3,byte param_4,long param_5,ulong *param_6)
3: 
4: {
5: ulong uVar1;
6: uint uVar2;
7: ulong uVar3;
8: uint uVar4;
9: int iVar5;
10: ulong uVar6;
11: ulong uVar7;
12: 
13: if (param_3 < 1) {
14: uVar3 = 0;
15: uVar7 = 0;
16: uVar1 = 0;
17: }
18: else {
19: uVar6 = 0;
20: uVar3 = 0;
21: uVar7 = 0;
22: uVar1 = 0;
23: do {
24: while( true ) {
25: uVar4 = SEXT24(*(short *)(param_1 + (long)*(int *)(param_2 + uVar6 * 4) * 2));
26: uVar2 = (int)uVar4 >> 0x1f;
27: iVar5 = (int)((uVar4 ^ uVar2) - uVar2) >> (param_4 & 0x1f);
28: if (iVar5 != 0) break;
29: *(undefined2 *)(param_5 + uVar6 * 2) = 0;
30: uVar6 = uVar6 + 1;
31: if (param_3 <= (int)uVar6) goto LAB_00117c91;
32: }
33: uVar7 = uVar7 | 1 << ((byte)uVar6 & 0x3f);
34: *(short *)(param_5 + uVar6 * 2) = (short)iVar5;
35: uVar3 = uVar3 | (long)(int)(uVar2 + 1) << ((byte)uVar6 & 0x3f);
36: if (iVar5 == 1) {
37: uVar1 = uVar6 & 0xffffffff;
38: }
39: uVar6 = uVar6 + 1;
40: } while ((int)uVar6 < param_3);
41: }
42: LAB_00117c91:
43: param_6[1] = uVar3;
44: *param_6 = uVar7;
45: return uVar1;
46: }
47: 
