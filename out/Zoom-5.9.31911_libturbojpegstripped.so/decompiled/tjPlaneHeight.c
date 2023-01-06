1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined  [16] tjPlaneHeight(int param_1,int param_2,undefined8 param_3)
5: 
6: {
7: int iVar1;
8: long lVar2;
9: ulong uVar3;
10: int iVar4;
11: uint uVar5;
12: ulong uVar6;
13: 
14: if ((((0 < param_2) && (uVar5 = (uint)param_3, uVar5 < 6)) &&
15: (param_1 < (int)((uVar5 != 3) + 1 + (uint)(uVar5 != 3)))) && (-1 < param_1)) {
16: iVar1 = *(int *)(&DAT_0018bc70 + (long)(int)uVar5 * 4);
17: iVar4 = iVar1 + 7;
18: if (-1 < iVar1) {
19: iVar4 = iVar1;
20: }
21: uVar5 = -(iVar4 >> 3);
22: uVar6 = (ulong)uVar5;
23: uVar5 = param_2 + -1 + (iVar4 >> 3) & uVar5;
24: uVar3 = (ulong)uVar5;
25: if (param_1 != 0) {
26: lVar2 = (long)(int)(uVar5 << 3);
27: uVar3 = lVar2 / (long)iVar1 & 0xffffffff;
28: uVar6 = lVar2 % (long)iVar1 & 0xffffffff;
29: }
30: return CONCAT88(uVar6,uVar3);
31: }
32: s_No_error_003a6000._0_8_ = 0x48656e616c506a74;
33: ram0x003a6008 = 0x3a29287468676965;
34: _DAT_003a6010 = 0x64696c61766e4920;
35: _DAT_003a6018 = 0x6e656d7567726120;
36: _DAT_003a6020 = 0x74;
37: return CONCAT88(param_3,0xffffffff);
38: }
39: 
