1: 
2: undefined  [16] tjPlaneHeight(uint param_1,int param_2,uint param_3)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: uint uVar3;
8: undefined4 *puVar4;
9: int iVar5;
10: 
11: if (((param_2 < 1) || (5 < param_3)) || ((param_3 != 3) + 1 + (uint)(param_3 != 3) <= param_1)) {
12: puVar4 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
13: *(undefined2 *)(puVar4 + 8) = 0x74;
14: *puVar4 = 0x6c506a74;
15: puVar4[1] = 0x48656e61;
16: puVar4[2] = 0x68676965;
17: puVar4[3] = 0x3a292874;
18: puVar4[4] = 0x766e4920;
19: puVar4[5] = 0x64696c61;
20: puVar4[6] = 0x67726120;
21: puVar4[7] = 0x6e656d75;
22: return CONCAT88(0x74,0xffffffff);
23: }
24: iVar1 = *(int *)(&DAT_0018fdb0 + (long)(int)param_3 * 4);
25: iVar5 = iVar1 + 7;
26: if (-1 < iVar1) {
27: iVar5 = iVar1;
28: }
29: uVar3 = param_2 + -1 + (iVar5 >> 3) & -(iVar5 >> 3);
30: if (param_1 != 0) {
31: lVar2 = (long)(int)(uVar3 << 3);
32: return CONCAT88(lVar2 % (long)iVar1,lVar2 / (long)iVar1) & (undefined  [16])0xffffffffffffffff;
33: }
34: return CONCAT88((long)(int)param_3,(ulong)uVar3);
35: }
36: 
