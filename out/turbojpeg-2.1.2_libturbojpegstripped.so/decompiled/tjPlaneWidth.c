1: 
2: undefined  [16] tjPlaneWidth(uint param_1,int param_2,uint param_3)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: uint uVar3;
8: undefined4 *puVar4;
9: int iVar5;
10: undefined auVar6 [16];
11: 
12: if (((param_2 < 1) || (5 < param_3)) || ((param_3 != 3) + 1 + (uint)(param_3 != 3) <= param_1)) {
13: auVar6 = __tls_get_addr(&PTR_00398fc0);
14: puVar4 = SUB168(auVar6,0);
15: *(undefined *)(puVar4 + 8) = 0;
16: *puVar4 = 0x6c506a74;
17: puVar4[1] = 0x57656e61;
18: puVar4[2] = 0x68746469;
19: puVar4[3] = 0x203a2928;
20: puVar4[4] = 0x61766e49;
21: puVar4[5] = 0x2064696c;
22: puVar4[6] = 0x75677261;
23: puVar4[7] = 0x746e656d;
24: return CONCAT88(SUB168(auVar6 >> 0x40,0),0xffffffff);
25: }
26: iVar1 = *(int *)(&DAT_0018fdd0 + (long)(int)param_3 * 4);
27: iVar5 = iVar1 + 7;
28: if (-1 < iVar1) {
29: iVar5 = iVar1;
30: }
31: uVar3 = param_2 + -1 + (iVar5 >> 3) & -(iVar5 >> 3);
32: if (param_1 != 0) {
33: lVar2 = (long)(int)(uVar3 << 3);
34: return CONCAT88(lVar2 % (long)iVar1,lVar2 / (long)iVar1) & (undefined  [16])0xffffffffffffffff;
35: }
36: return CONCAT88((long)(int)param_3,(ulong)uVar3);
37: }
38: 
