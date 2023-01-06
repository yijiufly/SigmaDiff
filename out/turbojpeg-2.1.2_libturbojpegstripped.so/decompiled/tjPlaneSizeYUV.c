1: 
2: long tjPlaneSizeYUV(ulong param_1,undefined8 param_2,uint param_3,int param_4,uint param_5)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: long lVar3;
8: undefined4 *puVar4;
9: 
10: if (((0 < (int)param_2) && (0 < param_4)) && (param_5 < 6)) {
11: iVar1 = tjPlaneWidth(param_1,param_2,param_5);
12: iVar2 = tjPlaneHeight(param_1 & 0xffffffff,param_4,param_5);
13: if ((-1 < iVar1) && (-1 < iVar2)) {
14: if (param_3 == 0) {
15: lVar3 = (long)(iVar2 + -1) * (long)iVar1;
16: }
17: else {
18: lVar3 = (long)(iVar2 + -1) *
19: (long)(int)((param_3 ^ (int)param_3 >> 0x1f) - ((int)param_3 >> 0x1f));
20: }
21: return lVar3 + iVar1;
22: }
23: return -1;
24: }
25: puVar4 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
26: *(undefined2 *)(puVar4 + 8) = 0x746e;
27: *(undefined *)((long)puVar4 + 0x22) = 0;
28: *puVar4 = 0x6c506a74;
29: puVar4[1] = 0x53656e61;
30: puVar4[2] = 0x59657a69;
31: puVar4[3] = 0x29285655;
32: puVar4[4] = 0x6e49203a;
33: puVar4[5] = 0x696c6176;
34: puVar4[6] = 0x72612064;
35: puVar4[7] = 0x656d7567;
36: return -1;
37: }
38: 
