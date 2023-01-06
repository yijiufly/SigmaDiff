1: 
2: long tjBufSize(int param_1,int param_2,uint param_3)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: undefined4 *puVar3;
8: long lVar4;
9: 
10: if (((0 < param_1) && (0 < param_2)) && (param_3 < 6)) {
11: iVar1 = *(int *)(&DAT_0018fdd0 + (long)(int)param_3 * 4);
12: iVar2 = *(int *)(&DAT_0018fdb0 + (long)(int)param_3 * 4);
13: lVar4 = 2;
14: if (param_3 != 3) {
15: lVar4 = (long)(int)(0x100 / (long)(iVar1 * iVar2)) + 2;
16: }
17: return ((iVar1 + -1 + param_1 & -iVar1) * (-iVar2 & iVar2 + -1 + param_2)) * lVar4 + 0x800;
18: }
19: puVar3 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
20: *(undefined8 *)(puVar3 + 4) = 0x6772612064696c61;
21: puVar3[6] = 0x6e656d75;
22: *puVar3 = 0x75426a74;
23: puVar3[1] = 0x7a695366;
24: puVar3[2] = 0x3a292865;
25: puVar3[3] = 0x766e4920;
26: *(undefined2 *)(puVar3 + 7) = 0x74;
27: return -1;
28: }
29: 
