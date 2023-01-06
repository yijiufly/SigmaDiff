1: 
2: long tjBufSizeYUV2(undefined4 param_1,int param_2,undefined4 param_3,uint param_4)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: undefined4 *puVar3;
8: int iVar4;
9: long lVar5;
10: 
11: if (param_4 < 6) {
12: iVar4 = 0;
13: lVar5 = 0;
14: do {
15: iVar1 = tjPlaneWidth(iVar4,param_1,param_4);
16: iVar2 = tjPlaneHeight(iVar4,param_3,param_4);
17: if ((iVar1 < 0) || (iVar2 < 0)) {
18: return -1;
19: }
20: iVar4 = iVar4 + 1;
21: lVar5 = lVar5 + (long)(iVar1 + -1 + param_2 & -param_2) * (long)iVar2;
22: } while ((param_4 != 3) + 1 + (uint)(param_4 != 3) != iVar4);
23: }
24: else {
25: puVar3 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
26: *(undefined2 *)(puVar3 + 8) = 0x74;
27: lVar5 = -1;
28: *puVar3 = 0x75426a74;
29: puVar3[1] = 0x7a695366;
30: puVar3[2] = 0x56555965;
31: puVar3[3] = 0x3a292832;
32: puVar3[4] = 0x766e4920;
33: puVar3[5] = 0x64696c61;
34: puVar3[6] = 0x67726120;
35: puVar3[7] = 0x6e656d75;
36: }
37: return lVar5;
38: }
39: 
