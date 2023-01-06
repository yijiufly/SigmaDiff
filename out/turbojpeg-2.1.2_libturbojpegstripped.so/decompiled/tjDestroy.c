1: 
2: int tjDestroy(void *param_1)
3: 
4: {
5: int iVar1;
6: undefined8 *puVar2;
7: uint uVar3;
8: 
9: if (param_1 == (void *)0x0) {
10: puVar2 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
11: iVar1 = -1;
12: *puVar2 = 0x2064696c61766e49;
13: *(undefined4 *)(puVar2 + 1) = 0x646e6168;
14: *(undefined2 *)((long)puVar2 + 0xc) = 0x656c;
15: *(undefined *)((long)puVar2 + 0xe) = 0;
16: }
17: else {
18: *(undefined4 *)((long)param_1 + 0x5f8) = 0;
19: *(undefined4 *)((long)param_1 + 0x6d0) = 0;
20: iVar1 = _setjmp((__jmp_buf_tag *)((long)param_1 + 0x528));
21: if (iVar1 == 0) {
22: uVar3 = *(uint *)((long)param_1 + 0x600);
23: if ((uVar3 & 1) != 0) {
24: thunk_FUN_0011f4e0(param_1);
25: uVar3 = *(uint *)((long)param_1 + 0x600);
26: }
27: if ((uVar3 & 2) != 0) {
28: thunk_FUN_0011f4e0((long)param_1 + 0x208);
29: }
30: free(param_1);
31: }
32: else {
33: iVar1 = -1;
34: }
35: }
36: return iVar1;
37: }
38: 
