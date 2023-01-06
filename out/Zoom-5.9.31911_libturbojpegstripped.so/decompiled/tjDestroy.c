1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: int tjDestroy(void *param_1)
5: 
6: {
7: uint uVar1;
8: int iVar2;
9: 
10: if (param_1 == (void *)0x0) {
11: s_No_error_003a6000._8_4_ = 0x646e6168;
12: DAT_003a600e = 0;
13: s_No_error_003a6000._0_8_ = 0x2064696c61766e49;
14: iVar2 = -1;
15: _DAT_003a600c = 0x656c;
16: }
17: else {
18: *(undefined4 *)((long)param_1 + 0x5f8) = 0;
19: *(undefined4 *)((long)param_1 + 0x6d0) = 0;
20: iVar2 = _setjmp((__jmp_buf_tag *)((long)param_1 + 0x528));
21: if (iVar2 == 0) {
22: uVar1 = *(uint *)((long)param_1 + 0x600);
23: if ((uVar1 & 1) != 0) {
24: thunk_FUN_00116730(param_1);
25: uVar1 = *(uint *)((long)param_1 + 0x600);
26: }
27: if ((uVar1 & 2) != 0) {
28: thunk_FUN_00116730((long)param_1 + 0x208);
29: }
30: free(param_1);
31: }
32: else {
33: iVar2 = -1;
34: }
35: }
36: return iVar2;
37: }
38: 
