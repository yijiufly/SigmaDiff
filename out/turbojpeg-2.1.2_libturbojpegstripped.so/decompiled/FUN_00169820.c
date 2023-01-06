1: 
2: uint FUN_00169820(code **param_1,_IO_FILE *param_2,uint param_3)
3: 
4: {
5: code **ppcVar1;
6: uint uVar2;
7: int iVar3;
8: ulong uVar4;
9: 
10: while( true ) {
11: uVar2 = _IO_getc(param_2);
12: uVar4 = (ulong)uVar2;
13: if (uVar2 == 0x23) {
14: do {
15: uVar2 = _IO_getc(param_2);
16: uVar4 = (ulong)uVar2;
17: if (uVar2 == 10) goto LAB_00169900;
18: } while (uVar2 != 0xffffffff);
19: }
20: if ((int)uVar4 == -1) break;
21: LAB_00169900:
22: if ((0x20 < (uint)uVar4) || ((0x100002600U >> (uVar4 & 0x3f) & 1) == 0)) {
23: uVar2 = (uint)uVar4 - 0x30;
24: if (9 < uVar2) {
25: LAB_0016986c:
26: ppcVar1 = (code **)*param_1;
27: *(undefined4 *)(ppcVar1 + 5) = 0x3f7;
28: (**ppcVar1)(param_1);
29: }
30: LAB_0016987c:
31: iVar3 = _IO_getc(param_2);
32: do {
33: if (iVar3 == 0x23) {
34: do {
35: iVar3 = _IO_getc(param_2);
36: if (iVar3 == 10) break;
37: } while (iVar3 != -1);
38: }
39: if (9 < iVar3 - 0x30U) {
40: return uVar2;
41: }
42: uVar2 = iVar3 + -0x30 + uVar2 * 10;
43: if (uVar2 <= param_3) goto LAB_0016987c;
44: ppcVar1 = (code **)*param_1;
45: *(undefined4 *)(ppcVar1 + 5) = 0x3f9;
46: (**ppcVar1)(param_1);
47: iVar3 = _IO_getc(param_2);
48: } while( true );
49: }
50: }
51: ppcVar1 = (code **)*param_1;
52: uVar2 = 0xffffffcf;
53: *(undefined4 *)(ppcVar1 + 5) = 0x2b;
54: (**ppcVar1)(param_1);
55: goto LAB_0016986c;
56: }
57: 
