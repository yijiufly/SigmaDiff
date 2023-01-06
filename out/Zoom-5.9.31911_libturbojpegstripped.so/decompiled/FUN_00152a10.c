1: 
2: uint FUN_00152a10(code **param_1,_IO_FILE *param_2,uint param_3)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: uint uVar3;
8: 
9: while( true ) {
10: iVar2 = _IO_getc(param_2);
11: if (iVar2 == 0x23) {
12: do {
13: iVar2 = _IO_getc(param_2);
14: if (iVar2 == -1) goto LAB_00152a6f;
15: } while (iVar2 != 10);
16: }
17: if (iVar2 == -1) break;
18: if ((((iVar2 != 9) && (iVar2 != 0x20)) && (iVar2 != 0xd)) && (iVar2 != 10)) {
19: LAB_00152a87:
20: uVar3 = iVar2 - 0x30;
21: if (9 < uVar3) {
22: ppcVar1 = (code **)*param_1;
23: *(undefined4 *)(ppcVar1 + 5) = 0x3f7;
24: (**ppcVar1)(param_1);
25: }
26: do {
27: iVar2 = _IO_getc(param_2);
28: if (iVar2 == 0x23) {
29: do {
30: iVar2 = _IO_getc(param_2);
31: if (iVar2 == -1) break;
32: } while (iVar2 != 10);
33: }
34: if (9 < iVar2 - 0x30U) {
35: if (param_3 < uVar3) {
36: ppcVar1 = (code **)*param_1;
37: *(undefined4 *)(ppcVar1 + 5) = 0x3f9;
38: (**ppcVar1)(param_1);
39: }
40: return uVar3;
41: }
42: uVar3 = iVar2 + -0x30 + uVar3 * 10;
43: } while( true );
44: }
45: }
46: LAB_00152a6f:
47: ppcVar1 = (code **)*param_1;
48: *(undefined4 *)(ppcVar1 + 5) = 0x2b;
49: (**ppcVar1)(param_1);
50: goto LAB_00152a87;
51: }
52: 
