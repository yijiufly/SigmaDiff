1: 
2: void FUN_0014a3f0(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: long lVar2;
7: int iVar3;
8: code **ppcVar4;
9: char *pcVar5;
10: long in_FS_OFFSET;
11: byte bStack41;
12: code *pcStack40;
13: long lStack32;
14: 
15: param_1[1] = (code *)0x0;
16: lStack32 = *(long *)(in_FS_OFFSET + 0x28);
17: pcStack40 = (code *)FUN_0014a620();
18: ppcVar4 = (code **)FUN_0014a5a0(param_1,0xa8);
19: if (ppcVar4 == (code **)0x0) {
20: FUN_0014a630(param_1);
21: ppcVar1 = (code **)*param_1;
22: ppcVar1[5] = (code *)0x36;
23: (**ppcVar1)(param_1);
24: }
25: ppcVar4[0xc] = (code *)0x3b9aca00;
26: ppcVar4[0xe] = (code *)0x0;
27: ppcVar4[0x10] = (code *)0x0;
28: *ppcVar4 = FUN_00148a90;
29: ppcVar4[0xd] = (code *)0x0;
30: ppcVar4[0xf] = (code *)0x0;
31: ppcVar4[0x11] = (code *)0x0;
32: ppcVar4[1] = FUN_00148e10;
33: ppcVar4[0x12] = (code *)0x0;
34: ppcVar4[0x13] = (code *)0xa8;
35: ppcVar4[2] = FUN_00149ac0;
36: ppcVar4[3] = FUN_001498a0;
37: ppcVar4[4] = FUN_00149d00;
38: ppcVar4[5] = FUN_00149690;
39: ppcVar4[6] = FUN_00149f10;
40: ppcVar4[7] = FUN_00149300;
41: ppcVar4[8] = FUN_00148f50;
42: ppcVar4[9] = FUN_00148c60;
43: ppcVar4[10] = FUN_00148dd0;
44: ppcVar4[0xb] = pcStack40;
45: param_1[1] = (code *)ppcVar4;
46: pcVar5 = getenv("JPEGMEM");
47: if (pcVar5 != (char *)0x0) {
48: bStack41 = 0x78;
49: iVar3 = __isoc99_sscanf(pcVar5,"%ld%c",&pcStack40,&bStack41);
50: if (0 < iVar3) {
51: lVar2 = 1000;
52: if ((bStack41 & 0xdf) == 0x4d) {
53: lVar2 = 1000000;
54: }
55: ppcVar4[0xb] = (code *)((long)pcStack40 * lVar2);
56: }
57: }
58: if (lStack32 == *(long *)(in_FS_OFFSET + 0x28)) {
59: return;
60: }
61: /* WARNING: Subroutine does not return */
62: __stack_chk_fail();
63: }
64: 
