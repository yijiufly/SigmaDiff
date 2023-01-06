1: 
2: void FUN_00112400(long param_1)
3: 
4: {
5: code **ppcVar1;
6: 
7: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,1,200);
8: *(code ***)(param_1 + 0x1f0) = ppcVar1;
9: ppcVar1[0xc] = (code *)0x0;
10: ppcVar1[0xd] = (code *)0x0;
11: ppcVar1[0xe] = (code *)0x0;
12: *ppcVar1 = FUN_00111ae0;
13: ppcVar1[0xf] = (code *)0x0;
14: ppcVar1[8] = (code *)0x0;
15: ppcVar1[9] = (code *)0x0;
16: ppcVar1[10] = (code *)0x0;
17: ppcVar1[0xb] = (code *)0x0;
18: ppcVar1[0x14] = (code *)0x0;
19: ppcVar1[0x15] = (code *)0x0;
20: ppcVar1[0x16] = (code *)0x0;
21: ppcVar1[0x17] = (code *)0x0;
22: ppcVar1[0x10] = (code *)0x0;
23: ppcVar1[0x11] = (code *)0x0;
24: ppcVar1[0x12] = (code *)0x0;
25: ppcVar1[0x13] = (code *)0x0;
26: return;
27: }
28: 
