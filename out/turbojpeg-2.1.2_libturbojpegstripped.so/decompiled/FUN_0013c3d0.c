1: 
2: void FUN_0013c3d0(long param_1)
3: 
4: {
5: code **ppcVar1;
6: undefined (*pauVar2) [16];
7: int iVar3;
8: 
9: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x68);
10: iVar3 = *(int *)(param_1 + 0x38);
11: *(code ***)(param_1 + 0x250) = ppcVar1;
12: ppcVar1[8] = (code *)0x0;
13: ppcVar1[9] = (code *)0x0;
14: *ppcVar1 = FUN_0013afd0;
15: ppcVar1[10] = (code *)0x0;
16: ppcVar1[0xb] = (code *)0x0;
17: pauVar2 = (undefined (*) [16])(***(code ***)(param_1 + 8))(param_1,1,(long)(iVar3 << 7) << 2);
18: *(undefined (**) [16])(param_1 + 0xc0) = pauVar2;
19: if (0 < *(int *)(param_1 + 0x38)) {
20: iVar3 = 0;
21: do {
22: iVar3 = iVar3 + 1;
23: *pauVar2 = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
24: pauVar2[1] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
25: pauVar2[2] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
26: pauVar2[3] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
27: pauVar2[4] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
28: pauVar2[5] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
29: pauVar2[6] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
30: pauVar2[7] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
31: pauVar2[8] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
32: pauVar2[9] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
33: pauVar2[10] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
34: pauVar2[0xb] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
35: pauVar2[0xc] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
36: pauVar2[0xd] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
37: pauVar2[0xe] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
38: pauVar2[0xf] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
39: pauVar2 = pauVar2[0x10];
40: } while (*(int *)(param_1 + 0x38) != iVar3 && iVar3 <= *(int *)(param_1 + 0x38));
41: }
42: return;
43: }
44: 
