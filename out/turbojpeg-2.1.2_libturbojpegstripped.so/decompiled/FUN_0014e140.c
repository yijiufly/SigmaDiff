1: 
2: void FUN_0014e140(long param_1)
3: 
4: {
5: code **ppcVar1;
6: undefined (*pauVar2) [16];
7: ulong uVar3;
8: int iVar4;
9: undefined8 *puVar5;
10: byte bVar6;
11: 
12: bVar6 = 0;
13: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x158);
14: *(code ***)(param_1 + 0x250) = ppcVar1;
15: *ppcVar1 = FUN_0014ca40;
16: ppcVar1[10] = (code *)0x0;
17: ppcVar1[0x19] = (code *)0x0;
18: uVar3 = (ulong)(((int)ppcVar1 - (int)(undefined8 *)((ulong)(ppcVar1 + 0xb) & 0xfffffffffffffff8))
19: + 0xd0U >> 3);
20: puVar5 = (undefined8 *)((ulong)(ppcVar1 + 0xb) & 0xfffffffffffffff8);
21: while (uVar3 != 0) {
22: uVar3 = uVar3 - 1;
23: *puVar5 = 0;
24: puVar5 = puVar5 + (ulong)bVar6 * -2 + 1;
25: }
26: ppcVar1[0x1a] = (code *)0x0;
27: ppcVar1[0x29] = (code *)0x0;
28: uVar3 = (ulong)(((int)ppcVar1 - (int)(undefined8 *)((ulong)(ppcVar1 + 0x1b) & 0xfffffffffffffff8))
29: + 0x150U >> 3);
30: puVar5 = (undefined8 *)((ulong)(ppcVar1 + 0x1b) & 0xfffffffffffffff8);
31: while (uVar3 != 0) {
32: uVar3 = uVar3 - 1;
33: *puVar5 = 0;
34: puVar5 = puVar5 + (ulong)bVar6 * -2 + 1;
35: }
36: *(undefined *)(ppcVar1 + 0x2a) = 0x71;
37: if (*(int *)(param_1 + 0x138) != 0) {
38: pauVar2 = (undefined (*) [16])
39: (***(code ***)(param_1 + 8))(param_1,1,(long)(*(int *)(param_1 + 0x38) << 7) << 2);
40: *(undefined (**) [16])(param_1 + 0xc0) = pauVar2;
41: if (0 < *(int *)(param_1 + 0x38)) {
42: iVar4 = 0;
43: do {
44: iVar4 = iVar4 + 1;
45: *pauVar2 = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
46: pauVar2[1] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
47: pauVar2[2] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
48: pauVar2[3] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
49: pauVar2[4] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
50: pauVar2[5] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
51: pauVar2[6] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
52: pauVar2[7] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
53: pauVar2[8] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
54: pauVar2[9] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
55: pauVar2[10] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
56: pauVar2[0xb] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
57: pauVar2[0xc] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
58: pauVar2[0xd] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
59: pauVar2[0xe] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
60: pauVar2[0xf] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
61: pauVar2 = pauVar2[0x10];
62: } while (*(int *)(param_1 + 0x38) != iVar4 && iVar4 <= *(int *)(param_1 + 0x38));
63: }
64: }
65: return;
66: }
67: 
