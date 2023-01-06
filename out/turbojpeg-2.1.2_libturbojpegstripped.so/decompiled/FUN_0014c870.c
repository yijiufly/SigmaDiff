1: 
2: void FUN_0014c870(long param_1)
3: 
4: {
5: code **ppcVar1;
6: ulong uVar2;
7: undefined8 *puVar3;
8: byte bVar4;
9: 
10: bVar4 = 0;
11: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x170);
12: *(code ***)(param_1 + 0x1f0) = ppcVar1;
13: *ppcVar1 = FUN_0014a640;
14: ppcVar1[0xd] = (code *)0x0;
15: ppcVar1[0x1c] = (code *)0x0;
16: ppcVar1[2] = FUN_0014b3d0;
17: uVar2 = (ulong)(((int)ppcVar1 - (int)(undefined8 *)((ulong)(ppcVar1 + 0xe) & 0xfffffffffffffff8))
18: + 0xe8U >> 3);
19: puVar3 = (undefined8 *)((ulong)(ppcVar1 + 0xe) & 0xfffffffffffffff8);
20: while (uVar2 != 0) {
21: uVar2 = uVar2 - 1;
22: *puVar3 = 0;
23: puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
24: }
25: ppcVar1[0x1d] = (code *)0x0;
26: ppcVar1[0x2c] = (code *)0x0;
27: uVar2 = (ulong)(((int)ppcVar1 - (int)(undefined8 *)((ulong)(ppcVar1 + 0x1e) & 0xfffffffffffffff8))
28: + 0x168U >> 3);
29: puVar3 = (undefined8 *)((ulong)(ppcVar1 + 0x1e) & 0xfffffffffffffff8);
30: while (uVar2 != 0) {
31: uVar2 = uVar2 - 1;
32: *puVar3 = 0;
33: puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
34: }
35: *(undefined *)(ppcVar1 + 0x2d) = 0x71;
36: return;
37: }
38: 
