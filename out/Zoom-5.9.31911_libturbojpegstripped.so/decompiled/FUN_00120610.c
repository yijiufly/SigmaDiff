1: 
2: void FUN_00120610(long param_1)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: undefined8 uVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: 
16: lVar6 = *(long *)(param_1 + 0x268);
17: uVar4 = (***(code ***)(param_1 + 8))(param_1,1,0x400);
18: *(undefined8 *)(lVar6 + 0x10) = uVar4;
19: uVar4 = (***(code ***)(param_1 + 8))(param_1,1,0x400);
20: *(undefined8 *)(lVar6 + 0x18) = uVar4;
21: uVar4 = (***(code ***)(param_1 + 8))(param_1,1,0x800);
22: *(undefined8 *)(lVar6 + 0x20) = uVar4;
23: lVar5 = (***(code ***)(param_1 + 8))(param_1,1,0x800);
24: lVar1 = *(long *)(lVar6 + 0x10);
25: lVar2 = *(long *)(lVar6 + 0x18);
26: lVar10 = 0x2c8d00;
27: lVar3 = *(long *)(lVar6 + 0x20);
28: *(long *)(lVar6 + 0x28) = lVar5;
29: lVar9 = 0x5b6900;
30: lVar7 = -0x80;
31: lVar6 = -0xb2f480;
32: lVar8 = -0xe25100;
33: do {
34: *(int *)(lVar1 + 0x200 + lVar7 * 4) = (int)((ulong)lVar6 >> 0x10);
35: *(int *)(lVar2 + 0x200 + lVar7 * 4) = (int)((ulong)lVar8 >> 0x10);
36: *(long *)(lVar3 + 0x400 + lVar7 * 8) = lVar9;
37: lVar9 = lVar9 + -0xb6d2;
38: *(long *)(lVar5 + 0x400 + lVar7 * 8) = lVar10;
39: lVar7 = lVar7 + 1;
40: lVar10 = lVar10 + -0x581a;
41: lVar6 = lVar6 + 0x166e9;
42: lVar8 = lVar8 + 0x1c5a2;
43: } while (lVar7 != 0x80);
44: return;
45: }
46: 
