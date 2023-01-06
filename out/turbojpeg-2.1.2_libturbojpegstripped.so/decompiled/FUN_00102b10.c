1: 
2: void FUN_00102b10(code **param_1,int param_2,long param_3)
3: 
4: {
5: code *pcVar1;
6: ulong uVar2;
7: undefined8 *puVar3;
8: code **ppcVar4;
9: byte bVar5;
10: 
11: bVar5 = 0;
12: param_1[1] = (code *)0x0;
13: ppcVar4 = (code **)*param_1;
14: if (param_2 != 0x3e) {
15: *(int *)(ppcVar4 + 6) = param_2;
16: ppcVar4[5] = (code *)0x3e0000000c;
17: (**ppcVar4)();
18: ppcVar4 = (code **)*param_1;
19: }
20: if (param_3 != 0x208) {
21: *(int *)(ppcVar4 + 6) = (int)param_3;
22: ppcVar4[5] = (code *)0x20800000015;
23: (**ppcVar4)(param_1);
24: ppcVar4 = (code **)*param_1;
25: }
26: pcVar1 = param_1[3];
27: param_1[0x40] = (code *)0x0;
28: uVar2 = (ulong)(((int)param_1 - (int)(undefined8 *)((ulong)(param_1 + 1) & 0xfffffffffffffff8)) +
29: 0x208U >> 3);
30: puVar3 = (undefined8 *)((ulong)(param_1 + 1) & 0xfffffffffffffff8);
31: while (uVar2 != 0) {
32: uVar2 = uVar2 - 1;
33: *puVar3 = 0;
34: puVar3 = puVar3 + (ulong)bVar5 * -2 + 1;
35: }
36: *param_1 = (code *)ppcVar4;
37: param_1[3] = pcVar1;
38: *(undefined4 *)(param_1 + 4) = 0;
39: FUN_0014a3f0(param_1);
40: param_1[2] = (code *)0x0;
41: param_1[5] = (code *)0x0;
42: param_1[0xb] = (code *)0x0;
43: param_1[0xc] = (code *)0x0;
44: param_1[0xd] = (code *)0x0;
45: param_1[0xe] = (code *)0x0;
46: param_1[0xf] = (code *)0x0;
47: param_1[0x10] = (code *)0x0;
48: param_1[0x14] = (code *)0x0;
49: param_1[0x11] = (code *)0x0;
50: param_1[0x15] = (code *)0x0;
51: param_1[0x12] = (code *)0x0;
52: param_1[0x16] = (code *)0x0;
53: param_1[0x13] = (code *)0x0;
54: param_1[0x17] = (code *)0x0;
55: param_1[0x3f] = (code *)0x0;
56: param_1[8] = (code *)0x3ff0000000000000;
57: *(undefined4 *)((long)param_1 + 0x24) = 100;
58: return;
59: }
60: 
