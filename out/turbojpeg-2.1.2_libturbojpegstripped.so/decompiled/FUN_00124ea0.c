1: 
2: void FUN_00124ea0(code **param_1,int param_2,long param_3)
3: 
4: {
5: code *pcVar1;
6: undefined8 *puVar2;
7: ulong uVar3;
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
20: if (param_3 != 0x278) {
21: *(int *)(ppcVar4 + 6) = (int)param_3;
22: ppcVar4[5] = (code *)0x27800000015;
23: (**ppcVar4)(param_1);
24: ppcVar4 = (code **)*param_1;
25: }
26: pcVar1 = param_1[3];
27: param_1[0x4e] = (code *)0x0;
28: uVar3 = (ulong)(((int)param_1 - (int)(undefined8 *)((ulong)(param_1 + 1) & 0xfffffffffffffff8)) +
29: 0x278U >> 3);
30: puVar2 = (undefined8 *)((ulong)(param_1 + 1) & 0xfffffffffffffff8);
31: while (uVar3 != 0) {
32: uVar3 = uVar3 - 1;
33: *puVar2 = 0;
34: puVar2 = puVar2 + (ulong)bVar5 * -2 + 1;
35: }
36: *param_1 = (code *)ppcVar4;
37: param_1[3] = pcVar1;
38: *(undefined4 *)(param_1 + 4) = 1;
39: FUN_0014a3f0(param_1);
40: param_1[2] = (code *)0x0;
41: param_1[5] = (code *)0x0;
42: param_1[0x19] = (code *)0x0;
43: param_1[0x1a] = (code *)0x0;
44: param_1[0x1b] = (code *)0x0;
45: param_1[0x1c] = (code *)0x0;
46: param_1[0x1d] = (code *)0x0;
47: param_1[0x21] = (code *)0x0;
48: param_1[0x1e] = (code *)0x0;
49: param_1[0x22] = (code *)0x0;
50: param_1[0x1f] = (code *)0x0;
51: param_1[0x23] = (code *)0x0;
52: param_1[0x20] = (code *)0x0;
53: param_1[0x24] = (code *)0x0;
54: param_1[0x32] = (code *)0x0;
55: FUN_00136980(param_1);
56: FUN_001336d0(param_1);
57: *(undefined4 *)((long)param_1 + 0x24) = 200;
58: puVar2 = (undefined8 *)(**(code **)param_1[1])(param_1,0,0x90);
59: param_1[0x44] = (code *)puVar2;
60: *puVar2 = 0;
61: puVar2[0x11] = 0;
62: uVar3 = (ulong)(((int)puVar2 - (int)(undefined8 *)((ulong)(puVar2 + 1) & 0xfffffffffffffff8)) +
63: 0x90U >> 3);
64: puVar2 = (undefined8 *)((ulong)(puVar2 + 1) & 0xfffffffffffffff8);
65: while (uVar3 != 0) {
66: uVar3 = uVar3 - 1;
67: *puVar2 = 0;
68: puVar2 = puVar2 + (ulong)bVar5 * -2 + 1;
69: }
70: return;
71: }
72: 
