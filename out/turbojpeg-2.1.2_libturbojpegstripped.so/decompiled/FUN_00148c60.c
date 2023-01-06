1: 
2: void FUN_00148c60(code **param_1,uint param_2)
3: 
4: {
5: code *pcVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: undefined8 *puVar4;
9: undefined8 *puVar5;
10: long lVar6;
11: 
12: pcVar2 = param_1[1];
13: if (param_2 < 2) {
14: if (param_2 == 1) {
15: lVar6 = *(long *)(pcVar2 + 0x88);
16: while (lVar6 != 0) {
17: while (*(int *)(lVar6 + 0x2c) != 0) {
18: *(undefined4 *)(lVar6 + 0x2c) = 0;
19: (**(code **)(lVar6 + 0x48))(param_1,lVar6 + 0x38);
20: lVar6 = *(long *)(lVar6 + 0x30);
21: if (lVar6 == 0) goto LAB_00148d59;
22: }
23: lVar6 = *(long *)(lVar6 + 0x30);
24: }
25: LAB_00148d59:
26: lVar6 = *(long *)(pcVar2 + 0x90);
27: *(undefined8 *)(pcVar2 + 0x88) = 0;
28: while (lVar6 != 0) {
29: while (*(int *)(lVar6 + 0x2c) != 0) {
30: *(undefined4 *)(lVar6 + 0x2c) = 0;
31: (**(code **)(lVar6 + 0x48))(param_1,lVar6 + 0x38);
32: lVar6 = *(long *)(lVar6 + 0x30);
33: if (lVar6 == 0) goto LAB_00148d91;
34: }
35: lVar6 = *(long *)(lVar6 + 0x30);
36: }
37: LAB_00148d91:
38: *(undefined8 *)(pcVar2 + 0x90) = 0;
39: }
40: }
41: else {
42: ppcVar3 = (code **)*param_1;
43: *(undefined4 *)(ppcVar3 + 5) = 0xe;
44: *(uint *)((long)ppcVar3 + 0x2c) = param_2;
45: (**ppcVar3)();
46: }
47: pcVar1 = pcVar2 + (long)(int)param_2 * 8;
48: puVar4 = *(undefined8 **)(pcVar1 + 0x78);
49: *(undefined8 *)(pcVar1 + 0x78) = 0;
50: while (puVar4 != (undefined8 *)0x0) {
51: puVar5 = (undefined8 *)*puVar4;
52: lVar6 = puVar4[2] + puVar4[1] + 0x37;
53: FUN_0014a5d0(param_1,puVar4,lVar6);
54: *(long *)(pcVar2 + 0x98) = *(long *)(pcVar2 + 0x98) - lVar6;
55: puVar4 = puVar5;
56: }
57: puVar4 = *(undefined8 **)(pcVar1 + 0x68);
58: *(undefined8 *)(pcVar1 + 0x68) = 0;
59: while (puVar4 != (undefined8 *)0x0) {
60: puVar5 = (undefined8 *)*puVar4;
61: lVar6 = puVar4[2] + puVar4[1] + 0x37;
62: FUN_0014a5b0(param_1,puVar4,lVar6);
63: *(long *)(pcVar2 + 0x98) = *(long *)(pcVar2 + 0x98) - lVar6;
64: puVar4 = puVar5;
65: }
66: return;
67: }
68: 
