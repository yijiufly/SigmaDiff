1: 
2: void FUN_0016b5d0(code **param_1,long param_2)
3: 
4: {
5: FILE *__s;
6: code **ppcVar1;
7: int iVar2;
8: void **ppvVar3;
9: uint uVar4;
10: uint uVar5;
11: 
12: __s = *(FILE **)(param_2 + 0x20);
13: if (*(int *)(param_2 + 0x58) != 0) {
14: ppcVar1 = (code **)param_1[2];
15: if (*(int *)(param_2 + 0x38) == 0) {
16: FUN_0016b1d0();
17: }
18: else {
19: FUN_0016ae80();
20: }
21: uVar5 = *(uint *)((long)param_1 + 0x8c);
22: if (uVar5 == 0) {
23: if (ppcVar1 == (code **)0x0) goto LAB_0016b675;
24: }
25: else {
26: uVar4 = uVar5;
27: if (ppcVar1 == (code **)0x0) {
28: do {
29: uVar5 = uVar5 - 1;
30: ppvVar3 = (void **)(**(code **)(param_1[1] + 0x38))
31: (param_1,*(undefined8 *)(param_2 + 0x40),uVar5,1,0);
32: fwrite(*ppvVar3,1,(ulong)*(uint *)(param_2 + 0x4c),__s);
33: } while (uVar5 != 0);
34: goto LAB_0016b675;
35: }
36: while( true ) {
37: ppcVar1[2] = (code *)(ulong)uVar4;
38: uVar4 = uVar4 - uVar5;
39: uVar5 = uVar5 - 1;
40: ppcVar1[1] = (code *)(ulong)uVar4;
41: (**ppcVar1)(param_1);
42: ppvVar3 = (void **)(**(code **)(param_1[1] + 0x38))
43: (param_1,*(undefined8 *)(param_2 + 0x40),uVar5,1,0);
44: fwrite(*ppvVar3,1,(ulong)*(uint *)(param_2 + 0x4c),__s);
45: if (uVar5 == 0) break;
46: uVar4 = *(uint *)((long)param_1 + 0x8c);
47: }
48: }
49: *(int *)(ppcVar1 + 4) = *(int *)(ppcVar1 + 4) + 1;
50: }
51: LAB_0016b675:
52: fflush(__s);
53: iVar2 = ferror(__s);
54: if (iVar2 == 0) {
55: return;
56: }
57: ppcVar1 = (code **)*param_1;
58: *(undefined4 *)(ppcVar1 + 5) = 0x25;
59: /* WARNING: Could not recover jumptable at 0x0016b6a1. Too many branches */
60: /* WARNING: Treating indirect jump as call */
61: (**ppcVar1)(param_1);
62: return;
63: }
64: 
