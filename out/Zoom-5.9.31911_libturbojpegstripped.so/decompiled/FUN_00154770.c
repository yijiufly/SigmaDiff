1: 
2: void FUN_00154770(code **param_1,long param_2)
3: 
4: {
5: byte *pbVar1;
6: byte bVar2;
7: uint uVar3;
8: code **ppcVar4;
9: _IO_FILE *__fp;
10: byte **ppbVar5;
11: int iVar6;
12: byte *pbVar7;
13: 
14: ppcVar4 = (code **)param_1[2];
15: __fp = *(_IO_FILE **)(param_2 + 0x20);
16: if (*(int *)(param_2 + 0x58) != 0) {
17: if (*(int *)(param_2 + 0x38) == 0) {
18: FUN_00153fe0();
19: }
20: else {
21: FUN_00154420();
22: }
23: iVar6 = *(int *)((long)param_1 + 0x8c);
24: while (iVar6 != 0) {
25: while( true ) {
26: if (ppcVar4 != (code **)0x0) {
27: uVar3 = *(uint *)((long)param_1 + 0x8c);
28: ppcVar4[2] = (code *)(ulong)uVar3;
29: ppcVar4[1] = (code *)(ulong)(uVar3 - iVar6);
30: (**ppcVar4)(param_1);
31: }
32: iVar6 = iVar6 + -1;
33: ppbVar5 = (byte **)(**(code **)(param_1[1] + 0x38))
34: (param_1,*(undefined8 *)(param_2 + 0x40),iVar6,1,0);
35: pbVar7 = *ppbVar5;
36: pbVar1 = pbVar7 + (ulong)(*(int *)(param_2 + 0x4c) - 1) + 1;
37: if (*(int *)(param_2 + 0x4c) == 0) break;
38: do {
39: bVar2 = *pbVar7;
40: pbVar7 = pbVar7 + 1;
41: _IO_putc((uint)bVar2,__fp);
42: } while (pbVar7 != pbVar1);
43: if (iVar6 == 0) goto LAB_00154832;
44: }
45: }
46: LAB_00154832:
47: if (ppcVar4 != (code **)0x0) {
48: *(int *)(ppcVar4 + 4) = *(int *)(ppcVar4 + 4) + 1;
49: }
50: }
51: fflush((FILE *)__fp);
52: iVar6 = ferror((FILE *)__fp);
53: if (iVar6 != 0) {
54: ppcVar4 = (code **)*param_1;
55: *(undefined4 *)(ppcVar4 + 5) = 0x25;
56: /* WARNING: Could not recover jumptable at 0x0015488f. Too many branches */
57: /* WARNING: Treating indirect jump as call */
58: (**ppcVar4)(param_1);
59: return;
60: }
61: return;
62: }
63: 
