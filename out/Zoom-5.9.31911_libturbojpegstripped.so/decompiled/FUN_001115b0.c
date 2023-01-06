1: 
2: void FUN_001115b0(code **param_1)
3: 
4: {
5: code *pcVar1;
6: char *__dest;
7: long lVar2;
8: undefined8 uVar3;
9: undefined8 uVar4;
10: char **ppcVar5;
11: code **ppcVar6;
12: char *__src;
13: char cVar7;
14: int iVar8;
15: char *__n;
16: char *pcVar9;
17: char *pcVar10;
18: char *pcVar11;
19: long in_FS_OFFSET;
20: ulong uStack624;
21: char acStack584 [520];
22: long lStack64;
23: 
24: pcVar1 = param_1[0x3e];
25: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
26: pcVar10 = *(char **)((long)param_1[5] + 8);
27: __dest = *(char **)param_1[5];
28: uStack624 = *(ulong *)(pcVar1 + 0x20);
29: lVar2 = *(long *)(pcVar1 + 0x18);
30: uVar3 = *(undefined8 *)(pcVar1 + 0x28);
31: uVar4 = *(undefined8 *)(pcVar1 + 0x30);
32: pcVar9 = __dest;
33: if (pcVar10 < (char *)0x200) {
34: pcVar9 = acStack584;
35: }
36: iVar8 = *(int *)(pcVar1 + 0x20) + 7;
37: while (7 < iVar8) {
38: while( true ) {
39: iVar8 = iVar8 + -8;
40: cVar7 = (char)((lVar2 << 7 | 0x7fU) >> ((byte)iVar8 & 0x3f));
41: *pcVar9 = cVar7;
42: if (cVar7 == -1) break;
43: pcVar9 = pcVar9 + 1;
44: if (iVar8 < 8) goto LAB_00111651;
45: }
46: pcVar9[1] = '\0';
47: pcVar9 = pcVar9 + 2;
48: }
49: LAB_00111651:
50: if (pcVar10 < (char *)0x200) {
51: pcVar11 = pcVar9 + -(long)acStack584;
52: __src = acStack584;
53: while (pcVar9 = __dest, pcVar11 != (char *)0x0) {
54: __n = pcVar11;
55: if (pcVar10 <= pcVar11) {
56: __n = pcVar10;
57: }
58: pcVar9 = __dest + (long)__n;
59: memcpy(__dest,__src,(size_t)__n);
60: pcVar10 = pcVar10 + -(long)__n;
61: if (pcVar10 == (char *)0x0) {
62: ppcVar5 = (char **)param_1[5];
63: iVar8 = (*(code *)ppcVar5[3])(param_1);
64: if (iVar8 == 0) {
65: ppcVar6 = (code **)*param_1;
66: *(undefined4 *)(ppcVar6 + 5) = 0x18;
67: (**ppcVar6)();
68: break;
69: }
70: pcVar9 = *ppcVar5;
71: pcVar10 = ppcVar5[1];
72: }
73: pcVar11 = pcVar11 + -(long)__n;
74: __dest = pcVar9;
75: __src = __src + (long)__n;
76: }
77: }
78: else {
79: pcVar10 = pcVar10 + (long)(__dest + -(long)pcVar9);
80: }
81: uStack624 = uStack624 & 0xffffffff00000000;
82: ppcVar5 = (char **)param_1[5];
83: *ppcVar5 = pcVar9;
84: ppcVar5[1] = pcVar10;
85: *(undefined8 *)(pcVar1 + 0x18) = 0;
86: *(ulong *)(pcVar1 + 0x20) = uStack624;
87: *(undefined8 *)(pcVar1 + 0x28) = uVar3;
88: *(undefined8 *)(pcVar1 + 0x30) = uVar4;
89: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
90: return;
91: }
92: /* WARNING: Subroutine does not return */
93: __stack_chk_fail();
94: }
95: 
