1: 
2: undefined8 FUN_00108780(char **param_1)
3: 
4: {
5: char **ppcVar1;
6: char cVar2;
7: char *__n;
8: char *pcVar3;
9: undefined8 uVar4;
10: int iVar5;
11: char *pcVar6;
12: char *pcVar7;
13: char *__src;
14: long in_FS_OFFSET;
15: char acStack568 [520];
16: long lStack48;
17: 
18: __src = acStack568;
19: pcVar7 = acStack568;
20: pcVar3 = param_1[2];
21: lStack48 = *(long *)(in_FS_OFFSET + 0x28);
22: pcVar6 = param_1[1];
23: if ((char *)0x1ff < pcVar6) {
24: pcVar7 = *param_1;
25: }
26: iVar5 = *(int *)(param_1 + 3) + 7;
27: while (7 < iVar5) {
28: while( true ) {
29: iVar5 = iVar5 + -8;
30: cVar2 = (char)(((long)pcVar3 << 7 | 0x7fU) >> ((byte)iVar5 & 0x3f));
31: *pcVar7 = cVar2;
32: if (cVar2 == -1) break;
33: pcVar7 = pcVar7 + 1;
34: if (iVar5 < 8) goto LAB_001087ed;
35: }
36: pcVar7[1] = '\0';
37: pcVar7 = pcVar7 + 2;
38: }
39: LAB_001087ed:
40: param_1[2] = (char *)0x0;
41: *(undefined4 *)(param_1 + 3) = 0;
42: if ((char *)0x1ff < pcVar6) {
43: pcVar3 = *param_1;
44: *param_1 = pcVar7;
45: param_1[1] = param_1[1] + (long)(pcVar3 + -(long)pcVar7);
46: }
47: else {
48: pcVar7 = pcVar7 + -(long)acStack568;
49: if (pcVar7 != (char *)0x0) {
50: pcVar3 = param_1[1];
51: pcVar6 = *param_1;
52: do {
53: while( true ) {
54: __n = pcVar3;
55: if (pcVar7 < pcVar3) {
56: __n = pcVar7;
57: }
58: memcpy(pcVar6,__src,(size_t)__n);
59: pcVar6 = __n + (long)*param_1;
60: __src = __src + (long)__n;
61: pcVar3 = param_1[1] + -(long)__n;
62: *param_1 = pcVar6;
63: param_1[1] = pcVar3;
64: if (pcVar3 != (char *)0x0) break;
65: ppcVar1 = *(char ***)(param_1[6] + 0x28);
66: iVar5 = (*(code *)ppcVar1[3])();
67: if (iVar5 == 0) {
68: uVar4 = 0;
69: goto LAB_00108885;
70: }
71: pcVar6 = *ppcVar1;
72: pcVar3 = ppcVar1[1];
73: pcVar7 = pcVar7 + -(long)__n;
74: *param_1 = pcVar6;
75: param_1[1] = pcVar3;
76: if (pcVar7 == (char *)0x0) goto LAB_00108880;
77: }
78: pcVar7 = pcVar7 + -(long)__n;
79: } while (pcVar7 != (char *)0x0);
80: }
81: }
82: LAB_00108880:
83: uVar4 = 1;
84: LAB_00108885:
85: if (lStack48 != *(long *)(in_FS_OFFSET + 0x28)) {
86: /* WARNING: Subroutine does not return */
87: __stack_chk_fail();
88: }
89: return uVar4;
90: }
91: 
