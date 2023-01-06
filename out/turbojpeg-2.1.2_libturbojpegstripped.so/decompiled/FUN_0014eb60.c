1: 
2: void FUN_0014eb60(long *param_1)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: char *pcVar3;
8: long lVar4;
9: char *pcVar5;
10: byte bVar6;
11: 
12: bVar6 = 0;
13: if ((*(int *)(param_1 + 4) != 0) && (500 < *(int *)((long)param_1 + 0xac))) {
14: lVar4 = 0x2f;
15: lVar1 = param_1[2];
16: lVar2 = *param_1;
17: pcVar5 = "Progressive JPEG image has more than 500 scans";
18: pcVar3 = (char *)(*(long *)(lVar1 + 0x20) + 0x608);
19: while (lVar4 != 0) {
20: lVar4 = lVar4 + -1;
21: *pcVar3 = *pcVar5;
22: pcVar5 = pcVar5 + 1;
23: pcVar3 = pcVar3 + 1;
24: }
25: pcVar3 = (char *)__tls_get_addr(&PTR_00398fc0);
26: lVar4 = 0x2f;
27: pcVar5 = "Progressive JPEG image has more than 500 scans";
28: while (lVar4 != 0) {
29: lVar4 = lVar4 + -1;
30: *pcVar3 = *pcVar5;
31: pcVar5 = pcVar5 + (ulong)bVar6 * -2 + 1;
32: pcVar3 = pcVar3 + (ulong)bVar6 * -2 + 1;
33: }
34: *(undefined4 *)(*(long *)(lVar1 + 0x20) + 0x6d0) = 1;
35: *(undefined4 *)(lVar2 + 0x178) = 0;
36: /* WARNING: Subroutine does not return */
37: __longjmp_chk(lVar2 + 0xa8,1);
38: }
39: return;
40: }
41: 
