1: 
2: long tjGetErrorStr2(long param_1)
3: 
4: {
5: long lVar1;
6: 
7: if ((param_1 != 0) && (*(int *)(param_1 + 0x6d0) != 0)) {
8: *(undefined4 *)(param_1 + 0x6d0) = 0;
9: return param_1 + 0x608;
10: }
11: lVar1 = __tls_get_addr(&PTR_00398fc0);
12: return lVar1;
13: }
14: 
