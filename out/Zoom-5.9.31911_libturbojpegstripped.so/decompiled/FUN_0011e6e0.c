1: 
2: undefined8 FUN_0011e6e0(code **param_1)
3: 
4: {
5: long *plVar1;
6: long lVar2;
7: code *pcVar3;
8: size_t __size;
9: void *__dest;
10: size_t __n;
11: 
12: plVar1 = (long *)param_1[5];
13: __n = plVar1[9];
14: __size = __n * 2;
15: __dest = malloc(__size);
16: if (__dest == (void *)0x0) {
17: pcVar3 = *param_1;
18: *(undefined4 *)(pcVar3 + 0x28) = 0x36;
19: *(undefined4 *)(pcVar3 + 0x2c) = 10;
20: (**(code **)*param_1)(param_1);
21: __n = plVar1[9];
22: }
23: memcpy(__dest,(void *)plVar1[8],__n);
24: if ((void *)plVar1[7] != (void *)0x0) {
25: free((void *)plVar1[7]);
26: }
27: lVar2 = plVar1[9];
28: plVar1[7] = (long)__dest;
29: plVar1[8] = (long)__dest;
30: plVar1[9] = __size;
31: plVar1[1] = lVar2;
32: *plVar1 = (long)__dest + lVar2;
33: return 1;
34: }
35: 
