1: 
2: void FUN_00153f40(long param_1,long param_2)
3: 
4: {
5: void *pvVar1;
6: void **ppvVar2;
7: 
8: if (*(int *)(param_2 + 0x58) == 0) {
9: pvVar1 = *(void **)(param_2 + 0x60);
10: }
11: else {
12: ppvVar2 = (void **)(**(code **)(*(long *)(param_1 + 8) + 0x38))
13: (param_1,*(undefined8 *)(param_2 + 0x40),
14: *(undefined4 *)(param_2 + 0x54),1,1);
15: *(int *)(param_2 + 0x54) = *(int *)(param_2 + 0x54) + 1;
16: pvVar1 = *ppvVar2;
17: }
18: pvVar1 = memcpy(pvVar1,**(void ***)(param_2 + 0x28),(ulong)*(uint *)(param_1 + 0x88));
19: if (0 < (int)*(uint *)(param_2 + 0x50)) {
20: memset((void *)((ulong)*(uint *)(param_1 + 0x88) + (long)pvVar1),0,
21: (ulong)*(uint *)(param_2 + 0x50));
22: }
23: if (*(int *)(param_2 + 0x58) != 0) {
24: return;
25: }
26: fwrite(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),*(FILE **)(param_2 + 0x20));
27: return;
28: }
29: 