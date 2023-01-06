1: 
2: void tjDecompress(void)
3: 
4: {
5: uint in_stack_00000018;
6: 
7: if ((in_stack_00000018 & 0x200) != 0) {
8: /* WARNING: Treating indirect jump as call */
9: tjDecompressToYUV();
10: return;
11: }
12: /* WARNING: Treating indirect jump as call */
13: tjDecompress2();
14: return;
15: }
16: 
