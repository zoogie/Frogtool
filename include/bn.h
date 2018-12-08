// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#ifndef bn_h
#define bn_h


int bn_compare(u8 *a, u8 *b, u32 n);
void bn_sub_modulus(u8 *a, u8 *N, u32 n);
void bn_add(u8 *d, u8 *a, u8 *b, u8 *N, u32 n);
void bn_mul(u8 *d, u8 *a, u8 *b, u8 *N, u32 n);
void bn_exp(u8 *d, u8 *a, u8 *N, u32 n, u8 *e, u32 en);
void bn_inv(u8 *d, u8 *a, u8 *N, u32 n);
void bn_shiftr(u8 *in, u32 size, u32 shiftn);
#endif
