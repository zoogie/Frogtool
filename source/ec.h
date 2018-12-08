// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#ifndef ec_h
#define ec_h

#include <3ds.h>

void ec_priv_to_pub(u8 *k, u8 *Q);
int check_ecdsa(u8 *Q, u8 *R, u8 *S, u8 *hash);
int generate_ecdsa(u8 *R, u8 *S, u8 *k, u8 *hash, bool randsig);

#endif
