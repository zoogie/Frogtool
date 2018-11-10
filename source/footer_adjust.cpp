// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#include <3ds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec.h"
#include "footer_adjust.h"

Result load2buffer(u8 *buf, u32 size, const char *filename){
	u32 bytesread=0;
	FILE *f=fopen(filename,"rb");
	bytesread=fread(buf, 1, size, f);
	fclose(f);
	if(bytesread != size){
		printf("File read error: %s\n", filename);
		return 1;
	}
	return 0;
}

Result dumpfile(u8 *buf, u32 size, const char *filename){
	u32 byteswritten=0;
	FILE *f=fopen(filename,"wb");
	byteswritten=fwrite(buf, 1, size, f);
	fclose(f);
	if(byteswritten != size){
		printf("File write error: %s\n", filename);
		return 1;
	}
	return 0;
}

Result copyFile(const char *src, const char *dst){
	u32 limit=0x80000;
	u8 *copybuf=(u8*)malloc(limit);
	int bytesread=0;
	int byteswritten=-1;
	
	FILE *f=fopen(src,"rb");
	bytesread=fread(copybuf, 1, limit, f);
	fclose(f);
	if(bytesread){
		FILE *g=fopen(dst,"wb");
		byteswritten=fwrite(copybuf, 1, bytesread, g);
		fclose(g);
	}
	free(copybuf);
	printf("%s - %s\n", dst, bytesread==byteswritten ? "OK":"FAIL");
	return 0;
}

int doSigning(u8 *ctcert_bin, footer_t *footer)
{
	
	Result res=0;
	uint8_t ct_priv[0x1e];
	uint8_t tmp_pub[0x3c];
	uint8_t temp_hash[0x20];
	int rv;
	ecc_cert_t *ct_cert = &footer->ct;
	ct_cert=(ecc_cert_t*)malloc(SIZE_CTCERTBIN);

	uint8_t ap_priv[0x1e];
	memset(ap_priv, 0, 0x1e);
	ap_priv[0x1d]=1;

	ecc_cert_t *ap_cert = &footer->ap;
	ap_cert=(ecc_cert_t*)malloc(SIZE_CTCERTBIN);

	printf("\x1b[34;1mloading keys from ctcert.bin...\n");
	//load2buffer(ctcert_bin, SIZE_CTCERTBIN, "/ctcert.bin");
	memcpy(ct_cert, ctcert_bin, 0x180);
	memcpy(ct_priv, ctcert_bin+0x180, 0x1e);
	
	ec_priv_to_pub(ct_priv, tmp_pub);
	if(memcmp(tmp_pub, &ct_cert->pubkey, sizeof(tmp_pub)) != 0)
	{
		printf("error: ecc priv key does not correspond to the cert\n");
	}

	printf("using zeroed AP privkey to generate AP cert...\n");
	memset(ap_cert, 0, sizeof(*ap_cert));
	memcpy(&ap_cert->key_id, &footer->ap.key_id, 0x40);

	snprintf(ap_cert->issuer, sizeof(ap_cert->issuer), "%s-%s", ct_cert->issuer, ct_cert->key_id); // cert chain

	ap_cert->key_type = 0x02000000; // key type
	ec_priv_to_pub(ap_priv, ap_cert->pubkey.r);// pub key
	ap_cert->sig.type = 0x05000100;// sig
	
	FSUSER_UpdateSha256Context((uint8_t*)ap_cert->issuer, 0x100, temp_hash);
	
	printf("signing ap...\n"); // actually sign it
	rv = generate_ecdsa(ap_cert->sig.val.r, ap_cert->sig.val.s, ct_priv, temp_hash);
	if(rv < 0)
	{
		printf("error: problem signing AP\n");
	}

	// now sign the actual footer
	printf("signing footer...\n");
	FSUSER_UpdateSha256Context(footer, 0x1A0, temp_hash);
	rv = generate_ecdsa(footer->sig.r, footer->sig.s, ap_priv, temp_hash);
	if(rv < 0)
	{
		printf("error: problem signing footer\n");
	}

	printf("re-verifying footer sig...  "); printf("\rre-verifying footer sig...  "); //this printf is glitchy looking without this hacky workaround
	FSUSER_UpdateSha256Context(footer, 0x1A0, temp_hash);
	rv = check_ecdsa(ap_cert->pubkey.r, footer->sig.r, footer->sig.s, temp_hash);
	if(rv == 1)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD\n");
		res |= 1;
	}
	printf("re-verifying ap sig...      "); printf("\rre-verifying ap sig...      ");
	FSUSER_UpdateSha256Context((uint8_t*)ap_cert->issuer, sizeof(ecc_cert_t)-sizeof(ap_cert->sig), temp_hash);
	rv = check_ecdsa(ct_cert->pubkey.r, ap_cert->sig.val.r, ap_cert->sig.val.s, temp_hash);
	if(rv == 1)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD\n");
		res |= 2;
	}
	
	if(res){
		printf("OVERALL: %d FAIL!!!\n",(int)res);
	}
	else{
		printf("OVERALL: SUCCESS!!\n");
	}
	
	memcpy(&footer->ap, ap_cert, 0x180);
	memcpy(&footer->ct, ct_cert, 0x180);
	
	printf("signing complete!\n\x1b[37;1m");

	return 0;
}