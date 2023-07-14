#include <3ds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include "utils/crypto.h"
#include "tadpole.h"
#include "superfrog_bin.h"

#define menu_size 3
#define FROGHASH "\xb8\x50\x8a\x15\x95\xdb\x0b\xab"
#define WAIT() while (1) {gspWaitForVBlank(); hidScanInput(); if (hidKeysDown() & KEY_START) { break; } }
PrintConsole topScreen, bottomScreen;
AM_TWLPartitionInfo info;
u8 region=42; //42 would be an error for region, which should be <= 6
int havecfw=0;
u8 wrongfirmware=0;

const char *bkblack="\x1b[40;1m";
const char *green="\x1b[32;1m";
const char *yellow="\x1b[33;1m";
const char *bkyellow="\x1b[43;1m";
const char *blue="\x1b[34;1m";
const char *dblue="\x1b[34;0m";
const char *white="\x1b[37;1m";
const char *dwhite="\x1b[37;0m";

int import_tad(u64 tid, u8 op, u8 *workbuf, const char *ext){
	Handle handle;
	Result res;
	FS_Path filePath;
	FS_Path archPath = { PATH_EMPTY, 1, (u8*)"" };
	char fpath[64]={0};
	uint16_t filepath16[256];
	ssize_t units=0;
	u32 len=255;
	
	memset(fpath, 0, 64);
	sprintf(fpath,"sdmc:/%08lX%s",(u32)tid, ext);
	if(access(fpath, F_OK ) == -1 ) {
		printf("%s missing on SD\n\n",fpath);
		return 1;
	
	}
	memset(filepath16, 0, sizeof(filepath16));
	units = utf8_to_utf16(filepath16, (u8*)(fpath+5), len);
	
	filePath.type = PATH_UTF16;
	filePath.size = (units+1)*sizeof(uint16_t);
	filePath.data = (const u8*)filepath16;
	
	printf("import:%d %s\n", op, fpath);
	res = FSUSER_OpenFileDirectly(&handle, ARCHIVE_SDMC, archPath, filePath, FS_OPEN_READ, 0);
	printf("fsopen: %08X\n",(int)res);
	printf("importing dsiware...\n");
	res = AM_ImportTwlBackup(handle, op, workbuf, 0x20000);
	printf("twl import: %08X %s\n\n",(int)res, res ? "FAILED!" : "SUCCESS!");
	FSFILE_Close(handle);
	
	return res;
}

Result export_tad(u64 tid, u8 op, u8 *workbuf, const char *ext){  //export is a reserved word in c++ TIL
	Result res;
	char fpath[256]={0};
	memset(fpath, 0, 128);
	sprintf(fpath,"sdmc:/%08lX%s",(u32)tid, ext);
	if(access(fpath, F_OK ) != -1 ) {
		printf("DS dlp already exists on SD\n\n");
		return 1;
	}
	printf("exporting:%d %016llX to\n%s...\n", op, tid, fpath);
	res = AM_ExportTwlBackup(tid, op, workbuf, 0x20000, fpath);
	printf("twl export: %08X %s\n\n",(int)res, res ? "FAILED!" : "SUCCESS!");
	
	return res;
}

Result menuUpdate(int cursor, int showinfo){
	consoleClear();
	printf("%sFrogtool v2.3 - zoogie & jason0597%s\n\n", green, white);
	char menu[menu_size][128] = {
		"INJECT  patched          DS Download Play",
		"BOOT    patched          DS Download Play",
		"RESTORE clean            DS Download Play",
	};
	
	for(int i=0;i<menu_size;i++){
		printf("%s %s%s\n", cursor == i ? bkyellow : bkblack, menu[i], bkblack);
	}
	
	printf("\n%sUP & DOWN to choose, A to select, START to exit%s\n\n", green, white);
	
	if(!showinfo){
		consoleSelect(&bottomScreen);
		consoleClear();
		printf("%sTWL PARTITION INFO   Bytes        Blocks%s", green, white);
		printf("Capacity:            0x%08lX   %04d\n",(u32)info.capacity,(int)info.capacity/0x20000);
		printf("FreeSpace:           0x%08lX   %04d\n",(u32)info.freeSpace,(int)info.freeSpace/0x20000);
		printf("TitlesCapacity:      0x%08lX   %04d\n",(u32)info.titlesCapacity,(int)info.titlesCapacity/0x20000);
		printf("TitlesFreeSpace:     0x%08lX   %04d\n\n\n\n",(u32)info.titlesFreeSpace,(int)info.titlesFreeSpace/0x20000);
		printf("%s\n\n\n\n\n", green);
		printf("                 **  **\n");
		printf("                * **** *\n");
		printf("                * **** *\n");
		printf("                ********\n");
		printf("               **********\n");
		printf("               **      **\n");
		printf("              ***      ***\n");
		printf("              ****    ****\n");
		printf("               ****  ****\n");
		printf("              ************\n");
		//printf("                  Gero!\n");
		printf("%s\n", white);
		consoleSelect(&topScreen);
	}
	
	return 0;
}

Result waitKey(){
	printf("\nTouch the %sFrogs%s to continue ...\n", green, white);
	
	while(1){
		gspWaitForVBlank();
		gfxSwapBuffers();
		
		hidScanInput();
		u32 kDown = hidKeysDown();
		if(kDown & KEY_TOUCH) break;
	}
	
	return 0;
}

u8 *readAllBytes(const char *filename, u32 *filelen) {
	FILE *fileptr = fopen(filename, "rb");
	if (fileptr == NULL) {
		printf("ERROR: Failed to open sdmc:%s !!!\n\n", filename);
		printf("Press START to exit\n");
		WAIT();
		nsExit();  //see if we can exit in a civilized manner here
		amExit();
		romfsExit();
		gfxExit();
		exit(0);
	}
	fseek(fileptr, 0, SEEK_END);
	*filelen = ftell(fileptr);
	rewind(fileptr);
	
	if(*filelen>0x300000) *filelen=0x300000;

	u8 *buffer = (u8*)malloc(*filelen);

	fread(buffer, *filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;
}

void writeAllBytes(const char* filename, u8 *filedata, u32 filelen) {
	FILE *fileptr = fopen(filename, "wb");
	fwrite(filedata, 1, filelen, fileptr);
	fclose(fileptr);
}

Result doStuff(u64 tid) {
	Result res=0;
	u32 dsiware_size, ctcert_size, movable_size, injection_size;
	u8 *dsiware, *ctcert, *injection, *movable;
	u8 header_hash[0x20], srl_hash[0x20];
	u32 flipnote_size=0x00218800;
	footer_t *footer=(footer_t*)malloc(SIZE_FOOTER);
	u8 normalKey[0x10], normalKey_CMAC[0x10];
	u8 *header = new u8[0xF0];
	char tidname[128]={0};
	
	ctcert_size = 0x19E;
	ctcert = (u8*)malloc(ctcert_size);
	
	snprintf(tidname, 55, "/%08lX.bin", (u32)(tid & 0xffffffff));
	printf("Reading sdmc:%08lX.bin\n", (u32)(tid & 0xffffffff));
	dsiware = readAllBytes(tidname, &dsiware_size);
	printf("Reading & parsing sdmc:/movable.sed\n");
	movable = readAllBytes("/movable.sed", &movable_size);
	printf("Reading sdmc:/frogcert.bin\n");
	injection = readAllBytes("/frogcert.bin", &injection_size);
	FSUSER_UpdateSha256Context(injection, injection_size, srl_hash);
	injection_size -= ctcert_size;
	memcpy(ctcert, injection + injection_size, ctcert_size);
	
	printf("Checking frogcert.bin\n");
	if(memcmp(srl_hash, FROGHASH, 8)) {
		printf("Oh noes, sdmc:/frogcert.bin is corrupted!\n");
		res = 4;
		goto fail;
	}
	
	printf("Scrambling keys\n");
	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
	
	// === HEADER ===
	printf("Decrypting header\n");
	getSection((dsiware + 0x4020), 0xF0, normalKey, header);

	if (memcmp(header, "3FDT", 4)) {
		printf("DECRYPTION FAILED!!!\nThis likely means the input movable.sed is wrong\nPress START to continue\n");
		WAIT();
		res=3;
		goto fail;
	}

	printf("Injecting new srl.nds size\n");
	*(u32*)(header+0x48+4)=flipnote_size;
	*(u32*)(header+0x40)=(flipnote_size&0xFFFF8000) | 0x20000; //after install size (estimate)

	printf("Placing back header\n");
	placeSection((dsiware + 0x4020), header, 0xF0, normalKey, normalKey_CMAC);

	printf("Calculating new header hash\n");
	FSUSER_UpdateSha256Context(header, 0xF0, header_hash);
	delete[] header;

	// === SRL.NDS ===
	// Basically, the srl.nds of DS Download play is right at the end of the TAD container
	// Because we don't care about what it contains, we can overwrite it directly with our new
	// flipnote srl.nds straight off the bat, without having to do any decryption
	// We of course need to extend our vector of dsiwareBin by the necessary difference in bytes
	// to accomodate the new flipnote srl.nds (which is 0x218800 in size!!)
	printf("Resizing array\n");
	printf("Old DSiWare size: %lX\n", dsiware_size);
	dsiware_size += (injection_size - 0x69BC0); // new TAD size = old TAD size + (new srl size - old srl size)
	printf("New DSiWare size: %lX\n", dsiware_size);
	dsiware = (u8*)realloc(dsiware, dsiware_size);
	printf("Placing back srl.nds\n");
	placeSection((dsiware + 0x5190), injection, injection_size, normalKey, normalKey_CMAC);

	printf("Calculating new srl.nds hash\n");
	FSUSER_UpdateSha256Context(injection, injection_size, srl_hash);

	// === FOOTER ===
	printf("Decrypting footer\n");
	getSection((dsiware + 0x4130), 0x4E0, normalKey, (u8*)footer);

	printf("Fixing hashes\n");
	memcpy(footer->hdr_hash , header_hash, 0x20); //Fix the header hash
	memcpy(footer->content_hash[0], srl_hash, 0x20);	//Fix the srl.nds hash
	//calculateSha256((u8*)footer, (13 * 0x20), ((u8*)footer + (13 * 0x20))); //Fix the master hash

	printf("Signing footer...\n");
	if((res = doSigning(ctcert, footer))) goto fail;
	
	printf("Placing back footer\n");
	placeSection((dsiware + 0x4130), (u8*)footer, 0x4E0, normalKey, normalKey_CMAC);
	delete[] footer;
	
	snprintf(tidname, 55, "/%08lX.bin.patched", (u32)(tid & 0xffffffff));
	printf("Writing sdmc:%s...\n", tidname);
	writeAllBytes(tidname, dsiware, dsiware_size);
	printf("Done!\n\n");

	fail:
	free(dsiware);
	free(ctcert);
	free(injection);
	free(movable);
	return res;
}

Result copyStuff(){
	printf("Copying files to sdmc ...\n");
	//copyFile("romfs:/boot.nds","/boot.nds");  ;-;
	//copyFile("romfs:/boot.firm","/boot.firm");
	mkdir("/private/",0777); mkdir("/private/ds/",0777); mkdir("/private/ds/app/",0777); mkdir("/private/ds/app/4B47554A/",0777); mkdir("/private/ds/app/4B47554A/001/",0777); //inelegant but simple
	copyFile("romfs:/T00031_1038C2A757B77_000.ppm","/private/ds/app/4B47554A/001/T00031_1038C2A757B77_000.ppm");
	printf("Done!\n");
	return 0;
}

static __attribute__((naked)) Result svcGetCFWinfo(u8 *info) {
    asm volatile(
            "svc 0x2E\n"
            "bx lr"
    );
}

Result checkFile(const char *path, const char *inhash){
	u8 *filebuff=(u8*)malloc(0x10000);
	u8 shabuff[0x20]={0};
	u32 bytesread=0;
	
	FILE *f=fopen(path, "rb");
	if(!f) return 2;
	bytesread=fread(filebuff, 1, 0x10000, f);
	fclose(f);
	FSUSER_UpdateSha256Context(filebuff, bytesread, shabuff);
	free(filebuff);
	
	if(memcmp(shabuff, inhash, 4)) return 1; //"\xa9\x76\x31\xe2"
	return 0;
}

extern "C" int nimhax(void);

int main(int argc, char* argv[])
{
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);
	gfxSetDoubleBuffering(GFX_BOTTOM, false);
	u8* fb = gfxGetFramebuffer(GFX_BOTTOM, GFX_LEFT, NULL, NULL);
	
	u32 BUF_SIZE = 0x20000;
	u64 tid=0;
	u8 op=5;
	u8 cfwinfo[16]={0};
	u64 SECOND=1000*1000*1000;
	int cursor=0;
	int showinfo=1;
	const char *ppm="/private/ds/app/4B47554A/001/T00031_1038C2A757B77_000.ppm";
	Result res;
	
	u32 kver = osGetKernelVersion();   //the current recommended frogminer guide requires firm 11.16 so we will kinda suggest that here. if a surprise firm drops and native firm changes, this will safeguard users immediately
	if(kver != 0x023A0000){
		wrongfirmware=1;
	}	
											//almost all versions of luma a9lh that can run on 11.9+ have a custom svc called svcGetCFWinfo that places the text "LUMA" at the beginning of a 16 byte buffer arg1
	svcGetCFWinfo(cfwinfo);					//this is by no means a catch-all way to detect a9lh cfw, but it should help a bit.
	res = memcmp(cfwinfo, "LUMA", 4);		//the reason we care about cfw is that if a9lh is present, b9sTool will 100% chance brick the user's 3ds
	if(!res){
		havecfw|=1;
	}
	
	FS_Archive archive;
	res = FSUSER_OpenArchive(&archive, ARCHIVE_NAND_W_FS, fsMakePath(PATH_EMPTY, "")); //another cfw check that's not likely as useful as the above
	if(res==0){                                                                     
		FSUSER_CloseArchive(archive); 
		havecfw|=2;
	}
	
	u8 *buf = (u8*)malloc(BUF_SIZE);
	res = nsInit();
	printf("nsInit: %08X\n",(int)res);
	res = cfguInit();
	printf("cfguInit: %08X\n",(int)res);
	res = romfsInit();
	printf("romfsInit: %08X\n",(int)res);
	//res = AM_GetTWLPartitionInfo(&info);
	//printf("twlInfo: %08X\n",(int)res);
	res = CFGU_SecureInfoGetRegion(&region);
	printf("region: %d\n", (int)region);

	if(access("/movable.sed", F_OK)) {
		printf("movable.sed not found, trying nimhax\n");
		nimhax(); // if this fails, it will exit here
	}

	res = amInit();
	printf("amInit: %08X\n",(int)res);

	res = seed_check();
	if(res){
		if(res==3)printf("ERROR: sdmc:/movable.sed keyy isn't correct!\n");
		else printf("ERROR: sdmc:/movable.sed couldn't be read!\nDid you forget it?\n");
		WAIT();
		goto fail;
	}
	else{
		printf("movable.sed: good!\n");
	}
	
	printf("checking ppm ...\n");
	if(!checkFile(ppm, "\xa9\x76\x31\xe2")){ 
		printf("ppm: ready!\n");
	}
	else{
		printf("ppm not found, copying to sdmc ...\n");
		copyStuff();
		printf("checking ppm again ...\n");
		if(checkFile(ppm, "\xa9\x76\x31\xe2")){
			printf("ERROR: Your flipnote .ppm file cannot be written!\n");
			printf("Please copy it to sdmc manually!\n");
			printf("(sdmc:%s)\n", ppm);
			WAIT();
			goto fail;
		}
		printf("ppm good to go!\n");
	}
	
	printf("\nloading menu...\n");
	svcSleepThread(3*SECOND);
	
	tid = 0x00048005484E4441;   //dlp
	if	(region == 4) tid = 0x00048005484E4443; //chn
	else if	(region == 5) tid = 0x00048005484E444B; //kor
	memcpy(fb, superfrog_bin, superfrog_bin_size);
	menuUpdate(cursor, showinfo);
	if(wrongfirmware) printf("\n\nWARNING!!\nYou are not on the expected firmware!\n(firm 11.16.0-X)\n");
	
	while (aptMainLoop())
	{
		gspWaitForVBlank();
		gfxSwapBuffers();
		hidScanInput();

		u32 kDown = hidKeysDown();
		if (kDown & KEY_START)
			break; // break in order to return to hbmenu
		if(kDown & KEY_A){
			switch(cursor){
				case 0: if(havecfw) {printf("You already have CFW! %d\n\n", havecfw); break;}
						//if(wrongfirmware) {printf("You are not on the correct firmware!\n\n"); break;}
						export_tad(tid, op, buf, ".bin"); if(doStuff(tid)) break;
				        import_tad(tid, op, buf, ".bin.patched"); break;
				case 1: //if(havecfw) {printf("You already have CFW!\n\n"); break;}
						//if(wrongfirmware) {printf("You are not on firm 11.16.0-XX!\n\n"); break;}
						printf("Booting dlp now ...\n");
						NS_RebootToTitle(0, tid); 
						while(1)gspWaitForVBlank();
				case 2: import_tad(tid, op, buf, ".bin"); break;
				default:;
			}
			waitKey();
			//showinfo = AM_GetTWLPartitionInfo(&info);
			menuUpdate(cursor, showinfo);
		}
		else if(kDown & KEY_UP){
			cursor--;
			if(cursor<0) cursor=0;
			menuUpdate(cursor, showinfo);
		}
		else if(kDown & KEY_DOWN){
			cursor++;
			if(cursor>=menu_size) cursor=menu_size-1;
			menuUpdate(cursor, showinfo);
		}
		
	}
	
	fail:

    free(buf);
	nsExit();
	amExit();
	romfsExit();
	gfxExit();
	
	return 0;
}