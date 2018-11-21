#include <3ds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include "crypto.h"
#include "tadpole.h"
#include "superfrog_bin.h"

#define ROMFS "romfs:" //define as "" to load srl.nds and ctcert.bin from sd instead
#define menu_size 3
#define WAITA() while (1) {gspWaitForVBlank(); hidScanInput(); if (hidKeysDown() & KEY_A) { break; } }
PrintConsole topScreen, bottomScreen;
AM_TWLPartitionInfo info;
u8 region=42; //42 would be an error for region, which should be <= 6
u8 havecfw=0;
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
	printf("%sFrogtool v2.0 - zoogie & jason0597%s\n\n", green, white);
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
		printf("!!! Failed to open %s !!!\n", filename);
		WAITA();
		exit(-1);
	}
	fseek(fileptr, 0, SEEK_END);
	*filelen = ftell(fileptr);
	rewind(fileptr);

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

void doStuff() {
	u8 *dsiware, *ctcert, *injection, *movable;
	u32 dsiware_size, ctcert_size, movable_size, injection_size;
	u8 header_hash[0x20], srl_hash[0x20];

	printf("Reading 484E4441.bin\n");
	dsiware = readAllBytes("/484E4441.bin", &dsiware_size);
	printf("Reading ctcert.bin\n");
	ctcert = readAllBytes(ROMFS "/ctcert.bin", &ctcert_size);
	printf("Reading flipnote srl.nds\n");
	injection = readAllBytes(ROMFS "/srl.nds", &injection_size);
	printf("Reading & parsing movable.sed\n");
	movable = readAllBytes("/movable.sed", &movable_size);

	printf("Scrambling keys\n");
	u8 normalKey[0x10], normalKey_CMAC[0x10];
	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
	
	// === HEADER ===
	printf("Decrypting header\n");
	u8 *header = new u8[0xF0];
	getSection((dsiware + 0x4020), 0xF0, normalKey, header);
	
	if (header[0] != 0x33 || header[1] != 0x46 || header[2] != 0x44 || header[3] != 0x54) {
		printf("DECRYPTION FAILED!!!\n");
	}

	printf("Injecting new srl.nds size\n");
	u8 flipnote_size_LE[4] = {0x00, 0x88, 0x21, 0x00}; // the size of flipnote in little endian
	memcpy((header + 0x48 + 4), flipnote_size_LE, 4);

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
	footer_t *footer=(footer_t*)malloc(SIZE_FOOTER);
	getSection((dsiware + 0x4130), 0x4E0, normalKey, (u8*)footer);

	printf("Fixing hashes\n");
	memcpy(footer->hdr_hash , header_hash, 0x20); //Fix the header hash
	memcpy(footer->content_hash[0], srl_hash, 0x20);	//Fix the srl.nds hash
	//calculateSha256((u8*)footer, (13 * 0x20), ((u8*)footer + (13 * 0x20))); //Fix the master hash

	printf("Signing footer\n");
	doSigning(ctcert, footer);
	
	printf("Placing back footer\n");
	placeSection((dsiware + 0x4130), (u8*)footer, 0x4E0, normalKey, normalKey_CMAC);
	delete[] footer;
	
	printf("Writing sdmc:/484E4441.bin.patched...\n");
	writeAllBytes("/484E4441.bin.patched", dsiware, dsiware_size);
	printf("Done!\n\n");

	free(dsiware);
	free(ctcert);
	free(injection);
	free(movable);
}

Result copyStuff(){
	printf("Copying files to sdmc ...\n");
	//copyFile("romfs:/boot.nds","/boot.nds");  ;-;
	//copyFile("romfs:/boot.firm","/boot.firm");
	mkdir("/private/",0777); mkdir("/private/ds/",0777); mkdir("/private/ds/app/",0777); mkdir("/private/ds/app/4B47554A/",0777); mkdir("/private/ds/app/4B47554A/001/",0777); //inelegant but simple
	copyFile("romfs:/T00031_1038C2A757B77_000.ppm","/private/ds/app/4B47554A/001/T00031_1038C2A757B77_000.ppm");
	printf("Done!\n\n");
	return 0;
}

int main(int argc, char* argv[])
{
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);
	gfxSetDoubleBuffering(GFX_BOTTOM, false);
	u8* fb = gfxGetFramebuffer(GFX_BOTTOM, GFX_LEFT, NULL, NULL);
	
	u32 BUF_SIZE = 0x20000;
	u64 tid=0;
	u8 op=5;
	u32 SECOND=1000*1000*1000;
	int cursor=0;
	int showinfo=1;
	Result res;
	
	u32 kver = osGetKernelVersion();   //the current recommended frogminer guide requires firm 11.8 so we will enforce that here. if a surprise firm drops and native firm changes, this will safeguard users immediately
	if(kver != 0x02370000){
		wrongfirmware=1;
	}
	
	FS_Archive archive;
	res = FSUSER_OpenArchive(&archive, ARCHIVE_NAND_RW, fsMakePath(PATH_EMPTY, "")); //almost all versions of luma or aureinand patch access to this archive which shouln't be available to userland
	if(res==0){                                                                      //still, this is not a foolproof way to detect a9lh or other type of cfw is installed, but it helps
		FSUSER_CloseArchive(archive);                                                //the reason we care about cfw is that if a9lh is present, b9sTool will 100% chance brick the user's 3ds
		havecfw=1;
	}
	
	u8 *buf = (u8*)malloc(BUF_SIZE);
	res = amInit();
	printf("amInit: %08X\n",(int)res);
	res = nsInit();
	printf("nsInit: %08X\n",(int)res);
	res = cfguInit();
	printf("cfguInit: %08X\n",(int)res);
	res = romfsInit();
	printf("romfsInit: %08X\n",(int)res);
	res = AM_GetTWLPartitionInfo(&info);
	printf("twlInfo: %08X\n",(int)res);
	res = CFGU_SecureInfoGetRegion(&region);
	printf("region: %d\n\n", (int)region);
	svcSleepThread(2*SECOND);
	
	tid = 0x00048005484E4441;   //dlp
	memcpy(fb, superfrog_bin, superfrog_bin_size);
	menuUpdate(cursor, showinfo);
	
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
				case 0: if(havecfw) {printf("You already have CFW!\n\n"); break;}
						if(wrongfirmware) {printf("You are not on firm 11.8.0-XX!\n\n"); break;}
						export_tad(tid, op, buf, ".bin"); doStuff();
				        import_tad(tid, op, buf, ".bin.patched");  copyStuff(); break;
				case 1: //if(havecfw) {printf("You already have CFW!\n\n"); break;}
						//if(wrongfirmware) {printf("You are not on firm 11.8.0-XX!\n\n"); break;}
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

    free(buf);
	nsExit();
	amExit();
	romfsExit();
	gfxExit();
	
	return 0;
}