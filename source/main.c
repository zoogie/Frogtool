#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <3ds.h>

#define menu_size 4
PrintConsole topScreen, bottomScreen;
AM_TWLPartitionInfo info;

const char *bkblack="\x1b[40;1m";
const char *green="\x1b[32;1m";
const char *yellow="\x1b[33;1m";
const char *bkyellow="\x1b[43;1m";
const char *blue="\x1b[34;1m";
const char *dblue="\x1b[34;0m";
const char *white="\x1b[37;1m";
const char *dwhite="\x1b[37;0m";

Result import(u64 tid, u8 op, u8 *workbuf, char *ext){
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

Result export(u64 tid, u8 op, u8 *workbuf, char *ext){
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
	printf("%sFrogtool v1.1 - zoogie%s\n\n", green, white);
	char menu[menu_size][128] = {
		"EXPORT  clean   DS Download Play",
		"IMPORT  patched DS Download Play",
		"BOOT    patched DS Download Play",
		"RESTORE clean   DS Download Play",
	};
	
	for(int i=0;i<menu_size;i++){
		printf("%s %s%s\n", cursor == i ? bkyellow : bkblack, menu[i], bkblack);
	}
	
	printf("\n%sPress START to exit%s\n\n", green, white);
	
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
	printf("\nTap the %sFrog%s to continue ...\n", green, white);
	
	while(1){
		gspWaitForVBlank();
		gfxSwapBuffers();
		
		hidScanInput();
		u32 kDown = hidKeysDown();
		if(kDown & KEY_TOUCH) break;
	}
	
	return 0;
}

int main(int argc, char* argv[])
{
	gfxInitDefault();
	consoleInit(GFX_TOP, &topScreen);
	consoleInit(GFX_BOTTOM, &bottomScreen);
	consoleSelect(&topScreen);
	u32 BUF_SIZE = 0x20000;
	u64 tid=0;
	u8 op=5;
	u32 SECOND=1000*1000*1000;
	int cursor=0;
	int showinfo=1;
	
	u8 *buf = (u8*)malloc(BUF_SIZE);
	Result res = nsInit();
	printf("nsInit: %08X\n",(int)res);
	res = amInit();
	printf("amInit: %08X\n",(int)res);
	res = AM_GetTWLPartitionInfo(&info);
	printf("twlInfo: %08X\n\n",(int)res);
	showinfo=res;
	svcSleepThread(1*SECOND);
	tid = 0x00048005484E4441;   //dlp
	//tid = 0x0004800542383841;
	//tid = 0x000480044b385545; 
	//tid = 0x000480044b454e4a; 
	
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
				case 0: export(tid, op, buf, ".bin"); break;
				case 1: import(tid, op, buf, ".bin.patched"); break;
				case 2: printf("Booting dlp now ...\n");
						NS_RebootToTitle(0, tid); 
						while(1)gspWaitForVBlank();
				case 3: import(tid, op, buf, ".bin"); break;
				default:;
			}
			waitKey();
			showinfo = AM_GetTWLPartitionInfo(&info);
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
	gfxExit();
	
	return 0;
}