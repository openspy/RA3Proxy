#include <windows.h>
#include <assert.h>
void install_fesl_patches();
void write_string_offset(void* address, int string_len, const char* string) {

	void* write_address = (void*)((ptrdiff_t)(ptrdiff_t)address);
	DWORD oldProtect;

	BOOL success = VirtualProtect(write_address, string_len, PAGE_READWRITE, &oldProtect);


	assert(success);
	SIZE_T numWritten = 0;
	success = WriteProcessMemory(GetCurrentProcess(), write_address, string, string_len, &numWritten);
	assert(success);

	DWORD protect;
	success = VirtualProtect(write_address, string_len, oldProtect, &protect);

	assert(success);

}

void write_wide_string_offset(void* address, int string_len, const wchar_t* string) {

	void* write_address = (void*)((ptrdiff_t)(ptrdiff_t)address);
	DWORD oldProtect;

	BOOL success = VirtualProtect(write_address, string_len, PAGE_READWRITE, &oldProtect);


	assert(success);
	SIZE_T numWritten = 0;
	success = WriteProcessMemory(GetCurrentProcess(), write_address, string, string_len, &numWritten);
	assert(success);

	DWORD protect;
	success = VirtualProtect(write_address, string_len, oldProtect, &protect);

	assert(success);

}

void perform_ra3_patches() {
	write_string_offset((void*)0x00C1D348, 0x56, "http://redalert3pc.comp.pubsvs.openspy.net/competitionservice/competitionservice.asmx");
	write_string_offset((void*)0x00C1D3A0, 0x48, "http://redalert3pc.auth.pubsvs.openspy.net/AuthService/AuthService.asmx");
	write_string_offset((void*)0x00C21150, 0x15, "peerchat.openspy.net");
	write_string_offset((void*)0x00CA15E0, 0x16, "%s.master.openspy.net");
	write_string_offset((void*)0x00CA16F4, 0x19, "%s.available.openspy.net");
	write_string_offset((void*)0x00CA1710, 0x14, "natneg3.openspy.net");
	write_string_offset((void*)0x00CA1724, 0x14, "natneg2.openspy.net");
	write_string_offset((void*)0x00CA1738, 0x14, "natneg1.openspy.net");
	write_string_offset((void*)0x00CA1888, 0x40, "http://%s.auth.pubsvs.openspy.net/AuthService/AuthService.asmx");
	write_string_offset((void*)0x00CA1E3C, 0x0C, "openspy.net");
	write_string_offset((void*)0x00CA1F18, 0x4D, "http://%s.comp.pubsvs.openspy.net/CompetitionService/CompetitionService.asmx");
	write_string_offset((void*)0x00CA210C, 0x1C, "http://ingamead.openspy.net");
	write_string_offset((void*)0x00CA2194, 0x36, "http://ingamead.openspy.net/IGNAdServer/service1.asmx");
	write_string_offset((void*)0x00CA2F70, 0x14, "%s.ms%d.openspy.net");
	write_string_offset((void*)0x00CA3EF0, 0x40, "http://%s.sake.openspy.net/SakeStorageServer/StorageServer.asmx");
	write_string_offset((void*)0x00CDA6B0, 0x11, "gpcm.openspy.net");
	write_string_offset((void*)0x00CDA6F0, 0x11, "gpsp.openspy.net");

	write_wide_string_offset((void*)0xC21950, 94, L"http://psweb.openspy.net/clans/ClanActions.asmx/ClanInfoByProfileID?authToken=%s&profileid=%d");
	write_wide_string_offset((void*)0xC21A10, 94, L"http://redalert3services.openspy.net/LaunchService.aspx?u=radEvT&p=Y6f3pH9&lt=%d&mid=%s&gp=%s");
	write_wide_string_offset((void*)0xC21B00, 66, L"http://redalert3services.openspy.net/GetPlayerRankIcon.aspx?gp=%s");
	write_wide_string_offset((void*)0xC21B88, 71, L"http://redalert3services.openspy.net/GetPlayerLadderRatings.aspx?gp=%s");
	write_wide_string_offset((void*)0xca1370, 92, L"http://cc3tibwars.sake.openspy.net/SakeFileServer/download.aspx?gameid=1422&pid=0&fileid=%d");
	write_wide_string_offset((void*)0xc1a104, 26, L"nowhere.openspy.net:28940");

	install_fesl_patches();
}