#include "stdafx.h"

bool NTAPI RtlVerifyVersion(IN DWORD MajorVersion, IN DWORD MinorVersion OPTIONAL, IN DWORD BuildNumber OPTIONAL, IN BYTE Flags) {
	DWORD Versions[3];
	RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	if (Versions[0] == MajorVersion &&
		((Flags & RTL_VERIFY_FLAGS_MINOR_VERSION) ? Versions[1] == MinorVersion : true) &&
		((Flags & RTL_VERIFY_FLAGS_BUILD_NUMBERS) ? Versions[2] == BuildNumber : true))return true;
	return false;
}

bool NTAPI RtlIsWindowsVersionOrGreater(IN DWORD MajorVersion, IN DWORD MinorVersion, IN DWORD BuildNumber) {
	static DWORD Versions[3]{};
	if (!Versions[0])RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);

	if (Versions[0] == MajorVersion) {
		if (Versions[1] == MinorVersion) return Versions[2] >= BuildNumber;
		else return (Versions[1] > MinorVersion);
	}
	else return Versions[0] > MajorVersion;
}

bool NTAPI RtlIsWindowsVersionInScope(
	IN DWORD MinMajorVersion, IN DWORD MinMinorVersion, IN DWORD MinBuildNumber,
	IN DWORD MaxMajorVersion, IN DWORD MaxMinorVersion, IN DWORD MaxBuildNumber) {
	return RtlIsWindowsVersionOrGreater(MinMajorVersion, MinMinorVersion, MinBuildNumber) &&
		!RtlIsWindowsVersionOrGreater(MaxMajorVersion, MaxMinorVersion, MaxBuildNumber);
}

WINDOWS_VERSION NTAPI NtWindowsVersion() {
	static WINDOWS_VERSION version = null;
	DWORD versions[3]{};
	if (version)return version;
	RtlGetNtVersionNumbers(versions, versions + 1, versions + 2);

	switch (versions[0]) {
	case 5: {
		switch (versions[1]) {
		case 1:return version = versions[2] == 2600 ? xp : invalid;
		case 2:return version = versions[2] == 3790 ? xp : invalid;
		default:break;
		}
		break;
	}
		  break;
	case 6: {
		switch (versions[1]) {
		case 0: {
			switch (versions[2]) {
			case 6000:
			case 6001:
			case 6002:
				return version = vista;
			default:
				break;
			}
			break;
		}
			  break;
		case 1: {
			switch (versions[2]) {
			case 7600:
			case 7601:
				return version = win7;
			default:
				break;
			}
			break;
		}
			  break;
		case 2: {
			if (versions[2] == 9200)return version = win8;
			break;
		}
			  break;
		case 3: {
			if (versions[2] == 9600)return version = win8_1;
			break;
		}
			  break;
		default:
			break;
		}
		break;
	}
		  break;
	case 10: {
		if (versions[1])break;
		switch (versions[2]) {
		case 10240:
		case 10586: return version = win10;
		case 14393: return version = win10_1;
		case 15063:
		case 16299:
		case 17134:
		case 17763:
		case 18362:return version = win10_2;
		default:if (RtlIsWindowsVersionOrGreater(versions[0], versions[1], 15063))return version = win10_2;
			break;
		}
		break;
	}
		   break;
	default:
		break;
	}
	return version = invalid;
}
