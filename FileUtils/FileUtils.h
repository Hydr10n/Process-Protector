/*
 * Heade File: FileUtils.h
 * Last Update: 2020/10/15
 *
 * Copyright (C) Hydr10n@GitHub. All Rights Reserved.
 */

#pragma once

#include <Windows.h>
#include <Shlwapi.h>
#include <string>

#pragma comment(lib, "Shlwapi")

namespace Hydr10n {
	namespace FileUtils {
		LPCWSTR WINAPI SkipUnicodeLongPathPrefix(LPCWSTR lpcwPath) {
			constexpr WCHAR lpcwPrefix[] = L"\\\\?\\";
			const LPCWSTR ret = StrStrW(lpcwPath, lpcwPrefix);
			return ret == NULL || ret != lpcwPath ? lpcwPath : ret + ARRAYSIZE(lpcwPrefix) - 1;
		}

		template <class Lambda>
		DWORD WINAPI GetFileName(std::wstring& fileName, const Lambda& lambda) {
			DWORD ret;
			try {
				fileName.resize(UNICODE_STRING_MAX_CHARS);
				fileName.resize(ret = lambda());
				fileName.shrink_to_fit();
			}
			catch (...) { ret = 0; }
			return ret;
		}

		DWORD WINAPI GetModuleFileNameW(std::wstring& fileName, HMODULE hModule = NULL) { return GetFileName(fileName, [&]() { return GetModuleFileNameW(hModule, &fileName[0], (DWORD)fileName.size()); }); }

		DWORD WINAPI GetFinalPathNameByHandleW(std::wstring& fileName, HANDLE hFile, DWORD dwFlags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) { return GetFileName(fileName, [&]() { return ::GetFinalPathNameByHandleW(hFile, &fileName[0], (DWORD)fileName.size(), dwFlags); }); }
	}
}