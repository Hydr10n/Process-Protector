/*
 * Heade File: ProcessProtector.h
 * Last Update: 2020/10/16
 *
 * Copyright (C) Hydr10n@GitHub. All Rights Reserved.
 */

#pragma once

#pragma warning(disable:4005)
#pragma warning(disable:4302)
#pragma warning(disable:4311)

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include "../DetoursHelpers/DetoursHelpers.h"
#include "../std_container_helpers/set_helper.h"

#pragma comment(lib, "ntdll")

namespace Hydr10n {
	namespace ProcessUtils {
		class ProcessProtector final {
		public:
			static bool Hide(DWORD dwProcessId) { return std_container_helpers::set_helper::modify(m_HiddenProcessIds, dwProcessId, false); }

			static bool Unhide(DWORD dwProcessId) { return std_container_helpers::set_helper::modify(m_HiddenProcessIds, dwProcessId, true); }

			static bool Protect(DWORD dwProcessId) { return std_container_helpers::set_helper::modify(m_ProtectedProcessIds, dwProcessId, false); }

			static bool Unprotect(DWORD dwProcessId) { return std_container_helpers::set_helper::modify(m_ProtectedProcessIds, dwProcessId, true); }

		private:
			using PCLIENT_ID = struct { HANDLE UniqueProcess, UniqueThread; }*;

			static std::set<DWORD> m_HiddenProcessIds, m_ProtectedProcessIds;
			static decltype(NtQuerySystemInformation)* m_NtQuerySystemInformation;
			static NTSTATUS(NTAPI* m_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

			static const struct static_constructor {
				static_constructor() {
					using DetoursHelpers::ChangeProcAddr;
					m_NtQuerySystemInformation = NtQuerySystemInformation;
					m_NtOpenProcess = (decltype(m_NtOpenProcess))DetourFindFunction("ntdll", "NtOpenProcess");
					ChangeProcAddr((PVOID*)&m_NtQuerySystemInformation, MyNtQuerySystemInformation, FALSE);
					ChangeProcAddr((PVOID*)&m_NtOpenProcess, MyNtOpenProcess, FALSE);
				}

				~static_constructor() {
					using DetoursHelpers::ChangeProcAddr;
					ChangeProcAddr((PVOID*)&m_NtQuerySystemInformation, MyNtQuerySystemInformation, TRUE);
					ChangeProcAddr((PVOID*)&m_NtOpenProcess, MyNtOpenProcess, TRUE);
				}
			} m_static_constructor;

			static NTSTATUS NTAPI MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
				const NTSTATUS ret = m_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
				if (NT_SUCCESS(ret) && SystemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
					for (PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation, pPrevious = NULL; pCurrent != NULL; pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset)) {
						if (!std_container_helpers::set_helper::contains(m_HiddenProcessIds, (DWORD)pCurrent->UniqueProcessId))
							pPrevious = pCurrent;
						else if (pPrevious != NULL)
							pPrevious->NextEntryOffset = pCurrent->NextEntryOffset ? pPrevious->NextEntryOffset + pCurrent->NextEntryOffset : 0;
						if (!pCurrent->NextEntryOffset)
							break;
					}
				return ret;
			}

			static NTSTATUS NTAPI MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
				NTSTATUS ret = m_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
				if (NT_SUCCESS(ret) && std_container_helpers::set_helper::contains(m_ProtectedProcessIds, (DWORD)ClientId->UniqueProcess)) {
					CloseHandle(*ProcessHandle);
					*ProcessHandle = NULL;
					ret = STATUS_ACCESS_DENIED;
				}
				return ret;
			}
		};

		decltype(ProcessProtector::m_static_constructor) ProcessProtector::m_static_constructor;
		decltype(ProcessProtector::m_HiddenProcessIds) ProcessProtector::m_HiddenProcessIds;
		decltype(ProcessProtector::m_ProtectedProcessIds) ProcessProtector::m_ProtectedProcessIds;
		decltype(ProcessProtector::m_NtQuerySystemInformation) ProcessProtector::m_NtQuerySystemInformation;
		decltype(ProcessProtector::m_NtOpenProcess) ProcessProtector::m_NtOpenProcess;
	}
}