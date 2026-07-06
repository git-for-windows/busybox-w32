/* Licensed under GPLv2, see file LICENSE in this source tree. */
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <wchar.h>

static volatile LONG received;

static BOOL WINAPI receive_signal(DWORD event)
{
	if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT)
		return FALSE;
	InterlockedIncrement(&received);
	return TRUE;
}

static int collect(HANDLE pipe, char *text, DWORD capacity, DWORD *used)
{
	DWORD available, got;

	if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL))
		return GetLastError() == ERROR_BROKEN_PIPE ? 0 : -1;
	if (!available)
		return 0;
	if (available >= capacity - *used)
		return -1;
	if (!ReadFile(pipe, text + *used, available, &got, NULL))
		return -1;
	*used += got;
	text[*used] = '\0';
	return 1;
}

static int drain(HANDLE pipe)
{
	char buffer[8192];
	DWORD available, got;

	if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL))
		return GetLastError() == ERROR_BROKEN_PIPE ? 0 : -1;
	if (available) {
		if (available > sizeof(buffer))
			available = sizeof(buffer);
		if (!ReadFile(pipe, buffer, available, &got, NULL))
			return -1;
	}
	return 0;
}

static int worker(const wchar_t *binary, const wchar_t *script,
		const wchar_t *fixture, const wchar_t *report_name)
{
	SECURITY_ATTRIBUTES inherit = { sizeof(inherit), NULL, TRUE };
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION child;
	HANDLE in_read = NULL, in_write = NULL;
	HANDLE out_read = NULL, out_write = NULL;
	HANDLE err_read = NULL, err_write = NULL;
	int report_fd = _wopen(report_name,
		_O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
		_S_IREAD | _S_IWRITE);
	FILE *report = report_fd < 0 ? NULL : _fdopen(report_fd, "wb");
	wchar_t command[32768];
	char events[16384] = "";
	DWORD used = 0, written, exit_code = 0, start;
	int ready = 0, sent = 0, resumed = 0, next_blocked = 0, ret = 1;

	if (!report) {
		if (report_fd >= 0)
			_close(report_fd);
		return 2;
	}
	if (!SetConsoleCtrlHandler(NULL, FALSE) ||
			!SetConsoleCtrlHandler(receive_signal, TRUE) ||
	    !CreatePipe(&in_read, &in_write, &inherit, 0) ||
	    !CreatePipe(&out_read, &out_write, &inherit, 4096) ||
	    !CreatePipe(&err_read, &err_write, &inherit, 0) ||
	    !SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0) ||
	    !SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0) ||
	    !SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0))
		goto setup_failed;
	if (_snwprintf(command, 32768, L"\"%ls\" ash \"%ls\" \"%ls\"",
			binary, script, fixture) < 0)
		goto setup_failed;
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = in_read;
	si.hStdOutput = out_write;
	si.hStdError = err_write;
	if (!CreateProcessW(binary, command, NULL, NULL, TRUE, 0,
			NULL, NULL, &si, &child))
		goto setup_failed;
	CloseHandle(child.hThread);
	CloseHandle(in_read);
	CloseHandle(out_write);
	CloseHandle(err_write);
	in_read = out_write = err_write = NULL;

	start = GetTickCount();
	while (GetTickCount() - start < 5000) {
		if (collect(err_read, events,
				sizeof(events), &used) < 0)
			break;
		if (strstr(events, "ready\n")) {
			ready = 1;
			break;
		}
		if (WaitForSingleObject(child.hProcess, 0) == WAIT_OBJECT_0)
			break;
		Sleep(1);
	}
	if (ready) {
		Sleep(75);
		start = GetTickCount();
		sent = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
		while (GetTickCount() - start < 5000) {
			if (collect(err_read, events,
					sizeof(events), &used) < 0)
				break;
			if (strstr(events, "next-ready\n")) {
				resumed = 1;
				Sleep(75);
				next_blocked = WaitForSingleObject(
					child.hProcess, 0) == WAIT_TIMEOUT;
				break;
			}
			if (WaitForSingleObject(child.hProcess, 0)
					== WAIT_OBJECT_0) {
				resumed = 1;
				break;
			}
			Sleep(1);
		}
	}
	if (next_blocked) {
		const char followup[] = "next input\n";
		if (!WriteFile(in_write, followup, sizeof(followup) - 1,
				&written, NULL) ||
				written != sizeof(followup) - 1)
			fprintf(report, "followup write failed: %lu\n",
				(unsigned long)GetLastError());
	}
	/* Release both directions even if the candidate failed the test. */
	CloseHandle(in_write);
	in_write = NULL;
	start = GetTickCount();
	while (GetTickCount() - start < 5000) {
		if (collect(err_read, events, sizeof(events), &used) < 0 ||
				drain(out_read) < 0)
			break;
		if (WaitForSingleObject(child.hProcess, 0) == WAIT_OBJECT_0) {
			if (GetExitCodeProcess(child.hProcess, &exit_code)) {
				ret = 0;
				break;
			}
		}
		Sleep(1);
	}
	if (collect(err_read, events, sizeof(events), &used) < 0)
		ret = 3;
	fprintf(report, "ready=%d sent=%d received=%ld resumed=%d "
		"next_blocked=%d exit=%lu\n%s", ready, sent, (long)received,
		resumed, next_blocked, (unsigned long)exit_code, events);
	if (ret)
		fprintf(report, "process not verified exited: pid=%lu\n",
			(unsigned long)child.dwProcessId);
	CloseHandle(child.hProcess);
	goto cleanup;

 setup_failed:
	fprintf(report, "setup failed: %lu\n", (unsigned long)GetLastError());
 cleanup:
	if (in_read) CloseHandle(in_read);
	if (in_write) CloseHandle(in_write);
	if (out_read) CloseHandle(out_read);
	if (out_write) CloseHandle(out_write);
	if (err_read) CloseHandle(err_read);
	if (err_write) CloseHandle(err_write);
	if (fclose(report))
		ret = 4;
	return ret;
}

int wmain(int argc, wchar_t **argv)
{
	wchar_t self[32768], command[65536];
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION child;
	DWORD exit_code;

	if (argc == 6 && wcscmp(argv[1], L"--worker") == 0)
		return worker(argv[2], argv[3], argv[4], argv[5]);
	if (argc != 5)
		return 2;
	if (!GetModuleFileNameW(NULL, self, 32768) ||
	    _snwprintf(command, 65536,
			L"\"%ls\" --worker \"%ls\" \"%ls\" \"%ls\" \"%ls\"",
			self, argv[1], argv[2], argv[3], argv[4]) < 0)
		return 3;
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	if (!CreateProcessW(self, command, NULL, NULL, FALSE,
			CREATE_NEW_CONSOLE, NULL, NULL, &si, &child))
		return 4;
	CloseHandle(child.hThread);
	if (WaitForSingleObject(child.hProcess, INFINITE) != WAIT_OBJECT_0 ||
			!GetExitCodeProcess(child.hProcess, &exit_code)) {
		CloseHandle(child.hProcess);
		return 5;
	}
	CloseHandle(child.hProcess);
	return exit_code;
}
