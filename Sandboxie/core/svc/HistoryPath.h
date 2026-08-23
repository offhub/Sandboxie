#pragma once

#include <string>

void HistoryPath_Initialize();
void HistoryPath_Shutdown();
void HistoryPath_Remember(const WCHAR* FileRoot, const WCHAR* RootPath);
void HistoryPath_Forget(const WCHAR* RootPath);
bool HistoryPath_Get(const WCHAR* RootPath, std::wstring& FileRoot);
