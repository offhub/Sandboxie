#pragma once

#include <string>

struct REGISTRY_HISTORY_CAPTURE
{
    std::wstring PendingPath;
    std::wstring FinalPath;
    bool Prepared = false;
};

void RegistryHistory_Initialize();
void RegistryHistory_Shutdown();
void RegistryHistory_RememberPath(const WCHAR* FileRoot,
    const WCHAR* RootPath);
void RegistryHistory_ForgetPath(const WCHAR* RootPath);
bool RegistryHistory_Prepare(const WCHAR* BoxName, const WCHAR* RootPath,
    REGISTRY_HISTORY_CAPTURE& Capture);
void RegistryHistory_Commit(const WCHAR* BoxName,
    REGISTRY_HISTORY_CAPTURE& Capture);
void RegistryHistory_Discard(REGISTRY_HISTORY_CAPTURE& Capture);
