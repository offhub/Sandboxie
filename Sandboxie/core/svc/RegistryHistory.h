#pragma once

#include <string>

struct REGISTRY_HISTORY_CAPTURE
{
    std::wstring PendingPath;
    std::wstring FinalPath;
    bool Prepared = false;
};

bool RegistryHistory_Prepare(const WCHAR* BoxName, const WCHAR* RootPath,
    REGISTRY_HISTORY_CAPTURE& Capture);
void RegistryHistory_Commit(const WCHAR* BoxName,
    REGISTRY_HISTORY_CAPTURE& Capture);
void RegistryHistory_Discard(REGISTRY_HISTORY_CAPTURE& Capture);
