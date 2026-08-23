#pragma once

enum EDeleteHistoryMode
{
	eDeleteHistoryLegacy,
	eDeleteHistoryNone,
	eDeleteHistoryBoth,
	eDeleteHistoryFile,
	eDeleteHistoryRegistry
};

struct SDeleteContentOptions
{
	SDeleteContentOptions(bool DeleteAllSnapshots = true,
		EDeleteHistoryMode History = eDeleteHistoryLegacy)
		: DeleteSnapshots(DeleteAllSnapshots), HistoryMode(History) {}

	bool DeleteFileHistory() const
	{
		return HistoryMode == eDeleteHistoryBoth ||
			HistoryMode == eDeleteHistoryFile;
	}

	bool DeleteRegistryHistory() const
	{
		return HistoryMode == eDeleteHistoryBoth ||
			HistoryMode == eDeleteHistoryRegistry;
	}

	bool DeleteSnapshots;
	EDeleteHistoryMode HistoryMode;
};
