#pragma once

enum EDeleteHistoryMode
{
	eDeleteHistoryLegacy,
	eDeleteHistoryNone,
	eDeleteHistoryAll,
	eDeleteHistoryRetainedFiles,
	eDeleteHistoryRegistry
};

struct SDeleteContentOptions
{
	SDeleteContentOptions(bool DeleteAllSnapshots = true,
		EDeleteHistoryMode History = eDeleteHistoryLegacy,
		bool DeleteFileState = false)
		: DeleteSnapshots(DeleteAllSnapshots), HistoryMode(History),
		  DeleteFileStateHistory(DeleteFileState) {}

	bool DeleteFileHistory() const
	{
		return HistoryMode == eDeleteHistoryAll ||
			HistoryMode == eDeleteHistoryRetainedFiles;
	}

	bool DeleteRegistryHistory() const
	{
		return HistoryMode == eDeleteHistoryAll ||
			HistoryMode == eDeleteHistoryRegistry;
	}

	bool DeleteSnapshots;
	EDeleteHistoryMode HistoryMode;
	bool DeleteFileStateHistory;
};
