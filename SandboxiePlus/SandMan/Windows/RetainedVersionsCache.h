#pragma once

#include <QHash>
#include <QList>
#include <QString>

#include <atomic>

struct SRetainedVersionRecord
{
	QString Artifact;
	QString BinaryPath;
	QString MetadataPath;
	QString LogicalPath;
	QString TruePath;
	QString Operation;
	QString State;
	QString ProcessName;
	QString Pid;
	QString Timestamp;
	qint64 TimestampFallback = 0;
	quint64 CapturedSort = 0;
	quint64 Size = 0;
	QString Hash;
	QString Lineage;
	bool MetadataValid = false;
	bool HasSize = false;
	bool IsEmpty = false;
	bool Reused = false;
	bool Pending = false;
	bool BlobAvailable = false;
};

struct SRetainedVersionsData
{
	QList<SRetainedVersionRecord> Records;
	QHash<QString, QString> PathLineages;
	QString Fingerprint;
	quint64 UsedVersions = 0;
	quint64 AccountedSize = 0;
	quint64 StoredSize = 0;
};

struct SRetainedVersionsScanResult
{
	SRetainedVersionsData Data;
	bool Complete = false;
	bool Stable = false;
	bool TooLarge = false;
	quint64 ChangeSequence = 0;
};

namespace RetainedVersionsCache
{
	static const int MaximumRecords = 100000;

	QString CachePath(const QString& BoxRoot);
	bool Read(const QString& BoxRoot, SRetainedVersionsData& Data);
	bool Write(const QString& BoxRoot, const SRetainedVersionsData& Data);
	bool Remove(const QString& BoxRoot);
	QString CalculateFingerprint(const QString& HistoryPath,
		const std::atomic_bool* Cancel = NULL);
}
