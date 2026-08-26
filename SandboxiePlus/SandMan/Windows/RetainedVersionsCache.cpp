#include "stdafx.h"
#include "RetainedVersionsCache.h"

#include <QCryptographicHash>
#include <QDataStream>
#include <QDirIterator>
#include <QSaveFile>

#include <algorithm>

namespace
{
	const quint32 CacheMagic = 0x31564352;
	const quint16 CacheVersion = 1;
	const quint64 MaximumCacheBytes = 64ULL * 1024 * 1024;
	const quint32 MaximumStrings = 1024 * 1024;
	const quint32 MaximumLineages = RetainedVersionsCache::MaximumRecords;

	bool WriteString(QDataStream& Stream, const QString& Value)
	{
		QByteArray Data = Value.toUtf8();
		if (Data.size() > (int)MaximumStrings)
			return false;
		Stream << (quint32)Data.size();
		return Stream.writeRawData(Data.constData(), Data.size()) == Data.size();
	}

	bool ReadString(QDataStream& Stream, QFile& File, QString& Value)
	{
		quint32 Size = 0;
		Stream >> Size;
		if (Stream.status() != QDataStream::Ok || Size > MaximumStrings)
			return false;
		qint64 Position = File.pos();
		if (Position < 0 || Position > File.size() ||
				(qint64)Size > File.size() - Position)
			return false;
		QByteArray Data;
		Data.resize((int)Size);
		if (Stream.readRawData(Data.data(), (int)Size) != (int)Size)
			return false;
		Value = QString::fromUtf8(Data);
		return true;
	}

	bool WriteRecord(QDataStream& Stream, const SRetainedVersionRecord& Record)
	{
		if (!WriteString(Stream, Record.Artifact) ||
				!WriteString(Stream, Record.BinaryPath) ||
				!WriteString(Stream, Record.MetadataPath) ||
				!WriteString(Stream, Record.LogicalPath) ||
				!WriteString(Stream, Record.TruePath) ||
				!WriteString(Stream, Record.Operation) ||
				!WriteString(Stream, Record.State) ||
				!WriteString(Stream, Record.ProcessName) ||
				!WriteString(Stream, Record.Pid) ||
				!WriteString(Stream, Record.Timestamp) ||
				!WriteString(Stream, Record.Hash) ||
				!WriteString(Stream, Record.Lineage))
			return false;

		Stream << Record.TimestampFallback << Record.CapturedSort
			<< Record.Size;
		Stream << (quint8)(Record.MetadataValid ? 1 : 0)
			<< (quint8)(Record.HasSize ? 1 : 0)
			<< (quint8)(Record.IsEmpty ? 1 : 0)
			<< (quint8)(Record.Reused ? 1 : 0)
			<< (quint8)(Record.Pending ? 1 : 0)
			<< (quint8)(Record.BlobAvailable ? 1 : 0);
		return Stream.status() == QDataStream::Ok;
	}

	bool ReadRecord(QDataStream& Stream, QFile& File,
		SRetainedVersionRecord& Record)
	{
		if (!ReadString(Stream, File, Record.Artifact) ||
				!ReadString(Stream, File, Record.BinaryPath) ||
				!ReadString(Stream, File, Record.MetadataPath) ||
				!ReadString(Stream, File, Record.LogicalPath) ||
				!ReadString(Stream, File, Record.TruePath) ||
				!ReadString(Stream, File, Record.Operation) ||
				!ReadString(Stream, File, Record.State) ||
				!ReadString(Stream, File, Record.ProcessName) ||
				!ReadString(Stream, File, Record.Pid) ||
				!ReadString(Stream, File, Record.Timestamp) ||
				!ReadString(Stream, File, Record.Hash) ||
				!ReadString(Stream, File, Record.Lineage))
			return false;

		quint8 MetadataValid = 0;
		quint8 HasSize = 0;
		quint8 IsEmpty = 0;
		quint8 Reused = 0;
		quint8 Pending = 0;
		quint8 BlobAvailable = 0;
		Stream >> Record.TimestampFallback >> Record.CapturedSort
			>> Record.Size >> MetadataValid >> HasSize >> IsEmpty >> Reused
			>> Pending >> BlobAvailable;
		if (Stream.status() != QDataStream::Ok)
			return false;
		Record.MetadataValid = MetadataValid != 0;
		Record.HasSize = HasSize != 0;
		Record.IsEmpty = IsEmpty != 0;
		Record.Reused = Reused != 0;
		Record.Pending = Pending != 0;
		Record.BlobAvailable = BlobAvailable != 0;
		return true;
	}

	bool WriteLineage(QDataStream& Stream, const QString& Path,
		const QString& Lineage)
	{
		return WriteString(Stream, Path) && WriteString(Stream, Lineage);
	}

	bool ReadLineage(QDataStream& Stream, QFile& File, QString& Path,
		QString& Lineage)
	{
		return ReadString(Stream, File, Path) && ReadString(Stream, File, Lineage);
	}

	bool IsSafeRelativePath(const QString& Path)
	{
		if (Path.isEmpty() || QDir::isAbsolutePath(Path) || Path.contains(':'))
			return Path.isEmpty();
		QString Normalized = QDir::fromNativeSeparators(Path);
		if (Normalized.startsWith('/') || Normalized.startsWith("../") ||
				Normalized == ".." || Normalized.contains("/../"))
			return false;
		return true;
	}

	bool IsSafeArtifactPath(const QString& Path)
	{
		if (!IsSafeRelativePath(Path))
			return false;
		QString Normalized = QDir::fromNativeSeparators(Path);
		if (Normalized.isEmpty())
			return true;
		return Normalized.startsWith("Artifacts/", Qt::CaseInsensitive)
			&& (QFileInfo(Normalized).suffix().compare(
				"bin", Qt::CaseInsensitive) == 0
				|| QFileInfo(Normalized).suffix().compare(
				"txt", Qt::CaseInsensitive) == 0);
	}

	bool IsSafeHash(const QString& Hash)
	{
		if (Hash.isEmpty() || Hash.size() != 64)
			return Hash.isEmpty();
		for (const QChar& Character : Hash)
			if (!((Character >= QLatin1Char('0') &&
					Character <= QLatin1Char('9')) ||
				(Character >= QLatin1Char('a') &&
					Character <= QLatin1Char('f')) ||
				(Character >= QLatin1Char('A') &&
					Character <= QLatin1Char('F'))))
				return false;
		return true;
	}

	bool IsSafeLineageId(const QString& Lineage)
	{
		if (Lineage.size() != 51)
			return false;
		for (int Index = 0; Index < Lineage.size(); ++Index) {
			QChar Character = Lineage.at(Index);
			if (Index == 16 || Index == 33 || Index == 42) {
				if (Character != QLatin1Char('-'))
					return false;
			}
			else if (!((Character >= QLatin1Char('0') &&
					Character <= QLatin1Char('9')) ||
				(Character >= QLatin1Char('a') &&
					Character <= QLatin1Char('f')) ||
				(Character >= QLatin1Char('A') &&
					Character <= QLatin1Char('F'))))
				return false;
		}
		return true;
	}
}

namespace RetainedVersionsCache
{
	QString CachePath(const QString& BoxRoot)
	{
		return QDir(BoxRoot).filePath("RetainedVersions.cache");
	}

	bool Read(const QString& BoxRoot, SRetainedVersionsData& Data)
	{
		Data = SRetainedVersionsData();
		QString Path = CachePath(BoxRoot);
		QFileInfo CacheInfo(Path);
		if (!CacheInfo.isFile() || CacheInfo.isSymLink())
			return false;
		QFile File(Path);
		if (!File.open(QIODevice::ReadOnly) || File.size() <= 0 ||
				(quint64)File.size() > MaximumCacheBytes)
			return false;

		QDataStream Stream(&File);
		Stream.setVersion(QDataStream::Qt_5_15);
		quint32 Magic = 0;
		quint16 Version = 0;
		quint32 RecordCount = 0;
		quint32 LineageCount = 0;
		Stream >> Magic >> Version;
		if (Stream.status() != QDataStream::Ok || Magic != CacheMagic ||
				Version != CacheVersion ||
				!ReadString(Stream, File, Data.Fingerprint) ||
				!IsSafeHash(Data.Fingerprint))
			return false;
		Stream >> Data.UsedVersions >> Data.AccountedSize >> Data.StoredSize
			>> RecordCount;
		if (Stream.status() != QDataStream::Ok ||
				RecordCount > (quint32)RetainedVersionsCache::MaximumRecords)
			return false;

		for (quint32 Index = 0; Index < RecordCount; ++Index) {
			SRetainedVersionRecord Record;
			if (!ReadRecord(Stream, File, Record) ||
					!IsSafeArtifactPath(Record.BinaryPath) ||
					!IsSafeArtifactPath(Record.MetadataPath) ||
					!IsSafeHash(Record.Hash))
				return false;
			Data.Records.append(Record);
		}

		Stream >> LineageCount;
		if (Stream.status() != QDataStream::Ok ||
				LineageCount > MaximumLineages)
			return false;
		for (quint32 Index = 0; Index < LineageCount; ++Index) {
			QString Path;
			QString Lineage;
			// Lineage keys are logical host paths and may be absolute.
			if (!ReadLineage(Stream, File, Path, Lineage) ||
					Path.isEmpty() || !IsSafeLineageId(Lineage))
				return false;
			Data.PathLineages.insert(Path, Lineage);
		}
		return Stream.status() == QDataStream::Ok;
	}

	bool Write(const QString& BoxRoot, const SRetainedVersionsData& Data)
	{
		if (Data.Records.size() > RetainedVersionsCache::MaximumRecords ||
				Data.PathLineages.size() > (int)MaximumLineages)
			return false;

		QSaveFile File(CachePath(BoxRoot));
		if (!File.open(QIODevice::WriteOnly))
			return false;
		QDataStream Stream(&File);
		Stream.setVersion(QDataStream::Qt_5_15);
		Stream << CacheMagic << CacheVersion;
		if (!WriteString(Stream, Data.Fingerprint))
			return false;
		Stream << Data.UsedVersions << Data.AccountedSize << Data.StoredSize
			<< (quint32)Data.Records.size();
		for (const SRetainedVersionRecord& Record : Data.Records)
			if (!WriteRecord(Stream, Record))
				return false;
		Stream << (quint32)Data.PathLineages.size();
		for (auto It = Data.PathLineages.constBegin();
				It != Data.PathLineages.constEnd(); ++It)
			if (!WriteLineage(Stream, It.key(), It.value()))
				return false;
		if (Stream.status() != QDataStream::Ok || !File.flush())
			return false;
		return File.commit();
	}

	bool Remove(const QString& BoxRoot)
	{
		QString Path = CachePath(BoxRoot);
		return !QFile::exists(Path) || QFile::remove(Path);
	}

	QString CalculateFingerprint(const QString& HistoryPath,
		const std::atomic_bool* Cancel)
	{
		QByteArray Missing = "missing\n";
		if (!QDir(HistoryPath).exists())
			return QString::fromLatin1(
				QCryptographicHash::hash(Missing, QCryptographicHash::Sha256).toHex());

		QStringList Entries;
		QDirIterator Iterator(HistoryPath,
			QDir::AllEntries | QDir::Hidden | QDir::System |
			QDir::NoDotAndDotDot | QDir::NoSymLinks,
			QDirIterator::Subdirectories);
		QDir Root(HistoryPath);
		while (Iterator.hasNext()) {
			if (Cancel && Cancel->load())
				return QString();
			QString Path = Iterator.next();
			QFileInfo Info = Iterator.fileInfo();
			QString Relative = QDir::fromNativeSeparators(
				Root.relativeFilePath(Path));
			QString Entry = Relative + QLatin1Char('|') +
				(Info.isDir() ? QLatin1Char('d') : QLatin1Char('f')) +
				QLatin1Char('|') + QString::number(Info.size()) +
				QLatin1Char('|') + QString::number(
					Info.lastModified().toUTC().toMSecsSinceEpoch());
			Entries.append(Entry);
		}
		std::sort(Entries.begin(), Entries.end(),
			[](const QString& Left, const QString& Right) {
				return QString::compare(Left, Right, Qt::CaseSensitive) < 0;
			});
		QCryptographicHash Hash(QCryptographicHash::Sha256);
		for (const QString& Entry : Entries) {
			if (Cancel && Cancel->load())
				return QString();
			Hash.addData(Entry.toUtf8());
			Hash.addData("\0", 1);
		}
		return QString::fromLatin1(Hash.result().toHex());
	}
}
