#include "stdafx.h"
#include "FileHistoryWindow.h"
#include "FileStateHistoryWidget.h"
#include "HistoryWindowUtils.h"
#include "SandMan.h"
#include "../../MiscHelpers/Common/Finder.h"
#include "../../MiscHelpers/Common/PanelView.h"
#include "../../MiscHelpers/Common/TreeWidgetEx.h"
#include <algorithm>
#include <QEventLoop>
#include <QItemSelectionModel>
#include <QStackedLayout>
#include <QTabWidget>
#include <windows.h>


namespace
{
	enum EHistoryRole
	{
		eFolderPath = Qt::UserRole,
		eBinaryPath,
		eMetadataPath,
		eLogicalPath,
		eTruePath,
		eOperation,
		eProcess,
		eState,
		eSize,
		eDate,
		eExtension,
		eHash,
		eHashValue,
		eProcessName,
		eIsEmpty,
		eIsReused,
		eIsPending,
		eIsEvidence,
		eIsGroup,
		eLineage,
		eSortValue
	};

	enum EFilterScope
	{
		eAllFields,
		ePathField,
		eVersionField,
		eOperationField,
		eProcessField,
		eStateField,
		eSizeField,
		eDateField,
		eExtensionField,
		eHashField
	};

	struct SHistoryFilePair
	{
		QString BinaryPath;
		QString MetadataPath;
	};

	struct SSelectedEvidence
	{
		QString Path;
		QString LogicalPath;
		quint64 Captured = 0;
	};

	QString GetFileHistoryEditor()
	{
		QString Editor = theConf->GetString(
			"FileHistoryWindow/Editor").trimmed();
		return Editor.isEmpty()
			? theConf->GetString("Options/Editor", "notepad.exe")
			: Editor;
	}

	bool DetachSharedEvidence(const QString& Path)
	{
		static LONG Sequence = 0;
		BY_HANDLE_FILE_INFORMATION Info;
		if (QFileInfo(Path).fileName().compare(
				QStringLiteral("pending.bin"),
				Qt::CaseInsensitive) == 0)
			return false;

		HANDLE Handle = CreateFileW(
			(LPCWSTR)Path.utf16(), FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
		if (Handle == INVALID_HANDLE_VALUE)
			return false;

		bool Queried = GetFileInformationByHandle(Handle, &Info) != FALSE;
		CloseHandle(Handle);
		if (!Queried)
			return false;
		bool Shared = Info.nNumberOfLinks > 1;
		if (!Shared)
			return true;

		QString TempPath = Path + QStringLiteral(".edit.%1.%2")
			.arg(GetCurrentProcessId())
			.arg(InterlockedIncrement(&Sequence));
		if (!CopyFileW((LPCWSTR)Path.utf16(),
				(LPCWSTR)TempPath.utf16(), FALSE))
			return false;
		if (!MoveFileExW((LPCWSTR)TempPath.utf16(),
				(LPCWSTR)Path.utf16(),
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
			DeleteFileW((LPCWSTR)TempPath.utf16());
			return false;
		}
		return true;
	}

	void RemoveOrphanedBlobs(const QString& HistoryPath)
	{
		QDir Blobs(QDir::cleanPath(HistoryPath + "\\Blobs"));
		foreach(const QFileInfo& Blob, Blobs.entryInfoList(
				QDir::Files | QDir::Hidden | QDir::System |
				QDir::NoDotAndDotDot)) {
			BY_HANDLE_FILE_INFORMATION Info;
			HANDLE Handle = CreateFileW(
				(LPCWSTR)Blob.absoluteFilePath().utf16(),
				FILE_READ_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
			if (Handle == INVALID_HANDLE_VALUE)
				continue;
			bool Orphaned =
				GetFileInformationByHandle(Handle, &Info) != FALSE &&
				Info.nNumberOfLinks <= 1;
			CloseHandle(Handle);
			if (Orphaned)
				QFile::remove(Blob.absoluteFilePath());
		}
	}

	class CHistoryTreeItem : public QTreeWidgetItem
	{
	public:
		CHistoryTreeItem() : QTreeWidgetItem() {}
		explicit CHistoryTreeItem(QTreeWidget* Tree)
			: QTreeWidgetItem(Tree) {}
		explicit CHistoryTreeItem(QTreeWidgetItem* Parent)
			: QTreeWidgetItem(Parent) {}

		bool operator<(const QTreeWidgetItem& Other) const override
		{
			int Column = treeWidget() ? treeWidget()->sortColumn() : 0;
			QVariant Left = data(Column, eSortValue);
			QVariant Right = Other.data(Column, eSortValue);
			if (Left.isValid() && Right.isValid())
				return Left.toULongLong() < Right.toULongLong();
			return QTreeWidgetItem::operator<(Other);
		}
	};

	void AppendTreeItems(
		QTreeWidgetItem* Item, QList<QTreeWidgetItem*>& Items)
	{
		Items.append(Item);
		for (int Index = 0; Index < Item->childCount(); ++Index)
			AppendTreeItems(Item->child(Index), Items);
	}

	QList<QTreeWidgetItem*> TreeItems(QTreeWidget* Tree)
	{
		QList<QTreeWidgetItem*> Items;
		for (int Index = 0; Index < Tree->topLevelItemCount(); ++Index)
			AppendTreeItems(Tree->topLevelItem(Index), Items);
		return Items;
	}

	void SortTreeChildren(
		QTreeWidgetItem* Item, int Column, Qt::SortOrder Order)
	{
		Item->sortChildren(Column, Order);
		for (int Index = 0; Index < Item->childCount(); ++Index) {
			QTreeWidgetItem* Child = Item->child(Index);
			if (!Child->data(0, eIsEvidence).toBool())
				SortTreeChildren(Child, Column, Order);
		}
	}

	bool IsArtifactId(const QString& Name)
	{
		if (Name.length() != 51)
			return false;

		for (int i = 0; i < Name.length(); ++i) {
			QChar Ch = Name.at(i);
			if (i == 16 || i == 33 || i == 42) {
				if (Ch != QLatin1Char('-'))
					return false;
			}
			else if (!((Ch >= QLatin1Char('0') && Ch <= QLatin1Char('9'))
					|| (Ch >= QLatin1Char('A') && Ch <= QLatin1Char('F'))
					|| (Ch >= QLatin1Char('a') && Ch <= QLatin1Char('f')))) {
				return false;
			}
		}

		return true;
	}

	bool IsSha256(const QString& Hash)
	{
		if (Hash.length() != 64)
			return false;

		foreach(const QChar& Ch, Hash) {
			if (!((Ch >= QLatin1Char('0') && Ch <= QLatin1Char('9'))
					|| (Ch >= QLatin1Char('A') && Ch <= QLatin1Char('F'))
					|| (Ch >= QLatin1Char('a') && Ch <= QLatin1Char('f'))))
				return false;
		}
		return true;
	}

	QString UnescapeField(const QString& Field)
	{
		QString Result;
		Result.reserve(Field.length());

		for (int i = 0; i < Field.length(); ++i) {
			QChar Ch = Field.at(i);
			if (Ch == QLatin1Char('\\') && i + 1 < Field.length()) {
				QChar Esc = Field.at(++i);
				if (Esc == QLatin1Char('|') || Esc == QLatin1Char('\\'))
					Ch = Esc;
				else if (Esc == QLatin1Char('r'))
					Ch = QLatin1Char('\r');
				else if (Esc == QLatin1Char('n'))
					Ch = QLatin1Char('\n');
				else {
					Result.append(QLatin1Char('\\'));
					Ch = Esc;
				}
			}
			Result.append(Ch);
		}

		return Result;
	}

	bool ReadFields(const QString& Path, QMap<QString, QString>& Fields)
	{
		QFile File(Path);
		if (!File.open(QFile::ReadOnly))
			return false;

		QByteArray Data = File.read(256 * 1024 + 1);
		if (Data.isEmpty() || Data.size() > 256 * 1024
				|| (Data.size() % sizeof(wchar_t)) != 0)
			return false;

		QString Text = QString::fromWCharArray(
			(const wchar_t*)Data.constData(), Data.size() / sizeof(wchar_t));
		QTextStream Stream(&Text);
		while (!Stream.atEnd()) {
			QString Line = Stream.readLine();
			int Separator = Line.indexOf(QLatin1Char('='));
			if (Separator <= 0)
				continue;
			Fields.insert(Line.left(Separator), Line.mid(Separator + 1));
		}

		return !Fields.isEmpty();
	}

	bool ReadMetadata(const QString& Path, QMap<QString, QString>& Fields)
	{
		return ReadFields(Path, Fields)
			&& Fields.contains("artifact") && Fields.contains("path");
	}

	QString ResolveCounterLineage(
		const QString& IndexPath, const QString& Counter)
	{
		if (!IsArtifactId(Counter))
			return QString();

		QString Current = Counter;
		QSet<QString> Visited;
		for (int Depth = 0; Depth < 256; ++Depth) {
			QString Key = Current.toLower();
			if (Visited.contains(Key))
				return QString();
			Visited.insert(Key);

			QMap<QString, QString> Fields;
			QString Path = QDir(IndexPath).filePath(
				QStringLiteral("counter.%1.cnt").arg(Current));
			if (!ReadFields(Path, Fields))
				return QString();

			QString Redirect = Fields.value("redirect");
			if (!Redirect.isEmpty()) {
				if (!IsArtifactId(Redirect)
						|| Redirect.compare(Current, Qt::CaseInsensitive) == 0)
					return QString();
				Current = Redirect;
				continue;
			}

			bool ValidVersions = false;
			Fields.value("versions").toULongLong(&ValidVersions);
			return ValidVersions ? Current : QString();
		}
		return QString();
	}

	QHash<QString, QString> ReadPathLineages(const QString& HistoryPath)
	{
		QString IndexPath = QDir::cleanPath(HistoryPath + "\\Index");
		QDir Index(IndexPath);
		QHash<QString, QString> Lineages;
		QSet<QString> AmbiguousPaths;
		foreach(const QFileInfo& Marker, Index.entryInfoList(
				QStringList() << QStringLiteral("*.idx"),
				QDir::Files | QDir::NoSymLinks, QDir::Name)) {
			QMap<QString, QString> Fields;
			if (!ReadMetadata(Marker.absoluteFilePath(), Fields))
				continue;
			if (!IsArtifactId(Fields.value("artifact")))
				continue;
			QString Path = UnescapeField(Fields.value("dos_path")).toLower();
			QString Lineage = ResolveCounterLineage(
				IndexPath, Fields.value("counter"));
			if (Path.isEmpty() || Lineage.isEmpty()
					|| AmbiguousPaths.contains(Path))
				continue;
			if (Lineages.contains(Path)
					&& Lineages.value(Path).compare(
						Lineage, Qt::CaseInsensitive) != 0) {
				Lineages.remove(Path);
				AmbiguousPaths.insert(Path);
			}
			else
				Lineages.insert(Path, Lineage.toLower());
		}
		return Lineages;
	}

	QString EscapeFileHistoryJournalField(const QString& Value)
	{
		QString Escaped;
		Escaped.reserve(Value.size());
		foreach(const QChar& Character, Value) {
			if (Character == QLatin1Char('\\')
					|| Character == QLatin1Char('|')) {
				Escaped.append(QLatin1Char('\\'));
				Escaped.append(Character);
			}
			else if (Character == QLatin1Char('\r'))
				Escaped.append(QStringLiteral("\\r"));
			else if (Character == QLatin1Char('\n'))
				Escaped.append(QStringLiteral("\\n"));
			else
				Escaped.append(Character);
		}
		return Escaped;
	}

	bool WriteFileHistoryDeletionJournal(
		const QString& HistoryPath, const QMap<QString, int>& Deltas)
	{
		static LONG Sequence = 0;
		const qint64 MaximumBytes = 128 * 1024;
		QDir DeltaDir(QDir::cleanPath(
			HistoryPath + QStringLiteral("\\Deltas")));
		if (!DeltaDir.exists() && !QDir().mkpath(DeltaDir.absolutePath()))
			return false;

		auto WriteChunk = [&DeltaDir](const QString& Text) {
			QString JournalPath = DeltaDir.filePath(
				QStringLiteral("delete-%1-%2-%3.jrn")
					.arg(GetCurrentProcessId())
					.arg(QDateTime::currentMSecsSinceEpoch())
					.arg(InterlockedIncrement(&Sequence)));
			QString TempPath = JournalPath + QStringLiteral(".tmp");
			QFile File(TempPath);
			qint64 Length = (qint64)Text.size() * sizeof(wchar_t);
			if (!File.open(QFile::WriteOnly)
					|| File.write((const char*)Text.constData(), Length) != Length
					|| !File.flush()) {
				File.close();
				QFile::remove(TempPath);
				return false;
			}
			File.close();
			if (!MoveFileExW((LPCWSTR)TempPath.utf16(),
					(LPCWSTR)JournalPath.utf16(),
					MOVEFILE_WRITE_THROUGH)) {
				QFile::remove(TempPath);
				return false;
			}
			return true;
		};

		QString Text;
		for (auto It = Deltas.constBegin(); It != Deltas.constEnd(); ++It) {
			QString Line = EscapeFileHistoryJournalField(It.key())
				+ QStringLiteral("|") + QString::number(It.value())
				+ QStringLiteral("\r\n");
			if (!Text.isEmpty()
					&& (Text.size() + Line.size()) * sizeof(wchar_t)
						> MaximumBytes) {
				if (!WriteChunk(Text))
					return false;
				Text.clear();
			}
			Text.append(Line);
		}
		return Text.isEmpty() || WriteChunk(Text);
	}

	QString FormatFileTime(const QString& Value)
	{
		bool Ok = false;
		quint64 FileTime = Value.toULongLong(&Ok, 16);
		const quint64 UnixEpoch = 116444736000000000ULL;
		if (!Ok || FileTime < UnixEpoch)
			return QString();

		qint64 Msecs = (qint64)((FileTime - UnixEpoch) / 10000);
		return QDateTime::fromMSecsSinceEpoch(Msecs, Qt::UTC)
			.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
	}

	QString FormatSize(quint64 Size)
	{
		if (Size < 1024)
			return CFileHistoryWindow::tr("%1 B").arg(Size);
		if (Size < 1024 * 1024)
			return CFileHistoryWindow::tr("%1 KiB").arg(Size / 1024.0, 0, 'f', 1);
		if (Size < 1024ULL * 1024 * 1024)
			return CFileHistoryWindow::tr("%1 MiB").arg(Size / (1024.0 * 1024.0), 0, 'f', 1);
		return CFileHistoryWindow::tr("%1 GiB").arg(
			Size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
	}

	QString FormatLimitKB(quint64 SizeKB)
	{
		if (SizeKB == 0)
			return CFileHistoryWindow::tr("unlimited");
		if (SizeKB < 1024)
			return CFileHistoryWindow::tr("%1 KiB").arg(SizeKB);
		if (SizeKB < 1024 * 1024)
			return CFileHistoryWindow::tr("%1 MiB").arg(SizeKB / 1024.0, 0, 'f', 1);
		return CFileHistoryWindow::tr("%1 GiB").arg(SizeKB / (1024.0 * 1024.0), 0, 'f', 1);
	}

	QString FormatCountLimit(quint64 Count)
	{
		return Count == 0
			? CFileHistoryWindow::tr("unlimited")
			: QString::number(Count);
	}

	QString FilterValue(QTreeWidgetItem* Item, int Scope)
	{
		switch (Scope) {
		case ePathField:		return Item->data(0, eLogicalPath).toString();
		case eVersionField:		return Item->text(1);
		case eOperationField:	return Item->data(0, eOperation).toString();
		case eProcessField:		return Item->data(0, eProcess).toString();
		case eStateField:		return Item->data(0, eState).toString();
		case eSizeField:		return Item->data(0, eSize).toString();
		case eDateField:		return Item->data(0, eDate).toString();
		case eExtensionField:	return Item->data(0, eExtension).toString();
		case eHashField:		return Item->data(0, eHash).toString();
		default:
			return QStringLiteral("%1\n%2\n%3\n%4\n%5\n%6\n%7\n%8\n%9")
				.arg(Item->data(0, eLogicalPath).toString(),
					Item->text(1),
					Item->data(0, eOperation).toString(),
					Item->data(0, eProcess).toString(),
					Item->data(0, eState).toString(),
					Item->data(0, eSize).toString(),
					Item->data(0, eDate).toString(),
					Item->data(0, eExtension).toString(),
					Item->data(0, eHash).toString());
		}
	}

	int CompareArgumentCount(const QString& Command)
	{
		if (Command.trimmed().isEmpty())
			return 0;

		QRegularExpression Exp(QStringLiteral("%(\\d+)"));
		QStringList Parts = QProcess::splitCommand(Command);
		if (Parts.isEmpty() || Exp.match(Parts.first()).hasMatch())
			return -1;
		QRegularExpressionMatchIterator Matches = Exp.globalMatch(Command);
		QSet<int> Arguments;
		while (Matches.hasNext()) {
			bool Ok = false;
			int Argument = Matches.next().captured(1).toInt(&Ok);
			if (!Ok || Argument < 1 || Argument > 5)
				return -1;
			Arguments.insert(Argument);
		}
		int ArgumentCount = (int)Arguments.count();
		if (ArgumentCount < 2)
			return -1;
		for (int Argument = 1; Argument <= ArgumentCount; ++Argument) {
			if (!Arguments.contains(Argument))
				return -1;
		}
		return ArgumentCount;
	}

	QString QuoteCommandArgument(const QString& Argument)
	{
		if (!Argument.isEmpty()
				&& !Argument.contains(QRegularExpression(QStringLiteral("[\\s\"]"))))
			return Argument;

		QString Quoted = QStringLiteral("\"");
		int Backslashes = 0;
		foreach(const QChar& Ch, Argument) {
			if (Ch == QLatin1Char('\\')) {
				++Backslashes;
				continue;
			}
			if (Ch == QLatin1Char('"')) {
				Quoted += QString(Backslashes * 2 + 1, QLatin1Char('\\'));
				Quoted += Ch;
			}
			else {
				Quoted += QString(Backslashes, QLatin1Char('\\'));
				Quoted += Ch;
			}
			Backslashes = 0;
		}
		Quoted += QString(Backslashes * 2, QLatin1Char('\\'));
		Quoted += QLatin1Char('"');
		return Quoted;
	}

	QString BuildCompareCommand(
		const QString& Command, const QStringList& Paths)
	{
		QStringList Parts = QProcess::splitCommand(Command);
		if (Parts.isEmpty())
			return QString();

		QString ExpandedCommand = QuoteCommandArgument(Parts.takeFirst());
		QRegularExpression Exp(QStringLiteral("%(\\d+)"));
		int PathCount = (int)Paths.count();
		foreach(const QString& Part, Parts) {
			QRegularExpressionMatchIterator Matches = Exp.globalMatch(Part);
			QString ExpandedPart;
			int Offset = 0;
			bool SkipPart = false;
			while (Matches.hasNext()) {
				QRegularExpressionMatch Match = Matches.next();
				int Argument = Match.captured(1).toInt();
				if (Argument > PathCount) {
					SkipPart = true;
					break;
				}
				int Start = (int)Match.capturedStart();
				int End = (int)Match.capturedEnd();
				ExpandedPart += Part.mid(Offset, Start - Offset);
				ExpandedPart += QDir::toNativeSeparators(Paths[Argument - 1]);
				Offset = End;
			}
			if (SkipPart)
				continue;
			ExpandedPart += Part.mid(Offset);
			ExpandedCommand += QLatin1Char(' ')
				+ QuoteCommandArgument(ExpandedPart);
		}
		return ExpandedCommand;
	}

	bool StartExternalCommand(const QString& Command)
	{
		QStringList Parts = QProcess::splitCommand(Command);
		if (Parts.isEmpty())
			return false;
		std::wstring Program = Parts.takeFirst().toStdWString();
		QString Parameters;
		foreach(const QString& Part, Parts) {
			if (!Parameters.isEmpty())
				Parameters += QLatin1Char(' ');
			Parameters += QuoteCommandArgument(Part);
		}
		std::wstring NativeParameters = Parameters.toStdWString();

		SHELLEXECUTEINFOW Info = { 0 };
		Info.cbSize = sizeof(Info);
		Info.fMask = SEE_MASK_NOCLOSEPROCESS;
		Info.lpFile = Program.c_str();
		Info.lpParameters = NativeParameters.empty()
			? NULL : NativeParameters.c_str();
		Info.nShow = SW_SHOW;
		if (!ShellExecuteExW(&Info))
			return false;
		if (Info.hProcess)
			CloseHandle(Info.hProcess);
		return true;
	}

	int EvidenceLinkCount(const QString& Path)
	{
		BY_HANDLE_FILE_INFORMATION Info;
		HANDLE Handle = CreateFileW(
			(LPCWSTR)Path.utf16(), FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
		if (Handle == INVALID_HANDLE_VALUE)
			return -1;

		bool Queried = GetFileInformationByHandle(Handle, &Info) != FALSE;
		CloseHandle(Handle);
		return Queried ? (int)Info.nNumberOfLinks : -1;
	}

	void AppendUniqueCaseInsensitive(QStringList& Values, const QString& Value)
	{
		if (!Value.isEmpty() && !Values.contains(Value, Qt::CaseInsensitive))
			Values.append(Value);
	}

}


CFileHistoryWindow::CFileHistoryWindow(const CSandBoxPtr& pBox, QWidget* parent)
	: QDialog(parent), m_pBox(pBox), m_LastTab(0), m_Loading(false),
	  m_AbortRequested(false), m_Loaded(false),
	  m_TrackFileViewAdjusting(false),
	  m_TrackFileHideEmptyOverride(false),
	  m_TrackFileHideReusedOverride(false),
	  m_TrackFileHideEmptyValue(false),
	  m_TrackFileHideReusedValue(false)
{
	Qt::WindowFlags Flags = windowFlags();
	Flags |= Qt::CustomizeWindowHint | Qt::WindowMinimizeButtonHint
		| Qt::WindowMaximizeButtonHint;
	setWindowFlags(Flags);
	setWindowFlag(Qt::WindowStaysOnTopHint, theGUI->IsAlwaysOnTop());

	setWindowTitle(tr("%1 - File History").arg(CSandMan::GetBoxDisplayName(pBox)));

	QVBoxLayout* DialogLayout = new QVBoxLayout(this);
	QTabWidget* Tabs = new QTabWidget(this);
	m_pTabs = Tabs;
	QWidget* RetainedVersions = new QWidget(Tabs);
	QVBoxLayout* MainLayout = new QVBoxLayout(RetainedVersions);
	CFileStateHistoryWidget* FileChanges =
		new CFileStateHistoryWidget(pBox, Tabs);
	Tabs->addTab(FileChanges, tr("File Changes"));
	Tabs->addTab(RetainedVersions, tr("Retained Versions"));
	Tabs->addTab(new QWidget(Tabs), tr("Registry Changes"));
	int LastTab = theConf->GetInt("FileHistoryWindow/LastTab", 0);
	if (LastTab >= 0 && LastTab < 2)
		m_LastTab = LastTab;
	Tabs->setCurrentIndex(m_LastTab);
	connect(Tabs, &QTabWidget::currentChanged, this,
		[this, Tabs](int Index) {
			if (Index == 2) {
				emit OpenRegistryHistory();
				Tabs->setCurrentIndex(m_LastTab);
			}
			else if (Index >= 0)
				m_LastTab = Index;
		});
	DialogLayout->addWidget(Tabs);
	QHBoxLayout* ToolLayout = new QHBoxLayout();

	m_pFilterScope = new QComboBox(this);
	m_pFilterScope->addItem(tr("All fields"), eAllFields);
	m_pFilterScope->addItem(tr("Path"), ePathField);
	m_pFilterScope->addItem(tr("Version"), eVersionField);
	m_pFilterScope->addItem(tr("Operation"), eOperationField);
	m_pFilterScope->addItem(tr("Process"), eProcessField);
	m_pFilterScope->addItem(tr("State"), eStateField);
	m_pFilterScope->addItem(tr("Size"), eSizeField);
	m_pFilterScope->addItem(tr("Date"), eDateField);
	m_pFilterScope->addItem(tr("Extension"), eExtensionField);
	m_pFilterScope->addItem(tr("Hash / Blob"), eHashField);
	m_pFinder = new CFinder(this, this, CFinder::eRegExp | CFinder::eCaseSens);
	m_pFinder->SetCloseButtonAtEnd(false);
	QAbstractButton* SearchButton = m_pFinder->GetToggleButton();
	SearchButton->setText(tr("Search"));
	m_pViewOptionsButton = new QToolButton(this);
	m_pViewOptionsButton->setIcon(CSandMan::GetIcon("List"));
	m_pViewOptionsButton->setText(tr("Options"));
	m_pViewOptionsButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
	m_pViewOptionsButton->setCheckable(true);
	m_pViewOptionsButton->setAutoRaise(true);
	m_pViewOptionsButton->setToolTip(
		tr("Show or hide retained file history options."));
	m_pShowModify = new QCheckBox(tr("Modify"), this);
	m_pShowModify->setChecked(
		theConf->GetBool("FileHistoryWindow/ShowModify", true));
	m_pShowModify->setToolTip(
		tr("Show retained versions captured before a file modification."));
	m_pShowDeleteOnClose = new QCheckBox(tr("Delete-on-close"), this);
	m_pShowDeleteOnClose->setChecked(
		theConf->GetBool("FileHistoryWindow/ShowDeleteOnClose", true));
	m_pShowDeleteOnClose->setToolTip(
		tr("Show retained versions captured for delete-on-close operations."));
	m_pShowDelete = new QCheckBox(tr("Delete"), this);
	m_pShowDelete->setChecked(
		theConf->GetBool("FileHistoryWindow/ShowDelete", true));
	m_pShowDelete->setToolTip(
		tr("Show retained versions captured before a file deletion."));
	m_pShowReplace = new QCheckBox(tr("Replace"), this);
	m_pShowReplace->setChecked(
		theConf->GetBool("FileHistoryWindow/ShowReplace", true));
	m_pShowReplace->setToolTip(
		tr("Show retained versions captured before a file replacement."));
	m_pShowMigrate = new QCheckBox(tr("Migrate"), this);
	m_pShowMigrate->setChecked(
		theConf->GetBool("FileHistoryWindow/ShowMigrate", true));
	m_pShowMigrate->setToolTip(
		tr("Show retained versions captured during file migration."));
	m_pShowAvailable = new QCheckBox(tr("Available"), this);
	m_pShowAvailable->setChecked(
		theConf->GetBool("FileHistoryWindow/ShowAvailable", true));
	m_pShowAvailable->setToolTip(
		tr("Show retained versions with available evidence."));
	m_pShowPending = new QCheckBox(tr("Pending"), this);
	m_pShowPending->setChecked(
		theConf->GetBool("FileHistoryWindow/ShowPending", true));
	m_pShowPending->setToolTip(
		tr("Show pending retained versions, including still-live, still-linked, "
			"and still-open evidence."));
	m_pShowFinalized = new QCheckBox(tr("Finalized"), this);
	m_pShowFinalized->setChecked(
		theConf->GetBool("FileHistoryWindow/ShowFinalized", true));
	m_pShowFinalized->setToolTip(
		tr("Show retained versions finalized after a delete-on-close operation."));
	m_pHighlightSame = new QCheckBox(tr("Highlight same"), this);
	m_pHighlightSame->setChecked(
		theConf->GetBool("FileHistoryWindow/HighlightSameHash", true));
	m_pHighlightSame->setToolTip(
		tr("Highlight retained versions matching any selected SHA-256 hash."));
	m_pHideEmpty = new QCheckBox(tr("Hide 0-byte files"), this);
	m_pHideEmpty->setChecked(
		theConf->GetBool("FileHistoryWindow/HideEmptyFiles", true));
	m_pHideEmpty->setToolTip(
		tr("Hide retained evidence with an empty binary file."));
	m_pHideReused = new QCheckBox(tr("Hide reused files"), this);
	m_pHideReused->setChecked(
		theConf->GetBool("FileHistoryWindow/HideReusedFiles", true));
	m_pHideReused->setToolTip(
		tr("Hide retained evidence whose content reuses an existing blob."));
	m_pMergeRenamed = new QCheckBox(tr("Merge renamed paths"), this);
	m_pMergeRenamed->setChecked(
		theConf->GetBool("FileHistoryWindow/MergeRenamedPaths", false));
	m_pMergeRenamed->setToolTip(tr(
		"Group paths that share the same rename-linked per-file limit."));
	m_pGroupByParent = new QCheckBox(tr("Group by parent folder"), this);
	m_pGroupByParent->setChecked(
		theConf->GetBool("FileHistoryWindow/GroupByParentFolder", false));
	m_pGroupByParent->setToolTip(
		tr("Place retained file paths under their immediate parent folder."));
	QWidget* ViewOptionsWidget = new QWidget(this);
	QVBoxLayout* ViewOptionsLayout = new QVBoxLayout(ViewOptionsWidget);
	ViewOptionsLayout->setContentsMargins(0, 0, 0, 0);
	QWidget* TopOptionsRow = new QWidget(ViewOptionsWidget);
	TopOptionsRow->setMinimumHeight(m_pHighlightSame->sizeHint().height());
	QHBoxLayout* TopOptionsLayout = new QHBoxLayout(TopOptionsRow);
	TopOptionsLayout->setContentsMargins(0, 0, 0, 0);
	TopOptionsLayout->addWidget(m_pShowModify);
	TopOptionsLayout->addWidget(m_pShowDeleteOnClose);
	TopOptionsLayout->addWidget(m_pShowDelete);
	TopOptionsLayout->addWidget(m_pShowReplace);
	TopOptionsLayout->addWidget(m_pShowMigrate);
	QFrame* TopSeparator = new QFrame(TopOptionsRow);
	TopSeparator->setFrameShape(QFrame::VLine);
	TopSeparator->setFrameShadow(QFrame::Sunken);
	TopOptionsLayout->addWidget(TopSeparator);
	TopOptionsLayout->addWidget(m_pShowAvailable);
	TopOptionsLayout->addWidget(m_pShowPending);
	TopOptionsLayout->addWidget(m_pShowFinalized);
	TopOptionsLayout->addStretch();
	QWidget* BottomOptionsRow = new QWidget(ViewOptionsWidget);
	QHBoxLayout* BottomOptionsLayout = new QHBoxLayout(BottomOptionsRow);
	BottomOptionsLayout->setContentsMargins(0, 0, 0, 0);
	BottomOptionsLayout->addStretch();
	BottomOptionsLayout->addWidget(m_pHighlightSame);
    QFrame* separator = new QFrame(BottomOptionsRow);
    separator->setFrameShape(QFrame::VLine);
    separator->setFrameShadow(QFrame::Sunken);
	BottomOptionsLayout->addWidget(separator);
	BottomOptionsLayout->addWidget(m_pHideEmpty);
	BottomOptionsLayout->addWidget(m_pHideReused);
    QFrame* separator2 = new QFrame(BottomOptionsRow);
    separator2->setFrameShape(QFrame::VLine);
    separator2->setFrameShadow(QFrame::Sunken);
	BottomOptionsLayout->addWidget(separator2);
	BottomOptionsLayout->addWidget(m_pMergeRenamed);
	BottomOptionsLayout->addWidget(m_pGroupByParent);
	ViewOptionsLayout->addWidget(TopOptionsRow);
	ViewOptionsLayout->addWidget(BottomOptionsRow);
	ViewOptionsWidget->setVisible(false);
	QWidget* LoadControl = new QWidget(this);
	m_pAutoLoad = new QCheckBox(tr("Auto Load"), LoadControl);
	m_pAutoLoad->setChecked(
		theConf->GetBool("FileHistoryWindow/AutoLoad", true));
	m_pAutoLoad->setToolTip(
		tr("Automatically load retained versions when this window opens."));
	m_pLoadIndicator = new QLabel(LoadControl);
	m_pLoadIndicator->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
	m_pLoadIndicator->setMinimumWidth(
		fontMetrics().horizontalAdvance(
			tr("Refreshing... 0000000000 / 0000000000 files")) + 8);
	m_pLoadStack = new QStackedLayout(LoadControl);
	m_pLoadStack->setContentsMargins(0, 0, 0, 0);
	m_pLoadStack->addWidget(m_pAutoLoad);
	m_pLoadStack->addWidget(m_pLoadIndicator);
	m_pLoadStack->setCurrentWidget(m_pAutoLoad);
	m_pRefreshButton = new QPushButton(
		CSandMan::GetIcon("Refresh"), tr("Refresh"), this);
	m_pRefreshButton->setEnabled(false);

	ToolLayout->addWidget(SearchButton);
	ToolLayout->addWidget(m_pFilterScope);
	ToolLayout->addWidget(m_pFinder, 1);
	ToolLayout->addWidget(LoadControl);
	ToolLayout->addWidget(m_pRefreshButton);
	ToolLayout->addWidget(m_pViewOptionsButton);
	MainLayout->addLayout(ToolLayout);
	MainLayout->addWidget(ViewOptionsWidget);

	m_pTree = new QTreeWidgetEx(this);
	m_pTree->setColumnCount(8);
	m_pTree->setHeaderLabels(QStringList()
		<< tr("File / Evidence")
		<< tr("Version")
		<< tr("Captured")
		<< tr("Operation")
		<< tr("State")
		<< tr("Size")
		<< tr("Process")
		<< tr("Hash / Blob"));
	m_pTree->setAlternatingRowColors(theConf->GetBool("Options/AltRowColors", false));
	m_pTree->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_pTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pTree->setUniformRowHeights(true);
	m_pTree->setSortingEnabled(true);
	m_pTree->setExpandsOnDoubleClick(false);
	m_pTree->setContextMenuPolicy(Qt::CustomContextMenu);
	m_pFinder->SetTree(m_pTree);
	MainLayout->addWidget(m_pTree, 1);

	QHBoxLayout* LimitsLayout = new QHBoxLayout();
	m_pLimits = new QLabel(this);
	m_pLimits->setWordWrap(true);
	QPushButton* ConfigureLimitsButton = new QPushButton(
		CSandMan::GetIcon("Settings"),
		tr("Configure Limits and Options..."), this);
	LimitsLayout->addWidget(m_pLimits, 1);
	LimitsLayout->addWidget(ConfigureLimitsButton);
	MainLayout->addLayout(LimitsLayout);

	QHBoxLayout* BottomLayout = new QHBoxLayout();
	m_pStatus = new QLabel(this);
	m_pSelectionStatus = new QLabel(m_pHighlightSame->isChecked()
		? tr("Selected: 0; Highlighted: 0") : tr("Selected: 0"), this);
	m_pSelectionStatus->setToolTip(tr(
		"Visible selected rows and total rows matching any selected SHA-256 "
		"hash, including selected matches."));
	m_pRemoveHistory = new QPushButton(
		CSandMan::GetIcon("Erase"), tr("Remove Retained Versions..."), this);
	m_pOpenFolder = new QPushButton(CSandMan::GetIcon("Folder"), tr("Open Evidence Folder"), this);
	QPushButton* CloseButton = new QPushButton(tr("Close"), this);
	m_pOpenFolder->setEnabled(false);

	BottomLayout->addWidget(m_pStatus, 1);
	BottomLayout->addWidget(m_pSelectionStatus);
	BottomLayout->addWidget(m_pRemoveHistory);
	BottomLayout->addWidget(m_pOpenFolder);
	BottomLayout->addWidget(CloseButton);
	MainLayout->addLayout(BottomLayout);

	connect(m_pRefreshButton, SIGNAL(clicked(bool)), this, SLOT(Reload()));
	connect(m_pViewOptionsButton, &QToolButton::toggled,
		this, [ViewOptionsWidget](bool Expanded) {
			ViewOptionsWidget->setVisible(Expanded);
		});
	connect(m_pHighlightSame, &QCheckBox::toggled,
		this, [this](bool) { UpdateSelection(); });
	for (QCheckBox* Check : { m_pShowModify, m_pShowDeleteOnClose,
			m_pShowDelete, m_pShowReplace, m_pShowMigrate,
			m_pShowAvailable, m_pShowPending, m_pShowFinalized })
		connect(Check, &QCheckBox::toggled,
			this, [this](bool) { ApplyFilter(); });
	connect(m_pHideEmpty, &QCheckBox::toggled,
		this, [this](bool) {
			if (!m_TrackFileViewAdjusting)
				m_TrackFileHideEmptyOverride = false;
			ApplyFilter();
		});
	connect(m_pHideReused, &QCheckBox::toggled,
		this, [this](bool) {
			if (!m_TrackFileViewAdjusting)
				m_TrackFileHideReusedOverride = false;
			ApplyFilter();
		});
	connect(m_pMergeRenamed, &QCheckBox::toggled,
		this, [this](bool) { RebuildTree(true); });
	connect(m_pGroupByParent, &QCheckBox::toggled,
		this, [this](bool) { RebuildTree(true); });
	connect(SearchButton, SIGNAL(toggled(bool)),
		m_pFilterScope, SLOT(setVisible(bool)));
	connect(m_pFilterScope, SIGNAL(currentIndexChanged(int)), this, SLOT(UpdateFilterScope()));
	connect(m_pTree, SIGNAL(itemSelectionChanged()), this, SLOT(UpdateSelection()));
	connect(m_pTree, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)), this, SLOT(OpenEvidenceFolder()));
	connect(m_pTree, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(ShowContextMenu(const QPoint&)));
	connect(m_pTree->header(), SIGNAL(sortIndicatorChanged(int, Qt::SortOrder)),
		this, SLOT(SortHistory(int, Qt::SortOrder)));
	connect(m_pRemoveHistory, SIGNAL(clicked(bool)), this, SLOT(RemoveHistory()));
	connect(m_pOpenFolder, SIGNAL(clicked(bool)), this, SLOT(OpenEvidenceFolder()));
	connect(ConfigureLimitsButton, SIGNAL(clicked(bool)), this, SLOT(ConfigureLimits()));
	connect(CloseButton, SIGNAL(clicked(bool)), this, SLOT(close()));

	m_pCopyCell = new QAction(CPanelView::m_CopyCell, this);
	m_pCopyRow = new QAction(CPanelView::m_CopyRow, this);
	m_pCopyPanel = new QAction(CPanelView::m_CopyPanel, this);
	m_pCopyRow->setShortcut(QKeySequence::Copy);
	m_pCopyRow->setShortcutContext(Qt::WidgetWithChildrenShortcut);
	addAction(m_pCopyRow);
	connect(m_pCopyCell, SIGNAL(triggered(bool)), this, SLOT(CopyCell()));
	connect(m_pCopyRow, SIGNAL(triggered(bool)), this, SLOT(CopyRow()));
	connect(m_pCopyPanel, SIGNAL(triggered(bool)), this, SLOT(CopyPanel()));

	QAction* ResizeColumnsAction = new QAction(
		tr("Resize All Columns to Contents"), this);
	ResizeColumnsAction->setShortcut(
		QKeySequence(QStringLiteral("Ctrl+Shift++")));
	ResizeColumnsAction->setShortcutContext(Qt::WidgetWithChildrenShortcut);
	addAction(ResizeColumnsAction);
	connect(ResizeColumnsAction, &QAction::triggered, this,
		[this, Tabs, FileChanges]() {
			if (Tabs->currentWidget() == FileChanges)
				FileChanges->ResizeColumns();
			else
				ResizeColumns();
		});

	QByteArray Geometry = theConf->GetBlob("FileHistoryWindow/Window_Geometry");
	if (Geometry.isEmpty())
		resize(1100, 600);
	else
		restoreGeometry(Geometry);
	if (!m_pTree->header()->restoreState(
			theConf->GetBlob("FileHistoryWindow/Tree_Columns"))) {
		m_pTree->setColumnWidth(0, 400);
		m_pTree->setColumnWidth(1, 80);
		m_pTree->setColumnWidth(2, 180);
		m_pTree->setColumnWidth(3, 110);
		m_pTree->setColumnWidth(4, 160);
		m_pTree->setColumnWidth(5, 90);
		m_pTree->setColumnWidth(7, 300);
	}

	connect(FileChanges, &CFileStateHistoryWidget::TrackFiles, this,
		[this, Tabs, RetainedVersions](const QStringList& Hashes,
			const QStringList& FileNames) {
			QDir RetainedArtifacts(QDir(m_pBox->GetFileRoot()).filePath(
				"FileHistory\\Artifacts"));
			if (!m_pBox->GetBool("FileHistory", true, true, true) ||
					!RetainedArtifacts.exists() ||
					RetainedArtifacts.entryList(
						QDir::Dirs | QDir::NoDotAndDotDot).isEmpty()) {
				QMessageBox::information(this, tr("Retained File Versions"), tr(
					"Retained file history is disabled or no retained evidence "
					"exists for this sandbox."));
				return;
			}
			QStringList Values = Hashes;
			for (const QString& FileName : FileNames)
				AppendUniqueCaseInsensitive(Values, FileName);
			QString Expression;
			HistoryWindowUtils::EFilterBuildResult Result =
				HistoryWindowUtils::BuildSelectionFilter(
					Values, false, Expression);
			if (Result == HistoryWindowUtils::eFilterTooLarge) {
				QMessageBox::warning(this, tr("Retained File Versions"), tr(
					"The selected hashes and file names are too large to create "
					"a safe regular-expression filter."));
				return;
			}
			if (Result != HistoryWindowUtils::eFilterReady)
				return;
			Tabs->setCurrentWidget(RetainedVersions);
			PrepareTrackFileView();
			int Scope = Hashes.isEmpty() ? ePathField
				: FileNames.isEmpty() ? eHashField : eAllFields;
			int ScopeIndex = m_pFilterScope->findData(Scope);
			if (ScopeIndex >= 0)
				m_pFilterScope->setCurrentIndex(ScopeIndex);
			m_SelectionExcludePattern.clear();
			m_pFinder->SetSearchText(Expression, true);
		});

	m_pFinder->Open();
	if (m_pAutoLoad->isChecked())
		QTimer::singleShot(100, this, SLOT(Reload()));
}


CFileHistoryWindow::~CFileHistoryWindow()
{
	theConf->SetBlob("FileHistoryWindow/Window_Geometry", saveGeometry());
	theConf->SetBlob("FileHistoryWindow/Tree_Columns", m_pTree->header()->saveState());
	theConf->SetValue("FileHistoryWindow/LastTab", m_LastTab);
	theConf->SetValue("FileHistoryWindow/HideEmptyFiles",
		m_TrackFileHideEmptyOverride ? m_TrackFileHideEmptyValue
			: m_pHideEmpty->isChecked());
	theConf->SetValue("FileHistoryWindow/HideReusedFiles",
		m_TrackFileHideReusedOverride ? m_TrackFileHideReusedValue
			: m_pHideReused->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/MergeRenamedPaths", m_pMergeRenamed->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/GroupByParentFolder", m_pGroupByParent->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/HighlightSameHash", m_pHighlightSame->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/ShowModify", m_pShowModify->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/ShowDeleteOnClose",
		m_pShowDeleteOnClose->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/ShowDelete", m_pShowDelete->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/ShowReplace", m_pShowReplace->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/ShowMigrate", m_pShowMigrate->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/ShowAvailable", m_pShowAvailable->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/ShowPending", m_pShowPending->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/ShowFinalized", m_pShowFinalized->isChecked());
	theConf->SetValue("FileHistoryWindow/AutoLoad", m_pAutoLoad->isChecked());
}

void CFileHistoryWindow::SetProgressVisible(bool Visible)
{
	if (Visible)
		m_pLoadStack->setCurrentWidget(m_pLoadIndicator);
	else
		m_pLoadStack->setCurrentWidget(m_pAutoLoad);
}


void CFileHistoryWindow::SetHistoryTab(int Index)
{
	if (Index < 0 || Index >= 2)
		return;
	m_pTabs->setCurrentIndex(Index);
}


void CFileHistoryWindow::closeEvent(QCloseEvent* e)
{
	Q_UNUSED(e);
	emit Closed();
	deleteLater();
}


void CFileHistoryWindow::Reload()
{
	if (m_Loading) {
		m_AbortRequested = true;
		return;
	}

	m_AbortRequested = false;
	m_Loading = true;
	m_pRefreshButton->setIcon(CSandMan::GetIcon("Stop"));
	m_pRefreshButton->setText(tr("Abort"));
	m_pRefreshButton->setEnabled(true);
	m_pViewOptionsButton->setEnabled(false);
	m_pMergeRenamed->setEnabled(false);
	m_pGroupByParent->setEnabled(false);
	SetProgressVisible(true);
	m_pLoadIndicator->setText(
		m_Loaded ? tr("Refreshing...") : tr("Loading..."));
	m_pLoadIndicator->repaint();
	m_pRefreshButton->repaint();
	auto AbortReload = [this]() {
		for (QTreeWidgetItem* Item : m_EvidenceItems)
			delete Item;
		m_EvidenceItems.clear();
		m_PathLineages.clear();
		m_pTree->setSortingEnabled(true);
		m_pLoadIndicator->clear();
		SetProgressVisible(false);
		m_pStatus->setText(tr("Refresh aborted."));
		m_pRefreshButton->setIcon(CSandMan::GetIcon("Refresh"));
		m_pRefreshButton->setText(tr("Refresh"));
		m_pRefreshButton->setEnabled(true);
		m_pViewOptionsButton->setEnabled(true);
		m_pMergeRenamed->setEnabled(true);
		m_pGroupByParent->setEnabled(true);
		m_AbortRequested = false;
		m_Loading = false;
	};

	QSet<QString> CollapsedItems;
	bool HadParents = m_pTree->topLevelItemCount() > 0;
	foreach(QTreeWidgetItem* Item, TreeItems(m_pTree)) {
		if (Item->data(0, eIsEvidence).toBool() || Item->isExpanded())
			continue;
		QString Prefix = Item->data(0, eIsGroup).toBool()
			? QStringLiteral("group:") : QStringLiteral("path:");
		CollapsedItems.insert(
			Prefix + Item->data(0, eLogicalPath).toString().toLower());
	}
	m_EvidenceItems.clear();
	m_PathLineages.clear();
	m_pTree->setSortingEnabled(false);
	m_pTree->clear();

	quint64 MaxVersions = qMax(0,
		m_pBox->GetNum("FileHistoryMaxVersionsTotal", 2500, true, true));
	quint64 MaxVersionsPerFile = qMax(0,
		m_pBox->GetNum(
			"FileHistoryMaxVersionsPerFile", 25, true, true));
	quint64 MaxSizeKB = qMax<qint64>(0,
		m_pBox->GetNum64(
			"FileHistoryMaxSizeTotalKB", 1024 * 1024, true, true));
	quint64 MaxFileSizeKB = qMax<qint64>(0,
		m_pBox->GetNum64("FileHistoryMaxFileSizeKB", 10 * 1024, true, true));
	QString HistoryPath = QDir::cleanPath(
		m_pBox->GetFileRoot() + "\\FileHistory");
	QCoreApplication::processEvents(QEventLoop::AllEvents);
	if (m_AbortRequested) {
		AbortReload();
		return;
	}
	if (m_pBox->GetActiveProcessCount() == 0)
		RemoveOrphanedBlobs(HistoryPath);
	QCoreApplication::processEvents(QEventLoop::AllEvents);
	if (m_AbortRequested) {
		AbortReload();
		return;
	}
	QString ArtifactsPath = QDir::cleanPath(HistoryPath + "\\Artifacts");
	QDir Artifacts(ArtifactsPath);
	QFileInfoList ArtifactList = Artifacts.entryInfoList(
		QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks,
		QDir::Name);
	int ArtifactCount = 0;
	foreach(const QFileInfo& ArtifactInfo, ArtifactList) {
		if (IsArtifactId(ArtifactInfo.fileName()))
			++ArtifactCount;
	}
	int ArtifactIndex = 0;
	QString LoadPrefix = m_Loaded
		? tr("Refreshing...") : tr("Loading...");
	m_pLoadIndicator->setText(
		tr("%1 0 / %2 files").arg(LoadPrefix).arg(ArtifactCount));
	m_pLoadIndicator->repaint();
	QCoreApplication::processEvents(QEventLoop::AllEvents);
	if (m_AbortRequested) {
		AbortReload();
		return;
	}
	m_PathLineages = ReadPathLineages(HistoryPath);
	QCoreApplication::processEvents(QEventLoop::AllEvents);
	if (m_AbortRequested) {
		AbortReload();
		return;
	}
	quint64 UsedVersions = 0;
	quint64 AccountedSize = 0;
	quint64 StoredSize = 0;
	auto AddSize = [](quint64& Total, quint64 Size) {
		const quint64 MaximumSize = ~quint64(0);
		Total = Size > MaximumSize - Total ? MaximumSize : Total + Size;
	};

	foreach(const QFileInfo& ArtifactInfo, ArtifactList) {
		if (!IsArtifactId(ArtifactInfo.fileName()))
			continue;
		++ArtifactIndex;
		if (ArtifactIndex == 1 || ArtifactIndex == ArtifactCount ||
				(ArtifactIndex % 16) == 0) {
			m_pLoadIndicator->setText(
				tr("%1 %2 / %3 files")
					.arg(LoadPrefix).arg(ArtifactIndex).arg(ArtifactCount));
			m_pLoadIndicator->repaint();
		}
		QCoreApplication::processEvents(QEventLoop::AllEvents);
		if (m_AbortRequested) {
			AbortReload();
			return;
		}

		QDir ArtifactDir(ArtifactInfo.absoluteFilePath());
		QMap<QString, SHistoryFilePair> Pairs;

		foreach(const QFileInfo& FileInfo,
				ArtifactDir.entryInfoList(
					QStringList() << "*.bin" << "*.txt",
					QDir::Files | QDir::NoSymLinks,
					QDir::Name)) {
			QString BaseName = FileInfo.completeBaseName();
			SHistoryFilePair& Pair = Pairs[BaseName];
			if (FileInfo.suffix().compare("bin", Qt::CaseInsensitive) == 0)
				Pair.BinaryPath = FileInfo.absoluteFilePath();
			else
				Pair.MetadataPath = FileInfo.absoluteFilePath();
		}

		for (auto PairIt = Pairs.constBegin(); PairIt != Pairs.constEnd(); ++PairIt) {
			QCoreApplication::processEvents(QEventLoop::AllEvents);
			if (m_AbortRequested) {
				AbortReload();
				return;
			}
			const SHistoryFilePair& Pair = PairIt.value();
			QMap<QString, QString> Fields;
			bool MetadataValid = !Pair.MetadataPath.isEmpty()
				&& ReadMetadata(Pair.MetadataPath, Fields);

			QString TruePath;
			QString LogicalPath;
			if (MetadataValid) {
				TruePath = UnescapeField(Fields.value("path"));
				LogicalPath = UnescapeField(Fields.value("dos_path"));
				if (LogicalPath.isEmpty())
					LogicalPath = UnescapeField(Fields.value("path"));
			}
			if (LogicalPath.isEmpty())
				LogicalPath = tr("(Unknown path) [%1]").arg(ArtifactInfo.fileName());

			QString Lineage = m_PathLineages.value(LogicalPath.toLower());
			QTreeWidgetItem* Item = new CHistoryTreeItem();
			m_EvidenceItems.append(Item);
			Item->setData(0, eLineage, Lineage);
			QString State = Fields.value("state");
			bool Pending = PairIt.key().compare("pending", Qt::CaseInsensitive) == 0
				|| State.startsWith("still-", Qt::CaseInsensitive)
				|| State.compare("pending", Qt::CaseInsensitive) == 0;
			Item->setText(0, Pending ? tr("Pending version") : tr("Captured version"));

			QString Captured = FormatFileTime(Fields.value("timestamp"));
			if (Captured.isEmpty()) {
				QFileInfo TimeInfo(!Pair.BinaryPath.isEmpty()
					? Pair.BinaryPath : Pair.MetadataPath);
				Captured = TimeInfo.lastModified().toString(
					QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
			}
			Item->setText(2, Captured);
			QDateTime CapturedDate = QDateTime::fromString(
				Captured, QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
			if (CapturedDate.isValid())
				Item->setData(2, eSortValue,
					(quint64)CapturedDate.toMSecsSinceEpoch());
			Item->setText(3, Fields.value("operation"));
			Item->setText(4, State.isEmpty() ? tr("Available") : State);
			bool Reused = Fields.value("content_reused").compare(
				"y", Qt::CaseInsensitive) == 0;

			bool SizeOk = false;
			quint64 Size = 0;
			if (!Pair.BinaryPath.isEmpty()) {
				qint64 BinarySize = QFileInfo(Pair.BinaryPath).size();
				Size = BinarySize > 0 ? (quint64)BinarySize : 0;
				SizeOk = true;
				Item->setData(0, eIsEmpty, BinarySize == 0);
				if (Size)
					++UsedVersions;
				AddSize(AccountedSize, Size);
				if (!Reused)
					AddSize(StoredSize, Size);
			}
			else
				Size = Fields.value("size").toULongLong(&SizeOk);
			if (SizeOk) {
				Item->setText(5, FormatSize(Size));
				Item->setData(5, eSortValue, Size);
			}

			QString ProcessName = UnescapeField(Fields.value("image"));
			QString Process = ProcessName;
			QString Pid = Fields.value("pid");
			if (!Pid.isEmpty())
				Process += Process.isEmpty() ? tr("PID %1").arg(Pid) : tr(" (PID %1)").arg(Pid);
			Item->setText(6, Process);

			QString EvidencePath = !Pair.BinaryPath.isEmpty()
				? Pair.BinaryPath : Pair.MetadataPath;
			Item->setData(0, eFolderPath, QFileInfo(EvidencePath).absolutePath());
			Item->setData(0, eBinaryPath, Pair.BinaryPath);
			Item->setData(0, eMetadataPath, Pair.MetadataPath);
			Item->setData(0, eLogicalPath, LogicalPath);
			Item->setData(0, eTruePath, TruePath);
			Item->setData(0, eOperation, Item->text(3));
			Item->setData(0, eProcess, Item->text(6));
			Item->setData(0, eState, Item->text(4));
			Item->setData(0, eSize, Item->text(5));
			Item->setData(0, eDate, Item->text(2));
			Item->setData(0, eExtension, QFileInfo(LogicalPath).suffix());
			Item->setData(0, eProcessName, ProcessName);
			Item->setData(0, eIsReused, Reused);
			Item->setData(0, eIsPending, Pending);
			QString Hash = Fields.value("sha256");
			if (IsSha256(Hash)) {
				QString BlobPath = QDir::cleanPath(
					HistoryPath + "\\Blobs\\" + Hash + ".bin");
				bool BlobAvailable = QFileInfo::exists(BlobPath);
				QString HashDisplay = Hash;
				if (BlobAvailable)
					HashDisplay += Reused
						? tr(" (reused blob)") : tr(" (blob)");
				Item->setText(7, HashDisplay);
				Item->setData(0, eHashValue, Hash);
				Item->setData(0, eHash, HashDisplay);
				Item->setToolTip(7,
					tr("SHA-256: %1\nBlob: %2\nContent reused: %3")
						.arg(Hash)
						.arg(BlobAvailable ? BlobPath : tr("(not available)"))
						.arg(Reused ? tr("yes") : tr("no")));
			}
			Item->setData(0, eIsEvidence, true);
			Item->setToolTip(0, tr("Artifact: %1\nBinary: %2\nMetadata: %3")
				.arg(ArtifactInfo.fileName(),
					Pair.BinaryPath.isEmpty() ? tr("(missing)") : Pair.BinaryPath,
					Pair.MetadataPath.isEmpty() ? tr("(missing)") : Pair.MetadataPath));
			if (Pair.BinaryPath.isEmpty())
				Item->setText(4, State.isEmpty() ? tr("Metadata only") : State + tr(" (metadata only)"));
			else if (!MetadataValid)
				Item->setText(4, tr("Missing or invalid metadata"));
			Item->setData(0, eState, Item->text(4));
		}
	}

	RebuildTree(false);
	foreach(QTreeWidgetItem* Item, TreeItems(m_pTree)) {
		if (Item->data(0, eIsEvidence).toBool())
			continue;
		QString Prefix = Item->data(0, eIsGroup).toBool()
			? QStringLiteral("group:") : QStringLiteral("path:");
		Item->setExpanded(!HadParents || !CollapsedItems.contains(
			Prefix + Item->data(0, eLogicalPath).toString().toLower()));
	}
	ApplyFilter();
	m_pLimits->setText(tr("Usage / limits: %1 / %2 non-empty versions; "
		"%3 / %4 limit-accounted size; %5 stored after content reuse. "
		"Limits: %6 non-empty versions per file; %7 per capture.")
		.arg(QString::number(UsedVersions))
		.arg(FormatCountLimit(MaxVersions))
		.arg(FormatSize(AccountedSize))
		.arg(FormatLimitKB(MaxSizeKB))
		.arg(FormatSize(StoredSize))
		.arg(FormatCountLimit(MaxVersionsPerFile))
		.arg(FormatLimitKB(MaxFileSizeKB)));
	m_pRemoveHistory->setEnabled(QDir(HistoryPath).exists());
	m_pLoadIndicator->clear();
	SetProgressVisible(false);
	m_pRefreshButton->setIcon(CSandMan::GetIcon("Refresh"));
	m_pRefreshButton->setText(tr("Refresh"));
	m_pRefreshButton->setEnabled(true);
	m_pViewOptionsButton->setEnabled(true);
	m_pMergeRenamed->setEnabled(true);
	m_pGroupByParent->setEnabled(true);
	m_Loading = false;
	m_Loaded = true;
}


void CFileHistoryWindow::RebuildTree(bool PreserveState)
{
	int SortColumn = m_pTree->header()->sortIndicatorSection();
	Qt::SortOrder SortOrder = m_pTree->header()->sortIndicatorOrder();
	if (SortColumn < 0 || SortColumn >= m_pTree->columnCount()) {
		SortColumn = 0;
		SortOrder = Qt::AscendingOrder;
	}
	QSet<QString> CollapsedGroups;
	QSet<QString> CollapsedPaths;
	QSet<QString> SelectedGroups;
	QSet<QString> SelectedPaths;
	QSet<QString> SelectedGroupPaths;
	QSet<QTreeWidgetItem*> SelectedEvidence;
	QTreeWidgetItem* CurrentEvidence = NULL;
	QString CurrentGroup;
	QString CurrentPath;
	QString CurrentGroupPath;
	if (PreserveState) {
		QTreeWidgetItem* CurrentItem = m_pTree->currentItem();
		if (CurrentItem) {
			if (CurrentItem->data(0, eIsEvidence).toBool())
				CurrentEvidence = CurrentItem;
			else if (CurrentItem->data(0, eIsGroup).toBool()) {
				CurrentGroup = CurrentItem->data(
					0, eLogicalPath).toString().toLower();
				if (CurrentItem->childCount() > 0)
					CurrentGroupPath = CurrentItem->child(0)->data(
						0, eLogicalPath).toString().toLower();
			}
			else
				CurrentPath = CurrentItem->data(
					0, eLogicalPath).toString().toLower();
		}
		foreach(QTreeWidgetItem* Item, TreeItems(m_pTree)) {
			if (Item->data(0, eIsEvidence).toBool()) {
				if (Item->isSelected())
					SelectedEvidence.insert(Item);
				continue;
			}
			if (Item->data(0, eIsGroup).toBool()) {
				QString Group = Item->data(
					0, eLogicalPath).toString().toLower();
				if (!Item->isExpanded())
					CollapsedGroups.insert(Group);
				if (Item->isSelected())
					SelectedGroups.insert(Group);
				if (Item->isSelected()) {
					for (int Index = 0; Index < Item->childCount(); ++Index) {
						QTreeWidgetItem* PathItem = Item->child(Index);
						for (int ChildIndex = 0;
								ChildIndex < PathItem->childCount(); ++ChildIndex) {
							SelectedGroupPaths.insert(PathItem->child(
								ChildIndex)->data(
									0, eLogicalPath).toString().toLower());
						}
					}
				}
				continue;
			}
			for (int Index = 0; Index < Item->childCount(); ++Index) {
				QString Path = Item->child(Index)->data(
					0, eLogicalPath).toString().toLower();
				if (!Item->isExpanded())
					CollapsedPaths.insert(Path);
				if (Item->isSelected())
					SelectedPaths.insert(Path);
			}
		}
	}

	bool SignalsBlocked = m_pTree->blockSignals(true);
	bool HeaderSignalsBlocked = m_pTree->header()->blockSignals(true);
	m_pTree->setSortingEnabled(false);
	foreach(QTreeWidgetItem* Item, m_EvidenceItems) {
		QTreeWidgetItem* Parent = Item->parent();
		if (Parent)
			Parent->takeChild(Parent->indexOfChild(Item));
		else {
			int Index = m_pTree->indexOfTopLevelItem(Item);
			if (Index >= 0)
				m_pTree->takeTopLevelItem(Index);
		}
	}
	m_pTree->clear();

	QMap<QString, QTreeWidgetItem*> PathItems;
	foreach(QTreeWidgetItem* Item, m_EvidenceItems) {
		QString LogicalPath = Item->data(0, eLogicalPath).toString();
		QString PathKey = LogicalPath.toLower();
		QString Lineage = Item->data(0, eLineage).toString();
		QString GroupKey = !m_pMergeRenamed->isChecked() || Lineage.isEmpty()
			? QStringLiteral("path:") + PathKey
			: QStringLiteral("lineage:") + Lineage;
		QTreeWidgetItem* PathItem = PathItems.value(GroupKey);
		if (!PathItem) {
			PathItem = new CHistoryTreeItem(m_pTree);
			PathItem->setText(0, LogicalPath);
			PathItem->setData(0, Qt::ToolTipRole, LogicalPath);
			PathItem->setIcon(0, CSandMan::GetIcon("File"));
			PathItem->setData(0, eFolderPath,
				Item->data(0, eFolderPath));
			PathItem->setData(0, eLogicalPath, LogicalPath);
			PathItem->setData(0, eExtension,
				QFileInfo(LogicalPath).suffix());
			PathItem->setData(0, eIsEvidence, false);
			PathItem->setData(0, eIsGroup, false);
			PathItem->setData(0, eLineage, Lineage);
			PathItems.insert(GroupKey, PathItem);
		}
		PathItem->addChild(Item);
	}

	auto AddSize = [](quint64& Total, quint64 Size) {
		const quint64 MaximumSize = ~quint64(0);
		Total = Size > MaximumSize - Total ? MaximumSize : Total + Size;
	};
	for (auto ItemIt = PathItems.constBegin();
			ItemIt != PathItems.constEnd(); ++ItemIt) {
		QTreeWidgetItem* Item = ItemIt.value();
		quint64 LatestDate = 0;
		quint64 AccountedPathSize = 0;
		quint64 StoredPathSize = 0;
		QString LatestPath = Item->data(0, eLogicalPath).toString();
		QSet<QString> LogicalPaths;
		bool HasSize = false;
		for (int ChildIndex = 0; ChildIndex < Item->childCount(); ++ChildIndex) {
			QTreeWidgetItem* Child = Item->child(ChildIndex);
			quint64 ChildDate = Child->data(2, eSortValue).toULongLong();
			QString ChildPath = Child->data(0, eLogicalPath).toString();
			if (!ChildPath.isEmpty())
				LogicalPaths.insert(ChildPath);
			if (ChildDate >= LatestDate && !ChildPath.isEmpty()) {
				LatestDate = ChildDate;
				LatestPath = ChildPath;
				Item->setData(0, eFolderPath,
					Child->data(0, eFolderPath));
			}
			if (Child->data(5, eSortValue).isValid()) {
				quint64 ChildSize =
					Child->data(5, eSortValue).toULongLong();
				if (!Child->data(0, eBinaryPath).toString().isEmpty()) {
					AddSize(AccountedPathSize, ChildSize);
					if (!Child->data(0, eIsReused).toBool())
						AddSize(StoredPathSize, ChildSize);
				}
				HasSize = true;
			}
		}
		Item->setText(1, QString::number(Item->childCount()));
		Item->setData(1, eSortValue, Item->childCount());
		if (!Item->data(0, eLineage).toString().isEmpty()
				&& LogicalPaths.size() > 1) {
			QStringList Paths = LogicalPaths.values();
			Paths.sort(Qt::CaseInsensitive);
			Item->setText(0, LatestPath);
			Item->setData(0, eLogicalPath, LatestPath);
			Item->setData(0, eExtension, QFileInfo(LatestPath).suffix());
			Item->setToolTip(0,
				tr("Rename-linked paths:\n%1")
					.arg(Paths.join(QLatin1Char('\n'))));
		}
		if (LatestDate) {
			Item->setData(2, eSortValue, LatestDate);
			Item->setText(2, QDateTime::fromMSecsSinceEpoch(
				(qint64)LatestDate).toString(
					QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")));
		}
		if (HasSize) {
			Item->setData(5, eSortValue, StoredPathSize);
			Item->setText(5, FormatSize(StoredPathSize));
			if (StoredPathSize != AccountedPathSize)
				Item->setToolTip(5,
					tr("Stored size: %1\nLimit-accounted size: %2")
						.arg(FormatSize(StoredPathSize))
						.arg(FormatSize(AccountedPathSize)));
		}
	}

	if (m_pGroupByParent->isChecked()) {
		QMap<QString, QTreeWidgetItem*> FolderItems;
		for (auto ItemIt = PathItems.constBegin();
				ItemIt != PathItems.constEnd(); ++ItemIt) {
			QTreeWidgetItem* PathItem = ItemIt.value();
			QString FolderPath = QDir::toNativeSeparators(
				QFileInfo(PathItem->data(0, eLogicalPath).toString()).path());
			if (FolderPath == QStringLiteral("."))
				FolderPath = tr("(No parent folder)");
			QString FolderKey = FolderPath.toLower();
			QTreeWidgetItem* FolderItem = FolderItems.value(FolderKey);
			if (!FolderItem) {
				FolderItem = new CHistoryTreeItem(m_pTree);
				FolderItem->setText(0, FolderPath);
				FolderItem->setIcon(0, CSandMan::GetIcon("Folder"));
				FolderItem->setData(0, eLogicalPath, FolderPath);
				FolderItem->setData(0, eIsEvidence, false);
				FolderItem->setData(0, eIsGroup, true);
				FolderItems.insert(FolderKey, FolderItem);
			}
			int TopIndex = m_pTree->indexOfTopLevelItem(PathItem);
			if (TopIndex >= 0)
				FolderItem->addChild(m_pTree->takeTopLevelItem(TopIndex));
		}
        for (auto FolderIt = FolderItems.constBegin();
                FolderIt != FolderItems.constEnd(); ++FolderIt) {
            QTreeWidgetItem* FolderItem = FolderIt.value();
            int Versions = 0;
            quint64 LatestDate = 0;
            quint64 StoredFolderSize = 0;
            QString EvidenceFolder;
            for (int Index = 0; Index < FolderItem->childCount(); ++Index) {
                QTreeWidgetItem* PathItem = FolderItem->child(Index);
                Versions += PathItem->childCount();
                quint64 PathDate = PathItem->data(2,
                    eSortValue).toULongLong();
                if (PathDate >= LatestDate) {
                    LatestDate = PathDate;
                    EvidenceFolder = PathItem->data(
                        0, eFolderPath).toString();
                }
                AddSize(StoredFolderSize,
                    PathItem->data(5, eSortValue).toULongLong());
            }
            FolderItem->setData(0, eFolderPath, EvidenceFolder);
            FolderItem->setText(1, QString::number(Versions));
			FolderItem->setData(1, eSortValue, Versions);
			FolderItem->setText(5, FormatSize(StoredFolderSize));
			FolderItem->setData(5, eSortValue, StoredFolderSize);
			if (LatestDate) {
				FolderItem->setText(2, QDateTime::fromMSecsSinceEpoch(
					(qint64)LatestDate).toString(
						QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")));
				FolderItem->setData(2, eSortValue, LatestDate);
			}
			FolderItem->setData(0, Qt::ToolTipRole,
				tr("%1\nContains %2 retained file path(s).")
					.arg(FolderItem->text(0))
					.arg(FolderItem->childCount()));
		}
	}

	for (auto ItemIt = PathItems.constBegin();
			ItemIt != PathItems.constEnd(); ++ItemIt) {
		QTreeWidgetItem* PathItem = ItemIt.value();
		PathItem->sortChildren(2, Qt::DescendingOrder);
		for (int ChildIndex = 0;
				ChildIndex < PathItem->childCount(); ++ChildIndex) {
			QTreeWidgetItem* Child = PathItem->child(ChildIndex);
			int Version = PathItem->childCount() - ChildIndex;
			Child->setText(1, QString::number(Version));
			Child->setData(1, eSortValue, Version);
		}
	}
	m_pTree->setSortingEnabled(true);
	m_pTree->sortItems(SortColumn, SortOrder);
	SortHistory(SortColumn, SortOrder);

	if (PreserveState) {
		QTreeWidgetItem* RestoredCurrent = NULL;
		foreach(QTreeWidgetItem* Item, TreeItems(m_pTree)) {
			if (Item->data(0, eIsEvidence).toBool()) {
				Item->setSelected(SelectedEvidence.contains(Item));
				if (Item == CurrentEvidence)
					RestoredCurrent = Item;
				continue;
			}
			if (Item->data(0, eIsGroup).toBool()) {
				QString Group = Item->data(
					0, eLogicalPath).toString().toLower();
				Item->setExpanded(!CollapsedGroups.contains(Group));
				Item->setSelected(SelectedGroups.contains(Group));
				if (!CurrentGroup.isEmpty() && Group == CurrentGroup)
					RestoredCurrent = Item;
				continue;
			}
			bool Collapsed = false;
			bool Selected = false;
			for (int Index = 0; Index < Item->childCount(); ++Index) {
				QString Path = Item->child(Index)->data(
					0, eLogicalPath).toString().toLower();
				Collapsed |= CollapsedPaths.contains(Path);
				Selected |= SelectedPaths.contains(Path);
				Selected |= !m_pGroupByParent->isChecked()
					&& SelectedGroupPaths.contains(Path);
				if (!CurrentPath.isEmpty() && Path == CurrentPath)
					RestoredCurrent = Item;
				if (!m_pGroupByParent->isChecked()
						&& !CurrentGroupPath.isEmpty()
						&& Path == CurrentGroupPath)
					RestoredCurrent = Item;
			}
			Item->setExpanded(!Collapsed);
			Item->setSelected(Selected);
		}
		if (RestoredCurrent)
			m_pTree->setCurrentItem(
				RestoredCurrent, 0, QItemSelectionModel::NoUpdate);
	}
	m_pTree->blockSignals(SignalsBlocked);
	m_pTree->header()->blockSignals(HeaderSignalsBlocked);
	if (PreserveState)
		ApplyFilter();
}


void CFileHistoryWindow::ResizeColumns()
{
	for (int Column = 0; Column < m_pTree->columnCount(); ++Column)
		m_pTree->resizeColumnToContents(Column);
}


void CFileHistoryWindow::SortHistory(int Column, Qt::SortOrder Order)
{
	if (!m_pTree->isSortingEnabled())
		return;

	m_pTree->invisibleRootItem()->sortChildren(Column, Order);
	for (int Index = 0; Index < m_pTree->topLevelItemCount(); ++Index)
		SortTreeChildren(m_pTree->topLevelItem(Index), Column, Order);
}


void CFileHistoryWindow::SetFilter(
	const QRegularExpression& RegExp, int Options, int Column)
{
	Q_UNUSED(Options);
	Q_UNUSED(Column);

	m_FilterExp = RegExp;
	ApplyFilter();
}


void CFileHistoryWindow::UpdateFilterScope()
{
	ApplyFilter();
}


void CFileHistoryWindow::ApplyFilter()
{
	int Scope = m_pFilterScope->currentData().toInt();
	bool FilterEmpty = m_FilterExp.pattern().isEmpty();
	bool HideEmpty = m_pHideEmpty->isChecked();
	bool HideReused = m_pHideReused->isChecked();
	bool SelectionExclude = !m_SelectionExcludePattern.isEmpty()
		&& m_FilterExp.pattern() == m_SelectionExcludePattern;
	int TotalFiles = 0;
	int TotalEvidence = 0;
	int ListedFiles = 0;
	int ListedEvidence = 0;
	int EmptyEvidence = 0;
	int ReusedEvidence = 0;

	QList<QTreeWidgetItem*> Groups;
	QList<QTreeWidgetItem*> Paths;
	foreach(QTreeWidgetItem* Item, TreeItems(m_pTree)) {
		if (Item->data(0, eIsEvidence).toBool())
			continue;
		if (Item->data(0, eIsGroup).toBool())
			Groups.append(Item);
		else
			Paths.append(Item);
	}
	TotalFiles = Paths.count();

	foreach(QTreeWidgetItem* PathItem, Paths) {
		TotalEvidence += PathItem->childCount();
		QTreeWidgetItem* GroupItem = PathItem->parent();
		bool GroupMatches = GroupItem && !FilterEmpty
			&& m_FilterExp.match(FilterValue(GroupItem, Scope)).hasMatch();
		bool PathMatches = FilterEmpty
			|| GroupMatches
			|| m_FilterExp.match(FilterValue(PathItem, Scope)).hasMatch();
		bool ChildMatches = false;

		for (int ChildIndex = 0; ChildIndex < PathItem->childCount(); ++ChildIndex) {
			QTreeWidgetItem* Child = PathItem->child(ChildIndex);
			QString Operation = Child->data(0, eOperation).toString();
			bool OperationMatches = true;
			if (Operation.compare("modify", Qt::CaseInsensitive) == 0)
				OperationMatches = m_pShowModify->isChecked();
			else if (Operation.compare("delete-on-close",
					Qt::CaseInsensitive) == 0)
				OperationMatches = m_pShowDeleteOnClose->isChecked();
			else if (Operation.compare("delete", Qt::CaseInsensitive) == 0)
				OperationMatches = m_pShowDelete->isChecked();
			else if (Operation.compare("replace", Qt::CaseInsensitive) == 0)
				OperationMatches = m_pShowReplace->isChecked();
			else if (Operation.compare("migrate", Qt::CaseInsensitive) == 0)
				OperationMatches = m_pShowMigrate->isChecked();
			QString State = Child->data(0, eState).toString();
			bool StateMatches = true;
			if (Child->data(0, eIsPending).toBool())
				StateMatches = m_pShowPending->isChecked();
			else if (State.startsWith("finalized", Qt::CaseInsensitive))
				StateMatches = m_pShowFinalized->isChecked();
			else if (State.compare(tr("Available"),
					Qt::CaseInsensitive) == 0)
				StateMatches = m_pShowAvailable->isChecked();
			bool IsEmpty = Child->data(0, eIsEmpty).toBool();
			bool IsReused = Child->data(0, eIsReused).toBool();
			if (IsEmpty)
				++EmptyEvidence;
			if (IsReused)
				++ReusedEvidence;
			bool Match = !HideEmpty
				|| !IsEmpty;
			Match = Match && (!HideReused || !IsReused);
			Match = Match && OperationMatches && StateMatches;
			bool ChildFilterMatches = FilterEmpty
				|| m_FilterExp.match(FilterValue(Child, Scope)).hasMatch();
			Match = Match && (SelectionExclude
				? ChildFilterMatches
				: (PathMatches || ChildFilterMatches));
			Child->setHidden(!Match);
			ChildMatches |= Match;
			if (Match)
				++ListedEvidence;
		}
		PathItem->setHidden(!ChildMatches);
		if (ChildMatches)
			++ListedFiles;
	}
	foreach(QTreeWidgetItem* GroupItem, Groups) {
		bool HasVisiblePath = false;
		for (int Index = 0; Index < GroupItem->childCount(); ++Index)
			HasVisiblePath |= !GroupItem->child(Index)->isHidden();
		GroupItem->setHidden(!HasVisiblePath);
	}

	m_pHideEmpty->setToolTip(
		tr("Hide %1 retained 0-byte evidence item(s).")
			.arg(EmptyEvidence));
	m_pHideReused->setToolTip(
		tr("Hide %1 retained evidence item(s) whose content reused an "
			"existing blob.").arg(ReusedEvidence));
	m_pStatus->setText(
		tr("Listed: %1 of %2 file(s), %3 of %4 evidence item(s)")
			.arg(ListedFiles).arg(TotalFiles)
			.arg(ListedEvidence).arg(TotalEvidence));
	UpdateSelection();
}


void CFileHistoryWindow::UpdateHashHighlight(
	int& SelectedCount, int& HighlightedCount)
{
	SelectedCount = 0;
	HighlightedCount = 0;
	QSet<QString> SelectedHashes;
	if (m_pHighlightSame->isChecked()) {
		foreach(QTreeWidgetItem* Item, m_pTree->selectedItems()) {
			if (!Item->data(0, eIsEvidence).toBool())
				continue;
			QString Hash = Item->data(0, eHashValue).toString();
			if (IsSha256(Hash))
				SelectedHashes.insert(Hash.toLower());
		}
	}
	QBrush MatchBrush(theGUI->m_DarkTheme
		? QColor(125, 105, 0) : QColor(255, 248, 190));

	foreach(QTreeWidgetItem* Item, TreeItems(m_pTree)) {
		if (!Item->isHidden() && Item->isSelected())
			++SelectedCount;
		if (!Item->data(0, eIsEvidence).toBool())
			continue;
		QString Hash = Item->data(0, eHashValue).toString();
		bool Match = IsSha256(Hash)
			&& SelectedHashes.contains(Hash.toLower());
		for (int Column = 0; Column < m_pTree->columnCount(); ++Column)
			Item->setBackground(Column, Match ? MatchBrush : QBrush());
		if (!Item->isHidden() && Match)
			++HighlightedCount;
	}
}


void CFileHistoryWindow::UpdateSelection()
{
	int SelectedCount;
	int HighlightedCount;
	UpdateHashHighlight(SelectedCount, HighlightedCount);
	m_pSelectionStatus->setText(m_pHighlightSame->isChecked()
		? tr("Selected: %1; Highlighted: %2")
			.arg(SelectedCount).arg(HighlightedCount)
		: tr("Selected: %1").arg(SelectedCount));
	QTreeWidgetItem* Item = m_pTree->currentItem();
	m_pOpenFolder->setEnabled(
		Item && !Item->data(0, eFolderPath).toString().isEmpty());
}


void CFileHistoryWindow::OpenEvidenceFolder()
{
	QTreeWidgetItem* Item = m_pTree->currentItem();
	if (!Item)
		return;

	QString Path = Item->data(0, eFolderPath).toString();
	if (!Path.isEmpty())
		QDesktopServices::openUrl(QUrl::fromLocalFile(Path));
}


void CFileHistoryWindow::ShowContextMenu(const QPoint& Pos)
{
	QTreeWidgetItem* Item = m_pTree->itemAt(Pos);
	if (!Item)
		return;

	if (!Item->isSelected()) {
		m_pTree->clearSelection();
		Item->setSelected(true);
	}
	int Column = m_pTree->columnAt(Pos.x());
	if (Column < 0)
		Column = 0;
	m_pTree->setCurrentItem(
		Item, Column, QItemSelectionModel::NoUpdate);
	QMenu Menu(this);
	Menu.setToolTipsVisible(true);
	if (Item->data(0, eIsEvidence).toBool()) {
		int PendingCount = 0;
		QStringList EvidencePaths =
			GetSelectedEvidencePaths(&PendingCount);
		bool HasEvidence = !EvidencePaths.isEmpty() || PendingCount != 0;
		QMenu* OpenExternal = Menu.addMenu(
			CSandMan::GetIcon("EditIni"), tr("Open in External Editor"));
		QAction* OpenEditor = OpenExternal->addAction(tr("Unsandboxed"));
		OpenEditor->setEnabled(HasEvidence);
		connect(OpenEditor, SIGNAL(triggered(bool)),
			this, SLOT(OpenEvidenceInEditor()));

		QAction* OpenSandboxedEditor = OpenExternal->addAction(
			CSandMan::GetIcon("Run"), tr("Sandboxed"));
		OpenSandboxedEditor->setEnabled(HasEvidence);
		connect(OpenSandboxedEditor, SIGNAL(triggered(bool)),
			this, SLOT(OpenEvidenceInSandboxedEditor()));

		QString CompareCommand = theConf->GetString(
			"FileHistoryWindow/CompareCommand").trimmed();
		int CompareArguments = CompareArgumentCount(CompareCommand);
		int EvidenceCount = (int)EvidencePaths.count();
		int SelectedCount = (int)m_pTree->selectedItems().count();
		bool AllSelectedEvidence = PendingCount == 0
			&& EvidenceCount == SelectedCount;
		if (AllSelectedEvidence && EvidenceCount > 1
				&& EvidenceCount <= CompareArguments) {
			QMenu* CompareMenu = Menu.addMenu(tr("Compare"));
			QAction* CompareUnsandboxed = CompareMenu->addAction(
				tr("Unsandboxed"));
			QAction* CompareSandboxed = CompareMenu->addAction(
				CSandMan::GetIcon("Run"), tr("Sandboxed"));
			connect(CompareUnsandboxed, &QAction::triggered, this,
				[this]() { CompareEvidence(false); });
			connect(CompareSandboxed, &QAction::triggered, this,
				[this]() { CompareEvidence(true); });
		}
	}

	QStringList FullPathRules;
	QStringList FileNameRules;
	QStringList ExtensionRules;
	QStringList ProcessRules;
	bool HasFileNameSelection = false;
	bool HasFolderNameSelection = false;
	foreach(QTreeWidgetItem* Selected, m_pTree->selectedItems()) {
		if (Selected->isHidden())
			continue;
		QString LogicalPath = Selected->data(0, eLogicalPath).toString();
		bool HasLogicalPath = !LogicalPath.isEmpty()
			&& !LogicalPath.startsWith(QLatin1Char('('));
		if (Selected->data(0, eIsGroup).toBool())
			HasFolderNameSelection = true;
		else if (HasLogicalPath)
			HasFileNameSelection = true;
		if (HasLogicalPath) {
			AppendUniqueCaseInsensitive(FullPathRules, LogicalPath);
			QFileInfo FileInfo(LogicalPath);
			QString FileName = FileInfo.fileName();
			if (!FileName.isEmpty()) {
				AppendUniqueCaseInsensitive(FileNameRules,
					QStringLiteral("*\\") + FileName);
			}
			QString Extension = FileInfo.suffix();
			if (!Extension.isEmpty()) {
				AppendUniqueCaseInsensitive(ExtensionRules,
					QStringLiteral("*.") + Extension);
			}
		}

		QString ProcessName = Selected->data(0, eProcessName).toString();
		if (!ProcessName.isEmpty()) {
			QString ImageName = QFileInfo(ProcessName).fileName();
			if (ImageName.isEmpty())
				ImageName = ProcessName;
			AppendUniqueCaseInsensitive(ProcessRules,
				ImageName + QStringLiteral(",*"));
		}
	}
	QString NameOnlyLabel = HasFolderNameSelection && !HasFileNameSelection
		? tr("Folder Name Only")
		: HasFolderNameSelection
			? tr("File or Folder Name Only")
			: tr("File Name Only");
	QStringList LocalExclusions = m_pBox->GetTextList(
		"KeepFileVersionsExclude", false, false, false);
	auto LocalMatches = [&LocalExclusions](const QStringList& Candidates) {
		QStringList Matches;
		foreach(const QString& Candidate, Candidates) {
			foreach(const QString& Existing, LocalExclusions) {
				if (Candidate.compare(Existing, Qt::CaseInsensitive) == 0) {
					AppendUniqueCaseInsensitive(Matches, Existing);
					break;
				}
			}
		}
		return Matches;
	};
	QStringList LocalFullPathRules = LocalMatches(FullPathRules);
	QStringList LocalFileNameRules = LocalMatches(FileNameRules);
	QStringList LocalExtensionRules = LocalMatches(ExtensionRules);
	QStringList LocalProcessRules = LocalMatches(ProcessRules);
	if (!LocalFullPathRules.isEmpty() || !LocalFileNameRules.isEmpty() ||
			!LocalExtensionRules.isEmpty() || !LocalProcessRules.isEmpty()) {
		QMenu* RemoveExcludeMenu = Menu.addMenu(
			CSandMan::GetIcon("Close"), tr("Remove Exclusion"));
		QAction* RemoveFullPath = RemoveExcludeMenu->addAction(tr("Full Path"));
		QAction* RemoveFileName = RemoveExcludeMenu->addAction(NameOnlyLabel);
		QAction* RemoveExtension = RemoveExcludeMenu->addAction(tr("Extension"));
		QAction* RemoveProcess = RemoveExcludeMenu->addAction(tr("Process"));
		RemoveFullPath->setEnabled(!LocalFullPathRules.isEmpty());
		RemoveFileName->setEnabled(!LocalFileNameRules.isEmpty());
		RemoveExtension->setEnabled(!LocalExtensionRules.isEmpty());
		RemoveProcess->setEnabled(!LocalProcessRules.isEmpty());
		connect(RemoveFullPath, &QAction::triggered, this,
			[this, LocalFullPathRules]() { RemoveExcludeRules(LocalFullPathRules); });
		connect(RemoveFileName, &QAction::triggered, this,
			[this, LocalFileNameRules]() { RemoveExcludeRules(LocalFileNameRules); });
		connect(RemoveExtension, &QAction::triggered, this,
			[this, LocalExtensionRules]() { RemoveExcludeRules(LocalExtensionRules); });
		connect(RemoveProcess, &QAction::triggered, this,
			[this, LocalProcessRules]() { RemoveExcludeRules(LocalProcessRules); });
	}

	QAction* OpenFolder = Menu.addAction(
		CSandMan::GetIcon("Folder"), tr("Open Evidence Folder"));
	connect(OpenFolder, SIGNAL(triggered(bool)),
		this, SLOT(OpenEvidenceFolder()));

	Menu.addSeparator();
	QAction* UseFilter = Menu.addAction(tr("Use as Filter"));
	QAction* ExcludeFilter = Menu.addAction(tr("Exclude from View"));
	QMenu* ExcludeMenu = Menu.addMenu(
		CSandMan::GetIcon("Close"), tr("Exclude from Capture"));
	const QString ExcludeCaptureTip = tr(
		"Exclude matching paths from future retained-version captures. "
		"Existing retained versions are not removed.");
	ExcludeMenu->menuAction()->setToolTip(ExcludeCaptureTip);
	QAction* ExcludeFullPath = ExcludeMenu->addAction(tr("Full Path"));
	QAction* ExcludeFileName = ExcludeMenu->addAction(NameOnlyLabel);
	QAction* ExcludeExtension = ExcludeMenu->addAction(tr("Extension"));
	QAction* ExcludeProcess = ExcludeMenu->addAction(tr("Process"));
	for (QAction* Action : { ExcludeFullPath, ExcludeFileName,
			ExcludeExtension, ExcludeProcess })
		Action->setToolTip(ExcludeCaptureTip);
	ExcludeFullPath->setEnabled(!FullPathRules.isEmpty());
	ExcludeFileName->setEnabled(!FileNameRules.isEmpty());
	ExcludeExtension->setEnabled(!ExtensionRules.isEmpty());
	ExcludeProcess->setEnabled(!ProcessRules.isEmpty());
	connect(ExcludeFullPath, &QAction::triggered, this,
		[this, FullPathRules]() { AddExcludeRules(FullPathRules); });
	connect(ExcludeFileName, &QAction::triggered, this,
		[this, FileNameRules]() { AddExcludeRules(FileNameRules); });
	connect(ExcludeExtension, &QAction::triggered, this,
		[this, ExtensionRules]() { AddExcludeRules(ExtensionRules); });
	connect(ExcludeProcess, &QAction::triggered, this,
		[this, ProcessRules]() { AddExcludeRules(ProcessRules); });
	QAction* TrackFile = Menu.addAction(tr("Track File"));
	bool HasFilterValue = false;
	foreach(QTreeWidgetItem* Selected, m_pTree->selectedItems()) {
		if (!Selected->text(Column).isEmpty()) {
			HasFilterValue = true;
			break;
		}
	}
	UseFilter->setEnabled(HasFilterValue);
	ExcludeFilter->setEnabled(HasFilterValue);
	bool HasTrackHash = false;
	foreach(QTreeWidgetItem* Selected, m_pTree->selectedItems()) {
		if (IsSha256(Selected->data(0, eHashValue).toString())) {
			HasTrackHash = true;
			break;
		}
	}
	TrackFile->setEnabled(HasTrackHash);
	UseFilter->setToolTip(tr(
		"Hold Shift or Ctrl to combine this with the current view filter."));
	ExcludeFilter->setToolTip(tr(
		"Hold Shift or Ctrl to combine this with the current view filter."));
	TrackFile->setToolTip(tr(
		"Show every retained version matching the selected SHA-256 hashes."));
	connect(UseFilter, SIGNAL(triggered(bool)), this, SLOT(UseAsFilter()));
	connect(ExcludeFilter, SIGNAL(triggered(bool)), this, SLOT(ExcludeFromView()));
	connect(TrackFile, SIGNAL(triggered(bool)), this, SLOT(TrackFile()));
	Menu.addSeparator();
	m_pCopyCell->setEnabled(!Item->text(Column).isEmpty());
	m_pCopyRow->setEnabled(!m_pTree->selectedItems().isEmpty());
	m_pCopyPanel->setEnabled(m_pTree->topLevelItemCount() != 0);
	Menu.addAction(m_pCopyCell);
	Menu.addAction(m_pCopyRow);
	Menu.addAction(m_pCopyPanel);

	Menu.addSeparator();
	QAction* Delete = Menu.addAction(
		CSandMan::GetIcon("Erase"),
		m_pTree->selectedItems().count() > 1
			? tr("Delete Selected Retained Versions...")
			: Item->data(0, eIsEvidence).toBool()
				? tr("Delete This Retained Version...")
				: tr("Delete All Retained Versions for This File..."));
	connect(Delete, SIGNAL(triggered(bool)), this, SLOT(DeleteEvidence()));

	Menu.exec(m_pTree->viewport()->mapToGlobal(Pos));
}


void CFileHistoryWindow::AddExcludeRules(const QStringList& Rules)
{
	if (Rules.isEmpty())
		return;

	QStringList Existing = m_pBox->GetTextList(
		"KeepFileVersionsExclude", true, false, true);
	QList<SB_STATUS> Results;
	QStringList Added;
	foreach(const QString& Rule, Rules) {
		if (Rule.isEmpty() || Existing.contains(Rule, Qt::CaseInsensitive))
			continue;
		SB_STATUS Status =
			m_pBox->AppendText("KeepFileVersionsExclude", Rule);
		Results.append(Status);
		if (!Status.IsError()) {
			Existing.append(Rule);
			Added.append(Rule);
		}
	}
	if (Results.isEmpty()) {
		QMessageBox::information(this, "Sandboxie-Plus",
			tr("The selected retained-file exclusions already exist."));
		return;
	}
	theGUI->CheckResults(Results, this);
	if (!Added.isEmpty()) {
		m_pStatus->setText(
			tr("Added %1 exclusion rule(s) for the next sandbox run.")
				.arg(Added.count()));
	}
}


void CFileHistoryWindow::RemoveExcludeRules(const QStringList& Rules)
{
	if (Rules.isEmpty())
		return;

	QList<SB_STATUS> Results;
	QStringList Removed;
	foreach(const QString& Rule, Rules) {
		if (Rule.isEmpty())
			continue;
		SB_STATUS Status =
			m_pBox->DelValue("KeepFileVersionsExclude", Rule);
		Results.append(Status);
		if (!Status.IsError())
			Removed.append(Rule);
	}
	if (Results.isEmpty())
		return;
	theGUI->CheckResults(Results, this);
	if (!Removed.isEmpty()) {
		m_pStatus->setText(
			tr("Removed %1 box-local exclusion rule(s).")
				.arg(Removed.count()));
	}
}


QStringList CFileHistoryWindow::GetSelectedEvidencePaths(
	int* PendingCount, bool SortByCaptureTime) const
{
	QList<SSelectedEvidence> SelectedPaths;
	if (PendingCount)
		*PendingCount = 0;
	QSet<QTreeWidgetItem*> Selected;
	foreach(QTreeWidgetItem* Item, m_pTree->selectedItems())
		Selected.insert(Item);
	auto AddItem = [&SelectedPaths, PendingCount, &Selected](
			QTreeWidgetItem* Item) {
		if (!Selected.contains(Item) || Item->isHidden()
				|| !Item->data(0, eIsEvidence).toBool())
			return;
		if (Item->data(0, eIsPending).toBool()) {
			if (PendingCount)
				++*PendingCount;
			return;
		}

		QString Path = Item->data(0, eBinaryPath).toString();
		if (!Path.isEmpty()) {
			bool Duplicate = false;
			foreach(const SSelectedEvidence& Existing, SelectedPaths) {
				if (Existing.Path.compare(Path, Qt::CaseInsensitive) == 0) {
					Duplicate = true;
					break;
				}
			}
			if (!Duplicate) {
				SSelectedEvidence Evidence;
				Evidence.Path = Path;
				Evidence.LogicalPath = Item->data(
					0, eLogicalPath).toString();
				Evidence.Captured = Item->data(
					2, eSortValue).toULongLong();
				SelectedPaths.append(Evidence);
			}
		}
	};
	foreach(QTreeWidgetItem* Item, TreeItems(m_pTree))
		AddItem(Item);
	if (SortByCaptureTime) {
		std::sort(SelectedPaths.begin(), SelectedPaths.end(),
			[](const SSelectedEvidence& Left, const SSelectedEvidence& Right) {
				if (Left.Captured != Right.Captured)
					return Left.Captured < Right.Captured;
				int Compare = QString::compare(
					Left.LogicalPath, Right.LogicalPath,
					Qt::CaseInsensitive);
				if (Compare != 0)
					return Compare < 0;
				return QString::compare(
					Left.Path, Right.Path, Qt::CaseInsensitive) < 0;
			});
	}
	QStringList Paths;
	foreach(const SSelectedEvidence& Evidence, SelectedPaths)
		Paths.append(Evidence.Path);
	return Paths;
}


void CFileHistoryWindow::OpenEvidenceInEditor()
{
	int PendingCount = 0;
	QStringList Paths = GetSelectedEvidencePaths(&PendingCount);
	if (PendingCount) {
		QMessageBox::information(this, "Sandboxie-Plus",
			tr("%1 pending evidence item(s) cannot be opened until they are "
				"finalized. Pending evidence is still linked to the sandbox "
				"file and opening it in an editor could change both.")
				.arg(PendingCount));
	}
	if (Paths.isEmpty())
		return;
	if (Paths.count() > 1 &&
			QMessageBox::question(this, "Sandboxie-Plus",
				tr("Open %1 selected retained evidence files outside the "
					"sandbox in the configured external editor?")
					.arg(Paths.count()),
				QMessageBox::Yes,
				QMessageBox::No | QMessageBox::Default |
					QMessageBox::Escape,
					QMessageBox::NoButton) != QMessageBox::Yes)
		return;
	bool Detach = false;
	if (!ConfirmSharedEvidenceAccess(Paths, &Detach))
		return;

	QStringList FailedPaths;
	QString Editor = GetFileHistoryEditor();
	foreach(const QString& Path, Paths) {
		if ((Detach && !DetachSharedEvidence(Path)) ||
				!theGUI->OpenFileInEditor(Path, Editor))
			FailedPaths.append(Path);
	}
	if (!FailedPaths.isEmpty()) {
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("%1 retained evidence file(s) could not be opened in the "
				"configured external editor.\n\n%2")
				.arg(FailedPaths.count())
				.arg(FailedPaths.mid(0, 10).join("\n")));
	}
}


void CFileHistoryWindow::OpenEvidenceInSandboxedEditor()
{
	int PendingCount = 0;
	QStringList Paths = GetSelectedEvidencePaths(&PendingCount);
	if (PendingCount) {
		QMessageBox::information(this, "Sandboxie-Plus",
			tr("%1 pending evidence item(s) cannot be opened until they are "
				"finalized. Pending evidence is still linked to the sandbox "
				"file and opening it in an editor could change both.")
				.arg(PendingCount));
	}
	if (Paths.isEmpty())
		return;
	if (Paths.count() > 1 &&
			QMessageBox::question(this, "Sandboxie-Plus",
				tr("Open %1 selected retained evidence files inside sandbox "
					"%2 in the configured external editor?")
					.arg(Paths.count()).arg(CSandMan::GetBoxDisplayName(m_pBox)),
				QMessageBox::Yes,
				QMessageBox::No | QMessageBox::Default |
					QMessageBox::Escape,
					QMessageBox::NoButton) != QMessageBox::Yes)
		return;
	bool Detach = false;
	if (!ConfirmSharedEvidenceAccess(Paths, &Detach))
		return;

	QString Editor = GetFileHistoryEditor();
	QList<SB_STATUS> Results;
	QStringList FailedPaths;
	foreach(const QString& Path, Paths) {
		if (Detach && !DetachSharedEvidence(Path)) {
			FailedPaths.append(Path);
			continue;
		}
		QString Command = QStringLiteral("\"%1\" \"%2\"").arg(Editor, Path);
		SB_STATUS Status = m_pBox->RunStart(Command);
		if (Status.IsError())
			Results.append(Status);
	}
	if (!Results.isEmpty())
		theGUI->CheckResults(Results, this);
	if (!FailedPaths.isEmpty()) {
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("%1 retained evidence file(s) could not be prepared for "
				"editing without changing other retained versions.\n\n%2")
				.arg(FailedPaths.count())
				.arg(FailedPaths.mid(0, 10).join("\n")));
	}
}


void CFileHistoryWindow::CompareEvidence(bool Sandboxed)
{
	int PendingCount = 0;
	QStringList Paths = GetSelectedEvidencePaths(&PendingCount, true);
	QString Command = theConf->GetString(
		"FileHistoryWindow/CompareCommand").trimmed();
	int ArgumentCount = CompareArgumentCount(Command);
	int PathCount = (int)Paths.count();
	int SelectedCount = (int)m_pTree->selectedItems().count();
	if (PendingCount != 0 || PathCount <= 1 || PathCount > ArgumentCount
			|| PathCount != SelectedCount)
		return;
	bool Detach = false;
	if (!ConfirmSharedEvidenceAccess(Paths, &Detach))
		return;

	QStringList FailedPaths;
	if (Detach) foreach(const QString& Path, Paths) {
		if (!DetachSharedEvidence(Path))
			FailedPaths.append(Path);
	}
	if (!FailedPaths.isEmpty()) {
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("%1 retained evidence file(s) could not be prepared for "
				"comparison without changing other retained versions.\n\n%2")
				.arg(FailedPaths.count())
				.arg(FailedPaths.mid(0, 10).join("\n")));
		return;
	}

	Command = BuildCompareCommand(Command, Paths);
	if (Command.isEmpty())
		return;

	if (Sandboxed) {
		QList<SB_STATUS> Results;
		Results.append(m_pBox->RunStart(Command));
		theGUI->CheckResults(Results, this);
		return;
	}

	if (!StartExternalCommand(Command)) {
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("The external comparison tool could not be started.\n\n%1")
				.arg(Command));
	}
}


bool CFileHistoryWindow::ConfirmSharedEvidenceAccess(const QStringList& Paths,
	bool* Detach)
{
	int SharedCount = 0;
	QStringList QueryFailures;
	foreach(const QString& Path, Paths) {
		int LinkCount = EvidenceLinkCount(Path);
		if (LinkCount < 0)
			QueryFailures.append(Path);
		else if (LinkCount > 1)
			++SharedCount;
	}
	if (!QueryFailures.isEmpty()) {
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("The hard-link state of %1 retained evidence file(s) could not be "
				"checked, so they will not be opened.\n\n%2")
				.arg(QueryFailures.count())
				.arg(QueryFailures.mid(0, 10).join("\n")));
		return false;
	}
	if (SharedCount == 0) {
		*Detach = false;
		return true;
	}

	QMessageBox Message(QMessageBox::Warning, "Sandboxie-Plus",
		tr("%1 selected evidence file(s) share their data with another retained "
			"version through NTFS hard links.\n\n"
			"If the external program writes to one of these files, every linked "
			"version may be changed. Detach creates an independent copy first. If "
			"your external program is read-only, you may continue without detaching.")
			.arg(SharedCount), QMessageBox::NoButton, this);
	QPushButton* DetachButton = Message.addButton(tr("Detach and Continue"),
		QMessageBox::AcceptRole);
	QPushButton* ContinueButton = Message.addButton(tr("Continue Anyway"),
		QMessageBox::DestructiveRole);
	QPushButton* CancelButton = Message.addButton(QMessageBox::Cancel);
	Message.setDefaultButton(DetachButton);
	Message.setEscapeButton(CancelButton);
	Message.exec();

	if (Message.clickedButton() == CancelButton)
		return false;
	*Detach = Message.clickedButton() == DetachButton;
	return Message.clickedButton() == DetachButton ||
		Message.clickedButton() == ContinueButton;
}


void CFileHistoryWindow::CopyCell()
{
	QTreeWidgetItem* Current = m_pTree->currentItem();
	if (!Current)
		return;

	int Column = m_pTree->currentColumn();
	QList<QStringList> Rows;
	foreach(QTreeWidgetItem* Item, m_pTree->selectedItems()) {
		if (!Item->isHidden())
			Rows.append(QStringList() << Item->text(Column));
	}
	CPanelView::CopyToClipboard(QStringList(), Rows);
}


void CFileHistoryWindow::CopyRow()
{
	QList<QStringList> Rows;
	foreach(QTreeWidgetItem* Item, m_pTree->selectedItems()) {
		if (!Item->isHidden())
			Rows.append(HistoryWindowUtils::VisibleRow(m_pTree, Item));
	}
	CPanelView::CopyToClipboard(
		HistoryWindowUtils::VisibleHeaders(m_pTree), Rows);
}


void CFileHistoryWindow::CopyPanel()
{
	QList<QStringList> Rows;
	for (int Index = 0; Index < m_pTree->topLevelItemCount(); ++Index)
		HistoryWindowUtils::AppendVisibleRows(
			m_pTree, m_pTree->topLevelItem(Index), Rows);
	CPanelView::CopyToClipboard(
		HistoryWindowUtils::VisibleHeaders(m_pTree), Rows);
}


void CFileHistoryWindow::UseAsFilter()
{
	Qt::KeyboardModifiers Modifiers = QApplication::keyboardModifiers();
	ApplySelectionFilter(false, Modifiers.testFlag(Qt::ShiftModifier)
		|| Modifiers.testFlag(Qt::ControlModifier));
}


void CFileHistoryWindow::ExcludeFromView()
{
	Qt::KeyboardModifiers Modifiers = QApplication::keyboardModifiers();
	ApplySelectionFilter(true, Modifiers.testFlag(Qt::ShiftModifier)
		|| Modifiers.testFlag(Qt::ControlModifier));
}


void CFileHistoryWindow::TrackFile()
{
	QStringList Hashes;
	bool IncludesEmpty = false;
	foreach(QTreeWidgetItem* Item, m_pTree->selectedItems()) {
		QString Hash = Item->data(0, eHashValue).toString();
		if (IsSha256(Hash)) {
			IncludesEmpty |= Item->data(0, eIsEmpty).toBool();
			if (!Hashes.contains(Hash, Qt::CaseInsensitive))
				Hashes.append(Hash);
		}
	}
	QString Expression;
	HistoryWindowUtils::EFilterBuildResult Result =
		HistoryWindowUtils::BuildSelectionFilter(Hashes, false, Expression);
	if (Result == HistoryWindowUtils::eFilterTooLarge) {
		QMessageBox::warning(this, tr("Retained File Versions"), tr(
			"The selected hashes are too large to create a safe "
			"regular-expression filter."));
		return;
	}
	if (Result != HistoryWindowUtils::eFilterReady)
		return;
	if (IncludesEmpty) {
		QMessageBox::information(this, tr("Retained File Versions"), tr(
			"At least one selected file is 0 bytes. Every 0-byte file has "
			"the same SHA-256 hash, so Track File will show all retained "
			"0-byte files, not only the selected path."));
	}

	PrepareTrackFileView();
	int ScopeIndex = m_pFilterScope->findData(eHashField);
	if (ScopeIndex >= 0)
		m_pFilterScope->setCurrentIndex(ScopeIndex);
	m_SelectionExcludePattern.clear();
	m_pFinder->SetSearchText(Expression, true);
}


void CFileHistoryWindow::PrepareTrackFileView()
{
	m_pViewOptionsButton->setChecked(true);
	if (!m_TrackFileHideEmptyOverride) {
		m_TrackFileHideEmptyValue = m_pHideEmpty->isChecked();
		m_TrackFileHideEmptyOverride = true;
	}
	if (!m_TrackFileHideReusedOverride) {
		m_TrackFileHideReusedValue = m_pHideReused->isChecked();
		m_TrackFileHideReusedOverride = true;
	}
	m_TrackFileViewAdjusting = true;
	m_pHideEmpty->setChecked(false);
	m_pHideReused->setChecked(false);
	m_TrackFileViewAdjusting = false;
}


void CFileHistoryWindow::ApplySelectionFilter(bool Exclude, bool Combine)
{

	int Column = m_pTree->currentColumn();
	int Scope = eAllFields;
	switch (Column) {
	case 0: Scope = ePathField; break;
	case 1: Scope = eVersionField; break;
	case 2: Scope = eDateField; break;
	case 3: Scope = eOperationField; break;
	case 4: Scope = eStateField; break;
	case 5: Scope = eSizeField; break;
	case 6: Scope = eProcessField; break;
	case 7: Scope = eHashField; break;
	}

	QStringList Values;
	foreach(QTreeWidgetItem* Item, m_pTree->selectedItems()) {
		QString Value = Item->text(Column);
		if (Column == 0) {
			Value = QFileInfo(
				Item->data(0, eLogicalPath).toString()).fileName();
		}
		else if (Column == 7)
			Value = Item->data(0, eHashValue).toString();
		if (!Value.isEmpty())
			Values.append(Value);
	}

	QString Expression;
	HistoryWindowUtils::EFilterBuildResult Result =
		HistoryWindowUtils::BuildSelectionFilter(
			Values, Exclude, Expression);
	bool PreservesExclusion = !m_SelectionExcludePattern.isEmpty()
		&& m_FilterExp.pattern() == m_SelectionExcludePattern;
	if (Result == HistoryWindowUtils::eFilterReady && Combine
			&& !m_FilterExp.pattern().isEmpty()) {
		QString Combined;
		Result = HistoryWindowUtils::CombineSelectionFilter(
			m_FilterExp.pattern(), Expression, Combined);
		Expression = Combined;
		if (m_pFilterScope->currentData().toInt() != Scope)
			Scope = eAllFields;
	}
	if (Result == HistoryWindowUtils::eFilterTooLarge) {
		QMessageBox::warning(this, tr("Retained File Versions"), tr(
			"The selected values are too large to create a safe "
			"regular-expression filter."));
		return;
	}
	if (Result != HistoryWindowUtils::eFilterReady)
		return;

	int ScopeIndex = m_pFilterScope->findData(Scope);
	if (ScopeIndex >= 0)
		m_pFilterScope->setCurrentIndex(ScopeIndex);
	m_SelectionExcludePattern = Exclude || (Combine && PreservesExclusion)
		? Expression : QString();
	m_pFinder->SetSearchText(Expression, true);
}


bool CFileHistoryWindow::CanDeleteHistory()
{
	if (m_pBox->GetBool("NeverDelete", false)) {
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("Delete protection is enabled for this sandbox."));
		return false;
	}
	if (m_pBox->GetActiveProcessCount() > 0) {
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("Retained file versions cannot be deleted while the sandbox is running."));
		return false;
	}
	return true;
}


void CFileHistoryWindow::ConfigureLimits()
{
	QDialog Dialog(this);
	Dialog.setWindowTitle(
		tr("Configure Retained File Version Limits and Options"));

	QVBoxLayout* MainLayout = new QVBoxLayout(&Dialog);
	QLabel* Info = new QLabel(
		tr("Enter 0 for unlimited. Leave a field empty to inherit its "
			"global or template value, or the built-in default. Changes "
			"apply to newly started sandboxed processes. Migrated-file "
			"capture retains the host-derived baseline. The rule tabs edit "
			"box-local settings only; inherited rules remain active."),
		&Dialog);
	Info->setWordWrap(true);
	MainLayout->addWidget(Info);

	QGridLayout* FormLayout = new QGridLayout();
	const bool InitialEnabled = m_pBox->GetBool(
		"FileHistory", true, true, true);
	QCheckBox* Enabled = new QCheckBox(
		tr("Enable retained file version capture for matching tracked-file rules"),
		&Dialog);
	Enabled->setChecked(InitialEnabled);
	QLineEdit* MaxVersions = new QLineEdit(
		m_pBox->GetText("FileHistoryMaxVersionsTotal"), &Dialog);
	QLineEdit* MaxVersionsPerFile = new QLineEdit(
		m_pBox->GetText("FileHistoryMaxVersionsPerFile"), &Dialog);
	QLineEdit* MaxSizeKB = new QLineEdit(
		m_pBox->GetText("FileHistoryMaxSizeTotalKB"), &Dialog);
	QLineEdit* MaxFileSizeKB = new QLineEdit(
		m_pBox->GetText("FileHistoryMaxFileSizeKB"), &Dialog);
	QComboBox* CaptureMigrated = new QComboBox(&Dialog);
	QComboBox* LogWarnings = new QComboBox(&Dialog);
	QLineEdit* Editor = new QLineEdit(
		theConf->GetString("FileHistoryWindow/Editor"), &Dialog);
	QLineEdit* CompareCommand = new QLineEdit(
		theConf->GetString("FileHistoryWindow/CompareCommand"), &Dialog);
	QPlainTextEdit* IncludeRules = new QPlainTextEdit(&Dialog);
	QPlainTextEdit* ExcludeRules = new QPlainTextEdit(&Dialog);

	IncludeRules->setPlainText(
		m_pBox->GetTextList("KeepFileVersions", false).join("\n"));
	ExcludeRules->setPlainText(
		m_pBox->GetTextList("KeepFileVersionsExclude", false).join("\n"));
	IncludeRules->setPlaceholderText(
		tr("One KeepFileVersions rule per line"));
	ExcludeRules->setPlaceholderText(
		tr("One KeepFileVersionsExclude rule per line"));
	IncludeRules->setMinimumHeight(90);
	ExcludeRules->setMinimumHeight(90);
	Editor->setPlaceholderText(tr("Empty = External Ini Editor"));
	Editor->setToolTip(
		tr("Leave empty to use the External Ini Editor configured in Settings."));
	Editor->setMinimumWidth(240);
	CompareCommand->setPlaceholderText(
		tr("BCompare.exe /readonly /solo \"%1\" \"%2\""));
	CompareCommand->setToolTip(
		tr("Enter a complete command containing two to five contiguous path "
			"placeholders starting with %1. The highest placeholder sets the "
			"maximum selection count.\nCompare is shown for two up to that "
			"maximum, and unused placeholder arguments are omitted. Paths are "
			"quoted automatically when needed."));
	CompareCommand->setMinimumWidth(240);

	const quint64 InheritedMaxVersions = qMax(0,
		m_pBox->GetNum("FileHistoryMaxVersionsTotal", 2500, true, true));
	const quint64 InheritedMaxVersionsPerFile = qMax(0,
		m_pBox->GetNum(
			"FileHistoryMaxVersionsPerFile", 25, true, true));
	const quint64 InheritedMaxSizeKB = qMax<qint64>(0,
		m_pBox->GetNum64(
			"FileHistoryMaxSizeTotalKB", 1024 * 1024, true, true));
	const quint64 InheritedMaxFileSizeKB = qMax<qint64>(0,
		m_pBox->GetNum64("FileHistoryMaxFileSizeKB", 10 * 1024, true, true));
	MaxVersions->setPlaceholderText(tr("Inherited (currently %1)")
		.arg(InheritedMaxVersions));
	MaxVersionsPerFile->setPlaceholderText(tr("Inherited (currently %1)")
		.arg(InheritedMaxVersionsPerFile));
	MaxSizeKB->setPlaceholderText(tr("Inherited (currently %1)")
		.arg(InheritedMaxSizeKB));
	MaxFileSizeKB->setPlaceholderText(tr("Inherited (currently %1)")
		.arg(InheritedMaxFileSizeKB));
	bool EffectiveCaptureMigrated = m_pBox->GetBool(
		"FileHistoryCaptureMigrated", false, true, true);
	CaptureMigrated->addItem(
		tr("Inherited (currently %1)")
			.arg(EffectiveCaptureMigrated ? tr("enabled") : tr("disabled")),
		-1);
	CaptureMigrated->addItem(tr("Enabled"), 1);
	CaptureMigrated->addItem(tr("Disabled"), 0);
	QString CaptureMigratedValue =
		m_pBox->GetText("FileHistoryCaptureMigrated").trimmed();
	if (CaptureMigratedValue.compare("y", Qt::CaseInsensitive) == 0)
		CaptureMigrated->setCurrentIndex(1);
	else if (CaptureMigratedValue.compare("n", Qt::CaseInsensitive) == 0)
		CaptureMigrated->setCurrentIndex(2);
	bool EffectiveLogWarnings = m_pBox->GetBool(
		"FileHistoryLogWarnings", true, true, true);
	LogWarnings->addItem(
		tr("Inherited (currently %1)")
			.arg(EffectiveLogWarnings ? tr("enabled") : tr("disabled")),
		-1);
	LogWarnings->addItem(tr("Enabled"), 1);
	LogWarnings->addItem(tr("Disabled"), 0);
	QString LogWarningsValue =
		m_pBox->GetText("FileHistoryLogWarnings").trimmed();
	if (LogWarningsValue.compare("y", Qt::CaseInsensitive) == 0)
		LogWarnings->setCurrentIndex(1);
	else if (LogWarningsValue.compare("n", Qt::CaseInsensitive) == 0)
		LogWarnings->setCurrentIndex(2);
	QLabel* TotalUsage = new QLabel(&Dialog);
	QLabel* PerFileUsage = new QLabel(&Dialog);
	QLabel* TotalSize = new QLabel(&Dialog);
	QLabel* CaptureSize = new QLabel(&Dialog);
	foreach(QLabel* Label,
			QList<QLabel*>() << TotalUsage << PerFileUsage
				<< TotalSize << CaptureSize) {
		Label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
		Label->setSizePolicy(
			QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
	}
	int FormRow = 0;
	int LabelWidth = 0;
	auto AddLabel = [&Dialog, &FormLayout, &LabelWidth](const QString& LabelText,
			int Row) {
		QLabel* Label = new QLabel(LabelText, &Dialog);
		Label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
		LabelWidth = qMax(LabelWidth,
			Label->fontMetrics().horizontalAdvance(LabelText));
		FormLayout->addWidget(Label, Row, 0, 1, 2);
	};
	auto AddLimitRow = [&AddLabel, &FormLayout, &FormRow](
			const QString& LabelText, QLineEdit* Edit, QLabel* ValueLabel) {
		AddLabel(LabelText, FormRow);
		FormLayout->addWidget(Edit, FormRow, 2, 1, 2);
		FormLayout->addWidget(ValueLabel, FormRow, 4);
		++FormRow;
	};
	auto AddOptionRow = [&AddLabel, &FormLayout, &FormRow](
			const QString& LabelText, QWidget* Widget) {
		AddLabel(LabelText, FormRow);
		FormLayout->addWidget(Widget, FormRow, 2, 1, 2);
		++FormRow;
	};
	auto AddSpanningRow = [&AddLabel, &FormLayout, &FormRow](
			const QString& LabelText, QWidget* Widget) {
		AddLabel(LabelText, FormRow);
		FormLayout->addWidget(Widget, FormRow, 2, 1, 3);
		++FormRow;
	};
	FormLayout->addWidget(Enabled, FormRow, 0, 1, 5);
	++FormRow;
	AddLimitRow(tr("Maximum total non-empty versions:"),
		MaxVersions, TotalUsage);
	AddLimitRow(tr("Maximum non-empty versions per file:"),
		MaxVersionsPerFile, PerFileUsage);
	AddLimitRow(tr("Maximum total size (KiB):"),
		MaxSizeKB, TotalSize);
	AddLimitRow(tr("Maximum capture size (KiB):"),
		MaxFileSizeKB, CaptureSize);
	AddOptionRow(
		tr("Capture migrated-file baseline:"), CaptureMigrated);
	AddOptionRow(
		tr("Log file history warnings (SBIE2228/2229):"), LogWarnings);
	AddSpanningRow(tr("File History editor:"), Editor);
	AddSpanningRow(tr("External compare command:"), CompareCommand);
	FormLayout->setColumnStretch(4, 1);

	MainLayout->addLayout(FormLayout);

	auto ReadLimit = [](QLineEdit* Edit, quint64 Fallback, bool* Valid) {
		QString Text = Edit->text().trimmed();
		if (Text.isEmpty()) {
			*Valid = true;
			return Fallback;
		}
		bool Ok = false;
		quint64 Value = Text.toULongLong(&Ok);
		*Valid = Ok;
		return Ok ? Value : 0;
	};
	auto UpdateUsage = [MaxVersions, MaxVersionsPerFile, MaxSizeKB,
		MaxFileSizeKB, TotalUsage, PerFileUsage, TotalSize, CaptureSize,
		ReadLimit, InheritedMaxVersions, InheritedMaxVersionsPerFile,
		InheritedMaxSizeKB, InheritedMaxFileSizeKB]() {
		bool Valid = true;
		bool FieldValid;
		quint64 TotalVersions = ReadLimit(
			MaxVersions, InheritedMaxVersions, &FieldValid);
		Valid = Valid && FieldValid;
		quint64 PerFileVersions = ReadLimit(
			MaxVersionsPerFile, InheritedMaxVersionsPerFile, &FieldValid);
		Valid = Valid && FieldValid;
		quint64 MaxSize = ReadLimit(
			MaxSizeKB, InheritedMaxSizeKB, &FieldValid);
		Valid = Valid && FieldValid;
		quint64 MaxCaptureSize = ReadLimit(
			MaxFileSizeKB, InheritedMaxFileSizeKB, &FieldValid);
		Valid = Valid && FieldValid;
		if (!Valid) {
			TotalUsage->setText(CFileHistoryWindow::tr("invalid"));
			PerFileUsage->setText(CFileHistoryWindow::tr("invalid"));
			TotalSize->setText(CFileHistoryWindow::tr("invalid"));
			CaptureSize->setText(CFileHistoryWindow::tr("invalid"));
			return;
		}

		TotalSize->setText(FormatLimitKB(MaxSize));
		CaptureSize->setText(FormatLimitKB(MaxCaptureSize));
		auto LimitProduct = [](quint64 Count, quint64 Size,
			bool* Finite) {
			const quint64 Maximum = ~quint64(0);
			if (!Count || !Size) {
				*Finite = false;
				return quint64(0);
			}
			*Finite = true;
			return Count > Maximum / Size ? Maximum : Count * Size;
		};
		auto FormatUsage = [](quint64 Size, bool Finite) {
			return Finite
				? FormatLimitKB(Size)
				: CFileHistoryWindow::tr("unlimited");
		};

		bool TotalFinite;
		quint64 TotalUsageValue = LimitProduct(
			TotalVersions, MaxCaptureSize, &TotalFinite);
		if (MaxSize &&
				(!TotalFinite || MaxSize < TotalUsageValue)) {
			TotalUsageValue = MaxSize;
			TotalFinite = true;
		}
		TotalUsage->setText(FormatUsage(TotalUsageValue, TotalFinite));

		quint64 PerFileVersionLimit = 0;
		if (TotalVersions && PerFileVersions)
			PerFileVersionLimit = qMin(TotalVersions, PerFileVersions);
		else if (TotalVersions)
			PerFileVersionLimit = TotalVersions;
		else
			PerFileVersionLimit = PerFileVersions;
		bool PerFileFinite;
		quint64 PerFileUsageValue = LimitProduct(
			PerFileVersionLimit, MaxCaptureSize, &PerFileFinite);
		if (MaxSize &&
				(!PerFileFinite || MaxSize < PerFileUsageValue)) {
			PerFileUsageValue = MaxSize;
			PerFileFinite = true;
		}
		PerFileUsage->setText(
			FormatUsage(PerFileUsageValue, PerFileFinite));
	};
	UpdateUsage();
	connect(MaxVersions, &QLineEdit::textChanged, &Dialog,
		[UpdateUsage](const QString&) { UpdateUsage(); });
	connect(MaxVersionsPerFile, &QLineEdit::textChanged, &Dialog,
		[UpdateUsage](const QString&) { UpdateUsage(); });
	connect(MaxSizeKB, &QLineEdit::textChanged, &Dialog,
		[UpdateUsage](const QString&) { UpdateUsage(); });
	connect(MaxFileSizeKB, &QLineEdit::textChanged, &Dialog,
		[UpdateUsage](const QString&) { UpdateUsage(); });

	QTabWidget* RuleTabs = new QTabWidget(&Dialog);
	RuleTabs->addTab(IncludeRules, tr("Tracked Files"));
	RuleTabs->addTab(ExcludeRules, tr("Excluded Files"));
	RuleTabs->setToolTip(
		tr("Enter one [process,]path-pattern rule per line. Rules inherited "
			"from global settings or templates are not listed here."));
	MainLayout->addWidget(RuleTabs);

	QList<QLineEdit*> LimitEdits;
	LimitEdits << MaxVersions << MaxVersionsPerFile
		<< MaxSizeKB << MaxFileSizeKB;
	const qreal DpiScale = Dialog.logicalDpiX() / 96.0;
	const int TextPadding = qRound(24 * DpiScale);
	const int ColumnSpacing = FormLayout->horizontalSpacing();
	int FieldWidth = 0;
	foreach(QLineEdit* Edit, LimitEdits) {
		QString ShownText = Edit->text().isEmpty()
			? Edit->placeholderText() : Edit->text();
		FieldWidth = qMax(FieldWidth,
			Edit->minimumSizeHint().width());
		FieldWidth = qMax(FieldWidth,
			Edit->fontMetrics().horizontalAdvance(ShownText) + TextPadding);
	}
	foreach(QComboBox* Combo, QList<QComboBox*>()
			<< CaptureMigrated << LogWarnings) {
		int ComboWidth = Combo->minimumSizeHint().width();
		QFontMetrics Metrics(Combo->font());
		for (int Index = 0; Index < Combo->count(); ++Index)
			ComboWidth = qMax(ComboWidth,
				Metrics.horizontalAdvance(Combo->itemText(Index)) + TextPadding);
		FieldWidth = qMax(FieldWidth, ComboWidth);
	}
	foreach(QLineEdit* Edit, LimitEdits)
		Edit->setMinimumWidth(FieldWidth);
	foreach(QComboBox* Combo, QList<QComboBox*>()
			<< CaptureMigrated << LogWarnings)
		Combo->setMinimumWidth(FieldWidth);
	int LabelColumnWidth = (LabelWidth + ColumnSpacing + 1) / 2;
	FormLayout->setColumnMinimumWidth(0, LabelColumnWidth);
	FormLayout->setColumnMinimumWidth(1, LabelColumnWidth);
	int FieldColumnWidth = (FieldWidth + ColumnSpacing + 1) / 2;
	FormLayout->setColumnMinimumWidth(2, FieldColumnWidth);
	FormLayout->setColumnMinimumWidth(3, FieldColumnWidth);
	int UsageWidth = 0;
	foreach(QLabel* Label,
			QList<QLabel*>() << TotalUsage << PerFileUsage
				<< TotalSize << CaptureSize)
		UsageWidth = qMax(UsageWidth,
			Label->fontMetrics().horizontalAdvance(Label->text()));
	FormLayout->setColumnMinimumWidth(4, UsageWidth + TextPadding);

	QDialogButtonBox* Buttons = new QDialogButtonBox(
		QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &Dialog);
	connect(Buttons, SIGNAL(rejected()), &Dialog, SLOT(reject()));
	MainLayout->addWidget(Buttons);

	connect(Buttons, &QDialogButtonBox::accepted, &Dialog,
		[this, &Dialog, MaxVersions, MaxVersionsPerFile,
			MaxSizeKB, MaxFileSizeKB, Editor, CompareCommand]() {
		QStringList Invalid;
		auto Validate = [&Invalid](QLineEdit* Edit, quint64 Maximum,
			const QString& Name) {
			QString Text = Edit->text().trimmed();
			if (Text.isEmpty())
				return;
			bool Ok = false;
			quint64 Value = Text.toULongLong(&Ok);
			if (!Ok || Value > Maximum)
				Invalid.append(Name);
		};
		Validate(MaxVersions, 0x7FFFFFFFULL,
			tr("Maximum total non-empty versions"));
		Validate(MaxVersionsPerFile, 0x7FFFFFFFULL,
			tr("Maximum non-empty versions per file"));
		Validate(MaxSizeKB, 0x7FFFFFFFFFFFFFFFULL, tr("Maximum total size"));
		Validate(MaxFileSizeKB, 0x7FFFFFFFFFFFFFFFULL,
			tr("Maximum capture size"));
		if (CompareArgumentCount(CompareCommand->text()) < 0) {
			QMessageBox::warning(&Dialog, "Sandboxie-Plus",
				tr("The external compare command must contain two to five "
					"contiguous path placeholders starting with %1. For "
					"example:\n\nBCompare.exe /readonly /solo \"%1\" \"%2\""));
			return;
		}

		if (!Invalid.isEmpty()) {
			QMessageBox::warning(&Dialog, "Sandboxie-Plus",
				tr("Enter a non-negative whole number for:\n\n%1")
					.arg(Invalid.join("\n")));
			return;
		}
		Dialog.accept();
	});

	Dialog.adjustSize();
	if (theGUI->SafeExec(&Dialog) != QDialog::Accepted)
		return;

	QList<SB_STATUS> Results;
	if (Enabled->isChecked() != InitialEnabled) {
		Results.append(m_pBox->SetText("FileHistory",
			Enabled->isChecked() ? QStringLiteral("y") : QStringLiteral("n")));
	}
	auto Save = [this, &Results](const QString& Setting, QLineEdit* Edit) {
		QString NewValue = Edit->text().trimmed();
		QString OldValue = m_pBox->GetText(Setting);
		if (NewValue == OldValue)
			return;
		Results.append(NewValue.isEmpty()
			? m_pBox->DelValue(Setting)
			: m_pBox->SetText(Setting, NewValue));
	};
	Save("FileHistoryMaxVersionsTotal", MaxVersions);
	Save("FileHistoryMaxVersionsPerFile", MaxVersionsPerFile);
	Save("FileHistoryMaxSizeTotalKB", MaxSizeKB);
	Save("FileHistoryMaxFileSizeKB", MaxFileSizeKB);
	theConf->SetValue("FileHistoryWindow/Editor", Editor->text().trimmed());
	theConf->SetValue("FileHistoryWindow/CompareCommand",
		CompareCommand->text().trimmed());
	auto ReadRules = [](QPlainTextEdit* Edit) {
		QStringList Rules;
		foreach(const QString& Line,
				Edit->toPlainText().split(QLatin1Char('\n'))) {
			QString Rule = Line.trimmed();
			if (Rule.isEmpty())
				continue;
			bool Duplicate = false;
			foreach(const QString& Existing, Rules) {
				if (Existing.compare(Rule, Qt::CaseInsensitive) == 0) {
					Duplicate = true;
					break;
				}
			}
			if (!Duplicate)
				Rules.append(Rule);
		}
		return Rules;
	};
	auto SaveRules = [this, &Results](
			const QString& Setting, const QStringList& NewRules) {
		QStringList OldRules = m_pBox->GetTextList(Setting, false);
		QStringList AddedRules = NewRules;
		foreach(const QString& OldRule, OldRules) {
			int Index = AddedRules.indexOf(OldRule);
			if (Index >= 0)
				AddedRules.removeAt(Index);
			else
				Results.append(m_pBox->DelValue(Setting, OldRule));
		}
		foreach(const QString& AddedRule, AddedRules)
			Results.append(m_pBox->AppendText(Setting, AddedRule));
	};
	SaveRules("KeepFileVersions", ReadRules(IncludeRules));
	SaveRules("KeepFileVersionsExclude", ReadRules(ExcludeRules));
	int CaptureMigratedState = CaptureMigrated->currentData().toInt();
	QString NewCaptureMigratedValue = CaptureMigratedState < 0
		? QString()
		: (CaptureMigratedState
			? QStringLiteral("y") : QStringLiteral("n"));
	QString OldCaptureMigratedValue =
		m_pBox->GetText("FileHistoryCaptureMigrated").trimmed();
	if (NewCaptureMigratedValue.compare(
			OldCaptureMigratedValue, Qt::CaseInsensitive) != 0) {
		Results.append(NewCaptureMigratedValue.isEmpty()
			? m_pBox->DelValue("FileHistoryCaptureMigrated")
			: m_pBox->SetText(
				"FileHistoryCaptureMigrated", NewCaptureMigratedValue));
	}
	int LogWarningsState = LogWarnings->currentData().toInt();
	QString NewLogWarningsValue = LogWarningsState < 0
		? QString()
		: (LogWarningsState
			? QStringLiteral("y") : QStringLiteral("n"));
	QString OldLogWarningsValue =
		m_pBox->GetText("FileHistoryLogWarnings").trimmed();
	if (NewLogWarningsValue.compare(
			OldLogWarningsValue, Qt::CaseInsensitive) != 0) {
		Results.append(NewLogWarningsValue.isEmpty()
			? m_pBox->DelValue("FileHistoryLogWarnings")
			: m_pBox->SetText(
				"FileHistoryLogWarnings", NewLogWarningsValue));
	}
	theGUI->CheckResults(Results, this);
}


void CFileHistoryWindow::DeleteEvidence()
{
	QSet<QTreeWidgetItem*> EvidenceItems;
	QSet<QString> LogicalPaths;
	QSet<QString> ContentHashes;
	auto AddEvidenceItem = [&EvidenceItems, &LogicalPaths, &ContentHashes](
			QTreeWidgetItem* Item) {
		EvidenceItems.insert(Item);
		QString LogicalPath = Item->data(0, eLogicalPath).toString();
		if (!LogicalPath.isEmpty())
			LogicalPaths.insert(LogicalPath);
		QString Hash = Item->data(0, eHashValue).toString();
		if (IsSha256(Hash))
			ContentHashes.insert(Hash.toLower());
	};
	foreach(QTreeWidgetItem* Item, m_pTree->selectedItems()) {
		if (Item->isHidden())
			continue;

		if (Item->data(0, eIsEvidence).toBool())
			AddEvidenceItem(Item);
		else {
			QList<QTreeWidgetItem*> Descendants;
			AppendTreeItems(Item, Descendants);
			foreach(QTreeWidgetItem* Descendant, Descendants) {
				if (Descendant->data(0, eIsEvidence).toBool())
					AddEvidenceItem(Descendant);
			}
		}
	}

	if (EvidenceItems.isEmpty() || !CanDeleteHistory())
		return;

	QSet<QTreeWidgetItem*> MatchingItems;
	if (!ContentHashes.isEmpty()) {
		foreach(QTreeWidgetItem* Item, TreeItems(m_pTree)) {
			if (!Item->data(0, eIsEvidence).toBool())
				continue;
			QString Hash = Item->data(0, eHashValue).toString();
			if (!EvidenceItems.contains(Item) && IsSha256(Hash)
					&& ContentHashes.contains(Hash.toLower()))
				MatchingItems.insert(Item);
		}
	}
	if (!MatchingItems.isEmpty() && QMessageBox::question(
			this, "Sandboxie-Plus",
			tr("Also delete %1 other retained version(s) that have the same "
				"SHA-256 content hash as the selected evidence?")
				.arg(MatchingItems.count()),
			QMessageBox::Yes,
			QMessageBox::No | QMessageBox::Default | QMessageBox::Escape,
			QMessageBox::NoButton) == QMessageBox::Yes) {
		foreach(QTreeWidgetItem* Item, MatchingItems)
			AddEvidenceItem(Item);
	}

	QStringList Paths = LogicalPaths.values();
	Paths.sort(Qt::CaseInsensitive);
	QString PathList = Paths.mid(0, 5).join("\n");
	if (Paths.count() > 5)
		PathList += tr("\n... and %1 more").arg(Paths.count() - 5);

	if (QMessageBox::question(this, "Sandboxie-Plus",
			tr("Delete %1 retained version evidence item(s) for %2 file(s)?\n\n"
				"This removes only copies stored in the sandbox's FileHistory "
				"archive. It does not delete the current files inside the "
				"sandbox.\n\nAffected sandbox path(s):\n%3")
				.arg(EvidenceItems.count()).arg(Paths.count()).arg(PathList),
			QMessageBox::Yes,
			QMessageBox::No | QMessageBox::Default | QMessageBox::Escape,
			QMessageBox::NoButton) != QMessageBox::Yes)
		return;
	if (!CanDeleteHistory())
		return;

	QString HistoryPath = QDir::cleanPath(
		m_pBox->GetFileRoot() + "\\FileHistory");
	QStringList FailedPaths;
	QStringList FailedFolders;
	QSet<QString> ArtifactFolders;
	QMap<QString, int> DeletedVersions;
	int UnjournaledVersions = 0;
	foreach(QTreeWidgetItem* Item, EvidenceItems) {
		QString ArtifactFolder = Item->data(0, eFolderPath).toString();
		if (!ArtifactFolder.isEmpty())
			ArtifactFolders.insert(ArtifactFolder);
		QString BinaryPath = Item->data(0, eBinaryPath).toString();
		QString MetadataPath = Item->data(0, eMetadataPath).toString();
		bool RemovedNonEmptyBinary = false;
		if (!BinaryPath.isEmpty() && QFile::exists(BinaryPath)) {
			bool NonEmptyBinary = QFileInfo(BinaryPath).size() > 0;
			if (!QFile::remove(BinaryPath)) {
				FailedPaths.append(BinaryPath);
				continue;
			}
			RemovedNonEmptyBinary = NonEmptyBinary;
		}
		if (RemovedNonEmptyBinary) {
			QString TruePath = Item->data(0, eTruePath).toString();
			if (TruePath.isEmpty())
				++UnjournaledVersions;
			else {
				QString Key = TruePath;
				for (int Index = 0; Index < Key.size(); ++Index) {
					ushort Value = Key.at(Index).unicode();
					if (Value >= 'A' && Value <= 'Z')
						Key[Index] = QChar(Value | 0x20);
				}
				++DeletedVersions[Key];
			}
		}
		if (!MetadataPath.isEmpty() && QFile::exists(MetadataPath)
				&& !QFile::remove(MetadataPath))
			FailedPaths.append(MetadataPath);
	}
	foreach(const QString& ArtifactFolder, ArtifactFolders) {
		QDir Folder(ArtifactFolder);
		if (Folder.exists() && Folder.entryList(
				QDir::AllEntries | QDir::Hidden | QDir::System |
				QDir::NoDotAndDotDot).isEmpty()
				&& !QDir().rmdir(ArtifactFolder))
			FailedFolders.append(ArtifactFolder);
	}
	int JournalFailureCount = 0;
	if (!DeletedVersions.isEmpty()
			&& !WriteFileHistoryDeletionJournal(HistoryPath, DeletedVersions)) {
		foreach(int Count, DeletedVersions)
			JournalFailureCount += Count;
	}

	Reload();
	if (!FailedPaths.isEmpty()) {
		QString FailedList = FailedPaths.mid(0, 10).join("\n");
		if (FailedPaths.count() > 10)
			FailedList += tr("\n... and %1 more").arg(FailedPaths.count() - 10);
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("%1 retained version evidence file(s) could not be deleted.\n\n%2")
				.arg(FailedPaths.count()).arg(FailedList));
	}
	if (!FailedFolders.isEmpty()) {
		QString FailedList = FailedFolders.mid(0, 10).join("\n");
		if (FailedFolders.count() > 10)
			FailedList += tr("\n... and %1 more")
				.arg(FailedFolders.count() - 10);
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("%1 empty retained-version artifact folder(s) could not be "
				"removed.\n\n%2")
				.arg(FailedFolders.count()).arg(FailedList));
	}
	if (UnjournaledVersions || JournalFailureCount) {
		QMessageBox::warning(this, "Sandboxie-Plus",
			tr("The File History deletion journal could not be updated for %1 "
				"deleted evidence item(s). The affected counters may remain "
				"conservative until the FileHistory archive is cleared.")
				.arg(UnjournaledVersions + JournalFailureCount));
	}
}


void CFileHistoryWindow::RemoveHistory()
{
	if (!CanDeleteHistory())
		return;

	if (QMessageBox::question(this, "Sandboxie-Plus",
			tr("Do you really want to remove all retained file versions for sandbox %1?\n\n"
				"This permanently deletes all retained evidence from the "
				"FileHistory archive. Current files inside the sandbox are "
				"not deleted.")
				.arg(CSandMan::GetBoxDisplayName(m_pBox)),
			QMessageBox::Yes,
			QMessageBox::No | QMessageBox::Default | QMessageBox::Escape,
			QMessageBox::NoButton) != QMessageBox::Yes)
		return;

	m_pRemoveHistory->setEnabled(false);
	SB_PROGRESS Status = m_pBox->CleanFileHistory();
	if (Status.GetStatus() == OP_ASYNC) {
		connect(Status.GetValue().data(), SIGNAL(Finished()),
			this, SLOT(Reload()));
		theGUI->AddAsyncOp(Status.GetValue(), false,
			tr("Removing retained file versions..."), this);
	}
	else if (Status.IsError()) {
		theGUI->CheckResults(QList<SB_STATUS>() << Status, this);
		Reload();
	}
	else
		Reload();
}
