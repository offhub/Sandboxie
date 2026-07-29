#include "stdafx.h"
#include "FileHistoryWindow.h"
#include "SandMan.h"
#include "../../MiscHelpers/Common/Finder.h"
#include <QItemSelectionModel>
#include <windows.h>


namespace
{
	enum EHistoryRole
	{
		eFolderPath = Qt::UserRole,
		eBinaryPath,
		eMetadataPath,
		eLogicalPath,
		eOperation,
		eProcess,
		eState,
		eSize,
		eDate,
		eExtension,
		eHash,
		eIsEmpty,
		eIsReused,
		eIsPending,
		eIsEvidence,
		eSortValue
	};

	enum EFilterScope
	{
		eAllFields,
		ePathField,
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

	bool ReadMetadata(const QString& Path, QMap<QString, QString>& Fields)
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

		return Fields.contains("artifact") && Fields.contains("path");
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
		case eOperationField:	return Item->data(0, eOperation).toString();
		case eProcessField:		return Item->data(0, eProcess).toString();
		case eStateField:		return Item->data(0, eState).toString();
		case eSizeField:		return Item->data(0, eSize).toString();
		case eDateField:		return Item->data(0, eDate).toString();
		case eExtensionField:	return Item->data(0, eExtension).toString();
		case eHashField:		return Item->data(0, eHash).toString();
		default:
			return QStringLiteral("%1\n%2\n%3\n%4\n%5\n%6\n%7\n%8")
				.arg(Item->data(0, eLogicalPath).toString(),
					Item->data(0, eOperation).toString(),
					Item->data(0, eProcess).toString(),
					Item->data(0, eState).toString(),
					Item->data(0, eSize).toString(),
					Item->data(0, eDate).toString(),
					Item->data(0, eExtension).toString(),
					Item->data(0, eHash).toString());
		}
	}
}


CFileHistoryWindow::CFileHistoryWindow(const CSandBoxPtr& pBox, QWidget* parent)
	: QDialog(parent), m_pBox(pBox), m_Loading(false), m_Loaded(false)
{
	Qt::WindowFlags Flags = windowFlags();
	Flags |= Qt::CustomizeWindowHint | Qt::WindowMinimizeButtonHint
		| Qt::WindowMaximizeButtonHint;
	setWindowFlags(Flags);
	setWindowFlag(Qt::WindowStaysOnTopHint, theGUI->IsAlwaysOnTop());

	setWindowTitle(tr("%1 - Retained File Versions").arg(pBox->GetName()));

	QVBoxLayout* MainLayout = new QVBoxLayout(this);
	QHBoxLayout* ToolLayout = new QHBoxLayout();

	m_pFilterScope = new QComboBox(this);
	m_pFilterScope->addItem(tr("All fields"), eAllFields);
	m_pFilterScope->addItem(tr("Path"), ePathField);
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
	m_pHideEmpty = new QCheckBox(tr("Hide 0-byte files"), this);
	m_pHideEmpty->setChecked(
		theConf->GetBool("FileHistoryWindow/HideEmptyFiles", true));
	m_pHideEmpty->setToolTip(
		tr("Hide retained evidence with an empty binary file."));
	m_pHideReused = new QCheckBox(tr("Hide reused files"), this);
	m_pHideReused->setChecked(
		theConf->GetBool("FileHistoryWindow/HideReusedFiles", true));
	m_pLoadIndicator = new QLabel(this);
	m_pLoadIndicator->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
	m_pLoadIndicator->setText(tr("Refreshing..."));
	m_pLoadIndicator->setMinimumWidth(m_pLoadIndicator->sizeHint().width());
	m_pLoadIndicator->clear();
	m_pRefreshButton = new QPushButton(
		CSandMan::GetIcon("Refresh"), tr("Refresh"), this);

	ToolLayout->addWidget(SearchButton);
	ToolLayout->addWidget(m_pFilterScope);
	ToolLayout->addWidget(m_pFinder);
	ToolLayout->addStretch();
	ToolLayout->addWidget(m_pHideEmpty);
	ToolLayout->addWidget(m_pHideReused);
	ToolLayout->addWidget(m_pLoadIndicator);
	ToolLayout->addWidget(m_pRefreshButton);
	MainLayout->addLayout(ToolLayout);

	m_pTree = new QTreeWidget(this);
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
	m_pRemoveHistory = new QPushButton(
		CSandMan::GetIcon("Erase"), tr("Remove Retained Versions..."), this);
	m_pOpenFolder = new QPushButton(CSandMan::GetIcon("Folder"), tr("Open Evidence Folder"), this);
	QPushButton* CloseButton = new QPushButton(tr("Close"), this);
	m_pOpenFolder->setEnabled(false);

	BottomLayout->addWidget(m_pStatus, 1);
	BottomLayout->addWidget(m_pRemoveHistory);
	BottomLayout->addWidget(m_pOpenFolder);
	BottomLayout->addWidget(CloseButton);
	MainLayout->addLayout(BottomLayout);

	connect(m_pRefreshButton, SIGNAL(clicked(bool)), this, SLOT(Reload()));
	connect(m_pHideEmpty, &QCheckBox::toggled,
		this, [this](bool) { ApplyFilter(); });
	connect(m_pHideReused, &QCheckBox::toggled,
		this, [this](bool) { ApplyFilter(); });
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

	QAction* ResizeColumnsAction = new QAction(
		tr("Resize All Columns to Contents"), this);
	ResizeColumnsAction->setShortcut(
		QKeySequence(QStringLiteral("Ctrl+Shift++")));
	ResizeColumnsAction->setShortcutContext(Qt::WidgetWithChildrenShortcut);
	addAction(ResizeColumnsAction);
	connect(ResizeColumnsAction, SIGNAL(triggered(bool)),
		this, SLOT(ResizeColumns()));

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

	m_pFinder->Open();
	Reload();
}


CFileHistoryWindow::~CFileHistoryWindow()
{
	theConf->SetBlob("FileHistoryWindow/Window_Geometry", saveGeometry());
	theConf->SetBlob("FileHistoryWindow/Tree_Columns", m_pTree->header()->saveState());
	theConf->SetValue(
		"FileHistoryWindow/HideEmptyFiles", m_pHideEmpty->isChecked());
	theConf->SetValue(
		"FileHistoryWindow/HideReusedFiles", m_pHideReused->isChecked());
}


void CFileHistoryWindow::closeEvent(QCloseEvent* e)
{
	emit Closed();
	QDialog::closeEvent(e);
	deleteLater();
}


void CFileHistoryWindow::Reload()
{
	if (m_Loading)
		return;

	m_Loading = true;
	m_pRefreshButton->setEnabled(false);
	m_pLoadIndicator->setText(
		m_Loaded ? tr("Refreshing...") : tr("Loading..."));
	m_pLoadIndicator->repaint();
	m_pRefreshButton->repaint();

	int SortColumn = m_pTree->header()->sortIndicatorSection();
	Qt::SortOrder SortOrder = m_pTree->header()->sortIndicatorOrder();
	if (SortColumn < 0 || SortColumn >= m_pTree->columnCount()) {
		SortColumn = 0;
		SortOrder = Qt::AscendingOrder;
	}
	QSet<QString> CollapsedPaths;
	bool HadParents = m_pTree->topLevelItemCount() > 0;
	for (int Index = 0; Index < m_pTree->topLevelItemCount(); ++Index) {
		QTreeWidgetItem* Item = m_pTree->topLevelItem(Index);
		if (!Item->isExpanded()) {
			CollapsedPaths.insert(
				Item->data(0, eLogicalPath).toString().toLower());
		}
	}
	m_pTree->setSortingEnabled(false);
	m_pTree->clear();

	quint64 MaxVersions = qMax(0,
		m_pBox->GetNum("FileHistoryMaxVersionsTotal", 1000, true, true));
	quint64 MaxVersionsPerFile = qMax(0,
		m_pBox->GetNum(
			"FileHistoryMaxVersionsPerFile", 100, true, true));
	quint64 MaxSizeKB = qMax<qint64>(0,
		m_pBox->GetNum64(
			"FileHistoryMaxSizeTotalKB", 1024 * 1024, true, true));
	quint64 MaxFileSizeKB = qMax<qint64>(0,
		m_pBox->GetNum64("FileHistoryMaxFileSizeKB", 1024, true, true));
	QString HistoryPath = QDir::cleanPath(
		m_pBox->GetFileRoot() + "\\FileHistory");
	if (m_pBox->GetActiveProcessCount() == 0)
		RemoveOrphanedBlobs(HistoryPath);
	QString ArtifactsPath = QDir::cleanPath(HistoryPath + "\\Artifacts");
	QDir Artifacts(ArtifactsPath);
	QMap<QString, QTreeWidgetItem*> PathItems;
	quint64 UsedVersions = 0;
	quint64 UsedSize = 0;

	foreach(const QFileInfo& ArtifactInfo,
			Artifacts.entryInfoList(
				QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks,
				QDir::Name)) {
		if (!IsArtifactId(ArtifactInfo.fileName()))
			continue;

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
			const SHistoryFilePair& Pair = PairIt.value();
			QMap<QString, QString> Fields;
			bool MetadataValid = !Pair.MetadataPath.isEmpty()
				&& ReadMetadata(Pair.MetadataPath, Fields);

			QString LogicalPath;
			if (MetadataValid) {
				LogicalPath = UnescapeField(Fields.value("dos_path"));
				if (LogicalPath.isEmpty())
					LogicalPath = UnescapeField(Fields.value("path"));
			}
			if (LogicalPath.isEmpty())
				LogicalPath = tr("(Unknown path) [%1]").arg(ArtifactInfo.fileName());

			QString PathKey = LogicalPath.toLower();
			QTreeWidgetItem* PathItem = PathItems.value(PathKey);
			if (!PathItem) {
				PathItem = new CHistoryTreeItem(m_pTree);
				PathItem->setText(0, LogicalPath);
				PathItem->setIcon(0, CSandMan::GetIcon("File"));
				PathItem->setData(0, eFolderPath, ArtifactInfo.absoluteFilePath());
				PathItem->setData(0, eLogicalPath, LogicalPath);
				PathItem->setData(0, eExtension, QFileInfo(LogicalPath).suffix());
				PathItem->setData(0, eIsEvidence, false);
				PathItems.insert(PathKey, PathItem);
			}

			QTreeWidgetItem* Item = new CHistoryTreeItem(PathItem);
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

			bool SizeOk = false;
			quint64 Size = 0;
			if (!Pair.BinaryPath.isEmpty()) {
				qint64 BinarySize = QFileInfo(Pair.BinaryPath).size();
				Size = BinarySize > 0 ? (quint64)BinarySize : 0;
				SizeOk = true;
				Item->setData(0, eIsEmpty, BinarySize == 0);
				if (Size)
					++UsedVersions;
				quint64 MaximumSize = ~((quint64)0);
				UsedSize = Size > MaximumSize - UsedSize
					? MaximumSize : UsedSize + Size;
			}
			else
				Size = Fields.value("size").toULongLong(&SizeOk);
			if (SizeOk) {
				Item->setText(5, FormatSize(Size));
				Item->setData(5, eSortValue, Size);
			}

			QString Process = UnescapeField(Fields.value("image"));
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
			Item->setData(0, eOperation, Item->text(3));
			Item->setData(0, eProcess, Item->text(6));
			Item->setData(0, eState, Item->text(4));
			Item->setData(0, eSize, Item->text(5));
			Item->setData(0, eDate, Item->text(2));
			Item->setData(0, eExtension, QFileInfo(LogicalPath).suffix());
			bool Reused = Fields.value("content_reused").compare(
				"y", Qt::CaseInsensitive) == 0;
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

	for (auto ItemIt = PathItems.constBegin(); ItemIt != PathItems.constEnd(); ++ItemIt) {
		QTreeWidgetItem* Item = ItemIt.value();
		quint64 LatestDate = 0;
		quint64 TotalSize = 0;
		bool HasSize = false;
		for (int ChildIndex = 0; ChildIndex < Item->childCount(); ++ChildIndex) {
			QTreeWidgetItem* Child = Item->child(ChildIndex);
			LatestDate = qMax(
				LatestDate, Child->data(2, eSortValue).toULongLong());
			if (Child->data(5, eSortValue).isValid()) {
				quint64 ChildSize =
					Child->data(5, eSortValue).toULongLong();
				quint64 MaximumSize = ~((quint64)0);
				TotalSize = ChildSize > MaximumSize - TotalSize
					? MaximumSize : TotalSize + ChildSize;
				HasSize = true;
			}
		}
		Item->setText(1, QString::number(Item->childCount()));
		Item->setData(1, eSortValue, Item->childCount());
		if (LatestDate) {
			Item->setData(2, eSortValue, LatestDate);
			Item->setText(2, QDateTime::fromMSecsSinceEpoch(
				(qint64)LatestDate).toString(
					QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")));
		}
		if (HasSize) {
			Item->setData(5, eSortValue, TotalSize);
			Item->setText(5, FormatSize(TotalSize));
		}
	}

	for (auto ItemIt = PathItems.constBegin(); ItemIt != PathItems.constEnd(); ++ItemIt) {
		QTreeWidgetItem* PathItem = ItemIt.value();
		PathItem->sortChildren(2, Qt::DescendingOrder);
		for (int ChildIndex = 0; ChildIndex < PathItem->childCount(); ++ChildIndex) {
			QTreeWidgetItem* Child = PathItem->child(ChildIndex);
			int Version = PathItem->childCount() - ChildIndex;
			Child->setText(1, QString::number(Version));
			Child->setData(1, eSortValue, Version);
		}
	}
	m_pTree->setSortingEnabled(true);
	m_pTree->sortItems(SortColumn, SortOrder);
	SortHistory(SortColumn, SortOrder);
	for (int Index = 0; Index < m_pTree->topLevelItemCount(); ++Index) {
		QTreeWidgetItem* Item = m_pTree->topLevelItem(Index);
		Item->setExpanded(!HadParents || !CollapsedPaths.contains(
			Item->data(0, eLogicalPath).toString().toLower()));
	}
	ApplyFilter();
	m_pLimits->setText(tr("Usage / limits: %1 / %2 non-empty versions; "
		"%3 / %4 total size. Limits: %5 non-empty versions per file; "
		"%6 per capture.")
		.arg(QString::number(UsedVersions))
		.arg(FormatCountLimit(MaxVersions))
		.arg(FormatSize(UsedSize))
		.arg(FormatLimitKB(MaxSizeKB))
		.arg(FormatCountLimit(MaxVersionsPerFile))
		.arg(FormatLimitKB(MaxFileSizeKB)));
	m_pRemoveHistory->setEnabled(QDir(HistoryPath).exists());
	UpdateSelection();
	m_pLoadIndicator->clear();
	m_pRefreshButton->setEnabled(true);
	m_Loading = false;
	m_Loaded = true;
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
		m_pTree->topLevelItem(Index)->sortChildren(Column, Order);
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
	int TotalFiles = m_pTree->topLevelItemCount();
	int TotalEvidence = 0;
	int ListedFiles = 0;
	int ListedEvidence = 0;
	int EmptyEvidence = 0;
	int ReusedEvidence = 0;

	for (int Index = 0; Index < m_pTree->topLevelItemCount(); ++Index) {
		QTreeWidgetItem* PathItem = m_pTree->topLevelItem(Index);
		TotalEvidence += PathItem->childCount();
		bool PathMatches = FilterEmpty
			|| m_FilterExp.match(FilterValue(PathItem, Scope)).hasMatch();
		bool ChildMatches = false;

		for (int ChildIndex = 0; ChildIndex < PathItem->childCount(); ++ChildIndex) {
			QTreeWidgetItem* Child = PathItem->child(ChildIndex);
			bool IsEmpty = Child->data(0, eIsEmpty).toBool();
			bool IsReused = Child->data(0, eIsReused).toBool();
			if (IsEmpty)
				++EmptyEvidence;
			if (IsReused)
				++ReusedEvidence;
			bool Match = !HideEmpty
				|| !IsEmpty;
			Match = Match && (!HideReused || !IsReused);
			Match = Match && (PathMatches || FilterEmpty
				|| m_FilterExp.match(FilterValue(Child, Scope)).hasMatch());
			Child->setHidden(!Match);
			ChildMatches |= Match;
			if (Match)
				++ListedEvidence;
		}
		PathItem->setHidden(!ChildMatches);
		if (ChildMatches)
			++ListedFiles;
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
}


void CFileHistoryWindow::UpdateSelection()
{
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
	m_pTree->setCurrentItem(
		Item, 0, QItemSelectionModel::NoUpdate);
	QMenu Menu(this);
	if (Item->data(0, eIsEvidence).toBool()) {
		int PendingCount = 0;
		QStringList EvidencePaths =
			GetSelectedEvidencePaths(&PendingCount);
		bool HasEvidence = !EvidencePaths.isEmpty() || PendingCount != 0;
		QAction* OpenEditor = Menu.addAction(
			CSandMan::GetIcon("EditIni"),
			EvidencePaths.count() > 1
				? tr("Open Selected Evidence in External Editor (Unsandboxed)...")
				: tr("Open Evidence in External Editor (Unsandboxed)"));
		OpenEditor->setEnabled(HasEvidence);
		connect(OpenEditor, SIGNAL(triggered(bool)),
			this, SLOT(OpenEvidenceInEditor()));

		QAction* OpenSandboxedEditor = Menu.addAction(
			CSandMan::GetIcon("Run"),
			EvidencePaths.count() > 1
				? tr("Open Selected Evidence in External Editor (Sandboxed)...")
				: tr("Open Evidence in External Editor (Sandboxed)"));
		OpenSandboxedEditor->setEnabled(HasEvidence);
		connect(OpenSandboxedEditor, SIGNAL(triggered(bool)),
			this, SLOT(OpenEvidenceInSandboxedEditor()));
	}

	QAction* OpenFolder = Menu.addAction(
		CSandMan::GetIcon("Folder"), tr("Open Evidence Folder"));
	connect(OpenFolder, SIGNAL(triggered(bool)),
		this, SLOT(OpenEvidenceFolder()));

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


QStringList CFileHistoryWindow::GetSelectedEvidencePaths(
	int* PendingCount) const
{
	QStringList Paths;
	if (PendingCount)
		*PendingCount = 0;
	foreach(QTreeWidgetItem* Item, m_pTree->selectedItems()) {
		if (Item->isHidden() || !Item->data(0, eIsEvidence).toBool())
			continue;
		if (Item->data(0, eIsPending).toBool()) {
			if (PendingCount)
				++*PendingCount;
			continue;
		}

		QString Path = Item->data(0, eBinaryPath).toString();
		if (!Path.isEmpty() && !Paths.contains(Path, Qt::CaseInsensitive))
			Paths.append(Path);
	}
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

	QStringList FailedPaths;
	foreach(const QString& Path, Paths) {
		if (!DetachSharedEvidence(Path) ||
				!theGUI->OpenFileInEditor(Path))
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
					.arg(Paths.count()).arg(m_pBox->GetName()),
				QMessageBox::Yes,
				QMessageBox::No | QMessageBox::Default |
					QMessageBox::Escape,
				QMessageBox::NoButton) != QMessageBox::Yes)
		return;

	QString Editor = theConf->GetString("Options/Editor", "notepad.exe");
	QList<SB_STATUS> Results;
	QStringList FailedPaths;
	foreach(const QString& Path, Paths) {
		if (!DetachSharedEvidence(Path)) {
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
			"capture retains the host-derived baseline."),
		&Dialog);
	Info->setWordWrap(true);
	MainLayout->addWidget(Info);

	QFormLayout* FormLayout = new QFormLayout();
	QLineEdit* MaxVersions = new QLineEdit(
		m_pBox->GetText("FileHistoryMaxVersionsTotal"), &Dialog);
	QLineEdit* MaxVersionsPerFile = new QLineEdit(
		m_pBox->GetText("FileHistoryMaxVersionsPerFile"), &Dialog);
	QLineEdit* MaxSizeKB = new QLineEdit(
		m_pBox->GetText("FileHistoryMaxSizeTotalKB"), &Dialog);
	QLineEdit* MaxFileSizeKB = new QLineEdit(
		m_pBox->GetText("FileHistoryMaxFileSizeKB"), &Dialog);
	QComboBox* CaptureMigrated = new QComboBox(&Dialog);

	MaxVersions->setPlaceholderText(tr("Inherited (currently %1)")
		.arg(m_pBox->GetNum(
			"FileHistoryMaxVersionsTotal", 1000, true, true)));
	MaxVersionsPerFile->setPlaceholderText(tr("Inherited (currently %1)")
		.arg(m_pBox->GetNum(
			"FileHistoryMaxVersionsPerFile", 100, true, true)));
	MaxSizeKB->setPlaceholderText(tr("Inherited (currently %1)")
		.arg(m_pBox->GetNum64(
			"FileHistoryMaxSizeTotalKB", 1024 * 1024, true, true)));
	MaxFileSizeKB->setPlaceholderText(tr("Inherited (currently %1)")
		.arg(m_pBox->GetNum64(
			"FileHistoryMaxFileSizeKB", 1024, true, true)));
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

	FormLayout->addRow(
		tr("Maximum total non-empty versions:"), MaxVersions);
	FormLayout->addRow(
		tr("Maximum non-empty versions per file:"), MaxVersionsPerFile);
	FormLayout->addRow(tr("Maximum total size (KiB):"), MaxSizeKB);
	FormLayout->addRow(
		tr("Maximum capture size (KiB):"), MaxFileSizeKB);
	FormLayout->addRow(
		tr("Capture migrated-file baseline:"), CaptureMigrated);
	MainLayout->addLayout(FormLayout);

	QList<QLineEdit*> LimitEdits;
	LimitEdits << MaxVersions << MaxVersionsPerFile
		<< MaxSizeKB << MaxFileSizeKB;
	int FieldWidth = 0;
	foreach(QLineEdit* Edit, LimitEdits)
		FieldWidth = qMax(FieldWidth,
			Edit->fontMetrics().horizontalAdvance(Edit->placeholderText()) + 24);
	foreach(QLineEdit* Edit, LimitEdits)
		Edit->setMinimumWidth(FieldWidth);

	QDialogButtonBox* Buttons = new QDialogButtonBox(
		QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &Dialog);
	connect(Buttons, SIGNAL(rejected()), &Dialog, SLOT(reject()));
	MainLayout->addWidget(Buttons);

	connect(Buttons, &QDialogButtonBox::accepted, &Dialog,
		[this, &Dialog, MaxVersions, MaxVersionsPerFile,
			MaxSizeKB, MaxFileSizeKB]() {
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

	theGUI->CheckResults(Results, this);
	Reload();
}


void CFileHistoryWindow::DeleteEvidence()
{
	QSet<QTreeWidgetItem*> EvidenceItems;
	QSet<QString> LogicalPaths;
	foreach(QTreeWidgetItem* Item, m_pTree->selectedItems()) {
		if (Item->isHidden())
			continue;

		QString LogicalPath = Item->data(0, eLogicalPath).toString();
		if (!LogicalPath.isEmpty())
			LogicalPaths.insert(LogicalPath);

		if (Item->data(0, eIsEvidence).toBool())
			EvidenceItems.insert(Item);
		else {
			for (int Index = 0; Index < Item->childCount(); ++Index)
				EvidenceItems.insert(Item->child(Index));
		}
	}

	if (EvidenceItems.isEmpty() || !CanDeleteHistory())
		return;

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

	QStringList FailedPaths;
	foreach(QTreeWidgetItem* Item, EvidenceItems) {
		QString BinaryPath = Item->data(0, eBinaryPath).toString();
		QString MetadataPath = Item->data(0, eMetadataPath).toString();
		if (!BinaryPath.isEmpty() && QFile::exists(BinaryPath)
				&& !QFile::remove(BinaryPath)) {
			FailedPaths.append(BinaryPath);
			continue;
		}
		if (!MetadataPath.isEmpty() && QFile::exists(MetadataPath)
				&& !QFile::remove(MetadataPath))
			FailedPaths.append(MetadataPath);
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
				.arg(m_pBox->GetName()),
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
