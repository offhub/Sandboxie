/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "stdafx.h"
#include "FileStateHistoryWidget.h"
#include "HistoryWindowUtils.h"
#include "../SandMan.h"
#include "../../MiscHelpers/Common/Common.h"
#include "../../MiscHelpers/Common/CheckableMessageBox.h"
#include "../../MiscHelpers/Common/Finder.h"
#include "../../MiscHelpers/Common/PanelView.h"
#include "../../MiscHelpers/Common/TreeWidgetEx.h"

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QColor>
#include <QComboBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QItemSelectionModel>
#include <QLineEdit>
#include <QMap>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSet>
#include <QStackedLayout>
#include <QTimer>
#include <QTabWidget>
#include <QToolButton>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <windows.h>

namespace
{
    enum EChangeType
    {
        eAdded = 1,
        eRemoved,
        eContentModified,
        eMetadataModified,
        eModified,
        eTypeChanged
    };

    enum EFileStateRole
    {
        eChangeRole = Qt::UserRole,
        eDirectoryRole,
        eSortRole,
        eSizeRole,
        eRawPathRole,
        eGroupRole,
        eMarkerRole,
        eOldHashRole,
        eNewHashRole
    };

    enum EFilterScope
    {
        eAllFields = -1,
        eChangeField = 0,
        ePathField,
        eTypeField,
        eOldSizeField,
        eNewSizeField,
        eOldModifiedField,
        eNewModifiedField,
        eHashField
    };

    class CFileStateTreeItem : public QTreeWidgetItem
    {
    public:
        CFileStateTreeItem(QTreeWidget* tree, const QStringList& values)
            : QTreeWidgetItem(tree, values) {}

        bool operator<(const QTreeWidgetItem& other) const override
        {
            int column = treeWidget() ? treeWidget()->sortColumn() : 0;
            QVariant left = data(column, eSortRole);
            QVariant right = other.data(column, eSortRole);
            if (left.isValid() && right.isValid())
                return left.toULongLong() < right.toULongLong();
            return QTreeWidgetItem::operator<(other);
        }
    };

    const quint64 WindowsEpochSeconds = 11644473600ULL;
    const int MaxMapEntries = 250000;
    const qint64 MaxMapBytes = 64LL * 1024 * 1024;

    bool IsGenerationName(const QString& name)
    {
        return name.size() == 19 &&
            QDateTime::fromString(name, "yyyyMMdd-HHmmss-zzz").isValid();
    }

    bool IsSafeDirectory(const QString& path)
    {
        DWORD attributes = GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(path.utf16()));
        return attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    }

    bool IsSafeFile(const QString& path)
    {
        DWORD attributes = GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(path.utf16()));
        return attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & (FILE_ATTRIBUTE_DIRECTORY |
                FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    }

    bool IsPendingGenerationName(const QString& name)
    {
        static const QString prefix = QStringLiteral(".pending-");
        return name.startsWith(prefix) &&
            IsGenerationName(name.mid(prefix.size()));
    }

    bool IsStateGenerationPayloadName(const QString& name)
    {
        return name.compare(QStringLiteral("FileMap.dat"),
            Qt::CaseInsensitive) == 0 ||
            name.compare(QStringLiteral("Generation.ini"),
            Qt::CaseInsensitive) == 0 ||
            name.compare(QStringLiteral("FilePaths.dat"),
            Qt::CaseInsensitive) == 0 ||
            name.compare(QStringLiteral("FilePaths_v3.dat"),
            Qt::CaseInsensitive) == 0 ||
            name.compare(QStringLiteral("FilePaths_v3.sbie"),
            Qt::CaseInsensitive) == 0;
    }

    bool ValidateStateGenerationDirectory(const QString& path)
    {
        if (!IsSafeDirectory(path))
            return false;

        QDir directory(path);
        const QStringList entries = directory.entryList(
            QDir::AllEntries | QDir::Hidden | QDir::System |
                QDir::NoDotAndDotDot,
            QDir::Name);
        for (const QString& name : entries) {
            if (!IsStateGenerationPayloadName(name) ||
                    !IsSafeFile(directory.filePath(name)))
                return false;
        }
        return true;
    }

    bool RemoveStateGenerationDirectory(const QString& path)
    {
        QString name = QDir(path).dirName();
        if ((!IsGenerationName(name) && !IsPendingGenerationName(name)) ||
                !ValidateStateGenerationDirectory(path))
            return false;

        QDir directory(path);
        const QStringList entries = directory.entryList(
            QDir::AllEntries | QDir::Hidden | QDir::System |
                QDir::NoDotAndDotDot,
            QDir::Name);
        for (const QString& name : entries) {
            QString filePath = directory.filePath(name);
            if (!IsStateGenerationPayloadName(name) ||
                    !IsSafeFile(filePath) || !QFile::remove(filePath))
                return false;
        }
        return QDir().rmdir(path);
    }

    bool ValidateStateHistoryDirectory(const QString& path)
    {
        if (!IsSafeDirectory(path))
            return false;

        QDir history(path);
        const QStringList entries = history.entryList(
            QDir::AllEntries | QDir::Hidden | QDir::System |
                QDir::NoDotAndDotDot,
            QDir::Name);
        for (const QString& name : entries) {
            QString generationPath = history.filePath(name);
            if ((!IsGenerationName(name) && !IsPendingGenerationName(name)) ||
                    !ValidateStateGenerationDirectory(generationPath))
                return false;
        }
        return true;
    }

    bool RemoveStateHistoryDirectory(const QString& path)
    {
        if (!ValidateStateHistoryDirectory(path))
            return false;
        QDir history(path);
        const QStringList directories = history.entryList(
            QDir::Dirs | QDir::Hidden | QDir::System |
                QDir::NoDotAndDotDot,
            QDir::Name);
        for (const QString& name : directories) {
            if ((!IsGenerationName(name) && !IsPendingGenerationName(name)) ||
                    !RemoveStateGenerationDirectory(history.filePath(name)))
                return false;
        }
        if (!history.entryList(
                QDir::AllEntries | QDir::Hidden | QDir::System |
                    QDir::NoDotAndDotDot).isEmpty())
            return false;
        return QDir().rmdir(path);
    }

    void AppendUniqueCaseInsensitive(QStringList& values,
        const QString& value)
    {
        if (!value.isEmpty() && !values.contains(value, Qt::CaseInsensitive))
            values.append(value);
    }

    QString UnescapePath(const QByteArray& input, bool& ok)
    {
        QByteArray output;
        output.reserve(input.size());
        ok = true;
        for (int index = 0; index < input.size(); ++index) {
            char ch = input.at(index);
            if (ch != '\\') {
                output.append(ch);
                continue;
            }
            if (++index >= input.size()) {
                ok = false;
                break;
            }
            char escaped = input.at(index);
            if (escaped == '\\')
                output.append('\\');
            else if (escaped == 't')
                output.append('\t');
            else if (escaped == 'r')
                output.append('\r');
            else if (escaped == 'n')
                output.append('\n');
            else {
                ok = false;
                break;
            }
        }
        QString result = QString::fromUtf8(output.constData(), output.size());
        if (result.toUtf8() != output)
            ok = false;
        return result;
    }

    QString FormatFileTime(quint64 value)
    {
        if (value == 0)
            return QString();
        quint64 milliseconds = value / 10000;
        quint64 epochMilliseconds = WindowsEpochSeconds * 1000;
        if (milliseconds < epochMilliseconds)
            return QString();
        return QDateTime::fromMSecsSinceEpoch(
            qint64(milliseconds - epochMilliseconds), Qt::UTC)
            .toLocalTime().toString(Qt::ISODateWithMs);
    }

    QString FromUtf16(const quint16* data, int length)
    {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return QString::fromUtf16(
            reinterpret_cast<const char16_t*>(data), length);
#else
        return QString::fromUtf16(data, length);
#endif
    }

    QString ReadIniValue(const QString& path, const QString& key)
    {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly) || file.size() > 1024 * 1024)
            return QString();
        QByteArray bytes = file.readAll();
        QString text;
        if (bytes.size() >= 2 && (uchar)bytes.at(0) == 0xFF &&
                (uchar)bytes.at(1) == 0xFE)
            text = FromUtf16(
                reinterpret_cast<const quint16*>(bytes.constData() + 2),
                (bytes.size() - 2) / 2);
        else
            text = QString::fromUtf8(bytes);
        const QString prefix = key + QLatin1Char('=');
        for (const QString& line : text.split(QRegularExpression("[\\r\\n]+"))) {
            if (line.startsWith(prefix, Qt::CaseInsensitive))
                return line.mid(prefix.size()).trimmed();
        }
        return QString();
    }

    QString ChangeName(int change)
    {
        switch (change) {
        case eAdded: return CFileStateHistoryWidget::tr("Added");
        case eRemoved: return CFileStateHistoryWidget::tr("Removed");
        case eContentModified: return CFileStateHistoryWidget::tr("Content modified");
        case eMetadataModified: return CFileStateHistoryWidget::tr("Metadata modified");
        case eTypeChanged: return CFileStateHistoryWidget::tr("Type changed");
        default: return CFileStateHistoryWidget::tr("Modified");
        }
    }

    QColor ChangeColor(int change)
    {
        switch (change) {
        case eAdded: return QColor(210, 255, 210);
        case eRemoved: return QColor(255, 220, 220);
        case eContentModified: return QColor(255, 244, 190);
        case eMetadataModified: return QColor(225, 235, 255);
        case eTypeChanged: return QColor(245, 220, 255);
        default: return QColor(255, 235, 200);
        }
    }

}

CFileStateHistoryWidget::CFileStateHistoryWidget(const CSandBoxPtr& pBox,
    QWidget* parent)
    : QWidget(parent), m_pBox(pBox),
      m_pTabs(qobject_cast<QTabWidget*>(parent)), m_Loading(false),
      m_AbortRequested(false), m_Loaded(false)
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    QHBoxLayout* toolLayout = new QHBoxLayout();
    m_pFilterScope = new QComboBox(this);
    m_pFilterScope->addItem(tr("All fields"), eAllFields);
    m_pFilterScope->addItem(tr("Change"), eChangeField);
    m_pFilterScope->addItem(tr("Path"), ePathField);
    m_pFilterScope->addItem(tr("Type"), eTypeField);
    m_pFilterScope->addItem(tr("Old Size"), eOldSizeField);
    m_pFilterScope->addItem(tr("New Size"), eNewSizeField);
    m_pFilterScope->addItem(tr("Old Modified"), eOldModifiedField);
    m_pFilterScope->addItem(tr("New Modified"), eNewModifiedField);
    m_pFilterScope->addItem(tr("Hash Status"), eHashField);
    m_pFinder = new CFinder(this, this, CFinder::eRegExp | CFinder::eCaseSens);
    m_pFinder->SetCloseButtonAtEnd(false);
    QAbstractButton* search = m_pFinder->GetToggleButton();
    search->setText(tr("Search"));
    QWidget* loadControl = new QWidget(this);
    m_pAutoCompare = new QCheckBox(tr("Auto Compare"), loadControl);
    m_pAutoCompare->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/AutoCompare", true));
    m_pAutoCompare->setToolTip(tr(
        "Automatically compare the newest generations after loading."));
    m_pLoadIndicator = new QLabel(loadControl);
    m_pLoadIndicator->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_pLoadIndicator->setMinimumWidth(fontMetrics().horizontalAdvance(
        tr("Refreshing... 000000 / 000000 generations")) + 8);
    m_pLoadStack = new QStackedLayout(loadControl);
    m_pLoadStack->setContentsMargins(0, 0, 0, 0);
    m_pLoadStack->addWidget(m_pAutoCompare);
    m_pLoadStack->addWidget(m_pLoadIndicator);
    m_pLoadStack->setCurrentWidget(m_pAutoCompare);
    m_pRefresh = new QPushButton(CSandMan::GetIcon("Refresh"), tr("Refresh"), this);
    m_pRefresh->setEnabled(false);
    QToolButton* viewOptions = new QToolButton(this);
    viewOptions->setIcon(CSandMan::GetIcon("List"));
    viewOptions->setText(tr("Options"));
    viewOptions->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    viewOptions->setCheckable(true);
    viewOptions->setAutoRaise(true);
    toolLayout->addWidget(search);
    toolLayout->addWidget(m_pFilterScope);
    toolLayout->addWidget(m_pFinder, 1);
    toolLayout->addWidget(loadControl);
    toolLayout->addWidget(m_pRefresh);
    toolLayout->addWidget(viewOptions);
    mainLayout->addLayout(toolLayout);

    QHBoxLayout* generationLayout = new QHBoxLayout();
    m_pOlder = new QComboBox(this);
    m_pNewer = new QComboBox(this);
    m_pCompare = new QPushButton(CSandMan::GetIcon("Search"), tr("Compare"), this);
    generationLayout->addWidget(new QLabel(tr("Older generation:"), this));
    generationLayout->addWidget(m_pOlder, 1);
    generationLayout->addWidget(new QLabel(tr("Newer generation:"), this));
    generationLayout->addWidget(m_pNewer, 1);
    generationLayout->addWidget(m_pCompare);
    mainLayout->addLayout(generationLayout);

    m_pShowAdded = new QCheckBox(tr("Added"), this);
    m_pShowRemoved = new QCheckBox(tr("Removed"), this);
    m_pShowModified = new QCheckBox(tr("Modified"), this);
    m_pShowMetadata = new QCheckBox(tr("Metadata modified"), this);
    m_pShowMarkers = new QCheckBox(tr("Deletion markers"), this);
    m_pShowColors = new QCheckBox(tr("Color change types"), this);
    m_pHighlightSame = new QCheckBox(tr("Highlight same"), this);
    m_pShowFiles = new QCheckBox(tr("Files"), this);
    m_pShowFolders = new QCheckBox(tr("Folders"), this);
    m_pHideEmpty = new QCheckBox(tr("Hide 0-byte files"), this);
    m_pNormalizePaths = new QCheckBox(tr("Normalize paths"), this);
    m_pGroupByParent = new QCheckBox(tr("Group by parent folder"), this);
    m_pShowAdded->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/ShowAdded", true));
    m_pShowRemoved->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/ShowRemoved", true));
    m_pShowModified->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/ShowModified", true));
    m_pShowMetadata->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/ShowMetadata", true));
    m_pShowMarkers->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/ShowDeletionMarkers", true));
    m_pShowColors->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/ShowChangeColors", true));
    m_pHighlightSame->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/HighlightSameHash", true));
    m_pHighlightSame->setToolTip(tr(
        "Highlight file changes whose old or new SHA-256 matches any "
        "selected file change."));
    m_pShowFiles->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/ShowFiles", true));
    m_pShowFolders->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/ShowFolders", true));
    m_pHideEmpty->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/HideEmptyFiles", false));
    m_pNormalizePaths->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/NormalizePaths", true));
    m_pNormalizePaths->setToolTip(tr(
        "Display logical Windows paths instead of box-relative storage paths. "
        "This changes only the view."));
    m_pGroupByParent->setChecked(theConf->GetBool(
        "FileStateHistoryWindow/GroupByParentFolder", false));
    m_pGroupByParent->setToolTip(tr(
        "Place file changes under their immediate parent folder."));
    QWidget* ViewOptionsWidget = new QWidget(this);
    QVBoxLayout* viewOptionsLayout = new QVBoxLayout(ViewOptionsWidget);
    viewOptionsLayout->setContentsMargins(0, 0, 0, 0);
    QHBoxLayout* topOptionsLayout = new QHBoxLayout();
    topOptionsLayout->addWidget(m_pShowFiles);
    topOptionsLayout->addWidget(m_pShowFolders);
    topOptionsLayout->addWidget(m_pShowMarkers);
    QFrame* separator = new QFrame(ViewOptionsWidget);
    separator->setFrameShape(QFrame::VLine);
    separator->setFrameShadow(QFrame::Sunken);
    topOptionsLayout->addWidget(separator);
    topOptionsLayout->addWidget(m_pShowAdded);
    topOptionsLayout->addWidget(m_pShowRemoved);
    topOptionsLayout->addWidget(m_pShowModified);
    topOptionsLayout->addWidget(m_pShowMetadata);
    topOptionsLayout->addStretch();
    QHBoxLayout* bottomOptionsLayout = new QHBoxLayout();
    bottomOptionsLayout->addStretch();
    QFrame* separator2 = new QFrame(ViewOptionsWidget);
    bottomOptionsLayout->addWidget(m_pShowColors);
    bottomOptionsLayout->addWidget(m_pHighlightSame);
    separator2->setFrameShape(QFrame::VLine);
    separator2->setFrameShadow(QFrame::Sunken);
    bottomOptionsLayout->addWidget(separator2);
    bottomOptionsLayout->addWidget(m_pHideEmpty);
    QFrame* separator3 = new QFrame(ViewOptionsWidget);
    separator3->setFrameShape(QFrame::VLine);
    separator3->setFrameShadow(QFrame::Sunken);
    bottomOptionsLayout->addWidget(separator3);
    bottomOptionsLayout->addWidget(m_pNormalizePaths);
    bottomOptionsLayout->addWidget(m_pGroupByParent);
    viewOptionsLayout->addLayout(topOptionsLayout);
    viewOptionsLayout->addLayout(bottomOptionsLayout);
    ViewOptionsWidget->setVisible(false);
    mainLayout->addWidget(ViewOptionsWidget);

    m_pTree = new QTreeWidgetEx(this);
    m_pTree->setColumnCount(8);
    m_pTree->setHeaderLabels(QStringList() << tr("Change") << tr("Path")
        << tr("Type") << tr("Old Size") << tr("New Size")
        << tr("Old Modified") << tr("New Modified") << tr("Hash Status"));
    m_pTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_pTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pTree->setAlternatingRowColors(theConf->GetBool("Options/AltRowColors", false));
    m_pTree->setSortingEnabled(true);
    m_pTree->setUniformRowHeights(true);
    m_pTree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_pFinder->SetTree(m_pTree);
    mainLayout->addWidget(m_pTree, 1);

    QHBoxLayout* limitsLayout = new QHBoxLayout();
    m_pSummary = new QLabel(this);
    m_pSummary->setWordWrap(true);
    QPushButton* configure = new QPushButton(CSandMan::GetIcon("Settings"),
        tr("Configure Limits and Options..."), this);
    limitsLayout->addWidget(m_pSummary, 1);
    limitsLayout->addWidget(configure);
    mainLayout->addLayout(limitsLayout);

    QHBoxLayout* bottomLayout = new QHBoxLayout();
    m_pStatus = new QLabel(this);
    m_pSelectionStatus = new QLabel(m_pHighlightSame->isChecked()
        ? tr("Selected: 0; Highlighted: 0") : tr("Selected: 0"), this);
    m_pSelectionStatus->setToolTip(tr(
        "Visible selected rows and total rows matching any selected SHA-256 "
        "hash, including selected matches."));
    m_pDeleteOlder = new QPushButton(CSandMan::GetIcon("Erase"),
        tr("Delete Older Generation..."), this);
    m_pDeleteNewer = new QPushButton(CSandMan::GetIcon("Erase"),
        tr("Delete Newer Generation..."), this);
    m_pDeleteAll = new QPushButton(CSandMan::GetIcon("Erase"),
        tr("Delete All Generations..."), this);
    QPushButton* openFolder = new QPushButton(CSandMan::GetIcon("Folder"),
        tr("Open History Folder"), this);
    QPushButton* close = new QPushButton(tr("Close"), this);
    bottomLayout->addWidget(m_pStatus, 1);
    bottomLayout->addWidget(m_pSelectionStatus);
    bottomLayout->addWidget(m_pDeleteOlder);
    bottomLayout->addWidget(m_pDeleteNewer);
    bottomLayout->addWidget(m_pDeleteAll);
    bottomLayout->addWidget(openFolder);
    bottomLayout->addWidget(close);
    mainLayout->addLayout(bottomLayout);

    connect(m_pRefresh, SIGNAL(clicked(bool)), this, SLOT(Reload()));
    connect(viewOptions, &QToolButton::toggled,
        this, [ViewOptionsWidget](bool expanded) {
            ViewOptionsWidget->setVisible(expanded);
        });
    connect(search, SIGNAL(toggled(bool)),
        m_pFilterScope, SLOT(setVisible(bool)));
    connect(m_pFilterScope, SIGNAL(currentIndexChanged(int)),
        this, SLOT(UpdateFilterScope()));
    connect(m_pCompare, SIGNAL(clicked(bool)), this, SLOT(Compare()));
    connect(m_pOlder, SIGNAL(currentIndexChanged(int)), this, SLOT(UpdateControls()));
    connect(m_pNewer, SIGNAL(currentIndexChanged(int)), this, SLOT(UpdateControls()));
    for (QCheckBox* check : { m_pShowAdded, m_pShowRemoved,
            m_pShowModified, m_pShowMetadata, m_pShowMarkers, m_pShowFiles,
            m_pShowFolders, m_pHideEmpty })
        connect(check, SIGNAL(toggled(bool)), this, SLOT(ApplyFilter()));
    connect(m_pShowColors, &QCheckBox::toggled,
        this, [this](bool) { ApplyViewOptions(); });
    connect(m_pHighlightSame, &QCheckBox::toggled,
        this, [this](bool) { UpdateSelection(); });
    connect(m_pNormalizePaths, &QCheckBox::toggled,
        this, [this](bool) { RebuildView(); });
    connect(m_pGroupByParent, &QCheckBox::toggled,
        this, [this](bool) { RebuildView(); });
    connect(m_pTree, SIGNAL(itemSelectionChanged()),
        this, SLOT(UpdateSelection()));
    connect(m_pTree, SIGNAL(customContextMenuRequested(const QPoint&)),
        this, SLOT(ShowContextMenu(const QPoint&)));
    connect(m_pDeleteOlder, SIGNAL(clicked(bool)), this, SLOT(DeleteOlder()));
    connect(m_pDeleteNewer, SIGNAL(clicked(bool)), this, SLOT(DeleteNewer()));
    connect(m_pDeleteAll, SIGNAL(clicked(bool)), this, SLOT(DeleteAll()));
    connect(openFolder, SIGNAL(clicked(bool)), this, SLOT(OpenHistoryFolder()));
    connect(configure, SIGNAL(clicked(bool)), this, SLOT(Configure()));
    connect(close, &QPushButton::clicked, this, [this]() { window()->close(); });

    m_pCopyCell = new QAction(CPanelView::m_CopyCell, this);
    m_pCopyRow = new QAction(CPanelView::m_CopyRow, this);
    m_pCopyPanel = new QAction(CPanelView::m_CopyPanel, this);
    m_pCopyRow->setShortcut(QKeySequence::Copy);
    m_pCopyRow->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    addAction(m_pCopyRow);
    connect(m_pCopyCell, SIGNAL(triggered(bool)), this, SLOT(CopyCell()));
    connect(m_pCopyRow, SIGNAL(triggered(bool)), this, SLOT(CopyRow()));
    connect(m_pCopyPanel, SIGNAL(triggered(bool)), this, SLOT(CopyPanel()));

    QByteArray state = theConf->GetBlob("FileStateHistoryWindow/Tree_Columns");
    if (!state.isEmpty())
        m_pTree->header()->restoreState(state);
    else {
        m_pTree->setColumnWidth(0, 140);
        m_pTree->setColumnWidth(1, 420);
    }
    m_pFinder->Open();
    if (m_pTabs)
        connect(m_pTabs, &QTabWidget::currentChanged, this,
            [this](int) {
                if (!m_Loaded && !m_Loading && IsActiveTab())
                    QTimer::singleShot(0, this, [this]() {
                        if (!m_Loaded && !m_Loading && IsActiveTab())
                            Reload();
                    });
            });
    QTimer::singleShot(100, this, [this]() {
        if (!m_Loaded && !m_Loading && IsActiveTab())
            Reload();
    });
}

CFileStateHistoryWidget::~CFileStateHistoryWidget()
{
    theConf->SetBlob("FileStateHistoryWindow/Tree_Columns",
        m_pTree->header()->saveState());
    theConf->SetValue("FileStateHistoryWindow/ShowAdded",
        m_pShowAdded->isChecked());
    theConf->SetValue("FileStateHistoryWindow/ShowRemoved",
        m_pShowRemoved->isChecked());
    theConf->SetValue("FileStateHistoryWindow/ShowModified",
        m_pShowModified->isChecked());
    theConf->SetValue("FileStateHistoryWindow/ShowMetadata",
        m_pShowMetadata->isChecked());
    theConf->SetValue("FileStateHistoryWindow/ShowDeletionMarkers",
        m_pShowMarkers->isChecked());
    theConf->SetValue("FileStateHistoryWindow/ShowChangeColors",
        m_pShowColors->isChecked());
    theConf->SetValue("FileStateHistoryWindow/HighlightSameHash",
        m_pHighlightSame->isChecked());
    theConf->SetValue("FileStateHistoryWindow/ShowFiles",
        m_pShowFiles->isChecked());
    theConf->SetValue("FileStateHistoryWindow/ShowFolders",
        m_pShowFolders->isChecked());
    theConf->SetValue("FileStateHistoryWindow/HideEmptyFiles",
        m_pHideEmpty->isChecked());
    theConf->SetValue("FileStateHistoryWindow/NormalizePaths",
        m_pNormalizePaths->isChecked());
    theConf->SetValue("FileStateHistoryWindow/GroupByParentFolder",
        m_pGroupByParent->isChecked());
    theConf->SetValue("FileStateHistoryWindow/AutoCompare",
        m_pAutoCompare->isChecked());
}

void CFileStateHistoryWidget::SetProgressVisible(bool Visible)
{
    if (Visible)
        m_pLoadStack->setCurrentWidget(m_pLoadIndicator);
    else
        m_pLoadStack->setCurrentWidget(m_pAutoCompare);
}

bool CFileStateHistoryWidget::ReadMap(const QString& generation,
    QHash<QString, SFileStateEntry>& entries,
    QHash<QString, QString>& deletionMarkers, QString& snapshotBase,
    QString& error) const
{
    entries.clear();
    deletionMarkers.clear();
    snapshotBase.clear();
    if (generation.isEmpty())
        return true;
    if (!IsGenerationName(generation)) {
        error = tr("Invalid file-state generation name.");
        return false;
    }
    QString root = QDir(m_pBox->GetFileRoot()).filePath(
        "FileStateHistory/" + generation);
    if (!IsSafeDirectory(root) ||
            !IsSafeFile(QDir(root).filePath("Generation.ini")) ||
            !IsSafeFile(QDir(root).filePath("FileMap.dat"))) {
        error = tr("The selected file-state generation is incomplete or unsafe.");
        return false;
    }
    if (ReadIniValue(QDir(root).filePath("Generation.ini"), "Version") !=
            QStringLiteral("1")) {
        error = tr("The selected file-state generation uses an unsupported format.");
        return false;
    }
    QString metadataPath = QDir(root).filePath("Generation.ini");
    snapshotBase = ReadIniValue(metadataPath,
        "SnapshotBase");
    bool deleteModeOk = false;
    QString deleteModeText = ReadIniValue(metadataPath, "DeleteMode");
    int deleteMode = deleteModeText.isEmpty()
        ? 1 : deleteModeText.toInt(&deleteModeOk);
    if ((!deleteModeText.isEmpty() && !deleteModeOk) ||
            deleteMode < 1 || deleteMode > 3) {
        error = tr("The selected file-state generation has invalid deletion metadata.");
        return false;
    }

    QFile file(QDir(root).filePath("FileMap.dat"));
    if (!file.open(QIODevice::ReadOnly) || file.size() > MaxMapBytes) {
        error = tr("The selected file map is unavailable or exceeds the safe read limit.");
        return false;
    }
    if (file.readLine() != QByteArray("SBIE_FILE_STATE_MAP\t1\n")) {
        error = tr("The selected file map has an invalid header.");
        return false;
    }
    while (!file.atEnd()) {
        QByteArray line = file.readLine();
        if (line.endsWith('\n'))
            line.chop(1);
        if (line.endsWith('\r'))
            line.chop(1);
        if (line.isEmpty())
            continue;
        QList<QByteArray> fields = line.split('\t');
        if (fields.size() != 7 || entries.size() >= MaxMapEntries) {
            error = tr("The selected file map is malformed or contains too many entries.");
            return false;
        }
        bool attributesOk = false;
        bool sizeOk = false;
        bool createdOk = false;
        bool modifiedOk = false;
        bool pathOk = false;
        SFileStateEntry entry;
        entry.Directory = fields.at(0) == "D";
        if (!entry.Directory && fields.at(0) != "F") {
            error = tr("The selected file map contains an invalid entry type.");
            return false;
        }
        entry.Attributes = fields.at(1).toUInt(&attributesOk, 16);
        entry.Size = fields.at(2).toULongLong(&sizeOk, 10);
        entry.Created = fields.at(3).toULongLong(&createdOk, 16);
        entry.Modified = fields.at(4).toULongLong(&modifiedOk, 16);
        if (fields.at(5) == "!")
            entry.HashUnavailable = true;
        else if (fields.at(5) != "-") {
            if (fields.at(5).size() != 64) {
                error = tr("The selected file map contains an invalid hash.");
                return false;
            }
            for (char ch : fields.at(5)) {
                if (!((ch >= '0' && ch <= '9') ||
                        (ch >= 'a' && ch <= 'f') ||
                        (ch >= 'A' && ch <= 'F'))) {
                    error = tr("The selected file map contains an invalid hash.");
                    return false;
                }
            }
            entry.Hash = QByteArray::fromHex(fields.at(5));
            if (entry.Hash.size() != 32) {
                error = tr("The selected file map contains an invalid hash.");
                return false;
            }
        }
        entry.Path = UnescapePath(fields.at(6), pathOk);
        QString rawPath = entry.Path;
        rawPath.replace('/', '\\');
        QString normalized = QDir::cleanPath(rawPath).replace('/', '\\');
        if (!attributesOk || !sizeOk || !createdOk || !modifiedOk || !pathOk ||
                normalized.isEmpty() || normalized == "." ||
                normalized.startsWith("..\\") || normalized.contains(":") ||
                normalized.startsWith('\\') || normalized != rawPath) {
            error = tr("The selected file map contains an invalid path or field.");
            return false;
        }
        entry.Path = normalized;
        QString key = normalized.toCaseFolded();
        if (entries.contains(key)) {
            error = tr("The selected file map contains duplicate paths.");
            return false;
        }
        entries.insert(key, entry);
    }
    return ReadDeleteMarkers(root, deleteMode, deletionMarkers, error);
}

QString CFileStateHistoryWidget::BoxRelativePath(const QString& truePath) const
{
    QString logicalPath = QDir::toNativeSeparators(truePath);
    int serialSeparator = logicalPath.indexOf(':');
    if (serialSeparator > 2 && logicalPath.at(1) == QLatin1Char('~') &&
            logicalPath.at(0).isLetter())
        logicalPath = logicalPath.left(1) + logicalPath.mid(serialSeparator);
    QString boxedPath = QDir::toNativeSeparators(
        theAPI->GetBoxedPath(m_pBox.data(), logicalPath));
    QString boxRoot = QDir::toNativeSeparators(m_pBox->GetFileRoot());
    while (boxRoot.endsWith(QLatin1Char('\\')))
        boxRoot.chop(1);
    if (boxedPath.compare(boxRoot, Qt::CaseInsensitive) == 0)
        return QString();
    QString prefix = boxRoot + QLatin1Char('\\');
    if (!boxedPath.startsWith(prefix, Qt::CaseInsensitive))
        return QString();
    QString relative = boxedPath.mid(prefix.length());
    QString normalized = QDir::cleanPath(relative).replace('/', '\\');
    if (normalized.isEmpty() || normalized == QStringLiteral(".") ||
            normalized.startsWith(QStringLiteral("..\\")) ||
            normalized.startsWith(QLatin1Char('\\')) || normalized.contains(':'))
        return QString();
    return normalized;
}

bool CFileStateHistoryWidget::ReadDeleteMarkers(const QString& generationPath,
    int deleteMode, QHash<QString, QString>& markers, QString& error) const
{
    auto unescape = [](const QString& field) {
        QString result;
        result.reserve(field.length());
        for (int index = 0; index < field.length(); ++index) {
            QChar ch = field.at(index);
            if (ch != QLatin1Char('\\') || index + 1 >= field.length()) {
                result += ch;
                continue;
            }
            QChar escaped = field.at(++index);
            if (escaped == QLatin1Char('|') || escaped == QLatin1Char('\\'))
                result += escaped;
            else if (escaped == QLatin1Char('r'))
                result += QChar('\r');
            else if (escaped == QLatin1Char('n'))
                result += QChar('\n');
            else {
                result += QLatin1Char('\\');
                result += escaped;
            }
        }
        return result;
    };
    auto findPipe = [](const QString& line, int start) {
        for (int index = start; index < line.length(); ++index) {
            if (line.at(index) == QLatin1Char('\\') &&
                    index + 1 < line.length()) {
                ++index;
                continue;
            }
            if (line.at(index) == QLatin1Char('|'))
                return index;
        }
        return -1;
    };
    auto addMarker = [this, &markers](const QString& truePath) {
        QString relative = BoxRelativePath(truePath);
        if (!relative.isEmpty())
            markers.insert(relative.toCaseFolded(), relative);
    };
    auto readFile = [&](const QString& name, bool version3, bool journal) {
        QString path = QDir(generationPath).filePath(name);
        DWORD attributes = GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(path.utf16()));
        DWORD attributeError = GetLastError();
        if (attributes == INVALID_FILE_ATTRIBUTES &&
                (attributeError == ERROR_FILE_NOT_FOUND ||
                 attributeError == ERROR_PATH_NOT_FOUND))
            return true;
        QFile file(path);
        if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & (FILE_ATTRIBUTE_DIRECTORY |
                    FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
                file.size() > MaxMapBytes || !file.open(QFile::ReadOnly)) {
            error = tr("File deletion metadata is unavailable or unsafe: %1")
                .arg(path);
            return false;
        }
        QByteArray data = file.readAll();
        if (file.error() != QFile::NoError ||
                (!journal && (data.size() & 1) != 0)) {
            error = tr("Could not read file deletion metadata: %1").arg(path);
            return false;
        }
        if ((data.size() & 1) != 0)
            data.chop(1);
        QString contents;
        if (!data.isEmpty()) {
            const quint16* utf16 = reinterpret_cast<const quint16*>(
                data.constData());
            int length = data.size() / int(sizeof(quint16));
            if (length > 0 && utf16[0] == 0xFEFF) {
                ++utf16;
                --length;
            }
            contents = FromUtf16(utf16, length);
        }
        if (!contents.isEmpty() && !contents.endsWith('\n')) {
            if (!journal) {
                error = tr("File deletion metadata has an incomplete final line: %1")
                    .arg(path);
                return false;
            }
            int newline = contents.lastIndexOf('\n');
            contents = newline >= 0 ? contents.left(newline + 1) : QString();
        }
        for (QString line : contents.split('\n')) {
            if (line.endsWith('\r'))
                line.chop(1);
            if (line.isEmpty())
                continue;
            if (!version3) {
                QStringList parts = line.split('|');
                bool ok = false;
                quint32 flags = parts.value(1).toUInt(&ok, 16);
                if (ok && (flags & 1) != 0)
                    addMarker(parts.value(0));
            }
            else {
                int first = findPipe(line, 0);
                if (first < 0)
                    continue;
                int second = findPipe(line, first + 1);
                QString operation = second < 0
                    ? line.mid(first + 1)
                    : line.mid(first + 1, second - first - 1);
                QString firstPath = unescape(line.left(first));
                if (operation == QStringLiteral("1"))
                    addMarker(firstPath);
            }
            if (markers.size() > MaxMapEntries) {
                error = tr("File deletion metadata contains too many entries.");
                return false;
            }
        }
        return true;
    };

    bool ok = deleteMode == 1 ||
        (deleteMode == 2 && readFile(QStringLiteral("FilePaths.dat"),
            false, false)) ||
        (deleteMode == 3 &&
            readFile(QStringLiteral("FilePaths_v3.dat"), true, false) &&
            readFile(QStringLiteral("FilePaths_v3.sbie"), true, true));
    if (!ok)
        return false;

    QList<QString> keys = markers.keys();
    for (const QString& key : keys) {
        QString parent = markers.value(key);
        for (;;) {
            int separator = parent.lastIndexOf('\\');
            if (separator < 0)
                break;
            parent.truncate(separator);
            if (markers.contains(parent.toCaseFolded())) {
                markers.remove(key);
                break;
            }
        }
    }
    return true;
}

void CFileStateHistoryWidget::Reload()
{
    if (!m_Loaded && !IsActiveTab())
        return;
    if (m_Loading) {
        m_AbortRequested = true;
        return;
    }
    m_AbortRequested = false;
    m_Loading = true;
    m_pRefresh->setIcon(CSandMan::GetIcon("Stop"));
    m_pRefresh->setText(tr("Abort"));
    m_pRefresh->setEnabled(true);
    QString loadPrefix = m_Loaded ? tr("Refreshing...") : tr("Loading...");
    SetProgressVisible(true);
    m_pLoadIndicator->setText(loadPrefix);
    m_pLoadIndicator->repaint();
    m_pRefresh->repaint();
    auto AbortReload = [this]() {
        m_pOlder->clear();
        m_pNewer->clear();
        m_pTree->clear();
        m_pLoadIndicator->clear();
        SetProgressVisible(false);
        m_pStatus->setText(tr("Refresh aborted."));
        m_pRefresh->setIcon(CSandMan::GetIcon("Refresh"));
        m_pRefresh->setText(tr("Refresh"));
        m_pRefresh->setEnabled(true);
        m_AbortRequested = false;
        m_Loading = false;
    };
    QString oldName = m_pOlder->currentData().toString();
    QString newName = m_pNewer->currentData().toString();
    m_pOlder->clear();
    m_pNewer->clear();
    m_pTree->clear();

    QString historyPath = QDir(m_pBox->GetFileRoot()).filePath("FileStateHistory");
    QStringList generations;
    quint64 usedSize = 0;
    if (IsSafeDirectory(historyPath)) {
        QDir history(historyPath);
        generations = history.entryList(QDir::Dirs | QDir::NoDotAndDotDot |
            QDir::NoSymLinks, QDir::Name);
        for (int index = generations.size() - 1; index >= 0; --index) {
            QString path = history.filePath(generations.at(index));
            if (!IsGenerationName(generations.at(index)) ||
                    !IsSafeDirectory(path) ||
                    !IsSafeFile(QDir(path).filePath("Generation.ini")) ||
                    !IsSafeFile(QDir(path).filePath("FileMap.dat")))
                generations.removeAt(index);
        }
        QCoreApplication::processEvents(QEventLoop::AllEvents);
        if (m_AbortRequested) {
            AbortReload();
            return;
        }
        for (int index = 0; index < generations.size(); ++index) {
            if (index == 0 || index + 1 == generations.size() ||
                    ((index + 1) % 16) == 0) {
                m_pLoadIndicator->setText(tr("%1 %2 / %3 generations")
                    .arg(loadPrefix).arg(index + 1).arg(generations.size()));
                m_pLoadIndicator->repaint();
            }
            QCoreApplication::processEvents(QEventLoop::AllEvents);
            if (m_AbortRequested) {
                AbortReload();
                return;
            }
            QDir generation(history.filePath(generations.at(index)));
            const QFileInfoList files = generation.entryInfoList(
                QDir::Files | QDir::Hidden | QDir::System |
                    QDir::NoSymLinks);
            for (const QFileInfo& file : files) {
                if (IsSafeFile(file.absoluteFilePath()))
                    usedSize += quint64(file.size());
                QCoreApplication::processEvents(QEventLoop::AllEvents);
                if (m_AbortRequested) {
                    AbortReload();
                    return;
                }
            }
        }
    }
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    if (m_AbortRequested) {
        AbortReload();
        return;
    }

    if (generations.size() == 1)
        m_pOlder->addItem(tr("Assumed clean box"), QString());
    for (const QString& generation : generations) {
        m_pOlder->addItem(generation, generation);
        m_pNewer->addItem(generation, generation);
    }
    bool autoCompare = m_pAutoCompare->isChecked();
    if (generations.size() == 1) {
        m_pOlder->setCurrentIndex(0);
        m_pNewer->setCurrentIndex(0);
    }
    else if (generations.size() >= 2) {
        int oldIndex = m_pOlder->findData(oldName);
        int newIndex = m_pNewer->findData(newName);
        m_pOlder->setCurrentIndex(autoCompare || oldIndex < 0
            ? generations.size() - 2 : oldIndex);
        m_pNewer->setCurrentIndex(autoCompare || newIndex < 0
            ? generations.size() - 1 : newIndex);
    }

    int generationLimit = m_pBox->GetNum(
        "FileStateHistoryMaxGenerations", 20, true, true);
    int sizeLimit = m_pBox->GetNum(
        "FileStateHistoryMaxSizeKB", 256 * 1024, true, true);
    QString generationLimitText = generationLimit == 0
        ? tr("unlimited") : QString::number(generationLimit);
    QString sizeLimitText = sizeLimit == 0
        ? tr("unlimited") : FormatSize(quint64(sizeLimit) * 1024);
    QString note;
    if (generations.size() == 1) {
        note = tr(" The capture is compared with an assumed clean box; run and "
            "close the sandbox again for a two-generation comparison.");
    }
    else if (generations.isEmpty()) {
        note = m_pBox->GetBool("FileStateHistory", false, true, true)
            ? tr(" No captures exist yet; run and close the sandbox to create one.")
            : tr(" File-state capture is disabled.");
    }
    else if (!m_pBox->GetBool("FileStateHistory", false, true, true))
        note = tr(" File-state capture is disabled.");
    m_pSummary->setText(tr("Usage / limits: %1 / %2 generation(s); %3 / %4.%5")
        .arg(generations.size()).arg(generationLimitText)
        .arg(FormatSize(usedSize)).arg(sizeLimitText).arg(note));
    m_pStatus->setText(tr("Listed: 0 change(s); %1 generation(s)")
        .arg(generations.size()));
    UpdateControls();
    UpdateSelection();
    m_pLoadIndicator->clear();
    SetProgressVisible(false);
    m_pRefresh->setIcon(CSandMan::GetIcon("Refresh"));
    m_pRefresh->setText(tr("Refresh"));
    m_pRefresh->setEnabled(true);
    m_Loading = false;
    m_Loaded = true;
    if (autoCompare && !generations.isEmpty())
        QTimer::singleShot(0, this, SLOT(Compare()));
}

void CFileStateHistoryWidget::UpdateControls()
{
    QString older = m_pOlder->currentData().toString();
    QString newer = m_pNewer->currentData().toString();
    m_pCompare->setEnabled(m_pNewer->currentIndex() >= 0 && older != newer);
    m_pDeleteOlder->setEnabled(!older.isEmpty());
    m_pDeleteNewer->setEnabled(!newer.isEmpty());
    m_pDeleteAll->setEnabled(IsSafeDirectory(
        QDir(m_pBox->GetFileRoot()).filePath("FileStateHistory")));
}

void CFileStateHistoryWidget::ResizeColumns()
{
    for (int column = 0; column < m_pTree->columnCount(); ++column)
        m_pTree->resizeColumnToContents(column);
}

void CFileStateHistoryWidget::SetFilter(
    const QRegularExpression& regExp, int options, int column)
{
    Q_UNUSED(options);
    Q_UNUSED(column);
    m_FilterExp = regExp;
    ApplyFilter();
}

void CFileStateHistoryWidget::UpdateFilterScope()
{
    ApplyFilter();
}

bool CFileStateHistoryWidget::IsActiveTab() const
{
    return !m_pTabs || m_pTabs->currentWidget() == this;
}

void CFileStateHistoryWidget::Compare()
{
    if (m_Loading)
        return;
    QString olderName = m_pOlder->currentData().toString();
    QString newerName = m_pNewer->currentData().toString();
    if (newerName.isEmpty() || olderName == newerName)
        return;
    if (!olderName.isEmpty() && olderName > newerName)
        qSwap(olderName, newerName);
    QHash<QString, SFileStateEntry> older;
    QHash<QString, SFileStateEntry> newer;
    QHash<QString, QString> olderMarkers;
    QHash<QString, QString> newerMarkers;
    QString olderSnapshot;
    QString newerSnapshot;
    QString error;
    SetProgressVisible(true);
    m_pLoadIndicator->setText(tr("Comparing..."));
    m_pLoadIndicator->repaint();
    m_pRefresh->setEnabled(false);
    m_pCompare->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    if (!ReadMap(olderName, older, olderMarkers, olderSnapshot, error) ||
            !ReadMap(newerName, newer, newerMarkers, newerSnapshot, error)) {
        QApplication::restoreOverrideCursor();
        m_pLoadIndicator->clear();
        SetProgressVisible(false);
        m_pRefresh->setEnabled(true);
        UpdateControls();
        if (IsActiveTab())
            QMessageBox::critical(this, tr("File Changes"), error);
        else
            m_pStatus->setText(error);
        return;
    }
    QApplication::restoreOverrideCursor();
    if (!olderName.isEmpty() && olderSnapshot != newerSnapshot &&
            IsActiveTab() && QMessageBox::warning(this,
                tr("Sandbox Snapshot Base Changed"), tr(
                    "The selected captures use different Sandboxie snapshot bases. "
                    "A physical-layer comparison can contain many unrelated changes. "
                    "Continue with a best-effort comparison?"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) {
        m_pLoadIndicator->clear();
        SetProgressVisible(false);
        m_pRefresh->setEnabled(true);
        UpdateControls();
        return;
    }

    m_pTree->setSortingEnabled(false);
    m_pTree->clear();
    QSet<QString> keys;
    for (auto it = older.constBegin(); it != older.constEnd(); ++it)
        keys.insert(it.key());
    for (auto it = newer.constBegin(); it != newer.constEnd(); ++it)
        keys.insert(it.key());

    int changes = 0;
    for (const QString& key : keys) {
        bool hasOld = older.contains(key);
        bool hasNew = newer.contains(key);
        const SFileStateEntry oldEntry = older.value(key);
        const SFileStateEntry newEntry = newer.value(key);
        int change = 0;
        if (!hasOld)
            change = eAdded;
        else if (!hasNew)
            change = eRemoved;
        else if (oldEntry.Directory != newEntry.Directory)
            change = eTypeChanged;
        else {
            bool metadataChanged = oldEntry.Attributes != newEntry.Attributes;
            if (!oldEntry.Directory)
                metadataChanged = metadataChanged || oldEntry.Size != newEntry.Size ||
                    oldEntry.Created != newEntry.Created ||
                    oldEntry.Modified != newEntry.Modified;
            if (!oldEntry.Hash.isEmpty() && !newEntry.Hash.isEmpty()) {
                if (oldEntry.Hash != newEntry.Hash)
                    change = eContentModified;
                else if (metadataChanged)
                    change = eMetadataModified;
            }
            else if (metadataChanged)
                change = eModified;
        }
        if (!change)
            continue;

        const SFileStateEntry& display = hasNew ? newEntry : oldEntry;
        QString hashStatus;
        if (!oldEntry.Hash.isEmpty() && !newEntry.Hash.isEmpty())
            hashStatus = oldEntry.Hash == newEntry.Hash
                ? tr("Same SHA-256") : tr("Different SHA-256");
        else if (!hasOld || !hasNew)
            hashStatus = !display.Hash.isEmpty()
                ? tr("SHA-256 captured")
                : (display.HashUnavailable ? tr("Hash unavailable") : tr("Not hashed"));
        else if (oldEntry.HashUnavailable || newEntry.HashUnavailable)
            hashStatus = tr("Hash unavailable");
        else if (!oldEntry.Hash.isEmpty() || !newEntry.Hash.isEmpty())
            hashStatus = tr("SHA-256 captured in one generation");
        else
            hashStatus = tr("Not hashed");
        QTreeWidgetItem* item = new CFileStateTreeItem(m_pTree,
            QStringList() << ChangeName(change) << display.Path
            << (display.Directory ? tr("Folder") : tr("File"))
            << (hasOld && !oldEntry.Directory
                ? FormatSize(oldEntry.Size) : QString())
            << (hasNew && !newEntry.Directory
                ? FormatSize(newEntry.Size) : QString())
            << (hasOld ? FormatFileTime(oldEntry.Modified) : QString())
            << (hasNew ? FormatFileTime(newEntry.Modified) : QString())
            << hashStatus);
        if (hasOld && !oldEntry.Directory)
            item->setData(3, eSortRole, oldEntry.Size);
        if (hasNew && !newEntry.Directory)
            item->setData(4, eSortRole, newEntry.Size);
        item->setData(0, eChangeRole, change);
        item->setData(0, eDirectoryRole, display.Directory);
        item->setData(0, eSizeRole, display.Size);
        item->setData(0, eRawPathRole, display.Path);
        item->setData(0, eOldHashRole,
            QString::fromLatin1(oldEntry.Hash.toHex()));
        item->setData(0, eNewHashRole,
            QString::fromLatin1(newEntry.Hash.toHex()));
        QStringList hashes;
        if (!oldEntry.Hash.isEmpty() && oldEntry.Hash == newEntry.Hash) {
            hashes.append(tr("SHA-256: %1").arg(
                QString::fromLatin1(oldEntry.Hash.toHex())));
        }
        else if (!oldEntry.Hash.isEmpty()) {
            hashes.append(tr("Old SHA-256: %1").arg(
                QString::fromLatin1(oldEntry.Hash.toHex())));
        }
        if (!newEntry.Hash.isEmpty() && oldEntry.Hash != newEntry.Hash)
            hashes.append(tr("New SHA-256: %1").arg(
                QString::fromLatin1(newEntry.Hash.toHex())));
        if (!hashes.isEmpty())
            item->setToolTip(7, hashes.join(QLatin1Char('\n')));
        ++changes;
    }

    QSet<QString> markerKeys;
    for (auto it = olderMarkers.constBegin();
            it != olderMarkers.constEnd(); ++it)
        markerKeys.insert(it.key());
    for (auto it = newerMarkers.constBegin();
            it != newerMarkers.constEnd(); ++it)
        markerKeys.insert(it.key());
    for (const QString& key : markerKeys) {
        bool hadMarker = olderMarkers.contains(key);
        bool hasMarker = newerMarkers.contains(key);
        if (hadMarker == hasMarker)
            continue;
        QString rawPath = hasMarker
            ? newerMarkers.value(key) : olderMarkers.value(key);
        int change = hasMarker ? eRemoved : eAdded;
        QTreeWidgetItem* item = new CFileStateTreeItem(m_pTree,
            QStringList()
            << (hasMarker ? tr("Deletion marker added")
                          : tr("Deletion marker removed"))
            << rawPath << tr("Deletion marker")
            << QString() << QString() << QString() << QString() << QString());
        item->setData(0, eChangeRole, change);
        item->setData(0, eDirectoryRole, false);
        item->setData(0, eSizeRole, 0);
        item->setData(0, eRawPathRole, rawPath);
        item->setData(0, eMarkerRole, true);
        ++changes;
    }
    RebuildView();
    m_pLoadIndicator->clear();
    SetProgressVisible(false);
    m_pRefresh->setEnabled(true);
    UpdateControls();
    if (changes == 0 && IsActiveTab())
        QMessageBox::information(this, tr("File Changes"),
            tr("The selected file-state generations contain no differences."));
}

QString CFileStateHistoryWidget::DisplayPath(const QString& rawPath) const
{
    if (!m_pNormalizePaths->isChecked())
        return rawPath;
    QString physicalPath = QDir::toNativeSeparators(
        QDir(m_pBox->GetFileRoot()).filePath(rawPath));
    QString logicalPath = theAPI->GetRealPath(m_pBox.data(), physicalPath);
    return logicalPath.isEmpty() ? rawPath : QDir::toNativeSeparators(logicalPath);
}

void CFileStateHistoryWidget::RebuildView()
{
    int sortColumn = m_pTree->header()->sortIndicatorSection();
    Qt::SortOrder sortOrder = m_pTree->header()->sortIndicatorOrder();
    QTreeWidgetItem* currentItem = m_pTree->currentItem();
    if (currentItem && currentItem->data(0, eGroupRole).toBool())
        currentItem = NULL;
    int currentColumn = m_pTree->currentColumn();
    m_pTree->setSortingEnabled(false);

    QList<QTreeWidgetItem*> changes;
    while (m_pTree->topLevelItemCount() != 0) {
        QTreeWidgetItem* item = m_pTree->takeTopLevelItem(0);
        if (!item->data(0, eGroupRole).toBool()) {
            changes.append(item);
            continue;
        }
        while (item->childCount() != 0)
            changes.append(item->takeChild(0));
        delete item;
    }

    QMap<QString, QTreeWidgetItem*> groups;
    for (QTreeWidgetItem* item : changes) {
        QString path = DisplayPath(
            item->data(0, eRawPathRole).toString());
        item->setText(1, path);
        item->setData(1, Qt::ToolTipRole, path);
        if (!m_pGroupByParent->isChecked()) {
            m_pTree->addTopLevelItem(item);
            continue;
        }

        QString normalizedPath = QDir::toNativeSeparators(
            QDir::cleanPath(path));
        QString parentPath = QDir::toNativeSeparators(
            QFileInfo(normalizedPath).path());
        bool driveRoot = normalizedPath.size() == 2 &&
            normalizedPath.at(1) == QLatin1Char(':');
        if (parentPath == QStringLiteral(".") || driveRoot ||
                parentPath.compare(normalizedPath, Qt::CaseInsensitive) == 0)
            parentPath = tr("(No parent folder)");
        QString parentKey = parentPath.toCaseFolded();
        QTreeWidgetItem* group = groups.value(parentKey);
        if (!group) {
            group = new CFileStateTreeItem(m_pTree,
                QStringList() << tr("Parent folder") << parentPath);
            group->setIcon(0, CSandMan::GetIcon("Folder"));
            group->setData(0, eGroupRole, true);
            group->setFlags(group->flags() & ~Qt::ItemIsSelectable);
            group->setData(1, Qt::ToolTipRole,
                tr("%1\nContains file changes from this folder.")
                    .arg(parentPath));
            group->setExpanded(true);
            groups.insert(parentKey, group);
        }
        group->addChild(item);
    }

    m_pTree->setSortingEnabled(true);
    if (sortColumn < 0 || sortColumn >= m_pTree->columnCount())
        sortColumn = 1;
    m_pTree->sortItems(sortColumn, sortOrder);
    ApplyViewOptions();
    if (currentItem)
        m_pTree->setCurrentItem(currentItem, currentColumn,
            QItemSelectionModel::NoUpdate);
    ApplyFilter();
}

void CFileStateHistoryWidget::ApplyViewOptions()
{
    for (int index = 0; index < m_pTree->topLevelItemCount(); ++index) {
        QTreeWidgetItem* item = m_pTree->topLevelItem(index);
        QList<QTreeWidgetItem*> items;
        if (item->data(0, eGroupRole).toBool()) {
            for (int child = 0; child < item->childCount(); ++child)
                items.append(item->child(child));
        }
        else
            items.append(item);
        for (QTreeWidgetItem* change : items) {
            QBrush brush;
            if (m_pShowColors->isChecked())
                brush = QBrush(ChangeColor(
                    change->data(0, eChangeRole).toInt()));
            for (int column = 0; column < m_pTree->columnCount(); ++column)
                change->setBackground(column, brush);
        }
    }
    UpdateSelection();
}

QString CFileStateHistoryWidget::FilterText(QTreeWidgetItem* Item,
    int Scope) const
{
    QStringList Values = Scope == eAllFields
        ? HistoryWindowUtils::VisibleRow(m_pTree, Item)
        : QStringList() << Item->text(Scope);
    if (Scope == eAllFields || Scope == eHashField) {
        for (int Role : { eOldHashRole, eNewHashRole }) {
            QString Hash = Item->data(0, Role).toString();
            if (Hash.size() == 64)
                Values.append(Hash);
        }
    }
    return Values.join(QLatin1Char('\n'));
}

void CFileStateHistoryWidget::ApplyFilter()
{
    int visible = 0;
    int total = 0;
    int scope = m_pFilterScope->currentData().toInt();
    auto filterItem = [this, scope, &visible, &total](QTreeWidgetItem* item) {
        ++total;
        int change = item->data(0, eChangeRole).toInt();
        bool directory = item->data(0, eDirectoryRole).toBool();
        bool marker = item->data(0, eMarkerRole).toBool();
        QString filterText = FilterText(item, scope);
        bool show = m_FilterExp.pattern().isEmpty() ||
            m_FilterExp.match(filterText).hasMatch();
        if (!marker)
            show = show && (directory ? m_pShowFolders->isChecked()
                : m_pShowFiles->isChecked());
        if (marker)
            show = show && m_pShowMarkers->isChecked();
        if (!marker && !directory && m_pHideEmpty->isChecked() &&
                item->data(0, eSizeRole).toULongLong() == 0)
            show = false;
        if (change == eAdded)
            show = show && m_pShowAdded->isChecked();
        else if (change == eRemoved)
            show = show && m_pShowRemoved->isChecked();
        else if (change == eMetadataModified)
            show = show && m_pShowMetadata->isChecked();
        else
            show = show && m_pShowModified->isChecked();
        item->setHidden(!show);
        if (show)
            ++visible;
        return show;
    };
    for (int index = 0; index < m_pTree->topLevelItemCount(); ++index) {
        QTreeWidgetItem* item = m_pTree->topLevelItem(index);
        if (!item->data(0, eGroupRole).toBool()) {
            filterItem(item);
            continue;
        }
        bool showGroup = false;
        for (int child = 0; child < item->childCount(); ++child)
            showGroup |= filterItem(item->child(child));
        item->setHidden(!showGroup);
    }
    m_pStatus->setText(tr("Listed: %1 of %2 change(s)")
        .arg(visible).arg(total));
    UpdateSelection();
}

void CFileStateHistoryWidget::UpdateSelection()
{
    QSet<QString> selectedHashes;
    if (m_pHighlightSame->isChecked()) {
        for (QTreeWidgetItem* item : m_pTree->selectedItems()) {
            for (int role : { eOldHashRole, eNewHashRole }) {
                QString hash = item->data(0, role).toString();
                if (hash.size() == 64)
                    selectedHashes.insert(hash.toLower());
            }
        }
    }
    QBrush matchBrush(theGUI->m_DarkTheme
        ? QColor(125, 105, 0) : QColor(255, 248, 190));
    int selected = 0;
    int highlighted = 0;
    for (int index = 0; index < m_pTree->topLevelItemCount(); ++index) {
        QTreeWidgetItem* topLevel = m_pTree->topLevelItem(index);
        QList<QTreeWidgetItem*> items;
        if (topLevel->data(0, eGroupRole).toBool()) {
            for (int child = 0; child < topLevel->childCount(); ++child)
                items.append(topLevel->child(child));
        }
        else
            items.append(topLevel);
        for (QTreeWidgetItem* item : items) {
            QBrush brush;
            if (m_pShowColors->isChecked())
                brush = QBrush(ChangeColor(
                    item->data(0, eChangeRole).toInt()));
            QStringList hashes;
            for (int role : { eOldHashRole, eNewHashRole }) {
                QString hash = item->data(0, role).toString();
                if (hash.size() == 64)
                    hashes.append(hash.toLower());
            }
            bool match = false;
            for (const QString& hash : hashes) {
                if (selectedHashes.contains(hash)) {
                    match = true;
                    break;
                }
            }
            if (match)
                brush = matchBrush;
            for (int column = 0; column < m_pTree->columnCount(); ++column)
                item->setBackground(column, brush);
            if (!item->isHidden()) {
                if (item->isSelected())
                    ++selected;
                if (match)
                    ++highlighted;
            }
        }
    }
    m_pSelectionStatus->setText(m_pHighlightSame->isChecked()
        ? tr("Selected: %1; Highlighted: %2")
            .arg(selected).arg(highlighted)
        : tr("Selected: %1").arg(selected));
}

void CFileStateHistoryWidget::ShowContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* item = m_pTree->itemAt(pos);
    if (!item || item->data(0, eGroupRole).toBool())
        return;
    if (!item->isSelected()) {
        m_pTree->clearSelection();
        item->setSelected(true);
    }
    int column = m_pTree->columnAt(pos.x());
    if (column < 0)
        column = 0;
    m_pTree->setCurrentItem(item, column, QItemSelectionModel::NoUpdate);

    QMenu menu(this);
    menu.setToolTipsVisible(true);
    QMenu* openFolder = menu.addMenu(
        CSandMan::GetIcon("Folder"), tr("Open Folder in Windows Explorer"));
    QAction* openUnsandboxed = openFolder->addAction(tr("Unsandboxed"));
    QAction* openSandboxed = openFolder->addAction(
        CSandMan::GetIcon("Run"), tr("Sandboxed"));
    openSandboxed->setToolTip(tr(
        "Starts Windows Explorer inside this sandbox and may create another "
        "file-state generation after Explorer exits."));
    QString openRawPath = item->data(0, eRawPathRole).toString();
    bool openDirectory = item->data(0, eDirectoryRole).toBool();
    connect(openUnsandboxed, &QAction::triggered, this,
        [this, openRawPath, openDirectory]() {
            OpenSelectedFolder(openRawPath, openDirectory, false);
        });
    connect(openSandboxed, &QAction::triggered, this,
        [this, openRawPath, openDirectory]() {
            OpenSelectedFolder(openRawPath, openDirectory, true);
        });
    menu.addSeparator();
    QAction* useFilter = menu.addAction(tr("Use as Filter"));
    QAction* excludeFilter = menu.addAction(tr("Exclude from View"));
    bool hasFilterValue = false;
    for (QTreeWidgetItem* selected : m_pTree->selectedItems()) {
        if (!selected->text(column).isEmpty()) {
            hasFilterValue = true;
            break;
        }
    }
    useFilter->setEnabled(hasFilterValue);
    excludeFilter->setEnabled(hasFilterValue);
    useFilter->setToolTip(tr(
        "Hold Shift or Ctrl to combine this with the current view filter."));
    excludeFilter->setToolTip(tr(
        "Hold Shift or Ctrl to combine this with the current view filter."));
    connect(useFilter, SIGNAL(triggered(bool)), this, SLOT(UseAsFilter()));
    connect(excludeFilter, SIGNAL(triggered(bool)),
        this, SLOT(ExcludeFromView()));

    QStringList fullPathRules;
    QStringList fileNameRules;
    QStringList extensionRules;
    bool hasFileNameSelection = false;
    bool hasFolderNameSelection = false;
    for (QTreeWidgetItem* selected : m_pTree->selectedItems()) {
        if (selected->isHidden())
            continue;
        QString path = selected->data(0, eRawPathRole).toString();
        if (path.isEmpty())
            continue;
        AppendUniqueCaseInsensitive(fullPathRules, path);
        QFileInfo info(path);
        if (selected->data(0, eDirectoryRole).toBool())
            hasFolderNameSelection = true;
        else
            hasFileNameSelection = true;
        if (!info.fileName().isEmpty())
            AppendUniqueCaseInsensitive(fileNameRules,
                QStringLiteral("*\\") + info.fileName());
        if (!info.suffix().isEmpty())
            AppendUniqueCaseInsensitive(extensionRules,
                QStringLiteral("*.") + info.suffix());
    }
    QString nameOnlyLabel = hasFolderNameSelection && !hasFileNameSelection
        ? tr("Folder Name Only")
        : hasFolderNameSelection
            ? tr("File or Folder Name Only")
            : tr("File Name Only");
    QMenu* excludeCapture = menu.addMenu(
        CSandMan::GetIcon("Close"), tr("Exclude from Capture"));
    const QString excludeCaptureTip = tr(
        "Exclude matching paths from the next File Changes capture, usually "
        "when the sandbox closes. Existing history is not changed.");
    excludeCapture->menuAction()->setToolTip(excludeCaptureTip);
    QAction* excludeFullPath = excludeCapture->addAction(tr("Full Path"));
    QAction* excludeFileName = excludeCapture->addAction(nameOnlyLabel);
    QAction* excludeExtension = excludeCapture->addAction(tr("Extension"));
    for (QAction* action : { excludeFullPath, excludeFileName,
            excludeExtension })
        action->setToolTip(excludeCaptureTip);
    excludeFullPath->setEnabled(!fullPathRules.isEmpty());
    excludeFileName->setEnabled(!fileNameRules.isEmpty());
    excludeExtension->setEnabled(!extensionRules.isEmpty());
    connect(excludeFullPath, &QAction::triggered, this,
        [this, fullPathRules]() { AddExcludeRules(fullPathRules); });
    connect(excludeFileName, &QAction::triggered, this,
        [this, fileNameRules]() { AddExcludeRules(fileNameRules); });
    connect(excludeExtension, &QAction::triggered, this,
        [this, extensionRules]() { AddExcludeRules(extensionRules); });

    QStringList localExclusions = m_pBox->GetTextList(
        "FileStateHistoryExclude", false, false, false);
    auto localMatches = [&localExclusions](const QStringList& candidates) {
        QStringList matches;
        for (const QString& candidate : candidates) {
            for (const QString& existing : localExclusions) {
                if (candidate.compare(existing, Qt::CaseInsensitive) == 0) {
                    AppendUniqueCaseInsensitive(matches, existing);
                    break;
                }
            }
        }
        return matches;
    };
    QStringList localFullPathRules = localMatches(fullPathRules);
    QStringList localFileNameRules = localMatches(fileNameRules);
    QStringList localExtensionRules = localMatches(extensionRules);
    if (!localFullPathRules.isEmpty() || !localFileNameRules.isEmpty() ||
            !localExtensionRules.isEmpty()) {
        QMenu* removeExclude = menu.addMenu(
            CSandMan::GetIcon("Close"), tr("Remove Exclusion"));
        QAction* removeFullPath = removeExclude->addAction(tr("Full Path"));
        QAction* removeFileName = removeExclude->addAction(nameOnlyLabel);
        QAction* removeExtension = removeExclude->addAction(tr("Extension"));
        removeFullPath->setEnabled(!localFullPathRules.isEmpty());
        removeFileName->setEnabled(!localFileNameRules.isEmpty());
        removeExtension->setEnabled(!localExtensionRules.isEmpty());
        connect(removeFullPath, &QAction::triggered, this,
            [this, localFullPathRules]() { RemoveExcludeRules(localFullPathRules); });
        connect(removeFileName, &QAction::triggered, this,
            [this, localFileNameRules]() { RemoveExcludeRules(localFileNameRules); });
        connect(removeExtension, &QAction::triggered, this,
            [this, localExtensionRules]() { RemoveExcludeRules(localExtensionRules); });
    }

    QAction* trackFiles = menu.addAction(tr("Track Files"));
    QStringList hashes;
    QStringList fileNames;
    for (QTreeWidgetItem* selected : m_pTree->selectedItems()) {
        if (selected->isHidden() || selected->data(0, eMarkerRole).toBool())
            continue;
        QString oldHash = selected->data(0, eOldHashRole).toString();
        QString newHash = selected->data(0, eNewHashRole).toString();
        bool hasHash = false;
        for (const QString& hash : { oldHash, newHash }) {
            if (!hash.isEmpty() && hash.size() == 64) {
                AppendUniqueCaseInsensitive(hashes, hash);
                hasHash = true;
            }
        }
        if (!hasHash && !selected->data(0, eDirectoryRole).toBool()) {
            QString logicalPath = DisplayPath(
                selected->data(0, eRawPathRole).toString());
            QString fileName = QFileInfo(logicalPath).fileName();
            if (!fileName.isEmpty())
                AppendUniqueCaseInsensitive(fileNames, fileName);
        }
    }
    QDir retainedArtifacts(QDir(m_pBox->GetFileRoot()).filePath(
        "FileHistory\\Artifacts"));
    bool retainedHistoryAvailable = m_pBox->GetBool(
        "FileHistory", true, true, true) && retainedArtifacts.exists() &&
        !retainedArtifacts.entryList(
            QDir::Dirs | QDir::NoDotAndDotDot).isEmpty();
    trackFiles->setEnabled(retainedHistoryAvailable &&
        (!hashes.isEmpty() || !fileNames.isEmpty()));
    trackFiles->setToolTip(tr(
        "Switch to retained file history and match selected hashes, or file "
        "names when no hash was captured."));
    connect(trackFiles, &QAction::triggered, this,
        [this, hashes, fileNames]() { emit TrackFiles(hashes, fileNames); });

    menu.addSeparator();
    m_pCopyCell->setEnabled(!item->text(column).isEmpty());
    m_pCopyRow->setEnabled(!m_pTree->selectedItems().isEmpty());
    m_pCopyPanel->setEnabled(m_pTree->topLevelItemCount() != 0);
    menu.addAction(m_pCopyCell);
    menu.addAction(m_pCopyRow);
    menu.addAction(m_pCopyPanel);
    menu.exec(m_pTree->viewport()->mapToGlobal(pos));
}

void CFileStateHistoryWidget::CopyCell()
{
    QList<QStringList> rows;
    int column = m_pTree->currentColumn();
    for (QTreeWidgetItem* item : m_pTree->selectedItems()) {
        if (!item->isHidden())
            rows.append(QStringList() << item->text(column));
    }
    CPanelView::CopyToClipboard(QStringList(), rows);
}

void CFileStateHistoryWidget::CopyRow()
{
    QList<QStringList> rows;
    for (QTreeWidgetItem* item : m_pTree->selectedItems()) {
        if (!item->isHidden())
            rows.append(HistoryWindowUtils::VisibleRow(m_pTree, item));
    }
    CPanelView::CopyToClipboard(
        HistoryWindowUtils::VisibleHeaders(m_pTree), rows);
}

void CFileStateHistoryWidget::CopyPanel()
{
    QList<QStringList> rows;
    for (int index = 0; index < m_pTree->topLevelItemCount(); ++index) {
        HistoryWindowUtils::AppendVisibleRows(
            m_pTree, m_pTree->topLevelItem(index), rows);
    }
    CPanelView::CopyToClipboard(
        HistoryWindowUtils::VisibleHeaders(m_pTree), rows);
}

void CFileStateHistoryWidget::UseAsFilter()
{
    Qt::KeyboardModifiers modifiers = QApplication::keyboardModifiers();
    ApplySelectionFilter(false, modifiers.testFlag(Qt::ShiftModifier) ||
        modifiers.testFlag(Qt::ControlModifier));
}

void CFileStateHistoryWidget::ExcludeFromView()
{
    Qt::KeyboardModifiers modifiers = QApplication::keyboardModifiers();
    ApplySelectionFilter(true, modifiers.testFlag(Qt::ShiftModifier) ||
        modifiers.testFlag(Qt::ControlModifier));
}

void CFileStateHistoryWidget::ApplySelectionFilter(bool exclude, bool combine)
{
    int column = m_pTree->currentColumn();
    int scope = column;
    QStringList values;
    for (QTreeWidgetItem* item : m_pTree->selectedItems()) {
        if (column == eHashField) {
            bool hasHash = false;
            for (int role : { eOldHashRole, eNewHashRole }) {
                QString hash = item->data(0, role).toString();
                if (hash.size() == 64) {
                    AppendUniqueCaseInsensitive(values, hash);
                    hasHash = true;
                }
            }
            if (!hasHash)
                AppendUniqueCaseInsensitive(values, item->text(column));
        }
        else
            AppendUniqueCaseInsensitive(values, item->text(column));
    }
    QString expression;
    HistoryWindowUtils::EFilterBuildResult result =
        HistoryWindowUtils::BuildSelectionFilter(values, exclude, expression);
    if (result == HistoryWindowUtils::eFilterReady && combine &&
            !m_FilterExp.pattern().isEmpty()) {
        QString combined;
        result = HistoryWindowUtils::CombineSelectionFilter(
            m_FilterExp.pattern(), expression, combined);
        expression = combined;
        if (m_pFilterScope->currentData().toInt() != scope)
            scope = eAllFields;
    }
    if (result == HistoryWindowUtils::eFilterTooLarge) {
        QMessageBox::warning(this, tr("File Changes"), tr(
            "The selected values are too large to create a safe "
            "regular-expression filter."));
        return;
    }
    if (result == HistoryWindowUtils::eFilterReady) {
        int scopeIndex = m_pFilterScope->findData(scope);
        if (scopeIndex >= 0)
            m_pFilterScope->setCurrentIndex(scopeIndex);
        m_pFinder->SetSearchText(expression, true);
    }
}

void CFileStateHistoryWidget::AddExcludeRules(const QStringList& rules)
{
    QStringList existing = m_pBox->GetTextList(
        "FileStateHistoryExclude", true, false, true);
    QList<SB_STATUS> results;
    int added = 0;
    for (const QString& rule : rules) {
        if (rule.isEmpty() || existing.contains(rule, Qt::CaseInsensitive))
            continue;
        SB_STATUS status = m_pBox->AppendText("FileStateHistoryExclude", rule);
        results.append(status);
        if (!status.IsError()) {
            existing.append(rule);
            ++added;
        }
    }
    if (results.isEmpty()) {
        QMessageBox::information(this, tr("File Changes"),
            tr("The selected file-state exclusions already exist."));
        return;
    }
    theGUI->CheckResults(results, this);
    if (added)
        m_pStatus->setText(tr("Added %1 exclusion rule(s) for the next run.")
            .arg(added));
}

void CFileStateHistoryWidget::RemoveExcludeRules(const QStringList& rules)
{
    if (rules.isEmpty())
        return;
    QList<SB_STATUS> results;
    int removed = 0;
    for (const QString& rule : rules) {
        if (rule.isEmpty())
            continue;
        SB_STATUS status = m_pBox->DelValue("FileStateHistoryExclude", rule);
        results.append(status);
        if (!status.IsError())
            ++removed;
    }
    if (results.isEmpty())
        return;
    theGUI->CheckResults(results, this);
    if (removed)
        m_pStatus->setText(tr("Removed %1 box-local exclusion rule(s).")
            .arg(removed));
}

void CFileStateHistoryWidget::OpenSelectedFolder(const QString& rawPath,
    bool directory, bool sandboxed)
{
    if (rawPath.isEmpty())
        return;
    QString physicalPath = QDir::toNativeSeparators(
        QDir(m_pBox->GetFileRoot()).filePath(rawPath));
    QString folder = QDir::toNativeSeparators(directory
        ? physicalPath : QFileInfo(physicalPath).absolutePath());
    if (sandboxed) {
        QString logicalFolder = theAPI->GetRealPath(m_pBox.data(), folder);
        if (logicalFolder.isEmpty()) {
            QMessageBox::warning(this, tr("File Changes"),
                tr("The selected path cannot be translated to a sandbox path."));
            return;
        }
        if (theConf->GetInt("Options/WarnOpenFileStateSandbox", -1) == -1) {
            bool state = false;
            if (CCheckableMessageBox::question(this, "Sandboxie-Plus", tr(
                    "Opening Windows Explorer inside this sandbox starts a "
                    "sandboxed process. It can change sandbox contents and "
                    "may create another file-state generation after Explorer "
                    "exits. Refresh this history afterward to see it."),
                    tr("Don't show this message in future"), &state,
                    QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                    QDialogButtonBox::Ok, QMessageBox::Information) !=
                    QDialogButtonBox::Ok)
                return;
            if (state)
                theConf->SetValue("Options/WarnOpenFileStateSandbox", 1);
        }
        QList<SB_STATUS> results;
        results.append(m_pBox->RunStart(
            QStringLiteral("explorer.exe \"%1\"").arg(logicalFolder)));
        theGUI->CheckResults(results, this);
        return;
    }
    if (!IsSafeDirectory(folder)) {
        QMessageBox::information(this, tr("File Changes"),
            tr("The selected folder no longer exists or is unsafe to open "
                "from the sandbox storage."));
        return;
    }
    QString parameters = QStringLiteral("\"%1\"").arg(
        QDir::toNativeSeparators(folder));
    ShellExecuteW(NULL, NULL, L"explorer.exe",
        reinterpret_cast<LPCWSTR>(parameters.utf16()), NULL, SW_SHOWNORMAL);
}

void CFileStateHistoryWidget::Configure()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("File State History Options"));
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    QCheckBox* enabled = new QCheckBox(tr(
        "Capture a file-state generation after each completed sandbox run"), &dialog);
    enabled->setChecked(m_pBox->GetBool("FileStateHistory", false,
        true, true));
    QCheckBox* hashing = new QCheckBox(tr(
        "Use SHA-256 for files within the hashing limits"), &dialog);
    hashing->setChecked(m_pBox->GetText("FileStateHistoryHashMode", "Off",
        true, true, true)
        .compare("Limited", Qt::CaseInsensitive) == 0);
    QLabel* info = new QLabel(tr(
        "Enter 0 for unlimited. Leave a field empty to inherit its global or "
        "template value, or the built-in default. Changes apply to the next "
        "file-state capture."), &dialog);
    info->setWordWrap(true);
    layout->addWidget(info);
    layout->addWidget(enabled);
    layout->addWidget(hashing);

    QGridLayout* form = new QGridLayout();
    QLineEdit* generations = new QLineEdit(
        m_pBox->GetText("FileStateHistoryMaxGenerations"), &dialog);
    QLineEdit* totalSize = new QLineEdit(
        m_pBox->GetText("FileStateHistoryMaxSizeKB"), &dialog);
    QLineEdit* hashFile = new QLineEdit(
        m_pBox->GetText("FileStateHistoryHashMaxFileSizeKB"), &dialog);
    QLineEdit* hashTotal = new QLineEdit(
        m_pBox->GetText("FileStateHistoryHashMaxTotalKB"), &dialog);
    const quint64 inheritedGenerations = qMax(0,
        m_pBox->GetNum("FileStateHistoryMaxGenerations", 20, true, true));
    const quint64 inheritedTotalSize = qMax<qint64>(0,
        m_pBox->GetNum64("FileStateHistoryMaxSizeKB", 256 * 1024,
            true, true));
    const quint64 inheritedHashFile = qMax<qint64>(0,
        m_pBox->GetNum64("FileStateHistoryHashMaxFileSizeKB", 1024,
            true, true));
    const quint64 inheritedHashTotal = qMax<qint64>(0,
        m_pBox->GetNum64("FileStateHistoryHashMaxTotalKB", 64 * 1024,
            true, true));
    generations->setPlaceholderText(tr("Inherited (currently %1)")
        .arg(inheritedGenerations));
    totalSize->setPlaceholderText(tr("Inherited (currently %1)")
        .arg(inheritedTotalSize));
    hashFile->setPlaceholderText(tr("Inherited (currently %1)")
        .arg(inheritedHashFile));
    hashTotal->setPlaceholderText(tr("Inherited (currently %1)")
        .arg(inheritedHashTotal));
    QLabel* generationsValue = new QLabel(&dialog);
    QLabel* totalSizeValue = new QLabel(&dialog);
    QLabel* hashFileValue = new QLabel(&dialog);
    QLabel* hashTotalValue = new QLabel(&dialog);
    int formRow = 0;
    int labelWidth = 0;
    auto addLabel = [&dialog, &form, &labelWidth](const QString& text,
            int row) {
        QLabel* label = new QLabel(text, &dialog);
        label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        labelWidth = qMax(labelWidth,
            label->fontMetrics().horizontalAdvance(text));
        form->addWidget(label, row, 0, 1, 2);
    };
    auto addLimitRow = [&addLabel, &form, &formRow](const QString& label,
            QLineEdit* edit, QLabel* value) {
        addLabel(label, formRow);
        form->addWidget(edit, formRow, 2, 1, 2);
        form->addWidget(value, formRow, 4);
        ++formRow;
    };
    addLimitRow(tr("Maximum generations:"), generations, generationsValue);
    addLimitRow(tr("Maximum stored map size (KB):"), totalSize, totalSizeValue);
    addLimitRow(tr("Maximum hashed file size (KB):"), hashFile, hashFileValue);
    addLimitRow(tr("Maximum hashed bytes per capture (KB):"), hashTotal,
        hashTotalValue);
    QList<QLineEdit*> limitEdits;
    limitEdits << generations << totalSize << hashFile << hashTotal;
    auto formatLimit = [this](quint64 value) {
        return value == 0 ? tr("unlimited") : FormatSize(value * 1024);
    };
    auto readLimit = [](QLineEdit* edit, quint64 fallback, bool* valid) {
        QString text = edit->text().trimmed();
        if (text.isEmpty()) {
            *valid = true;
            return fallback;
        }
        bool ok = false;
        quint64 value = text.toULongLong(&ok);
        *valid = ok;
        return ok ? value : quint64(0);
    };
    auto updateLimitLabels = [=]() {
        bool valid = true;
        bool fieldValid = false;
        quint64 generationLimit = readLimit(generations,
            inheritedGenerations, &fieldValid);
        valid = valid && fieldValid;
        quint64 totalLimit = readLimit(totalSize,
            inheritedTotalSize, &fieldValid);
        valid = valid && fieldValid;
        quint64 hashFileLimit = readLimit(hashFile,
            inheritedHashFile, &fieldValid);
        valid = valid && fieldValid;
        quint64 hashTotalLimit = readLimit(hashTotal,
            inheritedHashTotal, &fieldValid);
        valid = valid && fieldValid;
        if (!valid) {
            generationsValue->setText(tr("invalid"));
            totalSizeValue->setText(tr("invalid"));
            hashFileValue->setText(tr("invalid"));
            hashTotalValue->setText(tr("invalid"));
            return;
        }
        generationsValue->setText(generationLimit == 0
            ? tr("unlimited") : tr("%1 generation(s)").arg(generationLimit));
        totalSizeValue->setText(formatLimit(totalLimit));
        hashFileValue->setText(formatLimit(hashFileLimit));
        hashTotalValue->setText(formatLimit(hashTotalLimit));
    };
    updateLimitLabels();
    for (QLineEdit* edit : limitEdits)
        connect(edit, &QLineEdit::textChanged, &dialog,
            [updateLimitLabels](const QString&) { updateLimitLabels(); });
    auto validate = [](QLineEdit* edit, quint64 maximum) {
        QString text = edit->text().trimmed();
        if (text.isEmpty())
            return true;
        bool ok = false;
        quint64 value = text.toULongLong(&ok);
        return ok && value <= maximum;
    };
    layout->addLayout(form);

    const qreal dpiScale = dialog.logicalDpiX() / 96.0;
    const int textPadding = qRound(24 * dpiScale);
    const int columnSpacing = form->horizontalSpacing();
    int fieldWidth = 0;
    for (QLineEdit* edit : limitEdits) {
        QString shownText = edit->text().isEmpty()
            ? edit->placeholderText() : edit->text();
        fieldWidth = qMax(fieldWidth, edit->minimumSizeHint().width());
        fieldWidth = qMax(fieldWidth,
            edit->fontMetrics().horizontalAdvance(shownText) + textPadding);
    }
    for (QLineEdit* edit : limitEdits)
        edit->setMinimumWidth(fieldWidth);
    form->setColumnMinimumWidth(0,
        (labelWidth + columnSpacing + 1) / 2);
    form->setColumnMinimumWidth(1,
        (labelWidth + columnSpacing) / 2);
    form->setColumnMinimumWidth(2,
        (fieldWidth + columnSpacing + 1) / 2);
    form->setColumnMinimumWidth(3,
        (fieldWidth + columnSpacing) / 2);
    int valueWidth = 0;
    for (QLabel* value : { generationsValue, totalSizeValue,
            hashFileValue, hashTotalValue })
        valueWidth = qMax(valueWidth,
            value->fontMetrics().horizontalAdvance(value->text()));
    form->setColumnMinimumWidth(4, valueWidth + textPadding);
    form->setColumnStretch(4, 1);

    layout->addWidget(new QLabel(tr(
        "Capture exclusions, one box-relative wildcard per line:"), &dialog));
    QPlainTextEdit* exclusions = new QPlainTextEdit(&dialog);
    exclusions->setPlainText(m_pBox->GetTextList(
        "FileStateHistoryExclude", false).join('\n'));
    exclusions->setPlaceholderText(tr("drive\\C\\Users\\*\\AppData\\Local\\Temp\\*"));
    layout->addWidget(exclusions, 1);
    QDialogButtonBox* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttons, &QDialogButtonBox::accepted, &dialog,
        [&dialog, generations, totalSize, hashFile, hashTotal, validate]() {
        if (!validate(generations, 0x7FFFFFFFULL) ||
                !validate(totalSize, 0x7FFFFFFFULL) ||
                !validate(hashFile, 0x7FFFFFFFULL) ||
                !validate(hashTotal, 0x7FFFFFFFULL)) {
            QMessageBox::warning(&dialog, CFileStateHistoryWidget::tr(
                "File Changes"), CFileStateHistoryWidget::tr(
                "Enter empty or non-negative whole numbers within the "
                "supported range for all file-state limits."));
            return;
        }
        dialog.accept();
    });
    connect(buttons, SIGNAL(rejected()), &dialog, SLOT(reject()));
    layout->addWidget(buttons);
    dialog.resize(650, 520);
    if (dialog.exec() != QDialog::Accepted)
        return;

    QList<SB_STATUS> results;
    auto save = [this, &results](const QString& setting,
            const QString& value, const QString& defaultValue) {
        QString normalized = value == defaultValue ? QString() : value;
        if (normalized.compare(m_pBox->GetText(setting).trimmed(),
                Qt::CaseInsensitive) == 0)
            return;
        results.append(normalized.isEmpty() ? m_pBox->DelValue(setting)
            : m_pBox->SetText(setting, normalized));
    };
    save("FileStateHistory", enabled->isChecked() ? "y" : "n", "n");
    save("FileStateHistoryHashMode", hashing->isChecked() ? "Limited" : "Off", "Off");
    save("FileStateHistoryMaxGenerations", generations->text().trimmed(), "20");
    save("FileStateHistoryMaxSizeKB", totalSize->text().trimmed(), "262144");
    save("FileStateHistoryHashMaxFileSizeKB", hashFile->text().trimmed(), "1024");
    save("FileStateHistoryHashMaxTotalKB", hashTotal->text().trimmed(), "65536");
    QStringList rules;
    for (const QString& line : exclusions->toPlainText().split('\n')) {
        QString rule = line.trimmed();
        if (!rule.isEmpty() && !rules.contains(rule, Qt::CaseInsensitive))
            rules.append(rule);
    }
    results.append(m_pBox->UpdateTextList("FileStateHistoryExclude", rules, false));
    theGUI->CheckResults(results, this);
}

bool CFileStateHistoryWidget::RemoveGeneration(const QString& generation)
{
    if (!IsGenerationName(generation))
        return false;
    QString boxRoot = m_pBox->GetFileRoot();
    QString historyPath = QDir(boxRoot).filePath("FileStateHistory");
    QString path = QDir(historyPath).filePath(generation);
    if (!RemoveStateGenerationDirectory(path))
        return false;
    QDir history(historyPath);
    if (history.entryList(QDir::AllEntries | QDir::Hidden | QDir::System |
            QDir::NoDotAndDotDot).isEmpty() && !QDir().rmdir(historyPath))
        return false;
    if (IsSafeDirectory(boxRoot)) {
        QDir root(boxRoot);
        if (root.entryList(QDir::AllEntries | QDir::Hidden | QDir::System |
                QDir::NoDotAndDotDot).isEmpty() && !QDir().rmdir(boxRoot))
            return false;
    }
    return true;
}

bool CFileStateHistoryWidget::CanDeleteHistory()
{
    if (m_pBox->GetBool("NeverDelete", false)) {
        QMessageBox::warning(this, "Sandboxie-Plus",
            tr("Delete protection is enabled for this sandbox."));
        return false;
    }
    if (m_pBox->GetActiveProcessCount() > 0) {
        QMessageBox::warning(this, "Sandboxie-Plus", tr(
            "File-state history cannot be deleted while the sandbox is running."));
        return false;
    }
    return true;
}

void CFileStateHistoryWidget::DeleteOlder()
{
    if (!CanDeleteHistory())
        return;
    QString generation = m_pOlder->currentData().toString();
    if (generation.isEmpty())
        return;
    if (QMessageBox::question(this, tr("Delete File-State Generation"),
            tr("Delete generation %1?").arg(generation)) == QMessageBox::Yes) {
        if (!RemoveGeneration(generation)) {
            QMessageBox::critical(this, tr("File Changes"), tr("The generation could not be deleted."));
            return;
        }
        Reload();
    }
}

void CFileStateHistoryWidget::DeleteNewer()
{
    if (!CanDeleteHistory())
        return;
    QString generation = m_pNewer->currentData().toString();
    if (generation.isEmpty())
        return;
    if (QMessageBox::question(this, tr("Delete File-State Generation"),
            tr("Delete generation %1?").arg(generation)) == QMessageBox::Yes) {
        if (!RemoveGeneration(generation)) {
            QMessageBox::critical(this, tr("File Changes"), tr("The generation could not be deleted."));
            return;
        }
        Reload();
    }
}

void CFileStateHistoryWidget::DeleteAll()
{
    if (!CanDeleteHistory())
        return;
    QString rootPath = QDir(m_pBox->GetFileRoot()).filePath("FileStateHistory");
    if (!IsSafeDirectory(rootPath) || QMessageBox::question(this,
            tr("Delete File State History"),
            tr("Delete all stored file-state generations?")) != QMessageBox::Yes)
        return;
    bool ok = RemoveStateHistoryDirectory(rootPath);
    QString boxRoot = m_pBox->GetFileRoot();
    if (ok && IsSafeDirectory(boxRoot)) {
        QDir root(boxRoot);
        if (root.entryList(QDir::AllEntries | QDir::Hidden | QDir::System |
                QDir::NoDotAndDotDot).isEmpty())
            ok = QDir().rmdir(boxRoot);
    }
    if (!ok)
        QMessageBox::critical(this, tr("File Changes"),
            tr("Not all generations could be deleted."));
    Reload();
}

void CFileStateHistoryWidget::OpenHistoryFolder()
{
    QString path = QDir(m_pBox->GetFileRoot()).filePath("FileStateHistory");
    if (!IsSafeDirectory(path)) {
        QMessageBox::information(this, tr("File Changes"),
            tr("No file-state history has been captured yet."));
        return;
    }
    QString parameters = QStringLiteral("\"%1\"").arg(
        QDir::toNativeSeparators(path));
    ShellExecuteW(NULL, NULL, L"explorer.exe",
        reinterpret_cast<LPCWSTR>(parameters.utf16()), NULL, SW_SHOWNORMAL);
}
