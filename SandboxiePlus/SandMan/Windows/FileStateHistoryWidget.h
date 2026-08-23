#pragma once

#include "SbiePlusAPI.h"
#include <QHash>
#include <QRegularExpression>
#include <QWidget>

class CFinder;
class QAction;
class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;

class CFileStateHistoryWidget : public QWidget
{
    Q_OBJECT

public:
    CFileStateHistoryWidget(const CSandBoxPtr& pBox,
        QWidget* parent = Q_NULLPTR);
    ~CFileStateHistoryWidget();

public slots:
    void ResizeColumns();

private slots:
    void Reload();
    void SetFilter(const QRegularExpression& RegExp, int Options = 0,
        int Column = -1);
    void UpdateFilterScope();
    void Compare();
    void ApplyFilter();
    void UpdateSelection();
    void ShowContextMenu(const QPoint& Pos);
    void CopyCell();
    void CopyRow();
    void CopyPanel();
    void UseAsFilter();
    void ExcludeFromView();
    void UpdateControls();
    void Configure();
    void DeleteOlder();
    void DeleteNewer();
    void DeleteAll();
    void OpenHistoryFolder();

private:
    struct SFileStateEntry
    {
        QString Path;
        bool Directory = false;
        quint32 Attributes = 0;
        quint64 Size = 0;
        quint64 Created = 0;
        quint64 Modified = 0;
        QByteArray Hash;
        bool HashUnavailable = false;
    };

    bool ReadMap(const QString& generation,
        QHash<QString, SFileStateEntry>& entries,
        QHash<QString, QString>& deletionMarkers, QString& snapshotBase,
        QString& error) const;
    bool ReadDeleteMarkers(const QString& GenerationPath, int DeleteMode,
        QHash<QString, QString>& Markers, QString& Error) const;
    QString BoxRelativePath(const QString& TruePath) const;
    bool RemoveGeneration(const QString& generation);
    bool CanDeleteHistory();
    void ApplySelectionFilter(bool Exclude, bool Combine);
    void AddExcludeRules(const QStringList& Rules);
    void RemoveExcludeRules(const QStringList& Rules);
    void OpenSelectedFolder(const QString& RawPath, bool Directory,
        bool Sandboxed);
    QString DisplayPath(const QString& RawPath) const;
    void RebuildView();
    CSandBoxPtr m_pBox;
    CFinder* m_pFinder;
    QComboBox* m_pFilterScope;
    QComboBox* m_pOlder;
    QComboBox* m_pNewer;
    QPushButton* m_pCompare;
    QPushButton* m_pRefresh;
    QPushButton* m_pDeleteOlder;
    QPushButton* m_pDeleteNewer;
    QPushButton* m_pDeleteAll;
    QCheckBox* m_pShowAdded;
    QCheckBox* m_pShowRemoved;
    QCheckBox* m_pShowModified;
    QCheckBox* m_pShowMetadata;
    QCheckBox* m_pShowFiles;
    QCheckBox* m_pShowFolders;
    QCheckBox* m_pHideEmpty;
    QCheckBox* m_pNormalizePaths;
    QCheckBox* m_pGroupByParent;
    QLabel* m_pSummary;
    QLabel* m_pStatus;
    QLabel* m_pSelectionStatus;
    QLabel* m_pLoadIndicator;
    QTreeWidget* m_pTree;
    QAction* m_pCopyCell;
    QAction* m_pCopyRow;
    QAction* m_pCopyPanel;
    QRegularExpression m_FilterExp;
    bool m_Loading;
    bool m_Loaded;
};
