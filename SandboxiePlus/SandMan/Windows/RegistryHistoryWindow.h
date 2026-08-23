#pragma once

#include "SbiePlusAPI.h"
#include <QRegularExpression>

class CFinder;
class QAction;
class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
class QStackedLayout;
class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;

class CRegistryHistoryWindow : public QDialog
{
    Q_OBJECT

public:
    CRegistryHistoryWindow(const CSandBoxPtr& pBox,
        QWidget* parent = Q_NULLPTR);
    ~CRegistryHistoryWindow();

    virtual void accept() {}
    virtual void reject() { close(); }

signals:
    void Closed();
    void OpenFileHistory(int Tab);

private slots:
    void Reload();
    void ResizeColumns();
    void SetFilter(const QRegularExpression& RegExp, int Options = 0,
        int Column = -1);
    void UpdateFilterScope();
    void UpdateSelection();
    void ShowContextMenu(const QPoint& Pos);
    void CopyCell();
    void CopyRow();
    void CopyPanel();
    void UseAsFilter();
    void ExcludeFromView();
    void OpenKeyInHost();
    void OpenKeyInSandbox();
    void OpenKeyInSandboxAdmin();
    void Compare();
    void Configure();
    void OpenHistoryFolder();
    void DeleteOlderGeneration();
    void DeleteNewerGeneration();
    void DeleteAllGenerations();
    void UpdateControls();

protected:
    void closeEvent(QCloseEvent* event);

private:
    void ApplyFilter();
    void ApplyViewOptions();
    void ApplySelectionFilter(bool Exclude, bool Combine);
    void DeleteGeneration(bool Older);
    void StartRegistryEditor(bool Elevated, int Attempt);
    void OpenRegistryKey(bool Sandbox, bool Elevated = false);
    void UpdateSummary();
    void SetProgressVisible(bool Visible);
    bool CanDeleteHistory();

    CSandBoxPtr m_pBox;
    QTabWidget* m_pTabs;
    CFinder* m_pFinder;
    QCheckBox* m_pShowAdded;
    QCheckBox* m_pShowRemoved;
    QCheckBox* m_pShowModified;
    QCheckBox* m_pHighlightSame;
    QCheckBox* m_pShowColors;
    QCheckBox* m_pShowMarkers;
    QCheckBox* m_pCompareHost;
    QCheckBox* m_pHideDateOnly;
    QCheckBox* m_pFilterUserAliases;
    QComboBox* m_pFilterScope;
    QComboBox* m_pOlder;
    QComboBox* m_pNewer;
    QTreeWidget* m_pTree;
    QLabel* m_pSummary;
    QLabel* m_pStatus;
    QLabel* m_pSelectionStatus;
    QLabel* m_pLoadIndicator;
    QCheckBox* m_pAutoCompare;
    QStackedLayout* m_pLoadStack;
    QPushButton* m_pRefreshButton;
    QPushButton* m_pCompare;
    QPushButton* m_pDeleteOlder;
    QPushButton* m_pDelete;
    QPushButton* m_pDeleteAll;
    QAction* m_pCopyCell;
    QAction* m_pCopyRow;
    QAction* m_pCopyPanel;
    QRegularExpression m_FilterExp;
    QString m_SummaryTemplate;
    QString m_SummaryDisabledNote;
    bool m_ResultsTruncated;
    bool m_HostAccessLimited;
    bool m_ComparisonComplete;
    bool m_Loading;
    bool m_AbortRequested;
    bool m_Loaded;
};
