#pragma once

#include "SbiePlusAPI.h"
#include <QRegularExpression>

class CFinder;
class QAction;
class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
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
    void Compare();
    void Configure();
    void OpenHistoryFolder();
    void DeleteGeneration();
    void DeleteAllGenerations();
    void UpdateControls();

protected:
    void closeEvent(QCloseEvent* event);

private:
    void ApplyFilter();
    void ApplyViewOptions();
    void ApplySelectionFilter(bool Exclude);
    void OpenRegistryKey(bool Sandbox);
    bool CanDeleteHistory();

    CSandBoxPtr m_pBox;
    CFinder* m_pFinder;
    QCheckBox* m_pHighlightSame;
    QCheckBox* m_pShowColors;
    QCheckBox* m_pHideDateOnly;
    QComboBox* m_pFilterScope;
    QComboBox* m_pOlder;
    QComboBox* m_pNewer;
    QTreeWidget* m_pTree;
    QLabel* m_pSummary;
    QLabel* m_pStatus;
    QLabel* m_pLoadIndicator;
    QPushButton* m_pRefreshButton;
    QPushButton* m_pCompare;
    QPushButton* m_pDelete;
    QPushButton* m_pDeleteAll;
    QAction* m_pCopyCell;
    QAction* m_pCopyRow;
    QAction* m_pCopyPanel;
    QRegularExpression m_FilterExp;
    bool m_ResultsTruncated;
    bool m_ComparisonComplete;
    bool m_Loading;
    bool m_Loaded;
};
