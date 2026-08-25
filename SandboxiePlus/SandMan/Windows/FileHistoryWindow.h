#pragma once

#include "SbiePlusAPI.h"
#include <QHash>
#include <QList>
#include <QRegularExpression>

class CFinder;
class QAction;
class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
class QStackedLayout;
class QToolButton;
class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;

class CFileHistoryWindow : public QDialog
{
	Q_OBJECT

public:
	CFileHistoryWindow(const CSandBoxPtr& pBox, QWidget* parent = Q_NULLPTR);
	~CFileHistoryWindow();

	virtual void accept() {}
	virtual void reject() { this->close(); }

signals:
	void Closed();
	void OpenRegistryHistory();

private slots:
	void Reload();
	void ResizeColumns();
	void SortHistory(int Column, Qt::SortOrder Order);
	void SetFilter(const QRegularExpression& RegExp, int Options = 0, int Column = -1);
	void UpdateFilterScope();
	void UpdateSelection();
	void OpenEvidenceFolder();
	void ShowContextMenu(const QPoint& Pos);
	void OpenEvidenceInEditor();
	void OpenEvidenceInSandboxedEditor();
	void CopyCell();
	void CopyRow();
	void CopyPanel();
	void UseAsFilter();
	void ExcludeFromView();
	void TrackFile();
	void DeleteEvidence();
	void RemoveHistory();
	void ConfigureLimits();

public:
	void SetHistoryTab(int Index);

protected:
	void closeEvent(QCloseEvent* e);

private:
	void AddExcludeRules(const QStringList& Rules);
	void RemoveExcludeRules(const QStringList& Rules);
	void ApplyFilter();
    void RebuildTree(bool PreserveState);
	void UpdateHashHighlight(int& SelectedCount, int& HighlightedCount);
	void ApplySelectionFilter(bool Exclude, bool Combine);
	void PrepareTrackFileView();
	void SetProgressVisible(bool Visible);
    bool CanDeleteHistory();
	void CompareEvidence(bool Sandboxed);
	QStringList GetSelectedEvidencePaths(int* PendingCount = NULL,
		bool SortByCaptureTime = false) const;
	bool ConfirmSharedEvidenceAccess(const QStringList& Paths, bool* Detach);

	CSandBoxPtr m_pBox;
	QTabWidget* m_pTabs;
	int m_LastTab;
	CFinder* m_pFinder;
	QCheckBox* m_pHighlightSame;
	QCheckBox* m_pShowModify;
	QCheckBox* m_pShowDeleteOnClose;
	QCheckBox* m_pShowDelete;
	QCheckBox* m_pShowReplace;
	QCheckBox* m_pShowMigrate;
	QCheckBox* m_pShowAvailable;
	QCheckBox* m_pShowPending;
	QCheckBox* m_pShowFinalized;
	QCheckBox* m_pHideEmpty;
	QCheckBox* m_pHideReused;
	QCheckBox* m_pMergeRenamed;
	QCheckBox* m_pGroupByParent;
	QComboBox* m_pFilterScope;
	QTreeWidget* m_pTree;
	QLabel* m_pLoadIndicator;
	QCheckBox* m_pAutoLoad;
	QStackedLayout* m_pLoadStack;
	QLabel* m_pLimits;
	QLabel* m_pStatus;
	QLabel* m_pSelectionStatus;
	QPushButton* m_pRefreshButton;
	QPushButton* m_pOpenFolder;
	QPushButton* m_pRemoveHistory;
	QToolButton* m_pViewOptionsButton;
	QAction* m_pCopyCell;
	QAction* m_pCopyRow;
	QAction* m_pCopyPanel;
	QRegularExpression m_FilterExp;
	QString m_SelectionExcludePattern;
	QHash<QString, QString> m_PathLineages;
	QList<QTreeWidgetItem*> m_EvidenceItems;
	bool m_Loading;
	bool m_AbortRequested;
	bool m_Loaded;
	bool m_TrackFileViewAdjusting;
	bool m_TrackFileHideEmptyOverride;
	bool m_TrackFileHideReusedOverride;
	bool m_TrackFileHideEmptyValue;
	bool m_TrackFileHideReusedValue;
};
