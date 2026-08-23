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

private slots:
	void Reload();
	void ResizeColumns();
	void SortHistory(int Column, Qt::SortOrder Order);
	void SetFilter(const QRegularExpression& RegExp, int Options = 0, int Column = -1);
	void UpdateFilterScope();
	void UpdateSelection();
	void UpdateHashHighlight();
	void OpenEvidenceFolder();
	void ShowContextMenu(const QPoint& Pos);
	void OpenEvidenceInEditor();
	void OpenEvidenceInSandboxedEditor();
	void CopyCell();
	void CopyRow();
	void CopyPanel();
	void UseAsFilter();
	void DeleteEvidence();
	void RemoveHistory();
	void ConfigureLimits();

protected:
	void closeEvent(QCloseEvent* e);

private:
	void AddExcludeRule(const QString& Rule);
	void ApplyFilter();
	bool CanDeleteHistory();
	void CompareEvidence(bool Sandboxed);
	QStringList GetSelectedEvidencePaths(int* PendingCount = NULL) const;
	bool ConfirmSharedEvidenceAccess(const QStringList& Paths, bool* Detach);

	CSandBoxPtr m_pBox;
	CFinder* m_pFinder;
	QCheckBox* m_pHighlightSame;
	QCheckBox* m_pHideEmpty;
	QCheckBox* m_pHideReused;
	QComboBox* m_pFilterScope;
	QTreeWidget* m_pTree;
	QLabel* m_pLoadIndicator;
	QLabel* m_pLimits;
	QLabel* m_pStatus;
	QPushButton* m_pRefreshButton;
	QPushButton* m_pOpenFolder;
	QPushButton* m_pRemoveHistory;
	QAction* m_pCopyCell;
	QAction* m_pCopyRow;
	QAction* m_pCopyPanel;
	QRegularExpression m_FilterExp;
	bool m_Loading;
	bool m_Loaded;
};
