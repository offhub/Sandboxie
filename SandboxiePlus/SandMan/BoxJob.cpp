#include "stdafx.h"
#include "BoxJob.h"
#include "SbiePlusAPI.h"
#include "../QSbieAPI/SbieUtils.h"


///////////////////////////////////////////////////////////////////////////////
// CCleanUpJob
//

SB_PROGRESS CCleanUpJob::Start()
{
	CSandBoxPlus* pBox = GetBox();

	SB_PROGRESS Status;
	if (!m_Options.DeleteSnapshots && pBox->HasSnapshots()) {
		QString Current;
		QString Default = pBox->GetDefaultSnapshot(&Current);
		Status = pBox->SelectSnapshotEx(m_UseCurrentSnapshot ? Current : Default,
			m_Options.DeleteFileHistory(), m_Options.DeleteRegistryHistory(),
			m_Options.DeleteFileStateHistory);
	}
	else if (!m_Options.DeleteFileHistory() || !m_Options.DeleteRegistryHistory() ||
			!m_Options.DeleteFileStateHistory)
		Status = pBox->CleanBoxExceptHistory(!m_Options.DeleteFileHistory(),
			!m_Options.DeleteRegistryHistory(), !m_Options.DeleteFileStateHistory);
	else // if everything is selected, use the normal cleaning procedure
		Status = pBox->CleanBox();

	if (Status.GetStatus() == OP_ASYNC)
		m_pProgress = Status.GetValue();

	return Status;
}

void CCleanUpJob::Finished()
{
	CSandBoxPlus* pBox = GetBox();

	emit theAPI->BoxCleaned(pBox);
}

///////////////////////////////////////////////////////////////////////////////
// COnDeleteJob
//

SB_PROGRESS COnDeleteJob::Start()
{
	m_pProgress = CSbieUtils::RunCommand(m_Command, true);
	if (m_pProgress.isNull())
		return SB_ERR();
	return SB_PROGRESS(OP_ASYNC, m_pProgress);
}
