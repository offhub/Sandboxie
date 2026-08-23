#pragma once

#include <QRegularExpression>
#include <QStringList>
#include <QTreeWidget>

namespace HistoryWindowUtils
{
	enum EFilterBuildResult
	{
		eFilterReady,
		eFilterEmpty,
		eFilterTooLarge
	};

	inline EFilterBuildResult BuildSelectionFilter(
		const QStringList& Values, bool Exclude, QString& Expression)
	{
		const int MaxGeneratedFilterLength = 64 * 1024;
		QStringList Alternatives;
		int ExpressionLength = 0;
		foreach(const QString& Value, Values) {
			if (Value.isEmpty())
				continue;
			QString Escaped = QRegularExpression::escape(Value);
			if (Alternatives.contains(Escaped))
				continue;
			ExpressionLength += Escaped.length() + 1;
			if (ExpressionLength > MaxGeneratedFilterLength)
				return eFilterTooLarge;
			Alternatives.append(Escaped);
		}
		if (Alternatives.isEmpty())
			return eFilterEmpty;

		Expression = QStringLiteral("(?:%1)")
			.arg(Alternatives.join(QLatin1Char('|')));
		if (Exclude) {
			Expression = QStringLiteral("^(?![\\s\\S]*%1)[\\s\\S]*$")
				.arg(Expression);
		}
		return eFilterReady;
	}

	inline EFilterBuildResult CombineSelectionFilter(
		const QString& Existing, const QString& Added, QString& Expression)
	{
		const int MaxGeneratedFilterLength = 64 * 1024;
		if (Existing.isEmpty()) {
			Expression = Added;
			return Added.isEmpty() ? eFilterEmpty : eFilterReady;
		}
		if (Added.isEmpty()) {
			Expression = Existing;
			return eFilterReady;
		}

		Expression = QStringLiteral(
			"^(?=[\\s\\S]*(?:%1))(?=[\\s\\S]*(?:%2))[\\s\\S]*$")
			.arg(Existing, Added);
		if (Expression.length() > MaxGeneratedFilterLength)
			return eFilterTooLarge;
		return eFilterReady;
	}

	inline QStringList VisibleHeaders(QTreeWidget* Tree)
	{
		QStringList Headers;
		for (int Column = 0; Column < Tree->columnCount(); ++Column) {
			if (!Tree->isColumnHidden(Column))
				Headers.append(Tree->headerItem()->text(Column));
		}
		return Headers;
	}

	inline QStringList VisibleRow(
		QTreeWidget* Tree, QTreeWidgetItem* Item, int Level = 0)
	{
		QStringList Row;
		for (int Column = 0; Column < Tree->columnCount(); ++Column) {
			if (Tree->isColumnHidden(Column))
				continue;
			QString Cell = Item->text(Column);
			if (Level && Column == 0) {
				Cell.prepend(
					QString(Level, QLatin1Char('_')) + QLatin1Char(' '));
			}
			Row.append(Cell);
		}
		return Row;
	}

	inline void AppendVisibleRows(QTreeWidget* Tree, QTreeWidgetItem* Item,
		QList<QStringList>& Rows, int Level = 0)
	{
		if (Item->isHidden())
			return;
		Rows.append(VisibleRow(Tree, Item, Level));
		for (int Index = 0; Index < Item->childCount(); ++Index)
			AppendVisibleRows(Tree, Item->child(Index), Rows, Level + 1);
	}
}
