#pragma once

#include <QRegularExpression>
#include <QStringList>

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
}
