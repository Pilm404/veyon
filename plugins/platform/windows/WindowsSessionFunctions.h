/*
 * WindowsSessionFunctions.h - declaration of WindowsSessionFunctions class
 *
 * Copyright (c) 2020-2025 Tobias Junghans <tobydox@veyon.io>
 *
 * This file is part of Veyon - https://veyon.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program (see COPYING); if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 */

#pragma once

#include <QTimer>

#include "PlatformSessionFunctions.h"

// clazy:excludeall=copyable-polymorphic

class WindowsSessionFunctions : public PlatformSessionFunctions
{
	Q_GADGET
public:
	enum class InterferingWindowHandling {
		None,
		FixWindowAttributes,
		TerminateProcess,
		CloseSession
	};
	Q_ENUM(InterferingWindowHandling)

	WindowsSessionFunctions();

	SessionId currentSessionId() override;

	SessionUptime currentSessionUptime() const override;
	QString currentSessionClientAddress() const override;
	QString currentSessionClientName() const override;
	QString currentSessionHostName() const override;

	QString currentSessionType() const override;
	bool currentSessionHasUser() const override;
	bool currentSessionIsRemote() const override;

	EnvironmentVariables currentSessionEnvironmentVariables() const override;
	QVariant querySettingsValueInCurrentSession(const QString& key) const override;

private:
	void initInterferingWindowHandling();
	void inspectDesktopWindows();
	WINBOOL inspectDesktopWindow(HWND window);

	static constexpr auto DesktopWindowsInspectionInterval = 1000;

	InterferingWindowHandling m_interferingWindowHandling = InterferingWindowHandling::None;
	QTimer m_desktopWindowsInspectionTimer;

};
