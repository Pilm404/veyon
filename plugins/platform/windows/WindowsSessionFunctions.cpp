/*
 * WindowsSessionFunctions.cpp - implementation of WindowsSessionFunctions class
 *
 * Copyright (c) 2020-2026 Tobias Junghans <tobydox@veyon.io>
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

#include <wtsapi32.h>

#include <QCoreApplication>
#include <QMessageBox>
#include <QHostInfo>
#include <QSettings>

#include "WindowsCoreFunctions.h"
#include "PlatformSessionManager.h"
#include "PlatformUserFunctions.h"
#include "VeyonConfiguration.h"
#include "WindowsPlatformConfiguration.h"
#include "WindowsSessionFunctions.h"
#include "WtsSessionManager.h"


WindowsSessionFunctions::WindowsSessionFunctions()
{
	if (VeyonCore::component() == VeyonCore::Component::Server)
	{
		QObject::connect (VeyonCore::instance(), &VeyonCore::initialized,
						  VeyonCore::instance(), [this]() { initInterferingWindowHandling(); });
	}
}



WindowsSessionFunctions::SessionId WindowsSessionFunctions::currentSessionId()
{
	const auto currentSession = WtsSessionManager::currentSession();

	if( currentSession == WtsSessionManager::activeConsoleSession() )
	{
		return DefaultSessionId;
	}

	return PlatformSessionManager::resolveSessionId( QString::number(currentSession) );
}



WindowsSessionFunctions::SessionUptime WindowsSessionFunctions::currentSessionUptime() const
{
	return WtsSessionManager::querySessionInformation(WtsSessionManager::currentSession(),
													  WtsSessionManager::SessionInfo::SessionUptime).toInt();
}



QString WindowsSessionFunctions::currentSessionClientAddress() const
{
	return WtsSessionManager::querySessionInformation(WtsSessionManager::currentSession(),
													  WtsSessionManager::SessionInfo::ClientAddress);
}



QString WindowsSessionFunctions::currentSessionClientName() const
{
	return WtsSessionManager::querySessionInformation(WtsSessionManager::currentSession(),
													  WtsSessionManager::SessionInfo::ClientName);
}



QString WindowsSessionFunctions::currentSessionHostName() const
{
	return QHostInfo::localHostName();
}



QString WindowsSessionFunctions::currentSessionType() const
{
	if(WtsSessionManager::currentSession() == WtsSessionManager::activeConsoleSession() )
	{
		return QStringLiteral("console");
	}

	return QStringLiteral("rdp");
}



bool WindowsSessionFunctions::currentSessionHasUser() const
{
	return WtsSessionManager::querySessionInformation( WtsSessionManager::currentSession(),
													   WtsSessionManager::SessionInfo::UserName ).isEmpty() == false;
}



PlatformSessionFunctions::EnvironmentVariables WindowsSessionFunctions::currentSessionEnvironmentVariables() const
{
	const auto processId = WtsSessionManager::findProcessId(QStringLiteral("explorer.exe"), WtsSessionManager::currentSession());
	const auto envStrings = WindowsCoreFunctions::queryProcessEnvironmentVariables(processId);

	EnvironmentVariables environmentVariables;
	for (const auto& envString : envStrings)
	{
		const auto envStringParts = envString.split(QLatin1Char('='));
		if (envStringParts.size() >= 2)
		{
			environmentVariables[envStringParts.at(0)] = envStringParts.mid(1).join(QLatin1Char('='));
		}
	}

	return environmentVariables;
}



QVariant WindowsSessionFunctions::querySettingsValueInCurrentSession(const QString& key) const
{
	if (key.startsWith(QLatin1String("HKEY")))
	{
		HANDLE userToken = nullptr;
		const auto sessionId = WtsSessionManager::currentSession();
		if (WTSQueryUserToken(sessionId, &userToken) == false)
		{
			vCritical() << "could not query user token for session" << sessionId;
			return {};
		}

		auto keyParts = key.split(QLatin1Char('\\'));
		if (keyParts.constFirst() == QStringLiteral("HKEY_CURRENT_USER"))
		{
			keyParts[0] = WtsSessionManager::queryUserSid(sessionId);
			keyParts.prepend(QStringLiteral("HKEY_USERS"));
		}

		if (ImpersonateLoggedOnUser(userToken) == false)
		{
			vCritical() << "could not impersonate session user";
			return {};
		}

		const auto value = QSettings(keyParts.mid(0, keyParts.length()-1).join(QLatin1Char('\\')), QSettings::NativeFormat)
						   .value(keyParts.constLast());

		RevertToSelf();
		CloseHandle(userToken);

		return value;
	}

	return QSettings(QSettings::UserScope, QCoreApplication::organizationName(), QCoreApplication::applicationName()).value(key);
}


void WindowsSessionFunctions::initInterferingWindowHandling()
{
	WindowsPlatformConfiguration config(&VeyonCore::config());

	m_interferingWindowsHandling = config.interferingWindowsHandling();
	m_showTerminateProcessDialog = config.showTerminateProcessDialog();

	if (m_interferingWindowsHandling != InterferingWindowHandling::None)
	{
		QObject::connect (&m_desktopWindowsInspectionTimer, &QTimer::timeout, &m_desktopWindowsInspectionTimer, [this]() {
			inspectDesktopWindows();
		});
		m_desktopWindowsInspectionTimer.start(DesktopWindowsInspectionInterval);
	}
}



void WindowsSessionFunctions::inspectDesktopWindows()
{
	EnumWindows([](HWND window, LPARAM instance) -> WINBOOL CALLBACK {
		const auto _this = reinterpret_cast<WindowsSessionFunctions *>(instance);
		return _this->inspectDesktopWindow(window);
	}, LPARAM(this));
}



WINBOOL WindowsSessionFunctions::inspectDesktopWindow(HWND window)
{
	DWORD processId = 0;
	if ( GetWindowThreadProcessId( window, &processId ) == false )
	{
		return TRUE;
	}

	if ( VeyonCore::platform().coreFunctions().isProgramRunningAsAdmin( processId ) )
	{
		return TRUE;
	}

	if ( IsWindowVisible( window ) == false )
	{
		return TRUE;
	}

	auto processHandle = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, 0, processId );

	if ( processHandle == nullptr )
	{
		return TRUE;
	}

	wchar_t buffer[MAX_PATH]{};
	DWORD size = MAX_PATH;

	if ( QueryFullProcessImageNameW( processHandle, 0, buffer, &size ) == false )
	{
		CloseHandle( processHandle );
		return TRUE;
	}

	QString filePath = QString::fromWCharArray( buffer );

	int score = 0;

	if ( VeyonCore::platform().filesystemFunctions().verifyFileSignature( filePath ) )
	{
		score -= 6;
	}

	RECT winRect;
	if ( GetWindowRect( window, &winRect ) == false )
	{
		CloseHandle( processHandle );
		return TRUE;
	}

	RECT desktopRect;
	GetWindowRect( GetDesktopWindow(), &desktopRect );

	RECT intersection;
	if ( IntersectRect( &intersection, &winRect, &desktopRect ) == false )
	{
		CloseHandle( processHandle );
		return TRUE;
	}

	DWORD affinity = 0;
	if ( GetWindowDisplayAffinity( window, &affinity ) )
	{
		if ( affinity == WDA_EXCLUDEFROMCAPTURE || affinity == WDA_MONITOR )
		{
			score += 3;
		}
	}

	if ( GetWindowTextLengthW( window ) == 0 )
	{
		score += 3;
	}

	const auto windowStyle = GetWindowLong( window, GWL_EXSTYLE );

	if ( (windowStyle & WS_EX_TRANSPARENT) || (windowStyle & WS_EX_TOPMOST) )
	{
		score += 3;
	}

	if ( windowStyle & WS_EX_TOOLWINDOW )
	{
		score += 1;
	}

	if ( windowStyle & WS_EX_LAYERED )
	{
		BYTE alpha;
		DWORD flags;

		if ( GetLayeredWindowAttributes( window, nullptr, &alpha, &flags ) )
		{
			if ( (flags & LWA_ALPHA) && alpha >= 255 )
			{
				score += 2;
			}

			if ( flags & LWA_COLORKEY )
			{
				score += 2;
			}
		}
	}

	if ( score >= 8 )
	{
		switch (m_interferingWindowsHandling)
		{
		case InterferingWindowHandling::TerminateProcess:
		{
			vDebug() << "Terminating process of interfering window" << filePath << processId << score;

		    TerminateProcess( processHandle, 0 );

			if ( m_showTerminateProcessDialog )
			{
				QMessageBox* box = new QMessageBox( QMessageBox::Information, tr( "Veyon" ),
													tr( "The application %1 was closed because it interfered with screen sharing." )
													.arg( filePath ), QMessageBox::Ok, nullptr );

				box->setAttribute(Qt::WA_DeleteOnClose);
				box->open();
			}

			break;
		}
		case InterferingWindowHandling::CloseSession:
			vDebug() << "Closing session due to interfering window" << filePath << processId << score;
			VeyonCore::platform().userFunctions().logoff();
			break;
		default:
			break;
		}
	}

	CloseHandle( processHandle );
	return TRUE;
}
