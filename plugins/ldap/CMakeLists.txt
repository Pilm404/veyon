include(BuildVeyonPlugin)

add_subdirectory(kldap)
add_subdirectory(common)

build_veyon_plugin(ldap
	NAME Ldap
	SOURCES
	LdapPlugin.cpp
	LdapPlugin.h
	AuthLdapConfiguration.h
	AuthLdapConfigurationWidget.cpp
	AuthLdapConfigurationWidget.h
	AuthLdapConfigurationWidget.ui
	AuthLdapCore.cpp
	AuthLdapCore.h
	AuthLdapDialog.cpp
	AuthLdapDialog.h
	AuthLdapDialog.ui
	)

target_link_libraries(ldap PRIVATE ldap-common)
