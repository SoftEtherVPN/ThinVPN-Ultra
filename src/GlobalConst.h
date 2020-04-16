// Desktop VPN Global Const

#pragma warning(disable : 4819)

#ifndef	GLOBAL_CONST_H
#define	GLOBAL_CONST_H

//// Brand
// (Define it if building SoftEther VPN Project.)
#define	GC_SOFTETHER_VPN
#define	GC_SOFTETHER_OSS


//// For DeskVPN
#define	DESK_PROTUCE_NAME_SUITE			"Desktop VPN"

#define DESK_PUBLISHER_NAME_UNICODE		L"IPA CyberLab"				// 元: L"SoftEther Corporation"
#define DESK_PUBLISHER_NAME_ANSI		"IPA CyberLab"				// 元: "SoftEther Corporation"
#define	DESK_SECURE_PACK_NAME			"IPA_DESK_SERVER"			// 元: "DESK_SERVER"
#define DESK_LOCALHOST_DUMMY_FQDN		"%s.secure.desktopvpn.com"

#define DESK_SECURE_PACK_EASY_MODE		// 有効にすると簡易モードになる


#define DG_REGKEY	"Software\\" DESK_PUBLISHER_NAME_ANSI "\\Desktop VPN Server\\Config Tool"
#define DI_REGKEY	"Software\\" DESK_PUBLISHER_NAME_ANSI "\\Desktop VPN Server\\Installer"

#define DI_RUDP_INSTALL_DIR		L"Common Files\\Desktop VPN Server RUDP Helper"

#define DI_PRODUCT_SERVER_NAME	"DeskServer"
#define DI_PRODUCT_CLIENT_NAME	"DeskClient"

#define DESK_SERVER_SVC_NAME			"DESKSERVER"										// Desk Server Windows サービス名

#define	DESK_SVC_NAME					"DESK"	// WideTunnel 内でのサービス名
#define DS_RPC_PORT						9823	// Server の RPC ポート					// 元: 9822


// インストールするファイル名
#define DI_FILENAME_DESKCLIENT		L"DeskClient.exe"
#define DI_FILENAME_DESKCONFIG		L"DeskConfig.exe"
#define DI_FILENAME_DESKSERVER		L"DeskServer.exe"
#define DI_FILENAME_DESKSETUP		L"DeskSetup.exe"
#define	DI_FILENAME_DESKHELPER		L"DeskHelper.exe"
#define DI_FILENAME_HAMCORE			L"hamcore.se2"

// 関係するファイル名
#define DI_FILENAME_SETUPINI		L"@DeskSetup.ini"



// ここから下は おそらくいじらなくて OK
#define DC_RDP_PORT_START				3500	// Client の RDP ポートの開始番号
#define DS_URDP_PORT					3457	// User-mode RDP ポート
#define DS_RDP_PORT						3389	// RDP のデフォルトのポート番号



//// Basic Variables

#define	CEDAR_PRODUCT_STR			"SoftEther"
#define	CEDAR_PRODUCT_STR_W			L"SoftEther"
#define	CEDAR_SERVER_STR			"SoftEther VPN Server"
#define	CEDAR_BRIDGE_STR			"SoftEther VPN Bridge"
#define	CEDAR_BETA_SERVER			"SoftEther VPN Server Pre Release"
#define	CEDAR_MANAGER_STR			"SoftEther VPN Server Manager"
#define	CEDAR_CUI_STR				"SoftEther VPN Command-Line Admin Tool"
#define CEDAR_ELOG					"SoftEther EtherLogger"
#define	CEDAR_CLIENT_STR			"SoftEther VPN Client"
#define CEDAR_CLIENT_MANAGER_STR	"SoftEther VPN Client Connection Manager"
#define	CEDAR_ROUTER_STR			"SoftEther VPN User-mode Router"
#define	CEDAR_SERVER_LINK_STR		"SoftEther VPN Server (Cascade Mode)"
#define	CEDAR_BRIDGE_LINK_STR		"SoftEther VPN Bridge (Cascade Mode)"
#define	CEDAR_SERVER_FARM_STR		"SoftEther VPN Server (Cluster RPC Mode)"



//// Default Port Number

#define	GC_DEFAULT_PORT		5555
#define	GC_CLIENT_CONFIG_PORT	9930
#define	GC_CLIENT_NOTIFY_PORT	9983


//// Software Name

#define	GC_SVC_NAME_VPNSERVER		"SEVPNSERVER"
#define	GC_SVC_NAME_VPNCLIENT		"SEVPNCLIENT"
#define	GC_SVC_NAME_VPNBRIDGE		"SEVPNBRIDGE"



//// Registry

#define	GC_REG_COMPANY_NAME			"SoftEther Project"




//// Setup Wizard

#define	GC_SW_UIHELPER_REGVALUE		"SoftEther VPN Client UI Helper"
#define	GC_SW_SOFTETHER_PREFIX		"se"
#define	GC_SW_SOFTETHER_PREFIX_W	L"se"



//// VPN UI Components

#define	GC_UI_APPID_CM				L"SoftEther.SoftEther VPN Client"



#endif	// GLOBAL_CONST_H

