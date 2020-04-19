// Desktop VPN Global Const

#pragma warning(disable : 4819)

#ifndef	GLOBAL_CONST_H
#define	GLOBAL_CONST_H

//// Brand
// (Define it if building SoftEther VPN Project.)
#define	GC_SOFTETHER_VPN
#define	GC_SOFTETHER_OSS


//// For DeskVPN
#define	DESK_PRODUCT_NAME_SUITE			"Thin Telework System"

#define DESK_PUBLISHER_NAME_UNICODE		L"Thin Telework System"		// 元: L"SoftEther Corporation"
#define DESK_PUBLISHER_NAME_ANSI		"Thin Telework System"			// 元: "SoftEther Corporation"
#define	DESK_SECURE_PACK_NAME			"THIN_SERVER"			// 元: "DESK_SERVER"
#define DESK_LOCALHOST_DUMMY_FQDN		"%s.secure.desktopvpn.com"	// TODO: 後で変更する

#define DESK_SETTINGS_DIR_NAME			L"Thin Telework System Settings"

#define DESK_SECURE_PACK_EASY_MODE		// 有効にすると簡易モードになる

#define DU_NO_THEEND_KEY_NAME			"NoTheEndDialog_Ver01"		// お疲れ様でした無効化キー 画像変更時に番号増やす


#define DG_REGKEY	"Software\\" DESK_PUBLISHER_NAME_ANSI "\\Thin Telework System Server\\Config Tool"
#define DI_REGKEY	"Software\\" DESK_PUBLISHER_NAME_ANSI "\\Thin Telework System Server\\Installer"

#define DU_REGKEY	"Software\\" DESK_PUBLISHER_NAME_ANSI "\\Thin Telework System Client\\UI"

#define DI_RUDP_INSTALL_DIR		L"Common Files\\Thin Telework System Server RUDP Helper"

#define DI_PRODUCT_SERVER_NAME	"ThinSvr"
#define DI_PRODUCT_CLIENT_NAME	"ThinClient"

#define DESK_SERVER_SVC_NAME			"THINSVR"										// Desk Server Windows サービス名

#define	DESK_SVC_NAME					"DESK"	// WideTunnel 内でのサービス名
#define DS_RPC_PORT						9823	// Server の RPC ポート					// 元: 9822

#define	SW_SINGLE_INSTANCE_NAME				"ThinTelework_Setup_Wizard"

// イベントログのソース名
#define	DS_EVENTLOG_SOURCE_NAME		L"Thin Telework System Server"

// 定数
#define DS_RPC_VER_SIGNATURE_STR	"Thin Telework System Server Configuration Procotol (localhost only)"
#define DS_CONFIG_FILENAME			"@ThinServer.config"
#define DS_CONFIG_FILENAME2			L"ThinServer.config"

#define	DC_CONFIG_FILENAME			L"ThinClient.config"


#define	GC_REG_COMPANY_NAME			"Thin Telework System"


// Installer 関係
#define SW_NAME_THINSVR			"thinsvr"
#define SW_LONG_THINSVR			L"Thin Telework System Server"

#define SW_NAME_THINCLIENT			"thinclient"
#define SW_LONG_THINCLIENT			L"Thin Telework System Client"


// インストールするファイル名
#define DI_FILENAME_DESKCLIENT		L"ThinClient.exe"
#define DI_FILENAME_DESKCONFIG		L"ThinConfig.exe"
#define DI_FILENAME_DESKSERVER		L"ThinSvr.exe"
#define DI_FILENAME_DESKSETUP		L"ThinSetup.exe"
#define	DI_FILENAME_DESKHELPER		L"ThinHelper.exe"
#define DI_FILENAME_HAMCORE			L"hamcore.se2"
#define DI_FILENAME_DESKSERVER_NOSHARE_SRC		L"ThinSvrNS.exe"

#define SW_SETUP_NOSIGN_EXESRC		L"|ThinSetup_nosign.exe"
#define SW_SETUP_EXE_X86			L"ThinSetup.exe"
#define SW_SETUP_EXE_X64			L"ThinSetup_x64.exe"

// 関係するファイル名
#define DI_FILENAME_SETUPINI		L"@ThinSetup.ini"


#define	GC_SVC_NAME_THINSVR		"THINSVR"

// ここから下は おそらくいじらなくて OK
#define DC_RDP_PORT_START				3500	// Client の RDP ポートの開始番号
#define DS_URDP_PORT					3457	// User-mode RDP ポート
#define DS_RDP_PORT						3389	// RDP のデフォルトのポート番号



//// Basic Variables

#define	CEDAR_PRODUCT_STR			"Thin Telework System"
#define	CEDAR_PRODUCT_STR_W			L"Thin Telework System"
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






//// Setup Wizard

#define	GC_SW_UIHELPER_REGVALUE		"SoftEther VPN Client UI Helper"
#define	GC_SW_SOFTETHER_PREFIX		""
#define	GC_SW_SOFTETHER_PREFIX_W	L""



//// VPN UI Components

#define	GC_UI_APPID_CM				L"SoftEther.SoftEther VPN Client"



#endif	// GLOBAL_CONST_H

