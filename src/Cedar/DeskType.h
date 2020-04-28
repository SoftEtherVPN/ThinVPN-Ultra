// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DeskType.h
// PacketiX Desktop VPN 型一覧ヘッダ

#ifndef	DESKTYPE_H
#define DESKTYPE_H

// Desk.h
typedef struct URDP_SERVER URDP_SERVER;

// DS.h
typedef struct DS DS;
typedef struct DS_INFO DS_INFO;
typedef struct DS_CLIENT DS_CLIENT;
typedef struct DS_HISTORY DS_HISTORY;
typedef struct DS_RADIUS_CACHE DS_RADIUS_CACHE;

// DC.h
typedef struct DC_ADVAUTH DC_ADVAUTH;
typedef struct DC DC;
typedef struct DC_AUTH DC_AUTH;
typedef bool (DC_AUTH_CALLBACK)(DC *dc, DC_AUTH *dc_auth, void *param);
typedef struct DC_SESSION DC_SESSION;
typedef bool (DC_PASSWORD_CALLBACK)(DC_SESSION *s, char *password, UINT password_max_size);
typedef bool (DC_OTP_CALLBACK)(DC *dc, char *otp, UINT otp_max_size, DC_SESSION *param);
typedef bool (DC_ADVAUTH_CALLBACK)(DC_SESSION *s, DC_AUTH *auth);
typedef void (DC_EVENT_CALLBACK)(DC_SESSION *s, UINT event_type, void *event_param);
typedef struct DC_LISTENED_SOCK_THREAD_PARAM DC_LISTENED_SOCK_THREAD_PARAM;
typedef struct DC_BLUE DC_BLUE;

// DsRpc.h
typedef struct RPC_DS_STATUS RPC_DS_STATUS;
typedef struct RPC_PCID RPC_PCID;
typedef struct RPC_DS_CONFIG RPC_DS_CONFIG;


#endif	// DESKTYPE_H



